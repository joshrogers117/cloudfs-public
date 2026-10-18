// SPDX-License-Identifier: AGPL-3.0-or-later
/// Namespace store: the inode tree + block map, backed by DO SQLite.
///
/// Design goals (SPEC §4, §6):
///  - Never load a whole tree/directory into memory — `list()` is paginated with
///    keyset (seek) cursors so a directory with 1M children pages in O(pageSize).
///  - Versioned writes (optimistic concurrency): callers can pass
///    `expectedVersion` and get a typed conflict instead of a silent clobber.
///  - Monotonic `seq` doubles as the change-feed cursor / sync anchor.
///  - Block map is content-addressed with refcounts so snapshot-aware GC and
///    cross-version dedup are cheap.

import { fixedBlockSize } from './file-manifest';
import { releaseStreamBlocks, decrementStreamReferences } from './stream-manifest';
import type { Block, Item, Page, StreamInfo } from "./types";
import { InvalidManifestError, sameBlockManifest, validateBlockManifest } from "./block-manifest";

export class ConflictError extends Error {
  constructor(
    public readonly itemId: string,
    public readonly expected: number,
    public readonly actual: number,
  ) {
    super(`version conflict on ${itemId}: expected ${expected}, found ${actual}`);
    this.name = "ConflictError";
  }
}

/// A mutation rejected because the target inode is held under an exclusive lease by
/// another principal (or the presented fence is stale). Audit B5: the lock gate. The
/// route maps this to 409 with `{ locked:true, heldBy }` so a client renders
/// "locked by Bob" / re-acquires instead of silently clobbering the holder's work.
export class LockedError extends Error {
  constructor(
    public readonly itemId: string,
    public readonly heldBy: string,
    public readonly reason: "held-by-other" | "fence-stale" = "held-by-other",
  ) {
    super(`item ${itemId} is locked (${reason}) by ${heldBy}`);
    this.name = "LockedError";
  }
}

export class NamespaceMutationError extends Error {
  constructor(public readonly code: "invalid_parent" | "root_protected" | "type_mismatch" | "directory_not_empty" | "readonly" | "replacement_changed" | "sharing_violation", message: string) {
    super(message); this.name = "NamespaceMutationError";
  }
}

export interface RenameReplacement { id: string; expectedVersion: number }

const DEFAULT_PAGE = 500;
const MAX_PAGE = 2000;

/// Audit B17/B18 — a rejected name. The route maps this to 400 so a bad name (empty,
/// contains a path separator / NUL, or is `.`/`..`) never lands as an item id.
export class InvalidNameError extends Error {
  constructor(public readonly name: string, public readonly reason: string) {
    super(`invalid item name ${JSON.stringify(name)}: ${reason}`);
    this.name = "InvalidNameError";
  }
}

/// Audit B17 — a rename/move destination already has a LIVE sibling with that name. The route
/// maps this to 409 so the client surfaces a "name already taken" instead of clobbering.
export class NameCollisionError extends Error {
  constructor(public readonly parent: string | null, public readonly nameValue: string) {
    super(`an item named ${JSON.stringify(nameValue)} already exists under ${parent ?? "(root)"}`);
    this.name = "NameCollisionError";
  }
}

/// Audit B17 — an attempt to move a directory into its own subtree (would create a cycle).
export class InvalidMoveError extends Error {
  constructor(public readonly id: string, public readonly newParent: string) {
    super(`cannot move ${id} into its own descendant ${newParent}`);
    this.name = "InvalidMoveError";
  }
}

/// Audit B18 — canonicalize a filesystem name for storage + id derivation. macOS sends
/// decomposed (NFD) Unicode while the web/CLI send composed (NFC); without normalization
/// the same visible name (`café`) becomes two distinct rows/ids — the canonical cross-platform
/// sync bug. We normalize to NFC at the write boundary so an id is byte-stable across clients.
/// Audit B17: also VALIDATE — reject empty, path separators, NUL, and the `.`/`..` specials that
/// would collide ids across directories or escape the tree under an `ON CONFLICT DO UPDATE`.
export function canonicalizeName(name: string): string {
  if (typeof name !== "string" || name.length === 0) throw new InvalidNameError(String(name), "empty");
  const nfc = name.normalize("NFC");
  if (nfc.includes("/") || nfc.includes("\\")) throw new InvalidNameError(name, "contains a path separator");
  if (nfc.includes("\u0000")) throw new InvalidNameError(name, "contains a NUL byte");
  if (nfc === "." || nfc === "..") throw new InvalidNameError(name, "is a reserved name");
  return nfc;
}

/// FINDING A: hard ceiling on a single bulk-seed request. The _seed seam is a
/// test/benchmark path mounted into production; without a bound a caller could pass
/// `count: 100000000` and wedge the single-threaded DO. 5000 comfortably covers the
/// largest legitimate seam caller (gateway.test.ts seeds 2500). The gateway rejects
/// (400) above this; bulkCreate also clamps defensively.
export const BULK_SEED_MAX = 5000;

export class NamespaceStore {
  constructor(private readonly sql: SqlStorage, private readonly onChange: () => void = () => {}, private readonly admit: (bytes?: number) => void = () => {},
    private readonly onDirectoryChange: (id: string) => void = () => {}) {}

  /// A child-name change is also a directory metadata change. macOS smbfs
  /// retains negative name-cache entries until the parent's mtime increases.
  /// Give each affected live parent its own sequence (never share a pagination
  /// cursor with the child), and advance time even within one millisecond or
  /// after the wall clock moves backwards. Caller transactions include these writes.
  private touchDirectories(ids: Array<string | null | undefined>): void {
    for (const id of new Set(ids)) {
      if (id == null) continue;
      const item = this.getItem(id);
      if (!item || item.deleted || !item.isDir) continue;
      const now = Math.max(Date.now(), (item.modifiedAt ?? 0) + 1, (item.changedAt ?? 0) + 1);
      const seq = this.nextSeq();
      this.sql.exec('UPDATE items SET modified_at=?,changed_at=?,version=version+1,updated_seq=? WHERE id=?;',now,now,seq,id);
      this.onDirectoryChange(id);
    }
  }

  private noteEntryChange(previous: Item | null, parent: string | null, name: string): void {
    if (!previous || previous.deleted || previous.parent !== parent || previous.name !== name) {
      this.touchDirectories([previous && !previous.deleted ? previous.parent : null, parent]);
    }
  }

  // ---- seq / fence counters (monotonic, single-row updates) ----------------

  /// Advance the change-feed sequence. Single UPDATE...RETURNING = atomic.
  nextSeq(): number {
    this.onChange();
    return Number(
      this.sql.exec(`UPDATE meta SET value = value + 1 WHERE key='seq' RETURNING value;`).one().value,
    );
  }

  currentSeq(): number {
    return Number(this.sql.exec(`SELECT value FROM meta WHERE key='seq';`).one().value);
  }

  nextFence(): number {
    return Number(
      this.sql.exec(`UPDATE meta SET value = value + 1 WHERE key='fence' RETURNING value;`).one().value,
    );
  }

  // ---- row mapping ----------------------------------------------------------

  private rowToItem(r: Record<string, SqlStorageValue>): Item {
    return {
      id: String(r.id),
      parent: r.parent === null ? null : String(r.parent),
      name: String(r.name),
      isDir: Number(r.is_dir) === 1,
      size: Number(r.size),
      contentVersion: String(r.content_version),
      etag: r.etag === null ? null : String(r.etag),
      version: Number(r.version),
      updatedSeq: Number(r.updated_seq),
      deleted: Number(r.deleted) === 1,
      createdAt: r.created_at === null || r.created_at === undefined ? null : Number(r.created_at),
      modifiedAt: r.modified_at === null || r.modified_at === undefined ? null : Number(r.modified_at),
      accessedAt: r.accessed_at == null ? null : Number(r.accessed_at),
      changedAt: r.changed_at == null ? null : Number(r.changed_at),
      fileAttributes: Number(r.file_attributes ?? 0),
    };
  }

  // ---- reads ----------------------------------------------------------------

  getItem(id: string): Item | null {
    const rows = this.sql.exec(`SELECT * FROM items WHERE id = ?;`, id).toArray();
    return rows.length ? this.rowToItem(rows[0] as any) : null;
  }

  setBasicInfo(id: string, patch: {createdAt?: number; modifiedAt?: number; accessedAt?: number; changedAt?: number; fileAttributes?: number}, expectedVersion: number, allowRetained = false): Item {
    const item = this.getItem(id);
    if (!item || (item.deleted && (!allowRetained || !this.hasOpenHandles(id)))) throw new Error(`no such item: ${id}`);
    if (item.version !== expectedVersion) throw new ConflictError(id, expectedVersion, item.version);
    const fields: Array<[string,number]> = [];
    for (const [field,column] of [['createdAt','created_at'],['modifiedAt','modified_at'],['accessedAt','accessed_at'],['changedAt','changed_at'],['fileAttributes','file_attributes']] as const) {
      if (patch[field] !== undefined) fields.push([column,patch[field]!]);
    }
    if (!fields.length) return item;
    if (patch.changedAt === undefined) fields.push(['changed_at',Date.now()]);
    const seq = item.deleted ? item.updatedSeq : this.nextSeq();
    this.sql.exec(`UPDATE items SET ${fields.map(([column]) => `${column}=?`).join(',')},version=version+1,updated_seq=? WHERE id=?;`,
      ...fields.map(([,value]) => value),seq,id);
    return this.getItem(id)!;
  }

  /// Audit B17 — resolve an item by its `(parent, name)` lookup key (the opaque-id world's
  /// replacement for the old path-derived id). Case-insensitive (NFC + NOCASE) per B18. Returns
  /// the LIVE row if one exists, else the most recent tombstone (so a recreate can reuse a
  /// versioned lineage if desired). Used by createItem/rename to find a sibling collision.
  lookupByParentName(parent: string | null, name: string): Item | null {
    const nfc = name.normalize("NFC");
    const where = parent === null ? "parent IS NULL" : "parent = ?";
    const params: SqlStorageValue[] = parent === null ? [nfc] : [parent, nfc];
    // Prefer a live row; fall back to a tombstone (newest by updated_seq).
    const rows = this.sql
      .exec(
        `SELECT * FROM items WHERE ${where}
           AND name = ? COLLATE NOCASE
         ORDER BY deleted ASC, updated_seq DESC LIMIT 1;`,
        ...params,
      )
      .toArray();
    return rows.length ? this.rowToItem(rows[0] as Record<string, SqlStorageValue>) : null;
  }

  /// The LIVE sibling at `(parent, name)`, or null. Distinct from `lookupByParentName` in that it
  /// never returns a tombstone — used to detect a name collision for a rename/create.
  liveSiblingByName(parent: string | null, name: string): Item | null {
    const nfc = name.normalize("NFC");
    const where = parent === null ? "parent IS NULL" : "parent = ?";
    const params: SqlStorageValue[] = parent === null ? [nfc] : [parent, nfc];
    const rows = this.sql
      .exec(
        `SELECT * FROM items WHERE ${where}
           AND name = ? COLLATE NOCASE AND deleted = 0 LIMIT 1;`,
        ...params,
      )
      .toArray();
    return rows.length ? this.rowToItem(rows[0] as Record<string, SqlStorageValue>) : null;
  }

  /// Paginated, index-served directory listing. The cursor is the last
  /// `(is_dir, name)` seen, base64-encoded — a keyset seek, not OFFSET (which
  /// scans). Hidden tombstones are excluded.
  list(parent: string, limit = DEFAULT_PAGE, cursor?: string | null): Page<Item> {
    const lim = Math.min(Math.max(1, limit), MAX_PAGE);
    let rows: Record<string, SqlStorageValue>[];

    if (cursor) {
      const { isDir, name } = decodeCursor(cursor);
      // Keyset predicate matching the items_dir_listing index order
      // (is_dir DESC, name ASC): advance past the last row of the prior page.
      rows = this.sql
        .exec(
          `SELECT * FROM items
           WHERE parent = ? AND deleted = 0
             AND ( is_dir < ? OR (is_dir = ? AND name > ?) )
           ORDER BY is_dir DESC, name
           LIMIT ?;`,
          parent, isDir, isDir, name, lim + 1,
        )
        .toArray();
    } else {
      rows = this.sql
        .exec(
          `SELECT * FROM items
           WHERE parent = ? AND deleted = 0
           ORDER BY is_dir DESC, name
           LIMIT ?;`,
          parent, lim + 1,
        )
        .toArray();
    }

    const hasMore = rows.length > lim;
    const pageRows = hasMore ? rows.slice(0, lim) : rows;
    const items = pageRows.map((r) => this.rowToItem(r as any));
    const last = pageRows[pageRows.length - 1];
    const nextCursor =
      hasMore && last ? encodeCursor(Number(last.is_dir), String(last.name)) : null;
    return { items, cursor: nextCursor };
  }

  /// Count of live children — cheap, index-served; used for UI + tests.
  childCount(parent: string): number {
    return Number(
      this.sql
        .exec(`SELECT COUNT(*) AS c FROM items WHERE parent = ? AND deleted = 0;`, parent)
        .one().c,
    );
  }

  /// Changes since a sync anchor (the monotonic seq). Paginated so a client that
  /// has been offline for a week doesn't pull the whole delta into memory at once.
  changesSince(seq: number, limit = DEFAULT_PAGE): { anchor: number; items: Item[]; cursor: number | null } {
    const lim = Math.min(Math.max(1, limit), MAX_PAGE);
    const rows = this.sql
      .exec(`SELECT * FROM items WHERE updated_seq > ? ORDER BY updated_seq LIMIT ?;`, seq, lim + 1)
      .toArray();
    const hasMore = rows.length > lim;
    const pageRows = hasMore ? rows.slice(0, lim) : rows;
    const items = pageRows.map((r) => this.rowToItem(r as any));
    const lastSeq = items.length ? items[items.length - 1].updatedSeq : seq;
    return {
      anchor: this.currentSeq(),
      items,
      cursor: hasMore ? lastSeq : null,
    };
  }

  // ---- writes (versioned / optimistic concurrency) -------------------------

  /// Create or replace an item. If `expectedVersion` is supplied and does not
  /// match the stored version, throws ConflictError (the Worker maps it to 409)
  /// — this is the project-file anti-clobber guard from SPEC §5.5.
  ///
  /// The result carries `untombstoned: true` iff this `put` transitioned an
  /// EXISTING, currently-tombstoned (deleted=1) row back to live (deleted=0) —
  /// i.e. a recreate at a path-deterministic id that a prior delete tombstoned.
  /// The DO create path uses this to clear stale grants ONLY on the deleted→live
  /// transition (grant-resurrection fix, I3) without dropping grants on an
  /// ordinary update of a live inode. A fresh create (no prior row) and a normal
  /// update (prior row already live) both report `untombstoned: false`.
  put(
    parent: string | null,
    name: string,
    isDir: boolean,
    size: number,
    opts?: { id?: string; expectedVersion?: number; etag?: string | null; contentVersion?: string },
  ): Item & { untombstoned: boolean } {
    this.admit();
    // Audit B17/B18: when the id is PATH-DERIVED (no explicit opts.id), canonicalize (NFC) +
    // VALIDATE the name so the id is byte-stable across NFC/NFD clients and a bad name
    // (separator/NUL/`.`/`..`/empty) can never land as an id. When an explicit `opts.id` is
    // supplied (root seed with id:"root" + empty name; snapshot restore re-applying an existing
    // id; seed fixtures), the id is authoritative — we still NFC-normalize the stored DISPLAY
    // name (so it matches what a client would send) but don't reject (root legitimately has "").
    // Audit B17: ids are now OPAQUE UUIDs, not `${parent}/${name}`. When no explicit `opts.id`
    // is given (the real create path), resolve the lookup by `(parent, name)`:
    //   - a LIVE sibling exists  → update it in place (its id is preserved; a "create" over a
    //     live name is an upsert, matching the old path-id behavior);
    //   - else                   → mint a fresh opaque id (`ino-<uuid>`). A prior TOMBSTONE at
    //     the same name does NOT block the new id — the recreate gets a brand-new id, which is
    //     exactly why opaque ids retire the grant-resurrection hazard (the old grants are bound
    //     to the dead id, never reused).
    // An explicit `opts.id` (snapshot restore re-applying a frozen id; seed fixtures; tests) is
    // honored verbatim and addresses that row by id.
    let id: string;
    let existing: Item | null;
    if (opts?.id !== undefined) {
      if (name.length > 0) name = name.normalize("NFC");
      id = opts.id;
      existing = this.getItem(id);
    } else {
      name = canonicalizeName(name);
      const liveSibling = this.liveSiblingByName(parent, name);
      if (liveSibling) {
        id = liveSibling.id;
        existing = liveSibling;
      } else {
        id = `ino-${crypto.randomUUID()}`;
        existing = null;
      }
    }
    // Capture the deleted→live transition BEFORE the upsert flips deleted to 0.
    const untombstoned = existing?.deleted === true;

    if (opts?.expectedVersion !== undefined) {
      const actual = existing && !existing.deleted ? existing.version : 0;
      if (actual !== opts.expectedVersion) {
        throw new ConflictError(id, opts.expectedVersion, actual);
      }
    }

    if (untombstoned) this.sql.exec(`DELETE FROM retained_blocks WHERE item_id=?;`, id);
    const seq = this.nextSeq();
    const version = existing ? existing.version + 1 : 1;
    const createdSeq = existing ? this.rawCreatedSeq(id) : seq;
    // Production derives contentVersion from the block-manifest hash; default
    // keeps it deterministic for the metadata-only path.
    const cv = opts?.contentVersion ?? `cv-${size}-${seq}`;
    const etag = opts?.etag ?? existing?.etag ?? null;

    const now = isDir && existing?.isDir && !existing.deleted
      ? Math.max(Date.now(), (existing.modifiedAt ?? 0) + 1, (existing.changedAt ?? 0) + 1)
      : Date.now();
    this.sql.exec(
      `INSERT INTO items (id,parent,name,is_dir,size,content_version,etag,version,created_seq,updated_seq,deleted,created_at,modified_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,0,?,?)
       ON CONFLICT(id) DO UPDATE SET
         parent=excluded.parent, name=excluded.name, is_dir=excluded.is_dir,
         size=excluded.size, content_version=excluded.content_version,
         etag=excluded.etag, version=excluded.version, updated_seq=excluded.updated_seq,
         deleted=0, modified_at=excluded.modified_at;`,
      id, parent, name, isDir ? 1 : 0, size, cv, etag, version, createdSeq, seq, now, now,
    );
    // items_change_time runs after a content-version update and uses wall time.
    // Apply the directory's monotonic time after that trigger has completed.
    if (isDir) this.sql.exec('UPDATE items SET changed_at=? WHERE id=?;',now,id);
    this.noteEntryChange(existing, parent, name);
    return { ...this.getItem(id)!, untombstoned };
  }

  private rawCreatedSeq(id: string): number {
    const r = this.sql.exec(`SELECT created_seq FROM items WHERE id = ?;`, id).toArray()[0];
    return r ? Number(r.created_seq) : this.currentSeq();
  }

  /// Audit B17 — rename/move an item. With opaque immutable ids this touches ONLY `(parent, name)`
  /// of the ONE row; descendants keep their ids (their `parent` pointer is unchanged, since a move
  /// only changes the moved node's parent, not its children's parents). No id rewrite, no cascade.
  /// Validates the new name (NFC + reserved/separator checks) and rejects a collision with a LIVE
  /// sibling at the destination `(parent, name)`. `expectedVersion` is the optimistic-concurrency
  /// guard (a concurrent edit of the same item → ConflictError). Returns the updated item.
  rename(
    id: string,
    opts: { parent?: string | null; name?: string; expectedVersion?: number; replace?: RenameReplacement; owner?: string; openHandle?: string },
  ): Item {
    const existing = this.getItem(id);
    if (!existing || existing.deleted) throw new Error(`no such item: ${id}`);
    if (opts.expectedVersion !== undefined && existing.version !== opts.expectedVersion) {
      throw new ConflictError(id, opts.expectedVersion, existing.version);
    }
    if (existing.parent === null || id === "root") throw new NamespaceMutationError("root_protected", "The filespace root cannot be renamed");
    const newParent = opts.parent === undefined ? existing.parent : opts.parent;
    const parent = newParent === null ? null : this.getItem(newParent);
    if (!parent || parent.deleted || !parent.isDir) throw new NamespaceMutationError("invalid_parent", "The destination parent must be a live directory");
    const newName = opts.name === undefined ? existing.name : canonicalizeName(opts.name);
    // No-op move would still bump a version; short-circuit identical (parent,name).
    if (!opts.replace && newParent === existing.parent && newName === existing.name) return existing;
    if (!this.deleteSharingAllowed(id, Date.now(), opts.owner, opts.openHandle)) {
      throw new NamespaceMutationError("sharing_violation", "An open handle does not share delete access");
    }
    // A move into a directory must not collide with a live sibling there (other than self).
    const collision = this.liveSiblingByName(newParent, newName);
    if (opts.replace) {
      if (!collision || collision.id !== opts.replace.id || collision.id === id) {
        throw new NamespaceMutationError("replacement_changed", "The destination entry changed before replacement");
      }
      if (collision.version !== opts.replace.expectedVersion) throw new ConflictError(collision.id, opts.replace.expectedVersion, collision.version);
      if (existing.isDir !== collision.isDir) throw new NamespaceMutationError("type_mismatch", "Cannot replace a file with a directory or a directory with a file");
      if (collision.isDir && this.childCount(collision.id) !== 0) throw new NamespaceMutationError("directory_not_empty", "The destination directory is not empty");
      if (!collision.isDir && ((collision.fileAttributes ?? 0) & 1)) throw new NamespaceMutationError("readonly", "The destination file is read-only");
      if (!this.deleteSharingAllowed(collision.id, Date.now(), opts.owner, opts.openHandle)) throw new NamespaceMutationError("sharing_violation", "An open handle does not share delete access");
    } else if (collision && collision.id !== id) {
      throw new NameCollisionError(newParent, newName);
    }
    // Reject moving a directory into its own subtree (would orphan a cycle).
    if (existing.isDir && newParent !== null && this.isAncestorOrSelf(id, newParent)) {
      throw new InvalidMoveError(id, newParent);
    }
    // The caller must wrap this in transactionSync. Every precondition is checked
    // before either entry changes; a SQL failure rolls back tombstone + rename + refs.
    if (opts.replace) {
      const removed = this.remove(opts.replace.id, opts.replace.expectedVersion, opts.owner, opts.openHandle);
      if (!removed.deleted) throw new NamespaceMutationError("replacement_changed", removed.reason ?? "The destination entry could not be replaced");
    }
    const seq = this.nextSeq();
    this.sql.exec(
      `UPDATE items SET parent = ?, name = ?, version = version + 1, updated_seq = ?, changed_at = ? WHERE id = ?;`,
      newParent, newName, seq, Date.now(), id,
    );
    this.touchDirectories([existing.parent, newParent]);
    return this.getItem(id)!;
  }

  /// Is `ancestorId` equal to, or an ancestor of, `id`? Walks the parent chain (bounded). Used to
  /// reject moving a directory into its own subtree.
  private isAncestorOrSelf(ancestorId: string, id: string): boolean {
    let cur: string | null = id;
    let guard = 0;
    while (cur !== null && guard++ < 100_000) {
      if (cur === ancestorId) return true;
      const r: Record<string, SqlStorageValue> | undefined =
        this.sql.exec(`SELECT parent FROM items WHERE id = ?;`, cur).toArray()[0];
      cur = r ? (r.parent === null ? null : String(r.parent)) : null;
    }
    return false;
  }

  /// Soft-delete (tombstone) so the deletion propagates through the change feed.
  /// Decrements block refcounts; GC reclaims orphaned blocks later.
  remove(id: string, expectedVersion?: number, owner?: string, openHandle?: string): { deleted: boolean; reason?: string } {
    const existing = this.getItem(id);
    if (!existing || existing.deleted) return { deleted: true };
    if (existing.parent === null || id === "root") return { deleted: false, reason: "root_protected" };
    if (existing.isDir && this.childCount(id) > 0) return { deleted: false, reason: "directory_not_empty" };
    if (!existing.isDir && ((existing.fileAttributes ?? 0) & 1)) return { deleted: false, reason: "readonly" };
    if (expectedVersion !== undefined && existing.version !== expectedVersion) {
      return { deleted: false, reason: "version conflict" };
    }
    if (!this.deleteSharingAllowed(id, Date.now(), owner, openHandle)) return { deleted: false, reason: "sharing_violation" };
    const seq = this.nextSeq();
    this.sql.exec(
      `UPDATE items SET deleted=1, version=version+1, updated_seq=? WHERE id=?;`,
      seq, id,
    );
    // Open descriptions pin the tombstoned inode's current payload and historical
    // recovery roots. Namespace visibility changes immediately; final close/expiry
    // performs the same idempotent release as an ordinary delete.
    this.reclaimUnopenedPayload(id);
    this.touchDirectories([existing.parent]);
    return { deleted: true };
  }

  /// Live inode ids in the subtree rooted at `id` (inclusive), BFS over the
  /// parent index. Bounded per level; used for recursive delete + bulk-op
  /// detection. Excludes tombstones.
  subtreeIds(id: string): string[] {
    const self = this.getItem(id);
    if (!self || self.deleted) return [];
    const out: string[] = [id];
    const queue = [id];
    let guard = 0;
    while (queue.length && guard++ < 1_000_000) {
      const parent = queue.shift()!;
      const kids = this.sql
        .exec(`SELECT id, is_dir FROM items WHERE parent = ? AND deleted = 0;`, parent)
        .toArray();
      for (const k of kids) {
        out.push(String(k.id));
        if (Number(k.is_dir) === 1) queue.push(String(k.id));
      }
    }
    return out;
  }

  /// Recursive (subtree) soft-delete. Tombstones `id` and every live descendant,
  /// releasing each item's block refs (so snapshot-aware GC can reclaim). Returns
  /// the deleted inode ids (children before parents is not required for
  /// tombstoning, but we return the full set so the caller can roll the delete up
  /// into a single bulk-op activity event). Non-recursive by intent: callers that
  /// want a single-item delete keep using `remove`.
  ///
  /// Finding #4: the block-ref release + block deletion — the dominant cost — are
  /// done SET-BASED over the whole subtree (one `UPDATE block_refs`, one `DELETE
  /// FROM blocks`, each driven by a recursive CTE evaluated server-side) instead of
  /// the prior per-item `remove()` doing SELECT-blocks + per-block UPDATE + DELETE.
  /// Per-inode seq/version tombstoning is PRESERVED exactly (each inode still gets
  /// its own monotonic seq + distinct updated_seq), so change-feed granularity is
  /// unchanged from the old per-item `remove()` path.
  removeSubtree(id: string, owner?: string, openHandle?: string): { deleted: string[] } {
    const parent = this.getItem(id)?.parent;
    const ids = this.subtreeIds(id);
    if (ids.length === 0) return { deleted: ids };
    if (ids.some(itemId => !this.deleteSharingAllowed(itemId, Date.now(), owner, openHandle))) throw new NamespaceMutationError("sharing_violation", "An open handle does not share delete access");

    // Release block refs for the WHOLE subtree in one statement: decrement each
    // referenced hash by the number of subtree blocks pointing at it (correct even
    // when multiple deleted files share a hash). The CTE re-derives the SAME live
    // subtree `subtreeIds()` walked, so no large IN-list of host parameters is
    // needed — but it MUST carry the `deleted=0` guard in BOTH the seed and the
    // recursion so it stops at tombstoned directories exactly like `subtreeIds`.
    // Without it the walk descends THROUGH an already-tombstoned dir into a still
    // -LIVE orphan beneath it and would clobber that live file's block map +
    // refcounts (GC then frees R2 blocks a live file still references — data loss).
    // This runs BEFORE the tombstone loop below, while these inodes are still live,
    // so `deleted=0` selects exactly the set we are about to delete (running it
    // after would select nothing, since the loop tombstones them all).
    const now = Date.now();
    const subtreeCte = `WITH RECURSIVE subtree(id, is_dir) AS (
        SELECT id, is_dir FROM items WHERE id=?1 AND deleted=0
        UNION ALL
        SELECT i.id, i.is_dir FROM items i
          JOIN subtree s ON i.parent = s.id WHERE s.is_dir=1 AND i.deleted=0
      ), unopened(id) AS (
        SELECT s.id FROM subtree s WHERE NOT EXISTS(
          SELECT 1 FROM open_handles h WHERE h.inode_id=s.id AND h.expires_at>?2
        )
      )`;
    this.sql.exec(
      `${subtreeCte}
       UPDATE block_refs
         SET refcount = refcount - (
           SELECT COUNT(*) FROM blocks b
             JOIN unopened s ON b.item_id = s.id
             WHERE b.block_hash = block_refs.block_hash
         )
       WHERE block_hash IN (
         SELECT b.block_hash FROM blocks b JOIN unopened s ON b.item_id = s.id
       );`,
      id, now,
    );
    this.sql.exec(
      `${subtreeCte}
       DELETE FROM blocks WHERE item_id IN (SELECT id FROM unopened);`,
      id, now,
    );
    decrementStreamReferences(this.sql,`${subtreeCte} SELECT b.block_hash FROM stream_blocks b JOIN unopened s ON s.id=b.item_id`,[id,now]);
    this.sql.exec(`${subtreeCte} DELETE FROM stream_blocks WHERE item_id IN(SELECT id FROM unopened);`,id,now);
    this.sql.exec(
      `${subtreeCte}
       DELETE FROM retained_blocks WHERE item_id IN (SELECT id FROM unopened);`,
      id, now,
    );
    this.sql.exec(
      `${subtreeCte}
       DELETE FROM item_streams WHERE item_id IN (SELECT id FROM unopened);`,
      id, now,
    );

    // Tombstone each inode individually so every deletion gets its own seq and
    // surfaces as a distinct change-feed entry (same granularity as remove()).
    for (const child of ids) {
      const seq = this.nextSeq();
      this.sql.exec(
        `UPDATE items SET deleted=1, version=version+1, updated_seq=? WHERE id=? AND deleted=0;`,
        seq, child,
      );
    }

    this.touchDirectories([parent]);
    return { deleted: ids };
  }

  /** Whether any unexpired open description pins this inode. */
  hasOpenHandles(itemId: string, now = Date.now()): boolean {
    return this.sql.exec(`SELECT 1 FROM open_handles WHERE inode_id=? AND expires_at>? LIMIT 1;`, itemId, now).toArray().length > 0;
  }

  deleteSharingAllowed(itemId: string, now = Date.now(), owner?: string, openHandle?: string): boolean {
    return this.sql.exec(`SELECT 1 FROM open_handles WHERE inode_id=? AND expires_at>? AND (share_mask & 4)=0
      AND NOT (handle_id=? AND owner=? AND (access_mask & 4)=4) LIMIT 1;`,
      itemId, now, openHandle ?? "", owner ?? "").toArray().length === 0;
  }

  /** Release a deleted inode's payload after its final handle closes or expires.
   * The tombstone and ACL grants remain for change-feed/authorization history. */
  reclaimUnopenedPayload(itemId: string, now = Date.now()): boolean {
    const item = this.sql.exec(`SELECT deleted FROM items WHERE id=?;`, itemId).toArray()[0];
    if (!item || Number(item.deleted) !== 1 || this.hasOpenHandles(itemId, now)) return false;
    const hadPayload=this.sql.exec(`SELECT 1 FROM blocks WHERE item_id=? UNION ALL
      SELECT 1 FROM stream_blocks WHERE item_id=? UNION ALL SELECT 1 FROM retained_blocks WHERE item_id=?
      UNION ALL SELECT 1 FROM item_streams WHERE item_id=? LIMIT 1;`,itemId,itemId,itemId,itemId).toArray().length>0;
    this.sql.exec(`UPDATE block_refs SET refcount=refcount-(
      SELECT COUNT(*) FROM blocks b WHERE b.item_id=?1 AND b.block_hash=block_refs.block_hash)
      WHERE block_hash IN (SELECT block_hash FROM blocks WHERE item_id=?1);`, itemId);
    decrementStreamReferences(this.sql, `SELECT block_hash FROM stream_blocks WHERE item_id=?1`, [itemId]);
    this.sql.exec(`DELETE FROM blocks WHERE item_id=?;`, itemId);
    this.sql.exec(`DELETE FROM stream_blocks WHERE item_id=?;`, itemId);
    this.sql.exec(`DELETE FROM retained_blocks WHERE item_id=?;`, itemId);
    this.sql.exec(`DELETE FROM item_streams WHERE item_id=?;`, itemId);
    return hadPayload;
  }

  /** Reclaim a bounded page of retained deleted payloads. Backups intentionally
   * omit volatile open handles, so a restored tombstone cannot retain old bytes. */
  reclaimDeletedPayloadBatch(now = Date.now(), limit = 256): { inodeIds: string[]; more: boolean } {
    const bounded = Number.isSafeInteger(limit) && limit > 0 ? Math.min(limit, 256) : 0;
    if (!bounded) return { inodeIds: [], more: false };
    const predicate = `i.deleted=1 AND NOT EXISTS(
      SELECT 1 FROM open_handles h WHERE h.inode_id=i.id AND h.expires_at>?
    ) AND EXISTS (
      SELECT 1 FROM blocks b WHERE b.item_id=i.id
      UNION ALL SELECT 1 FROM stream_blocks b WHERE b.item_id=i.id
      UNION ALL SELECT 1 FROM retained_blocks b WHERE b.item_id=i.id
      UNION ALL SELECT 1 FROM item_streams s WHERE s.item_id=i.id
    )`;
    const rows = this.sql.exec(`SELECT i.id FROM items i WHERE ${predicate} ORDER BY i.updated_seq,i.id LIMIT ?;`, now, bounded).toArray();
    const inodeIds: string[] = [];
    for (const row of rows) {
      const id = String(row.id);
      if (this.reclaimUnopenedPayload(id, now)) inodeIds.push(id);
    }
    const more = this.sql.exec(`SELECT 1 FROM items i WHERE ${predicate} LIMIT 1;`, now).toArray().length > 0;
    return { inodeIds, more };
  }

  // ---- block map (large-file support, SPEC §3.2) ---------------------------

  /// Replace a file's block map atomically (no awaits between statements =
  /// single coalesced transaction). Bumps refcounts; updates size/contentVersion.
  ///
  /// Finding #2: snapshot restore needs to re-apply a file's metadata AND its block
  /// map in a SINGLE write (one version bump, one change-feed entry) rather than a
  /// `put()` + `setBlockMap()` pair (two seq advances, version+2, two feed mutations,
  /// and a wasted content_version write). The OPTIONAL `upsert` lets restore do that:
  /// when supplied, the item is created-or-untombstoned with the given parent/name
  /// inside this same write. Existing callers pass no `upsert` and behave unchanged
  /// (still require the item to already exist).
  setBlockMap(
    itemId: string,
    blocks: Block[],
    opts?: { etag?: string | null; upsert?: { parent: string | null; name: string }; expectedVersion?: number; blockSize?: number; allowRetained?: boolean },
  ): Item {
    validateBlockManifest(blocks);
    const layout = fixedBlockSize(blocks, opts?.blockSize);
    const existing = this.getItem(itemId);
    if ((!existing || (existing.deleted && !opts?.allowRetained)) && !opts?.upsert) throw new Error(`no such item: ${itemId}`);
    if (existing?.deleted && opts?.allowRetained && !this.hasOpenHandles(itemId)) throw new Error(`no open handle for retained item: ${itemId}`);
    if (existing?.isDir && !opts?.upsert) throw new InvalidManifestError("a directory cannot receive a file manifest");
    // A lost successful reply may be retried with the original CAS version. An
    // exact, already-published image is a no-op; a different image still conflicts.
    if (!opts?.upsert && existing && opts?.expectedVersion !== undefined
      && existing.version === opts.expectedVersion + 1
      && (opts.etag ?? existing.etag) === existing.etag
      && sameBlockManifest(this.getBlockMap(itemId), blocks)) return existing;

    this.admit(65_536 + blocks.length * 4096);

    // One bounded query pair per batch instead of one identity lookup per block.
    // Validate against the persistent catalog BEFORE dropping any live references.
    for (let i = 0; i < blocks.length; i += 256) {
      const part = blocks.slice(i, i + 256);
      const byKey = new Map(part.map(b => [b.objectKey, b.blockHash]));
      const byHash = new Map(part.map(b => [b.blockHash, b.objectKey]));
      for (const row of this.sql.exec(`SELECT object_key,block_hash FROM known_objects
        WHERE object_key IN (SELECT value FROM json_each(?));`, JSON.stringify([...byKey.keys()]))) {
        if (byKey.get(String(row.object_key)) !== String(row.block_hash)) throw new InvalidManifestError("committed object hash cannot change");
      }
      for (const row of this.sql.exec(`SELECT object_key,block_hash FROM block_refs
        WHERE block_hash IN (SELECT value FROM json_each(?));`, JSON.stringify([...byHash.keys()]))) {
        if (byHash.get(String(row.block_hash)) !== String(row.object_key)) throw new InvalidManifestError("committed hash cannot identify another object key");
      }
    }

    // Optimistic concurrency (audit B4): a content commit against an EXISTING item
    // must present the version it based its edit on. Two editors flushing the same
    // project file otherwise race to unconditional last-writer-wins, and the loser's
    // blocks silently drop to refcount 0 → GC-collectable (the exact "naive
    // last-writer-wins destroys an editor's day" failure SPEC §5.5 forbids). When
    // `expectedVersion` is supplied and the stored version differs, throw — the route
    // maps ConflictError → 409 so the client can rebase/fork instead of clobbering.
    // A tombstoned (deleted) row counts as version 0 here (a recreate is not a clobber).
    if (opts?.expectedVersion !== undefined) {
      const actual = existing && (!existing.deleted || opts?.allowRetained) ? existing.version : 0;
      if (actual !== opts.expectedVersion) {
        throw new ConflictError(itemId, opts.expectedVersion, actual);
      }
    }

    // Retain authoritative old ownership BEFORE replacing the live map, in this
    // same synchronous SQL turn and only after optimistic concurrency succeeds.
    // Independent GC roots avoid changing live/snapshot refcount accounting.
    const retainedWrite = !opts?.upsert && !!existing?.deleted && !!opts?.allowRetained;
    if (existing?.deleted && !retainedWrite) {
      this.sql.exec(`DELETE FROM retained_blocks WHERE item_id=?;`, itemId);
    } else if (retainedWrite) {
      this.sql.exec(`INSERT OR IGNORE INTO retained_blocks (item_id,object_key,block_hash,retained_at)
        SELECT item_id,object_key,block_hash,? FROM blocks WHERE item_id=?;`, Date.now(), itemId);
    } else if (existing) {
      this.sql.exec(`INSERT OR IGNORE INTO retained_blocks (item_id,object_key,block_hash,retained_at)
        SELECT item_id,object_key,block_hash,? FROM blocks WHERE item_id=?;`, Date.now(), itemId);
    }
    // Release old references set-wise, then write bounded JSON batches. One SQL
    // parameter per batch avoids SQLite's bind limit and keeps work linear while
    // retaining exact multiplicity when a file repeats a content-addressed block.
    this.sql.exec(`UPDATE block_refs SET refcount=refcount-(
      SELECT COUNT(*) FROM blocks b WHERE b.item_id=?1 AND b.block_hash=block_refs.block_hash)
      WHERE block_hash IN (SELECT block_hash FROM blocks WHERE item_id=?1);`, itemId);
    this.sql.exec(`DELETE FROM blocks WHERE item_id=?;`, itemId);
    let size = 0;
    for (let i = 0; i < blocks.length; i += 256) {
      const part = blocks.slice(i, i + 256), json = JSON.stringify(part);
      this.sql.exec(`INSERT OR IGNORE INTO known_objects (object_key,block_hash)
        SELECT json_extract(value,'$.objectKey'),json_extract(value,'$.blockHash') FROM json_each(?);`, json);
      this.sql.exec(`DELETE FROM block_upload_claims WHERE object_key IN
        (SELECT json_extract(value,'$.objectKey') FROM json_each(?));`, json);
      this.sql.exec(`INSERT INTO blocks (item_id,chunk_idx,block_idx,block_hash,object_key,offset,length)
        SELECT ?1,json_extract(value,'$.chunkIdx'),json_extract(value,'$.blockIdx'),
          json_extract(value,'$.blockHash'),json_extract(value,'$.objectKey'),
          json_extract(value,'$.offset'),json_extract(value,'$.length') FROM json_each(?2);`, itemId, json);
      this.sql.exec(`INSERT INTO block_refs (block_hash,object_key,refcount)
        SELECT json_extract(value,'$.blockHash'),json_extract(value,'$.objectKey'),COUNT(*)
        FROM json_each(?) GROUP BY json_extract(value,'$.blockHash')
        ON CONFLICT(block_hash) DO UPDATE SET refcount=refcount+excluded.refcount;`, json);
      for (const b of part) size += b.length;
    }

    this.sql.exec('UPDATE items SET manifest_block_size=?,last_manifest_delta_digest=NULL WHERE id=?;',layout,itemId);
    const seq = this.nextSeq();
    const cv = `cv-${size}-${seq}`;
    const etag = opts?.etag ?? existing?.etag ?? null;

    const now = Date.now();
    if (existing) {
      // Single write: set block-map-derived size/cv AND (re)apply parent/name +
      // un-tombstone when `upsert` is given — exactly one version bump. A content
      // write bumps modified_at; created_at is preserved.
      const up = opts?.upsert;
      this.sql.exec(
        `UPDATE items SET size=?, content_version=?, etag=?, is_dir=0,
           parent=COALESCE(?,parent), name=COALESCE(?,name), deleted=?,
           version=version+1, updated_seq=?, modified_at=? WHERE id=?;`,
        size, cv, etag, up ? up.parent : null, up ? up.name : null, retainedWrite ? 1 : 0,
        retainedWrite ? existing.updatedSeq : seq, now, itemId,
      );
      if (!retainedWrite) this.noteEntryChange(existing, up?.parent ?? existing.parent, up?.name ?? existing.name);
      return this.getItem(itemId)!;
    }

    // Fresh upsert: create the file inode with its block map in this same write.
    const up = opts!.upsert!;
    this.sql.exec(
      `INSERT INTO items (id,parent,name,is_dir,size,content_version,etag,version,created_seq,updated_seq,deleted,created_at,modified_at)
       VALUES (?,?,?,0,?,?,?,1,?,?,0,?,?);`,
      itemId, up.parent, up.name, size, cv, etag, seq, seq, now, now,
    );
    this.sql.exec('UPDATE items SET manifest_block_size=? WHERE id=?;',layout,itemId);
    this.noteEntryChange(null, up.parent, up.name);
    return this.getItem(itemId)!;
  }

  /// Reverse lookup: which item owns a given object key. Used by the permissions
  /// layer to map a presign target (b.key) back to an inode for the ACL check
  /// (SPEC §4.4 enforcement-at-mint). Returns the item id or null.
  itemForObjectKey(objectKey: string): string | null {
    const r = this.sql.exec(`SELECT item_id FROM blocks WHERE object_key = ?1 UNION SELECT item_id FROM stream_blocks WHERE object_key=?1 LIMIT 1;`, objectKey).toArray()[0];
    return r ? String(r.item_id) : null;
  }

  /// Read owners include retained committed versions, but only a currently live
  /// immutable inode can authorize them. Iterate synchronously within the DO;
  /// do not materialize potentially many deduplicated owners or cross an await.
  *readOwnersForObjectKey(objectKey: string, handle?: { owner: string; requiredMask?: number }, now = Date.now()): IterableIterator<string> {
    const rows = handle ? this.sql.exec(`
      SELECT b.item_id FROM blocks b JOIN items i ON i.id=b.item_id
        WHERE b.object_key=?1 AND (i.deleted=0 OR (i.deleted=1 AND EXISTS(
          SELECT 1 FROM open_handles h WHERE h.inode_id=i.id AND h.owner=?2 AND h.expires_at>?3 AND (h.access_mask & ?4)=?4)))
      UNION
      SELECT b.item_id FROM stream_blocks b JOIN items i ON i.id=b.item_id WHERE b.object_key=?1 AND (i.deleted=0 OR (i.deleted=1 AND EXISTS(
          SELECT 1 FROM open_handles h WHERE h.inode_id=i.id AND h.owner=?2 AND h.expires_at>?3 AND (h.access_mask & ?4)=?4)))
      UNION
      SELECT r.item_id FROM retained_blocks r JOIN items i ON i.id=r.item_id
        WHERE r.object_key=?1 AND (i.deleted=0 OR (i.deleted=1 AND EXISTS(
          SELECT 1 FROM open_handles h WHERE h.inode_id=i.id AND h.owner=?2 AND h.expires_at>?3 AND (h.access_mask & ?4)=?4)));`,
      objectKey, handle.owner, now, handle.requiredMask ?? 1) : this.sql.exec(`
      SELECT b.item_id FROM blocks b JOIN items i ON i.id=b.item_id WHERE b.object_key=?1 AND i.deleted=0
      UNION
      SELECT b.item_id FROM stream_blocks b JOIN items i ON i.id=b.item_id WHERE b.object_key=?1 AND i.deleted=0
      UNION
      SELECT r.item_id FROM retained_blocks r JOIN items i ON i.id=r.item_id WHERE r.object_key=?1 AND i.deleted=0;`, objectKey);
    for (const row of rows) yield String(row.item_id);
  }

  /// Ordered block map for the read path. Cheap, index-served.
  getBlockMap(itemId: string): Block[] {
    return this.sql
      .exec(`SELECT * FROM blocks WHERE item_id=? ORDER BY chunk_idx, block_idx;`, itemId)
      .toArray()
      .map((r) => ({
        chunkIdx: Number(r.chunk_idx),
        blockIdx: Number(r.block_idx),
        blockHash: String(r.block_hash),
        objectKey: String(r.object_key),
        offset: Number(r.offset),
        length: Number(r.length),
      }));
  }

  /// Bulk seed for tests/benchmarks — one transaction, no per-row awaits.
  /// FINDING A: clamp `count` to a sane ceiling so a hostile/oversized request can't
  /// wedge the single-threaded DO (resource exhaustion). A negative/NaN count creates 0.
  bulkCreate(parent: string, prefix: string, count: number, isDir = false, size = 1024): number {
    const n = Number.isFinite(count) ? Math.max(0, Math.min(Math.floor(count), BULK_SEED_MAX)) : 0;
    let created = 0;
    let changed = false;
    for (let i = 0; i < n; i++) {
      const seq = this.nextSeq();
      const name = `${prefix}${String(i).padStart(7, "0")}`;
      const id = `${parent}/${name}`;
      const inserted = this.sql.exec(
        `INSERT OR IGNORE INTO items
         (id,parent,name,is_dir,size,content_version,etag,version,created_seq,updated_seq,deleted)
         VALUES (?,?,?,?,?,?,?,1,?,?,0);`,
        id, parent, name, isDir ? 1 : 0, size, `cv-${size}-${seq}`, null, seq, seq,
      );
      changed ||= inserted.rowsWritten > 0;
      created++;
    }
    if (changed) this.touchDirectories([parent]);
    return created;
  }

  // ---- named streams / xattrs (v14) ------------------------------------------------

  /// List an item's named streams (name + byte size). Empty if none / no item.
  listStreams(itemId: string): StreamInfo[] {
    return this.sql
      .exec(`SELECT name, size FROM item_streams WHERE item_id=? AND storage_kind!='deleted' ORDER BY name;`, itemId)
      .toArray()
      .map((r) => ({ name: String(r.name), size: Number(r.size) }));
  }

  /// Read one stream's bytes, or null if absent.
  getStream(itemId: string, name: string): Uint8Array | null {
    const r = this.sql
      .exec(`SELECT data FROM item_streams WHERE item_id=? AND name=? AND storage_kind='inline';`, itemId, name)
      .toArray()[0];
    if (!r) return null;
    const d = r.data as unknown;
    return d instanceof ArrayBuffer ? new Uint8Array(d) : (d as Uint8Array);
  }

  /// Upsert a stream. `data` is stored verbatim (may be ciphertext); `size` is the
  /// LOGICAL (plaintext) byte length the mount reports — defaults to data length
  /// when not given (plaintext storage / tests). Bumps the owning item's
  /// updated_seq. Returns the stored logical size, or null if the item is gone.
  putStream(itemId: string, name: string, data: Uint8Array, plaintextSize?: number, allowRetained = false): { size: number } | null {
    this.admit(65_536 + data.byteLength * 2);
    const exists = this.sql.exec(`SELECT 1 FROM items i WHERE i.id=? AND (i.deleted=0 OR (i.deleted=1 AND ?=1 AND EXISTS(
      SELECT 1 FROM open_handles h WHERE h.inode_id=i.id AND h.expires_at>?
    )));`, itemId, allowRetained ? 1 : 0, Date.now()).toArray()[0];
    if (!exists) return null;
    const size = plaintextSize ?? data.byteLength;
    releaseStreamBlocks(this.sql,itemId,name);
    const seq = this.nextSeq();
    this.sql.exec(
      `INSERT INTO item_streams (item_id,name,size,data,updated_seq) VALUES (?,?,?,?,?)
       ON CONFLICT(item_id,name) DO UPDATE SET size=excluded.size, data=excluded.data, updated_seq=excluded.updated_seq, storage_kind='inline', version=item_streams.version+1,last_delta_digest=NULL;`,
      itemId, name, size, data, seq,
    );
    this.sql.exec(`UPDATE items SET updated_seq=? WHERE id=? AND deleted=0;`, seq, itemId);
    return { size };
  }

  /// Delete a stream. Returns whether a row was removed. Bumps updated_seq.
  deleteStream(itemId: string, name: string, allowRetained = false): boolean {
    const exists = this.sql.exec(`SELECT 1 FROM items i WHERE i.id=? AND (i.deleted=0 OR (i.deleted=1 AND ?=1 AND EXISTS(
      SELECT 1 FROM open_handles h WHERE h.inode_id=i.id AND h.expires_at>?
    )));`, itemId, allowRetained ? 1 : 0, Date.now()).toArray()[0];
    if (!exists) return false;
    const had = this.sql.exec(`SELECT 1 FROM item_streams WHERE item_id=? AND name=? AND storage_kind!='deleted';`, itemId, name).toArray()[0];
    if (!had) return false;
    const seq = this.nextSeq();
    releaseStreamBlocks(this.sql,itemId,name);
    this.sql.exec(`UPDATE item_streams SET storage_kind='deleted',size=0,data=X'',version=version+1,last_delta_digest=NULL,updated_seq=? WHERE item_id=? AND name=?;`,seq,itemId,name);
    this.sql.exec(`UPDATE items SET updated_seq=? WHERE id=? AND deleted=0;`, seq, itemId);
    return true;
  }

  /// Populate rsrcForkSize + finderInfo on items from their streams (AAPL readdir
  /// enrichment). One batched query over the given ids to avoid N+1.
  enrichStreams(items: Item[]): void {
    if (items.length === 0) return;
    const byId = new Map(items.map((it) => [it.id, it]));
    const ids = [...byId.keys()];
    // DO SQLite allows 100 bind parameters. json_each keeps a 2,000-item page at one
    // parameter/query, and projecting only FinderInfo avoids loading resource-fork blobs
    // into memory merely to report their size.
    const rows = this.sql
      .exec(`SELECT item_id, name, size,
               CASE WHEN name = 'AFP_AfpInfo' AND size=60 AND length(data)<=256 THEN data END AS finder_info
             FROM item_streams WHERE item_id IN (SELECT value FROM json_each(?))
             AND storage_kind!='deleted' AND name IN ('AFP_Resource','AFP_AfpInfo');`, JSON.stringify(ids))
      .toArray();
    for (const r of rows) {
      const it = byId.get(String(r.item_id));
      if (!it) continue;
      if (r.name === "AFP_Resource") it.rsrcForkSize = Number(r.size);
      else if (r.name === "AFP_AfpInfo") {
        // AFP_AfpInfo is encrypted with the inode/name identity. Never slice
        // its ciphertext into a fake FinderInfo; forward the bounded envelope.
        const raw = r.finder_info as unknown;
        const d = raw instanceof ArrayBuffer ? new Uint8Array(raw) : (raw as Uint8Array);
        if (d && d.byteLength <= 256) {
          it.finderInfoCiphertext = btoa(String.fromCharCode(...d));
        }
      }
    }
  }
}

// ---- cursor codec (opaque keyset cursor) -----------------------------------

function encodeCursor(isDir: number, name: string): string {
  return btoa(unescape(encodeURIComponent(JSON.stringify([isDir, name]))));
}

function decodeCursor(cursor: string): { isDir: number; name: string } {
  try {
    const [isDir, name] = JSON.parse(decodeURIComponent(escape(atob(cursor))));
    return { isDir: Number(isDir), name: String(name) };
  } catch {
    throw new Error("invalid cursor");
  }
}
