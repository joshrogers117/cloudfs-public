// SPDX-License-Identifier: AGPL-3.0-or-later
/// Snapshot metadata + GFS retention (SPEC §4.7).
///
/// A snapshot is a named, frozen pointer to the namespace at a `seq` anchor — it
/// copies NO media bytes (the architecture pays off: every edit writes a new
/// immutable, content-addressed block, so a snapshot pays ZERO media cost).
/// Finding #1 correction: creating a snapshot is NOT O(1) — it copies the MANIFEST
/// ROWS (O(items + blocks) rows, ≈24M block rows at 95 TB) so a later restore can
/// reconstruct old manifests. That copy is done with a single set-based
/// `INSERT ... SELECT` per table (server-side bulk insert), not N row-by-row JS
/// statements, so the manifest copy is one bulk operation rather than O(N) calls.
///
///   create()   → freeze the current seq under a scope + tier.
///   listAt()   → enumerate a directory AS-OF a snapshot (items whose
///                created_seq ≤ anchor and that were not deleted by the anchor).
///   schedules  → declarative, GFS-tiered, executed server-side by the DO alarm
///                (fire even with all clients offline).
///   prune()    → enforce "keep last N per tier"; blocks the retention worker
///                hands to snapshot-aware GC become collectable.
///
/// Immutability hardening: retained snapshots carry an
/// `immutable_until` date; GC + pruning run with a gateway-held credential a
/// client never possesses, so a stolen client key cannot purge history.

import { readStreamManifest, releaseStreamBlocks, decrementStreamReferences } from './stream-manifest';
import type { Block, Item, Snapshot } from "./types";
import type { NamespaceStore } from "./namespace";

export interface ScheduleSpec {
  id: string;
  scope?: string;
  tier: string;
  intervalMs: number;
  retain: number;
}

export function isValidScheduleSpec(value: unknown): value is ScheduleSpec {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const spec = value as Record<string, unknown>;
  const label = (v: unknown) => typeof v === "string" && v.trim().length > 0 && v.length <= 256;
  return label(spec.id) && label(spec.tier) && (spec.scope === undefined || label(spec.scope))
    && typeof spec.intervalMs === "number" && Number.isSafeInteger(spec.intervalMs) && spec.intervalMs > 0
    && Number.isSafeInteger(Date.now() + spec.intervalMs)
    && typeof spec.retain === "number" && Number.isSafeInteger(spec.retain) && spec.retain >= 0 && spec.retain <= 10_000;
}

/// What a restore did (or would do). Returned to the caller for audit/UX.
/// `notFound` is a typed signal (unknown snapshot / path not in snapshot) — we
/// return it rather than throw, because thrown Errors don't cross the DO RPC
/// boundary cleanly (they surface as unhandled rejections in workerd).
export interface RestoreResult {
  snapshotId: string;
  /// set when the snapshot id is unknown or the path isn't frozen in it.
  notFound?: string;
  /// inode ids whose content/metadata were restored to the as-of state.
  restored: string[];
  /// inode ids re-created because they had been deleted since the snapshot.
  recreated: string[];
  /// inode ids skipped because the target was exclusively locked by another holder.
  conflicts: { id: string; heldBy: string }[];
  /// inodes present now but absent in the snapshot are NOT deleted (non-destructive);
  /// recorded here so the caller can surface "N items exist now that didn't then".
  newerThanSnapshot: string[];
  forbidden?: string[];
  skippedPermissions?: number;
  streamsCaptured?: boolean;
}

export class SnapshotStore {
  constructor(
    private readonly sql: SqlStorage,
    private readonly currentSeq: () => number,
    /// Optional: the namespace store, so restore re-applies through the canonical
    /// write path (new current versions, refcounts, change feed). Injected lazily
    /// to avoid a constructor cycle; restore() throws if it wasn't provided.
    private readonly ns?: NamespaceStore,
    private readonly admit: (bytes?: number) => void = () => {},
  ) {}

  create(opts: { id: string; label?: string; scope?: string; tier?: string; immutableUntil?: number | null; scheduleId?: string | null }): Snapshot {
    this.admit();
    const now = Date.now();
    const scope = opts.scope ?? "root";
    const snap: Snapshot = {
      id: opts.id,
      label: opts.label ?? null,
      scope,
      seqAnchor: this.currentSeq(),
      tier: opts.tier ?? "manual",
      createdAt: now,
      immutableUntil: opts.immutableUntil ?? null,
      scheduleId: opts.scheduleId ?? null,
    };
    // Audit B19: this snapshot's BASE is the most recent EXISTING snapshot of the SAME scope (the
    // chain it deltas against). A re-freeze of the same id keeps the same base; the first snapshot
    // of a scope has no base (full freeze). We exclude `opts.id` itself so a re-create doesn't base
    // on its own (about-to-be-replaced) frozen rows.
    const baseRow = this.sql
      .exec(`SELECT id FROM snapshots WHERE scope=? AND id<>? AND streams_captured=1 AND basic_info_captured=1 ORDER BY seq_anchor DESC, created_at DESC LIMIT 1;`, scope, snap.id)
      .toArray()[0];
    const baseSnapshotId = baseRow ? String(baseRow.id) : null;
    this.sql.exec(
      `INSERT OR REPLACE INTO snapshots
       (id,label,scope,seq_anchor,tier,created_at,immutable_until,schedule_id,base_snapshot_id,streams_captured,basic_info_captured)
       VALUES (?,?,?,?,?,?,?,?,?,1,1);`,
      snap.id, snap.label, snap.scope, snap.seqAnchor, snap.tier, snap.createdAt,
      snap.immutableUntil, snap.scheduleId, baseSnapshotId,
    );
    // Freeze only the DELTA vs. the base (audit B19) — items changed/created/deleted since the
    // base snapshot's anchor; the rest is inherited by chain resolution at read time.
    this.freeze(snap.id, snap.scope, baseSnapshotId);
    this.admit(0);
    return snap;
  }

  /// Copy every LIVE item under `scope` (the subtree root, or all if "root") and
  /// its block manifest into the snapshot_* tables. Pointers only — no media bytes.
  ///
  /// Finding I1: a snapshot's frozen manifest must hold its OWN block_refs. The old
  /// code relied on the LIVE file's ref keeping the block alive — but that ref is
  /// dropped when the file is overwritten/deleted (setBlockMap old-ref drop, remove,
  /// removeSubtree), at which point refcount hits 0 and `collectableBlocks()` would
  /// hand the snapshot's still-referenced object to GC → DATA LOSS. So freeze()
  /// increments block_refs.refcount by +N for each distinct hash that appears N
  /// times in THIS snapshot's frozen manifest (seeding a row if the hash had no live
  /// ref). prune()/deleteSnapshot decrements the same way. The same hash can live in
  /// multiple snapshots — each freeze adds its own refs independently.
  /// Re-freezing the same snapshot id is idempotent: we DELETE the prior frozen rows
  /// (and decrement the refs they held) before re-copying, so a re-freeze nets zero
  /// double-counting.
  ///
  /// COST (finding #1): this copies the MANIFEST ROWS — O(items + blocks) ROWS, but
  /// ZERO media bytes. It is NOT O(1): a root snapshot copies one row per live inode
  /// plus one per block (≈24M block rows at 95 TB). To keep that off the JS hot path,
  /// the copy is done as a single set-based `INSERT ... SELECT` per table (one SQL
  /// statement each, evaluated server-side inside the coalesced DO transaction)
  /// instead of N per-row JS round-trips. A recursive CTE re-derives the same live
  /// subtree id set the old BFS walked (scope itself if live, plus all live
  /// descendants of directories), so the rows copied / columns / id-scoping are identical.
  /// Audit B19 — freeze only the DELTA vs. `baseSnapshotId` (the prior snapshot of the same
  /// scope), so a snapshot stores O(changed items) rows instead of O(all live items). The rest is
  /// inherited by chain resolution (`effectiveFrozenItems`). The delta is:
  ///   • items in the live subtree whose `updated_seq > base.seq_anchor` (changed/created since
  ///     base) — copied as live rows (deleted=0);
  ///   • items the base's RESOLVED set had but are now gone (tombstoned/moved out of the subtree)
  ///     — recorded as delta-TOMBSTONES (deleted=1) so resolution knows they're absent as-of this
  ///     snapshot.
  /// With no base (the first snapshot of a scope) this freezes the FULL live subtree (deleted=0),
  /// exactly like the pre-B19 behavior.
  private freeze(snapshotId: string, scope: string, baseSnapshotId: string | null): void {
    // Finding I1 + re-freeze: release the block_refs THIS snapshot's frozen manifest held and drop
    // its prior delta rows, so a re-create of the same id nets zero double-counting.
    this.releaseSnapshotBlockRefs(snapshotId);
    this.sql.exec(`DELETE FROM snapshot_items WHERE snapshot_id=?;`, snapshotId);
    this.sql.exec(`DELETE FROM snapshot_blocks WHERE snapshot_id=?;`, snapshotId);
    this.sql.exec(`DELETE FROM snapshot_streams WHERE snapshot_id=?;`, snapshotId);
    this.sql.exec(`DELETE FROM snapshot_stream_blocks WHERE snapshot_id=?;`, snapshotId);

    const baseAnchor = baseSnapshotId
      ? Number(this.sql.exec(`SELECT seq_anchor FROM snapshots WHERE id=?;`, baseSnapshotId).one().seq_anchor)
      : -1; // -1 ⇒ every item is "newer", i.e. a full freeze for the first snapshot.

    // Live subtree ids (scope + live descendants) as a reusable recursive CTE.
    const subtreeCte = `WITH RECURSIVE subtree(id, is_dir) AS (
        SELECT id, is_dir FROM items WHERE id=?1 AND deleted=0
        UNION ALL
        SELECT i.id, i.is_dir FROM items i
          JOIN subtree s ON i.parent = s.id
          WHERE i.deleted=0 AND s.is_dir=1
      )`;

    // 1. Copy the CHANGED/new items (updated_seq > base anchor) as live frozen rows.
    this.sql.exec(
      `${subtreeCte}
       INSERT OR REPLACE INTO snapshot_items
         (snapshot_id,item_id,parent,name,is_dir,size,content_version,etag,deleted,created_at,modified_at,accessed_at,changed_at,file_attributes)
       SELECT ?2, i.id, i.parent, i.name, i.is_dir, i.size, i.content_version, i.etag, 0,i.created_at,i.modified_at,i.accessed_at,i.changed_at,i.file_attributes
       FROM items i JOIN subtree s ON i.id = s.id
       WHERE i.updated_seq > ?3;`,
      scope, snapshotId, baseAnchor,
    );

    // 2. Copy block manifests for exactly the items we just froze (their content changed too).
    this.sql.exec(
      `INSERT OR REPLACE INTO snapshot_blocks
         (snapshot_id,item_id,chunk_idx,block_idx,block_hash,object_key,offset,length)
       SELECT ?1, b.item_id, b.chunk_idx, b.block_idx, b.block_hash, b.object_key, b.offset, b.length
       FROM blocks b
       WHERE b.item_id IN (SELECT item_id FROM snapshot_items WHERE snapshot_id=?1 AND deleted=0);`,
      snapshotId,
    );

    this.sql.exec(`INSERT INTO snapshot_streams(snapshot_id,item_id,name,size,data,storage_kind,version)
      SELECT ?1,s.item_id,s.name,s.size,s.data,s.storage_kind,s.version FROM item_streams s
      JOIN snapshot_items i ON i.snapshot_id=?1 AND i.item_id=s.item_id AND i.deleted=0;`, snapshotId);

    this.sql.exec(`INSERT INTO snapshot_stream_blocks(snapshot_id,item_id,name,block_idx,block_hash,object_key,length)
      SELECT ?1,b.item_id,b.name,b.block_idx,b.block_hash,b.object_key,b.length FROM stream_blocks b
      JOIN snapshot_items i ON i.snapshot_id=?1 AND i.item_id=b.item_id AND i.deleted=0;`,snapshotId);
    this.sql.exec(`INSERT INTO block_refs(block_hash,object_key,refcount) SELECT block_hash,MIN(object_key),COUNT(*) FROM snapshot_stream_blocks
      WHERE snapshot_id=? GROUP BY block_hash ON CONFLICT(block_hash) DO UPDATE SET refcount=refcount+excluded.refcount;`,snapshotId);

    // 3. Delta-tombstones: items the BASE's resolved set had, but that are no longer LIVE under the
    //    scope now (deleted, or moved out). Record deleted=1 so resolution skips them as-of here.
    if (baseSnapshotId) {
      // Resolve the base in SQL: scheduled snapshots must not materialize the
      // entire filespace and then issue one insert per removed inode in JS.
      this.sql.exec(`${subtreeCte}, ancestry AS (
          SELECT value AS snapshot_id, CAST(key AS INTEGER) AS depth FROM json_each(?3)
        ), ranked AS (
          SELECT si.*, ROW_NUMBER() OVER (PARTITION BY item_id ORDER BY a.depth) AS rank
          FROM snapshot_items si JOIN ancestry a USING(snapshot_id)
        ) INSERT OR REPLACE INTO snapshot_items
          (snapshot_id,item_id,parent,name,is_dir,size,content_version,etag,deleted)
        SELECT ?2,item_id,parent,name,is_dir,size,content_version,etag,1 FROM ranked
        WHERE rank=1 AND deleted=0 AND NOT EXISTS (SELECT 1 FROM subtree WHERE subtree.id=ranked.item_id);`,
        scope, snapshotId, JSON.stringify(this.lineage(baseSnapshotId)));
    }

    // Finding I1: the snapshot holds its OWN block_refs for the (delta) blocks it froze. Bump
    // refcount by +N per distinct hash appearing N times in THIS snapshot's frozen manifest.
    this.sql.exec(
      `INSERT INTO block_refs (block_hash, object_key, refcount)
       SELECT block_hash, MIN(object_key), COUNT(*)
         FROM snapshot_blocks WHERE snapshot_id=?
        GROUP BY block_hash
       ON CONFLICT(block_hash) DO UPDATE SET refcount = refcount + excluded.refcount;`,
      snapshotId,
    );
  }

  /// Audit B19 — the snapshot lineage (newest-first): [S, base(S), base(base(S)), ...]. The chain
  /// is the same-scope `base_snapshot_id` links. Bounded (a GFS schedule keeps O(retain) snapshots).
  private lineage(snapshotId: string): string[] {
    const out: string[] = [];
    let cur: string | null = snapshotId;
    let guard = 0;
    const seen = new Set<string>();
    while (cur !== null && guard++ < 100_000 && !seen.has(cur)) {
      seen.add(cur);
      out.push(cur);
      const r: Record<string, SqlStorageValue> | undefined =
        this.sql.exec(`SELECT base_snapshot_id FROM snapshots WHERE id=?;`, cur).toArray()[0];
      cur = r && r.base_snapshot_id !== null ? String(r.base_snapshot_id) : null;
    }
    return out;
  }

  /// Resolve the EFFECTIVE frozen item set of a snapshot by walking its lineage newest-first: the
  /// first lineage snapshot that froze an item wins; a delta-tombstone (deleted=1) means the item
  /// is ABSENT as-of this snapshot. Returns id → resolved Item (live rows only). This reproduces
  /// EXACTLY what the pre-B19 full-copy freeze would have stored for the snapshot.
  private effectiveFrozenItems(snapshotId: string): Map<string, Item> {
    const out = new Map<string, Item>();
    const tombstoned = new Set<string>();
    for (const sid of this.lineage(snapshotId)) {
      const rows = this.sql.exec(`SELECT * FROM snapshot_items WHERE snapshot_id=?;`, sid).toArray();
      for (const r of rows) {
        const id = String(r.item_id);
        if (out.has(id) || tombstoned.has(id)) continue; // a newer lineage snapshot already decided it
        if (Number(r.deleted) === 1) { tombstoned.add(id); continue; }
        out.set(id, {
          id,
          parent: r.parent === null ? null : String(r.parent),
          name: String(r.name),
          isDir: Number(r.is_dir) === 1,
          size: Number(r.size),
          contentVersion: String(r.content_version),
          etag: r.etag === null ? null : String(r.etag),
          version: 0,
          updatedSeq: 0,
          deleted: false,
          createdAt: r.created_at == null ? null : Number(r.created_at),
          modifiedAt: r.modified_at == null ? null : Number(r.modified_at),
          accessedAt: r.accessed_at == null ? null : Number(r.accessed_at),
          changedAt: r.changed_at == null ? null : Number(r.changed_at),
          fileAttributes: Number(r.file_attributes ?? 0),
        });
      }
    }
    return out;
  }

  /// The lineage snapshot id whose frozen rows are EFFECTIVE for `itemId` as-of `snapshotId`
  /// (newest-first; the first that froze it), or null if the item is absent (never frozen, or
  /// delta-tombstoned) in the lineage. Used to resolve an item's frozen blocks from the right snap.
  private resolveFrozenSnapshotId(snapshotId: string, itemId: string): string | null {
    for (const sid of this.lineage(snapshotId)) {
      const r: Record<string, SqlStorageValue> | undefined =
        this.sql.exec(`SELECT deleted FROM snapshot_items WHERE snapshot_id=? AND item_id=?;`, sid, itemId).toArray()[0];
      if (!r) continue;
      return Number(r.deleted) === 1 ? null : sid; // tombstone ⇒ absent
    }
    return null;
  }

  /// Finding I1/I2: release the block_refs a snapshot's frozen manifest holds —
  /// decrement each referenced hash by the number of times it appears in THIS
  /// snapshot's snapshot_blocks (correct even when a hash is frozen multiple times
  /// within one snapshot). Mirrors the set-based decrement in
  /// namespace.ts:removeSubtree. Callers DELETE the frozen rows afterwards.
  private releaseSnapshotBlockRefs(snapshotId: string): void {
    decrementStreamReferences(this.sql,'SELECT block_hash FROM snapshot_stream_blocks WHERE snapshot_id=?',[snapshotId]);

    this.sql.exec(
      `UPDATE block_refs
         SET refcount = refcount - (
           SELECT COUNT(*) FROM snapshot_blocks sb
             WHERE sb.snapshot_id = ?1 AND sb.block_hash = block_refs.block_hash
         )
       WHERE block_hash IN (
         SELECT block_hash FROM snapshot_blocks WHERE snapshot_id = ?1
       );`,
      snapshotId,
    );
  }

  /// Finding #3: live inode ids in the subtree rooted at `path` (inclusive) that are NOT in the
  /// snapshot's EFFECTIVE frozen set — i.e. work created/moved-in since the snapshot. Audit B19:
  /// the frozen set is the lineage-resolved set (`effectiveFrozenItems`), so this still reports
  /// exactly the items the pre-delta full-copy would have flagged as newer.
  private liveSubtreeIdsNotFrozen(path: string, snapshotId: string): string[] {
    const frozen = this.effectiveFrozenItems(snapshotId);
    const live = this.sql
      .exec(
        `WITH RECURSIVE live(id, is_dir) AS (
             SELECT id, is_dir FROM items WHERE id=?1 AND deleted=0
             UNION ALL
             SELECT i.id, i.is_dir FROM items i
               JOIN live l ON i.parent = l.id
               WHERE i.deleted=0 AND l.is_dir=1
           )
         SELECT id FROM live;`,
        path,
      )
      .toArray()
      .map((r) => String(r.id));
    return live.filter((id) => !frozen.has(id));
  }

  private rowToSnap(r: Record<string, SqlStorageValue>): Snapshot {
    return {
      id: String(r.id),
      label: r.label === null ? null : String(r.label),
      scope: String(r.scope),
      seqAnchor: Number(r.seq_anchor),
      tier: String(r.tier),
      createdAt: Number(r.created_at),
      immutableUntil: r.immutable_until === null ? null : Number(r.immutable_until),
      scheduleId: r.schedule_id === null ? null : String(r.schedule_id),
    };
  }

  get(id: string): Snapshot | null {
    const r = this.sql.exec(`SELECT * FROM snapshots WHERE id=?;`, id).toArray()[0];
    return r ? this.rowToSnap(r as any) : null;
  }

  list(): Snapshot[] {
    return this.sql
      .exec(`SELECT * FROM snapshots ORDER BY created_at DESC;`)
      .toArray()
      .map((r) => this.rowToSnap(r as any));
  }

  /// Enumerate a directory AS-OF a snapshot, served from the FROZEN point-in-time
  /// content (snapshot_items) — so it reflects exactly what was live at create
  /// time, including the as-of size/content_version (not the current edited row).
  listAt(snapshotId: string, parent: string): Item[] {
    const items: Item[] = [];
    let cursor: string | undefined;
    do {
      const page = this.listPageAt(snapshotId, parent, cursor);
      items.push(...page.items);
      cursor = page.cursor ?? undefined;
    } while (cursor);
    return items.sort((a, b) => a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1);
  }

  /** Resolve only one directory's candidate IDs, not the entire frozen tree.
   * Newer moved-away rows/tombstones win over older rows under this parent. */
  listPageAt(snapshotId: string, parent: string, cursor?: string, limit = 256): { items: Item[]; cursor: string | null } {
    const snap = this.get(snapshotId);
    if (!snap) throw new Error(`no such snapshot: ${snapshotId}`);
    const rows = this.sql.exec(`WITH ancestry AS (
        SELECT value AS snapshot_id, CAST(key AS INTEGER) AS depth FROM json_each(?1)
      ), candidates AS (
        SELECT DISTINCT si.item_id FROM snapshot_items si JOIN ancestry a USING(snapshot_id)
        WHERE si.parent=?2 AND si.item_id>?3
      ), ranked AS (
        SELECT si.*, ROW_NUMBER() OVER (PARTITION BY si.item_id ORDER BY a.depth) AS rank
        FROM snapshot_items si JOIN ancestry a USING(snapshot_id) JOIN candidates c USING(item_id)
      ) SELECT * FROM ranked WHERE rank=1 AND deleted=0 AND parent=?2 ORDER BY item_id LIMIT ?4;`,
      JSON.stringify(this.lineage(snapshotId)), parent, cursor ?? "", limit + 1).toArray();
    const hasMore = rows.length > limit;
    const visible = rows.slice(0, limit);
    return { items: visible.map(row => this.snapshotItem(row, snap.seqAnchor)),
      cursor: hasMore ? String(visible[visible.length - 1].item_id) : null };
  }

  itemAt(snapshotId: string, itemId: string): Item | null {
    const snap = this.get(snapshotId);
    if (!snap) return null;
    const row = this.frozenItem(snapshotId, itemId);
    return row ? this.snapshotItem(row, snap.seqAnchor) : null;
  }

  blocksPageAt(snapshotId: string, itemId: string, afterOffset = -1, limit = 512): { blocks: Block[]; cursor: number | null } {
    const sid = this.resolveFrozenSnapshotId(snapshotId, itemId);
    if (!sid) return { blocks: [], cursor: null };
    const rows = this.sql.exec(`SELECT * FROM snapshot_blocks WHERE snapshot_id=? AND item_id=? AND offset>?
      ORDER BY offset LIMIT ?;`, sid, itemId, afterOffset, limit + 1).toArray();
    const page = rows.slice(0, limit).map(b => ({ chunkIdx: Number(b.chunk_idx), blockIdx: Number(b.block_idx),
      blockHash: String(b.block_hash), objectKey: String(b.object_key), offset: Number(b.offset), length: Number(b.length) }));
    return { blocks: page, cursor: rows.length > limit ? page[page.length - 1].offset : null };
  }

  streamsCaptured(snapshotId: string): boolean {
    return Number(this.sql.exec(`SELECT streams_captured FROM snapshots WHERE id=?;`, snapshotId).toArray()[0]?.streams_captured) === 1;
  }
  streamsAt(snapshotId: string, itemId: string): { name: string; size: number }[] {
    const sid = this.resolveFrozenSnapshotId(snapshotId, itemId);
    if (!sid) return [];
    return this.sql.exec(`SELECT name,size FROM snapshot_streams WHERE snapshot_id=? AND item_id=? AND storage_kind!='deleted' ORDER BY name;`, sid, itemId)
      .toArray().map(row => ({ name: String(row.name), size: Number(row.size) }));
  }
  streamAt(snapshotId: string, itemId: string, name: string): Uint8Array | null {
    const sid = this.resolveFrozenSnapshotId(snapshotId, itemId);
    if (!sid) return null;
    const row = this.sql.exec(`SELECT data FROM snapshot_streams WHERE snapshot_id=? AND item_id=? AND name=? AND storage_kind='inline';`, sid, itemId, name).toArray()[0];
    if (!row) return null;
    return row.data instanceof ArrayBuffer ? new Uint8Array(row.data) : row.data as unknown as Uint8Array;
  }

  streamManifestAt(snapshotId:string,itemId:string,name:string,offset=0,length=16*1024*1024) {
    const sid=this.resolveFrozenSnapshotId(snapshotId,itemId);
    return sid ? readStreamManifest(this.sql,itemId,name,offset,length,sid) : null;
  }

  ownsObjectAt(snapshotId: string, itemId: string, key: string): boolean {
    const sid = this.resolveFrozenSnapshotId(snapshotId, itemId);
    return sid !== null && this.sql.exec(`SELECT 1 FROM snapshot_blocks
      WHERE snapshot_id=?1 AND item_id=?2 AND object_key=?3 UNION SELECT 1 FROM snapshot_stream_blocks WHERE snapshot_id=?1 AND item_id=?2 AND object_key=?3 LIMIT 1;`, sid, itemId, key).toArray().length > 0;
  }

  private snapshotItem(row: Record<string, SqlStorageValue>, anchor: number): Item {
    const fork = this.sql.exec(`SELECT size FROM snapshot_streams WHERE snapshot_id=? AND item_id=? AND name='AFP_Resource' AND storage_kind!='deleted';`,
      String(row.snapshot_id), String(row.item_id)).toArray()[0];
    const finder = this.sql.exec(`SELECT data FROM snapshot_streams WHERE snapshot_id=? AND item_id=? AND name='AFP_AfpInfo' AND size=60 AND length(data)<=256;`,
      String(row.snapshot_id), String(row.item_id)).toArray()[0]?.data;
    const finderBytes = finder instanceof ArrayBuffer ? new Uint8Array(finder) : finder as unknown as Uint8Array | undefined;
    return { id: String(row.item_id), parent: row.parent === null ? null : String(row.parent),
      name: String(row.name), isDir: Number(row.is_dir) === 1, size: Number(row.size),
      contentVersion: String(row.content_version), etag: row.etag === null ? null : String(row.etag),
      version: 0, updatedSeq: anchor, deleted: false, createdAt: row.created_at == null ? null : Number(row.created_at),
      modifiedAt: row.modified_at == null ? null : Number(row.modified_at), accessedAt: row.accessed_at == null ? null : Number(row.accessed_at),
      changedAt: row.changed_at == null ? null : Number(row.changed_at), fileAttributes: Number(row.file_attributes ?? 0), rsrcForkSize: fork ? Number(fork.size) : 0, finderInfoCiphertext: finderBytes ? btoa(String.fromCharCode(...finderBytes)) : null };
  }

  // ---- restore (SPEC §4.7 self-service restore) -----------------------------

  /// Audit B19: resolve through the lineage — the item's row from the newest lineage snapshot that
  /// froze it (skipping delta-tombstones). Returns undefined if absent as-of the snapshot.
  private frozenItem(snapshotId: string, itemId: string): Record<string, SqlStorageValue> | undefined {
    const sid = this.resolveFrozenSnapshotId(snapshotId, itemId);
    if (sid === null) return undefined;
    return this.sql
      .exec(`SELECT * FROM snapshot_items WHERE snapshot_id=? AND item_id=?;`, sid, itemId)
      .toArray()[0];
  }

  private frozenBlocks(snapshotId: string, itemId: string): Block[] {
    // The blocks live with the item's effective frozen row (same lineage snapshot).
    const sid = this.resolveFrozenSnapshotId(snapshotId, itemId);
    if (sid === null) return [];
    return this.sql
      .exec(
        `SELECT * FROM snapshot_blocks WHERE snapshot_id=? AND item_id=? ORDER BY chunk_idx,block_idx;`,
        sid, itemId,
      )
      .toArray()
      .map((b) => ({
        chunkIdx: Number(b.chunk_idx),
        blockIdx: Number(b.block_idx),
        blockHash: String(b.block_hash),
        objectKey: String(b.object_key),
        offset: Number(b.offset),
        length: Number(b.length),
      }));
  }

  /// Frozen rows under `path` in this snapshot (the subtree to restore), BFS order
  /// (parent before child). Finding #3: returns the FULL frozen rows it already
  /// SELECTs — the restore loop consumes them directly instead of re-fetching each
  /// via frozenItem() (which was an N+1 against snapshot_items).
  private frozenSubtreeRows(
    snapshotId: string,
    path: string,
    recursive: boolean,
  ): Record<string, SqlStorageValue>[] {
    // Audit B19: resolve the lineage to the effective frozen set, then BFS over it by parent
    // (parent before child) so the restore loop recreates a child only after its parent is live.
    const resolved = this.effectiveFrozenItems(snapshotId);
    const toRow = (it: Item): Record<string, SqlStorageValue> => ({
      item_id: it.id, parent: it.parent, name: it.name, is_dir: it.isDir ? 1 : 0,
      size: it.size, content_version: it.contentVersion, etag: it.etag,
      created_at: it.createdAt, modified_at: it.modifiedAt, accessed_at: it.accessedAt ?? null, changed_at: it.changedAt ?? null, file_attributes: it.fileAttributes ?? 0,
    });
    const self = resolved.get(path);
    if (!self) return [];
    const out: Record<string, SqlStorageValue>[] = [toRow(self)];
    if (!recursive) return out;
    // Index children by parent for the BFS.
    const byParent = new Map<string, Item[]>();
    for (const it of resolved.values()) {
      if (it.parent === null) continue;
      const arr = byParent.get(it.parent) ?? [];
      arr.push(it);
      byParent.set(it.parent, arr);
    }
    const queue = [path];
    let guard = 0;
    while (queue.length && guard++ < 1_000_000) {
      const parent = queue.shift()!;
      for (const k of byParent.get(parent) ?? []) {
        out.push(toRow(k));
        if (k.isDir) queue.push(k.id);
      }
    }
    return out;
  }

  /// Restore `path` (file or, with `recursive`, a whole subtree) to its state
  /// AS OF the snapshot. NON-DESTRUCTIVE: every restored item is written through
  /// the canonical namespace write path, creating a NEW current version (bumped
  /// version + new updated_seq → appears in the change feed). Prior/current state
  /// stays in history (other snapshots + the change feed); nothing is silently
  /// lost. Items that exist now but not in the snapshot are NOT deleted.
  ///
  /// `isLockedByOther(itemId) -> heldBy|null` lets the caller refuse a target that
  /// is exclusively leased by someone else (conflict, surfaced not thrown).
  /// Idempotent in effect: restoring twice yields the same content (new versions).
  restore(
    snapshotId: string,
    path: string,
    opts: { recursive?: boolean; isLockedByOther?: (itemId: string) => string | null;
      canRestore?: (itemId: string, parent: string | null) => boolean;
      beforeRecreate?: (itemId: string) => void } = {},
  ): RestoreResult {
    if (!this.ns) throw new Error("restore requires a NamespaceStore");
    const res: RestoreResult = {
      snapshotId, restored: [], recreated: [], conflicts: [], newerThanSnapshot: [],
    };
    const snap = this.get(snapshotId);
    if (!snap) return { ...res, notFound: `no such snapshot: ${snapshotId}` };
    if (!this.streamsCaptured(snapshotId)) res.streamsCaptured = false;
    const frozen = this.frozenItem(snapshotId, path);
    if (!frozen) return { ...res, notFound: `path not present in snapshot: ${path}` };

    const recursive = !!opts.recursive;
    // Finding #3: full frozen rows (no per-id re-fetch in the loop below).
    const rows = this.frozenSubtreeRows(snapshotId, path, recursive);
    // Decide before restoring any parent: changing an ancestor must not make a
    // previously private descendant appear writable later in this same restore.
    const allowed = new Set(rows.filter(row => !opts.canRestore || opts.canRestore(String(row.item_id),
      row.parent === null ? null : String(row.parent))).map(row => String(row.item_id)));

    // Restore parents before children so a recreated child has a live parent.
    // frozenSubtreeRows is already BFS (parent before child); keep that order.
    for (const fi of rows) {
      const id = String(fi.item_id);
      if (!allowed.has(id)) { (res.forbidden ??= []).push(id); continue; }
      // Refuse a target exclusively locked by someone else (surface, don't throw).
      const heldBy = opts.isLockedByOther?.(id) ?? null;
      if (heldBy) {
        res.conflicts.push({ id, heldBy });
        continue;
      }
      const live = this.ns.getItem(id);
      const wasDeleted = !live || live.deleted;
      const parent = fi.parent === null ? null : String(fi.parent);
      const name = String(fi.name);
      const etag = fi.etag === null ? null : String(fi.etag);
      if (wasDeleted) opts.beforeRecreate?.(id);

      if (Number(fi.is_dir) === 0) {
        // Finding #2: restore the file's metadata AND block manifest in a SINGLE
        // write — exactly one version bump / one change-feed entry per file (was a
        // put() + setBlockMap() pair that double-bumped and emitted twice).
        const blocks = this.frozenBlocks(snapshotId, id);
        this.ns.setBlockMap(id, blocks, { etag, upsert: { parent, name } });
      } else {
        // Directories carry no block map: one put() is already a single write.
        this.ns.put(parent, name, true, Number(fi.size), { id, etag });
      }

      // File times reproduce the snapshot. A live directory's mtime must instead
      // advance: smbfs uses that signal to invalidate cached missing children.
      // Restoring an older directory timestamp would hide restored names until a
      // separate enumeration, especially if its previous time was in the future.
      const directoryTime = Number(fi.is_dir) === 1
        ? Math.max(Date.now(), (live?.modifiedAt ?? 0) + 1, (live?.changedAt ?? 0) + 1, Number(fi.modified_at ?? 0))
        : null;
      // Retain the canonical restore's single version/sequence bump for this inode.
      this.sql.exec('UPDATE items SET created_at=COALESCE(?,created_at),modified_at=COALESCE(?,modified_at),accessed_at=?,changed_at=?,file_attributes=? WHERE id=?;',
        fi.created_at ?? null,directoryTime ?? fi.modified_at ?? null,fi.accessed_at ?? null,directoryTime ?? fi.changed_at ?? null,fi.file_attributes ?? 0,id);
      if (this.streamsCaptured(snapshotId)) {
        const streamSource = this.resolveFrozenSnapshotId(snapshotId, id)!;
        releaseStreamBlocks(this.sql,id);
        this.sql.exec(`UPDATE item_streams SET storage_kind='deleted',data=X'',size=0,version=version+1,last_delta_digest=NULL WHERE item_id=?;`,id);
        this.sql.exec(`INSERT INTO item_streams(item_id,name,size,data,updated_seq,storage_kind,version)
          SELECT s.item_id,s.name,s.size,s.data,i.updated_seq,s.storage_kind,s.version+1 FROM snapshot_streams s JOIN items i ON i.id=s.item_id
          WHERE s.snapshot_id=? AND s.item_id=? ON CONFLICT(item_id,name) DO UPDATE SET size=excluded.size,data=excluded.data,
          updated_seq=excluded.updated_seq,storage_kind=excluded.storage_kind,version=MAX(item_streams.version,excluded.version),last_delta_digest=NULL;`,streamSource,id);
        this.sql.exec(`INSERT INTO stream_blocks(item_id,name,block_idx,block_hash,object_key,length)
          SELECT item_id,name,block_idx,block_hash,object_key,length FROM snapshot_stream_blocks WHERE snapshot_id=? AND item_id=?;`,streamSource,id);
        this.sql.exec(`INSERT INTO block_refs(block_hash,object_key,refcount) SELECT block_hash,MIN(object_key),COUNT(*) FROM stream_blocks
          WHERE item_id=? GROUP BY block_hash ON CONFLICT(block_hash) DO UPDATE SET refcount=refcount+excluded.refcount;`,id);
      }
      if (wasDeleted) res.recreated.push(id);
      else res.restored.push(id);
    }

    // Report (don't delete) live children under the restored folder that didn't
    // exist in the snapshot — non-destructive: the user keeps newer work.
    // Finding #3: ONE set-based query (live subtree ids NOT IN the frozen set)
    // instead of a second full BFS over the live namespace.
    if (recursive && Number(frozen.is_dir) === 1) {
      res.newerThanSnapshot = this.liveSubtreeIdsNotFrozen(path, snapshotId);
    }
    return res;
  }

  // ---- schedules + GFS retention -------------------------------------------

  setSchedule(spec: ScheduleSpec): void {
    if (!isValidScheduleSpec(spec)) throw new Error("invalid snapshot schedule");
    const now = Date.now();
    this.sql.exec(
      `INSERT INTO snapshot_schedules (id,scope,tier,interval_ms,retain,enabled,next_run_at,last_run_at)
       VALUES (?,?,?,?,?,1,?,NULL)
       ON CONFLICT(id) DO UPDATE SET scope=excluded.scope, tier=excluded.tier,
         interval_ms=excluded.interval_ms, retain=excluded.retain, enabled=1,
         next_run_at=excluded.next_run_at;`,
      spec.id, spec.scope ?? "root", spec.tier, spec.intervalMs, spec.retain, now + spec.intervalMs,
    );
  }

  /// Default GFS schedules for a NEW filespace: daily snapshots kept 7, weekly kept 4. INSERT OR
  /// IGNORE, so it never overwrites an admin's edits and is safe to call twice.
  ensureDefaultSchedules(): void {
    const now = Date.now();
    const defaults = [
      { id: "default-daily", tier: "daily", intervalMs: 24 * 3600_000, retain: 7 },
      { id: "default-weekly", tier: "weekly", intervalMs: 7 * 24 * 3600_000, retain: 4 },
    ];
    for (const d of defaults) {
      this.sql.exec(
        `INSERT OR IGNORE INTO snapshot_schedules (id,scope,tier,interval_ms,retain,enabled,next_run_at,last_run_at)
         VALUES (?,?,?,?,?,1,?,NULL);`,
        d.id, "root", d.tier, d.intervalMs, d.retain, now + d.intervalMs,
      );
    }
  }

  listSchedules(): Array<{ id: string; scope: string; tier: string; intervalMs: number; retain: number; enabled: boolean; nextRunAt: number; lastRunAt: number | null }> {
    return this.sql.exec(`SELECT * FROM snapshot_schedules ORDER BY interval_ms, id;`).toArray().map((r) => ({
      id: String(r.id), scope: String(r.scope), tier: String(r.tier),
      intervalMs: Number(r.interval_ms), retain: Number(r.retain), enabled: Number(r.enabled) === 1,
      nextRunAt: Number(r.next_run_at), lastRunAt: r.last_run_at === null ? null : Number(r.last_run_at),
    }));
  }

  /// Edit the retention count of an existing schedule in place (keeps enabled + next_run_at).
  /// Returns false for an unknown id.
  setScheduleRetain(id: string, retain: number): boolean {
    if (!Number.isSafeInteger(retain) || retain < 0 || retain > 10_000) throw new Error("invalid snapshot schedule");
    const c = this.sql.exec(`UPDATE snapshot_schedules SET retain=? WHERE id=?;`, retain, id);
    return c.rowsWritten > 0;
  }

  setScheduleEnabled(id: string, enabled: boolean): void {
    this.sql.exec(`UPDATE snapshot_schedules SET enabled=? WHERE id=?;`, enabled ? 1 : 0, id);
  }

  /// Earliest due schedule time — lets the DO arm an alarm.
  earliestDue(): number | null {
    const r = this.sql
      .exec(`SELECT MIN(next_run_at) AS n FROM snapshot_schedules WHERE enabled=1;`)
      .toArray()[0];
    return r && r.n !== null ? Number(r.n) : null;
  }

  /// Run all schedules due at/before `now`: create a snapshot per schedule,
  /// advance next_run_at, then prune that tier to its retention count.
  /// Idempotent enough for alarm retries (a duplicate snapshot id per tick is
  /// derived from next_run_at).
  runDue(now = Date.now()): { created: Snapshot[]; pruned: string[] } {
    const due = this.sql
      .exec(`SELECT * FROM snapshot_schedules WHERE enabled=1 AND next_run_at <= ? ORDER BY next_run_at,id LIMIT 8;`, now)
      .toArray();
    const created: Snapshot[] = [];
    const pruned: string[] = [];
    for (const s of due) {
      const interval = Number(s.interval_ms), retain = Number(s.retain);
      // Older installations may already contain unchecked values. Disable a
      // corrupt schedule so it cannot spin forever or starve healthy schedules.
      if (!isValidScheduleSpec({ id: s.id, scope: s.scope, tier: s.tier, intervalMs: interval, retain })) {
        this.sql.exec(`UPDATE snapshot_schedules SET enabled=0 WHERE id=?;`, String(s.id));
        continue;
      }
      const prior = Number(s.next_run_at);
      const next = prior + (Math.floor((now - prior) / interval) + 1) * interval;
      this.sql.exec(`UPDATE snapshot_schedules SET next_run_at=?, last_run_at=? WHERE id=?;`, next, now, String(s.id));
      // A deleted scope still has valuable backups. Do not replace those with
      // empty snapshots or run retention until that folder is live again.
      if (!this.sql.exec(`SELECT 1 FROM items WHERE id=? AND deleted=0 AND is_dir=1;`, String(s.scope)).toArray().length) continue;
      let id = `${String(s.id)}-${Number(s.next_run_at)}`;
      // Manual IDs share this namespace. An existing recovery point must never
      // be re-frozen merely because its ID matches a future schedule slot.
      if (this.get(id)) id = `auto-${crypto.randomUUID()}`;
      const snap = this.create({
        id,
        scope: String(s.scope),
        tier: String(s.tier),
        scheduleId: String(s.id),
        label: `auto:${String(s.tier)}`,
      });
      created.push(snap);
      pruned.push(...this.prune(String(s.id), retain, now));
    }
    return { created, pruned };
  }

  /// GFS retention: keep the newest `retain` snapshots for a schedule; delete
  /// older ones whose immutable_until has lapsed. Returns deleted ids.
  prune(scheduleId: string, retain: number, now = Date.now()): string[] {
    const toDelete = this.sql
      .exec(`SELECT id,created_at,immutable_until FROM (
          SELECT id,created_at,immutable_until,ROW_NUMBER() OVER (ORDER BY created_at DESC,seq_anchor DESC,id DESC) AS rank
          FROM snapshots WHERE schedule_id=?
        ) WHERE rank>? AND (immutable_until IS NULL OR immutable_until<=?) ORDER BY rank LIMIT 128;`, scheduleId, retain, now)
      .toArray();
    const deleted: string[] = [];
    for (const s of toDelete) {
      const lock = s.immutable_until === null ? null : Number(s.immutable_until);
      if (lock !== null && lock > now) continue; // Object-Lock: cannot purge yet.
      this.deleteSnapshot(String(s.id));
      deleted.push(String(s.id));
    }
    return deleted;
  }

  /// Finding I2: the FULL deletion of a snapshot — the only correct way to remove
  /// one. The old prune() did `DELETE FROM snapshots` ALONE, leaking snapshot_items/
  /// snapshot_blocks rows forever AND (after Finding I1) leaking block_refs so a
  /// block frozen only by this snapshot never reached refcount 0 → never collectable.
  /// Order matters: release the refs the frozen manifest holds FIRST (while the rows
  /// still exist), then delete the frozen rows, then the snapshot row. After this, a
  /// block with no remaining live OR other-snapshot ref correctly hits 0 and becomes
  /// collectable; one still held by another snapshot or a live file does NOT.
  deleteSnapshot(snapshotId: string): void {
    // Audit B19 — chain-preserving delete. A snapshot may be the BASE of newer snapshots, which
    // INHERIT its delta rows. Before removing it, push the rows each child still relies on DOWN into
    // that child (the child's own rows already win, so we only fill gaps), re-parent the child to
    // this snapshot's base, then delete this snapshot. This keeps every dependent snapshot's RESOLVED
    // view byte-identical. Without it, deleting a base would silently drop inherited content.
    const base = this.sql.exec(`SELECT base_snapshot_id FROM snapshots WHERE id=?;`, snapshotId).toArray()[0];
    const baseId = base && base.base_snapshot_id !== null ? String(base.base_snapshot_id) : null;
    const children = this.sql.exec(`SELECT id FROM snapshots WHERE base_snapshot_id=?;`, snapshotId).toArray().map((r) => String(r.id));

    for (const childId of children) {
      // Items this snapshot froze that the child does NOT already override → copy into the child so
      // the child keeps inheriting them. Carry the deleted flag (a delta-tombstone moves too).
      const inherited = `SELECT item_id FROM snapshot_items source WHERE source.snapshot_id=?2
        AND NOT EXISTS (SELECT 1 FROM snapshot_items child WHERE child.snapshot_id=?1 AND child.item_id=source.item_id)`;
      this.sql.exec(`INSERT INTO block_refs(block_hash,object_key,refcount)
        SELECT block_hash,MIN(object_key),COUNT(*) FROM snapshot_blocks
        WHERE snapshot_id=?2 AND item_id IN (${inherited}) GROUP BY block_hash
        ON CONFLICT(block_hash) DO UPDATE SET refcount=refcount+excluded.refcount;`, childId, snapshotId);
      this.sql.exec(`INSERT INTO snapshot_blocks(snapshot_id,item_id,chunk_idx,block_idx,block_hash,object_key,offset,length)
        SELECT ?1,item_id,chunk_idx,block_idx,block_hash,object_key,offset,length FROM snapshot_blocks
        WHERE snapshot_id=?2 AND item_id IN (${inherited});`, childId, snapshotId);
      this.sql.exec(`INSERT INTO snapshot_streams(snapshot_id,item_id,name,size,data,storage_kind,version)
        SELECT ?1,item_id,name,size,data,storage_kind,version FROM snapshot_streams WHERE snapshot_id=?2 AND item_id IN (${inherited});`, childId, snapshotId);
      this.sql.exec(`INSERT INTO block_refs(block_hash,object_key,refcount) SELECT block_hash,MIN(object_key),COUNT(*) FROM snapshot_stream_blocks
        WHERE snapshot_id=?2 AND item_id IN (${inherited}) GROUP BY block_hash
        ON CONFLICT(block_hash) DO UPDATE SET refcount=refcount+excluded.refcount;`,childId,snapshotId);
      this.sql.exec(`INSERT INTO snapshot_stream_blocks(snapshot_id,item_id,name,block_idx,block_hash,object_key,length)
        SELECT ?1,item_id,name,block_idx,block_hash,object_key,length FROM snapshot_stream_blocks WHERE snapshot_id=?2 AND item_id IN (${inherited});`,childId,snapshotId);
      this.sql.exec(`INSERT INTO snapshot_items(snapshot_id,item_id,parent,name,is_dir,size,content_version,etag,deleted,created_at,modified_at,accessed_at,changed_at,file_attributes)
        SELECT ?1,item_id,parent,name,is_dir,size,content_version,etag,deleted,created_at,modified_at,accessed_at,changed_at,file_attributes FROM snapshot_items
        WHERE snapshot_id=?2 AND item_id IN (${inherited});`, childId, snapshotId);
      // Re-parent the child onto this snapshot's base (drop the link to the deleted snapshot).
      this.sql.exec(`UPDATE snapshots SET base_snapshot_id=? WHERE id=?;`, baseId, childId);
    }

    // Now release THIS snapshot's refs (the moved blocks were re-credited to the child above, so
    // this nets to zero for them; un-inherited blocks correctly drop) and delete its rows.
    this.releaseSnapshotBlockRefs(snapshotId);
    this.sql.exec(`DELETE FROM snapshot_blocks WHERE snapshot_id=?;`, snapshotId);
    this.sql.exec(`DELETE FROM snapshot_streams WHERE snapshot_id=?;`, snapshotId);
    this.sql.exec(`DELETE FROM snapshot_stream_blocks WHERE snapshot_id=?;`, snapshotId);
    this.sql.exec(`DELETE FROM snapshot_items WHERE snapshot_id=?;`, snapshotId);
    this.sql.exec(`DELETE FROM snapshots WHERE id=?;`, snapshotId);
  }

  /// Snapshot-aware GC: a block is collectable iff NOTHING references it (refcount
  /// 0). Returns the object keys to delete from R2. Finding I1: a retained snapshot
  /// holds its OWN block_refs (added in freeze(), removed in deleteSnapshot()), so a
  /// block any snapshot still froze never reaches 0 even after the live file that
  /// originally wrote it is overwritten or deleted — conservative by construction.
  collectableBlocks(limit = 1000): { blockHash: string; objectKey: string }[] {
    return this.sql
      .exec(`SELECT b.block_hash,b.object_key FROM block_refs b WHERE b.refcount <= 0
        AND NOT EXISTS (SELECT 1 FROM retained_blocks r WHERE r.block_hash=b.block_hash)
        LIMIT ?;`, limit)
      .toArray()
      .map((r) => ({ blockHash: String(r.block_hash), objectKey: String(r.object_key) }));
  }
}
