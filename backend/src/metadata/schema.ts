// SPDX-License-Identifier: AGPL-3.0-or-later
/// Versioned schema for the FilespaceDO's SQLite storage.
///
/// DO SQLite does NOT support `PRAGMA user_version`, so we track applied
/// migrations in a `_schema_migrations` table (the durable-objects best-practice
/// pattern). `migrate()` is idempotent and runs once inside
/// `blockConcurrencyWhile()` before any request is served.
///
/// Capacity note (SPEC §7.3a): one DO per filespace, 10 GB SQLite each. The big
/// table is `blocks` (the chunk→block map: ≈24M rows at 95 TB / 4 MB blocks).
/// Everything is indexed so we never table-scan or load a whole tree into memory.

export const SCHEMA_VERSION = 30;

export function migrate(sql: SqlStorage): void {
  sql.exec(`CREATE TABLE IF NOT EXISTS _schema_migrations (
    id INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
  );`);

  const current = Number(
    sql.exec(`SELECT COALESCE(MAX(id), 0) AS v FROM _schema_migrations;`).one().v,
  );

  // ---- v1: namespace (items), advisory locks, monotonic seq -----------------
  if (current < 1) {
    sql.exec(`CREATE TABLE IF NOT EXISTS items (
      id TEXT PRIMARY KEY,
      parent TEXT,
      name TEXT NOT NULL,
      is_dir INTEGER NOT NULL,
      size INTEGER NOT NULL DEFAULT 0,
      content_version TEXT NOT NULL,
      etag TEXT,
      version INTEGER NOT NULL DEFAULT 1,
      created_seq INTEGER NOT NULL,
      updated_seq INTEGER NOT NULL,
      deleted INTEGER NOT NULL DEFAULT 0
    );`);
    // Directory listing is the hot path: index (parent, is_dir, name) so the
    // ORDER BY is index-served and pagination cursors seek instead of scan.
    sql.exec(`CREATE INDEX IF NOT EXISTS items_dir_listing
      ON items(parent, is_dir DESC, name);`);
    // Change-feed cursor: every mutation bumps updated_seq monotonically.
    sql.exec(`CREATE INDEX IF NOT EXISTS items_seq ON items(updated_seq);`);

    sql.exec(`CREATE TABLE IF NOT EXISTS locks (
      path TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      mode TEXT NOT NULL DEFAULT 'exclusive',
      fence INTEGER NOT NULL,
      acquired_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS locks_expiry ON locks(expires_at);`);

    sql.exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);`);
    sql.exec(`INSERT OR IGNORE INTO meta (key, value) VALUES ('seq', 0);`);
    sql.exec(`INSERT OR IGNORE INTO meta (key, value) VALUES ('fence', 0);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (1, ?);`, Date.now());
  }

  // ---- v2: large-file support — chunk/block map + multipart upload sessions --
  if (current < 2) {
    // Content-addressed block map. One row per (item, chunk, block).
    // `block_hash` is the content address (sha256 of the ciphertext block);
    // identical blocks across files/versions dedupe to the same object key.
    sql.exec(`CREATE TABLE IF NOT EXISTS blocks (
      item_id TEXT NOT NULL,
      chunk_idx INTEGER NOT NULL,
      block_idx INTEGER NOT NULL,
      block_hash TEXT NOT NULL,
      object_key TEXT NOT NULL,
      offset INTEGER NOT NULL,
      length INTEGER NOT NULL,
      PRIMARY KEY (item_id, chunk_idx, block_idx)
    );`);
    // Ordered block-map fetch for a file (the read path).
    sql.exec(`CREATE INDEX IF NOT EXISTS blocks_item ON blocks(item_id, chunk_idx, block_idx);`);
    // Refcount for snapshot-aware GC: how many (live items + retained snapshots)
    // reference a given content hash.
    sql.exec(`CREATE TABLE IF NOT EXISTS block_refs (
      block_hash TEXT PRIMARY KEY,
      object_key TEXT NOT NULL,
      refcount INTEGER NOT NULL DEFAULT 0
    );`);

    // Resumable multipart upload coordination (SPEC §5.4). The DO tracks the
    // session + per-part ETags so an interrupted upload resumes by re-querying.
    sql.exec(`CREATE TABLE IF NOT EXISTS uploads (
      upload_id TEXT PRIMARY KEY,
      item_id TEXT NOT NULL,
      key TEXT NOT NULL,
      total_size INTEGER NOT NULL,
      part_size INTEGER NOT NULL,
      state TEXT NOT NULL DEFAULT 'in_progress',
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );`);
    sql.exec(`CREATE TABLE IF NOT EXISTS upload_parts (
      upload_id TEXT NOT NULL,
      part_number INTEGER NOT NULL,
      etag TEXT NOT NULL,
      size INTEGER NOT NULL,
      checksum TEXT,
      PRIMARY KEY (upload_id, part_number)
    );`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (2, ?);`, Date.now());
  }

  // ---- v3: snapshots (point-in-time namespace), GFS retention ----------------
  if (current < 3) {
    // A snapshot is a named, frozen pointer to the namespace at a `seq` anchor
    // (SPEC §4.7). It copies no media bytes — restore reads items as-of the seq.
    sql.exec(`CREATE TABLE IF NOT EXISTS snapshots (
      id TEXT PRIMARY KEY,
      label TEXT,
      scope TEXT NOT NULL DEFAULT 'root',
      seq_anchor INTEGER NOT NULL,
      tier TEXT NOT NULL DEFAULT 'manual',
      created_at INTEGER NOT NULL,
      immutable_until INTEGER,
      schedule_id TEXT
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS snapshots_tier ON snapshots(tier, created_at);`);

    // Declarative schedules with GFS retention, executed server-side by alarm.
    sql.exec(`CREATE TABLE IF NOT EXISTS snapshot_schedules (
      id TEXT PRIMARY KEY,
      scope TEXT NOT NULL DEFAULT 'root',
      tier TEXT NOT NULL,
      interval_ms INTEGER NOT NULL,
      retain INTEGER NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      next_run_at INTEGER NOT NULL,
      last_run_at INTEGER
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS sched_next ON snapshot_schedules(enabled, next_run_at);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (3, ?);`, Date.now());
  }

  // ---- v4: tombstone-aware change feed needs an index on (deleted) ----------
  if (current < 4) {
    // Tombstones flow through the change feed so clients can prune deleted items.
    // (No column add — `deleted` already exists since v1; this records intent and
    // lets us evolve without renumbering.)
    sql.exec(`CREATE INDEX IF NOT EXISTS items_parent_live ON items(parent, deleted);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (4, ?);`, Date.now());
  }

  // ---- v5: integration — per-folder ACL grants + tamper-evident audit chain --
  if (current < 5) {
    // ACL grants live on the filespace (SPEC §4.10: ACLs attach to folder nodes).
    // The permissions evaluator (src/permissions.ts) reads these via a sync
    // PermissionStore adapter implemented in filespace-do.ts. Shape mirrors the
    // multiuser agent's documented DDL (multiuser-INTEGRATION.md §4).
    sql.exec(`CREATE TABLE IF NOT EXISTS grants (
      id TEXT PRIMARY KEY,
      space_id TEXT,
      inode_id TEXT NOT NULL,
      principal_type TEXT NOT NULL,
      principal_id TEXT NOT NULL,
      level TEXT NOT NULL,
      mount_as_root INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER,
      granted_by TEXT,
      granted_at INTEGER NOT NULL
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS grants_inode ON grants(inode_id);`);
    sql.exec(`CREATE INDEX IF NOT EXISTS grants_principal ON grants(inode_id, principal_type, principal_id);`);

    // Append-only, hash-chained audit log (SPEC §4.8; security/audit.ts).
    // The DO is the natural home: per-(org,space) chain, writes serialize here.
    // The full sealed record is in `json`; the common filter fields are also
    // columns so the reader API (AuditStore.query) can index-filter cheaply.
    sql.exec(`CREATE TABLE IF NOT EXISTS audit (
      seq INTEGER PRIMARY KEY,
      ts INTEGER NOT NULL,
      org_id TEXT,
      space_id TEXT,
      actor_sub TEXT,
      action TEXT NOT NULL,
      decision TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL,
      json TEXT NOT NULL
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS audit_filter ON audit(action, decision, ts);`);
    sql.exec(`CREATE INDEX IF NOT EXISTS audit_actor ON audit(actor_sub, ts);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (5, ?);`, Date.now());
  }

  // ---- v6: per-(org,space) durable rate-limit counters -----------------------
  if (current < 6) {
    // Token-bucket state keyed by limiter key (e.g. "presign:p:<sub>"). The DO is
    // the single consistent counter for its own space — exactly the class the
    // security review says must be global ("protects the single-threaded
    // FilespaceDO"). The consume() math lives in security/ratelimit.ts; this is
    // just the durable RateLimitStore backing it (so a fleet of Worker isolates
    // share one counter per space instead of each enforcing its own loose cap).
    sql.exec(`CREATE TABLE IF NOT EXISTS rate_buckets (
      key TEXT PRIMARY KEY,
      tokens REAL NOT NULL,
      updated_at INTEGER NOT NULL
    );`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (6, ?);`, Date.now());
  }

  // ---- v7: frozen point-in-time content for snapshot RESTORE -----------------
  if (current < 7) {
    // The live `items`/`blocks` tables only keep the CURRENT version — an in-place
    // content edit overwrites the block manifest, so "as-of" content can't be
    // reconstructed from them alone. To make RESTORE bring back old manifests
    // (SPEC §4.7 self-service restore), we FREEZE each live item's metadata + its
    // block manifest into these tables when a snapshot is created. This copies no
    // media bytes (only the manifest/pointers), and the frozen object_keys keep
    // their blocks alive via block_refs (snapshot-aware GC stays correct).
    sql.exec(`CREATE TABLE IF NOT EXISTS snapshot_items (
      snapshot_id TEXT NOT NULL,
      item_id TEXT NOT NULL,
      parent TEXT,
      name TEXT NOT NULL,
      is_dir INTEGER NOT NULL,
      size INTEGER NOT NULL,
      content_version TEXT NOT NULL,
      etag TEXT,
      PRIMARY KEY (snapshot_id, item_id)
    );`);
    // Subtree scan for restore: items under a parent, as-of a snapshot.
    sql.exec(`CREATE INDEX IF NOT EXISTS snap_items_parent ON snapshot_items(snapshot_id, parent);`);

    sql.exec(`CREATE TABLE IF NOT EXISTS snapshot_blocks (
      snapshot_id TEXT NOT NULL,
      item_id TEXT NOT NULL,
      chunk_idx INTEGER NOT NULL,
      block_idx INTEGER NOT NULL,
      block_hash TEXT NOT NULL,
      object_key TEXT NOT NULL,
      offset INTEGER NOT NULL,
      length INTEGER NOT NULL,
      PRIMARY KEY (snapshot_id, item_id, chunk_idx, block_idx)
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS snap_blocks_item ON snapshot_blocks(snapshot_id, item_id, chunk_idx, block_idx);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (7, ?);`, Date.now());
  }

  // ---- v8: audit ring-buffer / R2 archival high-water mark (WS3) -------------
  if (current < 8) {
    // The DO no longer keeps the full audit chain forever. An alarm tick seals
    // records older than the ring window (min(last 24h, last 2000 events)) into
    // R2 NDJSON segments, then DELETEs those rows from `audit`. `archived_through_seq`
    // is the high-water `seq` durably flushed to R2 — rows are only deleted AFTER a
    // successful R2 flush, so a verifier can splice R2 (≤ this seq) + the DO ring
    // (> this seq) and run verifyChain unbroken. -1 = nothing archived yet.
    //
    // We reuse the existing `meta` (key TEXT PK, value INTEGER) table — same row
    // shape as `seq`/`fence` — so no new table is needed for a single counter.
    sql.exec(`INSERT OR IGNORE INTO meta (key, value) VALUES ('archived_through_seq', -1);`);
    // Ring-trim seeks "rows with seq <= X ordered by seq" and "min/max seq"; the
    // PK on `audit(seq)` already serves both, but an explicit ts index lets the
    // time-window trim (seal everything with ts < cutoff) seek instead of scan.
    sql.exec(`CREATE INDEX IF NOT EXISTS audit_ts ON audit(ts);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (8, ?);`, Date.now());
  }

  // ---- v9: durable TEXT meta (e.g. the filespace key `<org>::<fs>`) ----------
  if (current < 9) {
    // The existing `meta` table is INTEGER-only (it holds `seq`/`fence`/
    // `archived_through_seq`), so it can't durably store the `<org>::<fs>`
    // filespace key the R2 audit archive is prefixed by. Without persisting that
    // key, a hibernated DO whose audit ring was fully sealed+emptied loses the
    // only place to recover it from — `keyFromTail()` then reads the empty ring,
    // returns null, and the reader SILENTLY DROPS all R2-archived history (and the
    // archive alarm never re-arms). A dedicated TEXT-valued meta table fixes that:
    // the key is written on the first appendAudit and read back on cold reads.
    sql.exec(`CREATE TABLE IF NOT EXISTS meta_text (key TEXT PRIMARY KEY, value TEXT NOT NULL);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (9, ?);`, Date.now());
  }

  // ---- v10 (PERF P1): reverse index on blocks(object_key) --------------------
  if (current < 10) {
    // `NamespaceStore.itemForObjectKey` does
    //   SELECT item_id FROM blocks WHERE object_key=? LIMIT 1
    // on EVERY presign GET mint (index.ts presign path → permissions enforcement-
    // at-mint, SPEC §4.4). The only pre-existing index on `blocks` is the PK/
    // `blocks_item` on (item_id, chunk_idx, block_idx), which can't serve a lookup
    // keyed by `object_key` — so each mint was a full table scan of `blocks`, the
    // largest table (≈24M rows at 95 TB / 4 MB blocks) on the single-threaded DO,
    // stalling the whole team on every cache-miss block fetch. Adding this index
    // turns that scan into a point seek. Idempotent + version-gated so existing
    // deployments pick it up on upgrade without rewriting prior migrations.
    sql.exec(`CREATE INDEX IF NOT EXISTS blocks_object_key ON blocks(object_key);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (10, ?);`, Date.now());
  }

  // ---- v11 (audit B17): opaque immutable inode ids + a (parent,name) unique index -----
  if (current < 11) {
    // BEFORE: an inode's id was PATH-DERIVED (`${parent}/${name}`), so a rename/move was
    // impossible without rewriting every descendant id + every reference (`blocks.item_id`,
    // `grants.inode_id`, `locks.path`, `snapshot_items`), AND unvalidated names could collide
    // ids across directories. AFTER: ids are OPAQUE, immutable UUIDs; `(parent, casefold(name))`
    // is the lookup key. A rename touches ONLY `(parent, name)` — no id rewrite, no cascade.
    //
    // The ROOT inode keeps its well-known literal id `"root"` (the namespace anchor clients
    // hardcode as the create parent); only NON-root rows are re-keyed.
    migrateToOpaqueIds(sql);

    // Live-only UNIQUE on (parent, casefolded NFC name): two live siblings can't share a name,
    // but a tombstone + a live recreate at the same (parent,name) coexist (distinct ids). The
    // case-folded form (audit B18) makes `Readme.txt`/`readme.txt` collide as one logical name.
    sql.exec(`CREATE UNIQUE INDEX IF NOT EXISTS items_parent_name_live
      ON items(parent, name COLLATE NOCASE) WHERE deleted = 0;`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (11, ?);`, Date.now());
  }

  // ---- v12 (audit B19): copy-on-write snapshot DELTAS ---------------------------------
  if (current < 12) {
    // BEFORE: each snapshot froze a FULL copy of every live item + block manifest under its scope
    // (≈24M block rows at 95 TB). One root snapshot ~doubled the largest table; a GFS schedule
    // blew past the 10 GB DO cap. AFTER: a snapshot freezes only the DELTA vs. its base (the prior
    // snapshot of the same scope) — items changed/created/deleted since the base — and inherits the
    // rest by chain resolution. `base_snapshot_id` links the lineage; a `deleted` marker on a
    // snapshot_items row records "this item was gone as-of this snapshot" (a delta tombstone).
    sql.exec(`ALTER TABLE snapshots ADD COLUMN base_snapshot_id TEXT;`);
    sql.exec(`ALTER TABLE snapshot_items ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0;`);
    // Resolve "the newest lineage snapshot that froze item X" — index the chain walk.
    sql.exec(`CREATE INDEX IF NOT EXISTS snapshots_scope_seq ON snapshots(scope, seq_anchor);`);
    sql.exec(`CREATE INDEX IF NOT EXISTS snap_items_item ON snapshot_items(item_id, snapshot_id);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (12, ?);`, Date.now());
  }

  // ---- v13 (SMB cutover): real wall-clock timestamps on items -------------------------
  if (current < 13) {
    // BEFORE: items carried no created/modified time; the mount SYNTHESIZED a
    // pseudo-mtime by hashing contentVersion (stable-per-content, but a fake date).
    // AFTER: nullable millisecond-epoch columns hold real times. Nullable + no
    // backfill = safe on live DOs; legacy rows stay NULL and the client falls back
    // to the hash-of-version synthesis. `created_at` is set once at create; a
    // rename does NOT touch `modified_at` (POSIX parity) — only content writes do.
    sql.exec(`ALTER TABLE items ADD COLUMN created_at INTEGER;`);
    sql.exec(`ALTER TABLE items ADD COLUMN modified_at INTEGER;`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (13, ?);`, Date.now());
  }

  // ---- v14 (SMB cutover): named streams / xattrs ------------------------------------
  if (current < 14) {
    // Apple metadata (FinderInfo, resource forks, `com.apple.*` xattrs) rides SMB
    // named streams. Storing them natively keeps macOS from spraying AppleDouble
    // `._` sidecar FILES into the object store. Streams are small metadata, so we
    // hold them INLINE in the DO (BLOB); the server caps encrypted writes at
    // 1.5 MiB to fit Cloudflare's 2 MB row limit. Every
    // stream mutation bumps the owning item's updated_seq so the change feed sees
    // it. Cascade-deleted with the item.
    sql.exec(`CREATE TABLE IF NOT EXISTS item_streams (
      item_id TEXT NOT NULL,
      name TEXT NOT NULL,
      size INTEGER NOT NULL,
      data BLOB NOT NULL,
      updated_seq INTEGER NOT NULL,
      PRIMARY KEY (item_id, name)
    );`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (14, ?);`, Date.now());
  }

  // ---- v15: retained block ownership for offline conflict recovery ----------
  if (current < 15) {
    // A journal stores the ORIGINAL committed manifest plus local dirty blocks.
    // Replacing the live manifest must not make its unchanged old blocks unreadable
    // or collectible. Store one server-derived reference per inode/object, not one
    // full manifest per edit. No client can create this ownership via presign.
    sql.exec(`CREATE TABLE IF NOT EXISTS retained_blocks (
      item_id TEXT NOT NULL,
      object_key TEXT NOT NULL,
      block_hash TEXT NOT NULL,
      retained_at INTEGER NOT NULL,
      PRIMARY KEY (item_id, object_key)
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS retained_blocks_object_key ON retained_blocks(object_key, item_id);`);
    sql.exec(`CREATE INDEX IF NOT EXISTS retained_blocks_hash ON retained_blocks(block_hash);`);
    // Existing retained snapshots are authoritative evidence of historical ownership.
    // Only live inode lineages are backfilled; deletion/recreation cannot inherit it.
    sql.exec(`INSERT OR IGNORE INTO retained_blocks (item_id,object_key,block_hash,retained_at)
      SELECT sb.item_id,sb.object_key,sb.block_hash,? FROM snapshot_blocks sb
        JOIN items i ON i.id=sb.item_id WHERE i.deleted=0;`, Date.now());
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (15, ?);`, Date.now());
  }

  // ---- v16: server-observed object provenance for manifest commits ----------
  if (current < 16) {
    // Catalog entries outlive namespace deletion. They never authorize a read;
    // they prevent a retired key from being claimed as a fresh unknown upload.
    sql.exec(`CREATE TABLE IF NOT EXISTS known_objects (
      object_key TEXT PRIMARY KEY,
      block_hash TEXT NOT NULL
    );`);
    for (const table of ["blocks", "retained_blocks", "snapshot_blocks", "block_refs"]) {
      sql.exec(`INSERT OR IGNORE INTO known_objects (object_key,block_hash)
        SELECT object_key,block_hash FROM ${table};`);
    }
    sql.exec(`CREATE TABLE IF NOT EXISTS block_upload_claims (
      object_key TEXT PRIMARY KEY,
      item_id TEXT,
      principal_id TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS block_upload_claims_expiry ON block_upload_claims(expires_at);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (16, ?);`, Date.now());
  }
  if (current < 17) {
    const columns = new Set(sql.exec(`PRAGMA table_info(grants);`).toArray().map(row => String(row.name)));
    if (!columns.has("authority_grant_id")) sql.exec(`ALTER TABLE grants ADD COLUMN authority_grant_id TEXT;`);
    if (!columns.has("authority_inode_id")) sql.exec(`ALTER TABLE grants ADD COLUMN authority_inode_id TEXT;`);
    sql.exec(`CREATE INDEX IF NOT EXISTS grants_authority ON grants(authority_grant_id);`);
    sql.exec(`CREATE TABLE IF NOT EXISTS revoked_acl_principals (principal_type TEXT NOT NULL, principal_id TEXT NOT NULL,
      PRIMARY KEY (principal_type,principal_id));`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (17, ?);`, Date.now());
  }
  if (current < 18) {
    const columns = new Set(sql.exec(`PRAGMA table_info(snapshots);`).toArray().map(row => String(row.name)));
    if (!columns.has("streams_captured")) sql.exec(`ALTER TABLE snapshots ADD COLUMN streams_captured INTEGER NOT NULL DEFAULT 0;`);
    sql.exec(`CREATE TABLE IF NOT EXISTS snapshot_streams (
      snapshot_id TEXT NOT NULL, item_id TEXT NOT NULL, name TEXT NOT NULL,
      size INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(snapshot_id,item_id,name));`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (18, ?);`, Date.now());
  }
  if (current < 19) {
    sql.exec(`CREATE TABLE IF NOT EXISTS disabled_acl_authorities (principal_id TEXT PRIMARY KEY);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (19, ?);`, Date.now());
  }
  if (current < 20) {
    // Early development DOs recorded v17 before principal retirement was added
    // to that migration. Repair forward: never replay/drop existing ACL data.
    const columns = new Set(sql.exec(`PRAGMA table_info(grants);`).toArray().map(row => String(row.name)));
    if (!columns.has("authority_grant_id")) sql.exec(`ALTER TABLE grants ADD COLUMN authority_grant_id TEXT;`);
    if (!columns.has("authority_inode_id")) sql.exec(`ALTER TABLE grants ADD COLUMN authority_inode_id TEXT;`);
    sql.exec(`CREATE INDEX IF NOT EXISTS grants_authority ON grants(authority_grant_id);`);
    sql.exec(`CREATE TABLE IF NOT EXISTS revoked_acl_principals (principal_type TEXT NOT NULL, principal_id TEXT NOT NULL,
      PRIMARY KEY (principal_type,principal_id));`);
    sql.exec(`CREATE TABLE IF NOT EXISTS disabled_acl_authorities (principal_id TEXT PRIMARY KEY);`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (20, ?);`, Date.now());
  }

  if (current < 21) {
    sql.exec(`CREATE TABLE IF NOT EXISTS verified_objects (
      storage_identity TEXT NOT NULL, object_key TEXT NOT NULL, block_hash TEXT NOT NULL,
      ciphertext_size INTEGER NOT NULL, plaintext_size INTEGER NOT NULL, verified_at INTEGER NOT NULL,
      PRIMARY KEY(storage_identity,object_key));`);
    sql.exec(`INSERT INTO _schema_migrations (id, applied_at) VALUES (21, ?);`, Date.now());
  }

  // Stream payloads live in immutable object storage; SQLite holds bounded rows.
  if (current < 22) {
    for (const table of ["item_streams", "snapshot_streams"]) {
      const columns = new Set(sql.exec(`PRAGMA table_info(${table});`).toArray().map(r => String(r.name)));
      if (!columns.has("storage_kind")) sql.exec(`ALTER TABLE ${table} ADD COLUMN storage_kind TEXT NOT NULL DEFAULT 'inline';`);
      if (!columns.has("version")) sql.exec(`ALTER TABLE ${table} ADD COLUMN version INTEGER NOT NULL DEFAULT 1;`);
    }
    sql.exec(`CREATE TABLE IF NOT EXISTS stream_blocks(item_id TEXT NOT NULL,name TEXT NOT NULL,block_idx INTEGER NOT NULL,
      block_hash TEXT NOT NULL,object_key TEXT NOT NULL,length INTEGER NOT NULL,PRIMARY KEY(item_id,name,block_idx));`);
    sql.exec(`CREATE INDEX IF NOT EXISTS stream_blocks_object ON stream_blocks(object_key,item_id);`);
    sql.exec(`CREATE TABLE IF NOT EXISTS snapshot_stream_blocks(snapshot_id TEXT NOT NULL,item_id TEXT NOT NULL,name TEXT NOT NULL,block_idx INTEGER NOT NULL,
      block_hash TEXT NOT NULL,object_key TEXT NOT NULL,length INTEGER NOT NULL,PRIMARY KEY(snapshot_id,item_id,name,block_idx));`);
    sql.exec(`CREATE INDEX IF NOT EXISTS snapshot_stream_blocks_object ON snapshot_stream_blocks(snapshot_id,item_id,object_key);`);
    sql.exec(`INSERT INTO _schema_migrations(id,applied_at) VALUES(22,?);`,Date.now());
  }

  if (current < 23) {
    const columns=new Set(sql.exec(`PRAGMA table_info(item_streams);`).toArray().map(r=>String(r.name)));
    if (!columns.has('last_delta_digest')) sql.exec(`ALTER TABLE item_streams ADD COLUMN last_delta_digest TEXT;`);
    sql.exec(`INSERT INTO _schema_migrations(id,applied_at) VALUES(23,?);`,Date.now());
  }

  if (current < 24) {
    sql.exec(`INSERT OR IGNORE INTO meta(key,value) VALUES ('visibility_generation',0);`);
    for (const table of ['grants', 'revoked_acl_principals', 'disabled_acl_authorities']) {
      for (const event of ['INSERT', 'UPDATE', 'DELETE']) {
        sql.exec(`CREATE TRIGGER IF NOT EXISTS visibility_${table}_${event.toLowerCase()}
          AFTER ${event} ON ${table} BEGIN
            UPDATE meta SET value=value+1 WHERE key='visibility_generation';
          END;`);
      }
    }
    sql.exec(`CREATE INDEX IF NOT EXISTS grants_expiry ON grants(expires_at);`);
    sql.exec(`INSERT INTO _schema_migrations(id,applied_at) VALUES(24,?);`,Date.now());
  }

  if (current < 25) {
    const columns=new Set(sql.exec('PRAGMA table_info(items);').toArray().map(r=>String(r.name)));
    if (!columns.has('manifest_block_size')) sql.exec('ALTER TABLE items ADD COLUMN manifest_block_size INTEGER;');
    if (!columns.has('last_manifest_delta_digest')) sql.exec('ALTER TABLE items ADD COLUMN last_manifest_delta_digest TEXT;');
    sql.exec('CREATE INDEX IF NOT EXISTS blocks_range ON blocks(item_id,offset);');
    sql.exec('INSERT INTO _schema_migrations(id,applied_at) VALUES(25,?);',Date.now());
  }

  if (current < 26) {
    const columns=new Set(sql.exec('PRAGMA table_info(block_refs);').toArray().map(r=>String(r.name)));
    if (!columns.has('unreferenced_at')) sql.exec('ALTER TABLE block_refs ADD COLUMN unreferenced_at INTEGER;');
    sql.exec('UPDATE block_refs SET unreferenced_at=? WHERE refcount<=0 AND unreferenced_at IS NULL;',Date.now());
    sql.exec('CREATE INDEX IF NOT EXISTS block_refs_zero ON block_refs(refcount,unreferenced_at,object_key);');
    sql.exec('CREATE INDEX IF NOT EXISTS verified_objects_key ON verified_objects(object_key);');
    sql.exec('CREATE INDEX IF NOT EXISTS uploads_object ON uploads(key,state);');
    sql.exec('CREATE INDEX IF NOT EXISTS snapshot_blocks_key ON snapshot_blocks(object_key);');
    sql.exec('CREATE INDEX IF NOT EXISTS snapshot_stream_blocks_key ON snapshot_stream_blocks(object_key);');
    sql.exec(`CREATE TABLE IF NOT EXISTS object_reclamation(object_key TEXT PRIMARY KEY,token TEXT NOT NULL,state TEXT NOT NULL,
      recovered_through INTEGER NOT NULL,next_at INTEGER NOT NULL,attempts INTEGER NOT NULL,last_error TEXT);`);
    sql.exec('CREATE INDEX IF NOT EXISTS object_reclamation_due ON object_reclamation(next_at);');
    sql.exec(`CREATE TRIGGER IF NOT EXISTS block_refs_unreferenced AFTER UPDATE OF refcount ON block_refs
      WHEN NEW.refcount<=0 AND OLD.refcount>0 BEGIN
        UPDATE block_refs SET unreferenced_at=CAST(unixepoch('subsec')*1000 AS INTEGER) WHERE block_hash=NEW.block_hash;
      END;`);
    // Every reference/claim writer, including restore and direct SQL paths,
    // participates. A new reference cancels quarantine; retirement is permanent.
    for (const table of ['blocks','stream_blocks','snapshot_blocks','snapshot_stream_blocks','retained_blocks','block_upload_claims','uploads']) {
      const key=table==='uploads'?'key':'object_key';
      for (const event of ['INSERT','UPDATE']) {
        sql.exec(`CREATE TRIGGER IF NOT EXISTS reclamation_${table}_${event.toLowerCase()} BEFORE ${event} ON ${table} BEGIN
          SELECT RAISE(ABORT,'object_retired') WHERE EXISTS(SELECT 1 FROM object_reclamation WHERE object_key=NEW.${key} AND state!='quarantined');
          DELETE FROM object_reclamation WHERE object_key=NEW.${key} AND state='quarantined';
        END;`);
      }
    }
    sql.exec('INSERT INTO _schema_migrations(id,applied_at) VALUES(26,?);',Date.now());
  }

  if (current < 27) {
    const add = (table: string, column: string, definition: string) => {
      const columns = new Set(sql.exec(`PRAGMA table_info(${table});`).toArray().map(row => String(row.name)));
      if (!columns.has(column)) sql.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition};`);
    };
    add('snapshots','basic_info_captured','INTEGER NOT NULL DEFAULT 0');
    for (const column of ['accessed_at','changed_at']) add('items',column,'INTEGER');
    add('items','file_attributes','INTEGER NOT NULL DEFAULT 0');
    for (const column of ['created_at','modified_at','accessed_at','changed_at']) add('snapshot_items',column,'INTEGER');
    add('snapshot_items','file_attributes','INTEGER NOT NULL DEFAULT 0');
    sql.exec(`CREATE TRIGGER IF NOT EXISTS items_change_time AFTER UPDATE OF content_version,parent,name ON items
      WHEN NEW.content_version!=OLD.content_version OR NEW.parent IS NOT OLD.parent OR NEW.name!=OLD.name
      BEGIN UPDATE items SET changed_at=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER) WHERE id=NEW.id; END;`);
    sql.exec('INSERT INTO _schema_migrations(id,applied_at) VALUES(27,?);',Date.now());
  }

  // v28: handle-owned byte ranges, independent of publication fencing.
  if (current < 28) {
    sql.exec(`CREATE TABLE IF NOT EXISTS range_locks (
      path TEXT NOT NULL, owner TEXT NOT NULL, handle TEXT NOT NULL,
      fence INTEGER NOT NULL, expires_at INTEGER NOT NULL, ranges TEXT NOT NULL,
      PRIMARY KEY(path,owner,handle));`);
    sql.exec(`CREATE INDEX IF NOT EXISTS range_locks_expiry ON range_locks(expires_at);`);
    sql.exec(`CREATE TABLE IF NOT EXISTS read_permits (
      path TEXT NOT NULL, owner TEXT NOT NULL, handle TEXT NOT NULL, fence INTEGER NOT NULL, expires_at INTEGER NOT NULL,
      PRIMARY KEY(path,owner,handle));`);
    sql.exec(`CREATE INDEX IF NOT EXISTS read_permits_expiry ON read_permits(expires_at);`);
    sql.exec(`CREATE TABLE IF NOT EXISTS range_waiters(path TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);`);
    sql.exec(`INSERT INTO _schema_migrations(id,applied_at) VALUES(28,?);`,Date.now());
  }

  // v29: bounded, inode-scoped open handles. These rows pin payload ownership
  // after unlink/replacement until the final handle closes or expires.
  if (current < 29) {
    sql.exec(`CREATE TABLE IF NOT EXISTS open_handles (
      handle_id TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      inode_id TEXT NOT NULL,
      access_mask INTEGER NOT NULL,
      share_mask INTEGER NOT NULL,
      opened_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );`);
    sql.exec(`CREATE INDEX IF NOT EXISTS open_handles_inode_expiry ON open_handles(inode_id,expires_at);`);
    sql.exec(`CREATE INDEX IF NOT EXISTS open_handles_expiry ON open_handles(expires_at);`);
    sql.exec(`CREATE INDEX IF NOT EXISTS open_handles_owner_expiry ON open_handles(owner,expires_at);`);
    sql.exec(`INSERT INTO _schema_migrations(id,applied_at) VALUES(29,?);`,Date.now());
  }

  // v30: distinguish manifest publication leases from application/advisory
  // leases. Existing leases are advisory by default and are never promoted.
  if (current < 30) {
    sql.exec(`ALTER TABLE locks ADD COLUMN purpose TEXT NOT NULL DEFAULT 'advisory';`);
    sql.exec(`INSERT INTO _schema_migrations(id,applied_at) VALUES(30,?);`,Date.now());
  }

}

/// Audit B17 — one-time, idempotent rewrite of path-derived inode ids to opaque UUIDs.
/// Builds a complete old-id → new-uuid map (root maps to itself), then rewrites EVERY
/// reference in a single pass: `items.id`, `items.parent`, `blocks.item_id`,
/// `grants.inode_id`, `locks.path`, `snapshot_items.(item_id,parent)`, `snapshot_blocks.item_id`,
/// `uploads.item_id`, `open_handles.inode_id`. Order matters only in that we read the full map up front, so a child whose
/// parent is also being re-keyed still resolves to the parent's NEW id. Re-running is a no-op
/// because it is version-gated AND a row whose id is already a UUID-shaped opaque id maps to
/// itself (the heuristic: an id containing `/` is path-derived; `root` is the anchor).
export function migrateToOpaqueIds(sql: SqlStorage): void {
  const rows = sql.exec(`SELECT id FROM items;`).toArray().map((r) => String(r.id));
  // Path-derived ids are exactly those that are NOT `root` and contain a `/`. A pre-existing
  // opaque id (none yet, but defensive) or `root` maps to itself.
  const remap = new Map<string, string>();
  for (const oldId of rows) {
    if (oldId === "root" || !oldId.includes("/")) {
      remap.set(oldId, oldId);
    } else {
      remap.set(oldId, `ino-${crypto.randomUUID()}`);
    }
  }
  // Nothing path-derived → nothing to do (a fresh DO seeded with opaque ids already).
  if (![...remap.entries()].some(([o, n]) => o !== n)) return;

  const newId = (old: string | null): string | null => (old === null ? null : remap.get(old) ?? old);

  // Rewrite items: id + parent. We must avoid PK collisions, so write into a temp shape via a
  // map-driven UPDATE per row (the row count is bounded by the filespace; this runs once).
  for (const [oldId, nid] of remap) {
    if (oldId === nid) {
      // Only the parent may need rewriting (a root-or-opaque id whose parent was path-derived).
      const parentRow = sql.exec(`SELECT parent FROM items WHERE id = ?;`, oldId).toArray()[0];
      const p = parentRow ? (parentRow.parent === null ? null : String(parentRow.parent)) : null;
      const np = newId(p);
      if (np !== p) sql.exec(`UPDATE items SET parent = ? WHERE id = ?;`, np, oldId);
      continue;
    }
    const parentRow = sql.exec(`SELECT parent FROM items WHERE id = ?;`, oldId).toArray()[0];
    const p = parentRow ? (parentRow.parent === null ? null : String(parentRow.parent)) : null;
    sql.exec(`UPDATE items SET id = ?, parent = ? WHERE id = ?;`, nid, newId(p), oldId);
    // Rewrite every reference to this id across the schema.
    sql.exec(`UPDATE blocks SET item_id = ? WHERE item_id = ?;`, nid, oldId);
    sql.exec(`UPDATE grants SET inode_id = ? WHERE inode_id = ?;`, nid, oldId);
    sql.exec(`UPDATE locks SET path = ? WHERE path = ?;`, nid, oldId);
    sql.exec(`UPDATE snapshot_items SET item_id = ? WHERE item_id = ?;`, nid, oldId);
    sql.exec(`UPDATE snapshot_items SET parent = ? WHERE parent = ?;`, nid, oldId);
    sql.exec(`UPDATE snapshot_blocks SET item_id = ? WHERE item_id = ?;`, nid, oldId);
    sql.exec(`UPDATE uploads SET item_id = ? WHERE item_id = ?;`, nid, oldId);
    sql.exec(`UPDATE open_handles SET inode_id = ? WHERE inode_id = ?;`, nid, oldId);
  }
}
