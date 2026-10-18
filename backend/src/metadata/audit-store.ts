// SPDX-License-Identifier: AGPL-3.0-or-later
/// SQLite-backed `AuditStore` (security/audit.ts) over the FilespaceDO's storage.
///
/// The DO is the right home for the per-(org,space) audit chain (SPEC §4.8;
/// security-INTEGRATION.md §5): it serializes writes, so the hash chain stays
/// consistent without extra locking. We persist the full sealed record as JSON
/// plus the common filter fields as columns for the reader API.
///
/// We do NOT reimplement chaining/hashing — that lives in `AuditLog`; this only
/// supplies `tail/append/query`.
///
/// Ring buffer (WS3): the DO keeps only a bounded recent window of audit events
/// (the archiver flushes older ones to R2, then calls `deleteUpToSeq`). The extra
/// helpers below (`count`, `oldestRecord`, `recordsUpTo`, `recordsFrom`,
/// `deleteUpToSeq`, and the `archived_through_seq` marker) support that trim +
/// the R2-fallback reader without breaking the `tail()` chaining contract —
/// `tail()` still returns the latest row, which is what `AuditLog.write` chains
/// off of (the chain never depends on already-archived rows being present).

import type { AuditQuery, AuditRecord, AuditStore } from "../security/audit";

export class DoAuditStore implements AuditStore {
  constructor(private readonly sql: SqlStorage) {}

  tail(): AuditRecord | null {
    const r = this.sql.exec(`SELECT json FROM audit ORDER BY seq DESC LIMIT 1;`).toArray()[0];
    if (r) return JSON.parse(String(r.json)) as AuditRecord;
    const checkpoint = this.sql.exec(`SELECT value FROM meta_text WHERE key='audit_chain_tail';`).toArray()[0];
    return checkpoint ? JSON.parse(String(checkpoint.value)) as AuditRecord : null;
  }

  /** The chain anchor outlives an empty resident ring. This write and append's
   * INSERT run in the same synchronous SQLite turn. */
  checkpointTail(rec: AuditRecord): void {
    this.sql.exec(`INSERT INTO meta_text(key,value) VALUES ('audit_chain_tail',?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value;`, JSON.stringify(rec));
  }

  append(rec: AuditRecord): void {
    this.sql.exec(
      `INSERT INTO audit (seq,ts,org_id,space_id,actor_sub,action,decision,prev_hash,hash,json)
       VALUES (?,?,?,?,?,?,?,?,?,?);`,
      rec.seq, rec.ts, rec.orgId, rec.spaceId ?? null, rec.actorSub,
      rec.action, rec.decision, rec.prevHash, rec.hash, JSON.stringify(rec),
    );
    this.checkpointTail(rec);
  }

  /// Reader for the audit history surface (CONTRACTS §5.4). Returns NEWEST-FIRST
  /// (`seq DESC`) so paging is natural: `limit` keeps the newest rows of the
  /// window, and `cursor` is an EXCLUSIVE upper bound on `seq` (page-back returns
  /// rows with `seq < cursor`). `verifyChain` consumers must re-sort ascending.
  query(filter: AuditQuery): AuditRecord[] {
    const where: string[] = [];
    const args: SqlStorageValue[] = [];
    if (filter.orgId) { where.push(`org_id = ?`); args.push(filter.orgId); }
    if (filter.spaceId) { where.push(`space_id = ?`); args.push(filter.spaceId); }
    if (filter.actorSub) { where.push(`actor_sub = ?`); args.push(filter.actorSub); }
    if (filter.action) { where.push(`action = ?`); args.push(filter.action); }
    if (filter.decision) { where.push(`decision = ?`); args.push(filter.decision); }
    if (filter.since !== undefined) { where.push(`ts >= ?`); args.push(filter.since); }
    if (filter.until !== undefined) { where.push(`ts <= ?`); args.push(filter.until); }
    if (filter.cursor !== undefined) { where.push(`seq < ?`); args.push(filter.cursor); }
    const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const limit = Math.min(Math.max(1, filter.limit ?? 1000), 10_000);
    const rows = this.sql
      .exec(`SELECT json FROM audit ${clause} ORDER BY seq DESC LIMIT ?;`, ...args, limit)
      .toArray();
    return rows.map((r) => JSON.parse(String(r.json)) as AuditRecord);
  }

  // ---- ring-buffer / archival support (WS3) ---------------------------------

  /// How many audit rows are currently held in the DO ring.
  count(): number {
    return Number(this.sql.exec(`SELECT COUNT(*) AS c FROM audit;`).one().c);
  }

  /// Lowest/highest seq still resident in the DO ring (null when empty).
  seqBounds(): { min: number; max: number } | null {
    const r = this.sql.exec(`SELECT MIN(seq) AS lo, MAX(seq) AS hi FROM audit;`).toArray()[0];
    if (!r || r.lo === null) return null;
    return { min: Number(r.lo), max: Number(r.hi) };
  }

  /// The oldest record still resident (the ring's earliest), or null.
  oldestRecord(): AuditRecord | null {
    const r = this.sql.exec(`SELECT json FROM audit ORDER BY seq ASC LIMIT 1;`).toArray()[0];
    return r ? (JSON.parse(String(r.json)) as AuditRecord) : null;
  }

  /// Resident records in ascending seq order, optionally bounded by an inclusive
  /// `[fromSeq, toSeq]` range. Used by the archiver (to seal a batch) and by the
  /// R2-fallback reader (to splice the ring portion of a query range).
  recordsInRange(fromSeq?: number, toSeq?: number, limit = 10_000): AuditRecord[] {
    const where: string[] = [];
    const args: SqlStorageValue[] = [];
    if (fromSeq !== undefined) { where.push(`seq >= ?`); args.push(fromSeq); }
    if (toSeq !== undefined) { where.push(`seq <= ?`); args.push(toSeq); }
    const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
    const rows = this.sql
      .exec(`SELECT json FROM audit ${clause} ORDER BY seq ASC LIMIT ?;`, ...args, Math.min(Math.max(1, limit), 50_000))
      .toArray();
    return rows.map((r) => JSON.parse(String(r.json)) as AuditRecord);
  }

  /// The set of records eligible to be SEALED to R2: older than `tsCutoff`
  /// (ms-epoch) AND/OR beyond the `maxKeep` newest events — i.e. everything NOT
  /// inside the ring window. Returned ascending by seq (chain order). We compute
  /// the trim boundary as the HIGHER seq cutoff of the two policies so the ring
  /// ends up holding `min(last 24h, last maxKeep events)` (whichever is smaller).
  sealCandidates(tsCutoff: number, maxKeep: number, limit = 512): AuditRecord[] {
    const bounds = this.seqBounds();
    if (!bounds) return [];
    // Count-policy boundary: keep the newest `maxKeep` rows → seal seq <= (max - maxKeep).
    const total = this.count();
    const countCutoffSeq = total > maxKeep ? bounds.max - maxKeep : bounds.min - 1;
    // Time-policy boundary: seal rows with ts < tsCutoff. Find the largest such seq.
    const r = this.sql
      .exec(`SELECT MAX(seq) AS s FROM audit WHERE ts < ?;`, tsCutoff)
      .toArray()[0];
    const timeCutoffSeq = r && r.s !== null ? Number(r.s) : bounds.min - 1;
    // "whichever is smaller" ring ⇒ seal up to the MAX of the two cutoffs.
    const cutoff = Math.max(countCutoffSeq, timeCutoffSeq);
    if (cutoff < bounds.min) return [];
    const rows = this.recordsInRange(undefined, cutoff, limit);
    // Bound payload memory as well as row count. One oversized legacy event is
    // still allowed to make progress; normal gateway events are much smaller.
    let bytes = 0;
    const encoder = new TextEncoder();
    return rows.filter((record, index) => {
      bytes += encoder.encode(JSON.stringify(record)).byteLength;
      return index === 0 || bytes <= 2 * 1024 * 1024;
    });
  }

  /// Delete every ring row with seq <= `seq` (inclusive). Called by the archiver
  /// ONLY after the batch is durably flushed to R2 (rows are never lost: their
  /// R2 segment is written + index.json updated first).
  deleteUpToSeq(seq: number): number {
    const before = this.count();
    this.sql.exec(`DELETE FROM audit WHERE seq <= ?;`, seq);
    return before - this.count();
  }

  /// High-water mark: the greatest seq durably flushed to R2 (-1 = none yet).
  archivedThroughSeq(): number {
    const r = this.sql.exec(`SELECT value FROM meta WHERE key='archived_through_seq';`).toArray()[0];
    return r ? Number(r.value) : -1;
  }

  setArchivedThroughSeq(seq: number): void {
    this.sql.exec(
      `INSERT INTO meta (key, value) VALUES ('archived_through_seq', ?)
       ON CONFLICT(key) DO UPDATE SET value=excluded.value;`,
      seq,
    );
  }

  /// Durably persist this DO's effective filespace key (`<org>::<fs>` — the R2
  /// audit prefix). Written on the first appendAudit so a hibernated DO whose ring
  /// was fully sealed+emptied can still recover the prefix and splice R2 history
  /// (the INTEGER `meta` table can't hold text, hence the dedicated `meta_text`).
  /// Idempotent upsert; the key never changes for a given DO.
  setFilespaceKey(key: string): void {
    this.sql.exec(
      `INSERT INTO meta_text (key, value) VALUES ('filespace_key', ?)
       ON CONFLICT(key) DO UPDATE SET value=excluded.value;`,
      key,
    );
  }

  /// Read back the durably-persisted filespace key, or null if never written.
  filespaceKey(): string | null {
    const r = this.sql.exec(`SELECT value FROM meta_text WHERE key='filespace_key';`).toArray()[0];
    return r ? String(r.value) : null;
  }
}
