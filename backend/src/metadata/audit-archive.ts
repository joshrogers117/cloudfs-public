// SPDX-License-Identifier: AGPL-3.0-or-later
/// R2 archival of the audit chain (WS3).
///
/// The FilespaceDO keeps only a small recent RING of audit events in its SQLite
/// (last 24h OR last 2000 events, whichever is smaller). Older sealed records are
/// flushed here to R2 as append-style NDJSON segments partitioned by
/// filespace + UTC day, plus a per-space manifest that keeps the hash chain
/// continuous across the DO→R2 boundary:
///
///   audit/{filespaceId}/{YYYY-MM-DD}/{firstSeq}-{lastSeq}.ndjson  // per-flush
///   audit/{filespaceId}/index.json                                // manifest
///
/// `{filespaceId}` is the effective DO key form `<org>::<fs>`.
///
/// Finding 2: each flush is written as its OWN immutable segment object keyed by
/// its seq range (under the day prefix), and `seal()` only APPENDS a manifest
/// entry. Previously a same-day flush did a read-modify-write of the WHOLE day
/// NDJSON (re-read + re-sort + re-PUT every flush ⇒ O(day^2) I/O under the hourly
/// archive cadence). Per-flush objects are write-once: no re-read, no per-day size
/// growth. A day therefore maps to MULTIPLE segments (one per flush), still in
/// strict ascending `seq` order.
///
/// CONTINUITY INVARIANT (the whole point): a verifier can concatenate every R2
/// segment in ascending seq order, then append the records still held in the DO
/// ring, and run the EXISTING `verifyChain` unchanged. For that to hold:
///   - segments are appended in strict ascending `seq` order (never rewritten),
///   - `segments[i].firstPrevHash === segments[i-1].lastHash`, and
///   - the DO ring's earliest record's `prevHash === segments[last].lastHash`
///     (or GENESIS_HASH when no segments exist yet).
/// The manifest records each segment's `firstPrevHash` + `lastHash` (plus seq
/// bounds + count) so continuity is checkable from the index alone, and so the
/// reader can locate which segment(s) cover a requested seq range.

import {
  GENESIS_HASH,
  hashRecord,
  toNdjson,
  type AuditQuery,
  type AuditRecord,
  type ChainVerifyResult,
} from "../security/audit";

/// One sealed segment, as recorded in index.json.
export interface AuditSegment {
  date: string;          // "YYYY-MM-DD" (UTC) — matches the {date}.ndjson key
  key: string;           // full R2 object key for the segment body
  firstSeq: number;      // seq of the segment's first record
  lastSeq: number;       // seq of the segment's last record
  firstPrevHash: string; // prevHash of the segment's FIRST record (chain link in)
  lastHash: string;      // hash of the segment's LAST record (chain link out)
  count: number;         // records in the segment
}

/// The per-space manifest at audit/{filespaceId}/index.json.
export interface AuditIndex {
  filespaceId: string;
  segments: AuditSegment[]; // ascending date/seq order
  /// The first seq STILL HELD in the DO ring (= archivedThroughSeq + 1). A reader
  /// uses this to decide ring-vs-R2 for a requested range; informational here.
  ringStartsAtSeq: number;
}

/// Minimal R2 surface we depend on (subset of Cloudflare's R2Bucket). Declared
/// locally so this module is testable with a tiny fake and doesn't hard-couple to
/// the ambient workers-types beyond what it uses.
export interface AuditR2 {
  get(key: string): Promise<{ text(): Promise<string> } | null>;
  put(key: string, value: string): Promise<unknown>;
}

const enc = (filespaceId: string) => `audit/${filespaceId}`;
const indexKey = (filespaceId: string) => `${enc(filespaceId)}/index.json`;
/// Per-flush immutable segment key: day prefix + the flush's seq range so it never
/// collides with another flush (Finding 2). Distinct from the legacy per-day key.
const segmentKey = (filespaceId: string, date: string, firstSeq: number, lastSeq: number) =>
  `${enc(filespaceId)}/${date}/${firstSeq}-${lastSeq}.ndjson`;

/// UTC YYYY-MM-DD for a ms-epoch timestamp (segments partition by UTC day so the
/// boundary is stable regardless of where the DO runs).
export function utcDay(ts: number): string {
  return new Date(ts).toISOString().slice(0, 10);
}

/// Parse NDJSON back into records (skips blank trailing lines).
function parseNdjson(body: string): AuditRecord[] {
  return body
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .map((l) => JSON.parse(l) as AuditRecord);
}

export class R2AuditArchive {
  // R2 reads open the Durable Object input gate. Serialize only archive
  // publication, never the entire DO or ordinary namespace/audit appends.
  private sealing: Promise<void> = Promise.resolve();
  constructor(
    private readonly r2: AuditR2,
    private readonly filespaceId: string,
  ) {}

  async loadIndex(): Promise<AuditIndex> {
    const obj = await this.r2.get(indexKey(this.filespaceId));
    if (!obj) {
      return { filespaceId: this.filespaceId, segments: [], ringStartsAtSeq: 0 };
    }
    return JSON.parse(await obj.text()) as AuditIndex;
  }

  private async putIndex(index: AuditIndex): Promise<void> {
    await this.r2.put(indexKey(this.filespaceId), JSON.stringify(index));
  }

  private async loadSegment(seg: AuditSegment): Promise<AuditRecord[]> {
    const obj = await this.r2.get(seg.key);
    if (!obj) throw new Error(`audit archive segment missing: ${seg.firstSeq}-${seg.lastSeq}`);
    const records = parseNdjson(await obj.text());
    if (records.length !== seg.count || records[0]?.seq !== seg.firstSeq
      || records.at(-1)?.seq !== seg.lastSeq || records[0]?.prevHash !== seg.firstPrevHash
      || records.at(-1)?.hash !== seg.lastHash) throw new Error("audit archive segment does not match its index");
    return records;
  }

  private assertIndex(index: AuditIndex): void {
    if (index.filespaceId !== this.filespaceId || !Array.isArray(index.segments)) throw new Error("invalid audit archive index");
    let seq = 0, hash = GENESIS_HASH;
    for (const segment of index.segments) {
      if (segment.firstSeq !== seq || !Number.isSafeInteger(segment.lastSeq) || segment.lastSeq < seq
        || segment.count !== segment.lastSeq - seq + 1 || segment.firstPrevHash !== hash
        || !/^[a-f0-9]{64}$/.test(segment.lastHash) || !segment.key.startsWith(`${enc(this.filespaceId)}/`)) {
        throw new Error("audit archive index has a gap or broken chain");
      }
      seq = segment.lastSeq + 1; hash = segment.lastHash;
    }
    if (index.ringStartsAtSeq !== seq) throw new Error("audit archive index high-water mismatch");
  }

  /** Recover pre-checkpoint installations whose resident ring was fully sealed.
   * Never invent a new genesis when durable history already exists. */
  async lastRecord(): Promise<AuditRecord | null> {
    const index = await this.loadIndex();
    this.assertIndex(index);
    const segment = index.segments.at(-1);
    if (!segment) return null;
    const records = await this.loadSegment(segment);
    const invalid = await this.verifyRun(records, { expectedSeq: segment.firstSeq, expectedPrev: segment.firstPrevHash, checked: 0 });
    if (invalid) throw new Error(`audit archive tail is invalid: ${invalid.reason}`);
    return records.at(-1)!;
  }

  /// Seal a batch of records (already ascending by seq, contiguous in the chain)
  /// into R2 and update index.json. Finding 2: each UTC-day group is written as a
  /// SEPARATE, immutable, write-once segment object keyed by its seq range — we
  /// never re-read or rewrite a prior segment, so a busy day no longer pays
  /// O(day^2) read-modify-write per flush. A day spanning multiple flushes is
  /// represented by multiple ascending-seq segments. Returns the new high-water
  /// `seq` (the last record sealed). A no-op for an empty batch.
  ///
  /// Idempotent against re-flush: records whose seq is already covered by an
  /// existing segment are skipped (so an alarm retry after a partial failure does
  /// not duplicate lines or fork the chain). Because segments only ever grow
  /// forward, "already covered" reduces to "seq <= the manifest high-water".
  async seal(records: AuditRecord[]): Promise<number | null> {
    const previous = this.sealing;
    let release!: () => void;
    this.sealing = new Promise<void>(resolve => { release = resolve; });
    await previous;
    try { return await this.sealSerial(records); }
    finally { release(); }
  }

  private async sealSerial(records: AuditRecord[]): Promise<number | null> {
    if (records.length === 0) return null;
    const index = await this.loadIndex();
    this.assertIndex(index);
    const tail = index.segments.at(-1);
    const alreadyThrough = tail?.lastSeq ?? -1;
    // Retries may overlap an already published segment. Sequence coverage alone
    // is not proof: a reset/reused sequence must never erase a different event.
    const overlaps = records.filter(record => record.seq <= alreadyThrough);
    if (overlaps.length) {
      const expected = new Map<number, string>();
      const lo = overlaps[0].seq, hi = overlaps.at(-1)!.seq;
      for (const segment of index.segments.filter(segment => segment.lastSeq >= lo && segment.firstSeq <= hi)) {
        for (const record of await this.loadSegment(segment)) expected.set(record.seq, record.hash);
      }
      if (overlaps.some(record => expected.get(record.seq) !== record.hash)) throw new Error("audit archive sequence was reused by a different event");
    }
    const fresh = records.filter((r) => r.seq > alreadyThrough);
    if (fresh.length === 0) return alreadyThrough;
    const invalid = await this.verifyRun(fresh, { expectedSeq: alreadyThrough + 1, expectedPrev: tail?.lastHash ?? GENESIS_HASH, checked: 0 });
    if (invalid) throw new Error(`audit archive cannot seal a broken chain: ${invalid.reason}`);

    // Keep contiguous sequence runs, even if the wall clock crosses back into a
    // prior UTC day. Grouping every same-day record together would reorder them.
    const groups: { day: string; records: AuditRecord[] }[] = [];
    for (const r of fresh) {
      const day = utcDay(r.ts);
      if (groups.at(-1)?.day !== day) groups.push({ day, records: [] });
      groups.at(-1)!.records.push(r);
    }

    // Write one immutable segment per day-group, in chronological order so the
    // manifest stays ascending by firstSeq. No prior-segment read = no RMW.
    for (const { day, records: group } of groups) {
      const first = group[0];
      const last = group[group.length - 1];
      const key = segmentKey(this.filespaceId, day, first.seq, last.seq);
      await this.r2.put(key, toNdjson(group)); // write-once: never rewritten
      index.segments.push({
        date: day,
        key,
        firstSeq: first.seq,
        lastSeq: last.seq,
        firstPrevHash: first.prevHash,
        lastHash: last.hash,
        count: group.length,
      });
    }

    index.segments.sort((a, b) => a.firstSeq - b.firstSeq);
    const highWater = index.segments[index.segments.length - 1].lastSeq;
    index.ringStartsAtSeq = highWater + 1;
    await this.putIndex(index);
    return highWater;
  }

  /// Read archived records from R2 matching `filter`, restricted to seq <
  /// `ringStartSeq` (the boundary the DO ring takes over at). Returns NEWEST-FIRST
  /// (`seq DESC`) to match the reader/page-back contract (CONTRACTS §5.4):
  ///   - `cursor` (when set) is an EXCLUSIVE upper bound on `seq` (page-back),
  ///   - `limit` keeps the newest matching rows of the window.
  /// Segments are scanned in DESCENDING seq order and the scan stops as soon as
  /// `limit` matches are collected, so paging back never loads the whole history.
  async query(filter: AuditQuery, ringStartSeq: number): Promise<AuditRecord[]> {
    const index = await this.loadIndex();
    this.assertIndex(index);
    if (index.ringStartsAtSeq < ringStartSeq) throw new Error("audit archive index is missing retained history");
    const upper = filter.cursor !== undefined
      ? Math.min(filter.cursor, ringStartSeq)
      : ringStartSeq;
    const limit = Math.min(Math.max(1, filter.limit ?? 1000), 10_000);
    // Newest segments first so we can short-circuit once `limit` is satisfied.
    const segs = index.segments
      .filter((s) => s.firstSeq < upper) // any record in-range possible
      .sort((a, b) => b.firstSeq - a.firstSeq);
    const out: AuditRecord[] = [];
    for (const seg of segs) {
      const recs = await this.loadSegment(seg);
      // Walk this segment newest-first.
      for (let i = recs.length - 1; i >= 0; i--) {
        const r = recs[i];
        if (r.seq >= upper) continue; // ring owns these / above the page cursor
        if (!matches(r, filter)) continue;
        out.push(r);
        if (limit !== undefined && out.length >= limit) return out;
      }
    }
    return out;
  }

  /// Concatenate EVERY archived record (all segments, ascending seq). Used by the
  /// continuity verifier: archived records + the DO ring, fed to `verifyChain`.
  async allArchived(): Promise<AuditRecord[]> {
    const index = await this.loadIndex();
    const out: AuditRecord[] = [];
    for (const seg of index.segments.slice().sort((a, b) => a.firstSeq - b.firstSeq)) {
      out.push(...await this.loadSegment(seg));
    }
    out.sort((a, b) => a.seq - b.seq);
    return out;
  }

  /// Check the manifest's chain-continuity invariant WITHOUT reading bodies:
  /// segment[0].firstPrevHash must be GENESIS, and each segment's firstPrevHash
  /// must equal the previous segment's lastHash. (`verifyChain` over the actual
  /// records is the deep check; this is the cheap structural one.)
  async verifyManifestContinuity(): Promise<{ ok: boolean; reason?: string }> {
    const index = await this.loadIndex();
    let expectedPrev = GENESIS_HASH;
    for (const seg of index.segments) {
      if (seg.firstPrevHash !== expectedPrev) {
        return { ok: false, reason: `segment ${seg.date} firstPrevHash != prior lastHash` };
      }
      expectedPrev = seg.lastHash;
    }
    return { ok: true };
  }

  /// Finding 3: verify the FULL chain (archived segments + the DO ring) but
  /// INCREMENTALLY — one segment body in memory at a time — instead of
  /// concatenating the whole history (allArchived() could blow the DO memory/time
  /// budget for a long-lived space). The cheap structural `verifyManifestContinuity`
  /// gates the inter-segment links from the index alone; here we additionally
  /// re-hash each segment's records in order, threading the running (expectedPrev,
  /// expectedSeq) across the segment boundary and finally across the seam into the
  /// caller-supplied DO `ring` (already bounded by the ring window). Result
  /// semantics match `verifyChain` exactly (ok / brokenAtSeq / reason / 1-based
  /// `checked`). Peak memory is one segment + the ring, never the full chain.
  async verifyContinuity(ring: AuditRecord[], archivedThrough?: number): Promise<ChainVerifyResult> {
    const index = await this.loadIndex();
    try { this.assertIndex(index); }
    catch (error) { return { ok: false, checked: 0, reason: String(error) }; }
    if (archivedThrough !== undefined && index.ringStartsAtSeq <= archivedThrough) {
      return { ok: false, checked: 0, reason: "audit archive index is missing retained history" };
    }
    const segs = index.segments.slice().sort((a, b) => a.firstSeq - b.firstSeq);
    const state = { expectedPrev: GENESIS_HASH, expectedSeq: 0, checked: 0 };
    for (const seg of segs) {
      if (archivedThrough !== undefined && seg.firstSeq > archivedThrough) break;
      // Cheap structural gate from the manifest before paying to read the body.
      if (seg.firstPrevHash !== state.expectedPrev) {
        return { ok: false, checked: state.checked, brokenAtSeq: seg.firstSeq, reason: "prevHash mismatch" };
      }
      // Bounded: only THIS segment's records are resident for the deep re-hash.
      let records: AuditRecord[];
      try { records = await this.loadSegment(seg); }
      catch (error) { return { ok: false, checked: state.checked, brokenAtSeq: seg.firstSeq, reason: String(error) }; }
      if (archivedThrough !== undefined) records = records.filter(record => record.seq <= archivedThrough);
      const bad = await this.verifyRun(records, state);
      if (bad) return bad;
    }
    // Continue across the seam into the DO ring (the chain's newest records).
    const bad = await this.verifyRun(ring, state);
    if (bad) return bad;
    return { ok: true, checked: state.checked };
  }

  /// Re-hash a contiguous run of records against a running chain `state` (mutated
  /// in place). Returns a failure result at the first broken link, or null when the
  /// whole run verifies. Shares verifyChain's exact rules so continuity semantics
  /// are identical when streamed segment-by-segment.
  private async verifyRun(
    recs: AuditRecord[],
    state: { expectedPrev: string; expectedSeq: number; checked: number },
  ): Promise<ChainVerifyResult | null> {
    for (const r of recs) {
      if (r.seq !== state.expectedSeq) {
        return { ok: false, checked: state.checked, brokenAtSeq: r.seq, reason: "seq gap or reorder" };
      }
      if (r.prevHash !== state.expectedPrev) {
        return { ok: false, checked: state.checked, brokenAtSeq: r.seq, reason: "prevHash mismatch" };
      }
      const { hash, ...unsealed } = r;
      if ((await hashRecord(unsealed)) !== hash) {
        return { ok: false, checked: state.checked, brokenAtSeq: r.seq, reason: "hash mismatch (record edited)" };
      }
      state.expectedPrev = r.hash;
      state.expectedSeq += 1;
      state.checked += 1;
    }
    return null;
  }
}

/// Field-filter a single record (mirrors DoAuditStore.query / InMemory store).
function matches(r: AuditRecord, f: AuditQuery): boolean {
  if (f.orgId !== undefined && r.orgId !== f.orgId) return false;
  if (f.spaceId !== undefined && r.spaceId !== f.spaceId) return false;
  if (f.actorSub !== undefined && r.actorSub !== f.actorSub) return false;
  if (f.action !== undefined && r.action !== f.action) return false;
  if (f.decision !== undefined && r.decision !== f.decision) return false;
  if (f.since !== undefined && r.ts < f.since) return false;
  if (f.until !== undefined && r.ts > f.until) return false;
  return true;
}
