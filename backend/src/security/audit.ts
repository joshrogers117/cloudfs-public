// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs audit log: append-only, tamper-evident, queryable (SPEC §4.8, §4.10 AuditEvent).
///
/// Why this matters here specifically: because the gateway is the SOLE enforcement point
/// (SPEC §4.4), "every byte a client could read corresponds to a logged mint event" — the
/// audit log is AUTHORITATIVE, not inferred. That property is only worth something if the
/// log can't be silently rewritten, so we hash-chain each record to the previous one.
///
/// Tamper-evidence (lightweight blockchain-style chaining, no external service):
///   record.hash = SHA-256( prevHash || canonicalJSON(record-without-hash) )
/// Any insertion, deletion, reorder, or edit breaks the chain from that point on, and
/// `verifyChain` pinpoints the first broken link. The genesis record chains off a constant.
///
/// Storage: this writer is storage-agnostic via the `AuditStore` interface. In production
/// the backing store is the FilespaceDO's SQLite (per SPEC: "also persisted" alongside the
/// NDJSON ship to OpenSearch/SIEM). An in-memory store is provided for tests + buffering.

export type AuditDecision = "allow" | "deny";

/// One structured event. Mirrors SPEC §4.10 AuditEvent + PresignedMint, unified.
export interface AuditEvent {
  /// who
  actorSub: string;            // member id / service-account id / guest-link id
  actorType: "session" | "service" | "guest";
  orgId: string;
  spaceId?: string;
  sessionId?: string;          // jti of the token that authorized the action
  sourceIp?: string;
  /// what
  action: string;              // 'presign.mint' | 'item.create' | 'lock.acquire' | 'acl.grant' | 'login' | ...
  decision: AuditDecision;
  targetInodeId?: string;
  levelChecked?: string;       // 'read' | 'read_write' | 'admin' | undefined
  /// presign specifics (SPEC PresignedMint)
  mintedObjectKeys?: string[];
  verb?: "GET" | "PUT";
  urlTtlSeconds?: number;
  /// free-form structured detail (avoid PII / plaintext; this log is metadata-only).
  detail?: Record<string, unknown>;
}

/// A sealed, chained record as stored/emitted. NDJSON-friendly (SPEC §4.8).
export interface AuditRecord extends AuditEvent {
  seq: number;        // monotonic per chain
  ts: number;         // ms epoch, server-stamped
  prevHash: string;   // hash of the previous record (genesis = GENESIS_HASH)
  hash: string;       // hash of this record (see hashRecord)
}

/// 64 hex zeros — the chain's anchor. A verifier knows the chain starts here.
export const GENESIS_HASH = "0".repeat(64);

/// Pluggable persistence. Implementations must be append-only in spirit (no update/delete
/// API surface). Production impl is SQLite-on-DO; see security-INTEGRATION.md.
export interface AuditStore {
  /// The last record (for chaining) or null if empty.
  tail(): Promise<AuditRecord | null> | AuditRecord | null;
  /// Append one sealed record. MUST NOT mutate existing rows.
  append(rec: AuditRecord): Promise<void> | void;
  /// Query for the reader API. Filters are ANDed; omitted filters match all.
  query(filter: AuditQuery): Promise<AuditRecord[]> | AuditRecord[];
}

export interface AuditQuery {
  orgId?: string;
  spaceId?: string;
  actorSub?: string;
  action?: string;
  decision?: AuditDecision;
  /// inclusive ms-epoch bounds
  since?: number;
  until?: number;
  limit?: number;
  /// EXCLUSIVE upper bound on `seq` for page-back (CONTRACTS §5.4). When set, the
  /// reader returns rows with `seq < cursor`, NEWEST-FIRST. Pairs with the client's
  /// continuation cursor = the lowest `seq` of the previous full page, so successive
  /// pages are strictly older and non-overlapping (the loop terminates on a short
  /// page). Readers order `seq DESC`; `verifyChain` consumers must re-sort ascending.
  cursor?: number;
}

const enc = new TextEncoder();

function toHex(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf);
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

/// Canonicalize a record (sans `hash`) deterministically so the digest is stable across
/// JS engines: sort keys recursively, then JSON.stringify. Order-independence is essential
/// or the chain would be falsely "tampered" by key-ordering differences.
function canonical(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
}

/// Compute the chained hash for a record. The record passed in must already have prevHash,
/// seq, ts and all event fields set; its own `hash` field is excluded from the digest.
export async function hashRecord(rec: Omit<AuditRecord, "hash">): Promise<string> {
  const material = `${rec.prevHash}|${canonical(rec)}`;
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(material));
  return toHex(digest);
}

/// The append-only writer. One instance per chain (per filespace/org, matching the DO).
export class AuditLog {
  constructor(private store: AuditStore) {}

  /// Seal + append an event. Returns the sealed record (also useful as the API response).
  /// `now` injectable for deterministic tests.
  async write(event: AuditEvent, now: number = Date.now()): Promise<AuditRecord> {
    const prev = await this.store.tail();
    const prevHash = prev ? prev.hash : GENESIS_HASH;
    const seq = prev ? prev.seq + 1 : 0;
    const unsealed: Omit<AuditRecord, "hash"> = { ...event, seq, ts: now, prevHash };
    const hash = await hashRecord(unsealed);
    const rec: AuditRecord = { ...unsealed, hash };
    await this.store.append(rec);
    return rec;
  }

  query(filter: AuditQuery): Promise<AuditRecord[]> | AuditRecord[] {
    return this.store.query(filter);
  }
}

export interface ChainVerifyResult {
  ok: boolean;
  /// 1-based count of records checked.
  checked: number;
  /// On failure: the seq of the first record whose chain/hash is invalid.
  brokenAtSeq?: number;
  reason?: string;
}

/// Re-derive every hash and confirm the chain is intact (no insert/delete/edit/reorder).
/// Records must be supplied in ascending seq order (a full-chain dump).
export async function verifyChain(records: AuditRecord[]): Promise<ChainVerifyResult> {
  let expectedPrev = GENESIS_HASH;
  let expectedSeq = 0;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    if (r.seq !== expectedSeq) {
      return { ok: false, checked: i, brokenAtSeq: r.seq, reason: "seq gap or reorder" };
    }
    if (r.prevHash !== expectedPrev) {
      return { ok: false, checked: i, brokenAtSeq: r.seq, reason: "prevHash mismatch" };
    }
    const { hash, ...unsealed } = r;
    const recomputed = await hashRecord(unsealed);
    if (recomputed !== hash) {
      return { ok: false, checked: i, brokenAtSeq: r.seq, reason: "hash mismatch (record edited)" };
    }
    expectedPrev = r.hash;
    expectedSeq += 1;
  }
  return { ok: true, checked: records.length };
}

/// Render records as NDJSON (SPEC §4.8: structured NDJSON shippable to OpenSearch/SIEM).
export function toNdjson(records: AuditRecord[]): string {
  return records.map((r) => JSON.stringify(r)).join("\n");
}

// ---- in-memory store (tests + ephemeral buffering before flush to DO/SIEM) -----------

export class InMemoryAuditStore implements AuditStore {
  private records: AuditRecord[] = [];

  tail(): AuditRecord | null {
    return this.records.length ? this.records[this.records.length - 1] : null;
  }

  append(rec: AuditRecord): void {
    this.records.push(rec);
  }

  query(filter: AuditQuery): AuditRecord[] {
    // Newest-first (seq DESC) so the reader/page-back contract (CONTRACTS §5.4)
    // holds: `cursor` is an EXCLUSIVE upper bound on seq, and `limit` keeps the
    // newest rows of the window (not the oldest).
    let out = this.records.filter((r) => {
      if (filter.orgId !== undefined && r.orgId !== filter.orgId) return false;
      if (filter.spaceId !== undefined && r.spaceId !== filter.spaceId) return false;
      if (filter.actorSub !== undefined && r.actorSub !== filter.actorSub) return false;
      if (filter.action !== undefined && r.action !== filter.action) return false;
      if (filter.decision !== undefined && r.decision !== filter.decision) return false;
      if (filter.since !== undefined && r.ts < filter.since) return false;
      if (filter.until !== undefined && r.ts > filter.until) return false;
      if (filter.cursor !== undefined && r.seq >= filter.cursor) return false;
      return true;
    });
    out.sort((a, b) => b.seq - a.seq);
    if (filter.limit !== undefined) out = out.slice(0, filter.limit);
    return out;
  }

  /// Test/inspection helper: the full chain in order.
  all(): AuditRecord[] {
    return [...this.records];
  }
}
