// SPDX-License-Identifier: AGPL-3.0-or-later
/// Advisory lock / lease manager (SPEC §5.5, §4.9).
///
/// Gateway-brokered advisory leases are our differentiator. Hardening over the
/// v1 prototype:
///   - TTL leases with auto-expiry sweep (crashed-client safety).
///   - Fencing tokens: a monotonic counter per grant. The data plane / writer
///     must present its fence; a holder whose lease expired and was re-granted to
///     someone else carries a stale fence and is rejected — defeats the classic
///     "zombie process writes after its lease expired" hazard (Kleppmann).
///   - Idempotent re-acquire: the same owner re-acquiring renews and KEEPS its
///     fence (so a retried request is a no-op, not a new token).
///   - Typed conflict responses so the client can render "locked by Bob".
///   - earliestExpiry() so the DO can arm an alarm to proactively reap leases.

import type { LockMode, LockPurpose, LockResult } from "./types";

interface LockRow {
  path: string;
  owner: string;
  mode: string;
  purpose: string;
  fence: number;
  acquired_at: number;
  expires_at: number;
}

export class LockManager {
  constructor(
    private readonly sql: SqlStorage,
    private readonly nextFence: () => number,
  ) {}

  private sweep(now: number): void {
    this.sql.exec(`DELETE FROM locks WHERE expires_at <= ?;`, now);
  }

  private row(path: string): LockRow | undefined {
    const r = this.sql.exec(`SELECT * FROM locks WHERE path = ?;`, path).toArray()[0];
    return r as unknown as LockRow | undefined;
  }

  /// Acquire (or idempotently renew) a lease. Returns a fencing token on grant.
  acquire(path: string, owner: string, ttlMs: number, mode: LockMode = "exclusive", purpose: LockPurpose = "advisory"): LockResult {
    if (purpose === "publication" && mode !== "exclusive") return {granted:false,path,reason:"purpose-mismatch"};
    const now = Date.now();
    this.sweep(now);
    const existing = this.row(path);
    const expiresAt = now + ttlMs;

    if (existing) {
      if (String(existing.owner) === owner) {
        // Idempotent acquisition cannot promote an advisory lease to
        // publication (or relabel a publication lease as advisory).
        if (existing.purpose !== purpose) return {granted:false,path,heldBy:owner,mode:existing.mode as LockMode,purpose:existing.purpose as LockPurpose,reason:"purpose-mismatch"};
        // Idempotent renew — keep the SAME fence so retries don't churn tokens.
        this.sql.exec(`UPDATE locks SET expires_at=?, mode=? WHERE path=?;`, expiresAt, mode, path);
        return { granted: true, path, owner, mode, purpose: existing.purpose as LockPurpose, fence: Number(existing.fence), expiresAt };
      }
      // Finding 1: a held shared lock + a DIFFERENT shared requester must NOT
      // overwrite the incumbent. The single-row schema (locks.path PRIMARY KEY)
      // can hold only one (owner, fence) per path, so true multi-holder
      // co-tenancy needs a composite-key schema change we can't make here.
      // Until then we REJECT the second shared owner with the standard typed
      // conflict instead of replacing the prior holder's owner+fence — the old
      // `UPDATE locks SET owner=?, fence=?` silently dropped the first holder's
      // lease and minted a fence that failed its validateFence()/renew(). The
      // incumbent's lease + fence are left fully intact by returning early.
      if (mode === "shared" && existing.mode === "shared") {
        return {
          granted: false,
          path,
          heldBy: String(existing.owner),
          mode: "shared",
          purpose: existing.purpose as LockPurpose,
          expiresAt: Number(existing.expires_at),
          reason: "held-by-other",
        };
      }
      return {
        granted: false,
        path,
        heldBy: String(existing.owner),
        mode: existing.mode as LockMode,
        purpose: existing.purpose as LockPurpose,
        expiresAt: Number(existing.expires_at),
        reason: "held-by-other",
      };
    }

    const fence = this.nextFence();
    this.sql.exec(
      `INSERT INTO locks (path,owner,mode,purpose,fence,acquired_at,expires_at) VALUES (?,?,?,?,?,?,?);`,
      path, owner, mode, purpose, fence, now, expiresAt,
    );
    return { granted: true, path, owner, mode, purpose, fence, expiresAt };
  }

  /// Renew a held lease. Requires the matching fence (rejects a stale holder
  /// whose lease was reassigned). Returns the conflict reason on failure.
  renew(path: string, owner: string, fence: number, ttlMs: number): LockResult {
    const now = Date.now();
    this.sweep(now);
    const existing = this.row(path);
    if (!existing) return { granted: false, path, reason: "not-found" };
    if (String(existing.owner) !== owner) {
      return { granted: false, path, heldBy: String(existing.owner), reason: "held-by-other" };
    }
    if (Number(existing.fence) !== fence) {
      return { granted: false, path, fence: Number(existing.fence), reason: "fence-stale" };
    }
    const expiresAt = now + ttlMs;
    this.sql.exec(`UPDATE locks SET expires_at=? WHERE path=?;`, expiresAt, path);
    return { granted: true, path, owner, mode: existing.mode as LockMode, purpose: existing.purpose as LockPurpose, fence, expiresAt };
  }

  release(path: string, owner: string, fence?: number): { released: boolean; reason?: string } {
    const existing = this.row(path);
    if (!existing) return { released: true }; // idempotent
    if (String(existing.owner) !== owner) return { released: false, reason: "not lock owner" };
    if (fence !== undefined && Number(existing.fence) !== fence) return { released: false, reason: "fence-stale" };
    this.sql.exec(`DELETE FROM locks WHERE path = ?;`, path);
    return { released: true };
  }

  status(path: string): LockResult {
    const now = Date.now();
    this.sweep(now);
    const existing = this.row(path);
    if (!existing) return { granted: false, path, reason: "not-found" };
    return {
      granted: true,
      path,
      heldBy: String(existing.owner),
      mode: existing.mode as LockMode,
      purpose: existing.purpose as LockPurpose,
      fence: Number(existing.fence),
      expiresAt: Number(existing.expires_at),
    };
  }

  /// Validate a fence for a write — the data-plane gate. A writer presenting a
  /// stale/expired fence is rejected so its bytes never land.
  validateFence(path: string, fence: number, owner?: string): boolean {
    const now = Date.now();
    this.sweep(now);
    const existing = this.row(path);
    return !!existing && existing.mode === "exclusive" && Number(existing.fence) === fence && Number(existing.expires_at) > now && (owner === undefined || existing.owner === owner);
  }

  /// Earliest lease expiry, so the DO can arm an alarm to reap on time.
  earliestExpiry(): number | null {
    const r = this.sql.exec(`SELECT MIN(expires_at) AS e FROM locks;`).toArray()[0];
    return r && r.e !== null ? Number(r.e) : null;
  }

  /// Proactive sweep callable from the alarm handler.
  reapExpired(now = Date.now()): number {
    const before = Number(this.sql.exec(`SELECT COUNT(*) AS c FROM locks;`).one().c);
    this.sweep(now);
    const after = Number(this.sql.exec(`SELECT COUNT(*) AS c FROM locks;`).one().c);
    return before - after;
  }
}
