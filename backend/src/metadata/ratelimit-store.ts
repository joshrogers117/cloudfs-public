// SPDX-License-Identifier: AGPL-3.0-or-later
/// SQLite-backed `RateLimitStore` (security/ratelimit.ts) over the FilespaceDO's
/// storage. The DO is the single consistent token-bucket counter for its own
/// (org, space) — so a fleet of Worker isolates share ONE counter per space
/// instead of each enforcing its own loose per-isolate cap (closes the
/// "global rate-limit DO" loose end for the per-space presign/mutation classes).
///
/// We do NOT reimplement the bucket math — `RateLimiter`/`consume()` own it; this
/// only supplies durable persistence. Reads/writes are synchronous (DO SQLite),
/// which satisfies the (sync | async) `RateLimitStore` interface.
///
/// ATOMICITY (Finding 6): `RateLimiter.check` falls back to a racy
/// get→compute→set when a store exposes only `get`/`set`. Although a single DO is
/// single-threaded, the two RPCs cross the isolate boundary as SEPARATE awaits, so
/// two concurrent inbound RPCs could each `get` the same prior tokens and both
/// admit — burst-boundary over-admit. We therefore also expose an ATOMIC
/// `consume()` that runs SELECT→consume→upsert in ONE synchronous DO method body
/// (mirrors the already-correct DirectoryDO.consumeRateBucket); `RateLimiter.check`
/// prefers it. The bucket math stays delegated to the shared `consume()`.

import { consume, type BucketState, type RateLimitConfig, type RateLimitResult, type RateLimitStore } from "../security/ratelimit";

export class DoRateLimitStore implements RateLimitStore {
  constructor(private readonly sql: SqlStorage) {}

  get(key: string): BucketState | null {
    const r = this.sql.exec(`SELECT tokens, updated_at FROM rate_buckets WHERE key = ?;`, key).toArray()[0];
    return r ? { tokens: Number(r.tokens), updatedAt: Number(r.updated_at) } : null;
  }

  set(key: string, state: BucketState): void {
    this.sql.exec(
      `INSERT INTO rate_buckets (key, tokens, updated_at) VALUES (?,?,?)
       ON CONFLICT(key) DO UPDATE SET tokens = excluded.tokens, updated_at = excluded.updated_at;`,
      key, state.tokens, state.updatedAt,
    );
  }

  /// ATOMIC check-and-consume: SELECT → token-bucket math → upsert in one
  /// synchronous body (no `await` splits the SELECT from the upsert), so two
  /// concurrent inbound RPCs can't both read the same prior tokens and over-admit
  /// at the burst boundary. `async` only to satisfy the store interface's
  /// `Promise`-typed `consume` hook — the body itself never yields. Math is
  /// delegated to the shared `consume()` (single source of truth).
  async consume(key: string, config: RateLimitConfig, cost: number, now: number): Promise<RateLimitResult> {
    const prior = this.get(key);
    const { result, next } = consume(prior, config, cost, now);
    this.set(key, next);
    return result;
  }
}
