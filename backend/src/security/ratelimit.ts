// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs rate limiting: per-principal / per-IP token-bucket (SPEC §5 abuse defense).
///
/// Threat: the gateway mints presigned URLs and mutates the metadata DO. An abusive or
/// compromised client could (a) hammer presign minting to enumerate/scrape the bucket, or
/// (b) flood DO mutations to exhaust the single-threaded FilespaceDO. We cap request rate
/// per identity BEFORE either of those privileged actions runs.
///
/// Algorithm: classic token bucket — `capacity` tokens, refilled at `refillPerSec`. Each
/// request costs `cost` tokens (default 1; presign mints can cost more). Bucket allows
/// short bursts (up to capacity) while bounding the sustained rate. Lazy refill: we compute
/// the accrual on read from a stored timestamp, so no background timer is needed (ideal for
/// Workers/DO where wall-clock ticks aren't free).
///
/// State: pluggable via `RateLimitStore`. In-memory is correct for a single isolate; for
/// GLOBAL limits across the fleet, back it with a Durable Object (one DO = one consistent
/// counter). See security-INTEGRATION.md. The math here is store-independent.

export interface BucketState {
  /// Fractional tokens currently available.
  tokens: number;
  /// ms-epoch of the last refill computation.
  updatedAt: number;
}

export interface RateLimitConfig {
  /// Max burst size (tokens). Also the starting fill.
  capacity: number;
  /// Steady-state refill rate.
  refillPerSec: number;
}

export interface RateLimitResult {
  allowed: boolean;
  /// Tokens left after this request (clamped >= 0), for X-RateLimit-Remaining.
  remaining: number;
  /// When denied: whole seconds the caller should wait before retrying (Retry-After).
  retryAfterSec: number;
  /// Echo of the limit for headers.
  limit: number;
}

/// Pure function: given prior state + config + now + cost, decide and return next state.
/// Exported for unit testing and for any custom store wiring. Never mutates inputs.
export function consume(
  prior: BucketState | null,
  config: RateLimitConfig,
  cost: number,
  now: number,
): { result: RateLimitResult; next: BucketState } {
  const { capacity, refillPerSec } = config;
  let tokens = prior ? prior.tokens : capacity;
  const last = prior ? prior.updatedAt : now;

  // Lazy refill, clamped to capacity. Guard against clock going backwards.
  const elapsedMs = Math.max(0, now - last);
  tokens = Math.min(capacity, tokens + (elapsedMs / 1000) * refillPerSec);

  const want = Math.max(0, cost);
  if (tokens >= want) {
    tokens -= want;
    return {
      result: { allowed: true, remaining: Math.floor(tokens), retryAfterSec: 0, limit: capacity },
      next: { tokens, updatedAt: now },
    };
  }

  // Denied: estimate wait until enough tokens accrue. refillPerSec<=0 => effectively forever.
  const deficit = want - tokens;
  const retryAfterSec = refillPerSec > 0 ? Math.ceil(deficit / refillPerSec) : Number.MAX_SAFE_INTEGER;
  return {
    result: { allowed: false, remaining: Math.floor(tokens), retryAfterSec, limit: capacity },
    next: { tokens, updatedAt: now }, // state still advances (records the refill)
  };
}

/// Pluggable persistence for bucket state, keyed by limiter-key (e.g. `principal:<sub>`).
///
/// ATOMICITY: `RateLimiter.check` does get → compute → set. For an IN-MEMORY store inside a single
/// isolate that triple is atomic (no `await` boundary crosses isolates). But for a store whose
/// `get`/`set` are SEPARATE network round-trips to a shared backend (e.g. the DirectoryDO), two
/// isolates can each `get` the same prior state before either `set`s — and both admit, OVER-ADMITTING
/// at the burst boundary (the review flagged this). The optional `consume` hook closes that gap: a
/// store that can run get→compute→set as ONE atomic backend operation implements it, and `check`
/// prefers it. The bucket math (`consume()` above) is the single source of truth either way.
export interface RateLimitStore {
  get(key: string): Promise<BucketState | null> | BucketState | null;
  set(key: string, state: BucketState): Promise<void> | void;
  /// OPTIONAL atomic check-and-consume. When present, `RateLimiter.check` uses THIS instead of the
  /// non-atomic get→compute→set, so concurrent callers across isolates can't over-admit at the
  /// burst boundary. Implementers MUST apply the SAME token-bucket math as `consume()` (typically by
  /// calling it) inside a single serialized backend operation, and return its `result`.
  consume?(key: string, config: RateLimitConfig, cost: number, now: number): Promise<RateLimitResult>;
}

/// The limiter. One config per "class" of limit (e.g. one for presign, one for general).
export class RateLimiter {
  constructor(
    private store: RateLimitStore,
    private config: RateLimitConfig,
  ) {}

  /// Check + consume `cost` tokens for `key`. `now` injectable for tests. Uses the store's ATOMIC
  /// `consume` when available (no burst-boundary over-admit across isolates); otherwise falls back
  /// to get→compute→set (correct for a single-isolate in-memory store).
  async check(key: string, cost = 1, now: number = Date.now()): Promise<RateLimitResult> {
    if (this.store.consume) {
      return this.store.consume(key, this.config, cost, now);
    }
    const prior = await this.store.get(key);
    const { result, next } = consume(prior, this.config, cost, now);
    await this.store.set(key, next);
    return result;
  }
}

/// Derive a stable limiter key. Prefer the authenticated principal (fair + abuse-resistant);
/// fall back to client IP for pre-auth endpoints (login, guest-code exchange).
export function principalKey(sub: string): string {
  return `p:${sub}`;
}

/// Best-effort client IP for Workers. Cloudflare populates `CF-Connecting-IP`; we never
/// trust a client-supplied `X-Forwarded-For` for limiting (spoofable). Returns "unknown"
/// if no trusted header is present — callers may choose to fail-closed on pre-auth routes.
export function ipKey(req: Request): string {
  const ip = req.headers.get("cf-connecting-ip") ?? "unknown";
  return `ip:${ip}`;
}

/// Attach standard rate-limit headers to a response (or build a 429).
export function rateLimitHeaders(r: RateLimitResult): Record<string, string> {
  const h: Record<string, string> = {
    "X-RateLimit-Limit": String(r.limit),
    "X-RateLimit-Remaining": String(Math.max(0, r.remaining)),
  };
  if (!r.allowed) h["Retry-After"] = String(r.retryAfterSec);
  return h;
}

/// Convenience: a 429 Response when `check` denies. Gateway returns this before any
/// privileged work (presign mint / DO mutation).
export function tooManyRequests(r: RateLimitResult): Response {
  return new Response(JSON.stringify({ error: "rate_limited", retryAfterSec: r.retryAfterSec }), {
    status: 429,
    headers: { "content-type": "application/json", ...rateLimitHeaders(r) },
  });
}

// ---- in-memory store (single-isolate limits + tests) ---------------------------------

export class InMemoryRateLimitStore implements RateLimitStore {
  private map = new Map<string, BucketState>();

  get(key: string): BucketState | null {
    return this.map.get(key) ?? null;
  }

  set(key: string, state: BucketState): void {
    this.map.set(key, state);
  }
}
