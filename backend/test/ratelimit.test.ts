// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import {
  RateLimiter,
  InMemoryRateLimitStore,
  consume,
  principalKey,
  ipKey,
  rateLimitHeaders,
  tooManyRequests,
  type BucketState,
  type RateLimitStore,
  type RateLimitConfig,
  type RateLimitResult,
} from "../src/security/ratelimit";

describe("token-bucket consume() (pure)", () => {
  const cfg = { capacity: 10, refillPerSec: 1 };

  it("starts full and allows up to capacity in a burst", () => {
    let state: BucketState | null = null;
    const now = 1000;
    for (let i = 0; i < 10; i++) {
      const { result, next } = consume(state, cfg, 1, now);
      expect(result.allowed).toBe(true);
      state = next;
    }
    // 11th in the same instant is denied
    const { result } = consume(state, cfg, 1, now);
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfterSec).toBe(1); // 1 token/sec
  });

  it("refills lazily over elapsed time", () => {
    // drain fully at t=0
    let state: BucketState = { tokens: 0, updatedAt: 0 };
    // after 5s, 5 tokens accrued
    const { result, next } = consume(state, cfg, 5, 5000);
    expect(result.allowed).toBe(true);
    expect(next.tokens).toBeCloseTo(0, 5);
  });

  it("clamps refill at capacity (no infinite accrual)", () => {
    const state: BucketState = { tokens: 0, updatedAt: 0 };
    // 1000s later would be 1000 tokens, but capacity is 10
    const { next } = consume(state, cfg, 0, 1_000_000);
    expect(next.tokens).toBeLessThanOrEqual(10);
  });

  it("supports weighted cost (expensive presign mints)", () => {
    const state: BucketState = { tokens: 10, updatedAt: 0 };
    const { result, next } = consume(state, cfg, 4, 0);
    expect(result.allowed).toBe(true);
    expect(next.tokens).toBeCloseTo(6, 5);
  });

  it("denies and computes retryAfter when cost exceeds available", () => {
    const state: BucketState = { tokens: 2, updatedAt: 0 };
    const { result } = consume(state, { capacity: 10, refillPerSec: 2 }, 6, 0);
    expect(result.allowed).toBe(false);
    // deficit 4 tokens / 2 per sec = 2s
    expect(result.retryAfterSec).toBe(2);
  });

  it("handles a backwards clock without granting free tokens", () => {
    const state: BucketState = { tokens: 3, updatedAt: 10_000 };
    const { next } = consume(state, cfg, 0, 5_000); // now < updatedAt
    expect(next.tokens).toBeCloseTo(3, 5); // no negative elapsed accrual
  });
});

describe("RateLimiter (stateful, store-backed)", () => {
  it("enforces per-key limits independently", async () => {
    const limiter = new RateLimiter(new InMemoryRateLimitStore(), { capacity: 3, refillPerSec: 1 });
    const now = 1000;
    expect((await limiter.check("p:alice", 1, now)).allowed).toBe(true);
    expect((await limiter.check("p:alice", 1, now)).allowed).toBe(true);
    expect((await limiter.check("p:alice", 1, now)).allowed).toBe(true);
    expect((await limiter.check("p:alice", 1, now)).allowed).toBe(false); // alice drained

    // bob has his own bucket, unaffected
    expect((await limiter.check("p:bob", 1, now)).allowed).toBe(true);
  });

  it("recovers after the refill window", async () => {
    const limiter = new RateLimiter(new InMemoryRateLimitStore(), { capacity: 1, refillPerSec: 1 });
    expect((await limiter.check("p:c", 1, 0)).allowed).toBe(true);
    expect((await limiter.check("p:c", 1, 0)).allowed).toBe(false);
    expect((await limiter.check("p:c", 1, 1000)).allowed).toBe(true); // 1s later, 1 token back
  });

  it("prefers the store's ATOMIC consume() when present (no non-atomic get→set)", async () => {
    // Closes the burst-boundary over-admit: a store with a single atomic check-and-consume must be
    // used by RateLimiter.check INSTEAD of the get→compute→set pair. We assert get/set are never
    // called when consume() exists, and that consume()'s result is what flows back.
    const events: string[] = [];
    const atomicStore: RateLimitStore = {
      get() {
        events.push("get");
        return null;
      },
      set() {
        events.push("set");
      },
      consume(key: string, config: RateLimitConfig, cost: number, now: number): Promise<RateLimitResult> {
        events.push(`consume:${key}`);
        // Delegate to the shared bucket math (single source of truth), as the DO impl does.
        return Promise.resolve(consume(null, config, cost, now).result);
      },
    };
    const limiter = new RateLimiter(atomicStore, { capacity: 2, refillPerSec: 1 });
    const r = await limiter.check("p:atomic", 1, 1000);
    expect(r.allowed).toBe(true);
    expect(events).toEqual(["consume:p:atomic"]); // ONLY the atomic path — never get/set.
  });
});

describe("key derivation + headers", () => {
  it("builds principal and IP keys", () => {
    expect(principalKey("member-123")).toBe("p:member-123");
    const req = new Request("https://gw.local/x", { headers: { "cf-connecting-ip": "203.0.113.9" } });
    expect(ipKey(req)).toBe("ip:203.0.113.9");
  });

  it("does not trust spoofable X-Forwarded-For", () => {
    const req = new Request("https://gw.local/x", { headers: { "x-forwarded-for": "1.2.3.4" } });
    expect(ipKey(req)).toBe("ip:unknown");
  });

  it("emits standard rate-limit headers, including Retry-After when denied", () => {
    const allow = rateLimitHeaders({ allowed: true, remaining: 5, retryAfterSec: 0, limit: 10 });
    expect(allow["X-RateLimit-Remaining"]).toBe("5");
    expect(allow["Retry-After"]).toBeUndefined();

    const deny = rateLimitHeaders({ allowed: false, remaining: 0, retryAfterSec: 3, limit: 10 });
    expect(deny["Retry-After"]).toBe("3");
  });

  it("builds a 429 response", async () => {
    const res = tooManyRequests({ allowed: false, remaining: 0, retryAfterSec: 2, limit: 10 });
    expect(res.status).toBe(429);
    expect(res.headers.get("Retry-After")).toBe("2");
    const body = (await res.json()) as any;
    expect(body.error).toBe("rate_limited");
  });
});
