// SPDX-License-Identifier: AGPL-3.0-or-later
// Version handshake (Audit): the backend advertises its wire-contract version on the
// public /v1/health body (`apiVersion`) AND on every response via the
// `X-CloudFS-API-Version` header, so a client can detect skew (e.g. a pre-B17 client
// that still constructs path-derived inode ids) without an extra round-trip.
import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { API_VERSION } from "../src/api-version";

describe("version handshake", () => {
  it("GET /v1/health advertises ok + the current apiVersion", async () => {
    const res = await SELF.fetch("https://gw.local/v1/health");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; apiVersion: number };
    expect(body.ok).toBe(true);
    expect(body.apiVersion).toBe(API_VERSION);
  });

  it("verified immutable uploads pin the wire contract at v3", () => {
    // A guard so a careless bump of API_VERSION without a wire-contract change is caught.
    expect(API_VERSION).toBe(3);
  });

  it("every response carries the X-CloudFS-API-Version header", async () => {
    // public route
    const health = await SELF.fetch("https://gw.local/v1/health");
    expect(health.headers.get("X-CloudFS-API-Version")).toBe(String(API_VERSION));
    // an authed route that 401s (no token) still gets stamped — a client can detect
    // version skew even before it has a valid token.
    const unauthed = await SELF.fetch("https://gw.local/v1/orgs/studio/spaces");
    expect(unauthed.status).toBe(401);
    expect(unauthed.headers.get("X-CloudFS-API-Version")).toBe(String(API_VERSION));
  });
});
