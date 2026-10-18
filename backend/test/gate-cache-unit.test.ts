// SPDX-License-Identifier: AGPL-3.0-or-later
// gate-cache-unit.test.ts — unit coverage for the gate-cache primitives (B21). Deterministic, no DO:
//   - a cache HIT elides the loader (the loader is the cross-DO read we're trying to avoid)
//   - the TTL is a CEILING: a hit past expiry re-runs the loader
//   - invalidation drops the entry so the very next read re-runs the loader (the stale-authz guard)
//   - an ERRORED jti read is NOT cached (so the gate keeps re-checking a flaky AuthDO)

import { describe, it, expect, beforeEach } from "vitest";
import {
  cachedAccountInactive,
  cachedJtiRevoked,
  cachedAclPrincipal,
  cachedSpaceRegistry,
  invalidateUser,
  invalidateJti,
  invalidateSpace,
  invalidateOrgAcl,
  __resetGateCachesForTest,
  GATE_CACHE_TTL_MS,
} from "../src/gate-cache";

beforeEach(() => __resetGateCachesForTest());

describe("gate-cache (B21) — hit/miss/expiry/invalidation", () => {
  it("a hit within the TTL elides the loader", async () => {
    let calls = 0;
    const load = async () => { calls++; return true; };
    expect(await cachedAccountInactive("org", "u", load, 1000)).toBe(true);
    expect(await cachedAccountInactive("org", "u", load, 1500)).toBe(true); // < TTL → cached
    expect(calls).toBe(1);
  });

  it("the TTL is a ceiling — a read past expiry re-runs the loader", async () => {
    let calls = 0;
    const load = async () => { calls++; return calls === 1; }; // first call true, then false
    expect(await cachedAccountInactive("org", "u", load, 1000)).toBe(true);
    // Past the TTL: the cache must re-read the LIVE value (now false).
    expect(await cachedAccountInactive("org", "u", load, 1000 + GATE_CACHE_TTL_MS + 1)).toBe(false);
    expect(calls).toBe(2);
  });

  it("invalidateUser forces the next account-status + ACL reads to re-run (stale-authz guard)", async () => {
    let statusCalls = 0;
    let aclCalls = 0;
    await cachedAccountInactive("org", "u", async () => { statusCalls++; return false; }, 1000);
    await cachedAclPrincipal("org", "u", async () => { aclCalls++; return { groupIds: [], orgRole: "admin" }; }, 1000);
    invalidateUser("org", "u");
    await cachedAccountInactive("org", "u", async () => { statusCalls++; return true; }, 1100);
    const acl = await cachedAclPrincipal("org", "u", async () => { aclCalls++; return { groupIds: [], orgRole: "standard" }; }, 1100);
    expect(statusCalls).toBe(2);
    expect(aclCalls).toBe(2);
    expect(acl.orgRole).toBe("standard"); // the LIVE (downgraded) role, not the cached admin
  });

  it("invalidateJti drops only the named jti's decision", async () => {
    let a = 0, b = 0;
    await cachedJtiRevoked("org", "jtiA", async () => { a++; return { revoked: false, errored: false }; }, 1000);
    await cachedJtiRevoked("org", "jtiB", async () => { b++; return { revoked: false, errored: false }; }, 1000);
    invalidateJti("org", "jtiA");
    await cachedJtiRevoked("org", "jtiA", async () => { a++; return { revoked: true, errored: false }; }, 1100);
    await cachedJtiRevoked("org", "jtiB", async () => { b++; return { revoked: false, errored: false }; }, 1100); // still cached
    expect(a).toBe(2); // re-read after invalidation
    expect(b).toBe(1); // untouched
  });

  it("an errored jti read is NOT cached (the gate keeps re-checking a flaky AuthDO)", async () => {
    let calls = 0;
    const flaky = async () => { calls++; return { revoked: false, errored: true }; };
    await cachedJtiRevoked("org", "j", flaky, 1000);
    await cachedJtiRevoked("org", "j", flaky, 1001); // same window, but the errored read wasn't cached
    expect(calls).toBe(2);
  });

  it("invalidateSpace drops the cached registry row (soft-delete bites immediately)", async () => {
    let calls = 0;
    await cachedSpaceRegistry("org", "sp", async () => { calls++; return { deletedAt: null }; }, 1000);
    invalidateSpace("org", "sp");
    const after = await cachedSpaceRegistry("org", "sp", async () => { calls++; return { deletedAt: 12345 }; }, 1100);
    expect(calls).toBe(2);
    expect(after?.deletedAt).toBe(12345); // the LIVE tombstone, not the cached live row
  });

  it("invalidateOrgAcl drops the whole org's ACL principals but leaves other orgs", async () => {
    let a = 0, b = 0;
    await cachedAclPrincipal("orgA", "u", async () => { a++; return { groupIds: [], orgRole: "admin" }; }, 1000);
    await cachedAclPrincipal("orgB", "u", async () => { b++; return { groupIds: [], orgRole: "admin" }; }, 1000);
    invalidateOrgAcl("orgA");
    await cachedAclPrincipal("orgA", "u", async () => { a++; return { groupIds: [], orgRole: "standard" }; }, 1100);
    await cachedAclPrincipal("orgB", "u", async () => { b++; return { groupIds: [], orgRole: "admin" }; }, 1100);
    expect(a).toBe(2); // orgA re-read
    expect(b).toBe(1); // orgB untouched
  });
});
