// SPDX-License-Identifier: AGPL-3.0-or-later
// gate-cache-b21-b22.test.ts — regression suite for the P2-EFFICIENCY gate-hardening pass:
//
//   B21 — per-isolate TTL cache on the SECURITY-CRITICAL pre-flight gate (revoked-jti point query,
//         account-active status, space-registry row, groups/role). The proof that matters is NOT
//         "the cache makes it faster" (hard to assert deterministically) but "the cache NEVER serves
//         stale AUTHORIZATION across a revoke/offboarding/space-delete". Each test below warms the
//         cache with an ALLOW, performs the revoking write through the SAME gateway path that owns
//         the invalidation, then asserts the very NEXT request is DENIED — i.e. the TTL is a ceiling,
//         never a stale-authz hole.
//
//   B22 — deny-path audits run via waitUntil; the success-path audit stays inline+durable. We assert
//         a denied op STILL lands its audit record (waitUntil keeps it alive) and the chain verifies.
//
//   B16 — presigned PUT pins content-length (signed into the URL) + the per-folder ACL runs on a
//         not-yet-owned key when the client declares the target `itemId`.
//
// All tests drive the REAL Worker via SELF.fetch (the gateway gate), not a mock — per the working
// agreement (a real-gateway/integration test per gate/presign change, NOT mock-only).

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { mintToken, filespaceDoName, type Scope } from "../src/security/auth";
import { verifyChain, type AuditRecord } from "../src/security/audit";
import { __resetGateCachesForTest } from "../src/gate-cache";

const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];
const SECRET = (env as any).AUTH_SIGNING_SECRET as string;
const ORIGIN = "https://gw.local";

const runInDo = runInDurableObject as unknown as <R>(s: unknown, cb: (inst: any) => R | Promise<R>) => Promise<R>;

let counter = 0;
function freshOrg(): string {
  return `gc-org-${Date.now()}-${counter++}`;
}

async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
  const u = await org.createUser({ orgId, email: `${role}-${crypto.randomUUID()}@test.local`, displayName: role, role });
  return u.id;
}
async function tokenFor(orgId: string, sub: string, scopes: Scope[] = ALL_SCOPES): Promise<string> {
  return mintToken(SECRET, { sub, type: "session", orgId, scopes, ttlSeconds: 900 });
}
function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, "content-type": "application/json" };
}
async function registerSpace(orgId: string, spaceId: string): Promise<void> {
  const stub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
  await stub.registerSpace({ spaceId, orgId, name: `Space ${spaceId}`, bucketProvider: "r2", bucketName: "bkt", keyPrefix: "p/" });
}
function fsUrl(spaceId: string, path: string): string {
  return `${ORIGIN}/v1/filespaces/${spaceId}${path}`;
}

// ============================================================================================
// B21 — cache is a CEILING, never a stale-authz hole (the security-critical property).
// ============================================================================================
describe("B21 — per-isolate gate cache never serves stale authorization", () => {
  it("a space soft-delete invalidates the cached registry row — the next presign is 410, not a stale 200", async () => {
    __resetGateCachesForTest();
    const orgId = freshOrg();
    const spaceId = "gc-space-del";
    await registerSpace(orgId, spaceId);
    const ownerTok = await tokenFor(orgId, await provisionUser(orgId, "owner"));

    // WARM the space-registry cache with a successful presign (the gate reads + caches the live,
    // not-deleted registry row).
    const warm = await SELF.fetch(fsUrl(spaceId, "/presign"), {
      method: "POST", headers: authHeaders(ownerTok),
      body: JSON.stringify({ key: `blocks/${orgId}::${spaceId}/obj`, method: "PUT" }),
    });
    expect(warm.status).toBe(200);

    // Soft-delete THROUGH the gateway DELETE (which calls invalidateSpace).
    const del = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/spaces/${spaceId}`, { method: "DELETE", headers: authHeaders(ownerTok) });
    expect(del.status).toBe(200);

    // The very next presign must 410 — the cached "live" row was invalidated, not served until TTL.
    const after = await SELF.fetch(fsUrl(spaceId, "/presign"), {
      method: "POST", headers: authHeaders(ownerTok),
      body: JSON.stringify({ key: `blocks/${orgId}::${spaceId}/obj`, method: "PUT" }),
    });
    expect(after.status).toBe(410);
    expect(((await after.json()) as any).error).toBe("filespace_deleted");
  });

  it("offboarding a user invalidates the cached account-status — the next request is 401 account_inactive, not a stale 200", async () => {
    __resetGateCachesForTest();
    const orgId = freshOrg();
    const spaceId = "gc-space-off";
    await registerSpace(orgId, spaceId);
    // An admin (does the offboarding) and a standard victim with a live session. The victim needs an
    // AuthDO account (the live-status gate reads AuthDO, not the OrgDO directory row), so create one.
    const adminTok = await tokenFor(orgId, await provisionUser(orgId, "admin"));
    const victimId = await provisionUser(orgId, "standard");
    const authStub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(orgId));
    await authStub.createAccount({ orgId, userId: victimId, email: `victim-${crypto.randomUUID()}@test.local`, displayName: "victim", role: "standard", emailVerified: true });
    const victimTok = await tokenFor(orgId, victimId);

    // WARM the victim's account-status cache (a GET that runs the gate) — caches "active".
    const warm = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/spaces`, { headers: authHeaders(victimTok) });
    expect(warm.status).toBe(200);

    // Offboard THROUGH the gateway PATCH (which calls propagateAccountOffboarding + invalidateUser).
    const patch = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/users/${victimId}`, {
      method: "PATCH", headers: authHeaders(adminTok), body: JSON.stringify({ status: "suspended" }),
    });
    expect(patch.status).toBe(200);

    // The victim's next request is rejected immediately — the cached "active" status was invalidated.
    const after = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/spaces`, { headers: authHeaders(victimTok) });
    expect(after.status).toBe(401);
    expect((await after.json() as any).error).toBe("account_inactive");
  });

  it("a role downgrade invalidates the cached ACL principal — the next admin-gated op reflects the new role", async () => {
    __resetGateCachesForTest();
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, await provisionUser(orgId, "owner"));
    const targetId = await provisionUser(orgId, "admin");
    const targetTok = await tokenFor(orgId, targetId);

    // WARM the target's ACL-principal cache: as an admin they can list invites (admin-gated).
    const warm = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/invites`, { headers: authHeaders(targetTok) });
    expect(warm.status).toBe(200);

    // Owner downgrades the target to `standard` THROUGH the gateway PATCH (calls invalidateUser).
    const patch = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/users/${targetId}`, {
      method: "PATCH", headers: authHeaders(ownerTok), body: JSON.stringify({ role: "standard" }),
    });
    expect(patch.status).toBe(200);

    // The next admin-gated op for the (now standard) target is forbidden — role change took effect
    // immediately, not after the cache TTL.
    const after = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/invites`, { headers: authHeaders(targetTok) });
    expect(after.status).toBe(403);
  });

  it("AuthDO.isJtiRevoked (B21 point query) checks BOTH sessions and service tokens", async () => {
    __resetGateCachesForTest();
    const orgId = freshOrg();
    const userId = await provisionUser(orgId, "standard");
    const authStub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(orgId));

    // A live (unrevoked) service token → not revoked.
    const liveJti = `svc-live-${crypto.randomUUID()}`;
    await authStub.createServiceToken({ id: liveJti, orgId, userId, label: "live", scopes: ["fs:read"], spaceId: null, hashedSecret: "x", createdByUserId: userId, createdAt: Date.now(), lastUsedAt: null, expiresAt: null, revoked: false });
    expect(await authStub.isJtiRevoked(liveJti)).toBe(false);

    // After revoke → revoked.
    await authStub.revokeServiceToken(liveJti);
    expect(await authStub.isJtiRevoked(liveJti)).toBe(true);

    // An entirely unknown jti is NOT revoked (absence ≠ revocation; the gate admits unknown jtis,
    // which is correct — an unknown jti is a freshly-minted, never-revoked credential).
    expect(await authStub.isJtiRevoked(`never-seen-${crypto.randomUUID()}`)).toBe(false);
  });

  it("revoking a service token invalidates its cached jti — the next request is 401 revoked, not a stale 200", async () => {
    __resetGateCachesForTest();
    const orgId = freshOrg();
    const spaceId = "gc-space-svc";
    await registerSpace(orgId, spaceId);
    const userId = await provisionUser(orgId, "standard");

    // Mint + persist a service token whose jti the gate checks against the AuthDO.
    const jti = `svc-${crypto.randomUUID()}`;
    const authStub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(orgId));
    await authStub.createServiceToken({
      id: jti, orgId, userId, label: "render", scopes: ["fs:read"], spaceId: null,
      hashedSecret: "x", createdByUserId: userId, createdAt: Date.now(), lastUsedAt: null, expiresAt: null, revoked: false,
    });
    const svcTok = await mintToken(SECRET, { sub: userId, type: "service", orgId, scopes: ["fs:read"], jti, ttlSeconds: 3600 });

    // WARM the jti cache with a successful read (the gate caches "not revoked").
    const warm = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/spaces`, { headers: { Authorization: `Bearer ${svcTok}` } });
    expect(warm.status).toBe(200);

    // Revoke the token THROUGH the AuthDO + invalidate its cached jti (mirrors the gateway revoke
    // route, which calls invalidateJti — we invalidate here since we created the token directly).
    await authStub.revokeServiceToken(jti);
    const { invalidateJti } = await import("../src/gate-cache");
    invalidateJti(orgId, jti);

    const after = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/spaces`, { headers: { Authorization: `Bearer ${svcTok}` } });
    expect(after.status).toBe(401);
    expect((await after.json() as any).error).toBe("revoked");
  });
});

// ============================================================================================
// B22 — deny-path audit deferral preserves durability + chain integrity.
// ============================================================================================
describe("B22 — deferred (waitUntil) deny audits still land durably + chain verifies", () => {
  it("a denied presign GET (no owning inode) records its deny audit and the chain stays intact", async () => {
    const orgId = freshOrg();
    const spaceId = "gc-space-audit";
    await registerSpace(orgId, spaceId);
    const adminTok = await tokenFor(orgId, await provisionUser(orgId, "admin"));

    // One allow (PUT) + one deny (GET on a non-existent object) + one allow (PUT).
    await SELF.fetch(fsUrl(spaceId, "/presign"), { method: "POST", headers: authHeaders(adminTok), body: JSON.stringify({ key: `blocks/${orgId}::${spaceId}/a`, method: "PUT" }) });
    const denied = await SELF.fetch(fsUrl(spaceId, "/presign"), { method: "POST", headers: authHeaders(adminTok), body: JSON.stringify({ key: `blocks/${orgId}::${spaceId}/missing`, method: "GET" }) });
    expect(denied.status).toBe(403);
    await SELF.fetch(fsUrl(spaceId, "/presign"), { method: "POST", headers: authHeaders(adminTok), body: JSON.stringify({ key: `blocks/${orgId}::${spaceId}/b`, method: "PUT" }) });

    // The DEFERRED deny audit landed durably (waitUntil keeps it alive) — query the deny feed.
    const denies = (await (await SELF.fetch(fsUrl(spaceId, "/audit?decision=deny&limit=1000"), { headers: authHeaders(adminTok) })).json()) as AuditRecord[];
    expect(denies.some((r) => r.action === "presign.mint" && r.decision === "deny")).toBe(true);

    // The full chain (allow + deny records interleaved) still verifies — no drop/fork from deferral.
    const all = (await (await SELF.fetch(fsUrl(spaceId, "/audit?limit=1000"), { headers: authHeaders(adminTok) })).json()) as AuditRecord[];
    const ordered = [...all].sort((a, b) => a.seq - b.seq);
    expect((await verifyChain(ordered)).ok).toBe(true);
  });
});

// ============================================================================================
// B16 — presigned PUT content-length pin + ACL on a declared (not-yet-owned) itemId.
// ============================================================================================
describe("B16 — presigned PUT pins content-length + ACLs a declared itemId", () => {
  it("a declared contentLength is signed into the PUT URL (signature binds it) and echoed back", async () => {
    const orgId = freshOrg();
    const spaceId = "gc-space-clen";
    await registerSpace(orgId, spaceId);
    const adminTok = await tokenFor(orgId, await provisionUser(orgId, "admin"));

    const res = await SELF.fetch(fsUrl(spaceId, "/presign"), {
      method: "POST", headers: authHeaders(adminTok),
      body: JSON.stringify({ key: `blocks/${orgId}::${spaceId}/sized`, method: "PUT", contentLength: 1048576 }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.contentLength).toBe(1048576);
    // The pinned length is folded into X-Amz-SignedHeaders (so the bucket enforces it).
    const url = new URL(body.url);
    expect((url.searchParams.get("X-Amz-SignedHeaders") ?? "").toLowerCase()).toContain("content-length");
  });

  it("an absurd/negative contentLength is rejected (400) — a client can't pin a garbage size", async () => {
    const orgId = freshOrg();
    const spaceId = "gc-space-badlen";
    await registerSpace(orgId, spaceId);
    const adminTok = await tokenFor(orgId, await provisionUser(orgId, "admin"));

    for (const bad of [-1, 6 * 1024 * 1024 * 1024, 1.5]) {
      const res = await SELF.fetch(fsUrl(spaceId, "/presign"), {
        method: "POST", headers: authHeaders(adminTok),
        body: JSON.stringify({ key: `blocks/${orgId}::${spaceId}/x`, method: "PUT", contentLength: bad }),
      });
      expect(res.status).toBe(400);
      expect((await res.json() as any).error).toBe("invalid_content_length");
    }
  });

  it("a PUT declaring an itemId the principal CANNOT write is denied at mint (ACL on a not-yet-owned key)", async () => {
    const orgId = freshOrg();
    const spaceId = "gc-space-itemacl";
    await registerSpace(orgId, spaceId);
    const adminTok = await tokenFor(orgId, await provisionUser(orgId, "admin"));

    // Admin creates a real item the standard user has NO grant on.
    const created = await SELF.fetch(fsUrl(spaceId, "/items"), {
      method: "POST", headers: authHeaders(adminTok), body: JSON.stringify({ parent: "root", name: "locked.mov", isDir: false }),
    });
    expect(created.status).toBe(201);
    const itemId = (await created.json() as any).id as string;

    // A STANDARD principal (fs:write scope, but ZERO ACL grant) declares that item on a PUT mint.
    const standardTok = await tokenFor(orgId, await provisionUser(orgId, "standard"), ["fs:write"]);
    const res = await SELF.fetch(fsUrl(spaceId, "/presign"), {
      method: "POST", headers: authHeaders(standardTok),
      body: JSON.stringify({ key: `blocks/${orgId}::${spaceId}/content`, method: "PUT", itemId }),
    });
    // Without B16 this would 200 (PUT to an unowned content-addressed key skipped the ACL); now the
    // declared itemId is ACL-checked and the unprivileged principal is forbidden.
    expect(res.status).toBe(403);
    expect((await res.json() as any).error).toBe("forbidden");
  });
});
