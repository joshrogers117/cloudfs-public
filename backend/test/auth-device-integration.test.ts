// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-device-integration.test.ts — the device-session lane END-TO-END through the real worker
// (SELF.fetch) + real AuthDO/DirectoryDO/OrgDO: approve (cookie+CSRF) → PKCE exchange →
// refresh rotation → devices list/revoke (with daemon-token cascade) → the §2.7 device-bound
// daemon mint → the B11 ACL regression (daemon token acting AS a human user keeps that user's
// folder grants). Every test provisions its own org so state never leaks across cases.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { mintToken, verifyToken, type Scope } from "../src/security/auth";
import { scopesForRole } from "../src/security/oidc";
import { canAccess, InMemoryPermissionStore } from "../src/permissions";
import { propagateAccountOffboarding } from "../src/auth-wiring";
import { issueEmailToken } from "../src/security/auth-email";
import { authStoresFor } from "../src/auth-stores";
import type { Env } from "../src/env";

const ORIGIN = "https://gw.local";
const SIGNING = (env as any).AUTH_SIGNING_SECRET as string;
const BOOT_SECRET = (env as any).BOOTSTRAP_SECRET as string;

// Distinct client IP per request: the public signup/login/device limiters are per-IP and
// deliberately tight (same pattern as auth-integration.test.ts).
let ipCounter = 0;
function freshIp(): string {
  ipCounter++;
  return `198.51.${Math.floor(ipCounter / 256) % 256}.${ipCounter % 256}`;
}
function jsonHeaders(extra?: Record<string, string>): Record<string, string> {
  return { "content-type": "application/json", "cf-connecting-ip": freshIp(), ...(extra ?? {}) };
}

function sessionCookie(res: Response): string | null {
  const sc = res.headers.get("set-cookie");
  if (!sc) return null;
  const m = /cfs_session=([^;]+)/.exec(sc);
  return m ? m[1] : null;
}

// ---- PKCE helpers (the app side of §3) -------------------------------------------------

function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const verifier = b64url(raw); // 43 chars
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: b64url(new Uint8Array(digest)) };
}

// ---- per-test org provisioning ----------------------------------------------------------

let emailCounter = 0;
function uniqueEmail(): string {
  return `dev-${Date.now()}-${emailCounter++}@example.test`;
}

interface Owner {
  cookie: string;
  csrf: string;
  orgId: string;
  userId: string;
  accountId: string;
  email: string;
}

/// Self-serve signup (open mode in dev/test) + mark the email VERIFIED directly in the AuthDO
/// (the verify-link flow is covered elsewhere; device exchanges compute scopes from the live
/// account, so the owner must be verified to carry full role scopes).
async function signupVerifiedOwner(): Promise<Owner> {
  const email = uniqueEmail();
  const res = await SELF.fetch(`${ORIGIN}/v1/auth/signup`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ orgName: "Device Org", email, password: "correct horse battery staple", displayName: "Owner" }),
  });
  expect(res.status).toBe(201);
  const body = (await res.json()) as any;
  const stub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(body.orgId));
  await stub.setEmailVerified(body.accountId, true);
  await stub.updateSessionsScopesForAccount(body.accountId, scopesForRole("owner"));
  return {
    cookie: sessionCookie(res)!,
    csrf: body.csrf,
    orgId: body.orgId,
    userId: body.userId,
    accountId: body.accountId,
    email,
  };
}

async function approve(owner: Owner, body: Record<string, unknown>, withCsrf = true): Promise<Response> {
  return SELF.fetch(`${ORIGIN}/v1/auth/device/approve`, {
    method: "POST",
    headers: jsonHeaders({
      cookie: `cfs_session=${owner.cookie}`,
      ...(withCsrf ? { "X-CFS-CSRF": owner.csrf } : {}),
    }),
    body: JSON.stringify(body),
  });
}

interface DeviceLogin {
  owner: Owner;
  refreshToken: string;
  accessToken: string;
  deviceId: string;
}

/// The full §3 handoff for a fresh verified owner: approve → exchange. Returns everything.
async function deviceLogin(deviceName = "Josh's MacBook Pro"): Promise<DeviceLogin> {
  const owner = await signupVerifiedOwner();
  const { verifier, challenge } = await pkcePair();
  const ap = await approve(owner, {
    state: "app-state-echo",
    codeChallenge: challenge,
    codeChallengeMethod: "S256",
    deviceName,
    deviceModel: "MacBookPro18,3",
  });
  expect(ap.status).toBe(201);
  const { code } = (await ap.json()) as { code: string };
  const ex = await SELF.fetch(`${ORIGIN}/v1/auth/device/token`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ code, codeVerifier: verifier }),
  });
  expect(ex.status).toBe(200);
  const body = (await ex.json()) as any;
  return { owner, refreshToken: body.refreshToken, accessToken: body.accessToken, deviceId: body.device.id };
}

async function postDevice(path: string, body: unknown, headers?: Record<string, string>): Promise<Response> {
  return SELF.fetch(`${ORIGIN}${path}`, { method: "POST", headers: jsonHeaders(headers), body: JSON.stringify(body) });
}

describe("password changes retire device authority", () => {
  for (const operation of ["change", "reset"] as const) {
    it(`${operation} retires refresh/access/daemon credentials and permits a fresh sign-in`, async () => {
      const login = await deviceLogin();
      const daemonResponse = await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` });
      expect(daemonResponse.status).toBe(201);
      const daemon = await daemonResponse.json() as { token: string };
      const usersUrl = `${ORIGIN}/v1/orgs/${login.owner.orgId}/users`;
      for (const token of [login.accessToken, daemon.token]) {
        expect((await SELF.fetch(usersUrl, { headers: { Authorization: `Bearer ${token}` } })).status).toBe(200);
      }
      let response: Response;
      const password = "replacement correct horse battery";
      if (operation === "reset") {
        const token = await issueEmailToken(authStoresFor(env as Env, login.owner.orgId).emailTokens, {
          orgId: login.owner.orgId, accountId: login.owner.accountId, email: login.owner.email, purpose: "password_reset",
        });
        response = await postDevice("/v1/auth/password/reset", { orgId: login.owner.orgId, token: token.token, newPassword: password });
      } else {
        response = await postDevice("/v1/auth/password/change", { currentPassword: "correct horse battery staple", newPassword: password },
          { cookie: `cfs_session=${login.owner.cookie}`, "X-CFS-CSRF": login.owner.csrf });
      }
      expect(response.status).toBe(204);
      expect((await postDevice("/v1/auth/device/refresh", { refreshToken: login.refreshToken })).status).toBe(401);
      for (const token of [login.accessToken, daemon.token]) {
        expect((await SELF.fetch(usersUrl, { headers: { Authorization: `Bearer ${token}` } })).status).toBe(401);
      }
      expect((await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${login.owner.cookie}` } })).status)
        .toBe(operation === "change" ? 200 : 401);
      const fresh = await postDevice("/v1/auth/login", { email: login.owner.email, password });
      expect(fresh.status).toBe(200);
      expect(sessionCookie(fresh)).toBeTruthy();
    });
  }
});

// =========================================================================================
// Happy path (§2.2 + §2.3 + §3)
// =========================================================================================

describe("device handoff: approve → exchange (happy path)", () => {
  it("native account lookup accepts a device bearer and returns its own live workspace role", async () => {
    const login = await deviceLogin();
    const other = await signupVerifiedOwner();
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/me`, {
      headers: { Authorization: `Bearer ${login.accessToken}`, cookie: `cfs_session=${other.cookie}` },
    });
    expect(res.status).toBe(200);
    const me = await res.json() as any;
    expect(me).toMatchObject({ userId: login.owner.userId, orgId: login.owner.orgId,
      email: login.owner.email, role: "owner", orgName: "Device Org" });
    expect(me).not.toHaveProperty("csrf");
    expect(me).not.toHaveProperty("mfa");
  });

  it("native account lookup never downgrades an invalid bearer to a valid cookie", async () => {
    const owner = await signupVerifiedOwner();
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/me`, {
      headers: { Authorization: "Bearer invalid", cookie: `cfs_session=${owner.cookie}` },
    });
    expect(res.status).toBe(401);
  });

  it("native account lookup supports daemon tokens without returning browser credentials", async () => {
    const login = await deviceLogin();
    const daemon = await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` });
    expect(daemon.status).toBe(201);
    const { token } = await daemon.json() as any;
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(200);
    const me = await res.json() as any;
    expect(me.userId).toBe(login.owner.userId);
    expect(me.role).toBe("owner");
    expect(me.scopes).not.toContain("fs:admin");
    expect(me).not.toHaveProperty("csrf");
  });

  it("approve mints an org-qualified code; exchange returns the full §2.3 payload; the access JWS authorizes", async () => {
    const owner = await signupVerifiedOwner();
    const { verifier, challenge } = await pkcePair();

    const ap = await approve(owner, {
      state: "S".repeat(43),
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      deviceName: "Josh's MacBook Pro",
      deviceModel: "MacBookPro18,3",
    });
    expect(ap.status).toBe(201);
    const apBody = (await ap.json()) as any;
    // Org-qualified one-time code: "<orgId>.dac-<uuid>.<secret>" — state echoed verbatim.
    expect(apBody.code.startsWith(`${owner.orgId}.dac-`)).toBe(true);
    expect(apBody.state).toBe("S".repeat(43));
    expect(apBody.expiresInSeconds).toBe(300);

    const ex = await postDevice("/v1/auth/device/token", { code: apBody.code, codeVerifier: verifier });
    expect(ex.status).toBe(200);
    const body = (await ex.json()) as any;
    expect(body.refreshToken.startsWith(`${owner.orgId}.dvt-dev-`)).toBe(true);
    expect(body.accessTtlSeconds).toBe(900);
    expect(body.orgId).toBe(owner.orgId);
    expect(body.orgName).toBe("Device Org");
    expect(body.account).toEqual({ email: owner.email, displayName: "Owner", role: "owner" });
    expect(body.device.id).toMatch(/^dev-/);
    expect(body.device.name).toBe("Josh's MacBook Pro");

    // The access JWS is a normal session token: jti == device-session id, fresh owner scopes.
    const principal = await verifyToken(SIGNING, body.accessToken);
    expect(principal.jti).toBe(body.device.id);
    expect(principal.sub).toBe(owner.userId);
    expect(principal.scopes).toEqual(scopesForRole("owner"));

    // …and it authorizes a real bearer-gated route through the gateway revocation gate.
    const users = await SELF.fetch(`${ORIGIN}/v1/orgs/${owner.orgId}/users`, {
      headers: { Authorization: `Bearer ${body.accessToken}` },
    });
    expect(users.status).toBe(200);
  });

  it("GET /v1/auth/devices lists the device with the §2.6 projection (no hashes)", async () => {
    const login = await deviceLogin("Edit Bay 3");
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/devices`, {
      headers: { cookie: `cfs_session=${login.owner.cookie}` },
    });
    expect(res.status).toBe(200);
    const { devices } = (await res.json()) as any;
    expect(devices).toHaveLength(1);
    expect(devices[0].id).toBe(login.deviceId);
    expect(devices[0].name).toBe("Edit Bay 3");
    expect(devices[0].model).toBe("MacBookPro18,3");
    expect(devices[0].revokedAt).toBeNull();
    expect(devices[0].expiresAt).toBeGreaterThan(Date.now() + 399 * 24 * 60 * 60 * 1000);
    // No secret-derived field leaks.
    expect(JSON.stringify(devices[0])).not.toMatch(/refresh|hash|secret/i);
  });
});

// =========================================================================================
// Approve gating (§2.2)
// =========================================================================================

describe("device approve gating", () => {
  it("requires a session cookie (401) and CSRF (403)", async () => {
    const owner = await signupVerifiedOwner();
    const { challenge } = await pkcePair();
    const body = { codeChallenge: challenge, codeChallengeMethod: "S256", deviceName: "Mac" };

    const anon = await postDevice("/v1/auth/device/approve", body);
    expect(anon.status).toBe(401);

    const noCsrf = await approve(owner, body, /* withCsrf */ false);
    expect(noCsrf.status).toBe(403);
    expect(((await noCsrf.json()) as any).error).toBe("csrf");
  });

  it("validates method/challenge/deviceName with typed 400s", async () => {
    const owner = await signupVerifiedOwner();
    const { challenge } = await pkcePair();

    const badMethod = await approve(owner, { codeChallenge: challenge, codeChallengeMethod: "plain", deviceName: "Mac" });
    expect(badMethod.status).toBe(400);
    expect(((await badMethod.json()) as any).error).toBe("bad_method");

    const badChallenge = await approve(owner, { codeChallenge: "short", codeChallengeMethod: "S256", deviceName: "Mac" });
    expect(badChallenge.status).toBe(400);
    expect(((await badChallenge.json()) as any).error).toBe("bad_challenge");

    const badName = await approve(owner, { codeChallenge: challenge, codeChallengeMethod: "S256", deviceName: "x".repeat(65) });
    expect(badName.status).toBe(400);
    expect(((await badName.json()) as any).error).toBe("bad_device_name");
  });
});

// =========================================================================================
// Exchange security edges (§2.3, §5.1)
// =========================================================================================

describe("device code exchange security", () => {
  async function approvedCode(owner: Owner): Promise<{ code: string; verifier: string }> {
    const { verifier, challenge } = await pkcePair();
    const ap = await approve(owner, { codeChallenge: challenge, codeChallengeMethod: "S256", deviceName: "Mac" });
    expect(ap.status).toBe(201);
    return { code: ((await ap.json()) as any).code, verifier };
  }

  it("a PKCE mismatch is refused (pkce_mismatch) AND burns the code", async () => {
    const owner = await signupVerifiedOwner();
    const { code, verifier } = await approvedCode(owner);
    const wrong = await postDevice("/v1/auth/device/token", { code, codeVerifier: "W".repeat(43) });
    expect(wrong.status).toBe(400);
    expect(((await wrong.json()) as any).error).toBe("pkce_mismatch");
    // The correct verifier is now too late — the failed attempt destroyed the code.
    const late = await postDevice("/v1/auth/device/token", { code, codeVerifier: verifier });
    expect(late.status).toBe(400);
    expect(((await late.json()) as any).error).toBe("invalid_code");
  });

  it("a code is single-use: the second exchange is invalid_code", async () => {
    const owner = await signupVerifiedOwner();
    const { code, verifier } = await approvedCode(owner);
    expect((await postDevice("/v1/auth/device/token", { code, codeVerifier: verifier })).status).toBe(200);
    const replay = await postDevice("/v1/auth/device/token", { code, codeVerifier: verifier });
    expect(replay.status).toBe(400);
    expect(((await replay.json()) as any).error).toBe("invalid_code");
  });

  it("garbage / unqualified codes are invalid_code", async () => {
    for (const code of ["nodot", "org1.dac-x", "org1.svc-1.s", ""]) {
      const res = await postDevice("/v1/auth/device/token", { code, codeVerifier: "v".repeat(43) });
      expect(res.status).toBe(400);
      expect(((await res.json()) as any).error).toBe("invalid_code");
    }
  });
});

// =========================================================================================
// Refresh (§2.4) — wire-level; the full grace/reuse state machine is unit-tested in
// auth-device-lane.test.ts (it needs an injected clock).
// =========================================================================================

describe("device refresh", () => {
  it("rotates on use; the just-superseded token still works inside the race grace", async () => {
    const login = await deviceLogin();
    const r1 = await postDevice("/v1/auth/device/refresh", { refreshToken: login.refreshToken });
    expect(r1.status).toBe(200);
    const b1 = (await r1.json()) as any;
    expect(b1.refreshToken).not.toBe(login.refreshToken);
    expect(b1.refreshToken.startsWith(`${login.owner.orgId}.dvt-`)).toBe(true);
    expect(b1.accessTtlSeconds).toBe(900);
    expect((await verifyToken(SIGNING, b1.accessToken)).jti).toBe(login.deviceId);

    // Lost-response retry: the ORIGINAL token re-presented within 60s rotates again (no revoke).
    const r2 = await postDevice("/v1/auth/device/refresh", { refreshToken: login.refreshToken });
    expect(r2.status).toBe(200);

    // …and the device is still live.
    const r3 = await postDevice("/v1/auth/device/refresh", {
      refreshToken: ((await r2.json()) as any).refreshToken,
    });
    expect(r3.status).toBe(200);
  });

  it("an unknown/garbage refresh token is 401 invalid_refresh", async () => {
    for (const refreshToken of ["nodot", "org1.dvt-dev-unknown.zzz", ""]) {
      const res = await postDevice("/v1/auth/device/refresh", { refreshToken });
      expect(res.status).toBe(401);
      expect(((await res.json()) as any).error).toBe("invalid_refresh");
    }
  });
});

// =========================================================================================
// Revoke (§2.6) + offboarding (§4.2)
// =========================================================================================

describe("device revoke", () => {
  it("DELETE /v1/auth/devices/:id revokes: refresh dies, the residual access JWS dies on the gate", async () => {
    const login = await deviceLogin();
    const del = await SELF.fetch(`${ORIGIN}/v1/auth/devices/${login.deviceId}`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${login.owner.cookie}`, "X-CFS-CSRF": login.owner.csrf }),
    });
    expect(del.status).toBe(204);

    const refresh = await postDevice("/v1/auth/device/refresh", { refreshToken: login.refreshToken });
    expect(refresh.status).toBe(401);
    expect(((await refresh.json()) as any).error).toBe("device_revoked");

    // The still-unexpired access JWS (jti == device id) is rejected by the EXISTING revocation
    // gate immediately (invalidateJti dropped the cached decision).
    const gated = await SELF.fetch(`${ORIGIN}/v1/orgs/${login.owner.orgId}/users`, {
      headers: { Authorization: `Bearer ${login.accessToken}` },
    });
    expect(gated.status).toBe(401);
    expect(((await gated.json()) as any).error).toBe("revoked");

    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, {
      headers: { Authorization: `Bearer ${login.accessToken}` },
    });
    expect(me.status).toBe(401);
    expect(((await me.json()) as any).error).toBe("revoked");

    // The devices list keeps the row, now marked revoked (§4.5 retention).
    const list = await SELF.fetch(`${ORIGIN}/v1/auth/devices`, {
      headers: { cookie: `cfs_session=${login.owner.cookie}` },
    });
    const { devices } = (await list.json()) as any;
    expect(devices[0].revokedAt).not.toBeNull();
  });

  it("revoke requires CSRF; a foreign device id is an opaque 404", async () => {
    const login = await deviceLogin();
    const noCsrf = await SELF.fetch(`${ORIGIN}/v1/auth/devices/${login.deviceId}`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${login.owner.cookie}` }),
    });
    expect(noCsrf.status).toBe(403);

    // A different account cannot revoke (or probe) someone else's device.
    const other = await signupVerifiedOwner();
    const foreign = await SELF.fetch(`${ORIGIN}/v1/auth/devices/${login.deviceId}`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${other.cookie}`, "X-CFS-CSRF": other.csrf }),
    });
    expect(foreign.status).toBe(404);
  });

  it("account offboarding revokes the device session (and its daemon token) too", async () => {
    const login = await deviceLogin();
    // Mint the daemon token first so the cascade has something to bite on.
    const daemon = await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` });
    expect(daemon.status).toBe(201);
    const daemonToken = ((await daemon.json()) as any).token as string;

    await propagateAccountOffboarding(env as any, login.owner.orgId, login.owner.userId, "suspended");

    const refresh = await postDevice("/v1/auth/device/refresh", { refreshToken: login.refreshToken });
    expect(refresh.status).toBe(401);
    expect(((await refresh.json()) as any).error).toBe("device_revoked");

    // The daemon token (userId == the human user) was swept by the service-token revoke.
    const gated = await SELF.fetch(`${ORIGIN}/v1/orgs/${login.owner.orgId}/users`, {
      headers: { Authorization: `Bearer ${daemonToken}` },
    });
    expect(gated.status).toBe(401);
  });
});

// =========================================================================================
// §2.7 daemon-token mint — device-bound, non-admin, scope-ceilinged, soft cutover
// =========================================================================================

describe("device daemon-token mint (§2.7)", () => {
  it("a non-admin DEVICE access JWS mints a 30-day data-plane token bound to the device session", async () => {
    const login = await deviceLogin("Mint Mac");
    const before = Date.now();
    const res = await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` });
    expect(res.status).toBe(201);
    const body = (await res.json()) as any;
    expect(body.id).toMatch(/^svc-/);
    // Scope ceiling: live and historical reads, never fs:admin / snapshot:write / audit.
    expect(body.scopes).toEqual(["fs:read", "fs:write", "fs:lock", "snapshot:read"]);
    expect(body.expiresAt).toBeGreaterThan(before + 29 * 24 * 60 * 60 * 1000);
    expect(body.expiresAt).toBeLessThan(before + 31 * 24 * 60 * 60 * 1000);

    // The daemon JWS acts AS THE HUMAN USER (decision C) with the capped scopes.
    const principal = await verifyToken(SIGNING, body.token);
    expect(principal.type).toBe("service");
    expect(principal.sub).toBe(login.owner.userId);
    expect(principal.jti).toBe(body.id);
    expect(principal.scopes).toEqual(["fs:read", "fs:write", "fs:lock", "snapshot:read"]);

    // The record is visible on the admin list with the device binding (cookie GET, owner role).
    const list = await SELF.fetch(`${ORIGIN}/v1/orgs/${login.owner.orgId}/service-tokens`, {
      headers: { cookie: `cfs_session=${login.owner.cookie}` },
    });
    expect(list.status).toBe(200);
    const tokens = (await list.json()) as any[];
    expect(tokens).toHaveLength(1);
    expect(tokens[0].deviceSessionId).toBe(login.deviceId);
    expect(tokens[0].label).toBe("daemon:Mint Mac");
  });

  it("a browser-session JWS and an admin service token CANNOT mint (device binding required)", async () => {
    const login = await deviceLogin();
    // A session JWS whose jti is NOT a device session (what a browser session re-mints).
    const sessionJws = await mintToken(SIGNING, {
      sub: login.owner.userId, type: "session", orgId: login.owner.orgId,
      scopes: scopesForRole("owner"), ttlSeconds: 900, jti: "sess-not-a-device",
    });
    const viaSession = await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${sessionJws}` });
    expect(viaSession.status).toBe(401);
    expect(((await viaSession.json()) as any).error).toBe("unauthorized");

    // An admin-minted service token (jti == svc-…) has no device row either.
    const adminMint = await SELF.fetch(`${ORIGIN}/v1/orgs/${login.owner.orgId}/service-tokens`, {
      method: "POST",
      headers: jsonHeaders({ cookie: `cfs_session=${login.owner.cookie}`, "X-CFS-CSRF": login.owner.csrf }),
      body: JSON.stringify({ label: "ci", scopes: ["fs:read"] }),
    });
    expect(adminMint.status).toBe(201);
    const adminToken = ((await adminMint.json()) as any).token as string;
    const viaService = await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${adminToken}` });
    expect(viaService.status).toBe(401);
    expect(((await viaService.json()) as any).error).toBe("unauthorized");

    // No bearer at all → 401 too.
    expect((await postDevice("/v1/auth/device/daemon-token", {})).status).toBe(401);
  });

  it("a revoked device cannot mint (device_revoked)", async () => {
    const login = await deviceLogin();
    const del = await SELF.fetch(`${ORIGIN}/v1/auth/devices/${login.deviceId}`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${login.owner.cookie}`, "X-CFS-CSRF": login.owner.csrf }),
    });
    expect(del.status).toBe(204);
    const res = await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` });
    expect(res.status).toBe(401);
    expect(((await res.json()) as any).error).toBe("device_revoked");
  });

  it("re-minting SOFT-EXPIRES the prior token for the same device (now+10min) instead of revoking it", async () => {
    const login = await deviceLogin();
    const first = (await (await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` })).json()) as any;
    const before = Date.now();
    const second = (await (await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` })).json()) as any;
    expect(second.id).not.toBe(first.id);

    const list = await SELF.fetch(`${ORIGIN}/v1/orgs/${login.owner.orgId}/service-tokens`, {
      headers: { cookie: `cfs_session=${login.owner.cookie}` },
    });
    const tokens = (await list.json()) as any[];
    const firstRow = tokens.find((t) => t.id === first.id)!;
    const secondRow = tokens.find((t) => t.id === second.id)!;
    // Prior token: NOT revoked (in-flight requests finish) but expiring within ~10 minutes.
    expect(firstRow.revoked).toBe(false);
    expect(firstRow.expiresAt).toBeLessThanOrEqual(before + 10 * 60 * 1000 + 5_000);
    expect(firstRow.expiresAt).toBeGreaterThan(before);
    // New token: full 30 days.
    expect(secondRow.expiresAt).toBeGreaterThan(before + 29 * 24 * 60 * 60 * 1000);
    // The prior token still WORKS during the cutover window.
    const stillWorks = await SELF.fetch(`${ORIGIN}/v1/orgs/${login.owner.orgId}/users`, {
      headers: { Authorization: `Bearer ${first.token}` },
    });
    expect(stillWorks.status).toBe(200);
  });

  it("revoking the device CASCADES to its daemon token (gate rejects it immediately)", async () => {
    const login = await deviceLogin();
    const daemon = (await (await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` })).json()) as any;

    // Daemon token works before the revoke…
    const ok = await SELF.fetch(`${ORIGIN}/v1/orgs/${login.owner.orgId}/users`, {
      headers: { Authorization: `Bearer ${daemon.token}` },
    });
    expect(ok.status).toBe(200);

    const del = await SELF.fetch(`${ORIGIN}/v1/auth/devices/${login.deviceId}`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${login.owner.cookie}`, "X-CFS-CSRF": login.owner.csrf }),
    });
    expect(del.status).toBe(204);

    // …and dies the moment the device is revoked (cascade + invalidateJti).
    const dead = await SELF.fetch(`${ORIGIN}/v1/orgs/${login.owner.orgId}/users`, {
      headers: { Authorization: `Bearer ${daemon.token}` },
    });
    expect(dead.status).toBe(401);
    expect(((await dead.json()) as any).error).toBe("revoked");
  });

  it("the daemon token is scope-capped: data-plane yes, fs:admin no", async () => {
    const login = await deviceLogin();
    const daemon = (await (await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${login.accessToken}` })).json()) as any;
    const auth = { Authorization: `Bearer ${daemon.token}` };
    const SPACE = `${ORIGIN}/v1/filespaces/cap-check`;

    // fs:read works (data plane)…
    const items = await SELF.fetch(`${SPACE}/items`, { headers: auth });
    expect(items.status).toBe(200);
    // Finder's historical data plane is included, but creating snapshots is not.
    expect((await SELF.fetch(`${SPACE}/snapshots`, { headers: auth })).status).toBe(200);
    const create = await SELF.fetch(`${SPACE}/snapshots`, { method: "POST", headers: { ...auth, "content-type": "application/json" }, body: "{}" });
    expect(create.status).toBe(403);
    expect(((await create.json()) as any).error).toBe("forbidden_scope");
    // …but the fs:admin surface (grants listing) is refused on scope.
    const grants = await SELF.fetch(`${SPACE}/grants`, { headers: auth });
    expect(grants.status).toBe(403);
    expect(((await grants.json()) as any).error).toBe("forbidden_scope");
  });
});

// =========================================================================================
// B11 / §2.7 ACL REGRESSION — the daemon token acting AS a human user must keep that
// user's per-folder grants through the service-principal mapping.
// =========================================================================================

describe("B11 regression: daemon token (service principal) honors the human user's grants", () => {
  it("pure evaluator: a `user` grant matches a service_account principal with the same id", () => {
    const store = new InMemoryPermissionStore();
    store.addInode({ id: "root", parentId: null, type: "folder" });
    store.addInode({ id: "f1", parentId: "root", type: "folder" });
    store.putGrant({
      id: "g1", spaceId: "sp", inodeId: "f1", principalType: "user", principalId: "usr-9",
      level: "edit", grantedByMemberId: "admin", grantedAt: Date.now(),
    });
    // The daemon token's ACL principal: type service_account, id == the HUMAN user id.
    const daemonPrincipal = { type: "service_account" as const, id: "usr-9", groupIds: [], orgRole: "standard" as const };
    expect(canAccess(store, daemonPrincipal, "f1", "read").allow).toBe(true);
    expect(canAccess(store, daemonPrincipal, "f1", "write").allow).toBe(true);
    // No grant elsewhere stays invisible.
    store.addInode({ id: "f2", parentId: "root", type: "folder" });
    expect(canAccess(store, daemonPrincipal, "f2", "read").allow).toBe(false);
  });

  it("end-to-end: a STANDARD user's folder grant works through their device-minted daemon token", async () => {
    // Org with a verified owner via the hardened bootstrap (full admin bearer for seeding).
    const orgId = `org-acl-${crypto.randomUUID().slice(0, 8)}`;
    const boot = await SELF.fetch(`${ORIGIN}/v1/bootstrap`, {
      method: "POST",
      headers: jsonHeaders({ "x-bootstrap-secret": BOOT_SECRET }),
      body: JSON.stringify({ orgId, email: `owner@${orgId}.test`, displayName: "Owner", password: "owner password 123" }),
    });
    expect(boot.status).toBe(201);
    const admin = (await boot.json()) as any;
    const adminAuth = { Authorization: `Bearer ${admin.token}`, "content-type": "application/json" };

    // A STANDARD teammate (no org-role short-circuit — grants are the ONLY thing admitting them).
    const orgStub = (env as any).ORG_DO.getByName(orgId);
    const std = await orgStub.createUser({ orgId, email: `std@${orgId}.test`, displayName: "Std", role: "standard" });

    // Their device session, seeded directly in the AuthDO (the handoff flow is covered above) +
    // its access JWS (jti == device-session id), exactly what the exchange would mint.
    const authStub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(orgId));
    const account = await authStub.createAccount({
      orgId, userId: std.id, email: `std@${orgId}.test`, displayName: "Std", role: "standard", emailVerified: true,
    });
    const deviceId = `dev-${crypto.randomUUID()}`;
    const nowMs = Date.now();
    await authStub.createDeviceSession({
      id: deviceId, accountId: account.id, userId: std.id, orgId,
      scopes: scopesForRole("standard"), deviceName: "Std's Mac", deviceModel: null,
      refreshHash: "seeded-not-used", prevRefreshHash: null, prevGraceUntil: null,
      rotationCounter: 0, createdAt: nowMs, lastSeenAt: nowMs,
      expiresAt: nowMs + 400 * 24 * 60 * 60 * 1000, revokedAt: null, revokeReason: null,
    });
    const accessJws = await mintToken(SIGNING, {
      sub: std.id, type: "session", orgId, scopes: scopesForRole("standard") as Scope[],
      ttlSeconds: 900, jti: deviceId,
    });

    // The device mints the daemon token — acting AS the standard user.
    const daemonRes = await postDevice("/v1/auth/device/daemon-token", {}, { Authorization: `Bearer ${accessJws}` });
    expect(daemonRes.status).toBe(201);
    const daemon = (await daemonRes.json()) as any;
    // Standard role scopes intersect the data-plane ceiling, including historical reads.
    expect(daemon.scopes).toEqual(["fs:read", "fs:write", "fs:lock", "snapshot:read"]);
    expect((await verifyToken(SIGNING, daemon.token)).sub).toBe(std.id);

    // Owner seeds a space with TWO folders and grants the standard user edit on ONE.
    const SP = "acl-space";
    const SPACE = `${ORIGIN}/v1/filespaces/${SP}`;
    await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/spaces`, {
      method: "POST", headers: adminAuth,
      body: JSON.stringify({ spaceId: SP, name: "ACL Space", bucketProvider: "r2", bucketName: "cloudfs", keyPrefix: `blocks/${orgId}::${SP}/` }),
    });
    const granted = (await (await SELF.fetch(`${SPACE}/items`, {
      method: "POST", headers: adminAuth,
      body: JSON.stringify({ parent: "root", name: "Granted", isDir: true }),
    })).json()) as any;
    const ungranted = (await (await SELF.fetch(`${SPACE}/items`, {
      method: "POST", headers: adminAuth,
      body: JSON.stringify({ parent: "root", name: "Ungranted", isDir: true }),
    })).json()) as any;
    const grant = await SELF.fetch(`${SPACE}/grants`, {
      method: "POST", headers: adminAuth,
      body: JSON.stringify({ inodeId: granted.id, principalType: "user", principalId: std.id, level: "edit" }),
    });
    expect(grant.status).toBe(201);

    // THE REGRESSION: through the daemon token (type service → ACL service_account, id == the
    // human user), the user's grant must resolve. Pre-fix, principalMatches discriminated on
    // type, so this read 404'd (invisible) and the daemon lost every per-folder grant.
    const daemonAuth = { Authorization: `Bearer ${daemon.token}`, "content-type": "application/json" };
    const read = await SELF.fetch(`${SPACE}/items/${encodeURIComponent(granted.id)}`, { headers: daemonAuth });
    expect(read.status).toBe(200);
    expect(((await read.json()) as any).name).toBe("Granted");

    // The edit grant admits a write too (create a child through the daemon token).
    const write = await SELF.fetch(`${SPACE}/items`, {
      method: "POST", headers: daemonAuth,
      body: JSON.stringify({ parent: granted.id, name: "clip.mov", size: 0 }),
    });
    expect(write.status).toBe(201);

    // No grant ⇒ still INVISIBLE (the fix must not widen access).
    const denied = await SELF.fetch(`${SPACE}/items/${encodeURIComponent(ungranted.id)}`, { headers: daemonAuth });
    expect(denied.status).toBe(404);
  });
});

// =========================================================================================
// Rate limits (§5.5) — buckets enforce AND are disjoint
// =========================================================================================

describe("device rate limits", () => {
  it("device/token is per-IP capped (10 burst) and DISJOINT from device/refresh", async () => {
    const ip = "203.0.250.1";
    const headers = { "content-type": "application/json", "cf-connecting-ip": ip };
    let limited = false;
    for (let i = 0; i < 11; i++) {
      const res = await SELF.fetch(`${ORIGIN}/v1/auth/device/token`, {
        method: "POST", headers, body: JSON.stringify({ code: "x.dac-x.x", codeVerifier: "v".repeat(43) }),
      });
      if (i < 10) {
        expect(res.status).toBe(400); // invalid_code — but ADMITTED to the handler
      } else {
        expect(res.status).toBe(429);
        limited = true;
      }
    }
    expect(limited).toBe(true);

    // Same IP, different bucket: refresh is NOT limited by the exhausted token bucket.
    const refresh = await SELF.fetch(`${ORIGIN}/v1/auth/device/refresh`, {
      method: "POST", headers, body: JSON.stringify({ refreshToken: "x.dvt-dev-x.x" }),
    });
    expect(refresh.status).toBe(401); // invalid_refresh — admitted, not 429
  });

  it("device/approve is per-ACCOUNT capped (10 burst)", async () => {
    const owner = await signupVerifiedOwner();
    const { challenge } = await pkcePair();
    for (let i = 0; i < 10; i++) {
      const res = await approve(owner, { codeChallenge: challenge, codeChallengeMethod: "S256", deviceName: `Mac ${i}` });
      expect(res.status).toBe(201);
    }
    const eleventh = await approve(owner, { codeChallenge: challenge, codeChallengeMethod: "S256", deviceName: "Mac 11" });
    expect(eleventh.status).toBe(429);
  });
});

// =========================================================================================
// §2.8 public config additions
// =========================================================================================

describe("GET /v1/auth/config/public (§2.8)", () => {
  it("carries webBaseUrl + productName for the Mac app probe", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/config/public`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.webBaseUrl).toBe("http://localhost:5173"); // dev WEB_BASE_URL
    expect(body.productName).toBe("CloudFS");
    expect(typeof body.mode).toBe("string");
    expect(typeof body.oidcEnabled).toBe("boolean");
  });
});
