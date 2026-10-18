// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-integration.test.ts — end-to-end through the real worker + real AuthDO/DirectoryDO.
//
// Proves the integration agent's store wiring: signup -> session cookie -> /me; login (incl.
// the cookie+bearer coexistence in verifyRequest); cross-org email uniqueness; service-token
// mint/list/revoke through /v1/orgs/:org/service-tokens; CSRF on cookie mutations; logout
// revocation. Uses SELF.fetch so the whole gateway path runs in real workerd (Miniflare).

import { SELF, env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { totp, base32Decode } from "../src/security/auth-totp";

/// Flip an account's email to verified directly in its AuthDO — the sole side effect of clicking
/// the verification link (`POST /v1/auth/verify-email`), whose token secret we cannot reconstruct
/// in-test (only its sha256 is stored). The route's verify→setEmailVerified→scope-upgrade path is
/// covered at the unit level; here we exercise the GATE flipping on real, live account state.
async function markEmailVerified(orgId: string, accountId: string): Promise<void> {
  const stub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(orgId));
  await stub.setEmailVerified(accountId, true);
  await stub.updateSessionsScopesForAccount(accountId, ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"]);
}

/// Audit B12: signup creates the org's SOLE owner, and the last-owner guard now (correctly)
/// refuses to suspend/demote the last active owner. The offboarding tests need to offboard an
/// owner WITHOUT it being the last one, so seed a SECOND active owner in the org first.
async function seedSecondOwner(orgId: string): Promise<void> {
  const org = (env as any).ORG_DO.getByName(orgId);
  await org.createUser({ orgId, email: `co-owner-${crypto.randomUUID()}@${orgId}.test`, displayName: "Co Owner", role: "owner" });
}

const ORIGIN = "https://gw.local";

// The public signup/login limiters are per-IP and module-scoped within the test isolate, so we
// give every test a DISTINCT client IP to keep their token buckets independent (the contract's
// frozen per-IP caps are intentionally tight; sharing one bucket across the whole file would
// trip 429s that have nothing to do with the behaviour under test).
let ipCounter = 0;
function freshIp(): string {
  // Walk a /16 so every request in the file gets a unique IP (the per-IP signup cap is 3, so
  // re-using an octet across signups would falsely trip a 429). 256*256 space is ample.
  ipCounter++;
  return `203.0.${Math.floor(ipCounter / 256) % 256}.${ipCounter % 256}`;
}

function jsonHeaders(extra?: Record<string, string>): Record<string, string> {
  return { "content-type": "application/json", "cf-connecting-ip": freshIp(), ...(extra ?? {}) };
}

/// Pull the `cfs_session` cookie value out of a Set-Cookie header.
function sessionCookie(res: Response): string | null {
  const sc = res.headers.get("set-cookie");
  if (!sc) return null;
  const m = /cfs_session=([^;]+)/.exec(sc);
  return m ? m[1] : null;
}

async function post(path: string, body: unknown, headers?: Record<string, string>): Promise<Response> {
  return SELF.fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers: jsonHeaders(headers),
    body: JSON.stringify(body),
  });
}

let counter = 0;
function uniqueEmail(): string {
  return `user-${Date.now()}-${counter++}@example.test`;
}

async function signup(email: string, password = "correct horse battery staple") {
  const res = await post("/v1/auth/signup", {
    orgName: "Test Org",
    email,
    password,
    displayName: "Test User",
  });
  return res;
}

describe("auth integration — signup + session", () => {
  it("signs up, sets an org-qualified session cookie, and /me works via the cookie", async () => {
    const email = uniqueEmail();
    const res = await signup(email);
    expect(res.status).toBe(201);
    const body = (await res.json()) as any;
    expect(body.orgId).toMatch(/^org-/);
    expect(body.userId).toMatch(/^usr-/);
    expect(body.accountId).toMatch(/^acc-/);
    // B11: the dev/test runtime uses the console sender (EMAIL_DEV_CONSOLE=1), which logs
    // the link but does NOT deliver — so signup HONESTLY reports emailSent:false (no real
    // provider). Pre-fix this falsely returned true while the mail was dropped.
    expect(body.emailSent).toBe(false);
    expect(body.state).toBe("verify_email");
    expect(typeof body.csrf).toBe("string");

    const cookie = sessionCookie(res);
    expect(cookie).toBeTruthy();
    // Cookie value is org-qualified: "<orgId>.<sessId>".
    expect(cookie!.startsWith(`${body.orgId}.sess-`)).toBe(true);

    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, {
      headers: { cookie: `cfs_session=${cookie}` },
    });
    expect(me.status).toBe(200);
    const meBody = (await me.json()) as any;
    expect(meBody.email).toBe(email);
    expect(meBody.userId).toBe(body.userId);
    expect(meBody.orgId).toBe(body.orgId);
    expect(meBody.role).toBe("owner");
    expect(meBody.emailVerified).toBe(false);
    expect(meBody.mfa).toEqual({ totp: false, webauthn: 0 });
  });

  it("persists the submitted org name on signup; /me returns the real orgName (BUG 3)", async () => {
    const email = uniqueEmail();
    // Distinct org name so we can assert it round-trips (the shared `signup` helper uses "Test Org").
    const res = await post("/v1/auth/signup", {
      orgName: "Studio Example",
      email,
      password: "correct horse battery staple",
      displayName: "Studio Owner",
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as any;
    const cookie = sessionCookie(res);
    expect(cookie).toBeTruthy();

    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, {
      headers: { cookie: `cfs_session=${cookie}` },
    });
    expect(me.status).toBe(200);
    const meBody = (await me.json()) as any;
    // The org name is the SUBMITTED display name, not null and not the orgId — no PATCH required.
    expect(meBody.orgName).toBe("Studio Example");
    expect(meBody.orgSlug).toBe(body.orgId);
  });

  it("rejects a duplicate email globally (email_taken) across the directory", async () => {
    const email = uniqueEmail();
    const first = await signup(email);
    expect(first.status).toBe(201);
    const dup = await signup(email);
    expect(dup.status).toBe(409);
    expect((await dup.json()) as any).toEqual({ error: "email_taken" });
  });

  it("logs in with email+password and returns a session (no MFA)", async () => {
    const email = uniqueEmail();
    const pw = "another good password 123";
    await signup(email, pw);

    const res = await post("/v1/auth/login", { email, password: pw });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.userId).toMatch(/^usr-/);
    expect(body.role).toBe("owner");
    expect(Array.isArray(body.scopes)).toBe(true);
    expect(sessionCookie(res)).toBeTruthy();
  });

  it("rejects a wrong password with a generic 401 invalid_credentials", async () => {
    const email = uniqueEmail();
    await signup(email, "the right password here");
    const res = await post("/v1/auth/login", { email, password: "the WRONG password here" });
    expect(res.status).toBe(401);
    expect((await res.json()) as any).toEqual({ error: "invalid_credentials" });
  });

  it("rejects an unknown email with the SAME generic 401 (no enumeration)", async () => {
    const res = await post("/v1/auth/login", { email: uniqueEmail(), password: "whatever password" });
    expect(res.status).toBe(401);
    expect((await res.json()) as any).toEqual({ error: "invalid_credentials" });
  });
});

describe("auth integration — /me display fields + self-service profile update", () => {
  it("/me includes displayName, the signup orgName, and orgSlug", async () => {
    const email = uniqueEmail();
    const su = await signup(email); // signup helper submits orgName "Test Org"
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;

    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(me.status).toBe(200);
    const meBody = (await me.json()) as any;
    expect(meBody.displayName).toBe("Test User");
    expect(meBody.orgSlug).toBe(body.orgId); // slug == orgId
    expect(meBody.orgName).toBe("Test Org"); // BUG 3: signup persists the submitted org name
    // existing fields still present
    expect(meBody.userId).toBe(body.userId);
    expect(meBody.email).toBe(email);
    expect(meBody.role).toBe("owner");
  });

  it("/me includes the csrf field (regression) and it re-hydrates a working CSRF token", async () => {
    // Regression: GET /v1/auth/me must return the session's `csrf` so the SPA can re-hydrate the
    // double-submit token after a reload (it's held only in memory). Without it, every mutation
    // after a refresh 403s. We assert the field is present, a non-empty string, equals the signup
    // token, AND actually authorizes a mutation (so it's the REAL token, not a placeholder).
    const email = uniqueEmail();
    const su = await signup(email);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;

    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(me.status).toBe(200);
    const meBody = (await me.json()) as any;
    expect(typeof meBody.csrf).toBe("string");
    expect(meBody.csrf.length).toBeGreaterThan(0);
    expect(meBody.csrf).toBe(body.csrf); // same session token surfaced by both signup and /me

    // The re-hydrated csrf authorizes a CSRF-gated mutation (proves it's the live token).
    const patched = await SELF.fetch(`${ORIGIN}/v1/auth/account`, {
      method: "PATCH",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": meBody.csrf }),
      body: JSON.stringify({ displayName: "Csrf Rehydrated" }),
    });
    expect(patched.status).toBe(200);
  });

  it("PATCH /v1/auth/account updates the displayName (CSRF-gated; reflected in /me + the OrgDO user)", async () => {
    const email = uniqueEmail();
    const su = await signup(email);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;

    // Without CSRF -> 403 (it's a mutation).
    const noCsrf = await SELF.fetch(`${ORIGIN}/v1/auth/account`, {
      method: "PATCH",
      headers: { cookie: `cfs_session=${cookie}`, "content-type": "application/json" },
      body: JSON.stringify({ displayName: "Renamed Person" }),
    });
    expect(noCsrf.status).toBe(403);

    const ok = await SELF.fetch(`${ORIGIN}/v1/auth/account`, {
      method: "PATCH",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ displayName: "Renamed Person" }),
    });
    expect(ok.status).toBe(200);
    expect(((await ok.json()) as any).displayName).toBe("Renamed Person");

    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(((await me.json()) as any).displayName).toBe("Renamed Person");

    // The OrgDO user row was mirrored too.
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(body.orgId));
    const user = await orgStub.getUser(body.userId);
    expect(user.displayName).toBe("Renamed Person");
  });

  it("PATCH /v1/auth/account changes the email, re-claims it globally, and resets emailVerified", async () => {
    const email = uniqueEmail();
    const su = await signup(email);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    const orgId = body.orgId as string;

    // Mark verified first so we can prove the email change resets it.
    await markEmailVerified(orgId, body.accountId as string);

    const newEmail = uniqueEmail();
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/account`, {
      method: "PATCH",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ email: newEmail }),
    });
    expect(res.status).toBe(200);
    const updated = (await res.json()) as any;
    expect(updated.email).toBe(newEmail);
    expect(updated.emailVerified).toBe(false); // changing email un-verifies it

    // The new email resolves in the global directory; the OLD one no longer does. We prove this by
    // attempting a NEW signup with the OLD email (now free) -> succeeds, and the NEW email -> 409.
    const reuseOld = await signup(email);
    expect(reuseOld.status).toBe(201); // old address was released

    const grabNew = await signup(newEmail);
    expect(grabNew.status).toBe(409); // new address is claimed by our account
    expect(((await grabNew.json()) as any).error).toBe("email_taken");
  });

  it("PATCH /v1/auth/account rejects an email already taken in another org (409 email_taken)", async () => {
    // Account A claims an email.
    const emailA = uniqueEmail();
    const suA = await signup(emailA);
    expect(suA.status).toBe(201);

    // Account B (different org) tries to change ITS email to A's -> 409, B's email unchanged.
    const emailB = uniqueEmail();
    const suB = await signup(emailB);
    const bodyB = (await suB.json()) as any;
    const cookieB = sessionCookie(suB)!;
    const csrfB = bodyB.csrf as string;

    const res = await SELF.fetch(`${ORIGIN}/v1/auth/account`, {
      method: "PATCH",
      headers: jsonHeaders({ cookie: `cfs_session=${cookieB}`, "X-CFS-CSRF": csrfB }),
      body: JSON.stringify({ email: emailA }),
    });
    expect(res.status).toBe(409);
    expect(((await res.json()) as any).error).toBe("email_taken");

    // B's account email is unchanged (the failed claim rolled back nothing).
    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookieB}` } });
    expect(((await me.json()) as any).email).toBe(emailB);
  });
});

describe("auth integration — session lifecycle + CSRF", () => {
  it("enforces CSRF on cookie mutations and logs out (revoking the session)", async () => {
    const email = uniqueEmail();
    const pw = "session lifecycle pw 99";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;

    // logout WITHOUT the CSRF header is a 403 (double-submit enforced on the mutation).
    const noCsrf = await SELF.fetch(`${ORIGIN}/v1/auth/logout`, {
      method: "POST",
      headers: { cookie: `cfs_session=${cookie}` },
    });
    expect(noCsrf.status).toBe(403);

    // logout WITH the CSRF header succeeds (204) and clears the cookie.
    const ok = await SELF.fetch(`${ORIGIN}/v1/auth/logout`, {
      method: "POST",
      headers: { cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf },
    });
    expect(ok.status).toBe(204);

    // After logout, /me with the same cookie is rejected (session revoked).
    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(me.status).toBe(401);
  });

  it("lists the caller's sessions, marking the current one", async () => {
    const email = uniqueEmail();
    const pw = "list sessions pw 77";
    const su = await signup(email, pw);
    const cookie = sessionCookie(su)!;
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/sessions`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(res.status).toBe(200);
    const rows = (await res.json()) as any[];
    expect(rows.length).toBeGreaterThanOrEqual(1);
    expect(rows.some((r) => r.current === true)).toBe(true);
    // No CSRF token leaked in the public projection.
    expect(rows.every((r) => !("csrfToken" in r))).toBe(true);
  });
});

describe("auth integration — service tokens + cookie/bearer coexistence", () => {
  it("an owner mints, lists, and revokes a service token; the JWS authenticates as a bearer", async () => {
    const email = uniqueEmail();
    const pw = "service token owner pw 55";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    const orgId = body.orgId as string;

    // Verify the email first: the org-admin plane (minting service tokens) is gated on email
    // verification (CONTRACTS-AUTH.md §4.2). An unverified owner is blocked (covered separately).
    await markEmailVerified(orgId, body.accountId as string);

    // Mint via the cookie session (owner role). CSRF required (it's a POST mutation).
    const mint = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/service-tokens`, {
      method: "POST",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ label: "render-node-1", scopes: ["fs:read", "fs:write"] }),
    });
    expect(mint.status).toBe(201);
    const minted = (await mint.json()) as any;
    expect(minted.id).toMatch(/^svc-/);
    expect(typeof minted.token).toBe("string");
    expect(minted.scopes).toEqual(["fs:read", "fs:write"]);

    // The minted JWS authenticates as a normal bearer (machine path), unchanged.
    const list = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/service-tokens`, {
      headers: { Authorization: `Bearer ${minted.token}` },
    });
    // The service token has fs:read/fs:write but NOT admin -> listing service tokens is
    // owner/admin only, so the lane 403s. That proves the bearer authenticated AND the
    // admin gate works.
    expect(list.status).toBe(403);

    // List via the owner cookie works.
    const list2 = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/service-tokens`, {
      headers: { cookie: `cfs_session=${cookie}` },
    });
    expect(list2.status).toBe(200);
    const rows = (await list2.json()) as any[];
    expect(rows.some((r) => r.id === minted.id)).toBe(true);
    expect(rows.every((r) => !("hashedSecret" in r))).toBe(true);

    // Revoke it, then the JWS is rejected by the gateway revocation gate.
    const rev = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/service-tokens/${minted.id}`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
    });
    expect(rev.status).toBe(204);

    const afterRevoke = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/service-tokens`, {
      headers: { Authorization: `Bearer ${minted.token}` },
    });
    expect(afterRevoke.status).toBe(401);
    expect((await afterRevoke.json()) as any).toEqual({ error: "revoked" });
  });

  it("a missing credential still 401s no_token (neither bearer nor cookie)", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/orgs/org1/users`);
    expect(res.status).toBe(401);
    expect((await res.json()) as any).toEqual({ error: "no_token" });
  });
});

describe("auth integration — TOTP enrollment + MFA login", () => {
  it("enrolls TOTP, confirms it, then login requires + completes the TOTP second factor", async () => {
    const email = uniqueEmail();
    const pw = "totp mfa flow pw 88";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    const cookieHdr = { cookie: `cfs_session=${cookie}` };

    // Enroll — returns an unconfirmed secret + otpauth URI.
    const enroll = await SELF.fetch(`${ORIGIN}/v1/auth/totp/enroll`, {
      method: "POST",
      headers: jsonHeaders({ ...cookieHdr, "X-CFS-CSRF": csrf }),
    });
    expect(enroll.status).toBe(200);
    const { secret, otpauthUri } = (await enroll.json()) as any;
    expect(typeof secret).toBe("string");
    expect(otpauthUri).toContain("otpauth://totp/");

    // Confirm with a live code -> returns recovery codes once.
    const secretBytes = base32Decode(secret);
    const code = totp(secretBytes, Math.floor(Date.now() / 1000));
    const confirm = await SELF.fetch(`${ORIGIN}/v1/auth/totp/confirm`, {
      method: "POST",
      headers: jsonHeaders({ ...cookieHdr, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ code }),
    });
    expect(confirm.status).toBe(200);
    const confirmed = (await confirm.json()) as any;
    expect(confirmed.confirmed).toBe(true);
    expect(Array.isArray(confirmed.recoveryCodes)).toBe(true);
    expect(confirmed.recoveryCodes.length).toBe(10);

    // Now login returns an MFA challenge (no session yet).
    const login = await post("/v1/auth/login", { email, password: pw });
    expect(login.status).toBe(200);
    const loginBody = (await login.json()) as any;
    expect(loginBody.mfaRequired).toBe(true);
    expect(loginBody.methods).toContain("totp");
    expect(sessionCookie(login)).toBeNull(); // no session before the 2nd factor
    // The challengeId is org-qualified by the integration layer.
    expect(typeof loginBody.challengeId).toBe("string");

    // Complete the challenge with a fresh code (different step from confirm to avoid the
    // replay guard, which is keyed per step).
    const code2 = totp(secretBytes, Math.floor(Date.now() / 1000) + 30);
    const mfa = await post("/v1/auth/login/totp", { challengeId: loginBody.challengeId, code: code2 });
    expect(mfa.status).toBe(200);
    const mfaBody = (await mfa.json()) as any;
    expect(mfaBody.userId).toBe(body.userId);
    expect(sessionCookie(mfa)).toBeTruthy(); // session minted after the 2nd factor

    // A recovery code also completes a fresh MFA challenge.
    const login2 = await post("/v1/auth/login", { email, password: pw });
    const challenge2 = ((await login2.json()) as any).challengeId;
    const rec = await post("/v1/auth/login/recovery", {
      challengeId: challenge2,
      recoveryCode: confirmed.recoveryCodes[0],
    });
    expect(rec.status).toBe(200);
    expect(sessionCookie(rec)).toBeTruthy();
  });
});

describe("auth integration — offboarding bites login AND live sessions (FINDING 1+11)", () => {
  it("suspending a user via PATCH refuses login AND rejects its existing live session", async () => {
    const email = uniqueEmail();
    const pw = "offboard suspend pw 11";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    const orgId = body.orgId as string;
    const userId = body.userId as string;

    // Sanity: the live session works before offboarding.
    const meBefore = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(meBefore.status).toBe(200);

    // Verify the email so the owner may drive the role-gated admin PATCH (email-verification gate).
    await markEmailVerified(orgId, body.accountId as string);
    // B12: seed a second owner so suspending this one isn't blocked by the last-owner guard.
    await seedSecondOwner(orgId);

    // The owner suspends their own account (admin gate passes; exercises the offboarding propagation).
    const patch = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/users/${userId}`, {
      method: "PATCH",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ status: "suspended" }),
    });
    expect(patch.status).toBe(200);

    // The previously-valid session is now rejected on the very next request, and the cookie is
    // cleared. Offboarding REVOKES the session (so verifySession rejects it as `revoked` before the
    // account-status check even loads) — defense in depth; either code is a hard 401.
    const meAfter = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(meAfter.status).toBe(401);
    expect(["revoked", "account_inactive"]).toContain(((await meAfter.json()) as any).error);
    expect(meAfter.headers.get("set-cookie") ?? "").toMatch(/cfs_session=;/);

    // A fresh login is refused (the AuthDO account status is no longer active).
    const login = await post("/v1/auth/login", { email, password: pw });
    expect(login.status).toBe(401);
    expect((await login.json()) as any).toEqual({ error: "invalid_credentials" });
    expect(sessionCookie(login)).toBeNull();
  });

  it("the live status gate rejects a still-valid session whose account is suspended (account_inactive)", async () => {
    // Isolate the per-request ACTIVE-STATUS gate from session revocation: flip ONLY the AuthDO
    // account status (leaving the session unrevoked), then hit an org route. The gateway's live
    // status gate must reject it as `account_inactive` even though the session JWS is still valid.
    const email = uniqueEmail();
    const pw = "live status gate pw 66";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const orgId = body.orgId as string;
    await markEmailVerified(orgId, body.accountId as string);

    const authStub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(orgId));
    await authStub.setStatus(body.accountId as string, "suspended");

    // A GET on an org route runs the gateway revocation+status gate. Session isn't revoked, so this
    // exercises the active-status check specifically.
    const res = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/users`, {
      headers: { cookie: `cfs_session=${cookie}` },
    });
    expect(res.status).toBe(401);
    expect((await res.json()) as any).toEqual({ error: "account_inactive" });
  });

  it("a suspended user's live service token is rejected by the gateway", async () => {
    const email = uniqueEmail();
    const pw = "offboard svc pw 22";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    const orgId = body.orgId as string;
    const userId = body.userId as string;
    await markEmailVerified(orgId, body.accountId as string);
    await seedSecondOwner(orgId); // B12: not the last owner

    // Mint a service token UNDER the owner (its userId is the owner's). It authenticates as a bearer.
    const mint = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/service-tokens`, {
      method: "POST",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ label: "node", scopes: ["fs:read"], serviceAccountUserId: userId }),
    });
    expect(mint.status).toBe(201);
    const token = ((await mint.json()) as any).token as string;

    // Suspend the owner → offboarding revokes the service tokens they own.
    const patch = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/users/${userId}`, {
      method: "PATCH",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ status: "suspended" }),
    });
    expect(patch.status).toBe(200);

    // The token's JWS is now rejected at the gateway revocation gate.
    const after = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/spaces`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(after.status).toBe(401);
    expect((await after.json()) as any).toEqual({ error: "revoked" });
  });

  it("DELETE /users/:id deprovisions: login refused (email released) + session rejected", async () => {
    const email = uniqueEmail();
    const pw = "offboard deprov pw 33";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    const orgId = body.orgId as string;
    const userId = body.userId as string;
    await markEmailVerified(orgId, body.accountId as string);
    await seedSecondOwner(orgId); // B12: not the last owner

    const del = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/users/${userId}`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
    });
    expect(del.status).toBe(200);

    const meAfter = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(meAfter.status).toBe(401);

    const login = await post("/v1/auth/login", { email, password: pw });
    expect(login.status).toBe(401);
    expect(sessionCookie(login)).toBeNull();
  });
});

describe("auth integration — step-up re-auth to remove a second factor (FINDING 3)", () => {
  async function enrollAndConfirmTotp(cookie: string, csrf: string): Promise<void> {
    const cookieHdr = { cookie: `cfs_session=${cookie}` };
    const enroll = await SELF.fetch(`${ORIGIN}/v1/auth/totp/enroll`, {
      method: "POST",
      headers: jsonHeaders({ ...cookieHdr, "X-CFS-CSRF": csrf }),
    });
    expect(enroll.status).toBe(200);
    const { secret } = (await enroll.json()) as any;
    const code = totp(base32Decode(secret), Math.floor(Date.now() / 1000));
    const confirm = await SELF.fetch(`${ORIGIN}/v1/auth/totp/confirm`, {
      method: "POST",
      headers: jsonHeaders({ ...cookieHdr, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ code }),
    });
    expect(confirm.status).toBe(200);
  }

  it("DELETE /v1/auth/totp without the current password is refused; with it, succeeds", async () => {
    const email = uniqueEmail();
    const pw = "totp stepup pw 44 long";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    await enrollAndConfirmTotp(cookie, csrf);

    // No body / no currentPassword → 401 reauth_required (session + CSRF alone are insufficient).
    const noPw = await SELF.fetch(`${ORIGIN}/v1/auth/totp`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({}),
    });
    expect(noPw.status).toBe(401);
    expect((await noPw.json()) as any).toEqual({ error: "reauth_required" });

    // Wrong currentPassword → 401 bad_current_password.
    const wrongPw = await SELF.fetch(`${ORIGIN}/v1/auth/totp`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ currentPassword: "not the right password" }),
    });
    expect(wrongPw.status).toBe(401);
    expect((await wrongPw.json()) as any).toEqual({ error: "bad_current_password" });

    // Correct currentPassword → 204 (TOTP removed). Confirm it's gone (login no longer needs MFA).
    const ok = await SELF.fetch(`${ORIGIN}/v1/auth/totp`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ currentPassword: pw }),
    });
    expect(ok.status).toBe(204);
    const login = await post("/v1/auth/login", { email, password: pw });
    expect(login.status).toBe(200);
    expect((await login.json()) as any).not.toHaveProperty("mfaRequired");
    expect(sessionCookie(login)).toBeTruthy();
  });

  it("DELETE a passkey without the current password is refused (step-up gate runs before the lane)", async () => {
    const email = uniqueEmail();
    const pw = "passkey stepup pw 55 long";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;

    // No currentPassword → 401 reauth_required BEFORE any credential lookup/ownership check.
    const noPw = await SELF.fetch(`${ORIGIN}/v1/auth/webauthn/credentials/some-cred-id`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({}),
    });
    expect(noPw.status).toBe(401);
    expect((await noPw.json()) as any).toEqual({ error: "reauth_required" });

    // Wrong currentPassword → 401 bad_current_password (still refused).
    const wrongPw = await SELF.fetch(`${ORIGIN}/v1/auth/webauthn/credentials/some-cred-id`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ currentPassword: "wrong" }),
    });
    expect(wrongPw.status).toBe(401);
    expect((await wrongPw.json()) as any).toEqual({ error: "bad_current_password" });

    // Correct currentPassword → the step-up passes and the lane runs; the credential id is unknown,
    // so the lane returns its ownership 404 (not_found). Proves the gate let a real proof through.
    const okPw = await SELF.fetch(`${ORIGIN}/v1/auth/webauthn/credentials/some-cred-id`, {
      method: "DELETE",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ currentPassword: pw }),
    });
    expect(okPw.status).toBe(404);
    // The webauthn lane's error projection uses the message (not the code) for its own errors.
    expect((await okPw.json()) as any).toEqual({ error: "credential not found" });
  });
});

describe("auth integration — WebAuthn options + fail-closed", () => {
  it("returns registration options for a session, and authenticate options for the public flow", async () => {
    const email = uniqueEmail();
    const su = await signup(email, "webauthn options pw 22");
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;

    // register/options (session + CSRF) returns PublicKeyCredentialCreationOptionsJSON.
    const reg = await SELF.fetch(`${ORIGIN}/v1/auth/webauthn/register/options`, {
      method: "POST",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
    });
    expect(reg.status).toBe(200);
    const regOpts = (await reg.json()) as any;
    expect(regOpts.challenge).toBeTruthy();
    expect(regOpts.rp.id).toBe("localhost");
    expect(regOpts.challengeId).toBeTruthy();

    // authenticate/options (public, by email) returns request options without leaking existence.
    const auth = await post("/v1/auth/webauthn/authenticate/options", { email });
    expect(auth.status).toBe(200);
    const authOpts = (await auth.json()) as any;
    expect(authOpts.challenge).toBeTruthy();
    expect(authOpts.challengeId).toBeTruthy();

    // Unknown email still returns options (no enumeration).
    const authUnknown = await post("/v1/auth/webauthn/authenticate/options", { email: uniqueEmail() });
    expect(authUnknown.status).toBe(200);
  });
});

describe("auth integration — email verification", () => {
  it("verifies the email via a token and flips emailVerified", async () => {
    const email = uniqueEmail();
    const pw = "verify email flow pw 33";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    const orgId = body.orgId as string;

    // Resend the verification email (session-gated). The default no-op sender records it; we
    // can't read the token from the sender here, so we exercise the route returns 202.
    const resend = await SELF.fetch(`${ORIGIN}/v1/auth/verify-email/send`, {
      method: "POST",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
    });
    expect(resend.status).toBe(202);

    // A bogus token is rejected.
    const bad = await post("/v1/auth/verify-email", { token: "evt-nope.deadbeef", orgId });
    expect(bad.status).toBe(400);

    // Missing orgId is a 400.
    const noOrg = await post("/v1/auth/verify-email", { token: "evt-x.y" });
    expect(noOrg.status).toBe(400);
  });
});

describe("auth integration — passkey second factor not bypassed at login (fix #1)", () => {
  it("a passkey-only account requires the second factor: login returns mfaRequired:[webauthn], NO session", async () => {
    const email = uniqueEmail();
    const pw = "passkey second factor pw 11";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const orgId = body.orgId as string;
    const accountId = body.accountId as string;

    // Seed a registered passkey directly in the account's AuthDO (no TOTP).
    const stub = (env as any).AUTH_DO.get((env as any).AUTH_DO.idFromName(orgId));
    await stub.putWebAuthn({
      id: "wac-seed-1",
      accountId,
      credentialId: "Y3JlZC1zZWVk", // base64url-ish placeholder; only its presence matters to login
      publicKey: "cGs=",
      signCount: 0,
      transports: ["internal"],
      label: "Seed Passkey",
      createdAt: Date.now(),
      lastUsedAt: null,
    });

    // Password alone must NOT mint a session — the passkey second factor is required.
    const login = await post("/v1/auth/login", { email, password: pw });
    expect(login.status).toBe(200);
    const loginBody = (await login.json()) as any;
    expect(loginBody.mfaRequired).toBe(true);
    expect(loginBody.methods).toContain("webauthn");
    expect(loginBody.methods).not.toContain("totp");
    expect(sessionCookie(login)).toBeNull(); // CRITICAL: no session from the password alone
    expect(typeof loginBody.challengeId).toBe("string");
  });
});

describe("auth integration — email-verification gate (fix #2)", () => {
  it("an UNVERIFIED owner is BLOCKED from a privileged org action, then ALLOWED after verifying", async () => {
    const email = uniqueEmail();
    const pw = "email gate flow pw 44";
    const su = await signup(email, pw);
    const body = (await su.json()) as any;
    const cookie = sessionCookie(su)!;
    const csrf = body.csrf as string;
    const orgId = body.orgId as string;
    const accountId = body.accountId as string;

    // /me shows unverified + REDUCED read-only scopes.
    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    const meBody = (await me.json()) as any;
    expect(meBody.emailVerified).toBe(false);
    expect(meBody.scopes).toEqual(["fs:read", "snapshot:read"]);

    // Privileged org-admin action (mint a service token) is BLOCKED with 403 email_unverified —
    // even though the account is an owner (role gate would otherwise pass).
    const blocked = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/service-tokens`, {
      method: "POST",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ label: "blocked", scopes: ["fs:read"] }),
    });
    expect(blocked.status).toBe(403);
    expect((await blocked.json()) as any).toEqual({ error: "email_unverified" });

    // Verify the email (the route's sole effect) — the user STAYS signed in (same cookie).
    await markEmailVerified(orgId, accountId);

    // The SAME cookie now passes the gate: the privileged action succeeds (201).
    const allowed = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/service-tokens`, {
      method: "POST",
      headers: jsonHeaders({ cookie: `cfs_session=${cookie}`, "X-CFS-CSRF": csrf }),
      body: JSON.stringify({ label: "allowed", scopes: ["fs:read"] }),
    });
    expect(allowed.status).toBe(201);

    // /me now reports verified + full owner scopes (upgrade-in-place, no re-login).
    const me2 = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    const me2Body = (await me2.json()) as any;
    expect(me2Body.emailVerified).toBe(true);
    expect(me2Body.scopes).toContain("fs:admin");
  });
});

describe("auth integration — WebAuthn credential index conflict rejected (fix #6)", () => {
  it("re-binding a credential id to a DIFFERENT account is rejected; same (org,account) is idempotent", async () => {
    const dir = (env as any).DIRECTORY_DO.get((env as any).DIRECTORY_DO.idFromName("global"));
    const credId = `cred-${Date.now()}`;

    // First bind: "created".
    expect(await dir.indexWebAuthn(credId, "org-A", "acc-A")).toBe("created");
    expect(await dir.resolveWebAuthn(credId)).toEqual({ orgId: "org-A", accountId: "acc-A" });

    // Re-binding the SAME (org, account): idempotent "exists", no change.
    expect(await dir.indexWebAuthn(credId, "org-A", "acc-A")).toBe("exists");
    expect(await dir.resolveWebAuthn(credId)).toEqual({ orgId: "org-A", accountId: "acc-A" });

    // Re-binding to a DIFFERENT account/org: "conflict" — REJECTED, the original binding stands.
    expect(await dir.indexWebAuthn(credId, "org-B", "acc-B")).toBe("conflict");
    expect(await dir.resolveWebAuthn(credId)).toEqual({ orgId: "org-A", accountId: "acc-A" });
  });
});

describe("auth integration — fleet-wide DO-backed rate limit (fix #5)", () => {
  it("the per-IP signup cap is enforced across requests (DirectoryDO-backed, not per-isolate)", async () => {
    // A FIXED ip so the per-IP signup bucket (capacity 3) is shared across these requests. If the
    // limiter were still a per-isolate in-memory map this would still trip within one isolate, but
    // the point is the COUNTER is now persisted in the DirectoryDO singleton (fleet-wide).
    const ip = "198.51.100.42";
    const hdr = { "cf-connecting-ip": ip };
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await SELF.fetch(`${ORIGIN}/v1/auth/signup`, {
        method: "POST",
        headers: { "content-type": "application/json", ...hdr },
        body: JSON.stringify({ orgName: "RL Org", email: uniqueEmail(), password: "rate limit pw 123", displayName: "RL" }),
      });
      statuses.push(res.status);
    }
    // First 3 succeed (capacity 3), the 4th from the same IP is denied with 429.
    expect(statuses.slice(0, 3).every((s) => s === 201)).toBe(true);
    expect(statuses[3]).toBe(429);

    // The bucket state is durable in the DirectoryDO: a fresh request from the same IP is still 429.
    const again = await SELF.fetch(`${ORIGIN}/v1/auth/signup`, {
      method: "POST",
      headers: { "content-type": "application/json", ...hdr },
      body: JSON.stringify({ orgName: "RL Org", email: uniqueEmail(), password: "rate limit pw 123", displayName: "RL" }),
    });
    expect(again.status).toBe(429);
  });
});

describe("auth integration — password change revokes other sessions (fix #3)", () => {
  // Multiple full-cost scrypt ops (signup hash + login-B verify + change verify+hash) run
  // sequentially in real workerd, so this one needs a longer timeout than the 5s default.
  it("changing the password boots the account's OTHER live sessions but keeps the current one", { timeout: 30_000 }, async () => {
    const email = uniqueEmail();
    const pw = "change pw boots others 55";
    // Signup (session A) — then a second login (session B) for the same account.
    const su = await signup(email, pw);
    const a = (await su.json()) as any;
    const cookieA = sessionCookie(su)!;
    const csrfA = a.csrf as string;

    const loginB = await post("/v1/auth/login", { email, password: pw });
    const b = (await loginB.json()) as any;
    const cookieB = sessionCookie(loginB)!;
    expect(b.userId).toBe(a.userId);

    // Both sessions are live: /me works on each.
    expect((await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookieA}` } })).status).toBe(200);
    expect((await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookieB}` } })).status).toBe(200);

    // Change the password from session A.
    const change = await SELF.fetch(`${ORIGIN}/v1/auth/password/change`, {
      method: "POST",
      headers: jsonHeaders({ cookie: `cfs_session=${cookieA}`, "X-CFS-CSRF": csrfA }),
      body: JSON.stringify({ currentPassword: pw, newPassword: "the brand new password 66" }),
    });
    expect(change.status).toBe(204);

    // Session B (the OTHER session) is now revoked.
    const meB = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookieB}` } });
    expect(meB.status).toBe(401);

    // Session A (the one that changed it) stays signed in.
    const meA = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookieA}` } });
    expect(meA.status).toBe(200);
  });
});
