import { seedOwnerFixture } from "./setup-fixture";
// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-join.test.ts — end-to-end through the real worker: `POST /v1/auth/join` +
// `GET /v1/auth/join/preview` (Build step 1 of ONBOARDING.md). Proves the invite-redeem gap is
// closed: an invitee goes from an emailed (org-qualified) join token to a signed-in session with
// a real credential, OrgDO membership, and (for a scoped invite) a synced ACL grant — all in one
// atomic call. Also covers the invite-creation `emailSent`/`joinToken` additions in invites.ts.
//
// Uses SELF.fetch so the whole gateway path (rate limits, DirectoryDO dedupe, OrgDO/AuthDO/
// FilespaceDO writes) runs in real workerd (Miniflare), mirroring auth-integration.test.ts.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { filespaceDoName } from "../src/security/auth";

const ORIGIN = "https://gw.local";
const BOOT_SECRET = "local-dev-bootstrap-secret-change-me-32chars";

// Every request gets a DISTINCT client IP (mirrors auth-integration.test.ts) so the tight
// per-IP signup/login/join buckets never collide across unrelated assertions in this file.
let ipCounter = 0;
function freshIp(): string {
  ipCounter++;
  return `203.2.${Math.floor(ipCounter / 256) % 256}.${ipCounter % 256}`;
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

let orgCounter = 0;
function freshOrgId(): string {
  orgCounter++;
  return `join-org-${Date.now()}-${orgCounter}`;
}
let emailCounter = 0;
function uniqueEmail(): string {
  emailCounter++;
  return `invitee-${Date.now()}-${emailCounter}@example.test`;
}

/// Seed a fresh org + owner via the deploy-time bootstrap route (token-only — no owner password
/// needed for these tests, mirrors email-config-integration.test.ts's convention).
const bootstrapOrg = seedOwnerFixture;

async function createInvite(orgId: string, ownerToken: string, body: Record<string, unknown>): Promise<Response> {
  return SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/invites`, {
    method: "POST",
    headers: jsonHeaders({ Authorization: `Bearer ${ownerToken}` }),
    body: JSON.stringify(body),
  });
}

function joinRequest(token: string, displayName: string, password: string): Promise<Response> {
  return SELF.fetch(`${ORIGIN}/v1/auth/join`, {
    method: "POST",
    headers: jsonHeaders(),
    body: JSON.stringify({ token, displayName, password }),
  });
}

describe("POST /v1/auth/join — happy path (account + membership + grant + session, one call)", () => {
  it("joins a SCOPED invite: account created, verified, OrgDO membership + ACL grant land, full-scope session minted", async () => {
    const orgId = freshOrgId();
    const { token: ownerToken } = await bootstrapOrg(orgId);

    // Pre-create the target folder so the scoped grant actually syncs — `syncGrant` leaves a
    // grant DORMANT until the inode exists in the space's namespace (same as production).
    const spaceId = "active-edit";
    const fsStub = (env as any).FILESPACE.get((env as any).FILESPACE.idFromName(filespaceDoName(orgId, spaceId)));
    const created = (await fsStub.createItem("root", "color", true, 0)) as { item: { id: string } };
    const inodeId = created.item.id;

    const email = uniqueEmail();
    const inviteRes = await createInvite(orgId, ownerToken, {
      email, role: "standard", scope: { spaceId, inodeId, level: "edit" },
    });
    expect(inviteRes.status).toBe(201);
    const invite = (await inviteRes.json()) as any;
    // joinToken is the ORG-QUALIFIED form (device-code precedent): "<orgId>.inv-<id>.<secret>".
    expect(invite.joinToken.startsWith(`${orgId}.inv-`)).toBe(true);
    expect(invite.rawToken.startsWith("inv-")).toBe(true); // unqualified rawToken is unchanged
    // No delivering email provider is configured in the test runtime (console/fake sender).
    expect(invite.emailSent).toBe(false);

    const joinRes = await joinRequest(invite.joinToken, "Priya Invitee", "a very good invite password");
    expect(joinRes.status).toBe(201);
    const joined = (await joinRes.json()) as any;
    expect(joined.orgId).toBe(orgId);
    expect(joined.role).toBe("standard");
    expect(joined.emailVerified).toBe(true);
    expect(joined.state).toBe("active");
    expect(typeof joined.csrf).toBe("string");
    // Full role scopes immediately — NOT the reduced signup UNVERIFIED_SCOPES set.
    expect(joined.scopes).toEqual(expect.arrayContaining(["fs:read", "fs:write"]));
    expect(joined.scopes).not.toContain("fs:admin"); // standard role, not owner/admin

    const cookie = sessionCookie(joinRes);
    expect(cookie).toBeTruthy();
    expect(cookie!.startsWith(`${orgId}.sess-`)).toBe(true);

    // The minted cookie works immediately and reports verified + the right identity.
    const me = await SELF.fetch(`${ORIGIN}/v1/auth/me`, { headers: { cookie: `cfs_session=${cookie}` } });
    expect(me.status).toBe(200);
    const meBody = (await me.json()) as any;
    expect(meBody.email).toBe(email);
    expect(meBody.userId).toBe(joined.userId);
    expect(meBody.emailVerified).toBe(true);

    // The password credential set during join also logs in on its own.
    const login = await SELF.fetch(`${ORIGIN}/v1/auth/login`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ email, password: "a very good invite password" }),
    });
    expect(login.status).toBe(200);

    // OrgDO membership landed with the invited role.
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    const user = await orgStub.getUser(joined.userId);
    expect(user.role).toBe("standard");
    expect(user.email).toBe(email);

    // The scoped ACL grant synced into the target space's enforcement store.
    const grants = await fsStub.listGrants(inodeId);
    expect(grants.some((g: any) => g.principalId === joined.userId && g.level === "edit")).toBe(true);

    // Single-use: a second join with the SAME token is refused (invite already accepted).
    const again = await joinRequest(invite.joinToken, "Second Try", "another good password 22");
    expect(again.status).toBe(409);
    expect(((await again.json()) as any).error).toBe("already_used");
  });

  it("joins an UNSCOPED invite (role-only, no grant expected)", async () => {
    const orgId = freshOrgId();
    const { token: ownerToken } = await bootstrapOrg(orgId);
    const email = uniqueEmail();
    const inviteRes = await createInvite(orgId, ownerToken, { email, role: "admin" });
    expect(inviteRes.status).toBe(201);
    const invite = (await inviteRes.json()) as any;

    const joinRes = await joinRequest(invite.joinToken, "Unscoped Joiner", "unscoped joiner password 1");
    expect(joinRes.status).toBe(201);
    const joined = (await joinRes.json()) as any;
    expect(joined.role).toBe("admin");
    expect(joined.scopes).toContain("fs:admin");
  });
});

describe("POST /v1/auth/join — invite validation errors (shared with the org-scoped redeem route)", () => {
  it("404s an unknown/malformed token without leaking whether the org exists", async () => {
    const res = await joinRequest("bogus-org.inv-nope.secret", "X", "whatever password 123");
    expect(res.status).toBe(404);
    expect(((await res.json()) as any).error).toBe("not_found");
  });

  it("410s an expired invite", async () => {
    const orgId = freshOrgId();
    const { token: ownerToken } = await bootstrapOrg(orgId);
    const inviteRes = await createInvite(orgId, ownerToken, { email: uniqueEmail(), role: "standard", ttlMs: -1 });
    expect(inviteRes.status).toBe(201);
    const invite = (await inviteRes.json()) as any;

    const res = await joinRequest(invite.joinToken, "X", "whatever password 123");
    expect(res.status).toBe(410);
    expect(((await res.json()) as any).error).toBe("expired");
  });

  it("410s a revoked invite", async () => {
    const orgId = freshOrgId();
    const { token: ownerToken } = await bootstrapOrg(orgId);
    const inviteRes = await createInvite(orgId, ownerToken, { email: uniqueEmail(), role: "standard" });
    const invite = (await inviteRes.json()) as any;

    const revoke = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/invites/${encodeURIComponent(invite.invite.id)}`, {
      method: "DELETE",
      headers: jsonHeaders({ Authorization: `Bearer ${ownerToken}` }),
    });
    expect(revoke.status).toBe(200);

    const res = await joinRequest(invite.joinToken, "X", "whatever password 123");
    expect(res.status).toBe(410);
    expect(((await res.json()) as any).error).toBe("revoked");
  });

  it("409s email_taken when the invited address already has an account, and leaves the invite PENDING", async () => {
    const orgId = freshOrgId();
    const { token: ownerToken } = await bootstrapOrg(orgId);
    const email = uniqueEmail();

    // A completely separate account claims the email first (e.g. self-serve signup elsewhere).
    const su = await SELF.fetch(`${ORIGIN}/v1/auth/signup`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ orgName: "Other Org", email, password: "already has an account pw", displayName: "Already" }),
    });
    expect(su.status).toBe(201);

    const inviteRes = await createInvite(orgId, ownerToken, { email, role: "standard" });
    const invite = (await inviteRes.json()) as any;

    const res = await joinRequest(invite.joinToken, "X", "whatever password 123");
    expect(res.status).toBe(409);
    expect(((await res.json()) as any).error).toBe("email_taken");

    // Untouched: still listed as pending, so it can be revoked/reissued or retried later.
    const pending = await SELF.fetch(`${ORIGIN}/v1/orgs/${orgId}/invites`, {
      headers: jsonHeaders({ Authorization: `Bearer ${ownerToken}` }),
    });
    const list = (await pending.json()) as any[];
    expect(list.some((i) => i.id === invite.invite.id)).toBe(true);
  });
});

describe("POST /v1/auth/join — request validation (before any invite/DO lookup)", () => {
  it("400s a missing/non-string token", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/join`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ displayName: "X", password: "whatever password 123" }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_token");
  });

  it("400s an empty display name", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/join`, {
      method: "POST",
      headers: jsonHeaders(),
      body: JSON.stringify({ token: "org-x.inv-y.z", displayName: "   ", password: "whatever password 123" }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_display_name");
  });

  it("400s a too-short password before touching the invite", async () => {
    const res = await joinRequest("org-x.inv-y.z", "X", "short");
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("weak_password");
  });

  it("400s malformed JSON", async () => {
    const res = await SELF.fetch(`${ORIGIN}/v1/auth/join`, {
      method: "POST",
      headers: jsonHeaders(),
      body: "{not json",
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("invalid_json");
  });
});

describe("GET /v1/auth/join/preview", () => {
  it("returns org name, invited email, role, and expiry for a valid token", async () => {
    const orgId = freshOrgId();
    const { token: ownerToken } = await bootstrapOrg(orgId);
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    await orgStub.setOrgName("Preview Org");

    const email = uniqueEmail();
    const inviteRes = await createInvite(orgId, ownerToken, { email, role: "admin" });
    const invite = (await inviteRes.json()) as any;

    const res = await SELF.fetch(`${ORIGIN}/v1/auth/join/preview?token=${encodeURIComponent(invite.joinToken)}`, {
      headers: jsonHeaders(),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.orgName).toBe("Preview Org");
    expect(body.email).toBe(email);
    expect(body.role).toBe("admin");
    expect(typeof body.expiresAt).toBe("number");
    expect(body.invitedByName).toBe("Owner");
  });

  it("404s an unknown token; missing token is also a 404", async () => {
    const unknown = await SELF.fetch(`${ORIGIN}/v1/auth/join/preview?token=org-x.inv-y.z`, { headers: jsonHeaders() });
    expect(unknown.status).toBe(404);
    expect(((await unknown.json()) as any).error).toBe("not_found");

    const missing = await SELF.fetch(`${ORIGIN}/v1/auth/join/preview`, { headers: jsonHeaders() });
    expect(missing.status).toBe(404);
  });

  it("410s an already-used invite", async () => {
    const orgId = freshOrgId();
    const { token: ownerToken } = await bootstrapOrg(orgId);
    const inviteRes = await createInvite(orgId, ownerToken, { email: uniqueEmail(), role: "standard" });
    const invite = (await inviteRes.json()) as any;

    const joinRes = await joinRequest(invite.joinToken, "X", "whatever password 123");
    expect(joinRes.status).toBe(201);

    const used = await SELF.fetch(`${ORIGIN}/v1/auth/join/preview?token=${encodeURIComponent(invite.joinToken)}`, {
      headers: jsonHeaders(),
    });
    expect(used.status).toBe(410);
    expect(((await used.json()) as any).error).toBe("already_used");
  });
});

describe("POST /v1/orgs/:org/invites — emailSent + joinToken (Build step 1 additions)", () => {
  it("create response carries an org-qualified joinToken and an honest emailSent:false (no provider configured)", async () => {
    const orgId = freshOrgId();
    const { token: ownerToken } = await bootstrapOrg(orgId);
    const res = await createInvite(orgId, ownerToken, { email: uniqueEmail(), role: "standard" });
    expect(res.status).toBe(201);
    const body = (await res.json()) as any;
    expect(body.emailSent).toBe(false);
    expect(typeof body.joinToken).toBe("string");
    expect(body.joinToken.startsWith(`${orgId}.`)).toBe(true);
    expect(body.rawToken.startsWith("inv-")).toBe(true);
  });
});
