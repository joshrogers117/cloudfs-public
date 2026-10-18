// SPDX-License-Identifier: AGPL-3.0-or-later
// role-transition.test.ts — audit B12: role-assignment policy + last-owner guard.
import { SELF, env, runInDurableObject } from "cloudflare:test";
import type { OrgDO } from "../src/org-do";
import { describe, it, expect } from "vitest";
import { evaluateRoleAssignment, orgRoleRank } from "../src/permissions";
import { mintToken, type Scope } from "../src/security/auth";

const ALL: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];

describe("B12: evaluateRoleAssignment (pure policy)", () => {
  it("rejects an unknown role", () => {
    const d = evaluateRoleAssignment({ actorRole: "owner", actorUserId: "a", targetUserId: "b", requestedRole: "superuser" });
    expect(d).toEqual({ allowed: false, code: "unknown_role" });
  });
  it("only an owner may assign the owner role", () => {
    expect(evaluateRoleAssignment({ actorRole: "admin", actorUserId: "a", targetUserId: "b", requestedRole: "owner" }))
      .toEqual({ allowed: false, code: "owner_requires_owner" });
    expect(evaluateRoleAssignment({ actorRole: "owner", actorUserId: "a", targetUserId: "b", requestedRole: "owner" }))
      .toEqual({ allowed: true });
  });
  it("an actor cannot assign a role above their own tier", () => {
    expect(evaluateRoleAssignment({ actorRole: "space_admin", actorUserId: "a", targetUserId: "b", requestedRole: "admin" }))
      .toEqual({ allowed: false, code: "exceeds_actor_role" });
  });
  it("an actor cannot change their OWN role (self-elevation guard)", () => {
    expect(evaluateRoleAssignment({ actorRole: "admin", actorUserId: "a", targetUserId: "a", requestedRole: "admin" }))
      .toEqual({ allowed: false, code: "no_self_role_change" });
  });
  it("a normal admin promoting a standard user to admin is allowed", () => {
    expect(evaluateRoleAssignment({ actorRole: "admin", actorUserId: "a", targetUserId: "b", requestedRole: "admin" }))
      .toEqual({ allowed: true });
  });
  it("orgRoleRank orders roles correctly", () => {
    expect(orgRoleRank("owner")).toBeGreaterThan(orgRoleRank("admin"));
    expect(orgRoleRank("admin")).toBeGreaterThan(orgRoleRank("space_admin"));
    expect(orgRoleRank("space_admin")).toBeGreaterThan(orgRoleRank("standard"));
    expect(orgRoleRank("nope")).toBe(-1);
  });
});

// End-to-end through the real OrgDO: an admin cannot escalate to owner.
async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({ orgId, email: `${role}-${crypto.randomUUID()}@rt.test`, displayName: role, role });
  return u.id;
}
function tok(sub: string, orgId: string): Promise<string> {
  return mintToken((env as any).AUTH_SIGNING_SECRET, { sub, type: "session", orgId, scopes: ALL, ttlSeconds: 900 });
}

describe("B12: privilege-escalation is blocked end-to-end", () => {
  const ORG = "org-rt";
  it("an admin PATCHing their own id to owner is 403 (the escalation hole)", async () => {
    const adminId = await provisionUser(ORG, "admin");
    const auth = { Authorization: `Bearer ${await tok(adminId, ORG)}`, "content-type": "application/json" };
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${ORG}/users/${adminId}`, {
      method: "PATCH", headers: auth, body: JSON.stringify({ role: "owner" }),
    });
    expect(res.status).toBe(403);
    expect((await res.json() as any).error).toBe("forbidden_role_assignment");
  });

  it("an admin promoting a DIFFERENT user to owner is 403", async () => {
    const adminId = await provisionUser(ORG, "admin");
    const victimId = await provisionUser(ORG, "standard");
    const auth = { Authorization: `Bearer ${await tok(adminId, ORG)}`, "content-type": "application/json" };
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${ORG}/users/${victimId}`, {
      method: "PATCH", headers: auth, body: JSON.stringify({ role: "owner" }),
    });
    expect(res.status).toBe(403);
  });

  it("an owner CAN promote a standard user to admin (legitimate path still works)", async () => {
    const ownerId = await provisionUser(ORG, "owner");
    const memberId = await provisionUser(ORG, "standard");
    const auth = { Authorization: `Bearer ${await tok(ownerId, ORG)}`, "content-type": "application/json" };
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${ORG}/users/${memberId}`, {
      method: "PATCH", headers: auth, body: JSON.stringify({ role: "admin" }),
    });
    expect(res.status).toBe(200);
    expect((await res.json() as any).role).toBe("admin");
  });

  it("the last active owner cannot be demoted or suspended (DO-level last-owner guard)", async () => {
    const ORG2 = `org-rt-last-${crypto.randomUUID().slice(0, 8)}`;
    const ownerId = await provisionUser(ORG2, "owner"); // the SOLE owner
    const org = (env as any).ORG_DO.getByName(ORG2);
    // Demoting the only owner is refused.
    await expectLastOwnerRejection(async () => await org.setUserRole(ownerId, "admin"));
    // Suspending/deprovisioning the only owner is refused.
    // Catch the expected async failure inside the DO: the test RPC wrapper can
    // report an already-handled rejection as unhandled when it crosses realms.
    const statusFailure = await runInDurableObject(org, async (instance: OrgDO) => {
      try { await instance.setUserStatus(ownerId, "suspended"); return null; }
      catch (error) { return String(error); }
    });
    expect(statusFailure).toMatch(/last active owner/);
    // With a SECOND owner, demoting the first IS allowed (no longer the last).
    const secondOwner = await provisionUser(ORG2, "owner");
    const demoted = await org.setUserRole(ownerId, "admin");
    expect(demoted.role).toBe("admin");
    // Now `secondOwner` is the last owner — demoting it is refused again.
    await expectLastOwnerRejection(async () => await org.setUserRole(secondOwner, "admin"));
  });
});

async function expectLastOwnerRejection(operation: () => Promise<unknown>): Promise<void> {
  let failure: unknown;
  try { await operation(); } catch (error) { failure = error; }
  expect(String(failure)).toMatch(/last active owner/);
}

it("concurrent demotions always leave an active owner", async () => {
  const orgId = `owner-race-${crypto.randomUUID().slice(0, 8)}`;
  const ids = await Promise.all([provisionUser(orgId, "owner"), provisionUser(orgId, "owner")]);
  const org = (env as any).ORG_DO.getByName(orgId);
  const results = await Promise.all(ids.map(async id => {
    try { await org.setUserRole(id, "admin"); return true; } catch { return false; }
  }));
  expect(results.filter(Boolean)).toHaveLength(1);
  expect(await org.countActiveOwners()).toBe(1);
});
