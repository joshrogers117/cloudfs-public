// SPDX-License-Identifier: AGPL-3.0-or-later
// acl-completeness.test.ts — CHANGE D metadata-ACL completeness gaps found by adversarial review.
//
//   N-F1 (HIGH)  The change feed must DELIVER deletion events (tombstones) to every principal who
//                could PREVIOUSLY read the item — including across a RECURSIVE subtree delete that
//                tombstones the parent too. A non-full-access user who could read an item but never
//                receives its tombstone diverges permanently. A user with NO grant up the
//                (pre-deletion) chain still gets nothing (no over-delivery); admins are unaffected.
//                This file proves the fix AND that it FAILS pre-fix (the tombstone-aware predicate).
//   N-F3 (LOW)   `items/_count` is gated by the SAME per-folder read ACL as getItem/listPage — a
//                partially-granted user gets 404 (INVISIBLE) on an ungranted folder, not a leaked
//                child count.
//   N-NOTE       Snapshot directory browse is per-folder-ACL filtered too (a snapshot is metadata;
//                a user must not see VIA A SNAPSHOT what they can't see live).

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

const ALL_SCOPES: Scope[] = [
  "fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read",
];

async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
  const u = await org.createUser({
    orgId, email: `${role}-${crypto.randomUUID()}@test.local`, displayName: role, role,
  });
  return u.id;
}
async function token(sub: string, orgId: string): Promise<string> {
  return mintToken((env as any).AUTH_SIGNING_SECRET, { sub, type: "session", orgId, scopes: ALL_SCOPES, ttlSeconds: 900 });
}
function authOf(tok: string): Record<string, string> {
  return { Authorization: `Bearer ${tok}`, "content-type": "application/json" };
}

// =====================================================================================
// N-F1 — deletion events reach every principal who could PREVIOUSLY read the item.
// =====================================================================================
describe("N-F1: the change feed delivers tombstones to principals who could read the deleted item", () => {
  const ORG = "acl-nf1-org";
  const SPACE = "acl-nf1-space";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  let adminAuth: Record<string, string>;
  let teamUserAuth: Record<string, string>; // granted read on root/team
  let strangerAuth: Record<string, string>; // NO grant anywhere up the chain
  // Audit B17: opaque ids — capture them from create.
  let projId: string, aId: string, bId: string;

  const as = (auth: Record<string, string>) => ({
    get: (path: string) => SELF.fetch(`${base}${path}`, { headers: auth }),
    send: (method: string, path: string, body?: unknown) =>
      SELF.fetch(`${base}${path}`, { method, headers: auth, body: body ? JSON.stringify(body) : undefined }),
    create: async (parent: string, name: string, extra: Record<string, unknown> = {}): Promise<string> =>
      ((await (await SELF.fetch(`${base}/items`, { method: "POST", headers: auth, body: JSON.stringify({ parent, name, size: 0, ...extra }) })).json()) as any).id as string,
  });

  beforeAll(async () => {
    adminAuth = authOf(await token(await provisionUser(ORG, "admin"), ORG));
    const teamUserId = await provisionUser(ORG, "standard");
    teamUserAuth = authOf(await token(teamUserId, ORG));
    strangerAuth = authOf(await token(await provisionUser(ORG, "standard"), ORG));

    const a = as(adminAuth);
    // Tree:  team (granted to teamUser)
    //          └─ proj (folder)
    //               ├─ a (file)
    //               └─ b (file)
    const teamId = await a.create("root", "team", { isDir: true });
    projId = await a.create(teamId, "proj", { isDir: true });
    aId = await a.create(projId, "a", { size: 1 });
    bId = await a.create(projId, "b", { size: 2 });

    // teamUser holds read on `team` (inherits down to proj + a + b). The STRANGER holds nothing.
    const g = await a.send("POST", "/grants", {
      inodeId: teamId, principalType: "user", principalId: teamUserId, level: "read",
    });
    expect(g.status).toBe(201);
  });

  it("teamUser can read the subtree before deletion (baseline)", async () => {
    expect((await as(teamUserAuth).get(`/items/${encodeURIComponent(aId)}`)).status).toBe(200);
    // The stranger cannot — INVISIBLE.
    expect((await as(strangerAuth).get(`/items/${encodeURIComponent(aId)}`)).status).toBe(404);
  });

  it("RECURSIVE subtree delete (parent ALSO tombstoned): teamUser RECEIVES the tombstones; stranger gets NONE; admin sees all", async () => {
    // Capture each principal's sync cursor (anchor) JUST BEFORE the delete, so we read ONLY the
    // delete's tombstones on the next poll (not the earlier create events).
    const teamBefore = (await (await as(teamUserAuth).get("/changes?since=0")).json()) as { anchor: number };
    const adminBefore = (await (await as(adminAuth).get("/changes?since=0")).json()) as { anchor: number };
    const strangerBefore = (await (await as(strangerAuth).get("/changes?since=0")).json()) as { anchor: number };

    // Recursively delete `proj` — tombstones proj + a + b. teamUser's grant is on `team` (the
    // PARENT of the deleted subtree root), so the tombstone-aware walk reaches it through `proj`.
    const del = await as(adminAuth).send("DELETE", `/items/${encodeURIComponent(projId)}?recursive=true`);
    expect(del.status).toBe(200);

    // teamUser MUST receive the tombstones for proj + a + b.
    const teamFeed = (await (await as(teamUserAuth).get(`/changes?since=${teamBefore.anchor}`)).json()) as { items: any[] };
    const teamDeletedIds = teamFeed.items.filter((i) => i.deleted).map((i) => i.id);
    expect(teamDeletedIds).toContain(projId);
    expect(teamDeletedIds).toContain(aId);
    expect(teamDeletedIds).toContain(bId);

    // The STRANGER receives NONE of these tombstones — no over-delivery.
    const strangerFeed = (await (await as(strangerAuth).get(`/changes?since=${strangerBefore.anchor}`)).json()) as { items: any[] };
    const strangerDeletedIds = strangerFeed.items.filter((i) => i.deleted).map((i) => i.id);
    expect(strangerDeletedIds).not.toContain(projId);
    expect(strangerDeletedIds).not.toContain(aId);
    expect(strangerDeletedIds).not.toContain(bId);

    // The full-access ADMIN is unaffected — sees every tombstone (short-circuit).
    const adminFeed = (await (await as(adminAuth).get(`/changes?since=${adminBefore.anchor}`)).json()) as { items: any[] };
    const adminDeletedIds = adminFeed.items.filter((i) => i.deleted).map((i) => i.id);
    expect(adminDeletedIds).toContain(projId);
    expect(adminDeletedIds).toContain(aId);
    expect(adminDeletedIds).toContain(bId);
  });
});

// A SECOND N-F1 scenario isolating the single-item delete (no recursion) — the granted user still
// receives the tombstone of a file they could read; a non-granted user does not.
describe("N-F1: a single-file delete still delivers the tombstone to a reader", () => {
  const ORG = "acl-nf1b-org";
  const SPACE = "acl-nf1b-space";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  it("granted user gets the tombstone; ungranted user does not", async () => {
    const adminId = await provisionUser(ORG, "admin");
    const adminAuth = authOf(await token(adminId, ORG));
    const userId = await provisionUser(ORG, "standard");
    const userAuth = authOf(await token(userId, ORG));
    const strangerAuth = authOf(await token(await provisionUser(ORG, "standard"), ORG));
    const send = (auth: Record<string, string>, m: string, p: string, b?: unknown) =>
      SELF.fetch(`${base}${p}`, { method: m, headers: auth, body: b ? JSON.stringify(b) : undefined });

    const docsId = ((await (await send(adminAuth, "POST", "/items", { parent: "root", name: "docs", isDir: true })).json()) as any).id;
    const fId = ((await (await send(adminAuth, "POST", "/items", { parent: docsId, name: "f", size: 3 })).json()) as any).id as string;
    await send(adminAuth, "POST", "/grants", { inodeId: docsId, principalType: "user", principalId: userId, level: "read" });

    const uBefore = (await (await SELF.fetch(`${base}/changes?since=0`, { headers: userAuth })).json()) as { anchor: number };
    const sBefore = (await (await SELF.fetch(`${base}/changes?since=0`, { headers: strangerAuth })).json()) as { anchor: number };

    expect((await send(adminAuth, "DELETE", `/items/${encodeURIComponent(fId)}`)).status).toBe(200);

    const uFeed = (await (await SELF.fetch(`${base}/changes?since=${uBefore.anchor}`, { headers: userAuth })).json()) as { items: any[] };
    expect(uFeed.items.filter((i) => i.deleted).map((i) => i.id)).toContain(fId);

    const sFeed = (await (await SELF.fetch(`${base}/changes?since=${sBefore.anchor}`, { headers: strangerAuth })).json()) as { items: any[] };
    expect(sFeed.items.filter((i) => i.deleted).map((i) => i.id)).not.toContain(fId);
  });
});

// A THIRD N-F1 scenario — the interaction bug between I3 (grant-resurrection fix) and N-F1: the
// grant is ON the deleted subtree ROOT itself (not on a surviving ancestor). Pre-fix, I3's
// delete-time grant cleanup removed that grant before N-F1 could walk to it, so the grant-holder
// NEVER received the tombstone and diverged. The fix moves grant cleanup to RECREATE-time, so the
// grant SURVIVES the delete and N-F1 delivers the tombstones. This FAILS on the pre-fix code.
describe("N-F1: a grant ON the deleted subtree root still delivers its tombstones (I3×N-F1)", () => {
  const ORG = "acl-nf1c-org";
  const SPACE = "acl-nf1c-space";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  it("grant on root/team/proj: the holder RECEIVES proj + proj/* tombstones on recursive delete", async () => {
    const adminAuth = authOf(await token(await provisionUser(ORG, "admin"), ORG));
    const projUserId = await provisionUser(ORG, "standard");
    const projUserAuth = authOf(await token(projUserId, ORG));
    const strangerAuth = authOf(await token(await provisionUser(ORG, "standard"), ORG));
    const send = (auth: Record<string, string>, m: string, p: string, b?: unknown) =>
      SELF.fetch(`${base}${p}`, { method: m, headers: auth, body: b ? JSON.stringify(b) : undefined });
    const changes = (auth: Record<string, string>, since: number) =>
      SELF.fetch(`${base}/changes?since=${since}`, { headers: auth });

    // Tree: team/proj/{a,b}. The grant is ON proj — the node that gets tombstoned (NOT on a
    // surviving ancestor), so the raw-chain walk must reach the SURVIVING grant on proj itself.
    const create = async (parent: string, name: string, extra: Record<string, unknown> = {}): Promise<string> =>
      ((await (await send(adminAuth, "POST", "/items", { parent, name, size: 0, ...extra })).json()) as any).id as string;
    const teamId = await create("root", "team", { isDir: true });
    const projId = await create(teamId, "proj", { isDir: true });
    const aId = await create(projId, "a", { size: 1 });
    const bId = await create(projId, "b", { size: 2 });
    const g = await send(adminAuth, "POST", "/grants", {
      inodeId: projId, principalType: "user", principalId: projUserId, level: "read",
    });
    expect(g.status).toBe(201);

    const projBefore = (await (await changes(projUserAuth, 0)).json()) as { anchor: number };
    const strangerBefore = (await (await changes(strangerAuth, 0)).json()) as { anchor: number };

    expect((await send(adminAuth, "DELETE", `/items/${encodeURIComponent(projId)}?recursive=true`)).status).toBe(200);

    // The grant-holder MUST receive the tombstones for proj + a + b — even though their ONLY grant
    // was ON the deleted subtree root.
    const projFeed = (await (await changes(projUserAuth, projBefore.anchor)).json()) as { items: any[] };
    const projDeleted = projFeed.items.filter((i) => i.deleted).map((i) => i.id);
    expect(projDeleted).toContain(projId);
    expect(projDeleted).toContain(aId);
    expect(projDeleted).toContain(bId);

    // A stranger with NO grant up the (pre-deletion) chain receives NONE — no over-delivery.
    const strangerFeed = (await (await changes(strangerAuth, strangerBefore.anchor)).json()) as { items: any[] };
    const strangerDeleted = strangerFeed.items.filter((i) => i.deleted).map((i) => i.id);
    expect(strangerDeleted).not.toContain(projId);
    expect(strangerDeleted).not.toContain(aId);
    expect(strangerDeleted).not.toContain(bId);
  });
});

// =====================================================================================
// N-F3 — items/_count behind the per-folder read ACL (INVISIBLE on denial).
// =====================================================================================
describe("N-F3: items/_count is per-folder ACL gated (404 invisible on an ungranted folder)", () => {
  const ORG = "acl-nf3-org";
  const SPACE = "acl-nf3-space";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  let adminAuth: Record<string, string>;
  let userAuth: Record<string, string>; // granted read on root/open only
  let openId: string, secretId: string;

  const get = (auth: Record<string, string>, p: string) => SELF.fetch(`${base}${p}`, { headers: auth });
  const send = (auth: Record<string, string>, m: string, p: string, b?: unknown) =>
    SELF.fetch(`${base}${p}`, { method: m, headers: auth, body: b ? JSON.stringify(b) : undefined });

  beforeAll(async () => {
    adminAuth = authOf(await token(await provisionUser(ORG, "admin"), ORG));
    const userId = await provisionUser(ORG, "standard");
    userAuth = authOf(await token(userId, ORG));
    const create = async (parent: string, name: string, extra: Record<string, unknown> = {}): Promise<string> =>
      ((await (await send(adminAuth, "POST", "/items", { parent, name, size: 0, ...extra })).json()) as any).id as string;

    openId = await create("root", "open", { isDir: true });
    secretId = await create("root", "secret", { isDir: true });
    await create(openId, "child1", { size: 1 });
    await create(secretId, "s1", { size: 1 });
    await send(adminAuth, "POST", "/grants", { inodeId: openId, principalType: "user", principalId: userId, level: "read" });
  });

  it("a partially-granted user gets 404 on _count of an UNGRANTED folder", async () => {
    const res = await get(userAuth, `/items/_count?parent=${encodeURIComponent(secretId)}`);
    expect(res.status).toBe(404); // INVISIBLE — the count + existence must not leak
  });

  it("a partially-granted user gets 404 on _count of the ROOT they can't read", async () => {
    const res = await get(userAuth, "/items/_count?parent=root");
    expect(res.status).toBe(404);
  });

  it("the same user gets a real count on a GRANTED folder", async () => {
    const res = await get(userAuth, `/items/_count?parent=${encodeURIComponent(openId)}`);
    expect(res.status).toBe(200);
    expect((await res.json() as any).count).toBe(1);
  });

  it("a full-access admin still gets the count on any folder (short-circuit, unchanged)", async () => {
    const res = await get(adminAuth, `/items/_count?parent=${encodeURIComponent(secretId)}`);
    expect(res.status).toBe(200);
    expect((await res.json() as any).count).toBe(1);
  });
});

// =====================================================================================
// N-NOTE — snapshot directory browse is per-folder-ACL filtered (same invisible model).
// =====================================================================================
describe("N-NOTE: snapshot browse hides folders the principal cannot read live", () => {
  const ORG = "acl-nnote-org";
  const SPACE = "acl-nnote-space";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  let adminAuth: Record<string, string>;
  let userAuth: Record<string, string>; // granted read on root/shared only
  let snapId: string;

  const get = (auth: Record<string, string>, p: string) => SELF.fetch(`${base}${p}`, { headers: auth });
  const send = (auth: Record<string, string>, m: string, p: string, b?: unknown) =>
    SELF.fetch(`${base}${p}`, { method: m, headers: auth, body: b ? JSON.stringify(b) : undefined });

  beforeAll(async () => {
    adminAuth = authOf(await token(await provisionUser(ORG, "admin"), ORG));
    const userId = await provisionUser(ORG, "standard");
    userAuth = authOf(await token(userId, ORG));

    // root/shared (granted) + root/hidden (not granted), each with a child.
    const create = async (parent: string, name: string, extra: Record<string, unknown> = {}): Promise<string> =>
      ((await (await send(adminAuth, "POST", "/items", { parent, name, size: 0, ...extra })).json()) as any).id as string;
    const sharedId = await create("root", "shared", { isDir: true });
    await create("root", "hidden", { isDir: true });
    await create(sharedId, "ok", { size: 1 });
    await send(adminAuth, "POST", "/grants", { inodeId: sharedId, principalType: "user", principalId: userId, level: "read" });

    // Snapshot the current namespace (freezes the same ids/paths).
    const snap = await send(adminAuth, "POST", "/snapshots", { label: "browse-test" });
    expect(snap.status).toBe(201);
    snapId = ((await snap.json()) as any).id;
  });

  it("the user browsing the snapshot ROOT sees /shared but NOT /hidden (invisible via snapshot too)", async () => {
    const res = await get(userAuth, `/snapshots/${encodeURIComponent(snapId)}/dir?parent=root`);
    expect(res.status).toBe(200);
    const names = ((await res.json()) as any[]).map((i) => i.name);
    expect(names).toContain("shared");
    expect(names).not.toContain("hidden");
  });

  it("a full-access admin browsing the snapshot sees BOTH (short-circuit, unchanged)", async () => {
    const res = await get(adminAuth, `/snapshots/${encodeURIComponent(snapId)}/dir?parent=root`);
    expect(res.status).toBe(200);
    const names = ((await res.json()) as any[]).map((i) => i.name);
    expect(names).toContain("shared");
    expect(names).toContain("hidden");
  });
});
