// SPDX-License-Identifier: AGPL-3.0-or-later
// authz-model.test.ts — CHANGE D + CHANGE E authorization-model enforcement.
//
// CHANGE D: per-folder ACL on metadata READS (default-deny / "invisible"). A user
// granted only on a subtree must NOT be able to stat/list/change-feed the rest of
// the tree; a full-access (admin/owner or whole-filespace grant) user sees exactly
// what they see today (regression guard).
//
// CHANGE E: space_admin is an org-wide admin, but repointing a space's STORAGE
// BACKEND is reserved to the org OWNER alone (space_admin/admin → 403); non-storage
// fields (display name) stay admin-editable.
//
// All assertions run through the real worker + DOs over signed bearer tokens.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];

async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({
    orgId, email: `${role}-${crypto.randomUUID()}@test.local`, displayName: role, role,
  });
  return u.id;
}

async function token(sub: string, orgId: string): Promise<string> {
  return mintToken((env as any).AUTH_SIGNING_SECRET, {
    sub, type: "session", orgId, scopes: ALL_SCOPES, ttlSeconds: 900,
  });
}

function authOf(tok: string): Record<string, string> {
  return { Authorization: `Bearer ${tok}`, "content-type": "application/json" };
}

// ---------------------------------------------------------------------------
// CHANGE D — per-folder ACL on metadata reads
// ---------------------------------------------------------------------------
describe("CHANGE D — per-folder ACL on metadata reads (default-deny / invisible)", () => {
  const ORG = "authz-d-org";
  const SPACE = "authz-d-space";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  let adminAuth: Record<string, string>;
  let userAuth: Record<string, string>; // granted only on /a
  // Audit B17: ids are opaque; capture the created ids and address by them.
  let aId: string, bId: string, axId: string, byId: string;

  // Helper: act as a given principal.
  const as = (auth: Record<string, string>) => ({
    get: (path: string) => SELF.fetch(`${base}${path}`, { headers: auth }),
    send: (method: string, path: string, body?: unknown) =>
      SELF.fetch(`${base}${path}`, { method, headers: auth, body: body ? JSON.stringify(body) : undefined }),
    create: async (parent: string, name: string, extra: Record<string, unknown> = {}): Promise<string> =>
      ((await (await SELF.fetch(`${base}/items`, { method: "POST", headers: auth, body: JSON.stringify({ parent, name, size: 0, ...extra }) })).json()) as any).id as string,
  });

  beforeAll(async () => {
    const adminId = await provisionUser(ORG, "admin");
    adminAuth = authOf(await token(adminId, ORG));
    const userId = await provisionUser(ORG, "standard");
    userAuth = authOf(await token(userId, ORG));

    const a = as(adminAuth);
    // Tree:  /a  (folder, GRANTED to user)  ->  /a/x  (file)
    //        /b  (folder, NOT granted)      ->  /b/y  (file)
    aId = await a.create("root", "a", { isDir: true });
    bId = await a.create("root", "b", { isDir: true });
    axId = await a.create(aId, "x", { size: 11 });
    byId = await a.create(bId, "y", { size: 22 });

    // Grant the user `read` on /a only (inherits to /a/x). No grant on /b.
    const g = await a.send("POST", "/grants", {
      inodeId: aId, principalType: "user", principalId: userId, level: "read",
    });
    expect(g.status).toBe(201);
  });

  it("getItem(/b) → 404 (INVISIBLE, not 403 — existence must not leak)", async () => {
    const res = await as(userAuth).get(`/items/${encodeURIComponent(bId)}`);
    expect(res.status).toBe(404);
  });

  it("getItem(/b/y) → 404 (invisible child of an invisible folder)", async () => {
    const res = await as(userAuth).get(`/items/${encodeURIComponent(byId)}`);
    expect(res.status).toBe(404);
  });

  it("getItem(/a) and getItem(/a/x) → 200 (granted subtree IS visible)", async () => {
    const ra = await as(userAuth).get(`/items/${encodeURIComponent(aId)}`);
    expect(ra.status).toBe(200);
    expect(((await ra.json()) as any).id).toBe(aId);
    const rx = await as(userAuth).get(`/items/${encodeURIComponent(axId)}`);
    expect(rx.status).toBe(200);
    expect(((await rx.json()) as any).id).toBe(axId);
  });

  it("listPage(root) for the granted user includes /a but EXCLUDES /b", async () => {
    const page = (await (await as(userAuth).get("/items?parent=root")).json()) as { items: any[]; cursor: string | null };
    const names = page.items.map((i) => i.name);
    expect(names).toContain("a");
    expect(names).not.toContain("b");
  });

  it("listPage(root/a) shows /a's children (x); listPage(root/b) is empty for the user", async () => {
    const inA = (await (await as(userAuth).get(`/items?parent=${encodeURIComponent(aId)}`)).json()) as { items: any[] };
    expect(inA.items.map((i) => i.name)).toContain("x");
    // root/b is invisible; even if the user names it, none of its children are readable.
    const inB = (await (await as(userAuth).get(`/items?parent=${encodeURIComponent(bId)}`)).json()) as { items: any[] };
    expect(inB.items.map((i) => i.name)).not.toContain("y");
  });

  it("changesSince for the granted user includes /a + /a/x but EXCLUDES /b + /b/y", async () => {
    const feed = (await (await as(userAuth).get("/changes?since=0")).json()) as { anchor: number; items: any[]; cursor: number | null };
    const ids = feed.items.map((i) => i.id);
    expect(ids).toContain(aId);
    expect(ids).toContain(axId);
    expect(ids).not.toContain(bId);
    expect(ids).not.toContain(byId);
    // The anchor reflects the underlying scan, NOT the filtered subset.
    expect(feed.anchor).toBeGreaterThan(0);
  });

  it("REGRESSION GUARD: a full-access admin sees EVERYTHING unchanged", async () => {
    const a = as(adminAuth);
    const page = (await (await a.get("/items?parent=root")).json()) as { items: any[] };
    const names = page.items.map((i) => i.name);
    expect(names).toContain("a");
    expect(names).toContain("b"); // admin still sees the ungranted folder
    expect((await a.get(`/items/${encodeURIComponent(bId)}`)).status).toBe(200);
    const feed = (await (await a.get("/changes?since=0")).json()) as { items: any[] };
    const ids = feed.items.map((i) => i.id);
    expect(ids).toContain(bId);
    expect(ids).toContain(byId);
  });
});

// A whole-filespace grant (read on "root") is the other full-access case: it must
// be IDENTICAL to admin AND must short-circuit (no per-item filtering).
describe("CHANGE D — a whole-filespace grant (read on root) = full visibility", () => {
  const ORG = "authz-d2-org";
  const SPACE = "authz-d2-space";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  it("a user granted read on root sees every item (same as admin)", async () => {
    const adminId = await provisionUser(ORG, "admin");
    const adminAuth = authOf(await token(adminId, ORG));
    const userId = await provisionUser(ORG, "standard");
    const userAuth = authOf(await token(userId, ORG));
    const a = (m: string, p: string, b?: unknown) =>
      SELF.fetch(`${base}${p}`, { method: m, headers: adminAuth, body: b ? JSON.stringify(b) : undefined });

    const cId = ((await (await a("POST", "/items", { parent: "root", name: "c", isDir: true })).json()) as any).id;
    await a("POST", "/items", { parent: "root", name: "d", isDir: true });
    await a("POST", "/grants", { inodeId: "root", principalType: "user", principalId: userId, level: "read" });

    const page = (await (await SELF.fetch(`${base}/items?parent=root`, { headers: userAuth })).json()) as { items: any[] };
    const names = page.items.map((i) => i.name);
    expect(names).toContain("c");
    expect(names).toContain("d");
    expect((await SELF.fetch(`${base}/items/${encodeURIComponent(cId)}`, { headers: userAuth })).status).toBe(200);
  });
});

// Pagination correctness: filtering must NOT break the keyset cursor. We seed a
// mix of visible (granted) and invisible (ungranted) siblings and page through
// with a tiny page size, proving the cursor advances over the underlying scan and
// the union of visible items across pages is exactly the granted set (no skips /
// repeats), even when a whole page filters down to zero items.
describe("CHANGE D — pagination progresses across a mix of visible/invisible items", () => {
  const ORG = "authz-d3-org";
  const SPACE = "authz-d3-space";
  const base = `https://gw.local/v1/filespaces/${SPACE}`;

  it("paging the user's filtered listing yields exactly the granted children, no skips", async () => {
    const adminId = await provisionUser(ORG, "admin");
    const adminAuth = authOf(await token(adminId, ORG));
    const userId = await provisionUser(ORG, "standard");
    const userAuth = authOf(await token(userId, ORG));
    const a = (m: string, p: string, b?: unknown) =>
      SELF.fetch(`${base}${p}`, { method: m, headers: adminAuth, body: b ? JSON.stringify(b) : undefined });

    // A dedicated parent folder with 10 file children f0..f9 (names sort lexically).
    const dirId = ((await (await a("POST", "/items", { parent: "root", name: "dir", isDir: true })).json()) as any).id;
    const granted = new Set<string>();
    let oddId = "";
    for (let i = 0; i < 10; i++) {
      const id = ((await (await a("POST", "/items", { parent: dirId, name: `f${i}`, size: i })).json()) as any).id as string;
      // grant the user read on the EVEN-indexed files only (file-level override grant)
      if (i % 2 === 0) {
        granted.add(id);
        const g = await a("POST", "/grants", { inodeId: id, principalType: "user", principalId: userId, level: "read" });
        expect(g.status).toBe(201);
      } else if (i === 1) {
        oddId = id;
      }
    }

    // Page through as the user with a tiny page size (2). Collect all visible ids.
    const seen: string[] = [];
    let cursor: string | null = null;
    let guard = 0;
    do {
      const url = `${base}/items?parent=${encodeURIComponent(dirId)}&limit=2${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
      const page = (await (await SELF.fetch(url, { headers: userAuth })).json()) as { items: any[]; cursor: string | null };
      for (const it of page.items) seen.push(it.id);
      cursor = page.cursor;
    } while (cursor && ++guard < 100);

    // Exactly the granted (even) files, each once — the cursor never skipped or
    // repeated a row despite pages that filtered down to fewer/zero items.
    expect(new Set(seen)).toEqual(granted);
    expect(seen.length).toBe(granted.size);
    expect(seen).not.toContain(oddId); // an ungranted (odd) file never leaks
  });
});

// ---------------------------------------------------------------------------
// CHANGE E — space_admin = org admin, but storage-backend repoint is owner-only
// ---------------------------------------------------------------------------
describe("CHANGE E — storage-backend repoint reserved to org OWNER", () => {
  let orgCounter = 0;
  const freshOrg = () => `authz-e-org-${Date.now()}-${orgCounter++}`;

  async function registerSpace(orgId: string, spaceId: string): Promise<void> {
    const stub = (env as any).ORG_DO.getByName(orgId);
    await stub.registerSpace({
      orgId, spaceId, name: "Original", bucketProvider: "r2", bucketName: "bkt", keyPrefix: "p/",
    });
  }

  async function patchSpace(orgId: string, spaceId: string, role: string, body: unknown): Promise<Response> {
    const tok = await token(await provisionUser(orgId, role), orgId);
    return SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}`, {
      method: "PATCH", headers: authOf(tok), body: JSON.stringify(body),
    });
  }

  it("a space_admin (non-owner) is DENIED a storage-backend repoint (403)", async () => {
    const orgId = freshOrg();
    const spaceId = "space-e1";
    await registerSpace(orgId, spaceId);
    const res = await patchSpace(orgId, spaceId, "space_admin", {
      storageBucket: "attacker-bucket", storageEndpoint: "https://evil.example.com",
    });
    expect(res.status).toBe(403);
    // The backend was NOT changed.
    const space = await (env as any).ORG_DO.getByName(orgId).getSpace(spaceId);
    expect(space.storageBucket ?? null).not.toBe("attacker-bucket");
  });

  it("a plain admin (non-owner) is ALSO denied a storage-backend repoint (403)", async () => {
    const orgId = freshOrg();
    const spaceId = "space-e2";
    await registerSpace(orgId, spaceId);
    const res = await patchSpace(orgId, spaceId, "admin", { storageCredentialRef: "scr-evil" });
    expect(res.status).toBe(403);
  });

  it("the org OWNER succeeds at a storage-backend repoint (200)", async () => {
    const orgId = freshOrg();
    const spaceId = "space-e3";
    await registerSpace(orgId, spaceId);
    const res = await patchSpace(orgId, spaceId, "owner", {
      storageEndpoint: "https://s3.example.com", storageRegion: "us-east-1",
      storageBucket: "new-bucket", storageCredentialRef: "scr-123",
    });
    expect(res.status).toBe(200);
    const updated = (await res.json()) as any;
    expect(updated.storageBucket).toBe("new-bucket");
    expect(updated.storageEndpoint).toBe("https://s3.example.com");
    expect(updated.storageCredentialRef).toBe("scr-123");
  });

  it("a space_admin CAN still edit a NON-storage field (display name) — org-wide admin authority", async () => {
    const orgId = freshOrg();
    const spaceId = "space-e4";
    await registerSpace(orgId, spaceId);
    const res = await patchSpace(orgId, spaceId, "space_admin", { name: "Renamed By SpaceAdmin" });
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).name).toBe("Renamed By SpaceAdmin");
  });

  it("a mixed PATCH (name + storage) by a space_admin is rejected wholesale (403) — no partial apply", async () => {
    const orgId = freshOrg();
    const spaceId = "space-e5";
    await registerSpace(orgId, spaceId);
    const res = await patchSpace(orgId, spaceId, "space_admin", { name: "Should Not Apply", storageBucket: "nope" });
    expect(res.status).toBe(403);
    const space = await (env as any).ORG_DO.getByName(orgId).getSpace(spaceId);
    expect(space.name).toBe("Original"); // name unchanged — the whole PATCH was rejected
  });
});
