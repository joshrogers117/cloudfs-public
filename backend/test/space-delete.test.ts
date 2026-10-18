// SPDX-License-Identifier: AGPL-3.0-or-later
// space-delete.test.ts — owner-gated SOFT delete of a filespace.
//
// DELETE /v1/orgs/:org/spaces/:id is a REVERSIBLE soft delete: it sets the OrgDO registry's
// `deleted_at` marker (so the space vanishes from listSpaces) and flips the FilespaceDO's durable
// tombstone (defense in depth). It is reserved to the org OWNER. After delete, every filespace-
// plane op (presign / item create / list) is refused with 410 Gone at the gateway chokepoint, and
// a DIRECT data-plane DO call is refused too. NOTHING in R2/object storage is deleted — this suite
// asserts only registry + gating behavior, never object deletion.

import { SELF, env, runInDurableObject } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

// Cast `runInDurableObject` to a minimal shape so its generic doesn't deeply instantiate the full
// FilespaceDO RPC type (TS2589) — same workaround as data-integrity-3.test.ts.
const runInDo = runInDurableObject as unknown as <R>(
  s: unknown,
  cb: (inst: any) => R | Promise<R>,
) => Promise<R>;

const ALL_SCOPES: Scope[] = [
  "fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read",
];

let orgCounter = 0;
function freshOrg(): string {
  return `del-org-${Date.now()}-${orgCounter++}`;
}

async function provisionUser(orgId: string, role: string): Promise<string> {
  const org = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
  const u = await org.createUser({
    orgId,
    email: `${role}-${crypto.randomUUID()}@test.local`,
    displayName: role,
    role,
  });
  return u.id;
}

async function tokenFor(orgId: string, role: string): Promise<string> {
  const sub = await provisionUser(orgId, role);
  return mintToken((env as any).AUTH_SIGNING_SECRET, {
    sub,
    type: "session",
    orgId,
    scopes: ALL_SCOPES,
    ttlSeconds: 900,
  });
}

function authHeaders(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}`, "content-type": "application/json" };
}

async function registerSpace(orgId: string, spaceId: string): Promise<void> {
  const stub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
  await stub.registerSpace({
    spaceId,
    orgId,
    name: `Space ${spaceId}`,
    bucketProvider: "r2",
    bucketName: "bkt",
    keyPrefix: "p/",
  });
}

function spacesUrl(orgId: string, spaceId?: string): string {
  return `https://gw.local/v1/orgs/${orgId}/spaces${spaceId ? `/${spaceId}` : ""}`;
}

describe("DELETE /v1/orgs/:org/spaces/:id — owner-gated SOFT delete", () => {
  it("owner deletes → space gone from listSpaces; OrgDO marker set; row preserved", async () => {
    const orgId = freshOrg();
    const spaceId = "space-del-1";
    await registerSpace(orgId, spaceId);
    const ownerTok = await tokenFor(orgId, "owner");

    // Visible before delete.
    const listBefore = await SELF.fetch(spacesUrl(orgId), { headers: authHeaders(ownerTok) });
    expect((((await listBefore.json()) as any[])).map((s) => s.id)).toContain(spaceId);

    const del = await SELF.fetch(spacesUrl(orgId, spaceId), {
      method: "DELETE",
      headers: authHeaders(ownerTok),
    });
    expect(del.status).toBe(200);
    const body = (await del.json()) as any;
    expect(body).toEqual({ deleted: true, id: spaceId });

    // Gone from the org's space list.
    const listAfter = await SELF.fetch(spacesUrl(orgId), { headers: authHeaders(ownerTok) });
    const ids = ((await listAfter.json()) as any[]).map((s) => s.id);
    expect(ids).not.toContain(spaceId);

    // The OrgDO row is PRESERVED (reversible) with the marker set — getSpace hides it, but
    // getSpaceIncludingDeleted still finds the tombstoned row (NOT dropped; R2-safe).
    const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(await orgStub.getSpace(spaceId)).toBeNull();
    const withDeleted = await orgStub.getSpaceIncludingDeleted(spaceId);
    expect(withDeleted).not.toBeNull();
    expect(withDeleted.deletedAt).toBeGreaterThan(0);
  });

  it("after delete, a presign on that space is refused with 410 Gone", async () => {
    const orgId = freshOrg();
    const spaceId = "space-del-presign";
    await registerSpace(orgId, spaceId);
    const ownerTok = await tokenFor(orgId, "owner");

    await SELF.fetch(spacesUrl(orgId, spaceId), { method: "DELETE", headers: authHeaders(ownerTok) });

    const presign = await SELF.fetch(`https://gw.local/v1/filespaces/${spaceId}/presign`, {
      method: "POST",
      headers: authHeaders(ownerTok),
      body: JSON.stringify({
        key: `blocks/${orgId}::${spaceId}/obj`,
        method: "PUT",
      }),
    });
    expect(presign.status).toBe(410);
    expect(((await presign.json()) as any).error).toBe("filespace_deleted");
  });

  it("after delete, an item create (mutation) and a list on that space are refused with 410", async () => {
    const orgId = freshOrg();
    const spaceId = "space-del-mut";
    await registerSpace(orgId, spaceId);
    const ownerTok = await tokenFor(orgId, "owner");

    await SELF.fetch(spacesUrl(orgId, spaceId), { method: "DELETE", headers: authHeaders(ownerTok) });

    const create = await SELF.fetch(`https://gw.local/v1/filespaces/${spaceId}/items`, {
      method: "POST",
      headers: authHeaders(ownerTok),
      body: JSON.stringify({ parent: "root", name: "x.mov", size: 1 }),
    });
    expect(create.status).toBe(410);

    const list = await SELF.fetch(
      `https://gw.local/v1/filespaces/${spaceId}/items?parent=root`,
      { headers: authHeaders(ownerTok) },
    );
    expect(list.status).toBe(410);
  });

  it("a NON-owner (admin / space_admin / standard) is DENIED with 403; the space survives", async () => {
    for (const role of ["admin", "space_admin", "standard"]) {
      const orgId = freshOrg();
      const spaceId = `space-del-${role}`;
      await registerSpace(orgId, spaceId);
      const tok = await tokenFor(orgId, role);

      const del = await SELF.fetch(spacesUrl(orgId, spaceId), {
        method: "DELETE",
        headers: authHeaders(tok),
      });
      expect(del.status).toBe(403);

      // Still live: present in the list AND its registry marker is null.
      // (Listed as an org admin: a grant-less standard member no longer sees spaces — access-scoped list.)
      const adminTok = role === "standard" ? await tokenFor(orgId, "owner") : tok;
      const list = await SELF.fetch(spacesUrl(orgId), { headers: authHeaders(adminTok) });
      expect(((await list.json()) as any[]).map((s) => s.id)).toContain(spaceId);
      const orgStub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
      expect((await orgStub.getSpace(spaceId)).deletedAt).toBeNull();
    }
  });

  it("deleting an UNKNOWN space id is a 404 (owner)", async () => {
    const orgId = freshOrg();
    const ownerTok = await tokenFor(orgId, "owner");
    const del = await SELF.fetch(spacesUrl(orgId, "does-not-exist"), {
      method: "DELETE",
      headers: authHeaders(ownerTok),
    });
    expect(del.status).toBe(404);
  });

  it("a re-delete (idempotent) of an already-deleted space is safe (200)", async () => {
    const orgId = freshOrg();
    const spaceId = "space-del-idem";
    await registerSpace(orgId, spaceId);
    const ownerTok = await tokenFor(orgId, "owner");

    const first = await SELF.fetch(spacesUrl(orgId, spaceId), {
      method: "DELETE",
      headers: authHeaders(ownerTok),
    });
    expect(first.status).toBe(200);

    const second = await SELF.fetch(spacesUrl(orgId, spaceId), {
      method: "DELETE",
      headers: authHeaders(ownerTok),
    });
    expect(second.status).toBe(200);
    expect(await second.json()).toEqual({ deleted: true, id: spaceId });

    // Still only one (tombstoned) row — re-delete didn't change visibility or duplicate state.
    const list = await SELF.fetch(spacesUrl(orgId), { headers: authHeaders(ownerTok) });
    expect(((await list.json()) as any[]).map((s) => s.id)).not.toContain(spaceId);
  });

  it("the deleted space vanishes but the rest of the org's space list is intact", async () => {
    const orgId = freshOrg();
    await registerSpace(orgId, "keep-1");
    await registerSpace(orgId, "drop-me");
    await registerSpace(orgId, "keep-2");
    const ownerTok = await tokenFor(orgId, "owner");

    await SELF.fetch(spacesUrl(orgId, "drop-me"), { method: "DELETE", headers: authHeaders(ownerTok) });

    const list = await SELF.fetch(spacesUrl(orgId), { headers: authHeaders(ownerTok) });
    expect(list.status).toBe(200); // the org plane is NOT errored, only the one space is gone
    const ids = ((await list.json()) as any[]).map((s) => s.id);
    expect(ids).toContain("keep-1");
    expect(ids).toContain("keep-2");
    expect(ids).not.toContain("drop-me");
  });
});

describe("FilespaceDO tombstone — defense in depth (direct DO call)", () => {
  it("markDeleted() sets a durable tombstone, and a direct data-plane op then refuses", async () => {
    // Run INSIDE the DO so a thrown guard error is observed in-process (calling a throwing method
    // across the DO-RPC boundary would surface as an unhandled rejection in the test pool; the
    // codebase deliberately avoids throwing across RPC). This still exercises the real guard.
    const orgId = freshOrg();
    const spaceId = "space-direct-do";
    const doName = `${orgId}::${spaceId}`;
    const ns = (env as any).FILESPACE;
    const stub = ns.get(ns.idFromName(doName));

    await runInDo(stub, async (instance: any) => {
      // Live: not deleted, a direct create succeeds.
      expect(instance.isDeleted()).toBe(false);
      const before = await instance.createItem("root", "live.mov", false, 1, {});
      expect("item" in before).toBe(true);

      // Tombstone it (durable in SQLite ⇒ hibernation-safe).
      await instance.markDeleted();
      expect(instance.isDeleted()).toBe(true);

      // A direct data-plane op now refuses (defense in depth — the gateway never reaches here).
      await expect(instance.createItem("root", "after.mov", false, 1, {})).rejects.toThrow(
        /filespace_deleted/,
      );
      await expect(instance.getInodeForObjectKey(`blocks/${doName}/obj`)).rejects.toThrow(
        /filespace_deleted/,
      );
    });
  });
});
