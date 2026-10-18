// SPDX-License-Identifier: AGPL-3.0-or-later
// org-admin-patch.test.ts — PATCH /v1/orgs/:org (rename) + PATCH /v1/orgs/:org/spaces/:id (update).
//
// Both run through the real worker + OrgDO. We mint bearer tokens for provisioned users of varying
// roles (owner/admin/space_admin/standard) to prove the gating, and assert the OrgDO state changes
// (org display name; space mutable fields) take effect via the registry RPC.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];

let orgCounter = 0;
function freshOrg(): string {
  return `patch-org-${Date.now()}-${orgCounter++}`;
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

describe("PATCH /v1/orgs/:org — org rename (owner/admin only)", () => {
  it("an admin renames the org; GET reflects it; slug stays the orgId", async () => {
    const orgId = freshOrg();
    const adminTok = await tokenFor(orgId, "admin");

    const res = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}`, {
      method: "PATCH",
      headers: authHeaders(adminTok),
      body: JSON.stringify({ name: "Acme Editorial" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.name).toBe("Acme Editorial");
    expect(body.slug).toBe(orgId);
    expect(body.orgId).toBe(orgId);

    // Persisted in the OrgDO (getOrgName RPC).
    const stub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(await stub.getOrgName()).toBe("Acme Editorial");

    // GET /v1/orgs/:org returns the new name.
    const get = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}`, { headers: authHeaders(adminTok) });
    expect(get.status).toBe(200);
    expect(((await get.json()) as any).name).toBe("Acme Editorial");
  });

  it("a standard user is DENIED the rename (403)", async () => {
    const orgId = freshOrg();
    // Provision an admin (so the org exists with an admin) but PATCH as a standard member.
    await tokenFor(orgId, "admin");
    const stdTok = await tokenFor(orgId, "standard");

    const res = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}`, {
      method: "PATCH",
      headers: authHeaders(stdTok),
      body: JSON.stringify({ name: "Hijacked Name" }),
    });
    expect(res.status).toBe(403);

    const stub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    expect(await stub.getOrgName()).toBeNull(); // never changed
  });

  it("rejects an empty/blank name with 400", async () => {
    const orgId = freshOrg();
    const adminTok = await tokenFor(orgId, "admin");
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}`, {
      method: "PATCH",
      headers: authHeaders(adminTok),
      body: JSON.stringify({ name: "   " }),
    });
    expect(res.status).toBe(400);
  });
});

describe("PATCH /v1/orgs/:org/spaces/:id — filespace update (admin/space_admin)", () => {
  async function registerSpace(orgId: string, spaceId: string): Promise<void> {
    const stub = (env as any).ORG_DO.get((env as any).ORG_DO.idFromName(orgId));
    await stub.registerSpace({
      spaceId,
      orgId,
      name: "Original Name",
      bucketProvider: "r2",
      bucketName: "bkt",
      keyPrefix: "p/",
    });
  }

  // CHANGE E: storage-backend fields are now OWNER-only (repointing storage is the most
  // dangerous op). This test exercises the full storage descriptor, so it acts as OWNER.
  it("an owner updates the name + storage fields on an existing space; create path untouched", async () => {
    const orgId = freshOrg();
    const spaceId = "space-A";
    await registerSpace(orgId, spaceId);
    const adminTok = await tokenFor(orgId, "owner");

    const res = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}`, {
      method: "PATCH",
      headers: authHeaders(adminTok),
      body: JSON.stringify({
        name: "Renamed Space",
        storageEndpoint: "https://s3.example.com",
        storageRegion: "us-east-1",
        storageBucket: "my-bucket",
        storageForcePathStyle: true,
        storageCredentialRef: "scr-123",
      }),
    });
    expect(res.status).toBe(200);
    const updated = (await res.json()) as any;
    expect(updated.name).toBe("Renamed Space");
    expect(updated.storageEndpoint).toBe("https://s3.example.com");
    expect(updated.storageRegion).toBe("us-east-1");
    expect(updated.storageBucket).toBe("my-bucket");
    expect(updated.storageForcePathStyle).toBe(true);
    expect(updated.storageCredentialRef).toBe("scr-123");
    // Immutable create-time fields are preserved (not clobbered).
    expect(updated.id).toBe(spaceId);
    expect(updated.bucketProvider).toBe("r2");
    expect(updated.keyPrefix).toBe("p/");
  });

  it("a partial PATCH touches only the given field, preserving the rest", async () => {
    const orgId = freshOrg();
    const spaceId = "space-B";
    await registerSpace(orgId, spaceId);
    const ownerTok = await tokenFor(orgId, "owner");
    const adminTok = await tokenFor(orgId, "admin");

    // First set storage fields. CHANGE E: storage-backend edits are OWNER-only.
    await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}`, {
      method: "PATCH",
      headers: authHeaders(ownerTok),
      body: JSON.stringify({ storageBucket: "keep-me" }),
    });
    // Then rename only — a NON-storage field, so a plain admin may do it.
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}`, {
      method: "PATCH",
      headers: authHeaders(adminTok),
      body: JSON.stringify({ name: "Just A Rename" }),
    });
    const updated = (await res.json()) as any;
    expect(updated.name).toBe("Just A Rename");
    expect(updated.storageBucket).toBe("keep-me"); // untouched by the rename-only PATCH
  });

  it("a space_admin is ALLOWED to PATCH a space; a standard user is DENIED (403)", async () => {
    const orgId = freshOrg();
    const spaceId = "space-C";
    await registerSpace(orgId, spaceId);

    const spaceAdminTok = await tokenFor(orgId, "space_admin");
    const okRes = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}`, {
      method: "PATCH",
      headers: authHeaders(spaceAdminTok),
      body: JSON.stringify({ name: "Space Admin Rename" }),
    });
    expect(okRes.status).toBe(200);
    expect(((await okRes.json()) as any).name).toBe("Space Admin Rename");

    const stdTok = await tokenFor(orgId, "standard");
    const denied = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}`, {
      method: "PATCH",
      headers: authHeaders(stdTok),
      body: JSON.stringify({ name: "Nope" }),
    });
    expect(denied.status).toBe(403);
  });

  it("PATCH on an unknown space id is a 404", async () => {
    const orgId = freshOrg();
    const adminTok = await tokenFor(orgId, "admin");
    const res = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/does-not-exist`, {
      method: "PATCH",
      headers: authHeaders(adminTok),
      body: JSON.stringify({ name: "x" }),
    });
    expect(res.status).toBe(404);
  });
});

describe("POST /v1/orgs/:org/spaces — create assigns a stable, non-null id (BUG 5)", () => {
  it("create (no spaceId) → list returns a real, stable id; PATCH targets it", async () => {
    const orgId = freshOrg();
    const adminTok = await tokenFor(orgId, "admin");

    // Create WITHOUT supplying a spaceId — the registry must mint a stable id, not persist "null".
    const create = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces`, {
      method: "POST",
      headers: authHeaders(adminTok),
      body: JSON.stringify({
        name: "My Filespace",
        bucketProvider: "r2",
        bucketName: "bkt",
        keyPrefix: "p/",
      }),
    });
    expect(create.status).toBe(201);
    const created = (await create.json()) as any;
    // The id is present in the create response, non-null, and NOT the literal string "null".
    expect(typeof created.id).toBe("string");
    expect(created.id).not.toBe("null");
    expect(created.id.length).toBeGreaterThan(0);
    expect(created.id).toMatch(/^fs-/);
    const spaceId = created.id as string;

    // GET list returns the SAME id (stable across GETs).
    const list = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces`, {
      headers: authHeaders(adminTok),
    });
    expect(list.status).toBe(200);
    const spaces = (await list.json()) as any[];
    expect(spaces).toHaveLength(1);
    expect(spaces[0].id).toBe(spaceId);
    expect(spaces[0].name).toBe("My Filespace");

    // PATCH by the returned id targets the row (not a 404) and renames it.
    const patch = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces/${spaceId}`, {
      method: "PATCH",
      headers: authHeaders(adminTok),
      body: JSON.stringify({ name: "Renamed" }),
    });
    expect(patch.status).toBe(200);
    expect(((await patch.json()) as any).name).toBe("Renamed");

    // The id is unchanged after the PATCH (stable).
    const relist = await SELF.fetch(`https://gw.local/v1/orgs/${orgId}/spaces`, {
      headers: authHeaders(adminTok),
    });
    const relisted = (await relist.json()) as any[];
    expect(relisted[0].id).toBe(spaceId);
    expect(relisted[0].name).toBe("Renamed");
  });
});
