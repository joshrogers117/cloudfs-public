// SPDX-License-Identifier: AGPL-3.0-or-later
// storage-credentials-integration.test.ts — end-to-end through the gateway (SELF.fetch):
// the /v1/orgs/:org/storage-credentials CRUD routes + the role gate + the delete-in-use 409
// against a REAL OrgDO + a real referencing filespace, plus per-space storage-field round-trip.
//
// Bootstrap mints an owner token; a second provisioned standard user proves the 403 gate.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";

const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];
const BOOT_SECRET = "local-dev-bootstrap-secret-change-me-32chars";

async function bootstrap(orgId: string): Promise<{ token: string; userId: string }> {
  const res = await SELF.fetch("https://gw.local/v1/bootstrap", {
    method: "POST",
    headers: { "content-type": "application/json", "x-bootstrap-secret": BOOT_SECRET },
    // allowTokenOnly: token-only seeding (no admin password) is now an explicit opt-in (auth-spec §2.5).
    body: JSON.stringify({ orgId, email: `owner@${orgId}.test`, displayName: "Owner", allowTokenOnly: true }),
  });
  const b = (await res.json()) as { token: string; userId: string };
  return b;
}

async function standardToken(orgId: string): Promise<string> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({ orgId, email: `std-${crypto.randomUUID()}@${orgId}.test`, displayName: "Std", role: "standard" });
  return mintToken((env as any).AUTH_SIGNING_SECRET, { sub: u.id, type: "session", orgId, scopes: ALL_SCOPES, ttlSeconds: 900 });
}

const ORG = "scred-org";
let ownerAuth: Record<string, string>;
let stdAuth: Record<string, string>;
const BASE = `https://gw.local/v1/orgs/${ORG}`;

beforeAll(async () => {
  const boot = await bootstrap(ORG);
  ownerAuth = { Authorization: `Bearer ${boot.token}`, "content-type": "application/json" };
  stdAuth = { Authorization: `Bearer ${await standardToken(ORG)}`, "content-type": "application/json" };
});

describe("storage-credentials CRUD (end-to-end, real OrgDO)", () => {
  it("owner can create → list → delete; the secret never appears in any response", async () => {
    // create
    const created = await SELF.fetch(`${BASE}/storage-credentials`, {
      method: "POST", headers: ownerAuth,
      body: JSON.stringify({ label: "B2 prod", accessKeyId: "AKID-INT", secretAccessKey: "integration-secret-value" }),
    });
    expect(created.status).toBe(201);
    const credText = await created.clone().text();
    expect(credText).not.toContain("integration-secret-value");
    const cred = (await created.json()) as { id: string; label: string; accessKeyId: string };
    expect(cred.id).toMatch(/^scr-/);
    expect(cred.accessKeyId).toBe("AKID-INT");

    // list — never carries the secret
    const listed = await SELF.fetch(`${BASE}/storage-credentials`, { headers: ownerAuth });
    expect(listed.status).toBe(200);
    const listText = await listed.clone().text();
    expect(listText).not.toContain("integration-secret-value");
    const body = (await listed.json()) as { credentials: { id: string }[] };
    expect(body.credentials.some((c) => c.id === cred.id)).toBe(true);

    // delete (unused) → 204
    const del = await SELF.fetch(`${BASE}/storage-credentials/${cred.id}`, { method: "DELETE", headers: ownerAuth });
    expect(del.status).toBe(204);
  });

  it("a standard (non-admin) member is 403 on list and create", async () => {
    const list = await SELF.fetch(`${BASE}/storage-credentials`, { headers: stdAuth });
    expect(list.status).toBe(403);
    const create = await SELF.fetch(`${BASE}/storage-credentials`, {
      method: "POST", headers: stdAuth,
      body: JSON.stringify({ label: "x", accessKeyId: "a", secretAccessKey: "s" }),
    });
    expect(create.status).toBe(403);
  });

  it("DELETE of a credential referenced by a filespace → 409 credential_in_use with space names", async () => {
    // create the managed credential
    const cred = (await (await SELF.fetch(`${BASE}/storage-credentials`, {
      method: "POST", headers: ownerAuth,
      body: JSON.stringify({ label: "In use", accessKeyId: "AKID-USE", secretAccessKey: "in-use-secret" }),
    })).json()) as { id: string };

    // register a filespace that references it via storageCredentialRef
    const reg = await SELF.fetch(`${BASE}/spaces`, {
      method: "POST", headers: ownerAuth,
      body: JSON.stringify({
        spaceId: "fs-using", name: "Using Space", bucketProvider: "wasabi", bucketName: "wb",
        keyPrefix: `blocks/${ORG}::fs-using/`,
        storageEndpoint: "https://s3.us-east-1.wasabisys.com", storageRegion: "us-east-1",
        storageBucket: "wb", storageForcePathStyle: true, storageCredentialRef: cred.id,
      }),
    });
    expect(reg.status).toBe(201);

    // the per-space storage fields ROUND-TRIP on GET (settings page needs them)
    const spaces = (await (await SELF.fetch(`${BASE}/spaces`, { headers: ownerAuth })).json()) as any[];
    const sp = spaces.find((s) => s.id === "fs-using");
    expect(sp.storageEndpoint).toBe("https://s3.us-east-1.wasabisys.com");
    expect(sp.storageRegion).toBe("us-east-1");
    expect(sp.storageBucket).toBe("wb");
    expect(sp.storageForcePathStyle).toBe(true);
    expect(sp.storageCredentialRef).toBe(cred.id);

    // delete is blocked while referenced
    const del = await SELF.fetch(`${BASE}/storage-credentials/${cred.id}`, { method: "DELETE", headers: ownerAuth });
    expect(del.status).toBe(409);
    const body = (await del.json()) as { error: string; spaces: string[] };
    expect(body.error).toBe("credential_in_use");
    expect(body.spaces).toContain("Using Space");
  });

  it("storage/test rejects a non-admin (403) and validates the body (400) for an admin", async () => {
    const denied = await SELF.fetch(`${BASE}/storage/test`, { method: "POST", headers: stdAuth, body: JSON.stringify({}) });
    expect(denied.status).toBe(403);
    // admin with a missing endpoint/bucket → 400
    const bad = await SELF.fetch(`${BASE}/storage/test`, { method: "POST", headers: ownerAuth, body: JSON.stringify({ region: "auto" }) });
    expect(bad.status).toBe(400);
  });
});
