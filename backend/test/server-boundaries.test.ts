// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF, env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import type { Env } from "../src/env";
import { filespaceDoName, mintToken, type Scope } from "../src/security/auth";
import { seedOwnerFixture } from "./setup-fixture";

async function fixture() {
  const e = env as Env;
  const orgId = `server-${crypto.randomUUID()}`;
  const owner = await seedOwnerFixture(orgId);
  const org = e.ORG_DO.get(e.ORG_DO.idFromName(orgId));
  const member = await org.createUser({ orgId, email: `member@${orgId}.test`, displayName: "Member", role: "standard" });
  // Scope alone is intentionally broad: folder/org authority must still be enforced.
  const scopes: Scope[] = ["fs:read", "fs:write", "fs:admin", "snapshot:read", "snapshot:write"];
  const memberToken = await mintToken(e.AUTH_SIGNING_SECRET, { sub: member.id, orgId, type: "session", scopes, ttlSeconds: 900 });
  const fs = e.FILESPACE.get(e.FILESPACE.idFromName(filespaceDoName(orgId, "space")));
  const created = await fs.createItem("root", "Private", true, 0);
  if (!("item" in created)) throw new Error("fixture");
  const folder = created.item;
  const fileResult = await fs.createItem(folder.id, "clip.mov", false, 0);
  if (!("item" in fileResult)) throw new Error("fixture");
  const file = fileResult.item;
  const request = (token: string, method: string, path: string, body?: unknown) => SELF.fetch(`https://test/v1/filespaces/space${path}`, {
    method, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { owner, member, memberToken, fs, folder, file, request };
}

describe("server authority boundaries", () => {
  it("requires current inode access for every multipart operation", async () => {
    const f = await fixture();
    await f.fs.beginUpload("private-upload", f.file.id, "private-object", 20, 10);
    for (const [method, path, body] of [
      ["GET", "/uploads/private-upload", undefined],
      ["DELETE", "/uploads/private-upload", undefined],
      ["PUT", "/uploads/private-upload/parts", { partNumber: 1, size: 10, etag: "part" }],
      ["POST", "/uploads/private-upload/complete", { etag: "complete" }],
    ] as const) {
      expect((await f.request(f.memberToken, method, path, body)).status).toBe(404);
    }
    expect((await f.fs.uploadStatus("private-upload")).session?.state).toBe("in_progress");
    await f.fs.grantAccess({ spaceId: "space", inodeId: f.folder.id, principalType: "user", principalId: f.member.id, level: "read" }, f.owner.userId);
    expect((await f.request(f.memberToken, "GET", "/uploads/private-upload")).status).toBe(200);
    expect((await f.request(f.memberToken, "DELETE", "/uploads/private-upload")).status).toBe(403);
    expect((await f.request(f.owner.token, "DELETE", "/uploads/private-upload")).status).toBe(200);
  });

  it("rejects invalid schedule input and prevents folder administrators changing global retention", async () => {
    const f = await fixture();
    const valid = { id: "hourly", tier: "hourly", intervalMs: 3600000, retain: 24 };
    await f.fs.grantAccess({ spaceId: "space", inodeId: f.folder.id, principalType: "user", principalId: f.member.id, level: "admin" }, f.owner.userId);
    expect((await f.request(f.memberToken, "POST", "/schedules", valid)).status).toBe(403);
    for (const patch of [{ intervalMs: 0 }, { intervalMs: -1 }, { retain: -1 }, { retain: 0.5 }, { tier: "" }]) {
      expect((await f.request(f.owner.token, "POST", "/schedules", { ...valid, ...patch })).status).toBe(400);
    }
    expect((await f.request(f.owner.token, "POST", "/schedules", valid)).status).toBe(201);
    expect((await f.request(f.owner.token, "PATCH", "/schedules/hourly", { enabled: "false" })).status).toBe(400);
    expect((await f.request(f.owner.token, "PATCH", "/schedules/hourly", { enabled: false })).status).toBe(200);
  });
});
