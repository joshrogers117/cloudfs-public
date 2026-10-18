// SPDX-License-Identifier: AGPL-3.0-or-later
import { createExecutionContext, env, waitOnExecutionContext } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Env } from "../src/env";
import { filespaceDoName } from "../src/security/auth";
import { seedOwnerFixture } from "./setup-fixture";

describe("legacy upload completion cannot claim durable publication", () => {
  it("refuses fully reported parts in strict mode without completing the row or changing the file/activity", async () => {
    const bindings = env as Env, orgId = `legacy-${crypto.randomUUID()}`;
    const owner = await seedOwnerFixture(orgId), spaceId = "files";
    const space = bindings.FILESPACE.getByName(filespaceDoName(orgId, spaceId));
    const created = await space.createItem("root", "clip.mov", false, 0);
    if (!("item" in created)) throw new Error("fixture item creation failed");
    const uploadId = crypto.randomUUID();
    await space.beginUpload(uploadId, created.item.id, `blocks/${orgId}::${spaceId}/unverified`, 4, 4);
    await space.recordUploadPart(uploadId, 1, "client-asserted-etag", 4);
    await space.transferBegin({ id: uploadId, path: created.item.id, direction: "upload", bytesTotal: 4 });
    const before = await space.liveActivity();
    const ctx = createExecutionContext();
    const response = await worker.fetch(new Request(`https://gw.local/v1/filespaces/${spaceId}/uploads/${uploadId}/complete`, {
      method: "POST", headers: { authorization: `Bearer ${owner.token}`, "content-type": "application/json" },
      body: JSON.stringify({ etag: "client-asserted-complete" }),
    }), { ...bindings, STORAGE_VERIFY_UPLOADS: "1" }, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ error: "legacy_multipart_unverified" });
    expect((await space.uploadStatus(uploadId)).session?.state).toBe("in_progress");
    expect(await space.getItem(created.item.id)).toEqual(created.item);
    expect(await space.getBlockMap(created.item.id)).toEqual([]);
    expect(await space.liveActivity()).toEqual(before);
  });
});
