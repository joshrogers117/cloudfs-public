// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { HttpGatewayClient } from "../src/gateway/http.js";
import { ExitCode } from "../src/exit-codes.js";
import { makeFetch, fakeToken, type Handler } from "./fetch-mock.js";
import { runCliWith } from "./helpers.js";

const TOKEN = fakeToken({ sub: "ed@studio", typ: "session", org: "studio", scp: ["snapshot:read", "fs:write"], exp: 4102444800 });
const BASE = "https://gw.cloudfs.example";
const RESTORE_PATH = "/v1/filespaces/active-edit/snapshots/snap-1/restore";

function client(routes: Record<string, Handler>) {
  const mf = makeFetch(routes);
  const c = new HttpGatewayClient({ baseUrl: BASE, token: TOKEN, fetch: mf.fetch });
  return { c, mf };
}

const RESULT = {
  snapshotId: "snap-1",
  restored: ["/ShowA/Edit/timeline.prproj", "/ShowA/Edit/clip.mov"],
  recreated: ["/ShowA/Edit/deleted.mov"],
  conflicts: [{ id: "/ShowA/Edit/locked.mov", heldBy: "colorist@studio" }],
  newerThanSnapshot: ["/ShowA/Edit/added-after.mov"],
};

describe("HttpGatewayClient.snapshotRestore — request shape (API.md)", () => {
  it("POSTs to /snapshots/:id/restore with { path, recursive, mode } and bearer auth", async () => {
    const { c, mf } = client({ [`POST ${RESTORE_PATH}`]: { status: 200, json: RESULT } });
    const res = await c.snapshotRestore({ filespace: "active-edit", id: "snap-1", path: "/ShowA/Edit", recursive: true, mode: "merge" });
    expect(res).toEqual(RESULT);
    const req = mf.last();
    expect(req.method).toBe("POST");
    expect(req.path).toBe(RESTORE_PATH);
    expect(req.headers.authorization).toBe(`Bearer ${TOKEN}`);
    expect(req.body).toEqual({ path: "/ShowA/Edit", recursive: true, mode: "merge" });
  });

  it("omits absent options (single-file restore)", async () => {
    const { c, mf } = client({ [`POST ${RESTORE_PATH}`]: { status: 200, json: { ...RESULT, restored: ["/ShowA/Edit/timeline.prproj"], recreated: [], conflicts: [], newerThanSnapshot: [] } } });
    await c.snapshotRestore({ filespace: "active-edit", id: "snap-1", path: "/ShowA/Edit/timeline.prproj" });
    expect(mf.last().body).toEqual({ path: "/ShowA/Edit/timeline.prproj", recursive: undefined, mode: undefined });
  });

  it("defensively maps a partial/empty RestoreResult", async () => {
    const { c } = client({ [`POST ${RESTORE_PATH}`]: { status: 200, json: { restored: ["/x"] } } });
    const res = await c.snapshotRestore({ filespace: "active-edit", id: "snap-1", path: "/x" });
    expect(res).toEqual({ snapshotId: "snap-1", restored: ["/x"], recreated: [], conflicts: [], newerThanSnapshot: [] });
  });
});

describe("snapshot restore — through the CLI (--json + counts)", () => {
  it("--json returns the full RestoreResult arrays under the stable envelope", async () => {
    const { c } = client({ [`POST ${RESTORE_PATH}`]: { status: 200, json: RESULT } });
    const r = await runCliWith(["--json", "snapshot", "restore", "snap-1", "/ShowA/Edit", "active-edit", "--recursive"], c);
    expect(r.code).toBe(0);
    expect(r.json.ok).toBe(true);
    expect(r.json.data).toEqual(RESULT);
  });

  it("table view summarizes counts, not raw arrays", async () => {
    const { c } = client({ [`POST ${RESTORE_PATH}`]: { status: 200, json: RESULT } });
    const r = await runCliWith(["snapshot", "restore", "snap-1", "/ShowA/Edit", "active-edit", "-r"], c);
    expect(r.code).toBe(0);
    const out = r.stdout.join("\n");
    expect(out).toContain("restored: 2");
    expect(out).toContain("conflicts: 1");
    expect(out).toMatch(/Restored 2 item\(s\) from snap-1/);
  });

  it("passes --recursive through to the request body", async () => {
    const { c, mf } = client({ [`POST ${RESTORE_PATH}`]: { status: 200, json: RESULT } });
    await runCliWith(["snapshot", "restore", "snap-1", "/ShowA/Edit", "active-edit", "-r"], c);
    expect(mf.last().body.recursive).toBe(true);
  });
});

describe("snapshot restore — error → stable exit code (API.md §2)", () => {
  const cases: { status: number; error: string; expect: number }[] = [
    { status: 404, error: "no such item", expect: ExitCode.NOT_FOUND },
    { status: 409, error: "conflict", expect: ExitCode.CONFLICT },
    { status: 403, error: "forbidden", expect: ExitCode.PERMISSION_DENIED },
    { status: 401, error: "expired", expect: ExitCode.TOKEN_EXPIRED },
  ];
  for (const tc of cases) {
    it(`${tc.status} ${tc.error} -> exit ${tc.expect}`, async () => {
      const { c } = client({ [`POST ${RESTORE_PATH}`]: { status: tc.status, json: { error: tc.error, reason: "x" } } });
      await expect(c.snapshotRestore({ filespace: "active-edit", id: "snap-1", path: "/ShowA/Edit" })).rejects.toMatchObject({ code: tc.expect });
    });
  }

  it("409 (all targets locked) surfaces as exit 21 with a JSON error envelope via the CLI", async () => {
    const { c } = client({ [`POST ${RESTORE_PATH}`]: { status: 409, json: { error: "conflict", conflict: true } } });
    const r = await runCliWith(["--json", "snapshot", "restore", "snap-1", "/ShowA/Edit", "active-edit"], c);
    expect(r.code).toBe(ExitCode.CONFLICT);
    expect(r.json.ok).toBe(false);
    expect(r.json.error.code).toBe(ExitCode.CONFLICT);
  });
});
