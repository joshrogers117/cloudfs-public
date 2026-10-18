// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { runCli } from "./helpers.js";

describe("--json output shape (stable schema)", () => {
  it("wraps success in { ok: true, data }", async () => {
    const r = await runCli(["--json", "filespace", "list"]);
    expect(r.json.ok).toBe(true);
    expect(Array.isArray(r.json.data)).toBe(true);
    expect(r.json.data[0]).toMatchObject({ id: expect.any(String), name: expect.any(String), status: expect.any(String) });
  });

  it("wraps errors in { ok: false, error: { message, code } }", async () => {
    const r = await runCli(["--json", "stat", "/missing", "active-edit"]);
    expect(r.json.ok).toBe(false);
    expect(r.json.error).toMatchObject({ message: expect.any(String), code: 20 });
  });

  it("includes structured detail for sync-barrier failures", async () => {
    const r = await runCli(["--json", "wait", "/ShowA", "active-edit", "--timeout", "0.1", "--interval", "20"], {
      authenticated: true,
      pendingUploads: 2,
    });
    expect(r.json.ok).toBe(false);
    expect(r.json.error.code).toBe(50);
    expect(r.json.error.detail).toMatchObject({ path: "/ShowA", pendingUploads: 2 });
  });

  it("auth status --json carries the auth fields", async () => {
    const r = await runCli(["--json", "auth", "status"], { authenticated: true, token: "svc" });
    expect(r.json.ok).toBe(true);
    expect(r.json.data).toMatchObject({ authenticated: true, kind: "service-account" });
  });

  it("version --json exposes the exit-code table", async () => {
    const r = await runCli(["--json", "version"]);
    expect(r.json.data.name).toBe("cloudfs");
    expect(r.json.data.exitCodes["0"]).toBe("success");
    expect(r.json.data.exitCodes["10"]).toContain("not authenticated");
  });

  it("events stream emits one NDJSON object per line", async () => {
    const r = await runCli(["--json", "events", "active-edit"]);
    expect(r.code).toBe(0);
    const lines = r.stdout.filter((l) => l.trim().length > 0);
    expect(lines.length).toBe(3);
    for (const line of lines) {
      const obj = JSON.parse(line);
      expect(obj).toMatchObject({ seq: expect.any(Number), type: expect.any(String), path: expect.any(String) });
    }
  });
});
