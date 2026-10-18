// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { runCli } from "./helpers.js";
import { parseSize, formatSize } from "../src/util.js";
import { hoistGlobalFlags } from "../src/app.js";

describe("argument parsing", () => {
  it("resolves the filespace from a positional argument", async () => {
    const r = await runCli(["--json", "cache", "info", "active-edit"]);
    expect(r.json.ok).toBe(true);
    expect(r.json.data).toHaveProperty("location");
  });

  it("resolves the filespace from --filespace", async () => {
    const r = await runCli(["--json", "--filespace", "active-edit", "cache", "info"]);
    expect(r.json.ok).toBe(true);
  });

  it("parses cache set-size human sizes", async () => {
    const r = await runCli(["--json", "cache", "set-size", "512GiB", "active-edit"]);
    expect(r.json.ok).toBe(true);
    expect(r.json.data.sizeBytes).toBe(512 * 1024 ** 3);
  });

  it("honours -r/--recursive on pin", async () => {
    const r = await runCli(["--json", "cache", "pin", "/ShowA", "active-edit", "-r"]);
    expect(r.json.ok).toBe(true);
    expect(r.json.data).toMatchObject({ path: "/ShowA", pinned: true });
  });

  it("cache pin-list returns per-item byte accounting + cache state", async () => {
    const r = await runCli(["--json", "cache", "pin-list", "active-edit"]);
    expect(r.json.ok).toBe(true);
    expect(Array.isArray(r.json.data)).toBe(true);
    // The mock pins /ShowA by default; each row carries cached/total + state.
    const showA = r.json.data.find((p: { path: string }) => p.path === "/ShowA");
    expect(showA).toMatchObject({
      path: "/ShowA",
      state: "pinned",
      cachedBytes: showA.totalBytes,
    });
    expect(typeof showA.cachedBytes).toBe("number");
    expect(typeof showA.totalBytes).toBe("number");
  });

  it("cache pins alias resolves to pin-list", async () => {
    const r = await runCli(["--json", "cache", "pins", "active-edit"]);
    expect(r.json.ok).toBe(true);
    expect(Array.isArray(r.json.data)).toBe(true);
  });

  it("share link create accepts --kind and --expires", async () => {
    const r = await runCli(["--json", "share", "link", "create", "/ShowA", "active-edit", "--kind", "guest", "--expires", "5"]);
    expect(r.json.ok).toBe(true);
    expect(r.json.data.kind).toBe("guest");
    expect(r.json.data.expiresAt).not.toBeNull();
  });

  it("permissions grant captures level and --mount-as-root", async () => {
    const r = await runCli(["--json", "permissions", "grant", "colorist@x.tv", "/ShowA/Color", "read-write", "active-edit", "--mount-as-root"]);
    expect(r.json.ok).toBe(true);
    expect(r.json.data).toMatchObject({ level: "read-write", mountAsRoot: true });
  });

  it("aliases resolve (fs -> filespace, whoami -> auth status)", async () => {
    const a = await runCli(["--json", "fs", "list"]);
    expect(a.json.ok).toBe(true);
    const b = await runCli(["--json", "auth", "whoami"], { authenticated: true });
    expect(b.json.ok).toBe(true);
  });

  it("yaml output is selectable via --output yaml", async () => {
    const r = await runCli(["--output", "yaml", "cache", "info", "active-edit"]);
    expect(r.code).toBe(0);
    expect(r.stdout.join("\n")).toContain("location:");
  });

  it("quiet mode suppresses human output but preserves exit code", async () => {
    const r = await runCli(["--quiet", "filespace", "list"]);
    expect(r.code).toBe(0);
    expect(r.stdout.join("").trim()).toBe("");
  });

  // Audit B27: global flags placed AFTER the subcommand used to be rejected as an
  // "unknown option" (exit 2) under commander's positional-options mode. They now work.
  it("accepts a global --json placed AFTER the subcommand", async () => {
    const r = await runCli(["filespace", "list", "--json"]);
    expect(r.code).toBe(0);
    expect(r.json?.ok).toBe(true);
  });

  it("accepts a value-taking global (--filespace) placed AFTER the subcommand + its args", async () => {
    const r = await runCli(["--json", "cache", "info", "--filespace", "active-edit"]);
    expect(r.code).toBe(0);
    expect(r.json.ok).toBe(true);
    expect(r.json.data).toHaveProperty("location");
  });

  it("accepts --output yaml placed AFTER the subcommand", async () => {
    const r = await runCli(["cache", "info", "active-edit", "--output", "yaml"]);
    expect(r.code).toBe(0);
    expect(r.stdout.join("\n")).toContain("location:");
  });
});

describe("enum validation (B27)", () => {
  it("rejects an invalid grant level with USAGE (not a silent down-grant)", async () => {
    const r = await runCli(["--json", "permissions", "grant", "x@y.tv", "/ShowA", "write", "active-edit"]);
    expect(r.code).toBe(2); // USAGE
    expect(r.json.ok).toBe(false);
    expect(r.json.error.message).toMatch(/invalid level "write"/);
  });

  it("accepts a valid grant level", async () => {
    const r = await runCli(["--json", "permissions", "grant", "x@y.tv", "/ShowA", "read-write", "active-edit"]);
    expect(r.code).toBe(0);
    expect(r.json.data.level).toBe("read-write");
  });

  it("rejects an invalid share --kind", async () => {
    const r = await runCli(["--json", "share", "link", "create", "/ShowA", "active-edit", "--kind", "guests"]);
    expect(r.code).toBe(2);
    expect(r.json.error.message).toMatch(/invalid --kind "guests"/);
  });

  it("rejects an invalid user --role", async () => {
    const r = await runCli(["--json", "users", "create", "new@x.tv", "--role", "superuser"]);
    expect(r.code).toBe(2);
    expect(r.json.error.message).toMatch(/invalid role "superuser"/);
  });
});

describe("hoistGlobalFlags (global-flags-after-subcommand, B27)", () => {
  it("hoists a trailing boolean global to the front", () => {
    expect(hoistGlobalFlags(["filespace", "list", "--json"])).toEqual(["--json", "filespace", "list"]);
  });
  it("hoists a value-taking global with its separate value", () => {
    expect(hoistGlobalFlags(["cache", "info", "--filespace", "active-edit"])).toEqual([
      "--filespace", "active-edit", "cache", "info",
    ]);
  });
  it("hoists the --opt=value form as a single token", () => {
    expect(hoistGlobalFlags(["ls", "/", "--output=yaml"])).toEqual(["--output=yaml", "ls", "/"]);
  });
  it("leaves a leading global where it is (idempotent ordering)", () => {
    expect(hoistGlobalFlags(["--json", "filespace", "list"])).toEqual(["--json", "filespace", "list"]);
  });
  it("does NOT hoist --token (subcommand-owned) or unknown options", () => {
    expect(hoistGlobalFlags(["auth", "login", "--token", "X"])).toEqual(["auth", "login", "--token", "X"]);
    expect(hoistGlobalFlags(["foo", "--bogus", "v"])).toEqual(["foo", "--bogus", "v"]);
  });
  it("leaves everything after a literal -- untouched", () => {
    expect(hoistGlobalFlags(["run", "--", "--json", "x"])).toEqual(["run", "--", "--json", "x"]);
  });
});

describe("size helpers", () => {
  it("parseSize handles units and bare bytes", () => {
    expect(parseSize("1024")).toBe(1024);
    expect(parseSize("1KiB")).toBe(1024);
    expect(parseSize("2GB")).toBe(2 * 1024 ** 3);
    expect(parseSize("1.5TiB")).toBe(Math.round(1.5 * 1024 ** 4));
  });

  it("formatSize round-trips to human strings", () => {
    expect(formatSize(0)).toBe("0 B");
    expect(formatSize(1024)).toBe("1.0 KiB");
    expect(formatSize(1024 ** 3)).toBe("1.0 GiB");
  });
});
