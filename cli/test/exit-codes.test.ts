// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, expect, it } from "vitest";
import { runCli } from "./helpers.js";
import { ExitCode } from "../src/exit-codes.js";

describe("exit codes (stable contract)", () => {
  it("returns OK (0) on a successful command", async () => {
    const r = await runCli(["filespace", "list"]);
    expect(r.code).toBe(ExitCode.OK);
  });

  it("returns NOT_AUTHENTICATED (10) when not logged in", async () => {
    const r = await runCli(["filespace", "list"], { authenticated: false });
    expect(r.code).toBe(ExitCode.NOT_AUTHENTICATED);
  });

  it("returns AUTH_FAILED (11) for a bad token on login", async () => {
    const r = await runCli(["auth", "login", "--token", "bad"], { authenticated: false });
    expect(r.code).toBe(ExitCode.AUTH_FAILED);
  });

  it("returns NOT_FOUND (20) for a missing path", async () => {
    const r = await runCli(["stat", "/does-not-exist", "active-edit"]);
    expect(r.code).toBe(ExitCode.NOT_FOUND);
  });

  it("returns NOT_FOUND (20) for an unknown filespace", async () => {
    const r = await runCli(["filespace", "status", "ghost"]);
    expect(r.code).toBe(ExitCode.NOT_FOUND);
  });

  it("returns CONFLICT (21) when creating a duplicate filespace", async () => {
    const r = await runCli(["filespace", "create", "Active Edit"]);
    expect(r.code).toBe(ExitCode.CONFLICT);
  });

  it("returns NOT_CONNECTED (23) when unmounting an unmounted filespace", async () => {
    const r = await runCli(["unmount", "archive"]);
    expect(r.code).toBe(ExitCode.NOT_CONNECTED);
  });

  it("returns USAGE (2) for an unknown command", async () => {
    const r = await runCli(["frobnicate"]);
    expect(r.code).toBe(ExitCode.USAGE);
  });

  it("returns USAGE (2) for a missing required argument", async () => {
    const r = await runCli(["stat"]);
    expect(r.code).toBe(ExitCode.USAGE);
  });

  it("returns USAGE (2) when no filespace is selectable", async () => {
    // No --filespace, no env in test, no positional arg.
    const prev = process.env.CLOUDFS_FILESPACE;
    delete process.env.CLOUDFS_FILESPACE;
    try {
      const r = await runCli(["cache", "info"]);
      expect(r.code).toBe(ExitCode.USAGE);
    } finally {
      if (prev !== undefined) process.env.CLOUDFS_FILESPACE = prev;
    }
  });

  it("auth status returns NOT_AUTHENTICATED (10) when unauthenticated", async () => {
    const r = await runCli(["auth", "status"], { authenticated: false });
    expect(r.code).toBe(ExitCode.NOT_AUTHENTICATED);
  });

  it("returns SYNC_TIMEOUT (50) when wait cannot reach sync before the deadline", async () => {
    const r = await runCli(["wait", "/ShowA", "active-edit", "--timeout", "0.1", "--interval", "20"], {
      authenticated: true,
      pendingUploads: 3,
    });
    expect(r.code).toBe(ExitCode.SYNC_TIMEOUT);
  });
});
