// SPDX-License-Identifier: AGPL-3.0-or-later
// context.test.ts — audit B11: the CLI must NOT silently fall back to the mock.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildContext, resolveGatewayUrl, NoGatewayConfiguredError } from "../src/context.js";
import type { GlobalOptions } from "../src/context.js";

const BASE_GLOBAL: GlobalOptions = { output: "table", json: false, quiet: false };

// Snapshot + restore the env keys this suite mutates.
const KEYS = ["CLOUDFS_GATEWAY_URL", "CLOUDFS_GATEWAY", "CLOUDFS_TOKEN", "CLOUDFS_TOKEN_FILE", "CLOUDFS_MOCK", "CLOUDFS_DAEMON_SOCKET"];
let saved: Record<string, string | undefined>;
beforeEach(() => {
  saved = {};
  for (const k of KEYS) { saved[k] = process.env[k]; delete process.env[k]; }
  // Ensure no daemon socket is auto-detected (keep the gateway client unwrapped).
  process.env.CLOUDFS_DAEMON_SOCKET = "/definitely/not/a/socket";
});
afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
});

describe("B11: CLI gateway selection is fail-loud (no silent mock)", () => {
  it("throws NoGatewayConfiguredError when no URL and no --mock (the misconfig trap)", () => {
    expect(() => buildContext({ ...BASE_GLOBAL })).toThrow(NoGatewayConfiguredError);
  });

  it("throws (with the token-set hint) when a token is present but no gateway URL", () => {
    process.env.CLOUDFS_TOKEN = "a.real.token";
    expect(() => buildContext({ ...BASE_GLOBAL })).toThrow(/token is set but CLOUDFS_GATEWAY_URL/);
  });

  it("uses the mock ONLY when explicitly requested via --mock", () => {
    const ctx = buildContext({ ...BASE_GLOBAL, mock: true });
    expect(ctx.client).toBeTruthy(); // the mock client (no throw)
  });

  it("uses the mock when CLOUDFS_MOCK=1 is set", () => {
    process.env.CLOUDFS_MOCK = "1";
    const ctx = buildContext({ ...BASE_GLOBAL });
    expect(ctx.client).toBeTruthy();
  });

  it("builds a real HTTP client when CLOUDFS_GATEWAY_URL is set", () => {
    process.env.CLOUDFS_GATEWAY_URL = "https://gw.example";
    const ctx = buildContext({ ...BASE_GLOBAL });
    expect(ctx.client).toBeTruthy();
  });

  it("accepts the LEGACY CLOUDFS_GATEWAY env var as a URL (unified naming)", () => {
    process.env.CLOUDFS_GATEWAY = "https://gw.legacy.example";
    expect(resolveGatewayUrl()).toBe("https://gw.legacy.example");
    const ctx = buildContext({ ...BASE_GLOBAL });
    expect(ctx.client).toBeTruthy(); // no throw — the legacy var satisfies the URL requirement
  });
});

describe("B16: --token-file keeps the token off argv/ps", () => {
  it("reads the bearer token from --token-file (trimmed)", () => {
    const tmp = join(tmpdir(), `cfs-token-${Math.random().toString(36).slice(2)}`);
    writeFileSync(tmp, "  secret-bearer-token\n");
    try {
      process.env.CLOUDFS_GATEWAY_URL = "https://gw.example";
      // No throw + a client is built; resolveToken reads the file (the token never hit argv).
      const ctx = buildContext({ ...BASE_GLOBAL, tokenFile: tmp });
      expect(ctx.client).toBeTruthy();
    } finally {
      rmSync(tmp, { force: true });
    }
  });
});
