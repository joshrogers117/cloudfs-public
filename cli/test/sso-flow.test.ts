// SPDX-License-Identifier: AGPL-3.0-or-later
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, existsSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runOidcLogin } from "../src/auth/oidc-flow.js";
import { saveToken, loadToken, clearToken, tokenPath } from "../src/auth/token-store.js";
import { ExitCode } from "../src/exit-codes.js";

/**
 * Tests run against an in-process FAKE gateway that collapses the IdP round-trip:
 * its `/v1/auth/oidc/start` reads our `return_to` and 302s straight back to the
 * loopback listener with `?token=<minted>` — exactly what the real gateway does
 * after the IdP callback. No real OIDC IdP is involved (that is the LIVE prereq).
 */

const MINTED = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlZEBzdHVkaW8iLCJ0eXAiOiJzZXNzaW9uIn0.sig";

let gateway: Server;
let gatewayUrl: string;
let mode: "redirect-token" | "error" | "deny" = "redirect-token";

async function startFakeGateway(): Promise<void> {
  gateway = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname === "/v1/auth/oidc/start") {
      const returnTo = url.searchParams.get("return_to");
      if (!returnTo) {
        res.writeHead(400).end("missing return_to");
        return;
      }
      if (mode === "error") {
        // No IdP configured on the gateway (the without-IdP case).
        res.writeHead(500, { "content-type": "application/json" }).end(JSON.stringify({ error: "oidc_not_configured" }));
        return;
      }
      const loc = new URL(returnTo);
      if (mode === "deny") loc.searchParams.set("error", "access_denied");
      else loc.searchParams.set("token", MINTED);
      res.writeHead(302, { location: loc.toString() }).end();
      return;
    }
    res.writeHead(404).end("nope");
  });
  await new Promise<void>((resolve) => gateway.listen(0, "127.0.0.1", () => resolve()));
  const addr = gateway.address();
  gatewayUrl = `http://127.0.0.1:${typeof addr === "object" && addr ? addr.port : 0}`;
}

/** A fake "browser": GET the URL and follow redirects (Node global fetch). */
async function fakeBrowserGet(url: string): Promise<boolean> {
  // Drives the redirect chain into the loopback listener; fire-and-forget.
  void fetch(url, { redirect: "follow" }).catch(() => {});
  return true;
}

beforeEach(async () => {
  mode = "redirect-token";
  await startFakeGateway();
});
afterEach(async () => {
  await new Promise<void>((resolve) => gateway.close(() => resolve()));
});

describe("OIDC SSO loopback flow (runOidcLogin)", () => {
  it("captures the token delivered to the loopback ?token= and returns it", async () => {
    const { token } = await runOidcLogin({ gatewayUrl, openBrowser: fakeBrowserGet, log: () => {}, timeoutMs: 5000 });
    expect(token).toBe(MINTED);
  });

  it("targets the gateway's /v1/auth/oidc/start with a loopback return_to", async () => {
    let openedUrl = "";
    await runOidcLogin({
      gatewayUrl,
      log: () => {},
      timeoutMs: 5000,
      openBrowser: (u) => {
        openedUrl = u;
        return fakeBrowserGet(u);
      },
    });
    const u = new URL(openedUrl);
    expect(u.pathname).toBe("/v1/auth/oidc/start");
    const returnTo = new URL(u.searchParams.get("return_to")!);
    expect(returnTo.hostname).toBe("127.0.0.1");
    expect(returnTo.pathname).toBe("/callback");
  });

  it("rejects with AUTH_FAILED (11) when the IdP denies (error in callback)", async () => {
    mode = "deny";
    await expect(
      runOidcLogin({ gatewayUrl, openBrowser: fakeBrowserGet, log: () => {}, timeoutMs: 5000 }),
    ).rejects.toMatchObject({ code: ExitCode.AUTH_FAILED });
  });

  it("still prints the URL when no browser is available (headless fallback)", async () => {
    const lines: string[] = [];
    // Manually drive the loopback after capturing the printed URL.
    let printedUrl = "";
    const p = runOidcLogin({
      gatewayUrl,
      timeoutMs: 5000,
      log: (l) => {
        lines.push(l);
        const m = l.match(/http:\/\/\S+oidc\/start\S*/);
        if (m) {
          printedUrl = m[0];
          void fetch(printedUrl, { redirect: "follow" }).catch(() => {});
        }
      },
      openBrowser: () => false, // no browser
    });
    const { token } = await p;
    expect(token).toBe(MINTED);
    expect(lines.some((l) => l.includes("/v1/auth/oidc/start"))).toBe(true);
    expect(printedUrl).not.toBe("");
  });
});

describe("token store", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "cfs-cfg-"));
    process.env.CLOUDFS_CONFIG_DIR = dir;
  });
  afterEach(() => {
    delete process.env.CLOUDFS_CONFIG_DIR;
    rmSync(dir, { recursive: true, force: true });
  });

  it("saves, loads, and clears a token under CLOUDFS_CONFIG_DIR", () => {
    expect(loadToken()).toBeNull();
    saveToken("  tok-123\n");
    expect(tokenPath()).toBe(join(dir, "token"));
    expect(loadToken()).toBe("tok-123");
    expect(existsSync(tokenPath())).toBe(true);
    clearToken();
    expect(loadToken()).toBeNull();
  });

  it("writes the token file with 0600 permissions", () => {
    saveToken("secret");
    const mode = statSync(tokenPath()).mode & 0o777;
    expect(mode & 0o077).toBe(0); // no group/other access
  });

  it("the full SSO flow result is what gets persisted", async () => {
    const { token } = await runOidcLogin({ gatewayUrl, openBrowser: fakeBrowserGet, log: () => {}, timeoutMs: 5000 });
    saveToken(token);
    expect(loadToken()).toBe(MINTED);
  });
});
