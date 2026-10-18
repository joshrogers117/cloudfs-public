// SPDX-License-Identifier: AGPL-3.0-or-later
// cors.test.ts — split-origin web-console CORS (audit B9).
import { SELF, env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { corsHeadersFor, handleCorsPreflight, allowedOrigins } from "../src/cors";

const WEB = (env as any).WEB_BASE_URL as string; // http://localhost:5173 in dev/test

describe("B9: CORS allow-list (pure)", () => {
  it("includes WEB_BASE_URL and extra CORS_ALLOWED_ORIGINS", () => {
    const set = allowedOrigins({ WEB_BASE_URL: "https://a.example/", CORS_ALLOWED_ORIGINS: "https://b.example, https://c.example" });
    expect(set.has("https://a.example")).toBe(true); // trailing slash normalized away
    expect(set.has("https://b.example")).toBe(true);
    expect(set.has("https://c.example")).toBe(true);
  });

  it("reflects an allow-listed Origin (never `*`) with credentials", () => {
    const req = new Request("https://gw.local/v1/items", { headers: { Origin: WEB } });
    const h = corsHeadersFor(req, env as any);
    expect(h["Access-Control-Allow-Origin"]).toBe(WEB);
    expect(h["Access-Control-Allow-Origin"]).not.toBe("*");
    expect(h["Access-Control-Allow-Credentials"]).toBe("true");
    expect(h["Vary"]).toBe("Origin");
  });

  it("emits NO CORS headers for a non-allow-listed origin (fail-closed)", () => {
    const req = new Request("https://gw.local/v1/items", { headers: { Origin: "https://evil.example" } });
    expect(Object.keys(corsHeadersFor(req, env as any))).toHaveLength(0);
  });

  it("a preflight from an allowed origin → 204 with CORS headers", () => {
    const req = new Request("https://gw.local/v1/items", { method: "OPTIONS", headers: { Origin: WEB } });
    const res = handleCorsPreflight(req, env as any)!;
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(WEB);
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("PUT");
  });
});

describe("B9: CORS end-to-end through the Worker", () => {
  it("an OPTIONS preflight from WEB_BASE_URL gets a 204 + ACAO", async () => {
    const res = await SELF.fetch("https://gw.local/v1/filespaces/fs1/items?parent=root", {
      method: "OPTIONS",
      headers: { Origin: WEB, "Access-Control-Request-Method": "GET" },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(WEB);
  });

  it("a real cross-origin response carries the ACAO header so the browser can read it", async () => {
    const res = await SELF.fetch("https://gw.local/v1/health", { headers: { Origin: WEB } });
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(WEB);
  });

  it("a non-allow-listed origin gets NO ACAO header (browser blocks the read)", async () => {
    const res = await SELF.fetch("https://gw.local/v1/health", { headers: { Origin: "https://evil.example" } });
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });
});
