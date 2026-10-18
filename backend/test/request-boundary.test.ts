// SPDX-License-Identifier: AGPL-3.0-or-later
import { SELF } from "cloudflare:test";
import { describe, it, expect, vi } from "vitest";
import { MAX_API_BODY_BYTES, requestBoundary, requestCategory } from "../src/request-boundary";

describe("bounded API requests and private operational errors", () => {
  it("rejects an oversized declared body before invoking routing", async () => {
    const handler = vi.fn();
    const response = await requestBoundary(new Request("https://test/v1/setup/init", {
      method: "POST", headers: { "content-length": String(MAX_API_BODY_BYTES + 1) },
    }), handler);
    expect(response.status).toBe(413);
    expect(handler).not.toHaveBeenCalled();
  });

  it("bounds a chunked stream without trusting Content-Length, even if a parser catches its error", async () => {
    let cancelled = false;
    let pulls = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) { pulls++; controller.enqueue(new Uint8Array(1024 * 1024)); },
      cancel() { cancelled = true; },
    });
    const response = await requestBoundary(new Request("https://test/v1/filespaces/f/blocks/i", {
      method: "PUT", body,
    }), async req => {
      try { await req.json(); } catch { return Response.json({ error: "invalid_json" }, { status: 400 }); }
      return Response.json({ ok: true });
    });
    expect(response.status).toBe(413);
    expect(cancelled).toBe(true);
    expect(pulls).toBeLessThanOrEqual(19);
  });

  it("uses the smaller named-stream limit", async () => {
    const response = await requestBoundary(new Request("https://test/v1/filespaces/f/items/i/streams/AFP_Resource", {
      method: "PUT", headers: { "content-length": String(4 * 1024 * 1024 + 1) },
    }), async () => Response.json({ ok: true }));
    expect(response.status).toBe(413);
  });

  it("does not log or return secrets from unexpected exceptions, URLs or request headers", async () => {
    const logger = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const response = await requestBoundary(new Request("https://test/v1/auth/oidc/callback?code=private-code", {
        headers: { authorization: "Bearer private-token" },
      }), async () => { throw new Error("upstream URL contains private-password"); });
      expect(response.status).toBe(500);
      expect(await response.json()).toEqual({ error: "internal_error" });
      const event = logger.mock.calls[0][0];
      expect(JSON.stringify(event)).not.toMatch(/private/);
      expect(event.requestId).toBe(response.headers.get("X-CloudFS-Request-ID"));
      expect(event.category).toBe("auth");
    } finally { logger.mockRestore(); }
  });

  it("returns 400 for malformed JSON and preserves response cookies", async () => {
    const malformed = await requestBoundary(new Request("https://test/v1/x", { method: "POST", body: "{" }), async req => {
      await req.json(); return new Response();
    });
    expect(malformed.status).toBe(400);
    const valid = await requestBoundary(new Request("https://test/v1/auth/login"), async () => new Response(null, {
      status: 204, headers: { "set-cookie": "session=value; HttpOnly; Secure" },
    }));
    expect(valid.headers.get("set-cookie")).toContain("HttpOnly");
    expect(valid.headers.get("cache-control")).toBe("no-store");
  });

  it("returns tracing and no-store headers even on pre-auth failures and preflight", async () => {
    for (const method of ["GET", "OPTIONS"]) {
      const response = await SELF.fetch("https://test/v1/filespaces/f/items", { method });
      expect(response.headers.get("X-CloudFS-Request-ID")).toMatch(/^[0-9a-f-]{36}$/);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("X-CloudFS-API-Version")).toBeTruthy();
    }
  });

  it("never includes user supplied path segments in log categories", () => {
    expect(requestCategory("/v1/filespaces/secret-folder/items/private-name")).toBe("filespace");
    expect(requestCategory("/v1/private-name")).toBe("api");
  });
});
