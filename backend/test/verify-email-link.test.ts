// SPDX-License-Identifier: AGPL-3.0-or-later
// verify-email-link.test.ts — BUG 2 regression.
//
// The email VERIFICATION link a human clicks must target the WEB APP's GET-able `/verify-email`
// page (which POSTs {token, orgId} to the POST confirm route), NOT the Worker's POST-only
// `/v1/auth/verify-email` API route — a GET against that route 401s ("no_token"). The link base is
// WEB_BASE_URL (the SPA origin), distinct from PUBLIC_BASE_URL (the Worker/API origin).

import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { buildVerifyUrl, buildResetUrl } from "../src/auth-wiring";

const REQ = new Request("https://gw.local/v1/auth/signup");

describe("verify-email link (BUG 2)", () => {
  it("points at the WEB APP's /verify-email page, not the POST-only API route", () => {
    const url = buildVerifyUrl(env as any, REQ, "org-123")("evt-abc.secret");
    const parsed = new URL(url);

    // Path is the SPA page, NOT the Worker API route (which is POST-only and would 401 on a GET).
    expect(parsed.pathname).toBe("/verify-email");
    expect(parsed.pathname).not.toBe("/v1/auth/verify-email");

    // Origin is WEB_BASE_URL (the SPA), the dev default in wrangler.jsonc — not the Worker origin.
    expect(parsed.origin).toBe("http://localhost:5173");

    // Token + orgId are carried as query params for the SPA page to POST to the confirm route.
    expect(parsed.searchParams.get("token")).toBe("evt-abc.secret");
    expect(parsed.searchParams.get("orgId")).toBe("org-123");
  });

  it("falls back to PUBLIC_BASE_URL, then the request origin, when WEB_BASE_URL is unset", () => {
    const { WEB_BASE_URL: _omit, ...noWeb } = env as any;

    // No WEB_BASE_URL but PUBLIC_BASE_URL set → use PUBLIC_BASE_URL.
    const withPublic = buildVerifyUrl(
      { ...noWeb, PUBLIC_BASE_URL: "https://portal.example" } as any,
      REQ,
      "org-9",
    )("t");
    expect(new URL(withPublic).origin).toBe("https://portal.example");
    expect(new URL(withPublic).pathname).toBe("/verify-email");

    // Neither set → fall back to the request origin.
    const withReqOrigin = buildVerifyUrl(
      { ...noWeb, PUBLIC_BASE_URL: undefined } as any,
      REQ,
      "org-9",
    )("t");
    expect(new URL(withReqOrigin).origin).toBe("https://gw.local");
  });
});

// Audit B11 — the password-RESET link must ALSO target the web app's /reset-password page
// (a human clicks it), not the Worker/API origin which has no such page. Pre-fix the reset
// link used baseUrl (PUBLIC_BASE_URL/API origin) while verify used webBaseUrl, so the
// forgot-password flow dead-ended in every topology.
describe("password-reset link (B11)", () => {
  it("points at the WEB APP's /reset-password page on WEB_BASE_URL, not the API origin", () => {
    const url = buildResetUrl(env as any, REQ, "org-123")("rt-abc.secret");
    const parsed = new URL(url);
    expect(parsed.pathname).toBe("/reset-password");
    // WEB_BASE_URL (SPA) is the dev default — NOT PUBLIC_BASE_URL (the Worker/API origin).
    expect(parsed.origin).toBe("http://localhost:5173");
    expect(parsed.searchParams.get("token")).toBe("rt-abc.secret");
    expect(parsed.searchParams.get("orgId")).toBe("org-123");
  });

  it("uses the SAME base as the verify link (both land on the SPA, not the API)", () => {
    const reset = new URL(buildResetUrl(env as any, REQ, "o")("t"));
    const verify = new URL(buildVerifyUrl(env as any, REQ, "o")("t"));
    expect(reset.origin).toBe(verify.origin);
  });
});
