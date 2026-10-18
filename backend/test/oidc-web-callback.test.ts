// SPDX-License-Identifier: AGPL-3.0-or-later
// oidc-web-callback.test.ts — the BROWSER-SSO callback wrapper (auth-wiring.handleOidcWebCallback).
//
// Unlike the raw `handleOidcCallback` (token-return JSON, covered by test/oidc.test.ts), the web
// flow must mint a `cfs_session` BROWSER SESSION (identical to password login) and 302-redirect to
// the SPA's /auth/callback (WEB_BASE_URL — audit B9), appending `?error=<code>` on failure. We run against
// the real AuthDO/DirectoryDO/OrgDO (cloudflare:test env) with a MOCKED IdP fetch + the OrgDO-backed
// UserDirectory, so the whole session-mint path runs for real.

import { env } from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import { handleOidcWebCallback } from "../src/auth-wiring";
import { orgDirectory } from "../src/oidc-wiring";
import { handleOidcStart, type OidcConfig, type IdTokenClaims, type FetchLike } from "../src/security/oidc";
import { verifySession } from "../src/security/auth-session";
import { authStoresFor } from "../src/auth-stores";

const SECRET = (env as any).AUTH_SIGNING_SECRET as string;
const ISSUER = "https://idp.local.test";
const CLIENT_ID = "cloudfs-dev-client";
const ORG = "org1"; // matches OIDC_ORG_ID in wrangler.jsonc
// Audit B9: the post-SSO redirect lands on the WEB APP (WEB_BASE_URL), not the Worker
// origin (PUBLIC_BASE_URL) — the SPA renders /auth/callback; the Worker has no such page.
const BASE = "http://localhost:5173"; // matches WEB_BASE_URL in wrangler.jsonc

// ---- RSA keypair + signed-id_token helpers (mock IdP, NO network) --------------------
const enc = new TextEncoder();
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(o: unknown): string {
  return b64url(enc.encode(JSON.stringify(o)));
}

let keyPair: CryptoKeyPair;
let jwk: JsonWebKey;
const KID = "test-key-web";

beforeAll(async () => {
  const algo = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  keyPair = (await crypto.subtle.generateKey(algo, true, ["sign", "verify"])) as CryptoKeyPair;
  jwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as JsonWebKey;
});

async function makeIdToken(claims: Partial<IdTokenClaims>): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const full: IdTokenClaims = {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: "idp-sub-web",
    exp: nowSec + 300,
    iat: nowSec,
    email: "editor@acmepost.com",
    email_verified: true,
    name: "Eddie Editor",
    ...claims,
  };
  const header = { alg: "RS256", kid: KID, typ: "JWT" };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(full)}`;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keyPair.privateKey, enc.encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

function mockFetch(opts: { idToken?: string; tokenStatus?: number } = {}): FetchLike {
  return async (input: string) => {
    if (input.includes("jwks")) {
      return new Response(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "RS256", use: "sig" }] }), { status: 200 });
    }
    if (input.includes("/token")) {
      if (opts.tokenStatus && opts.tokenStatus >= 400) {
        return new Response(JSON.stringify({ error: "invalid_grant" }), { status: opts.tokenStatus });
      }
      return new Response(JSON.stringify({ id_token: opts.idToken, token_type: "Bearer", expires_in: 3600 }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };
}

function webConfig(over: Partial<OidcConfig> = {}): OidcConfig {
  return {
    issuer: ISSUER,
    authorizationEndpoint: `${ISSUER}/authorize`,
    tokenEndpoint: `${ISSUER}/token`,
    jwksUri: `${ISSUER}/jwks`,
    clientId: CLIENT_ID,
    clientSecret: "client-secret-xyz",
    redirectUri: `${BASE}/v1/auth/oidc/callback`,
    orgId: ORG,
    allowedDomains: ["acmepost.com"],
    autoProvision: true,
    ...over,
  };
}

/// Drive start → web callback. Returns the 302 Response from handleOidcWebCallback.
async function startThenWebCallback(claimsOver: Partial<IdTokenClaims> = {}): Promise<Response> {
  const config = webConfig();
  const start = await handleOidcStart(config, { AUTH_SIGNING_SECRET: SECRET });
  const cookie = start.response.headers.get("set-cookie")!.split(";")[0]; // cfs_oidc=...
  const idToken = await makeIdToken({ nonce: start.nonce, ...claimsOver });
  const cbReq = new Request(`${config.redirectUri}?code=auth-code-web&state=${encodeURIComponent(start.state)}`, {
    headers: { cookie },
  });
  const dir = orgDirectory(env as any, config.orgId);
  return handleOidcWebCallback(cbReq, env as any, { config, env: env as any, dir, fetchImpl: mockFetch({ idToken }) });
}

function sessionCookieValue(res: Response): string | null {
  for (const [k, v] of res.headers as any) {
    if (k.toLowerCase() === "set-cookie") {
      const m = /cfs_session=([^;]+)/.exec(v);
      if (m) return m[1];
    }
  }
  // Fallback: combined header.
  const sc = res.headers.get("set-cookie");
  if (sc) {
    const m = /cfs_session=([^;]+)/.exec(sc);
    if (m) return m[1];
  }
  return null;
}

describe("OIDC browser-SSO callback — cookie + 302 redirect (web flow)", () => {
  it("mints a cfs_session browser session and 302s to WEB_BASE_URL/auth/callback (no ?error)", async () => {
    const res = await startThenWebCallback({ email: `web-${Date.now()}@acmepost.com` });
    expect(res.status).toBe(302);

    const loc = new URL(res.headers.get("Location")!);
    expect(`${loc.origin}${loc.pathname}`).toBe(`${BASE}/auth/callback`);
    expect(loc.searchParams.get("error")).toBeNull();

    // An org-qualified cfs_session cookie is set ("<orgId>.sess-...").
    const cookie = sessionCookieValue(res);
    expect(cookie).toBeTruthy();
    expect(cookie!.startsWith(`${ORG}.sess-`)).toBe(true);

    // The cfs_oidc login-state cookie is cleared (one-time use, burned).
    const allCookies = (res.headers as any).getSetCookie ? (res.headers as any).getSetCookie() : [res.headers.get("set-cookie")];
    const joined = allCookies.join("; ");
    expect(joined).toMatch(/cfs_oidc=;/);

    // The minted session row is REAL: verifySession against the org's AuthDO accepts the bare id.
    const bareSessionId = cookie!.slice(ORG.length + 1);
    const stores = authStoresFor(env as any, ORG);
    const bareReq = new Request("https://gw.local/x", { headers: { cookie: `cfs_session=${bareSessionId}` } });
    const verified = await verifySession(bareReq, stores.sessions, { AUTH_SIGNING_SECRET: SECRET });
    expect(verified.session.orgId).toBe(ORG);
    expect(verified.session.scopes.length).toBeGreaterThan(0);
  });

  it("302s to /auth/callback?error=<code> on a failed token exchange (no session cookie)", async () => {
    const config = webConfig();
    const start = await handleOidcStart(config, { AUTH_SIGNING_SECRET: SECRET });
    const cookie = start.response.headers.get("set-cookie")!.split(";")[0];
    const cbReq = new Request(`${config.redirectUri}?code=c&state=${encodeURIComponent(start.state)}`, {
      headers: { cookie },
    });
    const dir = orgDirectory(env as any, config.orgId);
    const res = await handleOidcWebCallback(cbReq, env as any, {
      config,
      env: env as any,
      dir,
      fetchImpl: mockFetch({ tokenStatus: 400 }),
    });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get("Location")!);
    expect(`${loc.origin}${loc.pathname}`).toBe(`${BASE}/auth/callback`);
    expect(loc.searchParams.get("error")).toBe("token_exchange_failed");
    expect(sessionCookieValue(res)).toBeNull(); // no session minted on failure
  });

  it("302s with ?error=state_mismatch on a CSRF state mismatch", async () => {
    const config = webConfig();
    const start = await handleOidcStart(config, { AUTH_SIGNING_SECRET: SECRET });
    const cookie = start.response.headers.get("set-cookie")!.split(";")[0];
    const idToken = await makeIdToken({ nonce: start.nonce });
    const cbReq = new Request(`${config.redirectUri}?code=c&state=TAMPERED`, { headers: { cookie } });
    const dir = orgDirectory(env as any, config.orgId);
    const res = await handleOidcWebCallback(cbReq, env as any, {
      config,
      env: env as any,
      dir,
      fetchImpl: mockFetch({ idToken }),
    });
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("Location")!).searchParams.get("error")).toBe("state_mismatch");
  });
});
