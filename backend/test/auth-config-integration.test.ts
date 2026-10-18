import { seedOwnerFixture } from "./setup-fixture";
// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-config-integration.test.ts — the PLUGGABLE auth provider end-to-end through the gateway
// (SELF.fetch) against the REAL DirectoryDO/OrgDO/AuthDO, plus the two behavioral guarantees that
// can't be unit-tested in isolation:
//   - the UNAUTHENTICATED public-config endpoint shape,
//   - /v1/orgs/:org/auth-config CRUD + role gate + secret-never-leaks across DO reads,
//   - password-login-refused-when-oidc-only (the auth_mode_oidc gate),
//   - first-OIDC-login-provisions-owner (bootstrap-via-OIDC), driven through the REAL
//     handleOidcWebCallback + prepareOidcCallback with a MOCKED IdP fetch (no network).
//
// Storage is isolated per test FILE (vitest-pool-workers), so mutating the global DirectoryDO
// auth-config here doesn't leak into other files; within this file each block cleans up.

import { SELF, env } from "cloudflare:test";
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { mintToken, type Scope } from "../src/security/auth";
import { handleOidcWebCallback } from "../src/auth-wiring";
import { prepareOidcCallback } from "../src/oidc-wiring";
import { handleOidcStart, type OidcConfig, type IdTokenClaims, type FetchLike } from "../src/security/oidc";
import { verifySession } from "../src/security/auth-session";
import { authStoresFor } from "../src/auth-stores";

const ALL_SCOPES: Scope[] = ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read"];
const BOOT_SECRET = "local-dev-bootstrap-secret-change-me-32chars";
const SECRET = (env as any).AUTH_SIGNING_SECRET as string;

const bootstrap = seedOwnerFixture;

async function standardToken(orgId: string): Promise<string> {
  const org = (env as any).ORG_DO.getByName(orgId);
  const u = await org.createUser({ orgId, email: `std-${crypto.randomUUID()}@${orgId}.test`, displayName: "Std", role: "standard" });
  return mintToken(SECRET, { sub: u.id, type: "session", orgId, scopes: ALL_SCOPES, ttlSeconds: 900 });
}

function dirStub() {
  return (env as any).DIRECTORY_DO.get((env as any).DIRECTORY_DO.idFromName("global"));
}
async function clearAuthConfig() {
  await dirStub().deleteAuthConfig();
}

// FINDING B: the auth-config singleton is deployment-wide, so the gateway now only lets the
// DESIGNATED PRIMARY org (AUTH_CONFIG_ADMIN_ORG, falling back to OIDC_ORG_ID) manage it. The test
// env sets OIDC_ORG_ID="org1" (wrangler.jsonc), so the primary org IS "org1" here — use it so the
// legitimate owner-CRUD path matches. A second, non-primary org's owner is refused (see the
// dedicated Finding-B block below). Storage is isolated per test FILE so reusing "org1" is safe.
const ORG = "org1";
let ownerAuth: Record<string, string>;
let stdAuth: Record<string, string>;
const BASE = `https://gw.local/v1/orgs/${ORG}`;
const CLERK_ISSUER = "https://clerk.acme.test";
const CLIENT_SECRET = "sk_test_SUPERSECRET_clerk_value";

// B11: an oidc/both PUT now runs issuer discovery first (rejects an unreachable IdP so a
// typo can't lock out the deployment). The integration tests use an unreachable test issuer,
// so stub global fetch to SERVE that issuer's discovery doc; everything else calls through.
const realFetch = globalThis.fetch;
function installDiscoveryStub() {
  globalThis.fetch = (async (input: any, init?: any) => {
    const u = typeof input === "string" ? input : (input?.url ?? "");
    if (typeof u === "string" && u.endsWith("/.well-known/openid-configuration")) {
      return new Response(JSON.stringify({
        issuer: CLERK_ISSUER,
        authorization_endpoint: `${CLERK_ISSUER}/oauth/authorize`,
        token_endpoint: `${CLERK_ISSUER}/oauth/token`,
        jwks_uri: `${CLERK_ISSUER}/.well-known/jwks.json`,
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return realFetch(input, init);
  }) as typeof fetch;
}

beforeAll(async () => {
  installDiscoveryStub();
  const boot = await bootstrap(ORG);
  ownerAuth = { Authorization: `Bearer ${boot.token}`, "content-type": "application/json" };
  stdAuth = { Authorization: `Bearer ${await standardToken(ORG)}`, "content-type": "application/json" };
});
afterAll(() => { globalThis.fetch = realFetch; });

describe("auth-config CRUD (end-to-end, real DirectoryDO)", () => {
  afterEach(clearAuthConfig);

  it("GET null → PUT clerk → GET safe shape → DELETE; secret never leaks across DO reads", async () => {
    const init = await SELF.fetch(`${BASE}/auth-config`, { headers: ownerAuth });
    expect(init.status).toBe(200);
    expect(await init.json()).toEqual({ config: null });

    const put = await SELF.fetch(`${BASE}/auth-config`, {
      method: "PUT", headers: ownerAuth,
      body: JSON.stringify({ mode: "oidc", oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "cid-int", clientSecret: CLIENT_SECRET, allowedDomains: ["acme.test"], autoProvision: true } }),
    });
    expect(put.status).toBe(200);
    expect(await put.clone().text()).not.toContain(CLIENT_SECRET);
    expect(await put.json()).toEqual({
      mode: "oidc",
      oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "cid-int", allowedDomains: ["acme.test"], autoProvision: true, configured: true },
    });

    // fresh DO read — still safe
    const got = await SELF.fetch(`${BASE}/auth-config`, { headers: ownerAuth });
    expect(await got.clone().text()).not.toContain(CLIENT_SECRET);
    expect((await got.json() as any).config.oidc.clientId).toBe("cid-int");

    const del = await SELF.fetch(`${BASE}/auth-config`, { method: "DELETE", headers: ownerAuth });
    expect(del.status).toBe(204);
    const after = await SELF.fetch(`${BASE}/auth-config`, { headers: ownerAuth });
    expect(await after.json()).toEqual({ config: null });
  });

  it("a standard (non-admin) member is 403 on GET / PUT / DELETE / validate", async () => {
    expect((await SELF.fetch(`${BASE}/auth-config`, { headers: stdAuth })).status).toBe(403);
    expect((await SELF.fetch(`${BASE}/auth-config`, { method: "PUT", headers: stdAuth, body: JSON.stringify({ mode: "builtin" }) })).status).toBe(403);
    expect((await SELF.fetch(`${BASE}/auth-config`, { method: "DELETE", headers: stdAuth })).status).toBe(403);
    expect((await SELF.fetch(`${BASE}/auth-config/validate`, { method: "POST", headers: stdAuth, body: JSON.stringify({ issuer: CLERK_ISSUER }) })).status).toBe(403);
  });

  it("PUT with a bad provider/preset → 400", async () => {
    const bad = await SELF.fetch(`${BASE}/auth-config`, {
      method: "PUT", headers: ownerAuth,
      body: JSON.stringify({ mode: "oidc", oidc: { preset: "ldap", issuer: CLERK_ISSUER, clientId: "c", clientSecret: "s" } }),
    });
    expect(bad.status).toBe(400);
  });
});

describe("public auth-config endpoint (UNAUTHENTICATED)", () => {
  afterEach(clearAuthConfig);

  it("reflects the deploy env default with no runtime row (no auth header)", async () => {
    const res = await SELF.fetch("https://gw.local/v1/auth/config/public");
    expect(res.status).toBe(200);
    // wrangler.jsonc has OIDC_* set → env implies SSO available ('both').
    const body = (await res.json()) as { mode: string; oidcEnabled: boolean; providerLabel?: string };
    expect(body.oidcEnabled).toBe(true);
    expect(body.mode).toBe("both");
  });

  it("ONBOARDING.md build step 6: carries appDownloadUrl when APP_DOWNLOAD_URL is set, omits it otherwise", async () => {
    const before = await SELF.fetch("https://gw.local/v1/auth/config/public");
    expect((await before.json()) as { appDownloadUrl?: string }).not.toHaveProperty("appDownloadUrl");

    (env as any).APP_DOWNLOAD_URL = "https://cdn.example.com/cloud-fs/CloudFS-latest.dmg";
    try {
      const res = await SELF.fetch("https://gw.local/v1/auth/config/public");
      const body = (await res.json()) as { appDownloadUrl?: string };
      expect(body.appDownloadUrl).toBe("https://cdn.example.com/cloud-fs/CloudFS-latest.dmg");
    } finally {
      (env as any).APP_DOWNLOAD_URL = undefined;
    }
  });

  it("keeps the native gateway separate from the browser portal on split origins", async () => {
    const previous = { PUBLIC_BASE_URL: (env as any).PUBLIC_BASE_URL, WEB_BASE_URL: (env as any).WEB_BASE_URL };
    Object.assign(env, { PUBLIC_BASE_URL: "https://api.team.test/", WEB_BASE_URL: "https://console.team.test/" });
    try {
      const response = await SELF.fetch("https://request.team.test/v1/auth/config/public");
      expect(await response.json()).toMatchObject({ gatewayBaseUrl: "https://api.team.test", webBaseUrl: "https://console.team.test" });
    } finally { Object.assign(env, previous); }
  });

  it("reflects a saved runtime oidc config: { mode:'oidc', oidcEnabled:true, providerLabel }", async () => {
    await SELF.fetch(`${BASE}/auth-config`, {
      method: "PUT", headers: ownerAuth,
      body: JSON.stringify({ mode: "oidc", oidc: { preset: "okta", issuer: "https://acme.okta.com", clientId: "c", clientSecret: CLIENT_SECRET } }),
    });
    const res = await SELF.fetch("https://gw.local/v1/auth/config/public");
    const text = await res.clone().text();
    expect(text).not.toContain(CLIENT_SECRET);
    // Auth-spec §2.8: the payload also carries webBaseUrl + productName (Mac-app probe fields).
    expect(await res.json()).toEqual({
      mode: "oidc",
      oidcEnabled: true,
      providerLabel: "Okta",
      webBaseUrl: "http://localhost:5173",
      gatewayBaseUrl: (env as any).PUBLIC_BASE_URL.replace(/\/+$/, ""),
      productName: "CloudFS",
      passkeysEnabled: false,
      signupMode: "closed",
    });
  });
});

describe("password login/signup refused when mode='oidc' (auth_mode_oidc)", () => {
  afterEach(clearAuthConfig);

  async function setOidcOnly() {
    const res = await SELF.fetch(`${BASE}/auth-config`, {
      method: "PUT", headers: ownerAuth,
      body: JSON.stringify({ mode: "oidc", oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "c", clientSecret: CLIENT_SECRET } }),
    });
    expect(res.status).toBe(200);
  }

  it("POST /v1/auth/login → 403 auth_mode_oidc when built-in is disabled", async () => {
    await setOidcOnly();
    const res = await SELF.fetch("https://gw.local/v1/auth/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "x@acme.test", password: "whatever-Long-Enough-123" }),
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "auth_mode_oidc" });
  });

  it("POST /v1/auth/signup → 403 auth_mode_oidc; POST /v1/auth/password/forgot → 403", async () => {
    await setOidcOnly();
    const signup = await SELF.fetch("https://gw.local/v1/auth/signup", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "y@acme.test", password: "whatever-Long-Enough-123", orgName: "Y", displayName: "Y" }),
    });
    expect(signup.status).toBe(403);
    expect((await signup.json() as any).error).toBe("auth_mode_oidc");

    const forgot = await SELF.fetch("https://gw.local/v1/auth/password/forgot", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "y@acme.test" }),
    });
    expect(forgot.status).toBe(403);
  });

  it("mode='both' still allows password login attempts (no auth_mode_oidc gate)", async () => {
    await SELF.fetch(`${BASE}/auth-config`, {
      method: "PUT", headers: ownerAuth,
      body: JSON.stringify({ mode: "both", oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "c", clientSecret: CLIENT_SECRET } }),
    });
    const res = await SELF.fetch("https://gw.local/v1/auth/login", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "nobody@acme.test", password: "whatever-Long-Enough-123" }),
    });
    // NOT the oidc gate — the login lane runs and returns invalid_credentials for an unknown user.
    expect(res.status).not.toBe(403);
    expect((await res.json() as any).error).not.toBe("auth_mode_oidc");
  });
});

// ---- bootstrap-via-OIDC: first login of an empty org provisions the OWNER -------------
// Driven through the REAL handleOidcWebCallback + prepareOidcCallback with a mocked IdP fetch.

const enc = new TextEncoder();
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlJson(o: unknown): string {
  return b64url(enc.encode(JSON.stringify(o)));
}

describe("bootstrap-via-OIDC — first login of an empty org → owner", () => {
  let keyPair: CryptoKeyPair;
  let jwk: JsonWebKey;
  const KID = "bootstrap-key";
  const ISSUER = "https://idp.bootstrap.test";
  const CLIENT_ID = "bootstrap-client";

  beforeAll(async () => {
    const algo = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
    keyPair = (await crypto.subtle.generateKey(algo, true, ["sign", "verify"])) as CryptoKeyPair;
    jwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as JsonWebKey;
  });

  async function makeIdToken(claims: Partial<IdTokenClaims>): Promise<string> {
    const nowSec = Math.floor(Date.now() / 1000);
    const full: IdTokenClaims = {
      iss: ISSUER, aud: CLIENT_ID, sub: "boot-sub", exp: nowSec + 300, iat: nowSec,
      email: "founder@nodomain.test", email_verified: true, name: "Founder", ...claims,
    };
    const signingInput = `${b64urlJson({ alg: "RS256", kid: KID, typ: "JWT" })}.${b64urlJson(full)}`;
    const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keyPair.privateKey, enc.encode(signingInput));
    return `${signingInput}.${b64url(new Uint8Array(sig))}`;
  }

  function mockFetch(idToken: string): FetchLike {
    return async (input: string) => {
      if (input.includes("jwks")) {
        return new Response(JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "RS256", use: "sig" }] }), { status: 200 });
      }
      if (input.includes("/token")) {
        return new Response(JSON.stringify({ id_token: idToken, token_type: "Bearer", expires_in: 3600 }), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    };
  }

  function configFor(orgId: string): OidcConfig {
    return {
      issuer: ISSUER,
      authorizationEndpoint: `${ISSUER}/authorize`,
      tokenEndpoint: `${ISSUER}/token`,
      jwksUri: `${ISSUER}/jwks`,
      clientId: CLIENT_ID,
      clientSecret: "client-secret",
      redirectUri: "https://gw.local/v1/auth/oidc/callback",
      orgId,
      // FINDING 4+12: first-login owner bootstrap is now gated by an EXPLICIT allow-list. The
      // bootstrap email's domain must be allow-listed (or OIDC_BOOTSTRAP_EMAIL set), else the owner
      // mint is REFUSED. autoProvision stays OFF so a SECOND/normal user is still rejected — only the
      // empty-org bootstrap path provisions the owner, and only for an allow-listed identity.
      allowedDomains: ["nodomain.test"],
      autoProvision: false,
    };
  }

  it("the first OIDC login of an empty org provisions an OWNER (despite autoProvision off)", async () => {
    const orgId = `boot-${crypto.randomUUID()}`;
    const founderEmail = `founder-${Date.now()}@nodomain.test`;

    // Empty org → prepareOidcCallback selects the bootstrap directory.
    const orgStub = (env as any).ORG_DO.getByName(orgId);
    expect(await orgStub.countUsers()).toBe(0);

    const config = configFor(orgId);
    const prepared = await prepareOidcCallback(env as any, config);

    const start = await handleOidcStart(config, { AUTH_SIGNING_SECRET: SECRET });
    const cookie = start.response.headers.get("set-cookie")!.split(";")[0];
    const idToken = await makeIdToken({ nonce: start.nonce, email: founderEmail });
    const cbReq = new Request(`${config.redirectUri}?code=c&state=${encodeURIComponent(start.state)}`, { headers: { cookie } });

    const res = await handleOidcWebCallback(cbReq, env as any, { config: prepared.config, env: env as any, dir: prepared.dir, fetchImpl: mockFetch(idToken) });
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("Location")!).searchParams.get("error")).toBeNull();

    // The org now has exactly one member — and they are the OWNER.
    expect(await orgStub.countUsers()).toBe(1);
    const owner = await orgStub.getUserByEmail(founderEmail.toLowerCase());
    expect(owner).not.toBeNull();
    expect(owner.role).toBe("owner");

    // The minted session is real + carries owner-level scopes (fs:admin).
    const sc = res.headers.get("set-cookie") ?? "";
    const m = /cfs_session=([^;]+)/.exec(sc);
    expect(m).not.toBeNull();
    const bareSessionId = m![1].slice(orgId.length + 1);
    const stores = authStoresFor(env as any, orgId);
    const bareReq = new Request("https://gw.local/x", { headers: { cookie: `cfs_session=${bareSessionId}` } });
    const verified = await verifySession(bareReq, stores.sessions, { AUTH_SIGNING_SECRET: SECRET });
    expect(verified.session.orgId).toBe(orgId);
    expect(verified.session.scopes).toContain("fs:admin");
  });

  it("a SECOND user (org no longer empty) is gated by allowedDomains/autoProvision (rejected here)", async () => {
    const orgId = `boot2-${crypto.randomUUID()}`;
    const orgStub = (env as any).ORG_DO.getByName(orgId);

    // Bootstrap the owner first.
    const config = configFor(orgId);
    {
      const prepared = await prepareOidcCallback(env as any, config);
      const start = await handleOidcStart(config, { AUTH_SIGNING_SECRET: SECRET });
      const cookie = start.response.headers.get("set-cookie")!.split(";")[0];
      const idToken = await makeIdToken({ nonce: start.nonce, email: `owner-${Date.now()}@nodomain.test` });
      const cbReq = new Request(`${config.redirectUri}?code=c&state=${encodeURIComponent(start.state)}`, { headers: { cookie } });
      const res = await handleOidcWebCallback(cbReq, env as any, { config: prepared.config, env: env as any, dir: prepared.dir, fetchImpl: mockFetch(idToken) });
      expect(res.status).toBe(302);
      expect(new URL(res.headers.get("Location")!).searchParams.get("error")).toBeNull();
    }
    expect(await orgStub.countUsers()).toBe(1);

    // Now a DIFFERENT identity (org is non-empty) with autoProvision off + empty allow-list →
    // prepareOidcCallback returns the NORMAL directory, and mapIdentityToPrincipal REJECTS the
    // provision → the web callback 302s with ?error=provision_denied (no second member created).
    const prepared2 = await prepareOidcCallback(env as any, config);
    const start2 = await handleOidcStart(config, { AUTH_SIGNING_SECRET: SECRET });
    const cookie2 = start2.response.headers.get("set-cookie")!.split(";")[0];
    const idToken2 = await makeIdToken({ nonce: start2.nonce, email: `intruder-${Date.now()}@nodomain.test` });
    const cbReq2 = new Request(`${config.redirectUri}?code=c&state=${encodeURIComponent(start2.state)}`, { headers: { cookie: cookie2 } });
    const res2 = await handleOidcWebCallback(cbReq2, env as any, { config: prepared2.config, env: env as any, dir: prepared2.dir, fetchImpl: mockFetch(idToken2) });
    expect(res2.status).toBe(302);
    expect(new URL(res2.headers.get("Location")!).searchParams.get("error")).toBe("provision_denied");
    expect(await orgStub.countUsers()).toBe(1); // still just the owner
  });

  it("FINDING 4+12: bootstrap OWNER is REFUSED for an email NOT on the allow-list (fail closed)", async () => {
    const orgId = `boot3-${crypto.randomUUID()}`;
    const orgStub = (env as any).ORG_DO.getByName(orgId);
    expect(await orgStub.countUsers()).toBe(0);

    // Config allow-lists ONLY nodomain.test; the first verified SSO identity is from a DIFFERENT
    // domain (gmail.com) with no OIDC_BOOTSTRAP_EMAIL → owner bootstrap must be REFUSED, NOT minted.
    const config = configFor(orgId); // allowedDomains: ["nodomain.test"]
    const prepared = await prepareOidcCallback(env as any, config);
    const start = await handleOidcStart(config, { AUTH_SIGNING_SECRET: SECRET });
    const cookie = start.response.headers.get("set-cookie")!.split(";")[0];
    const idToken = await makeIdToken({ nonce: start.nonce, email: `randomer-${Date.now()}@gmail.com` });
    const cbReq = new Request(`${config.redirectUri}?code=c&state=${encodeURIComponent(start.state)}`, { headers: { cookie } });

    const res = await handleOidcWebCallback(cbReq, env as any, { config: prepared.config, env: env as any, dir: prepared.dir, fetchImpl: mockFetch(idToken) });
    // The web callback 302s with the bootstrap_denied error; no owner is created.
    expect(res.status).toBe(302);
    expect(new URL(res.headers.get("Location")!).searchParams.get("error")).toBe("bootstrap_denied");
    expect(await orgStub.countUsers()).toBe(0);
    // No session cookie was minted.
    expect(/cfs_session=/.test(res.headers.get("set-cookie") ?? "")).toBe(false);
  });
});

// ---- FINDING B: cross-tenant confused deputy on the DEPLOYMENT-WIDE auth-config singleton ----
// The PRIMARY org (OIDC_ORG_ID="org1" in the test env) may manage the global auth-config. A SECOND,
// attacker-created org — even with its own OWNER — must NOT be able to read or rewrite it, or it
// could hijack SSO for the whole deployment (swap the OIDC issuer/clientId/secret + allowedDomains).
describe("FINDING B: only the designated primary org can manage the global auth-config", () => {
  afterEach(clearAuthConfig);

  const ATTACKER_ORG = "attacker-org";
  let attackerOwner: Record<string, string>;
  beforeAll(async () => {
    // Self-signed-up attacker who is a genuine OWNER of THEIR OWN throwaway org.
    const boot = await bootstrap(ATTACKER_ORG);
    attackerOwner = { Authorization: `Bearer ${boot.token}`, "content-type": "application/json" };
  });

  const attackerBase = `https://gw.local/v1/orgs/${ATTACKER_ORG}`;
  const evil = {
    mode: "oidc",
    oidc: { preset: "okta", issuer: "https://attacker.okta.test", clientId: "evil-cid", clientSecret: "evil-secret", allowedDomains: ["attacker.test"], autoProvision: true },
  };

  it("a SECOND org's OWNER is 403 on PUT/GET/DELETE/validate (not the primary org)", async () => {
    // Even though the attacker is a real owner of attacker-org, the org in the PATH is NOT the
    // designated primary org → the gateway refuses BEFORE the handler's role gate runs.
    const put = await SELF.fetch(`${attackerBase}/auth-config`, { method: "PUT", headers: attackerOwner, body: JSON.stringify(evil) });
    expect(put.status).toBe(403);

    expect((await SELF.fetch(`${attackerBase}/auth-config`, { headers: attackerOwner })).status).toBe(403);
    expect((await SELF.fetch(`${attackerBase}/auth-config`, { method: "DELETE", headers: attackerOwner })).status).toBe(403);
    expect((await SELF.fetch(`${attackerBase}/auth-config/validate`, { method: "POST", headers: attackerOwner, body: JSON.stringify({ issuer: "https://attacker.okta.test" }) })).status).toBe(403);

    // And the global singleton was NOT mutated by the rejected PUT.
    expect(await dirStub().getAuthConfig()).toBeNull();
  });

  it("the attacker cannot overwrite a config the PRIMARY org legitimately set (SSO-hijack blocked)", async () => {
    // Primary org (org1) sets the real provider.
    const put = await SELF.fetch(`${BASE}/auth-config`, {
      method: "PUT", headers: ownerAuth,
      body: JSON.stringify({ mode: "oidc", oidc: { preset: "clerk", issuer: CLERK_ISSUER, clientId: "real-cid", clientSecret: CLIENT_SECRET } }),
    });
    expect(put.status).toBe(200);

    // Attacker tries to swap it for their IdP — refused; the stored row is unchanged.
    const hijack = await SELF.fetch(`${attackerBase}/auth-config`, { method: "PUT", headers: attackerOwner, body: JSON.stringify(evil) });
    expect(hijack.status).toBe(403);

    const row = await dirStub().getAuthConfig();
    expect(row).not.toBeNull();
    expect(row!.issuer).toBe(CLERK_ISSUER);
    expect(row!.clientId).toBe("real-cid");
  });
});
