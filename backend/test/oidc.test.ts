// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect, beforeAll } from "vitest";
import {
  handleOidcStart,
  handleOidcCallback,
  validateIdToken,
  mapIdentityToPrincipal,
  scopesForRole,
  pkceChallengeS256,
  sealLoginState,
  openLoginState,
  discover,
  OidcError,
  type OidcConfig,
  type UserDirectory,
  type DirectoryUser,
  type IdTokenClaims,
  type FetchLike,
} from "../src/security/oidc";
import { verifyToken } from "../src/security/auth";

const SECRET = "test-oidc-signing-secret-32-chars-min!";
const ISSUER = "https://idp.example.com";
const CLIENT_ID = "cfs-client-123";

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
let altKeyPair: CryptoKeyPair; // a DIFFERENT key, to forge a bad-signature token
let jwk: JsonWebKey;
const KID = "test-key-1";

beforeAll(async () => {
  const algo = { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" };
  keyPair = (await crypto.subtle.generateKey(algo, true, ["sign", "verify"])) as CryptoKeyPair;
  altKeyPair = (await crypto.subtle.generateKey(algo, true, ["sign", "verify"])) as CryptoKeyPair;
  jwk = (await crypto.subtle.exportKey("jwk", keyPair.publicKey)) as JsonWebKey;
});

/// Build + RS256-sign an id_token. `signWith` lets us forge a bad signature.
async function makeIdToken(
  claims: Partial<IdTokenClaims>,
  opts: { alg?: string; kid?: string; signWith?: CryptoKey } = {},
): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const full: IdTokenClaims = {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: "idp-sub-001",
    exp: nowSec + 300,
    iat: nowSec,
    email: "editor@acmepost.com",
    email_verified: true,
    name: "Eddie Editor",
    ...claims,
  };
  const header = { alg: opts.alg ?? "RS256", kid: opts.kid ?? KID, typ: "JWT" };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(full)}`;
  const sigKey = opts.signWith ?? keyPair.privateKey;
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", sigKey, enc.encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

/// A mock fetch that serves JWKS + token endpoint. `tokenIdToken` is what the exchange returns.
function mockFetch(opts: { idToken?: string; tokenStatus?: number; jwksKeys?: JsonWebKey[] } = {}): FetchLike {
  return async (input: string) => {
    if (input.includes("jwks")) {
      const keys = (opts.jwksKeys ?? [{ ...jwk, kid: KID, alg: "RS256", use: "sig" }]);
      return new Response(JSON.stringify({ keys }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (input.includes("/token")) {
      if (opts.tokenStatus && opts.tokenStatus >= 400) {
        return new Response(JSON.stringify({ error: "invalid_grant" }), { status: opts.tokenStatus });
      }
      return new Response(JSON.stringify({ id_token: opts.idToken, token_type: "Bearer", expires_in: 3600 }), {
        status: 200, headers: { "content-type": "application/json" },
      });
    }
    if (input.includes(".well-known")) {
      return new Response(JSON.stringify({
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        jwks_uri: `${ISSUER}/jwks`,
      }), { status: 200 });
    }
    return new Response("not found", { status: 404 });
  };
}

function baseConfig(over: Partial<OidcConfig> = {}): OidcConfig {
  return {
    issuer: ISSUER,
    authorizationEndpoint: `${ISSUER}/authorize`,
    tokenEndpoint: `${ISSUER}/token`,
    jwksUri: `${ISSUER}/jwks`,
    clientId: CLIENT_ID,
    clientSecret: "client-secret-xyz",
    redirectUri: "https://gw.cloudfs.local/v1/auth/oidc/callback",
    orgId: "acmepost",
    allowedDomains: ["acmepost.com"],
    autoProvision: true,
    ...over,
  };
}

// ---- in-memory user directory (consumes the multiuser API shape) ---------------------

class FakeDirectory implements UserDirectory {
  users: DirectoryUser[] = [];
  async getUserByEmail(email: string) {
    return this.users.find((u) => u.email === email.toLowerCase()) ?? null;
  }
  async createUser(input: { orgId: string; email: string; displayName: string; role?: any; idpSubject?: string | null }) {
    const u: DirectoryUser = {
      id: `usr-${this.users.length + 1}`,
      orgId: input.orgId,
      email: input.email.toLowerCase(),
      displayName: input.displayName,
      role: input.role ?? "standard",
      status: "active",
      idpSubject: input.idpSubject ?? null,
    };
    this.users.push(u);
    return u;
  }
  async groupsForUser() { return []; }
}

// =====================================================================================

describe("PKCE / state / nonce generation (start)", () => {
  it("S256 challenge = base64url(sha256(verifier))", async () => {
    // Known RFC 7636 Appendix B test vector.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = await pkceChallengeS256(verifier);
    expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("builds an authorize URL with state, nonce, PKCE S256, and a sealed cookie", async () => {
    const r = await handleOidcStart(baseConfig(), { AUTH_SIGNING_SECRET: SECRET });
    const u = new URL(r.authorizeUrl);
    expect(u.searchParams.get("response_type")).toBe("code");
    expect(u.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(u.searchParams.get("code_challenge_method")).toBe("S256");
    expect(u.searchParams.get("code_challenge")).toBeTruthy();
    expect(u.searchParams.get("state")).toBe(r.state);
    expect(u.searchParams.get("nonce")).toBe(r.nonce);
    expect(r.response.status).toBe(302);
    const setCookie = r.response.headers.get("set-cookie")!;
    expect(setCookie).toMatch(/cfs_oidc=/);
    expect(setCookie).toMatch(/HttpOnly/);
    expect(setCookie).toMatch(/Secure/);
    expect(setCookie).toMatch(/SameSite=Lax/);
  });

  it("state/nonce/verifier differ across requests (CSPRNG)", async () => {
    const a = await handleOidcStart(baseConfig(), { AUTH_SIGNING_SECRET: SECRET });
    const b = await handleOidcStart(baseConfig(), { AUTH_SIGNING_SECRET: SECRET });
    expect(a.state).not.toBe(b.state);
    expect(a.nonce).not.toBe(b.nonce);
  });
});

describe("login-state cookie (signed, stateless)", () => {
  it("seals and re-opens an intact state", async () => {
    const st = { state: "s", nonce: "n", verifier: "v", exp: Math.floor(Date.now() / 1000) + 60 };
    const sealed = await sealLoginState(SECRET, st);
    const opened = await openLoginState(SECRET, sealed, Date.now());
    expect(opened).toEqual(st);
  });

  it("rejects a tampered cookie", async () => {
    const sealed = await sealLoginState(SECRET, { state: "s", nonce: "n", verifier: "v", exp: Math.floor(Date.now() / 1000) + 60 });
    const [payload] = sealed.split(".");
    await expect(openLoginState(SECRET, `${payload}.AAAA`, Date.now())).rejects.toMatchObject({ code: "bad_state_cookie" });
  });

  it("rejects an expired cookie", async () => {
    const sealed = await sealLoginState(SECRET, { state: "s", nonce: "n", verifier: "v", exp: 1000 });
    await expect(openLoginState(SECRET, sealed, 2_000_000)).rejects.toMatchObject({ code: "state_expired" });
  });
});

describe("id_token validation matrix", () => {
  const cfg = { issuer: ISSUER, jwksUri: `${ISSUER}/jwks`, clientId: CLIENT_ID };

  it("accepts a valid id_token", async () => {
    const tok = await makeIdToken({ nonce: "the-nonce" });
    const claims = await validateIdToken(tok, cfg, "the-nonce", mockFetch(), Date.now());
    expect(claims.sub).toBe("idp-sub-001");
    expect(claims.email).toBe("editor@acmepost.com");
  });

  it("rejects an expired id_token", async () => {
    const past = Math.floor(Date.now() / 1000) - 10_000;
    const tok = await makeIdToken({ nonce: "n", exp: past, iat: past - 60 });
    await expect(validateIdToken(tok, cfg, "n", mockFetch(), Date.now())).rejects.toMatchObject({ code: "expired" });
  });

  it("rejects a bad signature (signed with a different key)", async () => {
    const tok = await makeIdToken({ nonce: "n" }, { signWith: altKeyPair.privateKey });
    await expect(validateIdToken(tok, cfg, "n", mockFetch(), Date.now())).rejects.toMatchObject({ code: "bad_signature" });
  });

  it("rejects a wrong audience", async () => {
    const tok = await makeIdToken({ nonce: "n", aud: "some-other-client" });
    await expect(validateIdToken(tok, cfg, "n", mockFetch(), Date.now())).rejects.toMatchObject({ code: "bad_aud" });
  });

  it("rejects a wrong issuer", async () => {
    const tok = await makeIdToken({ nonce: "n", iss: "https://evil.example.com" });
    await expect(validateIdToken(tok, cfg, "n", mockFetch(), Date.now())).rejects.toMatchObject({ code: "bad_iss" });
  });

  it("rejects a nonce mismatch (replay defense)", async () => {
    const tok = await makeIdToken({ nonce: "WRONG" });
    await expect(validateIdToken(tok, cfg, "the-nonce", mockFetch(), Date.now())).rejects.toMatchObject({ code: "bad_nonce" });
  });

  it("rejects alg:none / algorithm confusion", async () => {
    const header = b64urlJson({ alg: "none", typ: "JWT" });
    const payload = b64urlJson({ iss: ISSUER, aud: CLIENT_ID, sub: "x", exp: 9_999_999_999, iat: 1, nonce: "n" });
    await expect(validateIdToken(`${header}.${payload}.`, cfg, "n", mockFetch(), Date.now())).rejects.toMatchObject({ code: "bad_alg" });
  });

  it("rejects when no JWKS key matches the kid", async () => {
    const tok = await makeIdToken({ nonce: "n" }, { kid: "unknown-kid" });
    await expect(validateIdToken(tok, cfg, "n", mockFetch(), Date.now())).rejects.toMatchObject({ code: "kid_mismatch" });
  });
});

describe("identity -> principal mapping", () => {
  it("provisions a new user whose domain is allowed", async () => {
    const dir = new FakeDirectory();
    const claims = { iss: ISSUER, aud: CLIENT_ID, sub: "s", exp: 1, iat: 1, email: "new@acmepost.com", email_verified: true, name: "New Person" } as IdTokenClaims;
    const mapped = await mapIdentityToPrincipal(claims, baseConfig(), dir);
    expect(mapped.provisioned).toBe(true);
    expect(mapped.user.role).toBe("standard");
    expect(mapped.user.idpSubject).toBe("s");
    expect(mapped.scopes).toEqual(scopesForRole("standard"));
  });

  it("reuses an existing active user and applies their role scopes", async () => {
    const dir = new FakeDirectory();
    await dir.createUser({ orgId: "acmepost", email: "boss@acmepost.com", displayName: "Boss", role: "admin" });
    const claims = { email: "boss@acmepost.com", email_verified: true, sub: "s2" } as IdTokenClaims;
    const mapped = await mapIdentityToPrincipal(claims, baseConfig(), dir);
    expect(mapped.provisioned).toBe(false);
    expect(mapped.user.role).toBe("admin");
    expect(mapped.scopes).toContain("fs:admin");
  });

  it("rejects a disallowed domain (no auto-provision)", async () => {
    const dir = new FakeDirectory();
    const claims = { email: "freelancer@example.com", email_verified: true, sub: "s3" } as IdTokenClaims;
    await expect(mapIdentityToPrincipal(claims, baseConfig(), dir)).rejects.toMatchObject({ code: "provision_denied" });
  });

  it("rejects an allowed domain when autoProvision is off and user does not exist", async () => {
    const dir = new FakeDirectory();
    const claims = { email: "ghost@acmepost.com", email_verified: true, sub: "s4" } as IdTokenClaims;
    await expect(mapIdentityToPrincipal(claims, baseConfig({ autoProvision: false }), dir)).rejects.toMatchObject({ code: "provision_denied" });
  });

  it("rejects a suspended/deprovisioned user", async () => {
    const dir = new FakeDirectory();
    const u = await dir.createUser({ orgId: "acmepost", email: "gone@acmepost.com", displayName: "Gone", role: "standard" });
    u.status = "deprovisioned";
    const claims = { email: "gone@acmepost.com", email_verified: true, sub: "s5" } as IdTokenClaims;
    await expect(mapIdentityToPrincipal(claims, baseConfig(), dir)).rejects.toMatchObject({ code: "user_inactive" });
  });

  it("rejects an unverified email", async () => {
    const dir = new FakeDirectory();
    const claims = { email: "spoof@acmepost.com", email_verified: false, sub: "s6" } as IdTokenClaims;
    await expect(mapIdentityToPrincipal(claims, baseConfig(), dir)).rejects.toMatchObject({ code: "email_unverified" });
  });
});

describe("scopesForRole", () => {
  it("owner/admin get all scopes incl. audit:read", () => {
    expect(scopesForRole("owner")).toContain("audit:read");
    expect(scopesForRole("admin")).toContain("fs:admin");
  });
  it("standard users get data scopes but not fs:admin/audit:read", () => {
    const s = scopesForRole("standard");
    expect(s).toContain("fs:read");
    expect(s).not.toContain("fs:admin");
    expect(s).not.toContain("audit:read");
  });
});

describe("full callback -> session token (end to end, mocked IdP)", () => {
  async function startThenCallback(over: Partial<OidcConfig> = {}, claimsOver: Partial<IdTokenClaims> = {}) {
    const config = baseConfig(over);
    const env = { AUTH_SIGNING_SECRET: SECRET };
    const dir = new FakeDirectory();

    // 1. start -> capture state/nonce + the sealed cookie
    const start = await handleOidcStart(config, env);
    const cookie = start.response.headers.get("set-cookie")!.split(";")[0]; // cfs_oidc=...

    // 2. mint an id_token bound to the issued nonce, served by the token endpoint
    const idToken = await makeIdToken({ nonce: start.nonce, ...claimsOver });
    const fetchImpl = mockFetch({ idToken });

    // 3. callback request carries ?code&state + the login cookie
    const cbReq = new Request(
      `${config.redirectUri}?code=auth-code-abc&state=${encodeURIComponent(start.state)}`,
      { headers: { cookie } },
    );
    return handleOidcCallback(cbReq, { config, env, dir, fetchImpl });
  }

  it("mints a verifiable cloud-fs session token with role scopes", async () => {
    const res = await startThenCallback();
    expect(res.provisioned).toBe(true);
    expect(res.user.email).toBe("editor@acmepost.com");

    const principal = await verifyToken(SECRET, res.token);
    expect(principal.type).toBe("session");
    expect(principal.orgId).toBe("acmepost");
    expect(principal.sub).toBe(res.user.id);
    expect(principal.scopes).toEqual(scopesForRole("standard"));

    // callback clears the one-time login cookie
    expect(res.response.headers.get("set-cookie")).toMatch(/cfs_oidc=;/);
  });

  it("rejects a callback whose state does not match the cookie (CSRF)", async () => {
    const config = baseConfig();
    const env = { AUTH_SIGNING_SECRET: SECRET };
    const start = await handleOidcStart(config, env);
    const cookie = start.response.headers.get("set-cookie")!.split(";")[0];
    const idToken = await makeIdToken({ nonce: start.nonce });
    const cbReq = new Request(`${config.redirectUri}?code=c&state=TAMPERED`, { headers: { cookie } });
    await expect(
      handleOidcCallback(cbReq, { config, env, dir: new FakeDirectory(), fetchImpl: mockFetch({ idToken }) }),
    ).rejects.toMatchObject({ code: "state_mismatch" });
  });

  it("rejects a callback with no login-state cookie", async () => {
    const config = baseConfig();
    const cbReq = new Request(`${config.redirectUri}?code=c&state=s`);
    await expect(
      handleOidcCallback(cbReq, { config, env: { AUTH_SIGNING_SECRET: SECRET }, dir: new FakeDirectory(), fetchImpl: mockFetch() }),
    ).rejects.toMatchObject({ code: "no_state_cookie" });
  });

  it("surfaces a failed token exchange", async () => {
    const config = baseConfig();
    const env = { AUTH_SIGNING_SECRET: SECRET };
    const start = await handleOidcStart(config, env);
    const cookie = start.response.headers.get("set-cookie")!.split(";")[0];
    const cbReq = new Request(`${config.redirectUri}?code=c&state=${encodeURIComponent(start.state)}`, { headers: { cookie } });
    await expect(
      handleOidcCallback(cbReq, { config, env, dir: new FakeDirectory(), fetchImpl: mockFetch({ tokenStatus: 400 }) }),
    ).rejects.toMatchObject({ code: "token_exchange_failed" });
  });

  it("propagates a provider error param", async () => {
    const config = baseConfig();
    const env = { AUTH_SIGNING_SECRET: SECRET };
    const start = await handleOidcStart(config, env);
    const cookie = start.response.headers.get("set-cookie")!.split(";")[0];
    const cbReq = new Request(`${config.redirectUri}?error=access_denied&state=${encodeURIComponent(start.state)}`, { headers: { cookie } });
    await expect(
      handleOidcCallback(cbReq, { config, env, dir: new FakeDirectory(), fetchImpl: mockFetch() }),
    ).rejects.toMatchObject({ code: "provider_error" });
  });
});

describe("discovery", () => {
  it("merges endpoints from the well-known doc", async () => {
    const d = await discover(ISSUER, mockFetch());
    expect(d.authorizationEndpoint).toBe(`${ISSUER}/authorize`);
    expect(d.tokenEndpoint).toBe(`${ISSUER}/token`);
    expect(d.jwksUri).toBe(`${ISSUER}/jwks`);
  });

  it("throws on a failed discovery fetch", async () => {
    const failing: FetchLike = async () => new Response("err", { status: 500 });
    await expect(discover(ISSUER, failing)).rejects.toBeInstanceOf(OidcError);
  });
});
