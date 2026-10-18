// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs SSO via OpenID Connect (OIDC) Authorization-Code flow + PKCE (SPEC §4.5).
///
/// WHY: today humans authenticate only via the bootstrap admin token + service-account
/// tokens (security/auth.ts). This module lets a human log in through the org's IdP
/// (Okta, Entra ID, Google, Auth0, ...) and walk away with a cloud-fs SESSION token.
///
/// FLOW (RFC 6749 code flow + RFC 7636 PKCE S256 + OIDC Core id_token validation):
///   1. handleOidcStart  — generate state + nonce + PKCE verifier; stash them in a SIGNED,
///      short-lived cookie (HMAC over the transient values, so the gateway stays STATELESS
///      — no server-side login record needed); 302 to the provider authorize endpoint.
///   2. provider authenticates the user, redirects back with ?code&state.
///   3. handleOidcCallback — re-read+verify the signed cookie, check `state` matches,
///      exchange code -> tokens at the provider token endpoint (sending the PKCE verifier),
///      validate the returned `id_token` (RS256 sig via provider JWKS + iss/aud/exp/iat/nonce),
///      extract the verified identity (sub + email).
///   4. map identity -> org principal: per-org policy (allowed email domain / pre-invited),
///      find-or-provision the user via the multiuser users model (we CALL its API, never
///      reimplement it), then mint a cloud-fs session token (auth.ts) with role->scopes.
///
/// SECURITY POSTURE (fails closed everywhere):
///   - Reject `alg:none` / non-RS256 id_tokens; verify signature BEFORE trusting claims.
///   - state defeats CSRF; nonce defeats id_token replay; PKCE defeats code interception.
///   - Disallowed email domains / non-provisionable identities are REJECTED, not provisioned.
///   - Client secret + signing secret are Worker SECRETS (see oidc-INTEGRATION.md).
///   - `fetch`, JWKS, and `now` are injectable so this is unit-testable with NO real IdP.

import {
  mintToken,
  DEFAULT_TTL_SECONDS,
  type Scope,
  type Principal as AuthPrincipal,
} from "./auth";

// Re-use the multiuser role vocabulary without importing its DO (keep this module
// portable + unit-testable). Structurally identical to permissions.ts `OrgRole`.
export type OrgRole = "owner" | "admin" | "space_admin" | "standard";

// ---- errors ---------------------------------------------------------------------------

/// Distinct from auth.ts AuthError so callers can tell "login flow failed" (browser-facing,
/// usually a redirect/HTML) apart from "bearer token rejected" (API 401/403).
export class OidcError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 401 | 403 | 500 | 502 = 400,
    readonly code: string = "oidc_error",
  ) {
    super(message);
    this.name = "OidcError";
  }
}

// ---- config & ports -------------------------------------------------------------------

/// Per-deployment OIDC config. Discovery doc fields can be supplied directly (so a test
/// or an offline deploy needn't hit /.well-known) or fetched once via `discover()`.
export interface OidcConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  clientId: string;
  clientSecret: string;
  /// Absolute callback URL registered with the IdP. MUST match exactly.
  redirectUri: string;
  /// OAuth scopes asked of the IdP (NOT cloud-fs Scopes). 'openid' is mandatory.
  scopes?: string[];
  /// Org this login provisions into (one IdP config per org in the simple model).
  orgId: string;
  /// Allow-list of email domains permitted to auto-provision. Empty/undefined => provisioning
  /// disabled (only pre-existing/pre-invited users may log in) — the safe default.
  allowedDomains?: string[];
  /// If true, a verified identity whose domain is allowed is auto-created. If false, the
  /// user must already exist (pre-invited) or login is rejected. Default false (fail closed).
  autoProvision?: boolean;
}

/// Env subset this module needs. The real Env (env.ts) is a superset.
export interface OidcEnv {
  /// HMAC key for both cloud-fs session tokens AND the transient login cookie. (Worker SECRET.)
  AUTH_SIGNING_SECRET: string;
}

/// The multiuser users model, consumed via its existing exports (users.ts / org-do.ts).
/// We depend on this INTERFACE, not the concrete DO, so unit tests inject a fake and prod
/// passes an adapter over OrgDO (see oidc-INTEGRATION.md). Method shapes match OrgDO RPC.
export interface UserDirectory {
  getUserByEmail(email: string): Promise<DirectoryUser | null>;
  createUser(input: {
    orgId: string;
    email: string;
    displayName: string;
    role?: OrgRole;
    idpSubject?: string | null;
  }): Promise<DirectoryUser>;
  /// Group ids for ACL group-union (optional; ok to return []).
  groupsForUser?(userId: string): Promise<string[]>;
}

export interface DirectoryUser {
  id: string;
  orgId: string;
  email: string;
  displayName: string;
  role: OrgRole;
  status: "active" | "suspended" | "deprovisioned";
  idpSubject: string | null;
}

/// Injectable fetch (defaults to global) so tests mock the token + JWKS endpoints.
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

// ---- role -> cloud-fs scopes ----------------------------------------------------------

const ALL_SCOPES: Scope[] = [
  "fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read",
];

/// Map an org role to the cloud-fs session scopes. Mirrors index.ts ALL_ADMIN_SCOPES for
/// owner/admin; standard users get day-to-day data scopes; per-folder ACLs (permissions.ts)
/// still gate the actual targets. Keep this the single source of truth for OIDC sessions.
export function scopesForRole(role: OrgRole): Scope[] {
  switch (role) {
    case "owner":
    case "admin":
      return [...ALL_SCOPES];
    case "space_admin":
      return ["fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write"];
    case "standard":
    default:
      return ["fs:read", "fs:write", "fs:lock", "snapshot:read", "snapshot:write"];
  }
}

// ---- base64url / crypto helpers (no Node Buffer; workerd globals only) ----------------

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomB64url(byteLen: number): string {
  const buf = new Uint8Array(byteLen);
  crypto.getRandomValues(buf);
  return b64urlEncode(buf);
}

async function sha256(input: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(input)));
}

/// PKCE S256 code challenge: base64url( SHA-256( verifier ) ) (RFC 7636 §4.2).
export async function pkceChallengeS256(verifier: string): Promise<string> {
  return b64urlEncode(await sha256(verifier));
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  if (!secret || secret.length < 16) {
    throw new OidcError("signing secret missing or too short (need >= 16 chars)", 500, "bad_secret");
  }
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}

function timingSafeEqStr(a: string, b: string): boolean {
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

// ---- transient login state (signed cookie; stateless gateway) -------------------------

/// The transient values carried across the redirect round-trip. Signed (HMAC), short TTL.
export interface LoginState {
  state: string;
  nonce: string;
  verifier: string; // PKCE code_verifier — secret; never sent to the browser in clear form
  exp: number;      // seconds since epoch
}

const LOGIN_COOKIE = "cfs_oidc";
/// 10 minutes is plenty for a human to authenticate at the IdP and bounce back.
const LOGIN_STATE_TTL_SECONDS = 10 * 60;

/// Serialize+sign the login state into an opaque cookie value: base64url(json).hmac.
export async function sealLoginState(secret: string, st: LoginState): Promise<string> {
  const key = await importHmacKey(secret);
  const payload = b64urlEncode(enc.encode(JSON.stringify(st)));
  const sig = b64urlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(payload))));
  return `${payload}.${sig}`;
}

/// Verify + parse a sealed login state. Throws OidcError on tamper/expiry/malformed.
export async function openLoginState(secret: string, sealed: string, now: number): Promise<LoginState> {
  const parts = sealed.split(".");
  if (parts.length !== 2) throw new OidcError("malformed login state", 400, "bad_state_cookie");
  const [payload, sig] = parts;
  const key = await importHmacKey(secret);
  const ok = await crypto.subtle.verify("HMAC", key, b64urlDecode(sig), enc.encode(payload));
  if (!ok) throw new OidcError("login state signature invalid", 400, "bad_state_cookie");
  let st: LoginState;
  try {
    st = JSON.parse(dec.decode(b64urlDecode(payload)));
  } catch {
    throw new OidcError("login state unparseable", 400, "bad_state_cookie");
  }
  if (typeof st.exp !== "number" || Math.floor(now / 1000) >= st.exp) {
    throw new OidcError("login state expired", 400, "state_expired");
  }
  return st;
}

/// FINDING #3: the hardened OIDC login-cookie name carrying the `__Host-` prefix (forces Secure +
/// Path=/ + no Domain). `__Host-` REQUIRES the Secure attribute, which a browser drops over plain
/// http — so it's only usable over HTTPS. We pick the name per-transport (`loginCookieName`): the
/// prefixed name + Secure on HTTPS, the plain `cfs_oidc` (no Secure) over http/localhost so the dev
/// stack + tests keep working. The start→callback round-trip uses the SAME transport, so the names
/// agree; `readLoginCookie` also accepts both names defensively.
const LOGIN_COOKIE_SECURE = "__Host-cfs_oidc";

function loginCookieName(secure: boolean): string {
  return secure ? LOGIN_COOKIE_SECURE : LOGIN_COOKIE;
}

/// Detect HTTPS from the request URL (mirrors auth-wiring's `secureCookies` minus the env flag,
/// which the OIDC handlers don't carry). Over http/localhost we fall back to the plain cookie name.
export function oidcCookieSecure(req: Request): boolean {
  try {
    return new URL(req.url).protocol === "https:";
  } catch {
    return false;
  }
}

function buildCookie(name: string, value: string, maxAgeSeconds: number, secure: boolean): string {
  // HttpOnly: JS can't read it (XSS-resistant). Secure: HTTPS only (omitted on http so `__Host-`/
  // Secure isn't silently dropped by the browser). SameSite=Lax: the top-level IdP redirect back to
  // us still sends the cookie, but cross-site POSTs don't.
  const secureAttr = secure ? "; Secure" : "";
  return `${name}=${value}; Max-Age=${maxAgeSeconds}; Path=/; HttpOnly${secureAttr}; SameSite=Lax`;
}

function clearCookie(name: string, secure: boolean): string {
  const secureAttr = secure ? "; Secure" : "";
  return `${name}=; Max-Age=0; Path=/; HttpOnly${secureAttr}; SameSite=Lax`;
}

function readCookie(req: Request, name: string): string | null {
  const header = req.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return null;
}

/// Read the OIDC login-state cookie regardless of which transport minted it (prefixed first).
function readLoginCookie(req: Request): string | null {
  return readCookie(req, LOGIN_COOKIE_SECURE) ?? readCookie(req, LOGIN_COOKIE);
}

// ---- discovery ------------------------------------------------------------------------

/// Fetch the OIDC discovery document and merge endpoints into a partial config. Optional —
/// callers may hard-configure the endpoints instead. Network is injected for tests.
export async function discover(
  issuer: string,
  fetchImpl: FetchLike = fetch,
): Promise<Pick<OidcConfig, "issuer" | "authorizationEndpoint" | "tokenEndpoint" | "jwksUri">> {
  const url = `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const res = await fetchImpl(url);
  if (!res.ok) throw new OidcError(`discovery failed (${res.status})`, 502, "discovery_failed");
  const d = (await res.json()) as any;
  if (!d.authorization_endpoint || !d.token_endpoint || !d.jwks_uri) {
    throw new OidcError("discovery doc missing endpoints", 502, "discovery_incomplete");
  }
  return {
    issuer: d.issuer ?? issuer,
    authorizationEndpoint: d.authorization_endpoint,
    tokenEndpoint: d.token_endpoint,
    jwksUri: d.jwks_uri,
  };
}

// ---- STEP 1: start --------------------------------------------------------------------

export interface StartResult {
  /// 302 Response with Location=authorize URL and the sealed-state Set-Cookie header.
  response: Response;
  /// Echoed for tests/inspection.
  authorizeUrl: string;
  state: string;
  nonce: string;
}

/// Build the provider authorize URL (with state, nonce, PKCE S256) and a 302 carrying the
/// sealed login-state cookie. `now`/randomness defaults are overridable for tests.
export async function handleOidcStart(
  config: OidcConfig,
  env: OidcEnv,
  opts: { now?: number; returnTo?: string; secure?: boolean } = {},
): Promise<StartResult> {
  const now = opts.now ?? Date.now();
  // FINDING #3: hardened `__Host-`-prefixed + Secure cookie over HTTPS; plain over http. Default
  // true (HTTPS) when the caller doesn't specify — the gateway passes `oidcCookieSecure(req)`.
  const secure = opts.secure ?? true;
  const state = randomB64url(32);
  const nonce = randomB64url(32);
  const verifier = randomB64url(48); // 64 base64url chars — within RFC 7636 43..128
  const challenge = await pkceChallengeS256(verifier);

  const sealed = await sealLoginState(env.AUTH_SIGNING_SECRET, {
    state, nonce, verifier, exp: Math.floor(now / 1000) + LOGIN_STATE_TTL_SECONDS,
  });

  const u = new URL(config.authorizationEndpoint);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", config.clientId);
  u.searchParams.set("redirect_uri", config.redirectUri);
  u.searchParams.set("scope", (config.scopes ?? ["openid", "email", "profile"]).join(" "));
  u.searchParams.set("state", state);
  u.searchParams.set("nonce", nonce);
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");

  const headers = new Headers({ Location: u.toString() });
  headers.append("Set-Cookie", buildCookie(loginCookieName(secure), sealed, LOGIN_STATE_TTL_SECONDS, secure));
  return {
    response: new Response(null, { status: 302, headers }),
    authorizeUrl: u.toString(),
    state,
    nonce,
  };
}

// ---- id_token validation (RS256 via JWKS) ---------------------------------------------

interface Jwk {
  kty: string;
  kid?: string;
  n?: string;
  e?: string;
  alg?: string;
  use?: string;
}

export interface IdTokenClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  exp: number;
  iat: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  [k: string]: unknown;
}

async function importRsaJwk(jwk: Jwk): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true } as JsonWebKey,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
}

/// Fetch the provider JWKS and pick the key matching the token's `kid` (RS256 only).
async function resolveSigningKey(jwksUri: string, kid: string | undefined, fetchImpl: FetchLike): Promise<CryptoKey> {
  const res = await fetchImpl(jwksUri);
  if (!res.ok) throw new OidcError(`JWKS fetch failed (${res.status})`, 502, "jwks_failed");
  const body = (await res.json()) as { keys?: Jwk[] };
  const keys = (body.keys ?? []).filter((k) => k.kty === "RSA");
  if (!keys.length) throw new OidcError("JWKS has no RSA keys", 502, "jwks_empty");
  const jwk = kid ? keys.find((k) => k.kid === kid) : keys[0];
  if (!jwk) throw new OidcError("no JWKS key matches token kid", 401, "kid_mismatch");
  return importRsaJwk(jwk);
}

/// Full OIDC id_token validation: RS256 signature (via JWKS) + iss/aud/exp/iat/nonce.
/// Throws OidcError on ANY failure (fail closed). `now` injectable.
export async function validateIdToken(
  idToken: string,
  config: Pick<OidcConfig, "issuer" | "jwksUri" | "clientId">,
  expectedNonce: string,
  fetchImpl: FetchLike,
  now: number,
): Promise<IdTokenClaims> {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new OidcError("malformed id_token", 401, "bad_id_token");
  const [h, p, s] = parts;

  let header: { alg?: string; kid?: string; typ?: string };
  try {
    header = JSON.parse(dec.decode(b64urlDecode(h)));
  } catch {
    throw new OidcError("bad id_token header", 401, "bad_id_token");
  }
  // Reject alg:none and any non-RS256 (no algorithm confusion / downgrade).
  if (header.alg !== "RS256") throw new OidcError(`unsupported id_token alg '${header.alg}'`, 401, "bad_alg");

  // Verify signature BEFORE trusting any claim bytes.
  const key = await resolveSigningKey(config.jwksUri, header.kid, fetchImpl);
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, b64urlDecode(s), enc.encode(`${h}.${p}`),
  );
  if (!ok) throw new OidcError("id_token signature invalid", 401, "bad_signature");

  let claims: IdTokenClaims;
  try {
    claims = JSON.parse(dec.decode(b64urlDecode(p)));
  } catch {
    throw new OidcError("bad id_token payload", 401, "bad_id_token");
  }

  const nowSec = Math.floor(now / 1000);
  const skew = 60; // OIDC tolerance

  if (claims.iss !== config.issuer) throw new OidcError("id_token iss mismatch", 401, "bad_iss");

  const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!auds.includes(config.clientId)) throw new OidcError("id_token aud mismatch", 401, "bad_aud");

  if (typeof claims.exp !== "number" || nowSec - skew >= claims.exp) {
    throw new OidcError("id_token expired", 401, "expired");
  }
  if (typeof claims.iat === "number" && claims.iat - skew > nowSec) {
    throw new OidcError("id_token issued in the future", 401, "bad_iat");
  }
  // nonce binds this id_token to OUR authorize request — defeats replay.
  if (!claims.nonce || !timingSafeEqStr(claims.nonce, expectedNonce)) {
    throw new OidcError("id_token nonce mismatch", 401, "bad_nonce");
  }
  if (!claims.sub) throw new OidcError("id_token missing sub", 401, "bad_id_token");

  return claims;
}

// ---- token exchange -------------------------------------------------------------------

interface TokenResponse {
  id_token?: string;
  access_token?: string;
  token_type?: string;
  expires_in?: number;
}

/// Exchange the authorization code for tokens at the provider token endpoint, sending the
/// PKCE verifier + client credentials. Returns the raw id_token (validated separately).
export async function exchangeCode(
  config: OidcConfig,
  code: string,
  verifier: string,
  fetchImpl: FetchLike,
): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code_verifier: verifier,
  });
  const res = await fetchImpl(config.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: body.toString(),
  });
  if (!res.ok) {
    let detail = "";
    try { detail = JSON.stringify(await res.json()); } catch { /* ignore */ }
    throw new OidcError(`token exchange failed (${res.status}) ${detail}`, 502, "token_exchange_failed");
  }
  const tok = (await res.json()) as TokenResponse;
  if (!tok.id_token) throw new OidcError("token response had no id_token", 502, "no_id_token");
  return tok;
}

// ---- identity -> org principal mapping ------------------------------------------------

export interface MappedPrincipal {
  user: DirectoryUser;
  scopes: Scope[];
  /// Whether this login provisioned a brand-new user.
  provisioned: boolean;
}

function emailDomain(email: string): string {
  const at = email.lastIndexOf("@");
  return at >= 0 ? email.slice(at + 1).toLowerCase() : "";
}

/// Find-or-provision the verified identity in the org directory under per-org policy, then
/// compute its cloud-fs scopes. Provisioning is gated: domain must be allow-listed AND
/// `autoProvision` enabled, else an unknown user is REJECTED (fail closed). Suspended/
/// deprovisioned users are rejected even if they exist.
export async function mapIdentityToPrincipal(
  claims: IdTokenClaims,
  config: OidcConfig,
  dir: UserDirectory,
): Promise<MappedPrincipal> {
  const email = (claims.email ?? "").trim().toLowerCase();
  if (!email) throw new OidcError("id_token has no email claim", 403, "no_email");
  // FINDING 4+12: FAIL CLOSED on email verification. Require an EXPLICIT `email_verified === true`;
  // an absent (undefined) or false claim is rejected — never treat a missing claim as verified
  // (provisioning an account off an unverified/spoofable email is an account-takeover vector).
  if (claims.email_verified !== true) {
    throw new OidcError("id_token email not verified by IdP", 403, "email_unverified");
  }

  const existing = await dir.getUserByEmail(email);
  if (existing) {
    if (existing.status !== "active") {
      throw new OidcError(`user ${email} is ${existing.status}`, 403, "user_inactive");
    }
    if (existing.orgId !== config.orgId) {
      throw new OidcError("user belongs to a different org", 403, "wrong_org");
    }
    return { user: existing, scopes: scopesForRole(existing.role), provisioned: false };
  }

  // No existing user -> provisioning path. Both gates must pass.
  const domain = emailDomain(email);
  const allowed = (config.allowedDomains ?? []).map((d) => d.toLowerCase());
  if (!config.autoProvision || allowed.length === 0 || !allowed.includes(domain)) {
    throw new OidcError(`login for ${email} not permitted (no account; provisioning denied)`, 403, "provision_denied");
  }
  const created = await dir.createUser({
    orgId: config.orgId,
    email,
    displayName: (claims.name as string) ?? email,
    role: "standard", // new SSO users start as standard; admins promote (SPEC §4.2)
    idpSubject: claims.sub,
  });
  return { user: created, scopes: scopesForRole(created.role), provisioned: true };
}

// ---- STEP 3: callback -----------------------------------------------------------------

export interface CallbackResult {
  /// The minted cloud-fs SESSION token (the thing the client uses as a bearer henceforth).
  token: string;
  user: DirectoryUser;
  scopes: Scope[];
  provisioned: boolean;
  /// A 200 JSON Response (token in body) with a Set-Cookie that CLEARS the login cookie.
  /// Callers may instead 302 to the app and deliver the token however they prefer.
  response: Response;
}

export interface CallbackDeps {
  config: OidcConfig;
  env: OidcEnv;
  dir: UserDirectory;
  fetchImpl?: FetchLike;
  now?: number;
}

/// The full callback: validate state cookie, exchange code, validate id_token, map identity,
/// mint a cloud-fs session token. Throws OidcError on any failure (caller renders/redirects).
export async function handleOidcCallback(req: Request, deps: CallbackDeps): Promise<CallbackResult> {
  const { config, env, dir } = deps;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ?? Date.now();

  const url = new URL(req.url);
  // Surface IdP-side errors (user denied consent, etc.) verbatim but safely.
  const providerError = url.searchParams.get("error");
  if (providerError) throw new OidcError(`provider returned error: ${providerError}`, 401, "provider_error");

  const code = url.searchParams.get("code");
  const returnedState = url.searchParams.get("state");
  if (!code || !returnedState) throw new OidcError("callback missing code/state", 400, "bad_callback");

  // Re-open the signed login-state cookie and bind state (CSRF defense). FINDING #3: accept either
  // the `__Host-`-prefixed (HTTPS) or plain (http) name — whichever `handleOidcStart` minted.
  const sealed = readLoginCookie(req);
  if (!sealed) throw new OidcError("login state cookie missing", 400, "no_state_cookie");
  const login = await openLoginState(env.AUTH_SIGNING_SECRET, sealed, now);
  if (!timingSafeEqStr(returnedState, login.state)) {
    throw new OidcError("state mismatch (possible CSRF)", 400, "state_mismatch");
  }

  // Exchange code -> tokens (PKCE verifier proves we started this flow).
  const tokens = await exchangeCode(config, code, login.verifier, fetchImpl);

  // Validate id_token: sig (JWKS RS256) + iss/aud/exp/iat + nonce binding.
  const claims = await validateIdToken(tokens.id_token!, config, login.nonce, fetchImpl, now);

  // Map verified identity -> org user (find-or-provision under policy).
  const mapped = await mapIdentityToPrincipal(claims, config, dir);

  // Mint the cloud-fs session token (auth.ts) with role-derived scopes.
  const token = await mintToken(env.AUTH_SIGNING_SECRET, {
    sub: mapped.user.id,
    type: "session",
    orgId: config.orgId,
    scopes: mapped.scopes,
    ttlSeconds: DEFAULT_TTL_SECONDS.session,
  });

  // FINDING #3: clear the login cookie under the SAME per-transport name the browser holds.
  const secure = oidcCookieSecure(req);
  const headers = new Headers({ "content-type": "application/json" });
  headers.append("Set-Cookie", clearCookie(loginCookieName(secure), secure)); // one-time use; burn it
  const response = new Response(
    JSON.stringify({
      token,
      userId: mapped.user.id,
      email: mapped.user.email,
      role: mapped.user.role,
      scopes: mapped.scopes,
      provisioned: mapped.provisioned,
    }, null, 2),
    { status: 200, headers },
  );

  return { token, user: mapped.user, scopes: mapped.scopes, provisioned: mapped.provisioned, response };
}

// Re-export for callers wiring the session into verifyRequest downstream.
export type { AuthPrincipal };
