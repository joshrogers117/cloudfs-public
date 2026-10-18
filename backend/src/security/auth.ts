// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs token authentication: mint/verify signed tokens, derive a Principal.
///
/// Design goals (SPEC §4.4, §4.5):
///   - The gateway is the SOLE authZ decision point. Every gateway call carries a
///     bearer token; presigned-URL minting and DO mutations are authorized against a
///     LIVE, verified Principal — never the client's say-so.
///   - Signed tokens are self-describing. The gateway also checks durable revocation,
///     account status and current roles through a bounded 10-second per-isolate cache.
///     Token expiry and already-minted object URL expiry remain independent limits.
///   - Zero external deps: HMAC-SHA-256 (symmetric) via WebCrypto, available in workerd.
///     The wire format is a JWT-compatible compact JWS (header.payload.signature, base64url)
///     so a future migration to asymmetric (RS256/ES256) IdP-issued JWTs is drop-in:
///     `verifyToken` already routes on the header `alg`.
///
/// Token taxonomy (all share one signed envelope, differ by `typ` + `scopes`):
///   - session     — a human member's short-lived session (minted after SSO, SPEC §4.5).
///   - service     — a service-account / CLI / render-farm token (SPEC §3.8, R11).
///                   Long(er)-lived, narrowly scoped, rotatable by jti revocation.
///   - guest       — a single-folder, download-only, time-boxed guest link (SPEC §4.3).
///
/// SECURITY NOTES:
///   - HMAC verification is constant-time (WebCrypto `verify`), defeating timing oracles.
///   - `verifyToken` enforces exp/nbf and rejects `alg:none` and algorithm confusion.
///   - The signing secret is a Worker SECRET (never a `var`), see security-INTEGRATION.md.

export type TokenType = "session" | "service" | "guest";

/// Coarse capability scopes checked at the gateway BEFORE minting/mutating.
/// Fine-grained per-folder ACLs (SPEC §4.10 Grant table) are owned by the
/// permissions module; scopes here gate the *kind* of operation, ACLs gate the *target*.
export type Scope =
  | "fs:read"        // enumerate metadata, request read presigns
  | "fs:write"       // create/modify items, request write presigns
  | "fs:lock"        // acquire/release advisory leases (SPEC §4.9)
  | "fs:admin"       // grant/revoke ACLs, manage a space
  | "snapshot:read"  // load/browse snapshots
  | "snapshot:write" // create snapshots, restore
  | "audit:read";    // read the audit log

/// The verified caller. Everything downstream (presign, DO mutations, audit) keys off this.
export interface Principal {
  /// Stable subject id: member id, service-account id, or guest-link id.
  sub: string;
  type: TokenType;
  /// Org tenant the token is bound to — the root of multi-tenant isolation (SPEC §4.1).
  orgId: string;
  /// Optional filespace binding. Guest/service tokens are usually pinned to ONE space.
  /// `undefined` = the token may address any space its org owns (still org-scoped).
  spaceId?: string;
  scopes: Scope[];
  /// JWT id — unique per token; the handle for revocation/rotation.
  jti: string;
  /// Seconds since epoch.
  iat: number;
  exp: number;
}

/// Claims as they appear on the wire (compact JWS payload).
interface Claims {
  sub: string;
  typ: TokenType;
  org: string;
  spc?: string;
  scp: Scope[];
  jti: string;
  iat: number;
  exp: number;
  nbf?: number;
}

export interface MintOptions {
  sub: string;
  type: TokenType;
  orgId: string;
  spaceId?: string;
  scopes: Scope[];
  /// Lifetime in seconds. Caller picks per token-type policy (see DEFAULT_TTL_SECONDS).
  ttlSeconds: number;
  /// Optional explicit jti (else a random uuid). Useful for deterministic tests/rotation.
  jti?: string;
  /// Optional not-before offset in seconds (default 0).
  notBeforeSeconds?: number;
}

/// Recommended ceilings per token type. The gateway should clamp to these (SPEC §4.4:
/// "TTL on the order of minutes ... keep it tight so a leaked URL dies fast"). Sessions
/// are short so SCIM deprovisioning bites quickly; service tokens are longer but rotatable.
export const DEFAULT_TTL_SECONDS: Record<TokenType, number> = {
  session: 15 * 60,        // 15 min — refreshed by the client against the live SSO session
  service: 24 * 60 * 60,   // 24 h — CI/render-farm; rotate via jti revocation
  guest: 7 * 24 * 60 * 60, // 7 days — matches SPEC guest-link default
};

export class AuthError extends Error {
  constructor(
    message: string,
    /// HTTP status (401 bad/expired credentials, 403 scope, 503 unavailable authority).
    readonly status: 401 | 403 | 503 = 401,
    readonly code: string = "unauthorized",
  ) {
    super(message);
    this.name = "AuthError";
  }
}

// ---- base64url + bytes helpers (no Node Buffer; workerd/global only) -----------------

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

function b64urlJson(obj: unknown): string {
  return b64urlEncode(enc.encode(JSON.stringify(obj)));
}

// ---- HMAC key handling ----------------------------------------------------------------

/// FINDING #4: memoize the imported CryptoKey per secret value. `crypto.subtle.importKey`
/// ran on EVERY mint/verify (a cookie request pays it twice). `AUTH_SIGNING_SECRET` is stable
/// for the isolate's lifetime, so the derived key can be cached module-wide keyed by the secret
/// string. We cache the PROMISE (not the resolved key) so concurrent first-callers share one
/// import; a rejected import (weak secret) is NOT cached so a later valid secret can still import.
/// Semantics are unchanged — `sign`/`verify` operate on the same non-extractable HMAC key.
const hmacKeyCache = new Map<string, Promise<CryptoKey>>();

/// Import a raw secret string as an HMAC-SHA-256 key, memoized per secret (see above).
function importHmacKey(secret: string): Promise<CryptoKey> {
  if (!secret || secret.length < 16) {
    // Refuse weak secrets at the source rather than minting forgeable tokens.
    throw new AuthError("signing secret missing or too short (need >= 16 chars)", 401, "bad_secret");
  }
  const cached = hmacKeyCache.get(secret);
  if (cached) return cached;
  const p = crypto.subtle
    .importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"])
    .catch((e) => {
      // Don't cache a failed import — a transient/invalid state shouldn't poison future calls.
      hmacKeyCache.delete(secret);
      throw e;
    });
  hmacKeyCache.set(secret, p);
  return p;
}

// ---- mint / verify --------------------------------------------------------------------

/// Mint a signed compact-JWS token. `now` is injectable for deterministic tests.
export async function mintToken(secret: string, opts: MintOptions, now: number = Date.now()): Promise<string> {
  const key = await importHmacKey(secret);
  const iat = Math.floor(now / 1000);
  const claims: Claims = {
    sub: opts.sub,
    typ: opts.type,
    org: opts.orgId,
    scp: opts.scopes,
    jti: opts.jti ?? crypto.randomUUID(),
    iat,
    exp: iat + Math.max(1, Math.floor(opts.ttlSeconds)),
  };
  if (opts.spaceId !== undefined) claims.spc = opts.spaceId;
  if (opts.notBeforeSeconds) claims.nbf = iat + opts.notBeforeSeconds;

  const header = { alg: "HS256", typ: "JWT" };
  const signingInput = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(signingInput));
  return `${signingInput}.${b64urlEncode(new Uint8Array(sig))}`;
}

/// Options that shape verification beyond signature/expiry.
export interface VerifyOptions {
  /// If set, the token's jti must NOT be in this set (revocation list / rotation).
  /// Keep this small + hot (e.g. a KV/DO-backed denylist of revoked service tokens).
  revokedJtis?: Set<string>;
  /// Clock-skew tolerance in seconds for exp/nbf (default 30s).
  clockSkewSeconds?: number;
}

/// Verify signature + temporal claims, returning a Principal. Throws AuthError on any failure.
/// `now` injectable for tests.
export async function verifyToken(
  secret: string,
  token: string,
  opts: VerifyOptions = {},
  now: number = Date.now(),
): Promise<Principal> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AuthError("malformed token", 401, "malformed");
  const [h, p, s] = parts;

  // Parse + validate header. Reject alg:none and any non-HS256 (no algorithm confusion).
  let header: { alg?: string; typ?: string };
  try {
    header = JSON.parse(dec.decode(b64urlDecode(h)));
  } catch {
    throw new AuthError("bad token header", 401, "malformed");
  }
  if (header.alg !== "HS256") {
    throw new AuthError(`unsupported alg '${header.alg}'`, 401, "bad_alg");
  }

  // Verify signature BEFORE trusting any payload bytes.
  const key = await importHmacKey(secret);
  const ok = await crypto.subtle.verify("HMAC", key, b64urlDecode(s), enc.encode(`${h}.${p}`));
  if (!ok) throw new AuthError("bad signature", 401, "bad_signature");

  let claims: Claims;
  try {
    claims = JSON.parse(dec.decode(b64urlDecode(p)));
  } catch {
    throw new AuthError("bad token payload", 401, "malformed");
  }

  const nowSec = Math.floor(now / 1000);
  const skew = opts.clockSkewSeconds ?? 30;
  if (typeof claims.exp !== "number" || nowSec - skew >= claims.exp) {
    throw new AuthError("token expired", 401, "expired");
  }
  if (typeof claims.nbf === "number" && nowSec + skew < claims.nbf) {
    throw new AuthError("token not yet valid", 401, "not_yet_valid");
  }
  if (!claims.sub || !claims.org || !claims.typ || !Array.isArray(claims.scp) || !claims.jti) {
    throw new AuthError("incomplete claims", 401, "malformed");
  }
  if (opts.revokedJtis?.has(claims.jti)) {
    throw new AuthError("token revoked", 401, "revoked");
  }

  return {
    sub: claims.sub,
    type: claims.typ,
    orgId: claims.org,
    spaceId: claims.spc,
    scopes: claims.scp,
    jti: claims.jti,
    iat: claims.iat,
    exp: claims.exp,
  };
}

// ---- scope + tenant guards ------------------------------------------------------------

/// True iff the principal carries the required scope. `fs:admin` is NOT a superset here —
/// scopes are explicit and additive at mint time (least privilege); the permissions module
/// decides role→scope mapping. Keep authZ boring and explicit.
export function hasScope(principal: Principal, scope: Scope): boolean {
  return principal.scopes.includes(scope);
}

/// Assert a scope or throw 403. Use at the gateway right before the privileged action.
export function requireScope(principal: Principal, scope: Scope): void {
  if (!hasScope(principal, scope)) {
    throw new AuthError(`missing required scope '${scope}'`, 403, "forbidden_scope");
  }
}

/// Multi-tenant isolation guard (SPEC §4.1, §4.4): a token may only address its own org,
/// and — if pinned — only its bound space. The gateway MUST call this before deriving a
/// FilespaceDO stub, so one tenant can never reach another's DO/filespace.
export function assertTenant(principal: Principal, orgId: string, spaceId?: string): void {
  if (principal.orgId !== orgId) {
    throw new AuthError("cross-tenant access denied", 403, "cross_tenant");
  }
  if (principal.spaceId !== undefined && spaceId !== undefined && principal.spaceId !== spaceId) {
    throw new AuthError("token not valid for this filespace", 403, "wrong_space");
  }
}

/// Build the tenant-scoped DO name. ALWAYS namespace the DO by org so two orgs that pick
/// the same human-friendly space id land on DIFFERENT Durable Objects (SPEC §4.4: the
/// bucket/DO must be unreachable across tenants). The gateway should feed this into
/// `FILESPACE.idFromName(...)` instead of the bare space id.
export function filespaceDoName(orgId: string, spaceId: string): string {
  return `${orgId}::${spaceId}`;
}

// ---- request middleware ---------------------------------------------------------------

/// Minimal env shape this middleware needs. The real Env (env.ts) is a superset; we accept
/// a structural subset so the module stays decoupled and unit-testable.
export interface AuthEnv {
  /// Worker SECRET holding the HMAC signing key. NOT a plaintext `var`. See INTEGRATION.
  AUTH_SIGNING_SECRET: string;
}

/// Pull a bearer token from the Authorization header. Returns null when absent/malformed.
export function bearerFromRequest(req: Request): string | null {
  const h = req.headers.get("authorization");
  if (!h) return null;
  const m = /^Bearer\s+(.+)$/i.exec(h.trim());
  return m ? m[1].trim() : null;
}

/// A resolver that turns a request's browser SESSION COOKIE into a short-lived `session` JWS
/// (jti == the live session row's id) — the cloud-fs cookie path (CONTRACTS-AUTH.md §1.5,
/// §4.7). `auth.ts` stays storage-free: the integration layer injects this (backed by the
/// session lane's `verifySession`, which loads + idle/absolute-checks + re-mints the JWS). It
/// returns null when there is no session cookie (so `verifyRequest` falls back to / requires a
/// bearer), or throws an `AuthError` when a cookie IS present but invalid (revoked/expired/idle
/// — never silently downgraded to "no token"). The `csrf` flag asks the resolver to ALSO run
/// the double-submit CSRF check (mutating requests only). On success it returns the freshly
/// minted JWS, which `verifyRequest` then verifies through the normal stateless path so the
/// resulting Principal is identical in shape to a bearer-authed one.
export interface SessionResolver {
  (req: Request, opts: { requireCsrf: boolean }): Promise<{ jws: string } | null>;
}

/// Optional knobs for the unified gate.
export interface RequestAuthOptions extends VerifyOptions {
  /// Injected cookie→JWS resolver (the session lane). Absent => bearer-only (legacy behaviour).
  sessionResolver?: SessionResolver;
  /// True when the request is state-changing (POST/PUT/DELETE/PATCH): the cookie path then
  /// also enforces the double-submit CSRF header. Bearer (machine) callers are exempt — they
  /// carry no ambient cookie, so CSRF doesn't apply to them.
  isMutation?: boolean;
}

/// The gateway entrypoint: verify the request → Principal, or throw AuthError.
///
/// AUTH PRECEDENCE (CONTRACTS-AUTH.md §4.7) — bearer FIRST, then cookie:
///   1. `Authorization: Bearer <jws>` present  → verify it (machines: cloudfsd, CLI, service
///      tokens, OIDC/bootstrap sessions). This is the UNCHANGED legacy path; daemon/CLI auth
///      keeps working exactly as before, and CSRF never applies to bearer callers.
///   2. no bearer, but a `cfs_session` cookie + an injected `sessionResolver` → resolve the
///      cookie to a live-session JWS (idle/absolute/revocation enforced server-side by the
///      resolver, plus CSRF on mutations) and verify THAT JWS through the same stateless path.
///   3. neither → 401 `no_token`.
///
/// Because both paths end at `verifyToken`, the returned Principal is byte-identical in shape
/// regardless of how the caller authenticated. Stateless beyond the optional revocation set +
/// the session row the resolver consults.
export async function verifyRequest(
  req: Request,
  env: AuthEnv,
  opts: RequestAuthOptions = {},
  now: number = Date.now(),
): Promise<Principal> {
  const bearer = bearerFromRequest(req);
  if (bearer) {
    // Path 1 — legacy bearer. Unchanged; the daemon/CLI/service-token flow is untouched.
    return verifyToken(env.AUTH_SIGNING_SECRET, bearer, opts, now);
  }
  // Path 2 — browser session cookie (only when a resolver is wired in).
  if (opts.sessionResolver) {
    const resolved = await opts.sessionResolver(req, { requireCsrf: !!opts.isMutation });
    if (resolved) {
      return verifyToken(env.AUTH_SIGNING_SECRET, resolved.jws, opts, now);
    }
  }
  // Path 3 — nothing presented.
  throw new AuthError("missing bearer token", 401, "no_token");
}
