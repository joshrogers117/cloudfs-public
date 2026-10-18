// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs browser-session lane: opaque server-side sessions delivered as an HttpOnly cookie,
/// double-submit CSRF tokens for state-changing requests, plus verify / rotate / revoke and the
/// idle + absolute expiry policy (CONTRACTS-AUTH.md §1.5, §4.2, §4.7).
///
/// Model (CONTRACTS-AUTH.md §1.5):
///   - A `BrowserSession` row in `AuthDO` is the source of truth: it binds an account+org+scopes,
///     carries the CSRF token, and tracks `issuedAt / expiresAt / lastSeenAt / revokedAt`.
///   - The cookie value is the OPAQUE session id (`sess-<uuid>`) — NOT a bearer of authority by
///     itself. On each authenticated request the gateway loads the row, enforces idle+absolute
///     bounds + revocation, and (re-)mints a SHORT-LIVED `session` JWS whose `jti == session.id`
///     to drive the existing stateless `verifyRequest` gate. So revocation/idle is real
///     (server-side) while the hot path stays stateless within one 15-min JWS TTL.
///   - Logout/idle-expiry adds `session.id` to the revoked-jti set so the residual JWS dies too.
///
/// CSRF: double-submit. The CSRF token lives in the session row AND is returned to the SPA in
/// the JSON body (readable by JS). State-changing cookie-authed requests must echo it in the
/// `X-CFS-CSRF` header; we compare in constant time against the row. SameSite=Lax on the cookie
/// is the first line; the double-submit token is defense-in-depth against top-level POST CSRF.
///
/// Workers-correct: WebCrypto only (`crypto.randomUUID`, `crypto.getRandomValues`). All time +
/// randomness + the `mintToken` call are injectable so the module is deterministic in tests.
/// Depends only on the `SessionStore` interface (CONTRACTS-AUTH.md §2), the `Scope` type, and
/// `mintToken` from `auth.ts`. Never imports `cloudflare:workers`.

import type { Scope } from "./auth";
import { mintToken, DEFAULT_TTL_SECONDS, type AuthEnv } from "./auth";

// ---------------------------------------------------------------------------------------
// Contract types (CONTRACTS-AUTH.md §1.5). Owned by this lane until the integration agent
// lifts them into the shared `auth-types.ts`; shapes are frozen.
// ---------------------------------------------------------------------------------------

export interface BrowserSession {
  authEpoch?: number;
  id: string; // "sess-<uuid>"; ALSO the jti of the minted session JWS (1:1)
  accountId: string;
  userId: string; // == Account.userId; the Principal.sub
  orgId: string;
  scopes: Scope[]; // from scopesForRole(role) at login time
  csrfToken: string; // random 32-byte base64url; double-submit value
  issuedAt: number;
  expiresAt: number; // absolute cap (default 12h)
  lastSeenAt: number; // updated on use; idle policy below
  revokedAt: number | null;
}

/// The `SessionStore` (CONTRACTS-AUTH.md §2) — injected, never a concrete DO.
export interface SessionStore {
  createSession(input: {
    authEpoch?: number;
    accountId: string;
    userId: string;
    orgId: string;
    scopes: Scope[];
    csrfToken: string;
    expiresAt: number;
  }): Promise<BrowserSession>;
  getSession(sessionId: string): Promise<BrowserSession | null>;
  touchSession(sessionId: string, lastSeenAt: number): Promise<void>;
  revokeSession(sessionId: string): Promise<void>;
  listSessions(accountId: string): Promise<BrowserSession[]>;
  revokedSessionJtis(): Promise<Set<string>>; // feeds VerifyOptions.revokedJtis
}

// ---------------------------------------------------------------------------------------
// Frozen policy + wire constants (CONTRACTS-AUTH.md §1.5, §4).
// ---------------------------------------------------------------------------------------

/// Absolute session lifetime: 12h. After this the row is dead regardless of activity.
export const ABSOLUTE_LIFETIME_MS = 12 * 60 * 60 * 1000;
/// Idle timeout: a session unused for 30m is rejected and must be re-auth'd.
export const IDLE_TIMEOUT_MS = 30 * 60 * 1000;

/// Audit B21 — only persist a session's `lastSeenAt` when the stored value is at least this old, so a
/// busy session stops issuing a DO write on every request. Far smaller than IDLE_TIMEOUT_MS, so the
/// idle policy is unaffected (the worst case is the persisted lastSeenAt trailing real activity by
/// up to this window — still ~30x inside the idle timeout).
export const TOUCH_SESSION_THROTTLE_MS = 60 * 1000;

/// Cookie name (CONTRACTS-AUTH.md §4): HttpOnly, Secure, SameSite=Lax, Path=/.
export const SESSION_COOKIE = "cfs_session";
/// FINDING #3: the hardened cookie name carrying the `__Host-` prefix. The prefix tells the
/// browser to enforce Secure + Path=/ + no Domain (it refuses to accept a `__Host-` cookie that
/// lacks Secure or carries a Domain), shrinking the cookie-fixation surface. BUT `__Host-` REQUIRES
/// the Secure attribute, which a browser drops over plain `http://localhost` — so this name is only
/// usable over HTTPS. We therefore pick the name per-request (see `sessionCookieName`): the prefixed
/// name + Secure on HTTPS deployments, the plain name (no Secure) over http/localhost so the dev
/// stack + E2E harness keep working.
export const SESSION_COOKIE_SECURE = "__Host-cfs_session";

/// Resolve the session cookie name for a given transport: the `__Host-`-prefixed name over HTTPS,
/// the plain name over http (dev/localhost). Read sites that don't know the transport should accept
/// BOTH (see `readSessionCookie`).
export function sessionCookieName(secure: boolean): string {
  return secure ? SESSION_COOKIE_SECURE : SESSION_COOKIE;
}
/// Double-submit CSRF header (CONTRACTS-AUTH.md §4).
export const CSRF_HEADER = "X-CFS-CSRF";
/// CSRF token entropy in bytes.
export const CSRF_TOKEN_BYTES = 32;

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

export class SessionError extends Error {
  constructor(
    message: string,
    readonly status: 401 | 403 = 401,
    readonly code: string = "session_error",
  ) {
    super(message);
    this.name = "SessionError";
  }
}

// ---------------------------------------------------------------------------------------
// base64url + cookie helpers (no Node Buffer; workerd globals only) — mirrors oidc.ts.
// ---------------------------------------------------------------------------------------

const enc = new TextEncoder();

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomB64url(byteLen: number): string {
  const buf = new Uint8Array(byteLen);
  crypto.getRandomValues(buf);
  return b64urlEncode(buf);
}

/// Constant-time string comparison over UTF-8 bytes: XOR-accumulate, no early return. Used for
/// the CSRF double-submit check so an attacker can't time-probe the token. (Returns false on
/// length mismatch — token length is fixed, not secret.)
export function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

/// Build the `Set-Cookie` for the session. HttpOnly (XSS can't read it), Secure (HTTPS only),
/// SameSite=Lax (top-level nav sends it; cross-site POSTs don't). `Max-Age` is the absolute
/// remaining lifetime in seconds so the browser drops the cookie at the absolute cap too.
///
/// FINDING #3: `opts.secure` (default true, preserving prior behaviour) toggles BOTH the
/// `__Host-` name prefix AND the `Secure` attribute. Over HTTPS we emit the hardened
/// `__Host-cfs_session` + Secure; over plain http (dev/localhost) callers pass `secure:false` to
/// emit the plain `cfs_session` with NO Secure attribute (a `__Host-`/Secure cookie is silently
/// dropped by the browser on http, which would break the dev stack + E2E harness).
export function buildSessionCookie(
  value: string,
  maxAgeSeconds: number,
  opts: { secure?: boolean; sameSite?: "Lax" | "None" } = {},
): string {
  const secure = opts.secure ?? true;
  const maxAge = Math.max(0, Math.floor(maxAgeSeconds));
  const secureAttr = secure ? "; Secure" : "";
  // Audit B9: a split-origin (Pages-hosted) console needs SameSite=None so the cookie
  // is sent on cross-site API calls. SameSite=None REQUIRES Secure, so we only honor it
  // over https; otherwise fall back to Lax (the safe same-origin default).
  const sameSite = opts.sameSite === "None" && secure ? "None" : "Lax";
  return `${sessionCookieName(secure)}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly${secureAttr}; SameSite=${sameSite}`;
}

/// Build the cookie that CLEARS the session (logout / revoke). Same attributes so the browser
/// matches and deletes it. `opts.secure` mirrors `buildSessionCookie` (default true).
export function clearSessionCookie(opts: { secure?: boolean } = {}): string {
  const secure = opts.secure ?? true;
  const secureAttr = secure ? "; Secure" : "";
  return `${sessionCookieName(secure)}=; Max-Age=0; Path=/; HttpOnly${secureAttr}; SameSite=Lax`;
}

/// Read the opaque session id out of the request `Cookie` header. Returns null when absent.
/// FINDING #3: accepts BOTH the `__Host-`-prefixed (HTTPS) and the plain (dev/http) cookie names —
/// the read site doesn't know the transport, and a single request only ever carries one of them.
/// The prefixed name is preferred if (improbably) both are present.
export function readSessionCookie(req: Request): string | null {
  const header = req.headers.get("cookie");
  if (!header) return null;
  let plain: string | null = null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    const name = part.slice(0, eq).trim();
    if (name === SESSION_COOKIE_SECURE) return part.slice(eq + 1).trim();
    if (name === SESSION_COOKIE) plain = part.slice(eq + 1).trim();
  }
  return plain;
}

// ---------------------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------------------

/// Generate a fresh CSRF token (32 random bytes, base64url). Exposed for the login lanes that
/// mint a session out of band, but `createBrowserSession` does this for you.
export function generateCsrfToken(): string {
  return randomB64url(CSRF_TOKEN_BYTES);
}

/// Create a new browser session row bound to account+org+scopes, with a fresh CSRF token and an
/// absolute expiry 12h out. Returns the persisted `BrowserSession`. The opaque `session.id` is
/// what goes in the cookie; `session.csrfToken` is returned to the SPA body. `now` injectable.
export async function createBrowserSession(
  store: SessionStore,
  input: { accountId: string; userId: string; orgId: string; scopes: Scope[]; authEpoch?: number },
  now: number = Date.now(),
): Promise<BrowserSession> {
  const csrfToken = generateCsrfToken();
  const expiresAt = now + ABSOLUTE_LIFETIME_MS;
  return store.createSession({
    authEpoch: input.authEpoch,
    accountId: input.accountId,
    userId: input.userId,
    orgId: input.orgId,
    scopes: input.scopes,
    csrfToken,
    expiresAt,
  });
}

/// Why a session is not currently usable, for precise error codes.
export type SessionInvalidReason = "not_found" | "revoked" | "expired" | "idle";

/// Pure policy check: is this row live right now? Encapsulates revoked / absolute-expiry / idle.
/// Separated out so it is trivially unit-testable without a store.
export function sessionInvalidReason(
  session: BrowserSession | null,
  now: number,
): SessionInvalidReason | null {
  if (!session) return "not_found";
  if (session.revokedAt !== null) return "revoked";
  if (now >= session.expiresAt) return "expired";
  if (now - session.lastSeenAt >= IDLE_TIMEOUT_MS) return "idle";
  return null;
}

/// The outcome of verifying a request's session cookie: the live row plus the freshly-minted
/// short-lived `session` JWS to drop back into the cookie, and the remaining absolute lifetime
/// (so the caller can set `Max-Age`).
export interface VerifiedSession {
  session: BrowserSession;
  /// A fresh short-lived `session`-type compact-JWS (jti == session.id) for `verifyRequest`.
  jws: string;
  /// Remaining absolute lifetime in seconds — for the refreshed cookie's `Max-Age`.
  remainingSeconds: number;
}

/// Verify + rotate-forward a request's session: read the cookie, load the row, enforce
/// revoked/absolute/idle, bump `lastSeenAt` (sliding idle window), and re-mint a 15-min session
/// JWS bound to the row's principal. Throws `SessionError(401)` with a precise code on any
/// invalidity. `mintFn` is injectable so tests don't depend on a real signing secret; it
/// defaults to the real `mintToken`. `now` injectable.
export async function verifySession(
  req: Request,
  store: SessionStore,
  env: AuthEnv,
  opts: {
    now?: number;
    mintFn?: typeof mintToken;
    /// Override the residual JWS TTL (defaults to the existing 15-min session policy).
    jwsTtlSeconds?: number;
  } = {},
): Promise<VerifiedSession> {
  const now = opts.now ?? Date.now();
  const mintFn = opts.mintFn ?? mintToken;

  const sessionId = readSessionCookie(req);
  if (!sessionId) throw new SessionError("missing session cookie", 401, "no_session");

  const session = await store.getSession(sessionId);
  const bad = sessionInvalidReason(session, now);
  if (bad || !session) {
    // Collapse "not_found" and the live-but-invalid cases into a 401; the code distinguishes
    // them for logs/metrics without leaking to the client beyond the status.
    throw new SessionError(`session ${bad ?? "not_found"}`, 401, bad ?? "not_found");
  }

  // Slide the idle window. Audit B21: THROTTLE the durable write — every cookie-authed request used
  // to issue a `touchSession` UPDATE to the AuthDO, but the idle window is 30 min, so persisting
  // `lastSeenAt` to a 60s granularity is indistinguishable for the idle policy while eliminating a
  // per-request DO write on a busy session. We always advance the IN-MEMORY `lastSeenAt` (so the
  // re-minted JWS reflects THIS request and the response is unchanged); we only skip the DB write
  // when the stored value is younger than the throttle window.
  const touched: BrowserSession = { ...session, lastSeenAt: now };
  if (now - session.lastSeenAt >= TOUCH_SESSION_THROTTLE_MS) {
    await store.touchSession(session.id, now);
  }

  // Re-mint the short-lived JWS. jti == session.id so logout can revoke the residual token,
  // and the absolute cap is respected by clamping the JWS TTL to the remaining lifetime.
  const remainingMs = touched.expiresAt - now;
  const remainingSeconds = Math.max(0, Math.floor(remainingMs / 1000));
  const jwsTtl = Math.min(opts.jwsTtlSeconds ?? DEFAULT_TTL_SECONDS.session, remainingSeconds || 1);
  const jws = await mintFn(
    env.AUTH_SIGNING_SECRET,
    {
      sub: touched.userId,
      type: "session",
      orgId: touched.orgId,
      scopes: touched.scopes,
      ttlSeconds: jwsTtl,
      jti: touched.id, // 1:1 with the session row for revocation
    },
    now,
  );

  return { session: touched, jws, remainingSeconds };
}

/// Enforce the double-submit CSRF check on a state-changing, cookie-authed request: the
/// `X-CFS-CSRF` header must be present and equal (constant-time) to the session's stored token.
/// Throws `SessionError(403, "csrf")` otherwise. Call this AFTER `verifySession` on every
/// mutating route (POST/DELETE) per CONTRACTS-AUTH.md §4.
export function enforceCsrf(req: Request, session: BrowserSession): void {
  const presented = req.headers.get(CSRF_HEADER);
  if (!presented || !timingSafeEqualStr(presented, session.csrfToken)) {
    throw new SessionError("missing or invalid CSRF token", 403, "csrf");
  }
}

/// Rotate a session's identity AND CSRF token after a privilege change (e.g. completing MFA, or
/// any "elevate" event) — defeats session fixation. Revokes the old row (adding its jti to the
/// revoked set on the next sweep) and creates a fresh row with the same binding + a NEW absolute
/// window. Returns the new session. The caller re-sets the cookie + returns the new CSRF token.
export async function rotateSession(
  store: SessionStore,
  oldSessionId: string,
  now: number = Date.now(),
): Promise<BrowserSession> {
  const old = await store.getSession(oldSessionId);
  if (!old) throw new SessionError("session not found", 401, "not_found");
  await store.revokeSession(old.id);
  return createBrowserSession(
    store,
    { accountId: old.accountId, userId: old.userId, orgId: old.orgId, scopes: old.scopes, authEpoch: old.authEpoch },
    now,
  );
}

/// Revoke a single session (logout, or "sign out this device"). Idempotent; safe if already
/// revoked/absent. The revoked id flows into `revokedSessionJtis()` so the residual ≤15-min JWS
/// is rejected by `verifyRequest`.
export async function revokeBrowserSession(store: SessionStore, sessionId: string): Promise<void> {
  await store.revokeSession(sessionId);
}

/// Public projection of a session row (no CSRF token leaked) for `GET /v1/auth/sessions`.
export interface PublicSession {
  id: string;
  orgId: string;
  issuedAt: number;
  expiresAt: number;
  lastSeenAt: number;
  revokedAt: number | null;
  current: boolean;
}

/// List the caller's sessions, marking which one is the current request. CSRF tokens are
/// stripped. (CONTRACTS-AUTH.md §4.2 `GET /v1/auth/sessions`.)
export async function listSessionsPublic(
  store: SessionStore,
  accountId: string,
  currentSessionId: string | null,
): Promise<PublicSession[]> {
  const rows = await store.listSessions(accountId);
  return rows.map((s) => ({
    id: s.id,
    orgId: s.orgId,
    issuedAt: s.issuedAt,
    expiresAt: s.expiresAt,
    lastSeenAt: s.lastSeenAt,
    revokedAt: s.revokedAt,
    current: s.id === currentSessionId,
  }));
}

/// Build the `Set-Cookie` + the JSON-safe body fields after a successful login that produced a
/// session. The caller appends `Set-Cookie` to its response and merges `body` into the JSON.
/// The opaque session id is the cookie value; CSRF goes in the body for the SPA to echo back.
export function sessionLoginResponse(
  session: BrowserSession,
  now: number = Date.now(),
): { setCookie: string; csrf: string; body: { csrf: string } } {
  const remainingSeconds = Math.max(1, Math.floor((session.expiresAt - now) / 1000));
  return {
    setCookie: buildSessionCookie(session.id, remainingSeconds),
    csrf: session.csrfToken,
    body: { csrf: session.csrfToken },
  };
}
