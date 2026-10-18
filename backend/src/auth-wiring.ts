// SPDX-License-Identifier: AGPL-3.0-or-later
// auth-wiring.ts — integration glue mounting the CONTRACTS-AUTH.md route surface (§4) into the
// gateway, plus the cookie→Principal session resolver `verifyRequest` uses (auth.ts §SessionResolver).
//
// Ownership (CONTRACTS-AUTH.md §3): the integration agent owns route wiring + the real stores.
// This module composes the frozen lane handlers (auth-signup/password/session/totp/webauthn/
// email/service-tokens) over the DO-backed adapters in `auth-stores.ts`. No lane file is edited.
//
// ORG BINDING. Login is bare email+password with no org. A browser session lives in
// `AuthDO(orgId)`, the MFA challenge in the same, and the cookie/challengeId carry no org. To
// resolve before the org is known WITHOUT a directory scan on the hot path (CONTRACTS-AUTH.md
// §1.7), we EMBED the org into the opaque handles we hand the client:
//   - the session cookie value becomes  "<orgId>.<sessId>"  (qualifyCookie / splitCookie),
//   - the MFA challengeId becomes        "<orgId>.<challengeId>" (qualifyChallenge / splitChallenge),
//   - email-verify / reset links carry  ?orgId=<orgId>.
// The lanes stay untouched; we wrap their I/O at the integration boundary.

import type { Env } from "./env";
import { completeLegacyAccount } from "./legacy-account";
import type { Principal, Scope, SessionResolver } from "./security/auth";
import { AuthError } from "./security/auth";
import { RateLimiter, ipKey, tooManyRequests } from "./security/ratelimit";
import type { OrgRole } from "./permissions";

import { authStoresFor, emailSenderFor, emailSenderForOrg, DoOrgProvisioner, DoRateLimitStore, type AuthStores } from "./auth-stores";
import { invalidateJti } from "./gate-cache";
import { DIRECTORY_DO_NAME } from "./directory-do";
import { resolveAuthMode } from "./oidc-wiring";
import { evaluateSignupGate, shouldRefuseOpenSignupOnHttps } from "./signup-mode";
import {
  handleOidcCallback,
  OidcError,
  type CallbackDeps,
  type DirectoryUser,
} from "./security/oidc";

import {
  handleSignup,
  handleLogin,
  handleLoginTotp,
  handleLoginRecovery,
  signupErrorResponse,
  SignupError,
  canonicalEmail,
  scopesForLogin,
  type SignupDeps,
  type SignupLimiters,
} from "./security/auth-signup";
import {
  SESSION_COOKIE,
  sessionCookieName,
  readSessionCookie,
  verifySession,
  enforceCsrf,
  createBrowserSession,
  revokeBrowserSession,
  clearSessionCookie,
  listSessionsPublic,
  sessionLoginResponse,
  generateCsrfToken,
  ABSOLUTE_LIFETIME_MS,
  SessionError,
  type BrowserSession,
} from "./security/auth-session";
import {
  setPassword,
  changePassword,
  resetPassword,
  verifyPassword,
  PasswordError,
  scryptCostFromEnv,
  assertPasswordNotBreached,
  assertAcceptablePassword,
  type ScryptCost,
  type PasswordStore,
  type BreachCheckOptions,
} from "./security/auth-password";
import { enrollTotp, confirmTotp, disableTotp, TotpError, type TotpDeps } from "./security/auth-totp";
import {
  handleWebAuthn,
  WebAuthnError,
  type WebAuthnDeps,
  type WebAuthnConfig,
} from "./security/auth-webauthn";
import {
  sendVerificationEmail,
  confirmEmailToken,
  issueEmailToken,
  verifyEmailToken,
} from "./security/auth-email";
import {
  mintServiceToken,
  mintDeviceDaemonToken,
  listServiceTokens,
  revokeServiceToken,
  type ServiceTokenDeps,
  type ServiceTokenRole,
} from "./security/auth-service-tokens";
import {
  approveDevice,
  exchangeDeviceCode,
  refreshDeviceSession,
  toPublicDeviceSession,
  DeviceAuthError,
  type DeviceAuthDeps,
} from "./security/auth-device";
import { verifyToken, bearerFromRequest, filespaceDoName } from "./security/auth";

import type { Account } from "./security/auth-types";

// Invite-redeem primitives (Build step 1 of ONBOARDING.md — `POST /v1/auth/join` composes
// signup's account/credential machinery with invites.ts's existing redeem logic). invites.ts
// does NOT import anything from this file (it takes an injected `InviteNotifyDeps` thunk
// instead — see invites.ts), so this one-directional edge creates no module cycle.
import {
  parseInviteToken,
  validateInvite,
  redeemInvite,
  REDEEM_HTTP_STATUS,
  type RedeemError,
} from "./invites";

// ---------------------------------------------------------------------------------------
// JSON + opaque-handle helpers
// ---------------------------------------------------------------------------------------

function json(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json", ...(extraHeaders ?? {}) },
  });
}

function directoryStub(env: Env) {
  return env.DIRECTORY_DO.get(env.DIRECTORY_DO.idFromName(DIRECTORY_DO_NAME));
}

/// Human-readable `reason` for a signup-mode 403 (the typed `error` code is the contract).
function signupBlockReason(code: "signup_disabled" | "domain_not_allowed", mode: string): string {
  if (code === "domain_not_allowed") return "your email domain is not allowed to sign up on this deployment";
  return mode === "invite"
    ? "self-serve signup requires a valid invite token on this deployment"
    : "self-serve signup is disabled on this deployment";
}

/// FINDING #3: decide whether to emit HARDENED (`__Host-` prefixed + Secure) auth cookies for this
/// request. `__Host-` requires the Secure attribute, which the browser drops over plain http —
/// so we only enable it over HTTPS. The `COOKIE_SECURE` env flag forces it on/off (e.g. behind a
/// TLS-terminating proxy that forwards http to the Worker); otherwise we auto-detect from the
/// request URL protocol. Dev/localhost + the http E2E harness fall to the plain `cfs_session` name.
export function secureCookies(env: Env, req: Request): boolean {
  const flag = env.COOKIE_SECURE;
  if (flag === "1" || flag === "true") return true;
  if (flag === "0" || flag === "false") return false;
  try {
    return new URL(req.url).protocol === "https:";
  } catch {
    return false;
  }
}

/// Rewrite a session `Set-Cookie` so its VALUE carries the org: `<name>=<orgId>.<sessId>; ...`,
/// preserving the other attributes. FINDING #3: also normalize the cookie to the per-request
/// transport — the hardened `__Host-cfs_session` name + a `Secure` attribute over HTTPS, or the
/// plain `cfs_session` name with NO Secure over http (so the dev/E2E http stack keeps working).
/// The lanes build the cookie with a fixed name/Secure; this is the single chokepoint that adapts
/// it to the live request, so the name stays consistent end-to-end with the read sites.
/// Exported for the setup wizard (setup.ts), which mints the operator's first session.
export function qualifyCookie(setCookie: string, orgId: string, secure: boolean): string {
  const eq = setCookie.indexOf("=");
  const semi = setCookie.indexOf(";");
  const value = semi === -1 ? setCookie.slice(eq + 1) : setCookie.slice(eq + 1, semi);
  let attrs = semi === -1 ? "" : setCookie.slice(semi);
  // Drop any Secure the lane emitted, then re-add it only when serving over HTTPS.
  attrs = attrs.replace(/;\s*Secure/gi, "");
  if (secure) attrs += "; Secure";
  return `${sessionCookieName(secure)}=${orgId}.${value}${attrs}`;
}

/// Split the inbound org-qualified cookie value into { orgId, sessionId }, or null.
function splitCookie(req: Request): { orgId: string; sessionId: string } | null {
  const raw = readSessionCookie(req);
  if (!raw) return null;
  const dot = raw.indexOf(".");
  if (dot <= 0 || dot >= raw.length - 1) return null;
  return { orgId: raw.slice(0, dot), sessionId: raw.slice(dot + 1) };
}

/// A clone of `req` whose `cfs_session` cookie holds ONLY the bare session id (what the session
/// lane's `readSessionCookie` expects).
function reqWithBareCookie(req: Request, sessionId: string): Request {
  const headers = new Headers(req.headers);
  headers.set("cookie", `${SESSION_COOKIE}=${sessionId}`);
  return new Request(req.url, { method: req.method, headers });
}

function qualify(orgId: string, handle: string): string {
  return `${orgId}.${handle}`;
}
function split(qualified: unknown): { orgId: string; handle: string } | null {
  if (typeof qualified !== "string") return null;
  const dot = qualified.indexOf(".");
  if (dot <= 0 || dot >= qualified.length - 1) return null;
  return { orgId: qualified.slice(0, dot), handle: qualified.slice(dot + 1) };
}

const MUTATING = new Set(["POST", "PUT", "DELETE", "PATCH"]);

/// Whether a `/v1/auth/*` sub-route (after the `v1/auth` prefix) is a BUILT-IN credential entry
/// point — i.e. one the `auth_mode_oidc` gate refuses when the deployment runs in external-OIDC-only
/// mode. Covers password signup/login (+TOTP/recovery MFA), forgot/reset, and the PUBLIC passwordless
/// WebAuthn assertion (`authenticate/options|verify`). Session-gated routes and email-verify are NOT
/// here (they don't grant built-in entry and shouldn't lock out a live session). `seg` is `p.slice(2)`.
function isBuiltinCredentialRoute(seg: string[], method: string): boolean {
  if (method !== "POST") return false;
  if (seg[0] === "signup" && !seg[1]) return true;
  if (seg[0] === "join" && !seg[1]) return true; // sets a password credential, same as signup
  if (seg[0] === "login" && (!seg[1] || seg[1] === "totp" || seg[1] === "recovery")) return true;
  if (seg[0] === "password" && (seg[1] === "forgot" || seg[1] === "reset" || seg[1] === "enroll-legacy")) return true;
  if (seg[0] === "webauthn" && seg[1] === "authenticate" && (seg[2] === "options" || seg[2] === "verify")) return true;
  return false;
}

// ---------------------------------------------------------------------------------------
// Public-surface rate limiters (FLEET-WIDE, DirectoryDO-backed — see fix #5 note below).
// ---------------------------------------------------------------------------------------

// FLEET-WIDE limiters (fix #5): the per-IP + per-email signup/login token buckets are backed by
// the global DirectoryDO singleton, NOT a per-isolate in-memory map. An in-memory store is diluted
// across ephemeral Workers isolates, so credential-stuffing simply spreads across isolates to dodge
// the cap; a DO-backed counter is strongly consistent system-wide.
//
// Four INDEPENDENT stores — one per bucket, each with a distinct `bucket` prefix. The signup and
// login lanes both key their per-email bucket as the literal `email:<email>` (and per-IP as
// `ip:<ip>`); without separate buckets signup and login would collide on those keys (and their
// different capacities would corrupt each other's counts). The prefix keeps the four disjoint.
//
// Each check-and-consume is one atomic DirectoryDO RPC, including concurrent isolates.
function signupLimiters(env: Env): SignupLimiters {
  return {
    signupIp: new RateLimiter(new DoRateLimitStore(env, "signupIp"), { capacity: 3, refillPerSec: 1 / 300 }),
    signupEmail: new RateLimiter(new DoRateLimitStore(env, "signupEmail"), { capacity: 2, refillPerSec: 1 / 600 }),
    loginIp: new RateLimiter(new DoRateLimitStore(env, "loginIp"), { capacity: 10, refillPerSec: 1 / 3 }),
    loginEmail: new RateLimiter(new DoRateLimitStore(env, "loginEmail"), { capacity: 5, refillPerSec: 1 / 12 }),
  };
}

// Build step 1 of ONBOARDING.md — `POST /v1/auth/join` / `GET /v1/auth/join/preview` limiters.
// Same fleet-wide DirectoryDO-backed shape + own bucket prefixes as signup (join provisions an
// account too, so it deserves the same abuse posture). Preview is a cheap read (no provisioning,
// no email send) so it gets a looser per-IP cap of its own.
interface JoinLimiters {
  joinIp: RateLimiter;
  joinEmail: RateLimiter;
}
function joinLimiters(env: Env): JoinLimiters {
  return {
    joinIp: new RateLimiter(new DoRateLimitStore(env, "joinIp"), { capacity: 3, refillPerSec: 1 / 300 }),
    joinEmail: new RateLimiter(new DoRateLimitStore(env, "joinEmail"), { capacity: 2, refillPerSec: 1 / 600 }),
  };
}
function joinPreviewLimiter(env: Env): RateLimiter {
  return new RateLimiter(new DoRateLimitStore(env, "joinPreview"), { capacity: 20, refillPerSec: 1 / 10 });
}

// FINDING #1: the password forgot/reset routes had NO rate limiting. They are dispatched by
// handleAuthRoutes BEFORE the index.ts preAuthLimiter (which only covers invite-redeem/share-resolve),
// so an attacker could call them unbounded: `forgot` sends a transactional EMAIL per request (email
// amplification + enumeration-timing oracle), and while `reset` carries a 256-bit token (brute force
// infeasible), the missing attempt cap removed a defense layer. We mirror the fleet-wide, DirectoryDO-
// backed login buckets (own `bucket` prefixes so they stay disjoint). Forgot is capped per-IP AND
// per-email (the costly side effect is the email send, keyed on the requested address); reset is
// capped per-IP (the token, not an address, is the credential). Caps are deliberately tight — a
// human resets rarely — and refill slowly. Checked BEFORE any directory lookup or email send.
interface ForgotLimiters {
  ip: RateLimiter;
  email: RateLimiter;
}
function forgotPasswordLimiters(env: Env): ForgotLimiters {
  return {
    ip: new RateLimiter(new DoRateLimitStore(env, "forgotIp"), { capacity: 5, refillPerSec: 1 / 60 }),
    email: new RateLimiter(new DoRateLimitStore(env, "forgotEmail"), { capacity: 3, refillPerSec: 1 / 300 }),
  };
}
function resetPasswordLimiter(env: Env): RateLimiter {
  return new RateLimiter(new DoRateLimitStore(env, "resetIp"), { capacity: 10, refillPerSec: 1 / 30 });
}

// Device-session lane rate limits (auth-spec §5.5) — fleet-wide, DirectoryDO-backed, each bucket
// with its own prefix so the four stay disjoint from each other AND from the login/signup buckets.
//   deviceApprove : per-account (a signed-in user approving devices) — 10 burst / 1 per 60s
//   deviceToken   : per-IP (public code exchange)                    — 10 burst / 1 per 6s
//   deviceRefresh : per-IP (public; a healthy app refreshes ~5/hr)   — 30 burst / 1 per 2s
//   daemonToken   : per-DEVICE-SESSION (the §2.7 mint)               —  5 burst / 1 per 600s
function deviceApproveLimiter(env: Env): RateLimiter {
  return new RateLimiter(new DoRateLimitStore(env, "deviceApprove"), { capacity: 10, refillPerSec: 1 / 60 });
}
function deviceTokenLimiter(env: Env): RateLimiter {
  return new RateLimiter(new DoRateLimitStore(env, "deviceToken"), { capacity: 10, refillPerSec: 1 / 6 });
}
function deviceRefreshLimiter(env: Env): RateLimiter {
  return new RateLimiter(new DoRateLimitStore(env, "deviceRefresh"), { capacity: 30, refillPerSec: 1 / 2 });
}
function daemonTokenLimiter(env: Env): RateLimiter {
  return new RateLimiter(new DoRateLimitStore(env, "daemonToken"), { capacity: 5, refillPerSec: 1 / 600 });
}

// ---------------------------------------------------------------------------------------
// Per-request config
// ---------------------------------------------------------------------------------------

/// Exported for the public-config route (auth-spec §2.8: `productName` joins the payload).
export function productName(env: Env): string {
  return env.PRODUCT_NAME ?? "cloud-fs";
}

/// Operator-tunable scrypt cost from env (`SCRYPT_COST_N`). `undefined` => use the frozen default.
/// Threaded into signup/login (rehash target) and the change/reset routes so every password is
/// hashed at the SAME cost and older hashes upgrade transparently on the next login.
function scryptCostForEnv(env: Env): ScryptCost | undefined {
  return scryptCostFromEnv(env);
}

/// Breached-password check options from env (`CHECK_BREACHED_PASSWORDS`). FINDING #2: the gate is
/// DEFAULT-OFF — the check runs only when the flag is explicitly "1"/"true" (off in dev/tests so the
/// suite never touches the network). Turn it ON in prod for defence-in-depth. Production uses the
/// platform fetch + the real HIBP endpoint. On an HIBP error the check now FAILS OPEN *and LOGS*
/// (see auth-password.ts `reportBreachError`) so a forced-but-misconfigured endpoint silently
/// no-opping is observable. SIGNUP stays fail-open (an outage must not lock out new users); the
/// deliberate, retryable change/reset routes pass `failClosed:true` (below) to reject on an outage.
function breachCheckForEnv(env: Env): BreachCheckOptions {
  const flag = env.CHECK_BREACHED_PASSWORDS;
  return { enabled: flag === "1" || flag === "true" };
}
export function baseUrl(env: Env, req: Request): string {
  return (env.PUBLIC_BASE_URL ?? new URL(req.url).origin).replace(/\/+$/, "");
}
/// Origin of the WEB APP (the browser SPA) for links a HUMAN clicks in email. Falls back to
/// PUBLIC_BASE_URL, then the request origin. Distinct from `baseUrl` (the Worker/API origin):
/// a human-clicked verification link must reach the SPA's GET-able page, not a POST-only API route.
/// Exported for the public-config route (auth-spec §2.8: the Mac app learns the portal origin here).
export function webBaseUrl(env: Env, req: Request): string {
  return (env.WEB_BASE_URL ?? env.PUBLIC_BASE_URL ?? new URL(req.url).origin).replace(/\/+$/, "");
}
/// Build the email VERIFICATION link a human clicks. Exported for regression coverage: it must
/// target the WEB APP's public `/verify-email` page (which POSTs {token, orgId} to the POST confirm
/// route), NOT the Worker's POST-only `/v1/auth/verify-email` API route — a GET there 401s.
export function buildVerifyUrl(env: Env, req: Request, orgId: string): (token: string) => string {
  const base = webBaseUrl(env, req);
  return (token) =>
    `${base}/verify-email?token=${encodeURIComponent(token)}&orgId=${encodeURIComponent(orgId)}`;
}
export function buildResetUrl(env: Env, req: Request, orgId: string): (token: string) => string {
  // Audit B11: the reset link must land on the WEB APP's /reset-password page (a human
  // clicks it), NOT the Worker/API origin which has no such page. Mirror buildVerifyUrl
  // (which already uses webBaseUrl); pre-fix this used baseUrl (the API origin), so the
  // forgot-password flow dead-ended in every topology.
  const base = webBaseUrl(env, req);
  return (token) =>
    `${base}/reset-password?token=${encodeURIComponent(token)}&orgId=${encodeURIComponent(orgId)}`;
}

export function passkeysConfigured(env: Env): boolean {
  const rp = env.WEBAUTHN_RP_ID?.trim();
  const origins = (env.WEBAUTHN_ORIGIN ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!rp || !/^[a-z0-9.-]+$/i.test(rp) || !origins.length) return false;
  return origins.some(origin => {
    try {
      const url = new URL(origin);
      return url.origin === origin && (url.protocol === "https:" || (url.protocol === "http:" && url.hostname === "localhost"))
        && (url.hostname === rp || url.hostname.endsWith(`.${rp}`));
    } catch { return false; }
  });
}

function webAuthnConfig(env: Env): WebAuthnConfig | null {
  if (!passkeysConfigured(env)) return null;
  const origins = (env.WEBAUTHN_ORIGIN ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  return {
    rpID: env.WEBAUTHN_RP_ID!,
    rpName: env.WEBAUTHN_RP_NAME ?? productName(env),
    expectedOrigin: origins.length === 1 ? origins[0] : origins,
  };
}

// ---------------------------------------------------------------------------------------
// Account store bound to a specific org, plus the directory for resolveEmail. Built from the
// AuthStores bundle (auth-stores.ts) — the lanes need exactly these methods.
// ---------------------------------------------------------------------------------------

function accountStoreFor(env: Env, orgId: string): SignupDeps["accounts"] {
  const stores = authStoresFor(env, orgId);
  return {
    resolveEmail: (email) => stores.accounts.resolveEmail(email),
    createAccount: (input) => stores.accounts.createAccount(input),
    getAccount: (id) => stores.accounts.getAccount(id),
    getAccountByUserId: (id) => stores.accounts.getAccountByUserId(id),
  };
}

/// Build the SignupDeps for a flow already bound to `orgId` (login, MFA). For signup the org is
/// created mid-flow, so we use the dedicated signup builder below.
async function loginDeps(env: Env, req: Request, orgId: string): Promise<SignupDeps> {
  const stores = authStoresFor(env, orgId);
  return {
    accounts: accountStoreFor(env, orgId),
    org: { createOrgWithOwner: () => Promise.reject(new Error("org provisioning not supported here")) },
    passwords: stores.credentials,
    sessions: stores.sessions,
    emailTokens: stores.emailTokens,
    // Runtime per-org config FIRST, then EMAIL_PROVIDER/env, then console/fake.
    emailSender: await emailSenderForOrg(env, orgId),
    totp: stores.credentials,
    // Passkey read so login can detect a WebAuthn second factor (CONTRACTS-AUTH.md §4.2).
    webauthn: stores.credentials,
    limiters: signupLimiters(env),
    buildVerifyUrl: buildVerifyUrl(env, req, orgId),
    productName: productName(env),
    ...(scryptCostForEnv(env) ? { scryptCost: scryptCostForEnv(env) } : {}),
  };
}

// ---------------------------------------------------------------------------------------
// Session resolver for the gateway hot path (auth.ts SessionResolver).
// ---------------------------------------------------------------------------------------

export function makeSessionResolver(env: Env): SessionResolver {
  return async (req, { requireCsrf }) => {
    const c = splitCookie(req);
    if (!c) return null;
    const stores = authStoresFor(env, c.orgId);
    try {
      const verified = await verifySession(reqWithBareCookie(req, c.sessionId), stores.sessions, env);
      if (requireCsrf) enforceCsrf(req, verified.session);
      return { jws: verified.jws };
    } catch (e) {
      if (e instanceof SessionError) throw new AuthError(e.message, e.status, e.code);
      throw e;
    }
  };
}

/// Union of revoked session + service jtis for an org (VerifyOptions.revokedJtis, §4.7), PLUS an
/// `errored` flag (FINDING #5). The revocation read used to swallow ALL AuthDO errors and return an
/// EMPTY set, which FAIL-OPENS: during an AuthDO blip a revoked-but-unexpired SERVICE TOKEN would be
/// admitted because its jti appeared "not revoked". We can't safely fail-open the service-token path
/// (a long-lived machine credential), so we surface the read failure to the caller and let it FAIL
/// CLOSED for every principal. An empty set with errored:true is never evidence of admission.
export async function gatewayRevokedJtis(
  env: Env,
  orgId: string,
): Promise<{ jtis: Set<string>; errored: boolean }> {
  try {
    const stores = authStoresFor(env, orgId);
    const [sess, svc] = await Promise.all([
      stores.sessions.revokedSessionJtis(),
      stores.serviceTokens.revokedServiceJtis(),
    ]);
    return { jtis: new Set<string>([...sess, ...svc]), errored: false };
  } catch {
    // Preserve the failure flag; callers must reject the unavailable authority.
    return { jtis: new Set<string>(), errored: true };
  }
}

/// Audit B21 — POINT-KEYED revocation check for ONE jti. Replaces the two full-list `revoked*Jtis()`
/// transfers (the whole org's revoked session + service ids) the per-request gate used to do, with a
/// single O(1) AuthDO RPC that checks BOTH tables for just the presented jti. Same fail-closed
/// semantics as `gatewayRevokedJtis`: an AuthDO error returns errored:true, and the caller rejects
/// every principal with 503 rather than admitting a credential against an unknowable state.
export async function gatewayJtiRevoked(
  env: Env,
  orgId: string,
  jti: string,
): Promise<{ revoked: boolean; errored: boolean }> {
  try {
    const stub = env.AUTH_DO.get(env.AUTH_DO.idFromName(orgId));
    const revoked = await stub.isJtiRevoked(jti);
    return { revoked, errored: false };
  } catch {
    return { revoked: false, errored: true };
  }
}

/// OFFBOARDING propagation to the AuthDO (FINDING 1+11). OrgDO `setUserStatus` only flips the OrgDO
/// directory row; on its own a deprovisioned/suspended user can still log in (the AuthDO Account is
/// still `active`) and live sessions/service tokens keep authenticating. This mirrors a non-active
/// status into the credential trust boundary so the block bites at BOTH the login path and every
/// live request:
///   - set the AuthDO Account status to match (login reads this and refuses),
///   - REVOKE all of the account's browser sessions (their ≤15-min JWS dies on the revocation gate),
///   - REVOKE all of the account's service tokens (same gate),
///   - on DEPROVISION (terminal), RELEASE the global directory email so it can be re-claimed.
/// Best-effort + idempotent: a no-AuthDO-account user (bootstrap/OIDC-only) simply has no sessions to
/// revoke. Status `active` is a no-op here (re-activation is handled by setUserStatus alone).
export async function propagateAccountOffboarding(
  env: Env,
  orgId: string,
  userId: string,
  status: "active" | "suspended" | "deprovisioned",
): Promise<void> {
  if (status === "active") return;
  const stores = authStoresFor(env, orgId);
  const account = await stores.accounts.getAccountByUserId(userId);
  if (account) {
    await stores.accounts.setStatus(account.id, status);
    // Revoke every browser session for this account so its residual JWS is rejected on the gate.
    const sessions = await stores.sessions.listSessions(account.id);
    await Promise.all(
      sessions
        .filter((s) => s.revokedAt === null)
        .map((s) => stores.sessions.revokeSession(s.id)),
    );
    // Audit B21: the per-isolate gate cache may hold a "not revoked" decision for one of THESE jtis
    // (jti == session.id). Drop this isolate's cached entries; other isolates and already
    // in-flight reads may retain the old answer until the 10-second gate TTL expires.
    for (const s of sessions) invalidateJti(orgId, s.id);
    // Device sessions (auth-spec §4.2): revoke every live one so the long-lived refresh token AND
    // its residual ≤15-min access JWS (jti == device-session id) die too. The daemon tokens those
    // sessions minted carry userId == THIS user, so the service-token sweep below revokes them.
    const devices = await stores.devices.listDeviceSessions(account.id);
    await Promise.all(
      devices
        .filter((d) => d.revokedAt === null)
        .map((d) => stores.devices.revokeDeviceSession(d.id, "account_inactive", Date.now())),
    );
    for (const d of devices) invalidateJti(orgId, d.id);
    if (status === "deprovisioned") {
      // Terminal: free the global email claim so the address can be re-used by a future account.
      await stores.accounts.releaseEmail(account.email).catch(() => {});
    }
  }
  // Service tokens are keyed by userId (the service-account identity), not accountId — revoke any
  // the offboarded user owns so machine credentials minted under them die too.
  const tokens = await stores.serviceTokens.listServiceTokens(orgId);
  const owned = tokens.filter((t) => t.userId === userId && !t.revoked);
  await Promise.all(owned.map((t) => stores.serviceTokens.revokeServiceToken(t.id)));
  // Audit B21: same as sessions — drop each revoked service-token jti from the gate cache so a
  // still-unexpired service JWS is rechecked locally. Other isolates remain TTL-bounded.
  for (const t of owned) invalidateJti(orgId, t.id);
}

/// True (= "blocked") when the principal's AuthDO Account exists and is NOT active (suspended/
/// deprovisioned). The gateway caches this fact for at most 10 seconds. A lookup failure returns
/// 503; a legacy bootstrap/OIDC principal without a local Account remains governed by its OrgDO
/// identity. An unavailable authority is never cached as an active account.
export async function isAccountInactive(env: Env, principal: Principal): Promise<boolean> {
  if (principal.type !== "session") return false; // machine/service tokens have no Account row
  try {
    const account = await authStoresFor(env, principal.orgId).accounts.getAccountByUserId(principal.sub);
    if (!account) return false;
    return account.status !== "active";
  } catch {
    throw new AuthError("account authorization unavailable", 503, "authorization_unavailable");
  }
}

/// Email-verification gate for the ROLE-gated org-admin plane (CONTRACTS-AUTH.md §4.2). The
/// reduced-scope half of the gate already blocks the SCOPE-gated filespace plane for an unverified
/// account; this closes the org-admin routes (create user/space/invite, etc.) which are gated by
/// ORG ROLE, not session scope, so reduced scopes alone wouldn't stop them.
///
/// Returns true (= "blocked") for a self-signup account whose email is unverified; the caller then
/// 403s `email_unverified`. Returns false (= "allowed") when:
///   - the principal is a machine/service token (machines aren't email accounts), OR
///   - there is no AuthDO Account for this user (bootstrap/OIDC users live only in OrgDO — they
///     aren't subject to the self-signup email gate), OR
///   - the account's email IS verified.
/// Lookup errors fail closed with 503; role alone cannot prove that this email was verified.
export async function isOrgMutationEmailBlocked(env: Env, principal: Principal): Promise<boolean> {
  if (principal.type !== "session") return false; // machines / service tokens are not email accounts
  try {
    const account = await authStoresFor(env, principal.orgId).accounts.getAccountByUserId(principal.sub);
    if (!account) return false; // no self-signup Account (e.g. bootstrap/OIDC user) → not gated
    return !account.emailVerified;
  } catch {
    throw new AuthError("account authorization unavailable", 503, "authorization_unavailable");
  }
}

// ---------------------------------------------------------------------------------------
// Authenticated-session context for session-gated routes.
// ---------------------------------------------------------------------------------------

interface SessionCtx {
  orgId: string;
  session: BrowserSession;
  account: Account;
  stores: AuthStores;
}

async function loadSessionCtx(env: Env, req: Request, requireCsrf: boolean): Promise<SessionCtx> {
  const c = splitCookie(req);
  if (!c) throw new AuthError("authentication required", 401, "no_session");
  const stores = authStoresFor(env, c.orgId);
  let verified;
  try {
    verified = await verifySession(reqWithBareCookie(req, c.sessionId), stores.sessions, env);
    if (requireCsrf) enforceCsrf(req, verified.session);
  } catch (e) {
    if (e instanceof SessionError) throw new AuthError(e.message, e.status, e.code);
    throw e;
  }
  const account = await stores.accounts.getAccount(verified.session.accountId);
  if (!account) throw new AuthError("account not found", 401, "no_account");
  // OFFBOARDING enforcement (FINDING 1+11): a suspended/deprovisioned account's live session is
  // rejected on the next request. The cookie is cleared via the AuthError → errorResponse path so
  // the dead session doesn't linger client-side.
  if (account.status !== "active") {
    throw new AuthError(`account is ${account.status}`, 401, "account_inactive");
  }
  if ((verified.session.authEpoch ?? 0) !== (account.authEpoch ?? 0)) {
    throw new AuthError("authentication changed; sign in again", 401, "authentication_changed");
  }
  return { orgId: c.orgId, session: verified.session, account, stores };
}

/// Step-up re-auth gate (FINDING 3) for SECURITY-SENSITIVE second-factor REMOVAL (disable TOTP /
/// delete a passkey). Session + CSRF alone are insufficient: an attacker riding a live session could
/// silently strip a victim's MFA. Mirroring `runChangePassword`, we require a fresh `currentPassword`
/// proof. The plaintext is verified (constant-time) against the account's stored scrypt credential;
/// a wrong/missing password throws 401 so removal is refused. An account with NO password credential
/// (e.g. passwordless/SSO-only) cannot satisfy this gate — it must use a different re-auth path; we
/// fail closed with `reauth_required` rather than silently allowing the removal.
async function requirePasswordStepUp(ctx: SessionCtx, req: Request): Promise<void> {
  const b = (await req.json().catch(() => ({}))) as { currentPassword?: string };
  if (typeof b.currentPassword !== "string" || b.currentPassword.length === 0) {
    throw new AuthError("currentPassword is required to remove a second factor", 401, "reauth_required");
  }
  const cred = await ctx.stores.credentials.getPassword(ctx.account.id);
  if (!cred) {
    throw new AuthError("re-authentication required", 401, "reauth_required");
  }
  const ok = await verifyPassword(cred, b.currentPassword);
  if (!ok) {
    throw new AuthError("current password is incorrect", 401, "bad_current_password");
  }
}

// ---------------------------------------------------------------------------------------
// Error → Response
// ---------------------------------------------------------------------------------------

/// Session-rejection error codes whose response should ALSO clear the `cfs_session` cookie so a
/// dead/invalid session doesn't linger client-side (FINDING 1+11: an offboarded session is rejected
/// AND cleared; also covers expired/idle/revoked + the missing-account case).
const CLEAR_COOKIE_CODES = new Set<string>([
  "account_inactive",
  "no_account",
  "not_found",
  "revoked",
  "expired",
  "idle",
]);

/// `secure` (FINDING #3) selects the cookie name when CLEARING a dead session so the cleared
/// cookie matches the one the browser holds (`__Host-cfs_session` over HTTPS, `cfs_session` over
/// http). Defaults to true (prefixed); callers with the request in scope pass the detected value.
function errorResponse(e: unknown, secure = true): Response {
  if (e instanceof SignupError) return signupErrorResponse(e);
  if (
    e instanceof AuthError ||
    e instanceof SessionError ||
    e instanceof PasswordError ||
    e instanceof TotpError ||
    e instanceof WebAuthnError ||
    e instanceof DeviceAuthError
  ) {
    const code = (e as { code?: string }).code ?? (e as Error).message;
    const extra = CLEAR_COOKIE_CODES.has(code) ? { "set-cookie": clearSessionCookie({ secure }) } : undefined;
    return json({ error: code }, (e as { status: number }).status, extra);
  }
  if ((e as Error)?.message === "authentication_changed" || (e as Error)?.message === "device_revoked") {
    return json({ error: "authentication_changed" }, 401);
  }
  return json({ error: "authentication_unavailable" }, 500);
}

// ---------------------------------------------------------------------------------------
// The /v1/auth/* dispatcher (pre-auth + session-gated; sits before the gateway bearer gate).
// ---------------------------------------------------------------------------------------

export async function handleAuthRoutes(req: Request, env: Env, p: string[]): Promise<Response | null> {
  if (p[0] !== "v1" || p[1] !== "auth") return null;
  const seg = p.slice(2);
  const method = req.method;
  const isMutation = MUTATING.has(method);

  try {
    // ===== PUBLIC =====
    // BUILT-IN-DISABLED gate: when the deployment auth mode is 'oidc' (external IdP only), the
    // built-in credential entry points — password signup/login (+MFA), forgot/reset — are REFUSED
    // with a clear `auth_mode_oidc` error (the SPA shows only the SSO button). 'both' allows either;
    // 'builtin' is the default. The mode is the RUNTIME auth-config (admin console), falling back to
    // the env (OIDC_* ⇒ 'both'). Session-gated routes (logout/me/password change/...) stay open so a
    // user who already has a session isn't locked out mid-flight.
    if (isBuiltinCredentialRoute(seg, method)) {
      const mode = await resolveAuthMode(env);
      if (mode === "oidc") {
        return json({ error: "auth_mode_oidc" }, 403);
      }
    }

    // NOTE: each handler is `return await` (not bare `return`) so a rejected promise is caught
    // by THIS try/catch and mapped via errorResponse — a bare `return runX()` would let the
    // rejection escape the gateway uncaught.
    if (seg[0] === "signup" && !seg[1] && method === "POST") return await runSignup(req, env);
    if (seg[0] === "password" && seg[1] === "enroll-legacy" && seg.length === 2 && method === "POST") {
      const limit = await resetPasswordLimiter(env).check(ipKey(req));
      if (!limit.allowed) return tooManyRequests(limit);
      const body = await req.json().catch(() => null) as { orgId?: unknown; token?: unknown; newPassword?: unknown } | null;
      if (!body || typeof body.orgId !== 'string' || !/^[a-z0-9][a-z0-9-]{0,62}$/.test(body.orgId) ||
          typeof body.token !== 'string' || body.token.length > 256 || typeof body.newPassword !== 'string') return json({ error: 'invalid_body' }, 400);
      assertAcceptablePassword(body.newPassword);
      await assertPasswordNotBreached(body.newPassword, { ...breachCheckForEnv(env), failClosed: true });
      return await completeLegacyAccount(env, body as { orgId: string; token: string; newPassword: string });
    }
    // Build step 1 of ONBOARDING.md: atomic invite-join (account + credential + membership +
    // grants + session in one call) and its public preview (join-page header). Both PUBLIC —
    // the invite token IS the credential for join, and preview leaks nothing beyond the invite's
    // own fields (no org enumeration).
    if (seg[0] === "join" && !seg[1] && method === "POST") return await runJoin(req, env);
    if (seg[0] === "join" && seg[1] === "preview" && method === "GET") return await runJoinPreview(req, env);
    if (seg[0] === "login" && !seg[1] && method === "POST") return await runLogin(req, env);
    // Device-session lane (auth-spec §2.3/§2.4/§2.7) — PUBLIC: the code+verifier / refresh token /
    // device access JWS IS the credential; each route verifies it itself. Per-IP / per-device
    // rate limits inside (§5.5).
    if (seg[0] === "device" && seg[1] === "token" && !seg[2] && method === "POST")
      return await runDeviceToken(req, env);
    if (seg[0] === "device" && seg[1] === "refresh" && !seg[2] && method === "POST")
      return await runDeviceRefresh(req, env);
    if (seg[0] === "device" && seg[1] === "daemon-token" && !seg[2] && method === "POST")
      return await runDeviceDaemonToken(req, env);
    if (seg[0] === "login" && seg[1] === "totp" && method === "POST") return await runLoginMfa(req, env, "totp");
    if (seg[0] === "login" && seg[1] === "recovery" && method === "POST") return await runLoginMfa(req, env, "recovery");
    if (seg[0] === "password" && seg[1] === "forgot" && method === "POST") return await runForgotPassword(req, env);
    if (seg[0] === "password" && seg[1] === "reset" && method === "POST") return await runResetPassword(req, env);
    if (seg[0] === "verify-email" && !seg[1] && method === "POST") return await runVerifyEmail(req, env);

    if (seg[0] === "webauthn") {
      const wa = seg.slice(1);
      const cfg = webAuthnConfig(env);
      if (!cfg) return json({ error: "not found" }, 404);
      const isPublicWa = wa[0] === "authenticate" && (wa[1] === "options" || wa[1] === "verify");
      if (isPublicWa) {
        // A passkey used as the SECOND factor after a password verify begins by POSTing the
        // single-use login challengeId (`<orgId>.mfa-…`) to `authenticate/options`. We consume
        // that login challenge HERE, bind the ceremony to the password-proven account, and emit
        // options scoped to that account's passkeys (CONTRACTS-AUTH.md §4.2/§4.4). The webauthn
        // challenge we return then carries the account binding, so `authenticate/verify` runs the
        // normal public path and only an assertion from THAT account's passkey mints the session.
        if (wa[1] === "options") {
          const sf = await consumeLoginMfaForWebAuthn(req, env);
          if (sf) return await runWebAuthnSecondFactor(req, env, wa, cfg, sf);
        }
        return await runWebAuthn(req, env, wa, cfg, null);
      }
      const ctx = await loadSessionCtx(env, req, isMutation);
      return await runWebAuthn(req, env, wa, cfg, ctx);
    }

    // ===== SESSION-GATED =====
    // Device approve (auth-spec §2.2): the signed-in portal user mints the one-time code.
    if (seg[0] === "device" && seg[1] === "approve" && !seg[2] && method === "POST")
      return await runDeviceApprove(req, env);
    // Device list / revoke (auth-spec §2.6) — account settings surface.
    if (seg[0] === "devices" && !seg[1] && method === "GET") return await runListDevices(req, env);
    if (seg[0] === "devices" && seg[1] && method === "DELETE")
      return await runRevokeDevice(req, env, decodeURIComponent(seg[1]));
    if (seg[0] === "logout" && !seg[1] && method === "POST") return await runLogout(req, env);
    if (seg[0] === "me" && !seg[1] && method === "GET") {
      // Native device/legacy clients have a bearer, not a browser cookie. Let
      // the normal gateway signature, revocation and account gates verify it.
      // An invalid bearer must not fall back to an unrelated browser session.
      if (req.headers.has("Authorization")) return null;
      return await runMe(req, env);
    }
    if (seg[0] === "account" && !seg[1] && method === "PATCH") return await runUpdateAccount(req, env);
    if (seg[0] === "sessions" && !seg[1] && method === "GET") return await runListSessions(req, env);
    if (seg[0] === "sessions" && seg[1] && method === "DELETE")
      return await runRevokeSession(req, env, decodeURIComponent(seg[1]));
    if (seg[0] === "password" && seg[1] === "change" && method === "POST") return await runChangePassword(req, env);
    if (seg[0] === "totp") return await runTotp(req, env, seg.slice(1));
    if (seg[0] === "verify-email" && seg[1] === "send" && method === "POST")
      return await runResendVerification(req, env);

    return null;
  } catch (e) {
    return errorResponse(e, secureCookies(env, req));
  }
}

// ---------------------------------------------------------------------------------------
// Service-token admin surface: /v1/orgs/:org/service-tokens[/:id] (bearer/cookie Principal).
// ---------------------------------------------------------------------------------------

export async function handleServiceTokenRoutes(
  req: Request,
  env: Env,
  principal: Principal,
  orgId: string,
  rest: string[],
): Promise<Response | null> {
  if (rest[0] !== "service-tokens") return null;
  const stores = authStoresFor(env, orgId);
  const role = await callerRole(env, principal);
  const deps: ServiceTokenDeps = {
    store: stores.serviceTokens,
    env,
    createServiceAccountUser: async ({ orgId: o, label }) => {
      const u = await env.ORG_DO.get(env.ORG_DO.idFromName(o)).createServiceAccount({ orgId: o, name: label });
      return { userId: u.id };
    },
  };
  try {
    if (rest[1] === undefined && req.method === "POST") {
      const b = (await req.json()) as {
        label: string;
        scopes: Scope[];
        spaceId?: string | null;
        serviceAccountUserId?: string;
        expiresAt?: number | null;
      };
      const ttlSeconds =
        b.expiresAt === undefined
          ? undefined
          : b.expiresAt === null
            ? null
            : Math.max(1, Math.floor((b.expiresAt - Date.now()) / 1000));
      const res = await mintServiceToken(deps, role as ServiceTokenRole, principal.sub, {
        orgId,
        label: b.label,
        scopes: b.scopes,
        spaceId: b.spaceId ?? null,
        serviceAccountUserId: b.serviceAccountUserId,
        ttlSeconds,
      });
      return json(
        { id: res.id, token: res.token, label: res.label, scopes: res.scopes, expiresAt: res.expiresAt },
        201,
      );
    }
    if (rest[1] === undefined && req.method === "GET") {
      return json(await listServiceTokens(deps, role as ServiceTokenRole, orgId));
    }
    if (rest[1] && req.method === "DELETE") {
      const tokenId = decodeURIComponent(rest[1]);
      await revokeServiceToken(deps, role as ServiceTokenRole, orgId, tokenId);
      // Audit B21: the service-token jti (== tokenId) may be cached as "not revoked" on the gate —
      // drop it here; other isolates may retain the prior decision for the gate TTL.
      invalidateJti(orgId, tokenId);
      return new Response(null, { status: 204 });
    }
    return json({ error: "not found" }, 404);
  } catch (e) {
    return errorResponse(e, secureCookies(env, req));
  }
}

async function callerRole(env: Env, principal: Principal): Promise<OrgRole> {
  try {
    const u = await env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId)).getUser(principal.sub);
    return u?.role ?? "standard";
  } catch {
    return "standard";
  }
}

// ---------------------------------------------------------------------------------------
// OIDC BROWSER-SSO callback (CONTRACTS-AUTH.md §4 / oidc.ts session-mint-on-callback pattern).
//
// The web flow needs a BROWSER SESSION + a 302 back to the SPA — NOT the bearer-token JSON the
// raw `handleOidcCallback` returns (that path is kept for API/test callers). This wrapper:
//   1. runs `handleOidcCallback` to validate state/code/id_token + find-or-provision the org user,
//   2. mints a `cfs_session` browser session IDENTICAL to the password-login path (createSession +
//      sessionLoginResponse + org-qualified cookie via qualifyCookie), and
//   3. 302-redirects to `<PUBLIC_BASE_URL>/auth/callback` with that cookie + the cleared cfs_oidc
//      cookie. On ANY OidcError it 302s to `…/auth/callback?error=<code>` instead (the SPA renders
//      the failure). Reusing the SAME session machinery means an OIDC session is indistinguishable
//      from a password-login session at the gateway.
// ---------------------------------------------------------------------------------------

/// The SPA path the gateway redirects the browser to after the OIDC round-trip completes.
const OIDC_WEB_CALLBACK_PATH = "/auth/callback";

function oidcWebRedirect(env: Env, req: Request, opts: { error?: string; setCookie?: string[] }): Response {
  // Audit B9: the post-SSO redirect must land on the WEB APP's /auth/callback page
  // (the SPA renders success/failure), NOT the Worker/API origin — on a split-origin
  // deployment PUBLIC_BASE_URL is the gateway, whose /auth/callback is a raw 401 JSON.
  // Mirror buildVerifyUrl/buildResetUrl which already use webBaseUrl.
  const base = webBaseUrl(env, req);
  const loc = opts.error
    ? `${base}${OIDC_WEB_CALLBACK_PATH}?error=${encodeURIComponent(opts.error)}`
    : `${base}${OIDC_WEB_CALLBACK_PATH}`;
  const headers = new Headers({ Location: loc });
  for (const c of opts.setCookie ?? []) headers.append("Set-Cookie", c);
  return new Response(null, { status: 302, headers });
}

/// Browser-SSO callback: validate the OIDC round-trip, mint a `cfs_session`, and 302 to the SPA.
/// `deps` carries the validated OidcConfig + the UserDirectory (+ optional fetch/now for tests).
/// Always returns a 302 (success → cookie + redirect; failure → `?error=<code>` redirect), so the
/// browser is never shown a raw JSON error.
export async function handleOidcWebCallback(req: Request, env: Env, deps: CallbackDeps): Promise<Response> {
  let user: DirectoryUser;
  let scopes: import("./security/auth").Scope[];
  let clearLoginCookie: string | null = null;
  try {
    const result = await handleOidcCallback(req, deps);
    user = result.user;
    scopes = result.scopes;
    // Re-use the cfs_oidc-clearing Set-Cookie the raw handler already built (it burns the one-time
    // login-state cookie) so the web flow cleans it up too.
    clearLoginCookie = result.response.headers.get("set-cookie");
  } catch (e) {
    const code = e instanceof OidcError ? e.code : "oidc_error";
    return oidcWebRedirect(env, req, { error: code });
  }

  // Mint a browser session in the user's org. OIDC users live in OrgDO and may have no AuthDO
  // Account; the session row needs an accountId, so we reuse an existing Account if one exists,
  // else fall back to the userId (the gateway hot path keys off userId/scopes, not accountId).
  const orgId = user.orgId;
  const stores = authStoresFor(env, orgId);
  const account = await stores.accounts.getAccountByUserId(user.id);
  const session = await stores.sessions.createSession({
    accountId: account?.id ?? user.id,
    authEpoch: account?.authEpoch,
    userId: user.id,
    orgId,
    scopes,
    csrfToken: generateCsrfToken(),
    expiresAt: Date.now() + ABSOLUTE_LIFETIME_MS,
  });
  const { setCookie } = sessionLoginResponse(session);
  const cookies = [qualifyCookie(setCookie, orgId, secureCookies(env, req))];
  if (clearLoginCookie) cookies.push(clearLoginCookie);
  return oidcWebRedirect(env, req, { setCookie: cookies });
}

// ---------------------------------------------------------------------------------------
// Route bodies — PUBLIC
// ---------------------------------------------------------------------------------------

/// True when the request arrived over https (a real deployment, not localhost dev).
/// Cloudflare terminates TLS, so the inbound URL's scheme is authoritative.
function isHttpsRequest(req: Request): boolean {
  try { return new URL(req.url).protocol === "https:"; } catch { return false; }
}

async function runSignup(req: Request, env: Env): Promise<Response> {
  // Deployment signup-mode gate (SIGNUP_MODE). Runs BEFORE provisioning anything — cheapest,
  // fail-closed. We peek at a CLONE of the body for the email + inviteToken so the lane's own
  // parse (which owns validation/dedupe/rate-limit) still consumes the real request body
  // unchanged. A malformed body falls through to the lane, which returns the proper 400.
  const peek = (await req.clone().json().catch(() => ({}))) as { email?: unknown; inviteToken?: unknown };
  const gateEmail = typeof peek.email === "string" ? canonicalEmail(peek.email) : "";
  const inviteToken = typeof peek.inviteToken === "string" ? peek.inviteToken : undefined;

  // Audit B7 — insecure-by-default tripwire. The committed dev config ships
  // SIGNUP_MODE="open", and the documented quickstart used to deploy it verbatim:
  // strangers got self-serve orgs that presign into the studio's default bucket. If
  // an https request (a real deployment, not localhost dev) arrives under "open"
  // mode, REFUSE signup with a clear operator-facing error unless the deployer has
  // explicitly opted in via SIGNUP_OPEN_ON_HTTPS=1. This converts a silent insecure
  // default into a loud, fail-closed stop.
  if (shouldRefuseOpenSignupOnHttps(env, isHttpsRequest(req))) {
    console.warn("[cloudfs] REFUSING open signup on an https deployment: SIGNUP_MODE=open is the DEV default. Set SIGNUP_MODE=invite (recommended) or SIGNUP_OPEN_ON_HTTPS=1 to intentionally allow public signup.");
    return json({
      error: "signup_disabled",
      reason: "Open self-serve signup is disabled on this deployment. The operator must set SIGNUP_MODE=invite (and hand out invite tokens) or explicitly enable open signup.",
    }, 403);
  }

  const gate = evaluateSignupGate(env, { email: gateEmail, inviteToken });
  if (!gate.allowed) {
    return json({ error: gate.code, reason: signupBlockReason(gate.code, gate.mode) }, gate.status);
  }

  // Signup creates the org mid-flow, so we build deps whose AccountStore + email/session stores
  // bind to the org the provisioner returns. We capture it via a one-shot closure.
  const provisioner = new DoOrgProvisioner(env);
  let boundOrgId: string | null = null;
  const accountsProxy: SignupDeps["accounts"] = {
    resolveEmail: (email) =>
      directoryStub(env).resolve(email) as Promise<{ orgId: string; accountId: string } | null>,
    createAccount: (input) => authStoresFor(env, requireBound(boundOrgId)).accounts.createAccount(input),
    getAccount: (id) => authStoresFor(env, requireBound(boundOrgId)).accounts.getAccount(id),
    getAccountByUserId: (id) => authStoresFor(env, requireBound(boundOrgId)).accounts.getAccountByUserId(id),
  };
  const deps: SignupDeps = {
    accounts: accountsProxy,
    org: {
      createOrgWithOwner: async (input) => {
        const res = await provisioner.createOrgWithOwner(input);
        boundOrgId = res.orgId;
        return res;
      },
    },
    passwords: lazyStore(env, () => requireBound(boundOrgId), "credentials"),
    sessions: lazyStore(env, () => requireBound(boundOrgId), "sessions"),
    emailTokens: lazyStore(env, () => requireBound(boundOrgId), "emailTokens"),
    emailSender: emailSenderFor(env),
    totp: lazyStore(env, () => requireBound(boundOrgId), "credentials"),
    limiters: signupLimiters(env),
    // buildVerifyUrl needs the org; it's known by the time the email lane calls it (post-provision).
    buildVerifyUrl: (token) => buildVerifyUrl(env, req, requireBound(boundOrgId))(token),
    productName: productName(env),
    ...(scryptCostForEnv(env) ? { scryptCost: scryptCostForEnv(env) } : {}),
    breachCheck: breachCheckForEnv(env),
  };
  const secure = secureCookies(env, req);
  try {
    const res = await handleSignup(req, deps);
    return json(res.body, res.status, { "set-cookie": qualifyCookie(res.setCookie, res.body.orgId, secure) });
  } catch (e) {
    return errorResponse(e, secure);
  }
}

// ---------------------------------------------------------------------------------------
// JOIN — POST /v1/auth/join + GET /v1/auth/join/preview  (Build step 1 of ONBOARDING.md)
//
// The invite-redeem gap this closes: `redeemInvite` (invites.ts) has only ever provisioned an
// OrgDO `User` row (+ optional ACL grant) — it never created an AuthDO `Account`/credential, so
// an invited teammate had org membership but no way to actually log in. `runJoin` is an ATOMIC
// composition of invites.ts's existing redeem logic with the same account/credential/session
// machinery `runSignup` uses, so one POST takes an invitee from token to a signed-in session.
//
// State machine:
//   (public request)
//        | rate-limit per IP  -- denied --> 429
//        v
//   validate body (token/displayName/password shape)  -- bad --> 400
//        |
//        v
//   split the ORG-QUALIFIED token ("<orgId>.inv-<id>.<secret>", same qualify/split scheme as the
//   device-code lane) and validate the invite (pure `validateInvite`, no mutation yet)
//        |                                                -- bad --> 404/409/410 (invites.ts's
//        |                                                   REDEEM_HTTP_STATUS, shared with the
//        |                                                   org-scoped redeem route)
//        v
//   rate-limit per invited email
//        |
//        v
//   directory dedupe pre-check (resolveEmail)  -- exists --> 409 email_taken (invite left PENDING
//        |                                                    — untouched, so it can be revoked
//        |                                                    or safely retried)
//        v
//   redeemInvite(...) — OrgDO User (create-or-reuse) + ACL grant + invite marked accepted
//        |                                                -- fails --> mapped RedeemError status
//        v
//   createAccount(emailVerified:true) — possession of the emailed single-use token IS the proof
//        | (claims the email globally; the AUTHORITATIVE dedupe, same as signup)
//        v
//   setPassword (scrypt, same as signup)
//        |
//        v
//   best-effort sync the invite's OrgDO grant into the target FilespaceDO's ACL store (mirrors
//   index.ts's `syncRedeemedGrant`, but AWAITED here — `handleAuthRoutes` has no ExecutionContext
//   to `waitUntil` against, and join is low-frequency enough that the extra RPC is cheap)
//        v
//   create BrowserSession with FULL role scopes (NOT the reduced unverified set — the token
//   already proved the email) + set cookie
//        v
//   201 { orgId, accountId, userId, role, scopes, emailVerified:true, state:"active", csrf }
//
// ATOMICITY (see the report for the full write-up): `redeemInvite` runs BEFORE the AuthDO
// account is created because `Account.userId` must reference an EXISTING OrgDO `User.id` — the
// OrgDO side has to exist first. If the OrgDO half lands but the AuthDO half then fails (a race
// on the global email claim, or a store error), we do NOT attempt a cross-DO rollback (the same
// accepted tradeoff `runSignup` makes when `createAccount` fails after `createOrgWithOwner`
// succeeds) — we log loudly (`console.error`, distinct from the best-effort `console.warn`s
// elsewhere in this file) so the gap is discoverable, and return a coherent error. A password-set
// failure after the account exists is the least bad of these: the account is real + email-verified,
// so the user can complete via the existing `POST /v1/auth/password/forgot` flow once the web
// join page points them at it.
// ---------------------------------------------------------------------------------------

export interface JoinBody {
  /** Org-qualified invite token from the join link (`CreateInviteResult.joinToken`). */
  token: string;
  displayName: string;
  password: string;
}

const MAX_JOIN_DISPLAY_NAME_LENGTH = 100;

/// Map an invite validation/redeem failure to the shared `{status, error}` shape (one source of
/// truth with the org-scoped `/v1/orgs/:org/invites/redeem` route via `REDEEM_HTTP_STATUS`).
function joinInviteErrorResponse(error: RedeemError): Response {
  return json({ error }, REDEEM_HTTP_STATUS[error]);
}

/// Same email_taken-vs-other classification `auth-signup.ts`'s (private) `mapEmailTaken` does,
/// duplicated here rather than imported (that helper isn't exported — CONTRACTS-AUTH.md keeps
/// lane internals private; the classification itself is a two-line regex, not worth widening the
/// lane's public surface for). A NON-email_taken failure at this point means the OrgDO half of
/// the join already landed (see the atomicity note above), so we log it loudly.
function isEmailTakenError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  const code = (err as { code?: unknown })?.code;
  return code === "email_taken" || /email[_\s-]?taken|already (in use|exists)/i.test(msg);
}

async function runJoin(req: Request, env: Env): Promise<Response> {
  const now = Date.now();
  const limiters = joinLimiters(env);
  const secure = secureCookies(env, req);

  const ipRl = await limiters.joinIp.check(ipKey(req));
  if (!ipRl.allowed) return tooManyRequests(ipRl);

  let body: Partial<JoinBody>;
  try {
    body = (await req.json()) as Partial<JoinBody>;
  } catch {
    return json({ error: "invalid_json" }, 400);
  }
  if (typeof body.token !== "string" || body.token.length === 0) {
    return json({ error: "invalid_token" }, 400);
  }
  if (typeof body.displayName !== "string" || body.displayName.trim().length === 0) {
    return json({ error: "invalid_display_name" }, 400);
  }
  const displayName = body.displayName.trim();
  if (displayName.length > MAX_JOIN_DISPLAY_NAME_LENGTH) {
    return json({ error: "invalid_display_name" }, 400);
  }
  // Light pre-check (mirrors `runSignup`'s `assertPasswordShape`) so a doomed request never
  // touches the invite/OrgDO/AuthDO — `setPassword` re-validates authoritatively below.
  if (typeof body.password !== "string" || body.password.length < 8) {
    return json({ error: "weak_password" }, 400);
  }
  if (body.password.length > 1024) {
    return json({ error: "password_too_long" }, 400);
  }
  const password = body.password;

  // Split the org-qualified token ("<orgId>.inv-<id>.<secret>") — same scheme + helper as the
  // device-code lane. A malformed/unqualified token addresses a bogus (but harmlessly empty)
  // OrgDO, so it falls through to `not_found` below rather than crashing.
  const qc = split(body.token);
  if (!qc) return json({ error: "not_found" }, 404);

  const parsed = await parseInviteToken(qc.handle);
  if (!parsed) return json({ error: "not_found" }, 404);

  const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(qc.orgId));
  const record = await orgStub.getInvite(parsed.inviteId);
  const check = validateInvite(record, parsed.tokenHash, now);
  if (!check.ok) {
    if (check.error === "expired" && record && record.status === "pending") {
      await orgStub.updateInviteStatus(record.id, "expired").catch(() => {});
    }
    return joinInviteErrorResponse(check.error);
  }
  const email = canonicalEmail(record!.email);

  const emailRl = await limiters.joinEmail.check(`email:${email}`);
  if (!emailRl.allowed) return tooManyRequests(emailRl);

  // Directory dedupe pre-check (fail fast + cheap, mirrors `runSignup`). The invite is left
  // PENDING on this path — nothing was mutated, so it can be revoked/reissued or retried.
  const existing = (await directoryStub(env).resolve(email)) as { orgId: string; accountId: string } | null;
  if (existing) {
    return json({ error: "email_taken" }, 409);
  }

  // Optional breached-password check (same policy/env gate as signup), BEFORE any provisioning.
  const breach = breachCheckForEnv(env);
  if (breach.enabled) {
    try {
      await assertPasswordNotBreached(password, breach);
    } catch (e) {
      if (e instanceof PasswordError) return json({ error: e.code }, e.status);
      throw e;
    }
  }

  // ---- OrgDO half: membership + ACL grant (reuses the existing redeem logic verbatim). ----
  const redeemed = await redeemInvite(env, qc.orgId, qc.handle, displayName);
  if (!redeemed.ok) return joinInviteErrorResponse(redeemed.error!);
  const userId = redeemed.userId!;
  const role = redeemed.scope!.role;

  // ---- AuthDO half: the credential-bearing Account, pre-verified (token possession proved the
  // address). From here on, an OrgDO membership already exists — see the atomicity note above. ----
  const stores = authStoresFor(env, qc.orgId);
  let account: Account;
  try {
    account = await stores.accounts.createAccount({
      orgId: qc.orgId, userId, email, displayName, role, emailVerified: true,
    });
  } catch (err) {
    if (isEmailTakenError(err)) {
      console.error({ event: "join_incomplete", stage: "email_claim" });
      return json({ error: "email_taken" }, 409);
    }
    console.error({ event: "join_incomplete", stage: "account_creation" });
    return json({ error: "join_incomplete" }, 500);
  }

  try {
    await setPassword(stores.credentials, account.id, password, { now, ...(scryptCostForEnv(env) ? { cost: scryptCostForEnv(env) } : {}) });
  } catch (e) {
    console.error({ event: "join_incomplete", stage: "password_creation" });
    if (e instanceof PasswordError) return json({ error: e.code }, e.status);
    return json({ error: "join_incomplete" }, 500);
  }

  // Best-effort: propagate the invite's OrgDO grant into the target FilespaceDO's ACL store
  // (mirrors index.ts's `syncRedeemedGrant`, but AWAITED — this handler has no ExecutionContext
  // to defer against, and join is low-frequency enough that the extra RPC is cheap). A failure
  // here never fails the join response: the grant is already durable in OrgDO and a later
  // admin action / sync can reconcile it.
  const grantSpaceId = redeemed.scope?.spaceId;
  if (redeemed.grantId && grantSpaceId && redeemed.scope?.inodeId) {
    try {
      const rows = await orgStub.grantsForPrincipal("user", userId);
      const g = (rows as any[]).find((r) => r.id === redeemed.grantId);
      if (g) {
        const fsStub = env.FILESPACE.get(env.FILESPACE.idFromName(filespaceDoName(qc.orgId, grantSpaceId)));
        await fsStub.syncGrant(g);
      }
    } catch {
      /* best-effort — the grant survives in OrgDO regardless */
    }
  }

  // Email is verified (the emailed single-use token proved it), so join grants FULL role scopes
  // immediately — never the reduced UNVERIFIED_SCOPES set signup starts with.
  const scopes: Scope[] = scopesForLogin(role, true);
  const session = await createBrowserSession(stores.sessions, { accountId: account.id, userId, orgId: qc.orgId, scopes, authEpoch: account.authEpoch }, now);
  const { setCookie, csrf } = sessionLoginResponse(session, now);

  return json(
    { orgId: qc.orgId, accountId: account.id, userId, role, scopes, emailVerified: true, state: "active", csrf },
    201,
    { "set-cookie": qualifyCookie(setCookie, qc.orgId, secure) },
  );
}

export interface JoinPreviewBody {
  orgName: string | null;
  email: string;
  role: OrgRole;
  expiresAt: number;
  invitedByName: string | null;
}

/// GET /v1/auth/join/preview?token=… — enough for the join page header, PUBLIC + rate-limited.
/// 404 for an unknown/malformed token, 410 for a used/expired/revoked one — never distinguishing
/// "no such org" from "no such invite in a real org" (both collapse to the SAME 404), so the
/// response never leaks whether an org exists.
async function runJoinPreview(req: Request, env: Env): Promise<Response> {
  const rl = await joinPreviewLimiter(env).check(ipKey(req));
  if (!rl.allowed) return tooManyRequests(rl);

  const token = new URL(req.url).searchParams.get("token");
  if (typeof token !== "string" || token.length === 0) return json({ error: "not_found" }, 404);

  const qc = split(token);
  if (!qc) return json({ error: "not_found" }, 404);
  const parsed = await parseInviteToken(qc.handle);
  if (!parsed) return json({ error: "not_found" }, 404);

  const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(qc.orgId));
  const record = await orgStub.getInvite(parsed.inviteId);
  const check = validateInvite(record, parsed.tokenHash, Date.now());
  if (!check.ok) {
    if (check.error === "not_found" || check.error === "token_mismatch") {
      return json({ error: "not_found" }, 404);
    }
    return json({ error: check.error }, 410); // expired | revoked | already_used
  }
  const rec = record!;

  const [orgName, inviter] = await Promise.all([
    orgStub.getOrgName().catch(() => null),
    orgStub.getUser(rec.createdByMemberId).catch(() => null),
  ]);

  const out: JoinPreviewBody = {
    orgName: orgName ?? null,
    email: rec.email,
    role: rec.role,
    expiresAt: rec.expiresAt,
    invitedByName: inviter?.displayName ?? null,
  };
  return json(out);
}

async function runLogin(req: Request, env: Env): Promise<Response> {
  // Resolve the org up front from the body email so all login reads bind correctly. If the email
  // doesn't resolve we still run the login lane (which timing-equalizes + returns invalid_credentials)
  // against a dummy org so response time/shape doesn't leak existence.
  const body = (await req.clone().json().catch(() => ({}))) as { email?: unknown };
  const email = typeof body.email === "string" ? canonicalEmail(body.email) : "";
  const resolved = email ? await directoryStub(env).resolve(email) : null;
  const orgId = (resolved as { orgId: string } | null)?.orgId ?? "org-__unresolved__";
  const deps = await loginDeps(env, req, orgId);
  const secure = secureCookies(env, req);
  try {
    const res = await handleLogin(req, deps);
    if (res.kind === "mfa") {
      // Embed the org in the challengeId so login/totp|recovery can find the right AuthDO without
      // the client knowing the org.
      return json({ ...res.body, challengeId: qualify(orgId, res.body.challengeId) }, res.status);
    }
    return json(res.body, res.status, { "set-cookie": qualifyCookie(res.setCookie, res.body.orgId, secure) });
  } catch (e) {
    return errorResponse(e, secure);
  }
}

async function runLoginMfa(req: Request, env: Env, kind: "totp" | "recovery"): Promise<Response> {
  const body = (await req.clone().json().catch(() => ({}))) as { challengeId?: unknown };
  const qc = split(body.challengeId);
  if (!qc) return json({ error: "invalid_challenge" }, 401);
  // Rewrite the request body so the lane sees the BARE challengeId it stored.
  const innerBody = { ...(body as object), challengeId: qc.handle };
  const innerReq = new Request(req.url, {
    method: req.method,
    headers: req.headers,
    body: JSON.stringify(innerBody),
  });
  const deps = await loginDeps(env, req, qc.orgId);
  const secure = secureCookies(env, req);
  try {
    const res =
      kind === "totp" ? await handleLoginTotp(innerReq, deps) : await handleLoginRecovery(innerReq, deps);
    return json(res.body, res.status, { "set-cookie": qualifyCookie(res.setCookie, res.body.orgId, secure) });
  } catch (e) {
    return errorResponse(e, secure);
  }
}

async function runForgotPassword(req: Request, env: Env): Promise<Response> {
  let email: string | undefined;
  try {
    const b = (await req.json()) as { email?: string };
    email = typeof b.email === "string" ? canonicalEmail(b.email) : undefined;
  } catch {
    /* 202 regardless */
  }
  // FINDING #1: rate-limit BEFORE any directory lookup or email send. Per-IP first (caps the abuse
  // source), then per-email (caps the costly per-address email amplification). Both buckets are keyed
  // on values present in EVERY request regardless of whether the email exists, so a 429 never leaks
  // account existence (the enumeration-safe 202 is otherwise constant-shape). 429 carries Retry-After.
  const limiters = forgotPasswordLimiters(env);
  const ipRl = await limiters.ip.check(ipKey(req));
  if (!ipRl.allowed) return tooManyRequests(ipRl);
  if (email) {
    const emailRl = await limiters.email.check(`email:${email}`);
    if (!emailRl.allowed) return tooManyRequests(emailRl);
  }
  if (email) {
    try {
      const resolved = (await directoryStub(env).resolve(email)) as { orgId: string; accountId: string } | null;
      if (resolved) {
        const stores = authStoresFor(env, resolved.orgId);
        const account = await stores.accounts.getAccount(resolved.accountId);
        if (account && account.status === "active") {
          const issued = await issueEmailToken(stores.emailTokens, {
            orgId: account.orgId,
            accountId: account.id,
            email: account.email,
            purpose: "password_reset",
          });
          await (await emailSenderForOrg(env, resolved.orgId)).sendTransactional({
            to: account.email,
            subject: `Reset your ${productName(env)} password`,
            text:
              `Reset your password by opening this link:\n\n` +
              `${buildResetUrl(env, req, account.orgId)(issued.token)}\n\n` +
              `This link expires soon and can only be used once. If you didn't request it, ignore this email.\n`,
          });
        }
      }
    } catch {
      /* never leak existence */
    }
  }
  return json({ ok: true }, 202);
}

async function runResetPassword(req: Request, env: Env): Promise<Response> {
  // FINDING #1: cap reset attempts per-IP BEFORE any token verify, as a brute-force defense layer
  // (the 256-bit token is already infeasible to guess, but the cap removes the unbounded-attempt
  // surface). Keyed on IP — the credential here is the token in the body, not an address. 429 + Retry-After.
  const resetRl = await resetPasswordLimiter(env).check(ipKey(req));
  if (!resetRl.allowed) return tooManyRequests(resetRl);
  const b = (await req.json().catch(() => ({}))) as { token?: string; newPassword?: string; orgId?: string };
  if (!b || typeof b !== "object") return json({ error: "invalid_body" }, 400);
  const orgId = b.orgId ?? new URL(req.url).searchParams.get("orgId") ?? undefined;
  if (typeof b.token !== "string" || typeof b.newPassword !== "string") {
    return json({ error: "token and newPassword are required" }, 400);
  }
  if (!orgId) return json({ error: "orgId is required" }, 400);
  // Policy failures must leave the reset link usable. In particular a typo or a
  // temporarily unavailable breached-password service must not consume the token.
  try {
    assertAcceptablePassword(b.newPassword);
    await assertPasswordNotBreached(b.newPassword, { ...breachCheckForEnv(env), failClosed: true });
  } catch (e) {
    if (e instanceof PasswordError) return json({ error: e.code }, e.status);
    throw e;
  }
  const stores = authStoresFor(env, orgId);
  const result = await verifyEmailToken(stores.emailTokens, b.token, "password_reset");
  if (!result.ok) return json({ error: result.error }, result.error === "expired" ? 410 : 400);
  const account = await stores.accounts.getAccount(result.record.accountId);
  if (!account || account.status !== "active") return json({ error: "account_inactive" }, 401);
  if (account.email !== result.record.email) return json({ error: "invalid_token" }, 400);
  try {
    await resetPassword(passwordRetirementStore(env, stores, account, undefined, result.record.email), result.record.accountId, b.newPassword, {
      ...(scryptCostForEnv(env) ? { cost: scryptCostForEnv(env) } : {}),
    });
  } catch (e) {
    if (e instanceof PasswordError) return json({ error: e.code }, e.status);
    throw e;
  }
  return new Response(null, { status: 204 });
}

async function runVerifyEmail(req: Request, env: Env): Promise<Response> {
  const b = (await req.json().catch(() => ({}))) as { token?: string; orgId?: string };
  const token = b.token ?? new URL(req.url).searchParams.get("token") ?? undefined;
  const orgId = b.orgId ?? new URL(req.url).searchParams.get("orgId") ?? undefined;
  if (typeof token !== "string") return json({ error: "token is required" }, 400);
  if (!orgId) return json({ error: "orgId is required" }, 400);
  const stores = authStoresFor(env, orgId);
  const res = await confirmEmailToken(stores.emailTokens, token);
  if (!res.ok) return json({ error: res.error }, res.error === "expired" ? 410 : 400);
  // The verified address and scope upgrade are one transaction: an old mailbox's
  // link must never verify a different address or elevate a later profile change.
  if (!await env.AUTH_DO.getByName(orgId).confirmEmailAddress(res.accountId, res.email)) {
    return json({ error: "invalid_token" }, 400);
  }
  return json({ verified: true });
}

// ---------------------------------------------------------------------------------------
// Route bodies — SESSION-GATED
// ---------------------------------------------------------------------------------------

async function runResendVerification(req: Request, env: Env): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, MUTATING.has(req.method));
  if (ctx.account.emailVerified) return json({ ok: true, alreadyVerified: true }, 202);
  await sendVerificationEmail(
    {
      store: ctx.stores.emailTokens,
      sender: await emailSenderForOrg(env, ctx.orgId),
      buildUrl: buildVerifyUrl(env, req, ctx.orgId),
    },
    {
      orgId: ctx.orgId,
      accountId: ctx.account.id,
      email: ctx.account.email,
      displayName: ctx.account.displayName,
      productName: productName(env),
    },
  );
  return json({ ok: true }, 202);
}

async function runLogout(req: Request, env: Env): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, MUTATING.has(req.method));
  await revokeBrowserSession(ctx.stores.sessions, ctx.session.id);
  // FINDING #3: clear the cookie under its per-transport name so the browser actually deletes it.
  return new Response(null, {
    status: 204,
    headers: { "set-cookie": clearSessionCookie({ secure: secureCookies(env, req) }) },
  });
}

async function runMe(req: Request, env: Env): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, false);
  // Read the org's display name from OrgDO (the org's stable slug is its id). Best-effort: a
  // missing/unset name surfaces as null without failing the call.
  const [totp, webauthn, orgName] = await Promise.all([
    ctx.stores.credentials.getTotp(ctx.account.id),
    ctx.stores.credentials.listWebAuthn(ctx.account.id),
    env.ORG_DO.get(env.ORG_DO.idFromName(ctx.orgId)).getOrgName().catch(() => null),
  ]);
  return json({
    userId: ctx.account.userId,
    orgId: ctx.account.orgId,
    email: ctx.account.email,
    displayName: ctx.account.displayName,
    role: ctx.account.role,
    scopes: ctx.session.scopes,
    emailVerified: ctx.account.emailVerified,
    orgName: orgName ?? null,
    orgSlug: ctx.account.orgId,
    // The double-submit CSRF token, so the SPA can re-hydrate it after a reload
    // (it's held only in memory). Without this, every mutation after a refresh 403s.
    csrf: ctx.session.csrfToken,
    mfa: { totp: !!(totp && totp.confirmed), webauthn: webauthn.length },
  });
}

/// PATCH /v1/auth/account — self-service profile update for the CURRENT session user. Body
/// `{ displayName?, email? }`. Session-gated + CSRF (it's a mutation). Updates the AuthDO account
/// row; on an email change it RE-CLAIMS the address in the global DirectoryDO index (409 if taken)
/// BEFORE writing the new email, and mirrors displayName/email into the OrgDO User row so the
/// directory/role record stays in sync. Changing the email resets `emailVerified` (the new address
/// is unproven). Returns the updated `/me`-shaped projection.
async function runUpdateAccount(req: Request, env: Env): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, true); // CSRF enforced on the mutation
  const b = (await req.json().catch(() => ({}))) as { displayName?: unknown; email?: unknown };

  const patch: { displayName?: string; email?: string } = {};
  if (b.displayName !== undefined) {
    if (typeof b.displayName !== "string" || b.displayName.trim().length === 0) {
      return json({ error: "invalid_display_name" }, 400);
    }
    if (b.displayName.trim().length > 100) return json({ error: "invalid_display_name" }, 400);
    patch.displayName = b.displayName.trim();
  }
  let newEmail: string | undefined;
  if (b.email !== undefined) {
    if (typeof b.email !== "string") return json({ error: "invalid_email" }, 400);
    const canon = canonicalEmail(b.email);
    if (canon.length === 0 || canon.length > 254 || !/^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(canon)) {
      return json({ error: "invalid_email" }, 400);
    }
    if (canon !== ctx.account.email) {
      patch.email = canon;
      newEmail = canon;
    }
  }
  if (patch.displayName === undefined && patch.email === undefined) {
    return json({ error: "nothing to update" }, 400);
  }

  // On an email change, RE-CLAIM the global directory entry FIRST (fail closed): if the address is
  // taken in any org, 409 before we mutate anything. The reclaim is idempotent for our own account.
  if (newEmail) {
    const outcome = await ctx.stores.accounts.reclaimEmail(ctx.account.email, newEmail, ctx.orgId, ctx.account.id);
    if (outcome === "taken") return json({ error: "email_taken" }, 409);
  }

  // Update the AuthDO account row. (Intra-org dupe is also guarded here; the directory claim above
  // is the authoritative cross-org guard.)
  let updated;
  try {
    updated = await ctx.stores.accounts.setAccountProfile(ctx.account.id, patch);
  } catch (e) {
    // If the local write fails after a successful directory re-claim, roll the claim back so the
    // user isn't stranded with the directory pointing at the new address but the account unchanged.
    if (newEmail) {
      await ctx.stores.accounts
        .reclaimEmail(newEmail, ctx.account.email, ctx.orgId, ctx.account.id)
        .catch(() => {});
    }
    const code = (e as { code?: string })?.code;
    if (code === "email_taken") return json({ error: "email_taken" }, 409);
    throw e;
  }
  if (!updated) return json({ error: "no_account" }, 401);

  // Mirror the change into the OrgDO User row (the directory/role record). Best-effort beyond the
  // authoritative AuthDO update; an OrgDO email collision is unexpected (the directory already
  // guards it) but is surfaced if it happens.
  try {
    await env.ORG_DO.get(env.ORG_DO.idFromName(ctx.orgId)).setUserProfile(ctx.account.userId, patch);
  } catch (e) {
    if (/already exists/i.test((e as Error)?.message ?? "")) {
      // Roll back: release the new directory claim + restore the account email so state is consistent.
      if (newEmail) {
        await ctx.stores.accounts
          .reclaimEmail(newEmail, ctx.account.email, ctx.orgId, ctx.account.id)
          .catch(() => {});
        await ctx.stores.accounts
          .setAccountProfile(ctx.account.id, { email: ctx.account.email })
          .catch(() => {});
      }
      return json({ error: "email_taken" }, 409);
    }
    throw e;
  }

  const orgName = await env.ORG_DO.get(env.ORG_DO.idFromName(ctx.orgId)).getOrgName().catch(() => null);
  return json({
    userId: updated.userId,
    orgId: updated.orgId,
    email: updated.email,
    displayName: updated.displayName,
    role: updated.role,
    emailVerified: updated.emailVerified,
    orgName: orgName ?? null,
    orgSlug: updated.orgId,
  });
}

async function runListSessions(req: Request, env: Env): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, false);
  return json(await listSessionsPublic(ctx.stores.sessions, ctx.account.id, ctx.session.id));
}

async function runRevokeSession(req: Request, env: Env, sessionId: string): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, true);
  const owned = await ctx.stores.sessions.listSessions(ctx.account.id);
  if (!owned.some((s) => s.id === sessionId)) return json({ error: "not_found" }, 404);
  await revokeBrowserSession(ctx.stores.sessions, sessionId);
  // Audit B21: drop the revoked session's jti from the gate cache (defense in depth — the cookie
  // resolver re-validates sessions independently, but a stale "not revoked" must never linger).
  invalidateJti(ctx.orgId, sessionId);
  return new Response(null, { status: 204 });
}

/** The only password-reset/change write path: commit and authorization retirement
 * share one SQLite transaction, with a generation fence against stale sign-ins. */
function passwordRetirementStore(env: Env, stores: AuthStores, account: Account, keepSessionId?: string,
    expectedEmail = account.email): PasswordStore {
  return {
    getPassword: id => stores.credentials.getPassword(id),
    deletePassword: id => stores.credentials.deletePassword(id),
    putPassword: async cred => {
      const retired = await env.AUTH_DO.getByName(account.orgId)
        .replacePasswordAndRetireSessions(cred, account.authEpoch ?? 0, keepSessionId, expectedEmail);
      for (const id of retired) invalidateJti(account.orgId, id);
    },
  };
}

async function runChangePassword(req: Request, env: Env): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, true);
  const b = (await req.json().catch(() => ({}))) as { currentPassword?: string; newPassword?: string };
  if (typeof b.currentPassword !== "string" || typeof b.newPassword !== "string") {
    return json({ error: "currentPassword and newPassword are required" }, 400);
  }
  try {
    // Optional breached-password check on the NEW password before re-hashing (no-op when the flag
    // is off). Rejects with 400 password_breached. FINDING #2: like reset, a change is deliberate +
    // retryable, so FAIL CLOSED (500 password_breach_check_unavailable) if the check is ON but HIBP errors.
    await assertPasswordNotBreached(b.newPassword, { ...breachCheckForEnv(env), failClosed: true });
    await changePassword(passwordRetirementStore(env, ctx.stores, ctx.account, ctx.session.id), ctx.account.id, b.currentPassword, b.newPassword, {
      ...(scryptCostForEnv(env) ? { cost: scryptCostForEnv(env) } : {}),
    });
  } catch (e) {
    if (e instanceof PasswordError) return json({ error: e.code }, e.status);
    throw e;
  }
  return new Response(null, { status: 204 });
}

async function runTotp(req: Request, env: Env, sub: string[]): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, MUTATING.has(req.method));
  const deps: TotpDeps = { store: ctx.stores.credentials, issuer: productName(env) };
  if (sub[0] === "enroll" && req.method === "POST") {
    return json(await enrollTotp(ctx.account.id, ctx.account.email, deps));
  }
  if (sub[0] === "confirm" && req.method === "POST") {
    const b = (await req.json().catch(() => ({}))) as { code?: string };
    if (typeof b.code !== "string") return json({ error: "code is required" }, 400);
    return json(await confirmTotp(ctx.account.id, b.code, deps));
  }
  if (sub[0] === undefined && req.method === "DELETE") {
    // FINDING 3: removing a second factor is step-up-gated (fresh password), like change-password.
    await requirePasswordStepUp(ctx, req);
    await disableTotp(ctx.account.id, deps);
    return new Response(null, { status: 204 });
  }
  return json({ error: "not found" }, 404);
}

// ---------------------------------------------------------------------------------------
// Device-session lane (auth-spec §2.2–§2.4, §2.6, §2.7) — route bodies.
// ---------------------------------------------------------------------------------------

/// Build the device lane's injected deps for one org (mirrors loginDeps).
function deviceAuthDeps(env: Env, orgId: string): DeviceAuthDeps {
  const stores = authStoresFor(env, orgId);
  return {
    store: stores.devices,
    accounts: { getAccount: (id) => stores.accounts.getAccount(id) },
    env,
  };
}

/// Revoke a device session AND cascade to the daemon service tokens it minted (§2.6): each
/// cascaded token is revoked + its jti dropped from the gate cache, and the device-session id
/// itself is invalidated so a residual ≤15-min device access JWS dies on the next request.
async function revokeDeviceSessionCascade(
  env: Env,
  orgId: string,
  deviceSessionId: string,
  reason: string,
): Promise<void> {
  const stores = authStoresFor(env, orgId);
  await stores.devices.revokeDeviceSession(deviceSessionId, reason, Date.now());
  invalidateJti(orgId, deviceSessionId);
  const tokens = await stores.serviceTokens.listServiceTokens(orgId);
  const cascade = tokens.filter((t) => t.deviceSessionId === deviceSessionId && !t.revoked);
  await Promise.all(cascade.map((t) => stores.serviceTokens.revokeServiceToken(t.id)));
  for (const t of cascade) invalidateJti(orgId, t.id);
}

/// POST /v1/auth/device/approve — cookie + CSRF gated (§2.2). Mints the single-use, PKCE-bound,
/// 5-min authorization code and returns it ORG-QUALIFIED ("<orgId>.dac-<id>.<secret>") so the
/// public exchange can address the right AuthDO without the app knowing the org.
async function runDeviceApprove(req: Request, env: Env): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, true); // CSRF enforced — it's a mutation
  const rl = await deviceApproveLimiter(env).check(`account:${ctx.account.id}`);
  if (!rl.allowed) return tooManyRequests(rl);
  const b = (await req.json().catch(() => ({}))) as {
    state?: unknown;
    codeChallenge?: unknown;
    codeChallengeMethod?: unknown;
    deviceName?: unknown;
    deviceModel?: unknown;
  };
  const res = await approveDevice(
    deviceAuthDeps(env, ctx.orgId),
    { accountId: ctx.account.id, userId: ctx.account.userId, orgId: ctx.orgId, authEpoch: ctx.account.authEpoch },
    {
      codeChallenge: b.codeChallenge,
      codeChallengeMethod: b.codeChallengeMethod,
      deviceName: b.deviceName,
      deviceModel: b.deviceModel,
    },
  );
  // `state` is the APP's CSRF binding — echoed verbatim for the SPA to append to the
  // cloudfs:// callback; the server stores nothing about it (§5.2).
  return json(
    {
      code: qualify(ctx.orgId, res.code),
      state: typeof b.state === "string" ? b.state : null,
      expiresInSeconds: res.expiresInSeconds,
    },
    201,
  );
}

/// POST /v1/auth/device/token — PUBLIC (§2.3): the code+PKCE-verifier IS the credential.
async function runDeviceToken(req: Request, env: Env): Promise<Response> {
  const rl = await deviceTokenLimiter(env).check(ipKey(req));
  if (!rl.allowed) return tooManyRequests(rl);
  const b = (await req.json().catch(() => ({}))) as { code?: unknown; codeVerifier?: unknown };
  const qc = split(b.code);
  if (!qc) return json({ error: "invalid_code" }, 400);
  const res = await exchangeDeviceCode(deviceAuthDeps(env, qc.orgId), {
    codeHandle: qc.handle,
    codeVerifier: b.codeVerifier,
  });
  const orgName = await env.ORG_DO.get(env.ORG_DO.idFromName(qc.orgId)).getOrgName().catch(() => null);
  return json({
    refreshToken: qualify(qc.orgId, res.refreshToken),
    accessToken: res.accessToken,
    accessTtlSeconds: res.accessTtlSeconds,
    orgId: qc.orgId,
    orgName: orgName ?? null,
    account: {
      email: res.account.email,
      displayName: res.account.displayName,
      role: res.account.role,
    },
    device: { id: res.session.id, name: res.session.deviceName },
  });
}

/// POST /v1/auth/device/refresh — PUBLIC (§2.4): rotate-on-use + race grace + reuse detection.
async function runDeviceRefresh(req: Request, env: Env): Promise<Response> {
  const rl = await deviceRefreshLimiter(env).check(ipKey(req));
  if (!rl.allowed) return tooManyRequests(rl);
  const b = (await req.json().catch(() => ({}))) as { refreshToken?: unknown };
  const qc = split(b.refreshToken);
  if (!qc) return json({ error: "invalid_refresh" }, 401);
  const res = await refreshDeviceSession(deviceAuthDeps(env, qc.orgId), { refreshHandle: qc.handle });
  return json({
    refreshToken: qualify(qc.orgId, res.refreshToken),
    accessToken: res.accessToken,
    accessTtlSeconds: res.accessTtlSeconds,
  });
}

/// POST /v1/auth/device/daemon-token (§2.7) — auth is a BEARER device access JWS, verified HERE
/// (this route sits before the gateway bearer gate): the jti must name a LIVE device session in
/// the token's org, bound to the same user. A browser session (jti = sess-…) or a pasted service
/// token (jti = svc-…) has no device row, so neither can mint. NO admin role required — the
/// device binding is the authorization; the scope ceiling + 30-day TTL are enforced in the lane.
async function runDeviceDaemonToken(req: Request, env: Env): Promise<Response> {
  const bearer = bearerFromRequest(req);
  if (!bearer) return json({ error: "unauthorized" }, 401);
  let principal;
  try {
    principal = await verifyToken(env.AUTH_SIGNING_SECRET, bearer);
  } catch {
    return json({ error: "unauthorized" }, 401);
  }
  const stores = authStoresFor(env, principal.orgId);
  const session = await stores.devices.getDeviceSession(principal.jti);
  if (!session || session.userId !== principal.sub) {
    return json({ error: "unauthorized" }, 401);
  }
  if (session.revokedAt !== null) return json({ error: "device_revoked" }, 401);
  if (Date.now() >= session.expiresAt) return json({ error: "device_expired" }, 401);

  const rl = await daemonTokenLimiter(env).check(`device:${session.id}`);
  if (!rl.allowed) return tooManyRequests(rl);

  const account = await stores.accounts.getAccount(session.accountId);
  if (!account || account.status !== "active") return json({ error: "account_inactive" }, 401);

  const deps: ServiceTokenDeps = {
    store: stores.serviceTokens,
    env,
    // Never reached: the daemon mint always reuses the HUMAN user (decision C). Kept for the
    // ServiceTokenDeps shape only.
    createServiceAccountUser: async ({ orgId: o, label }) => {
      const u = await env.ORG_DO.get(env.ORG_DO.idFromName(o)).createServiceAccount({ orgId: o, name: label });
      return { userId: u.id };
    },
  };
  const res = await mintDeviceDaemonToken(deps, {
    orgId: principal.orgId,
    userId: session.userId,
    deviceSessionId: session.id,
    deviceName: session.deviceName,
    deviceScopes: session.scopes,
  });
  // Token shown ONCE, as with the admin mint.
  return json({ id: res.id, token: res.token, expiresAt: res.expiresAt, scopes: res.scopes }, 201);
}

/// GET /v1/auth/devices — browser-session gated, read (§2.6). Refresh hashes never leave the DO.
async function runListDevices(req: Request, env: Env): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, false);
  const rows = await ctx.stores.devices.listDeviceSessions(ctx.account.id);
  return json({ devices: rows.map(toPublicDeviceSession) });
}

/// DELETE /v1/auth/devices/:id — browser-session + CSRF (§2.6). Ownership-checked (404 on a
/// foreign/unknown id — no existence leak), revokes + cascades to the device's daemon tokens.
async function runRevokeDevice(req: Request, env: Env, deviceSessionId: string): Promise<Response> {
  const ctx = await loadSessionCtx(env, req, true);
  const session = await ctx.stores.devices.getDeviceSession(deviceSessionId);
  if (!session || session.accountId !== ctx.account.id) return json({ error: "not_found" }, 404);
  await revokeDeviceSessionCascade(env, ctx.orgId, deviceSessionId, "user_revoked");
  return new Response(null, { status: 204 });
}

// ---------------------------------------------------------------------------------------
// WebAuthn
// ---------------------------------------------------------------------------------------

async function runWebAuthn(
  req: Request,
  env: Env,
  wa: string[],
  cfg: WebAuthnConfig,
  ctx: SessionCtx | null,
): Promise<Response> {
  const deps = webAuthnDeps(env, cfg, ctx?.orgId ?? null, false, secureCookies(env, req));
  const routeCtx = ctx
    ? {
        account: {
          id: ctx.account.id,
          userId: ctx.account.userId,
          orgId: ctx.account.orgId,
          email: ctx.account.email,
          displayName: ctx.account.displayName,
          role: ctx.account.role,
        },
      }
    : {};
  // FINDING 3: removing a passkey (DELETE credentials/:id) is step-up-gated (fresh password),
  // mirroring change-password / TOTP-disable. Session + CSRF alone let a live-session attacker strip
  // a victim's second factor. We verify HERE (before delegating) since the lane's DELETE doesn't read
  // the body. `ctx` is always present on this session-gated route.
  if (ctx && req.method === "DELETE" && wa[0] === "credentials" && typeof wa[1] === "string" && wa[2] === undefined) {
    await requirePasswordStepUp(ctx, req);
  }
  const res = await handleWebAuthn(req, deps, wa, routeCtx);
  if (res === null) return json({ error: "not found" }, 404);
  return res;
}

/// A passkey-as-second-factor binding resolved from a single-use login challenge.
interface SecondFactorBinding {
  orgId: string;
  accountId: string;
}

/// If the inbound `authenticate/options` body carries a qualified login-MFA challengeId
/// (`<orgId>.mfa-…`), CONSUME it (single-use) and return the bound { orgId, accountId } so the
/// webauthn ceremony can be scoped to the password-proven account. Returns null when the body
/// carries no such challenge (the normal passwordless `{ email }` flow). A malformed/expired/
/// wrong-purpose login challenge also returns null, so the request falls through to the normal
/// public path (which will simply 200 with empty options — non-enumerating).
async function consumeLoginMfaForWebAuthn(req: Request, env: Env): Promise<SecondFactorBinding | null> {
  const body = (await req.clone().json().catch(() => ({}))) as { challengeId?: unknown };
  const qc = split(body.challengeId);
  // Only a login-MFA handle (`mfa-…`) triggers the second-factor path; a bare webauthn handle
  // (`wch-…`) or no challengeId means the ordinary passwordless flow.
  if (!qc || !qc.handle.startsWith("mfa-")) return null;
  const stores = authStoresFor(env, qc.orgId);
  const challenge = await stores.credentials.takeChallenge(qc.handle); // single-use
  if (!challenge || challenge.purpose !== "login_mfa" || challenge.accountId === null) return null;
  if (Date.now() >= challenge.expiresAt) return null;
  return { orgId: qc.orgId, accountId: challenge.accountId };
}

/// Run the passkey-as-second-factor `authenticate/options` step. The login challenge is already
/// consumed; we bind the ceremony to its account, list that account's passkeys, and store the
/// webauthn challenge in the fallback bucket (so the separate, org-less verify request finds it).
async function runWebAuthnSecondFactor(
  req: Request,
  env: Env,
  wa: string[],
  cfg: WebAuthnConfig,
  sf: SecondFactorBinding,
): Promise<Response> {
  const deps = webAuthnDeps(env, cfg, sf.orgId, /* forceFallbackChallenges */ true, secureCookies(env, req));
  const res = await handleWebAuthn(req, deps, wa, { secondFactor: { accountId: sf.accountId } });
  if (res === null) return json({ error: "not found" }, 404);
  return res;
}

/// A stable fallback AuthDO bucket for storing WebAuthn challenges that have no resolvable org
/// yet — the public `authenticate/options` flow for an UNKNOWN email (non-enumeration: we must
/// still 200 with options). Such a challenge can only ever be completed by a credential that
/// resolves to a real account, and `authenticate/verify` reads the challenge from the SAME
/// fallback bucket (the email-mode verify carries no org), so the round-trip stays consistent.
const WEBAUTHN_FALLBACK_ORG = "__webauthn_orphan__";

/// WebAuthn deps. For email-mode public auth, `resolveEmail` binds the org via the directory; for
/// session flows the org is fixed; for an unknown email the challenge lives in the fallback
/// bucket. `mintForAccount` writes the session in the account's own org and returns an
/// org-qualified cookie directly.
function webAuthnDeps(
  env: Env,
  cfg: WebAuthnConfig,
  sessionOrgId: string | null,
  forceFallbackChallenges = false,
  secure = true, // FINDING #3: per-transport session-cookie name for mintForAccount's Set-Cookie.
): WebAuthnDeps {
  const orgRef: { id: string | null } = { id: sessionOrgId };
  // Challenge storage: SESSION flows (register; sessionOrgId set) store in the caller's org so
  // the register/verify pair round-trips there. PUBLIC authenticate flows (sessionOrgId null)
  // ALWAYS use the fallback bucket — `authenticate/verify` carries no org cookie, so storing the
  // options-step challenge in a fixed bucket is the only place verify can reliably find it; the
  // real account/org is recovered separately from the asserting credential id.
  // `forceFallbackChallenges` is set for the passkey-as-second-factor `options` step: the org IS
  // known (so we can list the account's passkeys), but the SEPARATE public verify request still
  // carries no org, so the webauthn challenge must live in the fallback bucket for verify to find.
  const isPublicFlow = sessionOrgId === null || forceFallbackChallenges;
  const challengeOrg = () => (isPublicFlow ? WEBAUTHN_FALLBACK_ORG : orgRef.id ?? WEBAUTHN_FALLBACK_ORG);

  const accounts: WebAuthnDeps["accounts"] = {
    resolveEmail: async (emailLower) => {
      const r = (await directoryStub(env).resolve(emailLower)) as { orgId: string; accountId: string } | null;
      if (r) orgRef.id = r.orgId;
      return r;
    },
    getAccount: async (accountId) => {
      if (!orgRef.id) return null;
      const a = await authStoresFor(env, orgRef.id).accounts.getAccount(accountId);
      return a
        ? { id: a.id, userId: a.userId, orgId: a.orgId, role: a.role, status: a.status, emailVerified: a.emailVerified, authEpoch: a.authEpoch }
        : null;
    },
  };

  const store: WebAuthnDeps["store"] = {
    listWebAuthn: (id) => authStoresFor(env, requireOrg(orgRef)).credentials.listWebAuthn(id),
    // On `authenticate/verify` the org is unknown (no cookie carries it). Resolve it from the
    // DirectoryDO's credential->org index, bind it, then read the row from that org's AuthDO.
    getWebAuthnByCredentialId: async (cid) => {
      if (!orgRef.id) {
        const idx = (await directoryStub(env).resolveWebAuthn(cid)) as
          | { orgId: string; accountId: string }
          | null;
        if (!idx) return null;
        orgRef.id = idx.orgId;
      }
      return authStoresFor(env, orgRef.id).credentials.getWebAuthnByCredentialId(cid);
    },
    // Persist the row in the account's org AND index it globally so passwordless verify can find
    // its home org later. Index FIRST so a credential id already bound to a DIFFERENT account
    // (fix #6) is rejected with a 409 BEFORE we write the AuthDO row (no dangling row on conflict).
    putWebAuthn: async (cred) => {
      const org = requireOrg(orgRef);
      const idx = await directoryStub(env).indexWebAuthn(cred.credentialId, org, cred.accountId);
      if (idx === "conflict") {
        throw new WebAuthnError("credential already registered", 409, "credential_exists");
      }
      await authStoresFor(env, org).credentials.putWebAuthn(cred);
    },
    updateWebAuthnSignCount: (id, c, t) =>
      authStoresFor(env, requireOrg(orgRef)).credentials.updateWebAuthnSignCount(id, c, t),
    // Delete the AuthDO row. We deliberately leave the DirectoryDO credential->org index entry:
    // it is self-healing on read (a `resolveWebAuthn` hit followed by a now-missing AuthDO row
    // makes `getWebAuthnByCredentialId` return null, so verify reports "unknown credential"),
    // and avoiding the extra lookup keeps delete a single point write.
    deleteWebAuthn: (id) => authStoresFor(env, requireOrg(orgRef)).credentials.deleteWebAuthn(id),
    // Challenges tolerate the orphan bucket so the unknown-email options call still 200s.
    putChallenge: (c) => authStoresFor(env, challengeOrg()).credentials.putChallenge(c),
    takeChallenge: (id) => authStoresFor(env, challengeOrg()).credentials.takeChallenge(id),
  };

  const session: WebAuthnDeps["session"] = {
    mintForAccount: async (input) => {
      const stores = authStoresFor(env, input.orgId);
      // Reduced read-only scopes while the email is unverified (CONTRACTS-AUTH.md §4.2 gate);
      // full role scopes once verified — mirrors the password-login + signup paths.
      const scopes: Scope[] = scopesForLogin(input.role as OrgRole, input.emailVerified ?? true);
      const created = await stores.sessions.createSession({
        accountId: input.accountId,
        authEpoch: input.authEpoch,
        userId: input.userId,
        orgId: input.orgId,
        scopes,
        csrfToken: generateCsrfToken(),
        expiresAt: Date.now() + 12 * 60 * 60 * 1000,
      });
      const { setCookie, csrf } = sessionLoginResponse(created);
      return {
        setCookie: qualifyCookie(setCookie, input.orgId, secure),
        body: { userId: input.userId, orgId: input.orgId, role: input.role, scopes, csrf },
      };
    },
  };

  return { store, accounts, config: cfg, session };
}

function requireOrg(ref: { id: string | null }): string {
  if (!ref.id) throw new WebAuthnError("could not resolve account org", 400, "no_org");
  return ref.id;
}

// ---------------------------------------------------------------------------------------
// Small lazy-store helpers (signup binds the org mid-flow).
// ---------------------------------------------------------------------------------------

function requireBound(orgId: string | null): string {
  if (!orgId) throw new SignupError("internal: org not bound", 500, "internal");
  return orgId;
}

/// A store proxy that resolves the org lazily at call time (used by signup before/after the org
/// is provisioned). `key` selects which sub-store of the AuthStores bundle to forward to.
function lazyStore<K extends "credentials" | "sessions" | "emailTokens">(
  env: Env,
  getOrg: () => string,
  key: K,
): AuthStores[K] {
  const handler: ProxyHandler<object> = {
    get(_t, prop) {
      const target = authStoresFor(env, getOrg())[key] as unknown as Record<string | symbol, unknown>;
      const v = target[prop];
      return typeof v === "function" ? (v as (...a: unknown[]) => unknown).bind(target) : v;
    },
  };
  return new Proxy({}, handler) as AuthStores[K];
}
