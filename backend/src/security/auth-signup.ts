// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs self-serve SIGNUP + LOGIN composition lane (CONTRACTS-AUTH.md §4.1, §4.2).
///
/// This lane owns NO primitives. It COMPOSES the frozen primitive lanes into the two
/// public, pre-auth entrypoints of the system:
///
///   POST /v1/auth/signup       — open self-serve org creation + first owner account.
///   POST /v1/auth/login        — email+password -> session OR a 2FA challenge.
///   POST /v1/auth/login/totp   — completes a 2FA challenge with an authenticator code.
///   POST /v1/auth/login/recovery — completes a 2FA challenge with a recovery code.
///
/// What it reuses (never reimplements):
///   - auth-password.ts  : scrypt hash/verify (`setPassword`, `verifyAccountPassword`,
///                         `assertAcceptablePassword` via `setPassword`'s own check),
///                         constant-time compare (inside `verifyPassword`).
///   - auth-session.ts   : `createBrowserSession` (cookie + CSRF), `sessionLoginResponse`.
///   - auth-email.ts     : `sendVerificationEmail` (issues a single-use, hash-bound token
///                         and dispatches via the injected `EmailSender`).
///   - auth-totp.ts      : `verifyLoginTotp` / `verifyRecoveryCode` (the 2FA second factor).
///   - ratelimit.ts      : `RateLimiter` token buckets for per-IP + per-email abuse caps.
///   - auth.ts           : `Scope` (via the session lane) — tokens are minted by the session lane.
///   - oidc.ts           : `scopesForRole` — single source of truth for role -> scopes.
///
/// ABUSE CONTROLS (CONTRACTS-AUTH.md §4 "Auth: public" routes are rate-limited):
///   1. Per-IP AND per-email token buckets on BOTH signup and login, checked BEFORE any
///      privileged work (org create, scrypt verify, email send). Denied -> 429.
///   2. Dedupe: `AccountStore.createAccount` claims the email in the global directory and
///      throws `email_taken`; signup maps that to 409 with a generic body (no enumeration of
///      WHICH org owns it).
///   3. Email-verification gate: a freshly-signed-up owner account is `emailVerified:false`.
///      `assertEmailVerified` is exported for downstream privileged routes to gate on it; the
///      account can hold a session (to drive the "verify your email" UI) but cannot perform a
///      privileged action until verified.
///   4. Login is enumeration-safe: a missing account, a missing password credential, and a
///      wrong password all collapse to the SAME generic 401 (`invalid_credentials`). We still
///      run a scrypt verify against a dummy credential on the no-account path so the response
///      time does not leak account existence (timing-equalization).
///
/// WORKERS-CORRECTNESS: no Node built-ins. All randomness/ids via WebCrypto (`crypto.*`) —
/// inherited from the primitive lanes. All clocks/randomness/fetch are injectable so the unit
/// tests are deterministic with zero real network. Secret comparisons are constant-time (done
/// inside the password + session + email + totp lanes we call).

import {
  setPassword,
  verifyAccountPassword,
  hashPassword,
  assertPasswordNotBreached,
  type PasswordStore,
  type ScryptCost,
  type BreachCheckOptions,
} from "./auth-password";
import {
  createBrowserSession,
  sessionLoginResponse,
  type SessionStore,
  type BrowserSession,
} from "./auth-session";
import {
  sendVerificationEmail,
  type EmailTokenStore,
  type EmailSender,
  type TokenDeps,
} from "./auth-email";
import { verifyLoginTotp, verifyRecoveryCode, type TotpCredentialStore } from "./auth-totp";
import { RateLimiter } from "./ratelimit";
import { scopesForRole, type OrgRole } from "./oidc";
import type { Scope } from "./auth";

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

export class SignupError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 401 | 403 | 409 | 429 | 500 = 400,
    readonly code: string = "signup_error",
    /// Optional Retry-After (seconds) for 429s, surfaced as a header by `toResponse`.
    readonly retryAfterSec?: number,
  ) {
    super(message);
    this.name = "SignupError";
  }
}

// ---------------------------------------------------------------------------------------
// Shapes shared with this lane (mirrors the frozen CONTRACTS-AUTH.md types so the lane is
// self-contained until the integration agent's `auth-types.ts` exists; the integration
// adapter structurally satisfies these). Email is THE username; stored lowercased+trimmed.
// ---------------------------------------------------------------------------------------

export type AccountRole = OrgRole; // "owner" | "admin" | "space_admin" | "standard"
export type AccountStatus = "active" | "suspended" | "deprovisioned";

export interface Account {
  authEpoch?: number;
  id: string; //            "acc-<uuid>"
  userId: string; //        the OrgDO `User.id` ("usr-..."); Principal.sub uses THIS.
  orgId: string;
  email: string; //         canonical (lowercased+trimmed).
  displayName: string;
  role: AccountRole;
  status: AccountStatus;
  emailVerified: boolean;
  createdAt: number;
}

/// The `AccountStore` slice this lane needs (CONTRACTS-AUTH.md §2). `createAccount` claims the
/// email in the global directory and MUST throw (any error / `email_taken`) on collision.
export interface AccountStore {
  resolveEmail(emailLower: string): Promise<{ orgId: string; accountId: string } | null>;
  createAccount(input: {
    orgId: string;
    userId: string;
    email: string;
    displayName: string;
    role: AccountRole;
    emailVerified?: boolean;
  }): Promise<Account>;
  getAccount(accountId: string): Promise<Account | null>;
  getAccountByUserId(userId: string): Promise<Account | null>;
}

/// The minimal passkey-read slice login needs to decide whether a WebAuthn second factor exists
/// (CONTRACTS-AUTH.md §2 `CredentialStore.listWebAuthn`). We only need "does this account have ≥1
/// registered passkey?", so we narrow to the single read method and ignore the credential bodies.
export interface LoginWebAuthnStore {
  listWebAuthn(accountId: string): Promise<unknown[]>;
}

/// Provision the OrgDO side of a signup: a brand-new org plus its first `owner` human user.
/// Integration provides the real OrgDO-backed adapter; the unit tests inject an in-memory fake.
/// Kept separate from `AccountStore` because the org/user directory is the OrgDO's domain, while
/// the credential-bearing `Account` is the AuthDO's — see CONTRACTS-AUTH.md §1 KEY DECISIONS.
export interface OrgProvisioner {
  createOrgWithOwner(input: {
    orgName: string;
    ownerEmail: string; //   canonical (lowercased+trimmed)
    ownerDisplayName: string;
  }): Promise<{ orgId: string; userId: string }>;
}

// ---------------------------------------------------------------------------------------
// Rate-limit policy (frozen defaults; overridable for tests/policy)
// ---------------------------------------------------------------------------------------

/// Per-IP signup cap: org creation is expensive + abusable for resource exhaustion. A burst of
/// 3, refilling slowly (1 per 5 min) — generous for a human, hostile to a bot farm.
export const SIGNUP_IP_LIMIT = { capacity: 3, refillPerSec: 1 / 300 };
/// Per-email signup cap: blunts repeated attempts to grab the same address / hammer the
/// directory. Tighter than IP because one email = one account, system-wide.
export const SIGNUP_EMAIL_LIMIT = { capacity: 2, refillPerSec: 1 / 600 };

/// Per-IP login cap: a burst of 10, refilling 1/3s. Allows fat-fingering + a few tabs while
/// bounding credential-stuffing from a single source.
export const LOGIN_IP_LIMIT = { capacity: 10, refillPerSec: 1 / 3 };
/// Per-email login cap: 5 burst, 1/12s refill — slows an online password-guess against one
/// account without locking a legitimate user out for long.
export const LOGIN_EMAIL_LIMIT = { capacity: 5, refillPerSec: 1 / 12 };

/// The limiter set the handlers consume. Integration backs these stores with a DO for fleet-wide
/// limits; tests pass in-memory limiters. Two independent buckets per action (IP and email) so
/// neither dimension alone can exhaust the other.
export interface SignupLimiters {
  signupIp: RateLimiter;
  signupEmail: RateLimiter;
  loginIp: RateLimiter;
  loginEmail: RateLimiter;
}

// ---------------------------------------------------------------------------------------
// Dependencies (constructor/param injection — never a concrete DO; CONTRACTS-AUTH.md §2/§3)
// ---------------------------------------------------------------------------------------

export interface SignupDeps {
  accounts: AccountStore;
  org: OrgProvisioner;
  passwords: PasswordStore;
  sessions: SessionStore;
  emailTokens: EmailTokenStore;
  emailSender: EmailSender;
  totp: TotpCredentialStore;
  /// Read-only passkey lookup so login can detect a WebAuthn second factor (CONTRACTS-AUTH.md
  /// §4.2: "confirmed TOTP OR passkeys → mfaRequired"). Optional so unit tests that don't
  /// exercise passkeys can omit it; absence is treated as "no passkeys registered".
  webauthn?: LoginWebAuthnStore;
  limiters: SignupLimiters;
  /// Turn a freshly-issued clear email token into the public verification link. Origin/path
  /// policy lives in integration, not here (mirrors `sendVerificationEmail`'s `buildUrl`).
  buildVerifyUrl: (token: string) => string;
  /// Product name for email copy + the otpauth issuer; defaults handled by the email lane.
  productName?: string;
  /// Operator-tunable scrypt cost for the password the new owner sets at signup. Defaults to the
  /// frozen `SCRYPT_PARAMS` when omitted (integration threads `scryptCostFromEnv(env)`). Threaded
  /// here so a signup hashes at the SAME cost as a later login's `needsRehash` target.
  scryptCost?: ScryptCost;
  /// Optional breached-password check (HIBP k-anonymity). When `enabled`, a known-breached signup
  /// password is rejected with `password_breached` BEFORE the org/account is provisioned. Disabled
  /// by default (dev/tests); FAIL OPEN if HIBP is unreachable. Fetch is injectable for tests.
  breachCheck?: BreachCheckOptions;
  /// Injectable clock (epoch ms). Defaults to Date.now. Threaded into EVERY composed lane so the
  /// whole flow is deterministic under test.
  now?: () => number;
  /// Injectable randomness for the email-token lane (id/secret). Defaults to WebCrypto.
  randomBytes?: (n: number) => Uint8Array;
  /// Injectable id generator for the email-token lane. Defaults to "evt-"+randomUUID.
  newEmailTokenId?: () => string;
}

// ---------------------------------------------------------------------------------------
// Validation + canonicalization
// ---------------------------------------------------------------------------------------

/// Conservative RFC-5321-ish email shape check. We do NOT try to be fully compliant — the
/// verification email is the real proof of control. This only rejects obviously-bad input
/// before we touch the directory.
const EMAIL_RE = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;
const MAX_EMAIL_LENGTH = 254; // RFC 5321 max.
const MAX_ORG_NAME_LENGTH = 100;
const MAX_DISPLAY_NAME_LENGTH = 100;

/// Canonical email form used everywhere as the username (CONTRACTS-AUTH.md §1.1).
export function canonicalEmail(email: string): string {
  return email.trim().toLowerCase();
}

function assertValidEmail(email: unknown): string {
  if (typeof email !== "string") {
    throw new SignupError("email is required", 400, "invalid_email");
  }
  const canon = canonicalEmail(email);
  if (canon.length === 0 || canon.length > MAX_EMAIL_LENGTH || !EMAIL_RE.test(canon)) {
    throw new SignupError("a valid email address is required", 400, "invalid_email");
  }
  return canon;
}

function assertNonEmpty(value: unknown, max: number, field: string, code: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new SignupError(`${field} is required`, 400, code);
  }
  const trimmed = value.trim();
  if (trimmed.length > max) {
    throw new SignupError(`${field} is too long`, 400, code);
  }
  return trimmed;
}

// ---------------------------------------------------------------------------------------
// Rate-limit helper
// ---------------------------------------------------------------------------------------

/// Check a limiter and throw a 429 SignupError (carrying Retry-After) on denial. Both the IP
/// and email buckets are checked up front, before any privileged work runs.
async function enforceLimit(limiter: RateLimiter, key: string, now: number): Promise<void> {
  const r = await limiter.check(key, 1, now);
  if (!r.allowed) {
    throw new SignupError("too many requests, slow down", 429, "rate_limited", r.retryAfterSec);
  }
}

/// Best-effort client IP for pre-auth limiting. Cloudflare populates `CF-Connecting-IP`; a
/// client-supplied `X-Forwarded-For` is NEVER trusted (spoofable). Falls back to "unknown" so a
/// missing header doesn't crash — all such callers then share one (heavily-limited) bucket.
function clientIp(req: Request): string {
  return req.headers.get("cf-connecting-ip") ?? "unknown";
}

// ---------------------------------------------------------------------------------------
// Email-verification gate (CONTRACTS-AUTH.md §4 "email-verification gate before any
// privileged action")
// ---------------------------------------------------------------------------------------

/// Throw 403 unless the account's email is verified. Downstream privileged routes call this
/// (the account may still hold a session to drive the "verify your email" UI, but cannot act).
export function assertEmailVerified(account: Pick<Account, "emailVerified">): void {
  if (!account.emailVerified) {
    throw new SignupError("verify your email before continuing", 403, "email_unverified");
  }
}

/// The reduced scope set granted to a session whose account has NOT verified its email
/// (CONTRACTS-AUTH.md §4.2 email-verification gate, approach (b): "mint reduced scopes for an
/// unverified session and upgrade on verification"). Read-only data scopes only — enough to sign
/// in, browse, and reach the "verify your email" UI, but NO write/lock/admin/snapshot-write
/// capability. The existing per-route `requireScope` gates then block every mutating + privileged
/// action with the normal 403 until the session is re-minted with full scopes post-verification.
export const UNVERIFIED_SCOPES: Scope[] = ["fs:read", "snapshot:read"];

/// Pick the session scopes for an account at login/signup time. A verified account gets its full
/// role scopes (single source of truth: `scopesForRole`); an UNVERIFIED account gets the reduced
/// read-only set, so it can hold a session for the verify-email UI but cannot perform privileged
/// or mutating actions until it verifies (and the session is re-minted with full scopes).
export function scopesForLogin(role: AccountRole, emailVerified: boolean): Scope[] {
  return emailVerified ? scopesForRole(role) : [...UNVERIFIED_SCOPES];
}

// ---------------------------------------------------------------------------------------
// SIGNUP — POST /v1/auth/signup
// ---------------------------------------------------------------------------------------

export interface SignupBody {
  orgName: string;
  email: string;
  password: string;
  displayName: string;
}

export interface SignupResult {
  status: 201;
  body: {
    orgId: string;
    accountId: string;
    userId: string;
    /// True when the verification email dispatched; FALSE when delivery failed but signup still
    /// COMPLETED (R1: a transient email-provider outage must not strand a fully-created account —
    /// the account/claim/password/session are committed and the user can resend from the
    /// verify-email screen). `true` on the happy path; `false` signals "use the resend flow".
    emailSent: boolean;
    /// The account starts UNVERIFIED; the SPA renders the "check your inbox" state.
    state: "verify_email";
    /// CSRF token for the session cookie we set (SPA echoes it back on mutations).
    csrf: string;
  };
  /// `Set-Cookie` for `cfs_session` (so the new owner is signed in, but gated until verified).
  setCookie: string;
}

/// Self-serve org signup. State machine:
///
///   (public request)
///        | rate-limit per IP + per email  -- denied --> 429
///        v
///   validate body (orgName/email/password/displayName)  -- bad --> 400
///        |
///        v
///   directory dedupe pre-check (resolveEmail)  -- exists --> 409 email_taken
///        |
///        v
///   provision Org + owner User (OrgDO)
///        |
///        v
///   createAccount(emailVerified:false)  -- email_taken race --> 409
///        | (claims email globally; THIS is the authoritative dedupe)
///        v
///   setPassword (scrypt hash)
///        |
///        v
///   issue + send verification email (single-use, hash-bound token)
///        | (R1: a send FAILURE is NON-FATAL — the token is already issued; we fall through with
///        |  emailSent:false rather than 500ing and stranding the just-created account)
///        v
///   create BrowserSession (owner scopes) + set cookie
///        |
///        v
///   201 { orgId, accountId, userId, emailSent, state:"verify_email", csrf }
///   (emailSent:true on the happy path; false when delivery failed and the user must resend)
///
/// The account is UNVERIFIED: it can sign in (to see the verify-email UI) but `assertEmailVerified`
/// blocks privileged actions until the link is clicked.
export async function handleSignup(req: Request, deps: SignupDeps): Promise<SignupResult> {
  const now = (deps.now ?? Date.now)();
  const ip = clientIp(req);

  // Parse + validate FIRST for the email key, but rate-limit IP before doing anything expensive.
  await enforceLimit(deps.limiters.signupIp, `ip:${ip}`, now);

  const body = await readJson<Partial<SignupBody>>(req);
  const email = assertValidEmail(body.email);
  const orgName = assertNonEmpty(body.orgName, MAX_ORG_NAME_LENGTH, "organization name", "invalid_org_name");
  const displayName = assertNonEmpty(body.displayName, MAX_DISPLAY_NAME_LENGTH, "display name", "invalid_display_name");
  if (typeof body.password !== "string") {
    throw new SignupError("password is required", 400, "weak_password");
  }

  // Per-email bucket (after we have the canonical email). Blunts repeated grabs of one address.
  await enforceLimit(deps.limiters.signupEmail, `email:${email}`, now);

  // Dedupe pre-check: fail fast + cheap before provisioning. The AUTHORITATIVE dedupe is the
  // directory claim inside createAccount (handles the concurrent-signup race). Generic message;
  // we never reveal which org owns the address (CONTRACTS-AUTH.md §1.7 anti-enumeration).
  const existing = await deps.accounts.resolveEmail(email);
  if (existing) {
    throw new SignupError("that email address is already in use", 409, "email_taken");
  }

  // Validate password strength BEFORE provisioning the org, so a weak password doesn't orphan an
  // org. `setPassword` -> `hashPassword` enforces MIN/MAX length; surface its 400 verbatim.
  assertPasswordShape(body.password);

  // Optional breached-password check (HIBP k-anonymity). Also BEFORE provisioning, so a known
  // breached password is rejected (400 password_breached) without orphaning an org. No-op when
  // disabled; fails open if HIBP is unreachable. Throws PasswordError -> mapped to 400 by the route.
  if (deps.breachCheck?.enabled) {
    await assertPasswordNotBreached(body.password, deps.breachCheck);
  }

  // Provision OrgDO side (new org + first owner user). Principal.sub == this userId downstream.
  const { orgId, userId } = await deps.org.createOrgWithOwner({
    orgName,
    ownerEmail: email,
    ownerDisplayName: displayName,
  });

  // Create the credential-bearing Account; this CLAIMS the email globally and is the
  // authoritative dedupe. A loser of the concurrent-signup race throws -> mapped to 409.
  let account: Account;
  try {
    account = await deps.accounts.createAccount({
      orgId,
      userId,
      email,
      displayName,
      role: "owner",
      emailVerified: false,
    });
  } catch (err) {
    throw mapEmailTaken(err);
  }

  // Hash + store the password (scrypt; constant-time verify later). `now` injected for tests;
  // `cost` is the operator-tunable scrypt cost (env-derived) so signup matches the login rehash target.
  await setPassword(deps.passwords, account.id, body.password, { now, ...(deps.scryptCost ? { cost: deps.scryptCost } : {}) });

  // Issue + send the verification email. Single-use, hash-bound token; clear secret never stored.
  // R1: email DELIVERY is best-effort and independently retryable. The token is issued BEFORE (and
  // inside) `sendVerificationEmail`, so even if the provider throws (auth-email.ts senders throw on
  // a non-2xx / network failure) the verify token is persisted and the existing resend flow works.
  // A send failure must NOT be fatal: the org/account/global-email-claim/password/session are all
  // already committed and consistent — failing here would 500 the request AND strand the account
  // (a retry creates a fresh org -> DirectoryDO.claim sees the email owned elsewhere -> 409). So we
  // treat a send failure as NON-FATAL: complete signup normally (201 + session) but signal
  // `emailSent:false` so the SPA points the user at the resend button.
  const tokenDeps: TokenDeps = {
    now: () => now,
    ...(deps.randomBytes ? { randomBytes: deps.randomBytes } : {}),
    ...(deps.newEmailTokenId ? { newId: deps.newEmailTokenId } : {}),
  };
  let emailSent = true;
  try {
    await sendVerificationEmail(
      {
        store: deps.emailTokens,
        sender: deps.emailSender,
        buildUrl: deps.buildVerifyUrl,
        tokenDeps,
      },
      {
        orgId,
        accountId: account.id,
        email: account.email,
        displayName,
        productName: deps.productName,
      },
    );
  } catch (err) {
    // Don't swallow silently — surface for observability. The user lands authenticated on the
    // verify-email screen and uses the existing session-gated resend flow to retry delivery.
    emailSent = false;
    console.warn({ event: "signup_verification_delivery_failed" });
  }
  // Audit B11: a no-op/console sender resolves "successfully" but DROPS the mail, so the
  // user would see emailSent:true and then hit 403 email_unverified forever with nothing
  // logged. Detect a non-delivering sender and report emailSent:false + a loud operator
  // warning, so the SPA shows the resend path and the operator sees the misconfig.
  if (emailSent && deps.emailSender.delivers === false) {
    emailSent = false;
    console.warn(
      `signup: NO email provider configured — verification mail for account=${account.id} org=${orgId} was DROPPED by the no-op sender. Configure EMAIL_PROVIDER (or run GET /v1/admin/doctor) so users can verify.`,
    );
  }

  // Sign the new owner in (gated until verified) so the client lands on the verify-email screen
  // already authenticated. The account is UNVERIFIED at signup, so it gets the reduced read-only
  // scope set — it can drive the verify-email UI but cannot perform privileged/mutating actions
  // until it verifies (which re-mints the session with full owner scopes). CONTRACTS-AUTH.md §4.2.
  const scopes: Scope[] = scopesForLogin("owner", false);
  const session = await createBrowserSession(
    deps.sessions,
    { accountId: account.id, userId: account.userId, orgId, scopes, authEpoch: account.authEpoch },
    now,
  );
  const { setCookie, csrf } = sessionLoginResponse(session, now);

  return {
    status: 201,
    setCookie,
    body: {
      orgId,
      accountId: account.id,
      userId: account.userId,
      emailSent, // R1: true on the happy path; false when delivery failed (signup still completed).
      state: "verify_email",
      csrf,
    },
  };
}

// ---------------------------------------------------------------------------------------
// LOGIN — POST /v1/auth/login  (email + password -> session OR 2FA challenge)
// ---------------------------------------------------------------------------------------

export interface LoginBody {
  email: string;
  password: string;
}

/// A successful, fully-authenticated login (no 2FA, or 2FA completed). Carries the session
/// cookie + the JSON body the SPA expects (CONTRACTS-AUTH.md §4.2).
export interface LoginSessionResult {
  kind: "session";
  status: 200;
  setCookie: string;
  body: { userId: string; orgId: string; role: AccountRole; scopes: Scope[]; csrf: string };
}

/// Password verified, but the account has a confirmed second factor: NO session yet. The SPA
/// completes via `POST /v1/auth/login/totp` (or webauthn) with the returned `challengeId`.
export interface LoginMfaResult {
  kind: "mfa";
  status: 200;
  body: { mfaRequired: true; methods: MfaMethod[]; challengeId: string };
}

export type MfaMethod = "totp" | "recovery" | "webauthn";
export type LoginResult = LoginSessionResult | LoginMfaResult;

/// How long a post-password 2FA challenge stays valid (seconds). Short: the user has just typed
/// their password and an authenticator code is seconds away.
export const MFA_CHALLENGE_TTL_SECONDS = 5 * 60;

/// Login state machine:
///
///   (public request)
///        | rate-limit per IP + per email  -- denied --> 429
///        v
///   validate body (email/password)  -- bad --> 400
///        |
///        v
///   resolve email -> {orgId, accountId}  -- miss --> run dummy scrypt verify, 401 invalid_credentials
///        |                                          (timing-equalized; no enumeration)
///        v
///   load account  -- suspended/deprovisioned --> 401 invalid_credentials
///        |
///        v
///   verifyAccountPassword (scrypt, constant-time)  -- wrong --> 401 invalid_credentials
///        |
///        v
///   confirmed TOTP OR ≥1 passkey?  --no--> mint session, set cookie, 200 { userId, orgId, role, scopes, csrf }
///        | yes
///        v
///   create single-use mfa challenge (binds accountId+orgId, TTL 5m)
///        v
///   200 { mfaRequired:true, methods:[...what's available], challengeId }   (NO session yet)
///        (methods: ["totp","recovery"] if TOTP confirmed, plus ["webauthn"] if any passkey)
///
/// Email verification is NOT required to LOG IN (the user needs a session to reach the
/// verify-email UI); it IS required (via `assertEmailVerified`) for privileged actions.
export async function handleLogin(req: Request, deps: SignupDeps): Promise<LoginResult> {
  const now = (deps.now ?? Date.now)();
  const ip = clientIp(req);

  await enforceLimit(deps.limiters.loginIp, `ip:${ip}`, now);

  const body = await readJson<Partial<LoginBody>>(req);
  if (typeof body.email !== "string" || typeof body.password !== "string") {
    throw new SignupError("email and password are required", 400, "invalid_request");
  }
  const email = canonicalEmail(body.email);
  await enforceLimit(deps.limiters.loginEmail, `email:${email}`, now);

  // Resolve before org is known (directory). A miss must NOT short-circuit cheaply, or response
  // time leaks which emails exist. We run a scrypt verify against a throwaway credential to keep
  // the timing profile of "no such account" close to "wrong password".
  const resolved = await deps.accounts.resolveEmail(email);
  if (!resolved) {
    await timingEqualizeNoAccount(body.password, now, deps.scryptCost);
    throw invalidCredentials();
  }

  const account = await deps.accounts.getAccount(resolved.accountId);
  if (!account || account.status !== "active") {
    // Still pay the scrypt cost for suspended/deprovisioned to avoid a timing tell.
    await timingEqualizeNoAccount(body.password, now, deps.scryptCost);
    throw invalidCredentials();
  }

  // Constant-time scrypt verify. `verifyAccountPassword` throws `no_password` if the account has
  // no password credential at all — collapse that to the same generic 401 (don't leak that the
  // account exists but is passkey-only).
  let ok: boolean;
  let rehash = false;
  try {
    // Pass the operator-tuned cost as the rehash target so a hash made under a weaker (older or
    // lower-N) cost is flagged for transparent upgrade on this successful login.
    const res = await verifyAccountPassword(deps.passwords, account.id, body.password, deps.scryptCost);
    ok = res.ok;
    rehash = res.rehash;
  } catch {
    throw invalidCredentials();
  }
  if (!ok) throw invalidCredentials();

  // Transparent upgrade: if the stored hash is weaker than the current target cost, re-hash the
  // (now-verified) plaintext at the new cost and persist it. Best-effort — a write failure must
  // not block an otherwise-valid login (the row stays flagged and upgrades on the next login).
  if (rehash) {
    try {
      const upgraded = await hashPassword(account.id, body.password, { now, ...(deps.scryptCost ? { cost: deps.scryptCost } : {}) });
      if (deps.passwords.putPasswordAtEpoch) await deps.passwords.putPasswordAtEpoch(upgraded, account.authEpoch ?? 0);
      else await deps.passwords.putPassword(upgraded);
    } catch {
      /* non-fatal: login proceeds; rehash retried next time */
    }
  }

  // Second factor? An account is 2FA-protected if it has a CONFIRMED TOTP credential OR ≥1
  // registered passkey (CONTRACTS-AUTH.md §4.2: "confirmed TOTP OR passkeys → mfaRequired").
  // Previously only TOTP was checked, so a passkey-only account got a full session from the
  // password alone — its passkey second factor was silently bypassed. We now gate on both and
  // advertise exactly the methods the account can use to complete the challenge.
  const [totpCred, passkeys] = await Promise.all([
    deps.totp.getTotp(account.id),
    deps.webauthn ? deps.webauthn.listWebAuthn(account.id) : Promise.resolve([] as unknown[]),
  ]);
  const hasTotp = !!(totpCred && totpCred.confirmed);
  const hasWebAuthn = passkeys.length > 0;

  if (hasTotp || hasWebAuthn) {
    const methods: MfaMethod[] = [];
    if (hasTotp) methods.push("totp", "recovery");
    if (hasWebAuthn) methods.push("webauthn");

    // Single-use login challenge, bound to this account + org, completed by EITHER the TOTP/
    // recovery path (login/totp|recovery) OR the webauthn-as-second-factor path (the webauthn
    // authenticate flow bound to this same challengeId). The session is minted only after a
    // valid second factor — never from the password alone.
    const challengeId = `mfa-${crypto.randomUUID()}`;
    await deps.totp.putChallenge({
      id: challengeId,
      accountId: account.id,
      purpose: "login_mfa",
      authEpoch: account.authEpoch ?? 0,
      value: account.orgId, // bind the org so completion needn't re-resolve.
      expiresAt: now + MFA_CHALLENGE_TTL_SECONDS * 1000,
    });
    return {
      kind: "mfa",
      status: 200,
      body: { mfaRequired: true, methods, challengeId },
    };
  }

  // No second factor: mint the session now.
  return mintLoginSession(deps, account, now);
}

// ---------------------------------------------------------------------------------------
// LOGIN /totp — POST /v1/auth/login/totp  (completes a 2FA challenge with an authenticator code)
// ---------------------------------------------------------------------------------------

export interface LoginTotpBody {
  challengeId: string;
  code: string;
}

/// Complete a TOTP-gated login. Consumes the single-use challenge, verifies the authenticator
/// code (auth-totp lane: ±1 step window + replay guard), then mints the session.
///
///   validate body -> 400
///   takeChallenge(challengeId)  -- missing/expired/wrong-purpose --> 401 invalid_challenge
///   verifyLoginTotp(accountId, code)  -- bad/replayed --> 401 (propagated from totp lane)
///   load account -> mint session, set cookie -> 200 { userId, orgId, role, scopes, csrf }
export async function handleLoginTotp(req: Request, deps: SignupDeps): Promise<LoginSessionResult> {
  const now = (deps.now ?? Date.now)();
  const ip = clientIp(req);
  await enforceLimit(deps.limiters.loginIp, `ip:${ip}`, now);

  const body = await readJson<Partial<LoginTotpBody>>(req);
  const taken = await takeMfaChallenge(deps, body.challengeId, now);
  if (typeof body.code !== "string" || body.code.trim().length === 0) {
    // Bad request, not a wrong code — restore the challenge so a corrected retry still works.
    await restoreMfaChallenge(deps, taken, now);
    throw new SignupError("a TOTP code is required", 400, "invalid_request");
  }

  // Validate the code BEFORE consuming the challenge: a wrong digit must NOT burn the single-use
  // challenge (that would let one mistyped code grief/DoS a 2FA login). verifyLoginTotp throws a
  // TotpError(401) on a bad/replayed/absent code — re-store the challenge, then propagate. On
  // SUCCESS we leave the challenge consumed (single-use stands).
  try {
    await verifyLoginTotp(taken.accountId, body.code, { store: deps.totp, now: () => now });
  } catch (e) {
    // Audit B13: a WRONG code counts against the per-challenge attempt cap (a malformed
    // request above does not). Once the cap is hit the challenge is burned, not restored.
    await restoreMfaChallenge(deps, taken, now, { countAttempt: true });
    throw e;
  }

  const account = await requireActiveAccount(deps, taken.accountId);
  return mintLoginSession(deps, account, now, taken.authEpoch ?? 0);
}

// ---------------------------------------------------------------------------------------
// LOGIN /recovery — POST /v1/auth/login/recovery  (completes a 2FA challenge with a recovery code)
// ---------------------------------------------------------------------------------------

export interface LoginRecoveryBody {
  challengeId: string;
  recoveryCode: string;
}

/// Complete a 2FA login with a one-time recovery code (authenticator unavailable). Consumes the
/// challenge, consumes the recovery code (auth-totp lane; atomic single-use), mints the session.
export async function handleLoginRecovery(req: Request, deps: SignupDeps): Promise<LoginSessionResult> {
  const now = (deps.now ?? Date.now)();
  const ip = clientIp(req);
  await enforceLimit(deps.limiters.loginIp, `ip:${ip}`, now);

  const body = await readJson<Partial<LoginRecoveryBody>>(req);
  const taken = await takeMfaChallenge(deps, body.challengeId, now);
  if (typeof body.recoveryCode !== "string" || body.recoveryCode.trim().length === 0) {
    await restoreMfaChallenge(deps, taken, now);
    throw new SignupError("a recovery code is required", 400, "invalid_request");
  }

  // As with TOTP: validate (and atomically consume) the recovery code BEFORE burning the login
  // challenge. A bad/used recovery code throws — restore the challenge so the user can retry with
  // a different code. On success the recovery code is already consumed and the challenge stays consumed.
  try {
    await verifyRecoveryCode(taken.accountId, body.recoveryCode, { store: deps.totp, now: () => now });
  } catch (e) {
    // Audit B13: a wrong recovery code counts against the per-challenge attempt cap too.
    await restoreMfaChallenge(deps, taken, now, { countAttempt: true });
    throw e;
  }

  const account = await requireActiveAccount(deps, taken.accountId);
  return mintLoginSession(deps, account, now, taken.authEpoch ?? 0);
}

// ---------------------------------------------------------------------------------------
// Shared internals
// ---------------------------------------------------------------------------------------

/// Mint a browser session for `account` + build the cookie/body. Centralized so signup, login,
/// and the two MFA completions produce identical session shapes (CONTRACTS-AUTH.md §4.2).
async function mintLoginSession(
  deps: SignupDeps,
  account: Account,
  now: number,
  authEpoch = account.authEpoch ?? 0,
): Promise<LoginSessionResult> {
  // Reduced scopes while the email is unverified (CONTRACTS-AUTH.md §4.2 gate, approach (b));
  // full role scopes once verified. Re-minted on the next login after verification.
  const scopes: Scope[] = scopesForLogin(account.role, account.emailVerified);
  const session: BrowserSession = await createBrowserSession(
    deps.sessions,
    { accountId: account.id, userId: account.userId, orgId: account.orgId, scopes, authEpoch },
    now,
  );
  const { setCookie, csrf } = sessionLoginResponse(session, now);
  return {
    kind: "session",
    status: 200,
    setCookie,
    body: { userId: account.userId, orgId: account.orgId, role: account.role, scopes, csrf },
  };
}

/// A taken (consumed) post-password MFA challenge, retained so we can RE-STORE it if the second
/// factor turns out to be wrong (so a mistyped code doesn't burn the challenge — fix #4).
interface TakenMfaChallenge {
  authEpoch?: number;
  id: string;
  accountId: string;
  value: string;
  expiresAt: number;
}

/// Take (single-use) a post-password MFA challenge, returning its id + bound accountId so the
/// caller can restore it on a wrong code. Validates presence, purpose, and expiry. A missing/
/// expired/wrong-purpose challenge collapses to a generic 401 so an attacker can't probe ids.
async function takeMfaChallenge(
  deps: SignupDeps,
  challengeId: unknown,
  now: number,
): Promise<TakenMfaChallenge> {
  if (typeof challengeId !== "string" || challengeId.length === 0) {
    throw new SignupError("a challenge id is required", 400, "invalid_request");
  }
  const challenge = await deps.totp.takeChallenge(challengeId); // single-use
  if (
    !challenge ||
    challenge.purpose !== "login_mfa" ||
    challenge.accountId === null ||
    now >= challenge.expiresAt
  ) {
    throw new SignupError("invalid or expired challenge", 401, "invalid_challenge");
  }
  return { id: challengeId, accountId: challenge.accountId, value: challenge.value, expiresAt: challenge.expiresAt, authEpoch: challenge.authEpoch };
}

/// Audit B13 — the max number of WRONG second-factor attempts a single login challenge
/// tolerates before it is BURNED (not restored), independent of source IP. Caps a
/// distributed-IP attacker grinding the 6-digit TOTP code across the 5-minute window. The
/// per-challenge counter rides in the challenge `value` as `orgId|attempts` (orgId is the
/// only datum the challenge carries), so no schema change is needed.
export const MFA_MAX_ATTEMPTS = 5;

/// Split a challenge value into its bound orgId and the failed-attempt count.
function parseChallengeValue(value: string): { orgId: string; attempts: number } {
  const i = value.lastIndexOf("|");
  if (i < 0) return { orgId: value, attempts: 0 };
  const attempts = Number(value.slice(i + 1));
  return { orgId: value.slice(0, i), attempts: Number.isFinite(attempts) ? attempts : 0 };
}

/// Re-store a taken MFA challenge under its ORIGINAL id + expiry after a failed second-factor
/// attempt, so the challenge remains usable for a retry within its (unchanged) TTL. We never
/// extend the expiry — the original window still bounds the retry budget. No-op if already expired.
///
/// Audit B13: a wrong-code attempt increments a per-challenge counter; once it reaches
/// MFA_MAX_ATTEMPTS the challenge is NOT restored (it dies, forcing a fresh password login), so
/// the single-use challenge can't be retried unboundedly within its TTL from many IPs.
async function restoreMfaChallenge(deps: SignupDeps, taken: TakenMfaChallenge, now: number,
                                   opts: { countAttempt?: boolean } = {}): Promise<void> {
  if (now >= taken.expiresAt) return;
  const { orgId, attempts } = parseChallengeValue(taken.value);
  const nextAttempts = opts.countAttempt ? attempts + 1 : attempts;
  // Burn the challenge once the wrong-code budget is spent — do NOT restore it.
  if (opts.countAttempt && nextAttempts >= MFA_MAX_ATTEMPTS) return;
  await deps.totp.putChallenge({
    id: taken.id,
    accountId: taken.accountId,
    purpose: "login_mfa",
    authEpoch: taken.authEpoch ?? 0,
    value: `${orgId}|${nextAttempts}`,
    expiresAt: taken.expiresAt,
  });
}

/// Load an account that must be present + active, else a generic 401. Used after a 2FA challenge
/// is consumed (the account could have been suspended between password and second factor).
async function requireActiveAccount(deps: SignupDeps, accountId: string): Promise<Account> {
  const account = await deps.accounts.getAccount(accountId);
  if (!account || account.status !== "active") {
    throw invalidCredentials();
  }
  return account;
}

/// The single generic credential failure. Same shape for missing account / wrong password /
/// no-password / suspended — no enumeration.
function invalidCredentials(): SignupError {
  return new SignupError("invalid email or password", 401, "invalid_credentials");
}

/// Validate password length up front (same rules as the password lane) without provisioning an
/// org for a doomed request. Delegates the exact bounds to `hashPassword`'s own check by reusing
/// its constants implicitly: we re-encode here only the length policy the lane enforces.
function assertPasswordShape(password: string): void {
  // MIN 8 / MAX 1024 mirror auth-password.ts (MIN_PASSWORD_LENGTH / MAX_PASSWORD_LENGTH). We keep
  // this thin pre-check so org provisioning never runs for an obviously-bad password; the
  // password lane re-validates authoritatively inside setPassword.
  if (password.length < 8) {
    throw new SignupError("password must be at least 8 characters", 400, "weak_password");
  }
  if (password.length > 1024) {
    throw new SignupError("password must be at most 1024 characters", 400, "password_too_long");
  }
}

/// Run a real scrypt derivation on the no-such-account / inactive path so the response time does
/// not betray account existence (timing-equalization). The result is discarded. We hash against a
/// fixed dummy accountId; the cost is dominated by scrypt, matching the real verify path. We hash at
/// the SAME operator-tuned `cost` as a real login verify so the timing profiles line up (and so the
/// equalization isn't accidentally heavier/cheaper than the real path).
async function timingEqualizeNoAccount(password: unknown, now: number, cost?: ScryptCost): Promise<void> {
  // Only bother if the client even sent a plausible password string; a non-string can't have been
  // a real attempt. Bounded to avoid a DoS via giant payloads (the password lane caps at 1024).
  if (typeof password !== "string" || password.length === 0 || password.length > 1024) return;
  try {
    await hashPassword("acc-timing-equalization-dummy", password, { now, ...(cost ? { cost } : {}) });
  } catch {
    // hashPassword throws on too-short/too-long; that's fine — we just wanted the time spent.
  }
}

/// Map an error from `createAccount` to the right HTTP error. The directory throws on a duplicate
/// claim; we treat ANY error whose message/code mentions the taken email as a 409, and re-raise
/// SignupErrors unchanged. Unknown errors become a 500 (the org was provisioned but the account
/// claim failed for a non-dedupe reason — integration logs + reconciles).
function mapEmailTaken(err: unknown): SignupError {
  if (err instanceof SignupError) return err;
  const msg = err instanceof Error ? err.message : String(err);
  const code = (err as { code?: unknown })?.code;
  if (code === "email_taken" || /email[_\s-]?taken|already (in use|exists)/i.test(msg)) {
    return new SignupError("that email address is already in use", 409, "email_taken");
  }
  return new SignupError("could not create account", 500, "account_create_failed");
}

/// Parse a JSON body, mapping malformed JSON to a clean 400 (never an unhandled throw).
async function readJson<T>(req: Request): Promise<T> {
  try {
    return (await req.json()) as T;
  } catch {
    throw new SignupError("request body must be valid JSON", 400, "invalid_json");
  }
}

// ---------------------------------------------------------------------------------------
// Response helper (integration may use this or build its own Response from the result objects)
// ---------------------------------------------------------------------------------------

/// Turn a `SignupError` into the project's `{ error }` JSON Response, attaching `Retry-After`
/// for 429s. Integration can use this directly in its catch, keeping error shapes consistent.
export function signupErrorResponse(err: SignupError): Response {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (err.status === 429 && err.retryAfterSec !== undefined) {
    headers["Retry-After"] = String(err.retryAfterSec);
  }
  return new Response(JSON.stringify({ error: err.code }), { status: err.status, headers });
}
