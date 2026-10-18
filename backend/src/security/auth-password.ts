// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs password credential lane: scrypt hashing, constant-time verify, and the
/// set / change / reset-password helpers (CONTRACTS-AUTH.md §1.2, §4.2).
///
/// Design goals:
///   - Workers-correct: NO Node built-ins. WebCrypto (`crypto.getRandomValues`,
///     `crypto.subtle.digest`) + `@noble/hashes/scrypt` (pure JS, WASM-free) only.
///   - Per-row cost params: every PasswordCredential stores its own `{algo,N,r,p,dkLen,salt}`
///     so the global default cost can be raised later WITHOUT invalidating existing hashes.
///     `verifyPassword` re-derives with the row's params; `needsRehash` flags stale rows so
///     callers can transparently upgrade on a successful login.
///   - Constant-time verify: the derived-key comparison is XOR-accumulate over equal-length
///     byte arrays (no early return), defeating timing oracles. The salt being random makes
///     the lengths constant per-algo anyway.
///   - Pure-ish: every helper takes its `CredentialStore` (and `now`) injected — no DO, no
///     global clock — so the module is deterministic and unit-testable with an in-memory fake.
///
/// This module depends ONLY on the `CredentialStore` interface (CONTRACTS-AUTH.md §2) and the
/// `Scope` type from `auth.ts`. It never imports `cloudflare:workers`.

import { scryptAsync } from "@noble/hashes/scrypt";

// ---------------------------------------------------------------------------------------
// Contract types (CONTRACTS-AUTH.md §1.2). Defined here, owned by this lane until the
// integration agent lifts them into the shared `auth-types.ts`; the shapes are frozen.
// ---------------------------------------------------------------------------------------

export type PasswordAlgo = "scrypt";

/// One password per account. Cost params are stored per-row (NOT hardcoded at verify) so
/// they can be raised later without breaking existing hashes (CONTRACTS-AUTH.md §1.2).
export interface PasswordCredential {
  accountId: string; // PK (one password per account)
  algo: PasswordAlgo; // "scrypt"
  N: number; // CPU/memory cost; power of two. Frozen default 2**15 = 32768.
  r: number; // block size. Frozen default 8.
  p: number; // parallelization. Frozen default 1.
  dkLen: number; // derived-key length in bytes. Frozen default 32.
  salt: string; // base64url of 16 random bytes
  hash: string; // base64url of the scrypt-derived key (dkLen bytes)
  updatedAt: number;
}

/// Subset of the `CredentialStore` (CONTRACTS-AUTH.md §2) this lane needs. Injected — never a
/// concrete DO. The integration adapter and the test fake both satisfy this.
export interface PasswordStore {
  putPasswordAtEpoch?(cred: PasswordCredential, authEpoch: number): Promise<void>;
  getPassword(accountId: string): Promise<PasswordCredential | null>;
  putPassword(cred: PasswordCredential): Promise<void>;
  deletePassword(accountId: string): Promise<void>;
}

// ---------------------------------------------------------------------------------------
// Frozen scrypt parameters (CONTRACTS-AUTH.md §1.2). The lane MUST store these per-row.
// ---------------------------------------------------------------------------------------

export const SCRYPT_PARAMS = {
  /// 2**15 = 32768 (audit B14). scrypt's memory cost is ~128·N·r bytes, so N=2^17 (the prior
  /// default) needs ~128 MiB PER derivation — at/over the Cloudflare Workers 128 MB isolate
  /// cap, which let a botnet OOM the isolate cheaply (the no-account login path runs a full
  /// derivation per bogus-email attempt for timing-equalization). N=2^15 ≈ 32 MiB stays
  /// comfortably under the cap while remaining strong. Per-row params are stored, so any
  /// existing 2^17 hashes still verify with THEIR params and `needsRehash` upgrades them down
  /// to this target on the next successful login. Operators may RAISE it (a beefier runtime)
  /// or LOWER it via `SCRYPT_COST_N` (see `scryptCostFromEnv`).
  N: 32768,
  r: 8,
  p: 1,
  dkLen: 32,
} as const;

/// Salt length in bytes (CONTRACTS-AUTH.md §1.2: "16-byte salt").
export const SALT_BYTES = 16;

/// Tunable cost: callers may override the default scrypt params (e.g. raise `N` over time, or
/// LOWER it in tests so a hash is cheap). Anything omitted falls back to the frozen default.
export interface ScryptCost {
  N?: number;
  r?: number;
  p?: number;
  dkLen?: number;
}

function resolveCost(cost?: ScryptCost): { N: number; r: number; p: number; dkLen: number } {
  return {
    N: cost?.N ?? SCRYPT_PARAMS.N,
    r: cost?.r ?? SCRYPT_PARAMS.r,
    p: cost?.p ?? SCRYPT_PARAMS.p,
    dkLen: cost?.dkLen ?? SCRYPT_PARAMS.dkLen,
  };
}

/// Derive the operator-tunable scrypt cost from the environment. `SCRYPT_COST_N` overrides the
/// default N (CPU/memory cost) so a deployer can dial the per-login cost to their CPU budget
/// without a code change. The value MUST be a power of two (scrypt requires N = 2^k); a missing,
/// non-numeric, non-power-of-two, or out-of-range value falls back to the frozen default and is
/// ignored (fail safe — never weaken below the default unintentionally, never crash on a typo).
/// Returns `undefined` when no valid override is present, so callers can pass it straight to the
/// `cost` option (where `undefined` means "use the frozen default"). r/p/dkLen stay frozen.
export function scryptCostFromEnv(env: { SCRYPT_COST_N?: string }): ScryptCost | undefined {
  const raw = env.SCRYPT_COST_N;
  if (raw === undefined || raw === null || `${raw}`.trim() === "") return undefined;
  const n = Number(raw);
  // Must be a positive integer power of two within scrypt's practical range. `n & (n-1)` is 0
  // only for powers of two. Lower bound 2 (the smallest legal N); upper bound 2^22 caps the
  // memory footprint so a fat-fingered value can't OOM the isolate.
  if (!Number.isInteger(n) || n < 2 || n > 2 ** 22 || (n & (n - 1)) !== 0) return undefined;
  return { N: n };
}

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

export class PasswordError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 401 | 404 | 500 = 400,
    readonly code: string = "password_error",
  ) {
    super(message);
    this.name = "PasswordError";
  }
}

// ---------------------------------------------------------------------------------------
// base64url + bytes helpers (no Node Buffer; workerd globals only) — mirrors auth.ts/oidc.ts.
// ---------------------------------------------------------------------------------------

const enc = new TextEncoder();

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

/// Cryptographically-random bytes from the platform CSPRNG (WebCrypto, available in workerd).
function randomBytes(n: number): Uint8Array {
  const buf = new Uint8Array(n);
  crypto.getRandomValues(buf);
  return buf;
}

/// Constant-time byte comparison: XOR-accumulate, NO early return. Returns false on length
/// mismatch (length is not itself secret here — both sides are dkLen). Defeats timing oracles
/// on the derived-key compare. (We don't depend on `@noble/hashes` `equalBytes`, which is
/// absent in the installed major version.)
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------------------
// Password policy
// ---------------------------------------------------------------------------------------

/// Minimum acceptable password length. Deliberately conservative; the front-of-house lanes
/// (signup / reset) can layer richer policy. We reject empty / trivially-short here so a
/// blank password can never be hashed into a credential.
/// Audit B16: raised from 8 → 10. A modern floor; the breach-check (HIBP) is defaulted ON in
/// the production wrangler env to also reject known-compromised passwords above the floor.
export const MIN_PASSWORD_LENGTH = 10;
/// Cap to bound scrypt input work and reject obviously-abusive payloads.
export const MAX_PASSWORD_LENGTH = 1024;

export function assertAcceptablePassword(password: string): void {
  if (typeof password !== "string" || password.length < MIN_PASSWORD_LENGTH) {
    throw new PasswordError(
      `password must be at least ${MIN_PASSWORD_LENGTH} characters`,
      400,
      "weak_password",
    );
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new PasswordError(
      `password must be at most ${MAX_PASSWORD_LENGTH} characters`,
      400,
      "password_too_long",
    );
  }
}

// ---------------------------------------------------------------------------------------
// Breached-password check (HaveIBeenPwned k-anonymity range API)
// ---------------------------------------------------------------------------------------
//
// OPTIONAL defence: reject passwords known to appear in public breach corpora, BEFORE we hash
// and persist them. Privacy-preserving: we SHA-1 the password, send ONLY the first 5 hex chars
// of the digest to the range API, and search the returned suffix list locally — the full hash
// (and therefore the password) never leaves the Worker. Gated behind `CHECK_BREACHED_PASSWORDS`
// (OFF in dev/tests; turn ON in prod). FAIL OPEN: a network error / non-2xx from HIBP ALLOWS the
// password (we never block a signup on a third-party outage). The fetch is injectable so unit
// tests never touch the network.

/// HIBP Pwned Passwords range endpoint. The 5-char prefix is appended at call time.
const HIBP_RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range/";

/// SHA-1 of `bytes` as an UPPERCASE hex string (HIBP returns uppercase suffixes). WebCrypto only.
async function sha1HexUpper(bytes: Uint8Array): Promise<string> {
  const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const digest = await crypto.subtle.digest("SHA-1", buf);
  let hex = "";
  for (const b of new Uint8Array(digest)) hex += b.toString(16).padStart(2, "0");
  return hex.toUpperCase();
}

/// Options for the breached-password check. `fetchImpl` + `endpoint` are injectable so tests
/// assert the k-anonymity request shape with zero network; `enabled` gates the whole check.
///
/// NOTE (FINDING #2): the check is OFF by default — `enabled` must be set true (the integration
/// derives this from `CHECK_BREACHED_PASSWORDS`=1/true in `breachCheckForEnv`). Turn it ON in prod.
export interface BreachCheckOptions {
  /// Master switch. When false/undefined the check is SKIPPED (returns false = "not breached").
  enabled?: boolean;
  /// Injectable fetch (defaults to the global). Tests pass a fake; prod passes the platform fetch.
  fetchImpl?: typeof fetch;
  /// Override the range endpoint base (defaults to the real HIBP API).
  endpoint?: string;
  /// FINDING #2: observability hook for the fail-open path. Invoked (best-effort) whenever the HIBP
  /// query ERRORS — a network failure, a parse failure, or a non-2xx status. When omitted we still
  /// emit a `console.warn` so a misconfigured/unreachable endpoint silently becoming a no-op is
  /// VISIBLE in logs/metrics rather than invisible. The hook never affects the returned verdict.
  onError?: (info: { kind: "status" | "network" | "parse"; status?: number; error?: unknown }) => void;
}

/// Richer result of the breach query so callers can distinguish "checked, not breached" from
/// "could not check (errored)" — the latter is what FINDING #2's optional fail-closed mode keys on.
export interface BreachCheckResult {
  /// True iff the password was positively found in the corpus.
  breached: boolean;
  /// True iff the query could not complete (network/parse/non-2xx). `breached` is false in this case
  /// (fail-open default), but a caller may choose to fail closed on it.
  errored: boolean;
}

/// Emit the fail-open observability signal: the caller-supplied hook AND a console.warn (FINDING #2),
/// so a forced/misconfigured endpoint silently no-opping the check is never invisible.
function reportBreachError(
  opts: BreachCheckOptions,
  info: { kind: "status" | "network" | "parse"; status?: number; error?: unknown },
): void {
  // console.warn is the baseline metric sink in workerd (surfaces in `wrangler tail`/logs).
  console.warn(
    `[breach-check] HIBP query failed (${info.kind}${info.status ? ` ${info.status}` : ""}) — failing OPEN; password NOT verified against the breach corpus`,
  );
  try {
    opts.onError?.(info);
  } catch {
    /* an observability hook must never break the auth flow */
  }
}

/// Query the HIBP Pwned Passwords corpus for `password` (k-anonymity range query), returning both
/// the verdict AND whether the query errored. Never throws. On ANY error/non-2xx it reports the
/// failure (FINDING #2 observability) and returns `{ breached:false, errored:true }` (FAIL OPEN by
/// default — the verdict alone never blocks on an HIBP outage).
export async function checkPasswordBreach(
  password: string,
  opts: BreachCheckOptions = {},
): Promise<BreachCheckResult> {
  if (!opts.enabled) return { breached: false, errored: false };
  const doFetch = opts.fetchImpl ?? fetch;
  const base = opts.endpoint ?? HIBP_RANGE_ENDPOINT;
  let res: Response;
  try {
    const sha1 = await sha1HexUpper(enc.encode(password));
    const prefix = sha1.slice(0, 5);
    const suffix = sha1.slice(5); // the part we match locally; never sent.
    res = await doFetch(`${base}${prefix}`, {
      method: "GET",
      // Add-Padding asks HIBP to pad the response so its size doesn't leak the prefix's hit count.
      headers: { "Add-Padding": "true" },
    });
    if (!res.ok) {
      reportBreachError(opts, { kind: "status", status: res.status });
      return { breached: false, errored: true };
    }
    const text = await res.text();
    // Each line is "<SUFFIX>:<count>" (CRLF-separated). A breach is a suffix match with count>0
    // (padding rows are synthetic and carry count 0). Compare suffix case-insensitively.
    for (const line of text.split(/\r?\n/)) {
      const colon = line.indexOf(":");
      if (colon === -1) continue;
      const lineSuffix = line.slice(0, colon).trim().toUpperCase();
      if (lineSuffix !== suffix) continue;
      const count = Number(line.slice(colon + 1).trim());
      return { breached: Number.isFinite(count) && count > 0, errored: false };
    }
    return { breached: false, errored: false };
  } catch (error) {
    reportBreachError(opts, { kind: "network", error });
    return { breached: false, errored: true }; // fail open on network/parse error.
  }
}

/// True iff `password` appears in the HIBP Pwned Passwords corpus (k-anonymity range query).
/// Returns false (allow) when disabled OR on ANY error/non-2xx (FAIL OPEN). Never throws. Errors are
/// now LOGGED (FINDING #2) via `checkPasswordBreach`, which this thin wrapper delegates to.
export async function isPasswordBreached(
  password: string,
  opts: BreachCheckOptions = {},
): Promise<boolean> {
  return (await checkPasswordBreach(password, opts)).breached;
}

/// Assert a password is not known-breached, throwing `PasswordError(400, "password_breached")`
/// when it is. No-op when the check is disabled. Call this at signup + password change + reset
/// BEFORE hashing/persisting.
///
/// FAIL-OPEN vs FAIL-CLOSED (FINDING #2): by default an HIBP outage is FAIL-OPEN (the password is
/// allowed) — never block a user on a third-party outage, and a forced-but-broken endpoint is now
/// observable (logged) rather than a silent no-op. Pass `failClosed:true` to instead REJECT with
/// `PasswordError(503, "password_breach_check_unavailable")` when the check is enabled but could not
/// complete. Recommended for password CHANGE/RESET (a deliberate, retryable action) but NOT for
/// signup, where failing closed would lock new users out during an outage. (PasswordError's status
/// type caps at 500, so the fail-closed rejection is a 500 `password_breach_check_unavailable`.)
export async function assertPasswordNotBreached(
  password: string,
  opts: BreachCheckOptions & { failClosed?: boolean } = {},
): Promise<void> {
  const { breached, errored } = await checkPasswordBreach(password, opts);
  if (breached) {
    throw new PasswordError(
      "this password has appeared in a data breach; choose a different one",
      400,
      "password_breached",
    );
  }
  if (errored && opts.failClosed) {
    throw new PasswordError(
      "could not verify the password against the breach corpus; please try again",
      500,
      "password_breach_check_unavailable",
    );
  }
}

// ---------------------------------------------------------------------------------------
// Core scrypt KDF
// ---------------------------------------------------------------------------------------

/// Derive the scrypt key for `password` with the given salt + cost. Uses `scryptAsync` so the
/// KDF yields to the event loop (cooperative; avoids monopolizing the isolate) — important in
/// workerd where a single long sync compute blocks the request.
async function deriveKey(
  password: string,
  salt: Uint8Array,
  cost: { N: number; r: number; p: number; dkLen: number },
): Promise<Uint8Array> {
  return scryptAsync(enc.encode(password), salt, {
    N: cost.N,
    r: cost.r,
    p: cost.p,
    dkLen: cost.dkLen,
  });
}

/// Hash a plaintext password into a fully self-describing `PasswordCredential` (algo + cost +
/// salt + hash). Generates a fresh random salt. `cost` overrides the frozen default params;
/// `now` is injectable for deterministic tests.
export async function hashPassword(
  accountId: string,
  password: string,
  opts: { cost?: ScryptCost; now?: number } = {},
): Promise<PasswordCredential> {
  assertAcceptablePassword(password);
  const cost = resolveCost(opts.cost);
  const salt = randomBytes(SALT_BYTES);
  const dk = await deriveKey(password, salt, cost);
  return {
    accountId,
    algo: "scrypt",
    N: cost.N,
    r: cost.r,
    p: cost.p,
    dkLen: cost.dkLen,
    salt: b64urlEncode(salt),
    hash: b64urlEncode(dk),
    updatedAt: opts.now ?? Date.now(),
  };
}

/// Verify a plaintext password against a stored credential. Re-derives with the CREDENTIAL's
/// own stored params (never the global default) and compares in constant time. Returns a
/// boolean — callers decide the 401. Throws only on a structurally-invalid credential row.
export async function verifyPassword(
  cred: PasswordCredential,
  password: string,
): Promise<boolean> {
  if (cred.algo !== "scrypt") {
    throw new PasswordError(`unsupported password algo '${cred.algo}'`, 500, "bad_algo");
  }
  // Reject empty input fast (an empty stored hash must never match an empty password).
  if (typeof password !== "string" || password.length === 0) return false;
  if (password.length > MAX_PASSWORD_LENGTH) return false;

  const salt = b64urlDecode(cred.salt);
  const expected = b64urlDecode(cred.hash);
  const dk = await deriveKey(password, salt, {
    N: cred.N,
    r: cred.r,
    p: cred.p,
    dkLen: cred.dkLen,
  });
  return timingSafeEqual(dk, expected);
}

/// True iff a stored credential's params are weaker than the current target cost — a signal to
/// transparently re-hash on the next successful login. (Compared field-by-field; a higher N or
/// any changed param means "rehash".)
export function needsRehash(cred: PasswordCredential, target?: ScryptCost): boolean {
  const t = resolveCost(target);
  return cred.algo !== "scrypt" || cred.N < t.N || cred.r !== t.r || cred.p !== t.p || cred.dkLen !== t.dkLen;
}

// ---------------------------------------------------------------------------------------
// Store-backed helpers (CONTRACTS-AUTH.md §4.2). Each takes the `PasswordStore` injected.
// ---------------------------------------------------------------------------------------

/// Set (or replace) an account's password. Used by signup and admin "set password". Hashes
/// with the (optional) target cost and persists a fresh credential.
export async function setPassword(
  store: PasswordStore,
  accountId: string,
  newPassword: string,
  opts: { cost?: ScryptCost; now?: number } = {},
): Promise<PasswordCredential> {
  const cred = await hashPassword(accountId, newPassword, opts);
  await store.putPassword(cred);
  return cred;
}

/// Change password: verify the current password, then set the new one. Throws
/// `PasswordError(401, "no_password")` if no credential exists, `PasswordError(401,
/// "bad_current_password")` if the current password is wrong (constant-time verify).
/// `POST /v1/auth/password/change` (CONTRACTS-AUTH.md §4.2).
export async function changePassword(
  store: PasswordStore,
  accountId: string,
  currentPassword: string,
  newPassword: string,
  opts: { cost?: ScryptCost; now?: number } = {},
): Promise<PasswordCredential> {
  // Validate the NEW password before doing the (costly) current-password verify, so a
  // weak-new-password request fails fast and cheaply.
  assertAcceptablePassword(newPassword);

  const existing = await store.getPassword(accountId);
  if (!existing) {
    throw new PasswordError("account has no password set", 401, "no_password");
  }
  const ok = await verifyPassword(existing, currentPassword);
  if (!ok) {
    throw new PasswordError("current password is incorrect", 401, "bad_current_password");
  }
  return setPassword(store, accountId, newPassword, opts);
}

/// Reset password: set a new password WITHOUT the current one (gated upstream by a verified
/// single-use reset token, owned by the email lane). `POST /v1/auth/password/reset`
/// (CONTRACTS-AUTH.md §4.2). The caller is responsible for having validated the reset token
/// and for revoking the account's live sessions afterward.
export async function resetPassword(
  store: PasswordStore,
  accountId: string,
  newPassword: string,
  opts: { cost?: ScryptCost; now?: number } = {},
): Promise<PasswordCredential> {
  return setPassword(store, accountId, newPassword, opts);
}

/// Verify a login attempt against the stored credential for an account. Returns whether the
/// password matched plus a `rehash` hint. Does NOT throw on a wrong password (returns
/// `{ ok: false }`) so the login handler controls enumeration-safe responses; throws only if
/// the account has no password credential at all (`no_password`) — the caller maps that to the
/// same generic 401 as a wrong password to avoid leaking which accounts have passwords.
export async function verifyAccountPassword(
  store: PasswordStore,
  accountId: string,
  password: string,
  target?: ScryptCost,
): Promise<{ ok: boolean; rehash: boolean }> {
  const cred = await store.getPassword(accountId);
  if (!cred) {
    throw new PasswordError("account has no password set", 401, "no_password");
  }
  const ok = await verifyPassword(cred, password);
  return { ok, rehash: ok && needsRehash(cred, target) };
}

// ---------------------------------------------------------------------------------------
// Test-only / introspection exports (kept internal-ish; safe to expose).
// ---------------------------------------------------------------------------------------

/// base64url helpers re-exported for sibling auth lanes + tests (single source of truth here).
export const passwordCodec = { b64urlEncode, b64urlDecode, randomBytes };
