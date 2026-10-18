// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs TOTP (RFC 6238) — second-factor enrollment, verification, and recovery codes.
///
/// LANE: this file is owned solely by the TOTP lane (see CONTRACTS-AUTH.md §3). It depends
/// only on the `CredentialStore` interface (constructor/param injection) — never on a
/// concrete Durable Object — so it is unit-testable against an in-memory fake.
///
/// WORKERS CORRECTNESS (workers-best-practices):
///   - No Node built-ins. HMAC/SHA come from `@noble/hashes` (pure JS, WASM-free); randomness
///     comes from WebCrypto (`crypto.getRandomValues`), never `Math.random`.
///   - All secret/code comparisons are CONSTANT-TIME (XOR-accumulate over fixed-length bytes)
///     to deny timing oracles.
///   - The clock is INJECTED (`now: number` ms-epoch, default `Date.now()`) so verification,
///     skew windows, and replay are deterministic in tests.
///   - No module-level mutable request state; every function is pure-ish over its args + deps.
///
/// FROZEN PARAMS (CONTRACTS-AUTH.md §1.3):
///   algorithm SHA-1 · 6 digits · 30s period · ±1 step skew · 10 recovery codes (10 base32
///   chars each, single-use, stored sha256-hashed). The TOTP `secret` is stored plaintext in
///   the DO (the DO is the trust boundary); recovery codes are stored hashed only.
///
/// REPLAY GUARD: a successfully-consumed time-step is recorded as a short-lived challenge
/// (`purpose: "totp_used"`, value = the step number) via the injected CredentialStore, so the
/// same code can never be replayed inside its validity window — even across the ±1 skew.

import { sha1 } from "@noble/hashes/sha1";
import { sha256 } from "@noble/hashes/sha2";
import { hmac } from "@noble/hashes/hmac";

// ---------------------------------------------------------------------------------------
// Frozen TOTP parameters (CONTRACTS-AUTH.md §1.3)
// ---------------------------------------------------------------------------------------

/// RFC 6238 step length in seconds.
export const TOTP_PERIOD_SECONDS = 30;
/// Number of output digits.
export const TOTP_DIGITS = 6;
/// Allowed step skew on either side of the current step (±1 => accepts prev/current/next).
export const TOTP_SKEW_STEPS = 1;
/// Hash algorithm name as it appears in the otpauth:// URI.
export const TOTP_ALGORITHM = "SHA1";
/// Recovery-code policy.
export const RECOVERY_CODE_COUNT = 10;
export const RECOVERY_CODE_LENGTH = 10; // chars of base32
/// Random secret length in bytes (20 bytes = 160 bits, the RFC 6238 / authenticator default).
export const TOTP_SECRET_BYTES = 20;
/// How long a consumed-step replay marker is retained (one full window + slack, in ms).
const REPLAY_TTL_MS = (TOTP_SKEW_STEPS * 2 + 1) * TOTP_PERIOD_SECONDS * 1000 + 60_000;

// ---------------------------------------------------------------------------------------
// Types shared with the contract (CONTRACTS-AUTH.md §1.3). Defined locally so this lane is
// self-contained; the integration agent's `auth-types.ts` mirrors these shapes 1:1. If/when
// that file lands, these can be re-exported from it without changing any call site.
// ---------------------------------------------------------------------------------------

export interface TotpCredential {
  accountId: string; // PK
  secret: string; // base32 TOTP secret (RFC 4648, no padding). Stored as-is.
  confirmed: boolean; // false until the user proves a code during enrollment
  createdAt: number;
  confirmedAt: number | null;
}

export interface RecoveryCode {
  accountId: string;
  codeHash: string; // sha256 (base64url) of a single-use recovery code
  usedAt: number | null; // null = unused
}

/// The slice of `CredentialStore` (CONTRACTS-AUTH.md §2) this lane needs. We narrow to exactly
/// the methods used so the lane stays decoupled and the in-memory test fake is tiny.
export interface TotpCredentialStore {
  beginTotpEnrollment(cred: TotpCredential): Promise<boolean>;
  completeTotpEnrollment(accountId: string, secret: string, confirmedAt: number, step: number, expiresAt: number, recoveryHashes: string[]): Promise<boolean>;
  claimTotpStep(accountId: string, secret: string, step: number, expiresAt: number): Promise<boolean>;
  getTotp(accountId: string): Promise<TotpCredential | null>;
  putTotp(cred: TotpCredential): Promise<void>;
  confirmTotp(accountId: string, confirmedAt: number): Promise<void>;
  deleteTotp(accountId: string): Promise<void>;
  putRecoveryCodes(accountId: string, codeHashes: string[]): Promise<void>;
  consumeRecoveryCode(accountId: string, codeHash: string, usedAt: number): Promise<boolean>;
  // short-lived challenges (reused here as the TOTP replay guard)
  putChallenge(c: {
    authEpoch?: number;
    id: string;
    accountId: string | null;
    purpose: string;
    value: string;
    expiresAt: number;
  }): Promise<void>;
  takeChallenge(
    id: string,
  ): Promise<{ authEpoch?: number; accountId: string | null; purpose: string; value: string; expiresAt: number } | null>;
}

/// Dependencies injected into each handler. `now`/`randomBytes` are injectable for
/// deterministic tests; they default to production WebCrypto.
export interface TotpDeps {
  store: TotpCredentialStore;
  /// ms-epoch clock. Injected for tests.
  now?: () => number;
  /// CSPRNG byte source. Injected for tests; defaults to WebCrypto.
  randomBytes?: (n: number) => Uint8Array;
  /// Issuer label shown in authenticator apps (e.g. "cloud-fs"). From env at the call site.
  issuer?: string;
}

export class TotpError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 401 | 404 | 409 = 400,
    readonly code: string = "totp_error",
  ) {
    super(message);
    this.name = "TotpError";
  }
}

// ---------------------------------------------------------------------------------------
// Low-level encoding helpers (no Node Buffer; workerd/global only)
// ---------------------------------------------------------------------------------------

const utf8 = new TextEncoder();

/// RFC 4648 base32 alphabet (no padding for our secrets/codes).
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode bytes to unpadded RFC 4648 base32 (uppercase) — the format authenticator apps want.
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/// Decode an RFC 4648 base32 string (case-insensitive, padding/spaces tolerated) to bytes.
/// Throws `TotpError` on an invalid character so a corrupt stored secret fails loudly.
export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new TotpError(`invalid base32 character '${ch}'`, 400, "bad_secret");
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/// base64url-encode bytes (no padding).
function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/// CSPRNG bytes via WebCrypto (workers-safe). Never Math.random.
function defaultRandomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/// Constant-time byte-array equality. Compares the full fixed length regardless of where the
/// first mismatch is, so it never leaks information through timing. (`@noble/hashes` does not
/// export `equalBytes` at v1.8.x, so we implement the standard XOR-accumulate locally.)
export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  // Compare lengths in constant-ish time by mixing the length difference into the accumulator
  // and iterating a fixed number of steps (the longer of the two) so the loop count never
  // reveals the secret length.
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) {
    const av = i < a.length ? a[i] : 0;
    const bv = i < b.length ? b[i] : 0;
    diff |= av ^ bv;
  }
  return diff === 0;
}

/// Constant-time string equality (UTF-8 bytes). Used for the 6-digit OTP compare.
function timingSafeEqualStr(a: string, b: string): boolean {
  return timingSafeEqualBytes(utf8.encode(a), utf8.encode(b));
}

// ---------------------------------------------------------------------------------------
// RFC 6238 core — HOTP/TOTP code generation
// ---------------------------------------------------------------------------------------

/// The time-step counter T = floor((unixSeconds - T0) / period). T0 defaults to 0 per RFC 6238.
export function timeStep(unixSeconds: number, period: number = TOTP_PERIOD_SECONDS): number {
  return Math.floor(unixSeconds / period);
}

/// 8-byte big-endian counter (RFC 4226 §5.1). JS bitwise is 32-bit, so build the 64-bit
/// counter across two 32-bit halves to stay correct past 2^32 steps (~4083 AD).
function counterBytes(counter: number): Uint8Array {
  const buf = new Uint8Array(8);
  let hi = Math.floor(counter / 0x100000000);
  let lo = counter >>> 0;
  for (let i = 7; i >= 4; i--) {
    buf[i] = lo & 0xff;
    lo = Math.floor(lo / 256);
  }
  for (let i = 3; i >= 0; i--) {
    buf[i] = hi & 0xff;
    hi = Math.floor(hi / 256);
  }
  return buf;
}

/// HOTP value for a given counter (RFC 4226 §5.3): dynamic-truncation of HMAC-SHA1, mod 10^digits.
export function hotp(secret: Uint8Array, counter: number, digits: number = TOTP_DIGITS): string {
  const mac = hmac(sha1, secret, counterBytes(counter));
  const offset = mac[mac.length - 1] & 0x0f;
  const binCode =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  const otp = binCode % 10 ** digits;
  return otp.toString().padStart(digits, "0");
}

/// TOTP value at a given unix time (RFC 6238). Thin wrapper over HOTP with the time-step counter.
export function totp(
  secret: Uint8Array,
  unixSeconds: number,
  digits: number = TOTP_DIGITS,
  period: number = TOTP_PERIOD_SECONDS,
): string {
  return hotp(secret, timeStep(unixSeconds, period), digits);
}

/// Verify a submitted code against the secret across the ±skew window. Returns the matched
/// step number (for the replay guard) or `null` if no step in the window matches. Constant-time
/// per-candidate compare; we still scan the full window even after a match would be cheaper,
/// because the window is tiny (3 steps) and correctness/replay-tracking need the exact step.
export function verifyTotpCode(
  secret: Uint8Array,
  code: string,
  unixSeconds: number,
  opts: { digits?: number; period?: number; skew?: number } = {},
): number | null {
  const digits = opts.digits ?? TOTP_DIGITS;
  const period = opts.period ?? TOTP_PERIOD_SECONDS;
  const skew = opts.skew ?? TOTP_SKEW_STEPS;
  const submitted = code.trim();
  // Reject obviously malformed input before touching the secret (length/charset are public).
  if (submitted.length !== digits || !/^\d+$/.test(submitted)) return null;

  const center = timeStep(unixSeconds, period);
  let matched: number | null = null;
  for (let i = -skew; i <= skew; i++) {
    const step = center + i;
    const candidate = hotp(secret, step, digits);
    // Constant-time compare; assign without breaking so timing doesn't reveal which step hit.
    if (timingSafeEqualStr(candidate, submitted)) {
      matched = step;
    }
  }
  return matched;
}

// ---------------------------------------------------------------------------------------
// otpauth:// enrollment URI (for QR generation client-side)
// ---------------------------------------------------------------------------------------

/// Build the standard otpauth://totp/ URI consumed by authenticator apps & QR encoders.
/// Label is `Issuer:account` (both percent-encoded), with issuer/algorithm/digits/period params.
export function buildOtpauthUri(params: {
  secretBase32: string;
  accountName: string; // usually the user's email
  issuer: string;
  digits?: number;
  period?: number;
  algorithm?: string;
}): string {
  const issuer = params.issuer;
  const q = new URLSearchParams({
    secret: params.secretBase32,
    issuer,
    algorithm: params.algorithm ?? TOTP_ALGORITHM,
    digits: String(params.digits ?? TOTP_DIGITS),
    period: String(params.period ?? TOTP_PERIOD_SECONDS),
  });
  // Label is `Issuer:account`. Per the otpauth convention (Google Authenticator's KeyUriFormat)
  // the issuer/account SEPARATOR is a LITERAL colon; the two sides are percent-encoded
  // individually. URLSearchParams uses '+' for spaces; otpauth consumers expect '%20', so we
  // normalize the query too.
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(params.accountName)}`;
  return `otpauth://totp/${label}?${q.toString().replace(/\+/g, "%20")}`;
}

// ---------------------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------------------

/// Hash a recovery code for storage: sha256 -> base64url. Single function so enrollment and
/// verification hash identically. Code is upper-cased + de-spaced first (user-friendly entry).
export function hashRecoveryCode(code: string): string {
  const normalized = code.toUpperCase().replace(/\s+/g, "");
  return b64urlEncode(sha256(utf8.encode(normalized)));
}

/// Generate `count` random base32 recovery codes (display form). Each is `length` base32 chars
/// drawn uniformly from the CSPRNG (rejection-free: we map whole random bytes through base32 and
/// slice, which is uniform because base32 chars map 1:1 to 5-bit groups).
export function generateRecoveryCodes(
  count: number,
  length: number,
  randomBytes: (n: number) => Uint8Array,
): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    // 5 bits per char => ceil(length*5/8) bytes gives at least `length` chars.
    const nBytes = Math.ceil((length * 5) / 8);
    const raw = base32Encode(randomBytes(nBytes)).slice(0, length);
    codes.push(raw);
  }
  return codes;
}

// ---------------------------------------------------------------------------------------
// Enrollment / confirmation / login handlers (the lane's public surface)
// ---------------------------------------------------------------------------------------

export interface EnrollResult {
  secret: string; // base32 secret (unconfirmed)
  otpauthUri: string; // for QR
}

/// Begin (or restart) TOTP enrollment for an account: generate a fresh secret, persist it
/// UNCONFIRMED, and return the secret + otpauth URI. Re-enrolling overwrites any prior
/// unconfirmed secret. Refuses to clobber an ALREADY-CONFIRMED credential (409) — callers must
/// delete first (re-auth-gated) to rotate. CONTRACTS-AUTH.md §4.3 `POST /v1/auth/totp/enroll`.
export async function enrollTotp(
  accountId: string,
  accountEmail: string,
  deps: TotpDeps,
): Promise<EnrollResult> {
  const now = (deps.now ?? Date.now)();
  const rnd = deps.randomBytes ?? defaultRandomBytes;

  const existing = await deps.store.getTotp(accountId);
  if (existing?.confirmed) {
    throw new TotpError("TOTP already enabled; remove it before re-enrolling", 409, "totp_exists");
  }

  const secretBytes = rnd(TOTP_SECRET_BYTES);
  const secretBase32 = base32Encode(secretBytes);

  const cred: TotpCredential = {
    accountId,
    secret: secretBase32,
    confirmed: false,
    createdAt: now,
    confirmedAt: null,
  };
  if (!await deps.store.beginTotpEnrollment(cred)) {
    throw new TotpError("TOTP already enabled; remove it before re-enrolling", 409, "totp_exists");
  }

  const otpauthUri = buildOtpauthUri({
    secretBase32,
    accountName: accountEmail,
    issuer: deps.issuer ?? "cloud-fs",
  });
  return { secret: secretBase32, otpauthUri };
}

export interface ConfirmResult {
  confirmed: true;
  recoveryCodes: string[]; // shown ONCE
}

/// Confirm enrollment: the user proves possession by submitting a valid code. On first valid
/// code we mark the credential confirmed AND generate+store (hashed) the one-time recovery
/// codes, returning their plaintext exactly once. Idempotent-unfriendly by design: an already
/// confirmed credential returns 409 (recovery codes are not re-shown).
/// CONTRACTS-AUTH.md §4.3 `POST /v1/auth/totp/confirm`.
export async function confirmTotp(
  accountId: string,
  code: string,
  deps: TotpDeps,
): Promise<ConfirmResult> {
  const now = (deps.now ?? Date.now)();
  const rnd = deps.randomBytes ?? defaultRandomBytes;

  const cred = await deps.store.getTotp(accountId);
  if (!cred) throw new TotpError("no TOTP enrollment in progress", 404, "no_totp");
  if (cred.confirmed) throw new TotpError("TOTP already confirmed", 409, "totp_exists");

  const secret = base32Decode(cred.secret);
  const matchedStep = verifyTotpCode(secret, code, Math.floor(now / 1000));
  if (matchedStep === null) {
    throw new TotpError("invalid TOTP code", 401, "bad_code");
  }

  const recoveryCodes = generateRecoveryCodes(RECOVERY_CODE_COUNT, RECOVERY_CODE_LENGTH, rnd);
  if (!await deps.store.completeTotpEnrollment(accountId, cred.secret, now, matchedStep,
      now + REPLAY_TTL_MS, recoveryCodes.map(hashRecoveryCode))) {
    throw new TotpError("TOTP enrollment changed or was already confirmed", 409, "totp_exists");
  }

  return { confirmed: true, recoveryCodes };
}

/// Verify a login-time TOTP code for an account with a CONFIRMED credential. Enforces the ±1
/// step window AND the single-use replay guard (a step accepted once cannot be reused within its
/// window). Throws on no/unconfirmed credential or a bad/replayed code. Returns void on success;
/// the caller (auth-session lane) mints the session. CONTRACTS-AUTH.md §4.2 `POST /v1/auth/login/totp`.
export async function verifyLoginTotp(accountId: string, code: string, deps: TotpDeps): Promise<void> {
  const now = (deps.now ?? Date.now)();
  const cred = await deps.store.getTotp(accountId);
  if (!cred || !cred.confirmed) {
    throw new TotpError("TOTP is not enabled for this account", 401, "no_totp");
  }

  const secret = base32Decode(cred.secret);
  const matchedStep = verifyTotpCode(secret, code, Math.floor(now / 1000));
  if (matchedStep === null) {
    throw new TotpError("invalid TOTP code", 401, "bad_code");
  }

  // Claim without deleting an existing marker: a read/delete/reinsert sequence
  // across RPC awaits allows a concurrent login to reuse the same code.
  await recordUsedStep(accountId, cred.secret, matchedStep, now, deps.store);
}

/// Verify and CONSUME a one-time recovery code (used when the authenticator is unavailable).
/// Hash-compares against stored hashes; `consumeRecoveryCode` atomically marks it used and
/// returns false if it was missing or already used. CONTRACTS-AUTH.md §4.2 `POST /v1/auth/login/recovery`.
export async function verifyRecoveryCode(
  accountId: string,
  recoveryCode: string,
  deps: TotpDeps,
): Promise<void> {
  const now = (deps.now ?? Date.now)();
  const cred = await deps.store.getTotp(accountId);
  if (!cred || !cred.confirmed) {
    throw new TotpError("TOTP is not enabled for this account", 401, "no_totp");
  }
  const codeHash = hashRecoveryCode(recoveryCode);
  const ok = await deps.store.consumeRecoveryCode(accountId, codeHash, now);
  if (!ok) {
    throw new TotpError("invalid or already-used recovery code", 401, "bad_recovery_code");
  }
}

/// Remove TOTP from an account. The route layer (auth-wiring `runTotp` DELETE) STEP-UP-GATES this
/// with a fresh password proof (FINDING 3) before calling in — session+CSRF alone are insufficient
/// for second-factor removal. CONTRACTS-AUTH.md §4.3 `DELETE /v1/auth/totp`.
export async function disableTotp(accountId: string, deps: TotpDeps): Promise<void> {
  await deps.store.deleteTotp(accountId);
}

// ---- replay-guard internals -----------------------------------------------------------

/// Persist a short-lived single-use marker that `step` was consumed for `accountId`.
async function recordUsedStep(
  accountId: string,
  secret: string,
  step: number,
  now: number,
  store: TotpCredentialStore,
): Promise<void> {
  if (!await store.claimTotpStep(accountId, secret, step, now + REPLAY_TTL_MS)) {
    throw new TotpError("TOTP code already used or enrollment changed", 401, "code_replayed");
  }
}
