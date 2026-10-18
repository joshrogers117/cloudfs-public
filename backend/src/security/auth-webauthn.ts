// SPDX-License-Identifier: AGPL-3.0-or-later
/// cloud-fs WebAuthn / passkeys lane (CONTRACTS-AUTH.md §1.4, §4.4).
///
/// Passwordless-capable passkey support: the registration ceremony (generate
/// challenge + creation options, verify the attestation, persist
/// credentialId + COSE public key + signCount + transports) and the
/// authentication ceremony (generate challenge + request options, verify the
/// assertion, bump signCount, mint a session).
///
/// DESIGN / CONTRACT NOTES
///   - Verification is delegated to `@simplewebauthn/server` (CONTRACTS-AUTH.md §5:
///     "USE it"). Its core is isomorphic — WebCrypto + `@peculiar/asn1-*` + tiny-cbor,
///     NO Node built-ins — so it runs unmodified in workerd. We do NOT hand-roll
///     COSE-key/CBOR/attestation parsing.
///   - Workers-correct (workers-best-practices skill): no Node built-ins, all
///     randomness from `crypto.getRandomValues`/`crypto.randomUUID` (WebCrypto
///     globals), NO module-level mutable request state — every per-request value
///     is injected through `deps`. Secret-equality comparisons are constant-time
///     (`@simplewebauthn`'s verifier compares the signature in constant time; our
///     credential-id lookup is by exact key, not a byte loop).
///   - The challenge is INJECTED (`deps.randomChallenge`, defaulting to a 32-byte
///     `crypto.getRandomValues`) and STORED via the injected `CredentialStore`
///     challenge table (single-use `takeChallenge`), per the lane brief. Tests pass
///     deterministic `now`/`randomChallenge`/store fakes — no real network.
///   - RP ID + expected origin come from `env` (the integration lane wires these to
///     the portal domain; `localhost` in dev), NOT stored per-credential
///     (CONTRACTS-AUTH.md §1.4).
///
/// ASSERTION CHECKS ENFORCED (all delegated to @simplewebauthn, configured here):
///   registration:  challenge match (single-use, server-stored) · expectedOrigin ·
///                  expectedRPID (rpIdHash) · requireUserPresence · userVerification
///                  (configurable) · attestation signature validity.
///   authentication: challenge match (single-use, server-stored) · expectedOrigin ·
///                  expectedRPID (rpIdHash) · user-present/user-verified flags ·
///                  assertion signature over authData‖clientDataHash · and — enforced
///                  by THIS module — signCount regression rejection (cloned-authenticator
///                  detection): we reject when the authenticator reports a counter that
///                  did not advance past the stored value (when either is non-zero).

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  // The library exports a verification-input type ALSO named `WebAuthnCredential`
  // (id/publicKey/counter/transports). Alias it so it does not collide with the
  // cloud-fs domain record of the same name (CONTRACTS-AUTH.md §1.4).
  type WebAuthnCredential as LibWebAuthnCredential,
} from "@simplewebauthn/server";

import { AuthError } from "./auth";

/**
 * Local error carrying an arbitrary HTTP status + machine code. `auth.ts`'s
 * `AuthError` is intentionally narrowed to 401/403 (the gateway's authZ codes)
 * and is owned by another lane, so WebAuthn-specific statuses (400 bad ceremony,
 * 404 not-found, 409 duplicate, 500 misconfig) use this instead. `errorResponse`
 * understands both. The `status` is surfaced verbatim; `code` mirrors AuthError's
 * `.code` convention for symmetric handling in tests.
 */
export class WebAuthnError extends Error {
  constructor(
    message: string,
    readonly status: number = 400,
    readonly code: string = "webauthn_error",
  ) {
    super(message);
    this.name = "WebAuthnError";
  }
}

// ============================================================================
// Shared domain types.
//
// CONTRACTS-AUTH.md §3 says these live in `backend/src/security/auth-types.ts`,
// which the INTEGRATION agent "creates and freezes first" and lanes import
// read-only. That file does not exist yet, and this lane may NOT create or edit
// it (it is integration-owned). To stay self-contained and keep `tsc` clean, we
// re-declare ONLY the slice this module needs, matching the contract byte-for-byte.
// When integration freezes `auth-types.ts`, swap these for a read-only import.
// ============================================================================

/** CONTRACTS-AUTH.md §1.4 */
export type AuthnTransport = "usb" | "nfc" | "ble" | "internal" | "hybrid";

/** CONTRACTS-AUTH.md §1.4 — the persisted passkey record. */
export interface WebAuthnCredential {
  id: string; // "wac-<uuid>" internal row id
  accountId: string;
  credentialId: string; // base64url of the raw credential id (the WebAuthn handle)
  publicKey: string; // base64url of the COSE public key bytes
  signCount: number; // updated on each successful assertion (clone detection)
  transports: AuthnTransport[];
  label: string | null; // user-facing name ("MacBook Touch ID")
  createdAt: number;
  lastUsedAt: number | null;
}

/**
 * CONTRACTS-AUTH.md §2 — the slice of `CredentialStore` this lane depends on.
 * (Injected; unit tests pass an in-memory fake, integration passes the AuthDO
 * adapter.) The full interface lives in auth-types.ts; we only need WebAuthn +
 * challenge methods here.
 */
export interface WebAuthnCredentialStore {
  listWebAuthn(accountId: string): Promise<WebAuthnCredential[]>;
  getWebAuthnByCredentialId(credentialId: string): Promise<WebAuthnCredential | null>;
  putWebAuthn(cred: WebAuthnCredential): Promise<void>;
  updateWebAuthnSignCount(id: string, signCount: number, lastUsedAt: number): Promise<void>;
  deleteWebAuthn(id: string): Promise<void>;
  putChallenge(c: {
    id: string;
    accountId: string | null;
    purpose: string;
    value: string;
    expiresAt: number;
  }): Promise<void>;
  takeChallenge(
    id: string,
  ): Promise<{ accountId: string | null; purpose: string; value: string; expiresAt: number } | null>; // single-use
}

/**
 * CONTRACTS-AUTH.md §2 — minimal AccountStore slice for resolving the login
 * before the org is known (`authenticate/options` accepts a bare `email`).
 */
export interface WebAuthnAccountStore {
  resolveEmail(emailLower: string): Promise<{ orgId: string; accountId: string } | null>;
  getAccountByUserId?(userId: string): Promise<{ id: string; userId: string; orgId: string; role: string } | null>;
  getAccount(
    accountId: string,
  ): Promise<{ id: string; userId: string; orgId: string; role: string; status: string; authEpoch?: number; emailVerified?: boolean } | null>;
}

// ============================================================================
// Module config + dependency injection.
// ============================================================================

/**
 * RP configuration. The integration lane sources these from env so the portal
 * domain is configurable (`localhost` in dev). NOT stored per-credential.
 */
export interface WebAuthnConfig {
  /** Relying Party ID — the portal registrable domain, e.g. "portal.cloudfs.app" or "localhost". */
  rpID: string;
  /** Human-visible RP name shown in the platform passkey UI. */
  rpName: string;
  /**
   * Expected origin(s) of the ceremony, e.g. "https://portal.cloudfs.app" or
   * "http://localhost:5173". One or many (dev + prod). The assertion's
   * clientDataJSON.origin MUST be one of these.
   */
  expectedOrigin: string | string[];
  /** Require user verification (biometric/PIN) — true for passwordless. Default true. */
  requireUserVerification?: boolean;
  /** Challenge TTL in ms (default 5 min). */
  challengeTtlMs?: number;
}

/**
 * What this lane needs to mint a session after a successful passwordless
 * assertion. Provided by the SESSION lane / integration so this module never
 * reaches into another lane's file. Returns the cookie+body payload shape that
 * CONTRACTS-AUTH.md §4.4 specifies for the success response.
 */
export interface SessionMinter {
  mintForAccount(input: {
    accountId: string;
    userId: string;
    orgId: string;
    role: string;
    /// Whether the account's email is verified — the minter reduces scopes if false
    /// (CONTRACTS-AUTH.md §4.2 email-verification gate). Optional; treated as verified if omitted.
    authEpoch?: number; emailVerified?: boolean;
  }): Promise<{
    setCookie: string; // Set-Cookie header value for `cfs_session`
    body: { userId: string; orgId: string; role: string; scopes: string[]; csrf: string };
  }>;
}

/** Everything a WebAuthn handler needs, all injected (no globals, no Node). */
export interface WebAuthnDeps {
  store: WebAuthnCredentialStore;
  accounts: WebAuthnAccountStore;
  config: WebAuthnConfig;
  /** Mints the human session on passwordless auth. Optional for register-only deployments. */
  session?: SessionMinter;
  /** Clock — injectable for deterministic tests. Defaults to `Date.now`. */
  now?: () => number;
  /** Challenge source — 32 random bytes by default (WebCrypto). Injectable for tests. */
  randomChallenge?: () => Uint8Array;
  /** ID generator for stored rows + challenge ids. Defaults to `crypto.randomUUID`. */
  newId?: () => string;
}

const CHALLENGE_PURPOSE_REGISTER = "webauthn.register";
const CHALLENGE_PURPOSE_AUTH = "webauthn.authenticate";
const DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000;

// ---- small WebCrypto-only base64url helpers (no Node Buffer) ----------------

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url to a fresh `ArrayBuffer`-backed Uint8Array (the strict type the lib wants). */
function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** UTF-8 encode into a fresh `ArrayBuffer`-backed Uint8Array (strict variance for the lib). */
function utf8Bytes(s: string): Uint8Array<ArrayBuffer> {
  const src = new TextEncoder().encode(s);
  const out = new Uint8Array(new ArrayBuffer(src.length));
  out.set(src);
  return out;
}

function now(deps: WebAuthnDeps): number {
  return (deps.now ?? Date.now)();
}

function newId(deps: WebAuthnDeps): string {
  return (deps.newId ?? (() => crypto.randomUUID()))();
}

/** Default challenge source: 32 cryptographically-random bytes (WebCrypto). */
function freshChallenge(deps: WebAuthnDeps): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(32));
  if (deps.randomChallenge) {
    out.set(deps.randomChallenge());
    return out;
  }
  crypto.getRandomValues(out);
  return out;
}

/** Map our stored transports to the library's transport union (1:1 for our subset). */
function toLibTransports(t: AuthnTransport[]): AuthenticatorTransportFuture[] {
  return t as AuthenticatorTransportFuture[];
}

/** Narrow the library's transport union back to our stored subset (drop unsupported). */
function fromLibTransports(t: AuthenticatorTransportFuture[] | undefined): AuthnTransport[] {
  const allowed: AuthnTransport[] = ["usb", "nfc", "ble", "internal", "hybrid"];
  if (!t) return [];
  return t.filter((x): x is AuthnTransport => (allowed as string[]).includes(x));
}

function json(body: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...(extraHeaders ?? {}) },
  });
}

function errorResponse(e: unknown): Response {
  if (e instanceof AuthError || e instanceof WebAuthnError) {
    return json({ error: e.message }, e.status);
  }
  // Verification failures from @simplewebauthn throw plain Errors; surface as 400.
  const msg = e instanceof Error ? e.message : "webauthn error";
  return json({ error: msg }, 400);
}

// ============================================================================
// Ceremony primitives (pure-ish; exported for direct unit testing).
// ============================================================================

/**
 * REGISTRATION — step 1: generate creation options + stash the challenge.
 *
 * Caller (integration) provides the authenticated account (from the live
 * `cfs_session`). We exclude already-registered credentials so the user can't
 * double-enrol the same authenticator. The challenge is INJECTED and STORED
 * single-use; the returned `challengeId` is echoed back on verify.
 */
export async function startRegistration(
  deps: WebAuthnDeps,
  account: { id: string; userId: string; email: string; displayName: string },
): Promise<{ options: PublicKeyCredentialCreationOptionsJSON; challengeId: string }> {
  const existing = await deps.store.listWebAuthn(account.id);
  const challengeBytes = freshChallenge(deps);

  const options = await generateRegistrationOptions({
    rpName: deps.config.rpName,
    rpID: deps.config.rpID,
    userName: account.email,
    userDisplayName: account.displayName,
    // Stable, opaque user handle (NOT the email) — passwordless discoverable creds key on it.
    userID: utf8Bytes(account.userId),
    challenge: challengeBytes,
    attestationType: "none",
    excludeCredentials: existing.map((c) => ({
      id: c.credentialId,
      transports: toLibTransports(c.transports),
    })),
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: deps.config.requireUserVerification === false ? "preferred" : "required",
    },
  });

  const challengeId = `wch-${newId(deps)}`;
  await deps.store.putChallenge({
    id: challengeId,
    accountId: account.id,
    purpose: CHALLENGE_PURPOSE_REGISTER,
    value: options.challenge, // base64url challenge the authenticator will sign
    expiresAt: now(deps) + (deps.config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS),
  });

  return { options, challengeId };
}

/**
 * REGISTRATION — step 2: verify the attestation and persist the credential.
 *
 * Enforces: single-use server-stored challenge match, expectedOrigin,
 * expectedRPID (rpIdHash), user-present, and user-verification (when required),
 * plus attestation-signature validity (all via @simplewebauthn). On success the
 * COSE public key + initial signCount + transports are stored.
 */
export async function finishRegistration(
  deps: WebAuthnDeps,
  input: {
    accountId: string;
    challengeId: string;
    response: RegistrationResponseJSON;
    label?: string | null;
  },
): Promise<WebAuthnCredential> {
  const stored = await takeValidChallenge(deps, input.challengeId, CHALLENGE_PURPOSE_REGISTER);
  // Challenge must belong to the account that started the ceremony.
  if (stored.accountId !== input.accountId) {
    throw new WebAuthnError("challenge does not match account", 400, "challenge_mismatch");
  }

  const verification = await verifyRegistrationResponse({
    response: input.response,
    expectedChallenge: stored.value,
    expectedOrigin: deps.config.expectedOrigin,
    expectedRPID: deps.config.rpID,
    requireUserPresence: true,
    requireUserVerification: deps.config.requireUserVerification !== false,
  });

  if (!verification.verified || !verification.registrationInfo) {
    throw new WebAuthnError("registration verification failed", 400, "attestation_invalid");
  }

  const info = verification.registrationInfo;
  // Reject a second registration of the same credential id (unique index, §1.4).
  const dupe = await deps.store.getWebAuthnByCredentialId(info.credential.id);
  if (dupe) {
    throw new WebAuthnError("credential already registered", 409, "credential_exists");
  }

  const cred: WebAuthnCredential = {
    id: `wac-${newId(deps)}`,
    accountId: input.accountId,
    credentialId: info.credential.id, // base64url
    publicKey: b64urlEncode(info.credential.publicKey), // COSE public key bytes -> base64url
    signCount: info.credential.counter,
    transports: fromLibTransports(info.credential.transports),
    label: input.label ?? null,
    createdAt: now(deps),
    lastUsedAt: null,
  };
  await deps.store.putWebAuthn(cred);
  return cred;
}

/**
 * AUTHENTICATION — step 1: generate request options + stash the challenge.
 *
 * Three modes (CONTRACTS-AUTH.md §4.4):
 *   - `{ email }`  : resolve the account via the directory and narrow
 *     `allowCredentials` to that account's passkeys (non-discoverable fallback).
 *   - `{}` (usernameless / discoverable): empty `allowCredentials`; the platform
 *     picks a resident credential and we resolve the account on verify by
 *     credential id.
 *   - `{ secondFactor: { accountId } }` : a passkey used as the SECOND FACTOR after a
 *     successful password verify. The account is already known (the integration layer
 *     resolved it from the single-use login challenge), so we ALWAYS bind the challenge to
 *     it (no enumeration concern — the password already proved the account) and narrow
 *     `allowCredentials` to that account's passkeys. `finishAuthentication` then enforces
 *     the asserting credential belongs to this bound account.
 */
export async function startAuthentication(
  deps: WebAuthnDeps,
  input: { email?: string; secondFactor?: { accountId: string } },
): Promise<{ options: PublicKeyCredentialRequestOptionsJSON; challengeId: string }> {
  let accountId: string | null = null;
  let allowCredentials:
    | { id: string; transports?: AuthenticatorTransportFuture[] }[]
    | undefined;

  if (input.secondFactor) {
    // Post-password second-factor: bind unconditionally to the pre-resolved account.
    accountId = input.secondFactor.accountId;
    const creds = await deps.store.listWebAuthn(accountId);
    allowCredentials = creds.map((c) => ({
      id: c.credentialId,
      transports: toLibTransports(c.transports),
    }));
  } else if (input.email) {
    const emailLower = input.email.trim().toLowerCase();
    const resolved = await deps.accounts.resolveEmail(emailLower);
    // Non-enumerating: if unknown, we still emit options with an empty allow-list
    // so an attacker can't distinguish "no account" from "no passkeys".
    if (resolved) {
      accountId = resolved.accountId;
      const creds = await deps.store.listWebAuthn(resolved.accountId);
      allowCredentials = creds.map((c) => ({
        id: c.credentialId,
        transports: toLibTransports(c.transports),
      }));
    }
  }

  const challengeBytes = freshChallenge(deps);
  const options = await generateAuthenticationOptions({
    rpID: deps.config.rpID,
    challenge: challengeBytes,
    allowCredentials,
    userVerification: deps.config.requireUserVerification === false ? "preferred" : "required",
  });

  const challengeId = `wch-${newId(deps)}`;
  await deps.store.putChallenge({
    id: challengeId,
    accountId, // may be null for discoverable / unknown-email flows
    purpose: CHALLENGE_PURPOSE_AUTH,
    value: options.challenge,
    expiresAt: now(deps) + (deps.config.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS),
  });

  return { options, challengeId };
}

/**
 * AUTHENTICATION — step 2: verify the assertion, update signCount, return the
 * matched credential + account.
 *
 * Enforces EVERY required check:
 *   - challenge match (single-use, server-stored)         [here + @simplewebauthn]
 *   - expectedOrigin                                      [@simplewebauthn]
 *   - expectedRPID / rpIdHash                             [@simplewebauthn]
 *   - user-present + user-verified flags                  [@simplewebauthn]
 *   - assertion signature over authData‖clientDataHash    [@simplewebauthn, constant-time]
 *   - signCount REGRESSION rejection (clone detection)    [HERE, see below]
 */
export async function finishAuthentication(
  deps: WebAuthnDeps,
  input: { challengeId: string; response: AuthenticationResponseJSON; requireAccountId?: string },
): Promise<{
  credential: WebAuthnCredential;
  account: { id: string; userId: string; orgId: string; role: string; authEpoch?: number; emailVerified?: boolean };
}> {
  const stored = await takeValidChallenge(deps, input.challengeId, CHALLENGE_PURPOSE_AUTH);

  // Resolve the credential by the id the authenticator returned.
  const credentialId = input.response.id; // base64url credential id
  const cred = await deps.store.getWebAuthnByCredentialId(credentialId);
  if (!cred) {
    throw new WebAuthnError("unknown credential", 400, "unknown_credential");
  }

  // If the challenge was bound to an account (email flow), the asserting
  // credential MUST belong to it — defeats credential-substitution.
  if (stored.accountId !== null && stored.accountId !== cred.accountId) {
    throw new WebAuthnError("credential does not match challenge", 400, "challenge_mismatch");
  }

  // Post-password second-factor: the asserting credential MUST belong to the account the
  // password already proved (defeats using someone ELSE's passkey to complete the 2nd factor).
  if (input.requireAccountId !== undefined && input.requireAccountId !== cred.accountId) {
    throw new WebAuthnError("credential does not match challenge", 400, "challenge_mismatch");
  }

  const account = await deps.accounts.getAccount(cred.accountId);
  if (!account) throw new WebAuthnError("account not found", 400, "no_account");
  if (account.status !== "active") {
    throw new AuthError("account is not active", 403, "account_inactive");
  }

  const libCred: LibWebAuthnCredential = {
    id: cred.credentialId,
    publicKey: b64urlDecode(cred.publicKey),
    counter: cred.signCount,
    transports: toLibTransports(cred.transports),
  };

  // @simplewebauthn enforces signature/origin/rpIdHash/UP/UV AND the
  // signCount-regression check itself (it knows `credential.counter`): per spec it
  // throws when `(new > 0 || stored > 0) && new <= stored` — i.e. the counter did
  // not strictly advance while at least one side is non-zero. That is exactly the
  // cloned-authenticator rule (CONTRACTS-AUTH.md §1.4). We normalize that specific
  // throw into a TYPED `signcount_regression` (401) so callers get a stable code
  // instead of a bare library Error, while a 0/0 authenticator (counters that never
  // increment) is correctly allowed through.
  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response: input.response,
      expectedChallenge: stored.value,
      expectedOrigin: deps.config.expectedOrigin,
      expectedRPID: deps.config.rpID,
      credential: libCred,
      requireUserVerification: deps.config.requireUserVerification !== false,
    });
  } catch (e) {
    if (isSignCountRegression(e)) {
      throw new WebAuthnError(
        "authenticator signCount regression — possible cloned authenticator",
        401,
        "signcount_regression",
      );
    }
    throw e;
  }

  if (!verification.verified) {
    throw new WebAuthnError("assertion verification failed", 400, "assertion_invalid");
  }

  const newCounter = verification.authenticationInfo.newCounter;
  await deps.store.updateWebAuthnSignCount(cred.id, newCounter, now(deps));

  return {
    credential: { ...cred, signCount: newCounter, lastUsedAt: now(deps) },
    account: {
      id: account.id,
      userId: account.userId,
      orgId: account.orgId,
      role: account.role,
      emailVerified: account.emailVerified,
      authEpoch: account.authEpoch,
    },
  };
}

/**
 * Recognize @simplewebauthn's signCount-regression throw. The library emits a
 * stable message ("Response counter value N was lower than expected M") from this
 * one spec check; matching it lets us re-throw a typed error without re-implementing
 * (and thus risking divergence from) the spec rule.
 */
function isSignCountRegression(e: unknown): boolean {
  return e instanceof Error && /counter value .* lower than expected/i.test(e.message);
}

/** Fetch a stored challenge, assert single-use validity, purpose, and TTL. */
async function takeValidChallenge(
  deps: WebAuthnDeps,
  challengeId: string,
  expectedPurpose: string,
): Promise<{ accountId: string | null; purpose: string; value: string; expiresAt: number }> {
  const c = await deps.store.takeChallenge(challengeId); // single-use: store deletes on read
  if (!c) throw new WebAuthnError("challenge not found or already used", 400, "challenge_unknown");
  if (c.purpose !== expectedPurpose) {
    throw new WebAuthnError("challenge purpose mismatch", 400, "challenge_purpose");
  }
  if (c.expiresAt <= now(deps)) {
    throw new WebAuthnError("challenge expired", 400, "challenge_expired");
  }
  return c;
}

// ============================================================================
// Public-shape mappers + management helpers.
// ============================================================================

/** Strip internal/secret fields for the `GET .../credentials` list (§4.4). */
export function toPublicCredential(c: WebAuthnCredential): {
  id: string;
  credentialId: string;
  label: string | null;
  transports: AuthnTransport[];
  createdAt: number;
  lastUsedAt: number | null;
} {
  return {
    id: c.id,
    credentialId: c.credentialId,
    label: c.label,
    transports: c.transports,
    createdAt: c.createdAt,
    lastUsedAt: c.lastUsedAt,
  };
}

// ============================================================================
// HTTP handlers — CONTRACTS-AUTH.md §3 "handleX(req, deps, pathParts)" shape.
//
// Integration dispatches these; auth/CSRF gating happens BEFORE dispatch, so the
// caller passes the resolved `account` for session-gated routes via `ctx`.
// ============================================================================

/** Context the integration layer threads in after running the session/CSRF gate. */
export interface WebAuthnRouteCtx {
  /** The authenticated account for session-gated routes (register/list/delete). */
  account?: { id: string; userId: string; orgId: string; email: string; displayName: string; role: string };
  /**
   * Passkey-as-SECOND-FACTOR binding (CONTRACTS-AUTH.md §4.2/§4.4). When the public
   * `authenticate/options|verify` routes are reached AFTER a successful password verify, the
   * integration layer resolves the single-use login challenge to its bound account and threads
   * it here. `options` then narrows to this account's passkeys and binds the new webauthn
   * challenge to it; `verify` enforces the asserting credential belongs to this account and
   * mints the session — the passkey is a genuine SECOND factor, not a passwordless entrypoint.
   */
  secondFactor?: { accountId: string };
}

/**
 * Dispatch the WebAuthn route surface. `pathParts` is the path AFTER
 * `/v1/auth/webauthn/` (e.g. ["register","options"]). Returns null if no route
 * matched (so integration can fall through / 404).
 */
export async function handleWebAuthn(
  req: Request,
  deps: WebAuthnDeps,
  pathParts: string[],
  ctx: WebAuthnRouteCtx = {},
): Promise<Response | null> {
  const [a, b, c] = pathParts;
  try {
    // ---- register/options (session) ----
    if (req.method === "POST" && a === "register" && b === "options") {
      const account = requireAccount(ctx);
      const { options, challengeId } = await startRegistration(deps, account);
      return json({ ...options, challengeId });
    }

    // ---- register/verify (session) ----
    if (req.method === "POST" && a === "register" && b === "verify") {
      const account = requireAccount(ctx);
      const body = (await req.json()) as {
        challengeId?: string;
        response?: RegistrationResponseJSON;
        label?: string | null;
      };
      if (!body?.challengeId || !body?.response) {
        throw new WebAuthnError("missing challengeId or response", 400, "bad_request");
      }
      const cred = await finishRegistration(deps, {
        accountId: account.id,
        challengeId: body.challengeId,
        response: body.response,
        label: body.label ?? null,
      });
      return json({ credentialId: cred.credentialId, label: cred.label }, 201);
    }

    // ---- authenticate/options (public; or post-password second factor) ----
    if (req.method === "POST" && a === "authenticate" && b === "options") {
      const body = (await req.json().catch(() => ({}))) as { email?: string };
      // A second-factor binding (resolved from a login challenge by integration) takes priority
      // over a body email: the password already proved the account, so we scope to its passkeys.
      const { options, challengeId } = await startAuthentication(
        deps,
        ctx.secondFactor ? { secondFactor: ctx.secondFactor } : { email: body?.email },
      );
      return json({ ...options, challengeId });
    }

    // ---- authenticate/verify (public; or post-password second factor) -> mints session ----
    if (req.method === "POST" && a === "authenticate" && b === "verify") {
      const body = (await req.json()) as { challengeId?: string; response?: AuthenticationResponseJSON };
      if (!body?.challengeId || !body?.response) {
        throw new WebAuthnError("missing challengeId or response", 400, "bad_request");
      }
      const { account } = await finishAuthentication(deps, {
        challengeId: body.challengeId,
        response: body.response,
        // Second-factor: the asserting credential MUST belong to the password-proven account.
        ...(ctx.secondFactor ? { requireAccountId: ctx.secondFactor.accountId } : {}),
      });
      if (!deps.session) {
        throw new WebAuthnError("session minting not configured", 500, "no_session_minter");
      }
      const minted = await deps.session.mintForAccount({
        accountId: account.id,
        userId: account.userId,
        orgId: account.orgId,
        role: account.role,
        emailVerified: account.emailVerified,
      authEpoch: account.authEpoch,
      });
      return json(minted.body, 200, { "set-cookie": minted.setCookie });
    }

    // ---- GET credentials (session) ----
    if (req.method === "GET" && a === "credentials" && b === undefined) {
      const account = requireAccount(ctx);
      const creds = await deps.store.listWebAuthn(account.id);
      return json(creds.map(toPublicCredential));
    }

    // ---- DELETE credentials/:id (session + CSRF + step-up) ----
    // The route layer (auth-wiring `runWebAuthn`) STEP-UP-GATES this with a fresh password proof
    // (FINDING 3) BEFORE delegating here — session+CSRF alone would let a live-session attacker strip
    // a victim's passkey. This lane still enforces ownership (no IDOR) below.
    if (req.method === "DELETE" && a === "credentials" && typeof b === "string" && c === undefined) {
      const account = requireAccount(ctx);
      const all = await deps.store.listWebAuthn(account.id);
      const target = all.find((x) => x.id === b);
      // Only delete a credential the caller actually owns (no IDOR).
      if (!target) throw new WebAuthnError("credential not found", 404, "not_found");
      await deps.store.deleteWebAuthn(target.id);
      return new Response(null, { status: 204 });
    }

    return null;
  } catch (e) {
    return errorResponse(e);
  }
}

function requireAccount(ctx: WebAuthnRouteCtx): NonNullable<WebAuthnRouteCtx["account"]> {
  if (!ctx.account) throw new AuthError("authentication required", 401, "no_session");
  return ctx.account;
}
