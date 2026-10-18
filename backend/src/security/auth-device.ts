// SPDX-License-Identifier: AGPL-3.0-or-later
/// auth-device.ts — the DEVICE-SESSION lane (auth-spec §2.1–§2.4): the Mac app's browser-handoff
/// sign-in. A signed-in portal user APPROVES a device (minting a single-use, PKCE-bound,
/// 5-minute authorization code); the app exchanges code+verifier for a LONG-LIVED device
/// session (opaque refresh token, 400-day SLIDING expiry, rotate-on-use with reuse detection)
/// plus a short-lived access JWS whose `jti == deviceSessionId` so the EXISTING revocation gate
/// (`isJtiRevoked`) covers it with zero new gateway code.
///
/// Security model (auth-spec §5.1–§5.3):
///   - PKCE S256 is MANDATORY: on macOS a custom URL scheme is first-claimant, so the code must
///     be useless alone. The code binds sha256(verifier) at approval; only the process holding
///     the verifier can exchange it. A failed PKCE attempt BURNS the code (consume-then-verify).
///   - The refresh secret is high-entropy (32 bytes), stored ONLY as sha256(secret); rotation on
///     every refresh with a 60s race-grace for the lost-response retry; presentation of a
///     superseded secret AFTER the grace ⇒ assume theft ⇒ revoke the whole device session.
///   - Account status + role are re-read on every exchange/rotate, so offboarding and role
///     changes propagate within one access-token TTL.
///
/// Like the sibling lanes (auth-session/auth-service-tokens), this module is PURE-ish: stores,
/// clock, randomness and the signing env are injected; no `cloudflare:workers` import. The
/// integration layer (auth-wiring.ts) owns HTTP parsing, org-qualified handles and rate limits.

import { mintToken, DEFAULT_TTL_SECONDS, type Scope, type AuthEnv } from "./auth";
import { hashSecret, verifySecret } from "./auth-service-tokens";
import { timingSafeEqualStr } from "./auth-session";
import { scopesForLogin } from "./auth-signup";
import type { Account } from "./auth-types";

// ---------------------------------------------------------------------------------------
// Frozen policy constants (auth-spec §4.1 / §4.3).
// ---------------------------------------------------------------------------------------

/// One-time device authorization codes live 5 minutes (single use regardless).
export const DEVICE_CODE_TTL_MS = 5 * 60 * 1000;
/// Device-session lifetime — SLIDING: re-armed to now+400d on every successful rotation, so an
/// active device never expires; an abandoned one dies after 400 days of silence.
export const DEVICE_SESSION_LIFETIME_MS = 400 * 24 * 60 * 60 * 1000;
/// After a rotation the SUPERSEDED refresh secret stays valid for this window, ONLY to absorb the
/// lost-response retry race (the single in-flight client re-presenting the old secret). Past it,
/// presenting the old secret is treated as token theft (reuse detection).
export const REFRESH_ROTATION_GRACE_MS = 60 * 1000;
/// Access-JWS TTL the device lane mints (same 15-min `session` policy as the cookie path).
export const DEVICE_ACCESS_TTL_SECONDS = DEFAULT_TTL_SECONDS.session;

/// PKCE bounds (RFC 7636 §4.1): both the verifier and the S256 challenge are 43–128 base64url chars.
const PKCE_MIN = 43;
const PKCE_MAX = 128;
const SECRET_BYTES = 32; // 256-bit opaque secret half (refresh + device-code secrets)

// ---------------------------------------------------------------------------------------
// Types (auth-spec §4.1) — the canonical row shapes; AuthDO persists exactly these.
// ---------------------------------------------------------------------------------------

/// One-time device authorization code row (`device_codes`). Secret stored hashed only.
export interface DeviceCodeRecord {
  authEpoch?: number;
  id: string; // "dac-<uuid>"
  accountId: string;
  userId: string;
  orgId: string;
  secretHash: string; // sha256(secret) b64url
  codeChallenge: string; // PKCE S256 challenge (b64url)
  deviceName: string;
  deviceModel: string | null;
  createdAt: number;
  expiresAt: number; // createdAt + DEVICE_CODE_TTL_MS
  consumedAt: number | null;
}

/// Long-lived per-device session row (`device_sessions`). `id` is ALSO the jti of every access
/// JWS the session mints, so the existing `isJtiRevoked` gate covers device access tokens.
export interface DeviceSessionRecord {
  authEpoch?: number;
  id: string; // "dev-<uuid>"
  accountId: string;
  userId: string;
  orgId: string;
  scopes: Scope[]; // refreshed from the live role on every rotation
  deviceName: string;
  deviceModel: string | null;
  refreshHash: string; // sha256(current secret)
  prevRefreshHash: string | null; // superseded secret (rotation race window)
  prevGraceUntil: number | null;
  rotationCounter: number;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number; // SLIDING: now + DEVICE_SESSION_LIFETIME_MS on every rotation
  revokedAt: number | null;
  revokeReason: string | null;
}

/// Persistence contract — tests pass an in-memory fake; integration passes the AuthDO adapter.
export interface DeviceStore {
  createDeviceCode(rec: DeviceCodeRecord): Promise<void>;
  /// Atomic single-use consume: stamp `consumedAt` IFF currently unconsumed and return the row;
  /// null when absent OR already consumed (the DO's single-threaded read-then-act makes it atomic).
  consumeDeviceCode(id: string, consumedAt: number): Promise<DeviceCodeRecord | null>;
  createDeviceSession(rec: DeviceSessionRecord): Promise<void>;
  getDeviceSession(id: string): Promise<DeviceSessionRecord | null>;
  /// Persist a successful rotation (new secret hash + race-grace bookkeeping + slid expiry).
  rotateDeviceSession(
    id: string,
    patch: {
      refreshHash: string;
      prevRefreshHash: string;
      prevGraceUntil: number;
      scopes: Scope[];
      lastSeenAt: number;
      expiresAt: number;
    },
  ): Promise<boolean>;
  revokeDeviceSession(id: string, reason: string, revokedAt: number): Promise<void>;
  listDeviceSessions(accountId: string): Promise<DeviceSessionRecord[]>;
}

/// Everything the lane needs, injected (mirrors ServiceTokenDeps).
export interface DeviceAuthDeps {
  store: DeviceStore;
  /// Account re-read for status/role refresh on exchange + every rotation.
  accounts: { getAccount(accountId: string): Promise<Account | null> };
  /// Carries AUTH_SIGNING_SECRET for the access-JWS mint.
  env: AuthEnv;
  now?: () => number;
  randomId?: () => string;
  randomBytes?: (len: number) => Uint8Array;
}

export class DeviceAuthError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
  ) {
    super(message);
    this.name = "DeviceAuthError";
  }
}

// ---------------------------------------------------------------------------------------
// base64url + PKCE helpers (workerd globals only)
// ---------------------------------------------------------------------------------------

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

/// True iff `s` is a base64url string within [min, max] characters (PKCE wire validation).
export function isValidB64url(s: unknown, min: number, max: number): s is string {
  return typeof s === "string" && s.length >= min && s.length <= max && B64URL_RE.test(s);
}

/// b64url(SHA-256(verifier)) — the S256 transform (RFC 7636 §4.2).
export async function computeS256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64urlEncode(new Uint8Array(digest));
}

function defaultRandomBytes(len: number): Uint8Array {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
}

/// Strip ASCII control characters and trim — device names render in security-sensitive UI
/// (the approval screen + device list), so they must never smuggle escapes.
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001f\u007f]/g;
function sanitizeLabel(raw: unknown, maxLen: number): string | null {
  if (typeof raw !== "string") return null;
  const cleaned = raw.replace(CONTROL_RE, "").trim();
  if (cleaned.length === 0 || cleaned.length > maxLen) return null;
  return cleaned;
}

// ---------------------------------------------------------------------------------------
// §2.2 approve — mint the single-use authorization code (caller is the cookie-authed user)
// ---------------------------------------------------------------------------------------

export interface ApproveDeviceInput {
  codeChallenge: unknown;
  codeChallengeMethod: unknown;
  deviceName: unknown;
  deviceModel?: unknown;
}

export interface ApproveDeviceResult {
  /// The BARE one-time code: "dac-<id>.<secret>". The wiring org-qualifies it on the wire.
  code: string;
  expiresInSeconds: number;
}

export async function approveDevice(
  deps: DeviceAuthDeps,
  ctx: { accountId: string; userId: string; orgId: string; authEpoch?: number },
  input: ApproveDeviceInput,
): Promise<ApproveDeviceResult> {
  if (input.codeChallengeMethod !== "S256") {
    throw new DeviceAuthError("codeChallengeMethod must be exactly 'S256'", 400, "bad_method");
  }
  if (!isValidB64url(input.codeChallenge, PKCE_MIN, PKCE_MAX)) {
    throw new DeviceAuthError("codeChallenge must be 43-128 base64url chars", 400, "bad_challenge");
  }
  const deviceName = sanitizeLabel(input.deviceName, 64);
  if (!deviceName) {
    throw new DeviceAuthError("deviceName must be non-empty and at most 64 chars", 400, "bad_device_name");
  }
  const deviceModel = input.deviceModel === undefined || input.deviceModel === null
    ? null
    : sanitizeLabel(input.deviceModel, 32); // an over-long/garbage model degrades to null (display-only)

  const now = (deps.now ?? Date.now)();
  const randomId = deps.randomId ?? (() => crypto.randomUUID());
  const randomBytes = deps.randomBytes ?? defaultRandomBytes;

  const id = `dac-${randomId()}`;
  const secret = b64urlEncode(randomBytes(SECRET_BYTES)); // 43 b64url chars
  const rec: DeviceCodeRecord = {
    authEpoch: ctx.authEpoch ?? 0,
    id,
    accountId: ctx.accountId,
    userId: ctx.userId,
    orgId: ctx.orgId,
    secretHash: await hashSecret(secret),
    codeChallenge: input.codeChallenge,
    deviceName,
    deviceModel,
    createdAt: now,
    expiresAt: now + DEVICE_CODE_TTL_MS,
    consumedAt: null,
  };
  await deps.store.createDeviceCode(rec);
  return { code: `${id}.${secret}`, expiresInSeconds: Math.floor(DEVICE_CODE_TTL_MS / 1000) };
}

// ---------------------------------------------------------------------------------------
// §2.3 exchange — code + PKCE verifier → device session + first access JWS (PUBLIC route)
// ---------------------------------------------------------------------------------------

export interface ExchangeDeviceCodeResult {
  /// BARE refresh handle: "dvt-<deviceSessionId>.<secret>". The wiring org-qualifies it.
  refreshToken: string;
  accessToken: string;
  accessTtlSeconds: number;
  session: DeviceSessionRecord;
  account: Account;
}

/// Split a bare "prefix-id.secret" handle at the FIRST dot. Null on malformed input.
function splitHandle(handle: string): { id: string; secret: string } | null {
  const dot = handle.indexOf(".");
  if (dot <= 0 || dot >= handle.length - 1) return null;
  return { id: handle.slice(0, dot), secret: handle.slice(dot + 1) };
}

export async function exchangeDeviceCode(
  deps: DeviceAuthDeps,
  input: { codeHandle: unknown; codeVerifier: unknown },
): Promise<ExchangeDeviceCodeResult> {
  // One opaque `invalid_code` for absent/expired/consumed/bad-secret — do not distinguish (§2.3).
  const invalid = () => new DeviceAuthError("invalid, expired or already-used code", 400, "invalid_code");
  if (typeof input.codeHandle !== "string") throw invalid();
  const parts = splitHandle(input.codeHandle);
  if (!parts || !parts.id.startsWith("dac-")) throw invalid();

  const now = (deps.now ?? Date.now)();

  // CONSUME FIRST (atomic single-use): even a failed PKCE/verifier attempt burns the code, so a
  // scheme-squatting attacker gets exactly one guess that also destroys the artifact (§5.1).
  const rec = await deps.store.consumeDeviceCode(parts.id, now);
  if (!rec) throw invalid();
  if (now >= rec.expiresAt) throw invalid();
  if (!(await verifySecret(parts.secret, rec.secretHash))) throw invalid();

  // PKCE S256: b64url(sha256(verifier)) must equal the challenge bound at approval. Constant-time
  // compare; failure is a DISTINCT code (the legitimate app can tell its own bug from a bad code)
  // but the code is already burned either way.
  if (!isValidB64url(input.codeVerifier, PKCE_MIN, PKCE_MAX)) {
    throw new DeviceAuthError("codeVerifier must be 43-128 base64url chars", 400, "pkce_mismatch");
  }
  const challenge = await computeS256Challenge(input.codeVerifier);
  if (!timingSafeEqualStr(challenge, rec.codeChallenge)) {
    throw new DeviceAuthError("PKCE verifier does not match the bound challenge", 400, "pkce_mismatch");
  }

  // Re-read the account (status may have changed inside the 5-min window).
  const account = await deps.accounts.getAccount(rec.accountId);
  if (!account || account.status !== "active") {
    throw new DeviceAuthError("account is not active", 401, "account_inactive");
  }

  const randomId = deps.randomId ?? (() => crypto.randomUUID());
  const randomBytes = deps.randomBytes ?? defaultRandomBytes;
  const refreshSecret = b64urlEncode(randomBytes(SECRET_BYTES));
  const scopes = scopesForLogin(account.role, account.emailVerified);
  const session: DeviceSessionRecord = {
    authEpoch: rec.authEpoch ?? 0,
    id: `dev-${randomId()}`,
    accountId: account.id,
    userId: account.userId,
    orgId: rec.orgId,
    scopes,
    deviceName: rec.deviceName,
    deviceModel: rec.deviceModel,
    refreshHash: await hashSecret(refreshSecret),
    prevRefreshHash: null,
    prevGraceUntil: null,
    rotationCounter: 0,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + DEVICE_SESSION_LIFETIME_MS,
    revokedAt: null,
    revokeReason: null,
  };
  await deps.store.createDeviceSession(session);

  const accessToken = await mintDeviceAccessJws(deps, session, scopes, now);
  return {
    refreshToken: `dvt-${session.id}.${refreshSecret}`,
    accessToken,
    accessTtlSeconds: DEVICE_ACCESS_TTL_SECONDS,
    session,
    account,
  };
}

// ---------------------------------------------------------------------------------------
// §2.4 refresh — rotate-on-use + race grace + reuse detection + sliding expiry (PUBLIC route)
// ---------------------------------------------------------------------------------------

export interface RefreshDeviceSessionResult {
  refreshToken: string; // BARE "dvt-<id>.<newSecret>" — wiring org-qualifies
  accessToken: string;
  accessTtlSeconds: number;
  session: DeviceSessionRecord;
}

export async function refreshDeviceSession(
  deps: DeviceAuthDeps,
  input: { refreshHandle: unknown },
): Promise<RefreshDeviceSessionResult> {
  if (typeof input.refreshHandle !== "string") {
    throw new DeviceAuthError("invalid refresh token", 401, "invalid_refresh");
  }
  const parts = splitHandle(input.refreshHandle);
  if (!parts || !parts.id.startsWith("dvt-")) {
    throw new DeviceAuthError("invalid refresh token", 401, "invalid_refresh");
  }
  const sessionId = parts.id.slice("dvt-".length); // "dev-<uuid>"
  const now = (deps.now ?? Date.now)();

  // 1-2. load + liveness gates.
  const session = await deps.store.getDeviceSession(sessionId);
  if (!session) throw new DeviceAuthError("invalid refresh token", 401, "invalid_refresh");
  if (session.revokedAt !== null) {
    throw new DeviceAuthError("device session revoked", 401, "device_revoked");
  }
  if (now >= session.expiresAt) {
    throw new DeviceAuthError("device session expired", 401, "device_expired");
  }

  // 3-6. classify the presented secret: current → rotate; prev-within-grace → rotate (lost-response
  // retry); prev-after-grace → REUSE: revoke the whole session; anything else → invalid.
  const presentedHash = await hashSecret(parts.secret);
  const matchesCurrent = timingSafeEqualStr(presentedHash, session.refreshHash);
  const matchesPrev =
    session.prevRefreshHash !== null && timingSafeEqualStr(presentedHash, session.prevRefreshHash);

  if (!matchesCurrent && !matchesPrev) {
    throw new DeviceAuthError("invalid refresh token", 401, "invalid_refresh");
  }
  if (!matchesCurrent && matchesPrev) {
    const inGrace = session.prevGraceUntil !== null && now < session.prevGraceUntil;
    if (!inGrace) {
      // Reuse detected after the grace window: a superseded secret was presented — assume the
      // refresh token was copied/stolen. Kill the whole device session (thief AND victim die;
      // the victim re-authenticates via the normal sign-in path). §5.3.
      await deps.store.revokeDeviceSession(session.id, "refresh_reuse", now);
      throw new DeviceAuthError("refresh token reuse detected; device session revoked", 401, "refresh_reused");
    }
    // else: lost-response retry race — fall through and rotate again from here (the presented
    // prev secret is treated as current; the never-delivered intermediate secret dies).
  }

  // 7. account re-read BEFORE persisting the rotation, so a suspended/deprovisioned account gets
  //    `account_inactive` with NO rotation (the session is revoked instead) and a role change
  //    recomputes scopes for the new access token.
  const account = await deps.accounts.getAccount(session.accountId);
  if (!account || account.status !== "active") {
    await deps.store.revokeDeviceSession(session.id, "account_inactive", now);
    throw new DeviceAuthError("account is not active", 401, "account_inactive");
  }
  const scopes = scopesForLogin(account.role, account.emailVerified);

  // 3 (persist). rotate: new secret, prev = the secret just presented, fresh 60s grace, slide expiry.
  const randomBytes = deps.randomBytes ?? defaultRandomBytes;
  const newSecret = b64urlEncode(randomBytes(SECRET_BYTES));
  const newHash = await hashSecret(newSecret);
  const rotatedSuccessfully = await deps.store.rotateDeviceSession(session.id, {
    refreshHash: newHash,
    prevRefreshHash: presentedHash,
    prevGraceUntil: now + REFRESH_ROTATION_GRACE_MS,
    scopes,
    lastSeenAt: now,
    expiresAt: now + DEVICE_SESSION_LIFETIME_MS, // SLIDING — an active device never expires
  });

  if (!rotatedSuccessfully) throw new DeviceAuthError("device session revoked during refresh", 401, "device_revoked");

  const rotated: DeviceSessionRecord = {
    ...session,
    refreshHash: newHash,
    prevRefreshHash: presentedHash,
    prevGraceUntil: now + REFRESH_ROTATION_GRACE_MS,
    rotationCounter: session.rotationCounter + 1,
    scopes,
    lastSeenAt: now,
    expiresAt: now + DEVICE_SESSION_LIFETIME_MS,
  };
  const accessToken = await mintDeviceAccessJws(deps, rotated, scopes, now);
  return {
    refreshToken: `dvt-${session.id}.${newSecret}`,
    accessToken,
    accessTtlSeconds: DEVICE_ACCESS_TTL_SECONDS,
    session: rotated,
  };
}

// ---------------------------------------------------------------------------------------
// Shared: the device access JWS — a normal `session`-type token whose jti == deviceSessionId,
// so the existing point-keyed revocation gate kills it the moment the session row dies (§4.2).
// ---------------------------------------------------------------------------------------

async function mintDeviceAccessJws(
  deps: DeviceAuthDeps,
  session: DeviceSessionRecord,
  scopes: Scope[],
  now: number,
): Promise<string> {
  return mintToken(
    deps.env.AUTH_SIGNING_SECRET,
    {
      sub: session.userId,
      type: "session",
      orgId: session.orgId,
      scopes,
      ttlSeconds: DEVICE_ACCESS_TTL_SECONDS,
      jti: session.id,
    },
    now,
  );
}

// ---------------------------------------------------------------------------------------
// §2.6 public projection for the devices list (refresh hashes never leave the DO/lane).
// ---------------------------------------------------------------------------------------

export interface PublicDeviceSession {
  id: string;
  name: string;
  model: string | null;
  createdAt: number;
  lastSeenAt: number;
  expiresAt: number;
  revokedAt: number | null;
}

export function toPublicDeviceSession(s: DeviceSessionRecord): PublicDeviceSession {
  return {
    id: s.id,
    name: s.deviceName,
    model: s.deviceModel,
    createdAt: s.createdAt,
    lastSeenAt: s.lastSeenAt,
    expiresAt: s.expiresAt,
    revokedAt: s.revokedAt,
  };
}

// ---------------------------------------------------------------------------------------
// In-memory store (unit tests / dev) — mirrors the AuthDO semantics exactly.
// ---------------------------------------------------------------------------------------

export class InMemoryDeviceStore implements DeviceStore {
  readonly codes = new Map<string, DeviceCodeRecord>();
  readonly sessions = new Map<string, DeviceSessionRecord>();

  async createDeviceCode(rec: DeviceCodeRecord): Promise<void> {
    if (this.codes.has(rec.id)) throw new Error(`duplicate device code id ${rec.id}`);
    this.codes.set(rec.id, { ...rec });
  }

  async consumeDeviceCode(id: string, consumedAt: number): Promise<DeviceCodeRecord | null> {
    const rec = this.codes.get(id);
    if (!rec || rec.consumedAt !== null) return null;
    rec.consumedAt = consumedAt;
    return { ...rec };
  }

  async createDeviceSession(rec: DeviceSessionRecord): Promise<void> {
    if (this.sessions.has(rec.id)) throw new Error(`duplicate device session id ${rec.id}`);
    this.sessions.set(rec.id, { ...rec, scopes: [...rec.scopes] });
  }

  async getDeviceSession(id: string): Promise<DeviceSessionRecord | null> {
    const s = this.sessions.get(id);
    return s ? { ...s, scopes: [...s.scopes] } : null;
  }

  async rotateDeviceSession(
    id: string,
    patch: {
      refreshHash: string;
      prevRefreshHash: string;
      prevGraceUntil: number;
      scopes: Scope[];
      lastSeenAt: number;
      expiresAt: number;
    },
  ): Promise<boolean> {
    const s = this.sessions.get(id);
    if (!s || s.revokedAt !== null) return false;
    s.refreshHash = patch.refreshHash;
    s.prevRefreshHash = patch.prevRefreshHash;
    s.prevGraceUntil = patch.prevGraceUntil;
    s.scopes = [...patch.scopes];
    s.lastSeenAt = patch.lastSeenAt;
    s.expiresAt = patch.expiresAt;
    s.rotationCounter += 1;
    return true;
  }

  async revokeDeviceSession(id: string, reason: string, revokedAt: number): Promise<void> {
    const s = this.sessions.get(id);
    if (!s || s.revokedAt !== null) return;
    s.revokedAt = revokedAt;
    s.revokeReason = reason;
  }

  async listDeviceSessions(accountId: string): Promise<DeviceSessionRecord[]> {
    return [...this.sessions.values()]
      .filter((s) => s.accountId === accountId)
      .map((s) => ({ ...s, scopes: [...s.scopes] }));
  }
}
