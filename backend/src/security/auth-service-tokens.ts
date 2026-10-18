// SPDX-License-Identifier: AGPL-3.0-or-later
/// auth-service-tokens.ts — machine credentials (the cloudfsd / CLI / render-node carve-out).
///
/// This is the MINT path the frozen auth contract (CONTRACTS-AUTH.md §1.6, §2, §4.6)
/// promises but `auth.ts` does not implement: `auth.ts` can mint/verify a `service`-type
/// JWS, but there was no surface to ISSUE one for an org, persist its record, list it, or
/// revoke it. This module is that surface.
///
/// What an admin gets:
///   - mint  : create a `ServiceToken` record + a `service` HS256 JWS whose `jti == record.id`.
///             The JWS plaintext is returned EXACTLY ONCE (at creation). We persist only a
///             hash of the secret half — never the bearer string — so a DB read can never
///             reconstruct a usable credential.
///   - list  : the org's tokens, scrubbed of every secret (public view).
///   - revoke: flip `revoked=true`; the gateway folds `revokedServiceJtis()` into
///             `VerifyOptions.revokedJtis`, so the already-issued JWS dies on next verify
///             even though it is otherwise unexpired.
///
/// SECURITY / WORKERS NOTES:
///   - No Node built-ins. Secrets come from `crypto.getRandomValues` / `crypto.randomUUID`
///     (CSPRNG), hashing from WebCrypto `crypto.subtle.digest`, and the constant-time
///     compare from workerd's `crypto.subtle.timingSafeEqual` over fixed-length digests.
///   - We compare HASHES (always 32 bytes), never raw secrets of attacker-controlled
///     length — `timingSafeEqual` throws on length mismatch, so equal-length digests are
///     the only safe operand.
///   - Time / randomness / the org-user-creation call are all INJECTED (`ServiceTokenDeps`)
///     so the unit tests are deterministic and touch no real network or DO.
///
/// Storage + the JWS signing key live behind injected interfaces; this module imports no
/// `cloudflare:workers` and holds no module-level request state.

import {
  mintToken,
  AuthError,
  DEFAULT_TTL_SECONDS,
  type Scope,
  type AuthEnv,
} from "./auth";

// ---- types (structurally mirror CONTRACTS-AUTH.md §1.6 / §2; kept local so this lane is
//      self-contained and does not edit the integration-owned auth-types.ts) -------------

/// The persisted machine-credential record. `hashedSecret` is the ONLY secret-derived
/// field we keep; the bearer JWS is never stored. (Contract §1.6.)
export interface ServiceToken {
  id: string; // "svc-<uuid>"; ALSO the jti of the minted service JWS
  orgId: string;
  userId: string; // the service_account OrgDO user this token acts as (Principal.sub)
  label: string; // human label ("render-farm-node-7")
  scopes: Scope[]; // narrow, least-privilege; chosen at issue time by an admin
  spaceId: string | null; // optional pin (Principal.spaceId)
  hashedSecret: string; // sha256(base64url) of the raw secret half — defense in depth
  createdByUserId: string;
  createdAt: number;
  lastUsedAt: number | null;
  expiresAt: number | null; // optional; null = relies on jti-revocation
  revoked: boolean;
  /// auth-spec §4.1: the device session that minted this token through the device-bound
  /// daemon-token route (§2.7). Null for admin-minted tokens. Device revoke cascades to it;
  /// a re-mint soft-expires the prior token carrying the same id.
  deviceSessionId?: string | null;
}

/// The public projection returned by list/get — every secret-bearing field stripped.
export type ServiceTokenPublic = Omit<ServiceToken, "hashedSecret">;

/// Persistence contract (CONTRACTS-AUTH.md §2). Tests pass an in-memory fake; the
/// integration agent passes the real `AuthDO(orgId)`-backed adapter.
export interface ServiceTokenStore {
  createServiceToken(rec: ServiceToken): Promise<void>;
  getServiceToken(id: string): Promise<ServiceToken | null>;
  listServiceTokens(orgId: string): Promise<ServiceToken[]>;
  touchServiceToken(id: string, lastUsedAt: number): Promise<void>;
  revokeServiceToken(id: string): Promise<void>;
  /// Re-point a token's record expiry (daemon-token soft cutover, auth-spec §2.7). The gate
  /// enforces record expiry via `isJtiRevoked`, so shortening it retires the credential.
  setServiceTokenExpiry(id: string, expiresAt: number): Promise<void>;
  revokedServiceJtis(): Promise<Set<string>>; // feeds VerifyOptions.revokedJtis
}

/// Coarse org-role used for the owner/admin gate. Mirror of OrgRole (permissions.ts).
export type ServiceTokenRole = "owner" | "admin" | "space_admin" | "standard";

/// Everything this module needs, INJECTED so it stays pure-ish and unit-testable.
export interface ServiceTokenDeps {
  store: ServiceTokenStore;
  /// Carries AUTH_SIGNING_SECRET for `mintToken`. Structural subset of the real Env.
  env: AuthEnv;
  /// Mint a fresh service_account OrgDO user when the caller does not supply one. Injected
  /// so tests never touch OrgDO; integration wires this to `createServiceAccount`.
  createServiceAccountUser: (input: {
    orgId: string;
    label: string;
  }) => Promise<{ userId: string }>;
  /// Injectable clock (epoch ms). Defaults to Date.now at the call site if omitted.
  now?: () => number;
  /// Injectable id factory — returns the bare uuid (we prefix "svc-"). Defaults to randomUUID.
  randomId?: () => string;
  /// Injectable secret-bytes factory for the opaque secret half. Defaults to CSPRNG.
  randomBytes?: (len: number) => Uint8Array;
}

/// Input for a mint. `scopes` MUST be a non-empty subset chosen by the admin (least
/// privilege). `serviceAccountUserId` lets the caller reuse an existing service account;
/// when absent we create one. `ttlSeconds` defaults to the service ceiling; pass `null`
/// for a non-expiring token that relies purely on jti-revocation.
export interface MintServiceTokenInput {
  orgId: string;
  label: string;
  scopes: Scope[];
  spaceId?: string | null;
  serviceAccountUserId?: string;
  ttlSeconds?: number | null;
}

/// The mint result. `token` (the JWS plaintext) is present ONLY here, ONLY once.
export interface MintServiceTokenResult {
  id: string;
  token: string; // the `service` JWS — show once, store never
  label: string;
  scopes: Scope[];
  spaceId: string | null;
  expiresAt: number | null;
  record: ServiceTokenPublic;
}

// ---- base64url helpers (no Node Buffer; workerd globals only) --------------------------

function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ---- secret hashing + constant-time compare (WebCrypto only) ---------------------------

const VALID_SCOPES: ReadonlySet<Scope> = new Set<Scope>([
  "fs:read",
  "fs:write",
  "fs:lock",
  "fs:admin",
  "snapshot:read",
  "snapshot:write",
  "audit:read",
]);

/// SHA-256(secret) as base64url. This is what we persist; the input secret is discarded.
export async function hashSecret(secret: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return b64urlEncode(new Uint8Array(digest));
}

/// Constant-time check that `secret` hashes to `expectedHashB64url`. Both operands are
/// fixed-length (32-byte) SHA-256 digests, so workerd's `timingSafeEqual` (which requires
/// equal lengths) is safe and leaks no length/timing oracle. Never throws on bad input —
/// returns false.
export async function verifySecret(secret: string, expectedHashB64url: string): Promise<boolean> {
  let expected: Uint8Array;
  try {
    expected = b64urlDecode(expectedHashB64url);
  } catch {
    return false;
  }
  if (expected.length !== 32) return false; // not a SHA-256 digest → reject
  const actual = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret)),
  );
  // Both are exactly 32 bytes; timingSafeEqual compares without an early-out branch.
  return crypto.subtle.timingSafeEqual(actual, expected);
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- mint / list / revoke surface ------------------------------------------------------

const SECRET_BYTES = 32; // 256-bit opaque secret half

function defaultRandomBytes(len: number): Uint8Array {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
}

/// Strip the secret-derived field for any outward-facing projection.
export function toPublic(rec: ServiceToken): ServiceTokenPublic {
  const { hashedSecret: _hashedSecret, ...rest } = rec;
  return rest;
}

function requireAdmin(role: ServiceTokenRole): void {
  if (role !== "owner" && role !== "admin") {
    throw new AuthError("forbidden: owner/admin required to manage service tokens", 403, "forbidden_role");
  }
}

/// Mint a machine token for an org. OWNER/ADMIN only — the gate is enforced here so the
/// route layer cannot forget it. Persists only `hashedSecret`; returns the JWS once.
///
/// `callerRole` is the verified org-role of the principal making the request;
/// `callerUserId` is recorded as `createdByUserId` for audit.
export async function mintServiceToken(
  deps: ServiceTokenDeps,
  callerRole: ServiceTokenRole,
  callerUserId: string,
  input: MintServiceTokenInput,
): Promise<MintServiceTokenResult> {
  requireAdmin(callerRole);
  // `return await` (not bare `return`): a validation throw inside the core creates an ALREADY-
  // rejected promise; bare adoption attaches the handler a tick late, which workerd flags as an
  // unhandled rejection (same convention as handleAuthRoutes' dispatchers).
  return await mintServiceTokenCore(deps, callerUserId, input);
}

/// The role-UNgated mint core shared by the admin route (above, behind `requireAdmin`) and the
/// device-bound daemon mint (`mintDeviceDaemonToken`, which enforces its own device binding +
/// scope ceiling instead). Validation, persistence, and the show-once JWS are identical.
async function mintServiceTokenCore(
  deps: ServiceTokenDeps,
  callerUserId: string,
  input: MintServiceTokenInput & { deviceSessionId?: string | null },
): Promise<MintServiceTokenResult> {
  const label = input.label?.trim();
  if (!label) throw new AuthError("label required", 401, "bad_request");
  if (!Array.isArray(input.scopes) || input.scopes.length === 0) {
    throw new AuthError("at least one scope required (least privilege)", 401, "bad_request");
  }
  for (const s of input.scopes) {
    if (!VALID_SCOPES.has(s)) {
      throw new AuthError(`unknown scope '${s}'`, 401, "bad_scope");
    }
  }

  const now = (deps.now ?? Date.now)();
  const randomId = deps.randomId ?? (() => crypto.randomUUID());
  const randomBytes = deps.randomBytes ?? defaultRandomBytes;

  // Resolve (or create) the service_account user this token acts as.
  const userId =
    input.serviceAccountUserId ??
    (await deps.createServiceAccountUser({ orgId: input.orgId, label })).userId;

  const id = `svc-${randomId()}`;
  const spaceId = input.spaceId ?? null;

  // Lifetime: undefined → service ceiling; explicit null → non-expiring (jti-revocation only).
  const ttlSeconds = input.ttlSeconds === undefined ? DEFAULT_TTL_SECONDS.service : input.ttlSeconds;
  const expiresAt = ttlSeconds === null ? null : now + ttlSeconds * 1000;

  // The opaque secret half: belt-and-suspenders alongside the signed JWS (contract §1.6).
  // We persist only its hash, never the secret. The JWS signature remains the primary cred.
  const secret = b64urlEncode(randomBytes(SECRET_BYTES));
  const hashedSecret = await hashSecret(secret);

  // The bearer credential: a normal `service` HS256 JWS with jti == record id, so
  // revocation = adding this id to the gateway's revokedJtis set.
  const token = await mintToken(
    deps.env.AUTH_SIGNING_SECRET,
    {
      sub: userId,
      type: "service",
      orgId: input.orgId,
      spaceId: spaceId ?? undefined,
      scopes: input.scopes,
      // mintToken needs whole seconds and clamps to >=1; for a "non-expiring" record we
      // still issue a long-but-bounded JWS (a bare bearer must always carry an exp), and
      // rely on jti-revocation + re-mint for true longevity.
      ttlSeconds: ttlSeconds === null ? DEFAULT_TTL_SECONDS.service : ttlSeconds,
      jti: id,
    },
    now,
  );

  const record: ServiceToken = {
    id,
    orgId: input.orgId,
    userId,
    label,
    scopes: [...input.scopes],
    spaceId,
    hashedSecret,
    createdByUserId: callerUserId,
    createdAt: now,
    lastUsedAt: null,
    expiresAt,
    revoked: false,
    deviceSessionId: input.deviceSessionId ?? null,
  };
  await deps.store.createServiceToken(record);

  return {
    id,
    token,
    label,
    scopes: [...input.scopes],
    spaceId,
    expiresAt,
    record: toPublic(record),
  };
}

// ---- device-bound daemon mint (auth-spec §2.7) -------------------------------------------

/// Includes historical reads for Finder-mounted snapshots. Snapshot creation and
/// access management stay in the human UI; every historical read still checks ACLs.
/// Intersected with the device session's scopes at mint time.
export const DEVICE_DAEMON_SCOPE_CEILING: readonly Scope[] = ["fs:read", "fs:write", "fs:lock", "snapshot:read"];

/// Device-minted daemon token lifetime: 30 days (the app re-mints at <7 days remaining).
export const DEVICE_DAEMON_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;

/// Soft-cutover window for the PRIOR daemon token on a re-mint: not an instant revoke — the
/// daemon's token provider re-reads its credential within seconds, but in-flight requests finish.
export const DEVICE_DAEMON_SOFT_CUTOVER_MS = 10 * 60 * 1000;

export interface MintDeviceDaemonTokenInput {
  orgId: string;
  /// The HUMAN user the device session belongs to. Daemon I/O runs under the user's OWN ACLs —
  /// deliberately NOT a synthetic service account (decision C / §2.7).
  userId: string;
  deviceSessionId: string;
  deviceName: string;
  /// The device session's live scopes — the mint is capped to ceiling ∩ these.
  deviceScopes: Scope[];
}

/// Mint the daemon's 30-day data-plane service token from a live device session. NO admin role
/// required — the device binding (verified by the route: bearer access JWS whose jti names a
/// live device session) IS the authorization. Enforces the data-plane scope ceiling, reuses the
/// human user as the acting identity, records the `deviceSessionId` for cascade-revoke, and
/// SOFT-EXPIRES any previous live token minted for the same device session.
export async function mintDeviceDaemonToken(
  deps: ServiceTokenDeps,
  input: MintDeviceDaemonTokenInput,
): Promise<MintServiceTokenResult> {
  const scopes = DEVICE_DAEMON_SCOPE_CEILING.filter((s) => input.deviceScopes.includes(s));
  if (scopes.length === 0) {
    throw new AuthError("device session carries no data-plane scopes", 403, "forbidden_scope");
  }

  const now = (deps.now ?? Date.now)();
  // Soft cutover (§2.7): any prior LIVE token bound to this device session gets a 10-min runway
  // instead of an instant revoke. Tokens already expiring sooner are left alone.
  const cutover = now + DEVICE_DAEMON_SOFT_CUTOVER_MS;
  const prior = (await deps.store.listServiceTokens(input.orgId)).filter(
    (t) =>
      t.deviceSessionId === input.deviceSessionId &&
      !t.revoked &&
      (t.expiresAt === null || t.expiresAt > cutover),
  );
  for (const t of prior) {
    await deps.store.setServiceTokenExpiry(t.id, cutover);
  }

  return await mintServiceTokenCore(deps, input.userId, {
    orgId: input.orgId,
    label: `daemon:${input.deviceName}`,
    scopes,
    spaceId: null,
    serviceAccountUserId: input.userId, // the HUMAN user — daemon acts under their ACLs
    ttlSeconds: DEVICE_DAEMON_TOKEN_TTL_SECONDS,
    deviceSessionId: input.deviceSessionId,
  });
}

/// List an org's service tokens (public projection — no secrets). OWNER/ADMIN only.
export async function listServiceTokens(
  deps: ServiceTokenDeps,
  callerRole: ServiceTokenRole,
  orgId: string,
): Promise<ServiceTokenPublic[]> {
  requireAdmin(callerRole);
  const rows = await deps.store.listServiceTokens(orgId);
  return rows.map(toPublic);
}

/// Fetch one token (public projection). OWNER/ADMIN only. Returns null if it does not
/// belong to `orgId` (tenant isolation) or does not exist.
export async function getServiceToken(
  deps: ServiceTokenDeps,
  callerRole: ServiceTokenRole,
  orgId: string,
  id: string,
): Promise<ServiceTokenPublic | null> {
  requireAdmin(callerRole);
  const rec = await deps.store.getServiceToken(id);
  if (!rec || rec.orgId !== orgId) return null;
  return toPublic(rec);
}

/// Revoke a token: flips `revoked=true` so `revokedServiceJtis()` (and thus the gateway's
/// `VerifyOptions.revokedJtis`) rejects the already-issued JWS. OWNER/ADMIN only.
/// Idempotent. Throws 404 if the token is missing or belongs to another org.
export async function revokeServiceToken(
  deps: ServiceTokenDeps,
  callerRole: ServiceTokenRole,
  orgId: string,
  id: string,
): Promise<void> {
  requireAdmin(callerRole);
  const rec = await deps.store.getServiceToken(id);
  if (!rec || rec.orgId !== orgId) {
    throw new AuthError("no such service token", 401, "not_found");
  }
  await deps.store.revokeServiceToken(id);
}

/// The set of revoked jtis for the gateway hot path. Pass-through to the store so the
/// integration layer can union this with session revocations into VerifyOptions.revokedJtis.
export async function revokedServiceJtis(deps: ServiceTokenDeps): Promise<Set<string>> {
  return deps.store.revokedServiceJtis();
}

// ---- in-memory store (test/dev fake; the integration agent provides the AuthDO adapter) -

/// A dependency-free `ServiceTokenStore` for unit tests and local dev. Holds records in a
/// Map; `revokedServiceJtis` is derived from the live records. Not for production (no
/// durability) — the real store is `AuthDO(orgId)`-backed (contract §1.7).
export class InMemoryServiceTokenStore implements ServiceTokenStore {
  private readonly rows = new Map<string, ServiceToken>();

  async createServiceToken(rec: ServiceToken): Promise<void> {
    if (this.rows.has(rec.id)) throw new Error(`duplicate service token id ${rec.id}`);
    this.rows.set(rec.id, { ...rec, scopes: [...rec.scopes] });
  }

  async getServiceToken(id: string): Promise<ServiceToken | null> {
    const r = this.rows.get(id);
    return r ? { ...r, scopes: [...r.scopes] } : null;
  }

  async listServiceTokens(orgId: string): Promise<ServiceToken[]> {
    return [...this.rows.values()]
      .filter((r) => r.orgId === orgId)
      .map((r) => ({ ...r, scopes: [...r.scopes] }));
  }

  async touchServiceToken(id: string, lastUsedAt: number): Promise<void> {
    const r = this.rows.get(id);
    if (r) r.lastUsedAt = lastUsedAt;
  }

  async revokeServiceToken(id: string): Promise<void> {
    const r = this.rows.get(id);
    if (r) r.revoked = true;
  }

  async setServiceTokenExpiry(id: string, expiresAt: number): Promise<void> {
    const r = this.rows.get(id);
    if (r) r.expiresAt = expiresAt;
  }

  async revokedServiceJtis(): Promise<Set<string>> {
    const out = new Set<string>();
    for (const r of this.rows.values()) if (r.revoked) out.add(r.id);
    return out;
  }
}
