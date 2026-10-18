// SPDX-License-Identifier: AGPL-3.0-or-later
import { validRange } from "./metadata/range-locks";
import { isMetadataCapacityError } from './metadata/capacity';
import { validateFileDelta, fileVerificationBlocks } from './metadata/file-manifest';
import { validateStreamDelta, validateStreamRange, streamVerificationBlocks } from './metadata/stream-manifest';
import { FilespaceDO, BULK_SEED_MAX } from "./filespace-do";
import { OrgDO } from "./org-do";
import { AuthDO } from "./auth-do";
import { DirectoryDO } from "./directory-do";
import { presignForSpace, presignBatchForSpace } from "./presign";
import { API_VERSION } from "./api-version";
import { handleBackupRequest } from "./backup-api";
import { requiredUploadHeaders, resolveStorageConfigAsync, type SpaceStorageDescriptor } from "./storage";
import { storageIdentity, verifyStorageObjects, nativeVerificationBucket, ObjectVerificationError } from "./storage-object-verifier";
import { validateBlockManifest } from "./metadata/block-manifest";
import { canonicalizeName } from "./metadata/namespace";
import { uploadVerificationManifest } from "./upload-verification";
import type { Env } from "./env";
import {
  verifyRequest,
  bearerFromRequest,
  requireScope,
  assertTenant,
  filespaceDoName,
  mintToken,
  DEFAULT_TTL_SECONDS,
  AuthError,
  type Principal,
  type Scope,
} from "./security/auth";
import {
  handleAuthRoutes,
  handleServiceTokenRoutes,
  handleOidcWebCallback,
  makeSessionResolver,
  gatewayJtiRevoked,
  isOrgMutationEmailBlocked,
  isAccountInactive,
  webBaseUrl,
  baseUrl,
  productName,
  passkeysConfigured,
} from "./auth-wiring";
import { handleSetupStatus, handleSetupInit, provisionFirstOwner, SetupError } from "./setup";
import { prepareLegacyAccount } from "./legacy-account";
import {
  cachedJtiRevoked,
  cachedAccountInactive,
  cachedSpaceRegistry,
  cachedAclPrincipal,
} from "./gate-cache";
import { readSessionCookie } from "./security/auth-session";
import {
  RateLimiter,
  InMemoryRateLimitStore,
  principalKey,
  ipKey,
  tooManyRequests,
} from "./security/ratelimit";
import type { Action, Decision, OrgRole, Principal as AclPrincipal } from "./permissions";
import type { AuthedContext } from "./org-do";
import { handleUsersRequest } from "./users";
import { handleOrgRequest } from "./org-do";
import { handleInvitesRequest } from "./invites";
import { handleStorageCredentialsRequest, managedCredentialResolver } from "./storage-credentials";
import { openMasterKeyEnvelope } from "./filespace-keys";
import { handleEmailConfigRequest } from "./email-config";
import { runDoctor } from "./admin-doctor";
import { handleCorsPreflight, withCors } from "./cors";
import { authStoresFor, describeSelectedEmailProviderForOrg, emailSenderForOrg } from "./auth-stores";
import { PasswordError, MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH } from "./security/auth-password";
import { canonicalEmail } from "./security/auth-signup";
import { resolveSignupMode, shouldRefuseOpenSignupOnHttps } from "./signup-mode";
import { handleSharingRequest, shareLinkStoreFor } from "./sharing";
import { handleOidcStart, OidcError, oidcCookieSecure } from "./security/oidc";
import {
  resolveOidcConfig,
  resolvePublicAuthConfig,
  prepareOidcCallback,
} from "./oidc-wiring";
import { handleAuthConfigRequest, authConfigStoreFor } from "./auth-config";
import { DIRECTORY_DO_NAME } from "./directory-do";
import { requestBoundary } from "./request-boundary";
import { MAX_STREAM_BODY_BYTES } from "./metadata/stream-limits";
import { isValidScheduleSpec } from "./metadata/snapshots";

// Re-export the DO classes so the runtime can find them (wrangler bindings).
export { FilespaceDO };
export { OrgDO };
export { AuthDO };
export { DirectoryDO };

// API_VERSION moved to ./api-version (it must NOT be a named export of this entry
// module — workerd treats entry exports as handlers/DO-classes and rejects a bare const).

function json(data: unknown, status = 200, extraHeaders?: Record<string, string>): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json", ...(extraHeaders ?? {}) },
  });
}

// ---- constant-time secret compare (double-HMAC, length-blind) --------------
// Compare two strings without leaking length or content via timing: HMAC both
// under a fresh random key, then compare the fixed-length digests. Robust even
// when the strings differ in length (a naive char loop would short-circuit).
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw", crypto.getRandomValues(new Uint8Array(32)),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const te = new TextEncoder();
  const ha = new Uint8Array(await crypto.subtle.sign("HMAC", key, te.encode(a)));
  const hb = new Uint8Array(await crypto.subtle.sign("HMAC", key, te.encode(b)));
  let diff = 0;
  for (let i = 0; i < ha.length; i++) diff |= ha[i] ^ hb[i];
  return diff === 0;
}

// Audit B16: hard ceiling on a single presigned-PUT object so a client can't mint a URL for an
// arbitrarily large upload. A cloudfs block is ≤ a few MiB; this 5 GiB cap (S3's single-PUT max) is
// generous headroom for any legitimate object while bounding a hostile/buggy client.
const MAX_PRESIGN_PUT_BYTES = 5 * 1024 * 1024 * 1024;

// All scopes — granted to the bootstrap admin token so it can drive the full
// deploy-time seed flow (create space, grant, manifest, presign).
const ALL_ADMIN_SCOPES: Scope[] = [
  "fs:read", "fs:write", "fs:lock", "fs:admin", "snapshot:read", "snapshot:write", "audit:read",
];

/// PART A — deploy-time bootstrap (SECURITY-CRITICAL). Creates the FIRST org +
/// admin and mints an admin token. Gated by a strong BOOTSTRAP_SECRET (constant-
/// time compared), single-use per deployment. NOT an open
/// admin endpoint — without the secret it 401s; if the secret binding is unset or
/// weak (< 16 chars) the route is DISABLED (fails closed). See BOOTSTRAP.md.
async function handleBootstrap(req: Request, env: Env): Promise<Response> {
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  // Fail closed if the deployment has no (or a weak) bootstrap secret configured.
  const configured = env.BOOTSTRAP_SECRET;
  if (!configured || configured.length < 16) {
    return json({ error: "bootstrap_disabled" }, 404); // don't reveal the route exists
  }
  // Accept the secret from a header (preferred) or the body; constant-time compare.
  let body: { orgId?: string; email?: string; displayName?: string; secret?: string; allowTokenOnly?: boolean };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return json({ error: "invalid_body" }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) return json({ error: "invalid_body" }, 400);
  const presented = req.headers.get("x-bootstrap-secret") ?? (typeof body.secret === "string" ? body.secret : "");
  if (!(await timingSafeEqual(presented, configured))) {
    return json({ error: "unauthorized" }, 401);
  }

  const orgId = typeof body.orgId === "string" ? body.orgId.trim() : "";
  const email = typeof body.email === "string" ? canonicalEmail(body.email) : "";
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$/.test(orgId) || !/^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(email)) return json({ error: "valid orgId and email required" }, 400);

  // Audit B10: validate the optional password BEFORE provisioning anything, so a weak
  // password doesn't half-create the OrgDO user (which would block a clean retry).
  const password = typeof (body as { password?: unknown }).password === "string"
    ? (body as { password: string }).password : undefined;
  // Auth-spec §2.5 (decision D): a bootstrap MUST set a real admin credential. A deploy that
  // truly wants a credential-less seed (CI/automation) opts out EXPLICITLY with
  // `allowTokenOnly: true` — the silent password-less default was the "first admin can never
  // sign in" footgun. Humans should use the web setup wizard (/v1/setup/init) instead.
  if (password === undefined && body.allowTokenOnly !== true) {
    return json({
      error: "password_required",
      reason: "bootstrap now requires a `password` for the admin account; pass `allowTokenOnly: true` to explicitly seed without a sign-in credential (automation only)",
    }, 400);
  }
  if (password !== undefined && (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH)) {
    return json({ error: "weak_password", reason: `password must be ${MIN_PASSWORD_LENGTH}–${MAX_PASSWORD_LENGTH} characters` }, 400);
  }

  let provisioned;
  try {
    provisioned = await provisionFirstOwner(env, { orgId, email: canonicalEmail(email), displayName: body.displayName ?? "Admin", password });
  } catch (e) {
    if (e instanceof SetupError) return json({ error: e.code }, e.status);
    if (e instanceof PasswordError) return json({ error: e.code }, e.status ?? 400);
    return json({ error: "bootstrap_credential_failed" }, 409);
  }
  const { admin, account } = provisioned;
  const credentialed = account !== null;

  // Mint a session admin token bound to this org with all scopes (works regardless of the
  // password path — the operator can use it immediately for API setup).
  const token = await mintToken(env.AUTH_SIGNING_SECRET, {
    sub: admin.id,
    type: "session",
    orgId,
    scopes: ALL_ADMIN_SCOPES,
    ttlSeconds: DEFAULT_TTL_SECONDS.session,
  });

  return json({ orgId, userId: admin.id, role: admin.role, token, scopes: ALL_ADMIN_SCOPES, credentialed }, 201);
}

// ----------------------------------------------------------------------------
// Rate limiters (security/ratelimit.ts).
//   - presign + mutation classes are now GLOBAL per (org,space): they run inside
//     the FilespaceDO (stub.rateLimit), so a fleet of Worker isolates shares one
//     consistent counter per space instead of each enforcing a loose per-isolate
//     cap. This is the class the security review says must be global (it protects
//     the single-threaded DO). See FilespaceDO.rateLimit + metadata/ratelimit-store.
//   - the PRE-AUTH per-IP limiter stays in-memory: it gates public invite/share
//     redeem BEFORE any tenant/DO is resolved, so there is no per-space DO to key
//     it on; a coarse per-isolate cap is acceptable for that abuse class.
// ----------------------------------------------------------------------------
// Audit B16: a tiny per-isolate TTL cache for the unauthenticated public auth-config, so the
// route can't be used to hammer the global DirectoryDO singleton. The auth config changes rarely;
// a 10s staleness window is invisible to a sign-in page.
const PUBLIC_AUTH_CONFIG_TTL_MS = 10_000;
let publicAuthConfigCache: { value: Awaited<ReturnType<typeof resolvePublicAuthConfig>>; expiresAt: number } | null = null;

const preAuthStore = new InMemoryRateLimitStore();
const preAuthLimiter = new RateLimiter(preAuthStore, { capacity: 10, refillPerSec: 0.2 });
// Bootstrap brute-force defense: a per-IP cap on secret-presenting attempts.
// Looser than the redeem limiter because bootstrap is a legitimate deploy-time op
// (creating several orgs / retrying setup), and the real defenses are the strong
// secret + constant-time compare + single-use guard. A 32-char secret is
// uncrackable at this rate regardless.
const bootstrapLimiter = new RateLimiter(preAuthStore, { capacity: 30, refillPerSec: 1 });

// Audit B24: share links are served from the DURABLE OrgDO-backed store
// (`shareLinkStoreFor(env, orgId)`) at each call site — the prior per-isolate in-memory Map
// 404'd external links across isolates/PoPs in production.

// Public, token-as-credential routes that bypass the bearer-auth gate
// (multiuser-INTEGRATION.md §2): the invite/share token IS the credential.
function isPublicRoute(p: string[]): boolean {
  // /v1/orgs/:org/invites/redeem  ·  /v1/orgs/:org/shares/resolve
  return (
    p[0] === "v1" && p[1] === "orgs" && !!p[2] &&
    ((p[3] === "invites" && p[4] === "redeem") || (p[3] === "shares" && p[4] === "resolve"))
  );
}

// ---- principal mapping: auth.Principal (token) → permissions.Principal (ACL) ----
// The ACL evaluator keys off type/id/groupIds/orgRole. We resolve groups + role
// from the OrgDO (the tenancy authority), so a SCIM-synced group membership feeds
// the group-union ACL evaluation. Best-effort: a brand-new org with no OrgDO
// state yields no groups and a "standard" role (default-deny ACL still applies).
async function toAclPrincipal(env: Env, principal: Principal): Promise<AclPrincipal> {
  const type: AclPrincipal["type"] = principal.type === "service" ? "service_account" : "user";
  let groupIds: string[] = [];
  let orgRole: OrgRole | undefined;
  try {
    // Audit B21: cache (groups, role) per (org,user) for a short TTL. It runs on EVERY gated file op
    // (presign + every mutation), and the two underlying OrgDO reads are independent so the loader
    // also Promise.all's them. INVALIDATED on role change / group change / offboarding (see
    // invalidateUser + invalidateOrgAcl call sites) on this isolate. Other isolates and already
    // in-flight reads can retain prior membership/role decisions for the 10-second TTL.
    const cached = await cachedAclPrincipal(principal.orgId, principal.sub, async () => {
      const org = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
      const [groups, user] = await Promise.all([
        org.groupsForUser(principal.sub),
        org.getUser(principal.sub),
      ]);
      return { groupIds: groups, orgRole: user?.role };
    });
    groupIds = cached.groupIds;
    orgRole = cached.orgRole as OrgRole | undefined;
  } catch {
    // OrgDO not provisioned for this tenant yet — fall through to default-deny ACL.
  }
  return { type, id: principal.sub, groupIds, orgRole };
}

// Map auth.Principal → the AuthedContext the multiuser sub-routers expect.
async function toAuthedContext(env: Env, principal: Principal): Promise<AuthedContext> {
  // Administrative requests use live authority. Data-plane caching must not leave
  // a demoted administrator able to change settings with an existing CLI token.
  const org = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
  const user = await org.getUser(principal.sub);
  if (!user || user.status !== "active" || principal.type === "guest") {
    throw new AuthError("active workspace member required", 403, "forbidden");
  }
  return { principalUserId: user.id, orgRole: user.role };
}

// ---- invite-redeem → enforcement-store grant sync (multiuser-INTEGRATION.md §5) ----
// multiuser's redeemInvite durably writes the scoped grant into OrgDO and returns
// { ok, userId, grantId, scope:{spaceId,inodeId,level,role} }. But gateway `canAccess`
// enforces against the per-filespace DoAclStore (the `grants` table inside FilespaceDO),
// not OrgDO — so a redeemed grant would be invisible to enforcement. We close that gap
// by reading the freshly-written grant rows back from OrgDO and upserting the one for
// the redeemed scope into the target space's FilespaceDO ACL store, preserving the grant
// id so both stores share one key (idempotent; revoke parity). Best-effort: a failed sync
// never changes the redeem response the client sees (the grant is still durable in OrgDO
// and a later sync/admin action can reconcile it).
async function syncRedeemedGrant(
  env: Env,
  orgId: string,
  rest: string[],
  res: Response,
  defer: (p: Promise<unknown>) => void,
): Promise<Response> {
  // Only the public redeem route carries a scope to sync.
  if (!(rest[0] === "invites" && rest[1] === "redeem") || res.status !== 200) return res;
  let body: any;
  try {
    body = await res.clone().json();
  } catch {
    return res; // non-JSON / unexpected — pass through untouched
  }
  const scope = body?.scope;
  if (!body?.ok || !body?.userId || !scope?.spaceId || !scope?.inodeId || !scope?.level) {
    return res; // unscoped invite (role-only) — nothing to enforce in a space
  }
  // Audit B22: the grant is ALREADY durable in OrgDO (redeem succeeded); the enforcement-store sync
  // is best-effort + reconcilable, so defer it (waitUntil) instead of making the redeem response wait
  // on two more cross-DO RPCs. A sync failure is swallowed (the grant survives in OrgDO; a later
  // admin action / next sync reconciles it).
  defer(
    (async () => {
      const org = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
      const rows = await org.grantsForPrincipal("user", body.userId);
      // pick the grant for THIS redeemed scope (prefer the returned grantId).
      const g =
        rows.find((r: any) => r.id === body.grantId) ??
        rows.find((r: any) => r.inodeId === scope.inodeId && r.spaceId === scope.spaceId);
      if (g) {
        const stub = env.FILESPACE.get(env.FILESPACE.idFromName(filespaceDoName(orgId, scope.spaceId)));
        await stub.syncGrant(g);
      }
    })(),
  );
  return res;
}

// Audit helper — best-effort; never let an audit failure block or alter the response.
type AuditableStub = ReturnType<Env["FILESPACE"]["get"]>;
async function audit(
  stub: AuditableStub,
  principal: Principal,
  spaceId: string,
  event: {
    action: string;
    decision: "allow" | "deny";
    targetInodeId?: string;
    levelChecked?: string;
    mintedObjectKeys?: string[];
    verb?: "GET" | "PUT";
    urlTtlSeconds?: number;
    sourceIp?: string;
    detail?: Record<string, unknown>;
  },
): Promise<void> {
  try {
    await stub.appendAudit({
      actorSub: principal.sub,
      actorType: principal.type,
      orgId: principal.orgId,
      spaceId,
      sessionId: principal.jti,
      ...event,
    });
  } catch {
    /* audit is best-effort; do not fail the request on a logging error */
  }
}

/// The gateway Worker: authN + tenant isolation + authZ (scope + per-folder ACL)
/// + rate limiting + audit + presigned-URL minting. Stateless and global; all
/// metadata/lock/snapshot/upload state lives in the per-(org,space) Durable Object.
export default {
  // Audit B22: the handler now takes `ctx: ExecutionContext` so best-effort work (deny-path audit
  // appends, redeemed-grant ACL sync) can run via `ctx.waitUntil()` AFTER the response is sent
  // instead of blocking it. The success-path audit append stays INLINE + durable (the audit record
  // must be committed before we ack the mutation), and the hash chain is preserved regardless of
  // when a deferred append runs because every append is serialized inside the single-threaded
  // FilespaceDO. `waitUntil` keeps the deferred work alive past the response so it can't be dropped.
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Audit B9: CORS for a split-origin (Pages-hosted) web console. A preflight is
    // answered here; every real response is wrapped with the allow-listed CORS headers
    // (origin = WEB_BASE_URL / CORS_ALLOWED_ORIGINS only; never `*` with credentials).
    const res = await requestBoundary(req, async (bounded) =>
      handleCorsPreflight(bounded, env) ?? await handleRequest(bounded, env, ctx));
    if (res.status === 101) return res;
    return withApiVersion(withCors(res, req, env));
  },
} satisfies ExportedHandler<Env>;

/// Version handshake: stamp every response with the wire-contract version so a client
/// can detect skew (e.g. a pre-B17 client that still constructs path ids) without an
/// extra round-trip. Reuses the response body/status; only adds the header.
function withApiVersion(res: Response): Response {
  if (res.status === 101 || res.headers.get("X-CloudFS-API-Version")) return res; // already stamped
  const headers = new Headers(res.headers);
  headers.set("X-CloudFS-API-Version", String(API_VERSION));
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

async function handleRequest(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Audit B22: `defer(p)` runs best-effort work past the response without blocking it. It's
    // `ctx.waitUntil`-backed (so the runtime keeps the isolate alive until `p` settles), with the
    // promise's own rejection swallowed so a failed deferred append can never surface as an
    // unhandled rejection. Used ONLY for work whose latency must not be on the response path AND
    // whose failure is non-fatal to the response already returned (deny-path audits, grant sync).
    const defer = (p: Promise<unknown>): void => {
      ctx.waitUntil(Promise.resolve(p).catch(() => {}));
    };
    const url = new URL(req.url);
    const p = url.pathname.split("/").filter(Boolean);

    const backupResponse = await handleBackupRequest(req, env);
    if (backupResponse) return backupResponse;
    if (env.BACKUP_MODE) return json({ error: "maintenance", mode: env.BACKUP_MODE, retryable: true }, 503);

    if (p[0] === "v1" && p[1] === "health" && p.length === 2) {
      if (req.method !== "GET" && req.method !== "HEAD") return json({ error: "method not allowed" }, 405);
      return req.method === "HEAD" ? new Response(null, { status: 200 }) : json({ ok: true, apiVersion: API_VERSION });
    }

    // ---- Post-deploy readiness/doctor (audit B8) ----
    // GET /v1/admin/doctor — gated by the deploy-time BOOTSTRAP_SECRET (the operator
    // already holds it). Reports the config-health checks that otherwise fail silently
    // until first use (auth secret, STORAGE_ENC_KEY, default bucket probe, email
    // provider, signup mode, localhost URLs). Returns 200 with `{ok}` even on a
    // failing check so a CI/script reads the body; HTTP 503 when overall `ok:false`.
    if (p[0] === "v1" && p[1] === "admin" && p[2] === "doctor" && !p[3]) {
      if (req.method !== "GET") return json({ error: "method not allowed" }, 405);
      const configured = env.BOOTSTRAP_SECRET;
      if (!configured || configured.length < 16) return json({ error: "doctor_disabled" }, 404);
      const presented = req.headers.get("x-bootstrap-secret") ?? "";
      if (!(await timingSafeEqual(presented, configured))) return json({ error: "unauthorized" }, 401);
      const isHttps = url.protocol === "https:";
      const report = await runDoctor(env, { isHttps });
      return json(report, report.ok ? 200 : 503);
    }

    // ---- First-run setup wizard (auth-spec §2.5; handlers in setup.ts) ----
    // status is PUBLIC + per-isolate cached (the SPA boot probe); init shares the bootstrap
    // brute-force limiter (it presents the same BOOTSTRAP_SECRET).
    if (p[0] === "v1" && p[1] === "setup" && p[2] === "status" && !p[3]) {
      return await handleSetupStatus(req, env);
    }
    if (p[0] === "v1" && p[1] === "setup" && p[2] === "init" && !p[3]) {
      const pre = await bootstrapLimiter.check(`bootstrap:${ipKey(req)}`);
      if (!pre.allowed) return tooManyRequests(pre);
      try {
        return await handleSetupInit(req, env);
      } catch (e) { throw e; }
    }

    // ---- PART A: deploy-time bootstrap (secret-gated, single-use) ----
    if (p[0] === "v1" && p[1] === "bootstrap" && !p[2]) {
      // per-IP rate limit (brute-force defense on the secret). Own key namespace
      // so it has a dedicated bucket, not shared with the redeem limiter.
      const pre = await bootstrapLimiter.check(`bootstrap:${ipKey(req)}`);
      if (!pre.allowed) return tooManyRequests(pre);
      try {
        return await handleBootstrap(req, env);
      } catch (e) { throw e; }
    }

    // ---- PUBLIC: OIDC SSO login (start/callback) — these ARE the login, so they
    //      sit BEFORE verifyRequest, same as bootstrap/invite/share. They produce a
    //      normal HS256 session token that the existing verifyRequest gate then
    //      accepts on every later call (no change to that path). See oidc-INTEGRATION.md.
    if (p[0] === "v1" && p[1] === "auth" && p[2] === "oidc" && (p[3] === "start" || p[3] === "callback")) {
      // per-IP pre-auth rate limit (login abuse defense), reusing the shared bucket.
      const pre = await preAuthLimiter.check(ipKey(req));
      if (!pre.allowed) return tooManyRequests(pre);
      try {
        // Resolve the EFFECTIVE config: the RUNTIME (admin-console, encrypted) auth-config FIRST,
        // then the deploy OIDC_* env fallback. Null ⇒ SSO disabled → 404 (fail closed, don't
        // advertise). This is what makes the provider PLUGGABLE with no redeploy.
        const config = await resolveOidcConfig(env, req);
        if (!config) return json({ error: "not found" }, 404);
        if (p[3] === "start" && req.method === "GET") {
          // FINDING #3: hardened `__Host-`-prefixed + Secure login cookie over HTTPS; plain over http.
          const { response } = await handleOidcStart(config, env, { secure: oidcCookieSecure(req) });
          return response; // 302 → IdP authorize, with the sealed login-state cookie
        }
        if (p[3] === "callback" && req.method === "GET") {
          // BOOTSTRAP-VIA-OIDC: when the target org has no members, the first login provisions the
          // owner (prepareOidcCallback picks the bootstrap directory); else the normal per-domain
          // directory + policy applies.
          const prepared = await prepareOidcCallback(env, config);
          // BROWSER SSO (web flow): mint a `cfs_session` browser session (identical to password
          // login) and 302-redirect to the SPA's /auth/callback (PUBLIC_BASE_URL), appending
          // `?error=<code>` on failure — instead of returning the raw bearer-token JSON. The
          // token-return path (`handleOidcCallback`) remains available for API/test callers.
          return await handleOidcWebCallback(req, env, { config: prepared.config, env, dir: prepared.dir });
        }
        return json({ error: "method not allowed" }, 405);
      } catch (e: any) {
        if (e instanceof OidcError) return json({ error: e.code }, e.status);
        return json({ error: String(e?.message ?? e) }, 500);
      }
    }

    // ---- PUBLIC: the unauthenticated sign-in config the SPA reads to decide whether to show the
    //      password form and/or the SSO button + label. Reflects the runtime auth-config (admin
    //      console) first, then the deploy OIDC_* env. UNAUTHENTICATED on purpose. ----
    if (p[0] === "v1" && p[1] === "auth" && p[2] === "config" && p[3] === "public" && !p[4]) {
      if (req.method !== "GET") return json({ error: "method not allowed" }, 405);
      // Audit B16: this UNAUTHENTICATED route used to hit the global DirectoryDO singleton on
      // EVERY request (a cheap amplification target). The config changes rarely, so serve from
      // a short per-isolate TTL cache — a flood collapses to ~one DO read per isolate per window.
      const nowMs = Date.now();
      if (!publicAuthConfigCache || nowMs >= publicAuthConfigCache.expiresAt) {
        publicAuthConfigCache = { value: await resolvePublicAuthConfig(env), expiresAt: nowMs + PUBLIC_AUTH_CONFIG_TTL_MS };
      }
      // Auth-spec §2.8: the Mac app's reachability probe also learns the PORTAL origin
      // (`webBaseUrl`, for the device-authorize handoff on split-origin deployments) and the
      // product name. Both are derived per-request (env + request origin fallback), so they sit
      // OUTSIDE the cached DirectoryDO-backed value.
      return json({
        ...publicAuthConfigCache.value,
        webBaseUrl: webBaseUrl(env, req),
        gatewayBaseUrl: baseUrl(env, req),
        productName: productName(env),
        passkeysEnabled: publicAuthConfigCache.value.mode !== "oidc" && passkeysConfigured(env),
        signupMode: publicAuthConfigCache.value.mode === "oidc" || shouldRefuseOpenSignupOnHttps(env, new URL(req.url).protocol === "https:") ? "closed" : resolveSignupMode(env),
        // ONBOARDING.md build step 6: server-configured Mac-app download link, so an operator can
        // set/change it without a web rebuild. Derived per-request like webBaseUrl/productName
        // (cheap env read — no reason to route it through the DirectoryDO-backed cache above).
        appDownloadUrl: env.APP_DOWNLOAD_URL?.trim() || undefined,
      });
    }

    // ---- PUBLIC + SESSION-GATED auth surface (CONTRACTS-AUTH.md §4): signup, login (+MFA),
    //      logout, me, sessions, password change/forgot/reset, TOTP, WebAuthn, email-verify.
    //      These sit BEFORE the bearer gate: the public sub-routes ARE the login (like OIDC/
    //      bootstrap), and the session-gated ones authenticate via the `cfs_session` cookie
    //      themselves (loading + idle/CSRF-checking the live session). Returns null to fall
    //      through when the path isn't an auth route. ----
    if (p[0] === "v1" && p[1] === "auth" && p[2] !== "oidc") {
      const handled = await handleAuthRoutes(req, env, p);
      if (handled) return handled;
      // fall through (e.g. an unknown /v1/auth/* path) to the 404 below via the bearer gate.
    }

    // ---- public, token-as-credential routes (invite redeem / share resolve) ----
    if (isPublicRoute(p)) {
      // pre-auth per-IP rate limit (login/guest-code-exchange class)
      const pre = await preAuthLimiter.check(ipKey(req));
      if (!pre.allowed) return tooManyRequests(pre);
      try {
        const orgId = p[2];
        const rest = p.slice(3);
        if (rest[0] === "invites") {
          const res = await handleInvitesRequest(req, env, null, rest, orgId);
          // On a successful SCOPED invite redeem, multiuser durably wrote the grant
          // into OrgDO. Enforcement reads the per-filespace DoAclStore, so propagate
          // that grant into the target space's store (multiuser-INTEGRATION.md §5).
          // Audit B22: the propagation runs via waitUntil (defer) so the redeem response
          // returns immediately — the grant is already durable in OrgDO.
          return await syncRedeemedGrant(env, orgId, rest, res, defer);
        }
        // Audit B24: use the DURABLE OrgDO-backed share-link store (not the per-isolate
        // in-memory Map), so an external share link created on one isolate/PoP resolves on
        // every other — the in-memory Map 404'd external links across isolates in prod.
        return await handleSharingRequest(req, shareLinkStoreFor(env, orgId), null, rest, orgId);
      } catch (e: any) {
        return json({ error: String(e?.message ?? e) }, 500);
      }
    }

    // ---- authN: verify the request → Principal (F1; CONTRACTS-AUTH.md §4.7) ----
    // TWO accepted credentials, bearer FIRST then cookie (precedence in verifyRequest):
    //   1. `Authorization: Bearer <jws>` — machines (cloudfsd, CLI, service tokens, OIDC/
    //      bootstrap sessions). UNCHANGED legacy path; CSRF never applies.
    //   2. `cfs_session` cookie — browser sessions: the injected `sessionResolver` loads the
    //      live session row (idle/absolute/revocation enforced), re-mints the 15-min JWS, and
    //      enforces double-submit CSRF on mutations. The resolver throws AuthError on an invalid
    //      cookie (never silently downgrades to "no_token").
    // We pre-check the bearer's shape (cheap fail-closed) ONLY when a bearer is actually present;
    // a cookie-only request skips that and goes through the resolver.
    const bearer = bearerFromRequest(req);
    const hasCookie = !!readSessionCookie(req);
    if (!bearer && !hasCookie) {
      return json({ error: "no_token" }, 401);
    }
    if (bearer && bearer.split(".").length !== 3) {
      return json({ error: "malformed" }, 401);
    }
    const isMutation = req.method !== "GET" && req.method !== "HEAD";
    const verified = await verifyRequest(req, env, {
      sessionResolver: makeSessionResolver(env),
      isMutation,
    }).then(
      (pr) => ({ ok: true as const, pr }),
      (e) => ({ ok: false as const, e }),
    );
    if (!verified.ok) {
      const e = verified.e;
      if (e instanceof AuthError) return json({ error: e.code }, e.status);
      throw e;
    }
    const principal: Principal = verified.pr;

    // ---- revocation gate (CONTRACTS-AUTH.md §4.7): fold the org's revoked session+service
    //      jtis into the decision. The cookie path already rejects a revoked/expired session
    //      server-side (in the resolver), so this primarily catches a REVOKED SERVICE TOKEN
    //      whose JWS is otherwise still valid. Cheap point-keyed DO reads, off the per-item path.
    {
      // Audit B21: the revocation read and the account-status read are independent — fire them in
      // PARALLEL instead of awaiting sequentially (they each hit a different DO). Both reads are now
      // POINT-KEYED (one jti, one user) AND wrapped in a per-isolate 10s TTL cache: a burst of block
      // reads/writes for one principal collapses to a single fan-out. The cache is INVALIDATED on
      // every revoke/offboarding write (see auth-wiring.propagateAccountOffboarding + the service-
      // token/session revoke paths) on this isolate. Other isolates may retain the prior
      // authorization decision until its original TTL expires.
      const [revoked, accountInactive] = await Promise.all([
        cachedJtiRevoked(principal.orgId, principal.jti, () => gatewayJtiRevoked(env, principal.orgId, principal.jti)),
        cachedAccountInactive(principal.orgId, principal.sub, () => isAccountInactive(env, principal)),
      ]);
      // Fail closed for every token type when the revocation authority cannot be read.
      // gatewayJtiRevoked returns errored:true on an AuthDO error; an unavailable authority
      // must not admit a revoked-but-unexpired credential.
      // An errored read is not cached; a later request can retry the durable authority.
      if (revoked.errored) {
        return json({ error: "revocation_unavailable" }, 503);
      }
      if (revoked.revoked) {
        return json({ error: "revoked" }, 401);
      }
      // OFFBOARDING live-status gate (FINDING 1+11): a suspended/deprovisioned account is rejected
      // once the account-status check observes the change (up to the gate cache TTL),
      // before its ≤15-min session JWS naturally expires.
      if (accountInactive) {
        return json({ error: "account_inactive" }, 401);
      }
    }

    try {
      // Native account projection. Browser-only session/CSRF/MFA material stays
      // in auth-wiring.runMe; this path has passed every gateway bearer gate.
      if (req.method === "GET" && p.length === 3 && p[0] === "v1" && p[1] === "auth" && p[2] === "me") {
        if (!bearer) return json({ error: "no_token" }, 401);
        if (principal.type !== "session" && principal.type !== "service") return json({ error: "forbidden" }, 403);
        const org = env.ORG_DO.getByName(principal.orgId);
        const [user, orgName] = await Promise.all([org.getUser(principal.sub), org.getOrgName()]);
        if (!user || user.status !== "active") return json({ error: "account_inactive" }, 401);
        return json({
          userId: user.id, orgId: principal.orgId, email: user.email,
          displayName: user.displayName, role: user.role, scopes: principal.scopes,
          orgName: orgName ?? null, orgSlug: principal.orgId,
        });
      }
      // ---- mounted sub-routers: /v1/orgs/:org/... (multiuser plane) ----
      if (p[0] === "v1" && p[1] === "orgs" && p[2]) {
        const orgId = p[2];
        // every org route is tenant-scoped to the caller's org
        assertTenant(principal, orgId);
        const rest = p.slice(3);
        // Email-verification gate for the ROLE-gated org-admin plane (CONTRACTS-AUTH.md §4.2):
        // an unverified self-signup account may hold a session and READ, but cannot MUTATE the
        // org-admin surface (create users/spaces/invites/links/service-tokens). The filespace
        // plane is already gated by reduced session scopes; this closes the role-gated plane.
        if (isMutation && (await isOrgMutationEmailBlocked(env, principal))) {
          return json({ error: "email_unverified" }, 403);
        }
        const ctx = await toAuthedContext(env, principal);
        // Org-level PATCH (rename): `/v1/orgs/:org` with no sub-resource. Routed to the OrgDO
        // handler (which owner/admin-gates the rename) alongside the spaces registry below.
        if (rest.length === 0) {
          return await handleOrgRequest(req, env, ctx, rest, orgId);
        }
        switch (rest[0]) {
          case "legacy-account":
            if (rest.length !== 1) break;
            return await prepareLegacyAccount(req, env, principal);
          case "users":
          case "groups":
            return await handleUsersRequest(req, env, ctx, rest, orgId);
          case "spaces":
            return await handleOrgRequest(req, env, ctx, rest, orgId);
          case "storage-credentials":
          case "storage": {
            // UI-managed (encrypted) storage credentials + the connection-test probe.
            // Owner/admin gating is enforced inside the handler off ctx.orgRole.
            const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
            const res = await handleStorageCredentialsRequest(req, env, ctx, rest, orgId, {
              org: orgStub,
            });
            if (res) return res;
            break;
          }
          case "email-config": {
            // UI-managed (encrypted) per-org email-provider config + test-send. Owner/admin
            // gating is enforced inside the handler off ctx.orgRole.
            const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(orgId));
            const res = await handleEmailConfigRequest(req, env, ctx, rest, orgId, { org: orgStub });
            if (res) return res;
            break;
          }
          case "auth-config": {
            // DEPLOYMENT-level pluggable auth provider (built-in vs. external OIDC IdP), UI-managed
            // and encrypted-at-rest. Singleton on the global DirectoryDO (not per-org), but mounted
            // under /v1/orgs/:org for the owner/admin RBAC gate (enforced inside off ctx.orgRole).
            //
            // FINDING B: the row is DEPLOYMENT-WIDE, so owner/admin of the org in the PATH is NOT
            // sufficient — a second, attacker-created org's admin must NOT be able to rewrite the
            // global SSO provider (cross-tenant confused deputy / SSO hijack). Additionally require
            // that the caller's org IS the designated primary org (AUTH_CONFIG_ADMIN_ORG, falling
            // back to OIDC_ORG_ID). If neither is configured we REFUSE (fail safe — never "any org").
            const primaryOrg = (env.AUTH_CONFIG_ADMIN_ORG ?? env.OIDC_ORG_ID ?? await env.DIRECTORY_DO.get(env.DIRECTORY_DO.idFromName("global")).getSetupOrgId() ?? "").trim();
            if (!primaryOrg || orgId !== primaryOrg) {
              return json({ error: "forbidden: not the auth-config admin org" }, 403);
            }
            const dirStub = env.DIRECTORY_DO.get(env.DIRECTORY_DO.idFromName(DIRECTORY_DO_NAME));
            const isAdmin = ctx.orgRole === "owner" || ctx.orgRole === "admin";
            const res = await handleAuthConfigRequest(req, rest, isAdmin, {
              store: authConfigStoreFor(dirStub),
              encKey: env.STORAGE_ENC_KEY,
            });
            if (res) {
              // Audit B16: a successful write must invalidate the per-isolate public-config
              // cache so the sign-in page reflects the change immediately (not after the TTL).
              if ((req.method === "PUT" || req.method === "DELETE") && res.status < 300) {
                publicAuthConfigCache = null;
              }
              return res;
            }
            break;
          }
          case "invites":
            // Build step 1 of ONBOARDING.md: a successful create emails the invitee their join
            // link when a delivering provider is configured. The thunk defers the (OrgDO
            // email-config read + sender resolution) work so GET/DELETE never pay for it.
            return await handleInvitesRequest(req, env, ctx, rest, orgId, async () => ({
              emailSender: await emailSenderForOrg(env, orgId),
              buildJoinUrl: (joinToken) => `${webBaseUrl(env, req)}/join?token=${encodeURIComponent(joinToken)}`,
              productName: productName(env),
            }));
          case "doctor": {
            // ONBOARDING.md build step 5 "Health check": the SAME readiness probes as
            // `GET /v1/admin/doctor` (audit B8), but reachable from an already-signed-in
            // owner/admin session instead of the deploy-time BOOTSTRAP_SECRET — by the time
            // the setup wizard reaches this step the secret has already been used once and
            // cleared from page memory (Setup.tsx never re-holds it), so the bootstrap-gated
            // route is unusable here. Owner/admin gated off `ctx.orgRole` (same pattern as the
            // auth-config case above), unlike the bootstrap route which has no notion of org role.
            if (rest.length > 1) break;
            if (req.method !== "GET") return json({ error: "method not allowed" }, 405);
            if (ctx.orgRole !== "owner" && ctx.orgRole !== "admin") {
              return json({ error: "forbidden: admin required" }, 403);
            }
            // Always 200 (unlike the bootstrap route's 200/503 split): this is read by an
            // interactive wizard that renders pass/fail rows from the body, not a CI script
            // branching on HTTP status.
            const emailProvider = await describeSelectedEmailProviderForOrg(env, orgId);
            const report = await runDoctor(env, { isHttps: url.protocol === "https:", emailProvider });
            return json(report, 200);
          }
          case "shares":
          case "links":
            // Audit B24: durable OrgDO-backed share-link store (not the per-isolate Map).
            return await handleSharingRequest(req, shareLinkStoreFor(env, orgId), ctx, rest, orgId);
          case "service-tokens": {
            // Machine-credential admin surface (CONTRACTS-AUTH.md §4.6). Owner/admin gate is
            // enforced inside the lane (requireAdmin) off the verified Principal's org role.
            const res = await handleServiceTokenRoutes(req, env, principal, orgId, rest);
            if (res) return res;
            break;
          }
        }
        return json({ error: "not found" }, 404);
      }

      // ---- /v1/filespaces/:fs/<resource>/... (the metadata plane) ----
      if (p[0] !== "v1" || p[1] !== "filespaces" || !p[2]) return json({ error: "not found" }, 404);

      const spaceId = p[2];
      // ---- multi-tenant isolation BEFORE deriving the DO stub (F2) ----
      assertTenant(principal, principal.orgId, spaceId);
      // ---- SOFT-DELETE refusal chokepoint: EVERY filespace-plane request (presign, items,
      //      mutations, snapshots, locks, blocks, audit, activity, ...) flows through here, so this
      //      is the single place to refuse a soft-deleted space BEFORE any work or DO call. We ask
      //      the OrgDO registry whether the space is tombstoned; if so we return 410 Gone. The
      //      space is INVISIBLE (it's already excluded from listSpaces/getSpace), so an org admin
      //      can still LIST/inspect the rest of the org — only operations on THIS deleted space are
      //      refused, never the whole org plane. A truly-unknown space id is left alone (no row →
      //      the normal flow applies, e.g. a fresh DO is addressable as today). Best-effort: an
      //      OrgDO read error never blocks a live space (fail open to the existing behavior). ----
      {
        try {
          // Audit B21: cache the soft-delete registry row per (org,space) for a short TTL — EVERY
          // filespace-plane request (presign/items/blocks/...) reads it, so it's pure repeat work
          // for an active session. INVALIDATED on delete/purge/revive/register (see invalidateSpace
          // call sites) on this isolate; other isolates may retain the row until TTL expiry.
          const reg = await cachedSpaceRegistry(principal.orgId, spaceId, async () => {
            const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
            const row = await orgStub.getSpaceIncludingDeleted(spaceId);
            return row ? { deletedAt: row.deletedAt ?? null } : null;
          });
          if (reg && reg.deletedAt != null) {
            return json({ error: "filespace_deleted" }, 410);
          }
        } catch {
          return json({ error: "registry_unavailable" }, 503);
        }
      }
      const doName = filespaceDoName(principal.orgId, spaceId);
      const stub = env.FILESPACE.get(env.FILESPACE.idFromName(doName));
      const sourceIp = req.headers.get("cf-connecting-ip") ?? undefined;
      const resource = p[3];
      const q = url.searchParams;
      // A lease belongs to one authenticated client session, not every Mac using
      // that account. Legacy clients retain principal-only ownership.
      const clientId = req.headers.get("X-CloudFS-Client-ID");
      if (clientId !== null && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(clientId)) {
        return json({ error: "invalid_client_id" }, 400);
      }
      const lockOwner = clientId === null ? principal.sub : `${principal.sub}::client:${clientId.toLowerCase()}`;

      // small helpers bound to this request's principal/space.
      // FINDING #6 (N+1): `toAclPrincipal` makes TWO OrgDO RPCs (groupsForUser + getUser). It was
      // re-resolved on every gated mutation and again in presign — none memoized. Cache the resolved
      // AclPrincipal ONCE per request (a single in-flight promise) so gateMutation + presign reuse it
      // instead of re-hitting OrgDO. The principal is immutable for the request, so this is sound.
      let aclPrincipalCache: Promise<AclPrincipal> | undefined;
      const aclPrincipal = (): Promise<AclPrincipal> =>
        (aclPrincipalCache ??= toAclPrincipal(env, principal));
      /// scope + per-folder ACL gate before a privileged DO mutation. Returns a
      /// 403 Response on denial (already audited), or null to proceed.
      const gateMutation = async (scope: Scope, inodeId: string, action: Action, actionName: string,
        accessCheck?: (acl: AclPrincipal) => Promise<Decision>): Promise<Response | null> => {
        try {
          requireScope(principal, scope);
        } catch (e) {
          if (e instanceof AuthError) {
            // Audit B22: DENY-path audit is best-effort — the request is already being rejected, so
            // defer the append (waitUntil) instead of blocking the 4xx on a DO round-trip. The chain
            // stays intact (the DO serializes every append regardless of when it lands).
            defer(audit(stub, principal, spaceId, { action: actionName, decision: "deny", targetInodeId: inodeId, detail: { reason: e.code } }));
            return json({ error: e.code }, e.status);
          }
          throw e;
        }
        const rl = await stub.rateLimit("mutation", principalKey(principal.sub));
        if (!rl.allowed) {
          defer(audit(stub, principal, spaceId, { action: actionName, decision: "deny", targetInodeId: inodeId, detail: { reason: "rate_limited" } }));
          return tooManyRequests(rl);
        }
        const resolvedAcl = await aclPrincipal();
        const decision = accessCheck
          ? await accessCheck(resolvedAcl)
          : await stub.checkOpenAccess(resolvedAcl, inodeId, action, lockOwner);
        if (!decision.allow) {
          defer(audit(stub, principal, spaceId, { action: actionName, decision: "deny", targetInodeId: inodeId, levelChecked: decision.effectiveLevel ?? undefined, detail: { reason: decision.reason } }));
          return json({ error: "forbidden", reason: decision.reason }, 403);
        }
        // Audit B22: the SUCCESS-path audit stays INLINE + durable — the "we allowed this mutation"
        // record must be committed BEFORE the gate returns null and the caller performs the op, so a
        // crash can't ack a mutation that was never audited.
        await audit(stub, principal, spaceId, { action: actionName, decision: "allow", targetInodeId: inodeId, levelChecked: decision.effectiveLevel ?? undefined });
        return null;
      };

      switch (resource) {
        // ---- namespace -----------------------------------------------------
        case "items": {
          // Test/benchmark + admin seams for large-directory work.
          // FINDING A: these sat in the authenticated switch with NO scope/ACL gate,
          // so any principal that merely passed verifyRequest+assertTenant (e.g. an
          // fs:read-only user with zero grants) could write arbitrary inodes via _seed
          // or DoS the DO with an unclamped count. Gate _seed like every sibling
          // mutation (fs:write scope + ACL `create` on the parent) and _count like a
          // read (fs:read). The count is additionally clamped in seedChildren/bulkCreate.
          if (p[4] === "_seed" && req.method === "POST") {
            const b = (await req.json()) as { parent: string; prefix: string; count: number; isDir?: boolean };
            const parent = b.parent ?? "root";
            const denied = await gateMutation("fs:write", parent, "create", "item.seed");
            if (denied) return denied;
            // FINDING A: reject an over-bound count up front (the DO also clamps).
            if (!Number.isFinite(b.count) || b.count < 0 || b.count > BULK_SEED_MAX) {
              return json({ error: "count out of range", max: BULK_SEED_MAX }, 400);
            }
            const created = await stub.seedChildren(parent, b.prefix, b.count, !!b.isDir);
            return json({ created });
          }
          if (p[4] === "_count" && req.method === "GET") {
            requireScope(principal, "fs:read");
            // N-F3: gate `_count` behind the SAME per-folder read ACL as getItem/listPage. Without
            // it, a partially-granted user could learn an ungranted folder exists + its child count.
            // INVISIBLE on denial: 404 (not 403), so existence doesn't leak. Full-access principals
            // short-circuit in-DO (no per-item work).
            const count = await stub.childCountFor(await aclPrincipal(), q.get("parent") ?? "root");
            return count === null ? json({ error: "no such item" }, 404) : json({ count });
          }
          if (p[4]) {
            const id = decodeURIComponent(p[4]);

            // Writable-open preflight for local write-back clients. Never infer write
            // authority from read visibility or token scope alone. No unreadable
            // metadata is disclosed, and presign/commit still recheck live access.
            if (p[5] === "basic-info") {
              if (req.method !== 'PATCH' || p[6] !== undefined) return json({error:'method not allowed'},405);
              const denied = await gateMutation('fs:write',id,'write','item.basic-info');
              if (denied) return denied;
              const patch = await req.json() as Parameters<typeof stub.setBasicInfoFor>[2];
              const result = await stub.setBasicInfoFor(await aclPrincipal(),id,patch,lockOwner);
              if ('error' in result) return json(result,result.error === 'forbidden' ? 403 : result.error === 'not_found' ? 404 : ['locked','version_conflict'].includes(result.error!) ? 409 : 400);
              return json(result.item);
            }
            if (p[5] === "access") {
              if (req.method !== "GET" || p[6] !== undefined) return json({ error: "method not allowed" }, 405);
              requireScope(principal, "fs:read");
              const acl = await aclPrincipal();
              const item = await stub.getItemFor(acl, id, lockOwner);
              if (!item) return json({ error: "no such item" }, 404);
              const write = principal.scopes.includes("fs:write") && (await stub.checkOpenAccess(acl, id, "write", lockOwner)).allow;
              return json({ read: true, write }, 200, { "cache-control": "no-store" });
            }

            // Named streams / xattrs (v14): /items/:id/streams[/:name].
            if (p[5] === "streams") {
              const name = p[6] !== undefined ? decodeURIComponent(p[6]) : undefined;
              if (name === undefined) {
                if (req.method !== "GET") return json({ error: "method not allowed" }, 405);
                requireScope(principal, "fs:read");
                const list = await stub.listStreamsFor(await aclPrincipal(), id, lockOwner);
                return list === null ? json({ error: "no such item" }, 404) : json({ streams: list });
              }
              if (p[7] === 'manifest' && p[8] === undefined) {
                const offset=Number(q.get('offset') ?? 0), length=Number(q.get('length') ?? 16*1024*1024);
                try { validateStreamRange(offset,length); } catch { return json({error:'invalid_range'},400); }
                if (req.method === 'GET') {
                  requireScope(principal,'fs:read');
                  const result=await stub.streamManifestFor(await aclPrincipal(),id,name,offset,length,lockOwner);
                  return result ? json(result,200,{'cache-control':'no-store'}) : json({error:'no such item'},404);
                }
                if (req.method !== 'PUT') return json({error:'method not allowed'},405);
                requireScope(principal,'fs:write');
                const delta=await req.json();
                try { validateStreamDelta(delta); } catch { return json({error:'invalid_manifest'},400); }
                const blocks=streamVerificationBlocks(delta.blocks);
                if (blocks.some(b=>!b.objectKey.startsWith(`blocks/${doName}/`) || b.objectKey.includes('..'))) return json({error:'invalid_manifest'},400);
                const access=await stub.checkManifestUploadAccess(await aclPrincipal(),id,blocks,lockOwner);
                if ('error' in access) return json({error:'forbidden'},403);
                let identity:string|undefined;
                if ((env as Env & {STORAGE_VERIFY_UPLOADS?:string}).STORAGE_VERIFY_UPLOADS !== '0') {
                  const org=env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId)),space=await org.getSpace(spaceId);
                  const descriptor:SpaceStorageDescriptor|null=space?{provider:space.bucketProvider,endpoint:space.storageEndpoint,
                    region:space.storageRegion,bucket:space.storageBucket,forcePathStyle:space.storageForcePathStyle,credentialRef:space.storageCredentialRef}:null;
                  const config=await resolveStorageConfigAsync(env,descriptor,managedCredentialResolver(env,org)); identity=storageIdentity(config);
                  let pending;
                  try { pending=await stub.unverifiedObjects(blocks,identity); } catch { return json({error:'invalid_manifest'},400); }
                  if (pending.length) {
                    const budget=await stub.rateLimit('presign',principalKey(principal.sub),pending.length);
                    if (!budget.allowed) return tooManyRequests(budget);
                    const verified=await stub.verifyObjects(pending,config);
                    if ('error' in verified) return json(verified,503);
                  }
                }
                const result=await stub.commitStreamManifestFor(await aclPrincipal(),id,name,delta,lockOwner,identity);
                if ('error' in result) return json(result,result.error==='forbidden'?403:result.error==='not_found'?404:
                  ['locked','conflict'].includes(result.error)?409:result.error==='objects_unverified'?503:400);
                return json(result);
              }
              if (p[7] !== undefined) return json({error:'not found'},404);
              if (req.method === "GET") {
                requireScope(principal, "fs:read");
                const manifest=await stub.streamManifestFor(await aclPrincipal(),id,name,0,0,lockOwner);
                if (manifest?.exists && !manifest.legacy) return json({error:'stream_uses_manifest'},409);
                const bytes = await stub.getStreamFor(await aclPrincipal(), id, name, lockOwner);
                if (!bytes) return json({ error: "no such stream" }, 404);
                return new Response(bytes, { status: 200, headers: { "content-type": "application/octet-stream" } });
              }
              const streamFenceParam = q.get("fence");
              const streamFence = streamFenceParam === null ? undefined : Number(streamFenceParam);
              if (streamFence !== undefined && (!Number.isSafeInteger(streamFence) || streamFence < 1)) return json({ error: "invalid_fence" }, 400);
              if (req.method === "PUT") {
                requireScope(principal, "fs:write");
                const body = new Uint8Array(await req.arrayBuffer());
                if (body.byteLength > MAX_STREAM_BODY_BYTES) return json({ error: "body_too_large", maxBytes: MAX_STREAM_BODY_BYTES }, 413);
                const sizeParam = q.get("size");
                const plaintextSize = sizeParam === null ? body.byteLength : Number(sizeParam);
                const res = await stub.putStreamFor(await aclPrincipal(), id, name, body, plaintextSize, lockOwner, streamFence);
                if ("invalidSize" in res) return json({error:"invalid_stream_size"},400);
                if ("usesManifest" in res) return json({error:"stream_uses_manifest"},409);
                if ("tooLarge" in res) return json({ error: "body_too_large", maxBytes: res.maxBytes }, 413);
                if ("locked" in res) return json({ error: "locked", ...res }, 409);
                if ("denied" in res) return json({ error: "forbidden" }, 403);
                if ("notFound" in res) return json({ error: "no such item" }, 404);
                return json(res);
              }
              if (req.method === "DELETE") {
                requireScope(principal, "fs:write");
                const res = await stub.deleteStreamFor(await aclPrincipal(), id, name, lockOwner, streamFence);
                if ("locked" in res) return json({ error: "locked", ...res }, 409);
                if ("denied" in res) return json({ error: "forbidden" }, 403);
                if ("notFound" in res) return json({ error: "no such item" }, 404);
                return json(res);
              }
              return json({ error: "method not allowed" }, 405);
            }

            if (req.method === "GET") {
              requireScope(principal, "fs:read");
              // CHANGE D: per-folder ACL on stat. No `read` grant ⇒ INVISIBLE — we
              // return 404 (not 403) so existence/names/sizes don't leak. Broad-access
              // principals (owner/admin or whole-filespace grant) short-circuit in-DO.
              const item = await stub.getItemFor(await aclPrincipal(), id, lockOwner);
              return item ? json(item) : json({ error: "no such item" }, 404);
            }
            if (req.method === "DELETE") {
              const denied = await gateMutation("fs:write", id, "delete", "item.delete");
              if (denied) return denied;
              const openHandle = q.get("openHandle") ?? undefined;
              if (openHandle !== undefined && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(openHandle)) return json({error:"invalid_open_handle"},400);
              // Recursive (subtree) delete rolls the deletion up into ONE live-
              // activity event (a "large-delete" when the collapsed count meets
              // the bulk threshold) — see DO.deleteSubtree / liveActivity (WS3).
              if (q.get("recursive") === "true") {
                const subRes = await stub.deleteSubtree(id, principal.sub, lockOwner, openHandle);
                if ("forbidden" in subRes) return json({error:"forbidden",reason:subRes.reason},403);
                if ("locked" in subRes) {
                  return json({ error: "locked", locked: true, conflict: true, heldBy: subRes.heldBy, lockedItem: subRes.lockedItem, reason: subRes.reason }, 409);
                }
                return json(subRes);
              }
              const ev = q.get("expectedVersion");
              // owner = authenticated principal so the lock gate (B5) can tell the
              // holder's own delete from a teammate's.
              const delRes = await stub.deleteItem(id, ev === null ? undefined : Number(ev), lockOwner, openHandle);
              if ("locked" in delRes) {
                return json({ error: "locked", locked: true, conflict: true, heldBy: delRes.heldBy, reason: delRes.reason }, 409);
              }
              if (!delRes.deleted) return json({error:delRes.reason ?? "delete_failed"}, delRes.reason === "readonly" || delRes.reason === "root_protected" ? 403 : 409);
              return json(delRes);
            }
            if (req.method === "PATCH") {
              // Audit B17: rename/move (`PATCH /items/:id {parent?, name?}`). Opaque ids make this
              // a single-row `(parent,name)` update — no descendant rewrite. Requires `write` on
              // the item; a MOVE (changing parent) also requires `create` on the destination parent.
              const b = (await req.json()) as { parent?: string; name?: string; expectedVersion?: number; replace?: {id:string;expectedVersion:number}; openHandle?: string };
              if (b.openHandle !== undefined && (typeof b.openHandle !== "string" || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(b.openHandle))) return json({error:"invalid_open_handle"},400);
              const denied = await gateMutation("fs:write", id, "rename", "item.rename");
              if (denied) return denied;
              if (b.parent !== undefined) {
                const deniedDst = await gateMutation("fs:write", b.parent, "create", "item.rename.dst");
                if (deniedDst) return deniedDst;
              }
              const res = await stub.renameItem(id, {
                parent: b.parent, name: b.name, expectedVersion: b.expectedVersion, owner: lockOwner, replace:b.replace, principal:await aclPrincipal(), openHandle:b.openHandle,
              });
              if ("forbidden" in res) return json({error:"forbidden"},403);
              if ("invalidMutation" in res) return json({error:res.invalidMutation,reason:res.reason},res.invalidMutation === "readonly" || res.invalidMutation === "root_protected" ? 403 : res.invalidMutation === "replacement_changed" || res.invalidMutation === "directory_not_empty" || res.invalidMutation === "type_mismatch" ? 409 : 400);
              if ("notFound" in res) return json({ error: "no such item" }, 404);
              if ("locked" in res) return json({ error: "locked", locked: true, conflict: true, heldBy: res.heldBy, reason: res.reason }, 409);
              if ("invalidName" in res) return json({ error: "invalid_name", reason: res.reason }, 400);
              if ("nameCollision" in res) return json({ error: "name_collision", reason: res.reason }, 409);
              if ("invalidMove" in res) return json({ error: "invalid_move", reason: res.reason }, 400);
              if ("conflict" in res) return json({ error: res.message, conflict: true, expected: res.expected, actual: res.actual }, 409);
              return json(res.item);
            }
            return json({ error: "method not allowed" }, 405);
          }
          if (req.method === "GET") {
            requireScope(principal, "fs:read");
            const parent = q.get("parent") ?? "root";
            const limit = q.get("limit");
            const cursor = q.get("cursor");
            // CHANGE D: per-folder ACL on listing. Children the principal cannot
            // read/list are excluded. The DO keeps the keyset `cursor` over the
            // UNDERLYING scan (not the filtered subset), so pagination still
            // advances correctly; a page may return fewer items after filtering.
            return json(await stub.listPageFor(await aclPrincipal(), parent, limit ? Number(limit) : undefined, cursor));
          }
          if (req.method === "POST") {
            const b = (await req.json()) as {
              parent?: string; name: string; isDir?: boolean; size?: number; expectedVersion?: number; etag?: string | null;
            };
            const parent = b.parent ?? "root";
            // create requires `create` (edit) on the PARENT folder (SPEC §4.3).
            const denied = await gateMutation("fs:write", parent, "create", "item.create");
            if (denied) return denied;
            const res = await stub.createItem(parent, b.name, !!b.isDir, b.size ?? 0, {
              expectedVersion: b.expectedVersion,
              etag: b.etag ?? null,
              owner: lockOwner,   // lock gate (B5): holder's own re-create vs a teammate's clobber
            });
            if ('forbidden' in res) return json({error:'forbidden',reason:res.reason},403);
            if ('invalidParent' in res) return json({error:'invalid_parent'},400);
            if ('capacity' in res) return json({error:'metadata_capacity',reason:'Filespace metadata is full; preserve pending writes and contact the operator.'},507);
            if ("locked" in res) {
              return json({ error: "locked", locked: true, conflict: true, heldBy: res.heldBy, reason: res.reason }, 409);
            }
            if ("invalidName" in res) {
              return json({ error: "invalid_name", reason: res.reason }, 400);
            }
            if ("conflict" in res) {
              return json({ error: res.message, conflict: true, expected: res.expected, actual: res.actual }, 409);
            }
            return json(res.item, 201);
          }
          break;
        }

        // Folder administration is a live ACL capability, independent of org role.
        // Human sessions already have ordinary write scope; daemon/service tokens
        // still need explicit fs:admin and cannot gain an admin plane implicitly.
        case "access-management":
        case "grants": {
          const read = req.method === "GET";
          if (principal.type === "session") requireScope(principal, read ? "fs:read" : "fs:write");
          else requireScope(principal, "fs:admin");
          const org = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
          // Administrative actions never reuse the data-plane role/group cache.
          const [users, groups, groupIds] = await Promise.all([org.listUsers(), org.listGroups(), org.groupsForUser(principal.sub)]);
          const actorUser = users.find(user => user.id === principal.sub);
          if (!actorUser || actorUser.status !== "active") return json({ error: "forbidden" }, 403);
          const actor: AclPrincipal = { type: principal.type === "service" ? "service_account" : "user", id: principal.sub, orgRole: actorUser.role, groupIds };
          if (read && resource === "access-management" && q.has("parent")) {
            const page = await stub.listManagedFoldersFor(actor, q.get("parent")!, q.get("cursor"));
            return page ? json(page) : json({ error: "folder_admin_required" }, 403);
          }
          const protectedIds = users.filter(user => user.role !== "standard").map(user => user.id);
          const management = await stub.accessManagementFor(actor, protectedIds);
          const canChangeGrants = principal.type === "session" ? principal.scopes.includes("fs:write") : principal.scopes.includes("fs:admin");
          management.canManageAccess &&= canChangeGrants;
          management.canDelegateAdmin &&= canChangeGrants;
          management.grants = management.grants.map(grant => ({ ...grant, canModify: grant.canModify && canChangeGrants }));
          if (read) {
            if (resource === "access-management") {
              const permitted = management.canDelegateAdmin ? users : users.filter(user => user.role === "standard");
              return json({ ...management,
                grants: management.grants.map(grant => ({ ...grant, principalLabel: grant.principalType === "group"
                  ? groups.find(group => group.id === grant.principalId)?.name ?? "Deleted group"
                  : users.find(user => user.id === grant.principalId)?.displayName ?? "Deleted member" })),
                members: management.canManageAccess ? permitted.filter(user => user.status === "active") : [],
                groups: management.canManageAccess ? groups : [] });
            }
            if (!management.canManageAccess) return json({ error: "folder_admin_required" }, 403);
            const inodeId = q.get("inodeId");
            if (inodeId && !(await stub.checkAccess(actor, inodeId, "manage_acl")).allow) return json({ error: "folder_admin_required" }, 403);
            return json({ grants: management.grants.filter(g => !inodeId || g.inodeId === inodeId) });
          }
          if (resource !== "grants" || !["POST", "DELETE"].includes(req.method)) break;
          if (!management.canManageAccess) return json({ error: "folder_admin_required" }, 403);
          const body: Record<string, unknown> = req.method === "POST" ? await req.json() as Record<string, unknown> : {
            inodeId: q.get("inodeId"), principalType: q.get("principalType"), principalId: q.get("principalId"),
          };
          if (!body || typeof body !== "object" || Array.isArray(body)) return json({ error: "invalid_grant" }, 400);
          if (typeof body.inodeId !== "string" || !body.inodeId || typeof body.principalId !== "string" || !body.principalId
            || !["user", "service_account", "group"].includes(String(body.principalType))) return json({ error: "invalid_grant_target" }, 400);
          const principalType = body.principalType as AclPrincipal["type"];
          const target = users.find(user => user.id === body.principalId);
          if (principalType === "group" ? !groups.some(group => group.id === body.principalId)
            : !target || (req.method === "POST" && target.status !== "active") || (target.kind === "service_account" ? "service_account" : "user") !== principalType) return json({ error: "invalid_principal" }, 400);
          const protectedPrincipal = !!target && target.role !== "standard";
          if (req.method === "POST" && (!["read", "edit", "admin"].includes(String(body.level))
            || (body.mountAsRoot !== undefined && typeof body.mountAsRoot !== "boolean")
            || (body.expiresAt != null && (typeof body.expiresAt !== "number" || !Number.isFinite(body.expiresAt) || body.expiresAt <= Date.now())))) {
            return json({ error: "invalid_grant" }, 400);
          }
          const rl = await stub.rateLimit("mutation", principalKey(principal.sub));
          if (!rl.allowed) return tooManyRequests(rl);
          const result = req.method === "POST"
            ? await stub.grantAccessFor(actor, { spaceId, inodeId: body.inodeId, principalType, principalId: body.principalId,
                level: body.level as "read" | "edit" | "admin", mountAsRoot: body.mountAsRoot as boolean | undefined, expiresAt: body.expiresAt as number | null | undefined }, protectedPrincipal)
            : await stub.revokeAccessFor(actor, body.inodeId, principalType, body.principalId, protectedPrincipal);
          await audit(stub, principal, spaceId, { action: req.method === "POST" ? "acl.grant" : "acl.revoke", decision: "error" in result ? "deny" : "allow", targetInodeId: body.inodeId });
          if ("error" in result) return json(result, result.error === "folder_not_found" ? 404 : 403);
          return json(result, req.method === "POST" ? 201 : 200);
        }

        // ---- audit reader (gated by audit:read scope) ---------------------
        // Reads the DO ring first, then transparently falls back to R2-archived
        // segments for ranges older than the ring (WS3 §5.4). Optional appended
        // params `since`/`until` (ms-epoch) page into R2 history; the AuditRecord
        // shape is unchanged and remains hash-verifiable across the boundary.
        case "audit": {
          if (req.method === "GET") {
            requireScope(principal, "audit:read");
            const authority = await toAuthedContext(env, principal);
            if (authority.orgRole !== "owner" && authority.orgRole !== "admin") {
              return json({ error: "workspace_admin_required" }, 403);
            }
            const since = q.get("since");
            const until = q.get("until");
            const cursor = q.get("cursor");
            // Reader is NEWEST-FIRST (seq DESC). `cursor` is an EXCLUSIVE upper
            // bound on `seq` for page-back: the client passes the lowest seq of
            // the prior page, so successive pages are strictly older and
            // non-overlapping, terminating on a short page (CONTRACTS §5.4).
            const records = await stub.queryAudit({
              action: q.get("action") ?? undefined,
              decision: (q.get("decision") as "allow" | "deny" | null) ?? undefined,
              actorSub: q.get("actor") ?? undefined,
              since: since !== null ? Number(since) : undefined,
              until: until !== null ? Number(until) : undefined,
              cursor: cursor !== null ? Number(cursor) : undefined,
              limit: q.get("limit") ? Number(q.get("limit")) : undefined,
            });
            return json(records);
          }
          break;
        }

        // ---- live activity feed (WS3 §5.3, gated by audit:read scope) -----
        // In-progress transfers + rolled-up bulk ops from DO HOT STATE. NOT the
        // audit history — see `audit` for that. `GET …/activity/live`.
        case "activity": {
          if (p[4] === "live" && req.method === "GET") {
            requireScope(principal, "audit:read");
            const authority = await toAuthedContext(env, principal);
            if (authority.orgRole !== "owner" && authority.orgRole !== "admin") {
              return json({ error: "workspace_admin_required" }, 403);
            }
            return json(await stub.liveActivity());
          }
          break;
        }

        // ---- block map (large-file read/write path) -----------------------
        case 'reclamation': {
          requireScope(principal,req.method==='GET'?'fs:read':'fs:admin');
          if (req.method==='GET' && !p[4]) {
            const report=await stub.reclamationReportFor(await aclPrincipal());return json(report,'error' in report?403:200);
          }
          if (req.method==='POST' && p[4]==='quarantine' && !p[5]) {
            const body=await req.json() as {recoveredThrough:number};
            const result=await stub.quarantineObjectsFor(await aclPrincipal(),body.recoveredThrough,principal.orgId,spaceId);
            return json(result,'error' in result?(result.error==='forbidden'?403:400):200);
          }
          break;
        }
        case 'capacity': {
          if (req.method !== 'GET' || p[4]) break;
          requireScope(principal,'fs:read');
          const report=await stub.metadataCapacityFor(await aclPrincipal(),q.get('contributors') === '1');
          return json(report,'error' in report ? 403 : 200);
        }
        case "blocks": {
          const itemId = p[4] ? decodeURIComponent(p[4]) : q.get("item");
          if (!itemId) return json({ error: "item required" }, 400);
          if (req.method === "POST" && p[5] === "verify" && p.length === 6) {
            // Optional upload pipeline optimization. Receipts alone never publish
            // a manifest or acknowledge a durable file; PUT below remains the
            // authoritative ACL, lease, version and complete-receipt barrier.
            const denied = await gateMutation("fs:write", itemId, "write", "blocks.verify");
            if (denied) return denied;
            let blocks;
            try { blocks = uploadVerificationManifest(((await req.json()) as {blocks?: unknown}).blocks); }
            catch { return json({error:"invalid_manifest",reason:"invalid verification batch"},400); }
            const prefix = `blocks/${doName}/`;
            if (blocks.some(block => !block.objectKey.startsWith(prefix) || block.objectKey.includes(".."))) {
              return json({error:"invalid_manifest",reason:"object key is outside this filespace"},400);
            }
            const access = await stub.checkManifestUploadAccess(await aclPrincipal(),itemId,blocks,lockOwner);
            if ("error" in access) return json({error:"forbidden",reason:access.error},403);
            const org = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
            const space = await org.getSpace(spaceId);
            const descriptor: SpaceStorageDescriptor | null = space ? {provider:space.bucketProvider,endpoint:space.storageEndpoint,
              region:space.storageRegion,bucket:space.storageBucket,forcePathStyle:space.storageForcePathStyle,credentialRef:space.storageCredentialRef} : null;
            const config = await resolveStorageConfigAsync(env,descriptor,managedCredentialResolver(env,org));
            let pending;
            try { pending = await stub.unverifiedObjects(blocks,storageIdentity(config)); }
            catch { return json({error:"invalid_manifest",reason:"invalid content-addressed objects"},400); }
            if (pending.length) {
              const budget = await stub.rateLimit("presign",principalKey(principal.sub),pending.length);
              if (!budget.allowed) return tooManyRequests(budget);
              try {
                // Only this server's checksum-validated storage response can
                // become a receipt. The HTTP body contains identities, not proof.
                const objects = await verifyStorageObjects(config,pending,fetch,nativeVerificationBucket(env,config));
                const recorded = await stub.recordVerifiedObjects(objects,storageIdentity(config));
                if ("error" in recorded) return json(recorded,503);
              } catch (error) {
                return json({error:"object_verification_failed",reason:error instanceof ObjectVerificationError ? error.reason : "storage request failed"},503);
              }
            }
            return json({verified:new Set(blocks.map(block=>block.objectKey)).size});
          }
          if (req.method === 'GET' && p[5] === 'range' && p.length === 6) {
            requireScope(principal,'fs:read');
            const page = q.has('offset') || q.has('length')
              ? await stub.fileManifestExtentFor(await aclPrincipal(),itemId,Number(q.get('offset') ?? NaN),Number(q.get('length') ?? NaN),q.get('contentVersion') ?? undefined,lockOwner)
              : await stub.fileManifestRangeFor(await aclPrincipal(),itemId,Number(q.get('after') ?? '-1'),Number(q.get('limit') ?? '1024'),q.has('version') ? Number(q.get('version')) : undefined,lockOwner);
            if ('error' in page) return json(page,page.error === 'forbidden' ? 403 : page.error === 'not_found' ? 404 : page.error === 'version_conflict' ? 409 : page.error === 'invalid_manifest' ? 500 : 400);
            return json(page);
          }
          if (req.method === 'PATCH' && p.length === 5) {
            const denied = await gateMutation('fs:write',itemId,'write','blocks.delta');
            if (denied) return denied;
            const delta = await req.json();
            try { validateFileDelta(delta); } catch { return json({error:'invalid_manifest'},400); }
            const blocks = fileVerificationBlocks(delta.blocks), prefix = `blocks/${doName}/`;
            if (blocks.some(b=>!b.objectKey.startsWith(prefix) || b.objectKey.includes('..'))) return json({error:'invalid_manifest'},400);
            const access = await stub.checkManifestUploadAccess(await aclPrincipal(),itemId,blocks,lockOwner);
            if ('error' in access) return json({error:'forbidden',reason:access.error},403);
            let identity: string | undefined;
            if ((env as Env & {STORAGE_VERIFY_UPLOADS?:string}).STORAGE_VERIFY_UPLOADS !== '0') {
              const org = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId)), space = await org.getSpace(spaceId);
              const descriptor: SpaceStorageDescriptor | null = space ? {provider:space.bucketProvider,endpoint:space.storageEndpoint,region:space.storageRegion,
                bucket:space.storageBucket,forcePathStyle:space.storageForcePathStyle,credentialRef:space.storageCredentialRef} : null;
              const config = await resolveStorageConfigAsync(env,descriptor,managedCredentialResolver(env,org));
              identity = storageIdentity(config);
              let pending;
              try { pending = await stub.unverifiedObjects(blocks,identity); }
              catch { return json({error:'invalid_manifest',reason:'invalid object identity'},400); }
              for (let i=0;i<pending.length;i+=128) {
                const budget = await stub.rateLimit('presign',principalKey(principal.sub),Math.min(128,pending.length-i));
                if (!budget.allowed) return tooManyRequests(budget);
                const verified = await stub.verifyObjects(pending.slice(i,i+128),config);
                if ('error' in verified) return json(verified,503);
              }
            }
            const result = await stub.commitFileDelta(await aclPrincipal(),itemId,delta,lockOwner,identity);
            if ('error' in result) return json(result,result.error === 'forbidden' ? 403 : result.error === 'invalid_manifest' ? 400 : result.error === 'objects_unverified' ? 503 : 409);
            return json(result.item);
          }
          if (req.method === "GET") {
            requireScope(principal, "fs:read");
            const decision = await stub.checkOpenAccess(await aclPrincipal(), itemId, "read", lockOwner);
            if (!decision.allow) return json({ error: "forbidden", reason: decision.reason }, 403);
            return json(await stub.getBlockMap(itemId));
          }
          if (req.method === "PUT") {
            const denied = await gateMutation("fs:write", itemId, "write", "blocks.set");
            if (denied) return denied;
            // Audit B4/B5: the content-commit path now carries optimistic concurrency
            // (`expectedVersion`) and the lock gate (owner = authenticated principal,
            // optional `fence`). A version mismatch → 409 ConflictError; a live lease
            // by another editor → 409 LockedError. `force:true` is an explicit replace
            // (skips the version check) for genuine overwrite intent.
            const b = (await req.json()) as {
              blocks: any[]; etag?: string | null; expectedVersion?: number; force?: boolean; fence?: number; blockSize?: number;
            };
            try { validateBlockManifest(b.blocks); } catch { return json({error:"invalid_manifest"},400); }
            const prefix = `blocks/${doName}/`;
            if (b.blocks.some(block => !block.objectKey.startsWith(prefix) || block.objectKey.includes(".."))) {
              return json({error:"invalid_manifest",reason:"object key is outside this filespace"},400);
            }
            const manifestAccess = await stub.checkManifestUploadAccess(await aclPrincipal(),itemId,b.blocks,lockOwner);
            if ("error" in manifestAccess) return json({error:"forbidden",reason:manifestAccess.error},403);
            let verifiedStorageIdentity: string | undefined;
            if ((env as Env & {STORAGE_VERIFY_UPLOADS?:string}).STORAGE_VERIFY_UPLOADS !== "0") {
              const org = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
              const space = await org.getSpace(spaceId);
              const descriptor: SpaceStorageDescriptor | null = space ? {provider:space.bucketProvider,endpoint:space.storageEndpoint,
                region:space.storageRegion,bucket:space.storageBucket,forcePathStyle:space.storageForcePathStyle,credentialRef:space.storageCredentialRef} : null;
              const config = await resolveStorageConfigAsync(env,descriptor,managedCredentialResolver(env,org));
              verifiedStorageIdentity = storageIdentity(config);
              let pending;
              try { pending = await stub.unverifiedObjects(b.blocks,verifiedStorageIdentity); }
              catch { return json({error:"invalid_manifest",reason:"invalid content-addressed objects"},400); }
              // Bounded verification limits pending metadata while payloads flow
              // client→bucket. RPCs do not bypass platform connection limits.
              for (let i=0;i<pending.length;i+=128) {
                const budget = await stub.rateLimit("presign",principalKey(principal.sub),Math.min(128,pending.length-i));
                if (!budget.allowed) return tooManyRequests(budget);
                const verified = await stub.verifyObjects(pending.slice(i,i+128),config);
                if ("error" in verified) return json(verified,503);
              }
            }
            const setRes = await stub.setBlockMap(itemId, b.blocks, {
              etag: b.etag ?? null,
              blockSize: b.blockSize,
              expectedVersion: b.force ? undefined : b.expectedVersion,
              owner: lockOwner,
              fence: b.fence,
              principal: await aclPrincipal(),
              storageIdentity: verifiedStorageIdentity,
            });
            if ("invalidManifest" in setRes) return json({error:"invalid_manifest",reason:setRes.reason},400);
            if ("forbidden" in setRes) return json({ error: "forbidden", reason: setRes.reason }, 403);
            if ("locked" in setRes) {
              return json({ error: "locked", locked: true, conflict: true, heldBy: setRes.heldBy, reason: setRes.reason }, 409);
            }
            if ("conflict" in setRes) {
              return json({ error: setRes.message, conflict: true, expected: setRes.expected, actual: setRes.actual }, 409);
            }
            return json(setRes);
          }
          break;
        }

        // ---- change feed ---------------------------------------------------
        case "changes": {
          if (req.method === "GET" && p[4] === "subscribe" && !p[5]) {
            requireScope(principal, "fs:read");
            if (req.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "websocket_required" }, 426);
            const identity = await aclPrincipal();
            if (!(await stub.checkFilespaceRead(identity)).allow) return json({ error: "forbidden" }, 403);
            return stub.fetch(new Request("https://filespace/internal/changes", { headers: {
              Upgrade: "websocket", "X-CloudFS-Subscription": JSON.stringify({ principal: identity, expiresAt: principal.exp * 1000 })
            } }));
          }
          if (req.method === "GET" && !p[4]) {
            requireScope(principal, "fs:read");
            const limit = q.get("limit");
            // CHANGE D: per-folder ACL on the change feed. Changed items the
            // principal cannot read are excluded, but the sync `anchor` and page
            // `cursor` reflect the UNDERLYING scan position (not the filtered
            // result), so the client never misses a change it should receive and
            // the cursor still advances past filtered-out rows.
            return json(await stub.changesSinceFor(await aclPrincipal(), Number(q.get("since") ?? "0"), limit ? Number(limit) : undefined));
          }
          break;
        }

        // Byte ranges are handle-owned, and never authorize a whole-file commit.
        case "range-locks": {
          if (req.method !== "POST" || p[4]) break;
          requireScope(principal,"fs:read");
          const b = await req.json() as Record<string,unknown>;
          const actions = ["acquire","renew","release","check","release-read"];
          if (!b || typeof b !== "object" || typeof b.action !== "string" || !actions.includes(b.action)
            || typeof b.path !== "string" || !b.path || typeof b.handle !== "string"
            || !/^[A-Za-z0-9._:-]{1,160}$/.test(b.handle)
            || (b.fence !== undefined && (!Number.isSafeInteger(b.fence) || Number(b.fence)<1))
            || (b.ttlMs !== undefined && (typeof b.ttlMs !== "number" || !Number.isFinite(b.ttlMs) || b.ttlMs<=0)))
            return json({error:"invalid_range_lease"},400);
          const ranges=b.ranges;
          if ((b.action === "acquire" || b.action === "release" && ranges !== undefined)
            && (!Array.isArray(ranges) || !ranges.length || ranges.length>64 || !ranges.every(validRange)))
            return json({error:"invalid_ranges"},400);
          if ((b.action === "renew" || b.action === "release" || b.action === "release-read") && b.fence === undefined)
            return json({error:"missing_fence"},400);
          if (b.action === "check" && !validRange(b.range)) return json({error:"invalid_range"},400);
          if (b.action === "release-read") return json(await stub.releaseReadPermit(b.path,lockOwner,b.handle,Number(b.fence)));
          if (b.action === "release") return json(await stub.releaseRanges(b.path,lockOwner,b.handle,Number(b.fence),
            Array.isArray(ranges) ? ranges.filter(validRange) : undefined));
          // Lease mutation work has its own bounded principal budget. Hot read
          // admission uses the larger read/presign budget; cleanup never waits
          // behind throttled acquisitions or renewals.
          const limit = await stub.rateLimit(b.action === "check" ? "presign" : "mutation",principalKey(principal.sub),
            b.action === "acquire" && Array.isArray(ranges) ? ranges.length : 1);
          if (!limit.allowed) return tooManyRequests(limit);
          const identity=await aclPrincipal(), ttl=Math.min(Number(b.ttlMs ?? 60_000),60_000);
          if (b.action === "renew") return json(await stub.renewRangesFor(identity,b.path,lockOwner,b.handle,Number(b.fence),ttl,principal.scopes.includes("fs:lock")));
          if (b.action === "check" && validRange(b.range))
            return json(await stub.rangeAccessFor(identity,b.path,lockOwner,b.handle,b.range,b.fence === undefined ? undefined : Number(b.fence)));
          if (Array.isArray(ranges) && ranges.every(validRange)) {
            if (ranges.some(r=>r.exclusive)) requireScope(principal,"fs:lock");
            return json(await stub.acquireRangesFor(identity,b.path,lockOwner,b.handle,ranges,ttl,b.fence === undefined ? undefined : Number(b.fence),principal.scopes.includes("fs:lock")));
          }
          return json({error:"invalid_range_lease"},400);
        }

        // Open-file lifetime is independent of write/range locks. Only a
        // device-bound authenticated session can retain an unlinked inode;
        // neither a supplied owner nor a handle ID is bearer authority.
        case "open-handles": {
          if (req.method !== "POST" || p[4] !== undefined) return json({error:"method not allowed"},405);
          requireScope(principal,"fs:read");
          if (clientId === null) return json({error:"client_id_required"},400);
          const b = await req.json() as {action?:string;handleId?:string;handles?:string[];id?:string;accessMask?:number;shareMask?:number;ttlMs?:number;stream?:{name?:unknown;required?:unknown}};
          const validHandle = (id:unknown): id is string => typeof id === "string"
            && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
          if (!b || typeof b !== "object" || !["acquire","renew","renew-batch","close","directory-snapshot"].includes(b.action ?? "")
              || (b.action === "renew-batch" ? !Array.isArray(b.handles) || b.handles.length < 1 || b.handles.length > 128
                || !b.handles.every(validHandle) || new Set(b.handles).size !== b.handles.length : !validHandle(b.handleId))
              || (b.action !== "acquire" && b.stream !== undefined)) return json({error:"invalid_open_handle"},400);
          // Closing an existing handle cannot confer authority, and must still
          // work after its file ACL was revoked. Ownership is checked in-DO.
          if (b.action === "close") return json(await stub.closeOpenFor(lockOwner,b.handleId!));
          const ttlMs = b.ttlMs ?? 90_000;
          if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > 120_000) return json({error:"invalid_open_handle"},400);
          const budget = await stub.rateLimit("mutation",principalKey(principal.sub));
          if (!budget.allowed) return tooManyRequests(budget);
          const identity = await aclPrincipal();
          if (b.action === "renew-batch") return json(await stub.renewOpenBatchFor(identity,lockOwner,b.handles!,ttlMs,principal.scopes.includes("fs:write")));
          if (b.action === "renew") return json(await stub.renewOpenFor(identity,lockOwner,b.handleId!,ttlMs,principal.scopes.includes("fs:write")));
          if (typeof b.id !== "string" || !b.id || b.id.length > 4096
              || !Number.isSafeInteger(b.accessMask) || b.accessMask! < 0 || b.accessMask! > 7
              || !Number.isSafeInteger(b.shareMask) || b.shareMask! < 0 || b.shareMask! > 7) return json({error:"invalid_open_handle"},400);
          if (b.action === "directory-snapshot") {
            if ((b.accessMask !== 0 && b.accessMask !== 1) || b.stream !== undefined) return json({error:"invalid_open_handle"},400);
            return json(await stub.directorySnapshotFor(identity,b.id,lockOwner,
              {handleId:b.handleId!,accessMask:b.accessMask!,shareMask:b.shareMask!,ttlMs}));
          }
          let stream: {name:string;required:boolean}|undefined;
          if (b.stream !== undefined) {
            if (!b.stream || typeof b.stream !== "object" || Array.isArray(b.stream)
              || typeof b.stream.name !== "string" || typeof b.stream.required !== "boolean"
              || b.stream.name.length > 4096) return json({error:"invalid_open_handle"},400);
            try { stream = {name:canonicalizeName(b.stream.name),required:b.stream.required}; }
            catch { return json({error:"invalid_open_handle"},400); }
          }
          if ((b.accessMask! & 6) !== 0) requireScope(principal,"fs:write");
          return json(await stub.beginOpenFor(identity,b.id,lockOwner,
            {handleId:b.handleId!,accessMask:b.accessMask!,shareMask:b.shareMask!,ttlMs,stream}));
        }

        // ---- locks / leases ------------------------------------------------
        case "locks": {
          const path = q.get("path");
          if (req.method === "POST") {
            const b = (await req.json()) as {
              path: string; ttlMs?: number; mode?: "exclusive" | "shared"; purpose?: "advisory" | "publication"; fence?: number; renew?: boolean; includeItem?: boolean;
            };
            // F6: owner is the AUTHENTICATED principal, never the request body.
            const owner = lockOwner;
            if (typeof b.path !== "string" || !b.path || (b.mode !== undefined && !["exclusive", "shared"].includes(b.mode)) ||
                (b.purpose !== undefined && !["advisory", "publication"].includes(b.purpose)) ||
                (b.purpose === "publication" && (b.mode ?? "exclusive") !== "exclusive") || (b.renew && b.purpose !== undefined) ||
                (b.includeItem !== undefined && typeof b.includeItem !== "boolean") ||
                (b.includeItem === true && (b.purpose !== "publication" || (b.mode ?? "exclusive") !== "exclusive" || b.renew === true)) ||
                (b.ttlMs !== undefined && (!Number.isFinite(b.ttlMs) || b.ttlMs <= 0)) ||
                (b.fence !== undefined && (!Number.isSafeInteger(b.fence) || b.fence < 1)) || (b.renew && b.fence === undefined)) {
              return json({ error: "invalid_lease" }, 400);
            }
            if (b.includeItem === true) {
              // Returning an item snapshot is a write-path optimization. Keep
              // the scopes of the operations it replaces: ordinary read, write
              // authorization, and whole-file lock acquisition.
              requireScope(principal,"fs:read");
              requireScope(principal,"fs:write");
            }
            // lease acquisition is itself a permission-checked call (SPEC §4.9):
            // fs:lock scope + read_write (edit) ACL on the path's inode.
            const denied = await gateMutation("fs:lock", b.path, "write", "lock.acquire");
            if (denied) return denied;
            const ttl = Math.min(b.ttlMs ?? 30_000, 60_000);
            if (b.renew && b.fence !== undefined) {
              return json(await stub.renewLock(b.path, owner, b.fence, ttl));
            }
            if (b.includeItem === true) {
              const result = await stub.acquirePublicationLockWithItemFor(await aclPrincipal(),b.path,owner,ttl);
              if (!result.granted && result.reason === "forbidden") return json({error:"forbidden"},403);
              if (!result.granted && result.reason === "not-found") return json({error:"no such item"},404);
              return json(result);
            }
            return json(await stub.acquireLock(b.path, owner, ttl, b.mode ?? "exclusive", b.purpose ?? "advisory"));
          }
          if (req.method === "GET" && path) {
            requireScope(principal, "fs:read");
            // Audit B5 (medium): apply the same per-folder read ACL as getItemFor —
            // a principal with no `read` grant on the inode must not be able to probe
            // who is editing what (the same INVISIBLE treatment stat/blocks GET use).
            // The lock key IS the inode id for namespace items; non-inode lock keys
            // (admin-only) fall through to the in-DO admin short-circuit.
            const lockDecision = await stub.checkOpenAccess(await aclPrincipal(), path, "read", lockOwner);
            if (!lockDecision.allow) return json({ error: "no such item" }, 404);
            // The holder gets the fence; everyone else gets the badge fields only.
            return json(await stub.lockStatus(path, lockOwner));
          }
          if (req.method === "DELETE" && path) {
            requireScope(principal, "fs:lock");
            // F6: release as the authenticated principal — never a ?owner= param.
            const rawFence = q.get("fence");
            const fence = rawFence === null ? undefined : Number(rawFence);
            if (fence !== undefined && (!Number.isSafeInteger(fence) || fence < 1)) return json({ error: "invalid_fence" }, 400);
            return json(await stub.releaseLock(path, lockOwner, fence));
          }
          break;
        }

        // ---- multipart / resumable uploads --------------------------------
        case "uploads": {
          const uploadId = p[4] ? decodeURIComponent(p[4]) : null;
          if (!uploadId && req.method === "POST") {
            const b = (await req.json()) as { uploadId: string; itemId: string; key: string; totalSize: number; partSize: number };
            if (!b || typeof b !== "object" || typeof b.uploadId !== "string" || typeof b.itemId !== "string" || typeof b.key !== "string") return json({ error: "invalid_upload" }, 400);
            const denied = await gateMutation("fs:write", b.itemId, "write", "upload.begin");
            if (denied) return denied;
            const session = await stub.beginUpload(b.uploadId, b.itemId, b.key, b.totalSize, b.partSize);
            // Track the in-flight upload in DO hot state so it surfaces on the
            // live-activity feed (WS3 §5.3). Best-effort; never blocks the upload.
            await stub.transferBegin({ id: b.uploadId, path: b.itemId, direction: "upload", bytesTotal: b.totalSize });
            return json(session, 201);
          }
          // An upload ID is not an access credential. Check its current inode ACL
          // on every resume/status/part/abort/complete request, including revokes.
          if (uploadId) {
            requireScope(principal, req.method === "GET" ? "fs:read" : "fs:write");
            const { session } = await stub.uploadStatus(uploadId);
            if (!session || !await stub.getItemFor(await aclPrincipal(), session.itemId)) return json({ error: "not found" }, 404);
            if (req.method !== "GET") {
              const denied = await gateMutation("fs:write", session.itemId, "write", "upload.update");
              if (denied) return denied;
            }
          }
          if (uploadId && req.method === "GET") {
            requireScope(principal, "fs:read");
            return json(await stub.uploadStatus(uploadId));
          }
          if (uploadId && req.method === "DELETE") {
            requireScope(principal, "fs:write");
            await stub.abortUpload(uploadId);
            // Drop the in-flight transfer from the live feed on abort (WS3 §5.3).
            await stub.transferAbort(uploadId);
            return json({ aborted: true });
          }
          if (uploadId && p[5] === "parts" && req.method === "PUT") {
            requireScope(principal, "fs:write");
            const b = (await req.json()) as { partNumber: number; etag: string; size: number; checksum?: string };
            await stub.recordUploadPart(uploadId, b.partNumber, b.etag, b.size, b.checksum);
            return json({ recorded: true });
          }
          if (uploadId && p[5] === "complete" && req.method === "POST") {
            requireScope(principal, "fs:write");
            // This legacy route tracks reported parts; it never completes an S3
            // multipart upload or verifies its bytes. Do not label it durable.
            if (env.STORAGE_VERIFY_UPLOADS !== "0") return json({
              error: "legacy_multipart_unverified",
              reason: "Publish this file through verified block uploads.",
            }, 409);
            const b = (await req.json()) as { etag: string };
            const res = await stub.completeUpload(uploadId, b.etag);
            // Clear the in-flight transfer from hot state on a successful commit
            // (drops a `single` activity event onto the live feed). WS3 §5.3.
            if (res.completed) await stub.transferCommit(uploadId, { actor: principal.sub, type: "modify" });
            return json(res, res.completed ? 200 : 409);
          }
          break;
        }

        // ---- snapshots -----------------------------------------------------
        case "snapshots": {
          if (!p[4]) {
            if (req.method === "GET") {
              requireScope(principal, "snapshot:read");
              return json(await stub.listSnapshotsFor(await aclPrincipal()));
            }
            if (req.method === "POST") {
              requireScope(principal, "snapshot:write");
              // `id` is OPTIONAL now (WS4): omit it for a real manual snapshot and
              // the DO mints a server-side id. An explicit id is still honored.
              const b = (await req.json()) as { id?: string; label?: string; scope?: string; tier?: string; immutableUntil?: number | null };
              const authority = await toAuthedContext(env, principal);
              const org = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
              const actor: AclPrincipal = { type: principal.type === "service" ? "service_account" : "user",
                id: principal.sub, orgRole: authority.orgRole, groupIds: await org.groupsForUser(principal.sub) };
              const result = await stub.createSnapshotFor(actor, b);
              if (result.error) return json({ error: result.error }, result.error === "snapshot_exists" ? 409 : result.error === "forbidden" ? 403 : 404);
              return json(result.snapshot, 201);
            }
          } else {
            const snapId = decodeURIComponent(p[4]);
            if (p[5] === "dir" && req.method === "GET") {
              requireScope(principal, "snapshot:read");
              // N-NOTE: apply the SAME per-folder read ACL as live browse — a snapshot is metadata,
              // so a principal must not see VIA A SNAPSHOT what they can't see live (CHANGE D's
              // invisible model). Frozen children the principal can't read are excluded; full-access
              // principals short-circuit. LIVE grants ("can you see it now"), consistent with browse.
              return json(await stub.listSnapshotDirFor(await aclPrincipal(), snapId, q.get("parent") ?? "root"));
            }
            if (p[5] === "mount-roots" && req.method === "GET") {
              requireScope(principal, "snapshot:read");
              const result = await stub.snapshotMountRootsFor(await aclPrincipal(), snapId);
              if (!result) return json({ error: "snapshot_not_found" }, 404);
              if (!result.roots.length) return json({ error: "forbidden" }, 403);
              return json(result);
            }
            if (p[5] === "items" && p[6] && p[7] === "streams") {
              requireScope(principal, "snapshot:read");
              if (req.method !== "GET") return json({ error: "snapshot_read_only" }, 403);
              const itemId = decodeURIComponent(p[6]);
              if (!p[8]) {
                const result = await stub.snapshotStreamsFor(await aclPrincipal(), snapId, itemId);
                if (!result) return json({ error: "snapshot_item_unavailable" }, 404);
                if (!result.captured) return json({ error: "snapshot_predates_mac_metadata" }, 409);
                return json(result);
              }
              if (p[9] === 'manifest' && p[10] === undefined) {
                const offset=Number(q.get('offset') ?? 0),length=Number(q.get('length') ?? 16*1024*1024);
                try { validateStreamRange(offset,length); } catch { return json({error:'invalid_range'},400); }
                const result=await stub.snapshotStreamManifestFor(await aclPrincipal(),snapId,itemId,decodeURIComponent(p[8]),offset,length);
                return result ? json(result,200,{'cache-control':'no-store'}) : json({error:'snapshot_stream_unavailable'},404);
              }
              if (p[9] !== undefined) return json({error:'not found'},404);
              const streamHeader=await stub.snapshotStreamManifestFor(await aclPrincipal(),snapId,itemId,decodeURIComponent(p[8]),0,0);
              if (streamHeader?.exists && !streamHeader.legacy) return json({error:'stream_uses_manifest'},409);
              const bytes = await stub.snapshotStreamFor(await aclPrincipal(), snapId, itemId, decodeURIComponent(p[8]));
              return bytes ? new Response(bytes, { headers: { "content-type": "application/octet-stream", "cache-control": "no-store" } })
                : json({ error: "snapshot_stream_unavailable" }, 404);
            }
            if (p[5] === "items" && p[6] && req.method === "GET") {
              requireScope(principal, "snapshot:read");
              const item = await stub.snapshotItemFor(await aclPrincipal(), snapId, decodeURIComponent(p[6]));
              return item ? json(item) : json({ error: "snapshot_item_unavailable" }, 404);
            }
            if (p[5] === "page" && req.method === "GET") {
              requireScope(principal, "snapshot:read");
              const result = await stub.listSnapshotPageFor(await aclPrincipal(), snapId, q.get("parent") ?? "root", q.get("cursor") ?? undefined);
              return result ? json(result) : json({ error: "snapshot_folder_unavailable" }, 404);
            }
            if (p[5] === "blocks" && p[6] && req.method === "GET") {
              requireScope(principal, "snapshot:read");
              const cursor = q.has("cursor") ? Number(q.get("cursor")) : -1;
              if (!Number.isSafeInteger(cursor) || cursor < -1) return json({ error: "invalid_cursor" }, 400);
              const result = await stub.snapshotBlockMapFor(await aclPrincipal(), snapId, decodeURIComponent(p[6]), cursor);
              return result ? json(result) : json({ error: "snapshot_item_unavailable" }, 404);
            }
            if (p[5] === "presign" && p[6] === "batch" && req.method === "POST") {
              requireScope(principal, "snapshot:read");
              requireScope(principal, "fs:read");
              const b = await req.json() as { itemId?: string; keys?: { key: string; method?: string }[]; expiresIn?: number };
              if (typeof b.itemId !== "string" || !Array.isArray(b.keys) || b.keys.length < 1 || b.keys.length > 256
                  || (b.expiresIn !== undefined && (!Number.isFinite(b.expiresIn) || typeof b.expiresIn !== "number"))
                  || b.keys.some(k => !k || typeof k.key !== "string" || (k.method !== undefined && k.method !== "GET"))) {
                return json({ error: "snapshot_get_keys_required" }, 400);
              }
              const rate = await stub.rateLimit("presign", principalKey(principal.sub), b.keys.length);
              if (!rate.allowed) return tooManyRequests(rate);
              const prefix = `blocks/${doName}/`;
              const allowed = await stub.checkSnapshotObjectReadsFor(await aclPrincipal(), snapId, b.itemId, b.keys.map(k => k.key));
              const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
              const spaceReg = await orgStub.getSpace(spaceId);
              const descriptor: SpaceStorageDescriptor | null = spaceReg
                ? { provider: spaceReg.bucketProvider, endpoint: spaceReg.storageEndpoint, region: spaceReg.storageRegion, bucket: spaceReg.storageBucket, forcePathStyle: spaceReg.storageForcePathStyle, credentialRef: spaceReg.storageCredentialRef }
                : null;
              const managed = managedCredentialResolver(env, orgStub);
              const expiresIn = Math.min(Math.max(b.expiresIn ?? 300, 60), 900);
              const errors = b.keys.map((entry,index) => entry.key.includes("..") || !entry.key.startsWith(prefix) ? "key_prefix_violation" : allowed[index]);
              const minted = await presignBatchForSpace(env,descriptor,b.keys.flatMap((entry,index) => errors[index] ? [] : [{key:entry.key,method:"GET"}]),expiresIn,managed);
              let position = 0;
              const results = b.keys.map((entry,index) => errors[index] ? {key:entry.key,error:errors[index]!} : minted[position++]);
              return json({ results, expiresIn });
            }
            // POST .../snapshots/:snapId/restore  { path, recursive?, mode? }
            // Server-side restore (SPEC §4.7). Requires snapshot:read (to read the
            // frozen point-in-time) + EDIT on the TARGET path (canAccess), since it
            // mutates the live namespace. Non-destructive; locked targets surface
            // as conflicts. NOTE: only the /v1/filespaces/:fs form is routed — there
            // is no /v1/orgs/:org/spaces/... snapshot alias (handleOrgRequest has no
            // snapshot sub-routing); do not document one until it is wired.
            if (p[5] === "restore" && req.method === "POST") {
              requireScope(principal, "snapshot:read");
              const b = (await req.json()) as { path?: string; recursive?: boolean; mode?: string };
              const path = b.path ?? "root";
              // EDIT on the restore target (also rate-limits + audits via gateMutation).
              const denied = await gateMutation("fs:write", path, "write", "snapshot.restore",
                acl => stub.checkSnapshotRestoreAccess(acl,path));
              if (denied) return denied;
              const result = await stub.restoreSnapshot(snapId, path, {
                recursive: !!b.recursive,
                requesterOwner: lockOwner,
                principal: await aclPrincipal(),
              });
              // unknown snapshot / path-not-in-snapshot → 404 (typed, not thrown).
              if (result.notFound) return json({ error: "not found", reason: result.notFound }, 404);
              // 409 if every targeted item was blocked by a lock conflict and
              // nothing was restored; otherwise 200 with the breakdown.
              const nothingDone = result.restored.length === 0 && result.recreated.length === 0;
              const status = nothingDone && (result.skippedPermissions ?? result.forbidden?.length ?? 0) > 0 ? 403 : nothingDone && result.conflicts.length > 0 ? 409 : 200;
              return json(result, status);
            }
          }
          break;
        }

        // ---- snapshot schedules (GFS retention) ---------------------------
        case "schedules": {
          requireScope(principal, "fs:admin");
          const org = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
          const actor = await org.getUser(principal.sub);
          if (!actor || actor.status !== "active" || (actor.role !== "owner" && actor.role !== "admin")) return json({ error: "workspace_admin_required" }, 403);
          if (req.method === "POST") {
            const b = (await req.json()) as { id: string; scope?: string; tier: string; intervalMs: number; retain: number };
            if (!isValidScheduleSpec(b)) return json({ error: "invalid_schedule" }, 400);
            const target = await stub.getItemFor(await aclPrincipal(), b.scope ?? "root");
            if (!target || !target.isDir) return json({ error: "invalid_schedule_scope" }, 400);
            await stub.setSnapshotSchedule(b);
            return json({ ok: true }, 201);
          }
          if (req.method === "GET" && !p[4]) return json({ schedules: await stub.listSnapshotSchedules() });
          if (req.method === "PATCH" && p[4]) {
            const b = (await req.json()) as { enabled?: unknown; retain?: unknown };
            const hasEnabled = b && b.enabled !== undefined;
            const hasRetain = b && b.retain !== undefined;
            if (!b || (!hasEnabled && !hasRetain)
                || (hasEnabled && typeof b.enabled !== "boolean")
                || (hasRetain && !(typeof b.retain === "number" && Number.isSafeInteger(b.retain) && b.retain >= 0 && b.retain <= 10_000))) {
              return json({ error: "invalid_schedule" }, 400);
            }
            const sid = decodeURIComponent(p[4]);
            if (hasRetain && !(await stub.setSnapshotScheduleRetain(sid, b.retain as number))) return json({ error: "no such schedule" }, 404);
            if (hasEnabled) await stub.setSnapshotScheduleEnabled(sid, b.enabled as boolean);
            return json({ ok: true });
          }
          break;
        }

        // ---- presigned URL minting (THE enforcement gate, SPEC §4.4) -------
        case "presign": {
          // Audit B23 — BATCH presign: mint many keys in ONE request (a 1,000-file Finder copy or a
          // scrub that touches dozens of blocks shouldn't be 1,000 round-trips at the single-key
          // rate). Shares the per-request gate fan-out + resolves the space's storage descriptor
          // ONCE (also closes the B22 "re-reads the registry per mint" finding). Each key still
          // pays one rate-limit token and runs the per-folder ACL.
          if (p[4] === "batch" && req.method === "POST") {
            const bb = (await req.json()) as { keys: { key: string; method?: string; itemId?: string }[]; expiresIn?: number };
            if (!Array.isArray(bb.keys) || bb.keys.length === 0) return json({ error: "keys required" }, 400);
            if (bb.keys.length > 256) return json({ error: "too many keys (max 256)" }, 400);
            if (bb.keys.some(k => !k || typeof k.key !== "string" || (k.method !== undefined && typeof k.method !== "string") || (k.itemId !== undefined && typeof k.itemId !== "string"))) return json({ error: "invalid_keys" }, 400);
            // Need fs:write if ANY key is a PUT, else fs:read.
            const anyWrite = bb.keys.some((k) => (k.method ?? "GET").toUpperCase() === "PUT");
            requireScope(principal, anyWrite ? "fs:write" : "fs:read");
            if (bb.keys.some(k => ["GET", "HEAD"].includes((k.method ?? "GET").toUpperCase()))) requireScope(principal, "fs:read");
            // One rate-limit consume for the whole batch (cost = #keys).
            const rl = await stub.rateLimit("presign", principalKey(principal.sub), bb.keys.length);
            if (!rl.allowed) {
              defer(audit(stub, principal, spaceId, { action: "presign.mint", decision: "deny", detail: { reason: "rate_limited", batch: bb.keys.length } }));
              return tooManyRequests(rl);
            }
            const ttl = Math.min(Math.max(bb.expiresIn ?? 300, 60), 900);
            const prefix = `blocks/${doName}/`;
            // Resolve the storage descriptor + managed resolver ONCE for the whole batch (B22).
            const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
            const spaceReg = await orgStub.getSpace(spaceId);
            const storageDescriptor: SpaceStorageDescriptor | null = spaceReg
              ? { provider: spaceReg.bucketProvider, endpoint: spaceReg.storageEndpoint, region: spaceReg.storageRegion, bucket: spaceReg.storageBucket, forcePathStyle: spaceReg.storageForcePathStyle, credentialRef: spaceReg.storageCredentialRef }
              : null;
            const managed = managedCredentialResolver(env, orgStub);
            const acl = await aclPrincipal();
            const access = await stub.checkObjectAccessBatch(acl, bb.keys.map(k => ({ key: k.key, method: k.key.includes("..") || !k.key.startsWith(prefix) ? "INVALID" : (k.method ?? "GET").toUpperCase(), itemId: k.itemId })), lockOwner);
            const errors = bb.keys.map((k,index) => !["GET","HEAD","PUT"].includes((k.method??"GET").toUpperCase())
              ? "method_not_allowed" : k.key.includes("..") || !k.key.startsWith(prefix) ? "key_prefix_violation" : access[index]);
            const permitted = bb.keys.flatMap((k,index) => errors[index] ? [] : [{key:k.key,method:(k.method??"GET").toUpperCase()}]);
            const minted = await presignBatchForSpace(env,storageDescriptor,permitted,ttl,managed);
            let position = 0;
            const results = bb.keys.map((k,index) => errors[index] ? {key:k.key,error:errors[index]!} : minted[position++]);
            await audit(stub, principal, spaceId, { action: "presign.mint", decision: "allow", mintedObjectKeys: results.filter((r) => r.url).map((r) => r.key), urlTtlSeconds: ttl, sourceIp, detail: { batch: bb.keys.length } });
            return json({ urls: results, expiresIn: ttl }, 200, rateLimitHeadersOf(rl));
          }
          if (req.method === "POST") {
            // Audit B16: `itemId` lets the client DECLARE which namespace item a not-yet-committed
            // PUT block belongs to, so the per-folder ACL can run even before the block exists in the
            // `blocks` table (a content-addressed key alone can't be mapped to an inode). `contentLength`
            // pins the exact byte count into the presigned PUT signature (the bucket then rejects an
            // upload of any other size — a client can't smuggle an arbitrarily large object).
            const b = (await req.json()) as { key: string; method?: string; expiresIn?: number; itemId?: string; contentLength?: number };
            const verb = (b.method ?? "GET").toUpperCase();

            // 1. scope per verb (F3)
            const needScope: Scope = verb === "GET" || verb === "HEAD" ? "fs:read" : "fs:write";
            requireScope(principal, needScope);

            // 2. method allow-list (F3/F8)
            if (!["GET", "HEAD", "PUT"].includes(verb)) {
              defer(audit(stub, principal, spaceId, { action: "presign.mint", decision: "deny", detail: { reason: "method_not_allowed", verb } }));
              return json({ error: "method not allowed" }, 405);
            }

            // 3. rate limit (F5) — bucket-scrape defense (global per-space DO counter)
            const rl = await stub.rateLimit("presign", principalKey(principal.sub));
            if (!rl.allowed) {
              defer(audit(stub, principal, spaceId, { action: "presign.mint", decision: "deny", detail: { reason: "rate_limited" } }));
              return tooManyRequests(rl);
            }

            // 4. key-prefix confinement (F8): the key must live under this space's
            //    prefix and must not escape via path traversal. Space prefix is
            //    blocks/<org>::<space>/... — confine the mint to it.
            const prefix = `blocks/${doName}/`;
            if (b.key.includes("..") || !b.key.startsWith(prefix)) {
              defer(audit(stub, principal, spaceId, { action: "presign.mint", decision: "deny", mintedObjectKeys: [b.key], verb: verb as "GET" | "PUT", detail: { reason: "key_prefix_violation", prefix } }));
              return json({ error: "forbidden", reason: "key not under this space's prefix" }, 403);
            }

            // 5. per-folder ACL (F3): resolve key→inode→effective ACL. read for
            //    GET/HEAD, edit for PUT. Unknown keys (no owning inode yet) are
            //    allowed for PUT under the confined prefix (first upload of a new
            //    object) but denied for GET (can't read what doesn't exist).
            // Resolve the owning inode from the object key (committed blocks) OR, for a not-yet-
            // committed PUT, from the client-declared `itemId` (Audit B16). Either way the ACL runs
            // against the resolved inode — a PUT to a key the principal can't write is denied at mint.
            let inodeId: string | null;
            if (verb === "GET" || verb === "HEAD") {
              const access = await stub.checkObjectReadAccess(await aclPrincipal(), b.key, lockOwner);
              inodeId = access.inodeId;
              if (!access.decision.allow) {
                defer(audit(stub, principal, spaceId, { action: "presign.mint", decision: "deny", mintedObjectKeys: [b.key], detail: { reason: access.decision.reason } }));
                return json({ error: "forbidden", reason: access.decision.reason }, 403);
              }
            } else {
              const upload = await stub.prepareObjectUpload(await aclPrincipal(), b.key, b.itemId, lockOwner);
              inodeId = upload.inodeId;
              if (upload.error) return json({ error: upload.error }, 403);
            }
            // Legacy administrators may upload unowned blocks. Folder-scoped users
            // must declare a writable inode even before its first manifest commit.
            const unownedPut = !inodeId && verb === "PUT";

            // 6. server-side TTL clamp (F3/F8): ignore an over-long client TTL.
            const ttl = Math.min(Math.max(b.expiresIn ?? 300, 60), 900);
            // Audit B16: validate the optional pinned content length (a positive, sane byte count).
            // We don't INVENT a length (a missing one leaves the PUT unpinned, preserving back-compat
            // for clients that haven't adopted the field yet), but we reject an absurd/negative value.
            let pinContentLength: number | undefined;
            if (verb === "PUT" && b.contentLength !== undefined) {
              if (!Number.isInteger(b.contentLength) || b.contentLength < 0 || b.contentLength > MAX_PRESIGN_PUT_BYTES) {
                return json({ error: "invalid_content_length", reason: `contentLength must be an integer in [0, ${MAX_PRESIGN_PUT_BYTES}]` }, 400);
              }
              pinContentLength = b.contentLength;
            }

            // 7. mint, then audit the allow (F4). Resolve THIS space's storage backend from
            //    the org's filespace registry so a bring-your-own S3-compatible backend
            //    (R2/AWS S3/Backblaze B2/MinIO/Wasabi/Ceph) is used; a space with no override
            //    inherits the deployment-default backend (the `S3_*` env). Secret-free row;
            //    access keys are resolved from env at sign time (storage.ts).
            const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
            const spaceReg = await orgStub.getSpace(spaceId);
            const storageDescriptor: SpaceStorageDescriptor | null = spaceReg
              ? {
                  provider: spaceReg.bucketProvider,
                  endpoint: spaceReg.storageEndpoint,
                  region: spaceReg.storageRegion,
                  bucket: spaceReg.storageBucket,
                  forcePathStyle: spaceReg.storageForcePathStyle,
                  credentialRef: spaceReg.storageCredentialRef,
                }
              : null;
            // Resolve a managed `storageCredentialRef` (decrypt) FIRST, then env fallback; an
            // unresolvable ref fails closed inside presignForSpace. Audit B16: when a content length
            // is declared on a PUT, pin it into the signature so the bucket enforces the exact size.
            const managed = managedCredentialResolver(env, orgStub);
            const minted = await presignBatchForSpace(env, storageDescriptor,
              [{key:b.key,method:verb,contentLength:pinContentLength}], ttl, managed);
            if (!minted[0].url || (verb === "PUT" && !minted[0].verificationUrl)) return json({error:"storage_signing_failed"},503);
            const signed = minted[0].url;
            const uploadContract = verb === "PUT" ? {headers:requiredUploadHeaders(b.key),verificationUrl:minted[0].verificationUrl} : {};
            // SUCCESS-path mint audit stays INLINE + durable (the "we minted this URL" record must be
            // committed before the URL is handed out — it's the only server-side trace of the grant).
            const mintDetail: Record<string, unknown> = {};
            if (pinContentLength !== undefined) mintDetail.contentLength = pinContentLength;
            if (unownedPut) mintDetail.unownedPut = true;
            await audit(stub, principal, spaceId, { action: "presign.mint", decision: "allow", targetInodeId: inodeId ?? undefined, levelChecked: verb === "PUT" ? "edit" : "read", mintedObjectKeys: [b.key], verb: verb as "GET" | "PUT", urlTtlSeconds: ttl, sourceIp, detail: Object.keys(mintDetail).length ? mintDetail : undefined });
            return json({ url: signed, expiresIn: ttl, ...uploadContract, ...(pinContentLength !== undefined ? { contentLength: pinContentLength } : {}) }, 200, rateLimitHeadersOf(rl));
          }
          break;
        }

        // ---- filespace master-key delivery (ONBOARDING.md "Key model", build step 2) --------
        // cloudfsd fetches the per-filespace encryption key over this SAME authenticated channel
        // it already uses for the data plane — including a device-minted daemon token (30-day
        // service token, DEVICE_DAEMON_SCOPE_CEILING carries fs:read). The authority bar is
        // Any effective read grant needs the key, including a subfolder-only collaborator.
        // Presigned object URLs and metadata retain their independent per-inode ACL checks.
        case "mount-roots": {
          if (!p[4] && req.method === "GET") {
            requireScope(principal, "fs:read");
            return json({ roots: await stub.mountRootsFor(await aclPrincipal()) });
          }
          break;
        }
        case "key": {
          if (!p[4] && req.method === "GET") {
            requireScope(principal, "fs:read");
            const decision = await stub.checkFilespaceRead(await aclPrincipal());
            if (!decision.allow) {
              defer(audit(stub, principal, spaceId, { action: "key.fetch", decision: "deny", detail: { reason: decision.reason } }));
              return json({ error: "forbidden", reason: decision.reason }, 403);
            }
            const orgStub = env.ORG_DO.get(env.ORG_DO.idFromName(principal.orgId));
            const row = await orgStub.getFilespaceKey(spaceId);
            if (!row) {
              defer(audit(stub, principal, spaceId, { action: "key.fetch", decision: "deny", detail: { reason: "no_master_key" } }));
              // Not "no membership" — the caller IS authorized, but this space predates the key
              // service and hasn't been migrated yet (see POST …/spaces/:id/key/import).
              return json({ error: "no_master_key", reason: "no server-held key provisioned for this filespace yet" }, 404);
            }
            let envelope;
            try {
              envelope = await openMasterKeyEnvelope(env.STORAGE_ENC_KEY, row);
            } catch (e) {
              // STORAGE_ENC_KEY missing/rotated/tampered row — fail closed, never guess.
              return json({ error: "key_unavailable" }, 500);
            }
            await audit(stub, principal, spaceId, { action: "key.fetch", decision: "allow" });
            // Opaque wrapped-key envelope (never a bare key) — daemons MUST switch on `format`.
            return json(envelope);
          }
          break;
        }
      }
      return json({ error: "not found" }, 404);
    } catch (e: any) {
      if (String(e?.message ?? '').includes('object_retired')) return json({error:'object_retired',conflict:true,reason:'The object was retired after the operator recovery watermark. Keep local recovery data.'},409);
      if (isMetadataCapacityError(e)) return json({error:'metadata_capacity',reason:'Filespace metadata is full. Committed files remain readable; preserve pending local writes and contact the operator.'},507);
      if (e instanceof AuthError) return json({ error: e.code }, e.status);
      if (e?.name === "UploadInvalidError" || String(e?.message ?? "").startsWith("upload_invalid:")) return json({ error: "invalid_upload" }, 400);
      if (e?.name === "UploadConflictError" || String(e?.message ?? "").startsWith("upload_conflict:")) return json({ error: "upload_conflict" }, 409);
      // Audit B5: a mutation blocked by a live lease (or a stale fence) → 409 with a
      // typed `{ locked, heldBy, reason }` shape so the client can render "locked by
      // Bob" / re-acquire rather than treating it as a generic conflict.
      if (e?.name === "LockedError") {
        return json({ error: String(e.message), locked: true, conflict: true, heldBy: e.heldBy, reason: e.reason }, 409);
      }
      if (e?.name === "ConflictError") {
        return json({ error: String(e.message), conflict: true, expected: e.expected, actual: e.actual }, 409);
      }
      throw e;
    }
}

// small inline helper to surface rate-limit headers on a 200 mint response
function rateLimitHeadersOf(r: { limit: number; remaining: number }): Record<string, string> {
  return { "X-RateLimit-Limit": String(r.limit), "X-RateLimit-Remaining": String(Math.max(0, r.remaining)) };
}
