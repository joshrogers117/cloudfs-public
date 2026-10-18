// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * HttpGatewayClient — the REAL wire implementation of the GatewayClient seam.
 *
 * Codes EXACTLY against backend/API.md (the canonical contract):
 *   - `Authorization: Bearer <token>` (service-account / session JWS, HS256);
 *   - routes under `/v1/filespaces/:fs/*` and `/v1/orgs/:org/*`;
 *   - cursor pagination: `items` uses an opaque base64 `cursor`, `changes` uses a
 *     numeric `since`/`cursor` (updatedSeq) — both drained transparently here;
 *   - the standard error envelope `{ error, reason? }` mapped to stable exit codes.
 *
 * Bytes never transit the gateway (API.md §preamble) — the CLI only touches
 * metadata/control routes, so this client issues no media GET/PUTs.
 *
 * Engine-only operations (cache/pin/mount/flush/syncState) are NOT gateway
 * routes (they ride the local engine control socket per SPEC §3.8). Until that
 * socket client exists, those methods throw ENGINE_UNAVAILABLE so the failure is
 * explicit and correctly coded rather than silently wrong.
 */
import { CliError, ExitCode } from "../exit-codes.js";
import type { CacheInfo, GatewayClient, GatewayHealth } from "./client.js";
import { mapGatewayError, type GatewayErrorBody } from "./http-errors.js";
import type {
  AuthStatus,
  ChangeEvent,
  Filespace,
  Grant,
  Group,
  Invite,
  Item,
  PinnedItem,
  RestoreResult,
  ShareLink,
  Snapshot,
  SyncState,
  User,
} from "./types.js";

/** Minimal fetch surface so a mocked fetch can be injected in tests. */
export type FetchLike = (input: string, init?: {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}) => Promise<{
  ok: boolean;
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
  json(): Promise<unknown>;
}>;

export interface HttpGatewayOptions {
  baseUrl: string;
  token: string;
  /** Injected for tests; defaults to global fetch. */
  fetch?: FetchLike;
  /** Per-request timeout in ms (0 disables). Defaults to CLOUDFS_REQUEST_TIMEOUT_MS or 30s. */
  requestTimeoutMs?: number;
  /** Max RETRY attempts for transient failures on idempotent requests (0 disables). Default 3. */
  maxRetries?: number;
  /** Injected sleeper (tests); defaults to a real timer. */
  sleep?: (ms: number) => Promise<void>;
}

// ---- API.md §4 wire shapes (subset the CLI consumes) ----
interface WireItem {
  id: string;
  parent: string | null;
  name: string;
  isDir: boolean;
  size: number;
  contentVersion?: string;
  etag?: string | null;
  version?: number;
  updatedSeq?: number;
  deleted?: boolean;
}
interface WireSnapshot {
  id: string;
  label?: string | null;
  scope?: string;
  seqAnchor?: number;
  tier?: string;
  createdAt?: string;
  immutableUntil?: string | null;
  scheduleId?: string | null;
}

const ENGINE_ONLY = "this operation rides the local engine control socket (SPEC §3.8), not the gateway; engine client not yet wired";

/// Version handshake: the wire-contract version THIS CLI targets. Must equal the
/// backend's API_VERSION (index.ts). v2 = opaque inode ids (B17): paths are resolved by
/// walking the namespace, never by constructing `parent/name` ids. A gateway advertising
/// a different MAJOR version means the wire contract diverged and the CLI may misbehave.
export const EXPECTED_API_VERSION = 3;

/** Default per-request timeout (ms); env-overridable like the engine's requestTimeoutMs. */
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

function resolveRequestTimeoutMs(override?: number): number {
  if (override !== undefined) return override;
  const env = process.env.CLOUDFS_REQUEST_TIMEOUT_MS;
  if (env) {
    const n = Number(env);
    if (Number.isFinite(n) && n >= 0) return n; // 0 disables the timeout
  }
  return DEFAULT_REQUEST_TIMEOUT_MS;
}

/** Default RETRY attempts for transient failures (CLOUDFS_MAX_RETRIES-overridable). */
const DEFAULT_MAX_RETRIES = 3;
/** Base backoff (ms) for the exponential schedule when there's no Retry-After. */
const RETRY_BASE_DELAY_MS = 250;
/** Ceiling on any single backoff wait (ms) — caps a hostile Retry-After too. */
const RETRY_MAX_DELAY_MS = 10_000;
/** Transient HTTP statuses worth retrying on an IDEMPOTENT request. */
const RETRYABLE_STATUSES = new Set([429, 502, 503, 504]);
/** Idempotent methods we may safely retry (a retried POST/PUT/PATCH could double-apply). */
const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "DELETE", "OPTIONS"]);

function resolveMaxRetries(override?: number): number {
  if (override !== undefined) return Math.max(0, Math.floor(override));
  const env = process.env.CLOUDFS_MAX_RETRIES;
  if (env) {
    const n = Number(env);
    if (Number.isFinite(n) && n >= 0) return Math.floor(n);
  }
  return DEFAULT_MAX_RETRIES;
}

/** Parse a `Retry-After` header (delta-seconds or an HTTP-date) into ms, or null. */
export function parseRetryAfterMs(value: string | null, now: number = Date.now()): number | null {
  if (!value) return null;
  const secs = Number(value);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const date = Date.parse(value);
  if (!Number.isNaN(date)) return Math.max(0, date - now);
  return null;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export class HttpGatewayClient implements GatewayClient {
  private readonly base: string;
  private readonly token: string;
  private readonly fetch: FetchLike;
  /** Per-request timeout in ms (0 = disabled). FINDING 8. */
  private readonly requestTimeoutMs: number;
  /** Max retry attempts for transient failures on idempotent requests (0 = disabled). */
  private readonly maxRetries: number;
  /** Sleeper (injectable for tests). */
  private readonly sleep: (ms: number) => Promise<void>;
  /** Decoded token claims (best-effort; client-side, unverified). */
  private readonly claims: TokenClaims;

  constructor(opts: HttpGatewayOptions) {
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token;
    this.fetch = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
    this.requestTimeoutMs = resolveRequestTimeoutMs(opts.requestTimeoutMs);
    this.maxRetries = resolveMaxRetries(opts.maxRetries);
    this.sleep = opts.sleep ?? defaultSleep;
    this.claims = decodeJwtClaims(opts.token);
  }

  private get org(): string {
    if (!this.claims.org) {
      throw new CliError("token has no `org` claim; cannot address org-scoped routes", ExitCode.AUTH_FAILED);
    }
    return this.claims.org;
  }

  // --- core request helper: builds URL, sets auth, maps errors, retries transient faults ---
  // B27: a transient 429/502/503/504 or a network blip on an IDEMPOTENT request (GET/HEAD/
  // DELETE/OPTIONS) is retried up to `maxRetries` times with backoff. A `Retry-After` header
  // (delta-seconds or HTTP-date) is honored when present; otherwise an exponential schedule
  // (250ms, 500ms, 1s, …) capped at 10s is used. A retried request never DOUBLE-applies a
  // mutation because non-idempotent methods (POST/PUT/PATCH) are never retried.
  private async req<T>(
    method: string,
    path: string,
    opts: { query?: Record<string, string | number | undefined>; body?: unknown; signal?: AbortSignal } = {},
  ): Promise<T> {
    const url = this.url(path, opts.query);
    const canRetry = this.maxRetries > 0 && IDEMPOTENT_METHODS.has(method.toUpperCase());
    let attempt = 0;
    for (;;) {
      const result = await this.attempt<T>(method, url, opts);
      if (result.ok) return result.value;
      // Decide whether to retry: only transient signals, only idempotent methods, only
      // while attempts remain, and never once the caller's signal has aborted.
      const retryable = canRetry && result.retryable && attempt < this.maxRetries && !opts.signal?.aborted;
      if (!retryable) throw result.error;
      attempt++;
      const backoff = Math.min(RETRY_MAX_DELAY_MS, RETRY_BASE_DELAY_MS * 2 ** (attempt - 1));
      const waitMs = result.retryAfterMs ?? backoff;
      await this.sleep(Math.min(RETRY_MAX_DELAY_MS, waitMs));
    }
  }

  /**
   * A SINGLE request attempt. Returns a discriminated result so the retry loop can decide
   * without exceptions on the happy/transient path: `{ok,value}` on success, else
   * `{ok:false, retryable, retryAfterMs?, error}` carrying the mapped CliError to throw if
   * we give up.
   */
  private async attempt<T>(
    method: string,
    url: string,
    opts: { body?: unknown; signal?: AbortSignal },
  ): Promise<
    | { ok: true; value: T }
    | { ok: false; retryable: boolean; retryAfterMs?: number | null; error: CliError }
  > {
    // FINDING 8: bound every request with a timeout so a hung gateway can't hang the
    // CLI forever. We drive an AbortController from BOTH the (optional) caller signal
    // and a timer; whichever fires aborts the fetch. A timeout maps to NETWORK_ERROR.
    const controller = new AbortController();
    let timedOut = false;
    const onCallerAbort = () => controller.abort();
    if (opts.signal) {
      if (opts.signal.aborted) controller.abort();
      else opts.signal.addEventListener("abort", onCallerAbort, { once: true });
    }
    const timer =
      this.requestTimeoutMs > 0
        ? setTimeout(() => {
            timedOut = true;
            controller.abort();
          }, this.requestTimeoutMs)
        : undefined;

    let res: Awaited<ReturnType<FetchLike>>;
    try {
      res = await this.fetch(url, {
        method,
        headers: {
          authorization: `Bearer ${this.token}`,
          ...(opts.body !== undefined ? { "content-type": "application/json" } : {}),
        },
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
        signal: controller.signal,
      });
    } catch (e) {
      // DNS/TCP/TLS/abort — never reached the gateway. A timeout-driven abort gets a
      // clear timeout message; both still map to NETWORK_ERROR. A network blip is
      // retryable (the request never reached the gateway) UNLESS it was the caller
      // aborting, which is not a transient fault.
      const aborted = !!opts.signal?.aborted;
      const error = timedOut
        ? new CliError(`network error reaching gateway: request timed out after ${this.requestTimeoutMs}ms`, ExitCode.NETWORK_ERROR, { url, timeoutMs: this.requestTimeoutMs })
        : new CliError(`network error reaching gateway: ${e instanceof Error ? e.message : String(e)}`, ExitCode.NETWORK_ERROR, { url });
      return { ok: false, retryable: !aborted, error };
    } finally {
      if (timer) clearTimeout(timer);
      if (opts.signal) opts.signal.removeEventListener("abort", onCallerAbort);
    }

    if (!res.ok) {
      let body: GatewayErrorBody | undefined;
      try {
        body = (await res.json()) as GatewayErrorBody;
      } catch {
        body = undefined;
      }
      const retryAfterHeader = res.headers.get("retry-after");
      if (retryAfterHeader && body) body.retryAfter = retryAfterHeader;
      return {
        ok: false,
        retryable: RETRYABLE_STATUSES.has(res.status),
        retryAfterMs: parseRetryAfterMs(retryAfterHeader),
        error: mapGatewayError(res.status, body, url),
      };
    }

    if (res.status === 204) return { ok: true, value: undefined as T };
    const text = await res.text();
    if (!text) return { ok: true, value: undefined as T };
    return { ok: true, value: JSON.parse(text) as T };
  }

  private url(path: string, query?: Record<string, string | number | undefined>): string {
    const u = new URL(this.base + path);
    if (query) {
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined && v !== "") u.searchParams.set(k, String(v));
      }
    }
    return u.toString();
  }

  // ============ auth ============
  // The gateway only *verifies* tokens (API.md §1) — there is no login route.
  // `login` validates a token by calling an AUTHENTICATED route the token can read
  // (the org user directory). `/v1/health` is public, so probing it would prove only
  // reachability, never that the token is valid (FINDING 1).
  async login(opts: { token?: string; sso?: boolean }): Promise<AuthStatus> {
    if (opts.sso) {
      throw new CliError("interactive SSO login is not yet wired for the HTTP gateway; use --token / CLOUDFS_TOKEN", ExitCode.AUTH_FAILED);
    }
    if (!this.token) throw new CliError("authentication failed: no token provided", ExitCode.AUTH_FAILED);
    // FINDING 1: actually VALIDATE the token. `/v1/health` is PUBLIC (API.md §5), so
    // probing it proved only reachability — a bad/expired token still "succeeded".
    // Probe an AUTHENTICATED route the token is allowed to read (the org user
    // directory: GET /v1/orgs/:org/users — readable by any member, API.md §5) so a
    // bad token fails the auth gate (401/403 → AUTH_FAILED/PERMISSION_DENIED) and we
    // never report a false success or save an unverified token.
    await this.req<unknown>("GET", `/v1/orgs/${enc(this.org)}/users`);
    return this.authStatus();
  }

  async logout(): Promise<void> {
    // Stateless bearer auth: logout is local (drop the token). Nothing to call.
  }

  async authStatus(): Promise<AuthStatus> {
    const c = this.claims;
    const authenticated = !!this.token && (c.exp === undefined || c.exp * 1000 > Date.now());
    return {
      authenticated,
      principal: c.sub,
      kind: c.typ === "service" ? "service-account" : "user",
      org: c.org,
      scopes: c.scp,
      expiresAt: c.exp ? new Date(c.exp * 1000).toISOString() : null,
      gateway: this.base,
    };
  }

  // ============ version handshake (public /v1/health) ============
  /// GET /v1/health (PUBLIC, no auth) and compare wire versions. The backend advertises
  /// `apiVersion` in the body AND an `X-CloudFS-API-Version` header; we read the body and
  /// fall back to the header. A gateway with no version field is treated as a pre-handshake
  /// (v1) backend. `compatible` is false on a major-version mismatch.
  async health(): Promise<GatewayHealth> {
    let apiVersion: number | null = null;
    let ok = false;
    try {
      const body = await this.req<{ ok?: boolean; apiVersion?: number }>("GET", "/v1/health");
      ok = body?.ok !== false;
      if (typeof body?.apiVersion === "number") apiVersion = body.apiVersion;
    } catch (e) {
      // A health probe failure is a connectivity/usage issue, not a crash — surface it.
      if (e instanceof CliError) throw e;
      throw new CliError(`gateway health check failed: ${e instanceof Error ? e.message : String(e)}`, ExitCode.NETWORK_ERROR);
    }
    return {
      ok,
      apiVersion,
      expectedApiVersion: EXPECTED_API_VERSION,
      // A pre-handshake backend (no apiVersion) is assumed compatible (best-effort);
      // an explicit version must match the major we target.
      compatible: apiVersion === null ? true : apiVersion === EXPECTED_API_VERSION,
    };
  }

  // ============ filespaces (org space registry: /v1/orgs/:org/spaces) ============
  async listFilespaces(): Promise<Filespace[]> {
    const raw = await this.req<unknown>("GET", `/v1/orgs/${enc(this.org)}/spaces`);
    const list = asArray(raw, "spaces");
    return list.map(toFilespace);
  }
  async getFilespace(id: string): Promise<Filespace> {
    const list = await this.listFilespaces();
    const f = list.find((x) => x.id === id);
    if (!f) throw new CliError(`no such filespace: ${id}`, ExitCode.NOT_FOUND);
    return f;
  }
  async createFilespace(opts: { name: string; bucket?: string }): Promise<Filespace> {
    // FINDING 2: the backend (org-do.ts registerSpace) reads `bucketProvider`,
    // `bucketName` and `keyPrefix` — NOT a single `bucket`. Sending `{name,bucket}`
    // left those fields undefined and the DO persisted nulls (no validation). Parse
    // the `--bucket` URI (`provider://name[/prefix]`) into the three fields the
    // backend expects, and reject (USAGE) when it can't be parsed rather than
    // silently creating a malformed space.
    const { bucketProvider, bucketName, keyPrefix } = parseBucketUri(opts.bucket);
    const raw = await this.req<unknown>("POST", `/v1/orgs/${enc(this.org)}/spaces`, {
      body: { name: opts.name, bucketProvider, bucketName, keyPrefix },
    });
    return toFilespace(raw);
  }
  // Connect/disconnect are engine + registry concerns; the gateway has no such
  // route, so report the space's registry record (connect) / no-op (disconnect).
  async connectFilespace(id: string): Promise<Filespace> {
    return this.getFilespace(id);
  }
  async disconnectFilespace(id: string): Promise<Filespace> {
    const f = await this.getFilespace(id);
    return { ...f, status: "disconnected", mountPath: null };
  }

  // ============ mount / cache (LOCAL ENGINE — not gateway) ============
  async mount(): Promise<Filespace> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async unmount(): Promise<Filespace> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async cacheInfo(): Promise<CacheInfo> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async cacheSetSize(): Promise<CacheInfo> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async cacheSetLocation(): Promise<CacheInfo> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async pin(): Promise<{ path: string; pinned: boolean }> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async unpin(): Promise<{ path: string; pinned: boolean }> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async pinList(): Promise<PinnedItem[]> {
    // Pins live in cloudfsd, not the gateway — the engine seam owns `pin.list`.
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async prefetch(): Promise<{ path: string; queuedBlocks: number }> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }

  // ============ namespace (items) ============
  /// Audit B17/B28: resolve a CLI path (or an opaque id) to the server-assigned OPAQUE inode id by
  /// walking the namespace from root, matching each segment by NFC-normalized name. `root`/`/` →
  /// "root"; an already-opaque `ino-…` id is returned as-is (so a power user can pass an id directly).
  /// Throws NOT_FOUND (exit 20) when a segment doesn't exist.
  async resolvePathToId(filespace: string, path: string): Promise<string> {
    if (!path || path === "/" || path === "root") return "root";
    if (path.startsWith("ino-")) return path;
    const segments = path.replace(/^\/+/, "").replace(/\/+$/, "").split("/").map((s) => s.normalize("NFC")).filter(Boolean);
    let parent = "root";
    for (const seg of segments) {
      const page = await this.req<{ items: WireItem[]; cursor: string | null }>(
        "GET", `/v1/filespaces/${enc(filespace)}/items`, { query: { parent, limit: 2000 } },
      );
      const match = (page.items ?? []).find((i) => String(i.name).normalize("NFC").toLowerCase() === seg.toLowerCase());
      if (!match) throw new CliError(`no such path: ${path} (missing segment "${seg}")`, ExitCode.NOT_FOUND);
      parent = String(match.id);
    }
    return parent;
  }

  async list(filespace: string, path: string): Promise<Item[]> {
    const parent = await this.resolvePathToId(filespace, path);
    const out: Item[] = [];
    let cursor: string | undefined;
    do {
      const page = await this.req<{ items: WireItem[]; cursor: string | null }>(
        "GET",
        `/v1/filespaces/${enc(filespace)}/items`,
        { query: { parent, limit: 500, cursor } },
      );
      for (const it of page.items ?? []) out.push(toItem(it, path));
      cursor = page.cursor ?? undefined; // opaque base64; treat as black box
    } while (cursor);
    return out;
  }
  async stat(filespace: string, path: string): Promise<Item> {
    const id = await this.resolvePathToId(filespace, path);
    const raw = await this.req<WireItem>("GET", `/v1/filespaces/${enc(filespace)}/items/${enc(id)}`);
    return toItem(raw, parentPath(path));
  }

  // ============ share links (/v1/orgs/:org/shares) ============
  async shareCreate(opts: { filespace: string; path: string; kind: "guest" | "direct"; expiresInDays?: number }): Promise<ShareLink> {
    if (opts.kind === "direct") {
      // Direct links are pure cloudfs:// deep links (API.md §6) — no server call,
      // they grant nothing. Build locally.
      const url = buildDeepLink(opts.filespace, opts.path);
      return { id: url, path: opts.path, url, kind: "direct", expiresAt: null, createdBy: this.claims.sub ?? "", createdAt: new Date().toISOString() };
    }
    // FINDING 5: the backend (sharing.ts) reads `{spaceId, inodeId}` and a `ttlMs`
    // duration — NOT `{space, path, expiresInDays}` (which 400'd / dropped the ttl).
    // Map the CLI filespace → spaceId, the CLI path → inode id (same `pathToInode`
    // the namespace/grant routes use), and days → ttlMs.
    const raw = await this.req<Record<string, unknown>>("POST", `/v1/orgs/${enc(this.org)}/shares`, {
      body: {
        spaceId: opts.filespace,
        inodeId: await this.resolvePathToId(opts.filespace, opts.path),
        ttlMs: opts.expiresInDays !== undefined ? opts.expiresInDays * 86_400_000 : undefined,
      },
    });
    return toShareLink(raw, opts);
  }
  async shareList(filespace: string): Promise<ShareLink[]> {
    // FINDING 6: the backend (sharing.ts) filters on `?spaceId=`, not `?space=`.
    const raw = await this.req<unknown>("GET", `/v1/orgs/${enc(this.org)}/shares`, { query: { spaceId: filespace } });
    return asArray(raw, "shares").map((s) => toShareLink(s as Record<string, unknown>, { filespace }));
  }
  async shareRevoke(_filespace: string, id: string): Promise<void> {
    await this.req<unknown>("DELETE", `/v1/orgs/${enc(this.org)}/shares/${enc(id)}`);
  }

  // ============ identity admin (/v1/orgs/:org/users|groups) ============
  async usersList(): Promise<User[]> {
    const raw = await this.req<unknown>("GET", `/v1/orgs/${enc(this.org)}/users`);
    return asArray(raw, "users").map(toUser);
  }
  async userCreate(opts: { email: string; role: User["role"]; displayName?: string }): Promise<User> {
    // FINDING 3: the backend (users.ts) REQUIRES `displayName` and 400s without it.
    // Send it, defaulting to the email local-part when the caller gave no --name.
    const displayName = opts.displayName?.trim() || emailLocalPart(opts.email);
    const raw = await this.req<unknown>("POST", `/v1/orgs/${enc(this.org)}/users`, {
      body: { email: opts.email, role: opts.role, displayName },
    });
    return toUser(raw);
  }
  async userRemove(email: string): Promise<void> {
    // FINDING 4 (userRemove variant): the backend DELETE handler (users.ts) reads the
    // path segment as the `usr-<id>` and keys `setUserStatus(id, "deprovisioned")` off
    // it — an EMAIL there matches zero rows, so the user stays fully active (live
    // sessions/tokens) and `propagateAccountOffboarding` is a silent no-op while the
    // CLI prints "Removed". Resolve the email → userId first (same `resolveUserId` as
    // the group-member fix; a `usr-…` arg passes through, an unknown email → NOT_FOUND)
    // and DELETE the id, never the email.
    const userId = await this.resolveUserId(email);
    await this.req<unknown>("DELETE", `/v1/orgs/${enc(this.org)}/users/${enc(userId)}`);
  }
  async groupsList(): Promise<Group[]> {
    const raw = await this.req<unknown>("GET", `/v1/orgs/${enc(this.org)}/groups`);
    return asArray(raw, "groups").map(toGroup);
  }
  async groupCreate(name: string): Promise<Group> {
    const raw = await this.req<unknown>("POST", `/v1/orgs/${enc(this.org)}/groups`, { body: { name } });
    return toGroup(raw);
  }
  async groupAddMember(group: string, member: string): Promise<Group> {
    // FINDING 4: the backend (users.ts) keys group membership off `userId`, NOT email.
    // The add POST reads `b.userId` from the body (sending `{email}` added `undefined`),
    // so resolve the email → userId first and send `{userId}`.
    const userId = await this.resolveUserId(member);
    const raw = await this.req<unknown>("POST", `/v1/orgs/${enc(this.org)}/groups/${enc(group)}/members`, { body: { userId } });
    return toGroup(raw);
  }
  async groupRemoveMember(group: string, member: string): Promise<Group> {
    // FINDING 4: the backend remove reads `?userId=` from the QUERY (it previously
    // sat in the URL path → it matched nothing and returned a false `ok`). Resolve the
    // email → userId and pass it as the `userId` query param on the DELETE.
    const userId = await this.resolveUserId(member);
    const raw = await this.req<unknown>("DELETE", `/v1/orgs/${enc(this.org)}/groups/${enc(group)}/members`, {
      query: { userId },
    });
    return toGroup(raw ?? { name: group });
  }

  /**
   * FINDING 4: resolve a member reference (an email, or an already-resolved `usr-…`
   * id) to the backend `userId`. An `usr-`-prefixed value is treated as an id and
   * passed through (the `--user-id` escape hatch). Otherwise we list the org users
   * (GET /v1/orgs/:org/users — readable by any member) and match by email; an unknown
   * email is a NOT_FOUND error rather than a silent membership no-op.
   */
  private async resolveUserId(member: string): Promise<string> {
    if (member.startsWith("usr-")) return member;
    const users = await this.usersList();
    const hit = users.find((u) => u.email.toLowerCase() === member.toLowerCase());
    if (!hit || !hit.id) {
      throw new CliError(`no such member: ${member} (pass an email of an existing user, or a usr-<id>)`, ExitCode.NOT_FOUND);
    }
    return hit.id;
  }

  // ============ permissions / ACL grants (/v1/filespaces/:fs/grants) ============
  async permissionGrant(opts: Grant & { filespace: string }): Promise<Grant> {
    const { principalType, principalId } = splitPrincipal(opts.principal);
    // Audit B28: resolve the path to the OPAQUE inode id (not a constructed path id). Pre-fix this
    // wrote a grant against a nonexistent id that "succeeded" but never matched at enforcement.
    const inodeId = await this.resolvePathToId(opts.filespace, opts.path);
    await this.req<{ id: string }>("POST", `/v1/filespaces/${enc(opts.filespace)}/grants`, {
      body: {
        inodeId,
        principalType,
        principalId,
        level: toWireLevel(opts.level),
        mountAsRoot: opts.mountAsRoot,
        expiresAt: opts.expiresAt ?? undefined,
      },
    });
    return { principal: opts.principal, path: opts.path, level: opts.level, mountAsRoot: opts.mountAsRoot, expiresAt: opts.expiresAt ?? null };
  }
  async permissionRevoke(opts: { filespace: string; principal: string; path: string }): Promise<void> {
    const { principalType, principalId } = splitPrincipal(opts.principal);
    const inodeId = await this.resolvePathToId(opts.filespace, opts.path);
    await this.req<{ revoked: number }>("DELETE", `/v1/filespaces/${enc(opts.filespace)}/grants`, {
      query: { inodeId, principalType, principalId },
    });
  }
  async permissionList(filespace: string, path?: string): Promise<Grant[]> {
    const inodeId = path ? await this.resolvePathToId(filespace, path) : undefined;
    const raw = await this.req<unknown>("GET", `/v1/filespaces/${enc(filespace)}/grants`, {
      query: { inodeId },
    });
    return asArray(raw, "grants").map(toGrant);
  }

  // ============ invites (/v1/orgs/:org/invites) ============
  async inviteCreate(opts: { email: string; role: User["role"]; expiresInDays?: number }): Promise<Invite> {
    // FINDING 7: the backend (invites.ts CreateInviteInput) reads `ttlMs`, not
    // `expiresInDays`. Convert days → ttlMs and send the fields the handler expects.
    const raw = await this.req<Record<string, unknown>>("POST", `/v1/orgs/${enc(this.org)}/invites`, {
      body: {
        email: opts.email,
        role: opts.role,
        ttlMs: opts.expiresInDays !== undefined ? opts.expiresInDays * 86_400_000 : undefined,
      },
    });
    return toInvite(raw, opts);
  }
  async inviteList(): Promise<Invite[]> {
    const raw = await this.req<unknown>("GET", `/v1/orgs/${enc(this.org)}/invites`);
    return asArray(raw, "invites").map((i) => toInvite(i as Record<string, unknown>, {}));
  }
  async inviteRevoke(id: string): Promise<void> {
    await this.req<unknown>("DELETE", `/v1/orgs/${enc(this.org)}/invites/${enc(id)}`);
  }

  // ============ snapshots (/v1/filespaces/:fs/snapshots) ============
  async snapshotList(filespace: string): Promise<Snapshot[]> {
    const raw = await this.req<WireSnapshot[]>("GET", `/v1/filespaces/${enc(filespace)}/snapshots`);
    return (Array.isArray(raw) ? raw : []).map(toSnapshot);
  }
  async snapshotCreate(opts: { filespace: string; scope?: string; label?: string }): Promise<Snapshot> {
    // API.md §snapshots: `id` is OPTIONAL on POST. We omit it so the DO mints a
    // collision-free server-side id (`manual-<ts>-<rnd>`) rather than the CLI
    // inventing one (a millisecond-only client id can collide within the same ms).
    const raw = await this.req<WireSnapshot>("POST", `/v1/filespaces/${enc(opts.filespace)}/snapshots`, {
      body: { label: opts.label, scope: opts.scope },
    });
    return toSnapshot(raw ?? { id: "", label: opts.label ?? null, scope: opts.scope ?? "/" });
  }
  // POST /v1/filespaces/:fs/snapshots/:id/restore — restore `path` (file, or a
  // whole subtree with recursive:true) to its as-of-snapshot content (API.md).
  async snapshotRestore(opts: {
    filespace: string;
    id: string;
    path: string;
    recursive?: boolean;
    mode?: string;
  }): Promise<RestoreResult> {
    const raw = await this.req<Partial<RestoreResult>>(
      "POST",
      `/v1/filespaces/${enc(opts.filespace)}/snapshots/${enc(opts.id)}/restore`,
      { body: { path: opts.path, recursive: opts.recursive, mode: opts.mode } },
    );
    return toRestoreResult(raw, opts.id);
  }

  // ============ sync barriers (LOCAL ENGINE) ============
  async syncState(): Promise<SyncState> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }
  async flush(): Promise<SyncState> {
    throw new CliError(ENGINE_ONLY, ExitCode.ENGINE_UNAVAILABLE);
  }

  // ============ events / activity (change feed → NDJSON) ============
  // API.md §3: `changes` is keyset-paginated by numeric `since`/`cursor`
  // (updatedSeq). We synthesize the CLI's change events from those items.
  async *events(opts: { filespace: string; path?: string; signal?: AbortSignal }): AsyncIterable<ChangeEvent> {
    let since: number | undefined;
    // One drain of the currently-available feed (a live WS stream is API.md §9
    // future work; until then we drain the feed once and stop).
    for (;;) {
      if (opts.signal?.aborted) return;
      const page = await this.req<{ anchor: number; items: WireItem[]; cursor: number | null }>(
        "GET",
        `/v1/filespaces/${enc(opts.filespace)}/changes`,
        { query: { since, limit: 500 }, signal: opts.signal },
      );
      for (const it of page.items ?? []) {
        const ev = toChangeEvent(it);
        if (opts.path && !ev.path.startsWith(opts.path)) continue;
        yield ev;
      }
      if (page.cursor === null || page.cursor === undefined) return;
      since = page.cursor;
    }
  }
  async activity(opts: { filespace: string; limit?: number }): Promise<ChangeEvent[]> {
    const out: ChangeEvent[] = [];
    const limit = opts.limit ?? 50;
    for await (const e of this.events({ filespace: opts.filespace })) {
      out.push(e);
      if (out.length >= limit) break;
    }
    return out;
  }
}

// ===================== mapping helpers =====================

interface TokenClaims {
  sub?: string;
  typ?: string;
  org?: string;
  spc?: string;
  scp?: string[];
  jti?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
}

/** Decode (NOT verify) a compact JWS payload for display/routing. */
function decodeJwtClaims(token: string): TokenClaims {
  try {
    const parts = token.split(".");
    if (parts.length < 2) return {};
    const json = Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json) as TokenClaims;
  } catch {
    return {};
  }
}

function enc(s: string): string {
  return encodeURIComponent(s);
}

/** FINDING 3: derive a default display name from an email (the part before `@`). */
function emailLocalPart(email: string): string {
  const at = email.indexOf("@");
  const local = at > 0 ? email.slice(0, at) : email;
  return local.trim() || email;
}

// Audit B17/B28: inode ids are now OPAQUE (`ino-<uuid>`), not the path `parent/name`. The CLI can
// no longer CONSTRUCT an id from a path — `HttpGatewayClient.resolvePathToId` walks the namespace
// from root to resolve a path to the server-assigned id (the old `pathToInode` constructor is gone).
function parentPath(path: string): string {
  const i = path.replace(/\/+$/, "").lastIndexOf("/");
  return i <= 0 ? "/" : path.slice(0, i);
}

function asArray(raw: unknown, key: string): unknown[] {
  if (Array.isArray(raw)) return raw;
  if (raw && typeof raw === "object" && Array.isArray((raw as Record<string, unknown>)[key])) {
    return (raw as Record<string, unknown>)[key] as unknown[];
  }
  return [];
}

function toFilespace(raw: unknown): Filespace {
  const o = (raw ?? {}) as Record<string, unknown>;
  return {
    id: String(o.id ?? o.name ?? ""),
    name: String(o.name ?? o.id ?? ""),
    status: (o.status as Filespace["status"]) ?? "disconnected",
    role: o.role as string | undefined,
    bucket: o.bucket as string | undefined,
    rootPoint: (o.rootPoint as string | null | undefined) ?? null,
    mountPath: (o.mountPath as string | null | undefined) ?? null,
  };
}

function toItem(w: WireItem, parentDir: string): Item {
  const dir = parentDir === "/" ? "" : parentDir.replace(/\/+$/, "");
  const path = w.id === "root" ? "/" : `${dir}/${w.name}`;
  return {
    id: w.id,
    name: w.name,
    path,
    isDir: !!w.isDir,
    size: Number(w.size ?? 0),
    // The wire Item (API.md §4) carries no wall-clock mtime; surface the
    // content-version token as the closest stable change marker we have.
    modified: w.contentVersion ?? "",
    pinned: undefined,
  };
}

function toChangeEvent(w: WireItem): ChangeEvent {
  const type: ChangeEvent["type"] = w.deleted ? "delete" : (w.updatedSeq ?? 0) > 0 ? "modify" : "create";
  return {
    seq: Number(w.updatedSeq ?? 0),
    type,
    path: w.id === "root" ? "/" : `/${w.id}`,
    actor: "",
    ts: "",
  };
}

function toSnapshot(w: WireSnapshot): Snapshot {
  return {
    id: w.id,
    label: w.label ?? null,
    scope: w.scope ?? "/",
    createdAt: w.createdAt ?? "",
    immutableUntil: w.immutableUntil ?? null,
    schedule: w.scheduleId ?? null,
  };
}

function toRestoreResult(raw: Partial<RestoreResult> | undefined, snapshotId: string): RestoreResult {
  const r = raw ?? {};
  const strArr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);
  return {
    snapshotId: r.snapshotId ?? snapshotId,
    restored: strArr(r.restored),
    recreated: strArr(r.recreated),
    conflicts: Array.isArray(r.conflicts)
      ? r.conflicts.map((c) => ({ id: String((c as { id?: unknown }).id ?? ""), heldBy: String((c as { heldBy?: unknown }).heldBy ?? "") }))
      : [],
    newerThanSnapshot: strArr(r.newerThanSnapshot),
  };
}

function toShareLink(raw: Record<string, unknown>, ctx: { filespace?: string; path?: string; kind?: "guest" | "direct" }): ShareLink {
  // FINDING 7 (share variant): `createShareLink` (sharing.ts) returns
  // `{ share: ShareLinkRecord, rawToken, shareUrl }`, so the id/expiry live under
  // `raw.share.*` and the browser URL under `raw.shareUrl` — reading them at the top
  // level yielded an empty id/url. The list route returns bare records, so fall back
  // to the top-level fields when there's no nested `share`.
  const rec = (raw.share && typeof raw.share === "object" ? (raw.share as Record<string, unknown>) : raw);
  const inode = rec.inodeId as string | undefined;
  return {
    id: String(rec.id ?? raw.id ?? raw.token ?? ""),
    path: String(rec.path ?? raw.path ?? ctx.path ?? (inode && inode !== "root" ? `/${inode}` : "")),
    url: String(raw.shareUrl ?? rec.url ?? raw.url ?? raw.link ?? ""),
    kind: (rec.kind as "guest" | "direct") ?? (raw.kind as "guest" | "direct") ?? "guest",
    expiresAt: epochToIso(rec.expiresAt ?? raw.expiresAt),
    createdBy: String(rec.createdByMemberId ?? raw.createdBy ?? ""),
    createdAt: epochToIso(rec.createdAt ?? raw.createdAt) ?? "",
  };
}

/** Normalize an epoch-ms (backend) or ISO-string expiry to an ISO string, or null. */
function epochToIso(v: unknown): string | null {
  if (v == null) return null;
  if (typeof v === "number") return new Date(v).toISOString();
  return String(v);
}

function toUser(raw: unknown): User {
  const o = (raw ?? {}) as Record<string, unknown>;
  return {
    id: String(o.id ?? o.sub ?? o.email ?? ""),
    email: String(o.email ?? ""),
    role: (o.role as User["role"]) ?? "standard",
    groups: Array.isArray(o.groups) ? (o.groups as string[]) : [],
    status: (o.status as User["status"]) ?? "active",
  };
}

function toGroup(raw: unknown): Group {
  const o = (raw ?? {}) as Record<string, unknown>;
  return {
    id: String(o.id ?? o.name ?? ""),
    name: String(o.name ?? ""),
    members: Array.isArray(o.members) ? (o.members as string[]) : [],
  };
}

function toInvite(raw: Record<string, unknown>, ctx: { email?: string; role?: User["role"] }): Invite {
  // FINDING 7: `createInvite` (invites.ts) returns `{ invite: InviteRecord, rawToken }`,
  // so the id/email/role/expiry live under `raw.invite.*` and the one-time credential
  // is `raw.rawToken` — reading them at the top level printed an empty id/url/token.
  // The list route returns bare InviteRecord[], so fall back to the top-level fields
  // when there's no nested `invite`.
  const rec = (raw.invite && typeof raw.invite === "object" ? (raw.invite as Record<string, unknown>) : raw);
  // The InviteRecord carries no URL; the raw token IS the redeemable credential, so
  // surface it as the link to hand the invitee (shown ONCE at create time).
  const token = String(raw.rawToken ?? raw.url ?? raw.link ?? rec.token ?? "");
  return {
    id: String(rec.id ?? raw.id ?? raw.token ?? ""),
    email: String(rec.email ?? raw.email ?? ctx.email ?? ""),
    role: (rec.role as User["role"]) ?? (raw.role as User["role"]) ?? ctx.role ?? "standard",
    status: (rec.status as Invite["status"]) ?? (raw.status as Invite["status"]) ?? "pending",
    expiresAt: epochToIso(rec.expiresAt ?? raw.expiresAt),
    url: token,
  };
}

function toGrant(raw: unknown): Grant {
  const o = (raw ?? {}) as Record<string, unknown>;
  const principal = o.principalType === "group" ? `group:${o.principalId}` : String(o.principalId ?? o.principal ?? "");
  return {
    principal,
    path: o.inodeId === "root" || !o.inodeId ? "/" : `/${o.inodeId}`,
    level: fromWireLevel(String(o.level ?? "read")),
    mountAsRoot: (o.mountAsRoot as boolean | undefined) ?? false,
    expiresAt: (o.expiresAt as string | null | undefined) ?? null,
  };
}

/** Principal "group:editors" → {group, editors}; "x@y" → {user, x@y}. */
function splitPrincipal(principal: string): { principalType: "user" | "group"; principalId: string } {
  if (principal.startsWith("group:")) return { principalType: "group", principalId: principal.slice("group:".length) };
  return { principalType: "user", principalId: principal };
}

// CLI uses read/read-write/admin; API.md grants use read/edit/admin.
function toWireLevel(level: Grant["level"]): "read" | "edit" | "admin" {
  return level === "read-write" ? "edit" : level === "admin" ? "admin" : "read";
}
function fromWireLevel(level: string): Grant["level"] {
  return level === "edit" ? "read-write" : level === "admin" ? "admin" : "read";
}

/** Build a cloudfs:// deep link (API.md §6). */
function buildDeepLink(spaceId: string, path: string): string {
  const segs = path.replace(/^\/+/, "").split("/").filter(Boolean).map(encodeURIComponent);
  return `cloudfs://${spaceId}/${segs.join("/")}`;
}

/**
 * FINDING 2: parse a `--bucket` URI into the {bucketProvider, bucketName, keyPrefix}
 * the backend's registerSpace reads (org-do.ts). Format: `provider://name[/prefix]`,
 * e.g. `r2://studio-media`, `s3://bkt/team/edit`. The provider + bucket name are
 * required; the key prefix is optional (defaults to ""). Anything that doesn't yield
 * a non-empty provider AND bucket name is rejected as a USAGE error so we never
 * register a space with null storage fields.
 */
function parseBucketUri(bucket: string | undefined): { bucketProvider: string; bucketName: string; keyPrefix: string } {
  if (!bucket || !bucket.trim()) {
    throw new CliError("filespace create requires --bucket <provider://name[/prefix]> (e.g. r2://my-bucket)", ExitCode.USAGE);
  }
  const m = /^([a-zA-Z][\w+.-]*):\/\/([^/]+)(?:\/(.*))?$/.exec(bucket.trim());
  if (!m) {
    throw new CliError(`invalid --bucket URI: ${bucket} (expected provider://name[/prefix], e.g. r2://my-bucket)`, ExitCode.USAGE);
  }
  const bucketProvider = m[1];
  const bucketName = m[2];
  // strip any trailing slash from the prefix; absent prefix => ""
  const keyPrefix = (m[3] ?? "").replace(/\/+$/, "");
  return { bucketProvider, bucketName, keyPrefix };
}
