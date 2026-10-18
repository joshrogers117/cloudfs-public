// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * GatewayClient — the single seam between the CLI and everything remote/local.
 *
 * The CLI is a thin wrapper over the SAME documented gateway API the GUI uses
 * (SPEC §3.8). Two transports hide behind this one interface:
 *   - the **gateway** (Cloudflare Workers + Durable Objects) over HTTPS with
 *     bearer-token auth — snapshots, permissions, links, admin, metadata;
 *   - the **local engine** over its control socket — cache/pin/mount/sync state.
 *
 * Commands depend only on this interface, never on fetch/sockets directly, so:
 *   - `MockGatewayClient` lets the whole CLI build/run/test offline;
 *   - `HttpGatewayClient` (the real wire impl) can be dropped in later without
 *     touching a single command.
 *
 * See backend/src/index.ts for the concrete REST shape this will eventually call
 * (`/v1/filespaces/:fs/<resource>`, `Authorization: Bearer <token>`).
 */
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

export interface CacheInfo {
  sizeBytes: number;
  usedBytes: number;
  pinnedBytes: number;
  location: string;
  maxBytes: number;
}

/** Version-handshake probe of the public `/v1/health` route. */
export interface GatewayHealth {
  ok: boolean;
  /** Backend wire-contract version, or null if the gateway didn't advertise one. */
  apiVersion: number | null;
  /** The wire version THIS client targets (CLI-side constant). */
  expectedApiVersion: number;
  /** True when the gateway's major wire version matches what this client expects. */
  compatible: boolean;
}

export interface GatewayClient {
  // ---- auth & service accounts ----
  login(opts: { token?: string; sso?: boolean }): Promise<AuthStatus>;
  logout(): Promise<void>;
  authStatus(): Promise<AuthStatus>;
  /** Version handshake: GET /v1/health (public) and compare wire versions. */
  health(): Promise<GatewayHealth>;

  // ---- filespaces ----
  listFilespaces(): Promise<Filespace[]>;
  getFilespace(id: string): Promise<Filespace>;
  createFilespace(opts: { name: string; bucket?: string }): Promise<Filespace>;
  connectFilespace(id: string): Promise<Filespace>;
  disconnectFilespace(id: string): Promise<Filespace>;

  // ---- mount (engine) ----
  mount(opts: { filespace: string; at?: string; rootPoint?: string }): Promise<Filespace>;
  unmount(filespace: string): Promise<Filespace>;

  // ---- cache (engine) ----
  cacheInfo(filespace: string): Promise<CacheInfo>;
  cacheSetSize(filespace: string, bytes: number): Promise<CacheInfo>;
  cacheSetLocation(filespace: string, location: string): Promise<CacheInfo>;
  pin(filespace: string, path: string, recursive: boolean): Promise<{ path: string; pinned: boolean }>;
  unpin(filespace: string, path: string, recursive: boolean): Promise<{ path: string; pinned: boolean }>;
  /** Enumerate every pinned path with per-item byte accounting + cache state (CONTROL-API.md §5.4). */
  pinList(filespace: string): Promise<PinnedItem[]>;
  prefetch(filespace: string, path: string): Promise<{ path: string; queuedBlocks: number }>;

  // ---- namespace ----
  list(filespace: string, path: string): Promise<Item[]>;
  stat(filespace: string, path: string): Promise<Item>;

  // ---- share links ----
  shareCreate(opts: {
    filespace: string;
    path: string;
    kind: "guest" | "direct";
    expiresInDays?: number;
  }): Promise<ShareLink>;
  shareList(filespace: string): Promise<ShareLink[]>;
  shareRevoke(filespace: string, id: string): Promise<void>;

  // ---- identity admin ----
  usersList(): Promise<User[]>;
  userCreate(opts: { email: string; role: User["role"]; displayName?: string }): Promise<User>;
  userRemove(email: string): Promise<void>;
  groupsList(): Promise<Group[]>;
  groupCreate(name: string): Promise<Group>;
  groupAddMember(group: string, email: string): Promise<Group>;
  groupRemoveMember(group: string, email: string): Promise<Group>;

  // ---- permissions (ACLs) ----
  permissionGrant(opts: Grant & { filespace: string }): Promise<Grant>;
  permissionRevoke(opts: { filespace: string; principal: string; path: string }): Promise<void>;
  permissionList(filespace: string, path?: string): Promise<Grant[]>;

  // ---- invites ----
  inviteCreate(opts: { email: string; role: User["role"]; expiresInDays?: number }): Promise<Invite>;
  inviteList(): Promise<Invite[]>;
  inviteRevoke(id: string): Promise<void>;

  // ---- snapshots ----
  snapshotList(filespace: string): Promise<Snapshot[]>;
  snapshotCreate(opts: { filespace: string; scope?: string; label?: string }): Promise<Snapshot>;
  snapshotRestore(opts: { filespace: string; id: string; path: string; recursive?: boolean; mode?: string }): Promise<RestoreResult>;

  // ---- sync barriers ----
  syncState(filespace: string, path: string): Promise<SyncState>;
  /** Force the write-back journal to drain for `path`. Resolves when queued. */
  flush(filespace: string, path: string): Promise<SyncState>;

  // ---- events / activity ----
  /** Async stream of change/lock/upload events as they occur (NDJSON-friendly). */
  events(opts: { filespace: string; path?: string; signal?: AbortSignal }): AsyncIterable<ChangeEvent>;
  /** Point-in-time recent activity log (bounded). */
  activity(opts: { filespace: string; limit?: number }): Promise<ChangeEvent[]>;
}
