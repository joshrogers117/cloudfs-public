// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * EngineClient — the local-engine transport, talking to `cloudfsd` over its
 * Unix-domain-socket newline-JSON-RPC control plane (CONTROL-API.md).
 *
 * It implements the FULL {@link GatewayClient} interface so it is a drop-in for
 * the CLI's command layer, but only the LOCAL-ENGINE methods actually hit the
 * daemon:
 *   - cache.info / cache.setSize / cache.setLocation
 *   - pin / unpin / prefetch
 *   - mount / unmount
 *   - flush, sync.state (the `wait` poll), status
 *   - events / activity (NDJSON, streamed from JSON-RPC notifications)
 *   - filespace.connect / filespace.disconnect / filespace.list (status)
 *
 * Every NON-local method (auth, namespace ls/stat, share, users/groups, perms,
 * invites, snapshots) is delegated to the wrapped `gateway` client — so this is
 * the one composite the CLI uses: daemon for local, gateway for remote. That
 * retires the old `ENGINE_UNAVAILABLE` stubs on `HttpGatewayClient`.
 *
 * Connect failure (socket absent/unreachable) surfaces as ENGINE_UNAVAILABLE
 * (exit 42) — a transport condition, never a JSON-RPC error (CONTROL-API.md §1).
 */
import type { CacheInfo, GatewayClient, GatewayHealth } from "../gateway/client.js";
import type {
  AuthStatus,
  ChangeEvent,
  Filespace,
  Grant,
  Group,
  Invite,
  Item,
  PinCacheState,
  PinnedItem,
  RestoreResult,
  ShareLink,
  Snapshot,
  SyncState,
  User,
} from "../gateway/types.js";
import { RpcConnection, type Connector } from "./jsonrpc.js";

// ---- CONTROL-API.md §3 wire shapes (subset the CLI consumes) ----
interface EngineFilespace {
  id: string;
  name: string;
  status: "connected" | "connecting" | "disconnected";
  mountPath: string | null;
  rootPoint: string | null;
  role: string | null;
}
interface WireCacheInfo {
  filespace: string;
  location: string;
  sizeBytes: number;
  usedBytes: number;
  pinnedBytes: number;
  maxBytes: number;
  freeOnVolumeBytes?: number;
  hitRate?: number;
}
interface WirePinState {
  path: string;
  pinned: boolean;
  recursive: boolean;
  blocks: number;
  // --- APPENDED (CONTROL-API.md §5.4, CONTRACTS.md §4) — optional for back-compat
  //     with older daemons that omit them.
  cachedBytes?: number;
  totalBytes?: number;
  cacheState?: PinCacheState;
}
interface WirePrefetchAck {
  path: string;
  queuedBlocks: number;
}
interface WireSyncState {
  path: string;
  inSync: boolean;
  pendingUploads: number;
  pendingBytes: number;
}

export interface EngineClientOptions {
  socketPath: string;
  /** The gateway transport used for non-local methods. */
  gateway: GatewayClient;
  /** Test seam: a custom node:net connector. */
  connector?: Connector;
  requestTimeoutMs?: number;
}

export class EngineClient implements GatewayClient {
  private readonly conn: RpcConnection;
  private readonly gateway: GatewayClient;

  constructor(opts: EngineClientOptions) {
    this.conn = new RpcConnection({
      socketPath: opts.socketPath,
      connector: opts.connector,
      requestTimeoutMs: opts.requestTimeoutMs,
    });
    this.gateway = opts.gateway;
  }

  // ============================================================
  // LOCAL-ENGINE methods → cloudfsd over UDS JSON-RPC
  // ============================================================

  // ---- filespaces / connection ----
  async listFilespaces(): Promise<Filespace[]> {
    const list = await this.conn.call<EngineFilespace[]>("filespace.list", {});
    return (list ?? []).map(toFilespace);
  }
  async getFilespace(id: string): Promise<Filespace> {
    const list = await this.listFilespaces();
    const f = list.find((x) => x.id === id);
    if (!f) {
      // Defer to the gateway's registry if the engine doesn't know it yet.
      return this.gateway.getFilespace(id);
    }
    return f;
  }
  async connectFilespace(id: string): Promise<Filespace> {
    return toFilespace(await this.conn.call<EngineFilespace>("filespace.connect", { filespace: id }));
  }
  async disconnectFilespace(id: string): Promise<Filespace> {
    return toFilespace(await this.conn.call<EngineFilespace>("filespace.disconnect", { filespace: id, drain: true }));
  }

  // ---- mount ----
  async mount(opts: { filespace: string; at?: string; rootPoint?: string }): Promise<Filespace> {
    return toFilespace(
      await this.conn.call<EngineFilespace>("mount", {
        filespace: opts.filespace,
        at: opts.at,
        rootPoint: opts.rootPoint,
      }),
    );
  }
  async unmount(filespace: string): Promise<Filespace> {
    return toFilespace(await this.conn.call<EngineFilespace>("unmount", { filespace }));
  }

  // ---- cache ----
  async cacheInfo(filespace: string): Promise<CacheInfo> {
    return toCacheInfo(await this.conn.call<WireCacheInfo>("cache.info", { filespace }));
  }
  async cacheSetSize(filespace: string, bytes: number): Promise<CacheInfo> {
    return toCacheInfo(await this.conn.call<WireCacheInfo>("cache.setSize", { filespace, bytes }));
  }
  async cacheSetLocation(filespace: string, location: string): Promise<CacheInfo> {
    return toCacheInfo(await this.conn.call<WireCacheInfo>("cache.setLocation", { filespace, path: location }));
  }
  async pin(filespace: string, path: string, recursive: boolean): Promise<{ path: string; pinned: boolean }> {
    const r = await this.conn.call<WirePinState>("pin", { filespace, path, recursive });
    return { path: r.path, pinned: r.pinned };
  }
  async unpin(filespace: string, path: string, recursive: boolean): Promise<{ path: string; pinned: boolean }> {
    const r = await this.conn.call<WirePinState>("unpin", { filespace, path, recursive });
    return { path: r.path, pinned: r.pinned };
  }
  async pinList(filespace: string): Promise<PinnedItem[]> {
    const list = await this.conn.call<WirePinState[]>("pin.list", { filespace });
    return (list ?? []).map(toPinnedItem);
  }
  async prefetch(filespace: string, path: string): Promise<{ path: string; queuedBlocks: number }> {
    const r = await this.conn.call<WirePrefetchAck>("prefetch", { filespace, path });
    return { path: r.path, queuedBlocks: r.queuedBlocks };
  }

  // ---- sync barriers ----
  async syncState(filespace: string, path: string): Promise<SyncState> {
    return toSyncState(await this.conn.call<WireSyncState>("sync.state", { filespace, path }));
  }
  async flush(filespace: string, path: string): Promise<SyncState> {
    // `wait:false` (default) — drain the staged slices and return immediately.
    return toSyncState(await this.conn.call<WireSyncState>("flush", { filespace, path }));
  }

  // ---- events / activity (JSON-RPC notification stream → NDJSON) ----
  async *events(opts: { filespace: string; path?: string; signal?: AbortSignal }): AsyncIterable<ChangeEvent> {
    await this.conn.call("events.subscribe", { filespace: opts.filespace, kinds: ["activity"] });
    try {
      for await (const note of this.conn.notifications(opts.signal)) {
        if (note.method !== "activity") continue;
        const p = note.params as { filespace?: string; event?: ChangeEvent };
        if (!p.event) continue;
        if (opts.filespace && p.filespace && p.filespace !== opts.filespace) continue;
        if (opts.path && !p.event.path.startsWith(opts.path)) continue;
        yield p.event;
      }
    } finally {
      this.conn.close();
    }
  }
  async activity(opts: { filespace: string; limit?: number }): Promise<ChangeEvent[]> {
    const limit = opts.limit ?? 50;
    const out: ChangeEvent[] = [];
    const controller = new AbortController();
    for await (const e of this.events({ filespace: opts.filespace, signal: controller.signal })) {
      out.push(e);
      if (out.length >= limit) {
        controller.abort();
        break;
      }
    }
    return out;
  }

  /** Close the underlying socket (called by the CLI on shutdown). */
  close(): void {
    this.conn.close();
  }

  // ============================================================
  // REMOTE methods → delegate to the wrapped gateway client
  // ============================================================

  login(opts: { token?: string; sso?: boolean }): Promise<AuthStatus> {
    return this.gateway.login(opts);
  }
  logout(): Promise<void> {
    return this.gateway.logout();
  }
  authStatus(): Promise<AuthStatus> {
    return this.gateway.authStatus();
  }
  health(): Promise<GatewayHealth> {
    return this.gateway.health();
  }
  createFilespace(opts: { name: string; bucket?: string }): Promise<Filespace> {
    return this.gateway.createFilespace(opts);
  }
  list(filespace: string, path: string): Promise<Item[]> {
    return this.gateway.list(filespace, path);
  }
  stat(filespace: string, path: string): Promise<Item> {
    return this.gateway.stat(filespace, path);
  }
  shareCreate(opts: { filespace: string; path: string; kind: "guest" | "direct"; expiresInDays?: number }): Promise<ShareLink> {
    return this.gateway.shareCreate(opts);
  }
  shareList(filespace: string): Promise<ShareLink[]> {
    return this.gateway.shareList(filespace);
  }
  shareRevoke(filespace: string, id: string): Promise<void> {
    return this.gateway.shareRevoke(filespace, id);
  }
  usersList(): Promise<User[]> {
    return this.gateway.usersList();
  }
  userCreate(opts: { email: string; role: User["role"] }): Promise<User> {
    return this.gateway.userCreate(opts);
  }
  userRemove(email: string): Promise<void> {
    return this.gateway.userRemove(email);
  }
  groupsList(): Promise<Group[]> {
    return this.gateway.groupsList();
  }
  groupCreate(name: string): Promise<Group> {
    return this.gateway.groupCreate(name);
  }
  groupAddMember(group: string, email: string): Promise<Group> {
    return this.gateway.groupAddMember(group, email);
  }
  groupRemoveMember(group: string, email: string): Promise<Group> {
    return this.gateway.groupRemoveMember(group, email);
  }
  permissionGrant(opts: Grant & { filespace: string }): Promise<Grant> {
    return this.gateway.permissionGrant(opts);
  }
  permissionRevoke(opts: { filespace: string; principal: string; path: string }): Promise<void> {
    return this.gateway.permissionRevoke(opts);
  }
  permissionList(filespace: string, path?: string): Promise<Grant[]> {
    return this.gateway.permissionList(filespace, path);
  }
  inviteCreate(opts: { email: string; role: User["role"]; expiresInDays?: number }): Promise<Invite> {
    return this.gateway.inviteCreate(opts);
  }
  inviteList(): Promise<Invite[]> {
    return this.gateway.inviteList();
  }
  inviteRevoke(id: string): Promise<void> {
    return this.gateway.inviteRevoke(id);
  }
  snapshotList(filespace: string): Promise<Snapshot[]> {
    return this.gateway.snapshotList(filespace);
  }
  snapshotCreate(opts: { filespace: string; scope?: string; label?: string }): Promise<Snapshot> {
    return this.gateway.snapshotCreate(opts);
  }
  snapshotRestore(opts: { filespace: string; id: string; path: string; recursive?: boolean; mode?: string }): Promise<RestoreResult> {
    return this.gateway.snapshotRestore(opts);
  }
}

// ===================== mapping helpers =====================

function toFilespace(w: EngineFilespace): Filespace {
  return {
    id: w.id,
    name: w.name,
    status: w.status,
    role: w.role ?? undefined,
    rootPoint: w.rootPoint,
    mountPath: w.mountPath,
  };
}

function toCacheInfo(w: WireCacheInfo): CacheInfo {
  // CONTROL-API.md: maxBytes is the ceiling the user "set"; sizeBytes is current
  // resident. The CLI's CacheInfo keeps the same four fields + location.
  return {
    sizeBytes: w.sizeBytes,
    usedBytes: w.usedBytes,
    pinnedBytes: w.pinnedBytes,
    location: w.location,
    maxBytes: w.maxBytes,
  };
}

function toSyncState(w: WireSyncState): SyncState {
  return {
    path: w.path,
    inSync: w.inSync,
    pendingUploads: w.pendingUploads,
    pendingBytes: w.pendingBytes,
  };
}

function toPinnedItem(w: WirePinState): PinnedItem {
  // Per-item byte accounting is optional on the wire (older daemons omit it).
  // Mirror CONTRACTS.md §4.3: missing bytes → 0; missing state → derive the same
  // two-state result the engine would (fully resident → "pinned", else "pinning").
  const cachedBytes = w.cachedBytes ?? 0;
  const totalBytes = w.totalBytes ?? 0;
  return {
    path: w.path,
    recursive: w.recursive,
    cachedBytes,
    totalBytes,
    blocks: w.blocks,
    state: w.cacheState ?? (totalBytes > 0 && cachedBytes >= totalBytes ? "pinned" : "pinning"),
  };
}
