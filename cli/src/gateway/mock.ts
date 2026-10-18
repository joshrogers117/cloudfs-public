// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * MockGatewayClient — in-memory implementation of the GatewayClient seam.
 *
 * Lets the entire CLI build, run `--help`, exercise every command, emit stable
 * `--json`, and return correct exit codes WITHOUT any network or local engine.
 * It is also what the test suite drives. The real `HttpGatewayClient` will
 * implement the same interface against backend/src/index.ts.
 *
 * Behaviour is deterministic so `--json` output and tests are reproducible.
 */
import { CliError, ExitCode } from "../exit-codes.js";
import type { CacheInfo, GatewayClient, GatewayHealth } from "./client.js";
import { EXPECTED_API_VERSION } from "./http.js";
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

const GiB = 1024 ** 3;
const NOW = "2026-06-04T00:00:00.000Z";

export interface MockOptions {
  /** Pretend a valid token is present (so auth-gated commands succeed). */
  authenticated?: boolean;
  token?: string;
  gateway?: string;
  /** Number of pending uploads to report; >0 makes `wait` time out. */
  pendingUploads?: number;
}

export class MockGatewayClient implements GatewayClient {
  private authed: boolean;
  private readonly token: string | undefined;
  private readonly gateway: string;
  private pending: number;

  private filespaces: Filespace[] = [
    { id: "active-edit", name: "Active Edit", status: "connected", role: "admin", bucket: "r2://cloudfs-active", rootPoint: null, mountPath: "/Volumes/active-edit" },
    { id: "archive", name: "Archive", status: "disconnected", role: "read", bucket: "r2://cloudfs-archive", rootPoint: null, mountPath: null },
  ];

  private items: Item[] = [
    { id: "i1", name: "ShowA", path: "/ShowA", isDir: true, size: 0, modified: NOW, pinned: true },
    { id: "i2", name: "render-001.mov", path: "/ShowA/render-001.mov", isDir: false, size: 4 * GiB, modified: NOW, pinned: false },
    { id: "i3", name: "Color", path: "/ShowA/Color", isDir: true, size: 0, modified: NOW, pinned: false },
  ];

  private shares: ShareLink[] = [];
  private users: User[] = [
    { id: "u1", email: "owner@studio.tv", role: "owner", groups: ["editors"], status: "active" },
    { id: "u2", email: "colorist@studio.tv", role: "standard", groups: ["color"], status: "active" },
  ];
  private groups: Group[] = [
    { id: "g1", name: "editors", members: ["owner@studio.tv"] },
    { id: "g2", name: "color", members: ["colorist@studio.tv"] },
  ];
  private grants: Grant[] = [
    { principal: "group:editors", path: "/", level: "read-write" },
    { principal: "colorist@studio.tv", path: "/ShowA/Color", level: "read-write", mountAsRoot: true },
  ];
  private invites: Invite[] = [];
  private snapshots: Snapshot[] = [
    { id: "snap-2026-06-03T20:00", label: "nightly", scope: "/", createdAt: "2026-06-03T20:00:00.000Z", immutableUntil: "2026-09-01T20:00:00.000Z", schedule: "active-fast" },
  ];
  private cache: CacheInfo = { sizeBytes: 256 * GiB, usedBytes: 96 * GiB, pinnedBytes: 4 * GiB, location: "/var/cloudfs/cache", maxBytes: 10 * 1024 * GiB };

  constructor(opts: MockOptions = {}) {
    this.authed = opts.authenticated ?? false;
    this.token = opts.token;
    this.gateway = opts.gateway ?? "https://gateway.cloudfs.local";
    this.pending = opts.pendingUploads ?? 0;
  }

  private requireAuth(): void {
    if (!this.authed) {
      throw new CliError("not authenticated — run `cloudfs auth login` or set CLOUDFS_TOKEN", ExitCode.NOT_AUTHENTICATED);
    }
  }
  private fs(id: string): Filespace {
    const f = this.filespaces.find((x) => x.id === id);
    if (!f) throw new CliError(`no such filespace: ${id}`, ExitCode.NOT_FOUND);
    return f;
  }

  // ---- auth ----
  async login(opts: { token?: string; sso?: boolean }): Promise<AuthStatus> {
    if (opts.token === "" || opts.token === "bad") {
      throw new CliError("authentication failed: invalid token", ExitCode.AUTH_FAILED);
    }
    this.authed = true;
    return this.authStatus();
  }
  async logout(): Promise<void> {
    this.authed = false;
  }
  async authStatus(): Promise<AuthStatus> {
    return {
      authenticated: this.authed,
      principal: this.authed ? (this.token ? "ci-bot@svc" : "owner@studio.tv") : undefined,
      kind: this.authed ? (this.token ? "service-account" : "user") : undefined,
      org: this.authed ? "studio" : undefined,
      scopes: this.authed ? ["read", "write", "admin"] : undefined,
      expiresAt: this.authed ? (this.token ? null : "2026-06-05T00:00:00.000Z") : undefined,
      gateway: this.gateway,
    };
  }

  async health(): Promise<GatewayHealth> {
    // The offline mock speaks the current wire version by construction.
    return { ok: true, apiVersion: EXPECTED_API_VERSION, expectedApiVersion: EXPECTED_API_VERSION, compatible: true };
  }

  // ---- filespaces ----
  async listFilespaces(): Promise<Filespace[]> {
    this.requireAuth();
    return [...this.filespaces];
  }
  async getFilespace(id: string): Promise<Filespace> {
    this.requireAuth();
    return { ...this.fs(id) };
  }
  async createFilespace(opts: { name: string; bucket?: string }): Promise<Filespace> {
    this.requireAuth();
    const id = opts.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    if (this.filespaces.some((f) => f.id === id)) throw new CliError(`filespace already exists: ${id}`, ExitCode.CONFLICT);
    const f: Filespace = { id, name: opts.name, status: "disconnected", role: "admin", bucket: opts.bucket ?? `r2://cloudfs-${id}`, rootPoint: null, mountPath: null };
    this.filespaces.push(f);
    return { ...f };
  }
  async connectFilespace(id: string): Promise<Filespace> {
    this.requireAuth();
    const f = this.fs(id);
    f.status = "connected";
    return { ...f };
  }
  async disconnectFilespace(id: string): Promise<Filespace> {
    this.requireAuth();
    const f = this.fs(id);
    f.status = "disconnected";
    f.mountPath = null;
    return { ...f };
  }

  // ---- mount ----
  async mount(opts: { filespace: string; at?: string; rootPoint?: string }): Promise<Filespace> {
    this.requireAuth();
    const f = this.fs(opts.filespace);
    f.status = "connected";
    f.mountPath = opts.at ?? `/Volumes/${f.id}`;
    f.rootPoint = opts.rootPoint ?? null;
    return { ...f };
  }
  async unmount(filespace: string): Promise<Filespace> {
    this.requireAuth();
    const f = this.fs(filespace);
    if (!f.mountPath) throw new CliError(`filespace not mounted: ${filespace}`, ExitCode.NOT_CONNECTED);
    f.mountPath = null;
    return { ...f };
  }

  // ---- cache ----
  async cacheInfo(filespace: string): Promise<CacheInfo> {
    this.requireAuth();
    this.fs(filespace);
    return { ...this.cache };
  }
  async cacheSetSize(filespace: string, bytes: number): Promise<CacheInfo> {
    this.requireAuth();
    this.fs(filespace);
    if (bytes > this.cache.maxBytes) throw new CliError(`requested cache size exceeds max (${this.cache.maxBytes} bytes)`, ExitCode.USAGE);
    this.cache.sizeBytes = bytes;
    return { ...this.cache };
  }
  async cacheSetLocation(filespace: string, location: string): Promise<CacheInfo> {
    this.requireAuth();
    this.fs(filespace);
    this.cache.location = location;
    return { ...this.cache };
  }
  async pin(filespace: string, path: string, recursive: boolean): Promise<{ path: string; pinned: boolean }> {
    this.requireAuth();
    this.fs(filespace);
    for (const it of this.items) if (it.path === path || (recursive && it.path.startsWith(path + "/"))) it.pinned = true;
    return { path, pinned: true };
  }
  async unpin(filespace: string, path: string, recursive: boolean): Promise<{ path: string; pinned: boolean }> {
    this.requireAuth();
    this.fs(filespace);
    for (const it of this.items) if (it.path === path || (recursive && it.path.startsWith(path + "/"))) it.pinned = false;
    return { path, pinned: false };
  }
  async pinList(filespace: string): Promise<PinnedItem[]> {
    this.requireAuth();
    this.fs(filespace);
    // Deterministic fixture: every pinned item, fully resident (cached == total).
    // A 1 MiB block size keeps the synthetic block count honest.
    const BLOCK = 1024 ** 2;
    return this.items
      .filter((it) => it.pinned)
      .map((it) => {
        const total = it.size;
        const blocks = Math.max(1, Math.ceil(total / BLOCK));
        return {
          path: it.path,
          recursive: it.isDir,
          cachedBytes: total,
          totalBytes: total,
          blocks,
          state: "pinned" as const,
        };
      })
      .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }
  async prefetch(filespace: string, path: string): Promise<{ path: string; queuedBlocks: number }> {
    this.requireAuth();
    this.fs(filespace);
    return { path, queuedBlocks: 128 };
  }

  // ---- namespace ----
  async list(filespace: string, path: string): Promise<Item[]> {
    this.requireAuth();
    this.fs(filespace);
    const prefix = path === "/" ? "/" : path + "/";
    const depth = path === "/" ? 1 : path.split("/").filter(Boolean).length + 1;
    return this.items.filter((it) => it.path.startsWith(prefix) && it.path.split("/").filter(Boolean).length === depth);
  }
  async stat(filespace: string, path: string): Promise<Item> {
    this.requireAuth();
    this.fs(filespace);
    const it = this.items.find((x) => x.path === path);
    if (!it) throw new CliError(`no such path: ${path}`, ExitCode.NOT_FOUND);
    return { ...it };
  }

  // ---- share ----
  async shareCreate(opts: { filespace: string; path: string; kind: "guest" | "direct"; expiresInDays?: number }): Promise<ShareLink> {
    this.requireAuth();
    this.fs(opts.filespace);
    const id = `lnk-${this.shares.length + 1}`;
    const expiresAt = opts.kind === "guest" && opts.expiresInDays ? new Date(Date.parse(NOW) + opts.expiresInDays * 86400_000).toISOString() : null;
    const url = opts.kind === "guest" ? `https://share.cloudfs.local/g/${id}` : `cloudfs://${opts.filespace}${opts.path}`;
    const link: ShareLink = { id, path: opts.path, url, kind: opts.kind, expiresAt, createdBy: "owner@studio.tv", createdAt: NOW };
    this.shares.push(link);
    return { ...link };
  }
  async shareList(filespace: string): Promise<ShareLink[]> {
    this.requireAuth();
    this.fs(filespace);
    return [...this.shares];
  }
  async shareRevoke(filespace: string, id: string): Promise<void> {
    this.requireAuth();
    this.fs(filespace);
    const before = this.shares.length;
    this.shares = this.shares.filter((s) => s.id !== id);
    if (this.shares.length === before) throw new CliError(`no such share link: ${id}`, ExitCode.NOT_FOUND);
  }

  // ---- users & groups ----
  async usersList(): Promise<User[]> {
    this.requireAuth();
    return [...this.users];
  }
  async userCreate(opts: { email: string; role: User["role"] }): Promise<User> {
    this.requireAuth();
    if (this.users.some((u) => u.email === opts.email)) throw new CliError(`user already exists: ${opts.email}`, ExitCode.CONFLICT);
    const u: User = { id: `u${this.users.length + 1}`, email: opts.email, role: opts.role, groups: [], status: "active" };
    this.users.push(u);
    return { ...u };
  }
  async userRemove(email: string): Promise<void> {
    this.requireAuth();
    const before = this.users.length;
    this.users = this.users.filter((u) => u.email !== email);
    if (this.users.length === before) throw new CliError(`no such user: ${email}`, ExitCode.NOT_FOUND);
  }
  async groupsList(): Promise<Group[]> {
    this.requireAuth();
    return [...this.groups];
  }
  async groupCreate(name: string): Promise<Group> {
    this.requireAuth();
    if (this.groups.some((g) => g.name === name)) throw new CliError(`group already exists: ${name}`, ExitCode.CONFLICT);
    const g: Group = { id: `g${this.groups.length + 1}`, name, members: [] };
    this.groups.push(g);
    return { ...g };
  }
  private group(name: string): Group {
    const g = this.groups.find((x) => x.name === name);
    if (!g) throw new CliError(`no such group: ${name}`, ExitCode.NOT_FOUND);
    return g;
  }
  async groupAddMember(group: string, email: string): Promise<Group> {
    this.requireAuth();
    const g = this.group(group);
    if (!g.members.includes(email)) g.members.push(email);
    return { ...g };
  }
  async groupRemoveMember(group: string, email: string): Promise<Group> {
    this.requireAuth();
    const g = this.group(group);
    g.members = g.members.filter((m) => m !== email);
    return { ...g };
  }

  // ---- permissions ----
  async permissionGrant(opts: Grant & { filespace: string }): Promise<Grant> {
    this.requireAuth();
    this.fs(opts.filespace);
    const grant: Grant = { principal: opts.principal, path: opts.path, level: opts.level, mountAsRoot: opts.mountAsRoot, expiresAt: opts.expiresAt ?? null };
    this.grants = this.grants.filter((g) => !(g.principal === grant.principal && g.path === grant.path));
    this.grants.push(grant);
    return { ...grant };
  }
  async permissionRevoke(opts: { filespace: string; principal: string; path: string }): Promise<void> {
    this.requireAuth();
    this.fs(opts.filespace);
    const before = this.grants.length;
    this.grants = this.grants.filter((g) => !(g.principal === opts.principal && g.path === opts.path));
    if (this.grants.length === before) throw new CliError(`no such grant: ${opts.principal} on ${opts.path}`, ExitCode.NOT_FOUND);
  }
  async permissionList(filespace: string, path?: string): Promise<Grant[]> {
    this.requireAuth();
    this.fs(filespace);
    return this.grants.filter((g) => !path || g.path === path).map((g) => ({ ...g }));
  }

  // ---- invites ----
  async inviteCreate(opts: { email: string; role: User["role"]; expiresInDays?: number }): Promise<Invite> {
    this.requireAuth();
    const id = `inv-${this.invites.length + 1}`;
    const expiresAt = opts.expiresInDays ? new Date(Date.parse(NOW) + opts.expiresInDays * 86400_000).toISOString() : null;
    const inv: Invite = { id, email: opts.email, role: opts.role, status: "pending", expiresAt, url: `https://app.cloudfs.local/invite/${id}` };
    this.invites.push(inv);
    return { ...inv };
  }
  async inviteList(): Promise<Invite[]> {
    this.requireAuth();
    return [...this.invites];
  }
  async inviteRevoke(id: string): Promise<void> {
    this.requireAuth();
    const inv = this.invites.find((i) => i.id === id);
    if (!inv) throw new CliError(`no such invite: ${id}`, ExitCode.NOT_FOUND);
    inv.status = "revoked";
  }

  // ---- snapshots ----
  async snapshotList(filespace: string): Promise<Snapshot[]> {
    this.requireAuth();
    this.fs(filespace);
    return [...this.snapshots];
  }
  async snapshotCreate(opts: { filespace: string; scope?: string; label?: string }): Promise<Snapshot> {
    this.requireAuth();
    this.fs(opts.filespace);
    const snap: Snapshot = { id: `snap-${this.snapshots.length + 1}`, label: opts.label ?? null, scope: opts.scope ?? "/", createdAt: NOW, immutableUntil: null, schedule: null };
    this.snapshots.push(snap);
    return { ...snap };
  }
  async snapshotRestore(opts: { filespace: string; id: string; path: string; recursive?: boolean; mode?: string }): Promise<RestoreResult> {
    this.requireAuth();
    this.fs(opts.filespace);
    if (!this.snapshots.some((s) => s.id === opts.id)) throw new CliError(`no such snapshot: ${opts.id}`, ExitCode.NOT_FOUND);
    // Deterministic, illustrative result: the target restored, plus (recursive)
    // one re-created child, with nothing locked and one item newer-than-snapshot.
    return {
      snapshotId: opts.id,
      restored: [opts.path],
      recreated: opts.recursive ? [`${opts.path.replace(/\/$/, "")}/deleted-clip.mov`] : [],
      conflicts: [],
      newerThanSnapshot: opts.recursive ? [`${opts.path.replace(/\/$/, "")}/added-after.mov`] : [],
    };
  }

  // ---- sync barriers ----
  async syncState(filespace: string, path: string): Promise<SyncState> {
    this.requireAuth();
    this.fs(filespace);
    return { path, inSync: this.pending === 0, pendingUploads: this.pending, pendingBytes: this.pending * 4 * GiB };
  }
  async flush(filespace: string, path: string): Promise<SyncState> {
    this.requireAuth();
    this.fs(filespace);
    // Flushing forces the journal to drain in the mock.
    this.pending = 0;
    return { path, inSync: true, pendingUploads: 0, pendingBytes: 0 };
  }

  // ---- events / activity ----
  async *events(opts: { filespace: string; path?: string; signal?: AbortSignal }): AsyncIterable<ChangeEvent> {
    this.requireAuth();
    this.fs(opts.filespace);
    const sample: ChangeEvent[] = [
      { seq: 1, type: "upload", path: "/ShowA/render-001.mov", actor: "owner@studio.tv", ts: NOW },
      { seq: 2, type: "lock", path: "/ShowA/Color/grade.drx", actor: "colorist@studio.tv", ts: NOW },
      { seq: 3, type: "modify", path: "/ShowA/Color/grade.drx", actor: "colorist@studio.tv", ts: NOW },
    ];
    for (const e of sample) {
      if (opts.signal?.aborted) return;
      if (opts.path && !e.path.startsWith(opts.path)) continue;
      yield e;
    }
  }
  async activity(opts: { filespace: string; limit?: number }): Promise<ChangeEvent[]> {
    this.requireAuth();
    this.fs(opts.filespace);
    const events: ChangeEvent[] = [];
    for await (const e of this.events({ filespace: opts.filespace })) events.push(e);
    return events.slice(0, opts.limit ?? 50);
  }
}
