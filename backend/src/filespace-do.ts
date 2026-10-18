// SPDX-License-Identifier: AGPL-3.0-or-later
import { ReclamationStore } from './metadata/reclamation';
import { MetadataCapacity, isMetadataCapacityError } from './metadata/capacity';
import { applyFileDelta, validateFileDelta, fileVerificationBlocks, FileDeltaConflict, ManifestLayoutError, type FileDelta } from './metadata/file-manifest';
import { ChangeNotifications } from "./change-notifications";
import { readStreamManifest, commitStreamDelta, validateStreamDelta, streamVerificationBlocks, StreamConflictError, type StreamDelta } from './metadata/stream-manifest';
import { DurableObject } from "cloudflare:workers";
import { BackupState, type BackupEnv } from "./backup-state";
import type { Env } from "./env";
import { migrate } from "./metadata/schema";
import { MAX_STREAM_BODY_BYTES } from "./metadata/stream-limits";
import { ConflictError, InvalidNameError, NameCollisionError, InvalidMoveError, NamespaceMutationError, type RenameReplacement, canonicalizeName, NamespaceStore } from "./metadata/namespace";
import { LockManager } from "./metadata/locks";
import { OpenHandleStore, OPEN_HANDLE_DELETE, OPEN_HANDLE_MAX_TTL_MS, OPEN_HANDLE_READ, OPEN_HANDLE_WRITE, OPEN_HANDLE_MASK } from "./metadata/open-handles";
import { RangeLockManager, type FileLockRange, type RangeAccess } from "./metadata/range-locks";
import { UploadCoordinator } from "./metadata/uploads";
import { InvalidManifestError, validateBlockManifest } from "./metadata/block-manifest";
import { storageIdentity, verifyStorageObjects, nativeVerificationBucket, validateObjectVerificationInput, validateVerifiedObject, type ObjectVerificationInput, type VerifiedObject, ObjectVerificationError } from "./storage-object-verifier";
import { SnapshotStore, type ScheduleSpec, type RestoreResult } from "./metadata/snapshots";
import { SnapshotAccess } from "./metadata/snapshot-access";
import { DoAclStore } from "./metadata/acl-store";
import { grantMutationPolicy } from "./acl-management";
import { DoAuditStore } from "./metadata/audit-store";
import { R2AuditArchive, type AuditR2 } from "./metadata/audit-archive";
import { DoRateLimitStore } from "./metadata/ratelimit-store";
import {
  canAccess,
  isOrgAdmin,
  isGrantLive,
  principalMatches,
  grant as grantAcl,
  revokePrincipal,
  type Action,
  type Decision,
  type Grant as AclGrant,
  type GrantInput,
  type Principal as AclPrincipal,
} from "./permissions";
import { AuditLog, verifyChain, type AuditEvent, type AuditQuery, type AuditRecord, type ChainVerifyResult } from "./security/audit";
import { RateLimiter, type RateLimitConfig, type RateLimitResult } from "./security/ratelimit";
import {
  resolveStorageConfigAsync,
  listObjects,
  deleteObjects,
  type SpaceStorageDescriptor,
  type StorageConfig,
  type ManagedCredentialResolver,
} from "./storage";
import { managedCredentialResolver } from "./storage-credentials";

/// Audit ring-buffer policy (WS3): the DO keeps min(last 24h, last 2000 events).
/// At trim time we seal everything OUTSIDE this window to R2, then delete it.
const AUDIT_RING_MAX_EVENTS = 2000;
const AUDIT_RING_WINDOW_MS = 24 * 60 * 60 * 1000;
/// Re-evaluate the audit ring on a periodic alarm cadence even with no schedules.
const AUDIT_ARCHIVE_INTERVAL_MS = 60 * 60 * 1000; // hourly
const MAINTENANCE_RETRY_MS = 30_000;
/// Bulk-op rollup: a delete touching ≥ this many items collapses into ONE
/// "large-delete" live-activity event instead of N per-item entries (§5.3).
const BULK_DELETE_THRESHOLD = 50;
/// Hot-state caps so a long-lived DO can't grow these maps unbounded.
const ACTIVE_OPS_MAX = 500;
const HOT_EVENTS_MAX = 200;

/// An in-flight transfer tracked in DO hot state (mirrors CONTROL-API `Transfer`).
export interface ActiveTransfer {
  id: string;
  path: string;
  direction: "upload" | "download";
  bytesDone: number;
  bytesTotal: number;
  state: "active" | "completing";
  startedAt: number;
}

/// A live-activity event: an ordinary single op OR a rolled-up bulk op. Shape is
/// change-feed-compatible plus the `kind`/`op`/`count` rollup fields (§5.3).
export interface LiveActivityEvent {
  seq: number;
  type: string;            // 'create' | 'modify' | 'delete' | ...
  path: string;
  actor: string;
  ts: number;
  kind: "single" | "bulk";
  op?: string;             // e.g. 'large-delete' (bulk only)
  count?: number;          // items collapsed (bulk only)
}

export interface LiveActivity {
  transfers: ActiveTransfer[];
  events: LiveActivityEvent[];
}

/// Token-bucket configs for the per-(org,space) durable limiters. Mirror the
/// gateway's per-isolate defaults (security-INTEGRATION.md §6) but are now a
/// SINGLE consistent counter per space, since the DO serializes them.
// Audit B23: the prior caps (presign 5/s ≈ 20 MB/s of cache-miss reads; mutation 2/s ≈ a 1,000-file
// copy throttled to ~8 min) were far below a real media workload. Raised to realistic rates while
// keeping a burst cap that still protects the single-threaded DO from a runaway client. A single
// batch-presign request (below) also consumes ONE bucket token per key but in ONE round-trip.
const RL_CONFIGS: Record<"presign" | "mutation", RateLimitConfig> = {
  // Blocks are 1 MiB. Allow a 10 Gb/s workstation to keep its parallel object
  // transfers fed; the limiter remains per authenticated principal/filespace.
  presign: { capacity: 8192, refillPerSec: 2048 },
  mutation: { capacity: 300, refillPerSec: 50 },  // a 1,000-file Finder copy in ~20s, not ~8min
};
import type { Block, Item, LockMode, LockPurpose, LockResult, Page, Snapshot, StreamInfo, UploadSession } from "./metadata/types";

export type { Item, Block, LockResult, Page, Snapshot, UploadSession } from "./metadata/types";
export type { RestoreResult } from "./metadata/snapshots";
export { ConflictError, LockedError, BULK_SEED_MAX } from "./metadata/namespace";

/// One FilespaceDO instance per filespace (addressed by `idFromName(filespaceId)`).
/// The serverless analog of "one metadata server per filespace"
/// (SPEC §7.3a): a single-threaded, strongly-consistent authority that owns the
/// namespace + content-addressed block map (in DO SQLite) AND the advisory
/// locks/leases, snapshots, and multipart-upload coordination.
///
/// Performance choices:
///  - All hot reads are index-served and paginated — we never load a whole tree.
///  - A small in-memory item cache (lost on hibernation, rebuilt lazily) serves
///    repeated stat()s without touching SQLite; every write invalidates it.
///  - A single DO alarm reaps expired leases AND fires due snapshot schedules,
///    so both happen server-side even with all clients offline (SPEC §4.7/§5.5).
export class FilespaceDO extends DurableObject<Env> {
  private notifications: ChangeNotifications;
  private notificationScheduled = false;
  private notificationDirty = false;
  private scheduleChangeHint(): void {
    this.notificationDirty = true;
    if (this.notificationScheduled) return;
    this.notificationScheduled = true;
    this.ctx.waitUntil(Promise.resolve().then(async () => {
      try {
        do {
          this.notificationDirty = false;
          await this.ctx.storage.sync();
        } while (this.notificationDirty);
        this.notifications.broadcast();
      } finally { this.notificationScheduled = false; }
    }));
  }
  private visibilityGeneration(): number {
    return this.metaIntGet('visibility_generation');
  }
  private changeStamp(): string {
    return `${this.ns.currentSeq()}:${this.visibilityGeneration()}`;
  }
  async fetch(request: Request): Promise<Response> {
    // Only the authenticated gateway creates this internal request; the DO has
    // no public route. Never forward caller-supplied identity headers here.
    if (new URL(request.url).pathname !== '/internal/changes' || request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
      return new Response('Not found', { status: 404 });
    }
    const raw = request.headers.get('X-CloudFS-Subscription');
    if (!raw || raw.length > 32_768) return new Response('Invalid subscription', { status: 400 });
    const input = JSON.parse(raw) as { principal: AclPrincipal; expiresAt: number };
    if (!input.principal || typeof input.principal.id !== 'string' || this.isDeleted() || this.isPurging() || this.backupState.isBlocked()) {
      return new Response('Unavailable', { status: 403 });
    }
    await this.ctx.storage.sync();
    return this.notifications.accept(input.principal, input.expiresAt);
  }
  webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): void { this.notifications.message(ws, message); }
  webSocketClose(ws: WebSocket, code: number): void { this.notifications.close(ws, code); }
  webSocketError(ws: WebSocket): void { this.notifications.close(ws, 1011); }

  private readonly sql: SqlStorage;
  private readonly capacity: MetadataCapacity;
  private readonly reclamation: ReclamationStore;
  private reclamationOperation: Promise<void> | null = null;
  private readonly backupState: BackupState;
  private readonly ns: NamespaceStore;
  private readonly locks: LockManager;
  private readonly openHandles: OpenHandleStore;
  private readonly rangeLocks: RangeLockManager;
  private readonly uploads: UploadCoordinator;
  private readonly snapshots: SnapshotStore;
  /// ACL store + audit chain bound to this DO's SQLite (integration round). The
  /// permissions evaluator is pure/sync, so it runs IN the DO against `sql`.
  private readonly acl: DoAclStore;
  private readonly audit: AuditLog;
  /// The concrete ring store behind `audit` — exposes trim/range helpers the
  /// archiver needs (the AuditLog interface only does write/query).
  private readonly auditStore: DoAuditStore;
  /// R2-backed archive for sealed audit segments (null when AUDIT_BUCKET is
  /// unbound — local dev without R2; the DO then keeps the full chain in SQLite).
  /// Bound lazily once we know this DO's effective `<org>::<fs>` key (the R2
  /// prefix), which is learned from the first audit event's orgId+spaceId.
  private auditArchive: R2AuditArchive | null = null;
  private archiveOperations = new Set<Promise<unknown>>();
  /// The effective DO key form `<org>::<fs>` used as the R2 audit prefix. Learned
  /// from the first audit write (the gateway stamps orgId+spaceId on every event).
  private filespaceKey: string | null = null;

  /// DO HOT STATE for the live activity feed (lost on hibernation; rebuilt as ops
  /// flow). In-flight transfers + a short rolling tail of recent activity events
  /// (incl. bulk-op rollups). NOT the audit history — that is the hash chain.
  private activeTransfers = new Map<string, ActiveTransfer>();
  private hotEvents: LiveActivityEvent[] = [];
  /// Per-(org,space) durable rate limiters, one per class. Backed by the DO's
  /// SQLite so all Worker isolates share one consistent counter per space.
  private readonly limiters: Record<"presign" | "mutation", RateLimiter>;

  /// In-memory stat cache (id → Item). Persist-first, cache-second: writes update
  /// SQLite then invalidate here. Bounded so a huge filespace can't OOM the DO.
  private itemCache = new Map<string, Item>();
  private static readonly CACHE_MAX = 5_000;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.backupState = new BackupState(ctx.storage, env, 'filespace');
    this.sql = this.backupState.guardedSQL;
    this.capacity = new MetadataCapacity(this.sql,env);
    this.reclamation = new ReclamationStore(this.sql);
    this.ns = new NamespaceStore(this.sql, () => this.scheduleChangeHint(), bytes => this.capacity.admit(bytes), id => this.invalidate(id));
    this.locks = new LockManager(this.sql, () => this.ns.nextFence());
    this.openHandles = new OpenHandleStore(this.sql);
    this.rangeLocks = new RangeLockManager(this.sql, () => this.ns.nextFence());
    this.uploads = new UploadCoordinator(this.sql);
    this.snapshots = new SnapshotStore(this.sql, () => this.ns.currentSeq(), this.ns, bytes => this.capacity.admit(bytes));
    this.acl = new DoAclStore(this.sql, () => this.scheduleChangeHint());
    this.notifications = new ChangeNotifications(ctx, () => this.changeStamp(), principal =>
      !this.isDeleted() && !this.isPurging() && !this.backupState.isBlocked() &&
      (this.hasFullAccess(principal) || this.acl.matchingLiveInodes(principal).some(item => this.makeReadPredicate(principal)(item.id))));
    this.auditStore = new DoAuditStore(this.sql);
    this.audit = new AuditLog(this.auditStore);
    const rlStore = new DoRateLimitStore(this.sql);
    // Audit B23: the per-class caps are operator-tunable (document per-block-size throughput so an
    // admin can match RL_CONFIGS to their media workload). An invalid/absent override uses the
    // default. Tests also use these to drive a small, deterministic cap without a huge burst.
    const num = (v: string | undefined, fallback: number): number => {
      const n = Number(v); return Number.isFinite(n) && n > 0 ? n : fallback;
    };
    const e = this.env as Env;
    const presignCfg = { capacity: num(e.RL_PRESIGN_CAPACITY, RL_CONFIGS.presign.capacity), refillPerSec: num(e.RL_PRESIGN_REFILL, RL_CONFIGS.presign.refillPerSec) };
    const mutationCfg = { capacity: num(e.RL_MUTATION_CAPACITY, RL_CONFIGS.mutation.capacity), refillPerSec: num(e.RL_MUTATION_REFILL, RL_CONFIGS.mutation.refillPerSec) };
    this.limiters = {
      presign: new RateLimiter(rlStore, presignCfg),
      mutation: new RateLimiter(rlStore, mutationCfg),
    };
    // Race-free setup before any request is served.
    ctx.blockConcurrencyWhile(async () => {
      migrate(this.sql);
      this.seedIfEmpty();
      this.backupState.initialize();
      if (!this.backupState.isBlocked()) await this.armAlarm();
    });
  }

  private seedIfEmpty(): void {
    const count = Number(this.sql.exec(`SELECT COUNT(*) AS c FROM items;`).one().c);
    if (count > 0) return;
    // The root inode is always required (the namespace anchor).
    this.ns.put(null, "", true, 0, { id: "root" });
    // Audit B24: the demo fixtures (Project A / A001.mov / timeline.prproj) used to be seeded
    // into EVERY new filespace — including production ones, where they appear as phantom files an
    // editor never created. Gate them behind SEED_DEMO_ITEMS so a real deployment starts EMPTY;
    // the dev/test runtime sets the flag (see .dev.vars) to keep the fixture-based suites working.
    const demo = (this.env as Env).SEED_DEMO_ITEMS;
    if (!this.env.BACKUP_MODE && (demo === "1" || demo === "true")) {
      this.ns.put("root", "Project A", true, 0, { id: "projectA" });
      this.ns.put("root", "Archive", true, 0, { id: "archive" });
      this.ns.put("projectA", "A001.mov", false, 2_100_000_000, { id: "clipA001" }); // ~2 GB ProRes
      this.ns.put("projectA", "timeline.prproj", false, 4_200_000, { id: "timeline" });
    }
  }

  /** Protected deployment doctor uses a dedicated, empty object. No account or
   * namespace content is returned and no recurring work is armed. */

  backupDescribe() { return this.backupState.describe(); }
  async backupFreeze(input: Parameters<BackupState['freeze']>[0]) {
    this.backupState.freeze(input);
    await Promise.allSettled([...this.archiveOperations,...(this.reclamationOperation ? [this.reclamationOperation] : [])]);
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.sync();
  }
  async backupRelease(input: Parameters<BackupState['release']>[0]) {
    const result = this.backupState.release(input);
    if (!this.backupState.isBlocked()) await this.armAlarm();
    return result;
  }
  backupExportPage(input: Parameters<BackupState['exportPage']>[0]) { return this.backupState.exportPage(input); }
  backupCatalogPage(input: Parameters<BackupState['catalogPage']>[0]) { return this.backupState.catalogPage(input); }
  backupCheckReferences(input: Parameters<BackupState['checkReferences']>[0]) { return this.backupState.checkReferences(input); }
  backupRestoreBegin(input: Parameters<BackupState['restoreBegin']>[0]) { return this.backupState.restoreBegin(input); }
  backupRestorePage(input: Parameters<BackupState['restorePage']>[0]) { return this.backupState.restorePage(input); }
  backupRestoreCommit(input: Parameters<BackupState['restoreCommit']>[0]) { return this.backupState.restoreCommit(input); }
  backupRestoreStatus() { return this.backupState.restoreStatus(); }
  backupValidateCatalog(input: Parameters<BackupState['validateCatalog']>[0]) { return this.backupState.validateCatalog(input); }
  backupObjectsPage(input: Parameters<BackupState['objectsPage']>[0]) { return this.backupState.objectsPage(input); }
  backupExpectObjects(input: Parameters<BackupState['expectObjects']>[0]) { return this.backupState.expectObjects(input); }
  backupExpectedObject(input: Parameters<BackupState['expectedObject']>[0]) { return this.backupState.expectedObject(input); }
  backupRecordObject(input: Parameters<BackupState['recordObject']>[0]) { return this.backupState.recordObject(input); }
  backupVerifyObjects(input: Parameters<BackupState['verifyObjects']>[0]) { return this.backupState.verifyObjects(input); }

  async readiness() {
    const schemaVersion = Number(this.sql.exec(`SELECT MAX(id) AS version FROM _schema_migrations;`).one().version);
    if (!this.sql.exec(`SELECT 1 FROM items WHERE id='root' AND deleted=0;`).toArray().length) {
      throw new Error("metadata root is unavailable");
    }
    await this.ctx.storage.sync();
    return { schemaVersion, databaseBytes: this.sql.databaseSize, capacity: this.capacity.status() };
  }

  metadataCapacityFor(principal: AclPrincipal, contributors=false) {
    this.assertNotDeleted();
    if (!isOrgAdmin(principal.orgRole)) return {error:'forbidden' as const};
    return {...this.capacity.status(),...(contributors ? {contributors:this.capacity.contributors()} : {})};
  }

  // ---- soft-delete tombstone (defense in depth) -----------------------------
  //
  // The PRIMARY soft-delete enforcement is the gateway-level gate (it refuses every
  // filespace-plane request for a tombstoned space at a single chokepoint). This is a
  // belt-and-suspenders durable flag so even a DIRECT DO call (bypassing the gateway) refuses
  // data-plane work. It's stored in the existing `meta` table (key 'deleted', value 1), so it is
  // SQLite-backed and survives hibernation. REVERSIBLE: marking deleted leaves the namespace,
  // block map, snapshots, and underlying R2 objects fully intact — it only flips this flag.

  /// True iff this filespace has been soft-deleted (tombstone set). Read from SQLite so the
  /// answer is correct even immediately after a hibernation wake.
  isDeleted(): boolean {
    const rows = this.sql.exec(`SELECT value FROM meta WHERE key = 'deleted';`).toArray();
    return rows.length > 0 && Number(rows[0].value) === 1;
  }

  /// Set the durable soft-delete tombstone (idempotent). Called by the gateway AFTER the OrgDO
  /// registry marks the space deleted, so a direct data-plane DO call is also refused. Does NOT
  /// delete any namespace rows, block map, or R2 objects — the space stays recoverable.
  /// TODO(r2-cleanup): purging the underlying objects / tearing down this DO is a separate,
  /// deliberate maintainer decision — intentionally NOT done here.
  async markDeleted(): Promise<{ deleted: true }> {
    this.sql.exec(`INSERT INTO meta (key, value) VALUES ('deleted', 1)
      ON CONFLICT(key) DO UPDATE SET value = 1;`);
    return { deleted: true };
  }

  /// Throw if this filespace is tombstoned — guards the data-plane mutation/resolve entry points
  /// so a direct (non-gateway) DO call cannot mutate or be presigned against a deleted space. The
  /// gateway never reaches these (it 410s first), so this only fires on a bypass.
  private assertNotDeleted(): void {
    if (this.isDeleted()) throw new Error("filespace_deleted");
  }

  // ---- PURGE: permanent, prefix-scoped deletion of this space's objects + metadata ----------
  //
  // A purge IRREVERSIBLY deletes every object under this space's storage prefix
  // (`blocks/<org>::<space>/`) AND then hard-deletes this DO's own SQLite. It is the second step
  // of a deliberate two-step model: the space MUST already be soft-deleted (tombstoned) and the
  // gateway MUST have owner-gated + confirmation-checked the request before calling startPurge().
  //
  // SAFETY: the prefix is built from the orgId+spaceId the GATEWAY passes in (derived from the
  // TRUSTED principal + the OrgDO registry row), NEVER from client input. Every sweep page is
  // listed with `prefix=` and every key is re-asserted to start with the prefix before delete (in
  // storage.ts). The sweep is async + resumable: each alarm tick deletes one page and persists a
  // cursor, so a crash mid-sweep resumes from the cursor and re-listing already-deleted keys is a
  // harmless no-op (DeleteObjects is idempotent).
  //
  // Durable purge state (survives hibernation):
  //   meta('purging', 1)                      — sweep is active
  //   meta_text('purge_prefix', <prefix>)     — the EXACT, gateway-trusted prefix to sweep
  //   meta_text('purge_org', <orgId>)         — for the final OrgDO row hard-delete RPC
  //   meta_text('purge_space', <spaceId>)
  //   meta_text('purge_descriptor', <json>)   — the space's storage descriptor (resolve creds)
  //   meta('purge_deleted', <count>)          — running count of objects deleted (progress)
  //   meta('purge_done', 1)                   — sweep finished; objects + metadata gone

  /// True iff a purge sweep is currently armed/running on this filespace.
  isPurging(): boolean {
    const r = this.sql.exec(`SELECT value FROM meta WHERE key = 'purging';`).toArray();
    return r.length > 0 && Number(r[0].value) === 1;
  }

  private metaTextGet(key: string): string | null {
    const r = this.sql.exec(`SELECT value FROM meta_text WHERE key = ?;`, key).toArray();
    return r.length ? String(r[0].value) : null;
  }

  private metaTextSet(key: string, value: string): void {
    this.sql.exec(
      `INSERT INTO meta_text (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value;`,
      key, value,
    );
  }

  private metaIntGet(key: string): number {
    const r = this.sql.exec(`SELECT value FROM meta WHERE key = ?;`, key).toArray();
    return r.length ? Number(r[0].value) : 0;
  }

  private metaIntSet(key: string, value: number): void {
    this.sql.exec(
      `INSERT INTO meta (key, value) VALUES (?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value;`,
      key, value,
    );
  }

  /// Snapshot of purge progress for the gateway's status poll. `prefix` is echoed so an operator
  /// can SEE exactly which prefix is being swept (auditable). `done` flips true once objects +
  /// metadata are gone. P-F1: `failed`/`error` report a sweep that hit a TERMINAL state (per-key
  /// delete errors that can never make progress — object-lock/retention/legal-hold/Deny) so the
  /// gateway/UI surfaces "purge failed — retry" instead of an endlessly-"purging" spinner.
  purgeStatus(): { purging: boolean; done: boolean; failed: boolean; deleted: number; prefix: string | null; error?: string } {
    const failed = this.metaIntGet("purge_failed") === 1;
    return {
      purging: this.isPurging(),
      done: this.metaIntGet("purge_done") === 1,
      failed,
      deleted: this.metaIntGet("purge_deleted"),
      prefix: this.metaTextGet("purge_prefix"),
      ...(failed ? { error: this.metaTextGet("purge_error") ?? "purge_failed" } : {}),
    };
  }

  /// Arm an async, resumable purge sweep. Called by the gateway AFTER it has (1) confirmed the
  /// space is soft-deleted, (2) owner-gated, and (3) checked the typed confirmation. `orgId`/
  /// `spaceId` are the gateway-TRUSTED values from the principal + registry; the sweep prefix is
  /// built HERE from them (never from client input). `descriptor` is the space's secret-free
  /// storage row so the sweep resolves the SAME per-space credentials the presigner uses.
  /// Idempotent: arming an already-purging space just returns its current status.
  async startPurge(input: {
    orgId: string;
    spaceId: string;
    descriptor?: SpaceStorageDescriptor | null;
  }): Promise<{ purging: boolean; prefix: string }> {
    const { orgId, spaceId } = input;
    if (!orgId || !spaceId) throw new Error("startPurge: orgId and spaceId required");
    // The EXACT, trusted prefix — identical to the presign key-confinement prefix the gateway
    // enforces (`blocks/<org>::<space>/`). Built from gateway-trusted ids only.
    const prefix = `blocks/${orgId}::${spaceId}/`;

    if (this.isPurging()) {
      return { purging: true, prefix: this.metaTextGet("purge_prefix") ?? prefix };
    }
    // Tombstone too (a purge implies the soft-delete tombstone — defense in depth so the data
    // plane refuses even mid-sweep, and so a direct DO call can't write new objects under the
    // prefix while we're deleting it).
    this.sql.exec(`INSERT INTO meta (key, value) VALUES ('deleted', 1)
      ON CONFLICT(key) DO UPDATE SET value = 1;`);
    this.metaIntSet("purging", 1);
    this.metaIntSet("purge_done", 0);
    // P-F1: clear any prior terminal-failure marker so a RE-ISSUED purge POST arms a FRESH sweep
    // that can retry (e.g. after the operator removes an object-lock/legal-hold/Deny that stalled
    // the last attempt). A clean arm must not inherit the old failure flag/message.
    this.metaIntSet("purge_failed", 0);
    this.metaTextSet("purge_error", "");
    this.metaIntSet("purge_deleted", 0);
    this.metaTextSet("purge_prefix", prefix);
    this.metaTextSet("purge_org", orgId);
    this.metaTextSet("purge_space", spaceId);
    this.metaTextSet("purge_descriptor", JSON.stringify(input.descriptor ?? null));
    // Fire the sweep on the soonest alarm. setAlarm replaces; the alarm body checks isPurging()
    // first so it co-exists with lease/snapshot/audit ticks.
    await this.ctx.storage.setAlarm(Date.now());
    return { purging: true, prefix };
  }

  /// Resolve the StorageConfig for the sweep from this DO's env + the persisted descriptor, using
  /// the SAME managed-credential-first resolution the presigner uses (decrypt managed creds first,
  /// then env `S3_*__<REF>`, fail closed on an unresolvable ref). The OrgDO stub for the managed
  /// resolver is derived from the persisted orgId.
  private async resolvePurgeConfig(): Promise<StorageConfig> {
    const descriptorJson = this.metaTextGet("purge_descriptor");
    const descriptor = descriptorJson ? (JSON.parse(descriptorJson) as SpaceStorageDescriptor | null) : null;
    const orgId = this.metaTextGet("purge_org");
    let managed: ManagedCredentialResolver | undefined;
    if (orgId && (this.env as Env).ORG_DO) {
      const orgStub = (this.env as Env).ORG_DO.get((this.env as Env).ORG_DO.idFromName(orgId));
      managed = managedCredentialResolver(this.env as Env, orgStub as unknown as Parameters<typeof managedCredentialResolver>[1]);
    }
    return resolveStorageConfigAsync(this.env as Env, descriptor, managed);
  }

  /// Run ONE page of the purge sweep: list the FIRST page under the prefix and batch-delete it. We
  /// deliberately ALWAYS list from the start (no continuation token) and delete what we see: since
  /// each step deletes the keys it just listed, the next step's "first page" is the NEXT batch, and
  /// the sweep terminates when a list returns ZERO keys. This delete-and-re-list pattern is:
  ///   - RESUMABLE: a crash mid-sweep just re-lists from the start next tick (no fragile cursor that
  ///     could skip keys as the underlying set shrinks under it).
  ///   - IDEMPOTENT: re-listing already-deleted keys returns nothing; DeleteObjects on absent keys
  ///     is a no-op. Re-running after completion deletes nothing.
  ///   - STRICTLY PREFIX-SCOPED: every list carries `prefix=` and deleteObjects re-asserts every
  ///     key is under the prefix before deleting (storage.ts) — fail closed.
  /// When the prefix is empty it finalizes (OrgDO row hard-delete + this DO's deleteAll). Re-arms
  /// the alarm while keys remain. `fetchImpl` injectable for tests (fake S3, no network).
  async purgeStep(fetchImpl?: typeof fetch): Promise<{ deletedThisStep: number; done: boolean; remaining: boolean }> {
    if (!this.isPurging()) return { deletedThisStep: 0, done: this.metaIntGet("purge_done") === 1, remaining: false };
    const prefix = this.metaTextGet("purge_prefix");
    if (!prefix) {
      // Inconsistent state — disarm rather than risk an unprefixed sweep (fail closed).
      this.metaIntSet("purging", 0);
      return { deletedThisStep: 0, done: false, remaining: false };
    }
    const config = await this.resolvePurgeConfig();

    // Always page 1 (continuationToken=null) — see the delete-and-re-list rationale above.
    const page = await listObjects(config, prefix, null, fetchImpl);

    if (page.keys.length === 0) {
      // The audit bucket is deliberately outside the data-prefix sweep. Preserve
      // recent events, including purge initiation, before deleting local metadata.
      // One bounded archive batch per tick; any R2 failure leaves the DO intact.
      if (this.env.AUDIT_BUCKET && this.auditStore.count() > 0) {
        await this.archiveAuditRing(Date.now(), { maxEvents: 0, windowMs: 0 });
        if (this.auditStore.count() > 0) {
          await this.ctx.storage.setAlarm(Date.now() + 1_000);
          return { deletedThisStep: 0, done: false, remaining: true };
        }
      }
      // Prefix is empty → finalize. Signal the OrgDO to drop the registry row, then wipe this DO.
      await this.finalizePurge();
      return { deletedThisStep: 0, done: true, remaining: false };
    }

    // deleteObjects re-asserts every key is under `prefix` (fail closed) before deleting.
    const res = await deleteObjects(config, prefix, page.keys, fetchImpl);
    const deletedThisStep = res.deleted.length;
    this.metaIntSet("purge_deleted", this.metaIntGet("purge_deleted") + deletedThisStep);

    // P-F1 (NO-PROGRESS DETECTION): we just LISTED >0 keys but DELETED 0 of them. Because the sweep
    // is delete-and-re-list (no cursor), those same keys would be re-listed every tick FOREVER —
    // and per-key S3 errors (object-lock/retention, legal hold, a scoped DeleteObject Deny) do NOT
    // throw, so the alarm body would re-arm setAlarm(Date.now()) immediately in a tight storm and
    // finalizePurge would never run. A page that lists keys but deletes NONE can never make
    // progress, so we HARD-STOP into a terminal `purge_failed` state (persist a sample of the S3
    // error codes for the operator), clearing `purging` so the alarm stops re-arming. A re-issued
    // purge POST re-arms a fresh sweep (startPurge clears purge_failed), so this is recoverable.
    if (deletedThisStep === 0) {
      this.failPurge(this.summarizePurgeErrors(res.errors, page.keys.length));
      return { deletedThisStep: 0, done: false, remaining: false };
    }

    // More may remain (this page held keys) — re-arm to continue on the next tick.
    await this.ctx.storage.setAlarm(Date.now());
    return { deletedThisStep, done: false, remaining: true };
  }

  /// P-F1: collapse the per-key DeleteObjects errors (+ how many keys were listed but undeleted)
  /// into one short, operator-readable failure string, sampling a few distinct error codes so the
  /// status poll surfaces WHY the sweep stalled (e.g. "AccessDenied"/"ObjectLockRetentionPeriod").
  private summarizePurgeErrors(errors: { key: string; code: string }[], listed: number): string {
    const codes = [...new Set(errors.map((e) => e.code).filter(Boolean))].slice(0, 5);
    const sample = codes.length ? ` (codes: ${codes.join(", ")})` : "";
    return `purge stalled: listed ${listed} key(s) under the prefix but deleted 0${sample}`;
  }

  /// P-F1: move the sweep into a TERMINAL failed state. Persists the failure + message, clears the
  /// `purging` flag (so the alarm stops re-arming and no further sweep runs), and leaves
  /// `purge_done=0`. The OrgDO row + this DO's metadata are deliberately LEFT INTACT — the objects
  /// did not delete, so wiping would orphan them. A re-issued purge POST can retry (startPurge
  /// clears `purge_failed`). NOT a throw: a thrown error in the alarm would re-arm the storm we are
  /// preventing.
  private failPurge(error: string): void {
    this.metaIntSet("purge_failed", 1);
    this.metaTextSet("purge_error", error);
    this.metaIntSet("purging", 0);
  }

  /// Finalize: remove the OrgDO registry row (hard delete), then wipe this DO's entire storage
  /// namespace (items / blocks / snapshots / grants / audit / locks / meta — everything). After
  /// deleteAll() this DO is indistinguishable from a never-created one. Best-effort ordering: the
  /// OrgDO row removal happens BEFORE the wipe so a failure there leaves the sweep state intact and
  /// resumable; once the row is gone we wipe.
  private async finalizePurge(): Promise<void> {
    const orgId = this.metaTextGet("purge_org");
    const spaceId = this.metaTextGet("purge_space");
    // P-F3 (ORDERING): the irreversible steps are OrgDO-row-removal then deleteAll(). We must NOT
    // flip `purge_done=1` before those succeed: previously a `hardDeleteSpace` throw returned with
    // `done=1` already set while the registry row + this DO's metadata still SURVIVED ("done but
    // not gone"). Keep `purging=1` (still-in-progress) through the row removal so a stalled finalize
    // reads as in-progress, not falsely done, until the metadata wipe succeeds.
    if (orgId && spaceId && (this.env as Env).ORG_DO) {
      try {
        const orgStub = (this.env as Env).ORG_DO.get((this.env as Env).ORG_DO.idFromName(orgId));
        await orgStub.hardDeleteSpace(spaceId);
      } catch {
        // The OrgDO row removal failed: leave EVERYTHING intact and STILL purging (objects are gone
        // but the registry row + metadata survive). A re-armed sweep re-finalizes (its empty-prefix
        // first step re-runs this). Do NOT mark done and do NOT wipe — an operator/retry can finish
        // the row removal. The alarm re-arms via the catch in alarm().
        throw new Error("finalizePurge: hardDeleteSpace failed");
      }
    }
    // A request already in flight can append while the cross-DO finalization
    // awaits. Revisit the archive before wiping any such late audit rows.
    if (this.env.AUDIT_BUCKET && this.auditStore.count() > 0) throw new Error("purge audit drain pending");
    // Keep the resumable state until the atomic SQLite wipe succeeds. Marking
    // done first would strand the metadata if deleteAll throws. The gateway uses
    // the absent OrgDO registry row as the durable completion signal afterwards.
    // Older compatibility dates do not make deleteAll cancel alarms. Cancel
    // explicitly, but restore retryability if the atomic wipe itself fails.
    await this.ctx.storage.deleteAlarm();
    this.backupState.assertOrdinary();
    try { await this.ctx.storage.deleteAll(); }
    catch (error) {
      await this.ctx.storage.setAlarm(Date.now() + MAINTENANCE_RETRY_MS);
      throw error;
    }
  }

  // ---- cache helpers --------------------------------------------------------

  private cachePut(item: Item): void {
    if (this.itemCache.size >= FilespaceDO.CACHE_MAX) this.itemCache.clear();
    this.itemCache.set(item.id, item);
  }

  /// NamespaceStore also calls this for changed parent directory timestamps.
  /// Listings themselves are always read fresh.
  private invalidate(id: string): void {
    this.itemCache.delete(id);
  }

  // ---- namespace API (RPC) --------------------------------------------------

  /// Backward-compatible: returns the first page of children as a flat array.
  /// Prefer listPage() for huge directories.
  async enumerate(parent: string): Promise<Item[]> {
    return this.ns.list(parent).items;
  }

  /// Paginated directory listing with an opaque keyset cursor. O(pageSize) even
  /// for a directory with millions of children — never loads the whole tree.
  async listPage(parent: string, limit?: number, cursor?: string | null): Promise<Page<Item>> {
    return this.ns.list(parent, limit, cursor);
  }

  async childCount(parent: string): Promise<number> {
    return this.ns.childCount(parent);
  }

  /// N-F3: childCount with the SAME per-folder read ACL as getItemFor/listPageFor. A principal who
  /// cannot READ `parent` must not learn it exists or how many children it has — `_count` was gated
  /// only by the fs:read SCOPE, leaking existence + child count of an ungranted folder. Returns null
  /// (gateway → 404, INVISIBLE) when the principal can't read the parent; otherwise the count.
  /// Full-access principals (owner/admin or whole-filespace grant) short-circuit with no extra work.
  async childCountFor(principal: AclPrincipal, parent: string): Promise<number | null> {
    if (this.hasFullAccess(principal)) return this.ns.childCount(parent);
    return canAccess(this.acl, principal, parent, "read").allow ? this.ns.childCount(parent) : null;
  }

  async getItem(id: string): Promise<Item | null> {
    const cached = this.itemCache.get(id);
    if (cached) return cached;
    const item = this.ns.getItem(id);
    if (item && !item.deleted) this.cachePut(item);
    return item && !item.deleted ? item : null;
  }

  /// Create/replace an item. Optional `expectedVersion` enables optimistic
  /// concurrency — a mismatched version returns a typed `{ conflict }` result
  /// (Worker → 409), the project-file anti-clobber guard (SPEC §5.5).
  ///
  /// We return a discriminated result rather than throw, because thrown error
  /// classes don't survive the DO RPC serialization boundary (the .name is lost).
  async createItem(
    parent: string,
    name: string,
    isDir: boolean,
    size: number,
    opts?: { expectedVersion?: number; etag?: string | null; owner?: string },
  ): Promise<{ item: Item } | { forbidden: true; reason: string } | { invalidParent: true } | { capacity: true } | { conflict: true; message: string; expected: number; actual: number } | { locked: true; heldBy: string; reason: string } | { invalidName: true; message: string; reason: string }> {
    this.assertNotDeleted();
    const destination = this.ns.getItem(parent);
    if (!destination || destination.deleted || !destination.isDir) return {invalidParent:true};
    // Lock gate (audit B5): a create that would OVERWRITE an existing, LIVE item exclusively
    // leased by another principal is rejected (createItem upserts a live name). Audit B17: the
    // collision is resolved by `(parent, name)` now (opaque ids), not a path-derived id. A fresh
    // create or a recreate over a tombstone is unaffected. Returned (not thrown) so it crosses
    // the DO-RPC boundary as a typed result.
    let nameForLookup: string;
    try {
      nameForLookup = canonicalizeName(name);
    } catch {
      // The name is invalid; let put() raise the typed InvalidNameError below.
      nameForLookup = name;
    }
    const liveSibling = this.ns.liveSiblingByName(parent, nameForLookup);
    if (liveSibling) {
      if (this.contentReadOnly(liveSibling.id)) return {forbidden:true,reason:"file is read-only"};
      const heldBy = this.lockedByOther(liveSibling.id, opts?.owner);
      if (heldBy) return { locked: true, heldBy, reason: "held-by-other" };
    }
    try {
      const { untombstoned, ...item } = this.ctx.storage.transactionSync(()=>this.ns.put(parent, name, isDir, size, opts));
      // Audit B17: with OPAQUE ids a recreate over a tombstone gets a BRAND-NEW id, so the old
      // grants (bound to the dead id) can never resurrect — the grant-resurrection hazard is
      // retired by construction. We still defensively clear grants on the rare deleted→live
      // transition of the SAME id (explicit-id callers / snapshot restore reusing an id).
      if (untombstoned) this.acl.deleteGrantsForInodes([item.id]);
      this.cachePut(item);
      return { item };
    } catch (e) {
      if (isMetadataCapacityError(e)) return {capacity:true};
      if (e instanceof ConflictError) {
        return { conflict: true, message: e.message, expected: e.expected, actual: e.actual };
      }
      // Audit B17/B18: a rejected name (NFC validation) is a 400, returned (not thrown) so it
      // survives the DO-RPC boundary as a typed result.
      if (e instanceof InvalidNameError) {
        return { invalidName: true, message: e.message, reason: e.reason };
      }
      throw e;
    }
  }

  async deleteItem(id: string, expectedVersion?: number, owner?: string, openHandle?: string): Promise<{ deleted: boolean; reason?: string } | { locked: true; heldBy: string; reason: string }> {
    this.assertNotDeleted();
    // Lock gate (audit B5): a delete of an exclusively-leased item by anyone other
    // than the holder is rejected — an editor's open project file can't be deleted
    // out from under them. Mirrors restoreSnapshot's lock predicate. Returned (not
    // thrown) so it crosses the DO-RPC boundary as a typed result.
    const heldBy = this.lockedByOther(id, owner);
    if (heldBy) return { locked: true, heldBy, reason: "held-by-other" };
    const res = this.ctx.storage.transactionSync(() => this.ns.remove(id, expectedVersion, owner, openHandle));
    // Finding I3 (grant-resurrection) is now handled at RECREATE-time (see
    // createItem), NOT here: a deleted inode's grants must SURVIVE so the
    // change-feed tombstone delivery (N-F1) can walk to them and notify every
    // principal who could read the item PRE-deletion — including a principal whose
    // grant is ON the deleted node itself. The grant is cleared if/when the same
    // path-deterministic id is recreated, which is where resurrection could occur.
    // Live reads during the deleted window are already denied (tombstoned inode →
    // getInode null → canAccess denies), so the surviving grant leaks no access.
    this.invalidate(id);
    return res;
  }

  /// Recursive subtree delete (SPEC: a folder delete removes its contents). Used
  /// for the bulk-op path: tombstones `id` + every live descendant and ROLLS the
  /// delete up into ONE live-activity event (a "large-delete" when the collapsed
  /// count meets the bulk threshold, else a single event). The per-item audit
  /// records still chain normally at the gateway; this only feeds the LIVE feed.
  /// Returns the count of inodes deleted (so the gateway can report it).
  async deleteSubtree(id: string, actor: string, owner = actor, openHandle?: string): Promise<{ deleted: number; kind: "single" | "bulk" } | { locked: true; heldBy: string; lockedItem: string; reason: string } | {forbidden:true;reason:string}> {
    this.assertNotDeleted();
    // Lock gate (audit B5): refuse a recursive delete if ANY inode in the subtree is
    // exclusively leased by someone other than the actor — a bulk delete must not
    // silently destroy a teammate's open, locked project file. `actor` is the
    // authenticated principal (the same owner the lock route records). Returned (not
    // thrown) so it crosses the DO-RPC boundary as a typed result.
    const root = this.ns.getItem(id);
    if (id === "root" || root?.parent === null) return {forbidden:true,reason:"The filespace root cannot be deleted"};
    for (const itemId of this.ns.subtreeIds(id)) {
      if (this.contentReadOnly(itemId)) return {forbidden:true,reason:"The subtree contains a read-only file"};
      if (!this.ns.deleteSharingAllowed(itemId, Date.now(), owner, openHandle)) return {forbidden:true,reason:"An open handle does not share delete access"};
      const heldBy = this.lockedByOther(itemId, owner);
      if (heldBy) return { locked: true, heldBy, lockedItem: itemId, reason: "held-by-other" };
    }
    const { deleted } = this.ctx.storage.transactionSync(() => this.ns.removeSubtree(id, owner, openHandle));
    // Finding I3 (grant-resurrection) is now handled at RECREATE-time (see
    // createItem), NOT here: the grants on every tombstoned inode in the subtree
    // must SURVIVE so the change-feed tombstone delivery (N-F1) can walk to them and
    // notify a grant-holder whose grant is ON the deleted subtree (the deleted-root
    // or any node within it), not only on a surviving ancestor. Each path-
    // deterministic id's grant is cleared if/when that id is recreated. NOTE: an
    // inode that is deleted and NEVER recreated retains its (now-inert, invisible)
    // grant rows — a minor, acceptable storage leak: the inode is invisible to live
    // reads, and the rows are cleared if/when the path is reused.
    for (const child of deleted) this.invalidate(child);
    const { kind } = await this.recordDeleteActivity({ path: id, actor, count: deleted.length });
    return { deleted: deleted.length, kind };
  }

  /// Count of live inodes in the subtree rooted at `id` (inclusive). Cheap probe
  /// the gateway can use to decide single-vs-bulk BEFORE issuing a delete.
  async subtreeCount(id: string): Promise<number> {
    return this.ns.subtreeIds(id).length;
  }

  async setBasicInfoFor(principal: AclPrincipal, id: string,
    patch: {createdAt?: number; modifiedAt?: number; accessedAt?: number; changedAt?: number; fileAttributes?: number; expectedVersion: number; fence?: number}, owner?: string) {
    this.assertNotDeleted();
    if (!patch || typeof patch !== 'object' || !Number.isSafeInteger(patch.expectedVersion) || patch.expectedVersion < 1) return {error:'invalid_metadata'};
    for (const key of ['createdAt','modifiedAt','accessedAt','changedAt'] as const) {
      const value = patch[key];
      if (value !== undefined && (!Number.isSafeInteger(value) || value < -11644473600000 || value > 253402300799999)) return {error:'invalid_metadata'};
    }
    if (patch.fileAttributes !== undefined && (!Number.isSafeInteger(patch.fileAttributes) || patch.fileAttributes < 0 || patch.fileAttributes > 0x2127 || (patch.fileAttributes & ~0x2127) !== 0)) return {error:'unsupported_attributes'};
    if (patch.fence !== undefined && (!Number.isSafeInteger(patch.fence) || patch.fence < 1)) return {error:'invalid_metadata'};
    const existing = this.ns.getItem(id);
    if (!existing) return {error:'not_found'};
    if (!(existing.deleted ? this.checkOpenAccess(principal,id,'write',owner) : canAccess(this.acl,principal,id,'write')).allow) return {error:'forbidden'};
    if (this.lockedByOther(id,owner) || (patch.fence !== undefined && !this.locks.validateFence(id,patch.fence,owner))) return {error:'locked'};
    try {
      const item = this.ctx.storage.transactionSync(() => this.ns.setBasicInfo(id,patch,patch.expectedVersion,existing.deleted));
      this.invalidate(id);
      if (!item.deleted) this.cachePut(item);
      return {item};
    } catch (error) {
      if (error instanceof ConflictError) return {error:'version_conflict',actual:error.actual};
      throw error;
    }
  }

  /// Audit B17 — rename/move an item (`PATCH /items/:id {parent?, name?}`). With opaque immutable
  /// ids this touches ONLY `(parent, name)` of the one row; descendants are unaffected. Enforces
  /// the lock gate (a rename of an exclusively-leased item by another principal is rejected) and
  /// returns typed results across the DO-RPC boundary (locked / invalid_name / name_collision /
  /// conflict / not_found). The owning subtree ACL/visibility is re-checked at the gateway.
  async renameItem(
    id: string,
    opts: { parent?: string | null; name?: string; expectedVersion?: number; owner?: string; openHandle?: string; replace?: RenameReplacement; principal?: AclPrincipal },
  ): Promise<
    | { item: Item }
    | { locked: true; heldBy: string; reason: string }
    | { invalidName: true; reason: string }
    | { nameCollision: true; reason: string }
    | { invalidMove: true; reason: string }
    | { conflict: true; message: string; expected: number; actual: number }
    | { notFound: true }
    | { forbidden: true }
    | { invalidMutation: string; reason: string }
  > {
    this.assertNotDeleted();
    if (opts.expectedVersion !== undefined && (!Number.isSafeInteger(opts.expectedVersion) || opts.expectedVersion < 1)) return {invalidMutation:"invalid_version",reason:"Invalid source version"};
    if (opts.replace && (typeof opts.replace.id !== "string" || !opts.replace.id || !Number.isSafeInteger(opts.replace.expectedVersion) || opts.replace.expectedVersion < 1 || opts.expectedVersion === undefined)) return {invalidMutation:"invalid_replacement",reason:"Replacement requires source and destination versions"};
    if (opts.parent !== undefined && typeof opts.parent !== "string") return {invalidMutation:"invalid_parent",reason:"Invalid destination parent"};
    const existing = this.ns.getItem(id);
    if (!existing || existing.deleted) return { notFound: true };
    // Recheck all ACLs in the same synchronous turn as the mutation. In
    // particular, create permission on the folder is not delete permission on
    // an explicitly protected destination file.
    if (opts.principal && (!canAccess(this.acl,opts.principal,id,"rename").allow ||
        !canAccess(this.acl,opts.principal,opts.parent ?? existing.parent ?? "root","create").allow ||
        (opts.replace && !canAccess(this.acl,opts.principal,opts.replace.id,"delete").allow))) return {forbidden:true};
    if (opts.replace && !opts.principal) return {forbidden:true};
    const destinationHeldBy = opts.replace ? this.lockedByOther(opts.replace.id, opts.owner) : null;
    if (destinationHeldBy) {
      const lease = this.locks.status(opts.replace!.id);
      // Atomic replacement changes the name binding, not the inode. A foreign
      // writer may keep its lease and continue using the retained old inode if
      // its writable open explicitly shares delete. Ordinary locks and SMB
      // byte-range locks still exclude replacement.
      const retainedWriter = lease.granted && lease.mode === "exclusive" && lease.purpose === "publication" && lease.heldBy === destinationHeldBy
        && this.rangeLocks.heldByOther(opts.replace!.id, opts.owner) === null
        && this.openHandles.hasWritableDeleteShareHandle(opts.replace!.id, destinationHeldBy);
      if (!retainedWriter) return {locked:true,heldBy:destinationHeldBy,reason:"held-by-other"};
    }
    // Lock gate (B5): the moved item itself must not be leased by another principal.
    const heldBy = this.lockedByOther(id, opts?.owner);
    if (heldBy) return { locked: true, heldBy, reason: "held-by-other" };
    try {
      const item = this.ctx.storage.transactionSync(() => this.ns.rename(id, { parent: opts.parent, name: opts.name, expectedVersion: opts.expectedVersion, replace: opts.replace, owner: opts.owner, openHandle: opts.openHandle }));
      if (opts.replace) this.invalidate(opts.replace.id);
      this.invalidate(id);
      this.cachePut(item);
      return { item };
    } catch (e) {
      if (e instanceof InvalidNameError) return { invalidName: true, reason: e.reason };
      if (e instanceof NameCollisionError) return { nameCollision: true, reason: e.message };
      if (e instanceof InvalidMoveError) return { invalidMove: true, reason: e.message };
      if (e instanceof NamespaceMutationError) return {invalidMutation:e.code,reason:e.message};
      if (e instanceof ConflictError) return { conflict: true, message: e.message, expected: e.expected, actual: e.actual };
      throw e;
    }
  }

  /// Replace a file's content-addressed block map (large-file write path).
  ///
  /// `expectedVersion` (audit B4): optimistic concurrency on the content-commit path.
  /// When supplied for an existing item whose stored version differs, `ns.setBlockMap`
  /// throws ConflictError → the route returns 409 (the anti-clobber guard). It also
  /// enforces the lock gate (B5): a live exclusive lease held by a DIFFERENT owner
  /// rejects the commit with a typed "locked" conflict (mirrors restoreSnapshot).
  async setBlockMap(
    itemId: string,
    blocks: Block[],
    opts?: { etag?: string | null; expectedVersion?: number; owner?: string; fence?: number; principal?: AclPrincipal; storageIdentity?: string; blockSize?: number },
  ): Promise<Item | { invalidManifest: true; reason: string } | { locked: true; heldBy: string; reason: string } | { forbidden: true; reason: string } | { conflict: true; message: string; expected: number; actual: number }> {
    this.assertNotDeleted();
    const initial=this.ns.getItem(itemId);
    if (initial?.deleted && (!opts?.principal || !opts.owner || opts.expectedVersion === undefined
      || !this.openHandles.hasAccess(itemId,opts.owner,OPEN_HANDLE_WRITE))) return {forbidden:true,reason:"retained inode requires its writable open handle"};
    if (this.contentReadOnly(itemId)) return {forbidden:true,reason:"file is read-only"};
    try { validateBlockManifest(blocks); }
    catch (e) { if (e instanceof InvalidManifestError) return { invalidManifest: true, reason: e.message }; throw e; }
    if (opts?.expectedVersion !== undefined && (!Number.isSafeInteger(opts.expectedVersion) || opts.expectedVersion < 0)) {
      return { invalidManifest: true, reason: "expectedVersion must be a nonnegative safe integer" };
    }
    if (opts?.principal && (this.env as Env & {STORAGE_VERIFY_UPLOADS?: string}).STORAGE_VERIFY_UPLOADS !== "0") {
      try {
        if (!opts.storageIdentity || this.objectsNeedingVerification(blocks, opts.storageIdentity).length) {
          return { invalidManifest: true, reason: "objects require storage verification before publication" };
        }
      } catch (error) {
        if (error instanceof InvalidManifestError) return {invalidManifest:true,reason:error.message};
        throw error;
      }
    }
    // Conflicts are RETURNED (not thrown) so they survive the DO-RPC boundary as a
    // typed result — the same pattern createItem/restoreSnapshot use (an Error
    // subclass loses its class identity across the boundary, surfacing as a raw 500).
    const heldBy = this.lockedByOther(itemId, opts?.owner);
    if (heldBy) return { locked: true, heldBy, reason: "held-by-other" };
    // When the item is leased by THIS owner and a fence is presented, it must be the
    // live fence (defeats a zombie writer whose lease expired and was reassigned).
    if (opts?.fence !== undefined && !this.locks.validateFence(itemId, opts.fence, opts.owner)) {
      return { locked: true, heldBy: opts?.owner ?? "(stale-fence)", reason: "fence-stale" };
    }
    // The gateway supplies the authenticated principal, never a body field.
    // Check every reference in this same SQL turn as publication so an ACL or
    // object-owner change cannot race between validation and the commit.
    if (opts?.principal) {
      const reason = this.manifestAccessError(opts.principal, itemId, blocks, opts.owner);
      if (reason) return {forbidden:true,reason};
    }
    try {
      const item = this.ctx.storage.transactionSync(() =>
        this.ns.setBlockMap(itemId, blocks, { etag: opts?.etag, expectedVersion: opts?.expectedVersion, blockSize: opts?.blockSize, allowRetained: !!this.ns.getItem(itemId)?.deleted }));
      if (item.deleted) this.invalidate(itemId); else this.cachePut(item);
      return item;
    } catch (e) {
      if (e instanceof InvalidManifestError) return { invalidManifest: true, reason: e.message };
      if (e instanceof ConflictError) {
        return { conflict: true, message: e.message, expected: e.expected, actual: e.actual };
      }
      throw e;
    }
  }

  async commitFileDelta(principal: AclPrincipal, itemId: string, delta: FileDelta, owner: string, identity?: string) {
    this.assertNotDeleted();
    try {
      validateFileDelta(delta);
      const blocks = fileVerificationBlocks(delta.blocks);
      const reason = this.manifestAccessError(principal,itemId,blocks,owner);
      if (reason) return {error:'forbidden',reason};
      const heldBy = this.lockedByOther(itemId,owner);
      if (heldBy || !this.locks.validateFence(itemId,delta.fence,owner)) return {error:'locked',reason:'lease is not current'};
      if ((this.env as Env & {STORAGE_VERIFY_UPLOADS?:string}).STORAGE_VERIFY_UPLOADS !== '0'
        && (!identity || this.objectsNeedingVerification(blocks,identity).length)) return {error:'objects_unverified'};
      const itemBefore=this.ns.getItem(itemId);
      this.ctx.storage.transactionSync(() => applyFileDelta(this.sql,itemId,delta,() => this.ns.nextSeq(), bytes => this.capacity.admit(bytes),!!itemBefore?.deleted));
      const item = this.ns.getItem(itemId)!;
      if (item.deleted) this.invalidate(itemId); else this.cachePut(item);
      return {item};
    } catch (error) {
      if (error instanceof ManifestLayoutError) return {error:'manifest_layout',reason:error.message};
      if (error instanceof FileDeltaConflict) return {error:'version_conflict',expected:delta.expectedVersion,actual:error.actual};
      if (error instanceof InvalidManifestError) return {error:'invalid_manifest',reason:error.message};
      throw error;
    }
  }

  /** Version-bound keyset pages. ACL, item version and blocks share one SQL turn. */
  async fileManifestExtentFor(principal: AclPrincipal, itemId: string, offset: number, length: number, contentVersion?: string, owner?: string) {
    this.assertNotDeleted();
    if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 1 || length > 32*1024*1024
      || !Number.isSafeInteger(offset+length) || (contentVersion !== undefined && (typeof contentVersion !== 'string' || contentVersion.length > 256))) return {error:'invalid_range'};
    if (!this.checkOpenAccess(principal,itemId,'read',owner).allow) return {error:'forbidden'};
    const item = this.ns.getItem(itemId);
    if (!item || (item.deleted && !owner) || item.isDir) return {error:'not_found'};
    if (contentVersion && contentVersion !== item.contentVersion) return {error:'version_conflict',actual:item.contentVersion};
    if (offset >= item.size) return {format:2,item,firstBlockIndex:0,blocks:[],nextOffset:null};
    // One predecessor seek includes an overlapping block without scanning the
    // entire prefix. The following query is bounded by both bytes and rows.
    const first = this.sql.exec('SELECT offset,length FROM blocks WHERE item_id=? AND offset<=? ORDER BY offset DESC LIMIT 1;',itemId,offset).toArray()[0];
    if (!first || Number(first.offset)+Number(first.length)<=offset) return {error:'invalid_manifest'};
    const rows = this.sql.exec('SELECT * FROM blocks WHERE item_id=? AND offset>=? AND offset<? ORDER BY offset LIMIT 1025;',itemId,first.offset,Math.min(item.size,offset+length)).toArray();
    const more = rows.length > 1024; if (more) rows.pop();
    const layout = Number(this.sql.exec('SELECT manifest_block_size FROM items WHERE id=?;',itemId).one().manifest_block_size);
    // Fixed layouts have O(1) index recovery. Legacy variable layouts require
    // an index-only prefix count; the response and materialization stay bounded.
    const firstBlockIndex = layout > 0 ? Number(first.offset)/layout : Number(this.sql.exec('SELECT COUNT(*) AS n FROM blocks WHERE item_id=? AND offset<?;',itemId,first.offset).one().n);
    let end = Number(first.offset);
    const blocks = rows.map(r => ({chunkIdx:Number(r.chunk_idx),blockIdx:Number(r.block_idx),blockHash:String(r.block_hash),objectKey:String(r.object_key),offset:Number(r.offset),length:Number(r.length)}));
    for (const block of blocks) { if (block.offset !== end || block.length<=0 || block.length>item.size-end) return {error:'invalid_manifest'}; end+=block.length; }
    if (!Number.isSafeInteger(firstBlockIndex) || (!more && end<Math.min(item.size,offset+length))) return {error:'invalid_manifest'};
    return {format:2,item,firstBlockIndex,blocks,nextOffset:more ? end : null};
  }

  async fileManifestRangeFor(principal: AclPrincipal, itemId: string, after: number, limit: number, version?: number, owner?: string) {
    this.assertNotDeleted();
    if (!Number.isSafeInteger(after) || after < -1 || !Number.isSafeInteger(limit) || limit < 1 || limit > 1024
      || (version !== undefined && (!Number.isSafeInteger(version) || version < 1))) return {error:'invalid_range'};
    if (!this.checkOpenAccess(principal,itemId,'read',owner).allow) return {error:'forbidden'};
    const item = this.ns.getItem(itemId);
    if (!item || (item.deleted && !owner) || item.isDir) return {error:'not_found'};
    if (version !== undefined && version !== item.version) return {error:'version_conflict',actual:item.version};
    const rows = this.sql.exec('SELECT * FROM blocks WHERE item_id=? AND offset>? ORDER BY offset LIMIT ?;',itemId,after,limit+1).toArray();
    const more = rows.length > limit; if (more) rows.pop();
    const blocks = rows.map(r => ({chunkIdx:Number(r.chunk_idx),blockIdx:Number(r.block_idx),blockHash:String(r.block_hash),objectKey:String(r.object_key),offset:Number(r.offset),length:Number(r.length)}));
    return {format:1,item,blocks,cursor:more ? blocks[blocks.length-1].offset : null};
  }

  /** DOS content protection is independent of ACLs, including owner/admin ACL
   * bypass. Metadata-write authority can clear it, but cannot publish through it. */
  private contentReadOnly(id: string): boolean {
    const item = this.ns.getItem(id);
    return !!item && !item.isDir && ((item.fileAttributes ?? 0) & 1) !== 0;
  }

  private manifestAccessError(principal: AclPrincipal, itemId: string, blocks: Block[], owner?: string): string | null {
    const target = this.ns.getItem(itemId);
    if (!target || !this.checkOpenAccess(principal,itemId,"write",owner).allow) return "item is not writable";
    if (this.contentReadOnly(itemId)) return "file is read-only";
    const keys = [...new Set(blocks.map(block => block.objectKey))];
    const admin = ["owner","admin","space_admin"].includes(principal.orgRole ?? "");
    const readDecisions = new Map<string,Decision>();
    for (let i=0;i<keys.length;i+=256) {
      // New uploads dominate sequential writes. Resolve all claim/catalog rows
      // in one indexed join instead of three queries plus ACL walks per block.
      const rows = this.sql.exec(`SELECT j.value AS object_key,k.block_hash,c.principal_id,c.item_id,c.expires_at
        FROM json_each(?) j LEFT JOIN known_objects k ON k.object_key=j.value
        LEFT JOIN block_upload_claims c ON c.object_key=j.value;`,JSON.stringify(keys.slice(i,i+256)));
      for (const row of rows) {
        if (row.block_hash !== null) {
          let readable=false;
          for (const inodeId of this.ns.readOwnersForObjectKey(String(row.object_key), owner ? {owner, requiredMask:OPEN_HANDLE_READ} : undefined)) {
            let decision=readDecisions.get(inodeId);
            if (!decision) { decision=this.checkOpenAccess(principal,inodeId,"read",owner);readDecisions.set(inodeId,decision); }
            if (decision.allow) { readable=true;break; }
          }
          if (!readable) return "block is not currently readable";
        } else if (row.principal_id !== null) {
          // A claim declared for THIS inode is usable by any principal with write on it
          // (target write was checked above); other claims stay bound to their principal.
          const sameInode = row.item_id === itemId;
          if ((!sameInode && row.principal_id !== principal.id) || Number(row.expires_at) <= Date.now()
            || (!sameInode && !(row.item_id === null && admin))) return "block requires this item's upload authorization";
        } else if (!admin) return "block requires this item's upload authorization";
      }
    }
    return null;
  }

  async checkManifestUploadAccess(principal: AclPrincipal, itemId: string, blocks: Block[], owner?: string): Promise<{error:string} | {allowed:true}> {
    this.assertNotDeleted(); validateBlockManifest(blocks);
    const error = this.manifestAccessError(principal,itemId,blocks,owner);
    return error ? {error} : {allowed:true};
  }

  private objectsNeedingVerification(blocks: ObjectVerificationInput[], identity: string): ObjectVerificationInput[] {
    const unique = new Map(blocks.map(block => [block.objectKey, block]));
    const pending: ObjectVerificationInput[] = [];
    const entries = [...unique.values()];
    for (let i=0;i<entries.length;i+=256) {
      const batch = entries.slice(i,i+256);
      const verified = new Map(this.sql.exec(`SELECT object_key,block_hash,plaintext_size FROM verified_objects
        WHERE storage_identity=?1 AND object_key IN (SELECT value FROM json_each(?2));`, identity, JSON.stringify(batch.map(b=>b.objectKey)))
        .toArray().map(row=>[String(row.object_key),row]));
      for (const block of batch) {
        const record = verified.get(block.objectKey);
        if (record && (record.block_hash !== block.blockHash || Number(record.plaintext_size) !== block.length)) {
          throw new InvalidManifestError("verified immutable object identity or logical length cannot change");
        }
        if (!record) pending.push(block);
      }
    }
    return pending;
  }

  async unverifiedObjects(blocks: Block[], identity: string): Promise<ObjectVerificationInput[]> {
    this.assertNotDeleted(); validateBlockManifest(blocks);
    blocks.forEach(validateObjectVerificationInput);
    return this.objectsNeedingVerification(blocks, identity);
  }

  /** Binding-only RPC. Config comes from the gateway's trusted registry, never a
   * request body. Bounded batches limit work and pending receipt metadata. Receipt
   * publication follows every successful byte/checksum verification; final commit
   * independently rechecks current ACL, lease, CAS and receipt identity. */
  async verifyObjects(blocks: ObjectVerificationInput[], config: StorageConfig): Promise<{verified: number} | {error: string; reason?: string}> {
    this.assertNotDeleted();
    try {
      const verified = await verifyStorageObjects(config, blocks, fetch, nativeVerificationBucket(this.env as Env, config));
      return await this.recordVerifiedObjects(verified,storageIdentity(config));
    } catch (error) { if (isMetadataCapacityError(error)) throw error; return {error:"object_verification_failed", reason:error instanceof ObjectVerificationError ? error.reason : "storage request failed"}; }
  }

  /** Trusted binding-only receipt ingestion. The gateway supplies ONLY results
   * from its own storage verification, never request-body assertions. Keeping
   * stateless HEAD/GET work outside this coordination object lets independent
   * upload requests progress without sharing its outbound connection budget. */
  async recordVerifiedObjects(verified: VerifiedObject[], identity: string): Promise<{verified: number} | {error: string; reason?: string}> {
    try {
      this.assertNotDeleted();
      if (!Array.isArray(verified) || verified.length > 128 || typeof identity !== "string" || !identity || identity.length > 8192) {
        throw new ObjectVerificationError("invalid verification receipt batch");
      }
      verified.forEach(validateVerifiedObject);
      this.capacity.admit(65_536 + verified.length * 4096);
      this.ctx.storage.transactionSync(() => {
        for (const block of verified) {
          this.sql.exec(`INSERT OR IGNORE INTO verified_objects
            (storage_identity,object_key,block_hash,ciphertext_size,plaintext_size,verified_at) VALUES (?,?,?,?,?,?);`,
            identity,block.objectKey,block.blockHash,block.ciphertextSize,block.length,Date.now());
          // Another verification can finish while this RPC awaits storage. Never
          // replace its immutable receipt with a different logical interpretation.
          const receipt=this.sql.exec(`SELECT block_hash,ciphertext_size,plaintext_size FROM verified_objects
            WHERE storage_identity=? AND object_key=?;`,identity,block.objectKey).one();
          if (receipt.block_hash !== block.blockHash || Number(receipt.ciphertext_size) !== block.ciphertextSize
            || Number(receipt.plaintext_size) !== block.length) throw new ObjectVerificationError("immutable verification receipt conflict");
        }
      });
      return {verified:verified.length};
    } catch (error) { if (isMetadataCapacityError(error)) throw error; return {error:"object_verification_failed", reason:error instanceof ObjectVerificationError ? error.reason : "storage request failed"}; }
  }

  /// Returns the holder if `itemId` carries a live EXCLUSIVE lease owned by someone
  /// other than `owner` (the lock-enforcement gate, audit B5). Mirrors the predicate
  /// restoreSnapshot already uses so all mutation chokepoints agree.
  private lockedByOther(itemId: string, owner?: string): string | null {
    const st = this.locks.status(itemId);
    if (st.granted && st.heldBy && st.heldBy !== owner) {
      return st.heldBy;
    }
    return this.rangeLocks.heldByOther(itemId, owner);
  }

  async getBlockMap(itemId: string): Promise<Block[]> {
    return this.ns.getBlockMap(itemId);
  }

  /// Reverse lookup for the permissions seam: object key → owning inode, so the
  /// gateway can ACL-check a presign target before minting (SPEC §4.4).
  /// (Used by the permissions agent during the integration round.)
  async getInodeForObjectKey(objectKey: string): Promise<string | null> {
    // Refuse the presign-resolve path on a tombstoned space (defense in depth; the gateway 410s
    // first). A deleted space must not be presignable even on a direct DO call.
    this.assertNotDeleted();
    return this.ns.itemForObjectKey(objectKey);
  }

  private objectReadAccess(principal: AclPrincipal, objectKey: string, owner?: string): { inodeId: string | null; decision: Decision } {
    let denied: Decision = { allow: false, effectiveLevel: null, reason: "object not in namespace" };
    const handles=owner ? {owner,requiredMask:OPEN_HANDLE_READ} : undefined;
    for (const inodeId of this.ns.readOwnersForObjectKey(objectKey,handles)) {
      const decision = this.checkOpenAccess(principal, inodeId, "read", owner);
      if (decision.allow) return { inodeId, decision };
      denied = decision;
    }
    return { inodeId: null, decision: denied };
  }

  /// The authority and CURRENT ACL are evaluated together. A supplied read
  /// itemId is never evidence of ownership; only committed namespace rows count.
  async checkObjectReadAccess(principal: AclPrincipal, objectKey: string, owner?: string): Promise<{ inodeId: string | null; decision: Decision }> {
    this.assertNotDeleted();
    return this.objectReadAccess(principal, objectKey, owner);
  }

  private prepareObjectWrite(principal: AclPrincipal, key: string, itemId?: string, owner?: string): { inodeId: string | null; error: string | null } {
    const retired=this.sql.exec("SELECT 1 FROM object_reclamation WHERE object_key=? AND state!='quarantined';",key).toArray()[0];
    if (retired) return {inodeId:null,error:'object_retired'};
    const declared = itemId ? this.ns.getItem(itemId) : null;
    if (itemId && (!declared || declared.isDir || this.contentReadOnly(itemId) || !this.checkOpenAccess(principal,itemId,"write",owner).allow)) {
      return { inodeId: null, error: "forbidden" };
    }
    // Existing objects may only be retried under a checksum-bound PUT. Every
    // presigner derives the signed SHA-256 header from this canonical key; the
    // bucket rejects different bytes, including through an older minted URL.
    const known = this.sql.exec(`SELECT block_hash FROM known_objects WHERE object_key=?;`, key).toArray()[0];
    if (known) {
      const hash = key.slice(key.lastIndexOf("/") + 1);
      if (/^[0-9a-f]{64}$/.test(hash) && known.block_hash === hash) {
        for (const inodeId of this.ns.readOwnersForObjectKey(key,owner?{owner,requiredMask:OPEN_HANDLE_WRITE}:undefined)) {
          if (!this.contentReadOnly(inodeId) && this.checkOpenAccess(principal,inodeId,"write",owner).allow) return { inodeId: itemId ?? inodeId, error: null };
        }
      }
      return { inodeId: null, error: "forbidden" };
    }
    if (!itemId && !["owner", "admin", "space_admin"].includes(principal.orgRole ?? "")) {
      return { inodeId: null, error: "item_required" };
    }
    this.capacity.admit();
    const now = Date.now(), claim = this.sql.exec(`SELECT item_id,principal_id,expires_at FROM block_upload_claims WHERE object_key=?;`, key).toArray()[0];
    // Expiry requires the original uploader to renew its commit authorization;
    // it does NOT make already-uploaded bytes available for another identity to
    // claim. Retain the compact ownership record until publication/space purge.
    // Takeover rule: a claim declared for a concrete inode is shared by every
    // principal with WRITE on that same inode (verified above via `declared`).
    // The object key is the ciphertext hash bound to item+index+content, the PUT
    // is signed with the SHA-256 header + If-None-Match, and receipts are
    // immutable, so a co-writer cannot substitute bytes. A claim for a different
    // inode, or an admin claim with no inode, stays bound to its principal.
    const sameInode = !!claim && itemId !== undefined && claim.item_id === itemId;
    if (claim && !sameInode && (String(claim.principal_id) !== principal.id || claim.item_id !== (itemId ?? null))) {
      return { inodeId: null, error: "forbidden" };
    }
    this.sql.exec(`INSERT INTO block_upload_claims (object_key,item_id,principal_id,expires_at) VALUES (?,?,?,?)
      ON CONFLICT(object_key) DO UPDATE SET item_id=excluded.item_id,principal_id=excluded.principal_id,expires_at=excluded.expires_at;`,
      key, itemId ?? null, principal.id, now + 7 * 24 * 60 * 60 * 1000);
    return { inodeId: itemId ?? null, error: null };
  }

  async prepareObjectUpload(principal: AclPrincipal, key: string, itemId?: string, owner?: string): Promise<{ inodeId: string | null; error: string | null }> {
    this.assertNotDeleted();
    return this.prepareObjectWrite(principal, key, itemId, owner);
  }

  /// Validate one batch without two Worker→DO round trips per block. Every key
  /// still has its own namespace/ACL check, within one consistent SQL turn.
  async checkObjectAccessBatch(
    principal: AclPrincipal,
    entries: { key: string; method: string; itemId?: string }[],
    owner?: string,
  ): Promise<(string | null)[]> {
    this.assertNotDeleted();
    if (entries.length > 256) throw new Error("too many keys");
    return entries.map(entry => {
      if (!["GET", "HEAD", "PUT"].includes(entry.method)) return "method_not_allowed";
      if (entry.method === "PUT") return this.prepareObjectWrite(principal, entry.key, entry.itemId, owner).error;
      const read = this.objectReadAccess(principal, entry.key, owner);
      return read.decision.allow ? null : read.decision.reason === "object not in namespace" ? "object_not_in_namespace" : "forbidden";
    });
  }

  /// Change feed / sync anchor, paginated for clients that have been offline long.
  async changesSince(seq: number, limit?: number): Promise<{ anchor: number; items: Item[]; cursor: number | null }> {
    return this.ns.changesSince(seq, limit);
  }

  /// Bulk seed — for benchmarks/tests of large-directory pagination.
  /// FINDING A: `bulkCreate` clamps `count` to BULK_SEED_MAX so this RPC can never
  /// wedge the single-threaded DO regardless of how it's reached. The gateway ALSO
  /// rejects (400) above the bound before calling, so a hostile request is surfaced
  /// cleanly rather than silently truncated.
  async seedChildren(parent: string, prefix: string, count: number, isDir = false): Promise<number> {
    const n = this.ctx.storage.transactionSync(() => this.ns.bulkCreate(parent, prefix, count, isDir));
    this.itemCache.clear();
    return n;
  }

  // ---- ACL (permissions) — evaluated IN the DO, sync over SQLite ------------
  // The gateway passes the resolved Principal (incl. groupIds from OrgDO). We
  // never reimplement the evaluator — we call multiuser's canAccess() against
  // this DO's grant store + inode tree (multiuser-INTEGRATION.md §3b/§4).

  private rawAclStore() {
    return { getInode: (id: string) => this.acl.getRawInode(id), grantsForInode: (id: string) => this.acl.grantsForInode(id) };
  }

  private openActionMask(action: Action): number | null {
    if (action === "read") return OPEN_HANDLE_READ;
    if (action === "write") return OPEN_HANDLE_WRITE;
    if (action === "delete") return OPEN_HANDLE_DELETE;
    return null;
  }

  /** Evaluate current ACLs along the inode's original parent chain. Tombstones
   * use raw inode rows so deletion does not erase the ACL context of an open fd. */
  private currentInodeAccess(principal: AclPrincipal, inodeId: string, action: Action, deleted: boolean): Decision {
    const revoked=this.acl.isRevokedPrincipal(principal.type,principal.id)
      || ((principal.type==="user" || principal.type==="service_account")
        && (this.acl.isRevokedPrincipal("user",principal.id) || this.acl.isRevokedPrincipal("service_account",principal.id)));
    if (revoked) return {allow:false,effectiveLevel:null,reason:"principal was revoked"};
    return canAccess(deleted ? this.rawAclStore() : this.acl, principal, inodeId, action);
  }

  async beginOpenFor(principal: AclPrincipal, inodeId: string, owner: string,
    input: { handleId: string; accessMask: number; shareMask: number; ttlMs: number;
      stream?: { name: string; required: boolean } }): Promise<{ granted: boolean; expiresAt?: number; reason?: string;
        stream?: { exists: boolean; size: number } }> {
    this.assertNotDeleted();
    let streamLookup: { name: string; required: boolean } | undefined;
    if (input.stream !== undefined) {
      if (!input.stream || typeof input.stream !== "object" || Array.isArray(input.stream)
        || typeof input.stream.name !== "string" || typeof input.stream.required !== "boolean"
        || input.stream.name.length > 4096) return {granted:false,reason:"invalid"};
      try {
        streamLookup = {name:canonicalizeName(input.stream.name),required:input.stream.required};
      } catch {
        return {granted:false,reason:"invalid"};
      }
    }
    const item = this.ns.getItem(inodeId), now = Date.now();
    if (!item || item.deleted) return {granted:false,reason:"not_found"};
    if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1 || input.ttlMs > OPEN_HANDLE_MAX_TTL_MS
      || !Number.isSafeInteger(input.accessMask) || input.accessMask < 0 || (input.accessMask & ~OPEN_HANDLE_MASK) !== 0
      || !Number.isSafeInteger(input.shareMask) || input.shareMask < 0 || (input.shareMask & ~OPEN_HANDLE_MASK) !== 0) {
      return {granted:false,reason:"invalid"};
    }
    if (!canAccess(this.acl,principal,inodeId,"read").allow) return {granted:false,reason:"forbidden"};
    if ((input.accessMask & OPEN_HANDLE_WRITE) !== 0 && (this.contentReadOnly(inodeId) || !canAccess(this.acl,principal,inodeId,"write").allow)) return {granted:false,reason:"forbidden"};
    if ((input.accessMask & OPEN_HANDLE_DELETE) !== 0 && !canAccess(this.acl,principal,inodeId,"delete").allow) return {granted:false,reason:"forbidden"};
    let streamResult: {exists:boolean;size:number}|undefined;
    // Preserve the Windows open ordering: authorize first, then let the open
    // table report sharing/capacity/idempotency outcomes, and only then inspect
    // stream metadata. A required miss removes this exact grant in the same
    // SQLite transaction so a failed CREATE never leaves a remote open behind.
    const admitted = this.ctx.storage.transactionSync(() => {
      const result = this.openHandles.acquire({
        handleId:input.handleId,owner,inodeId,accessMask:input.accessMask,shareMask:input.shareMask,expiresAt:now+input.ttlMs,
      },now);
      if (!result.granted || !streamLookup) return result;
      const stream = readStreamManifest(this.sql,inodeId,streamLookup.name,0,0);
      if (streamLookup.required && !stream.exists) {
        const closed = this.openHandles.close(input.handleId,owner);
        if (!closed.closed) throw new Error("failed to roll back missing-stream open handle");
        return {granted:false as const,reason:"stream_not_found"};
      }
      streamResult = {exists:stream.exists,size:stream.exists?stream.size:0};
      return result;
    });
    await this.armAlarm();
    return admitted.granted
      ? {granted:true,expiresAt:admitted.handle.expiresAt,...(streamLookup ? {stream:streamResult!} : {})}
      : {granted:false,reason:admitted.reason};
  }

  /** Return one bounded directory page under a transient open description. The
   * temporary handle participates in the normal two-way share checks, then is
   * removed in the same SQLite transaction so the snapshot never pins an inode. */
  async directorySnapshotFor(principal: AclPrincipal, inodeId: string, owner: string,
    input: { handleId: string; accessMask: number; shareMask: number; ttlMs: number }): Promise<{
      granted: boolean; reason?: string; directory?: Item; items?: Item[]
    }> {
    this.assertNotDeleted();
    if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs < 1 || input.ttlMs > OPEN_HANDLE_MAX_TTL_MS
      || !Number.isSafeInteger(input.accessMask) || (input.accessMask !== 0 && input.accessMask !== OPEN_HANDLE_READ)
      || !Number.isSafeInteger(input.shareMask) || input.shareMask < 0 || (input.shareMask & ~OPEN_HANDLE_MASK) !== 0
      || typeof input.handleId !== "string" || !input.handleId || input.handleId.length > 128
      || typeof inodeId !== "string" || !inodeId || inodeId.length > 4096) {
      return {granted:false,reason:"invalid"};
    }
    const now = Date.now();
    const result = this.ctx.storage.transactionSync(() => {
      const directory = this.ns.getItem(inodeId);
      if (!directory || directory.deleted) return {granted:false as const,reason:"not_found"};
      // Do not inspect or return children until the caller has read permission
      // on the directory itself. Keep authorization in the transaction with the
      // temporary share admission so the listing reflects one local state.
      if (!this.currentInodeAccess(principal,inodeId,"read",false).allow) {
        return {granted:false as const,reason:"forbidden"};
      }
      const opened = this.openHandles.acquire({
        handleId:input.handleId,owner,inodeId,accessMask:input.accessMask,shareMask:input.shareMask,expiresAt:now+input.ttlMs,
      },now);
      if (!opened.granted) return {granted:false as const,reason:opened.reason};
      // A retry of an existing persistent handle must never turn that durable
      // open into a transient one by closing it at the end of this operation.
      if (opened.reused) return {granted:false as const,reason:"handle_conflict"};
      const closeTemporary = () => {
        const closed = this.openHandles.close(input.handleId,owner);
        if (!closed.closed || closed.inodeId !== inodeId) throw new Error("failed to close transient directory snapshot handle");
      };
      if (!directory.isDir) {
        closeTemporary();
        return {granted:false as const,reason:"not_directory"};
      }
      const page = this.listPageForSync(principal,inodeId,500,null);
      if (page.cursor !== null) {
        closeTemporary();
        return {granted:false as const,reason:"snapshot_too_large"};
      }
      closeTemporary();
      return {granted:true as const,directory,items:page.items};
    });
    // No snapshot handle survives the transaction, so its temporary expiry must
    // not change the alarm for any persistent open descriptions.
    return result;
  }

  async renewOpenFor(principal: AclPrincipal, owner: string, handleId: string, ttlMs: number, canWrite = true): Promise<{granted:boolean;expiresAt?:number;reason?:string}> {
    this.assertNotDeleted();
    const now=Date.now();
    const result=this.ctx.storage.transactionSync(()=>this.renewOpenSync(principal,owner,handleId,ttlMs,canWrite,now));
    if (result.granted) await this.armAlarm();
    return result;
  }

  /** Renew many device-bound handles as one SQLite transaction/alarm update.
   * Oversized batches are rejected wholesale to keep a direct DO caller bounded. */
  async renewOpenBatchFor(principal: AclPrincipal, owner: string, handleIds: string[], ttlMs: number, canWrite = true): Promise<{handles:Array<{handleId:string;granted:boolean;expiresAt?:number;reason?:string}>}> {
    this.assertNotDeleted();
    if (!Array.isArray(handleIds) || handleIds.length > 128) return {handles:[]};
    const now=Date.now();
    const results=this.ctx.storage.transactionSync(()=>handleIds.map(handleId=>({handleId,...this.renewOpenSync(principal,owner,handleId,ttlMs,canWrite,now)})));
    if (results.some(result=>result.granted)) await this.armAlarm();
    return {handles:results};
  }

  private renewOpenSync(principal: AclPrincipal, owner: string, handleId: string, ttlMs: number, canWrite: boolean, now: number): {granted:boolean;expiresAt?:number;reason?:string} {
    const handle=this.openHandles.get(handleId);
    if (!handle) return {granted:false,reason:"not_found"};
    if (handle.owner!==owner) return {granted:false,reason:"forbidden"};
    if (handle.expiresAt<=now) return {granted:false,reason:"expired"};
    if (!Number.isSafeInteger(ttlMs) || ttlMs<1 || ttlMs>OPEN_HANDLE_MAX_TTL_MS) return {granted:false,reason:"invalid"};
    if ((handle.accessMask & (OPEN_HANDLE_WRITE|OPEN_HANDLE_DELETE))!==0 && !canWrite) return {granted:false,reason:"forbidden"};
    const item=this.ns.getItem(handle.inodeId);
    if (!item) return {granted:false,reason:"not_found"};
    if (!this.currentInodeAccess(principal,handle.inodeId,"read",item.deleted).allow
      || ((handle.accessMask&OPEN_HANDLE_WRITE)!==0 && (this.contentReadOnly(handle.inodeId)||!this.currentInodeAccess(principal,handle.inodeId,"write",item.deleted).allow))
      || ((handle.accessMask&OPEN_HANDLE_DELETE)!==0 && !this.currentInodeAccess(principal,handle.inodeId,"delete",item.deleted).allow)) return {granted:false,reason:"forbidden"};
    const result=this.openHandles.renew(handleId,owner,now+ttlMs,now);
    return result.renewed?{granted:true,expiresAt:result.handle.expiresAt}:{granted:false,reason:result.reason};
  }

  async closeOpenFor(owner: string, handleId: string): Promise<{closed:boolean;reason?:string}> {
    const result=this.ctx.storage.transactionSync(()=>{
      const closed=this.openHandles.close(handleId,owner);
      if (closed.closed && closed.inodeId) this.ns.reclaimUnopenedPayload(closed.inodeId);
      return closed;
    });
    if (!result.closed) return {closed:false,reason:result.reason};
    if (result.inodeId) this.invalidate(result.inodeId);
    await this.armAlarm();
    return {closed:true};
  }

  /** Live paths keep their existing ACL semantics. A tombstone is reachable only
   * through this owner's active handle and a fresh ACL decision. */
  checkOpenAccess(principal: AclPrincipal, inodeId: string, action: Action, owner?: string): Decision {
    const item=this.ns.getItem(inodeId), mask=this.openActionMask(action);
    // Preserve the existing live-path ACL evaluator's behavior for missing IDs
    // (notably owner/admin short-circuits); retained-open rules apply only to a
    // row that is actually tombstoned.
    if (!item || !item.deleted) return canAccess(this.acl,principal,inodeId,action);
    if ((action!=="read" && action!=="write") || !owner || mask===null || !this.openHandles.hasAccess(inodeId,owner,mask)) {
      return {allow:false,effectiveLevel:null,reason:"no matching open handle"};
    }
    if (action==="write" && this.contentReadOnly(inodeId)) return {allow:false,effectiveLevel:null,reason:"file is read-only"};
    return this.currentInodeAccess(principal,inodeId,action,true);
  }

  /** Snapshot restore may recreate a deleted destination. This preflight keeps
   * normal tombstone writes handle-gated while allowing the existing raw ACL
   * evaluator to authorize this one recreation workflow. Per-item restore
   * permissions are still enforced again by SnapshotAccess inside restoreSnapshot. */
  checkSnapshotRestoreAccess(principal: AclPrincipal, inodeId: string): Decision {
    const item=this.ns.getItem(inodeId);
    if (!item || !item.deleted) return canAccess(this.acl,principal,inodeId,"write");
    return this.currentInodeAccess(principal,inodeId,"write",true);
  }

  /// The single ACL chokepoint the gateway calls before a mutation / mint / lock.
  async checkAccess(principal: AclPrincipal, inodeId: string, action: Action, owner?: string): Promise<Decision> {
    const item=this.ns.getItem(inodeId);
    if (item?.deleted && (action==="read" || action==="write")) return this.checkOpenAccess(principal,inodeId,action,owner);
    return canAccess(this.acl, principal, inodeId, action);
  }

  /** A filespace key is needed to decrypt even a single authorized folder. Possession
   * of this shared key does not grant object URLs: those retain their per-inode checks. */
  checkFilespaceRead(principal: AclPrincipal): Decision {
    const root = canAccess(this.acl, principal, "root", "read");
    if (root.allow) return root;
    for (const inode of this.acl.matchingLiveInodes(principal)) {
      const decision = canAccess(this.acl, principal, inode.id, "read");
      if (decision.allow) return decision;
    }
    return { allow: false, effectiveLevel: null, reason: "no readable filespace grant" };
  }

  /** Explicit subtree entry points avoid exposing unreadable ancestor folders. Disjoint
   * grants remain separate choices; clients must not silently treat one as the whole space. */
  mountRootsFor(principal: AclPrincipal): { id: string; name: string; mountAsRoot: boolean }[] {
    if (canAccess(this.acl, principal, "root", "read").allow) return [{ id: "root", name: this.ns.getItem("root")?.name ?? "", mountAsRoot: false }];
    return this.acl.matchingLiveInodes(principal).filter(inode => {
      if (!inode.isDir || !canAccess(this.acl, principal, inode.id, "read").allow) return false;
      const parent = this.acl.getInode(inode.id)?.parentId;
      return !parent || !canAccess(this.acl, principal, parent, "read").allow;
    }).map(({ id, name, mountAsRoot }) => ({ id, name, mountAsRoot }));
  }

  /// Spaces-list summary for one caller: does it hold ANY effective live grant (direct or via group,
  /// any level), is it a folder admin (an effective admin-level grant), and the filespace's logical
  /// used bytes (sum of live file sizes) when `withUsage`. One RPC per space; no cross-DO calls.
  spaceSummaryFor(principal: AclPrincipal, withUsage: boolean): { hasAccess: boolean; folderAdmin: boolean; usedBytes: number | null } {
    const hasAccess = this.checkFilespaceRead(principal).allow;
    let folderAdmin = false;
    if (hasAccess) {
      if (canAccess(this.acl, principal, "root", "manage_acl").allow) folderAdmin = true;
      else {
        for (const inode of this.acl.matchingLiveInodes(principal)) {
          if (canAccess(this.acl, principal, inode.id, "manage_acl").allow) { folderAdmin = true; break; }
        }
      }
    }
    let usedBytes: number | null = null;
    // COST: a full SUM(size) scan of the items table per call (O(items) in this DO). Candidate for a
    // maintained counter. Only run when the caller will actually receive the field: org owner/admin/
    // space_admin, or a member with read access to the whole filespace (root). A folder-scoped member
    // must not learn the filespace-wide byte total.
    const seesTotal = principal.orgRole === "owner" || principal.orgRole === "admin" || principal.orgRole === "space_admin"
      || canAccess(this.acl, principal, "root", "read").allow;
    if (withUsage && seesTotal) {
      usedBytes = Number(this.sql.exec(`SELECT COALESCE(SUM(size), 0) AS b FROM items WHERE deleted = 0 AND is_dir = 0;`).one().b);
    }
    return { hasAccess, folderAdmin, usedBytes };
  }

  // ---- CHANGE D: per-folder ACL enforcement on metadata READS ---------------
  // The documented model is default-deny / "invisible": no grant on (or above) an
  // inode ⇒ the principal must not even see it exists. getItem/listPage/changesSince
  // previously returned the WHOLE tree to any fs:read holder regardless of grants,
  // leaking names/sizes/structure. We now filter these reads against the principal's
  // ACL. The filter runs INSIDE the DO over local SQLite (the inode tree + grants),
  // so it issues ZERO cross-DO RPCs per item — the gateway resolves the AclPrincipal
  // ONCE per request (the N+1 memo) and hands it in here.

  /// O(1) broad-access short-circuit: org owner/admin (and any principal holding a
  /// live grant on the SPACE ROOT, which covers the whole filespace by inheritance)
  /// see EXACTLY today's result with NO per-item work. This keeps the common case
  /// (admins + whole-filespace editors) identical and avoids any O(items) walk.
  private hasFullAccess(principal: AclPrincipal): boolean {
    if (principal.orgRole === "owner" || principal.orgRole === "admin") return true;
    // A live read+ grant on "root" inherits down the entire tree, so the principal
    // can read everything — same outcome as today, decided in one canAccess walk.
    return canAccess(this.acl, principal, "root", "read").allow;
  }

  /// Build a memoized "can this principal READ inode X" predicate. Walks the parent
  /// chain ONCE per distinct inode and caches the boolean, so filtering a page of
  /// siblings that share ancestors stays ~O(items + depth) rather than O(items×depth).
  /// Semantics match canAccess(..,"read") exactly (group-union, expiry, inherit).
  private makeReadPredicate(principal: AclPrincipal): (inodeId: string) => boolean {
    const memo = new Map<string, boolean>();
    return (inodeId: string): boolean => {
      const cached = memo.get(inodeId);
      if (cached !== undefined) return cached;
      // canAccess walks inodeId→root; cache the result keyed on the leaf. (We keep
      // it simple/correct by delegating to the pure evaluator rather than threading
      // a partial walk through the memo — page sizes are bounded and reads are sync.)
      const allow = canAccess(this.acl, principal, inodeId, "read").allow;
      memo.set(inodeId, allow);
      return allow;
    };
  }

  /// getItem with ACL: returns null (gateway → 404, INVISIBLE) if the principal
  /// cannot read the target, instead of leaking existence with a 403.
  async getItemFor(principal: AclPrincipal, id: string, owner?: string): Promise<Item | null> {
    const item = this.ns.getItem(id);
    if (!item) return null;
    if (item.deleted) {
      if (!owner || !this.openHandles.hasAnyFor(id,owner) || !this.currentInodeAccess(principal,id,"read",true).allow) return null;
    } else if (!this.hasFullAccess(principal) && !canAccess(this.acl, principal, id, "read").allow) return null;
    // AAPL readdir enrichment (v14): attach rsrcForkSize/finderInfo from streams.
    const enriched = { ...item };
    this.ns.enrichStreams([enriched]);
    return enriched;
  }

  // ---- named streams / xattrs (v14). Same per-item ACL as the item itself:
  //      read to list/get, write to put/delete. Absent item / no access → null so
  //      existence never leaks (gateway maps to 404). ----------------------------

  private streamRead(principal: AclPrincipal, id: string, owner?: string): boolean {
    return this.checkOpenAccess(principal,id,"read",owner).allow;
  }
  private streamWrite(principal: AclPrincipal, id: string, owner?: string): boolean {
    return !this.contentReadOnly(id) && this.checkOpenAccess(principal,id,"write",owner).allow;
  }

  async listStreamsFor(principal: AclPrincipal, id: string, owner?: string): Promise<StreamInfo[] | null> {
    const item = this.ns.getItem(id);
    if (!item || (item.deleted && !owner)) return null;
    return this.streamRead(principal, id, owner) ? this.ns.listStreams(id) : null;
  }

  async getStreamFor(principal: AclPrincipal, id: string, name: string, owner?: string): Promise<Uint8Array | null> {
    const item = this.ns.getItem(id);
    if (!item || (item.deleted && !owner) || !this.streamRead(principal, id, owner)) return null;
    return this.ns.getStream(id, name);
  }

  async streamManifestFor(principal: AclPrincipal, id: string, name: string, offset=0, length=16*1024*1024, owner?: string) {
    this.assertNotDeleted();
    const item=this.ns.getItem(id);
    if (!item || (item.deleted && !owner) || !this.streamRead(principal,id,owner)) return null;
    return readStreamManifest(this.sql,id,name,offset,length);
  }

  async commitStreamManifestFor(principal: AclPrincipal,id:string,name:string,delta:StreamDelta,owner:string,identity?:string) {
    this.assertNotDeleted();
    try { validateStreamDelta(delta); } catch { return {error:'invalid_manifest' as const}; }
    this.capacity.admit(65_536 + delta.blocks.length * 4096);
    if (name === 'AFP_AfpInfo') return {error:'finder_info_requires_inline' as const};
    const item=this.ns.getItem(id);
    if (!item || (item.deleted && !this.openHandles.hasAccess(id,owner,OPEN_HANDLE_WRITE))) return {error:'not_found' as const};
    const blocks=streamVerificationBlocks(delta.blocks);
    const denied=this.manifestAccessError(principal,id,blocks,owner);
    if (denied) return {error:'forbidden' as const};
    const heldBy=this.lockedByOther(id,owner);
    if (heldBy || !this.locks.validateFence(id,delta.fence,owner)) return {error:'locked' as const,reason:heldBy?'held-by-other':'fence-stale'};
    try {
      if ((this.env as Env & {STORAGE_VERIFY_UPLOADS?:string}).STORAGE_VERIFY_UPLOADS !== '0'
        && (!identity || this.objectsNeedingVerification(blocks,identity).length)) return {error:'objects_unverified' as const};
      const result=this.ctx.storage.transactionSync(()=>commitStreamDelta(this.sql,id,name,delta,this.ns.nextSeq(),item.deleted));
      if (item.deleted) this.invalidate(id); else this.itemCache.delete(id); return result;
    } catch (error) {
      if (error instanceof StreamConflictError) return {error:'conflict' as const,actual:error.actual};
      if (error instanceof InvalidManifestError) return {error:'invalid_manifest' as const,reason:error.message};
      throw error;
    }
  }

  async putStreamFor(
    principal: AclPrincipal, id: string, name: string, data: Uint8Array, plaintextSize: number, owner?: string, fence?: number,
  ): Promise<{ size: number } | { invalidSize: true } | { usesManifest: true } | { tooLarge: true; maxBytes: number } | { denied: true } | { notFound: true } | { locked: true; heldBy: string; reason?: string }> {
    if (data.byteLength > MAX_STREAM_BODY_BYTES) return { tooLarge: true, maxBytes: MAX_STREAM_BODY_BYTES };
    if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0 || plaintextSize > MAX_STREAM_BODY_BYTES) return {invalidSize:true};
    const item = this.ns.getItem(id);
    if (!item || (item.deleted && !owner)) return { notFound: true };
    if (!this.streamWrite(principal, id, owner)) return { denied: true };
    const heldBy = this.lockedByOther(id, owner ?? principal.id);
    if (heldBy) return { locked: true, heldBy };
    if (fence !== undefined && !this.locks.validateFence(id, fence, owner ?? principal.id)) return { locked: true, heldBy: owner ?? principal.id, reason: "fence-stale" };
    const existing=readStreamManifest(this.sql,id,name,0,0);
    if (existing.exists && !existing.legacy) return {usesManifest:true};
    const res = this.ctx.storage.transactionSync(()=>this.ns.putStream(id, name, data, plaintextSize, item.deleted));
    if (item.deleted) this.invalidate(id); else this.itemCache.delete(id);
    return res ? { size: res.size } : { notFound: true };
  }

  async deleteStreamFor(
    principal: AclPrincipal, id: string, name: string, owner?: string, fence?: number,
  ): Promise<{ deleted: boolean } | { denied: true } | { notFound: true } | { locked: true; heldBy: string; reason?: string }> {
    const item = this.ns.getItem(id);
    if (!item || (item.deleted && !owner)) return { notFound: true };
    if (!this.streamWrite(principal, id, owner)) return { denied: true };
    const heldBy = this.lockedByOther(id, owner ?? principal.id);
    if (heldBy) return { locked: true, heldBy };
    if (fence !== undefined && !this.locks.validateFence(id, fence, owner ?? principal.id)) return { locked: true, heldBy: owner ?? principal.id, reason: "fence-stale" };
    const deleted = this.ctx.storage.transactionSync(()=>this.ns.deleteStream(id, name, item.deleted));
    if (item.deleted) this.invalidate(id); else this.itemCache.delete(id);
    return { deleted };
  }

  /// listPage with ACL: excludes children the principal cannot read/list. CRITICAL
  /// pagination correctness — the `cursor` returned is still the DO's keyset cursor
  /// over the UNDERLYING scan (ns.list decides it), so the next page advances past
  /// the same underlying rows even though filtering may drop some. A page can come
  /// back with fewer (or zero) items and a non-null cursor; that is correct.
  async listPageFor(
    principal: AclPrincipal,
    parent: string,
    limit?: number,
    cursor?: string | null,
  ): Promise<Page<Item>> {
    return this.listPageForSync(principal,parent,limit,cursor);
  }

  /** Synchronous ACL-filtered listing core shared with transactional snapshots. */
  private listPageForSync(principal: AclPrincipal,parent: string,limit?: number,cursor?: string | null): Page<Item> {
    const page = this.ns.list(parent,limit,cursor);
    // AAPL readdir-attr enrichment (v14): populate rsrcForkSize/finderInfo so the
    // SMB mount can pack directory entries without a per-file stream probe.
    this.ns.enrichStreams(page.items);
    if (this.hasFullAccess(principal)) return page;
    const canRead = this.makeReadPredicate(principal);
    // Filter items but PRESERVE page.cursor verbatim (keyset position over the scan).
    return { items: page.items.filter((it) => canRead(it.id)), cursor: page.cursor };
  }

  /// N-F1: a TOMBSTONE-AWARE read predicate for DELETION events. `makeReadPredicate` delegates to
  /// `canAccess`, whose store (`DoAclStore.getInode`) hides tombstoned items — so a deleted item
  /// evaluates as "inode not found" → not readable → the deletion is DROPPED for every non-full-
  /// access principal, and their client diverges permanently (it never learns the item is gone).
  ///
  /// A deletion must reach every principal who could PREVIOUSLY read the item. We evaluate that
  /// against the item's PRE-deletion position by walking the RAW items parent chain (via
  /// `getRawInode`, which ignores the deleted flag) so the walk survives a RECURSIVE subtree delete
  /// that tombstoned the parent too: we find the nearest ancestor carrying a matching live grant,
  /// ignoring `deleted` for the walk. Reuses the SAME pure evaluator (`canAccess`) over a store
  /// whose `getInode` is the tombstone-IGNORING `getRawInode`, so group-union / inheritance / expiry
  /// semantics are identical to a live read — just over the pre-deletion tree. A principal with NO
  /// grant anywhere up the (pre-deletion) chain still gets nothing (no over-delivery).
  private makeTombstoneReadPredicate(principal: AclPrincipal): (inodeId: string) => boolean {
    const memo = new Map<string, boolean>();
    // A thin store view that resolves inodes IGNORING tombstones, so the evaluator can walk the
    // full pre-deletion ancestor chain. grantsForInode is unchanged (grants are the same table).
    const rawStore = {
      getInode: (id: string) => this.acl.getRawInode(id),
      grantsForInode: (id: string) => this.acl.grantsForInode(id),
    };
    return (inodeId: string): boolean => {
      const cached = memo.get(inodeId);
      if (cached !== undefined) return cached;
      const allow = canAccess(rawStore, principal, inodeId, "read").allow;
      memo.set(inodeId, allow);
      return allow;
    };
  }

  /// changesSince with ACL: excludes changed items the principal cannot read.
  /// CRITICAL sync-anchor correctness — `anchor` (currentSeq) and `cursor` reflect
  /// the underlying SCAN position from ns.changesSince, NOT the filtered subset, so
  /// the client never skips a change it should still receive and the cursor still
  /// advances past filtered-out rows.
  ///
  /// N-F1: a DELETION event (a tombstoned change item) is evaluated against the item's PRE-deletion
  /// position via the tombstone-aware predicate, so a principal who could read the item still
  /// receives its tombstone (otherwise their client never learns it's gone and diverges forever).
  /// Live (non-deleted) change items use the ordinary live-read predicate.
  ///
  /// DOC NOTE (intentional, not a bug): a grant ADDED mid-sync does NOT backfill items whose
  /// `updated_seq` is below the client's cursor until those items next change — the change feed is
  /// keyed on updated_seq, not on ACL membership. Clients should RE-LIST a subtree when its ACL
  /// changes to pick up items that became visible without otherwise changing.
  async changesSinceFor(
    principal: AclPrincipal,
    seq: number,
    limit?: number,
  ): Promise<{ anchor: number; items: Item[]; cursor: number | null; visibility: string }> {
    const raw = this.ns.changesSince(seq, limit);
    // Membership/role changes and grant expiry also invalidate unchanged items.
    const expired = Number(this.sql.exec(`SELECT COALESCE(MAX(expires_at),0) AS expiry FROM grants WHERE expires_at > 0 AND expires_at <= ?;`, Date.now()).one().expiry);
    const visibility = JSON.stringify([this.visibilityGeneration(), expired, principal.type, principal.id,
      principal.orgRole ?? null, [...(principal.groupIds ?? [])].sort()]);
    const feed = { ...raw, visibility };
    if (this.hasFullAccess(principal)) return feed;
    const canReadLive = this.makeReadPredicate(principal);
    const canReadTombstone = this.makeTombstoneReadPredicate(principal);
    const items = feed.items.filter((it) =>
      it.deleted ? canReadTombstone(it.id) : canReadLive(it.id),
    );
    return { anchor: feed.anchor, items, cursor: feed.cursor, visibility };
  }

  /** Re-evaluate inside the mutation's synchronous storage turn. Gateway checks
   * are UX/audit gates only; a revoked/moved authority cannot race this write. */
  grantAccessFor(actor: AclPrincipal, input: GrantInput, protectedPrincipal: boolean): { id: string } | { error: string } {
    if (this.acl.isRevokedPrincipal(input.principalType, input.principalId)) return { error: "invalid_principal" };
    if (input.level === "admin" && this.acl.isDisabledAuthority(input.principalType, input.principalId)) return { error: "invalid_principal" };
    const policy = grantMutationPolicy(this.acl, actor, input, protectedPrincipal);
    if ("error" in policy) return policy;
    const source = policy.authority;
    const existingAuthority = !source && input.level === "admin"
      ? this.acl.findGrants(input.inodeId, input.principalType, input.principalId)
        .find(row => row.level === "admin" && !row.authorityGrantId && !row.authorityInodeId && isGrantLive(this.acl, row))
      : undefined;
    const expiresAt = source?.expiresAt
      ? Math.min(input.expiresAt || source.expiresAt, source.expiresAt) : input.expiresAt;
    const g: AclGrant = {
      ...input, id: existingAuthority?.id ?? `grant-${crypto.randomUUID()}`, grantedByMemberId: actor.id,
      grantedAt: Date.now(), expiresAt: expiresAt ?? null,
      authorityGrantId: source?.id ?? null, authorityInodeId: source?.inodeId ?? null,
    };
    // Setting a level replaces this tuple, so lowering edit to read really works.
    // Preserve a still-admin authority while adjusting its settings. Demotion or
    // revoke removes that id, invalidating grants issued under it.
    revokePrincipal(this.acl, input.inodeId, input.principalType, input.principalId);
    this.acl.putGrant(g);
    return { id: g.id };
  }

  revokeAccessFor(actor: AclPrincipal, inodeId: string, principalType: GrantInput["principalType"], principalId: string, protectedPrincipal: boolean): { revoked: number } | { error: string } {
    const policy = grantMutationPolicy(this.acl, actor, { inodeId, principalType, principalId }, protectedPrincipal);
    if ("error" in policy) return policy;
    return { revoked: revokePrincipal(this.acl, inodeId, principalType, principalId) };
  }

  revokeDeletedAclPrincipal(type: GrantInput["principalType"], id: string): void {
    this.acl.revokeDeletedPrincipal(type, id);
  }

  retireUserDelegation(userId: string): void {
    // A restored account needs a fresh explicit delegation; old source ids must
    // never regain authority merely because an account is reactivated.
    // Persist the barrier first: a grant request admitted before deactivation
    // may arrive after retirement. Both user/service-account aliases share it.
    this.scheduleChangeHint();
    this.sql.exec(`INSERT OR IGNORE INTO disabled_acl_authorities VALUES (?);`, userId);
    this.sql.exec(`DELETE FROM grants WHERE principal_id=? AND principal_type IN ('user','service_account') AND level='admin';`, userId);
  }

  reactivateUserDelegation(userId: string): void {
    this.scheduleChangeHint();
    this.sql.exec(`DELETE FROM disabled_acl_authorities WHERE principal_id=?;`, userId);
  }

  accessManagementFor(actor: AclPrincipal, protectedPrincipalIds: string[] = []) {
    const global = isOrgAdmin(actor.orgRole);
    const protectedIds = new Set(protectedPrincipalIds);
    const roots = global ? [{ inodeId: "root", name: "Filespace", path: "/" }]
      : this.acl.allGrants().filter(g => g.level === "admin" && principalMatches(g, actor)
        && isGrantLive(this.acl, g) && this.acl.getInode(g.inodeId)?.type === "folder"
        && canAccess(this.acl, actor, g.inodeId, "manage_acl").allow)
        .filter((g, i, rows) => rows.findIndex(row => row.inodeId === g.inodeId) === i)
        .map(g => ({ inodeId: g.inodeId, name: this.ns.getItem(g.inodeId)!.name, path: `/${this.ns.getItem(g.inodeId)!.name}` }));
    const grants = this.acl.allGrants().filter(g => this.acl.getInode(g.inodeId)
      && (global || canAccess(this.acl, actor, g.inodeId, "manage_acl").allow))
      .map(g => {
        const names: string[] = [];
        let current: string | null = g.inodeId;
        const seen = new Set<string>();
        while (current && current !== "root" && seen.size < 4096 && !seen.has(current)) {
          seen.add(current);
          const node = this.ns.getItem(current);
          if (!node || node.deleted) break;
          names.unshift(node.name);
          if (roots.some(root => root.inodeId === current)) break;
          current = node.parent;
        }
        const policy = grantMutationPolicy(this.acl, actor, g, protectedIds.has(g.principalId));
        // Delegation lineage is enforcement data, not directory metadata. Do not
        // expose an authority inode/grant above this caller's visible subtree.
        return { id: g.id, inodeId: g.inodeId, principalType: g.principalType,
          principalId: g.principalId, level: g.level, mountAsRoot: !!g.mountAsRoot,
          expiresAt: g.expiresAt ?? null, inodePath: `/${names.join('/')}`,
          canModify: !("error" in policy), active: isGrantLive(this.acl, g) };
      });
    return { canManageAccess: roots.length > 0, canDelegateAdmin: global,
      canManageWorkspace: actor.orgRole === "owner" || actor.orgRole === "admin", roots, grants };
  }

  listManagedFoldersFor(actor: AclPrincipal, parent: string, cursor?: string | null) {
    if (!canAccess(this.acl, actor, parent, "manage_acl").allow) return null;
    const page = this.ns.list(parent, 200, cursor);
    return { ...page, items: page.items.filter(item => item.isDir && !item.deleted
      && canAccess(this.acl, actor, item.id, "manage_acl").allow) };
  }

  /// Grant an ACL on a subtree. Caller (gateway) must have already verified the
  /// principal holds `admin`/`manage_acl` on the target (it does so via checkAccess).
  async grantAccess(input: GrantInput, grantedByMemberId: string): Promise<{ id: string }> {
    const g = grantAcl(this.acl, input, grantedByMemberId);
    return { id: g.id };
  }

  /// Sync an externally-minted grant (e.g. one OrgDO wrote on invite-redeem) into
  /// THIS space's enforcement store, PRESERVING its id so the two stores share one
  /// key (idempotent re-sync; revoke parity). The gateway calls this after a scoped
  /// invite redeem so `canAccess` at mint time actually sees the redeemed grant
  /// (multiuser-INTEGRATION.md §5). Returns `synced:false` if the target inode is
  /// not (yet) in this space's namespace — the grant stays dormant until it is.
  async syncGrant(grant: AclGrant): Promise<{ synced: boolean; id: string; reason?: string }> {
    if (!this.acl.getInode(grant.inodeId)) {
      return { synced: false, id: grant.id, reason: "inode not in this space's namespace" };
    }
    // putGrant is INSERT OR REPLACE on id → idempotent upsert.
    this.acl.putGrant({
      id: grant.id,
      spaceId: grant.spaceId,
      inodeId: grant.inodeId,
      principalType: grant.principalType,
      principalId: grant.principalId,
      level: grant.level,
      mountAsRoot: !!grant.mountAsRoot,
      expiresAt: grant.expiresAt ?? null,
      grantedByMemberId: grant.grantedByMemberId,
      grantedAt: grant.grantedAt,
    });
    return { synced: true, id: grant.id };
  }

  async revokeAccess(inodeId: string, principalType: GrantInput["principalType"], principalId: string): Promise<{ revoked: number }> {
    return { revoked: revokePrincipal(this.acl, inodeId, principalType, principalId) };
  }

  /// Audit B28 — list grants for an inode (or ALL grants in the space when `inodeId` is omitted).
  /// Powers `cloudfs permission list` and the Mac app's Members & Access tab (both previously hit a
  /// nonexistent GET route / stubbed to an empty array). Returns the grant rows with their inode id.
  async listGrants(inodeId?: string): Promise<Array<{ inodeId: string; principalType: string; principalId: string; level: string; mountAsRoot: boolean; expiresAt: number | null }>> {
    const rows = inodeId
      ? this.acl.grantsForInode(inodeId)
      : (this.sql.exec(`SELECT inode_id, principal_type, principal_id, level, mount_as_root, expires_at FROM grants;`).toArray().map((r) => ({
          inodeId: String(r.inode_id), principalType: String(r.principal_type), principalId: String(r.principal_id),
          level: String(r.level), mountAsRoot: Number(r.mount_as_root) === 1, expiresAt: r.expires_at === null ? null : Number(r.expires_at),
        })));
    // Normalize the per-inode shape to match the all-grants shape.
    return (inodeId ? rows.map((g: any) => ({ inodeId: g.inodeId, principalType: g.principalType, principalId: g.principalId, level: g.level, mountAsRoot: g.mountAsRoot, expiresAt: g.expiresAt ?? null })) : rows) as any;
  }

  // ---- audit (tamper-evident hash chain, SPEC §4.8 + WS3 R2 archival) --------

  /// Lazily bind the R2 archive for THIS filespace. The archive prefix is the
  /// effective `<org>::<fs>` key, which we only learn from an audit event's
  /// orgId+spaceId. Returns null when AUDIT_BUCKET is unbound (full chain stays in
  /// SQLite — back-compat / local dev).
  private ensureArchive(filespaceKey: string): R2AuditArchive | null {
    const bucket = this.env.AUDIT_BUCKET as AuditR2 | undefined;
    if (!bucket) return null;
    if (!this.auditArchive || this.filespaceKey !== filespaceKey) {
      this.filespaceKey = filespaceKey;
      this.auditArchive = new R2AuditArchive(bucket, filespaceKey);
    }
    return this.auditArchive;
  }

  /// Derive the effective `<org>::<fs>` key from an event (matches the gateway's
  /// `filespaceDoName(orgId, spaceId)`), so the R2 prefix lines up with the DO.
  private keyForEvent(e: { orgId?: string; spaceId?: string }): string | null {
    if (!e.orgId || !e.spaceId) return null;
    return `${e.orgId}::${e.spaceId}`;
  }

  /// Append a sealed audit record. Writes serialize in the single-threaded DO,
  /// so the chain stays consistent without extra locking. Also (best-effort)
  /// arms the periodic archive alarm so the ring is trimmed even when no lease /
  /// snapshot deadlines are pending.
  async appendAudit(event: AuditEvent): Promise<{ seq: number; hash: string }> {
    // Older installations could empty the whole ring before chain checkpoints
    // existed. Restore the last sealed record instead of silently restarting at
    // genesis. The second tail check protects concurrent appends during R2 I/O.
    if (!this.auditStore.tail() && this.auditStore.archivedThroughSeq() >= 0) {
      const key = this.filespaceKey ?? this.keyFromTail();
      const archive = key ? this.ensureArchive(key) : null;
      const tail = await archive?.lastRecord();
      if (!tail || tail.seq !== this.auditStore.archivedThroughSeq()) throw new Error("audit chain checkpoint cannot be recovered");
      if (!this.auditStore.tail()) this.auditStore.checkpointTail(tail);
    }
    // FINDING C: the chain seal is a read-modify-write — tail() (SQL) → hashRecord()
    // (crypto.subtle.digest, a NON-storage await that OPENS the DO input gate) →
    // append() (INSERT, seq is PRIMARY KEY). Two concurrent deliveries for THIS DO
    // would both read the same tail across the digest yield, compute the same seq=N+1,
    // and the 2nd INSERT throws a UNIQUE-constraint error — an audit event silently
    // LOST and/or a forked chain (same prevHash). Wrap the read→hash→append in
    // blockConcurrencyWhile so no other delivery interleaves between tail() and append()
    // (mirrors the documented rate-limiter mitigation, Finding 6). The archive arming
    // below is idempotent and stays outside the critical section.
    const rec = await this.ctx.blockConcurrencyWhile(() => this.audit.write(event));
    const key = this.keyForEvent(event);
    if (key) {
      // Persist the key DURABLY (not just in-memory): once the ring is fully
      // sealed+emptied and the DO hibernates, this is the only place the R2 prefix
      // survives — keyFromTail() reads it back so cold reads still splice R2
      // history and the archive alarm re-arms (Finding 5).
      if (this.filespaceKey !== key) this.auditStore.setFilespaceKey(key);
      this.ensureArchive(key);
      await this.armAlarm();
    }
    return { seq: rec.seq, hash: rec.hash };
  }

  /// Reader API (gated by `audit:read` scope at the gateway). Reads the DO RING
  /// first, then transparently FALLS BACK to R2 segments for ranges older than
  /// the ring (WS3 §5.4). The merged result is ascending-seq and shape-identical
  /// to the pre-archival reader, so `verifyChain` over it stays valid.
  async queryAudit(filter: AuditQuery): Promise<AuditRecord[]> {
    const limit = Math.min(Math.max(1, filter.limit ?? 1000), 10_000);
    const ringStart = this.auditStore.archivedThroughSeq() + 1;
    // The DO ring holds the NEWEST rows (seq >= ringStart). Read it newest-first,
    // honoring `cursor` (exclusive seq upper bound) + `limit` — the store already
    // orders `seq DESC` and applies both (CONTRACTS §5.4).
    const ring = this.audit.query(filter);
    const ringRecords = Array.isArray(ring) ? ring : await ring;

    // Recover the filespace key from the chain tail if the in-memory hint was
    // lost to hibernation — otherwise a reader AFTER a DO restart would silently
    // drop all R2-archived history (archived_through_seq is durable, but the key
    // is not). keyFromTail() reads it back from a resident record.
    const key = this.filespaceKey ?? this.keyFromTail();
    const archive = key ? this.ensureArchive(key) : null;

    // Fast path: nothing archived (no R2 bound, or the ring still holds the whole
    // chain). The ring result is already the newest-first page.
    if (!archive || ringStart <= 0) return ringRecords;

    // The ring already satisfied a full page → no need to descend into R2 yet.
    // (The caller pages further back with `cursor` = lowest seq of this page,
    // which will eventually cross below `ringStart` into the archive.)
    if (limit !== undefined && ringRecords.length >= limit) return ringRecords;

    // PAGE ACROSS THE RING → R2 BOUNDARY. We need older rows than the ring held,
    // still newest-first, still honoring the exclusive `cursor`. The archive query
    // restricts to seq < min(cursor, ringStart) internally; we only need enough to
    // top the page up to `limit` (unbounded when no limit).
    const need = limit !== undefined ? limit - ringRecords.length : undefined;
    const archived = await archive.query({ ...filter, limit: need }, ringStart);
    if (archived.length === 0) return ringRecords;

    // Both halves are newest-first and disjoint by `ringStart` (ring: seq >=
    // ringStart, archive: seq < ringStart), so concatenation stays seq-descending.
    // De-dup defensively on seq, then clamp to `limit`.
    const merged = [...ringRecords, ...archived];
    const out: AuditRecord[] = [];
    const seen = new Set<number>();
    for (const r of merged) {
      if (seen.has(r.seq)) continue;
      seen.add(r.seq);
      out.push(r);
    }
    return limit !== undefined ? out.slice(0, limit) : out;
  }

  /// Trim the DO audit ring: seal records OUTSIDE the ring window (min(last 24h,
  /// last 2000 events)) to R2, then delete them from SQLite. Rows are deleted ONLY
  /// after a durable R2 flush, so the chain is never lost. No-op when the archive
  /// is unbound. `now` injectable for deterministic tests; `policy` overrides the
  /// ring bounds (tests pass a tiny `maxEvents`/`windowMs` to force a trim with a
  /// handful of events). Returns what happened.
  async archiveAuditRing(now = Date.now(), policy?: { maxEvents?: number; windowMs?: number }): Promise<{ archived: number; deleted: number; throughSeq: number }> {
    this.backupState.assertOrdinary();
    const operation = this.archiveAuditRingImpl(now, policy);
    this.archiveOperations.add(operation);
    try { return await operation; } finally { this.archiveOperations.delete(operation); }
  }

  private async archiveAuditRingImpl(
    now: number,
    policy?: { maxEvents?: number; windowMs?: number },
  ): Promise<{ archived: number; deleted: number; throughSeq: number }> {
    const key = this.filespaceKey ?? this.keyFromTail();
    const archive = key ? this.ensureArchive(key) : null;
    if (!archive) return { archived: 0, deleted: 0, throughSeq: this.auditStore.archivedThroughSeq() };
    const windowMs = policy?.windowMs ?? AUDIT_RING_WINDOW_MS;
    const maxEvents = policy?.maxEvents ?? AUDIT_RING_MAX_EVENTS;
    const cutoff = now - windowMs;
    const candidates = this.auditStore.sealCandidates(cutoff, maxEvents);
    if (candidates.length === 0) {
      this.metaIntSet("audit_next_at", Date.now() + AUDIT_ARCHIVE_INTERVAL_MS);
      return { archived: 0, deleted: 0, throughSeq: this.auditStore.archivedThroughSeq() };
    }
    const through = await archive.seal(candidates);
    if (through === null) return { archived: 0, deleted: 0, throughSeq: this.auditStore.archivedThroughSeq() };
    // Durable in R2 now → safe to drop from the ring and advance the high-water.
    // Checkpoint before deleting the last resident row on pre-checkpoint stores.
    const tail = this.auditStore.tail();
    if (tail) this.auditStore.checkpointTail(tail);
    const deleted = this.auditStore.deleteUpToSeq(through);
    this.auditStore.setArchivedThroughSeq(Math.max(through, this.auditStore.archivedThroughSeq()));
    const backlog = this.auditStore.sealCandidates(cutoff, maxEvents, 1).length > 0;
    this.metaIntSet("audit_next_at", Date.now() + (backlog ? 1_000 : AUDIT_ARCHIVE_INTERVAL_MS));
    return { archived: candidates.length, deleted, throughSeq: through };
  }

  /// Recover the filespace key when the in-memory hint was lost to hibernation
  /// (the alarm/reader can run without a prior appendAudit call on this instance).
  /// Prefers the DURABLY-persisted key (written on the first appendAudit) so it
  /// survives even after the entire ring is sealed+emptied; only then falls back
  /// to deriving it from a resident chain record (back-compat for DOs whose key
  /// was written before the durable column existed AND that still hold rows).
  private keyFromTail(): string | null {
    const persisted = this.auditStore.filespaceKey();
    if (persisted) return persisted;
    const t = this.auditStore.tail() ?? this.auditStore.oldestRecord();
    return t ? this.keyForEvent(t) : null;
  }

  /// Continuity check across the DO→R2 boundary (WS3). Finding 3: verify
  /// INCREMENTALLY rather than concatenating the WHOLE history into memory —
  /// `allArchived()` could exceed the DO memory/time budget for a long-lived
  /// space. The archive deep-verifies its segments one body at a time, then we
  /// continue straight into the DO ring from the archived tail. Peak memory is one
  /// segment + the ring, never the full chain. Result semantics (ok / brokenAtSeq
  /// / reason) are preserved end-to-end. Admin/verification op, not a hot path.
  async verifyAuditContinuity(): Promise<ChainVerifyResult> {
    const key = this.filespaceKey ?? this.keyFromTail();
    const archive = key ? this.ensureArchive(key) : null;
    // The DO ring carries the records AFTER the archived high-water (bounded by
    // the ring window), so handing it as the in-memory continuation keeps the peak
    // at one segment + the ring.
    const ring = this.auditStore.recordsInRange();
    if (ring.length !== this.auditStore.count()) {
      return { ok: false, checked: 0, reason: "audit verification incomplete: archive the resident backlog before verifying the full chain" };
    }
    if (!archive) return verifyChain(ring); // no R2: ring is the whole chain
    return archive.verifyContinuity(ring, this.auditStore.archivedThroughSeq());
  }

  // ---- live activity (DO hot state: in-flight ops + bulk-op rollups) --------
  // WS3 §5.3: the LIVE feed is ephemeral and sourced from DO hot state — NOT the
  // audit history. We track in-flight transfers (begun on upload-begin, cleared
  // on commit/abort) and a short rolling tail of recent activity events, with
  // bulk ops (e.g. an N-file delete, N ≥ BULK_DELETE_THRESHOLD) COLLAPSED into a
  // single "large-delete" rollup so the feed shows one line, not thousands.

  /// Push a single live-activity event onto the rolling hot tail (bounded).
  private pushHotEvent(e: LiveActivityEvent): void {
    this.hotEvents.push(e);
    if (this.hotEvents.length > HOT_EVENTS_MAX) {
      this.hotEvents.splice(0, this.hotEvents.length - HOT_EVENTS_MAX);
    }
  }

  /// Mark a transfer in-flight (upload-begin or download-begin). Idempotent on id.
  async transferBegin(t: { id: string; path: string; direction?: "upload" | "download"; bytesTotal?: number }): Promise<void> {
    if (this.activeTransfers.size >= ACTIVE_OPS_MAX && !this.activeTransfers.has(t.id)) {
      // Evict the oldest to stay bounded (best-effort; hot state, not durable).
      const oldest = [...this.activeTransfers.values()].sort((a, b) => a.startedAt - b.startedAt)[0];
      if (oldest) this.activeTransfers.delete(oldest.id);
    }
    this.activeTransfers.set(t.id, {
      id: t.id,
      path: t.path,
      direction: t.direction ?? "upload",
      bytesDone: 0,
      bytesTotal: t.bytesTotal ?? 0,
      state: "active",
      startedAt: Date.now(),
    });
  }

  /// Update progress on an in-flight transfer (no-op if unknown / already gone).
  async transferProgress(id: string, bytesDone: number, bytesTotal?: number): Promise<void> {
    const t = this.activeTransfers.get(id);
    if (!t) return;
    t.bytesDone = bytesDone;
    if (bytesTotal !== undefined) t.bytesTotal = bytesTotal;
  }

  /// Commit (or abort) an in-flight transfer: remove it from hot state. On a
  /// successful upload commit we also drop a `single` activity event onto the
  /// rolling tail so the live feed reflects the just-completed write.
  async transferCommit(id: string, opts?: { actor?: string; type?: string; seq?: number }): Promise<void> {
    const t = this.activeTransfers.get(id);
    this.activeTransfers.delete(id);
    if (t && opts) {
      this.pushHotEvent({
        seq: opts.seq ?? this.ns.currentSeq(),
        type: opts.type ?? (t.direction === "upload" ? "modify" : "read"),
        path: t.path,
        actor: opts.actor ?? "",
        ts: Date.now(),
        kind: "single",
      });
    }
  }

  async transferAbort(id: string): Promise<void> {
    this.activeTransfers.delete(id);
  }

  /// Record a BULK delete as ONE rolled-up live-activity event (§5.3). Called by
  /// the gateway delete path when a delete is recursive / multi-item and the
  /// collapsed `count` meets BULK_DELETE_THRESHOLD; below threshold it records a
  /// `single` event. `path` is the bulk root (e.g. the deleted folder). Returns
  /// the kind it recorded so the caller can surface it.
  async recordDeleteActivity(opts: { path: string; actor: string; count: number; seq?: number }): Promise<{ kind: "single" | "bulk" }> {
    const seq = opts.seq ?? this.ns.currentSeq();
    if (opts.count >= BULK_DELETE_THRESHOLD) {
      this.pushHotEvent({
        seq, type: "delete", path: opts.path, actor: opts.actor, ts: Date.now(),
        kind: "bulk", op: "large-delete", count: opts.count,
      });
      return { kind: "bulk" };
    }
    this.pushHotEvent({
      seq, type: "delete", path: opts.path, actor: opts.actor, ts: Date.now(), kind: "single",
    });
    return { kind: "single" };
  }

  /// The live activity feed (WS3 §5.3): in-flight transfers + the rolling tail of
  /// recent activity events (incl. bulk rollups), newest LAST. Hot-state only; an
  /// empty result after hibernation is expected (history lives in `audit`).
  async liveActivity(): Promise<LiveActivity> {
    const transfers = [...this.activeTransfers.values()].sort((a, b) => a.startedAt - b.startedAt);
    return { transfers, events: [...this.hotEvents] };
  }

  // ---- durable rate limiting (per-(org,space) consistent counter) -----------

  /// Consume `cost` tokens from a named limiter class for `key`. Backed by this
  /// DO's SQLite, so every Worker isolate shares one counter per space (closes
  /// the "global rate-limit" loose end for presign/mutation classes). The gateway
  /// translates a denial into 429 + Retry-After.
  async rateLimit(cls: "presign" | "mutation", key: string, cost = 1): Promise<RateLimitResult> {
    // Classes share a SQL store, but not token state. A metadata mutation must
    // never clamp the much larger upload/read budget to its own capacity.
    return this.limiters[cls].check(`${cls}:${key}`, cost);
  }

  // ---- locks / leases -------------------------------------------------------

  async acquireLock(path: string, owner: string, ttlMs: number, mode: LockMode = "exclusive", purpose: LockPurpose = "advisory"): Promise<LockResult> {
    if (purpose === "publication" && mode !== "exclusive") {
      return {granted:false,path,reason:"purpose-mismatch"};
    }
    const rangeHolder = this.rangeLocks.heldByOther(path, owner);
    if (rangeHolder) return {granted:false,path,heldBy:rangeHolder,reason:"held-by-other"};
    const res = this.locks.acquire(path, owner, ttlMs, mode, purpose);
    await this.armAlarm();
    return res;
  }

  /** Acquire a publication lease and return the currently authorized item in
   * the same synchronous SQLite turn. The optional HTTP fast path uses this to
   * replace a separate write-access probe and post-lease stat without changing
   * the ordinary lock response. Denied/conflicting calls never include item
   * metadata. */
  async acquirePublicationLockWithItemFor(principal: AclPrincipal, path: string, owner: string, ttlMs: number): Promise<LockResult & {item?:Item}> {
    this.assertNotDeleted();
    const result = this.ctx.storage.transactionSync((): LockResult & {item?:Item} => {
      const item = this.ns.getItem(path);
      if (!item) return {granted:false,path,reason:"not-found"};
      // Both sides of the metadata response and publication authority are
      // rechecked at the DO boundary. A route preflight is not authoritative
      // because ACLs may change before this operation reaches the DO.
      if (!this.checkOpenAccess(principal,path,"read",owner).allow
        || !this.checkOpenAccess(principal,path,"write",owner).allow) {
        return {granted:false,path,reason:"forbidden"};
      }
      const rangeHolder = this.rangeLocks.heldByOther(path,owner);
      if (rangeHolder) return {granted:false,path,heldBy:rangeHolder,reason:"held-by-other"};
      const lease = this.locks.acquire(path,owner,ttlMs,"exclusive","publication");
      if (!lease.granted) return lease;
      const enriched = {...item};
      this.ns.enrichStreams([enriched]);
      return {...lease,item:enriched};
    });
    if (result.granted) await this.armAlarm();
    return result;
  }

  async renewLock(path: string, owner: string, fence: number, ttlMs: number): Promise<LockResult> {
    const res = this.locks.renew(path, owner, fence, ttlMs);
    await this.armAlarm();
    return res;
  }

  async releaseLock(path: string, owner: string, fence?: number): Promise<{ released: boolean; reason?: string }> {
    return this.locks.release(path, owner, fence);
  }

  /// Lock status for a reader. Audit B5 (medium): the live fencing token is a
  /// CAPABILITY — Kleppmann fencing assumes it is private to the holder. Publishing
  /// it to every `fs:read` principal lets any `fs:write` principal present the
  /// victim's fence and defeat the data-plane gate. So we return the fence ONLY to
  /// the lease holder; everyone else gets the "locked by Bob" badge fields
  /// (granted/heldBy/mode/expiresAt) without the fence.
  async lockStatus(path: string, requester?: string): Promise<LockResult> {
    const st = this.locks.status(path);
    if (st.granted && st.heldBy !== requester) {
      const { fence: _drop, ...rest } = st as LockResult & { fence?: number };
      return rest;
    }
    return st;
  }

  /// Data-plane gate: a writer must present a valid, unexpired fence (SPEC §5.5).
  async validateFence(path: string, fence: number): Promise<boolean> {
    return this.locks.validateFence(path, fence);
  }

  async acquireRangesFor(principal: AclPrincipal, path: string, owner: string, handle: string,
    ranges: FileLockRange[], ttlMs: number, fence?:number, canLockExclusive=true): Promise<LockResult> {
    this.assertNotDeleted();
    // Acquire is also an idempotent renewal of this handle. Check retained
    // ranges as well as additions so a shared addition cannot renew an old
    // exclusive range after write ACL or fs:lock scope is removed.
    const requiresExclusive = [...this.rangeLocks.heldRanges(path,owner,handle),...ranges].some(r=>r.exclusive);
    const action = requiresExclusive ? "write" : "read";
    if ((requiresExclusive && !canLockExclusive) || !this.checkOpenAccess(principal,path,action,owner).allow)
      return {granted:false,path,reason:"forbidden"};
    const lease=this.locks.status(path);
    if (lease.granted && lease.heldBy !== owner) return {granted:false,path,heldBy:lease.heldBy,reason:"held-by-other"};
    const result=this.rangeLocks.acquire(path,owner,handle,ranges,ttlMs,fence);
    await this.armAlarm(); return result;
  }
  async renewRangesFor(principal: AclPrincipal,path:string,owner:string,handle:string,fence:number,ttlMs:number,canLockExclusive=true): Promise<LockResult> {
    this.assertNotDeleted();
    const ranges=this.rangeLocks.heldRanges(path,owner,handle);
    if ((!canLockExclusive && ranges.some(r=>r.exclusive)) || !this.checkOpenAccess(principal,path,ranges.some(r=>r.exclusive)?"write":"read",owner).allow)
      return {granted:false,path,reason:"forbidden"};
    const result=this.rangeLocks.renew(path,owner,handle,fence,ttlMs);
    await this.armAlarm(); return result;
  }
  async releaseRanges(path:string,owner:string,handle:string,fence:number,ranges?:FileLockRange[]): Promise<{released:boolean;reason?:string}> {
    return this.rangeLocks.release(path,owner,handle,fence,ranges);
  }
  async rangeAccessFor(principal:AclPrincipal,path:string,owner:string,handle:string,range:FileLockRange,fence?:number): Promise<RangeAccess> {
    this.assertNotDeleted();
    if (!this.checkOpenAccess(principal,path,range.exclusive?"write":"read",owner).allow) return {allowed:false,reason:"forbidden"};
    const result=this.rangeLocks.access(path,owner,handle,range,fence);
    if (result.permitTtlMs !== undefined) await this.armAlarm();
    return result;
  }
  async releaseReadPermit(path:string,owner:string,handle:string,fence:number): Promise<{released:boolean}> {
    this.rangeLocks.releaseRead(path,owner,handle,fence); return {released:true};
  }

  // ---- multipart / resumable uploads ---------------------------------------

  async beginUpload(uploadId: string, itemId: string, key: string, totalSize: number, partSize: number): Promise<UploadSession> {
    this.assertNotDeleted();
    return this.ctx.storage.transactionSync(() => this.uploads.begin({ uploadId, itemId, key, totalSize, partSize }));
  }

  async recordUploadPart(uploadId: string, partNumber: number, etag: string, size: number, checksum?: string): Promise<void> {
    this.assertNotDeleted();
    this.ctx.storage.transactionSync(() => this.uploads.recordPart(uploadId, partNumber, etag, size, checksum));
  }

  async uploadStatus(uploadId: string): Promise<{ session: UploadSession | null; missing: number[] }> {
    const session = this.uploads.status(uploadId);
    return { session, missing: session ? this.uploads.missingParts(uploadId) : [] };
  }

  async completeUpload(uploadId: string, etag: string): Promise<{ completed: boolean; missing?: number[] }> {
    this.assertNotDeleted();
    return this.ctx.storage.transactionSync(() => this.uploads.complete(uploadId, etag));
  }

  async abortUpload(uploadId: string): Promise<void> {
    this.assertNotDeleted();
    this.ctx.storage.transactionSync(() => this.uploads.abort(uploadId));
  }

  // ---- snapshots ------------------------------------------------------------

  /// Create a manual snapshot (WS4: real implementation). Freezes the as-of
  /// content of `scope` (metadata + block manifests; no media bytes). The `id` is
  /// optional now — when omitted the DO MINTS one server-side (`manual-<ts>-<rnd>`)
  /// so a client can request a snapshot without inventing a unique id (the prior
  /// path REQUIRED a client-supplied id, which is why the client create was a
  /// stub). `tier` defaults to "manual"; an explicit id is still honored (so
  /// scheduled/auto snapshots and tests keep working unchanged).
  async createSnapshot(opts: { id?: string; label?: string; scope?: string; tier?: string; immutableUntil?: number | null }): Promise<Snapshot> {
    const id = opts.id ?? `manual-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    return this.ctx.storage.transactionSync(()=>this.snapshots.create({ ...opts, id }));
  }

  async listSnapshots(): Promise<Snapshot[]> {
    return this.snapshots.list();
  }

  /// Enumerate a directory as-of a snapshot (self-service restore browse). This
  /// is the LAZY PER-DIRECTORY listing the client folder-tree drills with: pass
  /// the inode id of any frozen directory as `parent` to expand just that level
  /// (root when omitted). O(children) — never materializes the whole subtree.
  async listSnapshotDir(snapshotId: string, parent: string): Promise<Item[]> {
    return this.snapshots.listAt(snapshotId, parent);
  }

  async listSnapshotsFor(principal: AclPrincipal): Promise<Snapshot[]> {
    this.assertNotDeleted();
    return this.snapshots.list().filter(snapshot => new SnapshotAccess(this.snapshots, this.acl, principal, snapshot.id).roots().length > 0);
  }

  async createSnapshotFor(principal: AclPrincipal, opts: { id?: string; label?: string; scope?: string; tier?: string; immutableUntil?: number | null }) {
    this.assertNotDeleted();
    const scope = opts.scope ?? "root";
    const item = this.ns.getItem(scope);
    if (!item || item.deleted || !item.isDir) return { error: "scope_not_found" as const };
    if (!canAccess(this.acl, principal, scope, "manage_acl").allow) return { error: "forbidden" as const };
    const id = opts.id ?? `manual-${crypto.randomUUID()}`;
    if (this.snapshots.get(id)) return { error: "snapshot_exists" as const };
    return { snapshot: this.ctx.storage.transactionSync(()=>this.snapshots.create({ ...opts, id, scope })) };
  }

  async snapshotMountRootsFor(principal: AclPrincipal, snapshotId: string) {
    this.assertNotDeleted();
    const snapshot = this.snapshots.get(snapshotId);
    if (!snapshot) return null;
    return { snapshot, roots: new SnapshotAccess(this.snapshots, this.acl, principal, snapshotId).roots(), streamsCaptured: this.snapshots.streamsCaptured(snapshotId) };
  }

  async snapshotStreamsFor(principal: AclPrincipal, snapshotId: string, itemId: string) {
    this.assertNotDeleted();
    if (!new SnapshotAccess(this.snapshots, this.acl, principal, snapshotId).canRead(itemId)) return null;
    return { streams: this.snapshots.streamsAt(snapshotId, itemId), captured: this.snapshots.streamsCaptured(snapshotId) };
  }
  async snapshotStreamFor(principal: AclPrincipal, snapshotId: string, itemId: string, name: string) {
    this.assertNotDeleted();
    if (!new SnapshotAccess(this.snapshots, this.acl, principal, snapshotId).canRead(itemId)) return null;
    return this.snapshots.streamAt(snapshotId, itemId, name);
  }

  async snapshotStreamManifestFor(principal:AclPrincipal,snapshotId:string,itemId:string,name:string,offset=0,length=16*1024*1024) {
    this.assertNotDeleted();
    if (!new SnapshotAccess(this.snapshots,this.acl,principal,snapshotId).canRead(itemId) || !this.snapshots.streamsCaptured(snapshotId)) return null;
    return this.snapshots.streamManifestAt(snapshotId,itemId,name,offset,length);
  }

  async snapshotItemFor(principal: AclPrincipal, snapshotId: string, itemId: string): Promise<Item | null> {
    this.assertNotDeleted();
    const access = new SnapshotAccess(this.snapshots, this.acl, principal, snapshotId);
    return access.canRead(itemId) ? access.item(itemId) : null;
  }

  async snapshotBlockMapFor(principal: AclPrincipal, snapshotId: string, itemId: string, cursor = -1) {
    this.assertNotDeleted();
    const access = new SnapshotAccess(this.snapshots, this.acl, principal, snapshotId);
    const item = access.item(itemId);
    if (!item || item.isDir || !access.canRead(itemId)) return null;
    return { item, ...this.snapshots.blocksPageAt(snapshotId, itemId, cursor) };
  }

  async checkSnapshotObjectReadsFor(principal: AclPrincipal, snapshotId: string, itemId: string, keys: string[]): Promise<(string | null)[]> {
    this.assertNotDeleted();
    const access = new SnapshotAccess(this.snapshots, this.acl, principal, snapshotId);
    if (!access.canRead(itemId)) return keys.map(() => "forbidden");
    return keys.map(key => this.snapshots.ownsObjectAt(snapshotId, itemId, key) ? null : "object_not_in_snapshot");
  }

  async listSnapshotPageFor(principal: AclPrincipal, snapshotId: string, parent: string, cursor?: string) {
    this.assertNotDeleted();
    const access = new SnapshotAccess(this.snapshots, this.acl, principal, snapshotId);
    if (!access.canRead(parent) || !access.item(parent)?.isDir) return null;
    const page = this.snapshots.listPageAt(snapshotId, parent, cursor);
    return { items: page.items.filter(item => access.canRead(item.id)), cursor: page.cursor };
  }

  async listSnapshotDirFor(principal: AclPrincipal, snapshotId: string, parent: string): Promise<Item[]> {
    this.assertNotDeleted();
    const access = new SnapshotAccess(this.snapshots, this.acl, principal, snapshotId);
    // Folder-only users browse through their projected entries without exposing
    // private ancestors. The mount endpoint supplies these same authorized roots.
    if (parent === "root" && !access.canRead(parent)) {
      return access.roots().flatMap(root => access.item(root.id) ?? []);
    }
    if (!access.canRead(parent)) return [];
    return this.snapshots.listAt(snapshotId, parent).filter(item => access.canRead(item.id));
  }

  /// Restore a path (file, or whole subtree with `recursive`) to its state AS OF
  /// a snapshot (SPEC §4.7). NON-DESTRUCTIVE: each restored item is re-written as
  /// a new current version (appears in the change feed); prior/current state stays
  /// in history. Respects locks: a target exclusively leased by ANOTHER owner is
  /// skipped and reported as a conflict (never clobbered). The gateway has already
  /// enforced EDIT (canAccess) on the target path before calling this.
  ///
  /// `requesterOwner` is the authenticated principal; a lock held BY the requester
  /// does not conflict (they may restore their own locked file). Returns a typed
  /// result {restored, recreated, conflicts, newerThanSnapshot}.
  async restoreSnapshot(
    snapshotId: string,
    path: string,
    opts?: { recursive?: boolean; requesterOwner?: string; principal?: AclPrincipal },
  ): Promise<RestoreResult> {
    const owner = opts?.requesterOwner;
    const isLockedByOther = (itemId: string): string | null => {
      // Lock keys are arbitrary path strings; the inode id IS the lock key the
      // lock route uses for namespace items. An exclusive lease by anyone other
      // than the requester blocks restore of that item.
      const st = this.locks.status(itemId);
      if (st.granted && st.heldBy && st.heldBy !== owner) {
        return st.heldBy;
      }
      return this.rangeLocks.heldByOther(itemId, owner);
    };
    const access = opts?.principal ? new SnapshotAccess(this.snapshots, this.acl, opts.principal, snapshotId) : null;
    const res = this.ctx.storage.transactionSync(()=>this.snapshots.restore(snapshotId, path, { recursive: opts?.recursive, isLockedByOther,
      canRestore: (id, parent) => !this.contentReadOnly(id) && (!access || access.canRestore(id, parent)),
      beforeRecreate: id => { this.acl.deleteGrantsForInodes([id]); },
    }));
    if (opts?.principal) {
      res.newerThanSnapshot = res.newerThanSnapshot.filter(id => canAccess(this.acl, opts.principal!, id, "read").allow);
      if (res.forbidden?.length) {
        res.skippedPermissions = res.forbidden.length;
        // Counts explain partial recovery without exposing inaccessible inode IDs.
        res.forbidden = res.forbidden.filter(id => access?.canRead(id));
      }
    }
    // Restores mutate the namespace → drop any cached stats for touched ids.
    for (const id of [...res.restored, ...res.recreated]) this.invalidate(id);
    return res;
  }

  async setSnapshotSchedule(spec: ScheduleSpec): Promise<void> {
    this.snapshots.setSchedule(spec);
    await this.armAlarm();
  }

  async ensureDefaultSnapshotSchedules(): Promise<void> {
    this.snapshots.ensureDefaultSchedules();
    await this.armAlarm();
  }

  async listSnapshotSchedules() {
    return this.snapshots.listSchedules();
  }

  async setSnapshotScheduleRetain(id: string, retain: number): Promise<boolean> {
    return this.snapshots.setScheduleRetain(id, retain);
  }

  async setSnapshotScheduleEnabled(id: string, enabled: boolean): Promise<void> {
    this.snapshots.setScheduleEnabled(id, enabled);
    await this.armAlarm();
  }

  /// Object keys safe to delete from R2 (snapshot-aware GC). The Worker runs the
  /// actual R2 deletes with the gateway-held GC credential (clients never have it).
  async collectableBlocks(limit?: number): Promise<{ blockHash: string; objectKey: string }[]> {
    return this.snapshots.collectableBlocks(limit);
  }

  reclamationReportFor(principal:AclPrincipal) {
    this.assertNotDeleted();
    if (!isOrgAdmin(principal.orgRole)) return {error:'forbidden' as const};
    return this.reclamation.report();
  }
  async quarantineObjectsFor(principal:AclPrincipal,recoveredThrough:number,orgId:string,spaceId:string) {
    this.assertNotDeleted();
    if (!isOrgAdmin(principal.orgRole)) return {error:'forbidden' as const};
    if (!Number.isSafeInteger(recoveredThrough) || recoveredThrough<0 || recoveredThrough>Date.now()) return {error:'invalid_recovery_watermark' as const};
    const quarantined=this.ctx.storage.transactionSync(()=>{
      this.metaTextSet('reclamation_org',orgId);this.metaTextSet('reclamation_space',spaceId);
      return this.reclamation.quarantine(recoveredThrough);
    });
    await this.armAlarm();
    return {quarantined,...this.reclamation.report(recoveredThrough)};
  }
  private async runReclamation(fetchImpl: typeof fetch = fetch):Promise<void> {
    if (this.reclamationOperation) return this.reclamationOperation;
    const operation=this.reclaimBatch(fetchImpl);this.reclamationOperation=operation;
    try {await operation;}
    catch (error) {
      if (!this.backupState.isBlocked()) this.sql.exec("UPDATE object_reclamation SET next_at=?,last_error='storage_configuration_unavailable' WHERE next_at<=?;",Date.now()+30*60*1000,Date.now());
      throw error;
    } finally {this.reclamationOperation=null;}
  }
  private async reclaimBatch(fetchImpl: typeof fetch):Promise<void> {
    const orgId=this.metaTextGet('reclamation_org'),spaceId=this.metaTextGet('reclamation_space');
    const tickets=this.reclamation.due();
    if (!tickets.length || this.backupState.isBlocked()) return;
    if (!orgId || !spaceId) throw new Error('reclamation_registry_unavailable');
    const org=this.env.ORG_DO.getByName(orgId),space=await org.getSpace(spaceId);
    if (!space) throw new Error('reclamation_registry_unavailable');
    const descriptor:SpaceStorageDescriptor={provider:space.bucketProvider,endpoint:space.storageEndpoint,region:space.storageRegion,
      bucket:space.storageBucket,forcePathStyle:space.storageForcePathStyle,credentialRef:space.storageCredentialRef};
    const config=await resolveStorageConfigAsync(this.env,descriptor,managedCredentialResolver(this.env,org));
    if (this.backupState.isBlocked() || this.isDeleted() || this.isPurging()) return;
    const ready=this.ctx.storage.transactionSync(()=>tickets.filter(t=>this.reclamation.begin(t)));
    if (!ready.length) return;
    await this.ctx.storage.sync();
    if (this.backupState.isBlocked()) return;
    let deleted=new Set<string>();
    try { deleted=new Set((await deleteObjects(config,`blocks/${orgId}::${spaceId}/`,ready.map(t=>t.key),fetchImpl)).deleted); }
    catch { /* Unknown outcomes retry under permanent publication tombstones. */ }
    if (this.backupState.isBlocked()) return;
    this.ctx.storage.transactionSync(()=>{for (const ticket of ready) this.reclamation.finish(ticket,deleted.has(ticket.key));});
  }

  // ---- alarm: lease reaping + scheduled snapshots ---------------------------

  /// Arm the alarm for the soonest of (next lease expiry, next snapshot due,
  /// next audit-archive tick). setAlarm replaces any existing alarm, so we always
  /// re-derive the minimum. The audit tick only participates once the archive is
  /// bound (AUDIT_BUCKET present AND we know this DO's filespace key) and there is
  /// something in the ring to potentially seal.
  private async armAlarm(): Promise<void> {
    if (this.backupState.isBlocked()) { await this.ctx.storage.deleteAlarm(); return; }
    // A late audit append or schedule toggle must not delete/replace an active
    // purge's independent deadline. Purge owns the sole alarm until it finishes.
    if (this.isPurging()) {
      if (await this.ctx.storage.getAlarm() === null) await this.ctx.storage.setAlarm(Date.now() + MAINTENANCE_RETRY_MS);
      return;
    }
    const expiry = this.locks.earliestExpiry();
    const snapshotDue = this.isDeleted() ? null : this.snapshots.earliestDue();
    const due = snapshotDue === null ? null : Math.max(snapshotDue, this.metaIntGet("snapshot_retry_at"));
    const auditDue = this.auditArchiveDue();
    const gcDue=this.isDeleted() ? null : this.reclamation.nextDue();
    const candidates = [expiry, this.rangeLocks.earliestExpiry(), this.openHandles.nextExpiry(), due, auditDue, gcDue,
      this.metaIntGet('restore_open_cleanup') === 1 ? Date.now() + 1 : null].filter((t): t is number => t !== null);
    if (!candidates.length) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    const next = Math.min(...candidates);
    const existing = await this.ctx.storage.getAlarm();
    if (existing === null || next < existing) {
      await this.ctx.storage.setAlarm(next);
    }
  }

  /// When the next periodic audit-archive tick should fire, or null when archival
  /// is inapplicable (no R2 binding / unknown filespace key / empty ring).
  private auditArchiveDue(): number | null {
    if (!this.env.AUDIT_BUCKET) return null;
    if (!(this.filespaceKey ?? this.keyFromTail())) return null;
    if (this.auditStore.count() === 0) return null;
    let next = this.metaIntGet("audit_next_at");
    if (!next) {
      next = Date.now() + AUDIT_ARCHIVE_INTERVAL_MS;
      this.metaIntSet("audit_next_at", next);
    }
    return next;
  }

  async alarm(): Promise<void> {
    if (this.backupState.isBlocked()) { await this.ctx.storage.deleteAlarm(); return; }
    // An alarm already delivered before explicit cancellation may arrive after
    // purge wiped all tables. Do not resurrect a namespace or retry missing SQL.
    if (!this.sql.exec(`SELECT 1 FROM sqlite_master WHERE type='table' AND name='meta';`).toArray().length) {
      await this.ctx.storage.deleteAlarm();
      return;
    }
    // PURGE SWEEP takes priority: if a purge is armed, run one page and return. purgeStep re-arms
    // the alarm itself when more pages remain, and finalizes (deleteAll) on completion — after a
    // finalize this DO's storage is wiped, so we must NOT fall through to lease/snapshot work that
    // would re-seed alarms on a now-empty namespace.
    if (this.isPurging()) {
      try {
        await this.purgeStep();
      } catch {
        // A transient list/delete failure leaves purge state intact (cursor unchanged) and
        // resumable. Re-arm shortly so the sweep retries rather than wedging.
        console.error("filespace_maintenance", { operation: "purge", result: "retry", retryAfterMs: MAINTENANCE_RETRY_MS });
        await this.ctx.storage.setAlarm(Date.now() + MAINTENANCE_RETRY_MS);
      }
      return;
    }
    const now = Date.now();
    if (!this.isDeleted()) {
      try { await this.runReclamation(); }
      catch { await this.ctx.storage.setAlarm(now+MAINTENANCE_RETRY_MS); }
    }
    this.locks.reapExpired(now);
    this.rangeLocks.reapExpired(now);
    const reclaimedHandles=this.ctx.storage.transactionSync(()=>{
      const inodeIds=this.openHandles.reapCandidates(now);
      for (const inodeId of inodeIds) this.ns.reclaimUnopenedPayload(inodeId,now);
      return inodeIds;
    });
    for (const inodeId of reclaimedHandles) this.invalidate(inodeId);
    if (this.metaIntGet('restore_open_cleanup') === 1) {
      const cleanup=this.ctx.storage.transactionSync(()=>{
        const result=this.ns.reclaimDeletedPayloadBatch(now,256);
        if (!result.more) this.metaIntSet('restore_open_cleanup',0);
        return result;
      });
      for (const inodeId of cleanup.inodeIds) this.invalidate(inodeId);
    }
    if (!this.isDeleted() && now >= this.metaIntGet("snapshot_retry_at")) {
      try {
        // No external I/O: snapshot rows, refs, pruning and next-run deadlines
        // either all commit or all roll back if one operation fails.
        this.ctx.storage.transactionSync(() => this.snapshots.runDue(now));
        this.metaIntSet("snapshot_retry_at", 0);
      } catch {
        this.metaIntSet("snapshot_retry_at", now + MAINTENANCE_RETRY_MS);
        console.error("filespace_maintenance", { operation: "snapshots", result: "retry", retryAfterMs: MAINTENANCE_RETRY_MS });
      }
    }
    // Trim the audit ring → seal older events to R2, delete from SQLite. Wrapped
    // so an R2 hiccup never wedges the lease/snapshot alarm path.
    try {
      await this.archiveAuditRing(now);
    } catch {
      this.metaIntSet("audit_next_at", Date.now() + MAINTENANCE_RETRY_MS);
      console.error("filespace_maintenance", { operation: "audit", result: "retry", retryAfterMs: MAINTENANCE_RETRY_MS });
    }
    this.itemCache.clear(); // schedules may have changed nothing visible, but be safe
    // Re-arm for the next pending deadline (alarms are one-shot).
    await this.armAlarm();
  }
}
