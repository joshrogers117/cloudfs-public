// SPDX-License-Identifier: AGPL-3.0-or-later
// cloudfsd — the concrete `Engine` (wave-2b, owner: CORE).
//
// Realizes every `ControlMethod` (CloudFSCore.Engine) by composing the already-
// built, frozen module seams:
//   • CloudFSCache    (DiskBlockCache)      — resizable/relocatable block store, pins.
//   • CloudFSCrypto   (makeBlockCrypto)     — per-block encrypt/decrypt + content hash.
//   • CloudFSGateway  (HttpGatewayClient)   — presign / block-maps / items / changes.
//   • CloudFSTransfer (RealTransferEngine)  — range-GET download / staged upload / sync.
//   • CloudFSMount    (MountBackend)        — the VFS mount adapter (stub by default).
//
// Per-filespace session state (the cache + transfer engine + mount/connection
// record) lives behind one `actor` so all bookkeeping is serialized. Each method
// fans to the right module; errors flow back as `EngineError` (1:1 to the wire
// codes + CLI exit codes). `events(...)` merges the per-filespace transfer
// progress + cache deltas into one control-plane notification stream.

import Foundation
import CloudFSCore
import CloudFSCrypto
import CloudFSCache
import CloudFSTransfer
import CloudFSGateway
import CloudFSMount

/// The concrete engine the control plane drives. An `actor`: every method runs in
/// isolation, so the per-filespace session map mutates without data races.
public actor CloudFSEngine: Engine {

    // MARK: Dependencies (process-wide)

    let config: EngineConfig
    let gateway: any GatewayClient
    /// Per-filespace gateway reachability, fed by `ReachabilityGateway` (truthful status).
    let reachability: GatewayReachabilityTracker
    let mount: any MountBackend
    /// Cipher mode + key for the filespaces this daemon serves (one master key for
    /// the headless/dev path; production loads per-filespace from the Keychain).
    private let cipherMode: CipherMode
    private let key: FilespaceKey?
    /// M6 — per-filespace key resolution. Consulted FIRST for every session
    /// (production: scoped key file, Keychain, or gateway); `key` is reserved
    /// for direct test/dev construction. nil provider = fallback only.
    /// ONBOARDING.md "Key model": async because a miss (no local Keychain/key-file
    /// source) now fetches the wrapped-key envelope from the gateway before giving
    /// up — see `Daemon.swift`'s `FilespaceKeyResolver`.
    private let keyProvider: (@Sendable (FilespaceID) async -> FilespaceKey?)?
    let blockSize: Int
    let journalDiskBudget: JournalDiskBudget
    /// The presigned-URL byte plane each transfer engine moves blocks over. Shared
    /// process-wide (one warm HTTP/2 pool); injectable so tests route it at a stub.
    let blob: BlobTransport
    /// Shared across adapters so many open files cannot multiply speculation.
    nonisolated let readAhead: ReadAheadController

    // MARK: Per-filespace session state (actor-isolated)

    /// One live session per connected filespace.
    final class Session {
        var record: EngineFilespace
        let cache: DiskBlockCache
        let transfer: RealTransferEngine
        let crypto: any BlockCrypto
        let leases: DistributedLeaseCoordinator
        let opens: DistributedOpenCoordinator
        let rangeLocks: DistributedRangeCoordinator
        let streams: ChunkedStreamStore
        let identity = UUID()
        let changes = ChangeSignal()
        var changeMonitor: Task<Void, Never>?
        deinit { changeMonitor?.cancel() }
        var offlineDataPath: (any EngineDataPath)?
        var paused: Bool = false
        var mountRoots: [FilespaceMountRoot]?
        var rootProjection: MountRootSnapshot?
        var directMountRoot: InodeID?
        var writeAuthorizations: [InodeID: Date] = [:]
        init(record: EngineFilespace, cache: DiskBlockCache, transfer: RealTransferEngine,
             crypto: any BlockCrypto, leases: DistributedLeaseCoordinator, opens: DistributedOpenCoordinator, rangeLocks: DistributedRangeCoordinator, streams: ChunkedStreamStore) {
            self.record = record; self.cache = cache; self.transfer = transfer; self.crypto = crypto
            self.leases = leases; self.opens = opens; self.rangeLocks = rangeLocks; self.streams = streams
        }
    }
    var snapshotSessions: [String: EngineSnapshotSession] = [:]
    var snapshotMonitor: Task<Void, Never>?
    private var sessions: [FilespaceID: Session] = [:]
    private var mountOperations: Set<FilespaceID> = []
    private var mountWaiters: [FilespaceID: [CheckedContinuation<Void, Never>]] = [:]

    func beginMountOperation(_ filespace: FilespaceID) async {
        if mountOperations.insert(filespace).inserted { return }
        await withCheckedContinuation { mountWaiters[filespace, default: []].append($0) }
    }
    func endMountOperation(_ filespace: FilespaceID) {
        if var queued = mountWaiters[filespace], !queued.isEmpty {
            let next = queued.removeFirst()
            mountWaiters[filespace] = queued.isEmpty ? nil : queued
            next.resume()
        } else { mountOperations.remove(filespace) }
    }
    /// Called only while this filespace's mount-operation gate is held.
    private func reconcileMount(_ filespace: FilespaceID, session: Session) async throws {
        guard let path = session.record.mountPath else { return }
        if try await mount.reconcile(filespace: filespace, at: path) == false {
            session.record.mountPath = nil
            session.record.status = .disconnected
            removeMountIntent(filespace: filespace)
        }
    }
    private func reconcileMount(_ filespace: FilespaceID) async throws {
        await beginMountOperation(filespace)
        defer { endMountOperation(filespace) }
        guard let session = sessions[filespace] else { return }
        try await reconcileMount(filespace, session: session)
    }

    var pinSessions: [FilespaceID: EnginePinSession] = [:]
    var savedCachePreferences: [FilespaceID: EngineCachePreferences]?
    var cachePreferenceBusy: Set<FilespaceID> = []
    var cachePreferenceWaiters: [FilespaceID: [CheckedContinuation<Void, Never>]] = [:]
    private var leaseCleanups: [FilespaceID: [InodeID: Task<Void, Never>]] = [:]

    // MARK: Resolved-manifest cache (P4)
    //
    // P4 — read-path manifest round-trip amplification. `getResolvedBlockManifest`
    // is 2 gateway round-trips (GET /blocks/:id + an internal getItem); the read
    // path used to call it inside `ensureRange` AND re-fetch the manifest AGAIN in
    // `readRange`, plus a getItem in `readContents` — ~4-5 gateway requests per VFS
    // read, each re-running the auth gate + hitting the FilespaceDO. During
    // sequential playback that is a per-editor round-trip storm.
    //
    // Fix: cache the ResolvedBlockManifest per (filespace, itemID, contentVersion),
    // actor-isolated so there are no data races. A contentVersion change (file
    // edited) is a DIFFERENT key, so a reader never decrypts against a stale block
    // map — and we proactively drop any other-version entry for the same item so the
    // stale map doesn't linger. The cache is bounded (LRU eviction at a fixed cap) so
    // it cannot grow unbounded across many files.

    private struct ManifestKey: Hashable {
        let filespace: FilespaceID
        let itemID: InodeID
        let contentVersion: String
    }
    /// LRU-ordered cache of resolved manifests. `manifestLRU` is the access order
    /// (oldest first); `manifestCache` is the store.
    private var manifestCache: [ManifestKey: ResolvedBlockManifest] = [:]
    var metadataGeneration: UInt64 = 0
    nonisolated let manifestRanges = ManifestRangeCache()
    nonisolated let directoryPrefetch = DirectoryPrefetcher()
    private var manifestLRU: [ManifestKey] = []
    /// Cap on distinct cached manifests (bounds memory across many open files).
    private let manifestCacheCap = 512

    /// Resolve `itemID`'s block manifest for `contentVersion`, serving from the
    /// actor-isolated cache when present so a re-read of the same version costs ZERO
    /// extra gateway round-trips. A miss fetches once (`getResolvedBlockManifest`) and
    /// caches it; `contentVersion` is the invalidation key (a new version is a new
    /// entry — never a stale-map reuse — and evicts the prior-version entry).
    func resolvedManifest(filespace: FilespaceID, itemID: InodeID,
                          contentVersion: String) async throws -> ResolvedBlockManifest {
        let key = ManifestKey(filespace: filespace, itemID: itemID, contentVersion: contentVersion)
        if let hit = manifestCache[key] {
            touchManifest(key)
            return hit
        }
        var result: ResolvedBlockManifest?
        for _ in 0..<3 {
            let generation = metadataGeneration
            let fetched = try await gateway.getResolvedBlockManifest(filespace: filespace, itemID: itemID)
            if generation == metadataGeneration { result = fetched; break }
        }
        guard let resolved = result else { throw EngineError(.conflict, "Metadata changed during the read; retry") }
        // Key under the REQUESTED contentVersion: the mount threads one consistent
        // version per read (readContents → readRange), so this key is stable across
        // a single file's reads and a HIT serves the re-read. A NEW version arrives
        // as a different key (so a stale block map is never reused) and we evict the
        // prior-version entry for this same item below — an edit fully refreshes the
        // map even though it stays under the item's slot.
        invalidateManifest(filespace: filespace, itemID: itemID, except: contentVersion)
        cacheManifest(key, resolved)
        return resolved
    }

    private func touchManifest(_ key: ManifestKey) {
        if let i = manifestLRU.firstIndex(of: key) { manifestLRU.remove(at: i) }
        manifestLRU.append(key)
    }

    private func cacheManifest(_ key: ManifestKey, _ value: ResolvedBlockManifest) {
        if manifestCache[key] == nil { manifestLRU.append(key) }
        else { touchManifest(key) }
        manifestCache[key] = value
        // Bound the cache: evict the least-recently-used until under the cap.
        while manifestLRU.count > manifestCacheCap {
            let victim = manifestLRU.removeFirst()
            manifestCache.removeValue(forKey: victim)
        }
    }

    /// P3 — a write-back commit landed for `itemID`: its contentVersion changed, so
    /// EVERY cached manifest for the item is stale-keyed. Drop them all; the next
    /// read — whatever version string it pins — re-resolves the CURRENT manifest
    /// from the gateway. (Called by the transfer engine BEFORE it drops the staging
    /// overlay, so no read window can assemble pre-commit blocks.)
    func noteRecoveryCompleted(filespace: FilespaceID, itemID: InodeID) {
        invalidateManifest(filespace: filespace, itemID: itemID, except: nil)
    }

    func noteCommitted(filespace: FilespaceID, itemID: InodeID, meta: ItemMetadata) {
        invalidateManifest(filespace: filespace, itemID: itemID, except: nil,
                           preserveReadVersion: meta.contentVersion)
        scheduleLeaseCleanup(filespace: filespace, itemID: itemID)
    }

    /// Drop complete cached manifests for `itemID` whose version differs from
    /// `except`. Ranged manifests are cleared unless a separately verified
    /// content version is supplied; retention requires both the cache key and
    /// returned item to match that exact version.
    private func invalidateManifest(filespace: FilespaceID, itemID: InodeID, except keep: String?,
                                    preserveReadVersion: String? = nil) {
        if keep == nil {
            if let preserveReadVersion {
                manifestRanges.retainExactVersion(filespace: filespace, itemID: itemID,
                                                  version: preserveReadVersion)
            } else {
                manifestRanges.invalidate(filespace: filespace, itemID: itemID)
            }
            directoryPrefetch.invalidate(filespace: filespace, itemID: itemID)
        }
        if keep == nil { metadataGeneration &+= 1 }
        readAhead.cancel(filespace: filespace, itemID: itemID, exceptVersion: keep)
        let stale = manifestCache.keys.filter {
            $0.filespace == filespace && $0.itemID == itemID && $0.contentVersion != keep
        }
        for k in stale {
            manifestCache.removeValue(forKey: k)
            if let i = manifestLRU.firstIndex(of: k) { manifestLRU.remove(at: i) }
        }
    }

    private func remoteAccessLost(_ filespace: FilespaceID, identity: UUID) async {
        guard let session = sessions[filespace], session.identity == identity else { return }
        manifestRanges.invalidate(filespace: filespace)
        directoryPrefetch.invalidate(filespace: filespace)
        metadataGeneration &+= 1
        for key in manifestCache.keys.filter({ $0.filespace == filespace }) {
            invalidateManifest(filespace: filespace, itemID: key.itemID, except: nil)
        }
        readAhead.cancel(filespace: filespace)
        session.writeAuthorizations.removeAll()
        invalidateOffline(filespace)
        session.rootProjection?.set([])
        suspendPinJobs(filespace)
        await session.changes.signal()
    }
    private func applyRemoteChanges(_ filespace: FilespaceID, identity: UUID, page: GatewayChangePage, reset: Bool) async throws {
        guard let session = sessions[filespace], session.identity == identity else { throw CancellationError() }
        if reset {
            manifestRanges.invalidate(filespace: filespace)
            directoryPrefetch.invalidate(filespace: filespace)
            metadataGeneration &+= 1 // also invalidate fills that have not entered the cache yet
            let ids = Set(manifestCache.keys.filter { $0.filespace == filespace }.map(\.itemID))
            for id in ids { invalidateManifest(filespace: filespace, itemID: id, except: nil) }
            session.writeAuthorizations.removeAll()
            invalidateOffline(filespace)
            let roots = try await gateway.mountRoots(filespace: filespace)
            guard sessions[filespace]?.identity == identity else { throw CancellationError() }
            // Preserve the chosen direct-root mode; a virtual shared-folder root
            // can add/revoke aliases without remounting the operating-system volume.
            if session.mountRoots != nil {
                session.rootProjection?.set(roots)
                session.mountRoots = session.rootProjection?.get() ?? roots
            }
            try await retryPins(filespace)
        }
        for item in page.updated {
            invalidateManifest(filespace: filespace, itemID: item.id, except: nil,
                               preserveReadVersion: item.contentVersion)
        }
        for id in page.deleted { invalidateManifest(filespace: filespace, itemID: id, except: nil) }
        if reset || !page.updated.isEmpty || !page.deleted.isEmpty {
            refreshPins(filespace)
            await session.changes.signal()
        }
    }
    func changeGeneration(_ filespace: FilespaceID) async -> UInt64 { await sessions[filespace]?.changes.current() ?? 0 }
    func waitForChanges(_ filespace: FilespaceID, after: UInt64) async -> UInt64 {
        guard let signal = sessions[filespace]?.changes else { return after }
        return await signal.wait(after: after)
    }

    // MARK: Init

    public init(config: EngineConfig,
                gateway: any GatewayClient,
                mount: any MountBackend = defaultMountBackend(),
                cipherMode: CipherMode = .aes256gcm,
                key: FilespaceKey? = nil,
                keyProvider: (@Sendable (FilespaceID) async -> FilespaceKey?)? = nil,
                blob: BlobTransport = BlobTransport()) {
        self.config = config
        let tracker = GatewayReachabilityTracker()
        self.reachability = tracker
        self.gateway = ReachabilityGateway(base: gateway, tracker: tracker)
        self.mount = mount
        self.cipherMode = cipherMode
        self.key = key
        self.keyProvider = keyProvider
        self.blockSize = config.blockSize
        self.journalDiskBudget = JournalDiskBudget(cacheRoot: URL(fileURLWithPath: config.cacheDir),
            limitBytes: config.pendingWriteLimitBytes ?? JournalDiskBudget.defaultLimitBytes,
            freeSpaceReserveBytes: config.pendingWriteReserveBytes ?? JournalDiskBudget.defaultReserveBytes)
        self.blob = blob
        let budgetMiB = min(128, max(8, config.readAheadBudgetMiB ?? kDefaultReadAheadBudgetMiB))
        self.readAhead = ReadAheadController(byteLimit: budgetMiB << 20)
    }

    /// Convenience init that routes the presigned-URL byte plane over `blobSession`
    /// (e.g. a `URLProtocol`-stubbed session in tests, so block GET/PUTs never hit
    /// the network). Avoids leaking `BlobTransport`/`RetryPolicy` to callers that
    /// only depend on the `cloudfsd` module.
    public init(config: EngineConfig,
                gateway: any GatewayClient,
                blobSession: URLSession,
                cipherMode: CipherMode = .aes256gcm,
                key: FilespaceKey? = nil,
                keyProvider: (@Sendable (FilespaceID) async -> FilespaceKey?)? = nil) {
        // Tight, jitter-free retry so a stubbed transient never adds wall-clock.
        let policy = RetryPolicy(maxAttempts: 4, baseDelayMs: 1, maxDelayMs: 1) { _ in }
        self.init(config: config, gateway: gateway, cipherMode: cipherMode, key: key,
                  keyProvider: keyProvider,
                  blob: BlobTransport(session: blobSession, policy: policy))
    }

    // MARK: Session helpers

    /// The cache directory for one filespace (sharded under the configured root so
    /// multiple filespaces never collide).
    private func cacheDir(for filespace: FilespaceID) -> URL {
        URL(fileURLWithPath: config.cacheDir).appendingPathComponent(filespace, isDirectory: true)
    }

    /// Build (but do not register) a session for `filespace`.
    private func makeSession(_ filespace: FilespaceID, rootPoint: String?, mountPath: String?) async throws -> Session {
        let preferences = try loadCachePreferences()[filespace]
        let directory = preferences?.location.map { URL(fileURLWithPath: $0) } ?? cacheDir(for: filespace)
        let cache = try DiskBlockCache(filespace: filespace, directory: directory,
                                       maxBytes: preferences?.maxBytes ?? config.cacheSizeBytes, blockSize: blockSize)
        let crypto: any BlockCrypto
        // Production resolves every filespace independently through keyProvider.
        // A direct test/dev construction may supply the fallback key instead.
        // ONBOARDING.md "Key model": `keyProvider` (when set) now ALSO covers a gateway
        // fetch when neither local source has the key — see `FilespaceKeyResolver`.
        if let resolved = await keyProvider?(filespace) ?? key {
            crypto = try makeBlockCrypto(mode: cipherMode, key: resolved, blockSize: blockSize)
        } else {
            // No key wired (headless smoke / metadata-only). Stub crypto throws on
            // any byte op; metadata/cache/pin paths still work.
            crypto = StubBlockCrypto(mode: cipherMode)
        }
        // Audit B2: a per-filespace durable write-back journal under the cache dir, so
        // a staged write survives a crash/SIGTERM/disconnect and replays on start.
        let journal = WriteBackJournal(cacheDir: cacheDir(for: filespace).path, diskBudget: journalDiskBudget)
        // P3: when a commit lands, the item's contentVersion changed — drop stale
        // cached manifests so a reader still pinning the PRE-commit version
        // re-resolves from the gateway instead of assembling stale blocks.
        let leases = DistributedLeaseCoordinator(gateway: gateway, filespace: filespace)
        let transfer = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                                          blob: blob, blockSize: blockSize,
                                          prefetchConcurrency: min(kMaxTransferConcurrency, max(1, config.downloadConcurrency ?? kDefaultDownloadConcurrency)),
                                          uploadConcurrency: min(kMaxTransferConcurrency, max(1, config.uploadConcurrency ?? kDefaultUploadConcurrency)), journal: journal,
                                          leaseFence: { _, id in try await leases.ensureForUpload(id) },
                                          onCommit: { [weak self] fs, item, meta in
                                              await self?.noteCommitted(filespace: fs, itemID: item, meta: meta)
                                          })
        let record = EngineFilespace(id: filespace, name: filespace, status: .connected,
                                     mountPath: mountPath, rootPoint: rootPoint, role: nil)
        return Session(record: record, cache: cache, transfer: transfer, crypto: crypto, leases: leases, opens: DistributedOpenCoordinator(gateway: gateway, filespace: filespace), rangeLocks: DistributedRangeCoordinator(gateway: gateway, filespace: filespace),
                       streams: ChunkedStreamStore(filespace: filespace, gateway: gateway, crypto: crypto, blob: blob, cache: cache))
    }

    /// Require a connected session or throw `notConnected` (CLI exit 23).
    func require(_ filespace: FilespaceID) throws -> Session {
        guard let s = sessions[filespace] else {
            throw EngineError(.notConnected, "filespace \(filespace) is not connected")
        }
        return s
    }

    // MARK: - filespace / connection (CONTROL-API.md §4) -------------------

    public func filespaceList() async throws -> [EngineFilespace] {
        // Include mounts still creating their session: a list used by sign-out
        // must wait for their eventual publication, not omit them.
        for filespace in Set(sessions.keys).union(mountOperations).sorted() { try await reconcileMount(filespace) }
        let snapshots = try await snapshotMounts(SnapshotMountsParams())
        return (sessions.values.map(\.record) + snapshots.map(\.filespaceRecord)).sorted { $0.id < $1.id }
    }

    public func connect(_ p: FilespaceConnectParams) async throws -> EngineFilespace {
        await beginMountOperation(p.filespace)
        let record: EngineFilespace
        do { record = try await connectSession(p) }
        catch { endMountOperation(p.filespace); throw error }
        endMountOperation(p.filespace)
        if let at = p.mountAt {
            return try await mount(MountParams(filespace: p.filespace, at: at, rootPoint: p.rootPoint))
        }
        return record
    }

    /// Caller holds the lifecycle gate, shared with disconnect and mount.
    func connectSession(_ p: FilespaceConnectParams, offline: Bool = false) async throws -> EngineFilespace {
        precondition(mountOperations.contains(p.filespace), "Session connection requires the lifecycle gate")
        if let existing = sessions[p.filespace] {
            if existing.record.mountPath != nil, let requested = p.rootPoint,
               requested != (existing.record.rootPoint ?? "root") {
                throw EngineError(.conflict, "Unmount the filespace before choosing a different root")
            }
            existing.record.status = .connected
            _ = try await existing.transfer.resume(filespace: p.filespace)
            existing.paused = false
            readAhead.setPaused(false, filespace: p.filespace)
            directoryPrefetch.setPaused(false, filespace: p.filespace)
            existing.record.paused = false
            if let rp = p.rootPoint { existing.record.rootPoint = rp }
            return existing.record
        }
        let session = try await makeSession(p.filespace, rootPoint: p.rootPoint, mountPath: nil)
        // Audit B2: replay any un-committed staged writes from a prior crash before
        // serving, so dirty bytes drive to durability instead of being lost.
        sessions[p.filespace] = session
        readAhead.setPaused(false, filespace: p.filespace)
        directoryPrefetch.setPaused(false, filespace: p.filespace)
        do {
            if offline { _ = try await session.transfer.pause(filespace: p.filespace); session.paused = true }
            try await session.transfer.replayJournal()
            if offline { session.record.status = .offline; session.record.paused = true; return session.record }
            try await restorePinIntents(p.filespace)
            startChangeMonitor(p.filespace, session: session)
        }
        catch {
            stopPinMaintenance(p.filespace)
            await session.transfer.shutdown(filespace: p.filespace)
            await session.leases.shutdown()
            await session.rangeLocks.shutdown()
            await session.opens.shutdown(isDurable: { [transfer = session.transfer] id in
                !(await transfer.hasStagedStateAfterShutdown(filespace: p.filespace, itemID: id))
            })
            sessions[p.filespace] = nil
            throw error
        }
        return session.record
    }

    private func startChangeMonitor(_ filespace: FilespaceID, session: Session) {
        if gateway.supportsChangeNotifications && session.changeMonitor == nil {
                let identity = session.identity
                let monitor = ChangeFeedMonitor(gateway: gateway, filespace: filespace,
                    checkpointURL: cacheDir(for: filespace).appendingPathComponent("changes-v1.json"),
                    accessLost: { [weak self] in await self?.remoteAccessLost(filespace, identity: identity) }) { [weak self] page, reset in
                        guard let self else { throw CancellationError() }
                        try await self.applyRemoteChanges(filespace, identity: identity, page: page, reset: reset)
                    }
                session.changeMonitor = Task.detached(priority: .utility) { await monitor.run() }
            }
    }

    public func disconnect(_ p: FilespaceDisconnectParams) async throws -> EngineFilespace {
        if snapshotSessions[p.filespace] != nil { return try await snapshotUnmount(SnapshotUnmountParams(mountId: p.filespace, force: p.drain != true)).filespaceRecord }
        await beginMountOperation(p.filespace)
        defer { endMountOperation(p.filespace) }
        let session = try require(p.filespace)
        try await unmountSnapshotsForParent(p.filespace, force: p.drain != true)
        try await reconcileMount(p.filespace, session: session)
        if p.drain == true {
            // Audit B2: flush write-back before quiescing and DO NOT swallow the
            // result with `try?` — a drain that times out or fails must surface so the
            // caller knows dirty bytes are not yet durable (the journal still holds
            // them, so they replay on the next connect, but the operator must know).
            _ = try await session.transfer.flush(filespace: p.filespace, path: "", wait: true, timeoutMs: nil)
        }
        if session.record.mountPath != nil {
            try await mount.unmount(filespace: p.filespace, force: p.drain != true)
            removeMountIntent(filespace: p.filespace)   // graceful: no remount on next start
            session.record.mountPath = nil
        }
        if p.drain == true {
            // Kernel teardown can deliver a final write after the initial
            // barrier. Do not drop its session/credentials until it commits.
            _ = try await session.transfer.flush(filespace: p.filespace, path: "", wait: true, timeoutMs: 60_000)
        }
        // P2 — drain any pending coalesced LRU/atime index updates before we drop the
        // session, so a clean disconnect persists the last cache-HIT atimes (the
        // per-read index rewrite was removed; this is the bounded shutdown flush).
        stopPinMaintenance(p.filespace)
        readAhead.setPaused(false, filespace: p.filespace)
        directoryPrefetch.setPaused(false, filespace: p.filespace)
        readAhead.cancel(filespace: p.filespace)
        manifestRanges.invalidate(filespace: p.filespace)
        directoryPrefetch.invalidate(filespace: p.filespace)
        await session.transfer.shutdown(filespace: p.filespace)
        await readAhead.cancelAndWait(filespace: p.filespace)
        await directoryPrefetch.cancelAndWait(filespace: p.filespace)
        await session.cache.flush()
        for task in leaseCleanups[p.filespace]?.values ?? [:].values { task.cancel() }
        leaseCleanups[p.filespace] = nil
        await session.leases.shutdown()
        await session.rangeLocks.shutdown()
        for cleanup in openCleanups[p.filespace]?.values ?? [:].values {
            cleanup.firstClose.cancel()
            cleanup.retry.cancel()
        }
        openCleanups[p.filespace] = nil
        await session.opens.shutdown(isDurable: { [transfer = session.transfer] id in
                !(await transfer.hasStagedStateAfterShutdown(filespace: p.filespace, itemID: id))
            })
        session.record.status = .disconnected
        session.record.mountPath = nil
        var record = session.record
        session.changeMonitor?.cancel()
        sessions[p.filespace] = nil
        record.status = .disconnected
        return record
    }

    public func setConnectionState(_ p: FilespaceSetConnectionParams) async throws -> EngineFilespace {
        switch p.state {
        case .connected:
            return try await connect(FilespaceConnectParams(filespace: p.filespace))
        case .disconnected:
            // GUI "pause sync": keep the session but mark disconnected + pause transfers.
            let session = try require(p.filespace)
            readAhead.setPaused(true, filespace: p.filespace)
            directoryPrefetch.setPaused(true, filespace: p.filespace)
            _ = try? await session.transfer.pause(filespace: p.filespace)
            session.paused = true
            session.record.paused = true
            session.record.status = .disconnected
            return session.record
        }
    }

    // MARK: - mount (CONTROL-API.md §5.1) ----------------------------------

    public func mount(_ p: MountParams) async throws -> EngineFilespace {
        await beginMountOperation(p.filespace)
        defer { endMountOperation(p.filespace) }
        // Auto-connect if needed (mount implies an active metadata session).
        let session: Session
        if let s = sessions[p.filespace] {
            session = s
        } else {
            _ = try await connectSession(FilespaceConnectParams(filespace: p.filespace, rootPoint: p.rootPoint), offline: p.offlinePin != nil)
            session = try require(p.filespace)
        }
        try await reconcileMount(p.filespace, session: session)
        if let current = session.record.mountPath {
            if p.offlinePin != nil { throw EngineError(.conflict, "Eject the current volume before opening an offline copy") }
            if let requested = p.rootPoint, requested != (session.record.rootPoint ?? "root") {
                throw EngineError(.conflict, "Unmount the filespace before choosing a different root")
            }
            if let requested = p.at,
               try KernelMountTable.canonicalMountPath(requested) != current {
                throw EngineError(.conflict, "Unmount the filespace before moving its mount location")
            }
            // An idempotent Open in Finder must retain the adapter's captured
            // projection, including disambiguated granted-folder names.
            return session.record
        }
        if let offlinePin = p.offlinePin {
            let path = try normalizePinPath(offlinePin)
            guard let identity = await gateway.offlineIdentity(filespace: p.filespace) else { throw EngineError(.permissionDenied, "Sign in to the account that prepared this offline copy") }
            let checkpoint = try await OfflineCheckpoint.load(directory: stableStateDirectory(p.filespace), path: path, identity: identity, crypto: session.crypto)
            guard checkpoint.filespace == p.filespace else { throw EngineError(.permissionDenied, "Offline filespace mismatch") }
            _ = try await session.transfer.pause(filespace: p.filespace)
            session.paused = true; session.changeMonitor?.cancel(); session.changeMonitor = nil
            stopPinMaintenance(p.filespace)
            let base = OfflineDataPath(checkpoint: checkpoint, cache: session.cache, crypto: session.crypto,
                fileURL: OfflineCheckpoint.url(directory: stableStateDirectory(p.filespace), path: path),
                spillDir: stableStateDirectory(p.filespace).appendingPathComponent("offline-spill").path)
            let view = RootedDataPath(base: base, roots: checkpoint.roots, directRoot: checkpoint.roots.count == 1 && checkpoint.entries.first(where: { $0.item.id.rawValue == checkpoint.roots[0].id })?.item.isDir == true ? InodeID(checkpoint.roots[0].id) : nil)
            let mountPoint = try KernelMountTable.canonicalMountPath(p.at ?? defaultMountPoint(for: p.filespace))
            try await mount.mount(filespace: p.filespace, displayName: p.name ?? "Offline copy", at: mountPoint, engine: view)
            session.offlineDataPath = view; session.record.mountPath = mountPoint; session.record.status = .offline; session.record.paused = true; session.record.readOnly = true
            return session.record
        }
        session.offlineDataPath = nil; session.record.readOnly = false
        try await restorePinIntents(p.filespace)
        startChangeMonitor(p.filespace, session: session)
        let roots = try await gateway.mountRoots(filespace: p.filespace)
        guard !roots.isEmpty else { throw EngineError(.permissionDenied, "No shared folders are available to mount") }
        let requestedRoot = p.rootPoint ?? session.record.rootPoint
        if let requestedRoot, requestedRoot != "root" {
            guard roots.contains(where: { $0.id == requestedRoot }) || roots.contains(where: { $0.id == "root" }) else {
                throw EngineError(.permissionDenied, "Requested mount root is not an accessible shared folder")
            }
            let metadata = try await gateway.getItem(filespace: p.filespace, id: InodeID(requestedRoot))
            guard metadata.isDir else { throw EngineError(.invalidParams, "Mount root must be a folder") }
            session.mountRoots = [FilespaceMountRoot(id: requestedRoot, name: metadata.name, mountAsRoot: true)]
            session.directMountRoot = InodeID(requestedRoot)
        } else if roots.contains(where: { $0.id == "root" }) {
            session.mountRoots = nil
            session.directMountRoot = nil
        } else {
            session.mountRoots = roots
            session.directMountRoot = roots.count == 1 && roots[0].mountAsRoot ? InodeID(roots[0].id) : nil
        }
        let mountPoint = try KernelMountTable.canonicalMountPath(p.at ?? defaultMountPoint(for: p.filespace))
        // P2 (crash recovery): persist the mount INTENT before the backend call —
        // the SMB server keeps a listener thread, and a daemon crash while serving
        // leaves the kernel's hard mount wedged with no server. On the next start,
        // `remountPersisted()` clears the wedge and re-serves the volume. The intent
        // is removed by a graceful unmount/disconnect, or if the backend refuses.
        persistMountIntent(filespace: p.filespace, mountPoint: mountPoint,
                           rootPoint: p.rootPoint ?? session.record.rootPoint,
                           name: p.name)
        do {
            try await mount.mount(filespace: p.filespace, displayName: p.name,
                                  at: mountPoint, engine: dataPath(for: p.filespace))
        } catch {
            removeMountIntent(filespace: p.filespace)
            throw error
        }
        session.record.mountPath = mountPoint
        // Capture kernel ownership for safe crash cleanup. Never unmount an
        // unrelated volume merely because it occupies our old directory.
        let source = try? await mount.recoverySource(filespace: p.filespace)
        persistMountIntent(filespace: p.filespace, mountPoint: mountPoint,
                           rootPoint: p.rootPoint ?? session.record.rootPoint, name: p.name, source: source)
        session.record.status = .connected
        // A new Connect action starts transfers again. An idempotent mount
        // above preserves an existing mounted volume's deliberate pause.
        _ = try await session.transfer.resume(filespace: p.filespace)
        session.paused = false
        session.record.paused = false
        if let rp = p.rootPoint { session.record.rootPoint = rp }
        return session.record
    }

    public func unmount(_ p: UnmountParams) async throws -> EngineFilespace {
        if snapshotSessions[p.filespace] != nil { return try await snapshotUnmount(SnapshotUnmountParams(mountId: p.filespace, force: p.force)).filespaceRecord }
        await beginMountOperation(p.filespace)
        defer { endMountOperation(p.filespace) }
        let session = try require(p.filespace)
        try await reconcileMount(p.filespace, session: session)
        if session.record.mountPath != nil {
            try await mount.unmount(filespace: p.filespace, force: p.force ?? false)
        }
        session.record.mountPath = nil
        readAhead.cancel(filespace: p.filespace)
        manifestRanges.invalidate(filespace: p.filespace)
        directoryPrefetch.invalidate(filespace: p.filespace)
        removeMountIntent(filespace: p.filespace)   // graceful: no remount on next start
        if p.force != true {
            // With the volume gone, kernel writers cannot race this last remote
            // barrier. Failure preserves the session and journal for recovery.
            _ = try await session.transfer.flush(filespace: p.filespace, path: "", wait: true, timeoutMs: 60_000)
        }
        return session.record
    }

    private func defaultMountPoint(for filespace: FilespaceID) -> String {
        ("~/cloudfs/\(filespace)" as NSString).expandingTildeInPath
    }

    // MARK: - Mount-intent persistence + crash remount (P2) -----------------

    private struct PersistedMount: Codable, Sendable {
        let filespace: FilespaceID
        let mountPoint: String
        let rootPoint: String?
        var name: String?
        var source: String?
        var sourceFilespace: String?
        var snapshotId: String?
    }

    private nonisolated var mountsFile: URL {
        URL(fileURLWithPath: config.cacheDir).appendingPathComponent("mounts.json")
    }

    private func loadMountIntents() -> [PersistedMount] {
        guard let data = try? Data(contentsOf: mountsFile) else { return [] }
        return (try? JSONDecoder().decode([PersistedMount].self, from: data)) ?? []
    }

    func persistMountIntent(filespace: FilespaceID, mountPoint: String, rootPoint: String?,
                                    name: String?, source: String? = nil, sourceFilespace: String? = nil, snapshotId: String? = nil) {
        var all = loadMountIntents().filter { $0.filespace != filespace }
        all.append(PersistedMount(filespace: filespace, mountPoint: mountPoint,
                                  rootPoint: rootPoint, name: name, source: source, sourceFilespace: sourceFilespace, snapshotId: snapshotId))
        try? JSONEncoder().encode(all).write(to: mountsFile, options: .atomic)
    }

    func removeMountIntent(filespace: FilespaceID) {
        let all = loadMountIntents().filter { $0.filespace != filespace }
        if all.isEmpty { try? FileManager.default.removeItem(at: mountsFile) }
        else { try? JSONEncoder().encode(all).write(to: mountsFile, options: .atomic) }
    }

    /// Re-establish every persisted mount after a daemon crash (P2). For each intent:
    /// best-effort force-unmount the wedged mountpoint the dead SMB server left
    /// behind, then remount in a DETACHED task (the mount call may block
    /// until unmount). A graceful shutdown removed its intents, so this is a no-op
    /// after a clean stop. Returns immediately.
    public func remountPersisted() {
        for e in loadMountIntents() {
            guard Self.forceUnmountWedged(at: e.mountPoint, source: e.source) else {
                FileHandleText.err("cloudfsd: skipped recovery mount at \(e.mountPoint); another or unidentified volume occupies it")
                continue
            }
            let params = MountParams(filespace: e.filespace, at: e.mountPoint,
                                     rootPoint: e.rootPoint, name: e.name)
            Task { [weak self] in
                guard let self else { return }
                do {
                    if let source = e.sourceFilespace, let snapshot = e.snapshotId {
                        _ = try await self.snapshotMount(SnapshotMountParams(filespace: source, snapshotId: snapshot, at: e.mountPoint, name: e.name))
                    } else { _ = try await self.mount(params) }
                }
                catch {
                    FileHandleText.err("cloudfsd: remount \(params.filespace) at \(e.mountPoint) failed: \(error)")
                }
            }
        }
    }

    /// A kernel-table lookup does not traverse a dead volume. Recovery may only
    /// detach the exact source recorded after our successful mount, never a
    /// foreign/replacement volume or an older intent without ownership evidence.
    private static func forceUnmountWedged(at path: String, source: String?) -> Bool {
        guard let records = try? KernelMountTable.snapshot() else { return false }
        guard let existing = records.first(where: { $0.path == path }) else { return true }
        guard existing.isCloudFSLoopbackSMB, let source, existing.source == source else { return false }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/sbin/umount")
        proc.arguments = ["-f", path]
        do { try proc.run(); proc.waitUntilExit(); return proc.terminationStatus == 0 }
        catch { return false }
    }

    // MARK: - status (CONTROL-API.md §5.2) ---------------------------------

    public func status(_ p: StatusParams) async throws -> [EngineStatus] {
        if let fs = p.filespace {
            return [try await statusFor(fs)]
        }
        var out: [EngineStatus] = []
        for fs in sessions.keys.sorted() { out.append(try await statusFor(fs)) }
        return out
    }

    private func statusFor(_ filespace: FilespaceID) async throws -> EngineStatus {
        try await reconcileMount(filespace)
        let session = try require(filespace)
        let cacheInfo = try await session.cache.info(filespace: filespace)
        let sync = try await session.transfer.syncState(filespace: filespace, path: "")
        let connection: EngineStatus.Connection
        switch session.record.status {
        case .offline:      connection = .offline
        case .connected:    connection = .connected
        case .connecting:   connection = .connecting
        case .disconnected: connection = .disconnected
        }
        let health: EngineStatus.Health = sync.pendingUploads > 0 ? .yellow : .green
        let net = reachability.snapshot(filespace)
        let storage = blob.telemetry.snapshot(filespace)
        // A degraded/offline gateway is never reported "green".
        let finalHealth: EngineStatus.Health = net.reachability == .offline ? .red
            : ((net.reachability == .degraded || storage.reachability == "degraded") && health == .green ? .yellow : health)
        return EngineStatus(filespace: filespace, connection: connection,
                            mountPath: session.record.mountPath, latencyMsToBucket: storage.requestDurationMs,
                            pendingUploads: sync.pendingUploads, pendingBytes: sync.pendingBytes,
                            cache: cacheInfo, health: finalHealth,
                            lastSuccessAt: net.lastSuccessAt, lastFailureAt: net.lastFailureAt,
                            lastFailureReason: net.lastFailureReason, reachability: net.reachability,
                            mountedRootIds: Self.mountedGrantRootIDs(session), gatewayLatencyMs: net.latencyMs, storage: storage)
    }

    /// The grant roots a granted-folders projection was built from. nil for a whole-filespace
    /// mount (`mountRoots == nil`) or an explicit folder selection (`rootPoint` set), where new
    /// grants cannot widen what the volume shows.
    private static func mountedGrantRootIDs(_ session: Session) -> [String]? {
        guard session.record.mountPath != nil, let roots = session.mountRoots else { return nil }
        if let point = session.record.rootPoint, point != "root" { return nil }
        return roots.map(\.id).sorted()
    }

    // MARK: - cache (CONTROL-API.md §5.3) ----------------------------------

    public func cacheInfo(_ p: CacheInfoParams) async throws -> CacheInfo {
        var info = try await require(p.filespace).cache.info(filespace: p.filespace)
        let budget = try journalDiskBudget.snapshot()
        info.pendingWriteUsedBytes = budget.usedBytes
        info.pendingWriteReservedBytes = budget.reservedBytes
        info.pendingWriteLimitBytes = budget.limitBytes
        info.pendingWriteFreeSpaceReserveBytes = budget.freeSpaceReserveBytes
        return info
    }
    public func cacheClear(_ p: CacheClearParams) async throws -> CacheInfo {
        try await require(p.filespace).cache.clear(filespace: p.filespace)
    }

    // MARK: - pin / prefetch / evict (CONTROL-API.md §5.4) -----------------

    public func prefetch(_ p: PathParams) async throws -> PrefetchAck {
        let session = try require(p.filespace)
        // Control callers (GUI, Finder appex) speak filespace-relative PATHS; the
        // gateway speaks inodes. Resolve once here for the whole prefetch/pin path
        // (previously the path STRING was passed as an InodeID, so any real path
        // failed with "inode not found").
        let itemID = try await resolveInode(p.filespace, path: p.path)
        let ack = try await session.transfer.prefetch(filespace: p.filespace, path: p.path,
                                                      itemID: itemID)
        // Associate the path with its now-resident blocks so a later pin(path)/
        // evict(path) resolves them (the cache is content-addressed otherwise).
        try await registerPathBlocks(p.filespace, path: p.path, itemID: itemID, session: session)
        return ack
    }

    /// Resolve a filespace-relative path ("a/b/c.mov"; "" = the root) to its
    /// InodeID by walking the gateway namespace one segment at a time (listings
    /// are cursor-paginated). Throws `.notFound` naming the missing segment.
    func resolveInode(_ filespace: FilespaceID, path: String) async throws -> InodeID {
        var inode = InodeID.root
        for segment in path.split(separator: "/").map(String.init) {
            var cursor: String?
            var next: InodeID?
            repeat {
                let page = try await dataPath(for: filespace).enumerate(container: inode, page: cursor)
                if let hit = page.items.first(where: { $0.name == segment }) { next = hit.id; break }
                cursor = page.nextPage
            } while cursor != nil
            guard let found = next else {
                throw EngineError(.notFound, "no such path component '\(segment)' in '\(path)'")
            }
            inode = found
        }
        return inode
    }

    /// Fetch `path`'s block manifest and register the path→block-hash association
    /// in the cache, so pin/unpin/evict by that path resolve to those blocks. Called
    /// after a path's blocks are materialized (prefetch / read).
    private func registerPathBlocks(_ filespace: FilespaceID, path: String, itemID: InodeID,
                                    session: Session) async throws {
        let manifest = try await gateway.getBlockManifest(filespace: filespace, itemID: itemID)
        try await session.cache.registerPath(path, blocks: manifest.blocks.map(\.hash))
    }
    public func evict(_ p: PathParams) async throws -> EvictAck {
        await readAhead.cancelAndWait(filespace: p.filespace)
        await directoryPrefetch.cancelAndWait(filespace: p.filespace)
        _ = try await unpin(PinParams(filespace: p.filespace, path: p.path, recursive: true))
        return try await require(p.filespace).cache.evict(p.path)
    }

    // MARK: - transfers (CONTROL-API.md §5.5) ------------------------------

    public func transfersCurrent(_ p: FilespaceOnlyParams) async throws -> [Transfer] {
        try await require(p.filespace).transfer.current(filespace: p.filespace)
    }
    public func transfersPause(_ p: FilespaceOnlyParams) async throws -> PauseResult {
        let session = try require(p.filespace)
        readAhead.setPaused(true, filespace: p.filespace)
        directoryPrefetch.setPaused(true, filespace: p.filespace)
        session.paused = true
        session.record.paused = true
        return try await session.transfer.pause(filespace: p.filespace)
    }
    public func transfersResume(_ p: FilespaceOnlyParams) async throws -> PauseResult {
        let session = try require(p.filespace)
        readAhead.setPaused(false, filespace: p.filespace)
        directoryPrefetch.setPaused(false, filespace: p.filespace)
        session.paused = false
        session.record.paused = false
        session.record.status = .connected
        return try await session.transfer.resume(filespace: p.filespace)
    }

    // MARK: - sync barriers (CONTROL-API.md §5.6) --------------------------

    public func syncState(_ p: SyncStateParams) async throws -> SyncState {
        if snapshotSessions[p.filespace] != nil { return SyncState(path: p.path, inSync: true, pendingUploads: 0, pendingBytes: 0) }
        // Gateway inode IDs are opaque UUIDs, not paths. Until subtree barriers
        // carry an authoritative inode set, conservatively include the whole
        // filespace so a path-specific query can never claim dirty content is safe.
        let state = try await require(p.filespace).transfer.syncState(filespace: p.filespace, path: "/")
        return SyncState(path: p.path, inSync: state.inSync, pendingUploads: state.pendingUploads,
                         pendingBytes: state.pendingBytes)
    }
    public func flush(_ p: FlushParams) async throws -> SyncState {
        if snapshotSessions[p.filespace] != nil { return SyncState(path: p.path, inSync: true, pendingUploads: 0, pendingBytes: 0) }
        let state = try await require(p.filespace).transfer.flush(filespace: p.filespace, path: "/",
                                                                  wait: p.wait ?? false, timeoutMs: p.timeoutMs)
        return SyncState(path: p.path, inSync: state.inSync, pendingUploads: state.pendingUploads,
                         pendingBytes: state.pendingBytes)
    }

    // MARK: - versioning (CONTROL-API.md §8) -------------------------------

    public func systemVersion() async throws -> SystemVersionResult {
        SystemVersionResult(engine: CloudFSEngine.engineVersion, api: ControlAPI.version)
    }
    public static let engineVersion = "0.2.0-wave2b"

    // MARK: - §7 data path (out-of-process: File Provider appex) -----------
    //
    // The in-process mount calls `EngineDataPath.readRange` directly; this exposes the SAME
    // read over the control channel so the sandboxed File Provider extension (a separate process)
    // can stream decrypted byte ranges served from this daemon's relocatable cache. The range is
    // materialized into a temp/App-Group file whose path the client reads.
    public func dataReadRange(_ p: DataReadRangeParams) async throws -> DataReadRangeResult {
        let (ref, range) = try await dataPath(for: p.filespace).readRange(
            p.itemId, version: p.version, offset: p.offset, length: p.length,
            alignment: p.alignment ?? 0)
        return DataReadRangeResult(path: ref.path, fd: ref.fd, offset: range.offset, length: range.length)
    }

    public func dataLookup(_ p: DataLookupParams) async throws -> ItemMetadata {
        try await dataPath(for: p.filespace).lookup(p.itemId)
    }

    public func dataEnumerate(_ p: DataEnumerateParams) async throws -> DataEnumerateResult {
        let (items, next) = try await dataPath(for: p.filespace).enumerate(container: p.container, page: p.page)
        return DataEnumerateResult(items: items, nextPage: next)
    }

    public func dataEnumerateChanges(_ p: DataEnumerateChangesParams) async throws -> DataEnumerateChangesResult {
        let (updated, deleted, newAnchor, moreComing) =
            try await dataPath(for: p.filespace).enumerateChanges(container: p.container, anchor: p.anchor)
        return DataEnumerateChangesResult(updated: updated, deleted: deleted,
                                          newAnchor: newAnchor, moreComing: moreComing)
    }

    // MARK: - events (CONTROL-API.md §6) -----------------------------------

    /// Merge every connected filespace's transfer-progress stream into one
    /// control-plane notification stream (filtered by `filespace`/`kinds`). The
    /// stream finishes when the subscriber tears it down.
    public nonisolated func events(_ p: EventsSubscribeParams) -> AsyncStream<EventNotification> {
        AsyncStream(bufferingPolicy: .unbounded) { continuation in
            let pump = Task { [weak self] in
                guard let self else { continuation.finish(); return }
                await self.pumpEvents(p, into: continuation)
            }
            continuation.onTermination = { _ in pump.cancel() }
        }
    }

    private func wants(_ kind: EventsSubscribeParams.Kind, in p: EventsSubscribeParams) -> Bool {
        guard let kinds = p.kinds else { return true }   // nil => all kinds
        return kinds.contains(kind)
    }

    /// Subscribe to each in-scope filespace's transfer stream and republish as
    /// `transfer` notifications. (A `cache` snapshot is emitted on terminal
    /// transfers so the menu-bar usage gauge updates live.)
    private func pumpEvents(_ p: EventsSubscribeParams,
                            into continuation: AsyncStream<EventNotification>.Continuation) async {
        let targets: [FilespaceID]
        if let fs = p.filespace { targets = [fs] } else { targets = Array(sessions.keys) }
        let wantTransfer = wants(.transfer, in: p)
        let wantCache = wants(.cache, in: p)

        await withTaskGroup(of: Void.self) { group in
            for fs in targets {
                guard let session = sessions[fs] else { continue }
                let stream = session.transfer.progressEvents(filespace: fs)
                let cache = session.cache
                group.addTask {
                    for await t in stream {
                        if Task.isCancelled { break }
                        if wantTransfer {
                            continuation.yield(.transfer(filespace: fs, transfer: t))
                        }
                        if wantCache, t.state == .done || t.state == .error {
                            if let info = try? await cache.info(filespace: fs) {
                                continuation.yield(.cache(filespace: fs, cache: info))
                            }
                        }
                    }
                }
            }
        }
        continuation.finish()
    }

    // MARK: - data path (EngineDataPath for the mount adapter) -------------

    /// A per-filespace `EngineDataPath` view the mount backend forwards VFS ops to.
    func dataPath(for filespace: FilespaceID) -> any EngineDataPath {
        if let offline = sessions[filespace]?.offlineDataPath { return offline }
        if let snapshot = snapshotSessions[filespace], let path = snapshot.dataPath { return path }
        let base = EngineDataPathAdapter(filespace: filespace, engine: self)
        if let session = sessions[filespace], let roots = session.mountRoots {
            let projection = session.rootProjection ?? MountRootSnapshot(roots)
            session.rootProjection = projection
            return RootedDataPath(base: base, roots: roots, directRoot: session.directMountRoot, projection: projection)
        }
        return base
    }

    // Internal accessors the data-path adapter uses (actor-isolated).
    /// A fresh writable OPEN always reaches the gateway. A five-second positive
    /// cache avoids an extra metadata RTT for every 1 MiB SMB WRITE while bounding
    /// revocation latency; upload/commit independently recheck current permissions.
    func authorizeWrite(filespace: FilespaceID, id: InodeID, refresh: Bool) async throws {
        let session = try require(filespace)
        if !refresh, let until = session.writeAuthorizations[id], until > Date() { return }
        session.writeAuthorizations[id] = nil // failed fresh checks revoke old local admission
        try await gateway.authorizeWrite(filespace: filespace, id: id)
        if session.writeAuthorizations.count >= 1024 {
            session.writeAuthorizations = session.writeAuthorizations.filter { $0.value > Date() }
            if session.writeAuthorizations.count >= 1024 { session.writeAuthorizations.removeAll() }
        }
        session.writeAuthorizations[id] = Date().addingTimeInterval(5)
    }

    private struct OpenCleanup {
        let id: UUID
        let firstClose: Task<Bool,Never>
        let retry: Task<Void,Never>
    }
    private var openCleanups: [FilespaceID: [String: OpenCleanup]] = [:]
    func beginOpen(filespace: FilespaceID, id: InodeID, handle: String, access: OpenFileAccess, sharing: OpenFileSharing) async throws {
        try await require(filespace).opens.open(id,handle:handle,access:access,sharing:sharing)
    }
    func beginStreamOpen(filespace: FilespaceID, id: InodeID, handle: String,
                         access: OpenFileAccess, sharing: OpenFileSharing,
                         name: String, required: Bool) async throws -> Int? {
        try await require(filespace).opens.openStream(id,handle:handle,access:access,
            sharing:sharing,name:name,required:required)
    }
    func endOpen(filespace: FilespaceID, id: InodeID, handle: String) async {
        guard let session = sessions[filespace] else { return }
        if let cleanup = openCleanups[filespace]?[handle] {
            if await cleanup.firstClose.value {
                cleanup.retry.cancel()
                if openCleanups[filespace]?[handle]?.id == cleanup.id { openCleanups[filespace]?[handle] = nil }
            }
            return
        }
        let transfer = session.transfer, opens = session.opens
        // Acknowledged local writes must finish before the final open reference
        // can release an unlinked inode's cloud payload. Wait for this bounded
        // first attempt so an immediate SMB delete-on-close can acquire an
        // exclusive handle after CLOSE. Failed flushes leave the journal intact
        // and keep renewing this reference during background recovery.
        let firstClose = Task<Bool,Never> {
            do {
                _ = try await transfer.flush(filespace:filespace,path:id.rawValue,wait:true,timeoutMs:60_000)
                try Task.checkCancellation()
                guard await transfer.stagedState(filespace:filespace,itemID:id) == nil else { return false }
                return await opens.close(handle)
            } catch { return false }
        }
        let cleanupID = UUID()
        let retry = Task { [weak self] in
            guard !(await firstClose.value) else { return }
            while !Task.isCancelled {
                do { try await Task.sleep(for:.seconds(5)) } catch { return }
                guard let self else { return }
                if await self.attemptOpenClose(filespace:filespace,id:id,handle:handle,transfer:transfer,opens:opens) {
                    await self.finishOpenCleanup(filespace:filespace,handle:handle,id:cleanupID)
                    return
                }
            }
        }
        openCleanups[filespace,default:[:]][handle] = OpenCleanup(id:cleanupID,firstClose:firstClose,retry:retry)
        if await firstClose.value {
            retry.cancel()
            if openCleanups[filespace]?[handle]?.id == cleanupID { openCleanups[filespace]?[handle] = nil }
        }
    }

    private func attemptOpenClose(filespace: FilespaceID, id: InodeID, handle: String,
                                  transfer: RealTransferEngine, opens: DistributedOpenCoordinator) async -> Bool {
        do {
            _ = try await transfer.flush(filespace:filespace,path:id.rawValue,wait:true,timeoutMs:60_000)
            try Task.checkCancellation()
            guard await transfer.stagedState(filespace:filespace,itemID:id) == nil else { return false }
            return await opens.close(handle)
        } catch { return false }
    }

    private func finishOpenCleanup(filespace: FilespaceID, handle: String, id: UUID) {
        guard openCleanups[filespace]?[handle]?.id == id else { return }
        openCleanups[filespace]?[handle] = nil
    }

    func beginWrite(filespace: FilespaceID, id: InodeID, handle: String) async throws {
        _ = try await require(filespace).leases.ensure(id, handle: handle)
    }
    func beginWriteSnapshot(filespace: FilespaceID, id: InodeID, handle: String) async throws -> ItemMetadata? {
        try await require(filespace).leases.ensureWithItem(id, handle: handle).item
    }
    func writeFence(filespace: FilespaceID, id: InodeID) async throws -> Int? {
        try await require(filespace).leases.ensure(id)
    }
    func endWrite(filespace: FilespaceID, id: InodeID, handle: String) async {
        guard let session = sessions[filespace] else { return }
        if await session.leases.close(id, handle: handle) {
            scheduleLeaseCleanup(filespace: filespace, itemID: id)
        }
    }
    private func scheduleLeaseCleanup(filespace: FilespaceID, itemID: InodeID) {
        guard let session = sessions[filespace], leaseCleanups[filespace]?[itemID] == nil else { return }
        let transfer = session.transfer, leases = session.leases
        leaseCleanups[filespace, default: [:]][itemID] = Task {
            do {
                while !Task.isCancelled {
                    _ = try await transfer.flush(filespace: filespace, path: itemID.rawValue, wait: true, timeoutMs: nil)
                    if await leases.releaseIfUnused(itemID, isDurable: {
                        await transfer.stagedState(filespace: filespace, itemID: itemID) == nil
                    }) { break }
                    try await Task.sleep(for: .milliseconds(10))
                }
            } catch { /* Journal and lease survive failed flush for explicit recovery. */ }
            leaseCleanups[filespace]?[itemID] = nil
        }
    }
    func withClosedWriteHandles<T: Sendable>(filespace: FilespaceID, itemID: InodeID,
        operation: @Sendable () async throws -> T) async throws -> T {
        try await require(filespace).leases.withClosedHandles(itemID, operation: operation)
    }
    func resetWriteLease(filespace: FilespaceID, itemID: InodeID) async throws {
        try await require(filespace).leases.resetForRecovery(itemID)
    }

    func streamStore(_ filespace: FilespaceID) throws -> ChunkedStreamStore { try require(filespace).streams }
    func checkRangeAccess(filespace: FilespaceID, id: InodeID, handle: String, offset: UInt64, length: UInt64, write: Bool) async throws {
        let session=try require(filespace), ranges=session.rangeLocks
        try await session.opens.check(id,handle:handle)
        try await session.leases.withPublicationProtection(id) { deadline in
            try await ranges.check(id,handle:handle,offset:offset,length:length,write:write,publicationDeadline:deadline)
        }
    }
    func rangeLockCoordinator(_ filespace: FilespaceID) throws -> DistributedRangeCoordinator { try require(filespace).rangeLocks }
    func sessionGateway() -> any GatewayClient { gateway }
    func sessionFor(_ filespace: FilespaceID) throws
        -> (cache: DiskBlockCache, transfer: RealTransferEngine, crypto: any BlockCrypto) {
        let s = try require(filespace)
        return (s.cache, s.transfer, s.crypto)
    }
    nonisolated var dataBlockSize: Int { blockSize }

    /// Audit B15 — a 0700, daemon-owned directory for transient decrypted plaintext (read
    /// materialization + write staging). Replaces the world-readable system `/tmp`: spilling
    /// decrypted bytes into `/tmp` on every read/write contradicted the encrypted-at-rest posture
    /// and exposed plaintext to other local users on a shared Mac. Created lazily with 0700 perms.
    ///
    /// Base is the cache root the admin chose (inherits the cache volume, swept with the cache).
    /// `CLOUDFS_SPILL_DIR` overrides the base — the macOS File-Provider launcher sets it to the
    /// App Group container so the *sandboxed* appex can read the bytes the daemon materializes for
    /// an out-of-process `data.readRange` (the daemon stays generic; the Apple path is injected).
    nonisolated func plaintextSpillDir() -> URL {
        let base = ProcessInfo.processInfo.environment["CLOUDFS_SPILL_DIR"]
            .flatMap { $0.isEmpty ? nil : $0 } ?? config.cacheDir
        let dir = URL(fileURLWithPath: base).appendingPathComponent(".plaintext-spill", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        return dir
    }
}
