// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSTransfer — the real prefetch / download / async-upload data mover.
// (DESIGN.md §4) Owner: TRANSFER.
//
// Composes the already-built leaf modules behind their frozen seams:
//   • CloudFSCache  (BlockCache)   — content-addressed 1 MiB block store, pin/evict.
//   • CloudFSCrypto (BlockCrypto)  — encrypt-on-write / decrypt-on-read, hash == SHA256(ct).
//   • CloudFSGateway(GatewayClient)— presign (GET/PUT), block-manifest GET/PUT.
//   • BlobTransport                — the presigned-URL byte plane (range GET / PUT) + retry.
//
// THE CONTRACT (TransferEngine):
//  READ  ensureRange  : align to blocks → cache HIT serves; MISS → presign(GET) →
//                       range GET ciphertext → decrypt → putBlock → resident.
//  PREFETCH prefetch  : enqueue every block under a path, bounded-concurrent, warm
//                       the cache ahead of the read (hides the hard-mount stall).
//  WRITE  stageWrite  : buffer the region (ack-local, never block the VFS callback) +
//                       kick a SEPARATE async upload task: encrypt → presign(PUT) →
//                       PUT each block → CAS the block manifest → mark synced.
//  BARRIER flush/syncState : pending upload/byte counts; flush{wait} awaits durability.
//  transfers.current/pause/resume + progressEvents(AsyncStream) for the control plane.
//
// Concurrency: an `actor` serializes all mutable bookkeeping; the network/SSD work
// runs in detached child tasks (download fan-out via TaskGroup with a bounded
// permit count; uploads on their own task per item) so the hot read path and the
// async write-back never block each other or a VFS callback.

import Foundation
import CryptoKit
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway

public actor RealTransferEngine: TransferEngine {

    // MARK: Dependencies (the composed seams)

    private let cache: BlockCache
    private let crypto: BlockCrypto
    private let gateway: GatewayClient
    private let writePresigns: WritePresignBatcher
    private let uploadReceipts: UploadReceiptBatcher
    private let readPresigns: ReadPresignBatcher
    private let verifiedBlocks = VerifiedBlockWindow()
    private let blob: BlobTransport
    private let leaseFence: (@Sendable (FilespaceID, InodeID) async throws -> Int?)?
    private let blockSize: Int
    private let prefetchConcurrency: Int
    private let downloadPool: TransferPermitPool
    private let uploadPool: TransferPermitPool
    private let uploadConcurrency: Int
    private let uploadPreparation: UploadPreparationBudget
    private let uploadPreparationLimit: Int
    /// Early and normal uploads share a global block-image preparation budget.
    /// A second bounded window prepares authorization while payloads transfer.
    /// Early PUTs never publish a manifest or own durability.
    private var earlyUploadCount = 0
    private var earlyUploadPeak = 0
    private var earlyUploadFileCursor = 0
    private var activeUploadRuns = 0
    private var closing: Set<FilespaceID> = []
    // Keep superseded tasks until they actually unwind. The current `uploads`
    // slot alone cannot describe all old generations still using the journal.
    private var uploadTasks: [UUID: (FilespaceID, Task<Void, Error>)] = [:]
    private var earlyTasks: [UUID: (FilespaceID, Task<Void, Never>)] = [:]
    private var downloadTasks: [UUID: (FilespaceID, Task<Void, Never>)] = [:]
    private var shutdownWaiters: [FilespaceID: [CheckedContinuation<Void, Never>]] = [:]
    func uploadRunCount() -> Int { activeUploadRuns }
    func earlyUploadMetrics() -> (active: Int, peak: Int) { (earlyUploadCount, earlyUploadPeak) }
    func uploadPreparationMetrics() -> UploadPreparationBudget.Metrics { uploadPreparation.metrics() }
    func uploadPayloadMetrics() async -> TransferPermitPool.Metrics { await uploadPool.metrics() }
    func uploadReceiptMetrics() async -> UploadReceiptBatcher.Metrics { await uploadReceipts.metrics() }
    func uploadPreparationCapacity() -> (preparation: Int, receipts: Int) { (uploadPreparationLimit, Self.receiptCapacity(uploadConcurrency: uploadConcurrency)) }

    // MARK: Mutable bookkeeping (actor-isolated)

    /// In-flight + recent transfers, keyed by transfer id, per filespace.
    private var transfersByFilespace: [FilespaceID: [String: Transfer]] = [:]
    private var terminalTransferIDs: [FilespaceID: [String]] = [:]
    private var uploadTransferIDs: [StagingKey: String] = [:]
    static let terminalTransferLimit = 128
    func retainedTransferCount(filespace: FilespaceID) -> Int { transfersByFilespace[filespace]?.count ?? 0 }
    /// Whether the transfer pool is paused, per filespace.
    private var paused: Set<FilespaceID> = []
    private struct PauseWaiter {
        let filespace: FilespaceID
        let ticket: TransferPermitPool.Ticket?
        let continuation: CheckedContinuation<Void, Error>
    }
    private var pauseWaiters: [UUID: PauseWaiter] = [:]
    private var backgroundDownloadIDs: Set<String> = []
    func pausedWaiterCount(filespace: FilespaceID) -> Int {
        pauseWaiters.values.filter { $0.filespace == filespace }.count
    }

    /// Park without holding a payload permit or the write mutation gate. A
    /// demand read joining a background flight wakes just that promoted ticket.
    private func awaitTransferResume(_ filespace: FilespaceID,
                                     ticket: TransferPermitPool.Ticket? = nil) async throws {
        try requireOpen(filespace)
        try Task.checkCancellation()
        while shouldPause(filespace, ticket: ticket) {
            let id = UUID()
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                    if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                    else { pauseWaiters[id] = PauseWaiter(filespace: filespace, ticket: ticket, continuation: continuation) }
                }
            } onCancel: { Task { await self.cancelPauseWaiter(id) } }
            try requireOpen(filespace)
            try Task.checkCancellation()
        }
    }
    private func shouldPause(_ filespace: FilespaceID, ticket: TransferPermitPool.Ticket? = nil) -> Bool {
        paused.contains(filespace) && (ticket?.pausesWithBackground ?? true)
    }
    private func cancelPauseWaiter(_ id: UUID) {
        pauseWaiters.removeValue(forKey: id)?.continuation.resume(throwing: CancellationError())
    }
    private func wakePauseWaiters(filespace: FilespaceID, ticket: TransferPermitPool.Ticket? = nil,
                                  cancelled: Bool = false) {
        let ids = pauseWaiters.compactMap { id, waiter in
            waiter.filespace == filespace && (ticket == nil || waiter.ticket?.id == ticket?.id) ? id : nil
        }
        for id in ids {
            guard let waiter = pauseWaiters.removeValue(forKey: id) else { continue }
            if cancelled { waiter.continuation.resume(throwing: CancellationError()) }
            else { waiter.continuation.resume() }
        }
    }
    /// Pending (not-yet-durable) staged writes per item: sparse plaintext buffer.
    private var staging: [StagingKey: StagedItem] = [:]
    /// In-flight upload tasks per item, so flush{wait} can await durability.
    private var uploads: [StagingKey: Task<Void, Error>] = [:]
    /// Per-key OWNERSHIP generation (Findings 1 & 3). `scheduleUpload` bumps this
    /// each time it supersedes a prior in-flight upload; `runUpload` captures its
    /// generation and only the CURRENT owner (gen[key] == myGen) may mutate
    /// `staging`/`uploads`/`lastError` or publish a terminal event. A superseded
    /// task must clear nothing, poison nothing, and publish nothing — the
    /// replacement task owns durability.
    private var uploadGen: [StagingKey: Int] = [:]
    private var deferredUploads: Set<StagingKey> = []
    private var localCommitVersions: [StagingKey: (latest: String, prior: Set<String>)] = [:]
    private func versionForWrite(_ supplied: String?, key: StagingKey) -> String? {
        guard let known = localCommitVersions[key], supplied == nil || known.prior.contains(supplied!) else { return supplied }
        return known.latest
    }

    /// Namespace/basic-info updates increment the same revision used by content
    /// CAS. Drain this inode, then exclude staging/commit until the metadata RPC
    /// completes. Otherwise an atomic-save rename races its own pending upload.
    public func mutateMetadata(filespace: FilespaceID, itemID: InodeID, replacingID: InodeID? = nil,
        operation: @Sendable () async throws -> (before: ItemMetadata, after: ItemMetadata)) async throws -> ItemMetadata {
        let key = StagingKey(filespace: filespace, itemID: itemID)
        // Stable ordering makes two concurrent opposing replacements deadlock-free.
        // Drain both inodes before holding the pair through the atomic remote RPC.
        let keys = Set([itemID, replacingID].compactMap { $0 }).sorted { $0.rawValue < $1.rawValue }
            .map { StagingKey(filespace: filespace, itemID: $0) }
        var acquired: [StagingKey] = []
        do {
            for next in keys {
                try await acquireDrainedMutation(next)
                acquired.append(next)
            }
        } catch { for held in acquired.reversed() { releaseMutation(held) }; throw error }
        defer { for held in acquired.reversed() { releaseMutation(held) } }
        try requireOpen(filespace)
        try Task.checkCancellation()
        let (before, after) = try await operation()
        if let replacingID { localCommitVersions[StagingKey(filespace: filespace, itemID: replacingID)] = nil }
        // Only carry old open-handle revisions across our own metadata-only
        // change. Never rebase a stale writer across another client's content.
        if before.contentVersion == after.contentVersion {
            let known = localCommitVersions[key]
            var prior = known?.latest == before.metadataVersion ? known!.prior : []
            prior.insert(before.metadataVersion)
            if prior.count > 128 { prior = Set(prior.sorted().suffix(128)) }
            localCommitVersions[key] = (after.metadataVersion, prior)
        } else {
            localCommitVersions[key] = nil
        }
        return after
    }
    /// Explicit deletion drains acknowledged writes before tombstoning an inode.
    /// Atomic-save replacement uses mutateMetadata's two-inode gate instead.
    public func deleteItem(filespace: FilespaceID, itemID: InodeID,
                           operation: @Sendable () async throws -> Void) async throws {
        let key = StagingKey(filespace: filespace, itemID: itemID)
        try await acquireDrainedMutation(key)
        defer { releaseMutation(key) }
        try requireOpen(filespace)
        try Task.checkCancellation()
        try await operation()
        localCommitVersions[key] = nil
    }

    private func acquireDrainedMutation(_ key: StagingKey) async throws {
        let deadline = Date().addingTimeInterval(30)
        while true {
            try Task.checkCancellation()
            try requireOpen(key.filespace)
            let remaining = Int(deadline.timeIntervalSinceNow * 1000)
            guard remaining > 0 else { throw EngineError(.syncFailed, "Timed out draining writes before namespace or metadata update") }
            _ = try await flush(filespace: key.filespace, path: key.itemID.rawValue, wait: true, timeoutMs: remaining)
            await acquireMutation(key)
            if staging[key] != nil {
                releaseMutation(key)
                continue // A writer arrived between the drain and the gate.
            }
            break
        }
    }
    /// Progress-event fan-out. Held in a thread-safe, lock-protected sink so a
    /// subscriber can register SYNCHRONOUSLY the moment it holds the stream — if
    /// registration were deferred to a child Task, a fast download could publish
    /// (and finish) before the subscriber was attached, dropping the terminal
    /// `.done` event and hanging the consumer forever.
    private let sink = ProgressSink()
    private var transferSeq: Int = 0

    private struct StagingKey: Hashable { let filespace: FilespaceID; let itemID: InodeID }

    private var mutating: Set<StagingKey> = []
    private var mutationWaiters: [StagingKey: [CheckedContinuation<Void, Never>]] = [:]
    private func acquireMutation(_ key: StagingKey) async {
        if mutating.insert(key).inserted { return }
        await withCheckedContinuation { mutationWaiters[key, default: []].append($0) }
    }
    private func releaseMutation(_ key: StagingKey) {
        if var queue = mutationWaiters[key], !queue.isEmpty {
            let next = queue.removeFirst()
            mutationWaiters[key] = queue.isEmpty ? nil : queue
            next.resume()
        } else {
            mutating.remove(key)
            // Run after the local ACK path returns. Catch-up reads only a stable,
            // acknowledged journal image and keeps no queued payload copies.
            Task { pumpAppendUploads() }
        }
        finishShutdownWaiters(key.filespace)
    }
    private func requireOpen(_ filespace: FilespaceID) throws {
        guard !closing.contains(filespace) else { throw EngineError(.notConnected, "Filespace session is closed") }
    }
    private func shutdownDrained(_ filespace: FilespaceID) -> Bool {
        !mutating.contains(where: { $0.filespace == filespace }) &&
        !uploadTasks.values.contains(where: { $0.0 == filespace }) &&
        !earlyTasks.values.contains(where: { $0.0 == filespace }) &&
        !downloadTasks.values.contains(where: { $0.0 == filespace })
    }
    private func finishShutdownWaiters(_ filespace: FilespaceID) {
        guard shutdownDrained(filespace) else { return }
        for waiter in shutdownWaiters.removeValue(forKey: filespace) ?? [] { waiter.resume() }
    }
    private func invalidateUpload(_ key: StagingKey) {
        deferredUploads.remove(key)
        uploadGen[key, default: 0] += 1
        uploads[key]?.cancel()
        uploads[key] = nil
        retryTasks[key]?.cancel()
        retryTasks[key] = nil
    }

    /// One staged block: its length always; its bytes ONLY transiently (P1: with a
    /// journal — production always — the journal file IS the byte store; the bytes
    /// drop from RAM once durably journaled, guarded by `seq` so a CONCURRENT newer
    /// write's bytes are never dropped by an older write's completion). Without a
    /// journal (test engines) the bytes stay in RAM.
    private struct DirtyBlock: Sendable {
        var bytes: Data?
        var length: Int
        /// The per-item write sequence that produced this image (drop-guard).
        var seq: Int
        /// Bound to this immutable dirty image. Any overwrite/trim constructs a
        /// new DirtyBlock, so an earlier PUT cannot replace newer local bytes.
        var prepared: PreparedUpload? = nil
    }
    /// Cancellation removes only this manifest's waiter. The bounded immutable
    /// PUT continues for any newer generation that still references its bytes.
    private actor PreparedUpload {
        nonisolated let created = ContinuousClock.now
        private var result: Result<BlockRef, Error>?
        private var waiters: [UUID: CheckedContinuation<BlockRef, Error>] = [:]
        func complete(_ value: Result<BlockRef, Error>) {
            guard result == nil else { return }
            result = value
            let pending = waiters; waiters.removeAll()
            for waiter in pending.values { waiter.resume(with: value) }
        }
        func value() async throws -> BlockRef {
            try Task.checkCancellation()
            if let result { return try result.get() }
            let id = UUID()
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                    else { waiters[id] = continuation }
                }
            } onCancel: {
                Task { await self.cancel(id) }
            }
        }
        private func cancel(_ id: UUID) {
            waiters.removeValue(forKey: id)?.resume(throwing: CancellationError())
        }
    }

    /// A staged (dirty, not-yet-uploaded) item — P0 dirty-block model: only the blocks a
    /// write actually touched are held (and journaled, and uploaded). RAM/disk/network
    /// cost is proportional to the bytes written, never to the file size.
    private final class StagedItem {
        let generation = UUID()
        /// blockIndex → staged image (length in RAM; bytes paged from the journal).
        /// An image may be shorter than the block's logical extent (write-beyond-EOF);
        /// readers/uploader zero-pad to `min(blockSize, size - i*blockSize)`.
        var dirty: [Int: DirtyBlock] = [:]
        /// Staged logical file size. Ranged writes only grow it (`max`); a replace sets it.
        var size: Int = 0
        /// The committed manifest this edit merges UNCHANGED blocks from (ranged writes).
        /// nil = no committed content (new/empty file) or a replace (which merges nothing).
        var base: ResolvedBlockManifest?
        /// P4 — how many committed bytes are still ALIVE. Set to the committed size
        /// when `base` resolves; a truncate LOWERS it: committed content beyond a
        /// truncate point is dead and must read back as zeros if the file regrows —
        /// never as resurrected old bytes.
        var effectiveBaseSize: Int = 0
        /// P4 — the persisted ceiling on alive committed bytes (journal `committedLimit`):
        /// survives a crash so a replayed truncate-then-grow never resurrects dead
        /// committed content. `Int.max` = no truncate happened. A replace sets 0.
        var committedLimitCap: Int = Int.max
        /// Whether `base` was resolved (tri-state with `base == nil`: "no manifest exists"
        /// must not be re-fetched on every write callback).
        var baseFetched = false
        /// True after a whole-file replace: the staged content fully defines the file —
        /// non-dirty in-size blocks are ZEROS (holes), never merged from `base`.
        var replaced = false
        var lastError: String?
        var replayedWithoutBase = false
        /// Monotonic per-item write sequence (the DirtyBlock drop-guard, P1).
        var writeSeq = 0
        /// Eight distinct, complete dirty blocks in the newly extended region
        /// enable early PUTs. Kernel SMB may reorder sequential application writes.
        /// Keep only eight identities for eligibility and pending INDEX metadata;
        /// no plaintext queue grows with the file or with gaps in its offset range.
        var earlyEligibleBlocks: Set<Int> = []
        var pendingEarlyBlocks: Set<Int> = []
        var acceptsEarlyUploads = true
        /// The version the edit was based on (audit B4): threaded into the commit as
        /// `expectedVersion` so a concurrent save is a typed 409, not a silent
        /// last-writer-wins. nil = unconditional (a brand-new file / no base).
        var baseVersion: String?
        /// Lease fence to present at commit when this client holds one (audit B5).
        var fence: Int?
        /// How many times the async upload has failed transiently; drives the
        /// bounded-backoff retry (audit B2/`no retry`). Reset on success.
        var retryAttempt: Int = 0
        init() {}
        func copy() -> StagedItem {
            let copy = StagedItem()
            copy.dirty = dirty; copy.size = size; copy.base = base
            copy.effectiveBaseSize = effectiveBaseSize; copy.committedLimitCap = committedLimitCap
            copy.baseFetched = baseFetched; copy.replaced = replaced
            copy.lastError = lastError; copy.writeSeq = writeSeq
            copy.earlyEligibleBlocks = earlyEligibleBlocks
            copy.pendingEarlyBlocks = pendingEarlyBlocks
            copy.acceptsEarlyUploads = acceptsEarlyUploads
            copy.replayedWithoutBase = replayedWithoutBase
            copy.baseVersion = baseVersion; copy.fence = fence; copy.retryAttempt = retryAttempt
            return copy
        }
        /// Pending (dirty) bytes — what syncState reports and progress totals use.
        var byteCount: Int { dirty.values.reduce(0) { $0 + $1.length } }
        /// The journal-persisted form of `committedLimitCap` (nil = no kill-line).
        var persistedCommittedLimit: Int? { committedLimitCap == Int.max ? nil : committedLimitCap }
    }

    /// One staged block's plaintext: in-RAM bytes, or paged from the journal (P1).
    private func dirtyBlockData(_ block: DirtyBlock, filespace: FilespaceID,
                                itemID: InodeID, index: Int) throws -> Data {
        try requireOpen(filespace)
        if let bytes = block.bytes { return bytes }
        guard let bytes = try journal?.readBlock(filespace: filespace, itemID: itemID, blockIndex: index),
              bytes.count == block.length else {
            throw EngineError(.syncFailed, "Staged block \(index) is missing or truncated; local journal retained")
        }
        return bytes
    }

    /// The durable write-back journal (audit B2). nil only for in-memory test engines
    /// that opt out; production always supplies a cache-dir-backed journal so a crash
    /// after an acked VFS write replays the bytes.
    private let journal: WriteBackJournal?
    /// P3 — invoked with the gateway-returned metadata the moment a commit lands
    /// (BEFORE the staging overlay drops). The composition root uses it to
    /// invalidate its cached manifests for the item: a reader holding the
    /// pre-commit contentVersion must re-resolve, not assemble stale blocks.
    private let onCommit: (@Sendable (FilespaceID, InodeID, ItemMetadata) async -> Void)?
    /// Items the retry loop has parked (awaiting backoff). Keeps the retry timer task
    /// per key so a fresh stageWrite supersedes it.
    private var retryTasks: [StagingKey: Task<Void, Never>] = [:]
    /// Bounded retry policy for the upload pipeline.
    private let maxUploadRetries: Int
    private let retryBaseDelayMs: Int
    private let uploadDebounceMs: Int
    /// A bucket-requested cooldown survives per-file retries and new write
    /// generations; an explicit flush must not defeat Retry-After.
    private var uploadNotBefore: ContinuousClock.Instant?
    private var uploadCooldownError: EngineError?

    // MARK: Init

    public init(cache: BlockCache,
                crypto: BlockCrypto,
                gateway: GatewayClient,
                blob: BlobTransport = BlobTransport(),
                blockSize: Int = kDefaultBlockSize,
                prefetchConcurrency: Int = kDefaultDownloadConcurrency,
                uploadConcurrency: Int = kDefaultUploadConcurrency,
                journal: WriteBackJournal? = nil,
                maxUploadRetries: Int = 6,
                retryBaseDelayMs: Int = 200,
                uploadDebounceMs: Int = 20,
                leaseFence: (@Sendable (FilespaceID, InodeID) async throws -> Int?)? = nil,
                onCommit: (@Sendable (FilespaceID, InodeID, ItemMetadata) async -> Void)? = nil) {
        self.cache = cache
        self.crypto = crypto
        self.gateway = gateway
        self.readPresigns = ReadPresignBatcher(gateway: gateway)
        self.writePresigns = WritePresignBatcher(gateway: gateway)
        self.blob = blob
        self.blockSize = max(1, blockSize)
        self.prefetchConcurrency = min(kMaxTransferConcurrency, max(1, prefetchConcurrency))
        self.uploadConcurrency = min(kMaxTransferConcurrency, max(1, uploadConcurrency))
        // Authorization takes a material fraction of a block PUT's lifetime.
        // Prepare one additional payload window, capped at 96 block images
        // across early and normal work; the adaptive PUT ceiling is unchanged.
        self.uploadPreparationLimit = Self.preparationLimit(uploadConcurrency: self.uploadConcurrency)
        // Receipt metadata is bounded (~300 B each) but must hold every object
        // that can complete while four verification RPCs are in flight, or the
        // optimisation silently degrades to the final commit at high slot counts.
        self.uploadReceipts = UploadReceiptBatcher(gateway: gateway, capacity: Self.receiptCapacity(uploadConcurrency: self.uploadConcurrency), concurrency: 4)
        self.uploadPreparation = UploadPreparationBudget(limit: self.uploadPreparationLimit)
        self.downloadPool = TransferPermitPool(limit: self.prefetchConcurrency, profileName: "download")
        self.uploadPool = TransferPermitPool(limit: self.uploadConcurrency, profileName: "upload")
        self.journal = journal
        self.maxUploadRetries = max(0, maxUploadRetries)
        self.retryBaseDelayMs = max(1, retryBaseDelayMs)
        self.uploadDebounceMs = max(0, uploadDebounceMs)
        self.onCommit = onCommit
        self.leaseFence = leaseFence
    }

    /// Replay the durable journal on daemon start (audit B2): re-stage every entry
    /// that was acked but never committed, so the upload pipeline drives it to the
    /// bucket. Idempotent — a committed block dedups on the content address.
    /// Understands both the P0 per-block layout and the legacy whole-image layout
    /// (a legacy entry replays as a whole-file replace — its exact old semantics).
    public func replayJournal() async throws {
        guard let journal else { return }
        for e in try await journal.replay() {
            try requireOpen(e.filespace)
            let key = StagingKey(filespace: e.filespace, itemID: e.itemID)
            let item = StagedItem()
            if let whole = e.wholeData {
                // Legacy whole-image entry: convert to the per-block layout so the
                // journal becomes the byte store; on a conversion failure keep the
                // bytes in RAM (one-time, bounded by the pre-upgrade staging).
                let blocks = Self.chunkIntoBlocks(whole, blockSize: blockSize)
                do {
                    try await journal.recordReplace(filespace: e.filespace, itemID: e.itemID,
                                                    baseVersion: e.baseVersion,
                                                    size: whole.count, blocks: blocks)
                    item.dirty = blocks.mapValues { DirtyBlock(bytes: nil, length: $0.count, seq: 0) }
                } catch {
                    item.dirty = blocks.mapValues { DirtyBlock(bytes: $0, length: $0.count, seq: 0) }
                }
                item.size = whole.count
                item.replaced = true
            } else {
                // P1: lengths only — the bytes stay on disk and page in at upload.
                item.dirty = e.blockLengths.mapValues { DirtyBlock(bytes: nil, length: $0, seq: 0) }
                item.size = e.size
                // P4: a persisted truncate/replace kill-line survives the crash.
                item.committedLimitCap = e.committedLimit ?? Int.max
                // base manifest re-resolves lazily in runUpload (a CAS guards the merge).
            }
            item.replayedWithoutBase = !e.baseCaptured && e.wholeData == nil && e.committedLimit != 0
            if e.baseCaptured {
                item.base = e.base
                item.baseFetched = true
                item.effectiveBaseSize = min(item.committedLimitCap, e.base?.manifest.size ?? 0)
            }
            item.baseVersion = e.baseVersion
            staging[key] = item
            scheduleUpload(filespace: e.filespace, itemID: e.itemID, key: key)
        }
    }

    /// Split a dense image into per-index block images (replace/legacy-replay path).
    private static func chunkIntoBlocks(_ data: Data, blockSize: Int) -> [Int: Data] {
        var out: [Int: Data] = [:]
        var offset = 0, i = 0
        while offset < data.count {
            let end = min(offset + blockSize, data.count)
            out[i] = data.subdata(in: offset..<end)
            offset = end; i += 1
        }
        return out
    }

    // MARK: - READ / download (DESIGN.md §4.1) -----------------------------

    public func ensureRange(filespace: FilespaceID, itemID: InodeID, offset: Int, length: Int) async throws {
        try requireOpen(filespace)
        guard length > 0 else { return }
        // Resolve the manifest WITH the gateway's authoritative per-block object keys
        // so each block's range-GET targets the exact bucket key the store uses (not a
        // client-built `chunks/<shard>/<hash>` key). Fixes the engine↔gateway mismatch.
        let resolved = try await gateway.getResolvedBlockManifest(filespace: filespace, itemID: itemID)
        try await ensureBlocks(resolved: resolved, filespace: filespace, itemID: itemID,
                               offset: offset, length: length)
    }

    /// P2 — residency with a CALLER-SUPPLIED resolved manifest: the read path and the
    /// daemon-side read-ahead already hold the (engine-cached) manifest, so warming a
    /// range must not cost a fresh gateway round-trip per call (the old per-read
    /// prefetch storm did exactly that).
    public func ensureBlocks(resolved: ResolvedBlockManifest, filespace: FilespaceID,
                             itemID: InodeID, offset: Int, length: Int,
                             priority: TransferPriority = .demand,
                             background: Bool = false,
                             authorizationLookAheadBlocks: Int = 0,
                             progress: (@Sendable (Int) -> Void)? = nil) async throws {
        try requireOpen(filespace)
        try Task.checkCancellation()
        guard length > 0 else { return }
        let manifest = resolved.manifest
        let indices = blockIndices(forOffset: offset, length: length, manifest: manifest)
        guard !indices.isEmpty else { return }

        let transferID = newTransferID()
        if background || priority == .speculative { backgroundDownloadIDs.insert(transferID) }
        let total = indices.reduce(0) { $0 + manifest.blocks[$1].length }
        publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                         direction: .download, bytesDone: 0, bytesTotal: total, state: .active))

        do {
            let done = try await fetchBlocks(indices, of: resolved, filespace: filespace,
                                             itemID: itemID, transferID: transferID, total: total, priority: priority,
                                             background: background,
                                             authorizationLookAheadBlocks: authorizationLookAheadBlocks, progress: progress)
            publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                             direction: .download, bytesDone: done, bytesTotal: total, state: .done))
        } catch {
            let abandoned = priority == .speculative &&
                (error is CancellationError || error is TransferPermitPool.SpeculationDeferred)
            publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                             direction: .download, bytesDone: 0, bytesTotal: total,
                             state: abandoned ? .done : .error, error: abandoned ? nil : "\(error)"))
            throw error
        }
    }

    public func prefetch(filespace: FilespaceID, path: String, itemID: InodeID) async throws -> PrefetchAck {
        try requireOpen(filespace)
        try await awaitTransferResume(filespace)
        let resolved = try await gateway.getResolvedBlockManifest(filespace: filespace, itemID: itemID)
        let manifest = resolved.manifest
        // Only the blocks not already resident need queueing.
        var toQueue: [Int] = []
        for i in manifest.blocks.indices {
            if await cache.contains(manifest.blocks[i].hash) == false { toQueue.append(i) }
        }
        guard !toQueue.isEmpty else { return PrefetchAck(path: path, queuedBlocks: 0) }

        let transferID = newTransferID()
        backgroundDownloadIDs.insert(transferID)
        let total = toQueue.reduce(0) { $0 + manifest.blocks[$1].length }
        publish(Transfer(id: transferID, filespace: filespace, path: path,
                         direction: .download, bytesDone: 0, bytesTotal: total, state: .active))
        // Run the warm-up concurrently but don't block the ack: return queuedBlocks now.
        // (DESIGN.md §3.4 "returns queuedBlocks".) We await fetch so a caller that
        // wants determinism (and our tests) can observe completion; the fan-out is
        // bounded-concurrent so it is fast.
        do {
            let done = try await fetchBlocks(toQueue, of: resolved, filespace: filespace,
                                            itemID: itemID, transferID: transferID, total: total, background: true)
            publish(Transfer(id: transferID, filespace: filespace, path: path,
                             direction: .download, bytesDone: done, bytesTotal: total, state: .done))
            return PrefetchAck(path: path, queuedBlocks: toQueue.count)
        } catch {
            publish(Transfer(id: transferID, filespace: filespace, path: path,
                             direction: .download, bytesDone: 0, bytesTotal: total,
                             state: .error, error: "\(error)"))
            throw error
        }
    }

    /// Concurrent, bounded fan-out fetch of a set of block indices. Cache HIT is
    /// free; MISS goes presign(GET) → range GET → decrypt → putBlock. Returns the
    /// total bytes made resident. (DESIGN.md §3.4 prefetch pool, §4.1 read path.)
    private func fetchBlocks(_ indices: [Int], of resolved: ResolvedBlockManifest,
                             filespace: FilespaceID, itemID: InodeID,
                             transferID: String, total: Int, priority: TransferPriority = .demand,
                             background: Bool = false,
                             authorizationLookAheadBlocks: Int = 0,
                             progress: (@Sendable (Int) -> Void)? = nil) async throws -> Int {
        let blocks = resolved.manifest.blocks
        if background || priority == .speculative { try await awaitTransferResume(filespace) }
        var doneBytes = 0
        let limit = prefetchConcurrency

        // Register known cold keys as one coherent metadata window, before
        // individual downloads compete for payload capacity. Preparing URLs
        // does not fetch bytes; the batcher bounds retention and expires them.
        let following = min(32, max(0, authorizationLookAheadBlocks))
        if indices.count > 1 || following > 0 {
            var coldKeys: [String] = []
            for i in indices.prefix(min(128, limit * 2)) {
                try Task.checkCancellation()
                if await cache.contains(blocks[i].hash) == false {
                    coldKeys.append(resolved.objectKey(for: blocks[i].hash))
                }
            }
            // Only established sequential prediction opts into future metadata.
            // Already-resident windows do not issue authorization traffic, and
            // these extra keys never expand the actual byte-download extent.
            if !coldKeys.isEmpty, following > 0, let last = indices.last {
                let nominalEnd = last + 1 + min(following, blocks.count - last - 1)
                // Round the metadata horizon to a32-key cohort. Advancing one
                // payload block must not create another one-key authorization
                // RPC; at most63 future keys are considered, still URL-only.
                let padding = (32 - nominalEnd % 32) % 32
                let end = nominalEnd + min(padding, blocks.count - nominalEnd)
                for i in (last + 1)..<end {
                    try Task.checkCancellation()
                    if await cache.contains(blocks[i].hash) == false {
                        coldKeys.append(resolved.objectKey(for: blocks[i].hash))
                    }
                }
            }
            if coldKeys.count > 1 {
                await readPresigns.prepare(filespace: filespace, keys: coldKeys, priority: priority)
            }
        }

        try await withThrowingTaskGroup(of: Int.self) { group in
            var inFlight = 0
            var iterator = indices.makeIterator()

            func startNext() -> Bool {
                guard let i = iterator.next() else { return false }
                let ref = blocks[i]
                // The gateway-authoritative object key for this block (what presign targets).
                let objectKey = resolved.objectKey(for: ref.hash)
                group.addTask { [self] in
                    try await fetchOneBlock(ref, objectKey: objectKey, blockIndex: resolved.firstBlockIndex + i,
                                            filespace: filespace, itemID: itemID, priority: priority, background: background)
                    return ref.length
                }
                return true
            }

            // Prime up to `limit` tasks.
            while inFlight < limit, startNext() { inFlight += 1 }

            // Drain + refill, emitting progress as each block lands.
            while inFlight > 0 {
                let n = try await group.next()!
                inFlight -= 1
                doneBytes += n
                // No block payload escapes its worker: this reports residency
                // only after that worker has finished verified cache admission.
                progress?(doneBytes)
                publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                                 direction: .download, bytesDone: doneBytes, bytesTotal: total,
                                 state: .active))
                if startNext() { inFlight += 1 }
            }
        }
        return doneBytes
    }

    /// The complete identity is required: one hash offered under another inode,
    /// index or filespace must not inherit the first caller's AEAD verification.
    private struct DownloadKey: Hashable {
        let filespace: FilespaceID
        let itemID: InodeID
        let index: Int
        let hash: BlockHash
        let objectKey: String
        let length: Int
    }
    private final class SharedDownload {
        let id = UUID()
        let ticket: TransferPermitPool.Ticket
        var task: Task<Void, Never>?
        var subscribers: [UUID: CheckedContinuation<Void, Error>] = [:]
        init(priority: TransferPriority, background: Bool) { ticket = .init(priority: priority, background: background) }
    }
    private var inFlightBlocks: [DownloadKey: SharedDownload] = [:]
    private var downloadPromotions = 0
    private var abandonedDownloads = 0
    func downloadSchedulingMetrics() async -> (pool: TransferPermitPool.Metrics, flights: Int, subscribers: Int, promotions: Int, abandoned: Int) {
        let pool = await downloadPool.metrics()
        return (pool, inFlightBlocks.count, inFlightBlocks.values.reduce(0) { $0 + $1.subscribers.count },
                downloadPromotions, abandonedDownloads)
    }
    func uploadSchedulingMetrics() async -> TransferPermitPool.Metrics { await uploadPool.metrics() }

    /// Fetch ONE block: cache HIT short-circuits; in-flight fetch awaited (dedup);
    /// MISS = presign(GET) → range GET ciphertext → verify+decrypt → admit the
    /// CIPHERTEXT into the cache.
    ///
    /// The cache is content-addressed by `SHA256(stored bytes)` and `ref.hash` IS
    /// `SHA256(ciphertext)` (== the bucket object key). So the block is stored and
    /// served as ciphertext keyed by `ref.hash`: `contains(ref.hash)` is a valid
    /// pre-fetch residency test (we can't know the plaintext hash before fetching),
    /// the cache integrity check holds, and blocks rest encrypted on disk. We
    /// decrypt on the way out to the VFS, never persisting plaintext.
    private nonisolated static func retryPresign(_ operation: @Sendable () async throws -> PresignedURL) async throws -> PresignedURL {
        let deadline = ContinuousClock.now.advanced(by: .seconds(60))
        for attempt in 0..<16 {
            try Task.checkCancellation()
            do { return try await operation() }
            catch let error as EngineError {
                let delay: Double
                switch error.data?["retryAfter"] {
                case .string(let value): delay = Double(value) ?? 1
                case .int(let value): delay = Double(value)
                default: delay = 1
                }
                guard attempt < 15, error.message == "rate_limited", delay.isFinite, delay >= 0 else { throw error }
                let remaining = ContinuousClock.now.duration(to: deadline).components
                let seconds = Double(remaining.seconds) + Double(remaining.attoseconds) / 1e18
                // Do not truncate a server-requested wait and retry too early.
                // Propagate its hint to the durable upload retry layer instead.
                guard delay < seconds else { throw error }
                try await Task.sleep(for: .seconds(max(0.01, delay)))
            }
        }
        throw EngineError(.gatewayError, "Presign retry exhausted")
    }

    private func fetchOneBlock(_ ref: BlockRef, objectKey: String, blockIndex: Int,
                               filespace: FilespaceID, itemID: InodeID,
                               priority: TransferPriority = .demand, background: Bool = false) async throws {
        try requireOpen(filespace)
        try Task.checkCancellation()
        let resident = await cache.contains(ref.hash)
        try requireOpen(filespace)
        try Task.checkCancellation()
        if resident { return }
        let key = DownloadKey(filespace: filespace, itemID: itemID, index: blockIndex,
                              hash: ref.hash, objectKey: objectKey, length: ref.length)
        let subscriber = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                // No suspension between lookup and insertion: simultaneous cache
                // misses share exactly one fetch and every caller owns a waiter.
                if let flight = inFlightBlocks[key] {
                    flight.subscribers[subscriber] = continuation
                    if priority == .demand, !background, flight.ticket.pausesWithBackground {
                        downloadPromotions += 1
                        flight.ticket.promote()
                        wakePauseWaiters(filespace: filespace, ticket: flight.ticket)
                        Task {
                            await downloadPool.promote(flight.ticket)
                            await readPresigns.promote(flight.ticket)
                        }
                    }
                    return
                }
                let flight = SharedDownload(priority: priority, background: background)
                flight.subscribers[subscriber] = continuation
                inFlightBlocks[key] = flight
                let task = Task { [self] in
                    defer { downloadTasks[flight.id] = nil; finishShutdownWaiters(filespace) }
                    while true {
                        let result: Result<Void, Error>
                        do {
                            try await performDownload(ref, key: key, ticket: flight.ticket)
                            result = .success(())
                        } catch {
                            // Demand may join between the pool shedding queued
                            // speculation and this actor receiving that result.
                            // Promotion must never turn a real read into a shed
                            // prefetch. The sticky demand ticket retries normally.
                            if error is TransferPermitPool.SpeculationDeferred,
                               flight.ticket.priority == .demand { continue }
                            result = .failure(error)
                        }
                        finishDownload(key, id: flight.id, result: result)
                        return
                    }
                }
                flight.task = task
                downloadTasks[flight.id] = (filespace, task)
            }
        } onCancel: { Task { await self.cancelDownload(key, subscriber: subscriber) } }
    }

    private func cancelDownload(_ key: DownloadKey, subscriber: UUID) async {
        guard let flight = inFlightBlocks[key],
              let continuation = flight.subscribers.removeValue(forKey: subscriber) else { return }
        if !flight.subscribers.isEmpty {
            continuation.resume(throwing: CancellationError())
            return
        }
        abandonedDownloads += 1
        inFlightBlocks[key] = nil
        flight.task?.cancel()
        // The final subscriber drains its abandoned worker before returning.
        // A caller cancelling read-ahead can then evict cache bytes knowing no
        // detached decrypt/cache insertion will repopulate them afterwards.
        await flight.task?.value
        continuation.resume(throwing: CancellationError())
    }

    private func finishDownload(_ key: DownloadKey, id: UUID, result: Result<Void, Error>) {
        guard let flight = inFlightBlocks[key], flight.id == id else { return }
        inFlightBlocks[key] = nil
        for subscriber in flight.subscribers.values { subscriber.resume(with: result) }
    }

    private func performDownload(_ ref: BlockRef, key: DownloadKey,
                                 ticket: TransferPermitPool.Ticket) async throws {
        let crypto = self.crypto, cache = self.cache
        let readPresigns = self.readPresigns, verifiedBlocks = self.verifiedBlocks
        let downloadPool = self.downloadPool
        // Metadata authorization has its own bounded, prioritized RPC queue.
        // Let it overlap active GETs instead of occupying a payload permit for
        // an entire gateway round trip. Recheck before signing too: a stale
        // cache miss may outlive another flight's completed admission.
        if await cache.contains(ref.hash) {
            WriteProfiler.shared.count("download.coalescedLateCacheHit")
            return
        }
        while true {
            try await awaitTransferResume(key.filespace, ticket: ticket)
            let authorizationStarted = ContinuousClock.now
            let signed = try await Self.retryPresign {
                try await readPresigns.sign(filespace: key.filespace, key: key.objectKey, ticket: ticket)
            }
            try Task.checkCancellation()
            let payloadAdmissionStarted = WriteProfiler.shared.start()
            let finished = try await downloadPool.withPermit(ticket: ticket) { [self] in
                WriteProfiler.shared.elapsed("download.payloadPermitWait", since: payloadAdmissionStarted)
                // The first cache lookup can suspend while an earlier shared fetch
                // admits the block and retires its flight. Recheck after admission
                // to avoid turning that stale miss into a duplicate network GET.
                // This is residency only; plaintextBlock still verifies the full
                // inode/index identity and AEAD before serving any cached bytes.
                if await cache.contains(ref.hash) {
                    WriteProfiler.shared.count("download.coalescedLateCacheHit")
                    return true
                }
                try Task.checkCancellation()
                if await shouldPause(key.filespace, ticket: ticket) { return false }
                // A congested payload queue can outlive a prepared URL. Snapshot
                // authorizations are shorter than live-file URLs; conservatively
                // refresh after at most 25 seconds, including metadata queue time.
                let authorization: PresignedURL
                let freshness = max(0, min(30, signed.expiresIn) - 5)
                if authorizationStarted.duration(to: .now) >= .seconds(freshness) {
                    authorization = try await Self.retryPresign {
                        try await readPresigns.sign(filespace: key.filespace, key: key.objectKey, ticket: ticket, forceFresh: true)
                    }
                    WriteProfiler.shared.count("readPresign.refreshedBeforeGET")
                } else { authorization = signed }
                let getStart = WriteProfiler.shared.start()
                // Pause may arrive while this block waits for a permit or refreshes
                // authorization. Release the permit before parking; demand joining
                // this flight can then promote and wake it without deadlocking.
                guard let ciphertext = try await getUnlessPaused(authorization.url, filespace: key.filespace,
                                                                  ticket: ticket) else { return false }
                WriteProfiler.shared.elapsed("download.get", since: getStart)
                WriteProfiler.shared.addBytes("download.receivedCiphertext", count: ciphertext.count)
                try Task.checkCancellation()
                let verificationStarted = WriteProfiler.shared.start()
                let plaintext = try await crypto.decryptBlock(ciphertext, itemID: key.itemID, blockIndex: key.index)
                guard plaintext.count == ref.length else {
                    throw EngineError(.syncFailed, "Downloaded block length differs from the committed manifest")
                }
                // Cache admission also verifies SHA256(ciphertext) == committed hash.
                try await cache.putBlock(ref.hash, plaintext: ciphertext)
                await verifiedBlocks.insert(plaintext, for: .init(filespace: key.filespace, itemID: key.itemID,
                                                                 index: key.index, hash: ref.hash))
                WriteProfiler.shared.elapsed("download.verifyAndAdmit", since: verificationStarted)
                return true
            }
            if finished { return }
        }
    }

    private func getUnlessPaused(_ url: String, filespace: FilespaceID,
                                 ticket: TransferPermitPool.Ticket) async throws -> Data? {
        try requireOpen(filespace)
        try Task.checkCancellation()
        guard !shouldPause(filespace, ticket: ticket) else { return nil }
        return try await blob.get(url: url, filespace: filespace, feedback: { [downloadPool] in await downloadPool.feedback($0) })
    }

    /// Authenticated bytes for assembly. A cold download already verified these
    /// exact bytes, so the bounded handoff avoids reading, hashing and decrypting
    /// them a second time. Disk hits still pass both checksum and AEAD validation.
    public func plaintextBlock(_ ref: BlockRef, resolved: ResolvedBlockManifest,
                               blockIndex: Int, filespace: FilespaceID, itemID: InodeID) async throws -> Data {
        try requireOpen(filespace)
        let key = VerifiedBlockWindow.Key(filespace: filespace, itemID: itemID, index: blockIndex, hash: ref.hash)
        for attempt in 0..<3 {
            if let bytes = await verifiedBlocks.get(key, length: ref.length) { return bytes }
            if let ciphertext = try await cache.readBlock(ref.hash) {
                let bytes = try await crypto.decryptBlock(ciphertext, itemID: itemID, blockIndex: blockIndex)
                guard bytes.count == ref.length else {
                    throw EngineError(.syncFailed, "Cached block length differs from the committed manifest")
                }
                await verifiedBlocks.insert(bytes, for: key)
                return bytes
            }
            if attempt < 2 {
                try await fetchOneBlock(ref, objectKey: resolved.objectKey(for: ref.hash), blockIndex: blockIndex,
                                        filespace: filespace, itemID: itemID)
            }
        }
        throw EngineError(.gatewayError, "Committed block could not be made available for reading")
    }

    // MARK: - WRITE staging + async upload (DESIGN.md §4.2) ---------------

    @discardableResult
    public func stageWrite(filespace: FilespaceID, itemID: InodeID, offset: Int, data: Data,
                           baseVersion: String?, fence: Int?) async throws -> Int {
        try requireOpen(filespace)
        let profile = WriteProfiler.shared
        let profileStart = profile.start()
        defer { profile.elapsed("stage.total", since: profileStart); profile.completedWrite(bytes: data.count) }
        guard offset >= 0, data.count <= Int.max - offset else { throw EngineError(.invalidParams, "invalid write extent") }
        let key = StagingKey(filespace: filespace, itemID: itemID)
        let mutationStart = profile.start()
        try requireOpen(filespace)
        await acquireMutation(key)
        profile.elapsed("stage.mutationWait", since: mutationStart)
        defer { releaseMutation(key) }
        try requireOpen(filespace)
        try Task.checkCancellation()
        invalidateUpload(key)
        var published = false
        defer {
            if !published, staging[key] != nil {
                scheduleUpload(filespace: filespace, itemID: itemID, key: key)
            }
        }
        // Work on a copy under the per-item mutation lock. Publish the overlay
        // only after its journal transaction succeeds, preserving prior acked data
        // if disk I/O fails partway through this write.
        let item: StagedItem
        if let existing = staging[key] {
            item = existing.copy()
        } else {
            item = StagedItem()
        }

        // Resolve the committed manifest ONCE per staging session (one gateway
        // round-trip on the FIRST write to an item — needed for the committed size and
        // for read-modify-write seeding of partially covered blocks). A `.notFound`
        // means no committed content (brand-new file); any other failure propagates —
        // guessing "empty" on a transient error would zero-corrupt a boundary block.
        let baseStart = profile.start()
        try await fetchBaseIfNeeded(item, filespace: filespace, itemID: itemID, growSize: true)
        profile.elapsed("stage.baseResolve", since: baseStart)
        if offset == item.size { profile.addBytes("stage.contiguousAppendBytes", count: data.count) }
        else { profile.addBytes(offset > item.size ? "stage.forwardGapWriteBytes" : "stage.nonAppendWriteBytes", count: data.count) }
        item.acceptsEarlyUploads = true

        // Splice the write into per-block dirty images. Only the touched blocks are
        // materialized; a partially covered block with committed content is seeded by
        // fetching THAT ONE block (the read path's cache makes this a HIT for
        // read-modify-write patterns) — never the whole file (P0; kills seedBuffer).
        let spliceStart = profile.start()
        item.writeSeq += 1
        let mySeq = item.writeSeq
        let end = offset + data.count
        var touched: [Int: Data] = [:]
        var i = offset / blockSize
        while i * blockSize < end {
            let bStart = i * blockSize
            let sliceLo = max(offset, bStart)
            let sliceHi = min(end, bStart + blockSize)
            let slice = data.subdata(in: (sliceLo - offset)..<(sliceHi - offset))

            var image: Data
            if let existing = item.dirty[i] {
                // RAM bytes or the journal file — `readBlock` is synchronous, so there
                // is no suspension between reading the current image and splicing.
                image = try dirtyBlockData(existing, filespace: filespace, itemID: itemID, index: i)
            } else if !item.replaced, let base = item.base,
                      Self.needsBaseSeed(blockStart: bStart, blockSize: blockSize,
                                         baseSize: item.effectiveBaseSize,
                                         writeLo: sliceLo, writeHi: sliceHi) {
                // Trim the seed to the ALIVE committed extent (a truncate killed the rest;
                // those bytes must come back as zeros, not resurrected content — P4).
                let usable = max(0, item.effectiveBaseSize - bStart)
                let seeded = Data(try await baseBlockPlaintext(blockIndex: i, base: base,
                                                               filespace: filespace, itemID: itemID).prefix(usable))
                // Re-check after the await: a concurrent write to this block may have
                // landed while we fetched — splice into the CURRENT image, not a stale one.
                if let racing = item.dirty[i] {
                    image = try dirtyBlockData(racing, filespace: filespace, itemID: itemID, index: i)
                } else {
                    image = seeded
                }
            } else if let racing = item.dirty[i] {
                image = try dirtyBlockData(racing, filespace: filespace, itemID: itemID, index: i)
            } else {
                image = Data()
            }
            // Grow the image to reach the write's start (an intra-block hole on a
            // never-written region is zeros) and through its end, then splice.
            let rel = sliceLo - bStart
            if image.count < rel { image.append(Data(repeating: 0, count: rel - image.count)) }
            if image.count < sliceHi - bStart {
                image.append(Data(repeating: 0, count: (sliceHi - bStart) - image.count))
            }
            image.replaceSubrange(rel..<(sliceHi - bStart), with: slice)
            item.dirty[i] = DirtyBlock(bytes: image, length: image.count, seq: mySeq)
            touched[i] = image
            i += 1
        }
        profile.elapsed("stage.splice", since: spliceStart)
        item.size = max(item.size, end)
        item.lastError = nil
        item.retryAttempt = 0
        // Capture the base version ONCE (the version the edit started from). A later
        // partial write must not overwrite it with a stale handle's version.
        if item.baseVersion == nil { item.baseVersion = versionForWrite(baseVersion, key: key) }
        if let fence { item.fence = fence }

        // Audit B2: persist the TOUCHED blocks to the durable journal + fsync BEFORE we
        // return, so the bytes survive a crash the instant the VFS write is acked.
        // Disk I/O ∝ bytes written (P0) — never the whole staged image. Failing to
        // journal is a hard error — we must not ack a write we can't make durable.
        if let journal {
            let journalStart = profile.start()
            try await journal.recordBlocks(filespace: filespace, itemID: itemID,
                                           baseVersion: item.baseVersion,
                                           size: item.size,
                                           committedLimit: item.persistedCommittedLimit,
                                           touched: touched, base: item.base, baseCaptured: item.baseFetched)
            profile.elapsed("stage.journalAwait", since: journalStart)
            // P1: the journal file is now the byte store — drop the RAM copy of each
            // block we just journaled, UNLESS a concurrent newer write replaced it
            // (its own completion will drop its own bytes).
            for i in touched.keys where item.dirty[i]?.seq == mySeq {
                item.dirty[i]?.bytes = nil
            }
        }

        // Publish only the acknowledged image. During a sustained append, full
        // immutable blocks may PUT in parallel with later journal transactions.
        // Neither path waits for the network before acknowledging local durability.
        for (index, bytes) in touched {
            // Original live committed bytes stay on the coalescing path. New
            // suffix blocks are eligible regardless of their arrival order.
            if bytes.count == blockSize, index * blockSize >= item.effectiveBaseSize {
                item.pendingEarlyBlocks.insert(index)
                if item.earlyEligibleBlocks.count < 8 { item.earlyEligibleBlocks.insert(index) }
            } else { item.pendingEarlyBlocks.remove(index) }
        }
        staging[key] = item
        published = true
        prepareAppendUploads(item, touched: touched, filespace: filespace, itemID: itemID)
        scheduleUpload(filespace: filespace, itemID: itemID, key: key)
        return item.size
    }

    private func prepareAppendUploads(_ item: StagedItem, touched: [Int: Data],
                                      filespace: FilespaceID, itemID: InodeID) {
        let profile = WriteProfiler.shared
        guard journal != nil, !closing.contains(filespace) else { return }
        guard item.earlyEligibleBlocks.count >= 8 else { profile.count("upload.direct.insufficientNewBlocks"); return }
        guard !paused.contains(filespace) else { profile.count("upload.direct.paused"); return }
        profile.count("upload.direct.eligibleWrite")
        for index in touched.keys.sorted() {
            guard let bytes = touched[index], bytes.count == blockSize,
                  item.dirty[index]?.length == blockSize, item.pendingEarlyBlocks.contains(index) else { continue }
            guard let reservation = uploadPreparation.tryAcquire() else { profile.count("upload.direct.capacityFull"); break }
            startPreparedUpload(item, bytes: bytes, index: index, filespace: filespace, itemID: itemID, reservation: reservation)
        }
    }

    private func startPreparedUpload(_ item: StagedItem, bytes: Data, index: Int,
                                     filespace: FilespaceID, itemID: InodeID,
                                     reservation: UploadPreparationBudget.Reservation) {
        item.pendingEarlyBlocks.remove(index)
        earlyUploadCount += 1
        earlyUploadPeak = max(earlyUploadPeak, earlyUploadCount)
        let prepared = PreparedUpload(), profile = WriteProfiler.shared
        let admittedAt = profile.start()
        let taskID = UUID()
        let task = Task { [self] in
            profile.elapsed("upload.early.taskStart", since: admittedAt)
            defer {
                profile.elapsed("upload.early.lifetime", since: admittedAt)
                earlyUploadCount -= 1
                reservation.release()
                pumpAppendUploads()
                earlyTasks[taskID] = nil
                finishShutdownWaiters(filespace)
            }
            do {
                let ref = try await uploadEarlyPlaintext(bytes, blockIndex: index, filespace: filespace, itemID: itemID)
                WriteProfiler.shared.addBytes("upload.earlyPutCompletedPlaintext", count: ref.length)
                await prepared.complete(.success(ref))
            } catch {
                let kind = (error as? EngineError)?.kind.rawValue ?? (error is CancellationError ? "cancelled" : "transportOrLocal")
                profile.count("upload.early.failure." + kind)
                await prepared.complete(.failure(error))
            }
        }
        earlyTasks[taskID] = (filespace, task)
        item.dirty[index]?.prepared = prepared
    }

    /// Catch up skipped blocks from pending index metadata, independent of wire
    /// arrival order and logical holes. Each free slot reads one verified full
    /// block from the acknowledged image; there is no pending payload queue.
    private func pumpAppendUploads() {
        let profile = WriteProfiler.shared
        profile.count("upload.catchup.pump")
        guard journal != nil, uploadPreparation.metrics().active < uploadPreparationLimit else { profile.count("upload.catchup.capacityFull"); return }
        let keys = staging.keys.filter { key in
            guard !closing.contains(key.filespace) else { return false }
            guard let item = staging[key] else { return false }
            if mutating.contains(key) { profile.count("upload.catchup.mutating"); return false }
            if paused.contains(key.filespace) { profile.count("upload.catchup.paused"); return false }
            if !item.acceptsEarlyUploads { profile.count("upload.catchup.manifestOwner"); return false }
            if item.earlyEligibleBlocks.count < 8 { profile.count("upload.catchup.insufficientNewBlocks"); return false }
            if item.pendingEarlyBlocks.isEmpty { profile.count("upload.catchup.noPendingBlocks"); return false }
            return true
        }.sorted { ($0.filespace, $0.itemID.rawValue) < ($1.filespace, $1.itemID.rawValue) }
        guard !keys.isEmpty else { return }
        var misses = 0
        while misses < keys.count {
            let key = keys[earlyUploadFileCursor % keys.count]
            earlyUploadFileCursor = (earlyUploadFileCursor + 1) % keys.count
            guard let item = staging[key], item.acceptsEarlyUploads else { misses += 1; continue }
            var selected: Int?
            while let index = item.pendingEarlyBlocks.popFirst() {
                if let block = item.dirty[index], block.length == blockSize, block.prepared == nil,
                   index * blockSize >= item.effectiveBaseSize, index < item.size / blockSize {
                    selected = index; break
                }
            }
            guard let index = selected, let block = item.dirty[index] else { misses += 1; continue }
            guard let reservation = uploadPreparation.tryAcquire() else {
                item.pendingEarlyBlocks.insert(index)
                break
            }
            do {
                // No await between current-image selection, descriptor read/hash,
                // and prepared-result attachment. A write cannot swap this image.
                let readStart = profile.start()
                let bytes = try dirtyBlockData(block, filespace: key.filespace, itemID: key.itemID, index: index)
                profile.elapsed("upload.catchup.readJournal", since: readStart)
                startPreparedUpload(item, bytes: bytes, index: index, filespace: key.filespace, itemID: key.itemID, reservation: reservation)
                misses = 0
            } catch {
                reservation.release()
                // This optional optimization never turns a damaged journal into
                // network bytes. The authoritative uploader reports the error.
                item.acceptsEarlyUploads = false
                misses += 1
            }
        }
    }

    /// Resolve the committed manifest ONCE per staging session. `growSize: true`
    /// (ranged writes) folds the committed size into the staged size — but ONLY on
    /// the very first resolve, so a prior truncate's smaller size is never
    /// re-inflated. A `.notFound` means no committed content; any other failure
    /// propagates (guessing "empty" would corrupt a boundary block).
    private func fetchBaseIfNeeded(_ item: StagedItem, filespace: FilespaceID,
                                   itemID: InodeID, growSize: Bool) async throws {
        guard !item.baseFetched && !item.replaced else { return }
        do {
            let resolved = try await gateway.getResolvedBlockManifest(filespace: filespace, itemID: itemID)
            item.base = resolved
            // Honor a persisted truncate ceiling (replay): dead committed bytes stay dead.
            item.effectiveBaseSize = min(item.committedLimitCap, resolved.manifest.size)
            if growSize { item.size = max(item.size, min(item.committedLimitCap, resolved.manifest.size)) }
        } catch let e as EngineError where e.kind == .notFound {
            item.base = nil
            item.effectiveBaseSize = 0
        }
        item.baseFetched = true
    }

    public func stageTruncate(filespace: FilespaceID, itemID: InodeID, newSize: Int,
                              baseVersion: String?, fence: Int?) async throws {
        guard newSize >= 0 else { throw EngineError(.invalidParams, "negative truncate size") }
        let key = StagingKey(filespace: filespace, itemID: itemID)
        try requireOpen(filespace)
        await acquireMutation(key)
        defer { releaseMutation(key) }
        try requireOpen(filespace)
        try Task.checkCancellation()
        invalidateUpload(key)
        var published = false
        defer {
            if !published, staging[key] != nil {
                scheduleUpload(filespace: filespace, itemID: itemID, key: key)
            }
        }
        let item: StagedItem
        if let existing = staging[key] {
            item = existing.copy()
        } else {
            item = StagedItem()
        }
        try await fetchBaseIfNeeded(item, filespace: filespace, itemID: itemID, growSize: false)
        item.earlyEligibleBlocks.removeAll()
        item.pendingEarlyBlocks.removeAll()
        item.writeSeq += 1
        let mySeq = item.writeSeq

        var touched: [Int: Data] = [:]
        var removed: Set<Int> = []
        if newSize < item.size {
            // Drop staged blocks fully beyond the boundary; trim the boundary block.
            let lastIndex = newSize == 0 ? -1 : (newSize - 1) / blockSize
            for i in item.dirty.keys where i > lastIndex {
                item.dirty[i] = nil
                removed.insert(i)
            }
            if lastIndex >= 0, let boundary = item.dirty[lastIndex] {
                let keep = newSize - lastIndex * blockSize
                if boundary.length > keep {
                    let bytes = Data(try dirtyBlockData(boundary, filespace: filespace, itemID: itemID,
                                                     index: lastIndex).prefix(keep))
                    item.dirty[lastIndex] = DirtyBlock(bytes: bytes, length: bytes.count, seq: mySeq)
                    touched[lastIndex] = bytes
                }
            }
        }
        // Committed content beyond the truncate point is DEAD (zeros on regrowth) —
        // both live (effectiveBaseSize) and persisted (committedLimitCap, journaled).
        item.effectiveBaseSize = min(item.effectiveBaseSize, newSize)
        item.committedLimitCap = min(item.committedLimitCap, newSize)
        item.size = newSize
        item.lastError = nil
        item.retryAttempt = 0
        if item.baseVersion == nil { item.baseVersion = versionForWrite(baseVersion, key: key) }
        if let fence { item.fence = fence }
        if let journal {
            try await journal.recordBlocks(filespace: filespace, itemID: itemID,
                                           baseVersion: item.baseVersion,
                                           size: item.size, committedLimit: item.committedLimitCap,
                                           touched: touched, removed: removed,
                                           base: item.base, baseCaptured: item.baseFetched)
            for i in touched.keys where item.dirty[i]?.seq == mySeq { item.dirty[i]?.bytes = nil }
        }
        staging[key] = item
        published = true
        scheduleUpload(filespace: filespace, itemID: itemID, key: key)
    }

    public func stageReplace(filespace: FilespaceID, itemID: InodeID, data: Data,
                             baseVersion: String?, fence: Int?) async throws {
        try await stageReplaceChunks(filespace: filespace, itemID: itemID,
                                     baseVersion: baseVersion, fence: fence,
                                     reader: InMemoryChunkReader(data: data, chunkSize: blockSize))
    }

    /// P1 — whole-file replace streamed from a file: read block-size chunks via
    /// FileHandle, journal each block, never hold more than one block in memory.
    public func stageReplace(filespace: FilespaceID, itemID: InodeID, contents: CacheFileRef,
                             baseVersion: String?, fence: Int?) async throws {
        let handle: Foundation.FileHandle
        if let path = contents.path {
            handle = try Foundation.FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        } else if let fd = contents.fd {
            handle = Foundation.FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        } else {
            throw EngineError(.invalidParams, "stageReplace contents carries neither path nor fd")
        }
        defer { if contents.path != nil { try? handle.close() } }
        try await stageReplaceChunks(filespace: filespace, itemID: itemID,
                                     baseVersion: baseVersion, fence: fence,
                                     reader: FileChunkReader(handle: handle, chunkSize: blockSize))
    }

    /// Shared replace pipeline: consume block-size chunks from `reader`, journal each
    /// block as it arrives (bytes drop from RAM once journaled), then mark the item
    /// replaced. The new content fully defines the file: every block dirty, size may
    /// SHRINK, nothing merged from the committed manifest, prior edits superseded.
    private func stageReplaceChunks(filespace: FilespaceID, itemID: InodeID,
                                    baseVersion: String?, fence: Int?,
                                    reader: ChunkReader) async throws {
        let key = StagingKey(filespace: filespace, itemID: itemID)
        try requireOpen(filespace)
        await acquireMutation(key)
        defer { releaseMutation(key) }
        try requireOpen(filespace)
        invalidateUpload(key)
        let previous = staging[key]
        let item = StagedItem()
        item.replaced = true
        item.baseFetched = true
        item.committedLimitCap = 0
        item.baseVersion = previous?.baseVersion ?? versionForWrite(baseVersion, key: key)
        item.fence = fence ?? previous?.fence
        do {
            if let journal {
                let lengths = try await journal.recordReplaceStreaming(filespace: filespace, itemID: itemID,
                    baseVersion: item.baseVersion, nextChunk: { try reader.next() })
                item.dirty = lengths.mapValues { DirtyBlock(bytes: nil, length: $0, seq: 0) }
                item.size = lengths.values.reduce(0, +)
            } else {
                while let chunk = try reader.next() {
                    item.dirty[item.dirty.count] = DirtyBlock(bytes: chunk, length: chunk.count, seq: 0)
                    item.size += chunk.count
                }
            }
        } catch {
            if previous != nil { scheduleUpload(filespace: filespace, itemID: itemID, key: key) }
            throw error
        }
        staging[key] = item
        scheduleUpload(filespace: filespace, itemID: itemID, key: key)
    }

    /// Whether a write covering `[writeLo, writeHi)` of the block at `blockStart` leaves
    /// any COMMITTED byte of that block uncovered (→ the block must be seeded from the
    /// committed content before splicing, or those bytes would read back as zeros).
    static func needsBaseSeed(blockStart: Int, blockSize: Int, baseSize: Int,
                              writeLo: Int, writeHi: Int) -> Bool {
        let committedExtent = min(blockSize, baseSize - blockStart)
        guard committedExtent > 0 else { return false }   // block is past the committed EOF
        return !(writeLo <= blockStart && writeHi >= blockStart + committedExtent)
    }

    /// Fetch + decrypt ONE committed block for read-modify-write seeding. Cache HIT is
    /// free; MISS goes presign(GET) → range GET → verify → admit (same as the read path).
    private func baseBlockPlaintext(blockIndex: Int, base: ResolvedBlockManifest,
                                    filespace: FilespaceID, itemID: InodeID) async throws -> Data {
        let bStart = blockIndex * blockSize
        guard let ref = base.manifest.blocks.first(where: { $0.offset == bStart }) else {
            return Data()   // no committed block at this position (sparse/hole) → zeros
        }
        try await fetchOneBlock(ref, objectKey: base.objectKey(for: ref.hash),
                                blockIndex: blockIndex, filespace: filespace, itemID: itemID)
        guard let ct = try await cache.readBlock(ref.hash) else {
            throw EngineError(.gatewayError, "seed block \(ref.hash.hex) could not be made resident")
        }
        return try await crypto.decryptBlock(ct, itemID: itemID, blockIndex: blockIndex)
    }

    /// Read-your-own-writes (audit B3): the dirty-block snapshot currently staged for
    /// `itemID`, or nil if nothing is dirty. Lengths only (P1) — the read path pages
    /// bytes per block via `stagedBlock` and overlays them over the committed manifest
    /// (zeros where neither exists within `size`).
    public func stagedState(filespace: FilespaceID, itemID: InodeID) -> StagedState? {
        guard !closing.contains(filespace) else { return nil }
        let key = StagingKey(filespace: filespace, itemID: itemID)
        guard let item = staging[key] else { return nil }
        return StagedState(size: item.size,
                           dirtyLengths: item.dirty.mapValues(\.length),
                           mergesCommitted: !item.replaced,
                           committedLimit: item.baseFetched ? item.effectiveBaseSize
                                                            : item.committedLimitCap,
                           originalBase: item.base, baseCaptured: item.baseFetched && !item.replayedWithoutBase)
    }

    /// Whether acknowledged journal state remains for an inode. Unlike
    /// `stagedState`, this shutdown-safe query remains available after `shutdown`
    /// has stopped ordinary session reads. Callers use it only after shutdown
    /// drains in-flight mutations, so the answer cannot race a late stage.
    public func hasStagedStateAfterShutdown(filespace: FilespaceID, itemID: InodeID) -> Bool {
        staging[StagingKey(filespace: filespace, itemID: itemID)] != nil
    }

    /// One staged block's plaintext (RAM or paged from the journal), or nil if not dirty.
    public func stagedBlock(filespace: FilespaceID, itemID: InodeID, blockIndex: Int) throws -> Data? {
        try requireOpen(filespace)
        let key = StagingKey(filespace: filespace, itemID: itemID)
        guard let item = staging[key], let block = item.dirty[blockIndex] else { return nil }
        return try dirtyBlockData(block, filespace: filespace, itemID: itemID, index: blockIndex)
    }

    private struct RecoveryReceipt {
        let generation: UUID
        let path: String
        let bytes: Int
        let sha256: String
    }
    private var recoveryReceipts: [StagingKey: RecoveryReceipt] = [:]

    // MARK: Retained-write recovery

    private func canExport(_ item: StagedItem) -> Bool {
        guard item.replayedWithoutBase else { return true }
        // Old journals do not contain the original unchanged block map. A later
        // remote manifest must NEVER be mistaken for the original edit's base.
        if item.replaced || item.committedLimitCap == 0 { return true }
        let count = (item.size + blockSize - 1) / blockSize
        return (0..<count).allSatisfy { item.dirty[$0] != nil }
    }

    public func recoveryItems(filespace: FilespaceID) async throws -> [RecoveryItem] {
        staging.compactMap { key, item in
            guard key.filespace == filespace, let error = item.lastError else { return nil }
            let lower = error.lowercased()
            let kind = lower.contains("deleted") ? "deleted" : lower.contains("conflict") ? "conflict" : "upload"
            let exportable = canExport(item)
            let reason = exportable ? error : error + ". The original unchanged blocks are unavailable after restart; local changes are retained."
            return RecoveryItem(id: key.itemID.rawValue, bytes: item.size, reason: reason,
                                kind: kind, canRetry: kind == "upload", canExport: exportable)
        }.sorted { $0.id < $1.id }
    }

    public func retryRecovery(filespace: FilespaceID, itemID: InodeID) async throws {
        let key = StagingKey(filespace: filespace, itemID: itemID)
        try requireOpen(filespace)
        await acquireMutation(key)
        defer { releaseMutation(key) }
        try requireOpen(filespace)
        guard let item = staging[key] else { throw EngineError(.notFound, "No local write needs recovery") }
        guard item.lastError != nil else { return }
        // Preserve baseVersion and captured base; a retry never rebases or overwrites
        // a remote edit. The ordinary uploader repeats the lease and CAS checks.
        item.lastError = nil
        item.retryAttempt = 0
        scheduleUpload(filespace: filespace, itemID: itemID, key: key)
    }

    public func exportRecovery(filespace: FilespaceID, itemID: InodeID,
                               destination: String) async throws -> RecoveryExportResult {
        guard destination.hasPrefix("/"), !destination.hasSuffix("/") else {
            throw EngineError(.invalidParams, "Choose an absolute destination file path")
        }
        let key = StagingKey(filespace: filespace, itemID: itemID)
        try requireOpen(filespace)
        await acquireMutation(key)
        defer { releaseMutation(key) }
        try requireOpen(filespace)
        guard let item = staging[key] else { throw EngineError(.notFound, "No local write needs recovery") }
        guard canExport(item) else {
            throw EngineError(.syncFailed, "Cannot safely reconstruct the original unchanged blocks after restart; local journal retained")
        }
        // Hold the mutation barrier through the entire streamed snapshot. Uploads
        // may continue their network phase but cannot commit/clear these generations.
        let requested = URL(fileURLWithPath: destination).standardizedFileURL
        let parent = requested.deletingLastPathComponent().resolvingSymlinksInPath()
        let output = parent.appendingPathComponent(requested.lastPathComponent)
        let temp = parent.appendingPathComponent(".cloudfs-recovery-" + UUID().uuidString)
        let fd = open(temp.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = Foundation.FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: temp) }
        var digest = SHA256()
        let base = item.replaced || item.replayedWithoutBase ? nil : item.base
        let refs = Dictionary(uniqueKeysWithValues: (base?.manifest.blocks ?? []).map { ($0.offset, $0) })
        let count = (item.size + blockSize - 1) / blockSize
        for index in 0..<count {
            try Task.checkCancellation()
            let offset = index * blockSize
            let length = min(blockSize, item.size - offset)
            var bytes: Data
            if let dirty = item.dirty[index] {
                bytes = try dirtyBlockData(dirty, filespace: filespace, itemID: itemID, index: index)
            } else if let base, let ref = refs[offset], offset < item.effectiveBaseSize {
                let usable = min(ref.length, item.effectiveBaseSize - offset)
                bytes = Data(try await baseBlockPlaintext(blockIndex: index, base: base,
                                            filespace: filespace, itemID: itemID).prefix(usable))
            } else { bytes = Data() }
            if bytes.count < length { bytes.append(Data(repeating: 0, count: length - bytes.count)) }
            let chunk = Data(bytes.prefix(length))
            try handle.write(contentsOf: chunk)
            digest.update(data: chunk)
        }
        try handle.synchronize()
        #if os(macOS)
        guard fcntl(fd, F_FULLFSYNC) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        #endif
        // Hard-link publication is atomic and exclusive: existing files, including
        // symlinks, are never replaced. No partial file appears under the chosen name.
        guard link(temp.path, output.path) == 0 else {
            throw EngineError(.invalidParams, "Cannot create the recovery file; choose a new filename (existing files are never replaced)")
        }
        let parentFD = open(parent.path, O_RDONLY)
        guard parentFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(parentFD) }
        guard fsync(parentFD) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let hash = digest.finalize().map { String(format: "%02x", $0) }.joined()
        recoveryReceipts[key] = RecoveryReceipt(generation: item.generation, path: output.path,
                                                bytes: item.size, sha256: hash)
        return RecoveryExportResult(path: output.path, bytes: item.size, sha256: hash)
    }

    public func completeRecovery(filespace: FilespaceID, itemID: InodeID, destination: String) async throws {
        let key = StagingKey(filespace: filespace, itemID: itemID)
        try requireOpen(filespace)
        await acquireMutation(key)
        defer { releaseMutation(key) }
        try requireOpen(filespace)
        guard let item = staging[key], let receipt = recoveryReceipts[key],
              receipt.generation == item.generation else {
            throw EngineError(.conflict, "Local changes changed or the daemon restarted; export a fresh recovery copy first")
        }
        let requested = URL(fileURLWithPath: destination).standardizedFileURL
        let path = requested.deletingLastPathComponent().resolvingSymlinksInPath().appendingPathComponent(requested.lastPathComponent).path
        guard path == receipt.path else { throw EngineError(.invalidParams, "Choose the verified recovery copy") }
        let fd = open(path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw EngineError(.syncFailed, "The recovery copy is missing or was replaced by a link; local journal retained") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        defer { try? handle.close() }
        var before = stat()
        guard fstat(fd, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG,
              before.st_size == receipt.bytes else {
            throw EngineError(.syncFailed, "The recovery copy changed; local journal retained")
        }
        var digest = SHA256()
        while let bytes = try handle.read(upToCount: blockSize), !bytes.isEmpty {
            try Task.checkCancellation()
            digest.update(data: bytes)
        }
        let hash = digest.finalize().map { String(format: "%02x", $0) }.joined()
        var after = stat(), named = stat()
        guard hash == receipt.sha256, fstat(fd, &after) == 0, lstat(path, &named) == 0,
              before.st_ino == after.st_ino, before.st_dev == after.st_dev,
              before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec, after.st_ino == named.st_ino,
              after.st_dev == named.st_dev, (named.st_mode & S_IFMT) == S_IFREG else {
            throw EngineError(.syncFailed, "The recovery copy changed; local journal retained")
        }
        // The user explicitly accepts the durable verified copy as recovery. Never
        // run this on export alone, and never clear newer acknowledged local edits.
        invalidateUpload(key)
        if let journal { try await journal.discardVerified(filespace: filespace, itemID: itemID) }
        staging[key] = nil
        uploads[key] = nil
        retryTasks[key]?.cancel(); retryTasks[key] = nil
        recoveryReceipts[key] = nil
        if let transferID = uploadTransferIDs.removeValue(forKey: key) {
            publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                             direction: .upload, bytesDone: 0, bytesTotal: item.byteCount, state: .error,
                             error: "Upload cancelled after verified local recovery"))
        }
    }

    /// Schedule the async write-back for one item. Replaces any prior in-flight
    /// task so the latest staged image wins (coalesces a burst of writes).
    private func scheduleUpload(filespace: FilespaceID, itemID: InodeID, key: StagingKey, debounce: Bool = true) {
        guard !closing.contains(filespace) else { return }
        uploads[key]?.cancel()
        // A fresh stage supersedes any parked retry timer for this key.
        retryTasks[key]?.cancel()
        retryTasks[key] = nil
        // Finding 1: bump the per-key ownership generation so the prior (now
        // superseded) task — which captured the OLD generation — can no longer
        // mutate or publish shared state. The replacement task owns durability.
        let myGen = (uploadGen[key] ?? 0) + 1
        uploadGen[key] = myGen
        let delay = debounce ? uploadDebounceMs : 0
        if delay > 0 { deferredUploads.insert(key) } else { deferredUploads.remove(key) }
        let transferID = uploadTransferID(for: key)
        publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                         direction: .upload, bytesDone: 0, bytesTotal: staging[key]?.byteCount ?? 0,
                         state: paused.contains(filespace) ? .paused : .queued))
        let taskID = UUID()
        let task = Task<Void, Error> { [self] in
            defer { uploadTasks[taskID] = nil; finishShutdownWaiters(filespace) }
            do {
                // Local ACK already crossed the unchanged durable journal barrier.
                // Coalesce a short burst BEFORE rereading/encrypting its old blocks;
                // each newer generation cancels this timer, not useful network work.
                if delay > 0 { try await Task.sleep(for: .milliseconds(delay)) }
                try Task.checkCancellation()
                guard uploadGen[key] == myGen else { return }
                deferredUploads.remove(key)
                try await runUpload(filespace: filespace, itemID: itemID, key: key, gen: myGen)
            } catch {
                guard uploadGen[key] == myGen else { return }
                deferredUploads.remove(key)
                staging[key]?.lastError = "\(error)"
                uploads[key] = nil
                publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                                 direction: .upload, bytesDone: 0, bytesTotal: staging[key]?.byteCount ?? 0,
                                 state: .error, error: "\(error)"))
            }
        }
        uploadTasks[taskID] = (filespace, task)
        uploads[key] = task
    }

    /// Re-drive a parked item after a bounded-backoff delay (audit B2: a single 429/
    /// 5xx/network blip used to park the bytes in RAM forever). The retry captures a
    /// NEW generation so it owns durability; a fresh stageWrite in the meantime
    /// cancels this timer and supersedes it.
    private func scheduleRetry(filespace: FilespaceID, itemID: InodeID, key: StagingKey, attempt: Int) {
        guard !closing.contains(filespace) else { return }
        retryTasks[key]?.cancel()
        // Exponential backoff with a sane ceiling (~6.4s at attempt 5).
        let delayMs = min(retryBaseDelayMs << min(attempt, 5), 10_000)
        let timer = Task { [self] in
            try? await Task.sleep(nanoseconds: UInt64(delayMs) * 1_000_000)
            if Task.isCancelled { return }
            self.fireRetry(filespace: filespace, itemID: itemID, key: key)
        }
        retryTasks[key] = timer
    }

    private func fireRetry(filespace: FilespaceID, itemID: InodeID, key: StagingKey) {
        retryTasks[key] = nil
        guard !closing.contains(filespace) else { return }
        // Only retry if the item is still dirty (a superseding stage would have
        // re-kicked it already, and a successful commit cleared it).
        guard staging[key] != nil else { return }
        scheduleUpload(filespace: filespace, itemID: itemID, key: key)
    }

    /// The per-block upload plan: what each block index of the NEW manifest is built
    /// from. Classification is pure (no I/O), so progress totals are exact upfront.
    /// P1: `.dirty` carries the expected LENGTH only — the bytes page in from the
    /// journal one block at a time inside the work loop (uploading a 20 GB staged
    /// write holds one block in memory, not twenty thousand).
    private enum BlockPlan: Sendable {
        case dirty(Int)                  // staged image (paged from journal, zero-padded)
        case reuse(BlockRef)             // unchanged committed block — zero I/O, ref copied
        case rmw(BlockRef, Int, Int)     // committed block re-shaped: (ref, expectedLen,
                                         // usable alive bytes) → fetch, trim, pad, re-encrypt
        case hole(Int)                   // no staged or committed bytes → zero block
    }

    /// Encrypt → presign(PUT) → PUT the DIRTY blocks only → CAS a manifest that
    /// REUSES the unchanged committed refs → mark synced. Network/CPU cost is
    /// proportional to the bytes written, never the file size (P0). Runs OFF the
    /// VFS callback (separate task). Honors pause.
    private func runUpload(filespace: FilespaceID, itemID: InodeID, key: StagingKey, gen: Int) async throws {
        activeUploadRuns += 1
        defer { activeUploadRuns -= 1 }
        // Finding 1: am I still the CURRENT owner of this key? A superseded task
        // must touch nothing — no clear, no poison, no publish.
        func isOwner() -> Bool { !closing.contains(filespace) && uploadGen[key] == gen }
        guard isOwner(), let item = staging[key] else { return }
        // This generation now has a complete-manifest owner. Stop catch-up so
        // it cannot duplicate PUTs absent from this owner's prepared snapshot.
        item.acceptsEarlyUploads = false

        // A replayed ranged entry has no base manifest yet — resolve it now (the CAS
        // still guards the merge: if the manifest moved, the commit 409s).
        if !item.baseFetched && !item.replaced {
            do {
                try await fetchBaseIfNeeded(item, filespace: filespace, itemID: itemID, growSize: false)
            } catch let e as EngineError {
                guard isOwner() else { return }
                // M4: the item vanished before the upload could even resolve its
                // base (the prod gateway 403s a deleted inode here too) — drop.
                if Self.indicatesMissingItem(e), await itemIsGone(filespace: filespace, itemID: itemID) {
                    throw EngineError(.syncFailed, "Remote file was deleted; unsynced local content retained in the journal")
                }
                throw e
            }
            guard isOwner() else { return }
        }

        // Snapshot the staged state under actor isolation, then build the pure
        // (no-I/O) per-block plan + the exact bytes-to-upload total.
        let dirty = item.dirty
        let size = item.size
        let base = item.replaced ? nil : item.base
        let baseLimit = item.replaced ? 0 : item.effectiveBaseSize   // alive committed bytes (P4)
        let baseByOffset: [Int: BlockRef] = Dictionary(
            uniqueKeysWithValues: (base?.manifest.blocks ?? []).map { ($0.offset, $0) })
        let blockCount = size == 0 ? 1 : (size + blockSize - 1) / blockSize   // size 0 → one empty block
        var plan: [BlockPlan] = []
        plan.reserveCapacity(blockCount)
        var total = 0
        for i in 0..<blockCount {
            let bStart = i * blockSize
            let expectedLen = max(0, min(blockSize, size - bStart))
            if dirty[i] != nil {
                plan.append(.dirty(expectedLen)); total += expectedLen
            } else if let ref = baseByOffset[bStart] {
                // How much of this committed block is still ALIVE (truncate kill-line).
                let usable = max(0, min(ref.length, baseLimit - bStart))
                if usable == expectedLen && usable == ref.length {
                    plan.append(.reuse(ref))                   // zero I/O
                } else if usable > 0 {
                    plan.append(.rmw(ref, expectedLen, usable)); total += expectedLen
                } else {
                    plan.append(.hole(expectedLen)); total += expectedLen
                }
            } else {
                plan.append(.hole(expectedLen)); total += expectedLen
            }
        }

        // Park while the pool is paused (DESIGN.md §4.3 pauseTransfers gates the pool).
        let transferID = uploadTransferID(for: key)
        publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                         direction: .upload, bytesDone: 0, bytesTotal: total, state: .queued))
        if paused.contains(filespace) {
            publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                             direction: .upload, bytesDone: 0, bytesTotal: total, state: .paused))
        }
        try await awaitTransferResume(filespace)
        publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                         direction: .upload, bytesDone: 0, bytesTotal: total, state: .active))

        do {
            // Finding 1: a superseded task must bail promptly. Cancellation is
            // cooperative, so check it at the top of the work loop (the fast path
            // had no checkpoint) and bail before doing any network work.
            try Task.checkCancellation()
            let refs = try await withThrowingTaskGroup(of: (Int, BlockRef).self) { group in
                var ordered = [BlockRef?](repeating: nil, count: plan.count)
                var next = 0
                var doneBytes = 0
                func enqueue(_ index: Int) {
                    let step = plan[index]
                    group.addTask { [self] in
                        let ref = try await uploadPreparedOrNormal(step, blockIndex: index, dirty: dirty, base: base,
                                                                  filespace: filespace, itemID: itemID)
                        return (index, ref)
                    }
                }
                while next < min(uploadPreparationLimit, plan.count) { enqueue(next); next += 1 }
                while let (index, ref) = try await group.next() {
                    ordered[index] = ref
                    if case .reuse = plan[index] {} else { doneBytes += ref.length }
                    if isOwner() {
                        publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                                         direction: .upload, bytesDone: doneBytes, bytesTotal: total, state: .active))
                    }
                    if next < plan.count { enqueue(next); next += 1 }
                }
                return ordered.compactMap { $0 }
            }


            // Finding 1: if a newer stageWrite superseded us while we were doing
            // network work, the replacement task owns durability — we must NOT
            // commit a stale manifest, clear B's staging, or publish. Bail silently.
            guard isOwner() else { return }

            // Overlap provider verification with PUTs, then await only this
            // inode's queued metadata before the authoritative manifest commit.
            // Failed/unsupported preverification never bypasses that commit.
            let receiptStart = WriteProfiler.shared.start()
            try await uploadReceipts.drain(filespace: filespace, itemID: itemID)
            WriteProfiler.shared.elapsed("upload.receipt.drain", since: receiptStart)
            guard isOwner() else { return }

            // Acquire external coordination before the transfer mutation gate.
            // Recovery takes the lease gate before inspecting/removing staging;
            // the opposite order here would deadlock completion against upload.
            let fence: Int?
            while true {
                try await awaitTransferResume(filespace)
                let leaseStart = WriteProfiler.shared.start()
                let candidateFence = try await leaseFence?(filespace, itemID) ?? item.fence
                WriteProfiler.shared.elapsed("upload.commitLease", since: leaseStart)
                let commitWait = WriteProfiler.shared.start()
                try requireOpen(filespace)
                await acquireMutation(key)
                WriteProfiler.shared.elapsed("upload.commitMutationWait", since: commitWait)
                if paused.contains(filespace) {
                    // Never park with the mutation gate held: staging, recovery
                    // and shutdown must remain able to preserve local writes.
                    releaseMutation(key)
                    continue
                }
                fence = candidateFence
                break
            }
            defer { releaseMutation(key) }
            try requireOpen(filespace)
            guard isOwner() else { return }
            try Task.checkCancellation()

            // CAS the block-map pointer on the DO — the durability commit (§4.2 step 4).
            // Audit B4/B5: thread the base contentVersion as `expectedVersion` and the
            // lease `fence` so a concurrent save / a stale-fence zombie is a typed 409
            // rather than an unconditional last-writer-wins clobber.
            let manifest = BlockManifest(itemID: itemID, blocks: refs,
                                         contentVersion: "")   // gateway derives the version
            let expectedVersion = item.baseVersion.flatMap(Self.versionNumber(from:))
            guard item.baseVersion == nil || expectedVersion != nil else {
                throw EngineError(.conflict, "Unsupported file version; refresh the file before retrying this save")
            }
            let commitStart = WriteProfiler.shared.start()
            let committed: ItemMetadata
            do {
                defer { WriteProfiler.shared.elapsed("upload.manifestCommit", since: commitStart) }
                committed = try await gateway.putBlockManifest(manifest, filespace: filespace, base: base, blockSize: blockSize,
                                                              expectedVersion: expectedVersion, fence: fence)
            }

            // Finding 1: the CAS itself awaits; re-confirm ownership before we
            // clear the shared staging/uploads slots a replacement task may now own.
            guard isOwner() else { return }

            var prior = localCommitVersions[key]?.prior ?? []
            if let previous = item.baseVersion { prior.insert(previous) }
            if prior.count > 128 { prior = Set(prior.sorted().suffix(128)) }
            localCommitVersions[key] = (committed.metadataVersion, prior)

            // P3: surface the commit's NEW metadata (contentVersion) BEFORE the
            // staging overlay drops — readers still see the overlay while the
            // composition root invalidates its stale-keyed cached manifests, so
            // there is no window where a pre-commit version key serves old blocks.
            if let onCommit {
                await onCommit(filespace, itemID, committed)
                guard isOwner() else { return }
            }
            // Retire the journal before exposing an empty staging set. Otherwise
            // a flush/disconnect can report completion while cleanup is still
            // suspended, leaving a committed generation to replay on restart.
            if let journal { await journal.clear(filespace: filespace, itemID: itemID) }
            guard isOwner() else { return }
            // The mutation gate remains held through cleanup and publication.
            staging[key] = nil
            uploads[key] = nil
            retryTasks[key]?.cancel(); retryTasks[key] = nil
            uploadTransferIDs[key] = nil
            publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                             direction: .upload, bytesDone: total, bytesTotal: total, state: .done))
        } catch is CancellationError {
            // Superseded by a newer staged image; the replacement task owns durability.
            return
        } catch let e as EngineError where e.kind == .conflict || e.kind == .locked {
            // Audit B4/B5: a real version/lock conflict — NOT transient. Keep the
            // local staging (and the journal entry) so nothing is lost, surface a
            // terminal conflict event so the UI can offer rebase/fork, and do NOT
            // retry (a blind retry would just lose the same race again).
            guard isOwner() else { return }
            staging[key]?.lastError = "\(e)"
            uploads[key] = nil
            publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                             direction: .upload, bytesDone: 0, bytesTotal: total,
                             state: .error, error: "conflict: \(e)"))
        } catch {
            // Findings 1 & 3: a superseded task whose cancellation surfaced as a
            // `.networkError` (BlobTransport retries to exhaustion on URLError.cancelled)
            // must NOT poison B's staging, destroy B's upload handle, or publish a
            // phantom `.error` event. Only the CURRENT owner reports a real failure.
            guard isOwner() else { return }
            // M4 (found live): the item was DELETED before its upload committed — the
            // commit can never succeed ("inode not found"), and retrying/parking the
            // entry forever poisons every flush. Confirm the item is really gone at
            // the gateway, then drop the staged entry: there is nothing left to sync.
            if let ee = error as? EngineError, Self.indicatesMissingItem(ee),
               await itemIsGone(filespace: filespace, itemID: itemID) {
                guard isOwner() else { return }
                staging[key]?.lastError = "Remote file deleted; local content retained"
                uploads[key] = nil
                publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                                 direction: .upload, bytesDone: 0, bytesTotal: total,
                                 state: .error, error: "Remote file deleted; local journal retained"))
                return
            }
            // Audit B2: a TRANSIENT failure (429/5xx/network) must NOT park the bytes
            // in RAM forever. Keep the staging + journal entry, drop only the in-flight
            // handle, and re-drive on a bounded exponential backoff. Surface a
            // persistent failure as `.error` only after the retry budget is exhausted.
            let attempt = (staging[key]?.retryAttempt ?? 0)
            uploads[key] = nil
            if attempt < maxUploadRetries && (error as? EngineError)?.kind != .syncFailed {
                staging[key]?.retryAttempt = attempt + 1
                publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                                 direction: .upload, bytesDone: 0, bytesTotal: total, state: .queued))
                scheduleRetry(filespace: filespace, itemID: itemID, key: key, attempt: attempt)
            } else {
                staging[key]?.lastError = "\(error)"
                publish(Transfer(id: transferID, filespace: filespace, path: itemID.rawValue,
                                 direction: .upload, bytesDone: 0, bytesTotal: total,
                                 state: .error, error: "\(error)"))
            }
        }
    }

    private func uploadEarlyPlaintext(_ bytes: Data, blockIndex: Int, filespace: FilespaceID,
                                      itemID: InodeID) async throws -> BlockRef {
        // A permit may have queued behind normal work before Pause was pressed.
        // Discard this speculation instead of holding a permit while paused.
        guard !paused.contains(filespace) else { throw CancellationError() }
        return try await uploadPlaintext(bytes, blockIndex: blockIndex, filespace: filespace, itemID: itemID, early: true)
    }

    private func uploadPreparedOrNormal(_ step: BlockPlan, blockIndex: Int, dirty: [Int: DirtyBlock],
                                        base: ResolvedBlockManifest?, filespace: FilespaceID,
                                        itemID: InodeID) async throws -> BlockRef {
        try Task.checkCancellation()
        if case .reuse(let ref) = step { return ref }
        try await awaitTransferResume(filespace)
        if case .dirty(let expectedLength) = step, let block = dirty[blockIndex],
           expectedLength == blockSize, block.length == expectedLength, let prepared = block.prepared,
           prepared.created.duration(to: .now) < .seconds(60) {
            // Await OUTSIDE the pool: the shared task needs a permit itself.
            // Superseding a manifest upload must not cancel an immutable PUT that
            // the newer generation still references. Failures fall back to the
            // ordinary uploader, whose errors preserve the journal and surface.
            let ref = try? await prepared.value()
            try Task.checkCancellation()
            if let ref {
                WriteProfiler.shared.addBytes("upload.preparedReusedPlaintext", count: ref.length)
                return ref
            }
        }
        let preparationStart = WriteProfiler.shared.start()
        let reservation = try await uploadPreparation.acquire()
        defer { reservation.release(); pumpAppendUploads() }
        WriteProfiler.shared.elapsed("upload.normal.preparationWait", since: preparationStart)
        try Task.checkCancellation()
        return try await uploadOneBlock(step, blockIndex: blockIndex, dirty: dirty, base: base,
                                       filespace: filespace, itemID: itemID)
    }

    private func uploadOneBlock(_ step: BlockPlan, blockIndex: Int, dirty: [Int: DirtyBlock],
                        base: ResolvedBlockManifest?, filespace: FilespaceID,
                        itemID: InodeID) async throws -> BlockRef {
        try Task.checkCancellation()

        // Resolve this block's plaintext per the plan; `.reuse` copies the
        // committed ref verbatim — no fetch, no encrypt, no PUT (P0).
        let chunk: Data
        switch step {
        case .reuse(let ref):
            return ref
        case .dirty(let expectedLen):
            // P1: page the staged image in from the journal (or RAM for
            // journal-less test engines) — one block resident at a time.
            guard let block = dirty[blockIndex] else {
                throw EngineError(.syncFailed, "staged block \(blockIndex) bytes unavailable")
            }
            var img = try dirtyBlockData(block, filespace: filespace, itemID: itemID, index: blockIndex)
            if img.count < expectedLen { img.append(Data(repeating: 0, count: expectedLen - img.count)) }
            if img.count > expectedLen { img = img.prefix(expectedLen) }
            chunk = img
        case .rmw(let ref, let expectedLen, let usable):
            // Committed block re-shaped (grown past a short tail, or truncated):
            // RMW that one block — fetch (cache HIT is free), trim to the alive
            // extent, zero-pad to the new extent, re-encrypt.
            guard let resolvedBase = base else {
                throw EngineError(.internal, "rmw plan without a base manifest")
            }
            try await fetchOneBlock(ref, objectKey: resolvedBase.objectKey(for: ref.hash),
                                    blockIndex: blockIndex, filespace: filespace, itemID: itemID, background: true)
            guard let ct = try await cache.readBlock(ref.hash) else {
                throw EngineError(.gatewayError, "rmw block \(ref.hash.hex) could not be made resident")
            }
            var pt = Data(try await crypto.decryptBlock(ct, itemID: itemID, blockIndex: blockIndex).prefix(usable))
            if pt.count < expectedLen { pt.append(Data(repeating: 0, count: expectedLen - pt.count)) }
            chunk = pt
        case .hole(let expectedLen):
            chunk = Data(repeating: 0, count: expectedLen)
        }

        return try await uploadPlaintext(chunk, blockIndex: blockIndex, filespace: filespace, itemID: itemID)
    }

    private func uploadPlaintext(_ chunk: Data, blockIndex: Int, filespace: FilespaceID,
                                 itemID: InodeID, early: Bool = false) async throws -> BlockRef {
        try requireOpen(filespace)
        try Task.checkCancellation()
        if !early { try await awaitTransferResume(filespace) }
        try await awaitUploadAdmission()
        let profile = WriteProfiler.shared
        let encryptionStart = profile.start()
        let (ciphertext, hash) = try await crypto.encryptBlock(chunk, itemID: itemID, blockIndex: blockIndex)
        profile.elapsed("upload.encrypt", since: encryptionStart)
        profile.elapsed(early ? "upload.early.encrypt" : "upload.normal.encrypt", since: encryptionStart)
        profile.addBytes("upload.encryptedPlaintext", count: chunk.count)
        // A local cache hit is not proof the destination bucket has this object.
        do {
            // Upload under the GATEWAY's object-key scheme (`blocks/<org>::<fs>/<hash>`),
            // the key the presign confinement accepts AND the manifest will record —
            // NOT the content-address cache key (`chunks/…`, which the gateway 403s).
            let objectKey = await gateway.uploadObjectKey(filespace: filespace, blockHash: hash)
            while true {
                if early, paused.contains(filespace) { throw CancellationError() }
                if !early { try await awaitTransferResume(filespace) }
                try await awaitUploadAdmission()
                let signStart = profile.start()
                let candidate: PresignedURL
                do {
                    candidate = try await Self.retryPresign { [writePresigns] in
                        try await writePresigns.sign(filespace: filespace, key: objectKey, itemID: itemID)
                    }
                } catch { throw recordUploadFailure(error) }
                profile.elapsed(early ? "upload.early.presign" : "upload.normal.presign", since: signStart)
                let authorizedAt = ContinuousClock.now
                // Another block may establish a cooldown while authorization is
                // suspended. Re-wait and refresh the URL rather than dispatching
                // early or holding an expired presign through a long cooldown.
                if uploadCooldownError != nil || (uploadNotBefore.map { $0 > .now } ?? false) { continue }
                let permitStart = profile.start()
                let sent = try await uploadPool.withPermit { [self] in
                    try await putPreparedCiphertext(ciphertext, hash: hash, signed: candidate,
                        authorizedAt: authorizedAt, filespace: filespace, early: early, permitStart: permitStart)
                }
                if sent { break }
            }
            // The PUT permit was released the moment the object landed; cache
            // admission (hash + disk write) must not hold a payload slot idle.
            // A failure here fails this block exactly as it did inside the permit.
            let cacheStart = profile.start()
            try await cache.putBlock(hash, plaintext: ciphertext)
            profile.elapsed(early ? "upload.early.cache" : "upload.normal.cache", since: cacheStart)
            await uploadReceipts.enqueue(filespace: filespace, itemID: itemID,
                block: UploadedBlockVerification(objectKey: objectKey, blockHash: hash.hex, length: chunk.count))
        }
        return BlockRef(hash: hash, offset: blockIndex * blockSize, length: chunk.count)
    }

    /// Authorization is prepared before payload admission. A cooldown established
    /// while queued must release this permit and reauthorize after the wait; never
    /// consume a payload slot while sleeping or send a stale authorized request.
    /// Prepared-image window. Authorization (batched presign, ~PUT-sized latency)
    /// must complete while earlier payloads transfer, so the window is 3x the
    /// payload slots, capped at 96 block images (96 at the default 32 slots).
    /// Memory cost: at most 96 x blockSize of staged/encrypted images, about
    /// 96 MiB at the 1 MiB default and roughly 192 MiB worst case per filespace
    /// while plaintext and ciphertext coexist (measured ~2 MiB per image).
    static func preparationLimit(uploadConcurrency: Int) -> Int { min(96, uploadConcurrency * 3) }
    /// Hard metadata bound for the receipt queue (pending + in-flight objects).
    static func receiptCapacity(uploadConcurrency: Int) -> Int { max(512, 16 * uploadConcurrency) }

    private func putPreparedCiphertext(_ ciphertext: Data, hash: BlockHash, signed: PresignedURL,
                                       authorizedAt: ContinuousClock.Instant, filespace: FilespaceID, early: Bool,
                                       permitStart: UInt64) async throws -> Bool {
        let profile = WriteProfiler.shared
        profile.elapsed(early ? "upload.early.permitWait" : "upload.normal.permitWait", since: permitStart)
        try Task.checkCancellation()
        try requireOpen(filespace)
        if paused.contains(filespace) {
            if early { throw CancellationError() }
            return false
        }
        let maximumAge = Duration.seconds(max(1, min(900, signed.expiresIn) - 5))
        guard uploadCooldownError == nil, !(uploadNotBefore.map { $0 > .now } ?? false),
              authorizedAt.duration(to: .now) < maximumAge else { return false }
        let putStart = profile.start()
        do {
            try await blob.put(url: signed.url, body: ciphertext, headers: signed.headers ?? [:], verificationUrl: signed.verificationUrl, filespace: filespace,
                               feedback: { [uploadPool] in await uploadPool.feedback($0) })
        } catch {
            // Record before leaving the payload permit, so the next queued PUT
            // cannot be admitted between a congestion response and its cooldown.
            throw recordUploadFailure(error)
        }
        profile.elapsed(early ? "upload.early.put" : "upload.normal.put", since: putStart)
        profile.addBytes("upload.putCompletedCiphertext", count: ciphertext.count)
        // Cache admission is the caller's job, AFTER this permit is released.
        return true
    }

    private func recordUploadFailure(_ error: Error) -> Error {
        if let cooldown = Self.retryAfterSeconds(error) {
            guard cooldown <= 86_400 else {
                let retained = EngineError(.syncFailed,
                    "Storage requested a retry delay longer than one day; local journal retained. After the storage service recovers, fully disconnect and reconnect the filespace (pause/resume does not reset this delay), then retry this upload.")
                uploadCooldownError = retained
                return retained
            }
            let deadline = ContinuousClock.now.advanced(by: .seconds(cooldown))
            if uploadNotBefore == nil || deadline > uploadNotBefore! { uploadNotBefore = deadline }
        }
        return error
    }

    private func awaitUploadAdmission() async throws {
        while true {
            try Task.checkCancellation()
            if let uploadCooldownError { throw uploadCooldownError }
            guard let deadline = uploadNotBefore, deadline > .now else { return }
            try await Task.sleep(until: deadline, clock: .continuous)
        }
    }

    private static func retryAfterSeconds(_ error: Error) -> Double? {
        guard let error = error as? EngineError else { return nil }
        let seconds: Double?
        switch error.data?["retryAfter"] {
        case .string(let value): seconds = Double(value)
        case .int(let value): seconds = Double(value)
        default: seconds = nil
        }
        guard let seconds, seconds.isFinite, seconds > 0 else { return nil }
        return seconds
    }

    /// Parse a numeric version out of a contentVersion string for the CAS guard. The
    /// gateway's Item.version is an integer; metadataVersion is stringified ("3").
    /// contentVersion is "cv-<size>-<seq>" which has no monotonic version — so when
    /// the base is a raw integer string we use it, otherwise nil (unconditional).
    private static func versionNumber(from base: String) -> Int? {
        Int(base)
    }

    /// Whether a commit failure's shape says the ITEM no longer exists. 404 maps to
    /// `.notFound`; the production gateway's authz gate answers 403 with reason
    /// "inode not found" for a deleted inode (it checks existence before ownership),
    /// which maps to `.permissionDenied` + that reason string.
    static func indicatesMissingItem(_ e: EngineError) -> Bool {
        if e.kind == .notFound { return true }
        guard e.kind == .permissionDenied else { return false }
        if case .string(let reason)? = e.data?["reason"], reason.lowercased().contains("not found") {
            return true
        }
        return e.message.lowercased().contains("not found")
    }

    /// Double-check against the gateway that the item is really gone before dropping
    /// staged bytes (a transient auth 403 must NEVER cost user data: if the item
    /// still resolves — or the check itself fails — we keep the entry and retry).
    private func itemIsGone(filespace: FilespaceID, itemID: InodeID) async -> Bool {
        do {
            _ = try await gateway.getItem(filespace: filespace, id: itemID)
            return false
        } catch let e as EngineError {
            return Self.indicatesMissingItem(e)
        } catch {
            return false
        }
    }

    // MARK: - Sync barriers (DESIGN.md §4.2, CONTROL-API.md §5.6) ----------

    public func flush(filespace: FilespaceID, path: String, wait: Bool, timeoutMs: Int?) async throws -> SyncState {
        try requireOpen(filespace)
        defer { WriteProfiler.shared.report() }
        if !wait { return syncStateNow(filespace: filespace, path: path) }
        guard timeoutMs == nil || timeoutMs! >= 0 else {
            throw EngineError(.invalidParams, "negative flush timeout")
        }
        let deadline = timeoutMs.map { ContinuousClock.now.advanced(by: .milliseconds($0)) }
        // Observe the staging set until it is empty. An upload task is only one
        // attempt: retries and newer writes may replace it while this waits.
        while true {
            try Task.checkCancellation()
            // An explicit durability barrier does not wait for the idle timer.
            // Newly staged generations observed while waiting are promoted too.
            for key in Array(deferredUploads) where key.filespace == filespace && matches(key.itemID, under: path) {
                scheduleUpload(filespace: key.filespace, itemID: key.itemID, key: key, debounce: false)
            }
            if let failedPath = firstStagingError(filespace: filespace, under: path) {
                throw EngineError(.syncFailed, "upload did not commit durably; local journal retained",
                                  data: ["path": .string(failedPath)])
            }
            let state = syncStateNow(filespace: filespace, path: path)
            if state.inSync { return state }
            if let deadline, ContinuousClock.now >= deadline {
                throw EngineError(.syncTimeout, "flush barrier timed out",
                    data: ["pendingUploads": .int(state.pendingUploads), "pendingBytes": .int(state.pendingBytes)])
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    public func syncState(filespace: FilespaceID, path: String) async throws -> SyncState {
        syncStateNow(filespace: filespace, path: path)
    }

    private func syncStateNow(filespace: FilespaceID, path: String) -> SyncState {
        var pendingUploads = 0
        var pendingBytes = 0
        for (key, item) in staging where key.filespace == filespace && matches(key.itemID, under: path) {
            pendingUploads += 1
            pendingBytes += item.byteCount
        }
        return SyncState(path: path, inSync: pendingUploads == 0,
                         pendingUploads: pendingUploads, pendingBytes: pendingBytes)
    }

    private func firstStagingError(filespace: FilespaceID, under path: String) -> String? {
        for (key, item) in staging
        where key.filespace == filespace && matches(key.itemID, under: path) && item.lastError != nil {
            return key.itemID.rawValue
        }
        return nil
    }

    /// A `path` matches an item if it IS the item or is an ancestor directory of it
    /// (so `flush(path:"projectA")` drains every staged file under projectA/).
    private func matches(_ itemID: InodeID, under path: String) -> Bool {
        let id = itemID.rawValue
        if path.isEmpty || path == id || path == "/" { return true }
        let prefix = path.hasSuffix("/") ? path : path + "/"
        return id.hasPrefix(prefix)
    }

    // MARK: - Transfers view + pause/resume (CONTROL-API.md §5.5) ----------

    public func current(filespace: FilespaceID) async throws -> [Transfer] {
        let active = transfersByFilespace[filespace]?.values.filter {
            $0.state == .queued || $0.state == .active || $0.state == .paused
        } ?? []
        return active.sorted { $0.id < $1.id }
    }

    public func pause(filespace: FilespaceID) async throws -> PauseResult {
        try requireOpen(filespace)
        paused.insert(filespace)
        for transfer in transfersByFilespace[filespace]?.values.filter({ $0.state == .queued || $0.state == .active }) ?? [] {
            if transfer.direction == .upload || backgroundDownloadIDs.contains(transfer.id) { publish(transfer) }
        }
        return PauseResult(paused: true)
    }

    public func stopBackgroundVerification(filespace: FilespaceID) async {
        await uploadReceipts.stop(filespace: filespace)
    }

    public func shutdown(filespace: FilespaceID) async {
        // Invalidate ownership before the first suspension: an already-sent CAS
        // may still succeed remotely, but may never clear this retained journal.
        closing.insert(filespace)
        paused.insert(filespace)
        wakePauseWaiters(filespace: filespace, cancelled: true)
        for key in Set(staging.keys).union(uploads.keys).union(retryTasks.keys) where key.filespace == filespace {
            staging[key]?.acceptsEarlyUploads = false
            invalidateUpload(key)
        }
        for entry in uploadTasks.values where entry.0 == filespace { entry.1.cancel() }
        for entry in earlyTasks.values where entry.0 == filespace { entry.1.cancel() }
        for entry in downloadTasks.values where entry.0 == filespace { entry.1.cancel() }
        await uploadReceipts.stop(filespace: filespace)
        await readPresigns.stop(filespace: filespace)
        await writePresigns.stop(filespace: filespace)
        if !shutdownDrained(filespace) {
            await withCheckedContinuation { shutdownWaiters[filespace, default: []].append($0) }
        }
    }

    public func resume(filespace: FilespaceID) async throws -> PauseResult {
        try requireOpen(filespace)
        paused.remove(filespace)
        wakePauseWaiters(filespace: filespace)
        for var transfer in transfersByFilespace[filespace]?.values.filter({ $0.state == .paused }) ?? [] {
            transfer.state = .queued
            publish(transfer)
        }
        pumpAppendUploads()
        return PauseResult(paused: false)
    }

    // MARK: - Progress event stream (CONTROL-API.md §6) -------------------

    public nonisolated func progressEvents(filespace: FilespaceID) -> AsyncStream<Transfer> {
        // Unbounded buffer: never drop or block a publisher; the consumer drains
        // at its own pace. Registration is SYNCHRONOUS (inside the lock-protected
        // sink) so no event — including the terminal `.done` — can be published
        // before this subscriber is attached.
        AsyncStream(bufferingPolicy: .unbounded) { continuation in
            let id = UUID()
            sink.add(filespace: filespace, id: id, continuation: continuation)
            continuation.onTermination = { [sink] _ in
                sink.remove(filespace: filespace, id: id)
            }
        }
    }

    /// Record + fan out a transfer state change to the transfers view and every
    /// progress subscriber (DESIGN.md §4.3 progress events).
    private func publish(_ incoming: Transfer) {
        var t = incoming
        if paused.contains(t.filespace), t.state == .active || t.state == .queued,
           t.direction == .upload || backgroundDownloadIDs.contains(t.id) { t.state = .paused }
        transfersByFilespace[t.filespace, default: [:]][t.id] = t
        terminalTransferIDs[t.filespace]?.removeAll { $0 == t.id }
        if t.state == .done || t.state == .error {
            backgroundDownloadIDs.remove(t.id)
            terminalTransferIDs[t.filespace, default: []].append(t.id)
            while (terminalTransferIDs[t.filespace]?.count ?? 0) > Self.terminalTransferLimit {
                let oldest = terminalTransferIDs[t.filespace]!.removeFirst()
                transfersByFilespace[t.filespace]?[oldest] = nil
            }
        }
        sink.yield(t)
    }

    private func uploadTransferID(for key: StagingKey) -> String {
        if let existing = uploadTransferIDs[key] { return existing }
        let id = newTransferID()
        uploadTransferIDs[key] = id
        return id
    }

    // MARK: - Helpers -----------------------------------------------------

    private func newTransferID() -> String {
        transferSeq += 1
        return "xfer-\(transferSeq)"
    }

    /// Map a byte range to the set of manifest block indices it touches. The
    /// manifest's `BlockRef.offset/length` are authoritative (the tail block may be
    /// short), so we intersect each block's byte span with the requested range.
    private func blockIndices(forOffset offset: Int, length: Int, manifest: BlockManifest) -> [Int] {
        let lo = max(0, offset)
        let hi = offset + length
        var out: [Int] = []
        for i in manifest.blocks.indices {
            let b = manifest.blocks[i]
            let bStart = b.offset
            let bEnd = b.offset + b.length
            if bStart < hi && bEnd > lo { out.append(i) }
        }
        return out
    }
}

// MARK: - Chunk readers for the replace pipeline (P1) ---------------------------
//
// Sequential block-size chunk sources: one block in memory at a time. Used only
// inside the transfer actor's replace pipeline (never escape its isolation).

private protocol ChunkReader: Sendable {
    func next() throws -> Data?
}

private final class InMemoryChunkReader: ChunkReader, @unchecked Sendable {
    private let data: Data
    private let chunkSize: Int
    private var offset = 0
    init(data: Data, chunkSize: Int) { self.data = data; self.chunkSize = chunkSize }
    func next() -> Data? {
        guard offset < data.count else { return nil }
        let end = min(offset + chunkSize, data.count)
        defer { offset = end }
        return data.subdata(in: offset..<end)
    }
}

/// Reads a REGULAR file in block-size chunks (FileHandle returns full chunks until
/// EOF for regular files — the CacheFileRef hand-off is always a regular file).
private final class FileChunkReader: ChunkReader, @unchecked Sendable {
    private let handle: Foundation.FileHandle
    private let chunkSize: Int
    init(handle: Foundation.FileHandle, chunkSize: Int) { self.handle = handle; self.chunkSize = chunkSize }
    func next() throws -> Data? {
        guard let d = try handle.read(upToCount: chunkSize), !d.isEmpty else { return nil }
        return d
    }
}

// MARK: - Progress fan-out sink ------------------------------------------------
//
// A lock-protected continuation registry, separate from the actor's isolation so
// `progressEvents` can attach a subscriber SYNCHRONOUSLY (before returning the
// stream). That closes the race where a fast download publishes its terminal
// `.done` event before a deferred registration runs — which would leave the
// consumer's `for await` loop waiting forever (the deadlock the suite hit).
private final class ProgressSink: @unchecked Sendable {
    private let lock = NSLock()
    private var subscribers: [FilespaceID: [UUID: AsyncStream<Transfer>.Continuation]] = [:]

    func add(filespace: FilespaceID, id: UUID, continuation: AsyncStream<Transfer>.Continuation) {
        lock.lock(); defer { lock.unlock() }
        subscribers[filespace, default: [:]][id] = continuation
    }
    func remove(filespace: FilespaceID, id: UUID) {
        lock.lock(); defer { lock.unlock() }
        subscribers[filespace]?[id] = nil
    }
    func yield(_ t: Transfer) {
        lock.lock()
        let conts = subscribers[t.filespace]?.values.map { $0 } ?? []
        lock.unlock()
        for c in conts { c.yield(t) }   // yield outside the lock (unbounded buffer → non-blocking)
    }
}
