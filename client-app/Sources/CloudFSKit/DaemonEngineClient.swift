// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - DaemonEngineClient
//
// The real EngineClient: connects to the cloudfsd Unix-domain socket and calls
// the control methods over newline-delimited JSON-RPC 2.0 (cloudfsd/CONTROL-API.md).
// One persistent connection is shared for request/response AND the event stream
// (the contract: "a client subscribes once per connection", §6). JSON-RPC errors
// are mapped to typed `EngineError`s via `EngineError.from(_:)`.
//
// Concurrency: the client is an `actor` so connect-on-first-use and the shared
// event fan-out are race-free. The underlying `UnixSocketConnection` is itself an
// actor; this type owns connection lifecycle + the event subscriber registry.

public actor DaemonEngineClient: EngineClient {

    public let socketPath: String
    private let connection: UnixSocketConnection
    private var connectionGeneration: UInt64 = 0
    private var lifecycleRevision: UInt64 = 0

    // Live transfer subscribers, keyed by filespace, fed by `transfer` events.
    // Each subscription keeps a running snapshot keyed by transfer id.
    private var transferContinuations: [UUID: (filespace: String, cont: AsyncStream<[Transfer]>.Continuation)] = [:]
    private var transferSnapshots: [String: [String: Transfer]] = [:]  // filespace -> id -> Transfer
    private var subscribedGeneration: UInt64?
    private var subscriptionTask: (id: UUID, generation: UInt64, task: Task<Void, Error>)?
    private var seedTasks: [String: (generation: UInt64, task: Task<Void, Error>)] = [:]
    private var seededFilespaces: Set<String> = []
    private var eventRevision: UInt64 = 0
    private var transferEventRevisions: [String: [String: UInt64]] = [:]
    private var dismissedDuringSeed: [String: Set<String>] = [:]
    private let recentSuccessLimit = 128

    public init(socketPath: String) {
        self.socketPath = socketPath
        self.connection = UnixSocketConnection(path: socketPath)
    }

    /// This client supports the daemon transport; individual calls report whether
    /// the daemon is reachable. The connection is opened lazily.
    nonisolated public var isAvailable: Bool { true }

    // MARK: Connection lifecycle

    /// Socket setup and handler registration happen in one connection-actor
    /// operation. Reentrant callers share that connection; no stale "is open"
    /// check can close a newer peer or miss the first subscribed notifications.
    private func ensureConnected() async throws -> UInt64 {
        let revision = lifecycleRevision
        let generation = try await connection.connect(notificationHandler: { [weak self] frame, generation in
            await self?.handleNotification(frame, generation: generation)
        }, closeHandler: { [weak self] generation in
            await self?.connectionDidClose(generation: generation)
        })
        guard revision == lifecycleRevision, generation >= connectionGeneration else {
            throw EngineError.unavailable("connection changed")
        }
        if generation != connectionGeneration {
            resetEventState()
            connectionGeneration = generation
        }
        return generation
    }

    private func resetEventState() {
        subscriptionTask?.task.cancel()
        subscriptionTask = nil
        for seed in seedTasks.values { seed.task.cancel() }
        seedTasks.removeAll()
        subscribedGeneration = nil
        seededFilespaces.removeAll()
        for sub in transferContinuations.values { sub.cont.finish() }
        transferContinuations.removeAll()
        transferSnapshots.removeAll()
        transferEventRevisions.removeAll()
        dismissedDuringSeed.removeAll()
    }

    private func connectionDidClose(generation: UInt64) {
        guard generation == connectionGeneration else { return }
        resetEventState()
    }

    public func disconnect() async {
        lifecycleRevision &+= 1
        resetEventState()
        await connection.close()
    }

    // MARK: Generic call helper

    /// Send `method`/`params`, await the response, decode `result` into `T`, and
    /// map a JSON-RPC `error` into a typed `EngineError`.
    func callResult<T: Decodable>(_ method: String, _ params: JSONValue, as type: T.Type) async throws -> T {
        let generation = try await ensureConnected()
        let frame = try await connection.call(method: method, params: params, generation: generation)
        if let err = frame.error { throw EngineError.from(err) }
        guard let result = frame.result else {
            // Some methods return `{}`; tolerate empty object for Void-ish results.
            throw EngineError.decoding("\(method): missing result")
        }
        do {
            return try result.decode(T.self)
        } catch {
            throw EngineError.decoding("\(method): \(error)")
        }
    }

    /// Call a method whose result we ignore (still surfaces errors).
    private func callVoid(_ method: String, _ params: JSONValue) async throws {
        let generation = try await ensureConnected()
        let frame = try await connection.call(method: method, params: params, generation: generation)
        if let err = frame.error { throw EngineError.from(err) }
    }

    // MARK: - Connection (§4)

    public func setConnectionState(_ connected: Bool, filespace: String) async throws {
        _ = try await callResult("filespace.setConnectionState",
            .params(["filespace": .string(filespace),
                     "state": .string(connected ? "connected" : "disconnected")]),
            as: EngineFilespace.self)
    }

    // MARK: - Mount (§5.1)

    public func mount(filespace: String, at path: String?, name: String?) async throws -> EngineFilespace {
        try await callResult("mount",
            .params(["filespace": .string(filespace), "at": path.map(JSONValue.string),
                     "name": name.map(JSONValue.string)]),
            as: EngineFilespace.self)
    }

    public func mountOffline(filespace: String, pinPath: String, name: String?) async throws -> EngineFilespace {
        try await callResult("mount", .params(["filespace": .string(filespace), "offlinePin": .string(pinPath),
                                               "name": name.map(JSONValue.string)]), as: EngineFilespace.self)
    }

    public func unmount(filespace: String, force: Bool) async throws -> EngineFilespace {
        try await callResult("unmount",
            .params(["filespace": .string(filespace), "force": .bool(force)]),
            as: EngineFilespace.self)
    }

    public func filespaceList() async throws -> [EngineFilespace] {
        try await callResult("filespace.list", .params([:]), as: [EngineFilespace].self)
    }

    public func createItemLink(filespace: String, path: String) async throws -> EngineItemLink {
        let result = try await callResult("link.create",
            .params(["filespace": .string(filespace), "path": .string(path)]), as: EngineItemLink.self)
        guard result.filespace == filespace else { throw EngineError.decoding("Link filespace does not match the request.") }
        return result
    }

    public func resolveItemLink(filespace: String, itemID: String) async throws -> EngineLinkTarget {
        let result = try await callResult("link.resolve",
            .params(["filespace": .string(filespace), "itemId": .string(itemID)]), as: EngineLinkTarget.self)
        guard result.filespace == filespace else { throw EngineError.decoding("Link filespace does not match the request.") }
        return result
    }

    // MARK: - Pin / prefetch / evict (§5.4)

    public func pin(filespace: String, path: String, recursive: Bool) async throws -> PinState {
        try await callResult("pin",
            .params(["filespace": .string(filespace), "path": .string(path), "recursive": .bool(recursive)]),
            as: PinState.self)
    }

    public func unpin(filespace: String, path: String, recursive: Bool) async throws -> PinState {
        try await callResult("unpin",
            .params(["filespace": .string(filespace), "path": .string(path), "recursive": .bool(recursive)]),
            as: PinState.self)
    }

    public func prefetch(filespace: String, path: String) async throws -> PrefetchAck {
        try await callResult("prefetch",
            .params(["filespace": .string(filespace), "path": .string(path)]),
            as: PrefetchAck.self)
    }

    public func evict(filespace: String, path: String) async throws -> EvictAck {
        try await callResult("evict",
            .params(["filespace": .string(filespace), "path": .string(path)]),
            as: EvictAck.self)
    }

    /// Enumerate every pin in the filespace via the `pin.list` control method
    /// (CONTROL-API §5.4). The daemon returns the appended per-pin byte accounting
    /// (`cachedBytes`/`totalBytes`/`cacheState`, CONTRACTS §4.1); `PinState`'s
    /// optional fields tolerate older daemons that omit them.
    public func pinList(filespace: String) async throws -> [PinState] {
        try await callResult("pin.list",
            .params(["filespace": .string(filespace)]),
            as: [PinState].self)
    }

    /// `status` for one filespace (CONTROL-API §3/§5.2): reachability + last success/failure.
    public func status(filespace: String) async throws -> EngineStatus {
        try await callResult("status", .params(["filespace": .string(filespace)]), as: EngineStatus.self)
    }

    // MARK: - Cache (§5.3)

    public func cacheInfo(filespace: String) async throws -> CacheInfo {
        try await callResult("cache.info",
            .params(["filespace": .string(filespace)]), as: CacheInfo.self)
    }

    public func cacheSetSize(filespace: String, bytes: Int64) async throws -> CacheInfo {
        try await callResult("cache.setSize",
            .params(["filespace": .string(filespace), "bytes": .int(Int(bytes))]),
            as: CacheInfo.self)
    }

    public func cacheSetLocation(filespace: String, path: String) async throws -> CacheInfo {
        try await callResult("cache.setLocation",
            .params(["filespace": .string(filespace), "path": .string(path)]),
            as: CacheInfo.self)
    }

    /// `cache.clear` returns the post-clear `CacheInfo` on the wire (same shape as
    /// `cache.setSize`/`cache.setLocation`); `freedBytes` isn't part of that
    /// contract, so it's derived HERE from the `usedBytes` delta across an
    /// immediately-preceding `cache.info` — never negative (a concurrent admission
    /// racing the clear could otherwise make the raw delta look negative).
    public func cacheClear(filespace: String) async throws -> CacheClearResult {
        let before = try await cacheInfo(filespace: filespace)
        let after = try await callResult("cache.clear",
            .params(["filespace": .string(filespace)]), as: CacheInfo.self)
        let freed = max(0, before.usedBytes - after.usedBytes)
        return CacheClearResult(info: after, freedBytes: freed)
    }

    // MARK: - Transfers (§5.5)

    public func currentTransfers(filespace: String) async throws -> [Transfer] {
        let engineTransfers = try await callResult("transfers.current",
            .params(["filespace": .string(filespace)]), as: [EngineTransfer].self)
        return engineTransfers.map { $0.toGUI() }
    }

    public func clearCompletedTransfers(filespace: String) async throws {
        let completed = Set((transferSnapshots[filespace] ?? [:]).values
            .filter { $0.state == .completed }.map(\.id))
        if seedTasks[filespace] != nil {
            dismissedDuringSeed[filespace, default: []].formUnion(completed)
        }
        for id in completed { transferSnapshots[filespace]?[id] = nil }
        trimTransferHistory(filespace: filespace)
        yieldSnapshot(filespace: filespace)
    }

    public func pauseTransfers(filespace: String) async throws {
        try await callVoid("transfers.pause", .params(["filespace": .string(filespace)]))
    }

    public func resumeTransfers(filespace: String) async throws {
        try await callVoid("transfers.resume", .params(["filespace": .string(filespace)]))
    }

    public func recoveryItems(filespace: String) async throws -> [RecoveryItem] {
        try await callResult("recovery.list", .params(["filespace": .string(filespace)]), as: [RecoveryItem].self)
    }

    public func retryRecovery(filespace: String, itemID: String) async throws {
        try await callVoid("recovery.retry", .params(["filespace": .string(filespace), "itemId": .string(itemID)]))
    }

    public func exportRecovery(filespace: String, itemID: String, destination: String) async throws -> RecoveryExportResult {
        try await callResult("recovery.export", .params([
            "filespace": .string(filespace), "itemId": .string(itemID), "destination": .string(destination)
        ]), as: RecoveryExportResult.self)
    }

    public func completeRecovery(filespace: String, itemID: String, destination: String) async throws {
        try await callVoid("recovery.complete", .params([
            "filespace": .string(filespace), "itemId": .string(itemID), "destination": .string(destination)
        ]))
    }

    // MARK: - Transfer event stream (§6)

    nonisolated public func transferUpdates(filespace: String) -> AsyncStream<[Transfer]> {
        AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            let token = UUID()
            let setup = Task { await self.registerTransferStream(token: token, filespace: filespace, continuation: continuation) }
            continuation.onTermination = { _ in
                setup.cancel()
                Task { await self.unregisterTransferStream(token: token) }
            }
        }
    }

    private func registerTransferStream(token: UUID, filespace: String, continuation: AsyncStream<[Transfer]>.Continuation) async {
        do {
            let generation = try await ensureConnected()
            try Task.checkCancellation()
            transferContinuations[token] = (filespace, continuation)
            if seededFilespaces.contains(filespace) {
                continuation.yield(snapshot(filespace: filespace))
                return
            }
            let seed: Task<Void, Error>
            if let existing = seedTasks[filespace], existing.generation == generation {
                seed = existing.task
            } else {
                seed = Task { try await self.seedTransfers(filespace: filespace, generation: generation) }
                seedTasks[filespace] = (generation, seed)
            }
            try await seed.value
            guard !Task.isCancelled, generation == connectionGeneration,
                  transferContinuations[token] != nil else { return }
            continuation.yield(snapshot(filespace: filespace))
        } catch {
            transferContinuations[token] = nil
            continuation.finish()
        }
    }

    private func ensureEventSubscription(generation: UInt64) async throws {
        if subscribedGeneration == generation { return }
        let task: Task<Void, Error>
        let taskID: UUID
        if let existing = subscriptionTask, existing.generation == generation {
            task = existing.task
            taskID = existing.id
        } else {
            task = Task { [connection] in
                let frame = try await connection.call(method: "events.subscribe",
                    params: .params(["kinds": .array([.string("transfer")])]), generation: generation)
                if let error = frame.error { throw EngineError.from(error) }
            }
            taskID = UUID()
            subscriptionTask = (taskID, generation, task)
        }
        do {
            try await task.value
            try Task.checkCancellation()
            guard generation == connectionGeneration else { throw EngineError.unavailable("connection changed") }
            subscribedGeneration = generation
            if subscriptionTask?.id == taskID { subscriptionTask = nil }
        } catch {
            if subscriptionTask?.id == taskID { subscriptionTask = nil }
            throw error
        }
    }

    private func seedTransfers(filespace: String, generation: UInt64) async throws {
        let startedAt = eventRevision
        defer {
            if seedTasks[filespace]?.generation == generation {
                seedTasks[filespace] = nil
                dismissedDuringSeed[filespace] = nil
                trimTransferHistory(filespace: filespace)
            }
        }
        try await ensureEventSubscription(generation: generation)
        let frame = try await connection.call(method: "transfers.current",
            params: .params(["filespace": .string(filespace)]), generation: generation)
        try Task.checkCancellation()
        if let error = frame.error { throw EngineError.from(error) }
        guard generation == connectionGeneration, let result = frame.result else {
            throw EngineError.unavailable("connection changed while reading transfers")
        }
        let current = try result.decode([EngineTransfer].self).map { $0.toGUI() }
        var byID: [String: Transfer] = [:]
        for transfer in current { byID[transfer.id] = transfer }
        // A seed reply describes an earlier server snapshot. Live events received
        // while it was in flight win, including a completion absent from the seed.
        for (id, revision) in transferEventRevisions[filespace] ?? [:] where revision > startedAt {
            byID[id] = transferSnapshots[filespace]?[id]
        }
        for id in dismissedDuringSeed[filespace] ?? [] { byID[id] = nil }
        transferSnapshots[filespace] = byID
        trimTransferHistory(filespace: filespace)
        seededFilespaces.insert(filespace)
    }

    private func snapshot(filespace: String) -> [Transfer] {
        Array((transferSnapshots[filespace] ?? [:]).values).sorted { $0.id < $1.id }
    }

    private func unregisterTransferStream(token: UUID) {
        transferContinuations[token]?.cont.finish()
        transferContinuations[token] = nil
    }

    // MARK: - Sync barriers (§5.6)

    public func syncState(filespace: String, path: String) async throws -> SyncState {
        try await callResult("sync.state",
            .params(["filespace": .string(filespace), "path": .string(path)]),
            as: SyncState.self)
    }

    public func flush(filespace: String, path: String, wait: Bool, timeoutMs: Int?) async throws -> SyncState {
        try await callResult("flush",
            .params(["filespace": .string(filespace), "path": .string(path),
                     "wait": .bool(wait), "timeoutMs": timeoutMs.map { .int($0) }]),
            as: SyncState.self)
    }

    // MARK: - Notification routing (§6)

    private func handleNotification(_ frame: RPCFrame, generation: UInt64) {
        guard generation == connectionGeneration else { return }
        guard let method = frame.method, let params = frame.params else { return }
        switch method {
        case "transfer":
            guard let fsName = params["filespace"]?.stringValue,
                  let transferVal = params["transfer"],
                  let engineTransfer = try? transferVal.decode(EngineTransfer.self)
            else { return }
            applyTransferEvent(filespace: fsName, transfer: engineTransfer.toGUI())
        default:
            // cache / activity / mount events are consumed elsewhere (or ignored
            // in the transfer-only stream); no-op here.
            break
        }
    }

    /// Fold a single transfer update into the per-filespace snapshot and push the
    /// new full snapshot to every subscriber of that filespace.
    private func applyTransferEvent(filespace: String, transfer: Transfer) {
        eventRevision &+= 1
        transferEventRevisions[filespace, default: [:]][transfer.id] = eventRevision
        var byID = transferSnapshots[filespace] ?? [:]
        if transfer.state == .failed || (transfer.state == .completed && transfer.kind == .upload) {
            // Repeated failures retain the latest reason. A successful upload of
            // this inode also resolves prior failed upload IDs (for example after
            // verified recovery followed by a new edit). A successful read range
            // does not prove every other failed download range has recovered.
            for old in byID.values where old.id != transfer.id && old.state == .failed
                && old.path == transfer.path && old.kind == transfer.kind {
                byID[old.id] = nil
            }
        }
        byID[transfer.id] = transfer
        transferSnapshots[filespace] = byID
        trimTransferHistory(filespace: filespace)
        yieldSnapshot(filespace: filespace)
    }

    private func trimTransferHistory(filespace: String) {
        let revisions = transferEventRevisions[filespace] ?? [:]
        let successes = (transferSnapshots[filespace] ?? [:]).values
            .filter { $0.state == .completed }
            .sorted {
                let left = revisions[$0.id, default: 0], right = revisions[$1.id, default: 0]
                return left == right ? $0.id > $1.id : left > right
            }
        for transfer in successes.dropFirst(recentSuccessLimit) {
            transferSnapshots[filespace]?[transfer.id] = nil
        }
        // While a seed is pending, deleted event IDs act as tombstones against a
        // stale response. Afterwards only retained state needs revision metadata.
        if seedTasks[filespace] == nil {
            transferEventRevisions[filespace] = revisions.filter { transferSnapshots[filespace]?[$0.key] != nil }
        }
    }

    private func yieldSnapshot(filespace: String) {
        let value = snapshot(filespace: filespace)
        for sub in transferContinuations.values where sub.filespace == filespace {
            sub.cont.yield(value)
        }
    }
}
