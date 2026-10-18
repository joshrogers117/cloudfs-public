// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// Coalesces already-admitted upload tasks; never reads or retains payload bytes.
/// Preserves each object's declared inode, conditional/checksum headers and 412
/// verification URL. Cancellation removes that waiter even during a shared RPC.
actor WritePresignBatcher {
    private struct Request: Sendable { let id: UUID; let filespace: FilespaceID; let key: String; let item: InodeID; let arrived: ContinuousClock.Instant }
    private let gateway: any GatewayClient
    private let coalesce: @Sendable () async -> Void
    private var queue: [Request] = []
    private var waiting: [UUID: CheckedContinuation<PresignedURL, Error>] = [:]
    private var stoppedFilespaces: Set<FilespaceID> = []
    private var batches: [UUID: (requests: [Request], task: Task<Void, Never>)] = [:]
    private var scheduled = false
    private var active = 0
    private var profiledRPCs = 0
    /// A small batch is held up to `window` (measured from its oldest key) so
    /// concurrently produced keys share one RPC; a full batch (32) or a quiet
    /// producer (`quiet` since the last arrival, with nothing in flight) dispatches
    /// at once. The four-RPC bound is unchanged.
    private let window: Duration
    private let quiet: Duration
    private var lastArrival = ContinuousClock.now
    private var timer: Task<Void, Never>?
    init(gateway: any GatewayClient, coalesce: @escaping @Sendable () async -> Void = { try? await Task.sleep(for: .microseconds(100)) },
         window: Duration = .milliseconds(15), quiet: Duration = .milliseconds(4)) {
        self.gateway = gateway; self.coalesce = coalesce; self.window = window; self.quiet = quiet
    }
    func sign(filespace: FilespaceID, key: String, itemID: InodeID) async throws -> PresignedURL {
        try Task.checkCancellation()
        guard !stoppedFilespaces.contains(filespace) else { throw CancellationError() }
        let profile = WriteProfiler.shared
        let started = profile.enabled ? profile.start() : 0
        defer { if profile.enabled { profile.elapsed("writePresign.wait", since: started) } }
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                guard waiting.count < 256 else { continuation.resume(throwing: EngineError(.networkError, "Write authorization queue is full")); return }
                let now = ContinuousClock.now
                lastArrival = now
                waiting[id] = continuation; queue.append(Request(id: id, filespace: filespace, key: key, item: itemID, arrived: now))
                if timer != nil, queue.count >= 32 { pump() }
                if !scheduled {
                    scheduled = true
                    Task { await coalesce(); pump() }
                }
            }
        } onCancel: { Task { await self.cancel(id) } }
    }
    /// Fence the old session before suspension, then wait for its actual RPCs
    /// to exit, including gateways that do not promptly observe cancellation.
    func stop(filespace: FilespaceID) async {
        stoppedFilespaces.insert(filespace)
        let running = batches.values.filter { $0.requests.first?.filespace == filespace }
        let removed = queue.filter { $0.filespace == filespace } + running.flatMap(\.requests)
        queue.removeAll { $0.filespace == filespace }
        for batch in running { batch.task.cancel() }
        for request in removed { finish(request, .failure(CancellationError())) }
        for batch in running { await batch.task.value }
        pump()
    }
    private func cancel(_ id: UUID) {
        queue.removeAll { $0.id == id }
        waiting.removeValue(forKey: id)?.resume(throwing: CancellationError())
    }
    private func pump() {
        scheduled = false
        while active < 4, let first = queue.first {
            let hold = holdRemaining(first)
            if hold > .zero {
                if timer == nil {
                    timer = Task { [self] in try? await Task.sleep(for: hold); await timerFired() }
                }
                return
            }
            var batch: [Request] = []
            queue.removeAll { request in
                guard request.filespace == first.filespace, batch.count < 32 else { return false }
                batch.append(request); return true
            }
            active += 1
            let id = UUID()
            let task = Task { await send(batch); batches[id] = nil; active -= 1; pump() }
            batches[id] = (batch, task)
        }
    }
    private func timerFired() { timer = nil; pump() }
    private func holdRemaining(_ first: Request) -> Duration {
        guard queue.count < 32 else { return .zero }
        let now = ContinuousClock.now
        var remaining = window - first.arrived.duration(to: now)
        if active == 0 { remaining = min(remaining, quiet - lastArrival.duration(to: now)) }
        return remaining
    }
    private func finish(_ request: Request, _ incomingResult: Result<PresignedURL, Error>) {
        guard let continuation = waiting.removeValue(forKey: request.id) else { return }
        let result: Result<PresignedURL, Error> = stoppedFilespaces.contains(request.filespace)
            ? .failure(CancellationError()) : incomingResult
        if WriteProfiler.shared.enabled, case .success = result { WriteProfiler.shared.count("writePresign.authorizedKeys") }
        continuation.resume(with: result)
    }
    private func single(_ request: Request) async {
        guard !stoppedFilespaces.contains(request.filespace), waiting[request.id] != nil else { return }
        let started = profileRPCStarted(batchSize: nil)
        defer { profileRPCFinished("writePresign.singleRPC", since: started) }
        do { finish(request, .success(try await gateway.presignWrite(filespace: request.filespace, key: request.key, itemID: request.item, expiresIn: nil))) }
        catch { finish(request, .failure(error)) }
    }
    private func send(_ requests: [Request]) async {
        guard let first = requests.first else { return }
        do {
            try Task.checkCancellation()
            let results: [PresignBatchResult]
            do {
                let started = profileRPCStarted(batchSize: requests.count)
                defer { profileRPCFinished("writePresign.batchRPC", since: started) }
                results = try await gateway.presignWriteBatch(filespace: first.filespace,
                    keys: requests.map { ($0.key, $0.item) }, expiresIn: nil)
            }
            try Task.checkCancellation()
            // The batch endpoint preserves entry order. Do not key only by hash:
            // two declarations with the same key can have different inode ACLs.
            for (index, request) in requests.enumerated() {
                if results.count == requests.count, results[index].key == request.key,
                   results[index].error == nil, let url = results[index].url {
                    let result = results[index]
                    finish(request, .success(PresignedURL(url: url, expiresIn: 300, headers: result.headers, verificationUrl: result.verificationUrl)))
                } else { await single(request) }
            }
        } catch let error as EngineError where error.kind == .unimplemented || error.kind == .notFound {
            for request in requests { await single(request) }
        } catch {
            for request in requests { finish(request, .failure(error)) }
        }
    }
    private func profileRPCStarted(batchSize: Int?) -> UInt64 {
        let profile = WriteProfiler.shared
        guard profile.enabled else { return 0 }
        profiledRPCs += 1
        profile.count("writePresign.rpcs")
        profile.count("writePresign.activeRPCs.\(profiledRPCs)")
        if let batchSize {
            profile.count("writePresign.batches")
            profile.count("writePresign.batchSize.\(batchSize)")
            for _ in 0..<batchSize { profile.count("writePresign.keys") }
        } else {
            profile.count("writePresign.singles")
            profile.count("writePresign.keys")
        }
        return profile.start()
    }
    private func profileRPCFinished(_ name: String, since started: UInt64) {
        let profile = WriteProfiler.shared
        guard profile.enabled else { return }
        profiledRPCs -= 1
        profile.elapsed(name, since: started)
    }
    func metrics() -> (queued: Int, waiting: Int, active: Int) { (queue.count, waiting.count, active) }
}
