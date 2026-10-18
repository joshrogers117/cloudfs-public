// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// Coalesces admitted reads without retaining payloads. Cancellation removes a
/// speculative waiter immediately even while a shared authorization RPC is
/// running. Authorization never holds a payload-transfer permit.
actor ReadPresignBatcher {
    private struct Object: Hashable, Sendable {
        let filespace: FilespaceID
        let key: String
    }
    private struct Request: Sendable {
        let id: UUID
        let filespace: FilespaceID
        let key: String
        let ticket: TransferPermitPool.Ticket
        var preparedObject: Object? = nil
    }
    private struct Preparation {
        let id: UUID
        let ticket: TransferPermitPool.Ticket
        let expires: ContinuousClock.Instant
        var result: PresignedURL?
    }
    private struct Subscriber {
        let requestID: UUID
        let ticket: TransferPermitPool.Ticket
    }
    private let gateway: any GatewayClient
    private let coalesce: @Sendable () async -> Void
    private var queue: [Request] = []
    private var waiting: [UUID: CheckedContinuation<PresignedURL, Error>] = [:]
    private var prepared: [Object: Preparation] = [:]
    private var subscribers: [UUID: Subscriber] = [:]
    private var stoppedFilespaces: Set<FilespaceID> = []
    // Own admission waits as well as admitted subscribers so disconnect can
    // cancel and drain readers that have not entered the metadata queue yet.
    private var signTasks: [UUID: (filespace: FilespaceID, task: Task<PresignedURL, Error>)] = [:]
    private let now: @Sendable () -> ContinuousClock.Instant
    private let preparationLimit = 128
    // Moving metadata before payload admission must not turn a burst of real
    // readers into queue-full errors. This separate priority gate admits at
    // most 128 awaiting subscribers; queued demand retains no URL or payload.
    private let admission = TransferPermitPool(limit: 128)
    private var scheduled = false
    private var active = 0
    /// Maintained only with opt-in profiling; never contains object identities.
    private var profiledRPCs = 0
    private var batches: [UUID: (requests: [Request], task: Task<Void, Never>)] = [:]
    private let maximumRPCs = 4
    private let maximumSpeculativeRPCs = 3
    init(gateway: any GatewayClient, coalesce: @escaping @Sendable () async -> Void = { try? await Task.sleep(for: .microseconds(100)) },
         now: @escaping @Sendable () -> ContinuousClock.Instant = { .now }) {
        self.gateway = gateway; self.coalesce = coalesce; self.now = now
    }

    /// Register a coherent window before its individual block tasks begin.
    /// These are only short-lived authorization results; no object bytes are
    /// requested. Every key still passes the gateway's scope and ACL checks.
    /// Snapshot URLs have a 60-second lifetime, so retain these for at most 30.
    func prepare(filespace: FilespaceID, keys: [String], priority: TransferPriority) {
        guard !stoppedFilespaces.contains(filespace) else { return }
        expirePreparations()
        for key in keys.prefix(preparationLimit) {
            let object = Object(filespace: filespace, key: key)
            guard prepared[object] == nil else { continue }
            if prepared.count >= preparationLimit {
                guard let oldest = prepared.filter({ $0.value.result != nil }).min(by: { $0.value.expires < $1.value.expires })?.key else { break }
                prepared[oldest] = nil
            }
            let id = UUID(), ticket = TransferPermitPool.Ticket(priority: priority)
            prepared[object] = Preparation(id: id, ticket: ticket, expires: now().advanced(by: .seconds(30)))
            queue.append(Request(id: id, filespace: filespace, key: key, ticket: ticket, preparedObject: object))
        }
        schedule()
    }

    private func schedule() {
        guard !scheduled, !queue.isEmpty else { return }
        scheduled = true
        Task { await coalesce(); pump() }
    }

    private func expirePreparations() {
        let instant = now()
        prepared = prepared.filter { $0.value.expires > instant }
        queue.removeAll { !isLive($0) }
        for batch in batches.values where !batch.requests.contains(where: { isLive($0) }) {
            batch.task.cancel()
        }
    }

    private func isLive(_ request: Request) -> Bool {
        guard !stoppedFilespaces.contains(request.filespace) else { return false }
        return waiting[request.id] != nil ||
            (request.preparedObject.flatMap { prepared[$0]?.id } == request.id) ||
            subscribers.values.contains { $0.requestID == request.id }
    }
    func sign(filespace: FilespaceID, key: String,
              ticket supplied: TransferPermitPool.Ticket? = nil,
              forceFresh: Bool = false) async throws -> PresignedURL {
        try Task.checkCancellation()
        guard !stoppedFilespaces.contains(filespace) else { throw CancellationError() }
        let ticket = supplied ?? TransferPermitPool.Ticket(priority: .demand)
        let admissionStarted = WriteProfiler.shared.start()
        let id = UUID()
        let task = Task {
            try await admission.withPermit(ticket: ticket) {
                WriteProfiler.shared.elapsed("readPresign.admissionWait", since: admissionStarted)
                return try await self.authorize(filespace: filespace, key: key, ticket: ticket, forceFresh: forceFresh)
            }
        }
        signTasks[id] = (filespace, task)
        defer { signTasks[id] = nil }
        return try await withTaskCancellationHandler { try await task.value }
        onCancel: { task.cancel() }
    }

    /// A disconnected transfer engine is never reused. Fence this filespace
    /// before any suspension, then drain both subscribers and autonomous warmup
    /// RPCs so no old session can authorize more work after shutdown returns.
    func stop(filespace: FilespaceID) async {
        stoppedFilespaces.insert(filespace)
        let owned = signTasks.values.filter { $0.filespace == filespace }.map(\.task)
        let running = batches.values.filter { $0.requests.first?.filespace == filespace }
        let removed = queue.filter { $0.filespace == filespace } + running.flatMap(\.requests)
        queue.removeAll { $0.filespace == filespace }
        prepared = prepared.filter { $0.key.filespace != filespace }
        for task in owned { task.cancel() }
        for batch in running { batch.task.cancel() }
        for request in removed { finish(request, .failure(CancellationError())) }
        for task in owned { _ = await task.result }
        for batch in running { await batch.task.value }
        pump()
    }

    private func authorize(filespace: FilespaceID, key: String,
                           ticket: TransferPermitPool.Ticket, forceFresh: Bool) async throws -> PresignedURL {
        try Task.checkCancellation()
        guard !stoppedFilespaces.contains(filespace) else { throw CancellationError() }
        let profile = WriteProfiler.shared
        let started = profile.enabled ? profile.start() : 0
        defer { if profile.enabled { profile.elapsed("readPresign.wait", since: started) } }
        expirePreparations()
        let object = Object(filespace: filespace, key: key)
        if forceFresh, prepared[object]?.result != nil { prepared[object] = nil }
        if let preparation = prepared[object], var result = preparation.result {
            // Expose the remaining conservative local freshness, so a queued
            // payload can refresh rather than using an aging prepared URL.
            result.expiresIn = min(result.expiresIn, max(1, Int(now().duration(to: preparation.expires).components.seconds)))
            profile.count("readPresign.preparedHit")
            return result
        }
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                guard waiting.count < 256 else { continuation.resume(throwing: EngineError(.networkError, "Read authorization queue is full")); return }
                waiting[id] = continuation
                if let preparation = prepared[object] {
                    subscribers[id] = Subscriber(requestID: preparation.id, ticket: ticket)
                    if ticket.priority == .demand { preparation.ticket.promote() }
                    profile.count("readPresign.preparedJoin")
                    pump()
                } else {
                    queue.append(Request(id: id, filespace: filespace, key: key, ticket: ticket))
                    schedule()
                }
            }
        } onCancel: { Task { await self.cancel(id) } }
    }
    /// A foreground caller may join while its shared block is already awaiting
    /// authorization. The same ticket carries that promotion through both queues.
    func promote(_ ticket: TransferPermitPool.Ticket) async {
        ticket.promote()
        await admission.promote(ticket)
        let joined = Set(subscribers.values.filter { $0.ticket.id == ticket.id }.map(\.requestID))
        for preparation in prepared.values where joined.contains(preparation.id) { preparation.ticket.promote() }
        // A preparation can expire while a real subscriber is still queued.
        // Its request survives, and promotion must survive with it.
        for request in queue where joined.contains(request.id) { request.ticket.promote() }
        for batch in batches.values {
            for request in batch.requests where joined.contains(request.id) { request.ticket.promote() }
        }
        pump()
    }
    private func cancel(_ id: UUID) {
        queue.removeAll { $0.id == id }
        waiting.removeValue(forKey: id)?.resume(throwing: CancellationError())
        subscribers[id] = nil
        for batch in batches.values where !batch.requests.contains(where: { isLive($0) }) {
            batch.task.cancel()
        }
    }
    private func pump() {
        scheduled = false
        while active < maximumRPCs {
            let speculativeActive = batches.values.filter { batch in
                batch.requests.allSatisfy { $0.ticket.priority == .speculative }
            }.count
            // Prioritize demand across filespaces and reserve an RPC for future
            // foreground work. Pure demand can still use all four RPCs.
            guard let first = queue.first(where: { $0.ticket.priority == .demand })
                ?? (speculativeActive < maximumSpeculativeRPCs ? queue.first : nil) else { return }
            var batch: [Request] = []
            queue.removeAll { request in
                guard request.filespace == first.filespace, request.ticket.priority == .demand,
                      batch.count < 32 else { return false }
                batch.append(request); return true
            }
            // Fill unused entries with same-filespace speculation. Authorization
            // is metadata-only; no payload buffers or extra RPC slots are added.
            queue.removeAll { request in
                guard request.filespace == first.filespace, batch.count < 32 else { return false }
                batch.append(request); return true
            }
            active += 1
            let id = UUID()
            let task = Task {
                await send(batch)
                batches[id] = nil
                active -= 1
                pump()
            }
            batches[id] = (batch, task)
        }
    }
    private func finish(_ request: Request, _ incomingResult: Result<PresignedURL, Error>) {
        let result: Result<PresignedURL, Error> = stoppedFilespaces.contains(request.filespace)
            ? .failure(CancellationError()) : incomingResult
        if let object = request.preparedObject, var preparation = prepared[object], preparation.id == request.id {
            if case .success(let signed) = result, preparation.expires > now() {
                preparation.result = signed; prepared[object] = preparation
            } else { prepared[object] = nil }
        }
        if WriteProfiler.shared.enabled, case .success = result { WriteProfiler.shared.count("readPresign.authorizedKeys") }
        waiting.removeValue(forKey: request.id)?.resume(with: result)
        let joined = subscribers.filter { $0.value.requestID == request.id }.map(\.key)
        for id in joined {
            subscribers[id] = nil
            waiting.removeValue(forKey: id)?.resume(with: result)
        }
    }
    private func single(_ request: Request) async {
        guard isLive(request) else { return }
        let started = profileRPCStarted(batchSize: nil)
        defer { profileRPCFinished("readPresign.singleRPC", since: started) }
        do { finish(request, .success(try await gateway.presign(filespace: request.filespace, key: request.key, method: .GET, expiresIn: nil))) }
        catch { finish(request, .failure(error)) }
    }
    private func send(_ requests: [Request]) async {
        guard let first = requests.first else { return }
        do {
            try Task.checkCancellation()
            let results: [PresignBatchResult]
            do {
                let started = profileRPCStarted(batchSize: requests.count)
                defer { profileRPCFinished("readPresign.batchRPC", since: started) }
                results = try await gateway.presignBatch(filespace: first.filespace,
                    keys: requests.map { ($0.key, .GET) }, expiresIn: nil)
            }
            try Task.checkCancellation()
            // Preserve positional correspondence; malformed batch results fall
            // back to single-key authorization and its structured errors.
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
        profile.count("readPresign.rpcs")
        profile.count("readPresign.activeRPCs.\(profiledRPCs)")
        if let batchSize {
            profile.count("readPresign.batches")
            profile.count("readPresign.batchSize.\(batchSize)")
            for _ in 0..<batchSize { profile.count("readPresign.keys") }
        } else {
            profile.count("readPresign.singles")
            profile.count("readPresign.keys")
        }
        return profile.start()
    }
    private func profileRPCFinished(_ name: String, since started: UInt64) {
        let profile = WriteProfiler.shared
        guard profile.enabled else { return }
        profiledRPCs -= 1
        profile.elapsed(name, since: started)
    }
    func metrics() -> (queued: Int, waiting: Int, active: Int, speculativeActive: Int, prepared: Int) {
        (queue.count, waiting.count, active,
         batches.values.filter { $0.requests.allSatisfy { $0.ticket.priority == .speculative } }.count, prepared.count)
    }
}
