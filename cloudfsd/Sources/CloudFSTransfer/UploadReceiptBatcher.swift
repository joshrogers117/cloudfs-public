// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// Best-effort provider verification overlaps the remaining uploads. Every queue
/// entry is metadata; success never publishes a manifest, clears a journal, or
/// marks a file durable. The authoritative manifest commit fills any missing
/// receipts after dropped, failed, canceled, or unsupported preverification.
/// Up to four RPCs (128 objects each) overlap independent server verification
/// contexts while sharing one hard metadata bound (`capacity`, scaled by the
/// engine with upload concurrency), including every object currently in any RPC.
actor UploadReceiptBatcher {
    private struct Key: Hashable { let filespace: FilespaceID; let item: InodeID }
    private struct Work { let key: Key; let block: UploadedBlockVerification }
    private struct Batch { let work: [Work]; let task: Task<Void, Never> }
    private struct Drain { let key: Key; let continuation: CheckedContinuation<Void, Error> }
    struct Metrics: Sendable { let pending: Int; let active: Int; let peak: Int; let dropped: Int; let disabled: Bool }
    private let gateway: any GatewayClient
    private let capacity: Int
    private let concurrency: Int
    private let coalesce: @Sendable () async -> Void
    private var pending: [Work] = []
    private var active: [UUID: Batch] = [:]
    private var coalescing = false
    private var drains: [UUID: Drain] = [:]
    private var stopped: Set<FilespaceID> = []
    private var disabled = false
    private var notBefore: ContinuousClock.Instant?
    private var peak = 0
    private var dropped = 0

    init(gateway: any GatewayClient, capacity: Int = 512, concurrency: Int = 4,
         coalesce: @escaping @Sendable () async -> Void = { try? await Task.sleep(for: .milliseconds(5)) }) {
        self.gateway = gateway; self.capacity = max(1, capacity)
        self.concurrency = min(4, max(1, concurrency)); self.coalesce = coalesce
    }
    func enqueue(filespace: FilespaceID, itemID: InodeID, block: UploadedBlockVerification) {
        guard !disabled, !stopped.contains(filespace), block.length > 0,
              !(notBefore.map { $0 > .now } ?? false) else { return }
        let key = Key(filespace: filespace, item: itemID)
        guard !pending.contains(where: { $0.key == key && $0.block == block }),
              !active.values.contains(where: { batch in batch.work.contains { $0.key == key && $0.block == block } }) else { return }
        guard pending.count + activeObjects < capacity else {
            dropped += 1; WriteProfiler.shared.count("upload.receipt.overflow"); return
        }
        pending.append(Work(key: key, block: block))
        peak = max(peak, pending.count + activeObjects)
        WriteProfiler.shared.count("upload.receipt.enqueued")
        if !coalescing, active.count < concurrency {
            coalescing = true
            Task { await coalesce(); coalescing = false; pump() }
        }
    }
    func drain(filespace: FilespaceID, itemID: InodeID) async throws {
        try Task.checkCancellation()
        let key = Key(filespace: filespace, item: itemID), id = UUID()
        guard contains(key) else { return }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                else { drains[id] = Drain(key: key, continuation: continuation) }
            }
        } onCancel: { Task { await self.cancelDrain(id) } }
    }
    func stop(filespace: FilespaceID) async {
        stopped.insert(filespace)
        pending.removeAll { $0.key.filespace == filespace }
        let tasks = active.values.filter { $0.work.first?.key.filespace == filespace }.map(\.task)
        for task in tasks { task.cancel() }
        for task in tasks { await task.value }
        finishDrains()
    }
    func metrics() -> Metrics {
        Metrics(pending: pending.count, active: activeObjects, peak: peak, dropped: dropped, disabled: disabled)
    }
    private var activeObjects: Int { active.values.reduce(0) { $0 + $1.work.count } }
    private func contains(_ key: Key) -> Bool {
        pending.contains { $0.key == key } || active.values.contains { $0.work.first?.key == key }
    }
    private func cancelDrain(_ id: UUID) { drains.removeValue(forKey: id)?.continuation.resume(throwing: CancellationError()) }
    private func finishDrains() {
        for (id, drain) in drains where !contains(drain.key) {
            drains.removeValue(forKey: id)?.continuation.resume()
        }
    }
    private func pump() {
        while !disabled, !(notBefore.map { $0 > .now } ?? false), active.count < concurrency, let first = pending.first {
            var work: [Work] = []
            pending.removeAll { candidate in
                guard candidate.key == first.key, work.count < 128 else { return false }
                work.append(candidate); return true
            }
            let id = UUID(), batch = work
            let task = Task { await run(id: id, work: batch) }
            active[id] = Batch(work: batch, task: task)
        }
    }
    private func run(id: UUID, work: [Work]) async {
        guard let first = work.first else { return }
        let profile = WriteProfiler.shared, started = profile.start()
        profile.count("upload.receipt.rpcs")
        do {
            try Task.checkCancellation()
            try await gateway.verifyUploadedBlocks(filespace: first.key.filespace, itemID: first.key.item, blocks: work.map(\.block))
            for _ in work { profile.count("upload.receipt.verified") }
        } catch {
            profile.count("upload.receipt.failed")
            if let error = error as? EngineError, error.kind == .unimplemented || error.kind == .notFound {
                // Older gateways have no route. A deleted inode may also
                // produce 404; conservatively use final verification then.
                disabled = true; pending.removeAll()
            } else if let error = error as? EngineError {
                let delay: Double?
                switch error.data?["retryAfter"] {
                case .string(let value): delay = BlobTransport.retryAfterSeconds(value)
                case .int(let value): delay = Double(value)
                default: delay = nil
                }
                if let delay, delay.isFinite, delay > 0 {
                    // Optional work must not ignore server backpressure.
                    // Drop metadata to the final commit instead of sleeping
                    // with an RPC slot or retaining an unbounded cooldown.
                    pending.removeAll()
                    if delay > 86_400 { disabled = true }
                    else {
                        let until = ContinuousClock.now.advanced(by: .seconds(delay))
                        notBefore = max(notBefore ?? until, until)
                    }
                }
            }
        }
        profile.elapsed("upload.receipt.rpc", since: started)
        active.removeValue(forKey: id)
        finishDrains()
        pump()
    }
}
