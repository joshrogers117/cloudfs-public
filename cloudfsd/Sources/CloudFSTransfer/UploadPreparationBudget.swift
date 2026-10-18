// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// Global block-image reservations shared by journal-backed and immediate early
/// uploads. Queued callers retain metadata only; the synchronous path lets the
/// transfer actor reserve before capturing bytes without yielding a staged image.
final class UploadPreparationBudget: @unchecked Sendable {
    final class Reservation: @unchecked Sendable {
        private let owner: UploadPreparationBudget
        private let id: UUID
        fileprivate init(owner: UploadPreparationBudget, id: UUID) { self.owner = owner; self.id = id }
        func release() { owner.release(id) }
        deinit { owner.release(id) }
    }
    struct Metrics: Sendable { let limit: Int; let active: Int; let queued: Int; let peak: Int }
    private struct Waiter { let id: UUID; let continuation: CheckedContinuation<Reservation, Error> }
    private let lock = NSLock()
    private let limit: Int
    private var active: Set<UUID> = []
    private var queue: [Waiter] = []
    private var peak = 0

    init(limit: Int) { self.limit = max(1, limit) }
    func metrics() -> Metrics { lock.withLock { Metrics(limit: limit, active: active.count, queued: queue.count, peak: peak) } }
    func tryAcquire() -> Reservation? {
        lock.withLock {
            guard queue.isEmpty, active.count < limit else { return nil }
            let id = UUID(); active.insert(id); peak = max(peak, active.count)
            return Reservation(owner: self, id: id)
        }
    }
    func acquire() async throws -> Reservation {
        try Task.checkCancellation()
        let id = UUID()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                let immediate: Result<Reservation, Error>? = lock.withLock {
                    if Task.isCancelled { return .failure(CancellationError()) }
                    if queue.isEmpty, active.count < limit {
                        active.insert(id); peak = max(peak, active.count)
                        return .success(Reservation(owner: self, id: id))
                    }
                    queue.append(Waiter(id: id, continuation: continuation)); return nil
                }
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: { self.cancel(id) }
    }
    private func cancel(_ id: UUID) {
        let waiter: Waiter? = lock.withLock {
            guard let index = queue.firstIndex(where: { $0.id == id }) else { return nil }
            return queue.remove(at: index)
        }
        waiter?.continuation.resume(throwing: CancellationError())
    }
    private func release(_ id: UUID) {
        let next: Waiter? = lock.withLock {
            guard active.remove(id) != nil, !queue.isEmpty else { return nil }
            let waiter = queue.removeFirst(); active.insert(waiter.id)
            return waiter
        }
        if let next { next.continuation.resume(returning: Reservation(owner: self, id: next.id)) }
    }
}
