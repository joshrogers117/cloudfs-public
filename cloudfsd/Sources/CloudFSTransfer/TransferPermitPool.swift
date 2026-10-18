// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// Caller-requested bytes always take precedence over optional read-ahead.
public enum TransferPriority: Sendable { case demand, speculative }

/// A shared block budget across every file. Queue entries retain no payloads.
/// Congestion lowers admission, never interrupts a transfer already holding a
/// permit; every permit is released even on cancellation or integrity failure.
actor TransferPermitPool {
    /// The ticket also closes the promotion-before-enqueue race: its priority is
    /// visible whether demand joins before, during or after permit acquisition.
    final class Ticket: @unchecked Sendable {
        let id = UUID()
        private let lock = NSLock()
        private var value: TransferPriority
        private var background: Bool
        init(priority: TransferPriority, background: Bool = false) {
            value = priority
            self.background = background || priority == .speculative
        }
        var priority: TransferPriority { lock.withLock { value } }
        var pausesWithBackground: Bool { lock.withLock { background } }
        func promote() { lock.withLock { value = .demand; background = false } }
    }
    struct Metrics: Sendable {
        let maximum: Int
        let limit: Int
        let active: Int
        let activeSpeculative: Int
        let queuedDemand: Int
        let queuedSpeculative: Int
        let peakActive: Int
        let peakQueuedSpeculative: Int
        let congestionReductions: Int
        let recoveries: Int
        let droppedSpeculation: Int
        /// Bare congestion signals that did not, on their own, reduce the limit.
        let isolatedSignals: Int
        let timeRecoveries: Int
    }
    struct SpeculationDeferred: Error {}
    private struct Waiter {
        let ticket: Ticket
        let continuation: CheckedContinuation<Void, Error>
    }
    private let maximum: Int
    private let maxSpeculativeWaiters: Int
    private let now: @Sendable () -> ContinuousClock.Instant
    private var limit: Int
    private var active: [UUID: Ticket] = [:]
    private var waiters: [Waiter] = []
    private var lastCongestion: ContinuousClock.Instant?   // last reduction (coalescing + recovery gate)
    private var lastSignal: ContinuousClock.Instant?       // last signal of any kind
    private var nextTimeRecovery: ContinuousClock.Instant?
    private let profileName: String?
    private var isolatedSignals = 0
    private var timeRecoveries = 0
    private var cleanCompletions = 0
    private var peakActive = 0
    private var peakQueuedSpeculative = 0
    private var congestionReductions = 0
    private var recoveries = 0
    private var droppedSpeculation = 0

    init(limit: Int, maxSpeculativeWaiters: Int? = nil, profileName: String? = nil,
         now: @escaping @Sendable () -> ContinuousClock.Instant = { .now }) {
        self.profileName = profileName
        maximum = max(1, limit)
        self.limit = max(1, limit)
        self.maxSpeculativeWaiters = max(0, maxSpeculativeWaiters ?? max(1, limit) * 2)
        self.now = now
    }

    func metrics() -> Metrics {
        Metrics(maximum: maximum, limit: limit, active: active.count,
                activeSpeculative: active.values.filter { $0.priority == .speculative }.count,
                queuedDemand: waiters.filter { $0.ticket.priority == .demand }.count,
                queuedSpeculative: waiters.filter { $0.ticket.priority == .speculative }.count,
                peakActive: peakActive, peakQueuedSpeculative: peakQueuedSpeculative,
                congestionReductions: congestionReductions, recoveries: recoveries,
                droppedSpeculation: droppedSpeculation,
                isolatedSignals: isolatedSignals, timeRecoveries: timeRecoveries)
    }

    /// Lowest admission a congestion response may impose.
    private var floor: Int { min(maximum, max(4, maximum / 4)) }
    /// A bare timeout/connection-loss/408 is only a hint: one isolated signal is
    /// counted but never reduces. Reduction needs evidence of sustained pressure:
    /// a server-declared overload (429/503 with Retry-After) or a second signal
    /// within two seconds. Reductions stay coalesced to one per half-second.
    ///
    /// Recovery: one permit per `limit` clean completions once half a second has
    /// passed since the last reduction, and independently one permit per second
    /// after max(3 s, Retry-After) without any signal, so a blip costs seconds, not
    /// hundreds of completions.
    func feedback(_ feedback: BlobTransferFeedback) {
        let instant = now()
        switch feedback {
        case .congestion, .overloaded:
            var hold = 3.0
            if case .overloaded(let retryAfter) = feedback, retryAfter.isFinite { hold = max(hold, min(retryAfter, 86_400)) }
            cleanCompletions = 0
            let previous = lastSignal
            lastSignal = instant
            let candidate = instant.advanced(by: .seconds(hold))
            nextTimeRecovery = max(nextTimeRecovery ?? candidate, candidate)
            var overloaded = false
            if case .overloaded = feedback { overloaded = true }
            let sustained = overloaded
                || previous.map({ $0.duration(to: instant) <= .seconds(2) }) ?? false
            guard sustained else { isolatedSignals += 1; publish(); return }
            guard lastCongestion.map({ $0.duration(to: instant) >= .milliseconds(500) }) ?? true else { return }
            lastCongestion = instant
            let reduced = max(floor, (limit * 3) / 4)
            if reduced < limit { limit = reduced; congestionReductions += 1 }
            publish()
        case .success:
            recoverByTime(instant)
            guard limit < maximum,
                  lastCongestion.map({ $0.duration(to: instant) >= .milliseconds(500) }) ?? true else { return }
            cleanCompletions += 1
            if cleanCompletions >= max(1, limit) {
                cleanCompletions = 0
                limit += 1
                recoveries += 1
                publish()
                drain()
            }
        }
    }

    private func recoverByTime(_ instant: ContinuousClock.Instant) {
        guard limit < maximum, let due = nextTimeRecovery, instant >= due else { return }
        let steps = 1 + Int(due.duration(to: instant) / .seconds(1))
        let restored = min(maximum - limit, steps)
        limit += restored; timeRecoveries += restored; recoveries += restored
        nextTimeRecovery = limit < maximum ? due.advanced(by: .seconds(steps)) : nil
        cleanCompletions = 0
        publish()
        drain()
    }

    private func publish() {
        guard let profileName, WriteProfiler.shared.enabled else { return }
        let profile = WriteProfiler.shared
        profile.setCount("\(profileName).pool.limit", limit)
        profile.setCount("\(profileName).pool.congestionReductions", congestionReductions)
        profile.setCount("\(profileName).pool.recoveries", recoveries)
        profile.setCount("\(profileName).pool.peakActive", peakActive)
        profile.setCount("\(profileName).pool.isolatedSignals", isolatedSignals)
    }

    func withPermit<T: Sendable>(priority: TransferPriority = .demand, ticket supplied: Ticket? = nil,
                                _ operation: @Sendable () async throws -> T) async throws -> T {
        let ticket = supplied ?? Ticket(priority: priority)
        try await acquire(ticket)
        defer { release(ticket) }
        try Task.checkCancellation()
        return try await operation()
    }

    func promote(_ ticket: Ticket) {
        ticket.promote()
        drain()
    }

    private func acquire(_ ticket: Ticket) async throws {
        try Task.checkCancellation()
        if waiters.isEmpty && canAdmit(ticket) { admit(ticket); return }
        if ticket.priority == .speculative,
           waiters.filter({ $0.ticket.priority == .speculative }).count >= maxSpeculativeWaiters {
            droppedSpeculation += 1
            throw SpeculationDeferred()
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                else {
                    waiters.append(Waiter(ticket: ticket, continuation: continuation))
                    peakQueuedSpeculative = max(peakQueuedSpeculative,
                        waiters.filter { $0.ticket.priority == .speculative }.count)
                    drain()
                }
            }
        } onCancel: { Task { await self.cancel(ticket.id) } }
    }
    private func canAdmit(_ ticket: Ticket) -> Bool {
        guard active.count < limit else { return false }
        if ticket.priority == .demand { return true }
        // Reserve room for foreground requests even before they arrive. On a
        // single-permit connection speculation remains useful while idle.
        let speculativeLimit = max(1, limit - max(1, limit / 4))
        return active.values.filter { $0.priority == .speculative }.count < speculativeLimit
    }
    private func admit(_ ticket: Ticket) {
        active[ticket.id] = ticket
        if active.count > peakActive { peakActive = active.count; publish() }
    }
    private func drain() {
        while active.count < limit {
            // FIFO within each class; new speculation never overtakes demand.
            let index = waiters.firstIndex { $0.ticket.priority == .demand }
                ?? waiters.firstIndex { canAdmit($0.ticket) }
            guard let index, canAdmit(waiters[index].ticket) else { return }
            let waiter = waiters.remove(at: index)
            admit(waiter.ticket)
            waiter.continuation.resume()
        }
    }
    private func cancel(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.ticket.id == id }) else { return }
        waiters.remove(at: index).continuation.resume(throwing: CancellationError())
        drain()
    }
    private func release(_ ticket: Ticket) {
        active[ticket.id] = nil
        recoverByTime(now())
        drain()
    }
}
