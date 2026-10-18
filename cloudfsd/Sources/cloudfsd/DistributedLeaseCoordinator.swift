// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// One renewable, exclusive whole-file lease per inode, shared by this daemon's
/// local handles. All network transitions serialize per inode. Losing a lease is
/// sticky: pending journal bytes may only resume through explicit recovery/CAS.
actor DistributedLeaseCoordinator {
    private struct Held {
        var fence: Int
        var deadline: ContinuousClock.Instant
        var handles: Set<String> = []
        var lost: EngineError?
    }
    private let gateway: any GatewayClient
    private let filespace: FilespaceID
    private let ttlMs: Int
    private var leases: [InodeID: Held] = [:]
    private var busy: Set<InodeID> = []
    private var waiters: [InodeID: [CheckedContinuation<Void, Never>]] = [:]
    private var renewal: Task<Void, Never>?
    private var stopped = false

    init(gateway: any GatewayClient, filespace: FilespaceID, ttlMs: Int = 60_000) {
        self.gateway = gateway; self.filespace = filespace; self.ttlMs = ttlMs
    }
    deinit { renewal?.cancel() }

    private func enter(_ id: InodeID) async {
        if busy.insert(id).inserted { return }
        await withCheckedContinuation { waiters[id, default: []].append($0) }
    }
    private func leave(_ id: InodeID) {
        if var queued = waiters[id], !queued.isEmpty {
            let next = queued.removeFirst(); waiters[id] = queued.isEmpty ? nil : queued; next.resume()
        } else { busy.remove(id) }
    }
    private func denied(_ result: FileLease) -> EngineError {
        var data: [String: CodableValue] = ["reason": .string(result.reason ?? "lease-lost")]
        if let holder = result.heldBy { data["heldBy"] = .string(holder) }
        return EngineError(.locked, result.heldBy == nil
            ? "The file's editing lease expired. Your pending changes are preserved. Retry from Recovery."
            : "This file is being edited on another device. Try again when that editor closes it.", data: data)
    }
    private func startRenewal() {
        guard renewal == nil else { return }
        let interval = UInt64(max(10, ttlMs / 3)) * 1_000_000
        // Renewal belongs to the session, not the request that first opened a
        // file. Keep request-local context out of this long-lived service task.
        renewal = Task.detached(priority: .medium) { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: interval) } catch { return }
                await self?.renewAll()
            }
        }
    }

    /// `handle` is globally unique within the daemon, including SMB connections.
    /// Nil is used by the upload barrier (including crash-replayed journals).
    func ensure(_ id: InodeID, handle: String? = nil) async throws -> Int? {
        try await ensureCore(id, handle: handle, includeItem: false).fence
    }

    /// A fresh publication grant can carry the item version read in the same
    /// backend transaction. Existing local leases intentionally return nil so
    /// callers refresh metadata under that already-held lease instead.
    func ensureWithItem(_ id: InodeID, handle: String) async throws -> (fence: Int?, item: ItemMetadata?) {
        try await ensureCore(id, handle: handle, includeItem: true)
    }

    private func ensureCore(_ id: InodeID, handle: String?, includeItem: Bool) async throws
        -> (fence: Int?, item: ItemMetadata?) {
        guard gateway.supportsFileLeases else { return (nil, nil) }
        await enter(id); defer { leave(id) }
        guard !stopped else { throw EngineError(.notConnected, "The filespace disconnected; pending changes remain in the local journal") }
        if var held = leases[id] {
            if let error = held.lost { throw error }
            guard ContinuousClock.now < held.deadline else {
                let error = denied(FileLease(granted: false, path: id.rawValue, reason: "lease-expired"))
                held.lost = error; leases[id] = held; throw error
            }
            if let handle { held.handles.insert(handle); leases[id] = held }
            return (held.fence, nil)
        }
        let started = ContinuousClock.now
        let result = try await gateway.acquireFileLease(filespace: filespace, id: id,
            ttlMs: ttlMs, purpose: .publication, includeItem: includeItem)
        // Shutdown can occur during initial acquisition, before this inode is
        // present in leases. Never publish late authority or restart renewal.
        guard !stopped else {
            if result.granted, let fence = result.fence {
                try? await gateway.releaseFileLease(filespace: filespace, id: id, fence: fence)
            }
            throw EngineError(.notConnected, "The filespace disconnected; pending changes remain in the local journal")
        }
        guard result.granted, result.path == id.rawValue, let fence = result.fence,
              fence > 0, result.purpose == .publication else {
            if result.granted, result.path == id.rawValue, let fence = result.fence, fence > 0 {
                try? await gateway.releaseFileLease(filespace: filespace, id: id, fence: fence)
            }
            throw denied(result)
        }
        // Use elapsed monotonic time, not server/local wall-clock agreement. A
        // response delayed beyond its usable TTL must never authorize a write.
        let deadline = started.advanced(by: .milliseconds(max(1, ttlMs - min(5_000, ttlMs / 10))))
        guard ContinuousClock.now < deadline else { throw denied(result) }
        leases[id] = Held(fence: fence, deadline: deadline, handles: handle.map { [$0] } ?? [])
        startRenewal()
        let item = includeItem ? result.item.flatMap { candidate -> ItemMetadata? in
            guard candidate.id == id, !candidate.isDir, candidate.size >= 0,
                  !candidate.contentVersion.isEmpty, Int(candidate.metadataVersion) != nil else { return nil }
            return candidate
        } : nil
        return (fence, item)
    }

    /// Crash replay has a new client identity while the dead process's lease may
    /// remain valid until its TTL. Only upload barriers wait for that INITIAL
    /// contested acquisition. Opens still use ensure() and return locked at once.
    /// A locally lost/expired lease is never reacquired here; its sticky Held
    /// record can be cleared only by explicit recovery after editor handles close.
    func ensureForUpload(_ id: InodeID, maxWaitMs: Int? = nil) async throws -> Int? {
        let budget = max(0, maxWaitMs ?? (ttlMs + 5_000))
        let deadline = ContinuousClock.now.advanced(by: .milliseconds(budget))
        let interval = max(10, min(1_000, budget / 20))
        while true {
            try Task.checkCancellation()
            do { return try await ensure(id) }
            catch let error as EngineError {
                // URLSession wraps an in-flight cancellation as networkError.
                try Task.checkCancellation()
                guard error.kind == .locked, leases[id] == nil, !stopped,
                      error.data?["reason"] == .string("held-by-other"),
                      ContinuousClock.now < deadline else { throw error }
                // No lease gate is held during this wait. Other writable OPENs
                // and shutdown can proceed; no lease is stolen or shortened.
                let wake = min(deadline, ContinuousClock.now.advanced(by: .milliseconds(interval)))
                try await ContinuousClock().sleep(until: wake)
            }
        }
    }

    @discardableResult
    func close(_ id: InodeID, handle: String) async -> Bool {
        await enter(id); defer { leave(id) }
        leases[id]?.handles.remove(handle)
        return leases[id]?.handles.isEmpty ?? false
    }

    /// Caller has first awaited the file's upload barrier. Checking handle refs
    /// under the same gate prevents a racing new OPEN from losing its lease.
    @discardableResult
    func releaseIfUnused(_ id: InodeID,
                         isDurable: @Sendable () async -> Bool = { true }) async -> Bool {
        await enter(id); defer { leave(id) }
        guard let held = leases[id], held.handles.isEmpty else { return true }
        // Recheck under the lease gate: a previous flush can finish just before
        // another write stages bytes and its last handle closes.
        guard await isDurable() else { return false }
        // Removal precedes no other local operation (gate is held across DELETE).
        // Fenced DELETE cannot release a later grant, even after a network delay.
        try? await gateway.releaseFileLease(filespace: filespace, id: id, fence: held.fence)
        leases[id] = nil
        return true
    }

    /// Keep final-close release serialized with an I/O admission check. A live
    /// publication lease excludes remote ranges; local SMB ranges remain checked.
    func withPublicationProtection<T: Sendable>(_ id: InodeID,
        operation: @Sendable (ContinuousClock.Instant?) async throws -> T) async rethrows -> T {
        await enter(id); defer { leave(id) }
        let held = leases[id]
        let deadline = !stopped && held?.lost == nil ? held?.deadline : nil
        return try await operation(deadline)
    }

    func renewAll() async {
        for id in Array(leases.keys) { await renew(id) }
    }
    func renew(_ id: InodeID) async {
        await enter(id); defer { leave(id) }
        guard !stopped else { return }
        guard var held = leases[id], held.lost == nil else { return }
        let started = ContinuousClock.now
        guard started < held.deadline else {
            held.lost = denied(FileLease(granted: false, path: id.rawValue, reason: "lease-expired"))
            leases[id] = held; return
        }
        do {
            let result = try await gateway.renewFileLease(filespace: filespace, id: id, fence: held.fence, ttlMs: ttlMs)
            guard result.granted, result.fence == held.fence else { throw denied(result) }
            held.deadline = started.advanced(by: .milliseconds(max(1, ttlMs - min(5_000, ttlMs / 10))))
        } catch {
            held.lost = EngineError(.locked, "The file's editing lease could not be renewed. Your pending changes are preserved. Retry from Recovery.",
                                    data: ["reason": .string("lease-lost")])
        }
        leases[id] = held
    }

    /// Explicit recovery may retry old bytes with their original CAS version.
    /// It cannot silently overwrite newer remote content or disrupt live handles.
    func resetForRecovery(_ id: InodeID) async throws {
        await enter(id); defer { leave(id) }
        guard let held = leases[id] else { return }
        guard held.handles.isEmpty else { throw EngineError(.locked, "Close the file in your editing app before retrying recovery") }
        try? await gateway.releaseFileLease(filespace: filespace, id: id, fence: held.fence)
        leases[id] = nil
    }

    func withClosedHandles<T: Sendable>(_ id: InodeID,
        operation: @Sendable () async throws -> T) async throws -> T {
        await enter(id); defer { leave(id) }
        if let held = leases[id], !held.handles.isEmpty {
            throw EngineError(.locked, "Close the file in your editing app before completing recovery")
        }
        let result = try await operation()
        if let held = leases.removeValue(forKey: id) {
            try? await gateway.releaseFileLease(filespace: filespace, id: id, fence: held.fence)
        }
        return result
    }

    func shutdown() async {
        stopped = true
        renewal?.cancel(); renewal = nil
        for id in Array(leases.keys) {
            await enter(id)
            if let held = leases.removeValue(forKey: id) {
                try? await gateway.releaseFileLease(filespace: filespace, id: id, fence: held.fence)
            }
            leave(id)
        }
    }
}
