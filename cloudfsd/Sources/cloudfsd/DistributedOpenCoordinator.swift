// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// Device-bound open references keep unlinked file data alive. This is separate
/// from edit/range locks: a reader must retain the inode too. Loss is sticky, so
/// a reconnect cannot silently reopen a different file at the original name.
actor DistributedOpenCoordinator {
    private struct Held {
        let id: InodeID
        let access: OpenFileAccess
        let sharing: OpenFileSharing
        var deadline: ContinuousClock.Instant
        var lost: EngineError?
    }
    private let gateway: any GatewayClient
    private let filespace: FilespaceID
    private let ttlMs: Int
    private var held: [String: Held] = [:]
    private var busy: Set<String> = []
    private var waiters: [String: [CheckedContinuation<Void,Never>]] = [:]
    private var renewal: Task<Void,Never>?
    private var stopped = false

    init(gateway: any GatewayClient, filespace: FilespaceID, ttlMs: Int = 90_000) {
        self.gateway = gateway; self.filespace = filespace; self.ttlMs = ttlMs
    }
    deinit { renewal?.cancel() }

    private func enter(_ handle: String) async {
        if busy.insert(handle).inserted { return }
        await withCheckedContinuation { waiters[handle,default:[]].append($0) }
    }
    private func leave(_ handle: String) {
        if var queued = waiters[handle], !queued.isEmpty {
            let next = queued.removeFirst(); waiters[handle] = queued.isEmpty ? nil : queued; next.resume()
        } else { busy.remove(handle) }
    }
    private func error(_ reason: String) -> EngineError {
        EngineError(reason == "sharing_violation" ? .locked : .notFound,
            reason == "sharing_violation" ? "Another open file handle does not permit this operation."
                : "This file handle is no longer valid. Close and reopen the file.",
            data:["reason":.string(reason)])
    }
    private func deadline(from start: ContinuousClock.Instant) -> ContinuousClock.Instant {
        start.advanced(by:.milliseconds(max(1,ttlMs - min(5_000,ttlMs / 10))))
    }
    private func startRenewal() {
        guard renewal == nil else { return }
        let interval = max(10,ttlMs / 3)
        renewal = Task.detached(priority:.utility) { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for:.milliseconds(interval)) } catch { return }
                await self?.renewAll()
            }
        }
    }

    func open(_ id: InodeID, handle: String, access: OpenFileAccess, sharing: OpenFileSharing) async throws {
        guard gateway.supportsOpenHandles else { return }
        await enter(handle); defer { leave(handle) }
        guard !stopped else { throw EngineError(.notConnected) }
        if let existing = held[handle] {
            guard existing.id == id, existing.access == access, existing.sharing == sharing else { throw EngineError(.invalidParams,"Open handle cannot change identity or access") }
            try check(id,handle:handle)
            return
        }
        let start = ContinuousClock.now
        let result: OpenHandleLease
        do {
            result = try await gateway.acquireOpenHandle(filespace:filespace,id:id,handle:handle,access:access,sharing:sharing,ttlMs:ttlMs)
        } catch {
            // An interrupted response may still have created a remote record.
            // Exact-owner close is idempotent; expiry also bounds failed cleanup.
            try? await gateway.closeOpenHandle(filespace:filespace,handle:handle)
            throw error
        }
        guard result.granted else { throw error(result.reason ?? "open_denied") }
        guard !stopped, ContinuousClock.now < deadline(from:start) else {
            try? await gateway.closeOpenHandle(filespace:filespace,handle:handle)
            throw error("open_expired")
        }
        held[handle] = Held(id:id,access:access,sharing:sharing,deadline:deadline(from:start))
        startRenewal()
    }

    /// Acquire a stream handle and return its current size. Gateways that return
    /// stream metadata do this in the same open transaction; older gateways are
    /// detected by the absent response field and use the existing list endpoint.
    /// A missing legacy stream leaves the open retained so the caller's ordinary
    /// CREATE cleanup closes it. A new gateway can reject a required missing
    /// stream without ever registering an open handle.
    func openStream(_ id: InodeID, handle: String, access: OpenFileAccess,
                    sharing: OpenFileSharing, name: String, required: Bool) async throws -> Int? {
        guard gateway.supportsOpenHandles else {
            return try await gateway.listStreams(filespace: filespace, id: id)
                .first { $0.name == name }?.size
        }
        await enter(handle); defer { leave(handle) }
        guard !stopped else { throw EngineError(.notConnected) }
        if let existing = held[handle] {
            guard existing.id == id, existing.access == access, existing.sharing == sharing else {
                throw EngineError(.invalidParams, "Open handle cannot change identity or access")
            }
            try check(id, handle: handle)
            return try await gateway.listStreams(filespace: filespace, id: id)
                .first { $0.name == name }?.size
        }

        let start = ContinuousClock.now
        let result: OpenHandleLease
        do {
            result = try await gateway.acquireOpenHandle(filespace: filespace, id: id, handle: handle,
                access: access, sharing: sharing, ttlMs: ttlMs,
                stream: OpenHandleStreamRequest(name: name, required: required))
        } catch {
            try? await gateway.closeOpenHandle(filespace: filespace, handle: handle)
            throw error
        }
        guard result.granted else { throw error(result.reason ?? "open_denied") }
        guard !stopped, ContinuousClock.now < deadline(from: start) else {
            try? await gateway.closeOpenHandle(filespace: filespace, handle: handle)
            throw error("open_expired")
        }

        held[handle] = Held(id: id, access: access, sharing: sharing, deadline: deadline(from: start))
        startRenewal()
        if let stream = result.stream {
            guard stream.size >= 0, stream.exists || stream.size == 0 else {
                throw EngineError(.gatewayError, "Gateway returned invalid named-stream metadata")
            }
            guard !required || stream.exists else {
                throw EngineError(.gatewayError, "Gateway granted an open for a required missing stream")
            }
            return stream.exists ? stream.size : nil
        }
        // An older endpoint ignores the optional input and omits response stream
        // data. Keep the acquired lease in `held`; caller cleanup owns its close.
        return try await gateway.listStreams(filespace: filespace, id: id)
            .first { $0.name == name }?.size
    }

    /// Called before and after bounded SMB I/O, including cache hits.
    func check(_ id: InodeID, handle: String) throws {
        guard gateway.supportsOpenHandles else { return }
        guard !stopped, var value = held[handle], value.id == id else { throw error("open_closed") }
        if let lost = value.lost { throw lost }
        guard ContinuousClock.now < value.deadline else {
            let lost = error("open_expired")
            value.lost = lost
            held[handle] = value
            throw lost
        }
    }

    @discardableResult
    func close(_ handle: String) async -> Bool {
        guard gateway.supportsOpenHandles else { return true }
        await enter(handle); defer { leave(handle) }
        guard held[handle] != nil else { return true }
        do { try await gateway.closeOpenHandle(filespace:filespace,handle:handle) }
        catch { return false }
        held[handle] = nil
        if held.isEmpty { renewal?.cancel(); renewal = nil }
        return true
    }
    func renewAll() async {
        let handles = held.keys.sorted()
        guard !stopped else { return }
        for start in stride(from: 0, to: handles.count, by: 128) {
            guard !stopped else { return }
            await renewBatch(Array(handles[start..<min(start + 128, handles.count)]))
        }
    }
    func renew(_ handle: String) async {
        await renewBatch([handle])
    }
    private func renewBatch(_ handles: [String]) async {
        // Canonical lock ordering lets simultaneous explicit and periodic batch
        // renewals serialize without deadlocking. Keep every handle gate held
        // until its corresponding result has been applied.
        let locked = handles.sorted()
        for handle in locked { await enter(handle) }
        defer { for handle in locked.reversed() { leave(handle) } }
        guard !stopped else { return }
        let start = ContinuousClock.now
        var eligible: [String] = []
        for handle in locked {
            guard var value = held[handle], value.lost == nil else { continue }
            guard start < value.deadline else {
                value.lost = error("open_expired"); held[handle] = value
                continue
            }
            eligible.append(handle)
        }
        guard !eligible.isEmpty else { return }
        do {
            let results = try await gateway.renewOpenHandles(filespace:filespace,handles:eligible,ttlMs:ttlMs)
            guard !stopped else { return }
            let byHandle = Dictionary(results.map { ($0.handleId, $0) }, uniquingKeysWith: { first, _ in first })
            for handle in eligible {
                guard var value = held[handle], value.lost == nil else { continue }
                guard let result = byHandle[handle], result.granted else {
                    value.lost = error(byHandle[handle]?.reason ?? "open_lost")
                    held[handle] = value
                    continue
                }
                value.deadline = deadline(from:start)
                held[handle] = value
            }
        } catch let failure as EngineError where failure.kind == .networkError || failure.kind == .gatewayError {
            // A transient outage may retry while the original monotonic expiry
            // is still valid. No error extends our local authority.
        } catch {
            guard !stopped else { return }
            for handle in eligible {
                guard var value = held[handle], value.lost == nil else { continue }
                value.lost = self.error("open_lost")
                held[handle] = value
            }
        }
    }
    func shutdown(isDurable: @Sendable (InodeID) async -> Bool) async {
        stopped = true; renewal?.cancel(); renewal = nil
        for handle in held.keys.sorted() {
            await enter(handle); defer { leave(handle) }
            guard let value = held.removeValue(forKey: handle) else { continue }
            // A staged write to a deleted inode still depends on backend
            // retention. Leave that reference to expire under the bounded
            // server TTL instead of explicitly releasing it during shutdown.
            if await isDurable(value.id) {
                try? await gateway.closeOpenHandle(filespace: filespace, handle: handle)
            }
        }
    }
    func shutdown() async {
        await shutdown(isDurable: { _ in true })
    }
}
