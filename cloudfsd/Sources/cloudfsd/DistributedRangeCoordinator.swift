// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// Independent renewable authority for each SMB handle. A lost range is never
/// silently reacquired: the application must close/reopen before trusting it.
actor DistributedRangeCoordinator {
    private struct Key: Hashable { let id: InodeID; let handle: String }
    private struct Held { let fence: Int; var ranges: [FileLockRange]; var deadline: ContinuousClock.Instant; var lost = false }
    private let gateway: any GatewayClient
    private let filespace: FilespaceID
    private let ttlMs: Int
    private var held: [Key: Held] = [:]
    private var readPermits: [Key: (fence:Int,deadline:ContinuousClock.Instant)] = [:]
    private var busy: Set<Key> = []
    private var waiters: [Key: [CheckedContinuation<Void, Never>]] = [:]
    private var renewal: Task<Void, Never>?
    private var stopped = false
    init(gateway: any GatewayClient, filespace: FilespaceID, ttlMs: Int = 60_000) {
        self.gateway = gateway; self.filespace = filespace; self.ttlMs = ttlMs
    }
    deinit { renewal?.cancel() }
    private func enter(_ key: Key) async {
        if busy.insert(key).inserted { return }
        await withCheckedContinuation { waiters[key,default:[]].append($0) }
    }
    private func leave(_ key: Key) {
        if var q=waiters[key], !q.isEmpty { let next=q.removeFirst(); waiters[key]=q.isEmpty ? nil : q; next.resume() }
        else { busy.remove(key) }
    }
    private func error(_ reason: String = "lease-lost") -> EngineError {
        EngineError(.locked,"The file's byte-range lock is unavailable. Close and reopen the file before continuing.",data:["reason":.string(reason)])
    }
    private func validate(_ key: Key) throws -> Held? {
        guard !stopped else { throw EngineError(.notConnected,"The filespace disconnected") }
        guard var old=held[key] else { return nil }
        if old.lost || ContinuousClock.now >= old.deadline { old.lost=true; held[key]=old; throw error() }
        return old
    }
    private func deadline(_ start: ContinuousClock.Instant) -> ContinuousClock.Instant {
        start.advanced(by:.milliseconds(max(1,ttlMs-min(5_000,ttlMs/10))))
    }
    private func startRenewal() {
        guard renewal == nil else { return }
        let interval=max(10,ttlMs/3)
        renewal=Task.detached { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for:.milliseconds(interval)) } catch { return }
                await self?.renewAll()
            }
        }
    }
    func acquire(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {
        guard gateway.supportsRangeLocks else { return }
        let key=Key(id:id,handle:handle); await enter(key); defer { leave(key) }
        let old=try validate(key), started=ContinuousClock.now
        let result=try await gateway.acquireRanges(filespace:filespace,id:id,handle:handle,ranges:ranges,fence:old?.fence,ttlMs:ttlMs)
        guard result.granted, let fence=result.fence else {
            if result.reason == "fence-stale" { held[key]?.lost=true }
            throw error(result.reason ?? "held-by-other")
        }
        guard !stopped, ContinuousClock.now < deadline(started) else {
            try? await gateway.releaseRanges(filespace:filespace,id:id,handle:handle,fence:fence,ranges:nil)
            if old != nil { held[key]?.lost=true }
            throw error()
        }
        var combined=old?.ranges ?? []
        for range in ranges where !combined.contains(range) { combined.append(range) }
        held[key]=Held(fence:fence,ranges:combined,deadline:deadline(started)); startRenewal()
    }
    func release(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {
        guard gateway.supportsRangeLocks else { return }
        let key=Key(id:id,handle:handle); await enter(key); defer { leave(key) }
        guard var old=try validate(key) else { throw error("range-not-locked") }
        // A shared SMB lock can have several local reservations. Until the
        // final exact unlock, retain its remote union but still validate that
        // the lease is live; a local decrement cannot hide lost authority.
        guard !ranges.isEmpty else { return }
        try await gateway.releaseRanges(filespace:filespace,id:id,handle:handle,fence:old.fence,ranges:ranges)
        old.ranges.removeAll { h in ranges.contains { $0.offset==h.offset && $0.length==h.length } }
        held[key]=old.ranges.isEmpty ? nil : old
    }
    func releaseAll(_ id: InodeID, handle: String) async {
        let key=Key(id:id,handle:handle); await enter(key); defer { leave(key) }
        if let permit=readPermits.removeValue(forKey:key) {
            try? await gateway.releaseReadPermit(filespace:filespace,id:id,handle:handle,fence:permit.fence)
        }
        if let old=held.removeValue(forKey:key) {
            try? await gateway.releaseRanges(filespace:filespace,id:id,handle:handle,fence:old.fence,ranges:nil)
        }
    }
    func check(_ id: InodeID, handle: String, offset: UInt64, length: UInt64, write: Bool, publicationDeadline: ContinuousClock.Instant? = nil) async throws {
        guard gateway.supportsRangeLocks else { return }
        let key=Key(id:id,handle:handle); await enter(key); defer { leave(key) }
        try Task.checkCancellation()
        let current = try validate(key)
        if write, length > 0, current?.ranges.contains(where: { range in
            !range.exclusive && range.length > 0 && (offset <= range.offset
                ? range.offset - offset < length : offset - range.offset < range.length)
        }) == true { throw error("shared-lock") }
        // The caller holds the publication coordinator's gate across this check,
        // so final-close release cannot race a positive local admission.
        if let publicationDeadline, ContinuousClock.now < publicationDeadline { return }
        if !write, let permit=readPermits[key], ContinuousClock.now < permit.deadline { return }
        readPermits[key]=nil
        var attempt=0
        while true {
            try Task.checkCancellation()
            let old=try validate(key), started=ContinuousClock.now
            let result: RangeAccess
            do {
                result=try await gateway.checkRangeAccess(filespace:filespace,id:id,handle:handle,
                    range:FileLockRange(offset:offset,length:length,exclusive:write),fence:old?.fence)
            } catch {
                try Task.checkCancellation()
                _ = try validate(key) // An HTTP failure cannot extend held authority.
                guard !write, attempt<2, Self.retryableReadFailure(error) else { throw error }
                // This POST only checks read admission. An uncertain grant is
                // handle-owned and expires in one second; retrying cannot gain
                // an application lock or authorize a file publication.
                try await Task.sleep(for:.milliseconds(attempt == 0 ? 100 : 250))
                attempt += 1
                continue
            }
            do {
                try Task.checkCancellation()
                guard result.allowed else {
                    if result.reason == "fence-stale" { held[key]?.lost=true }
                    if result.reason == "forbidden" { throw EngineError(.permissionDenied,"Access to this file was revoked") }
                    throw error(result.reason ?? "held-by-other")
                }
                _ = try validate(key) // Expiration while the HTTP check was in flight.
                if !write, let ttl=result.permitTtlMs, let fence=result.permitFence, ttl>0, ttl<=1_000 {
                    // Each response is bounded by its own request start. Failed
                    // attempts never become cached permission or extend a grant.
                    let until=started.advanced(by:.milliseconds(max(1,ttl-min(100,ttl/10))))
                    guard ContinuousClock.now < until else { throw error("read-permit-expired") }
                    // Keep memory bounded for workloads with many idle handles. Dropped
                    // local permits only cause a future check; server authority expires.
                    if readPermits.count >= 1024 { readPermits = readPermits.filter { ContinuousClock.now < $0.value.deadline } }
                    if readPermits.count < 1024 { readPermits[key]=(fence,until) }
                }
                return
            } catch {
                if !write, let fence=result.permitFence {
                    try? await gateway.releaseReadPermit(filespace:filespace,id:id,handle:handle,fence:fence)
                }
                try Task.checkCancellation()
                _ = try validate(key) // Cleanup may itself outlive held authority.
                guard !write, attempt<2, let admission=error as? EngineError,
                      admission.kind == .locked,
                      admission.data?["reason"] == .string("read-permit-expired") else { throw error }
                // The grant was already unusable on arrival; it never admitted
                // data or entered our cache. A fresh read-only check can recover
                // from that latency spike without reacquiring an application
                // lock. Share the same three-attempt budget as transport errors.
                try await Task.sleep(for:.milliseconds(attempt == 0 ? 100 : 250))
                attempt += 1
            }
        }
    }

    private static func retryableReadFailure(_ error: Error) -> Bool {
        let transientCodes=Set([URLError.Code.timedOut, .cannotFindHost, .cannotConnectToHost,
            .networkConnectionLost, .dnsLookupFailed, .notConnectedToInternet].map(\.rawValue))
        if let error=error as? URLError { return transientCodes.contains(error.code.rawValue) }
        guard let error=error as? EngineError else { return false }
        if error.kind == .networkError {
            // Retry only classified transport failures. Certificate, credential,
            // URL construction, cancellation and unclassified errors fail closed.
            guard error.data?["domain"] == .string(NSURLErrorDomain),
                  case .int(let code)=error.data?["code"] else { return false }
            return transientCodes.contains(code)
        }
        guard error.kind == .gatewayError, case .int(let status)=error.data?["status"] else { return false }
        return [408,429,500,502,503,504].contains(status)
    }
    func renewAll() async {
        for key in Array(held.keys) {
            await enter(key)
            defer { leave(key) }
            guard !stopped, var old=held[key], !old.lost else { continue }
            let start=ContinuousClock.now
            do {
                _ = try validate(key)
                let result=try await gateway.renewRanges(filespace:filespace,id:key.id,handle:key.handle,fence:old.fence,ttlMs:ttlMs)
                guard result.granted, result.fence==old.fence, ContinuousClock.now<deadline(start) else { throw error() }
                old.deadline=deadline(start)
            } catch { old.lost=true }
            held[key]=old
        }
    }
    func shutdown() async {
        stopped=true; renewal?.cancel(); renewal=nil
        for key in Set(held.keys).union(readPermits.keys) { await releaseAll(key.id,handle:key.handle) }
    }
}
