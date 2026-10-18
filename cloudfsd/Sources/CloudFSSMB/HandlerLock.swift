// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — SMB2 LOCK ([MS-SMB2] §2.2.26/§2.2.27): advisory byte-range locks.
//
// Ranges belong to an SMB handle locally and in the metadata authority. Shared
// locks coexist across clients; exclusive overlaps deny reads and writes. The
// separate whole-inode writer lease still serializes manifest publication.

import Foundation
import CloudFSCore

/// A held byte range on a node.
struct LockRange: Equatable {
    var offset: UInt64
    var length: UInt64
    var exclusive: Bool
    var owner: SMBFileId
    func overlaps(_ o: UInt64, _ l: UInt64) -> Bool {
        // Zero-length locks (offset marker) never overlap a data range.
        guard length > 0, l > 0 else { return false }
        return offset < o.addingReportingOverflow(l).partialValue && o < offset.addingReportingOverflow(length).partialValue
    }
}

/// Thread-safe advisory lock table keyed by node id.
final class LockTable: @unchecked Sendable {
    private let lock = NSLock()
    private var ranges: [InodeID: [LockRange]] = [:]

    /// Try to acquire `exclusive`/shared over `[offset,length)` for `owner`.
    /// Returns false on conflict, including an exclusive request overlapping the
    /// same handle's existing lock (MS-FSA 2.1.4.10, LockIntent = TRUE).
    func acquire(_ node: InodeID, offset: UInt64, length: UInt64, exclusive: Bool, owner: SMBFileId) -> Bool {
        acquireAll(node,ranges:[LockRange(offset:offset,length:length,exclusive:exclusive,owner:owner)])
    }

    /// Atomic multi-range acquisition: a later conflict cannot leak the earlier
    /// elements of a failed SMB LOCK request.
    func acquireAll(_ node: InodeID, ranges requested: [LockRange]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let held = ranges[node] ?? []
        var staged = held
        for request in requested {
            if (held + requested).contains(where: { $0.owner == request.owner && $0.offset == request.offset && $0.length == request.length && $0.exclusive != request.exclusive }) { return false }
            for old in staged where old.overlaps(request.offset, request.length) {
                // The same-open exemption applies to I/O through an exclusive
                // lock, not a second exclusive LOCK. Apple's BRL client can
                // share one SMB FID between local processes. Treating an exact
                // duplicate as an HTTP-style retry let both processes acquire
                // it and made one unlock consume the other's live reservation.
                // MS-FSA 2.1.4.10 also rejects overlap within this LOCK batch.
                if request.exclusive || (old.exclusive && old.owner != request.owner) { return false }
            }
            // Every successful shared LOCK is a distinct reservation, even for
            // identical ranges on one FID. Its UNLOCK consumes one reservation.
            guard staged.count < 4096, staged.filter({ $0.owner == request.owner }).count < 256 else { return false }
            staged.append(request)
        }
        ranges[node] = staged
        return true
    }
    func heldRanges(_ node: InodeID, owner: SMBFileId) -> [LockRange] {
        lock.lock(); defer { lock.unlock() }; return (ranges[node] ?? []).filter { $0.owner == owner }
    }
    /// Validate an unlock multiset and return only ranges whose final local
    /// reservation is consumed. The remote API stores their idempotent union.
    func remoteReleases(_ node: InodeID, requested: [LockRange]) -> [LockRange]? {
        lock.lock(); defer { lock.unlock() }
        var remaining = ranges[node] ?? []
        for request in requested {
            guard let index = remaining.firstIndex(where: { $0.owner == request.owner && $0.offset == request.offset && $0.length == request.length }) else { return nil }
            remaining.remove(at: index)
        }
        var released: [LockRange] = []
        for request in requested where !remaining.contains(where: { $0.owner == request.owner && $0.offset == request.offset && $0.length == request.length }) {
            if !released.contains(request) { released.append(request) }
        }
        return released
    }
    func allowsAccess(_ node: InodeID, offset: UInt64, length: UInt64, write: Bool, owner: SMBFileId) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !(ranges[node] ?? []).contains { $0.overlaps(offset,length) && ($0.exclusive ? $0.owner != owner : write) }
    }
    func hasRanges(owner: SMBFileId) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return ranges.values.contains { $0.contains { $0.owner == owner } }
    }

    /// Release one reservation owned by `owner` matching `[offset,length)`.
    func release(_ node: InodeID, offset: UInt64, length: UInt64, owner: SMBFileId) {
        lock.lock(); defer { lock.unlock() }
        if let index = ranges[node]?.firstIndex(where: { $0.owner == owner && $0.offset == offset && $0.length == length }) {
            ranges[node]?.remove(at: index)
        }
        if ranges[node]?.isEmpty == true { ranges[node] = nil }
    }

    /// Drop all ranges held by `owner` (called on CLOSE of that handle).
    func releaseAll(owner: SMBFileId) {
        lock.lock(); defer { lock.unlock() }
        for (node, held) in ranges {
            let kept = held.filter { $0.owner != owner }
            ranges[node] = kept.isEmpty ? nil : kept
        }
    }
}

extension SMBServer {
    /// Mandatory SMB I/O checks apply to every handle, even when it owns no locks.
    func checkRangeAccess(_ open: SMBOpen, offset: UInt64, length: UInt64, write: Bool) async throws {
        guard lockTable.allowsAccess(open.node,offset:offset,length:length,write:write,owner:open.fileId) else {
            throw EngineError(.locked,"The requested I/O conflicts with a byte-range lock")
        }
        try await table.engineRef().checkRangeAccess(open.node,handle:open.leaseHandle,offset:offset,length:length,write:write)
    }
    func handleLock(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        var r = ByteReader(body)
        guard (try? r.u16()) == 48 else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let count = Int((try? r.u16()) ?? 0)
        guard count > 0, count <= 64 else { return (.invalidParameter,errorBody(),DispatchExtra()) }
        _ = try? r.u32()                            // LockSequence
        let fileId = readFileId(&r)
        guard let open = state.open(fileId) else { return (.fileClosed, errorBody(), DispatchExtra()) }

        var elements: [(offset: UInt64, length: UInt64, flags: UInt32)] = []
        for _ in 0..<count {
            guard let off = try? r.u64(), let len = try? r.u64(), let fl = try? r.u32() else { break }
            _ = try? r.u32()                        // Reserved
            elements.append((off, len, fl))
        }

        guard count > 0, elements.count == count,
              elements.allSatisfy({ !$0.offset.addingReportingOverflow($0.length).overflow }) else {
            return (.invalidParameter, errorBody(), DispatchExtra())
        }
        let SHARED: UInt32 = 0x01, EXCLUSIVE: UInt32 = 0x02, UNLOCK: UInt32 = 0x04
        // MS-SMB2 does not permit mixing unlocks with acquisitions.
        let unlocking = elements[0].flags & UNLOCK != 0
        guard elements.allSatisfy({ e in
            let operation = e.flags & 7
            return (e.flags & ~UInt32(0x17)) == 0 && (operation == SHARED || operation == EXCLUSIVE || operation == UNLOCK)
                && (operation == UNLOCK) == unlocking
        }) else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        let requested = elements.map { LockRange(offset:$0.offset,length:$0.length,exclusive:$0.flags & EXCLUSIVE != 0,owner:open.fileId) }
        let wire = requested.map { FileLockRange(offset:$0.offset,length:$0.length,exclusive:$0.exclusive) }
        let table = self.table
        if unlocking {
            guard let remote = lockTable.remoteReleases(open.node,requested:requested) else { return (.rangeNotLocked,errorBody(),DispatchExtra()) }
            let releases = remote.map { FileLockRange(offset:$0.offset,length:$0.length,exclusive:$0.exclusive) }
            let status: NTStatus = SMBServer.bridgeSync {
                do { try await table.engineRef().releaseRanges(open.node,handle:open.leaseHandle,ranges:releases); return .success }
                catch let error as EngineError { return error.kind == .locked ? .rangeNotLocked : ntStatus(for:error) }
                catch { return .unsuccessful }
            }
            guard status == .success else { return (status,errorBody(),DispatchExtra()) }
            for e in elements { lockTable.release(open.node,offset:e.offset,length:e.length,owner:open.fileId) }
            open.rangeLease = lockTable.hasRanges(owner:open.fileId)
        } else {
            guard lockTable.acquireAll(open.node,ranges:requested) else { return (.lockNotGranted,errorBody(),DispatchExtra()) }
            let status: NTStatus = SMBServer.bridgeSync {
                do { try await table.engineRef().acquireRanges(open.node,handle:open.leaseHandle,ranges:wire); return .success }
                catch let error as EngineError { return error.kind == .locked ? .lockNotGranted : ntStatus(for:error) }
                catch { return .unsuccessful }
            }
            guard status == .success else {
                for r in requested { lockTable.release(open.node,offset:r.offset,length:r.length,owner:open.fileId) }
                return (status,errorBody(),DispatchExtra())
            }
            open.rangeLease = true
        }
        var w = ByteWriter(); w.u16(4); w.u16(0)     // StructureSize=4, Reserved
        return (.success, w.data, DispatchExtra())
    }
}
