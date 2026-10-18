// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// Bounded metadata only. Slices never become write-journal bases or complete
/// pin manifests. Invalidation also fences responses already in flight.
final class ManifestRangeCache: @unchecked Sendable {
    private struct InvalidatedRequest: Error {}
    private struct Key: Hashable { let fs: FilespaceID; let id: InodeID; let version: String; let offset: Int; let refreshStaleVersion: Bool }
    private final class Token { var invalidated = false } // accessed only under lock
    private struct Pending { let id: UUID; let token: Token; let task: Task<ResolvedBlockRange, Error>; var waiters = 1 }
    private struct Cached { let value: ResolvedBlockRange; let token: Token }
    private let lock = NSLock()
    private var entries: [Key: Cached] = [:]
    private var order: [Key] = []
    private var pending: [Key: Pending] = [:]

    func invalidate(filespace: FilespaceID, itemID: InodeID? = nil) {
        lock.withLock {
            let matches: (Key) -> Bool = { $0.fs == filespace && (itemID == nil || $0.id == itemID) }
            for key in entries.keys.filter(matches) { entries.removeValue(forKey: key)?.token.invalidated = true }
            order.removeAll(where: matches)
            for key in pending.keys.filter(matches) {
                if let work = pending.removeValue(forKey: key) { work.token.invalidated = true; work.task.cancel() }
            }
        }
    }

    /// Keep only cached slices that are proven to describe the current immutable
    /// content version. Metadata and namespace revisions do not change the block
    /// map, but a content publication does. Pending requests are cancelled
    /// conservatively: a refresh-on-conflict request can resolve a different
    /// current version than the one named by its cache key.
    func retainExactVersion(filespace: FilespaceID, itemID: InodeID, version: String) {
        guard !version.isEmpty else {
            invalidate(filespace: filespace, itemID: itemID)
            return
        }
        lock.withLock {
            let matches: (Key) -> Bool = { $0.fs == filespace && $0.id == itemID }
            let stale = entries.keys.filter { key in
                guard matches(key), key.version == version,
                      let cached = entries[key]?.value else { return matches(key) }
                return cached.item.contentVersion != version
            }
            for key in stale {
                entries.removeValue(forKey: key)?.token.invalidated = true
            }
            order.removeAll { stale.contains($0) }
            for key in pending.keys.filter(matches) {
                if let work = pending.removeValue(forKey: key) {
                    work.token.invalidated = true
                    work.task.cancel()
                }
            }
        }
    }

    func get(gateway: any GatewayClient, filespace: FilespaceID, itemID: InodeID, version: String, offset: Int, refreshStaleVersion: Bool = false) async throws -> ResolvedBlockRange {
        // A commit's change notification can arrive while its new manifest is
        // already being fetched. Fencing that response is correct; surfacing the
        // cache's internal cancellation as an SMB I/O failure is not. Start a
        // fresh, authorized request under the same version policy. A continuation
        // still cannot switch versions, and cancellation by the reader is final.
        for attempt in 0..<3 {
            try Task.checkCancellation()
            do {
                return try await getOnce(gateway: gateway, filespace: filespace, itemID: itemID,
                    version: version, offset: offset, refreshStaleVersion: refreshStaleVersion)
            } catch is InvalidatedRequest {
                try Task.checkCancellation()
                guard attempt < 2 else {
                    throw EngineError(.conflict, "Metadata kept changing during the read; retry")
                }
            }
        }
        throw EngineError(.conflict, "Metadata changed during the read; retry")
    }

    private func getOnce(gateway: any GatewayClient, filespace: FilespaceID, itemID: InodeID, version: String, offset: Int, refreshStaleVersion: Bool) async throws -> ResolvedBlockRange {
        try Task.checkCancellation()
        let key = Key(fs: filespace, id: itemID, version: version, offset: offset, refreshStaleVersion: refreshStaleVersion)
        let selected: (ResolvedBlockRange?, Pending?) = lock.withLock {
            if let hit = order.last(where: { k in
                guard k.fs == filespace, k.id == itemID, k.version == version, let r = entries[k]?.value, refreshStaleVersion || r.item.contentVersion == version else { return false }
                return offset >= r.item.size || (r.start <= offset && offset < r.end)
            }), let value = entries[hit] {
                order.removeAll { $0 == hit }; order.append(hit)
                return (value.value,nil)
            }
            if var work = pending[key] { work.waiters += 1; pending[key] = work; return (nil,work) }
            let work = Pending(id: UUID(), token: Token(), task: Task {
                do {
                    return try await gateway.getBlockRange(filespace: filespace, itemID: itemID, contentVersion: version, offset: offset, length: 16 << 20)
                } catch let error as EngineError where refreshStaleVersion && error.data?["error"] == .string("version_conflict") {
                    // A mounted handle can predate a completed local/remote write.
                    // Refresh only before assembly; continuation stays version-bound.
                    let current = try await gateway.getItem(filespace: filespace, id: itemID)
                    return try await gateway.getBlockRange(filespace: filespace, itemID: itemID, contentVersion: current.contentVersion, offset: offset, length: 16 << 20)
                }
            })
            pending[key] = work
            return (nil,work)
        }
        if let hit = selected.0 { return hit }
        let work = selected.1!
        defer {
            lock.withLock {
                if var active = pending[key], active.id == work.id {
                    active.waiters -= 1
                    pending[key] = active.waiters == 0 ? nil : active
                }
            }
        }
        do {
            let value = try await work.task.value
            try Task.checkCancellation()
            return try lock.withLock {
                guard !work.token.invalidated else { throw InvalidatedRequest() }
                entries[key] = Cached(value: value, token: work.token); order.removeAll { $0 == key }; order.append(key)
                while order.count > 128 || entries.values.reduce(0, { $0 + $1.value.resolved.manifest.blocks.count }) > 8192 {
                    entries.removeValue(forKey: order.removeFirst())
                }
                return value
            }
        } catch {
            try Task.checkCancellation()
            // invalidate() cancels the shared transport task, not its callers.
            // URLSession can report either CancellationError or URLError here;
            // only our invalidation token authorizes the bounded retry.
            if lock.withLock({ work.token.invalidated }) { throw InvalidatedRequest() }
            throw error
        }
    }
}
