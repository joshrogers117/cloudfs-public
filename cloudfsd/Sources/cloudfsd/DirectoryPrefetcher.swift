// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// Predict numbered file sequences only after three successful adjacent reads.
/// Candidates come exclusively from authorized listings, never a directory walk.
/// Two jobs / 4 MiB globally, at most two blocks per candidate, no chaining from
/// prefetch completion. Cancellation retains its reservation until work exits.
final class DirectoryPrefetcher: @unchecked Sendable {
    typealias Operation = @Sendable (ItemMetadata, Int) async throws -> Void
    struct Snapshot { let directories: Int; let entries: Int; let activeJobs: Int; let reservedBytes: Int }
    private struct Key: Hashable { let fs: FilespaceID; let parent: InodeID }
    private struct Sequence: Equatable { let family: String; let number: Int }
    private struct Directory {
        var items: [InodeID: ItemMetadata] = [:]
        var order: [InodeID] = []
        var last: Sequence?
        var lastID: InodeID?
        var direction = 0
        var consecutive = 0
        var touched = ContinuousClock.now
        var attempted: Set<InodeID> = []
    }
    private struct Job { let key: Key; let bytes: Int; let task: Task<Void,Never> }
    private let lock = NSLock()
    private var directories: [Key:Directory] = [:]
    private var order: [Key] = []
    private var jobs: [UUID:Job] = [:]
    private var paused: Set<FilespaceID> = []
    private static let pattern = try! NSRegularExpression(pattern: "^(.*?)([0-9]{1,12})(\\.[^.]+)$")
    private static func sequence(_ name: String) -> Sequence? {
        let range = NSRange(name.startIndex...,in: name)
        guard let m = pattern.firstMatch(in: name,range: range),
              let p = Range(m.range(at: 1),in: name),let n = Range(m.range(at: 2),in: name),let e = Range(m.range(at: 3),in: name),
              let value = Int(name[n]) else { return nil }
        return Sequence(family: String(name[p])+"|"+String(name[n].count)+"|"+String(name[e]),number: value)
    }
    func listing(filespace: FilespaceID, parent: InodeID, items: [ItemMetadata], firstPage: Bool) {
        lock.withLock {
            guard !paused.contains(filespace) else { return }
            let key = Key(fs: filespace,parent: parent)
            let candidates = items.filter { !$0.isDir && $0.size > 0 }
            // SMB re-enumerates when its directory cache expires. An identical
            // authorized listing must not erase the adjacent-read evidence or
            // cancel warmup already in flight. A changed/partial listing still
            // replaces everything, so removed or no-longer-authorized entries
            // can never remain speculative candidates.
            let unchanged = firstPage && directories[key].map { previous in
                previous.items.count == candidates.count && candidates.allSatisfy { item in
                    guard let old = previous.items[item.id] else { return false }
                    return old.name == item.name && old.parent == item.parent &&
                        old.size == item.size && old.contentVersion == item.contentVersion
                }
            } == true
            let reset = firstPage && !unchanged
            if reset { for job in jobs.values where job.key == key { job.task.cancel() } }
            var dir = reset ? Directory() : directories[key] ?? Directory()
            for item in candidates {
                if dir.items[item.id] == nil { dir.order.append(item.id) }
                dir.items[item.id] = item
            }
            while dir.order.count > 2048 {
                let removed = dir.order.removeFirst(); dir.items.removeValue(forKey: removed); dir.attempted.remove(removed)
            }
            directories[key] = dir; order.removeAll { $0 == key }; order.append(key)
            while order.count > 32 { directories.removeValue(forKey: order.removeFirst()) }
        }
    }
    func readCompleted(filespace: FilespaceID, itemID: InodeID, version: String, blockSize: Int, operation: @escaping Operation) {
        lock.withLock {
            guard !paused.contains(filespace), blockSize > 0, blockSize <= 2 << 20,
                  let key = order.last(where: { $0.fs == filespace && directories[$0]?.items[itemID] != nil }),
                  var dir = directories[key], let item = dir.items[itemID], item.contentVersion == version,
                  let next = Self.sequence(item.name), dir.lastID != itemID else { return }
            let now = ContinuousClock.now
            let step = dir.last.map { next.number - $0.number } ?? 0
            if dir.last?.family == next.family, abs(step) == 1, dir.touched.duration(to: now) < .seconds(3),
               dir.direction == 0 || dir.direction == step {
                dir.consecutive += 1; dir.direction = step
            } else {
                if dir.last != nil { for job in jobs.values where job.key == key { job.task.cancel() } }
                dir.consecutive = 1; dir.direction = 0
            }
            dir.last = next; dir.lastID = itemID; dir.touched = now
            if dir.consecutive >= 3 {
                for ahead in 1...2 {
                    guard jobs.count < 2, let candidate = dir.items.values.first(where: {
                        Self.sequence($0.name) == Sequence(family: next.family,number: next.number+dir.direction*ahead)
                    }), !dir.attempted.contains(candidate.id) else { continue }
                    let bytes = min(candidate.size,2*blockSize)
                    guard jobs.values.reduce(0, { $0+$1.bytes })+bytes <= 4 << 20 else { continue }
                    dir.attempted.insert(candidate.id)
                    let id = UUID()
                    let task = Task { [weak self] in
                        do { try Task.checkCancellation(); try await operation(candidate,bytes) } catch { /* Optional work never fails a foreground read. */ }
                        self?.finished(id)
                    }
                    jobs[id] = Job(key: key,bytes: bytes,task: task)
                }
            }
            directories[key] = dir
        }
    }
    private func finished(_ id: UUID) { lock.withLock { _ = jobs.removeValue(forKey: id) } }
    func invalidate(filespace: FilespaceID, itemID: InodeID? = nil) {
        lock.withLock { invalidateLocked(filespace: filespace,itemID: itemID) }
    }
    private func invalidateLocked(filespace: FilespaceID, itemID: InodeID?) {
        let keys = Set(order.filter { $0.fs == filespace && (itemID == nil || $0.parent == itemID || directories[$0]?.items[itemID!] != nil) })
        for key in keys { directories.removeValue(forKey: key) }
        order.removeAll { keys.contains($0) }
        for job in jobs.values where job.key.fs == filespace && (itemID == nil || keys.contains(job.key)) { job.task.cancel() }
    }
    func setPaused(_ value: Bool, filespace: FilespaceID) {
        lock.withLock {
            if value { paused.insert(filespace); invalidateLocked(filespace: filespace,itemID: nil) }
            else { paused.remove(filespace) }
        }
    }
    func cancelAndWait(filespace: FilespaceID) async {
        let tasks = lock.withLock {
            invalidateLocked(filespace: filespace,itemID: nil)
            return jobs.values.filter { $0.key.fs == filespace }.map(\.task)
        }
        for task in tasks { await task.value }
    }
    func snapshot() -> Snapshot {
        lock.withLock { Snapshot(directories: directories.count,entries: directories.values.reduce(0) { $0+$1.items.count },activeJobs: jobs.count,reservedBytes: jobs.values.reduce(0) { $0+$1.bytes }) }
    }
    deinit { for job in jobs.values { job.task.cancel() } }
}
