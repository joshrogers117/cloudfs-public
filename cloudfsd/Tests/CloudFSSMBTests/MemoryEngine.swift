// SPDX-License-Identifier: AGPL-3.0-or-later
// In-memory EngineDataPath for CloudFSSMB tests — a tiny filesystem behind the
// engine seam. Extended incrementally
// as later phases need timestamps/streams.

import Foundation
import CloudFSCore
@testable import CloudFSSMB

final class MemoryEngine: EngineDataPath, @unchecked Sendable {
    private let lock = NSLock()
    var items: [InodeID: ItemMetadata] = [:]
    var contents: [InodeID: Data] = [:]
    var readDelayNs: UInt64 = 0
    private var activeReads = 0, peakReads = 0
    var readConcurrency: (active: Int, peak: Int) { locked { (activeReads, peakReads) } }
    var denyWrites = false
    var denyDeletes = false
    var returnWriteSnapshot = false
    private var writeSnapshotCalls = 0
    private var authorizeWriteCalls = 0
    var writeSnapshotCallCount: Int { locked { writeSnapshotCalls } }
    var authorizeWriteCallCount: Int { locked { authorizeWriteCalls } }
    private var openRefs: [InodeID: Set<String>] = [:]
    private var beginOpenCalls = 0
    private var endOpenCalls = 0
    private var directorySnapshotCalls = 0
    private var unlinked: Set<InodeID> = []
    private var allocatedIDs: Set<InodeID> = [.root]
    private var nextAllocatedID: UInt64 = 1
    var beforeWrite: (@Sendable (Int, Data) async throws -> Void)?
    var rangeAccessHook: (@Sendable () async throws -> Void)?
    var rangeAcquireHook: (@Sendable () async throws -> Void)?
    var rangeReleaseHook: (@Sendable ([FileLockRange]) async throws -> Void)?
    func acquireRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {
        if let hook = locked({ rangeAcquireHook }) { try await hook() }
    }
    func releaseRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {
        if let hook = locked({ rangeReleaseHook }) { try await hook(ranges) }
    }
    func checkRangeAccess(_ id: InodeID, handle: String, offset: UInt64, length: UInt64, write: Bool) async throws {
        if let hook = locked({ rangeAccessHook }) { try await hook() }
    }
    func authorizeWrite(_ id: InodeID, refresh: Bool) async throws {
        try locked {
            authorizeWriteCalls += 1
            if denyWrites { throw EngineError(.permissionDenied, "Read-only") }
        }
    }
    func beginOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                   sharing: OpenFileSharing) async throws {
        try locked {
            beginOpenCalls += 1
            guard items[id] != nil, !unlinked.contains(id) else { throw EngineError(.notFound, id.rawValue) }
            openRefs[id, default: []].insert(handle)
        }
    }
    func endOpen(_ id: InodeID, handle: String) async {
        locked {
            endOpenCalls += 1
            openRefs[id]?.remove(handle)
            if openRefs[id]?.isEmpty == true { openRefs[id] = nil }
            purgeIfUnlinked(id)
        }
    }
    func openReferenceCount(_ id: InodeID) -> Int { locked { openRefs[id]?.count ?? 0 } }
    var beginOpenCallCount: Int { locked { beginOpenCalls } }
    var endOpenCallCount: Int { locked { endOpenCalls } }
    var directorySnapshotCallCount: Int { locked { directorySnapshotCalls } }

    func directorySnapshot(_ id: InodeID, handle: String, access: OpenFileAccess,
                           sharing: OpenFileSharing) async throws -> DirectorySnapshot? {
        try locked {
            directorySnapshotCalls += 1
            guard access.rawValue <= OpenFileAccess.read.rawValue,
                  let directory = items[id], directory.isDir, !unlinked.contains(id) else {
                throw EngineError(.notFound, id.rawValue)
            }
            let children = items.values.filter { $0.parent == id && !unlinked.contains($0.id) }
                .sorted { $0.name < $1.name }
            guard children.count <= 500 else { return nil }
            return DirectorySnapshot(directory: directory, items: children)
        }
    }
    func isDetached(_ id: InodeID) -> Bool { locked { unlinked.contains(id) } }
    func hasRetainedItem(_ id: InodeID) -> Bool { locked { items[id] != nil } }
    func seedStream(_ id: InodeID, name: String, data: Data) { locked { streams[id, default: [:]][name] = data } }
    private func purgeIfUnlinked(_ id: InodeID) {
        guard unlinked.contains(id), openRefs[id]?.isEmpty != false else { return }
        unlinked.remove(id); items[id] = nil; contents[id] = nil; streams[id] = nil
    }
    private var version = 1
    private var lookupCalls = 0
    var lookupCount: Int { locked { lookupCalls } }
    private var basicInfoWrites = 0
    var basicInfoWriteCount: Int { locked { basicInfoWrites } }

    private func allocateID(for path: InodeID) -> InodeID {
        if allocatedIDs.insert(path).inserted { return path }
        while true {
            let candidate = InodeID("\(path.rawValue)#\(nextAllocatedID)")
            nextAllocatedID &+= 1
            if allocatedIDs.insert(candidate).inserted { return candidate }
        }
    }

    init() {
        items[.root] = ItemMetadata(id: .root, parent: nil, name: "", isDir: true,
                                    size: 0, contentVersion: "root", metadataVersion: "1")
    }

    @discardableResult
    func seed(_ name: String, parent: InodeID = .root, data: Data) -> InodeID {
        lock.lock(); defer { lock.unlock() }
        let id = allocateID(for: InodeID("\(parent.rawValue)/\(name)"))
        items[id] = ItemMetadata(id: id, parent: parent, name: name, isDir: false,
                                 size: data.count, contentVersion: "cv-\(name)-1", metadataVersion: "1")
        contents[id] = data
        return id
    }

    @discardableResult
    func seedDir(_ name: String, parent: InodeID = .root) -> InodeID {
        lock.lock(); defer { lock.unlock() }
        let id = allocateID(for: InodeID("\(parent.rawValue)/\(name)"))
        items[id] = ItemMetadata(id: id, parent: parent, name: name, isDir: true,
                                 size: 0, contentVersion: "", metadataVersion: "1")
        return id
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }

    /// Thread-safe snapshot of item names (for test assertions).
    func snapshotNames() -> [String] { locked { items.values.map(\.name) } }
    private func bump(_ id: InodeID, size: Int) {
        guard let m = items[id] else { return }
        version += 1
        items[id] = ItemMetadata(id: id, parent: m.parent, name: m.name, isDir: m.isDir,
                                 size: size, contentVersion: "cv-\(m.name)-\(version)",
                                 metadataVersion: "\(version)", createdAt: m.createdAt, modifiedAt: Date(), accessedAt: m.accessedAt, changedAt: Date(), fileAttributes: m.fileAttributes)
    }

    func setBasicInfo(_ id: InodeID, info: BasicFileInfo) async throws -> ItemMetadata {
        try await authorizeWrite(id, refresh: true)
        return try locked {
            guard let m = items[id] else { throw EngineError(.notFound) }
            basicInfoWrites += 1
            version += 1
            let result = ItemMetadata(id: id, parent: m.parent, name: m.name, isDir: m.isDir, size: m.size,
                contentVersion: m.contentVersion, metadataVersion: String(version),
                createdAt: info.createdAt ?? m.createdAt, modifiedAt: info.modifiedAt ?? m.modifiedAt,
                accessedAt: info.accessedAt ?? m.accessedAt, changedAt: info.changedAt ?? m.changedAt,
                fileAttributes: info.fileAttributes ?? m.fileAttributes, rsrcForkSize: m.rsrcForkSize, finderInfo: m.finderInfo)
            items[id] = result; return result
        }
    }
    var lookupSnapshotHook: (@Sendable () async -> Void)?
    func lookup(_ id: InodeID) async throws -> ItemMetadata {
        let snapshot = try locked {
            lookupCalls += 1
            guard let m = items[id], !unlinked.contains(id) || openRefs[id]?.isEmpty == false else {
                throw EngineError(.notFound, id.rawValue)
            }
            return m
        }
        await lookupSnapshotHook?()
        return snapshot
    }
    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef { fatalError("unused") }
    func readRange(_ id: InodeID, version: String, offset: Int, length: Int,
                   alignment: Int) async throws -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int)) {
        let delay = locked { readDelayNs }
        if delay > 0 {
            locked { activeReads += 1; peakReads = max(peakReads, activeReads) }
        }
        defer { if delay > 0 { locked { activeReads -= 1 } } }
        if delay > 0 { try await Task.sleep(nanoseconds: delay) }
        return try locked {
            guard let data = contents[id] else { throw EngineError(.notFound, id.rawValue) }
            let lo = min(offset, data.count)
            let hi = min(offset + length, data.count)
            let slice = lo < hi ? data.subdata(in: lo..<hi) : Data()
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent("smb-test-\(UUID().uuidString)")
            try slice.write(to: url)
            return (CacheFileRef(fd: nil, path: url.path), (lo, slice.count))
        }
    }
    func write(id: InodeID?, fields: ItemMetadata, contents ref: CacheFileRef?,
               baseVersion: String?) async throws -> ItemMetadata {
        locked {
            let newID = allocateID(for: InodeID("\(fields.parent?.rawValue ?? "root")/\(fields.name)"))
            let created = ItemMetadata(id: newID, parent: fields.parent, name: fields.name,
                                       isDir: fields.isDir, size: 0, contentVersion: "cv-new-1",
                                       metadataVersion: "1")
            items[newID] = created
            if !fields.isDir { contents[newID] = Data() }
            return created
        }
    }
    func writeRange(_ id: InodeID, offset: Int, data: Data, baseVersion: String?) async throws -> Int {
        if let before = locked({ beforeWrite }) { try await before(offset, data) }
        return try locked {
            guard items[id] != nil else { throw EngineError(.notFound, id.rawValue) }
            var buf = contents[id] ?? Data()
            let end = offset + data.count
            if buf.count < end { buf.append(Data(repeating: 0, count: end - buf.count)) }
            buf.replaceSubrange(offset..<end, with: data)
            contents[id] = buf
            bump(id, size: buf.count)
            return buf.count
        }
    }
    func truncate(_ id: InodeID, newSize: Int, baseVersion: String?) async throws {
        try locked {
            guard var buf = contents[id] else { throw EngineError(.notFound, id.rawValue) }
            if buf.count > newSize { buf = buf.prefix(newSize) } else { buf.append(Data(repeating: 0, count: newSize - buf.count)) }
            contents[id] = buf
            bump(id, size: buf.count)
        }
    }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws {
        try locked {
            if denyDeletes { throw EngineError(.permissionDenied, "Delete denied") }
            if !recursive, items.values.contains(where: { $0.parent == id }) {
                throw EngineError(.conflict, "Directory is not empty", data: ["error": .string("directory_not_empty")])
            }
            unlinked.insert(id)
            purgeIfUnlinked(id)
        }
    }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata {
        try locked {
            guard let m = items[id] else { throw EngineError(.notFound, id.rawValue) }
            version += 1
            let moved = ItemMetadata(id: id, parent: newParent ?? m.parent, name: newName,
                                     isDir: m.isDir, size: m.size, contentVersion: m.contentVersion,
                                     metadataVersion: String(version))
            items[id] = moved
            return moved
        }
    }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String, replacing: ItemMetadata?) async throws -> ItemMetadata {
        try locked {
            guard let m = items[id] else { throw EngineError(.notFound, id.rawValue) }
            if let replacing {
                if denyDeletes { throw EngineError(.permissionDenied, "Replacement denied") }
                guard let target = items[replacing.id], target.metadataVersion == replacing.metadataVersion,
                      target.parent == (newParent ?? m.parent), target.name == newName else { throw EngineError(.conflict, "Replacement changed") }
                unlinked.insert(replacing.id)
                purgeIfUnlinked(replacing.id)
            }
            version += 1
            let moved = ItemMetadata(id: id, parent: newParent ?? m.parent, name: newName,
                isDir: m.isDir, size: m.size, contentVersion: m.contentVersion,
                metadataVersion: String(version), createdAt: m.createdAt, modifiedAt: m.modifiedAt,
                accessedAt: m.accessedAt, changedAt: m.changedAt, fileAttributes: m.fileAttributes)
            items[id] = moved
            return moved
        }
    }
    var enumerationSnapshotHook: (@Sendable () async -> Void)?
    var changeGenerationHook: (@Sendable () async -> UInt64)?
    var changeEnumerationHook: (@Sendable (InodeID) async -> Void)?
    var notificationCheckpointHook: (@Sendable (InodeID) async throws -> String)?
    var changePageHook: (@Sendable (String) async throws -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool))?
    func notificationCheckpoint(container: InodeID) async throws -> String {
        if let notificationCheckpointHook { return try await notificationCheckpointHook(container) }
        await changeEnumerationHook?(container)
        return String(await changeGeneration())
    }
    func changeGeneration() async -> UInt64 { await changeGenerationHook?() ?? 0 }
    func waitForChanges(after: UInt64) async -> UInt64 {
        try? await Task.sleep(for: .milliseconds(100))
        return await changeGeneration()
    }
    func enumerate(container: InodeID, page: String?) async throws -> (items: [ItemMetadata], nextPage: String?) {
        let snapshot = locked { items.values.filter { $0.parent == container && !unlinked.contains($0.id) }.sorted { $0.name < $1.name } }
        await enumerationSnapshotHook?()
        return (snapshot, nil)
    }
    func enumerateChanges(container: InodeID, anchor: String) async throws
        -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool) {
        await changeEnumerationHook?(container)
        if let changePageHook { return try await changePageHook(anchor) }
        return ([], [], anchor, false)
    }
    // Named streams (P4) — in-memory, keyed by (itemID, name).
    private var streams: [InodeID: [String: Data]] = [:]
    var streamReadError: EngineError?
    var streamListError: EngineError?
    private var streamLifecycle: [String] = []
    var streamLifecycleEvents: [String] { locked { streamLifecycle } }
    func beginWrite(_ id: InodeID, handle: String) async throws {
        locked { streamLifecycle.append("beginWrite") }
    }
    func beginWriteSnapshot(_ id: InodeID, handle: String) async throws -> ItemMetadata? {
        try locked {
            streamLifecycle.append("beginWrite")
            writeSnapshotCalls += 1
            guard returnWriteSnapshot else { return nil }
            guard let item = items[id], !unlinked.contains(id) else { throw EngineError(.notFound, id.rawValue) }
            return item
        }
    }
    func listStreams(_ id: InodeID) async throws -> [StreamInfo] {
        try locked {
            streamLifecycle.append("listStreams")
            if let error = streamListError { throw error }
            return (streams[id] ?? [:]).map { StreamInfo(name: $0.key, size: $0.value.count) }.sorted { $0.name < $1.name }
        }
    }
    func readStream(_ id: InodeID, name: String) async throws -> Data {
        try locked {
            if let error = streamReadError { throw error }
            guard (!unlinked.contains(id) || openRefs[id]?.isEmpty == false), let d = streams[id]?[name] else { throw EngineError(.notFound, "no stream \(name)") }
            return d
        }
    }
    func writeStream(_ id: InodeID, name: String, data: Data) async throws {
        locked {
            guard items[id] != nil, !unlinked.contains(id) || openRefs[id]?.isEmpty == false else { return }
            streams[id, default: [:]][name] = data
        }
    }
    func deleteStream(_ id: InodeID, name: String) async throws {
        locked { streams[id]?[name] = nil }
    }

    func setContentPolicy(_ id: InodeID, policy: ContentPolicy) async throws {}
    func requestDownload(_ id: InodeID, range: (offset: Int, length: Int)?) async throws -> PrefetchAck {
        PrefetchAck(path: id.rawValue, queuedBlocks: 0)
    }
    func evict(_ id: InodeID) async throws -> EvictAck { EvictAck(path: id.rawValue, evictedBlocks: 0, freedBytes: 0) }
}
