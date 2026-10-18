// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway
import CloudFSTransfer
import CloudFSCrypto

/// Historical data has its own manifest cache and no staged/live overlay. Every
/// read rechecks authorization before consulting even a resident verified block.
actor SnapshotDataPath: EngineDataPath {
    nonisolated let isReadOnly = true
    nonisolated let plaintextSpillDir: String
    let filespace: FilespaceID
    let gateway: SnapshotReadGateway
    let transfer: RealTransferEngine
    let crypto: any BlockCrypto
    let streams: ChunkedStreamStore
    private var manifests: [InodeID: ResolvedBlockManifest] = [:]
    init(filespace: FilespaceID, gateway: SnapshotReadGateway, transfer: RealTransferEngine, crypto: any BlockCrypto, spillDir: String, blob: BlobTransport = BlobTransport()) throws {
        streams = ChunkedStreamStore(filespace: filespace, gateway: gateway, crypto: crypto, blob: blob)
        self.filespace = filespace; self.gateway = gateway; self.transfer = transfer; self.crypto = crypto; plaintextSpillDir = spillDir
        try FileManager.default.createDirectory(atPath: spillDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    private var denied: EngineError { EngineError(.permissionDenied, "Snapshots are read-only. Copy a file to a writable volume to edit it.") }
    func lookup(_ id: InodeID) async throws -> ItemMetadata { try await decryptMacMetadata(gateway.getItem(filespace: filespace, id: id), crypto: crypto) }
    func enumerate(container: InodeID, page: String?) async throws -> (items: [ItemMetadata], nextPage: String?) {
        let result = try await gateway.listItems(filespace: filespace, parent: container, cursor: page)
        var enriched: [ItemMetadata] = []
        for item in result.items { enriched.append(try await decryptMacMetadata(item, crypto: crypto)) }
        return (enriched, result.cursor)
    }
    func enumerateChanges(container: InodeID, anchor: String) async throws -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool) {
        _ = try await lookup(container)
        return ([], [], anchor, false)
    }
    func readBytes(_ id: InodeID, version: String, offset: Int, length: Int) async throws -> Data {
        guard offset >= 0, length >= 0, length <= 1 << 20, offset <= Int.max - length else { throw EngineError(.invalidParams, "Invalid snapshot read extent") }
        let item = try await lookup(id)
        guard !item.isDir else { throw EngineError(.invalidParams, "Cannot read a folder") }
        let count = min(length, max(0, item.size - offset))
        guard count > 0 else { return Data() }
        let resolved: ResolvedBlockManifest
        if let cached = manifests[id] { resolved = cached }
        else {
            resolved = try await gateway.getResolvedBlockManifest(filespace: filespace, itemID: id)
            if manifests.count >= 128 { manifests.removeAll(keepingCapacity: true) }
            manifests[id] = resolved
        }
        await gateway.registerManifest(resolved, itemID: id)
        try await transfer.ensureBlocks(resolved: resolved, filespace: filespace, itemID: id, offset: offset, length: count)
        var bytes = Data(); bytes.reserveCapacity(count)
        for (index, ref) in resolved.manifest.blocks.enumerated() where ref.offset < offset + count && ref.offset + ref.length > offset {
            let lower = max(offset, ref.offset), upper = min(offset + count, ref.offset + ref.length)
            guard lower == offset + bytes.count else { throw EngineError(.syncFailed, "Snapshot manifest contains a gap or overlapping blocks") }
            let block = try await transfer.plaintextBlock(ref, resolved: resolved, blockIndex: index, filespace: filespace, itemID: id)
            guard upper - ref.offset <= block.count else { throw EngineError(.syncFailed, "Snapshot block is truncated") }
            bytes.append(block.subdata(in: lower - ref.offset..<upper - ref.offset))
        }
        guard bytes.count == count else { throw EngineError(.syncFailed, "Snapshot content is incomplete") }
        return bytes
    }
    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef {
        let item = try await lookup(id)
        return try await readRange(id, version: version, offset: 0, length: item.size, alignment: 0).ref
    }
    func readRange(_ id: InodeID, version: String, offset: Int, length: Int, alignment: Int) async throws -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int)) {
        guard offset >= 0, length >= 0, offset <= Int.max - length else { throw EngineError(.invalidParams, "Invalid snapshot read extent") }
        let item = try await lookup(id)
        let count = min(length, max(0, item.size - offset))
        guard !item.isDir else { throw EngineError(.invalidParams, "Cannot read a folder") }
        let path = URL(fileURLWithPath: plaintextSpillDir).appendingPathComponent(UUID().uuidString).path
        guard FileManager.default.createFile(atPath: path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw EngineError(.internal, "Cannot create a temporary snapshot read") }
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        do {
            var done = 0
            while done < count {
                let data = try await readBytes(id, version: version, offset: offset + done, length: min(1 << 20, count - done))
                guard !data.isEmpty else { throw EngineError(.syncFailed, "Snapshot read ended early") }
                try handle.write(contentsOf: data); done += data.count
            }
            try handle.close()
            return (CacheFileRef(path: path), (offset, count))
        } catch { try? handle.close(); try? FileManager.default.removeItem(atPath: path); throw error }
    }
    func beginWrite(_ id: InodeID, handle: String) async throws { throw denied }
    func beginOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                   sharing: OpenFileSharing) async throws {
        guard !access.contains(.write), !access.contains(.delete) else { throw denied }
    }
    func endOpen(_ id: InodeID, handle: String) async { }
    func authorizeWrite(_ id: InodeID, refresh: Bool) async throws { throw denied }
    func write(id: InodeID?, fields: ItemMetadata, contents: CacheFileRef?, baseVersion: String?) async throws -> ItemMetadata { throw denied }
    func writeRange(_ id: InodeID, offset: Int, data: Data, baseVersion: String?) async throws -> Int { throw denied }
    func truncate(_ id: InodeID, newSize: Int, baseVersion: String?) async throws { throw denied }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws { throw denied }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata { throw denied }
    func setContentPolicy(_ id: InodeID, policy: ContentPolicy) async throws { throw denied }
    func requestDownload(_ id: InodeID, range: (offset: Int, length: Int)?) async throws -> PrefetchAck { throw denied }
    func evict(_ id: InodeID) async throws -> EvictAck { throw denied }
    func listStreams(_ id: InodeID) async throws -> [StreamInfo] { try await gateway.listStreams(filespace: filespace, id: id) }
    func readStreamRange(_ id: InodeID, name: String, offset: Int, length: Int) async throws -> Data {
        try await streams.read(id, name: name, offset: offset, length: length)
    }
    func readStream(_ id: InodeID, name: String) async throws -> Data {
        guard let info = try await listStreams(id).first(where: { $0.name == name }) else { throw EngineError(.notFound) }
        guard info.size <= ChunkedStreamStore.maximumRange else { throw EngineError(.invalidParams, "Use ranged I/O for large named streams") }
        return try await streams.read(id, name: name, offset: 0, length: info.size)
    }
    func writeStreamRange(_ id: InodeID, name: String, offset: Int, data: Data) async throws -> Int { throw denied }
    func truncateStream(_ id: InodeID, name: String, size: Int) async throws { throw denied }
    func writeStream(_ id: InodeID, name: String, data: Data) async throws { throw denied }
    func deleteStream(_ id: InodeID, name: String) async throws { throw denied }
}
