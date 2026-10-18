// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CryptoKit
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
import CloudFSTransfer

struct OfflineStream: Codable, Sendable {
    let size: Int
    let blocks: [StreamBlock]
    let inlineCiphertext: Data?
}
struct OfflineEntry: Codable, Sendable {
    let item: ItemMetadata
    let manifest: BlockManifest?
    let streams: [String: OfflineStream]
}
struct OfflineCheckpoint: Codable, Sendable {
    static let lifetime: TimeInterval = 24 * 60 * 60
    static let maximumBytes = 64 << 20
    let format: Int
    let identity: String
    let filespace: FilespaceID
    let path: String
    let roots: [FilespaceMountRoot]
    let createdAt: Date
    let expiresAt: Date
    let anchor: Int
    let visibility: String
    let entries: [OfflineEntry]
    func validateAuthorization(identity expected: String, now: Date = Date()) throws {
        guard format == 1, identity == expected, !roots.isEmpty, now >= createdAt.addingTimeInterval(-60), now < expiresAt,
              expiresAt.timeIntervalSince(createdAt) <= Self.lifetime, entries.count <= 100_000 else {
            throw EngineError(.permissionDenied, "Offline copy expired or belongs to another account. Reconnect and refresh the pin.")
        }
    }
    func validate(identity expected: String, now: Date = Date()) throws {
        try validateAuthorization(identity: expected, now: now)
        let ids = Set(entries.map { $0.item.id.rawValue })
        guard ids.count == entries.count, roots.allSatisfy({ ids.contains($0.id) }) else { throw EngineError(.syncFailed, "Offline namespace is incomplete") }
        for entry in entries {
            if !entry.item.isDir {
                guard let manifest = entry.manifest, manifest.itemID == entry.item.id, manifest.contentVersion == entry.item.contentVersion else { throw EngineError(.syncFailed, "Offline manifest is incomplete") }
                var end = 0
                for ref in manifest.blocks {
                    guard ref.offset == end, ref.length > 0, end <= entry.item.size, ref.length <= entry.item.size - end else { throw EngineError(.syncFailed, "Offline manifest has a hole") }
                    end += ref.length
                }
                guard end == entry.item.size else { throw EngineError(.syncFailed, "Offline manifest ended early") }
            }
            for stream in entry.streams.values {
                guard stream.size >= 0, stream.size <= 128 << 30, stream.inlineCiphertext == nil || stream.blocks.isEmpty else { throw EngineError(.syncFailed, "Invalid offline stream") }
                var previous = -1
                for block in stream.blocks {
                    guard block.index > previous, block.index <= stream.size / ChunkedStreamStore.blockSize,
                          block.length > 0, block.length <= ChunkedStreamStore.blockSize,
                          block.length <= stream.size - block.index * ChunkedStreamStore.blockSize else { throw EngineError(.syncFailed, "Invalid offline stream block") }
                    previous = block.index
                }
            }
            if !roots.contains(where: { $0.id == entry.item.id.rawValue }), let parent = entry.item.parent {
                guard ids.contains(parent.rawValue) else { throw EngineError(.syncFailed, "Offline namespace is incomplete") }
            }
        }
    }
    static func identifier(_ path: String) -> String { SHA256.hash(data: Data(path.utf8)).map { String(format: "%02x", $0) }.joined() }
    static func url(directory: URL, path: String) -> URL { directory.appendingPathComponent("offline-v1").appendingPathComponent(identifier(path) + ".bin") }
    static func cryptoID(_ path: String) -> InodeID { InodeID("offline-checkpoint-v1:" + identifier(path)) }
    func save(directory: URL, crypto: any BlockCrypto) async throws {
        let bytes = try await seal(crypto: crypto)
        try persist(bytes, directory: directory)
    }
    func seal(crypto: any BlockCrypto) async throws -> Data {
        try validate(identity: identity)
        let bytes = try JSONEncoder().encode(self)
        guard bytes.count <= Self.maximumBytes else { throw EngineError(.syncFailed, "Offline metadata exceeds 64 MiB; pin a smaller subtree") }
        return try await crypto.encryptBlock(bytes, itemID: Self.cryptoID(path), blockIndex: 0).ciphertext
    }
    func persist(_ encrypted: Data, directory: URL) throws {
        let url = Self.url(directory: directory, path: path)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let attrs = try FileManager.default.attributesOfFileSystem(forPath: directory.path)
        guard (attrs[.systemFreeSize] as? NSNumber)?.int64Value ?? 0 > Int64(encrypted.count) + (1 << 30) else { throw EngineError(.syncFailed, "Insufficient disk space for offline metadata") }
        try encrypted.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        let handle = try FileHandle(forWritingTo: url); defer { try? handle.close() }
        try handle.synchronize()
    }
    static func load(directory: URL, path: String, identity: String, crypto: any BlockCrypto, now: Date = Date()) async throws -> OfflineCheckpoint {
        let url = url(directory: directory, path: path)
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        guard let size = attrs[.size] as? NSNumber, size.intValue <= maximumBytes + 256 else { throw EngineError(.syncFailed, "Invalid offline metadata size") }
        let ciphertext = try Data(contentsOf: url)
        let bytes = try await crypto.decryptBlock(ciphertext, itemID: cryptoID(path), blockIndex: 0)
        let checkpoint = try JSONDecoder().decode(Self.self, from: bytes)
        guard checkpoint.path == path else { throw EngineError(.syncFailed, "Offline checkpoint path mismatch") }
        try checkpoint.validate(identity: identity, now: now)
        return checkpoint
    }
}

/// A frozen, fully enumerated subtree. No gateway or blob transport is held by
/// this adapter: missing/corrupt content cannot become network I/O or false zeros.
actor OfflineDataPath: EngineDataPath {
    nonisolated let isReadOnly = true
    nonisolated let plaintextSpillDir: String
    let checkpoint: OfflineCheckpoint
    let cache: any BlockCache
    let crypto: any BlockCrypto
    let fileURL: URL
    private let entries: [InodeID: OfflineEntry]
    private let fileGeneration: Date?
    init(checkpoint: OfflineCheckpoint, cache: any BlockCache, crypto: any BlockCrypto, fileURL: URL, spillDir: String) {
        self.checkpoint = checkpoint; self.cache = cache; self.crypto = crypto; self.fileURL = fileURL; plaintextSpillDir = spillDir
        fileGeneration = (try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.modificationDate]) as? Date
        entries = Dictionary(uniqueKeysWithValues: checkpoint.entries.map { ($0.item.id, $0) })
    }
    private var denied: EngineError { EngineError(.permissionDenied, "Offline copies are read-only. Reconnect and remount to edit.") }
    private func entry(_ id: InodeID) throws -> OfflineEntry {
        try checkpoint.validateAuthorization(identity: checkpoint.identity)
        guard let fileGeneration, (try? FileManager.default.attributesOfItem(atPath: fileURL.path)[.modificationDate]) as? Date == fileGeneration else { throw EngineError(.permissionDenied, "Offline authorization was invalidated. Reconnect and refresh the pin.") }
        guard let value = entries[id] else { throw EngineError(.notFound, "Item is not in this offline subtree") }
        return value
    }
    func lookup(_ id: InodeID) async throws -> ItemMetadata { try await decryptMacMetadata(entry(id).item, crypto: crypto) }
    func enumerate(container: InodeID, page: String?) async throws -> (items: [ItemMetadata], nextPage: String?) {
        guard try entry(container).item.isDir else { throw EngineError(.invalidParams, "Not a directory") }
        let children = entries.values.map(\.item).filter { $0.parent == container }.sorted { $0.id.rawValue < $1.id.rawValue }
        let selected = Array(children.filter { page == nil || $0.id.rawValue > page! }.prefix(501))
        var result: [ItemMetadata] = []
        for item in selected.prefix(500) { result.append(try await decryptMacMetadata(item, crypto: crypto)) }
        return (result, selected.count > 500 ? result.last?.id.rawValue : nil)
    }
    private func plaintext(hash: String, item: InodeID, index: Int, length: Int) async throws -> Data {
        guard let cipher = try await cache.readBlockForOffline(BlockHash(hex: hash)) else { throw EngineError(.syncFailed, "Offline content is missing. Reconnect and refresh the pin.", data: ["reason": .string("offline_uncached")]) }
        guard SHA256.hash(data: cipher).map({ String(format: "%02x", $0) }).joined() == hash else { throw EngineError(.syncFailed, "Offline content checksum mismatch", data: ["reason": .string("offline_corrupt")]) }
        let bytes = try await crypto.decryptBlock(cipher, itemID: item, blockIndex: index)
        guard bytes.count == length else { throw EngineError(.syncFailed, "Offline content length mismatch") }
        return bytes
    }
    func readBytes(_ id: InodeID, version: String, offset: Int, length: Int) async throws -> Data {
        guard offset >= 0, length >= 0, length <= 1 << 20, offset <= Int.max - length else { throw EngineError(.invalidParams) }
        let value = try entry(id)
        guard let manifest = value.manifest else { throw EngineError(.invalidParams, "Cannot read a folder") }
        guard version.isEmpty || version == value.item.contentVersion else { throw EngineError(.conflict, "Offline copy has a different version") }
        let count = min(length, max(0, value.item.size - offset)); var bytes = Data()
        for (index,ref) in manifest.blocks.enumerated() where ref.offset < offset + count && ref.offset + ref.length > offset {
            let block = try await plaintext(hash: ref.hash.hex, item: id, index: index, length: ref.length)
            let low = max(offset, ref.offset), high = min(offset + count, ref.offset + ref.length)
            guard low == offset + bytes.count else { throw EngineError(.syncFailed, "Offline manifest is incomplete") }
            bytes.append(block[(low-ref.offset)..<(high-ref.offset)])
        }
        guard bytes.count == count else { throw EngineError(.syncFailed, "Offline content ended early") }
        return bytes
    }
    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef {
        try await readRange(id, version: version, offset: 0, length: entry(id).item.size, alignment: 0).ref
    }
    func readRange(_ id: InodeID, version: String, offset: Int, length: Int, alignment: Int) async throws -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int)) {
        guard offset >= 0, length >= 0, offset <= Int.max-length else { throw EngineError(.invalidParams) }
        let count = min(length,max(0,try entry(id).item.size-offset))
        try FileManager.default.createDirectory(atPath: plaintextSpillDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let path = URL(fileURLWithPath: plaintextSpillDir).appendingPathComponent(UUID().uuidString)
        guard FileManager.default.createFile(atPath: path.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw EngineError(.syncFailed, "Cannot create offline read file") }
        let handle = try FileHandle(forWritingTo: path)
        do { var done = 0
            while done < count { let bytes = try await readBytes(id, version: version, offset: offset+done, length: min(1 << 20,count-done)); try handle.write(contentsOf: bytes); done += bytes.count }
            try handle.close(); return (CacheFileRef(path: path.path),(offset,count))
        } catch { try? handle.close(); try? FileManager.default.removeItem(at: path); throw error }
    }
    func listStreams(_ id: InodeID) async throws -> [StreamInfo] { try entry(id).streams.map { StreamInfo(name: $0.key, size: $0.value.size) }.sorted { $0.name < $1.name } }
    func readStreamRange(_ id: InodeID, name: String, offset: Int, length: Int) async throws -> Data {
        guard offset >= 0, length >= 0, length <= ChunkedStreamStore.maximumRange, offset <= Int.max-length else { throw EngineError(.invalidParams) }
        guard let stream = try entry(id).streams[name] else { throw EngineError(.notFound) }
        let count = min(length,max(0,stream.size-offset))
        if let cipher = stream.inlineCiphertext {
            let bytes = try await crypto.decryptBlock(cipher, itemID: id, blockIndex: ChunkedStreamStore.legacyIndex(name))
            guard bytes.count == stream.size else { throw EngineError(.syncFailed, "Offline stream length mismatch") }
            return count == 0 ? Data() : bytes[offset..<(offset+count)]
        }
        var bytes = Data(repeating: 0, count: count) // Sparse stream holes are explicit in this captured format.
        for block in stream.blocks {
            let start = block.index * ChunkedStreamStore.blockSize, low = max(offset,start), high = min(offset+count,start+block.length)
            if high > low {
                let part = try await plaintext(hash: block.hash, item: ChunkedStreamStore.cryptoIdentity(id,name:name), index: block.index, length: block.length)
                bytes.replaceSubrange((low-offset)..<(high-offset),with:part[(low-start)..<(high-start)])
            }
        }
        return bytes
    }
    func readStream(_ id: InodeID, name: String) async throws -> Data {
        guard let stream = try entry(id).streams[name], stream.size <= ChunkedStreamStore.maximumRange else { throw EngineError(.invalidParams, "Use ranged stream reads") }
        return try await readStreamRange(id,name:name,offset:0,length:stream.size)
    }
    func enumerateChanges(container: InodeID, anchor: String) async throws -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool) { _ = try entry(container); return ([],[],anchor,false) }
    func beginWrite(_ id: InodeID, handle: String) async throws { throw denied }
    func authorizeWrite(_ id: InodeID, refresh: Bool) async throws { throw denied }
    func write(id: InodeID?, fields: ItemMetadata, contents: CacheFileRef?, baseVersion: String?) async throws -> ItemMetadata { throw denied }
    func writeRange(_ id: InodeID, offset: Int, data: Data, baseVersion: String?) async throws -> Int { throw denied }
    func truncate(_ id: InodeID, newSize: Int, baseVersion: String?) async throws { throw denied }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws { throw denied }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata { throw denied }
    func setContentPolicy(_ id: InodeID, policy: ContentPolicy) async throws { throw denied }
    func requestDownload(_ id: InodeID, range: (offset: Int, length: Int)?) async throws -> PrefetchAck { throw denied }
    func evict(_ id: InodeID) async throws -> EvictAck { throw denied }
    func writeStreamRange(_ id: InodeID, name: String, offset: Int, data: Data) async throws -> Int { throw denied }
    func truncateStream(_ id: InodeID, name: String, size: Int) async throws { throw denied }
    func writeStream(_ id: InodeID, name: String, data: Data) async throws { throw denied }
    func deleteStream(_ id: InodeID, name: String) async throws { throw denied }
}
