// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CryptoKit
import CloudFSCore
import CloudFSGateway
import CloudFSCrypto
import CloudFSCache

/// Bounded named-stream I/O. The server stores sparse per-chunk rows and applies
/// deltas with stream CAS + the parent inode's writer fence. No write is accepted
/// locally: successful return requires immutable object PUTs AND durable commit.
public actor ChunkedStreamStore {
    public static let blockSize = 1 << 20
    public static let maximumRange = 8 << 20
    public static let maximumSize = (1 << 53) - 1 // exact integer in gateway JSON/SQLite contract
    private let filespace: FilespaceID
    private let gateway: any GatewayClient
    private let crypto: any BlockCrypto
    private let blob: BlobTransport
    private let cache: (any BlockCache)?
    private let pool = TransferPermitPool(limit: 4)
    private struct Key: Hashable { let id: InodeID; let name: String }
    private var mutating = Set<Key>()
    private var waiters: [Key: [CheckedContinuation<Void, Never>]] = [:]

    public init(filespace: FilespaceID, gateway: any GatewayClient, crypto: any BlockCrypto,
                blob: BlobTransport, cache: (any BlockCache)? = nil) {
        self.filespace = filespace; self.gateway = gateway; self.crypto = crypto; self.blob = blob; self.cache = cache
    }
    /// Length-prefixed UTF-8 components remove concatenation/name-hash ambiguity.
    /// A separate inode domain also separates fork chunks from the main data fork
    /// and the old inline FNV-index encoding; each chunk authenticates its index.
    public nonisolated static func cryptoIdentity(_ id: InodeID, name: String) -> InodeID {
        var bytes = Data("CloudFS named stream v1\0".utf8)
        for component in [id.rawValue, name] {
            let data = Data(component.utf8); var count = UInt64(data.count).bigEndian
            withUnsafeBytes(of: &count) { bytes.append(contentsOf: $0) }; bytes.append(data)
        }
        return InodeID("stream-v1:" + SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined())
    }
    public nonisolated static func legacyIndex(_ name: String) -> Int {
        var h: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in name.utf8 { h ^= UInt64(byte); h = h &* 0x0000_0100_0000_01B3 }
        return Int(h & 0x7FFF_FFFF)
    }
    private func acquire(_ key: Key) async {
        if mutating.insert(key).inserted { return }
        await withCheckedContinuation { waiters[key, default: []].append($0) }
    }
    private func release(_ key: Key) {
        if var list = waiters[key], !list.isEmpty {
            let next = list.removeFirst(); waiters[key] = list.isEmpty ? nil : list; next.resume()
        } else { mutating.remove(key) }
    }
    private func extent(_ offset: Int, _ length: Int) throws {
        guard offset >= 0, length >= 0, length <= Self.maximumRange, offset <= Self.maximumSize - length else {
            throw EngineError(.invalidParams, "Invalid named-stream range")
        }
    }
    private func validate(_ manifest: StreamManifest, offset: Int, length: Int) throws {
        guard manifest.format == 1, manifest.blockSize == Self.blockSize, manifest.size >= 0, manifest.size <= Self.maximumSize,
              manifest.version >= 0, manifest.version <= Self.maximumSize, manifest.blocks.count <= 10 else { throw EngineError(.syncFailed, "Invalid stream manifest") }
        var indices = Set<Int>()
        for block in manifest.blocks {
            guard block.index >= 0, block.index <= Int.max / Self.blockSize,
                  block.length > 0, block.length <= Self.blockSize,
                  block.index * Self.blockSize < manifest.size,
                  block.length <= manifest.size - block.index * Self.blockSize,
                  block.hash.count == 64, block.hash.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }),
                  block.objectKey.hasSuffix("/" + block.hash), indices.insert(block.index).inserted,
                  block.index * Self.blockSize < offset + length,
                  length > 0, block.index >= offset / Self.blockSize else {
                throw EngineError(.syncFailed, "Malformed or unrelated stream block")
            }
        }
        guard manifest.exists || (manifest.size == 0 && !manifest.legacy && manifest.blocks.isEmpty) else { throw EngineError(.syncFailed, "Malformed stream tombstone") }
        guard !manifest.legacy || manifest.blocks.isEmpty else { throw EngineError(.syncFailed, "Mixed inline and chunked stream") }
    }
    private func legacy(_ id: InodeID, name: String) async throws -> Data {
        let cipher = try await gateway.readStream(filespace: filespace, id: id, name: name)
        guard cipher.count <= (4 << 20) + 256 else { throw EngineError(.syncFailed, "Legacy stream exceeds its storage format bound") }
        let bytes = try await crypto.decryptBlock(cipher, itemID: id, blockIndex: Self.legacyIndex(name))
        guard bytes.count <= 4 << 20 else { throw EngineError(.syncFailed, "Invalid legacy stream size") }
        return bytes
    }
    private func plaintext(_ block: StreamBlock, id: InodeID, name: String) async throws -> Data {
        let hash = BlockHash(hex: block.hash), crypto = self.crypto, blob = self.blob, cache = self.cache
        let gateway = self.gateway, filespace = self.filespace
        return try await pool.withPermit {
            var cipher: Data?
            if let hit = try? await cache?.readBlock(hash), SHA256.hash(data: hit).map({ String(format: "%02x", $0) }).joined() == block.hash { cipher = hit }
            if cipher == nil {
                let ticket = try await gateway.presign(filespace: filespace, key: block.objectKey, method: .GET, expiresIn: 60)
                let downloaded = try await blob.get(url: ticket.url, filespace: filespace)
                guard downloaded.count <= Self.blockSize + 256,
                      SHA256.hash(data: downloaded).map({ String(format: "%02x", $0) }).joined() == block.hash else {
                    throw EngineError(.syncFailed, "Named-stream ciphertext checksum mismatch")
                }
                cipher = downloaded
                try? await cache?.putBlock(hash, plaintext: downloaded)
            }
            let bytes = try await crypto.decryptBlock(cipher!, itemID: Self.cryptoIdentity(id, name: name), blockIndex: block.index)
            guard bytes.count == block.length else { throw EngineError(.syncFailed, "Named-stream plaintext length mismatch") }
            return bytes
        }
    }
    public func read(_ id: InodeID, name: String, offset: Int, length: Int) async throws -> Data {
        try extent(offset, length)
        if name == "AFP_AfpInfo" { let data = try await legacy(id, name: name); return offset >= data.count ? Data() : data.subdata(in: offset..<min(data.count, offset + length)) }
        let manifest: StreamManifest
        do { manifest = try await gateway.streamManifest(filespace: filespace, id: id, name: name, offset: offset, length: length) }
        catch let error as EngineError where error.kind == .unimplemented {
            let data = try await legacy(id, name: name); return offset >= data.count ? Data() : data.subdata(in: offset..<min(data.count, offset + length))
        }
        try validate(manifest, offset: offset, length: length)
        guard manifest.exists else { throw EngineError(.notFound, "No such stream") }
        if manifest.legacy {
            let data = try await legacy(id, name: name)
            guard data.count == manifest.size else { throw EngineError(.conflict, "Inline stream changed during read") }
            return offset >= data.count ? Data() : data.subdata(in: offset..<min(data.count, offset + length))
        }
        let count = min(length, max(0, manifest.size - offset))
        var result = Data(repeating: 0, count: count)
        try await withThrowingTaskGroup(of: (StreamBlock, Data).self) { group in
            for block in manifest.blocks { group.addTask { (block, try await self.plaintext(block, id: id, name: name)) } }
            for try await (block, bytes) in group {
                let start = block.index * Self.blockSize
                let low = max(start, offset), high = min(start + bytes.count, offset + count)
                if high > low { result.replaceSubrange(low - offset..<high - offset, with: bytes[(low - start)..<(high - start)]) }
            }
        }
        return result
    }
    public func write(_ id: InodeID, name: String, offset: Int, data: Data, fence: Int?) async throws -> Int {
        try extent(offset, data.count)
        return try await mutate(id, name: name, offset: offset, data: data, newSize: nil, fence: fence)
    }
    public func replace(_ id: InodeID, name: String, data: Data, fence: Int?) async throws {
        try extent(0, data.count)
        _ = try await mutate(id, name: name, offset: 0, data: data, newSize: data.count, fence: fence)
    }
    public func truncate(_ id: InodeID, name: String, size: Int, fence: Int?) async throws {
        guard size >= 0, size <= Self.maximumSize else { throw EngineError(.invalidParams, "Invalid stream size") }
        _ = try await mutate(id, name: name, offset: 0, data: Data(), newSize: size, fence: fence)
    }
    public func delete(_ id: InodeID, name: String, fence: Int?) async throws {
        let key = Key(id: id, name: name); await acquire(key); defer { release(key) }; try Task.checkCancellation()
        try await gateway.deleteStream(filespace: filespace, id: id, name: name, fence: fence)
    }
    private func mutate(_ id: InodeID, name: String, offset: Int, data: Data, newSize: Int?, fence: Int?) async throws -> Int {
        let key = Key(id: id, name: name); await acquire(key); defer { release(key) }; try Task.checkCancellation()
        if name == "AFP_AfpInfo" {
            var bytes: Data
            do { bytes = try await legacy(id, name: name) } catch let error as EngineError where error.kind == .notFound { bytes = Data() }
            let size = newSize ?? max(bytes.count, offset + data.count)
            guard size <= 64 << 10 else { throw EngineError(.invalidParams, "FinderInfo metadata exceeds its format bound") }
            if size > bytes.count { bytes.append(Data(repeating: 0, count: size - bytes.count)) } else { bytes = Data(bytes.prefix(size)) }
            if !data.isEmpty { bytes.replaceSubrange(offset..<offset + data.count, with: data) }
            let cipher = try await crypto.encryptBlock(bytes, itemID: id, blockIndex: Self.legacyIndex(name)).ciphertext
            try await gateway.writeStream(filespace: filespace, id: id, name: name, data: cipher, plaintextSize: size, fence: fence)
            return size
        }
        let queryOffset = (!data.isEmpty ? nil : newSize).map { $0 > 0 ? (($0 - 1) / Self.blockSize) * Self.blockSize : 0 } ?? ((offset / Self.blockSize) * Self.blockSize)
        let queryLength = !data.isEmpty || newSize == nil ? offset + data.count - queryOffset : Self.blockSize
        // A supported gateway describes absence with a successful, versioned
        // tombstone. HTTP 404 can mean an old endpoint or an inaccessible inode;
        // never turn that failure into permission to create/replace a stream.
        let manifest = try await gateway.streamManifest(filespace: filespace, id: id, name: name, offset: queryOffset, length: queryLength)
        try validate(manifest, offset: queryOffset, length: queryLength)
        let size = newSize ?? (data.isEmpty ? manifest.size : max(manifest.size, offset + data.count))
        var changes: [Int: Data] = [:]
        if manifest.legacy {
            let original = try await legacy(id, name: name)
            guard original.count == manifest.size else { throw EngineError(.conflict, "Inline stream changed during migration") }
            let retained = min(size, original.count)
            for index in 0..<(retained == 0 ? 0 : (retained - 1) / Self.blockSize + 1) {
                changes[index] = original.subdata(in: index * Self.blockSize..<min(retained, (index + 1) * Self.blockSize))
            }
        }
        if !data.isEmpty {
            let refs = Dictionary(uniqueKeysWithValues: manifest.blocks.map { ($0.index, $0) })
            var changedBytes = false
            for index in offset / Self.blockSize...(offset + data.count - 1) / Self.blockSize {
                let start = index * Self.blockSize, low = max(offset, start), high = min(offset + data.count, start + Self.blockSize)
                var bytes = changes[index] ?? Data()
                if bytes.isEmpty, !(low == start && high == start + Self.blockSize), let old = refs[index] { bytes = try await plaintext(old, id: id, name: name) }
                let original = bytes
                if bytes.count > size - start { bytes = Data(bytes.prefix(size - start)) }
                let required = max(bytes.count, high - start)
                if bytes.count < required { bytes.append(Data(repeating: 0, count: required - bytes.count)) }
                bytes.replaceSubrange(low - start..<high - start, with: data[(low - offset)..<(high - offset)])
                if bytes != original { changedBytes = true }
                changes[index] = bytes
            }
            // Repeated xattr writes are common on macOS (notably the short
            // com.apple.provenance value around atomic saves). Once the existing
            // bytes have been authenticated, an identical write needs no object
            // upload; the fenced manifest commit remains required. Keep sparse size changes and
            // legacy migration behavior below intact.
            if manifest.exists, !manifest.legacy, size == manifest.size, !changedBytes {
                // Retain the fenced/CAS manifest commit below. It validates the
                // writer lease and version even when bytes are identical; only
                // skip the immutable ciphertext upload.
                changes.removeAll(keepingCapacity: true)
            }
        } else if size < manifest.size, size > 0, size % Self.blockSize != 0,
                  let old = manifest.blocks.first(where: { $0.index == size / Self.blockSize }) {
            let bytes = try await plaintext(old, id: id, name: name)
            changes[old.index] = Data(bytes.prefix(size % Self.blockSize))
        }
        let gateway = self.gateway, crypto = self.crypto, blob = self.blob, filespace = self.filespace, pool = self.pool, cache = self.cache
        let blocks = try await withThrowingTaskGroup(of: StreamBlock.self) { group in
            for (index, bytes) in changes {
                group.addTask {
                    let uploaded = try await pool.withPermit {
                        let sealed = try await crypto.encryptBlock(bytes, itemID: Self.cryptoIdentity(id, name: name), blockIndex: index)
                        let objectKey = await gateway.uploadObjectKey(filespace: filespace, blockHash: sealed.hash)
                        let ticket = try await gateway.presignWrite(filespace: filespace, key: objectKey, itemID: id, expiresIn: 60)
                        try await blob.put(url: ticket.url, body: sealed.ciphertext, headers: ticket.headers ?? [:], verificationUrl: ticket.verificationUrl, filespace: filespace)
                        return (StreamBlock(index: index, hash: sealed.hash.hex, length: bytes.count, objectKey: objectKey),
                                sealed.hash, sealed.ciphertext)
                    }
                    // Seed after releasing the payload permit. Cache admission is
                    // useful for later partial writes but should not block uploads.
                    try? await cache?.putBlock(uploaded.1, plaintext: uploaded.2)
                    return uploaded.0
                }
            }
            var blocks: [StreamBlock] = []; for try await block in group { blocks.append(block) }; return blocks.sorted { $0.index < $1.index }
        }
        try Task.checkCancellation()
        let committed = try await gateway.updateStreamManifest(filespace: filespace, id: id, name: name,
            update: StreamManifestUpdate(size: size, expectedVersion: manifest.version, fence: fence, blocks: blocks))
        guard committed.size == size, committed.version > manifest.version, committed.exists, !committed.legacy else { throw EngineError(.syncFailed, "Stream commit was not confirmed") }
        return size
    }
}
