// SPDX-License-Identifier: AGPL-3.0-or-later
// cloudfsd — LOCAL DEV gateway (smoke / capstone only; NOT the production path).
//
// The production engine talks to the Cloudflare Workers gateway via
// `HttpGatewayClient` (CloudFSGateway). For the real mount capstone we need
// a metadata + presign source that serves ONE seeded encrypted file end-to-end
// WITHOUT depending on the gateway's `blocks/<org>::<space>/...` object-key layout
// (which differs from the engine's frozen `chunks/<shard>/<hash>` `BlockHash.objectKey`,
// so the real gateway's presign confinement 403s the engine's keys — a cross-module
// integration gap documented in E2E-SMOKE.md).
//
// This client is a drop-in `GatewayClient` that reads a tiny seed JSON describing
// the namespace + per-block presigned GET URLs (e.g. pointing at a local MinIO /
// HTTP server with Range support). Every OTHER part of the read pipeline stays
// 100% real: mount → EngineDataPath → DiskBlockCache → RealTransferEngine →
// BlobTransport (real HTTP range GET) → AES-256-CTR decrypt. Only the remote
// gateway+object-store are replaced by local equivalents (the explicitly-permitted
// fallback for the smoke).
//
// Gated behind `--dev-seed <file>`; absent that flag the daemon uses the real
// HttpGatewayClient exactly as before.

import Foundation
import CloudFSCore
import CloudFSGateway

/// On-disk seed format (JSON). One filespace's namespace + block URL table.
struct DevSeed: Decodable {
    struct Item: Decodable {
        var id: String
        var parent: String?
        var name: String
        var isDir: Bool
        var size: Int
        var contentVersion: String?
        /// Ordered blocks (file items only). `url` is a presigned GET (Range-capable).
        var blocks: [Block]?
    }
    struct Block: Decodable {
        var hash: String     // hex SHA-256 of the CIPHERTEXT (== BlockHash)
        var offset: Int
        var length: Int
        var url: String      // presigned GET URL for this block's ciphertext object
    }
    var filespace: String
    var items: [Item]
}

/// A `GatewayClient` backed by a seed file. Thread-safe (immutable after load).
final class LocalDevGateway: GatewayClient, @unchecked Sendable {
    func authorizeWrite(filespace: FilespaceID, id: InodeID) async throws {
        _ = try await getItem(filespace: filespace, id: id)
    }
    private let seed: DevSeed
    private let itemsByID: [String: DevSeed.Item]
    private let childrenByParent: [String: [DevSeed.Item]]
    /// objectKey (chunks/<shard>/<hash>) → presigned GET URL.
    private let urlByObjectKey: [String: String]

    init(seedPath: String) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: seedPath))
        let seed = try JSONDecoder().decode(DevSeed.self, from: data)
        self.seed = seed
        var byID: [String: DevSeed.Item] = [:]
        var byParent: [String: [DevSeed.Item]] = [:]
        var byKey: [String: String] = [:]
        for item in seed.items {
            byID[item.id] = item
            let parent = item.parent ?? "root"
            byParent[parent, default: []].append(item)
            for b in item.blocks ?? [] {
                byKey[BlockHash(hex: b.hash).objectKey] = b.url
            }
        }
        self.itemsByID = byID
        self.childrenByParent = byParent
        self.urlByObjectKey = byKey
    }

    var filespaceID: FilespaceID { seed.filespace }

    private func metadata(_ i: DevSeed.Item) -> ItemMetadata {
        ItemMetadata(id: InodeID(i.id), parent: i.parent.map { InodeID($0) },
                     name: i.name, isDir: i.isDir, size: i.size,
                     contentVersion: i.contentVersion ?? "cv-\(i.id)",
                     metadataVersion: "1")
    }

    func presign(filespace: FilespaceID, key: String, method: PresignMethod,
                 expiresIn: Int?) async throws -> PresignedURL {
        guard method == .GET || method == .HEAD else {
            throw EngineError(.permissionDenied, "dev gateway is read-only (got \(method))")
        }
        guard let url = urlByObjectKey[key] else {
            throw EngineError(.notFound, "dev gateway: no presigned URL for key \(key)")
        }
        return PresignedURL(url: url, expiresIn: expiresIn ?? 900)
    }

    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest {
        guard let item = itemsByID[itemID.rawValue], let blocks = item.blocks else {
            throw EngineError(.notFound, "dev gateway: no block manifest for \(itemID.rawValue)")
        }
        let refs = blocks.map { BlockRef(hash: BlockHash(hex: $0.hash), offset: $0.offset, length: $0.length) }
        return BlockManifest(itemID: itemID, blocks: refs,
                             contentVersion: item.contentVersion ?? "cv-\(item.id)")
    }

    /// Explicit (not the protocol-extension default) — a default impl dispatched via
    /// an `any GatewayClient` existential can fault on some toolchains. The dev seed
    /// keys blocks by content address, so that is the upload key too.
    func uploadObjectKey(filespace: FilespaceID, blockHash: BlockHash) async -> String {
        blockHash.objectKey
    }

    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata {
        throw EngineError(.permissionDenied, "dev gateway is read-only")
    }

    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata {
        throw EngineError(.permissionDenied, "dev gateway is read-only")
    }

    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata {
        throw EngineError(.permissionDenied, "dev gateway is read-only")
    }

    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws {
        throw EngineError(.permissionDenied, "dev gateway is read-only")
    }

    // Explicit (not the protocol-extension default — existential dispatch of a default impl
    // faults on some toolchains). The dev gateway is read-only.
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata {
        throw EngineError(.permissionDenied, "dev gateway is read-only")
    }

    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws
        -> (items: [ItemMetadata], cursor: String?) {
        let kids = childrenByParent[parent.rawValue] ?? []
        return (kids.map(metadata), nil)
    }

    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata {
        guard let item = itemsByID[id.rawValue] else {
            throw EngineError(.notFound, "dev gateway: unknown item \(id.rawValue)")
        }
        return metadata(item)
    }

    func changes(filespace: FilespaceID, since: Int?) async throws
        -> (anchor: Int, items: [ItemMetadata], cursor: Int?) {
        (0, [], nil)
    }
}
