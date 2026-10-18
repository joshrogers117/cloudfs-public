// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

public struct SnapshotGatewayInfo: Sendable, Decodable {
    public struct Snapshot: Sendable, Decodable {
        public let id: String
        public let scope: String
        public let label: String?
        public var name: String? { label }
        public init(id: String, scope: String, name: String? = nil) { self.id = id; self.scope = scope; self.label = name }
    }
    public let snapshot: Snapshot
    public let roots: [FilespaceMountRoot]
    public let streamsCaptured: Bool?
    public init(snapshot: Snapshot, roots: [FilespaceMountRoot], streamsCaptured: Bool? = true) { self.snapshot = snapshot; self.roots = roots; self.streamsCaptured = streamsCaptured }
}
public extension GatewayClient {
    func snapshotStreams(filespace: FilespaceID, snapshotID: String, id: InodeID) async throws -> [StreamInfo] { throw EngineError(.unimplemented, "Snapshot metadata is unavailable") }
    func snapshotStream(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String) async throws -> Data { throw EngineError(.unimplemented, "Snapshot metadata is unavailable") }

    func snapshotMountInfo(filespace: FilespaceID, snapshotID: String) async throws -> SnapshotGatewayInfo { throw EngineError(.unimplemented, "Snapshot mounting is unavailable") }
    func snapshotItem(filespace: FilespaceID, snapshotID: String, id: InodeID) async throws -> ItemMetadata { throw EngineError(.unimplemented, "Snapshot mounting is unavailable") }
    func snapshotItems(filespace: FilespaceID, snapshotID: String, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { throw EngineError(.unimplemented, "Snapshot mounting is unavailable") }
    func snapshotManifest(filespace: FilespaceID, snapshotID: String, itemID: InodeID) async throws -> ResolvedBlockManifest { throw EngineError(.unimplemented, "Snapshot mounting is unavailable") }
    func snapshotPresign(filespace: FilespaceID, snapshotID: String, itemID: InodeID, keys: [String]) async throws -> [PresignBatchResult] { throw EngineError(.unimplemented, "Snapshot mounting is unavailable") }
}
public extension HttpGatewayClient {
    func snapshotStreams(filespace: FilespaceID, snapshotID: String, id: InodeID) async throws -> [StreamInfo] {
        struct Reply: Decodable { let streams: [StreamInfo] }
        return try await sendJSON(Reply.self, "GET", path: snapshotPath(filespace, snapshotID) + "/items/" + pathEscape(id.rawValue) + "/streams").streams
    }
    func snapshotStream(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String) async throws -> Data {
        try await send("GET", path: snapshotPath(filespace, snapshotID) + "/items/" + pathEscape(id.rawValue) + "/streams/" + pathEscape(name))
    }

    private func snapshotPath(_ filespace: FilespaceID, _ snapshotID: String) -> String {
        "/v1/filespaces/\(pathEscape(filespace))/snapshots/\(pathEscape(snapshotID))"
    }
    func snapshotMountInfo(filespace: FilespaceID, snapshotID: String) async throws -> SnapshotGatewayInfo {
        try await sendJSON(SnapshotGatewayInfo.self, "GET", path: snapshotPath(filespace, snapshotID) + "/mount-roots")
    }
    func snapshotItem(filespace: FilespaceID, snapshotID: String, id: InodeID) async throws -> ItemMetadata {
        try await sendJSON(WireItem.self, "GET", path: snapshotPath(filespace, snapshotID) + "/items/" + pathEscape(id.rawValue)).metadata
    }
    func snapshotItems(filespace: FilespaceID, snapshotID: String, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) {
        var query = [URLQueryItem(name: "parent", value: parent.rawValue)]
        if let cursor { query.append(URLQueryItem(name: "cursor", value: cursor)) }
        let result = try await sendJSON(ItemsPage.self, "GET", path: snapshotPath(filespace, snapshotID) + "/page", query: query)
        return (result.items.map(\.metadata), result.cursor)
    }
    func snapshotManifest(filespace: FilespaceID, snapshotID: String, itemID: InodeID) async throws -> ResolvedBlockManifest {
        struct Page: Decodable { let item: WireItem; let blocks: [WireBlock]; let cursor: Int? }
        var refs: [BlockRef] = [], keys: [BlockHash: String] = [:], cursor: Int? = nil, version = ""
        repeat {
            let page = try await sendJSON(Page.self, "GET", path: snapshotPath(filespace, snapshotID) + "/blocks/" + pathEscape(itemID.rawValue),
                                          query: cursor.map { [URLQueryItem(name: "cursor", value: String($0))] } ?? [])
            version = page.item.contentVersion ?? ""
            for block in page.blocks {
                let hash = BlockHash(hex: block.blockHash)
                refs.append(BlockRef(hash: hash, offset: block.offset, length: block.length)); keys[hash] = block.objectKey
            }
            if let next = page.cursor, next <= (cursor ?? -1) { throw EngineError(.gatewayError, "Snapshot block cursor did not advance") }
            cursor = page.cursor
        } while cursor != nil
        return ResolvedBlockManifest(manifest: BlockManifest(itemID: itemID, blocks: refs, contentVersion: version), objectKeys: keys)
    }
    func snapshotPresign(filespace: FilespaceID, snapshotID: String, itemID: InodeID, keys: [String]) async throws -> [PresignBatchResult] {
        struct Body: Encodable { struct Key: Encodable { let key: String; let method = "GET" }; let itemId: String; let keys: [Key] }
        struct Reply: Decodable { struct Entry: Decodable { let key: String; let url: String?; let error: String? }; let results: [Entry] }
        let body = try JSONEncoder().encode(Body(itemId: itemID.rawValue, keys: keys.map { Body.Key(key: $0) }))
        let reply = try await sendJSON(Reply.self, "POST", path: snapshotPath(filespace, snapshotID) + "/presign/batch", body: body)
        return reply.results.map { PresignBatchResult(key: $0.key, url: $0.url, error: $0.error) }
    }
}
