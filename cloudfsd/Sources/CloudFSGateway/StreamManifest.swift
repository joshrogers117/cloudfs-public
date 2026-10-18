// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// Sparse, ranged named-stream metadata. Omitted chunks and bytes beyond a
/// chunk's stored plaintext length are zeroes, never remote uninitialized data.
public struct StreamBlock: Sendable, Codable, Equatable {
    public var index: Int
    public var hash: String
    public var length: Int
    public var objectKey: String
    public init(index: Int, hash: String, length: Int, objectKey: String) {
        self.index = index; self.hash = hash; self.length = length; self.objectKey = objectKey
    }
}
public struct StreamManifest: Sendable, Codable, Equatable {
    public var format: Int
    public var exists: Bool
    public var size: Int
    public var version: Int
    public var blockSize: Int
    public var legacy: Bool
    public var blocks: [StreamBlock]
    public init(size: Int, version: Int, exists: Bool = true, legacy: Bool = false, blocks: [StreamBlock] = []) {
        format = 1; self.exists = exists; self.size = size; self.version = version; blockSize = 1 << 20
        self.legacy = legacy; self.blocks = blocks
    }
}
public struct StreamManifestUpdate: Sendable, Codable {
    public let format: Int
    public let blockSize: Int
    public let size: Int
    public let expectedVersion: Int
    public let fence: Int?
    public let blocks: [StreamBlock]
    public init(size: Int, expectedVersion: Int, fence: Int?, blocks: [StreamBlock]) {
        format = 1; blockSize = 1 << 20
        self.size = size; self.expectedVersion = expectedVersion; self.fence = fence; self.blocks = blocks
    }
}
public extension GatewayClient {
    func streamManifest(filespace: FilespaceID, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        throw EngineError(.unimplemented, "Chunked named streams require a compatible gateway")
    }
    func updateStreamManifest(filespace: FilespaceID, id: InodeID, name: String, update: StreamManifestUpdate) async throws -> StreamManifest {
        throw EngineError(.unimplemented, "Chunked named streams require a compatible gateway")
    }
    func snapshotStreamManifest(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        throw EngineError(.unimplemented, "Chunked snapshot streams require a compatible gateway")
    }
}
public extension HttpGatewayClient {
    func streamManifest(filespace: FilespaceID, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        try await sendJSON(StreamManifest.self, "GET", path: "/v1/filespaces/\(pathEscape(filespace))/items/\(pathEscape(id.rawValue))/streams/\(pathEscape(name))/manifest",
                           query: [URLQueryItem(name: "offset", value: String(offset)), URLQueryItem(name: "length", value: String(length))])
    }
    func updateStreamManifest(filespace: FilespaceID, id: InodeID, name: String, update: StreamManifestUpdate) async throws -> StreamManifest {
        try await sendJSON(StreamManifest.self, "PUT", path: "/v1/filespaces/\(pathEscape(filespace))/items/\(pathEscape(id.rawValue))/streams/\(pathEscape(name))/manifest", body: JSONEncoder().encode(update))
    }
    func snapshotStreamManifest(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        try await sendJSON(StreamManifest.self, "GET", path: "/v1/filespaces/\(pathEscape(filespace))/snapshots/\(pathEscape(snapshotID))/items/\(pathEscape(id.rawValue))/streams/\(pathEscape(name))/manifest",
                           query: [URLQueryItem(name: "offset", value: String(offset)), URLQueryItem(name: "length", value: String(length))])
    }
}
