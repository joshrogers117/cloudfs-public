// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// Binds the existing verified byte downloader to immutable snapshot manifests.
/// No operation can fall through to the live namespace or mint write URLs.
public actor SnapshotReadGateway: GatewayClient {
    private let base: any GatewayClient
    private let source: FilespaceID
    private let snapshotID: String
    private var owners: [String: InodeID] = [:]
    private var streamOwners: [String: InodeID] = [:]
    private var streamOrder: [String] = []
    private var manifestKeys: [InodeID: [String]] = [:]
    private var manifestOrder: [InodeID] = []
    public init(base: any GatewayClient, filespace: FilespaceID, snapshotID: String) {
        self.base = base; source = filespace; self.snapshotID = snapshotID
    }
    private var denied: EngineError { EngineError(.permissionDenied, "Snapshots are read-only") }
    public func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata {
        try await base.snapshotItem(filespace: source, snapshotID: snapshotID, id: id)
    }
    public func mountRoots(filespace: FilespaceID) async throws -> [FilespaceMountRoot] {
        try await base.snapshotMountInfo(filespace: source, snapshotID: snapshotID).roots
    }
    public func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) {
        try await base.snapshotItems(filespace: source, snapshotID: snapshotID, parent: parent, cursor: cursor)
    }
    public func getResolvedBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> ResolvedBlockManifest {
        let manifest = try await base.snapshotManifest(filespace: source, snapshotID: snapshotID, itemID: itemID)
        registerManifest(manifest, itemID: itemID)
        return manifest
    }
    /// Bounded local presign routing only. The server independently verifies
    /// every key against this exact frozen inode before issuing a URL.
    public func registerManifest(_ manifest: ResolvedBlockManifest, itemID: InodeID) {
        if manifestKeys[itemID] == nil {
            while manifestOrder.count >= 128 {
                let old = manifestOrder.removeFirst()
                for key in manifestKeys.removeValue(forKey: old) ?? [] where owners[key] == old { owners[key] = nil }
            }
            manifestKeys[itemID] = Array(manifest.objectKeys.values)
            manifestOrder.append(itemID)
        }
        for key in manifest.objectKeys.values { owners[key] = itemID }
    }
    public func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest {
        try await getResolvedBlockManifest(filespace: filespace, itemID: itemID).manifest
    }
    public func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL {
        let results = try await presignBatch(filespace: filespace, keys: [(key, method)], expiresIn: expiresIn)
        guard let url = results.first?.url else { throw denied }
        return PresignedURL(url: url, expiresIn: 60)
    }
    public func presignBatch(filespace: FilespaceID, keys: [(key: String, method: PresignMethod)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        var groups: [InodeID: [String]] = [:]
        for entry in keys {
            guard entry.method == .GET, let id = owners[entry.key] ?? streamOwners[entry.key] else { throw denied }
            groups[id, default: []].append(entry.key)
        }
        var results: [String: PresignBatchResult] = [:]
        for (id, group) in groups {
            for start in stride(from: 0, to: group.count, by: 256) {
                let batch = Array(group[start..<min(start + 256, group.count)])
                for result in try await base.snapshotPresign(filespace: source, snapshotID: snapshotID, itemID: id, keys: batch) {
                    results[result.key] = result
                }
            }
        }
        return keys.map { results[$0.key] ?? PresignBatchResult(key: $0.key, url: nil, error: "not_authorized") }
    }
    public func authorizeWrite(filespace: FilespaceID, id: InodeID) async throws { throw denied }
    public func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata { throw denied }
    public func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata { throw denied }
    public func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws { throw denied }
    public func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata { throw denied }
    public func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { throw denied }
    public func listStreams(filespace: FilespaceID, id: InodeID) async throws -> [StreamInfo] { try await base.snapshotStreams(filespace: source, snapshotID: snapshotID, id: id) }
    public func streamManifest(filespace: FilespaceID, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        let result = try await base.snapshotStreamManifest(filespace: source, snapshotID: snapshotID, id: id, name: name, offset: offset, length: length)
        for block in result.blocks where streamOwners[block.objectKey] == nil {
            while streamOrder.count >= 512 { streamOwners.removeValue(forKey: streamOrder.removeFirst()) }
            streamOwners[block.objectKey] = id; streamOrder.append(block.objectKey)
        }
        return result
    }
    public func readStream(filespace: FilespaceID, id: InodeID, name: String) async throws -> Data { try await base.snapshotStream(filespace: source, snapshotID: snapshotID, id: id, name: name) }
    public func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int) async throws { throw denied }
    public func deleteStream(filespace: FilespaceID, id: InodeID, name: String) async throws { throw denied }
}
