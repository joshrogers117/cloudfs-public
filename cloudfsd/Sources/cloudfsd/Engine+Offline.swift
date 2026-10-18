// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway
import CloudFSTransfer

extension CloudFSEngine {
    func invalidateOffline(_ filespace: FilespaceID) {
        try? FileManager.default.removeItem(at: stableStateDirectory(filespace).appendingPathComponent("offline-v1"))
        for path in Array(pinSessions[filespace]?.intents.keys ?? [:].keys) {
            pinSessions[filespace]?.intents[path]?.offlineExpiresAt = nil
        }
    }
    func captureOfflineMetadata(_ filespace: FilespaceID, path: String, identity: String, items: [ItemMetadata],
                                manifests: [InodeID: BlockManifest], roots: [FilespaceMountRoot], anchor: Int, visibility: String) async throws -> OfflineCheckpoint {
        let session = try require(filespace)
        var entries: [OfflineEntry] = [], metadataBytes = 0, blockCount = 0
        for item in items {
            try Task.checkCancellation()
            var streams: [String: OfflineStream] = [:]
            for info in try await gateway.listStreams(filespace: filespace, id: item.id) {
                guard info.size >= 0, info.size <= 128 << 30 else { throw EngineError(.syncFailed, "Stream exceeds offline checkpoint limits") }
                if info.name == "AFP_AfpInfo" {
                    let cipher = try await gateway.readStream(filespace: filespace, id: item.id, name: info.name)
                    let bytes = try await session.crypto.decryptBlock(cipher, itemID: item.id, blockIndex: ChunkedStreamStore.legacyIndex(info.name))
                    guard bytes.count == info.size else { throw EngineError(.conflict, "Named stream changed during pin") }
                    streams[info.name] = OfflineStream(size: info.size, blocks: [], inlineCiphertext: cipher)
                } else {
                    var offset = 0, blocks: [StreamBlock] = [], streamVersion: Int?
                    repeat {
                        let manifest = try await gateway.streamManifest(filespace: filespace, id: item.id, name: info.name, offset: offset, length: min(ChunkedStreamStore.maximumRange,max(0,info.size-offset)))
                        guard manifest.exists, manifest.size == info.size, manifest.format == 1, manifest.blockSize == ChunkedStreamStore.blockSize,
                              streamVersion == nil || streamVersion == manifest.version else { throw EngineError(.conflict, "Named stream changed during pin") }
                        streamVersion = manifest.version
                        if manifest.legacy {
                            let cipher = try await gateway.readStream(filespace: filespace, id: item.id, name: info.name)
                            let bytes = try await session.crypto.decryptBlock(cipher, itemID: item.id, blockIndex: ChunkedStreamStore.legacyIndex(info.name))
                            guard bytes.count == info.size else { throw EngineError(.conflict, "Named stream changed during pin") }
                            streams[info.name] = OfflineStream(size: info.size, blocks: [], inlineCiphertext: cipher); break
                        }
                        blocks += manifest.blocks; blockCount += manifest.blocks.count
                        guard blockCount <= 131_072 else { throw EngineError(.syncFailed, "Offline stream metadata exceeds its bound") }
                        offset += ChunkedStreamStore.maximumRange
                    } while offset < info.size
                    if streams[info.name] == nil { streams[info.name] = OfflineStream(size: info.size, blocks: blocks, inlineCiphertext: nil) }
                }
            }
            let entry = OfflineEntry(item: item, manifest: manifests[item.id], streams: streams)
            metadataBytes += try JSONEncoder().encode(entry).count
            guard metadataBytes <= OfflineCheckpoint.maximumBytes - 65536 else { throw EngineError(.syncFailed, "Offline metadata exceeds 64 MiB; pin a smaller subtree") }
            entries.append(entry)
        }
        let now = Date()
        let result = OfflineCheckpoint(format: 1, identity: identity, filespace: filespace, path: path, roots: roots,
            createdAt: now, expiresAt: now.addingTimeInterval(OfflineCheckpoint.lifetime), anchor: anchor, visibility: visibility, entries: entries)
        try result.validate(identity: identity)
        return result
    }
}
