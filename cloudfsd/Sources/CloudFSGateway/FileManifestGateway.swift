// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

extension HttpGatewayClient {
    public var supportsManifestRanges: Bool { streamingManifests }

    public func getBlockRange(filespace: FilespaceID, itemID: InodeID, contentVersion: String, offset: Int, length: Int) async throws -> ResolvedBlockRange {
        guard offset >= 0, length > 0, length <= 32 << 20, offset <= Int.max-length else { throw EngineError(.invalidParams) }
        struct Page: Decodable { let format: Int; let item: WireItem; let firstBlockIndex: Int; let blocks: [WireBlock]; let nextOffset: Int? }
        var query = [URLQueryItem(name: "offset", value: String(offset)), URLQueryItem(name: "length", value: String(length))]
        if !contentVersion.isEmpty { query.append(URLQueryItem(name: "contentVersion", value: contentVersion)) }
        let page = try await sendJSON(Page.self, "GET", path: "/v1/filespaces/\(filespace)/blocks/\(pathEscape(itemID.rawValue))/range", query: query)
        let item = page.item.metadata
        guard page.format == 2, item.id == itemID, !item.isDir, item.size >= 0,
              contentVersion.isEmpty || item.contentVersion == contentVersion,
              page.firstBlockIndex >= 0, page.firstBlockIndex <= Int.max-page.blocks.count,
              page.blocks.count <= 1024 else { throw EngineError(.gatewayError, "Inconsistent manifest extent") }
        var refs: [BlockRef] = [], keys: [BlockHash:String] = [:]
        var end = page.blocks.first?.offset ?? item.size
        guard offset >= item.size ? page.blocks.isEmpty : end <= offset && !page.blocks.isEmpty else { throw EngineError(.gatewayError, "Missing manifest extent") }
        for block in page.blocks {
            guard block.offset == end, block.length > 0, end <= item.size, block.length <= item.size-end,
                  !block.objectKey.isEmpty else { throw EngineError(.gatewayError, "Invalid manifest extent") }
            let hash = BlockHash(hex: block.blockHash)
            if let previous = keys[hash], previous != block.objectKey { throw EngineError(.gatewayError, "Conflicting object identity") }
            refs.append(BlockRef(hash: hash, offset: end, length: block.length)); keys[hash] = block.objectKey; end += block.length
        }
        guard offset >= item.size || end > offset,
              page.nextOffset == nil ? end >= min(item.size,offset+length) : page.nextOffset == end else { throw EngineError(.gatewayError, "Incomplete manifest extent") }
        return ResolvedBlockRange(item: item, resolved: ResolvedBlockManifest(
            manifest: BlockManifest(itemID: itemID, blocks: refs, contentVersion: item.contentVersion), objectKeys: keys, firstBlockIndex: page.firstBlockIndex))
    }

    /// Every page carries its item/version from the same authority turn. A
    /// concurrent edit rejects continuation; never pair old blocks with new metadata.
    func rangedManifest(filespace: FilespaceID, itemID: InodeID) async throws -> ResolvedBlockManifest {
        struct Page: Decodable { let format: Int; let item: WireItem; let blocks: [WireBlock]; let cursor: Int? }
        var refs: [BlockRef] = [], keys: [BlockHash: String] = [:]
        var after = -1, version: Int?, contentVersion = "", size = 0, end = 0
        while true {
            try Task.checkCancellation()
            var query = [URLQueryItem(name: "after", value: String(after)), URLQueryItem(name: "limit", value: "1024")]
            if let version { query.append(URLQueryItem(name: "version", value: String(version))) }
            let page = try await sendJSON(Page.self, "GET", path: "/v1/filespaces/\(filespace)/blocks/\(pathEscape(itemID.rawValue))/range", query: query)
            guard page.format == 1, page.item.id == itemID.rawValue, !page.item.isDir, page.item.size >= 0,
                  let pageVersion = page.item.version, pageVersion > 0,
                  version == nil || (version == pageVersion && contentVersion == page.item.contentVersion && size == page.item.size),
                  page.blocks.count <= 1024, refs.count + page.blocks.count <= 131_072 else {
                throw EngineError(.gatewayError, "Inconsistent manifest page")
            }
            version = pageVersion; contentVersion = page.item.contentVersion ?? ""; size = page.item.size
            for block in page.blocks {
                guard block.offset == end, block.length > 0, block.length <= size - end else {
                    throw EngineError(.gatewayError, "Incomplete or overlapping file manifest")
                }
                let hash = BlockHash(hex: block.blockHash)
                if let prior = keys[hash], prior != block.objectKey { throw EngineError(.gatewayError, "Conflicting object identity") }
                refs.append(BlockRef(hash: hash, offset: block.offset, length: block.length))
                keys[hash] = block.objectKey; end += block.length
            }
            guard let cursor = page.cursor else {
                guard end == size else { throw EngineError(.gatewayError, "Incomplete file manifest") }
                return ResolvedBlockManifest(manifest: BlockManifest(itemID: itemID, blocks: refs, contentVersion: contentVersion), objectKeys: keys)
            }
            guard cursor > after, cursor == page.blocks.last?.offset else { throw EngineError(.gatewayError, "Invalid manifest continuation") }
            after = cursor
        }
    }

    public func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, base: ResolvedBlockManifest?,
                                 blockSize: Int, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata {
        guard streamingManifests else {
            return try await putBlockManifest(manifest, filespace: filespace, expectedVersion: expectedVersion, fence: fence)
        }
        let size = manifest.blocks.last.map { $0.offset + $0.length } ?? 0
        let fixed = blockSize > 0 && blockSize <= 16 * 1024 * 1024 && manifest.blocks.enumerated().allSatisfy {
            $0.element.offset == $0.offset * blockSize && $0.element.length == min(blockSize, size - $0.element.offset)
        }
        guard fixed else { throw EngineError(.invalidParams, "File blocks do not match the publication layout") }
        var delta: [WireBlock] = []
        // Compare against the journal's original base, never a freshly fetched
        // head. Avoid key minting/encoding work for unchanged extents.
        for (index, block) in manifest.blocks.enumerated() {
            if let base, base.manifest.blocks.indices.contains(index) {
                let previous = base.manifest.blocks[index]
                if previous.hash == block.hash && previous.offset == block.offset && previous.length == block.length { continue }
            }
            let key = await uploadObjectKey(filespace: filespace, blockHash: block.hash)
            delta.append(WireBlock(chunkIdx: index, blockIdx: 0, blockHash: block.hash.hex, objectKey: key, offset: block.offset, length: block.length))
        }
        let path = "/v1/filespaces/\(filespace)/blocks/\(pathEscape(manifest.itemID.rawValue))"
        if base != nil, let expectedVersion, expectedVersion > 0, let fence, fence > 0, delta.count <= 1024 {
            struct Delta: Encodable { let format = 1; let size: Int; let blockSize: Int; let expectedVersion: Int; let fence: Int; let blocks: [WireBlock] }
            do {
                let body = try JSONEncoder().encode(Delta(size: size, blockSize: blockSize, expectedVersion: expectedVersion, fence: fence, blocks: delta))
                return try await sendJSON(WireItem.self, "PATCH", path: path, body: body).metadata
            } catch let error as EngineError where error.data?["error"] == .string("manifest_layout") {
                // Legacy layout is the only fallback. Conflicts, stale leases,
                // permission failures and uncertain replies must remain failures.
            }
        }
        var wire: [WireBlock] = []
        for (index, block) in manifest.blocks.enumerated() {
            let key = await uploadObjectKey(filespace: filespace, blockHash: block.hash)
            wire.append(WireBlock(chunkIdx: index, blockIdx: 0, blockHash: block.hash.hex, objectKey: key, offset: block.offset, length: block.length))
        }
        struct Full: Encodable { let blocks: [WireBlock]; let blockSize: Int; let expectedVersion: Int?; let fence: Int? }
        let body = try JSONEncoder().encode(Full(blocks: wire, blockSize: blockSize, expectedVersion: expectedVersion, fence: fence))
        return try await sendJSON(WireItem.self, "PUT", path: path, body: body).metadata
    }
}
