// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSGateway

final class FileManifestGatewayTests: XCTestCase {
    private let blockSize = 1024 * 1024
    private func item(size: Int, version: Int = 4) -> String {
        #"{"id":"file","parent":"root","name":"file","isDir":false,"size":\#(size),"contentVersion":"cv-new","version":\#(version)}"#
    }
    func testBasicInfoWireUsesEpochMillisecondsAndCASWithoutContentMutation() async throws {
        StubURLProtocol.reset(); let session = URLSession.stubbed(); defer { session.invalidateAndCancel() }
        let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://test", token: "token"), session: session)
        StubURLProtocol.on("PATCH /v1/filespaces/fs/items/file/basic-info", json: #"{"id":"file","parent":"root","name":"file","isDir":false,"size":0,"contentVersion":"unchanged","version":5,"createdAt":1000,"modifiedAt":2000,"accessedAt":3000,"changedAt":4000,"fileAttributes":2}"#)
        let updated = try await client.setBasicInfo(filespace: "fs", id: "file", info: BasicFileInfo(modifiedAt: Date(timeIntervalSince1970: 2), fileAttributes: 2), expectedVersion: 4, fence: 8)
        XCTAssertEqual(updated.modifiedAt, Date(timeIntervalSince1970: 2)); XCTAssertEqual(updated.accessedAt, Date(timeIntervalSince1970: 3))
        XCTAssertEqual(updated.fileAttributes, 2); XCTAssertEqual(updated.contentVersion, "unchanged")
        let body = try XCTUnwrap(StubURLProtocol.requests.first?.body)
        let patch = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(patch["modifiedAt"] as? Int, 2000); XCTAssertEqual(patch["expectedVersion"] as? Int, 4)
        XCTAssertEqual(patch["fence"] as? Int, 8); XCTAssertNil(patch["createdAt"])
    }

    func testSmallEditSendsOnlyChangedExtentAndVersionFence() async throws {
        StubURLProtocol.reset(); let session = URLSession.stubbed(); defer { session.invalidateAndCancel() }
        let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://test", token: "token"), session: session, streamingManifests: true)
        let oldHash = BlockHash(hex: String(repeating: "a", count: 64)), newHash = BlockHash(hex: String(repeating: "b", count: 64))
        let oldBlocks = (0..<16384).map { BlockRef(hash: oldHash, offset: $0 * blockSize, length: blockSize) }
        let key = await client.uploadObjectKey(filespace: "fs", blockHash: oldHash)
        let base = ResolvedBlockManifest(manifest: BlockManifest(itemID: "file", blocks: oldBlocks, contentVersion: "old"), objectKeys: [oldHash:key])
        var changed = oldBlocks; changed[8000] = BlockRef(hash: newHash, offset: 8000 * blockSize, length: blockSize)
        StubURLProtocol.on("PATCH /v1/filespaces/fs/blocks/file", json: item(size: 16384 * blockSize))
        _ = try await client.putBlockManifest(BlockManifest(itemID: "file", blocks: changed, contentVersion: ""), filespace: "fs", base: base, blockSize: blockSize, expectedVersion: 3, fence: 7)
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
        let body = try XCTUnwrap(StubURLProtocol.requests.first?.body)
        XCTAssertLessThan(body.count, 1024)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String:Any])
        let blocks = try XCTUnwrap(json["blocks"] as? [[String:Any]])
        XCTAssertEqual(blocks.count, 1); XCTAssertEqual(blocks[0]["chunkIdx"] as? Int, 8000)
        XCTAssertEqual(json["expectedVersion"] as? Int, 3); XCTAssertEqual(json["fence"] as? Int, 7)
    }
    func testOnlyLegacyLayoutFallsBackToFullPublication() async throws {
        for code in ["manifest_layout", "version_conflict", "locked", "forbidden"] {
            StubURLProtocol.reset(); let session = URLSession.stubbed(); defer { session.invalidateAndCancel() }
            let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://test", token: "token"), session: session, streamingManifests: true)
            let hash = BlockHash(hex: "a"), refs = [BlockRef(hash: hash, offset: 0, length: 4)]
            let base = ResolvedBlockManifest(manifest: BlockManifest(itemID: "file", blocks: refs, contentVersion: "old"), objectKeys: [:])
            StubURLProtocol.on("PATCH /v1/filespaces/fs/blocks/file", status: code == "forbidden" ? 403 : 409, json: "{\"error\":\"\(code)\"}")
            StubURLProtocol.on("PUT /v1/filespaces/fs/blocks/file", json: item(size: 4))
            do {
                _ = try await client.putBlockManifest(base.manifest, filespace: "fs", base: base, blockSize: blockSize, expectedVersion: 3, fence: 7)
                XCTAssertEqual(code, "manifest_layout")
            } catch { XCTAssertNotEqual(code, "manifest_layout") }
            XCTAssertEqual(StubURLProtocol.requests.map(\.method), code == "manifest_layout" ? ["PATCH","PUT"] : ["PATCH"])
        }
    }
    func testRangePagesBindVersionAndRejectMixedImagesOrMissingContent() async throws {
        for scenario in ["valid", "changed", "missing"] {
            StubURLProtocol.reset(); let session = URLSession.stubbed(); defer { session.invalidateAndCancel() }
            let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://test", token: "token"), session: session, streamingManifests: true)
            let first = #"{"chunkIdx":0,"blockIdx":0,"blockHash":"a","objectKey":"blocks/a","offset":0,"length":4}"#
            let second = #"{"chunkIdx":1,"blockIdx":0,"blockHash":"b","objectKey":"blocks/b","offset":4,"length":4}"#
            let firstItem = item(size: 8), secondItem = item(size: 8, version: scenario == "changed" ? 5 : 4)
            StubURLProtocol.on("GET /v1/filespaces/fs/blocks/file/range") { request in
                let after = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!.queryItems!.first { $0.name == "after" }!.value!
                let json = after == "-1" ? "{\"format\":1,\"item\":\(firstItem),\"blocks\":[\(first)],\"cursor\":0}"
                    : "{\"format\":1,\"item\":\(secondItem),\"blocks\":[\(scenario == "missing" ? "" : second)],\"cursor\":null}"
                return StubURLProtocol.Stub(status: 200, json: json, headers: [:])
            }
            do {
                let manifest = try await client.getResolvedBlockManifest(filespace: "fs", itemID: "file")
                XCTAssertEqual(scenario, "valid"); XCTAssertEqual(manifest.manifest.blocks.count, 2)
            } catch { XCTAssertNotEqual(scenario, "valid") }
            XCTAssertEqual(StubURLProtocol.requests.count, 2)
            XCTAssertTrue(StubURLProtocol.requests[1].url.query!.contains("version=4"))
        }
    }
}
