// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSGateway

final class StreamManifestGatewayTests: XCTestCase {
    func testRangedManifestTombstoneAndDeltaPreserveVersionFenceAndSparseIndex() async throws {
        StubURLProtocol.reset()
        let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "test-token"), session: .stubbed())
        let path = "/v1/filespaces/fs/items/opaque-id/streams/AFP_Resource/manifest"
        StubURLProtocol.on("GET " + path, json: #"{"format":1,"exists":false,"legacy":false,"size":0,"version":19,"blockSize":1048576,"blocks":[]}"#)
        let absent = try await client.streamManifest(filespace: "fs", id: "opaque-id", name: "AFP_Resource", offset: 1 << 40, length: 1 << 20)
        XCTAssertFalse(absent.exists); XCTAssertEqual(absent.version, 19)
        let query = URLComponents(url: try XCTUnwrap(StubURLProtocol.requests.last?.url), resolvingAgainstBaseURL: false)?.queryItems
        XCTAssertEqual(query?.first { $0.name == "offset" }?.value, String(1 << 40))
        XCTAssertEqual(query?.first { $0.name == "length" }?.value, "1048576")
        StubURLProtocol.on("PUT " + path, json: #"{"format":1,"exists":true,"legacy":false,"size":1099511627777,"version":20,"blockSize":1048576,"blocks":[]}"#)
        let hash = String(repeating: "a", count: 64), key = "blocks/org::fs/" + hash
        let result = try await client.updateStreamManifest(filespace: "fs", id: "opaque-id", name: "AFP_Resource",
            update: StreamManifestUpdate(size: (1 << 40) + 1, expectedVersion: 19, fence: 27, blocks: [StreamBlock(index: 1 << 20, hash: hash, length: 1, objectKey: key)]))
        XCTAssertTrue(result.exists); XCTAssertEqual(result.version, 20)
        let body = try JSONDecoder().decode(StreamManifestUpdate.self, from: XCTUnwrap(StubURLProtocol.requests.last?.body))
        XCTAssertEqual(body.format, 1); XCTAssertEqual(body.blockSize, 1 << 20); XCTAssertEqual(body.expectedVersion, 19)
        XCTAssertEqual(body.fence, 27); XCTAssertEqual(body.blocks.first?.index, 1 << 20); XCTAssertEqual(body.blocks.first?.objectKey, key)
    }
    func testWriteBatchCarriesPerObjectInodeAndRequiredHeaders() async throws {
        StubURLProtocol.reset()
        let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "token"), session: .stubbed())
        StubURLProtocol.on("POST /v1/filespaces/fs/presign/batch", json: #"{"urls":[{"key":"one","url":"https://put.test/one","headers":{"if-none-match":"*","x-amz-checksum-sha256":"digest"},"verificationUrl":"https://get.test/one"},{"key":"two","error":"inode_denied"}],"expiresIn":300}"#)
        let results = try await client.presignWriteBatch(filespace: "fs", keys: [("one", "inode-one"), ("two", "inode-two")], expiresIn: 60)
        XCTAssertEqual(results.first?.headers?["if-none-match"], "*"); XCTAssertEqual(results.first?.verificationUrl, "https://get.test/one")
        XCTAssertNil(results.last?.url); XCTAssertEqual(results.last?.error, "inode_denied")
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(StubURLProtocol.requests.first?.body)) as? [String: Any])
        let keys = try XCTUnwrap(body["keys"] as? [[String: String]])
        XCTAssertEqual(keys, [["key": "one", "method": "PUT", "itemId": "inode-one"], ["key": "two", "method": "PUT", "itemId": "inode-two"]])
        XCTAssertEqual(body["expiresIn"] as? Int, 60)
    }

    func testSnapshotManifestRequestUsesFrozenEndpointWithRange() async throws {
        StubURLProtocol.reset()
        let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "token"), session: .stubbed())
        let path = "/v1/filespaces/fs/snapshots/frozen/items/inode/streams/AFP_Resource/manifest"
        StubURLProtocol.on("GET " + path, json: #"{"format":1,"exists":true,"legacy":false,"size":5242880,"version":2,"blockSize":1048576,"blocks":[]}"#)
        let manifest = try await client.snapshotStreamManifest(filespace: "fs", snapshotID: "frozen", id: "inode", name: "AFP_Resource", offset: 2 << 20, length: 1 << 20)
        XCTAssertEqual(manifest.size, 5 << 20); XCTAssertEqual(StubURLProtocol.requests.count, 1)
        XCTAssertEqual(StubURLProtocol.requests.first?.url.path, path)
    }
}
