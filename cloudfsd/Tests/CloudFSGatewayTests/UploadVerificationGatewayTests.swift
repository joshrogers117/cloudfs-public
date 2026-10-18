// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSGateway

final class UploadVerificationGatewayTests: XCTestCase {
    func testVerificationSendsExactUploadedIdentityAndEscapesInodeWithoutPublishingManifest() async throws {
        StubURLProtocol.reset()
        let session = URLSession.stubbed()
        defer { session.invalidateAndCancel() }
        let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gateway.test", token: "test-token"), session: session)
        StubURLProtocol.on("POST /v1/filespaces/fs/blocks/folder/file/verify", json: #"{"verified":1}"#)
        let object = UploadedBlockVerification(objectKey: "blocks/org::fs/" + String(repeating: "a", count: 64), blockHash: String(repeating: "a", count: 64), length: 1024)
        try await client.verifyUploadedBlocks(filespace: "fs", itemID: "folder/file", blocks: [object])
        let request = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(StubURLProtocol.requests.count, 1); XCTAssertEqual(request.method, "POST")
        XCTAssertTrue(request.url.absoluteString.contains("folder%2Ffile/verify"))
        let body = try XCTUnwrap(request.body)
        struct Body: Decodable { let blocks: [UploadedBlockVerification] }
        XCTAssertEqual(try JSONDecoder().decode(Body.self, from: body).blocks, [object])
        XCTAssertEqual(request.headers["Authorization"], "Bearer test-token")
    }
    func testEmptyAndOversizedVerificationBatchesFailBeforeNetwork() async throws {
        StubURLProtocol.reset(); let session = URLSession.stubbed()
        defer { session.invalidateAndCancel() }
        let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gateway.test", token: "test-token"), session: session)
        let object = UploadedBlockVerification(objectKey: "blocks/hash", blockHash: "hash", length: 1)
        for blocks in [[], Array(repeating: object, count: 129)] {
            do { try await client.verifyUploadedBlocks(filespace: "fs", itemID: "file", blocks: blocks); XCTFail("Unbounded request sent") }
            catch let error as EngineError { XCTAssertEqual(error.kind, .invalidParams) }
        }
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }
    func testServiceUnavailablePreservesHTTPDateCooldownForOptionalVerification() async throws {
        StubURLProtocol.reset(); let session = URLSession.stubbed()
        defer { session.invalidateAndCancel() }
        let client = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gateway.test", token: "test-token"), session: session)
        let cooldown = "Fri, 09 Oct 2026 23:59:59 GMT"
        StubURLProtocol.on("POST /v1/filespaces/fs/blocks/file/verify", status: 503,
                           json: #"{"error":"service_unavailable"}"#, headers: ["Retry-After": cooldown])
        let object = UploadedBlockVerification(objectKey: "blocks/hash", blockHash: "hash", length: 1)
        do {
            try await client.verifyUploadedBlocks(filespace: "fs", itemID: "file", blocks: [object])
            XCTFail("Unavailable service accepted verification")
        } catch let error as EngineError {
            XCTAssertEqual(error.kind, .gatewayError)
            XCTAssertEqual(error.data?["retryAfter"], .string(cooldown))
        }
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
    }
}
