// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSGateway

final class NotificationCheckpointGatewayTests: XCTestCase {
    private func client() -> HttpGatewayClient {
        StubURLProtocol.reset()
        return HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "test"), session: .stubbed())
    }

    func testCheckpointUsesAuthoritativeHighWaterWithoutTraversingHistory() async throws {
        let gateway = client()
        StubURLProtocol.on("GET /v1/filespaces/fs/changes", json:
            #"{"anchor":1203,"items":[],"cursor":1,"visibility":"member:read"}"#)
        let first = try await gateway.changeCheckpoint(filespace: "fs")
        let second = try await gateway.changeCheckpoint(filespace: "fs")
        XCTAssertEqual(first.anchor, 1203)
        XCTAssertEqual(first, second)
        XCTAssertEqual(StubURLProtocol.requests.count, 2)
        for request in StubURLProtocol.requests {
            let query = URLComponents(url: request.url, resolvingAgainstBaseURL: false)?.queryItems
            XCTAssertEqual(query?.first(where: { $0.name == "limit" })?.value, "1")
            XCTAssertNil(query?.first(where: { $0.name == "since" }))
        }
    }

    func testVisibilityOnlyChangeAndSequenceResetChangeToken() async throws {
        let gateway = client()
        StubURLProtocol.on("GET /v1/filespaces/fs/changes", json: #"{"anchor":7,"visibility":"read-a"}"#)
        let first = try await gateway.changeCheckpoint(filespace: "fs")
        StubURLProtocol.on("GET /v1/filespaces/fs/changes", json: #"{"anchor":7,"visibility":"read-b"}"#)
        let permissions = try await gateway.changeCheckpoint(filespace: "fs")
        StubURLProtocol.on("GET /v1/filespaces/fs/changes", json: #"{"anchor":0,"visibility":"read-b"}"#)
        let restored = try await gateway.changeCheckpoint(filespace: "fs")
        XCTAssertNotEqual(first.token, permissions.token)
        XCTAssertNotEqual(permissions.token, restored.token)
        XCTAssertNotEqual(GatewayChangeCheckpoint(anchor: 0, visibility: nil).token,
                          GatewayChangeCheckpoint(anchor: 0, visibility: "").token)
    }

    func testNegativeOrUnauthorizedCheckpointDoesNotBecomeAnEmptyBaseline() async throws {
        let gateway = client()
        StubURLProtocol.on("GET /v1/filespaces/fs/changes", json: #"{"anchor":-1}"#)
        do { _ = try await gateway.changeCheckpoint(filespace: "fs"); XCTFail("negative anchor accepted") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .gatewayError) }
        StubURLProtocol.on("GET /v1/filespaces/fs/changes", status: 403, json: #"{"error":"forbidden"}"#)
        do { _ = try await gateway.changeCheckpoint(filespace: "fs"); XCTFail("forbidden checkpoint accepted") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
    }

    func testCancelledCheckpointIssuesNoRequest() async throws {
        let gateway = client()
        let work = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await gateway.changeCheckpoint(filespace: "fs")
        }
        do { _ = try await work.value; XCTFail("cancellation ignored") }
        catch is CancellationError {}
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }
}
