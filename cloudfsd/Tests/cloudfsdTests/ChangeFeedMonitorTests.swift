// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSGateway
@testable import cloudfsd

private actor AppliedChanges {
    var anchors: [Int] = []
    var resets: [Bool] = []
    var failAt: Int?
    func fail(_ anchor: Int?) { failAt = anchor }
    func apply(_ page: GatewayChangePage, reset: Bool) throws {
        if page.anchor == failAt { throw EngineError(.syncFailed) }
        anchors.append(page.cursor ?? page.anchor); resets.append(reset)
    }
    func values() -> ([Int], [Bool]) { (anchors, resets) }
}
final class ChangeFeedMonitorTests: XCTestCase {
    private func fixture() -> (HttpGatewayClient, URL) {
        GWStub.reset()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("feed-monitor-" + UUID().uuidString)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return (HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "test"), session: GWStub.session()), directory.appendingPathComponent("cursor.json"))
    }
    func testEmptyFilteredPagesAreAppliedAndCheckpointedBeforeFinalAnchor() async throws {
        let (gateway, checkpoint) = fixture(), applied = AppliedChanges()
        GWStub.on("GET /v1/filespaces/fs/changes") { request in
            let since = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems?.first?.value ?? "0"
            let cursor = since == "0" ? "500" : since == "500" ? "1000" : "null"
            return (200, "{\"anchor\":1203,\"items\":[],\"cursor\":\(cursor),\"visibility\":\"a\"}")
        }
        let monitor = ChangeFeedMonitor(gateway: gateway, filespace: "fs", checkpointURL: checkpoint) { page, reset in
            try await applied.apply(page, reset: reset)
        }
        try await monitor.replay()
        let result = await applied.values()
        XCTAssertEqual(result.0, [500, 1000, 1203]); XCTAssertEqual(result.1, [true, false, false])
        let saved = try JSONSerialization.jsonObject(with: Data(contentsOf: checkpoint)) as! [String: Any]
        XCTAssertEqual(saved["anchor"] as? Int, 1203)
        // Restart forces invalidation of ephemeral state but resumes durable feed position.
        let restarted = ChangeFeedMonitor(gateway: gateway, filespace: "fs", checkpointURL: checkpoint) { page, reset in
            try await applied.apply(page, reset: reset)
        }
        try await restarted.replay()
        let values = await applied.values()
        XCTAssertEqual(values.0, [500,1000,1203,1203]); XCTAssertEqual(values.1.last, true)
    }
    func testConsumerFailureDoesNotAdvanceCheckpointAndVisibilityOnlyChangeResets() async throws {
        let (gateway, checkpoint) = fixture(), applied = AppliedChanges()
        GWStub.on("GET /v1/filespaces/fs/changes", json: #"{"anchor":5,"items":[],"cursor":null,"visibility":"a"}"#)
        let monitor = ChangeFeedMonitor(gateway: gateway, filespace: "fs", checkpointURL: checkpoint) { page, reset in
            try await applied.apply(page, reset: reset)
        }
        await applied.fail(5)
        do { try await monitor.replay(); XCTFail() } catch {}
        XCTAssertFalse(FileManager.default.fileExists(atPath: checkpoint.path))
        await applied.fail(nil); try await monitor.replay()
        GWStub.on("GET /v1/filespaces/fs/changes", json: #"{"anchor":5,"items":[],"cursor":null,"visibility":"b"}"#)
        try await monitor.replay()
        let values = await applied.values()
        XCTAssertEqual(values.1, [true, true])
    }
    func testSignalCannotLoseWakeBetweenObservationAndWaitAndCancelsPromptly() async throws {
        let signal = ChangeSignal()
        let before = await signal.current()
        await signal.signal()
        let after = await signal.wait(after: before)
        XCTAssertNotEqual(after, before)
        let waiter = Task { await signal.wait(after: after) }
        waiter.cancel()
        let result = await waiter.value
        XCTAssertEqual(result, after)
    }
}
