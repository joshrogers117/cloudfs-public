// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import cloudfsd

private final class Mode: @unchecked Sendable {
    private let lock = NSLock()
    private var _error: Error?
    var error: Error? { get { lock.lock(); defer { lock.unlock() }; return _error } set { lock.lock(); _error = newValue; lock.unlock() } }
}

/// Minimal gateway: `getItem` throws whatever `mode.error` holds, otherwise unimplemented-free success is
/// not needed — we only need the throw/return distinction, so success returns a fixed item.
private struct ModeGateway: GatewayClient {
    let mode: Mode
    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL { throw EngineError.unimplemented() }
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest { throw EngineError.unimplemented() }
    func uploadObjectKey(filespace: FilespaceID, blockHash: BlockHash) async -> String { "k" }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws { throw EngineError.unimplemented() }
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { throw EngineError.unimplemented() }
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata {
        if let e = mode.error { throw e }
        return ItemMetadata(id: id, parent: nil, name: "x", isDir: true, size: 0, contentVersion: "1", metadataVersion: "1")
    }
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { throw EngineError.unimplemented() }
    func changesWithDeletions(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, updated: [ItemMetadata], deleted: [InodeID], cursor: Int?) { throw EngineError.unimplemented() }
}

final class ReachabilityTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_000_000)
    private func classify(now: TimeInterval, success: TimeInterval?, failure: TimeInterval?) -> EngineStatus.Reachability? {
        GatewayReachabilityTracker.classify(now: t0.addingTimeInterval(now),
                                            lastSuccess: success.map { t0.addingTimeInterval($0) },
                                            lastFailure: failure.map { t0.addingTimeInterval($0) })
    }

    func testNoSamplesIsUnknown() { XCTAssertNil(classify(now: 0, success: nil, failure: nil)) }
    func testRecentSuccessOnlyIsOnline() { XCTAssertEqual(classify(now: 10, success: 5, failure: nil), .online) }
    func testFailureWithNoSuccessEverIsOffline() { XCTAssertEqual(classify(now: 10, success: nil, failure: 5), .offline) }
    func testFailureAfterStaleSuccessIsOffline() { XCTAssertEqual(classify(now: 100, success: 10, failure: 90), .offline) }
    func testFailureAndRecentSuccessIsDegraded() {
        XCTAssertEqual(classify(now: 100, success: 95, failure: 90), .degraded)   // success after failure
        XCTAssertEqual(classify(now: 100, success: 80, failure: 90), .degraded)   // failure after success, success within 30s
    }
    func testOldFailureWithRecentSuccessIsOnline() { XCTAssertEqual(classify(now: 100, success: 99, failure: 20), .online) }
    func testStaleFailureBeforeStaleSuccessIsOnline() { XCTAssertEqual(classify(now: 200, success: 100, failure: 50), .online) }

    func testTrackerRecordsTimesReasonAndLatencyAndSanitizes() {
        let tracker = GatewayReachabilityTracker()
        tracker.recordSuccess("fs", latencyMs: 100, now: t0)
        tracker.recordSuccess("fs", latencyMs: 200, now: t0.addingTimeInterval(1))
        tracker.recordFailure("fs", reason: GatewayReachabilityTracker.sanitize("network: failed https://x.example/a?sig=abc token=SECRET"), now: t0.addingTimeInterval(2))
        let s = tracker.snapshot("fs", now: t0.addingTimeInterval(3))
        XCTAssertEqual(s.latencyMs ?? 0, 120, accuracy: 0.001)   // EWMA 0.8/0.2
        XCTAssertEqual(s.lastSuccessAt, 1_000_001_000)
        XCTAssertEqual(s.lastFailureAt, 1_000_002_000)
        XCTAssertEqual(s.reachability, .degraded)
        XCTAssertFalse(s.lastFailureReason?.contains("SECRET") ?? true)
        XCTAssertFalse(s.lastFailureReason?.contains("x.example") ?? true)
        XCTAssertEqual(tracker.snapshot("other"), GatewayReachabilityTracker.Snapshot())
    }

    func testOnlyTransportAndServerErrorsCountAsFailures() {
        XCTAssertNotNil(GatewayReachabilityTracker.failureReason(for: EngineError(.networkError, "offline")))
        XCTAssertNotNil(GatewayReachabilityTracker.failureReason(for: EngineError(.gatewayError, "HTTP 503")))
        XCTAssertNotNil(GatewayReachabilityTracker.failureReason(for: URLError(.notConnectedToInternet)))
        XCTAssertNil(GatewayReachabilityTracker.failureReason(for: EngineError(.notFound, "gone")))
        XCTAssertNil(GatewayReachabilityTracker.failureReason(for: EngineError(.conflict, "cas")))
        XCTAssertNil(GatewayReachabilityTracker.failureReason(for: CancellationError()))
    }

    func testDecoratorClassifiesRealCallOutcomes() async throws {
        let mode = Mode()
        let tracker = GatewayReachabilityTracker()
        let gw = ReachabilityGateway(base: ModeGateway(mode: mode), tracker: tracker)
        _ = try await gw.getItem(filespace: "fs", id: InodeID("a"))
        XCTAssertEqual(tracker.snapshot("fs").reachability, .online)
        XCTAssertNotNil(tracker.snapshot("fs").latencyMs)

        mode.error = EngineError(.notFound, "missing")        // semantic answer keeps it online
        do { _ = try await gw.getItem(filespace: "fs", id: InodeID("a")); XCTFail() } catch {}
        XCTAssertEqual(tracker.snapshot("fs").reachability, .online)
        XCTAssertNil(tracker.snapshot("fs").lastFailureAt)

        mode.error = EngineError(.networkError, "The Internet connection appears to be offline.")
        do { _ = try await gw.getItem(filespace: "fs", id: InodeID("a")); XCTFail() } catch {}
        let snap = tracker.snapshot("fs")
        XCTAssertNotNil(snap.lastFailureAt)
        XCTAssertTrue(snap.lastFailureReason?.hasPrefix("network:") ?? false)
        XCTAssertEqual(snap.reachability, .degraded)   // failure + a success within the window
    }

    func testCancelledRequestLeavesReachabilityUnchangedButTimeoutRecordsFailure() async throws {
        let mode = Mode()
        let tracker = GatewayReachabilityTracker()
        let gw = ReachabilityGateway(base: ModeGateway(mode: mode), tracker: tracker)
        _ = try await gw.getItem(filespace: "fs", id: InodeID("a"))
        let before = tracker.snapshot("fs")

        // Exactly what GatewayClient.send produces for URLError.cancelled.
        mode.error = EngineError(.networkError, "cancelled")
        do { _ = try await gw.getItem(filespace: "fs", id: InodeID("a")); XCTFail() } catch {}
        let afterCancel = tracker.snapshot("fs")
        XCTAssertNil(afterCancel.lastFailureAt)
        XCTAssertEqual(afterCancel.reachability, .online)
        XCTAssertEqual(afterCancel.lastSuccessAt, before.lastSuccessAt)

        // Cancellation of the surrounding task is also not a failure.
        mode.error = EngineError(.networkError, "The operation couldn\u{2019}t be completed.")
        let task = Task { () -> Void in
            while !Task.isCancelled { await Task.yield() }
            _ = try? await gw.getItem(filespace: "fs", id: InodeID("a"))
        }
        task.cancel(); await task.value
        XCTAssertNil(tracker.snapshot("fs").lastFailureAt)

        // A genuine timeout still counts.
        mode.error = EngineError(.networkError, URLError(.timedOut).localizedDescription)
        do { _ = try await gw.getItem(filespace: "fs", id: InodeID("a")); XCTFail() } catch {}
        XCTAssertNotNil(tracker.snapshot("fs").lastFailureAt)
        XCTAssertTrue(GatewayReachabilityTracker.isCancellationMessage("cancelled"))
        XCTAssertTrue(GatewayReachabilityTracker.isCancellationMessage(URLError(.cancelled).localizedDescription))
        XCTAssertFalse(GatewayReachabilityTracker.isCancellationMessage("The request timed out."))
    }

    func testStatusEncodingKeepsLegacyShapeWhenFieldsAbsent() throws {
        let cache = CacheInfo(filespace: "fs", location: "/c", sizeBytes: 1, usedBytes: 0, pinnedBytes: 0, maxBytes: 1, freeOnVolumeBytes: 1, hitRate: 0)
        let s = EngineStatus(filespace: "fs", connection: .connected, mountPath: nil, latencyMsToBucket: nil,
                             pendingUploads: 0, pendingBytes: 0, cache: cache, health: .green)
        let json = String(decoding: try JSONEncoder().encode(s), as: UTF8.self)
        XCTAssertFalse(json.contains("reachability")); XCTAssertFalse(json.contains("lastFailureAt"))
        let old = try JSONDecoder().decode(EngineStatus.self, from: Data(json.utf8))
        XCTAssertNil(old.reachability)
    }
}
