// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSTransfer

final class StorageTelemetryTests: XCTestCase {
    final class Clock: @unchecked Sendable {
        let lock = NSLock(); var seconds: Double = 1000
        func now() -> Date { lock.lock(); defer { lock.unlock() }; return Date(timeIntervalSince1970: seconds) }
        func advance(_ n: Double) { lock.lock(); seconds += n; lock.unlock() }
    }
    func testIsolationCancellationConcurrentRatesAndExpiry() {
        let clock = Clock(); let tracker = StorageTelemetryTracker(now: { clock.now() })
        XCTAssertNil(tracker.snapshot("fs").reachability)
        tracker.begin("fs"); tracker.begin("fs")
        tracker.finish("fs", durationMs: 100, failure: nil, downloaded: 1000)
        tracker.finish("fs", durationMs: 200, failure: nil, downloaded: 2000, uploaded: 400)
        var s = tracker.snapshot("fs")
        XCTAssertEqual(s.requests, 2); XCTAssertEqual(s.activeRequests, 0)
        XCTAssertEqual(s.downloadBytesPerSecond, 3000); XCTAssertEqual(s.uploadBytesPerSecond, 400)
        XCTAssertEqual(s.requestDurationMs!, 120, accuracy: 0.01)
        XCTAssertEqual(tracker.snapshot("other").requests, 0)
        tracker.begin("fs"); tracker.finish("fs", durationMs: nil, failure: nil, cancelled: true)
        XCTAssertEqual(tracker.snapshot("fs").failures, 0)
        tracker.begin("fs"); tracker.finish("fs", durationMs: 10, failure: "HTTP 503")
        XCTAssertEqual(tracker.snapshot("fs").reachability, "degraded")
        tracker.retry("fs"); tracker.begin("fs"); tracker.finish("fs", durationMs: 10, failure: nil)
        s = tracker.snapshot("fs"); XCTAssertEqual(s.reachability, "online"); XCTAssertEqual(s.retries, 1)
        clock.advance(10)
        XCTAssertEqual(tracker.snapshot("fs").downloadBytesPerSecond, 0)
        clock.advance(21)
        XCTAssertNil(tracker.snapshot("fs").reachability); XCTAssertNil(tracker.snapshot("fs").requestDurationMs)
    }
    func testRealTransportRecordsRetriesAndPayloadBytes() async throws {
        BlobURLProtocol.reset()
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [BlobURLProtocol.self]
        let session = URLSession(configuration: config); defer { session.invalidateAndCancel() }
        let transport = BlobTransport(session: session, policy: RetryPolicy(baseDelayMs: 0, sleep: { _ in }))
        let url = "https://blob.test/telemetry?secret=never-record"
        BlobURLProtocol.serveGET(url, Data(repeating: 1, count: 123)); BlobURLProtocol.failFirst(1, on: url)
        let bytes = try await transport.get(url: url, filespace: "fs")
        XCTAssertEqual(bytes.count, 123)
        let s = transport.telemetry.snapshot("fs")
        XCTAssertEqual(s.requests, 2); XCTAssertEqual(s.retries, 1); XCTAssertEqual(s.failures, 1)
        XCTAssertEqual(s.lastFailureReason, "HTTP 503"); XCTAssertEqual(s.reachability, "online")
        XCTAssertGreaterThan(s.downloadBytesPerSecond, 0); XCTAssertEqual(s.activeRequests, 0)
    }
}
