// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
@testable import CloudFSTransfer

private final class SchedulingHTTPProtocol: URLProtocol, @unchecked Sendable {
    struct Reply: Sendable { var status: Int; var retryAfter: String? = nil; var bytes = Data([1,2,3,4]); var error: URLError? = nil }
    static let lock = NSLock()
    nonisolated(unsafe) static var replies: [Reply] = []
    nonisolated(unsafe) static var calls = 0
    static func configure(_ values: [Reply]) { lock.withLock { replies = values; calls = 0 } }
    static var count: Int { lock.withLock { calls } }
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "schedule.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        let reply = Self.lock.withLock { Self.calls += 1; return Self.replies.isEmpty ? Reply(status: 200) : Self.replies.removeFirst() }
        if let error = reply.error { client?.urlProtocol(self, didFailWithError: error); return }
        let headers = reply.retryAfter.map { ["Retry-After": $0] }
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: "HTTP/1.1", headerFields: headers)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: reply.bytes)
        client?.urlProtocolDidFinishLoading(self)
    }
}
private final class RetryClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant: UInt64 = 0
    private var delays: [Int] = []
    func now() -> UInt64 { lock.withLock { instant } }
    func sleep(_ delay: Int) { lock.withLock { delays.append(delay); instant += UInt64(delay) } }
    var sleeps: [Int] { lock.withLock { delays } }
}
private actor FeedbackLog {
    var values: [BlobTransferFeedback] = []
    func add(_ value: BlobTransferFeedback) { values.append(value) }
}
final class BlobSchedulingTransportTests: XCTestCase {
    private func transport(_ policy: RetryPolicy) -> BlobTransport {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [SchedulingHTTPProtocol.self]
        return BlobTransport(session: URLSession(configuration: config), policy: policy)
    }
    func testServerDelayAndCongestionFeedback() async throws {
        SchedulingHTTPProtocol.configure([.init(status: 429, retryAfter: "2"), .init(status: 200)])
        let clock = RetryClock(), feedback = FeedbackLog()
        var policy = RetryPolicy(baseDelayMs: 0, maxDelayMs: 0, sleep: { clock.sleep($0) })
        policy.nowMilliseconds = { clock.now() }
        let bytes = try await transport(policy).get(url: "https://schedule.test/object", feedback: { await feedback.add($0) })
        XCTAssertEqual(bytes, Data([1,2,3,4])); XCTAssertEqual(clock.sleeps, [2000])
        let values = await feedback.values
        XCTAssertEqual(values, [.overloaded(retryAfter: 2), .success], "429 with Retry-After is server-declared overload")
    }
    func testLongRetryAfterIsPropagatedWithoutEarlyRetry() async throws {
        SchedulingHTTPProtocol.configure([.init(status: 503, retryAfter: "120")])
        let clock = RetryClock()
        var policy = RetryPolicy(maxElapsedMs: 60_000, sleep: { clock.sleep($0) })
        policy.nowMilliseconds = { clock.now() }
        do { _ = try await transport(policy).get(url: "https://schedule.test/object"); XCTFail("should defer") }
        catch let error as EngineError { XCTAssertEqual(error.data?["retryAfter"], .string("120.0")) }
        XCTAssertEqual(SchedulingHTTPProtocol.count, 1); XCTAssertTrue(clock.sleeps.isEmpty)
    }
    func testCancellationAfterBackoffDoesNotMakeAnotherRequest() async throws {
        SchedulingHTTPProtocol.configure([.init(status: 503)])
        let policy = RetryPolicy(sleep: { _ in withUnsafeCurrentTask { $0?.cancel() } })
        let blob = transport(policy)
        let task = Task { try await blob.get(url: "https://schedule.test/object") }
        do { _ = try await task.value; XCTFail("must cancel") } catch is CancellationError {}
        XCTAssertEqual(SchedulingHTTPProtocol.count, 1)
    }
    func testPermanentErrorDoesNotReduceCapacityOrRetry() async throws {
        SchedulingHTTPProtocol.configure([.init(status: 403)])
        let log = FeedbackLog()
        do { _ = try await transport(RetryPolicy()).get(url: "https://schedule.test/object", feedback: { await log.add($0) }); XCTFail("must fail") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        let feedback = await log.values
        XCTAssertTrue(feedback.isEmpty); XCTAssertEqual(SchedulingHTTPProtocol.count, 1)
    }
    func testLostPutResponseStillRequiresExactImmutableBytes() async throws {
        for existing in [Data([1,2,3,4]), Data([1,2,3,5]), Data([1,2,3])] {
            SchedulingHTTPProtocol.configure([.init(status: 0, error: URLError(.networkConnectionLost)), .init(status: 412), .init(status: 200, bytes: existing)])
            let blob = transport(RetryPolicy(baseDelayMs: 0, maxDelayMs: 0, sleep: { _ in }))
            do {
                try await blob.put(url: "https://schedule.test/object", body: Data([1,2,3,4]), headers: ["if-none-match":"*"], verificationUrl: "https://schedule.test/verify")
                XCTAssertEqual(existing, Data([1,2,3,4]))
            } catch let error as EngineError {
                XCTAssertNotEqual(existing, Data([1,2,3,4])); XCTAssertEqual(error.kind, .syncFailed)
            }
            XCTAssertEqual(SchedulingHTTPProtocol.count, 3)
        }
    }
    func testRetryAfterDatesAndInvalidValues() {
        let now = Date(timeIntervalSince1970: 0)
        XCTAssertEqual(BlobTransport.retryAfterSeconds("Thu, 01 Jan 1970 00:00:10 GMT", now: now), 10)
        XCTAssertEqual(BlobTransport.retryAfterSeconds(" 2.5 "), 2.5)
        for value in ["-1", "NaN", "Infinity", "garbage"] { XCTAssertNil(BlobTransport.retryAfterSeconds(value)) }
    }
    func testDedicatedSessionDoesNotArtificiallyCapScheduler() {
        let config = BlobTransport.transferConfiguration()
        XCTAssertGreaterThanOrEqual(config.httpMaximumConnectionsPerHost, 128)
        XCTAssertNil(config.urlCache); XCTAssertNil(config.httpCookieStorage)
        XCTAssertFalse(config.httpShouldSetCookies)
    }
}
