// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
@testable import CloudFSTransfer

private final class UploadCooldownProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var retryAfter = "0.1"
    nonisolated(unsafe) private static var moments: [ContinuousClock.Instant] = []
    nonisolated(unsafe) private static var holdFirst = false
    nonisolated(unsafe) private static var firstRequest: UploadCooldownProtocol?
    private let stateLock = NSLock()
    private var finished = false
    static func configure(_ delay: String, hold: Bool = false) { lock.withLock { retryAfter = delay; moments = []; holdFirst = hold; firstRequest = nil } }
    static func releaseFirst() -> ContinuousClock.Instant {
        let (request, delay) = lock.withLock { let value = firstRequest; firstRequest = nil; return (value, retryAfter) }
        let now = ContinuousClock.now
        request?.respond(first: true, delay: delay)
        return now
    }
    static var requests: [ContinuousClock.Instant] { lock.withLock { moments } }
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "blob.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() { stateLock.withLock { finished = true } }
    override func startLoading() {
        let (first, delay, held) = Self.lock.withLock {
            Self.moments.append(.now)
            let first = Self.moments.count == 1, held = Self.moments.count == 1 && Self.holdFirst
            if held { Self.firstRequest = self }
            return (first, Self.retryAfter, held)
        }
        if !held { respond(first: first, delay: delay) }
    }
    private func respond(first: Bool, delay: String) {
        stateLock.withLock {
            guard !finished else { return }; finished = true
            let reply = HTTPURLResponse(url: request.url!, statusCode: first ? 503 : 200,
                                        httpVersion: "HTTP/1.1", headerFields: first ? ["Retry-After": delay] : [:])!
            client?.urlProtocol(self, didReceive: reply, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data())
            client?.urlProtocolDidFinishLoading(self)
        }
    }
}

final class UploadCooldownTests: XCTestCase {
    private func makeEngine(_ root: URL, concurrency: Int = 32) throws -> (RealTransferEngine, URLSession, WriteBackJournal) {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [UploadCooldownProtocol.self]
        let session = URLSession(configuration: config), journal = WriteBackJournal(cacheDir: root.path)
        let engine = RealTransferEngine(cache: try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20),
            crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32)), gateway: MockGateway(),
            blob: BlobTransport(session: session, policy: RetryPolicy(maxAttempts: 1)), blockSize: 1024,
            uploadConcurrency: concurrency, journal: journal, maxUploadRetries: 1, retryBaseDelayMs: 1, uploadDebounceMs: 0)
        return (engine, session, journal)
    }
    func testWholeFileRetryAndExplicitFlushHonorStorageCooldown() async throws {
        UploadCooldownProtocol.configure("0.1")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-upload-cooldown-\(UUID())")
        let (engine, session, journal) = try makeEngine(root)
        defer { session.invalidateAndCancel(); try? FileManager.default.removeItem(at: root) }
        try await engine.stageReplace(filespace: "fs", itemID: "file", data: Data(repeating: 42, count: 1024), baseVersion: nil, fence: nil)
        let committed = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 2000)
        XCTAssertTrue(committed.inSync)
        let attempts = UploadCooldownProtocol.requests
        XCTAssertEqual(attempts.count, 2)
        if attempts.count == 2 { XCTAssertGreaterThanOrEqual(attempts[0].duration(to: attempts[1]), .milliseconds(100)) }
        let entries = try await journal.replay(); XCTAssertTrue(entries.isEmpty)
    }
    func testUnrepresentableCooldownParksWritesWithoutConversionOverflowOrEarlyRetry() async throws {
        UploadCooldownProtocol.configure("1e300")
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-upload-huge-cooldown-\(UUID())")
        let (engine, session, journal) = try makeEngine(root)
        defer { session.invalidateAndCancel(); try? FileManager.default.removeItem(at: root) }
        try await engine.stageReplace(filespace: "fs", itemID: "file", data: Data(repeating: 23, count: 1024), baseVersion: nil, fence: nil)
        do { _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 1000); XCTFail("Impractical cooldown must retain write") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        XCTAssertEqual(UploadCooldownProtocol.requests.count, 1)
        let pending = try await journal.replay(); XCTAssertEqual(pending.first?.size, 1024)
        // A replacement generation must not turn an explicit service cooldown
        // into an early request. Reconnection creates a fresh recovered session.
        try await engine.stageReplace(filespace: "fs", itemID: "file", data: Data(repeating: 24, count: 1024), baseVersion: nil, fence: nil)
        do { _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 1000); XCTFail("New generation bypassed cooldown") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        XCTAssertEqual(UploadCooldownProtocol.requests.count, 1)
        let bytes = try journal.readBlock(filespace: "fs", itemID: "file", blockIndex: 0)
        XCTAssertEqual(bytes, Data(repeating: 24, count: 1024))
    }
    func testAuthorizedQueuedUploadRechecksCooldownAfterObtainingPayloadPermit() async throws {
        UploadCooldownProtocol.configure("0.1", hold: true)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-queued-upload-cooldown-\(UUID())")
        let (engine, session, journal) = try makeEngine(root, concurrency: 1)
        defer { _ = UploadCooldownProtocol.releaseFirst(); session.invalidateAndCancel(); try? FileManager.default.removeItem(at: root) }
        try await engine.stageReplace(filespace: "fs", itemID: "first", data: Data(repeating: 31, count: 1024), baseVersion: nil, fence: nil)
        try await engine.stageReplace(filespace: "fs", itemID: "second", data: Data(repeating: 47, count: 1024), baseVersion: nil, fence: nil)
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while await engine.uploadPayloadMetrics().queuedDemand != 1, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        let queued = await engine.uploadPayloadMetrics(), prepared = await engine.uploadPreparationMetrics()
        XCTAssertEqual(queued.active, 1); XCTAssertEqual(queued.queuedDemand, 1)
        XCTAssertEqual(prepared.active, 2); XCTAssertEqual(prepared.limit, 3)
        let rejectedAt = UploadCooldownProtocol.releaseFirst()
        let result = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 3000)
        XCTAssertTrue(result.inSync)
        let attempts = UploadCooldownProtocol.requests
        XCTAssertEqual(attempts.count, 3)
        for instant in attempts.dropFirst() { XCTAssertGreaterThanOrEqual(rejectedAt.duration(to: instant), .milliseconds(100)) }
        let pending = try await journal.replay(); XCTAssertTrue(pending.isEmpty)
        let drained = await engine.uploadPreparationMetrics()
        XCTAssertEqual(drained.active, 0); XCTAssertEqual(drained.queued, 0); XCTAssertEqual(drained.peak, 2)
    }
}
