// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import Security
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import CloudFSTransfer

/// Real crypto/cache + URLSession, with an explicitly simulated 20ms object RTT.
/// Measures scheduling, NOT R2, WAN, or network saturation.
private final class LatencyBlobProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var active = 0
    nonisolated(unsafe) private static var peak = 0
    nonisolated(unsafe) private static var total = 0
    private let instanceLock = NSLock()
    private var finished = false
    static func reset() { lock.withLock { active = 0; peak = 0; total = 0 } }
    static var metrics: (peak: Int, requests: Int) { lock.withLock { (peak, total) } }
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "blob.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        Self.lock.withLock { Self.active += 1; Self.peak = max(Self.peak, Self.active); Self.total += 1 }
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(20)) { [self] in
            instanceLock.lock()
            guard !finished else { instanceLock.unlock(); return }
            finished = true
            Self.lock.withLock { Self.active -= 1 }
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data())
            client?.urlProtocolDidFinishLoading(self)
            instanceLock.unlock()
        }
    }
    override func stopLoading() {
        instanceLock.withLock {
            guard !finished else { return }
            finished = true
            Self.lock.withLock { Self.active -= 1 }
        }
    }
}

final class TransferConcurrencyTests: XCTestCase {
    func testUploadPoolIsParallelAndGloballyBoundedAcrossFiles() async throws {
        LatencyBlobProtocol.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-parallel-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 16 << 20)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 17, count: 32))
        let gateway = MockGateway()
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [LatencyBlobProtocol.self]
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                                        blob: BlobTransport(session: session), blockSize: 4096, uploadConcurrency: 3)
        _ = try await engine.pause(filespace: "fs")
        for name in ["a", "b", "c"] {
            try await engine.stageReplace(filespace: "fs", itemID: InodeID(name), data: Data(repeating: 13, count: 4096 * 8),
                                          baseVersion: nil, fence: nil)
        }
        _ = try await engine.resume(filespace: "fs")
        let state = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        XCTAssertTrue(state.inSync)
        let metrics = LatencyBlobProtocol.metrics
        XCTAssertEqual(metrics.requests, 24)
        XCTAssertGreaterThan(metrics.peak, 1, "PUTs must overlap to hide object-store latency")
        XCTAssertLessThanOrEqual(metrics.peak, 3, "concurrency is bounded across every file, not per file")
        XCTAssertEqual(gateway.putManifests.count, 3)
        for manifest in gateway.putManifests {
            XCTAssertEqual(manifest.blocks.map(\.offset), Array(0..<8).map { $0 * 4096 }, "out-of-order completion must preserve manifest order")
        }
    }

    func testContinuousWritesCoalesceAndCancelledTimersCannotPublishOldImages() async throws {
        LatencyBlobProtocol.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-debounce-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
        let gateway = MockGateway(), configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [LatencyBlobProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
            blob: BlobTransport(session: session), blockSize: 4096,
            journal: WriteBackJournal(cacheDir: root.path), uploadDebounceMs: 100)
        for index in 0..<40 {
            try await engine.stageWrite(filespace: "fs", itemID: "burst", offset: (index % 4) * 4096,
                                        data: Data(repeating: UInt8(index), count: 4096), baseVersion: nil, fence: nil)
            try await Task.sleep(for: .milliseconds(2))
        }
        XCTAssertEqual(LatencyBlobProtocol.metrics.requests, 0, "continuous writes should cancel only idle timers, not repeatedly PUT old blocks")
        let before = try await engine.syncState(filespace: "fs", path: "/")
        XCTAssertFalse(before.inSync)
        let flushed = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 1000)
        XCTAssertTrue(flushed.inSync)
        XCTAssertEqual(LatencyBlobProtocol.metrics.requests, 4)
        let manifest = try XCTUnwrap(gateway.putManifests.last)
        for (index, ref) in manifest.blocks.enumerated() {
            let cached = try await cache.readBlock(ref.hash)
            let ciphertext = try XCTUnwrap(cached)
            let plaintext = try await crypto.decryptBlock(ciphertext, itemID: "burst", blockIndex: index)
            XCTAssertEqual(plaintext, Data(repeating: UInt8(36 + index), count: 4096))
        }
        try await Task.sleep(for: .milliseconds(150))
        XCTAssertEqual(gateway.putManifests.count, 1, "superseded timers must never publish after the explicit flush")
        XCTAssertEqual(LatencyBlobProtocol.metrics.requests, 4)
    }

    func testSupersededUploadHasOneStableIdentityAndNoGhostAfterFlush() async throws {
        LatencyBlobProtocol.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-transfer-identity-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [LatencyBlobProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let engine = RealTransferEngine(cache: try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20),
            crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32)), gateway: MockGateway(),
            blob: BlobTransport(session: session), blockSize: 4096, uploadDebounceMs: 0)
        let stream = engine.progressEvents(filespace: "fs")
        let events = Task { () -> [Transfer] in
            var values: [Transfer] = []
            for await value in stream { values.append(value); if value.state == .done { break } }
            return values
        }
        _ = try await engine.pause(filespace: "fs")
        var identities: Set<String> = []
        for index in 0..<32 {
            try await engine.stageWrite(filespace: "fs", itemID: "file", offset: 0,
                                        data: Data(repeating: UInt8(index), count: 4096), baseVersion: nil, fence: nil)
            try await Task.sleep(for: .milliseconds(1))
            let current = try await engine.current(filespace: "fs")
            XCTAssertEqual(current.count, 1)
            identities.formUnion(current.map(\.id))
        }
        _ = try await engine.resume(filespace: "fs")
        _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 2000)
        let remaining = try await engine.current(filespace: "fs")
        XCTAssertTrue(remaining.isEmpty, "cancelled generations cannot remain active after the latest image commits")
        let observed = await events.value
        XCTAssertEqual(identities.count, 1)
        XCTAssertEqual(Set(observed.map(\.id)), identities)
        XCTAssertEqual(observed.filter { $0.state == .done }.count, 1)
    }

    func testTerminalTransferHistoryIsBoundedWithoutEvictingActiveUploads() async throws {
        LatencyBlobProtocol.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-transfer-history-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [LatencyBlobProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: MockGateway(),
            blob: BlobTransport(session: session), blockSize: 4096)
        let (ciphertext, hash) = try await crypto.encryptBlock(Data("data".utf8), itemID: "cached", blockIndex: 0)
        try await cache.putBlock(hash, plaintext: ciphertext)
        let resolved = ResolvedBlockManifest(manifest: BlockManifest(itemID: "cached", blocks: [BlockRef(hash: hash, offset: 0, length: 4)], contentVersion: "1"), objectKeys: [:])
        _ = try await engine.pause(filespace: "fs")
        try await engine.stageWrite(filespace: "fs", itemID: "pending", offset: 0, data: Data("safe".utf8), baseVersion: nil, fence: nil)
        for _ in 0..<(RealTransferEngine.terminalTransferLimit + 32) {
            try await engine.ensureBlocks(resolved: resolved, filespace: "fs", itemID: "cached", offset: 0, length: 4)
        }
        let count = await engine.retainedTransferCount(filespace: "fs")
        let active = try await engine.current(filespace: "fs")
        XCTAssertEqual(count, RealTransferEngine.terminalTransferLimit + 1)
        XCTAssertEqual(active.map(\.path), ["pending"])
        _ = try await engine.resume(filespace: "fs")
        _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 2000)
        let finalCount = await engine.retainedTransferCount(filespace: "fs")
        let finalActive = try await engine.current(filespace: "fs")
        XCTAssertEqual(finalCount, RealTransferEngine.terminalTransferLimit)
        XCTAssertTrue(finalActive.isEmpty)
    }

    func testExplicitFlushBypassesIdleDelayButRetainsDeadlineAndPendingJournal() async throws {
        LatencyBlobProtocol.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-debounce-flush-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [LatencyBlobProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let journal = WriteBackJournal(cacheDir: root.path)
        let engine = RealTransferEngine(cache: try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20),
            crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32)), gateway: MockGateway(),
            blob: BlobTransport(session: session), blockSize: 4096, journal: journal, uploadDebounceMs: 2000)
        _ = try await engine.pause(filespace: "fs")
        try await engine.stageWrite(filespace: "fs", itemID: "file", offset: 0,
                                    data: Data("durable before upload".utf8), baseVersion: nil, fence: nil)
        do {
            _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 20)
            XCTFail("pause must still enforce the explicit flush deadline")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .syncTimeout) }
        let retained = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(retained.first?.size, Data("durable before upload".utf8).count)
        _ = try await engine.resume(filespace: "fs")
        let state = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 500)
        XCTAssertTrue(state.inSync, "forced flush must not wait for the two-second test idle delay")
        XCTAssertEqual(LatencyBlobProtocol.metrics.requests, 1)
    }

    func testCancellingQueuedPermitDoesNotLeakCapacity() async throws {
        let pool = TransferPermitPool(limit: 1)
        let gate = TestGate()
        let holder = Task { try await pool.withPermit { await gate.hold() } }
        while !(await gate.entered) { await Task.yield() }
        let cancelled = Task { try await pool.withPermit { XCTFail("cancelled waiter must not execute") } }
        await Task.yield()
        cancelled.cancel()
        do { try await cancelled.value; XCTFail("waiting cancellation must propagate") } catch is CancellationError {}
        await gate.release()
        try await holder.value
        let value = try await pool.withPermit { 42 }
        XCTAssertEqual(value, 42)
    }

    func testRepeatableTransferPipelineBenchmark() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_TRANSFER_BENCHMARK"] == "1",
                          "explicit synthetic transfer benchmark; not WAN throughput")
        var data = Data(count: 32 << 20)
        let result = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        XCTAssertEqual(result, errSecSuccess)
        for concurrency in [1, 8] {
            LatencyBlobProtocol.reset()
            let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-benchmark-\(UUID())")
            defer { try? FileManager.default.removeItem(at: root) }
            let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 64 << 20)
            let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
            let cfg = URLSessionConfiguration.ephemeral
            cfg.protocolClasses = [LatencyBlobProtocol.self]
            let session = URLSession(configuration: cfg)
            defer { session.invalidateAndCancel() }
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: MockGateway(),
                                            blob: BlobTransport(session: session), uploadConcurrency: concurrency,
                                            journal: WriteBackJournal(cacheDir: root.path))
            let start = ContinuousClock.now
            try await engine.stageReplace(filespace: "fs", itemID: "benchmark", data: data, baseVersion: nil, fence: nil)
            let acknowledged = ContinuousClock.now
            let state = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 30_000)
            XCTAssertTrue(state.inSync)
            let elapsed = start.duration(to: .now)
            let c = elapsed.components
            let seconds = Double(c.seconds) + Double(c.attoseconds) / 1e18
            FileHandle.standardError.write(Data("SYNTHETIC pipeline: 32 MiB incompressible, journal+crypto+cache, simulated 20ms PUT RTT, concurrency=\(concurrency), peak=\(LatencyBlobProtocol.metrics.peak), ack=\(start.duration(to: acknowledged)), total=\(elapsed), MiB/s=\(32 / seconds)\n".utf8))
        }
    }
}

private actor TestGate {
    var entered = false
    private var continuation: CheckedContinuation<Void, Never>?
    func hold() async {
        entered = true
        await withCheckedContinuation { continuation = $0 }
    }
    func release() { continuation?.resume(); continuation = nil }
}
