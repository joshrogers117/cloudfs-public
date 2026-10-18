// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import CloudFSTransfer

/// Hold actual URLSession requests without blocking its callback thread. Tests
/// release already-admitted I/O, then observe parked admissions deterministically.
private final class PauseBlobProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var held: Set<String> = []
    nonisolated(unsafe) private static var pending: [PauseBlobProtocol] = []
    nonisolated(unsafe) private static var requests: [String] = []
    nonisolated(unsafe) private static var objects: [String: Data] = [:]
    private let stateLock = NSLock()
    private var finished = false
    static func reset(hold: Set<String>) { lock.withLock { held = hold; pending = []; requests = []; objects = [:] } }
    static func seed(_ key: String, bytes: Data) { lock.withLock { objects[key] = bytes } }
    static func count(_ method: String) -> Int { lock.withLock { requests.filter { $0 == method }.count } }
    static func release(_ method: String) {
        let released = lock.withLock { () -> [PauseBlobProtocol] in
            held.remove(method)
            let values = pending.filter { $0.request.httpMethod == method }
            pending.removeAll { $0.request.httpMethod == method }
            return values
        }
        for item in released { item.finish() }
    }
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "blob.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let parked = Self.lock.withLock { () -> Bool in
            let method = request.httpMethod ?? "GET"
            Self.requests.append(method)
            if Self.held.contains(method) { Self.pending.append(self); return true }
            return false
        }
        if !parked { finish() }
    }
    private func finish() {
        stateLock.withLock {
            guard !finished else { return }
            finished = true
            let key = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?
                .queryItems?.first { $0.name == "key" }?.value ?? ""
            let bytes = Self.lock.withLock { Self.objects[key] }
            let isPut = request.httpMethod == "PUT"
            let status = isPut || bytes != nil ? 200 : 404
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: [:])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: isPut ? Data() : bytes ?? Data())
            client?.urlProtocolDidFinishLoading(self)
        }
    }
    override func stopLoading() { stateLock.withLock { finished = true } }
}

private actor PauseLeaseGate {
    private(set) var entered = false
    private var open = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async -> Int? {
        entered = true
        if !open { await withCheckedContinuation { waiters.append($0) } }
        return 1
    }
    func release() { open = true; let all = waiters; waiters = []; for waiter in all { waiter.resume() } }
}

final class TransferPauseTests: XCTestCase {
    private struct Fixture {
        let root: URL
        let cache: DiskBlockCache
        let crypto: AESGCMBlockCrypto
        let gateway: MockGateway
        let journal: WriteBackJournal
        let engine: RealTransferEngine
    }
    private func fixture(hold: Set<String> = [], lease: PauseLeaseGate? = nil) throws -> Fixture {
        PauseBlobProtocol.reset(hold: hold)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("transfer-pause-\(UUID())")
        let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 73, count: 32))
        let gateway = MockGateway(), journal = WriteBackJournal(cacheDir: root.path)
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [PauseBlobProtocol.self]
        let session = URLSession(configuration: config)
        let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
            blob: BlobTransport(session: session, policy: RetryPolicy(maxAttempts: 1)), blockSize: 4096,
            prefetchConcurrency: 2, uploadConcurrency: 1, journal: journal, maxUploadRetries: 0,
            uploadDebounceMs: 0, leaseFence: { _, _ in await lease?.wait() })
        addTeardownBlock {
            PauseBlobProtocol.release("GET"); PauseBlobProtocol.release("PUT")
            await lease?.release()
            await engine.shutdown(filespace: "fs")
            session.invalidateAndCancel()
            try? FileManager.default.removeItem(at: root)
        }
        return Fixture(root: root, cache: cache, crypto: crypto, gateway: gateway, journal: journal, engine: engine)
    }
    private func until(_ condition: () async -> Bool, file: StaticString = #filePath, line: UInt = #line) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await condition()) {
            guard ContinuousClock.now < deadline else {
                XCTFail("Pause condition timed out", file: file, line: line)
                throw EngineError(.syncTimeout)
            }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    private func seed(_ fixture: Fixture, item: InodeID, blocks: Int) async throws -> ResolvedBlockManifest {
        var refs: [BlockRef] = []
        for index in 0..<blocks {
            let (ciphertext, hash) = try await fixture.crypto.encryptBlock(Data(repeating: UInt8(index + 1), count: 4096), itemID: item, blockIndex: index)
            PauseBlobProtocol.seed(hash.objectKey, bytes: ciphertext)
            refs.append(BlockRef(hash: hash, offset: index * 4096, length: 4096))
        }
        let manifest = BlockManifest(itemID: item, blocks: refs, contentVersion: "1")
        fixture.gateway.manifests[item] = manifest
        return ResolvedBlockManifest(manifest: manifest, objectKeys: [:])
    }
    private func committedBytes(_ fixture: Fixture, item: InodeID) async throws -> Data {
        let manifest = try XCTUnwrap(fixture.gateway.putManifests.last { $0.itemID == item })
        var bytes = Data()
        for (index, block) in manifest.blocks.enumerated() {
            let cached = try await fixture.cache.readBlock(block.hash)
            bytes.append(try await fixture.crypto.decryptBlock(XCTUnwrap(cached), itemID: item, blockIndex: index))
        }
        return bytes
    }

    func testPauseStopsQueuedOrdinaryPUTsAndResumesTheSameJournaledImage() async throws {
        let f = try fixture(hold: ["PUT"])
        let bytes = Data(repeating: 38, count: 4 * 4096)
        try await f.engine.stageReplace(filespace: "fs", itemID: "upload", data: bytes, baseVersion: "1", fence: nil)
        try await until {
            let pool = await f.engine.uploadPayloadMetrics()
            return PauseBlobProtocol.count("PUT") == 1 && pool.queuedDemand == 2
        }
        _ = try await f.engine.pause(filespace: "fs")
        PauseBlobProtocol.release("PUT")
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 3 }
        XCTAssertEqual(PauseBlobProtocol.count("PUT"), 1, "already admitted PUT may finish; queued blocks must remain parked")
        let pool = await f.engine.uploadPayloadMetrics()
        XCTAssertEqual(pool.active, 0, "pause must not hold a payload permit")
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        let journal = try await f.journal.replay()
        XCTAssertEqual(journal.first?.size, bytes.count)
        let current = try await f.engine.current(filespace: "fs")
        XCTAssertTrue(current.allSatisfy { $0.state == .paused })
        _ = try await f.engine.resume(filespace: "fs")
        let result = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 3000)
        XCTAssertTrue(result.inSync)
        let committed = try await committedBytes(f, item: "upload")
        XCTAssertEqual(committed, bytes)
        XCTAssertEqual(PauseBlobProtocol.count("PUT"), 4)
        let empty = try await f.journal.replay()
        XCTAssertTrue(empty.isEmpty)
    }

    func testFinishingLastInflightPUTWhilePausedCannotCommitTheManifest() async throws {
        let f = try fixture(hold: ["PUT"])
        try await f.engine.stageReplace(filespace: "fs", itemID: "upload", data: Data("retained".utf8), baseVersion: "1", fence: nil)
        try await until { PauseBlobProtocol.count("PUT") == 1 }
        _ = try await f.engine.pause(filespace: "fs")
        PauseBlobProtocol.release("PUT")
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 1 }
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        let retained = try await f.journal.replay()
        XCTAssertEqual(retained.count, 1)
        _ = try await f.engine.resume(filespace: "fs")
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 3000)
        XCTAssertEqual(f.gateway.putManifests.count, 1)
        XCTAssertEqual(PauseBlobProtocol.count("PUT"), 1, "resume should reuse the completed immutable object")
    }

    func testPauseDuringCommitLeaseDoesNotHoldMutationGateOrCommitSupersededBytes() async throws {
        let lease = PauseLeaseGate(), f = try fixture(lease: lease)
        try await f.engine.stageReplace(filespace: "fs", itemID: "upload", data: Data("old".utf8), baseVersion: "1", fence: nil)
        try await until { await lease.entered }
        _ = try await f.engine.pause(filespace: "fs")
        await lease.release()
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 1 }
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        try await f.engine.stageReplace(filespace: "fs", itemID: "upload", data: Data("new".utf8), baseVersion: "1", fence: nil)
        _ = try await f.engine.resume(filespace: "fs")
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 3000)
        let committed = try await committedBytes(f, item: "upload")
        XCTAssertEqual(committed, Data("new".utf8))
        XCTAssertEqual(f.gateway.putManifests.count, 1)
        let waiting = await f.engine.pausedWaiterCount(filespace: "fs")
        XCTAssertEqual(waiting, 0)
    }

    func testPausedPrefetchCanBePromotedByDemandWithoutResumingOtherBackgroundWork() async throws {
        let f = try fixture(hold: ["GET"])
        let resolved = try await seed(f, item: "prefetch", blocks: 3)
        let warm = Task { try await f.engine.prefetch(filespace: "fs", path: "prefetch", itemID: "prefetch") }
        defer { warm.cancel() }
        try await until { PauseBlobProtocol.count("GET") == 2 }
        _ = try await f.engine.pause(filespace: "fs")
        PauseBlobProtocol.release("GET")
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 1 }
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 2)
        let download = await f.engine.downloadSchedulingMetrics()
        XCTAssertEqual(download.pool.active, 0)
        try await f.engine.ensureBlocks(resolved: resolved, filespace: "fs", itemID: "prefetch", offset: 8192, length: 4096)
        _ = try await warm.value
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 3, "foreground demand must fetch the parked block exactly once")
        let promoted = await f.engine.downloadSchedulingMetrics()
        XCTAssertEqual(promoted.promotions, 1)

        let other = try await seed(f, item: "pin", blocks: 1)
        let pin = Task { try await f.engine.ensureBlocks(resolved: other, filespace: "fs", itemID: "pin", offset: 0, length: 4096, background: true) }
        defer { pin.cancel() }
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 1 }
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 3, "demand promotion must not resume unrelated pin downloads")
        _ = try await f.engine.resume(filespace: "fs")
        try await pin.value
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 4)
    }

    func testCancellationAndShutdownReleasePausedWaitersWithoutDroppingJournal() async throws {
        let f = try fixture()
        let resolved = try await seed(f, item: "pin", blocks: 1)
        _ = try await f.engine.pause(filespace: "fs")
        let cancelled = Task { try await f.engine.prefetch(filespace: "fs", path: "pin", itemID: "pin") }
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 1 }
        cancelled.cancel()
        do { _ = try await cancelled.value; XCTFail("cancelled prefetch completed") } catch is CancellationError {}
        let pin = Task { try await f.engine.ensureBlocks(resolved: resolved, filespace: "fs", itemID: "pin", offset: 0, length: 4096, background: true) }
        try await f.engine.stageReplace(filespace: "fs", itemID: "upload", data: Data("saved".utf8), baseVersion: "1", fence: nil)
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 2 }
        await f.engine.shutdown(filespace: "fs")
        do { try await pin.value; XCTFail("closed pin completed") } catch { }
        let waiting = await f.engine.pausedWaiterCount(filespace: "fs")
        XCTAssertEqual(waiting, 0)
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 0)
        XCTAssertEqual(PauseBlobProtocol.count("PUT"), 0)
        let retained = try await WriteBackJournal(cacheDir: f.root.path).replay()
        XCTAssertEqual(retained.first?.size, 5)
    }

    func testBackgroundGETQueuedBeforePauseReleasesItsPermitAndRemainsPromotable() async throws {
        let f = try fixture(hold: ["GET"])
        let first = try await seed(f, item: "foreground", blocks: 2)
        let foreground = Task { try await f.engine.ensureBlocks(resolved: first, filespace: "fs", itemID: "foreground", offset: 0, length: 8192) }
        defer { foreground.cancel() }
        try await until { PauseBlobProtocol.count("GET") == 2 }
        let second = try await seed(f, item: "background", blocks: 1)
        let background = Task { try await f.engine.ensureBlocks(resolved: second, filespace: "fs", itemID: "background", offset: 0, length: 4096, background: true) }
        defer { background.cancel() }
        try await until { await f.engine.downloadSchedulingMetrics().pool.queuedDemand == 1 }
        _ = try await f.engine.pause(filespace: "fs")
        PauseBlobProtocol.release("GET")
        try await foreground.value
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 1 }
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 2, "a background permit queued before pause cannot start a GET afterward")
        let parked = await f.engine.downloadSchedulingMetrics()
        XCTAssertEqual(parked.pool.active, 0, "background pause must release the permit needed by foreground reads")
        try await f.engine.ensureBlocks(resolved: second, filespace: "fs", itemID: "background", offset: 0, length: 4096)
        try await background.value
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 3)
        let done = await f.engine.downloadSchedulingMetrics()
        XCTAssertEqual(done.promotions, 1)
        XCTAssertEqual(done.pool.active, 0)
    }

    func testPausedUploaderDoesNotFetchAnUncachedTruncateBoundaryFromItsQueuedPermit() async throws {
        let f = try fixture(hold: ["GET"])
        let demand = try await seed(f, item: "foreground", blocks: 2)
        let base = try await seed(f, item: "truncate", blocks: 1)
        let foreground = Task { try await f.engine.ensureBlocks(resolved: demand, filespace: "fs", itemID: "foreground", offset: 0, length: 8192) }
        defer { foreground.cancel() }
        try await until { PauseBlobProtocol.count("GET") == 2 }

        // The truncate ACK needs only its captured base manifest. Its uploader
        // must later fetch/decrypt the uncached block to retain the first half.
        try await f.engine.stageTruncate(filespace: "fs", itemID: "truncate", newSize: 2048, baseVersion: "1", fence: nil)
        try await until { await f.engine.downloadSchedulingMetrics().pool.queuedDemand == 1 }
        _ = try await f.engine.pause(filespace: "fs")
        PauseBlobProtocol.release("GET")
        try await foreground.value
        try await until { await f.engine.pausedWaiterCount(filespace: "fs") == 1 }
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 2, "the uploader's queued read-modify-write GET must honor pause")
        let resident = await f.cache.contains(base.manifest.blocks[0].hash)
        XCTAssertFalse(resident, "pause must park before downloading the truncate boundary")
        XCTAssertEqual(PauseBlobProtocol.count("PUT"), 0)
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        let retained = try await f.journal.replay()
        XCTAssertEqual(retained.first?.size, 2048)
        XCTAssertTrue(retained.first?.baseCaptured == true)

        _ = try await f.engine.resume(filespace: "fs")
        let synced = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 3000)
        XCTAssertTrue(synced.inSync)
        XCTAssertEqual(PauseBlobProtocol.count("GET"), 3)
        XCTAssertEqual(PauseBlobProtocol.count("PUT"), 1)
        let committed = try await committedBytes(f, item: "truncate")
        XCTAssertEqual(committed, Data(repeating: 1, count: 2048))
    }
}
