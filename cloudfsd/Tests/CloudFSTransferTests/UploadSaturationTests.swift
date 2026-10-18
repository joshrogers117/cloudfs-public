// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import Security
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import CloudFSTransfer

/// Injected PUT transport: a fixed simulated object-store RTT, recording peak
/// overlap and the summed PUT seconds (effective concurrency = sum / elapsed).
private final class SaturationPutProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var delayMs = 20
    nonisolated(unsafe) private static var active = 0
    nonisolated(unsafe) private static var peak = 0
    nonisolated(unsafe) private static var total = 0
    nonisolated(unsafe) private static var sumSeconds = 0.0
    nonisolated(unsafe) private static var first: ContinuousClock.Instant?
    nonisolated(unsafe) private static var last: ContinuousClock.Instant?
    private let instanceLock = NSLock()
    private var finished = false
    private var began = ContinuousClock.now
    static func reset(delayMs: Int) {
        lock.withLock { self.delayMs = delayMs; active = 0; peak = 0; total = 0; sumSeconds = 0; first = nil; last = nil }
    }
    static var metrics: (peak: Int, requests: Int, sumSeconds: Double, first: ContinuousClock.Instant?, last: ContinuousClock.Instant?) {
        lock.withLock { (peak, total, sumSeconds, first, last) }
    }
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "blob.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        began = .now
        let delay = Self.lock.withLock { () -> Int in
            Self.active += 1; Self.peak = max(Self.peak, Self.active); Self.total += 1
            if Self.first == nil { Self.first = .now }
            return Self.delayMs
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(delay)) { [self] in
            instanceLock.lock()
            guard !finished else { instanceLock.unlock(); return }
            finished = true
            let c = began.duration(to: .now).components
            Self.lock.withLock {
                Self.active -= 1; Self.last = .now
                Self.sumSeconds += Double(c.seconds) + Double(c.attoseconds) / 1e18
            }
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

private actor SaturationGate {
    private var open = false
    private var waiting: [CheckedContinuation<Void, Never>] = []
    func wait() async { if !open { await withCheckedContinuation { waiting.append($0) } } }
    func release() { open = true; let all = waiting; waiting = []; for waiter in all { waiter.resume() } }
}

/// Cache whose admission blocks on a gate: models a slow disk write.
private actor GatedAdmissionCache: BlockCache {
    let base: DiskBlockCache
    let gate: SaturationGate
    private(set) var admissionsEntered = 0
    init(base: DiskBlockCache, gate: SaturationGate) { self.base = base; self.gate = gate }
    func contains(_ hash: BlockHash) async -> Bool { await base.contains(hash) }
    func readBlock(_ hash: BlockHash) async throws -> Data? { try await base.readBlock(hash) }
    func putBlock(_ hash: BlockHash, plaintext: Data) async throws {
        admissionsEntered += 1
        await gate.wait()
        try await base.putBlock(hash, plaintext: plaintext)
    }
    func info(filespace: FilespaceID) async throws -> CacheInfo { try await base.info(filespace: filespace) }
    func setSize(filespace: FilespaceID, bytes: Int) async throws -> CacheInfo { try await base.setSize(filespace: filespace, bytes: bytes) }
    func setLocation(filespace: FilespaceID, path: String) async throws -> CacheInfo { try await base.setLocation(filespace: filespace, path: path) }
    func clear(filespace: FilespaceID) async throws -> CacheInfo { try await base.clear(filespace: filespace) }
    func registerPath(_ path: String, blocks: [BlockHash]) async throws { try await base.registerPath(path, blocks: blocks) }
    func pin(_ path: String, recursive: Bool) async throws -> PinState { try await base.pin(path, recursive: recursive) }
    func unpin(_ path: String, recursive: Bool) async throws -> PinState { try await base.unpin(path, recursive: recursive) }
    func pinList(filespace: FilespaceID) async throws -> [PinState] { try await base.pinList(filespace: filespace) }
    func evict(_ path: String) async throws -> EvictAck { try await base.evict(path) }
}

/// Cache whose admission always fails after the PUT has succeeded.
private actor FailingAdmissionCache: BlockCache {
    let base: DiskBlockCache
    private(set) var attempts = 0
    init(base: DiskBlockCache) { self.base = base }
    func contains(_ hash: BlockHash) async -> Bool { await base.contains(hash) }
    func readBlock(_ hash: BlockHash) async throws -> Data? { try await base.readBlock(hash) }
    func putBlock(_ hash: BlockHash, plaintext: Data) async throws {
        attempts += 1
        throw EngineError(.internal, "cache admission failed")
    }
    func info(filespace: FilespaceID) async throws -> CacheInfo { try await base.info(filespace: filespace) }
    func setSize(filespace: FilespaceID, bytes: Int) async throws -> CacheInfo { try await base.setSize(filespace: filespace, bytes: bytes) }
    func setLocation(filespace: FilespaceID, path: String) async throws -> CacheInfo { try await base.setLocation(filespace: filespace, path: path) }
    func clear(filespace: FilespaceID) async throws -> CacheInfo { try await base.clear(filespace: filespace) }
    func registerPath(_ path: String, blocks: [BlockHash]) async throws { try await base.registerPath(path, blocks: blocks) }
    func pin(_ path: String, recursive: Bool) async throws -> PinState { try await base.pin(path, recursive: recursive) }
    func unpin(_ path: String, recursive: Bool) async throws -> PinState { try await base.unpin(path, recursive: recursive) }
    func pinList(filespace: FilespaceID) async throws -> [PinState] { try await base.pinList(filespace: filespace) }
    func evict(_ path: String) async throws -> EvictAck { try await base.evict(path) }
}

private struct SaturationResult {
    let elapsed: Double, effective: Double, peakPut: Int, requests: Int
    let firstPut: Double, tail: Double, overflow: Int, receiptPeak: Int, verifyRPCs: Int, presignBatches: Int
}

final class UploadSaturationTests: XCTestCase {
    private func seconds(_ d: Duration) -> Double { Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18 }

    private func run(slots: Int, blocks: Int, blockSize: Int, putMs: Int, authMs: Int, verifyMs: Int,
                     random: Bool = false, timeoutMs: Int = 120_000) async throws -> SaturationResult {
        SaturationPutProtocol.reset(delayMs: putMs)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-saturation-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 4 << 30)
        let gateway = MockGateway()
        gateway.simulatedWriteAuthLatencyMs = authMs
        gateway.simulatedVerifyLatencyMs = verifyMs
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [SaturationPutProtocol.self]
        cfg.httpMaximumConnectionsPerHost = 256
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        let engine = RealTransferEngine(cache: cache, crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32)),
            gateway: gateway, blob: BlobTransport(session: session), blockSize: blockSize,
            uploadConcurrency: slots, journal: WriteBackJournal(cacheDir: root.path))
        var data = Data(count: blocks * blockSize)
        if random {
            _ = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        } else {
            data.withUnsafeMutableBytes { raw in for i in stride(from: 0, to: raw.count, by: 8) { raw.storeBytes(of: UInt64(i) &* 0x9E3779B97F4A7C15, toByteOffset: i, as: UInt64.self) } }
        }
        let start = ContinuousClock.now
        try await engine.stageReplace(filespace: "fs", itemID: "saturation", data: data, baseVersion: nil, fence: nil)
        let state = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: timeoutMs)
        XCTAssertTrue(state.inSync)
        let end = ContinuousClock.now
        let elapsed = seconds(start.duration(to: end))
        let m = SaturationPutProtocol.metrics
        let receipts = await engine.uploadReceiptMetrics()
        return SaturationResult(elapsed: elapsed, effective: m.sumSeconds / elapsed, peakPut: m.peak, requests: m.requests,
            firstPut: m.first.map { seconds(start.duration(to: $0)) } ?? -1,
            tail: m.last.map { seconds($0.duration(to: end)) } ?? -1,
            overflow: receipts.dropped, receiptPeak: receipts.peak,
            verifyRPCs: gateway.verifyBatchSizes.count, presignBatches: gateway.writeAuthBatchSizes.count)
    }

    /// Regression: the PUT permit must be released as soon as the object lands.
    /// With ONE slot and cache admission blocked, the second block's PUT must still
    /// be dispatched (before the fix it queued behind the first block's disk write).
    func testPayloadPermitIsReleasedBeforeCacheAdmission() async throws {
        SaturationPutProtocol.reset(delayMs: 5)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-permit-admission-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let gate = SaturationGate()
        let cache = GatedAdmissionCache(base: try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 8 << 20), gate: gate)
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [SaturationPutProtocol.self]
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        let gateway = MockGateway()
        let engine = RealTransferEngine(cache: cache, crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 9, count: 32)),
            gateway: gateway, blob: BlobTransport(session: session), blockSize: 4096, uploadConcurrency: 1)
        try await engine.stageReplace(filespace: "fs", itemID: "f", data: Data((0..<(4096 * 3)).map { UInt8(truncatingIfNeeded: $0 &* 31) }),
                                      baseVersion: nil, fence: nil)
        let flush = Task { try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 10_000) }
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while SaturationPutProtocol.metrics.requests < 3, ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(5)) }
        let during = SaturationPutProtocol.metrics.requests
        var pool = await engine.uploadPayloadMetrics()
        let settle = ContinuousClock.now.advanced(by: .seconds(2))
        while pool.active != 0, ContinuousClock.now < settle { try await Task.sleep(for: .milliseconds(5)); pool = await engine.uploadPayloadMetrics() }
        await gate.release()
        let state = try await flush.value
        XCTAssertEqual(during, 3, "every PUT must dispatch while cache admission is still blocked")
        XCTAssertEqual(pool.active, 0, "no payload permit may be held by cache admission")
        XCTAssertTrue(state.inSync)
        let admitted = await cache.admissionsEntered
        XCTAssertGreaterThanOrEqual(admitted, 3)
    }

    /// PUT succeeded but verified cache admission failed: the block upload must fail,
    /// the journal must be retained, no receipt may be queued, no manifest committed,
    /// and the payload permit must already be free.
    func testCacheAdmissionFailureAfterPUTFailsTheBlockAndRetainsTheJournal() async throws {
        SaturationPutProtocol.reset(delayMs: 5)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-admission-fail-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let cache = FailingAdmissionCache(base: try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 8 << 20))
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [SaturationPutProtocol.self]
        let session = URLSession(configuration: cfg)
        defer { session.invalidateAndCancel() }
        let gateway = MockGateway()
        gateway.simulatedVerifyLatencyMs = 5
        let engine = RealTransferEngine(cache: cache, crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 3, count: 32)),
            gateway: gateway, blob: BlobTransport(session: session), blockSize: 4096, uploadConcurrency: 1,
            journal: WriteBackJournal(cacheDir: root.path), maxUploadRetries: 0)
        try await engine.stageReplace(filespace: "fs", itemID: "f", data: Data(repeating: 5, count: 4096), baseVersion: nil, fence: nil)
        do {
            _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 3000)
            XCTFail("flush must not report success when cache admission failed")
        } catch is EngineError {}
        XCTAssertGreaterThanOrEqual(SaturationPutProtocol.metrics.requests, 1, "the PUT itself succeeded")
        let attempts = await cache.attempts
        XCTAssertGreaterThanOrEqual(attempts, 1)
        XCTAssertTrue(gateway.putManifests.isEmpty, "no manifest commit for the failed generation")
        let retained = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(retained.first?.size, 4096, "journal retained")
        XCTAssertTrue(gateway.verifyBatchSizes.isEmpty, "no receipt for a block whose admission failed")
        let receipts = await engine.uploadReceiptMetrics()
        XCTAssertEqual(receipts.peak, 0)
        let pool = await engine.uploadPayloadMetrics()
        XCTAssertEqual(pool.active, 0, "permit released before admission failed")
    }

    func testCapacityScalesWithUploadConcurrencyWithoutChangingTheDefaults() {
        XCTAssertEqual(RealTransferEngine.receiptCapacity(uploadConcurrency: 32), 512)
        XCTAssertEqual(RealTransferEngine.receiptCapacity(uploadConcurrency: 64), 1024)
        XCTAssertEqual(RealTransferEngine.preparationLimit(uploadConcurrency: 32), 96)
        XCTAssertEqual(RealTransferEngine.preparationLimit(uploadConcurrency: 64), 96)
        XCTAssertEqual(RealTransferEngine.preparationLimit(uploadConcurrency: 1), 3)
    }

    /// A 1,024-block file at 48/64 slots with a slow verification RPC must never
    /// overflow the receipt queue and must reach the full configured PUT overlap.
    func testNoReceiptOverflowAndFullOverlapAt48And64SlotsFor1024Blocks() async throws {
        for slots in [48, 64] {
            let r = try await run(slots: slots, blocks: 1024, blockSize: 4096, putMs: 150, authMs: 20, verifyMs: 600)
            XCTAssertEqual(r.requests, 1024, "slots=\(slots)")
            XCTAssertEqual(r.overflow, 0, "receipt queue overflowed at \(slots) slots")
            XCTAssertEqual(r.peakPut, slots, "PUT overlap must reach the configured slot count")
        }
    }

    /// Presign latency comparable to PUT latency must not starve the payload slots.
    func testSlowAuthorizationDoesNotStarvePayloadSlots() async throws {
        let r = try await run(slots: 32, blocks: 512, blockSize: 4096, putMs: 100, authMs: 100, verifyMs: 50)
        XCTAssertEqual(r.peakPut, 32)
        XCTAssertGreaterThan(r.effective, 32 * 0.5, "effective PUT concurrency \(r.effective)")
    }

    /// Opt-in synthetic saturation table. CLOUDFS_SATURATION_MIB (default 512).
    func testSyntheticSaturationTable() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_SATURATION_BENCH"] == "1", "opt-in synthetic benchmark")
        let mib = Int(ProcessInfo.processInfo.environment["CLOUDFS_SATURATION_MIB"] ?? "") ?? 512
        let putMs = Int(ProcessInfo.processInfo.environment["CLOUDFS_SATURATION_PUT_MS"] ?? "") ?? 350
        let rpcMs = Int(ProcessInfo.processInfo.environment["CLOUDFS_SATURATION_RPC_MS"] ?? "") ?? 100
        var lines = ["SATURATION \(mib) MiB, PUT \(putMs) ms, presign/receipt RPC \(rpcMs) ms",
                     "slots elapsed_s effective_conc peak firstPUT_s tail_s overflow receiptPeak verifyRPCs presignBatches MiB/s"]
        for slots in [32, 48, 64] {
            let r = try await run(slots: slots, blocks: mib, blockSize: 1 << 20, putMs: putMs, authMs: rpcMs, verifyMs: rpcMs, random: true)
            lines.append(String(format: "%d %.2f %.1f %d %.2f %.2f %d %d %d %d %.1f", slots, r.elapsed, r.effective, r.peakPut,
                                r.firstPut, r.tail, r.overflow, r.receiptPeak, r.verifyRPCs, r.presignBatches, Double(mib) / r.elapsed))
        }
        FileHandle.standardError.write(Data((lines.joined(separator: "\n") + "\n").utf8))
    }
}
