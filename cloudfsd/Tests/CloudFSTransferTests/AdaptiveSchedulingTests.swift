// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import CloudFSTransfer

private actor SchedulingGate {
    private var open = false
    private var waiting: [CheckedContinuation<Void, Never>] = []
    func wait() async { if !open { await withCheckedContinuation { waiting.append($0) } } }
    func release() { open = true; let all = waiting; waiting.removeAll(); for waiter in all { waiter.resume() } }
}
private actor SchedulingOrder {
    var values: [String] = []
    func append(_ value: String) { values.append(value) }
}
private final class SchedulingClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    func now() -> ContinuousClock.Instant { lock.withLock { instant } }
    func advance() { lock.withLock { instant = instant.advanced(by: .seconds(1)) } }
}
private final class SchedulingProgress: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [Int] = []
    func append(_ value: Int) { lock.withLock { recorded.append(value) } }
    var values: [Int] { lock.withLock { recorded } }
}
private actor SchedulingGateway: GatewayClient {
    var gates: [String: SchedulingGate] = [:]
    var requests: [String] = []
    var batchSizes: [Int] = []
    func hold(_ key: String, gate: SchedulingGate) { gates[key] = gate }
    func presignBatch(filespace: FilespaceID, keys: [(key: String, method: PresignMethod)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        requests.append(contentsOf: keys.map(\.key))
        batchSizes.append(keys.count)
        for key in keys { await gates[key.key]?.wait() }
        return keys.map { PresignBatchResult(key: $0.key, url: "https://blob.test/" + $0.key, error: nil) }
    }
    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL { throw EngineError.unimplemented() }
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest { throw EngineError.unimplemented() }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws { throw EngineError.unimplemented() }
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { throw EngineError.unimplemented() }
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { throw EngineError.unimplemented() }
}

/// Deliberately ignores cancellation while cache admission is in progress,
/// like an already-issued filesystem write. Cancellation must drain this work.
private actor SchedulingAdmissionCache: BlockCache {
    let base: DiskBlockCache
    let gate: SchedulingGate
    var entered = false
    var completed = false
    init(base: DiskBlockCache, gate: SchedulingGate) { self.base = base; self.gate = gate }
    func contains(_ hash: BlockHash) async -> Bool { await base.contains(hash) }
    func readBlock(_ hash: BlockHash) async throws -> Data? { try await base.readBlock(hash) }
    func putBlock(_ hash: BlockHash, plaintext: Data) async throws {
        entered = true
        await gate.wait()
        // DiskBlockCache itself correctly checks cancellation. An independent,
        // awaited operation models an OS write already beyond that checkpoint.
        let base = self.base
        try await Task.detached { try await base.putBlock(hash, plaintext: plaintext) }.value
        completed = true
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

/// Returns one deliberately stale miss after another flight has finished.
private actor SchedulingMissCache: BlockCache {
    let base: DiskBlockCache
    let gate: SchedulingGate
    var entered = false
    private var holdNextMiss = true
    init(base: DiskBlockCache, gate: SchedulingGate) { self.base = base; self.gate = gate }
    func contains(_ hash: BlockHash) async -> Bool {
        let shouldHold = holdNextMiss
        holdNextMiss = false
        let resident = await base.contains(hash)
        if shouldHold && !resident { entered = true; await gate.wait() }
        return resident
    }
    func readBlock(_ hash: BlockHash) async throws -> Data? { try await base.readBlock(hash) }
    func putBlock(_ hash: BlockHash, plaintext: Data) async throws { try await base.putBlock(hash, plaintext: plaintext) }
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

final class AdaptiveSchedulingTests: XCTestCase {
    private func until(_ predicate: () async -> Bool, file: StaticString = #filePath, line: UInt = #line) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !(await predicate()) {
            if ContinuousClock.now > deadline {
                XCTFail("Scheduling condition timed out", file: file, line: line)
                throw EngineError(.syncTimeout)
            }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    func testReadAheadLeavesCapacityForNewForegroundDemand() async throws {
        let pool = TransferPermitPool(limit: 4), gate = SchedulingGate(), order = SchedulingOrder()
        let speculative = (0..<4).map { i in Task { try await pool.withPermit(priority: .speculative) { await order.append("s\(i)"); await gate.wait() } } }
        try await until { let m = await pool.metrics(); return m.active == 3 && m.queuedSpeculative == 1 }
        let demand = Task { try await pool.withPermit { await order.append("d"); await gate.wait() } }
        try await until { await order.values.contains("d") }
        let full = await pool.metrics(); XCTAssertEqual(full.active, 4); XCTAssertEqual(full.activeSpeculative, 3)
        await gate.release()
        for task in speculative { try await task.value }; try await demand.value
        let final = await pool.metrics(); XCTAssertEqual(final.active, 0)
    }
    func testPromotionOvertakesSpeculationAndPreservesDemandFIFO() async throws {
        let pool = TransferPermitPool(limit: 2), hold = SchedulingGate(), first = SchedulingGate(), second = SchedulingGate()
        let order = SchedulingOrder()
        let holders = (0..<2).map { _ in Task { try await pool.withPermit { await hold.wait() } } }
        try await until { await pool.metrics().active == 2 }
        let olderSpec = Task { try await pool.withPermit(priority: .speculative) { await order.append("speculative") } }
        try await until { await pool.metrics().queuedSpeculative == 1 }
        let ticket = TransferPermitPool.Ticket(priority: .speculative)
        let promoted = Task { try await pool.withPermit(ticket: ticket) { await order.append("promoted"); await first.wait() } }
        try await until { await pool.metrics().queuedSpeculative == 2 }
        await pool.promote(ticket)
        let demand = Task { try await pool.withPermit { await order.append("demand"); await second.wait() } }
        try await until { await pool.metrics().queuedDemand == 2 }
        await hold.release()
        try await until { await order.values.count == 2 }
        let started = await order.values
        XCTAssertEqual(Set(started), ["promoted", "demand"])
        let mid = await pool.metrics(); XCTAssertEqual(mid.queuedSpeculative, 1)
        await first.release(); await second.release()
        for task in holders { try await task.value }; try await promoted.value; try await demand.value; try await olderSpec.value
        let all = await order.values; XCTAssertEqual(all.last, "speculative")
    }
    func testSpeculativeQueueIsBoundedAndCanceledWaitersReleaseCapacity() async throws {
        let pool = TransferPermitPool(limit: 1, maxSpeculativeWaiters: 2), gate = SchedulingGate()
        let holder = Task { try await pool.withPermit { await gate.wait() } }
        try await until { await pool.metrics().active == 1 }
        let waiting = (0..<2).map { _ in Task { try await pool.withPermit(priority: .speculative) { XCTFail("Canceled speculation ran") } } }
        try await until { await pool.metrics().queuedSpeculative == 2 }
        do { try await pool.withPermit(priority: .speculative) { XCTFail("Unbounded speculation ran") }; XCTFail("Expected shedding") }
        catch is TransferPermitPool.SpeculationDeferred {}
        for task in waiting { task.cancel() }
        for task in waiting { do { try await task.value; XCTFail("Cancellation did not propagate") } catch is CancellationError {} }
        let waitingMetrics = await pool.metrics()
        XCTAssertEqual(waitingMetrics.queuedSpeculative, 0); XCTAssertEqual(waitingMetrics.peakQueuedSpeculative, 2)
        XCTAssertEqual(waitingMetrics.droppedSpeculation, 1)
        await gate.release(); try await holder.value
        let result = try await pool.withPermit { 42 }; XCTAssertEqual(result, 42)
    }
    func testCongestionShrinksAdmissionWithoutRevokingActiveWorkAndRecoversToCeiling() async throws {
        let clock = SchedulingClock(), gate = SchedulingGate()
        let pool = TransferPermitPool(limit: 8, now: { clock.now() })
        let tasks = (0..<8).map { _ in Task { try await pool.withPermit { await gate.wait() } } }
        try await until { await pool.metrics().active == 8 }
        await pool.feedback(.congestion)
        for _ in 0..<8 { await pool.feedback(.congestion); await pool.feedback(.success) }
        let reduced = await pool.metrics()
        XCTAssertEqual(reduced.limit, 6); XCTAssertEqual(reduced.active, 8); XCTAssertEqual(reduced.congestionReductions, 1)
        let queued = Task { try await pool.withPermit { 99 } }
        try await until { await pool.metrics().queuedDemand == 1 }
        clock.advance()
        for _ in 0..<12 { await pool.feedback(.success) }
        let partial = await pool.metrics(); XCTAssertEqual(partial.limit, 7)
        for _ in 0..<14 { await pool.feedback(.success) }
        let recovered = await pool.metrics(); XCTAssertEqual(recovered.limit, 8); XCTAssertEqual(recovered.active, 8)
        await gate.release()
        for task in tasks { try await task.value }
        let result = try await queued.value; XCTAssertEqual(result, 99)
        let final = await pool.metrics(); XCTAssertEqual(final.active, 0); XCTAssertEqual(final.peakActive, 8)
        for _ in 0..<10 { clock.advance(); await pool.feedback(.congestion) }
        let floor = await pool.metrics(); XCTAssertEqual(floor.limit, 4, "floor is max(4, maximum/4)")
    }

    func testSingleIsolatedCongestionSignalIsRecordedButDoesNotReduce() async throws {
        let clock = SchedulingClock(), pool = TransferPermitPool(limit: 32, now: { clock.now() })
        await pool.feedback(.congestion)
        var m = await pool.metrics()
        XCTAssertEqual(m.limit, 32); XCTAssertEqual(m.congestionReductions, 0); XCTAssertEqual(m.isolatedSignals, 1)
        for _ in 0..<3 { clock.advance(); clock.advance(); clock.advance(); await pool.feedback(.congestion) }
        m = await pool.metrics()
        XCTAssertEqual(m.limit, 32, "signals more than two seconds apart are never sustained"); XCTAssertEqual(m.isolatedSignals, 4)
    }
    func testTwoSignalsWithinTwoSecondsReduceOnceAndBurstsCoalesce() async throws {
        let clock = SchedulingClock(), pool = TransferPermitPool(limit: 32, now: { clock.now() })
        await pool.feedback(.congestion); clock.advance(); await pool.feedback(.congestion)
        var m = await pool.metrics(); XCTAssertEqual(m.limit, 24); XCTAssertEqual(m.congestionReductions, 1)
        for _ in 0..<5 { await pool.feedback(.congestion) }
        m = await pool.metrics(); XCTAssertEqual(m.limit, 24, "a burst within half a second is one reduction"); XCTAssertEqual(m.congestionReductions, 1)
    }
    func testServerDeclaredOverloadReducesImmediately() async throws {
        let pool = TransferPermitPool(limit: 32)
        await pool.feedback(.overloaded(retryAfter: 0))
        let m = await pool.metrics(); XCTAssertEqual(m.limit, 24); XCTAssertEqual(m.congestionReductions, 1)
    }
    func testRecoveryByCompletionsNeedsOneLimitWorthOfCleanSuccesses() async throws {
        let clock = SchedulingClock(), pool = TransferPermitPool(limit: 32, now: { clock.now() })
        await pool.feedback(.overloaded(retryAfter: 0)); clock.advance()
        for _ in 0..<23 { await pool.feedback(.success) }
        var m = await pool.metrics(); XCTAssertEqual(m.limit, 24)
        await pool.feedback(.success)
        m = await pool.metrics(); XCTAssertEqual(m.limit, 25); XCTAssertEqual(m.timeRecoveries, 0)
    }
    func testRecoveryByElapsedTimeRestoresOnePermitPerSecondAfterThreeQuietSeconds() async throws {
        let clock = SchedulingClock(), pool = TransferPermitPool(limit: 32, now: { clock.now() })
        await pool.feedback(.overloaded(retryAfter: 0))
        clock.advance(); clock.advance()
        await pool.feedback(.success)
        var m = await pool.metrics(); XCTAssertEqual(m.limit, 24, "not before three quiet seconds")
        clock.advance(); await pool.feedback(.success)
        m = await pool.metrics(); XCTAssertEqual(m.limit, 25); XCTAssertEqual(m.timeRecoveries, 1)
        clock.advance(); clock.advance(); await pool.feedback(.success)
        m = await pool.metrics(); XCTAssertEqual(m.limit, 27)
        for _ in 0..<10 { clock.advance() }
        await pool.feedback(.success)
        m = await pool.metrics(); XCTAssertEqual(m.limit, 32, "time recovery never exceeds the ceiling")
        // A fresh signal restarts the quiet period.
        await pool.feedback(.congestion); clock.advance(); await pool.feedback(.congestion)
        for _ in 0..<2 { clock.advance() }
        await pool.feedback(.success)
        m = await pool.metrics(); XCTAssertEqual(m.limit, 24)
    }
    func testTimeRecoveryWaitsForTheServersRetryAfter() async throws {
        let clock = SchedulingClock(), pool = TransferPermitPool(limit: 32, now: { clock.now() })
        await pool.feedback(.overloaded(retryAfter: 10))
        for _ in 0..<9 { clock.advance(); await pool.feedback(.success) }
        var m = await pool.metrics()
        XCTAssertEqual(m.timeRecoveries, 0, "no time recovery before Retry-After elapses")
        XCTAssertLessThan(m.limit, 32)
        let before = m.limit
        clock.advance(); await pool.feedback(.success)
        m = await pool.metrics()
        XCTAssertEqual(m.timeRecoveries, 1); XCTAssertEqual(m.limit, before + 1)
    }
    func testReductionFloorIsMaxOfFourAndQuarterOfMaximum() async throws {
        for (maximum, expected) in [(32, 8), (8, 4), (2, 2), (64, 16)] {
            let clock = SchedulingClock(), pool = TransferPermitPool(limit: maximum, now: { clock.now() })
            for _ in 0..<40 { await pool.feedback(.overloaded(retryAfter: 0)); clock.advance() }
            let m = await pool.metrics(); XCTAssertEqual(m.limit, expected, "maximum \(maximum)")
        }
    }

    private struct Fixture {
        let root: URL
        let cache: DiskBlockCache
        let gateway: SchedulingGateway
        let engine: RealTransferEngine
        let session: URLSession
        let resolved: ResolvedBlockManifest
        let bytes: [Data]
        let keys: [String]
    }
    private func fixture(blocks: Int = 3, concurrency: Int = 2) async throws -> Fixture {
        BlobURLProtocol.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-demand-scheduling-\(UUID())")
        let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
        let gateway = SchedulingGateway(), config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [BlobURLProtocol.self]
        let session = URLSession(configuration: config)
        let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
            blob: BlobTransport(session: session), blockSize: 1024, prefetchConcurrency: concurrency)
        var refs: [BlockRef] = [], keys: [String] = [], mapping: [BlockHash: String] = [:], bytes: [Data] = []
        for i in 0..<blocks {
            let plaintext = Data(repeating: UInt8(i + 1), count: 1024)
            let (ciphertext, hash) = try await crypto.encryptBlock(plaintext, itemID: "file", blockIndex: i)
            let key = "block-\(i)"; keys.append(key); bytes.append(plaintext); mapping[hash] = key
            refs.append(BlockRef(hash: hash, offset: i * 1024, length: 1024))
            BlobURLProtocol.serveGET("https://blob.test/" + key, ciphertext)
        }
        return Fixture(root: root, cache: cache, gateway: gateway, engine: engine, session: session,
            resolved: ResolvedBlockManifest(manifest: BlockManifest(itemID: "file", blocks: refs, contentVersion: "1"), objectKeys: mapping), bytes: bytes, keys: keys)
    }
    func testDemandPromotesSharedAuthorizationAndSurvivesCancellationOfItsPrefetchOwner() async throws {
        let f = try await fixture(); defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        let firstGate = SchedulingGate(), secondGate = SchedulingGate()
        await f.gateway.hold(f.keys[0], gate: firstGate); await f.gateway.hold(f.keys[1], gate: secondGate)
        let first = Task { try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 1024, priority: .speculative) }
        try await until { await f.gateway.requests.contains(f.keys[0]) }
        let spec = Task { try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 1024, length: 1024, priority: .speculative) }
        try await until { await f.gateway.requests.contains(f.keys[1]) }
        let demand = Task { try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 1024, length: 1024) }
        try await until { await f.engine.downloadSchedulingMetrics().promotions == 1 }
        spec.cancel()
        do { try await spec.value; XCTFail("Canceled prefetch succeeded") } catch is CancellationError {}
        let active = await f.engine.downloadSchedulingMetrics()
        XCTAssertEqual(active.promotions, 1); XCTAssertEqual(active.flights, 2)
        await secondGate.release(); try await demand.value
        let plaintext = try await f.engine.plaintextBlock(f.resolved.manifest.blocks[1], resolved: f.resolved, blockIndex: 1, filespace: "fs", itemID: "file")
        XCTAssertEqual(plaintext, f.bytes[1]); XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[1]), 1)
        first.cancel()
        do { try await first.value; XCTFail("Canceled unrelated prefetch succeeded") } catch is CancellationError {}
        try await until { await f.engine.downloadSchedulingMetrics().pool.active == 0 }
        await firstGate.release()
        XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[0]), 0)
    }
    func testSlowAuthorizationDoesNotOccupyPayloadPermitsOrBlockAnAuthorizedDemand() async throws {
        let f = try await fixture(); defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        let firstGate = SchedulingGate(), secondGate = SchedulingGate()
        await f.gateway.hold(f.keys[0], gate: firstGate); await f.gateway.hold(f.keys[1], gate: secondGate)
        let first = Task { try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 1024) }
        try await until { await f.gateway.requests.contains(f.keys[0]) }
        let second = Task { try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 1024, length: 1024) }
        try await until { await f.gateway.requests.contains(f.keys[1]) }
        let awaitingAuthorization = await f.engine.downloadSchedulingMetrics()
        XCTAssertEqual(awaitingAuthorization.flights, 2)
        XCTAssertEqual(awaitingAuthorization.pool.active, 0, "Metadata round trips must not hold payload capacity")
        try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 2048, length: 1024)
        let plaintext = try await f.engine.plaintextBlock(f.resolved.manifest.blocks[2], resolved: f.resolved, blockIndex: 2, filespace: "fs", itemID: "file")
        XCTAssertEqual(plaintext, f.bytes[2])
        XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[2]), 1)
        first.cancel(); second.cancel()
        for task in [first, second] {
            do { try await task.value; XCTFail("Canceled authorization succeeded") } catch is CancellationError {}
        }
        await firstGate.release(); await secondGate.release()
        XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[0]), 0)
        XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[1]), 0)
        let final = await f.engine.downloadSchedulingMetrics(); XCTAssertEqual(final.pool.active, 0); XCTAssertEqual(final.flights, 0)
    }

    func testColdWindowUsesOneCoherentAuthorizationInsteadOfPerBlockRoundTrips() async throws {
        let f = try await fixture(blocks: 32, concurrency: 16)
        defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        let progress = SchedulingProgress()
        try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 32 * 1024,
                                        progress: { progress.append($0) })
        let batches = await f.gateway.batchSizes; XCTAssertEqual(batches, [32])
        XCTAssertEqual(progress.values, (1...32).map { $0 * 1024 })
        for i in 0..<32 {
            let bytes = try await f.engine.plaintextBlock(f.resolved.manifest.blocks[i], resolved: f.resolved, blockIndex: i, filespace: "fs", itemID: "file")
            XCTAssertEqual(bytes, f.bytes[i])
            XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[i]), 1)
        }
        let final = await f.engine.downloadSchedulingMetrics(); XCTAssertEqual(final.pool.active, 0); XCTAssertEqual(final.flights, 0)
        XCTAssertLessThanOrEqual(final.pool.peakActive, 16)
    }

    func testSlidingProgressWaitsForCacheAdmissionAndFutureAuthorizationFetchesNoExtraBytes() async throws {
        let f = try await fixture(blocks: 4)
        defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        let gate = SchedulingGate(), cache = SchedulingAdmissionCache(base: f.cache, gate: gate)
        let progress = SchedulingProgress()
        let engine = RealTransferEngine(cache: cache,
            crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32)), gateway: f.gateway,
            blob: BlobTransport(session: f.session), blockSize: 1024, prefetchConcurrency: 2)
        let task = Task {
            try await engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 1024,
                                          priority: .speculative, authorizationLookAheadBlocks: 32,
                                          progress: { progress.append($0) })
        }
        try await until { await cache.entered }
        XCTAssertTrue(progress.values.isEmpty, "queued or decrypting bytes cannot release unfinished-work budget")
        let authorization = await f.gateway.requests; XCTAssertEqual(Set(authorization), Set(f.keys))
        await gate.release(); try await task.value
        XCTAssertEqual(progress.values, [1024])
        for i in 0..<4 { XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[i]), i == 0 ? 1 : 0) }
        let bytes = try await engine.plaintextBlock(f.resolved.manifest.blocks[0], resolved: f.resolved, blockIndex: 0, filespace: "fs", itemID: "file")
        XCTAssertEqual(bytes, f.bytes[0])
    }

    func testSingleBlockSlidingRefillsAuthorizeFutureMetadataInWholeCohorts() async throws {
        let f = try await fixture(blocks: 128, concurrency: 16)
        defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        for i in 0..<33 {
            try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: i * 1024, length: 1024,
                                            priority: .speculative, authorizationLookAheadBlocks: 32)
        }
        try await until { await f.gateway.requests.count == 96 }
        let batches = await f.gateway.batchSizes; XCTAssertEqual(batches, [32, 32, 32], "one-block payload refills must not become one-RPC-per-block metadata traffic")
        for i in 0..<128 { XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[i]), i < 33 ? 1 : 0) }
    }
    func testCancelLastSubscriberReleasesPermitDuringSharedAuthorizationWithoutFetchingOrAdmittingBytes() async throws {
        let f = try await fixture(); defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        let gate = SchedulingGate(); await f.gateway.hold(f.keys[0], gate: gate)
        let abandoned = Task { try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 1024, priority: .speculative) }
        try await until { await f.gateway.requests.contains(f.keys[0]) }
        abandoned.cancel()
        do { try await abandoned.value; XCTFail("Canceled read succeeded") } catch is CancellationError {}
        try await until { let m = await f.engine.downloadSchedulingMetrics(); return m.pool.active == 0 && m.flights == 0 }
        try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 2048, length: 1024)
        await gate.release()
        let contains = await f.cache.contains(f.resolved.manifest.blocks[0].hash)
        XCTAssertFalse(contains); XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[0]), 0)
    }
    func testLateCacheMissAfterAnotherFlightFinishesDoesNotDownloadAgain() async throws {
        let f = try await fixture(blocks: 1); defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        let gate = SchedulingGate(), cache = SchedulingMissCache(base: f.cache, gate: gate)
        let engine = RealTransferEngine(cache: cache,
            crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32)), gateway: f.gateway,
            blob: BlobTransport(session: f.session), blockSize: 1024, prefetchConcurrency: 2)
        let lateMiss = Task {
            try await engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 1024, priority: .speculative)
        }
        try await until { await cache.entered }
        try await engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 1024)
        let finished = await engine.downloadSchedulingMetrics(); XCTAssertEqual(finished.flights, 0)
        await gate.release()
        try await lateMiss.value
        XCTAssertEqual(BlobURLProtocol.getCount("https://blob.test/" + f.keys[0]), 1,
                       "A cache miss observed before admission must not cause a second GET after the first flight retires")
        let signed = await f.gateway.requests; XCTAssertEqual(signed.count, 1)
        let bytes = try await engine.plaintextBlock(f.resolved.manifest.blocks[0], resolved: f.resolved, blockIndex: 0, filespace: "fs", itemID: "file")
        XCTAssertEqual(bytes, f.bytes[0])
        do {
            _ = try await engine.plaintextBlock(f.resolved.manifest.blocks[0], resolved: f.resolved, blockIndex: 0, filespace: "fs", itemID: "wrong-inode")
            XCTFail("Residency recheck bypassed cached-block authentication")
        } catch {}
    }
    func testLastCancellationDrainsCacheAdmissionBeforeCallerCanEvict() async throws {
        let f = try await fixture(blocks: 1); defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        let gate = SchedulingGate(), order = SchedulingOrder()
        let cache = SchedulingAdmissionCache(base: f.cache, gate: gate)
        let engine = RealTransferEngine(cache: cache,
            crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32)), gateway: f.gateway,
            blob: BlobTransport(session: f.session), blockSize: 1024, prefetchConcurrency: 2)
        let task = Task {
            do {
                try await engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 1024, priority: .speculative)
                await order.append("done")
            } catch { await order.append("done"); throw error }
        }
        try await until { await cache.entered }
        task.cancel()
        try await until { await engine.downloadSchedulingMetrics().abandoned == 1 }
        let before = await order.values; XCTAssertTrue(before.isEmpty, "Cancellation returned while cache admission could still mutate disk")
        await gate.release()
        do { try await task.value; XCTFail("Canceled task succeeded") } catch is CancellationError {}
        let completed = await cache.completed; XCTAssertTrue(completed)
        _ = try await cache.clear(filespace: "fs")
        let after = await cache.contains(f.resolved.manifest.blocks[0].hash); XCTAssertFalse(after)
        let drained = await engine.downloadSchedulingMetrics(); XCTAssertEqual(drained.pool.active, 0); XCTAssertEqual(drained.flights, 0)
    }
    func testDemandCannotShareAnotherInodesSuccessfulAuthentication() async throws {
        let f = try await fixture(blocks: 1); defer { f.session.invalidateAndCancel(); try? FileManager.default.removeItem(at: f.root) }
        let gate = SchedulingGate(); await f.gateway.hold(f.keys[0], gate: gate)
        let good = Task { try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "file", offset: 0, length: 1024) }
        try await until { await f.gateway.requests.count == 1 }
        let malformed = Task { try await f.engine.ensureBlocks(resolved: f.resolved, filespace: "fs", itemID: "other-file", offset: 0, length: 1024) }
        try await until { await f.engine.downloadSchedulingMetrics().flights == 2 }
        // Both cold misses must enter authorization before either admits bytes;
        // a genuine cache hit only promises residency and authenticates on read.
        try await until { await f.gateway.requests.count == 2 }
        await gate.release(); try await good.value
        do { try await malformed.value; XCTFail("Another inode reused successful AEAD verification") } catch {}
        let plaintext = try await f.engine.plaintextBlock(f.resolved.manifest.blocks[0], resolved: f.resolved, blockIndex: 0, filespace: "fs", itemID: "file")
        XCTAssertEqual(plaintext, f.bytes[0])
    }
}
