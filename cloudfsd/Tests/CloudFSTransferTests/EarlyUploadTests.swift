// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import CloudFSTransfer

/// A gated real URLSession boundary, so tests can leave immutable PUTs in flight
/// while newer local images are acknowledged. No wall-clock performance claims.
private final class EarlyBlobProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var held = true
    nonisolated(unsafe) private static var pending: [EarlyBlobProtocol] = []
    nonisolated(unsafe) private static var total = 0
    nonisolated(unsafe) private static var failRemaining = 0
    private let stateLock = NSLock()
    private var finished = false
    static func reset(failures: Int = 0) {
        lock.withLock { held = true; pending = []; total = 0; failRemaining = failures }
    }
    static var requests: Int { lock.withLock { total } }
    static func release() {
        let values = lock.withLock { () -> [EarlyBlobProtocol] in
            held = false; let values = pending; pending = []; return values
        }
        for value in values { value.finish() }
    }
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "blob.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let parked = Self.lock.withLock { () -> Bool in
            Self.total += 1
            if Self.held { Self.pending.append(self); return true }
            return false
        }
        if !parked { finish() }
    }
    private func finish() {
        stateLock.withLock {
            guard !finished else { return }
            finished = true
            let status = Self.lock.withLock { () -> Int in
                if Self.failRemaining > 0 { Self.failRemaining -= 1; return 500 }
                return 200
            }
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: [:])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data())
            client?.urlProtocolDidFinishLoading(self)
        }
    }
    override func stopLoading() { stateLock.withLock { finished = true } }
}

private final class JournalPublicationPause: @unchecked Sendable {
    private let lock = NSLock()
    private let releaseSignal = DispatchSemaphore(value: 0)
    private var armed = false
    private var entered = false
    func arm() { lock.withLock { armed = true } }
    var isEntered: Bool { lock.withLock { entered } }
    func release() { releaseSignal.signal() }
    func hit(_ phase: WriteBackJournal.PublicationPhase) throws {
        guard phase == .headRenamed, lock.withLock({ () -> Bool in
            guard armed else { return false }
            armed = false; entered = true; return true
        }) else { return }
        guard releaseSignal.wait(timeout: .now() + 10) == .success else {
            throw EngineError(.syncFailed, "test publication gate timed out")
        }
    }
}

final class EarlyUploadTests: XCTestCase {
    private struct Fixture {
        let root: URL
        let cache: DiskBlockCache
        let crypto: AESGCMBlockCrypto
        let gateway: MockGateway
        let engine: RealTransferEngine
    }
    private func fixture(failures: Int = 0, debounceMs: Int = 5000, uploadConcurrency: Int = 3,
                         publicationPause: JournalPublicationPause? = nil) throws -> Fixture {
        EarlyBlobProtocol.reset(failures: failures)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-early-put-\(UUID())")
        let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [EarlyBlobProtocol.self]
        let session = URLSession(configuration: configuration)
        addTeardownBlock { EarlyBlobProtocol.release(); session.invalidateAndCancel(); try? FileManager.default.removeItem(at: root) }
        let gateway = MockGateway()
        let journal = publicationPause.map { gate in
            WriteBackJournal(cacheDir: root.path, publicationFault: { try gate.hit($0) })
        } ?? WriteBackJournal(cacheDir: root.path)
        let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
            blob: BlobTransport(session: session, policy: RetryPolicy(maxAttempts: 1)), blockSize: 4096,
            uploadConcurrency: uploadConcurrency, journal: journal, uploadDebounceMs: debounceMs)
        return Fixture(root: root, cache: cache, crypto: crypto, gateway: gateway, engine: engine)
    }
    private func waitUntil(_ condition: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await condition()), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(1)) }
        let satisfied = await condition()
        XCTAssertTrue(satisfied)
    }
    private func bytes(_ fixture: Fixture, item: InodeID) async throws -> Data {
        let manifest = try XCTUnwrap(fixture.gateway.putManifests.last { $0.itemID == item })
        var result = Data()
        for (index, block) in manifest.blocks.enumerated() {
            let value = try await fixture.cache.readBlock(block.hash)
            result.append(try await fixture.crypto.decryptBlock(try XCTUnwrap(value), itemID: item, blockIndex: index))
        }
        return result
    }

    func testDefaultSizedPreparationWindowKeepsThirtyTwoPUTCeilingAndJournalUntilCommit() async throws {
        try await assertPreparationWindow(uploadConcurrency: 32, preparedImages: 96)
    }
    func testMaximumPreparationWindowCannotExceedNinetySixImages() async throws {
        try await assertPreparationWindow(uploadConcurrency: 64, preparedImages: 96)
    }
    private func assertPreparationWindow(uploadConcurrency: Int, preparedImages: Int) async throws {
        let f = try fixture(uploadConcurrency: uploadConcurrency)
        let expected = Data(repeating: 77, count: (preparedImages + 8) * 4096)
        try await f.engine.stageWrite(filespace: "fs", itemID: "bounded", offset: 0,
            data: expected, baseVersion: "1", fence: 91)
        try await waitUntil { EarlyBlobProtocol.requests == uploadConcurrency }
        try await waitUntil { await f.engine.uploadPayloadMetrics().queuedDemand == preparedImages - uploadConcurrency }
        let preparation = await f.engine.uploadPreparationMetrics()
        XCTAssertEqual(preparation.active, preparedImages)
        XCTAssertEqual(preparation.peak, preparedImages)
        XCTAssertEqual(preparation.limit, preparedImages)
        XCTAssertEqual(EarlyBlobProtocol.requests, uploadConcurrency)
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        let journal = WriteBackJournal(cacheDir: f.root.path)
        let retained = try await journal.replay()
        XCTAssertEqual(retained.first?.blockLengths.count, preparedImages + 8)
        EarlyBlobProtocol.release()
        let flushed = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        XCTAssertTrue(flushed.inSync)
        let finalBytes = try await bytes(f, item: "bounded")
        XCTAssertEqual(finalBytes, expected)
        try await waitUntil { await f.engine.uploadPreparationMetrics().active == 0 }
        let drained = await f.engine.uploadPreparationMetrics()
        XCTAssertEqual(drained.active, 0)
        XCTAssertEqual(drained.peak, preparedImages)
        let emptyJournal = try await journal.replay()
        XCTAssertTrue(emptyJournal.isEmpty)
    }

    func testAcknowledgedAppendPUTsOverlapButDoNotCommitAndRemainGloballyBounded() async throws {
        let f = try fixture(), first = Data(repeating: 17, count: 8 * 4096)
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0, data: first, baseVersion: "1", fence: 91)
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        XCTAssertTrue(f.gateway.putManifests.isEmpty, "early object presence must not make an incomplete file visible")
        let replay = try await WriteBackJournal(cacheDir: f.root.path).replay()
        XCTAssertEqual(replay.first?.blockLengths.count, 8, "PUT work begins only after the complete write is durable")
        try await f.engine.stageWrite(filespace: "fs", itemID: "b", offset: 0, data: first, baseVersion: "1", fence: 92)
        let saturated = await f.engine.earlyUploadMetrics()
        XCTAssertEqual(saturated.active, 9); XCTAssertEqual(saturated.peak, 9)
        try await waitUntil { await f.engine.uploadPayloadMetrics().queuedDemand == 6 }
        let preparation = await f.engine.uploadPreparationMetrics()
        XCTAssertEqual(preparation.active, 9); XCTAssertEqual(preparation.limit, 9)
        XCTAssertEqual(EarlyBlobProtocol.requests, 3, "prepared authorization cannot exceed the three-PUT ceiling")
        EarlyBlobProtocol.release()
        try await waitUntil { await f.engine.earlyUploadMetrics().active == 0 }
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: first.count, data: first, baseVersion: "1", fence: 91)
        let state = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        XCTAssertTrue(state.inSync)
        XCTAssertEqual(EarlyBlobProtocol.requests, 24, "the final manifest reuses prepared objects instead of PUTting their bytes again")
        let a = try await bytes(f, item: "a"), b = try await bytes(f, item: "b")
        XCTAssertEqual(a, first + first); XCTAssertEqual(b, first)
        XCTAssertEqual(f.gateway.putExpectedVersions, [1, 1])
        XCTAssertEqual(Set(f.gateway.putFences.compactMap { $0 }), [91, 92])
    }

    func testMetadataCatchUpUploadsEverySkippedBlockWithoutAnotherWriteOrManifest() async throws {
        let f = try fixture(), expected = Data(repeating: 31, count: 8 * 4096)
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0, data: expected, baseVersion: "1", fence: nil)
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        // These images arrive while the global preparation budget is occupied.
        // Only metadata queues; freeing slots catches up from the journal.
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: expected.count, data: expected, baseVersion: "1", fence: nil)
        try await f.engine.stageWrite(filespace: "fs", itemID: "b", offset: 0, data: expected, baseVersion: "1", fence: nil)
        XCTAssertEqual(EarlyBlobProtocol.requests, 3)
        let bounded = await f.engine.earlyUploadMetrics()
        XCTAssertEqual(bounded.active, 9)
        EarlyBlobProtocol.release()
        try await waitUntil {
            let active = await f.engine.earlyUploadMetrics().active
            return EarlyBlobProtocol.requests == 24 && active == 0
        }
        XCTAssertTrue(f.gateway.putManifests.isEmpty, "catch-up must not publish an intermediate file version")
        let finalBound = await f.engine.earlyUploadMetrics()
        XCTAssertEqual(finalBound.peak, 9)
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        XCTAssertEqual(EarlyBlobProtocol.requests, 24, "final upload should reuse every successfully prepared image")
        let a = try await bytes(f, item: "a"), b = try await bytes(f, item: "b")
        XCTAssertEqual(a, expected + expected); XCTAssertEqual(b, expected)
    }

    func testReorderedKernelWritesPrepareTheEntireNewRegionBeforeFlush() async throws {
        let f = try fixture()
        // macOS application writes are sequential, but SMB arrives upper half
        // first, then fills the gap below the current logical high-water mark.
        let order = [4, 5, 6, 7, 0, 1, 2, 3]
        for group in 0..<4 {
            for delta in order {
                let index = group * 8 + delta
                try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: index * 4096,
                    data: Data(repeating: UInt8(index), count: 4096), baseVersion: "1", fence: nil)
            }
        }
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        EarlyBlobProtocol.release()
        try await waitUntil {
            let active = await f.engine.earlyUploadMetrics().active
            return EarlyBlobProtocol.requests == 32 && active == 0
        }
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        XCTAssertEqual(EarlyBlobProtocol.requests, 32)
        let actual = try await bytes(f, item: "a")
        var expected = Data()
        for index in 0..<32 { expected.append(Data(repeating: UInt8(index), count: 4096)) }
        XCTAssertEqual(actual, expected)
    }

    func testReorderedHugeSparseGapPreparesOnlyEightExistingDirtyBlocks() async throws {
        // A logical cursor would traverse over 17 billion holes here. Catch-up
        // must work only from pending dirty indices and retain the same budget.
        let f = try fixture(debounceMs: 60_000)
        let distant = 1 << 34
        let indices = [distant + 4, 2, distant + 6, 0, distant + 5, 3, distant + 7, 1]
        for (value, index) in indices.enumerated() {
            try await f.engine.stageWrite(filespace: "fs", itemID: "sparse", offset: index * 4096,
                data: Data(repeating: UInt8(value + 1), count: 4096), baseVersion: "1", fence: nil)
        }
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        let occupied = await f.engine.earlyUploadMetrics()
        XCTAssertEqual(occupied.active, 8)
        EarlyBlobProtocol.release()
        try await waitUntil {
            let active = await f.engine.earlyUploadMetrics().active
            return EarlyBlobProtocol.requests == 8 && active == 0
        }
        XCTAssertTrue(f.gateway.putManifests.isEmpty, "never construct or publish a huge sparse manifest in this test")
        let bounded = await f.engine.earlyUploadMetrics()
        XCTAssertEqual(bounded.peak, 8)
        let journal = WriteBackJournal(cacheDir: f.root.path)
        let entries = try await journal.replay()
        XCTAssertEqual(Set(entries.first?.blockLengths.keys.map { $0 } ?? []), Set(indices))
        for (value, index) in indices.enumerated() {
            XCTAssertEqual(try journal.readBlock(filespace: "fs", itemID: "sparse", blockIndex: index),
                Data(repeating: UInt8(value + 1), count: 4096))
        }
        _ = try await f.engine.pause(filespace: "fs")
        // Cancel the large generation before fixture teardown without flushing
        // it: truncation is bounded by the eight dirty records, not logical size.
        try await f.engine.stageTruncate(filespace: "fs", itemID: "sparse", newSize: 0,
            baseVersion: "1", fence: nil)
        XCTAssertEqual(EarlyBlobProtocol.requests, 8)
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
    }

    func testOriginalCommittedOverwritesRemainCoalescedWhileNewSuffixCanReorder() async throws {
        let f = try fixture()
        var refs: [BlockRef] = []
        for index in 0..<8 {
            let (ciphertext, hash) = try await f.crypto.encryptBlock(Data(repeating: 17, count: 4096), itemID: "a", blockIndex: index)
            try await f.cache.putBlock(hash, plaintext: ciphertext)
            refs.append(BlockRef(hash: hash, offset: index * 4096, length: 4096))
        }
        f.gateway.manifests["a"] = BlockManifest(itemID: "a", blocks: refs, contentVersion: "1")
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0,
            data: Data(repeating: 99, count: 8 * 4096), baseVersion: "1", fence: nil)
        let before = await f.engine.earlyUploadMetrics()
        XCTAssertEqual(before.active, 0, "edits inside the frozen original base do not qualify as streaming extension")
        XCTAssertEqual(EarlyBlobProtocol.requests, 0)
        for index in [12, 13, 14, 15, 8, 9, 10, 11] {
            try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: index * 4096,
                data: Data(repeating: 31, count: 4096), baseVersion: "1", fence: nil)
        }
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        EarlyBlobProtocol.release()
        try await waitUntil {
            let active = await f.engine.earlyUploadMetrics().active
            return EarlyBlobProtocol.requests == 8 && active == 0
        }
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        XCTAssertEqual(EarlyBlobProtocol.requests, 16, "only the new suffix was prepared; original edits upload during final flush")
        let actual = try await bytes(f, item: "a")
        XCTAssertEqual(actual, Data(repeating: 99, count: 8 * 4096) + Data(repeating: 31, count: 8 * 4096))
    }

    func testCatchUpNeverReadsBetweenJournalHeadPublicationAndStagedImagePublication() async throws {
        let gate = JournalPublicationPause(), f = try fixture(publicationPause: gate)
        defer { gate.release() }
        let first = Data(repeating: 17, count: 8 * 4096), second = Data(repeating: 31, count: 8 * 4096)
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0, data: first, baseVersion: "1", fence: nil)
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        let alreadyPrepared = await f.engine.earlyUploadMetrics().active
        gate.arm()
        let writing = Task {
            try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: first.count, data: second, baseVersion: "1", fence: nil)
        }
        try await waitUntil { gate.isEntered }
        EarlyBlobProtocol.release()
        try await waitUntil { await f.engine.earlyUploadMetrics().active == 0 }
        XCTAssertEqual(EarlyBlobProtocol.requests, alreadyPrepared, "only previously reserved images may finish while journal publication is held")
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        gate.release()
        _ = try await writing.value
        try await waitUntil {
            let active = await f.engine.earlyUploadMetrics().active
            return EarlyBlobProtocol.requests == 16 && active == 0
        }
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        let actual = try await bytes(f, item: "a")
        XCTAssertEqual(actual, first + second)
        XCTAssertEqual(EarlyBlobProtocol.requests, 16)
    }

    func testInFlightOldPUTCannotSurviveOverwriteTruncateOrRegrowth() async throws {
        let f = try fixture(), original = Data(repeating: 17, count: 8 * 4096)
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0, data: original, baseVersion: "1", fence: nil)
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        let oldPrepared = await f.engine.earlyUploadMetrics().active
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0, data: Data(repeating: 99, count: 4096), baseVersion: "1", fence: nil)
        try await f.engine.stageTruncate(filespace: "fs", itemID: "a", newSize: 4096 + 64, baseVersion: "1", fence: nil)
        try await f.engine.stageTruncate(filespace: "fs", itemID: "a", newSize: original.count, baseVersion: "1", fence: nil)
        EarlyBlobProtocol.release()
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        var expected = Data(repeating: 99, count: 4096)
        expected.append(Data(repeating: 17, count: 64))
        expected.append(Data(repeating: 0, count: original.count - expected.count))
        let actual = try await bytes(f, item: "a")
        XCTAssertEqual(actual, expected)
        XCTAssertEqual(EarlyBlobProtocol.requests, oldPrepared + 8, "obsolete PUTs cannot be used for the new dirty images")
    }

    func testFailedEarlyPUTFallsBackWithoutLosingJournalOrPublishingPartialManifest() async throws {
        let f = try fixture(failures: 3), expected = Data(repeating: 42, count: 8 * 4096)
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0, data: expected, baseVersion: "1", fence: nil)
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        EarlyBlobProtocol.release()
        try await waitUntil { await f.engine.earlyUploadMetrics().active == 0 }
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        let journal = WriteBackJournal(cacheDir: f.root.path), replay = try await journal.replay()
        XCTAssertEqual(replay.first?.blockLengths.count, 8)
        for index in 0..<8 {
            XCTAssertEqual(try journal.readBlock(filespace: "fs", itemID: "a", blockIndex: index), Data(repeating: 42, count: 4096))
        }
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        let actual = try await bytes(f, item: "a")
        XCTAssertEqual(actual, expected)
        XCTAssertEqual(EarlyBlobProtocol.requests, 11)
    }

    func testPausePreventsQueuedEarlyWorkStartingAfterItsPermitBecomesAvailable() async throws {
        let f = try fixture()
        try await f.engine.stageReplace(filespace: "fs", itemID: "normal", data: Data(repeating: 1, count: 3 * 4096), baseVersion: "1", fence: nil)
        let flushing = Task { try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000) }
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        try await f.engine.stageWrite(filespace: "fs", itemID: "append", offset: 0, data: Data(repeating: 2, count: 8 * 4096), baseVersion: "1", fence: nil)
        let queued = await f.engine.earlyUploadMetrics()
        XCTAssertEqual(queued.active, 6)
        _ = try await f.engine.pause(filespace: "fs")
        EarlyBlobProtocol.release()
        try await waitUntil { await f.engine.earlyUploadMetrics().active == 0 }
        XCTAssertEqual(EarlyBlobProtocol.requests, 3, "a queued task must recheck pause after acquiring its permit")
        _ = try await f.engine.resume(filespace: "fs")
        let final = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        XCTAssertTrue(final.inSync)
        XCTAssertEqual(EarlyBlobProtocol.requests, 11)
        _ = try await flushing.value
    }

    func testSupersededManifestWaitersDrainWhileTheSharedPUTIsStillBlocked() async throws {
        let f = try fixture(debounceMs: 0), initial = Data(repeating: 1, count: 8 * 4096)
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0, data: initial, baseVersion: "1", fence: nil)
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        for index in 8..<32 {
            try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: index * 4096,
                data: Data(repeating: UInt8(index), count: 4096), baseVersion: "1", fence: nil)
            try await Task.sleep(for: .milliseconds(2))
        }
        try await waitUntil { await f.engine.uploadRunCount() == 1 }
        XCTAssertEqual(EarlyBlobProtocol.requests, 3, "shared PUTs remain blocked; canceled manifest snapshots must still drain")
        EarlyBlobProtocol.release()
        _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
        let finalRuns = await f.engine.uploadRunCount()
        XCTAssertEqual(finalRuns, 0)
        let actual = try await bytes(f, item: "a")
        var expected = initial
        for index in 8..<32 { expected.append(Data(repeating: UInt8(index), count: 4096)) }
        XCTAssertEqual(actual, expected)
    }

    func testSuccessfulEarlyPUTStillCannotBypassCASOrEraseRecoverableBytes() async throws {
        let f = try fixture(), expected = Data(repeating: 42, count: 8 * 4096)
        f.gateway.enforceExpectedVersion = true; f.gateway.versions["a"] = 2
        try await f.engine.stageWrite(filespace: "fs", itemID: "a", offset: 0, data: expected, baseVersion: "1", fence: 93)
        try await waitUntil { EarlyBlobProtocol.requests == 3 }
        EarlyBlobProtocol.release()
        do {
            _ = try await f.engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
            XCTFail("an early object upload is never permission to overwrite a newer version")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        XCTAssertTrue(f.gateway.putManifests.isEmpty)
        XCTAssertEqual(f.gateway.putExpectedVersions, [1]); XCTAssertEqual(f.gateway.putFences, [93])
        let recovered = try await WriteBackJournal(cacheDir: f.root.path).replay()
        XCTAssertEqual(recovered.first?.blockLengths.count, 8)
        let destination = f.root.appendingPathComponent("recovered.bin")
        _ = try await f.engine.exportRecovery(filespace: "fs", itemID: "a", destination: destination.path)
        XCTAssertEqual(try Data(contentsOf: destination), expected)
    }
}
