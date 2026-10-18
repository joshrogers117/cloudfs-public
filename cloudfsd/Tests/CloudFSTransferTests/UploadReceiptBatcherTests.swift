// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import CloudFSTransfer

private actor ReceiptTestGate {
    private var open = false
    private var waiters: [UUID: CheckedContinuation<Void, Error>] = [:]
    func wait() async throws {
        if open { return }; let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                else { waiters[id] = continuation }
            }
        } onCancel: { Task { await self.cancel(id) } }
    }
    private func cancel(_ id: UUID) { waiters.removeValue(forKey: id)?.resume(throwing: CancellationError()) }
    func release() { open = true; let all = waiters; waiters = [:]; for waiter in all.values { waiter.resume() } }
}
private actor ReceiptTestGateway: GatewayClient {
    enum Mode: Equatable { case success, failed, unsupported, throttled(String) }
    let gate: ReceiptTestGate?
    let mode: Mode
    let requestGates: [ReceiptTestGate]
    let requestModes: [Mode]
    var requests: [(FilespaceID, InodeID, [UploadedBlockVerification])] = []
    var active = 0
    var peak = 0
    init(gate: ReceiptTestGate? = nil, mode: Mode = .success,
         requestGates: [ReceiptTestGate] = [], requestModes: [Mode] = []) {
        self.gate = gate; self.mode = mode
        self.requestGates = requestGates; self.requestModes = requestModes
    }
    func verifyUploadedBlocks(filespace: FilespaceID, itemID: InodeID, blocks: [UploadedBlockVerification]) async throws {
        let index = requests.count
        requests.append((filespace, itemID, blocks)); active += 1; peak = max(peak, active)
        defer { active -= 1 }
        let selectedGate = requestGates.indices.contains(index) ? requestGates[index] : gate
        try await selectedGate?.wait()
        switch requestModes.indices.contains(index) ? requestModes[index] : mode {
        case .success: return
        case .failed: throw EngineError(.networkError, "Verification unavailable")
        case .unsupported: throw EngineError.unimplemented()
        case .throttled(let hint): throw EngineError(.gatewayError, "rate_limited", data: ["retryAfter": .string(hint)])
        }
    }
    func snapshot() -> (requests: [(FilespaceID, InodeID, [UploadedBlockVerification])], active: Int, peak: Int) { (requests, active, peak) }
    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL { throw EngineError.unimplemented() }
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest { throw EngineError.unimplemented() }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws { throw EngineError.unimplemented() }
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { throw EngineError.unimplemented() }
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { throw EngineError.unimplemented() }
}

private actor ReceiptDrainCompletion {
    private(set) var completed = false
    func finish() { completed = true }
}

final class UploadReceiptBatcherTests: XCTestCase {
    private func object(_ index: Int) -> UploadedBlockVerification {
        let hash = String(format: "%064x", index)
        return UploadedBlockVerification(objectKey: "blocks/test/\(hash)", blockHash: hash, length: 1024)
    }
    private func until(_ predicate: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !(await predicate()), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(1)) }
        let result = await predicate(); XCTAssertTrue(result)
    }
    func testMetadataQueueAndRPCsAreBoundedWhileUploadsCanContinue() async throws {
        let coalesce = ReceiptTestGate(), network = ReceiptTestGate(), gateway = ReceiptTestGateway(gate: network)
        let batcher = UploadReceiptBatcher(gateway: gateway, concurrency: 2, coalesce: { try? await coalesce.wait() })
        for index in 0..<522 { await batcher.enqueue(filespace: "fs", itemID: "file", block: object(index)) }
        var state = await batcher.metrics()
        XCTAssertEqual(state.pending, 512); XCTAssertEqual(state.active, 0); XCTAssertEqual(state.dropped, 10)
        await coalesce.release()
        try await until { await gateway.snapshot().active == 2 }
        state = await batcher.metrics()
        XCTAssertEqual(state.active, 256); XCTAssertEqual(state.pending, 256); XCTAssertEqual(state.peak, 512)
        let drain = Task { try await batcher.drain(filespace: "fs", itemID: "file") }
        await network.release(); try await drain.value
        let requests = await gateway.snapshot()
        XCTAssertEqual(requests.requests.map { $0.2.count }, [128, 128, 128, 128])
        XCTAssertEqual(Set(requests.requests.flatMap { $0.2 }), Set((0..<512).map(object)))
        XCTAssertEqual(requests.peak, 2)
        state = await batcher.metrics(); XCTAssertEqual(state.pending + state.active, 0)
    }
    func testFourRPCsDrainAThousandReceiptsWithoutOverflow() async throws {
        let coalesce = ReceiptTestGate(), network = ReceiptTestGate(), gateway = ReceiptTestGateway(gate: network)
        let batcher = UploadReceiptBatcher(gateway: gateway, capacity: 1024, coalesce: { try? await coalesce.wait() })
        for index in 0..<1024 { await batcher.enqueue(filespace: "fs", itemID: "file", block: object(index)) }
        await coalesce.release()
        try await until { await gateway.snapshot().active == 4 }
        var state = await batcher.metrics()
        XCTAssertEqual(state.dropped, 0); XCTAssertEqual(state.active, 512); XCTAssertEqual(state.pending, 512)
        let drain = Task { try await batcher.drain(filespace: "fs", itemID: "file") }
        await network.release(); try await drain.value
        let snapshot = await gateway.snapshot()
        XCTAssertEqual(snapshot.peak, 4)
        XCTAssertTrue(snapshot.requests.allSatisfy { $0.2.count <= 128 })
        XCTAssertEqual(Set(snapshot.requests.flatMap { $0.2 }), Set((0..<1024).map(object)))
        state = await batcher.metrics(); XCTAssertEqual(state.dropped, 0); XCTAssertEqual(state.pending + state.active, 0)
    }
    func testBackpressureWithFourRPCsStillDropsToFinalVerification() async throws {
        let coalesce = ReceiptTestGate(), gateway = ReceiptTestGateway(mode: .throttled("60"))
        let batcher = UploadReceiptBatcher(gateway: gateway, capacity: 1024, coalesce: { try? await coalesce.wait() })
        for index in 0..<1024 { await batcher.enqueue(filespace: "fs", itemID: "file", block: object(index)) }
        await coalesce.release()
        try await batcher.drain(filespace: "fs", itemID: "file")
        let calls = await gateway.snapshot().requests.count
        XCTAssertEqual(calls, 4, "only the in-flight RPCs run; the backlog is dropped, not retried early")
        await batcher.enqueue(filespace: "fs", itemID: "file", block: object(5000))
        let state = await batcher.metrics()
        XCTAssertEqual(state.pending + state.active, 0, "cooldown refuses new optional work")
    }
    func testDuplicateObjectsRetainTheirFilespaceAndInodeAuthorizationScope() async throws {
        let coalesce = ReceiptTestGate(), gateway = ReceiptTestGateway()
        let batcher = UploadReceiptBatcher(gateway: gateway, coalesce: { try? await coalesce.wait() })
        for _ in 0..<3 { await batcher.enqueue(filespace: "a", itemID: "first", block: object(1)) }
        await batcher.enqueue(filespace: "a", itemID: "second", block: object(1))
        await batcher.enqueue(filespace: "b", itemID: "first", block: object(1))
        await coalesce.release()
        try await batcher.drain(filespace: "a", itemID: "first")
        try await batcher.drain(filespace: "a", itemID: "second")
        try await batcher.drain(filespace: "b", itemID: "first")
        let calls = await gateway.snapshot().requests
        XCTAssertEqual(Set(calls.map { "\($0.0)/\($0.1.rawValue)" }), ["a/first", "a/second", "b/first"])
        XCTAssertTrue(calls.allSatisfy { $0.2 == [object(1)] })
    }
    func testFailedOrUnsupportedOptimizationStillLetsFinalCommitProceed() async throws {
        for mode in [ReceiptTestGateway.Mode.failed, .unsupported] {
            let coalesce = ReceiptTestGate(), gateway = ReceiptTestGateway(mode: mode)
            let batcher = UploadReceiptBatcher(gateway: gateway, concurrency: 2, coalesce: { try? await coalesce.wait() })
            for index in 0..<260 { await batcher.enqueue(filespace: "fs", itemID: "file", block: object(index)) }
            await coalesce.release()
            try await batcher.drain(filespace: "fs", itemID: "file")
            let state = await batcher.metrics()
            XCTAssertEqual(state.pending + state.active, 0)
            XCTAssertEqual(state.disabled, mode == .unsupported)
            let calls = await gateway.snapshot().requests.count
            XCTAssertEqual(calls, mode == .unsupported ? 2 : 3)
        }
    }
    func testCanceledManifestDrainDoesNotCancelSharedObjectVerification() async throws {
        let network = ReceiptTestGate(), gateway = ReceiptTestGateway(gate: network)
        let batcher = UploadReceiptBatcher(gateway: gateway, coalesce: {})
        await batcher.enqueue(filespace: "fs", itemID: "file", block: object(1))
        try await until { await gateway.snapshot().active == 1 }
        let canceled = Task { try await batcher.drain(filespace: "fs", itemID: "file") }
        canceled.cancel()
        do { try await canceled.value; XCTFail("Canceled drain completed") } catch is CancellationError {}
        let stillActive = await gateway.snapshot().active; XCTAssertEqual(stillActive, 1)
        await network.release()
        try await batcher.drain(filespace: "fs", itemID: "file")
        let count = await gateway.snapshot().requests.count; XCTAssertEqual(count, 1)
    }
    func testRetryAfterDropsOptionalBacklogWithoutSendingMoreRequestsEarly() async throws {
        try await assertRetryAfterSuppressesBacklog("60")
    }
    func testHTTPDateRetryAfterDropsOptionalBacklogWithoutSendingMoreRequestsEarly() async throws {
        let format = DateFormatter()
        format.locale = Locale(identifier: "en_US_POSIX")
        format.timeZone = TimeZone(secondsFromGMT: 0)
        format.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        try await assertRetryAfterSuppressesBacklog(format.string(from: Date().addingTimeInterval(3600)))
    }
    private func assertRetryAfterSuppressesBacklog(_ hint: String) async throws {
        let coalesce = ReceiptTestGate(), gateway = ReceiptTestGateway(mode: .throttled(hint))
        let batcher = UploadReceiptBatcher(gateway: gateway, concurrency: 1, coalesce: { try? await coalesce.wait() })
        for index in 0..<260 { await batcher.enqueue(filespace: "fs", itemID: "file", block: object(index)) }
        await coalesce.release()
        try await batcher.drain(filespace: "fs", itemID: "file")
        await batcher.enqueue(filespace: "fs", itemID: "file", block: object(999))
        try await batcher.drain(filespace: "fs", itemID: "file")
        let state = await batcher.metrics(), calls = await gateway.snapshot().requests.count
        XCTAssertEqual(state.pending + state.active, 0); XCTAssertFalse(state.disabled); XCTAssertEqual(calls, 1)
    }
    func testSameInodeDrainWaitsForBothInterleavedRPCsAndCancellationLeavesThemRunning() async throws {
        let coalesce = ReceiptTestGate(), first = ReceiptTestGate(), second = ReceiptTestGate()
        let gateway = ReceiptTestGateway(requestGates: [first, second])
        let batcher = UploadReceiptBatcher(gateway: gateway, coalesce: { try? await coalesce.wait() })
        for index in 0..<256 { await batcher.enqueue(filespace: "fs", itemID: "file", block: object(index)) }
        await coalesce.release()
        try await until { await gateway.snapshot().active == 2 }
        let canceled = Task { try await batcher.drain(filespace: "fs", itemID: "file") }
        canceled.cancel()
        do { try await canceled.value; XCTFail("Canceled drain succeeded") } catch is CancellationError {}
        let active = await gateway.snapshot().active; XCTAssertEqual(active, 2)
        let completion = ReceiptDrainCompletion()
        let drain = Task { try await batcher.drain(filespace: "fs", itemID: "file"); await completion.finish() }
        await second.release()
        try await until { await batcher.metrics().active == 128 }
        let premature = await completion.completed; XCTAssertFalse(premature)
        await first.release(); try await drain.value
        let complete = await completion.completed; XCTAssertTrue(complete)
        let calls = await gateway.snapshot(); XCTAssertEqual(calls.requests.count, 2); XCTAssertEqual(calls.peak, 2)
    }
    func testBackpressureFromOneRPCSurvivesSiblingSuccessAndStopsQueuedAdmission() async throws {
        for failure in [ReceiptTestGateway.Mode.throttled("60"), .unsupported] {
            let coalesce = ReceiptTestGate(), failed = ReceiptTestGate(), successful = ReceiptTestGate()
            let gateway = ReceiptTestGateway(requestGates: [failed, successful], requestModes: [failure, .success])
            let batcher = UploadReceiptBatcher(gateway: gateway, concurrency: 2, coalesce: { try? await coalesce.wait() })
            for index in 0..<384 { await batcher.enqueue(filespace: "fs", itemID: "file", block: object(index)) }
            await coalesce.release()
            try await until { await gateway.snapshot().active == 2 }
            await failed.release()
            try await until { let state = await batcher.metrics(); return state.active == 128 && state.pending == 0 }
            await batcher.enqueue(filespace: "other", itemID: "file", block: object(998))
            await successful.release()
            try await batcher.drain(filespace: "fs", itemID: "file")
            await batcher.enqueue(filespace: "other", itemID: "file", block: object(999))
            try await batcher.drain(filespace: "other", itemID: "file")
            let state = await batcher.metrics(), calls = await gateway.snapshot()
            XCTAssertEqual(state.active + state.pending, 0)
            XCTAssertEqual(state.disabled, failure == .unsupported)
            XCTAssertEqual(calls.requests.count, 2)
        }
    }
    func testDisconnectCancelsBothActiveRPCsAndPreservesAnotherFilespacesQueuedWork() async throws {
        let coalesce = ReceiptTestGate(), network = ReceiptTestGate(), gateway = ReceiptTestGateway(gate: network)
        let batcher = UploadReceiptBatcher(gateway: gateway, concurrency: 2, coalesce: { try? await coalesce.wait() })
        for index in 0..<256 { await batcher.enqueue(filespace: "stopping", itemID: "file", block: object(index)) }
        await batcher.enqueue(filespace: "remaining", itemID: "other", block: object(900))
        await coalesce.release()
        try await until { await gateway.snapshot().active == 2 }
        await batcher.stop(filespace: "stopping")
        try await until { await gateway.snapshot().requests.count == 3 }
        await batcher.enqueue(filespace: "stopping", itemID: "file", block: object(999))
        let state = await batcher.metrics(), calls = await gateway.snapshot()
        XCTAssertEqual(state.active, 1); XCTAssertEqual(state.pending, 0)
        XCTAssertEqual(calls.active, 1); XCTAssertEqual(calls.peak, 2)
        XCTAssertEqual(calls.requests.last?.0, "remaining")
        await network.release()
        try await batcher.drain(filespace: "remaining", itemID: "other")
        let final = await gateway.snapshot(); XCTAssertEqual(final.requests.count, 3); XCTAssertEqual(final.active, 0)
    }
    func testDisconnectCancelsAndDrainsActiveRPCAndRejectsLaterEnqueues() async throws {
        let network = ReceiptTestGate(), gateway = ReceiptTestGateway(gate: network)
        let batcher = UploadReceiptBatcher(gateway: gateway, concurrency: 1, coalesce: {})
        await batcher.enqueue(filespace: "fs", itemID: "file", block: object(1))
        try await until { await gateway.snapshot().active == 1 }
        await batcher.enqueue(filespace: "fs", itemID: "file", block: object(2))
        await batcher.stop(filespace: "fs")
        await batcher.enqueue(filespace: "fs", itemID: "file", block: object(3))
        let state = await batcher.metrics(), calls = await gateway.snapshot()
        XCTAssertEqual(state.pending + state.active, 0); XCTAssertEqual(calls.active, 0); XCTAssertEqual(calls.requests.count, 1)
        await network.release()
        await batcher.enqueue(filespace: "other", itemID: "file", block: object(4))
        try await batcher.drain(filespace: "other", itemID: "file")
        let final = await gateway.snapshot().requests
        XCTAssertEqual(final.count, 2); XCTAssertEqual(final.last?.0, "other")
    }
}
