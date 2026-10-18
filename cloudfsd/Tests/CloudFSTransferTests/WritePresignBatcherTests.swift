// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import CloudFSTransfer

private actor WriteBatchGate {
    var open = false
    var waiters: [CheckedContinuation<Void, Never>] = []
    func wait() async { if !open { await withCheckedContinuation { waiters.append($0) } } }
    func release() { open = true; let list = waiters; waiters = []; for waiter in list { waiter.resume() } }
}
private actor WriteStopObservation {
    private(set) var completed = false
    func finish() { completed = true }
}
private actor WriteBatchGateway: GatewayClient {
    let gate: WriteBatchGate?
    var batches: [[(key: String, itemID: InodeID)]] = []
    var spaces: [FilespaceID] = []
    var singles: [(String, InodeID)] = []
    var denied: InodeID?
    init(gate: WriteBatchGate? = nil, denied: InodeID? = nil) { self.gate = gate; self.denied = denied }
    func presignWriteBatch(filespace: FilespaceID, keys: [(key: String, itemID: InodeID)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        batches.append(keys); spaces.append(filespace); await gate?.wait()
        return keys.map { entry in
            PresignBatchResult(key: entry.key, url: entry.itemID == denied ? nil : "https://put.test/" + entry.itemID.rawValue,
                error: entry.itemID == denied ? "denied" : nil,
                headers: ["if-none-match": "*", "x-amz-checksum-sha256": entry.key], verificationUrl: "https://verify.test/" + entry.key)
        }
    }
    func presignWrite(filespace: FilespaceID, key: String, itemID: InodeID, expiresIn: Int?) async throws -> PresignedURL {
        singles.append((key, itemID)); throw EngineError(.permissionDenied)
    }
    func count() -> (batches: Int, singles: Int) { (batches.count, singles.count) }
    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL { throw EngineError.unimplemented() }
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest { throw EngineError.unimplemented() }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws { throw EngineError.unimplemented() }
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { throw EngineError.unimplemented() }
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { throw EngineError.unimplemented() }
}
final class WritePresignBatcherTests: XCTestCase {
    private func until(_ test: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(3))
        while !(await test()), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(1)) }
        let result = await test(); XCTAssertTrue(result)
    }
    func testThirtyTwoAdmittedObjectsShareOneRPCAndKeepEveryInodeAndIntegrityHeader() async throws {
        let coalesce = WriteBatchGate(), gateway = WriteBatchGateway()
        let batcher = WritePresignBatcher(gateway: gateway, coalesce: { await coalesce.wait() })
        let tasks = (0..<32).map { index in Task { try await batcher.sign(filespace: "fs", key: "key-\(index)", itemID: InodeID("inode-\(index)")) } }
        try await until { await batcher.metrics().waiting == 32 }; await coalesce.release()
        for (index, task) in tasks.enumerated() {
            let ticket = try await task.value
            XCTAssertEqual(ticket.url, "https://put.test/inode-\(index)")
            XCTAssertEqual(ticket.headers?["if-none-match"], "*")
            XCTAssertEqual(ticket.headers?["x-amz-checksum-sha256"], "key-\(index)")
            XCTAssertEqual(ticket.verificationUrl, "https://verify.test/key-\(index)")
        }
        let calls = await gateway.count(); XCTAssertEqual(calls.batches, 1); XCTAssertEqual(calls.singles, 0)
    }
    func testSteadyArrivalsCoalesceIntoFewLargeBatches() async throws {
        let gateway = WriteBatchGateway()
        let batcher = WritePresignBatcher(gateway: gateway, window: .milliseconds(100), quiet: .milliseconds(50))
        var tasks: [Task<PresignedURL, Error>] = []
        for index in 0..<64 {
            tasks.append(Task { try await batcher.sign(filespace: "fs", key: "key-\(index)", itemID: InodeID("inode-\(index)")) })
            try await Task.sleep(for: .milliseconds(2))
        }
        for (index, task) in tasks.enumerated() { let t = try await task.value; XCTAssertEqual(t.url, "https://put.test/inode-\(index)") }
        let counts = await gateway.count()
        XCTAssertLessThanOrEqual(counts.batches, 4, "64 keys arriving 2 ms apart must share RPCs")
        XCTAssertEqual(counts.singles, 0)
    }
    func testFullBatchDispatchesWithoutWaitingForTheWindow() async throws {
        let gateway = WriteBatchGateway()
        let batcher = WritePresignBatcher(gateway: gateway, window: .seconds(30), quiet: .seconds(30))
        let started = ContinuousClock.now
        let tasks = (0..<32).map { index in Task { try await batcher.sign(filespace: "fs", key: "k\(index)", itemID: InodeID("i\(index)")) } }
        for task in tasks { _ = try await task.value }
        XCTAssertLessThan(started.duration(to: .now), .seconds(5))
        let counts = await gateway.count(); XCTAssertEqual(counts.batches, 1)
    }
    func testSameObjectKeyWithDifferentInodeCannotReuseTheOtherInodesAuthorization() async throws {
        let coalesce = WriteBatchGate(), gateway = WriteBatchGateway(denied: "no-access")
        let batcher = WritePresignBatcher(gateway: gateway, coalesce: { await coalesce.wait() })
        let good = Task { try await batcher.sign(filespace: "fs", key: "same-key", itemID: "allowed") }
        let bad = Task { try await batcher.sign(filespace: "fs", key: "same-key", itemID: "no-access") }
        try await until { await batcher.metrics().waiting == 2 }; await coalesce.release()
        let ticket = try await good.value; XCTAssertEqual(ticket.url, "https://put.test/allowed")
        do { _ = try await bad.value; XCTFail("Denied inode reused another declaration") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        let calls = await gateway.count(); XCTAssertEqual(calls.singles, 1)
    }
    func testCancelledWaiterDrainsImmediatelyWithoutCancellingSharedRPCOrExceedingFourRPCs() async throws {
        let coalesce = WriteBatchGate(), network = WriteBatchGate(), gateway = WriteBatchGateway(gate: network)
        let batcher = WritePresignBatcher(gateway: gateway, coalesce: { await coalesce.wait() })
        let first = (0..<128).map { index in Task { try await batcher.sign(filespace: "fs", key: "old-\(index)", itemID: "inode") } }
        try await until { await batcher.metrics().waiting == 128 }; await coalesce.release()
        try await until { await gateway.count().batches == 4 }
        for task in first { task.cancel() }
        for task in first { do { _ = try await task.value; XCTFail("Cancelled waiter succeeded") } catch is CancellationError {} }
        let next = Task { try await batcher.sign(filespace: "fs", key: "new", itemID: "inode") }
        try await until { await batcher.metrics().queued == 1 }
        let state = await batcher.metrics(); XCTAssertEqual(state.active, 4); XCTAssertEqual(state.waiting, 1)
        await network.release()
        let ticket = try await next.value; XCTAssertEqual(ticket.verificationUrl, "https://verify.test/new")
        try await until { let value = await batcher.metrics(); return value.active == 0 && value.waiting == 0 }
    }

    func testStopRejectsQueuedWritesAndWaitsForOldRPCsWithoutStoppingOtherFilespace() async throws {
        let coalesce = WriteBatchGate(), network = WriteBatchGate(), gateway = WriteBatchGateway(gate: network)
        let batcher = WritePresignBatcher(gateway: gateway, coalesce: { await coalesce.wait() })
        let first = (0..<128).map { index in
            Task { try await batcher.sign(filespace: "stopped", key: "old-\(index)", itemID: "inode") }
        }
        try await until { await batcher.metrics().waiting == 128 }; await coalesce.release()
        try await until { await gateway.count().batches == 4 }
        let queued = Task { try await batcher.sign(filespace: "stopped", key: "queued", itemID: "inode") }
        let other = Task { try await batcher.sign(filespace: "other", key: "kept", itemID: "allowed") }
        try await until { await batcher.metrics().queued == 2 }
        let observation = WriteStopObservation()
        let stopping = Task { await batcher.stop(filespace: "stopped"); await observation.finish() }
        try await until { await batcher.metrics().waiting == 1 }
        for task in first + [queued] {
            do { _ = try await task.value; XCTFail("Stopped write authorization succeeded") }
            catch is CancellationError {}
        }
        let drained = await observation.completed; XCTAssertFalse(drained)
        let blocked = await batcher.metrics(); XCTAssertEqual(blocked.active, 4); XCTAssertEqual(blocked.queued, 1)
        // This gate deliberately ignores cancellation. stop must wait for the
        // actual old RPCs, and discard the successful responses they return.
        await network.release()
        await stopping.value
        let kept = try await other.value; XCTAssertEqual(kept.url, "https://put.test/allowed")
        do { _ = try await batcher.sign(filespace: "stopped", key: "late", itemID: "inode"); XCTFail("Old session authorized again") }
        catch is CancellationError {}
        await batcher.stop(filespace: "stopped")
        _ = try await batcher.sign(filespace: "other", key: "next", itemID: "allowed")
        try await until { await batcher.metrics().active == 0 }
        let final = await batcher.metrics(); XCTAssertEqual(final.waiting, 0); XCTAssertEqual(final.queued, 0)
        let spaces = await gateway.spaces
        XCTAssertEqual(spaces.filter { $0 == "stopped" }.count, 4)
        XCTAssertEqual(spaces.filter { $0 == "other" }.count, 2)
        let singles = await gateway.singles.count; XCTAssertEqual(singles, 0)
    }
}
