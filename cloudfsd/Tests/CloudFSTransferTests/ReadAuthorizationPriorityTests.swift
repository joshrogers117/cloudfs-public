// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import CloudFSTransfer

private actor AuthorizationGate {
    private var open = false
    private var waiters: [UUID: CheckedContinuation<Void, Error>] = [:]
    private let ignoresCancellation: Bool
    init(ignoresCancellation: Bool = false) { self.ignoresCancellation = ignoresCancellation }
    func wait() async throws {
        try Task.checkCancellation()
        if open { return }
        let id = UUID()
        if ignoresCancellation {
            return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                waiters[id] = continuation
            }
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                if Task.isCancelled { continuation.resume(throwing: CancellationError()) }
                else { waiters[id] = continuation }
            }
        } onCancel: { Task { await self.cancel(id) } }
    }
    private func cancel(_ id: UUID) { waiters.removeValue(forKey: id)?.resume(throwing: CancellationError()) }
    func release() { open = true; let pending = waiters; waiters.removeAll(); for waiter in pending.values { waiter.resume() } }
}
private actor AuthorizationStopObservation {
    private(set) var completed = false
    func finish() { completed = true }
}
private actor AuthorizationGateway: GatewayClient {
    let gate: AuthorizationGate
    var requests: [[String]] = []
    var spaces: [FilespaceID] = []
    var cancelled = 0
    var active = 0
    var peak = 0
    init(gate: AuthorizationGate) { self.gate = gate }
    func presignBatch(filespace: FilespaceID, keys: [(key: String, method: PresignMethod)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        requests.append(keys.map(\.key)); spaces.append(filespace); active += 1; peak = max(peak, active)
        defer { active -= 1 }
        do { try await gate.wait() }
        catch { cancelled += 1; throw error }
        return keys.map { PresignBatchResult(key: $0.key, url: "https://read.test/" + $0.key, error: nil) }
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

private final class AuthorizationClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = ContinuousClock.now
    func now() -> ContinuousClock.Instant { lock.withLock { instant } }
    func advance(seconds: Int) { lock.withLock { instant = instant.advanced(by: .seconds(seconds)) } }
}

final class ReadAuthorizationPriorityTests: XCTestCase {
    private func until(_ predicate: () async -> Bool, file: StaticString = #filePath, line: UInt = #line) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(5))
        while !(await predicate()) {
            if ContinuousClock.now > deadline { XCTFail("Authorization condition timed out", file: file, line: line); throw EngineError(.syncTimeout) }
            try await Task.sleep(for: .milliseconds(1))
        }
    }
    func testForegroundAuthorizationBypassesQueuedSpeculationUsingReservedRPC() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {})
        var speculative: [Task<PresignedURL, Error>] = []
        for i in 0..<3 {
            let ticket = TransferPermitPool.Ticket(priority: .speculative)
            speculative.append(Task { try await batcher.sign(filespace: "background", key: "spec-\(i)", ticket: ticket) })
            try await until { await gateway.requests.count == i + 1 }
        }
        let waiting = Task { try await batcher.sign(filespace: "background", key: "queued-spec", ticket: .init(priority: .speculative)) }
        try await until { await batcher.metrics().queued == 1 }
        let demand = Task { try await batcher.sign(filespace: "foreground", key: "demand") }
        try await until { await gateway.requests.count == 4 }
        let requests = await gateway.requests; XCTAssertEqual(requests[3], ["demand"])
        let occupied = await batcher.metrics(); XCTAssertEqual(occupied.active, 4); XCTAssertEqual(occupied.speculativeActive, 3)
        waiting.cancel()
        do { _ = try await waiting.value; XCTFail("Canceled queue entry succeeded") } catch is CancellationError {}
        await gate.release()
        for task in speculative { _ = try await task.value }; _ = try await demand.value
        try await until { await batcher.metrics().active == 0 }
        let finalCalls = await gateway.requests.count; XCTAssertEqual(finalCalls, 4)
    }
    func testPureDemandUsesAllFourRPCsAndNeverExceedsTheBound() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {})
        var tasks: [Task<PresignedURL, Error>] = []
        for i in 0..<4 {
            tasks.append(Task { try await batcher.sign(filespace: "fs-\(i)", key: "demand-\(i)") })
            try await until { await gateway.requests.count == i + 1 }
        }
        let fifth = Task { try await batcher.sign(filespace: "fifth", key: "fifth") }
        try await until { await batcher.metrics().queued == 1 }
        let state = await batcher.metrics(); XCTAssertEqual(state.active, 4); XCTAssertEqual(state.speculativeActive, 0)
        await gate.release()
        for task in tasks { _ = try await task.value }; _ = try await fifth.value
        try await until { await batcher.metrics().active == 0 }
        let peak = await gateway.peak; XCTAssertEqual(peak, 4)
    }
    func testSharedTicketPromotionWakesQueuedAuthorizationWithoutDuplicateRPC() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {})
        var tasks: [Task<PresignedURL, Error>] = []
        for i in 0..<3 {
            tasks.append(Task { try await batcher.sign(filespace: "fs", key: "spec-\(i)", ticket: .init(priority: .speculative)) })
            try await until { await gateway.requests.count == i + 1 }
        }
        let ticket = TransferPermitPool.Ticket(priority: .speculative)
        let promoted = Task { try await batcher.sign(filespace: "fs", key: "promoted", ticket: ticket) }
        try await until { await batcher.metrics().queued == 1 }
        await batcher.promote(ticket)
        try await until { await gateway.requests.count == 4 }
        tasks[0].cancel()
        do { _ = try await tasks[0].value; XCTFail("Canceled speculative subscriber succeeded") } catch is CancellationError {}
        try await until { await gateway.cancelled == 1 }
        await gate.release()
        for task in tasks.dropFirst() { _ = try await task.value }
        let signed = try await promoted.value; XCTAssertEqual(signed.url, "https://read.test/promoted")
        let calls = await gateway.requests.flatMap { $0 }; XCTAssertEqual(calls.filter { $0 == "promoted" }.count, 1)
        try await until { await batcher.metrics().active == 0 }
    }
    func testCancelSpeculativeMembersPreservesDemandWithinThirtyTwoKeyBatch() async throws {
        let gate = AuthorizationGate(), coalesce = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: { try? await coalesce.wait() })
        let speculative = (0..<16).map { i in Task { try await batcher.sign(filespace: "fs", key: "spec-\(i)", ticket: .init(priority: .speculative)) } }
        let demand = (0..<16).map { i in Task { try await batcher.sign(filespace: "fs", key: "demand-\(i)") } }
        try await until { await batcher.metrics().queued == 32 }; await coalesce.release()
        try await until { await gateway.requests.count == 1 }
        let batch = await gateway.requests[0]
        XCTAssertEqual(batch.count, 32); XCTAssertTrue(batch.prefix(16).allSatisfy { $0.hasPrefix("demand-") })
        for task in speculative { task.cancel() }
        for task in speculative { do { _ = try await task.value; XCTFail("Canceled speculation succeeded") } catch is CancellationError {} }
        let cancelled = await gateway.cancelled; XCTAssertEqual(cancelled, 0)
        await gate.release()
        for (i, task) in demand.enumerated() {
            let signed = try await task.value; XCTAssertEqual(signed.url, "https://read.test/demand-\(i)")
        }
        let calls = await gateway.requests.count; XCTAssertEqual(calls, 1)
        try await until { await batcher.metrics().active == 0 }
    }

    func testPreparedWindowJoinsOneCoherentBatchAndRetainsNoPayloadWork() async throws {
        let gate = AuthorizationGate(), coalesce = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: { try? await coalesce.wait() })
        let keys = (0..<32).map { "prepared-\($0)" }
        await batcher.prepare(filespace: "fs", keys: keys, priority: .speculative)
        let initial = await batcher.metrics(); XCTAssertEqual(initial.queued, 32); XCTAssertEqual(initial.prepared, 32)
        let demand = Task { try await batcher.sign(filespace: "fs", key: keys[0]) }
        try await until { await gateway.requests.count == 1 }
        let requests = await gateway.requests; XCTAssertEqual(requests, [keys])
        await gate.release(); _ = try await demand.value; await coalesce.release()
        try await until { await batcher.metrics().active == 0 }
        for key in keys {
            let signed = try await batcher.sign(filespace: "fs", key: key)
            XCTAssertEqual(signed.url, "https://read.test/" + key)
            XCTAssertLessThanOrEqual(signed.expiresIn, 30)
        }
        let calls = await gateway.requests.count; XCTAssertEqual(calls, 1)
        let final = await batcher.metrics(); XCTAssertEqual(final.waiting, 0); XCTAssertEqual(final.queued, 0)
    }

    func testPreparedAuthorizationExpiresAndNeverCrossesFilespaceScope() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate), clock = AuthorizationClock()
        await gate.release()
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {}, now: { clock.now() })
        await batcher.prepare(filespace: "first", keys: ["same-key"], priority: .speculative)
        try await until { let m = await batcher.metrics(); return m.active == 0 && m.queued == 0 }
        _ = try await batcher.sign(filespace: "first", key: "same-key")
        _ = try await batcher.sign(filespace: "second", key: "same-key")
        clock.advance(seconds: 31)
        _ = try await batcher.sign(filespace: "first", key: "same-key")
        let spaces = await gateway.spaces; XCTAssertEqual(spaces, ["first", "second", "first"])
        let state = await batcher.metrics(); XCTAssertEqual(state.prepared, 0)
    }

    func testPreparedMetadataIsBoundedAndForegroundPromotionKeepsReservedRPC() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {})
        await batcher.prepare(filespace: "fs", keys: (0..<256).map { "key-\($0)" }, priority: .speculative)
        try await until { await gateway.requests.count == 3 }
        let initial = await batcher.metrics()
        XCTAssertEqual(initial.prepared, 128); XCTAssertEqual(initial.queued, 32); XCTAssertEqual(initial.speculativeActive, 3)
        await batcher.prepare(filespace: "other", keys: (0..<256).map { "extra-\($0)" }, priority: .speculative)
        let bounded = await batcher.metrics(); XCTAssertEqual(bounded.prepared, 128)
        let ticket = TransferPermitPool.Ticket(priority: .speculative)
        let joined = Task { try await batcher.sign(filespace: "fs", key: "key-127", ticket: ticket) }
        try await until { await batcher.metrics().waiting == 1 }
        await batcher.promote(ticket)
        try await until { await gateway.requests.count == 4 }
        let promoted = await batcher.metrics(); XCTAssertEqual(promoted.active, 4); XCTAssertEqual(promoted.speculativeActive, 3)
        joined.cancel()
        do { _ = try await joined.value; XCTFail("Canceled preparation subscriber succeeded") } catch is CancellationError {}
        let canceled = await batcher.metrics(); XCTAssertEqual(canceled.waiting, 0)
        await gate.release(); try await until { await batcher.metrics().active == 0 }
        let keys = await gateway.requests.flatMap { $0 }; XCTAssertEqual(keys.count, 128); XCTAssertEqual(Set(keys).count, 128)
    }

    func testPayloadQueueCanForceFreshAuthorizationInsteadOfReusingAnAgingURL() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        await gate.release()
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {})
        await batcher.prepare(filespace: "fs", keys: ["key"], priority: .speculative)
        try await until { let m = await batcher.metrics(); return m.active == 0 && m.queued == 0 }
        _ = try await batcher.sign(filespace: "fs", key: "key", forceFresh: true)
        let requests = await gateway.requests; XCTAssertEqual(requests, [["key"], ["key"]])
    }

    func testDemandPromotionSurvivesExpiredPreparationWithQueuedSubscriber() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate), clock = AuthorizationClock()
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {}, now: { clock.now() })
        var holding: [Task<PresignedURL, Error>] = []
        for i in 0..<3 {
            holding.append(Task { try await batcher.sign(filespace: "fs", key: "held-\(i)", ticket: .init(priority: .speculative)) })
            try await until { await gateway.requests.count == i + 1 }
        }
        await batcher.prepare(filespace: "fs", keys: ["prepared"], priority: .speculative)
        let ticket = TransferPermitPool.Ticket(priority: .speculative)
        let joined = Task { try await batcher.sign(filespace: "fs", key: "prepared", ticket: ticket) }
        try await until { await batcher.metrics().waiting == 4 }
        clock.advance(seconds: 31)
        await batcher.prepare(filespace: "fs", keys: [], priority: .speculative)
        let expired = await batcher.metrics(); XCTAssertEqual(expired.prepared, 0); XCTAssertEqual(expired.queued, 1)
        await batcher.promote(ticket)
        try await until { await gateway.requests.count == 4 }
        let fourth = await gateway.requests[3]; XCTAssertEqual(fourth, ["prepared"])
        let promoted = await batcher.metrics(); XCTAssertEqual(promoted.active, 4); XCTAssertEqual(promoted.speculativeActive, 3)
        await gate.release()
        for task in holding { _ = try await task.value }; _ = try await joined.value
        try await until { await batcher.metrics().active == 0 }
    }

    func testBurstOfForegroundReadersWaitsForMetadataCapacityInsteadOfFailing() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {})
        let tasks = (0..<300).map { i in Task { try await batcher.sign(filespace: "fs", key: "key-\(i)") } }
        try await until { await batcher.metrics().waiting == 128 }
        let full = await batcher.metrics(); XCTAssertLessThanOrEqual(full.active, 4); XCTAssertEqual(full.waiting, 128)
        await gate.release()
        for (i, task) in tasks.enumerated() {
            let signed = try await task.value; XCTAssertEqual(signed.url, "https://read.test/key-\(i)")
        }
        try await until { await batcher.metrics().active == 0 }
        let keys = await gateway.requests.flatMap { $0 }; XCTAssertEqual(keys.count, 300); XCTAssertEqual(Set(keys).count, 300)
        let final = await batcher.metrics(); XCTAssertEqual(final.waiting, 0); XCTAssertEqual(final.queued, 0)
    }

    func testStopDrainsPreparedRPCsAndAdmissionWaitersWithoutStoppingOtherFilespace() async throws {
        let gate = AuthorizationGate(), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {})
        await batcher.prepare(filespace: "stopped", keys: (0..<128).map { "key-\($0)" }, priority: .speculative)
        try await until { await gateway.requests.count == 3 }
        let other = Task { try await batcher.sign(filespace: "other", key: "kept") }
        try await until { await gateway.requests.count == 4 }
        let readers = (0..<160).map { i in
            Task { try await batcher.sign(filespace: "stopped", key: "key-\(i % 128)") }
        }
        // Includes queued prepared subscribers and callers beyond the separate
        // 128-permit admission bound. The unrelated RPC stays blocked throughout.
        try await until { await batcher.metrics().waiting == 128 }
        await batcher.stop(filespace: "stopped")
        for reader in readers {
            do { _ = try await reader.value; XCTFail("Stopped reader succeeded") }
            catch is CancellationError {}
        }
        let stopped = await batcher.metrics()
        XCTAssertEqual(stopped.waiting, 1); XCTAssertEqual(stopped.active, 1)
        XCTAssertEqual(stopped.queued, 0); XCTAssertEqual(stopped.prepared, 0)
        let cancelled = await gateway.cancelled; XCTAssertEqual(cancelled, 3)
        let active = await gateway.active; XCTAssertEqual(active, 1)

        await batcher.prepare(filespace: "stopped", keys: ["later"], priority: .demand)
        do { _ = try await batcher.sign(filespace: "stopped", key: "later"); XCTFail("Stopped space authorized again") }
        catch is CancellationError {}
        await batcher.stop(filespace: "stopped") // Idempotent while another space is active.
        let beforeRelease = await gateway.requests.count; XCTAssertEqual(beforeRelease, 4)
        await gate.release()
        let signed = try await other.value; XCTAssertEqual(signed.url, "https://read.test/kept")
        _ = try await batcher.sign(filespace: "other", key: "next")
        try await until { await batcher.metrics().active == 0 }
        let spaces = await gateway.spaces
        XCTAssertEqual(spaces.filter { $0 == "stopped" }.count, 3)
        XCTAssertEqual(spaces.filter { $0 == "other" }.count, 2)
    }

    func testStopWaitsForUncooperativeRPCAndDiscardsItsLateSuccess() async throws {
        let gate = AuthorizationGate(ignoresCancellation: true), gateway = AuthorizationGateway(gate: gate)
        let batcher = ReadPresignBatcher(gateway: gateway, coalesce: {})
        await batcher.prepare(filespace: "stopped", keys: ["late"], priority: .speculative)
        try await until { await gateway.active == 1 }
        let observation = AuthorizationStopObservation()
        let stopping = Task { await batcher.stop(filespace: "stopped"); await observation.finish() }
        try await until { await batcher.metrics().prepared == 0 }
        let returnedEarly = await observation.completed; XCTAssertFalse(returnedEarly)
        let running = await gateway.active; XCTAssertEqual(running, 1)
        await gate.release()
        await stopping.value
        let stopped = await batcher.metrics()
        XCTAssertEqual(stopped.active, 0); XCTAssertEqual(stopped.prepared, 0)
        XCTAssertEqual(stopped.waiting, 0); XCTAssertEqual(stopped.queued, 0)
        do { _ = try await batcher.sign(filespace: "stopped", key: "late"); XCTFail("Late response escaped shutdown fence") }
        catch is CancellationError {}
        let requests = await gateway.requests; XCTAssertEqual(requests, [["late"]])
    }
}
