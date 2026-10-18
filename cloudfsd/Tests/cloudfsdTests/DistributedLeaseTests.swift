// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import cloudfsd

/// Stateful HTTP double: two real HttpGatewayClients carry different per-device
/// headers but the SAME user's bearer token. No callback bypasses HTTP encoding.
private final class LeaseHTTP: URLProtocol, @unchecked Sendable {
    private struct Entry { let owner: String; let fence: Int; let purpose: String }
    nonisolated(unsafe) private static var entries: [String: Entry] = [:]
    nonisolated(unsafe) private static var nextFence = 0
    nonisolated(unsafe) private static var requests = 0
    nonisolated(unsafe) private static var includeItemRequested = false
    nonisolated(unsafe) private static var omitLeaseItem = false
    nonisolated(unsafe) private static var holdNextAcquire = false
    nonisolated(unsafe) private static var pendingAcquireReply: (@Sendable () -> Void)?
    private static let mutex = NSLock()
    static func reset() { mutex.withLock { entries = [:]; nextFence = 0; requests = 0; includeItemRequested = false; omitLeaseItem = false; holdNextAcquire = false; pendingAcquireReply = nil } }
    static func omitItemInLeaseResponse() { mutex.withLock { omitLeaseItem = true } }
    static var didRequestItem: Bool { mutex.withLock { includeItemRequested } }
    static func suspendNextAcquisition() { mutex.withLock { holdNextAcquire = true } }
    static var hasPendingAcquisition: Bool { mutex.withLock { pendingAcquireReply != nil } }
    static func completeAcquisition() {
        let reply = mutex.withLock { let reply = pendingAcquireReply; pendingAcquireReply = nil; return reply }
        reply?()
    }
    static func expire(_ path: String) { mutex.withLock { entries[path] = nil } }
    static var requestCount: Int { mutex.withLock { requests } }
    static func session() -> URLSession {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [LeaseHTTP.self]
        return URLSession(configuration: config)
    }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        var body = request.httpBody ?? Data()
        if let stream = request.httpBodyStream {
            stream.open(); defer { stream.close() }
            var buffer = [UInt8](repeating: 0, count: 4096)
            while true { let count = stream.read(&buffer, maxLength: buffer.count); if count <= 0 { break }; body.append(contentsOf: buffer.prefix(count)) }
        }
        let json = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] ?? [:]
        let query = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems ?? []
        let path = json["path"] as? String ?? query.first { $0.name == "path" }?.value ?? ""
        let owner = request.value(forHTTPHeaderField: "X-CloudFS-Client-ID") ?? "missing"
        let response: [String: Any] = Self.mutex.withLock {
            Self.requests += 1
            if json["includeItem"] as? Bool == true { Self.includeItemRequested = true }
            let old = Self.entries[path]
            if request.httpMethod == "DELETE" {
                let fence = query.first { $0.name == "fence" }?.value.flatMap(Int.init)
                guard old == nil || old?.owner == owner && old?.fence == fence else {
                    return ["released": false, "reason": "fence-stale"]
                }
                Self.entries[path] = nil; return ["released": true]
            }
            if json["renew"] as? Bool == true {
                guard old?.owner == owner, old?.fence == json["fence"] as? Int else {
                    return ["granted": false, "path": path, "reason": "fence-stale"]
                }
                return ["granted": true, "path": path, "fence": old!.fence, "purpose": old!.purpose,
                        "expiresAt": Date().timeIntervalSince1970 * 1000 + 60_000]
            } else if let old, old.owner != owner {
                return ["granted": false, "path": path, "heldBy": old.owner, "reason": "held-by-other"]
            }
            guard json["purpose"] as? String == "publication" else {
                return ["granted": false, "path": path, "reason": "purpose-mismatch"]
            }
            if old == nil {
                Self.nextFence += 1; Self.entries[path] = Entry(owner: owner, fence: Self.nextFence, purpose: "publication")
            }
            var granted: [String: Any] = ["granted": true, "path": path, "fence": Self.entries[path]!.fence,
                "purpose": Self.entries[path]!.purpose, "expiresAt": Date().timeIntervalSince1970 * 1000 + 60_000]
            if json["includeItem"] as? Bool == true && !Self.omitLeaseItem {
                granted["item"] = ["id": path, "parent": "root", "name": "doc.txt", "isDir": false,
                    "size": 12, "contentVersion": "cv-7", "version": 9, "fileAttributes": 0]
            }
            return granted
        }
        let data = try! JSONSerialization.data(withJSONObject: response)
        let http = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: ["Content-Type": "application/json"])!
        let reply: @Sendable () -> Void = { [self] in
            client?.urlProtocol(self, didReceive: http, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data); client?.urlProtocolDidFinishLoading(self)
        }
        let suspended = Self.mutex.withLock {
            guard Self.holdNextAcquire, request.httpMethod == "POST", json["renew"] as? Bool != true else { return false }
            Self.holdNextAcquire = false; Self.pendingAcquireReply = reply; return true
        }
        if !suspended { reply() }
    }
}

final class DistributedLeaseTests: XCTestCase {
    private func client() -> HttpGatewayClient {
        HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://leases.test", token: "same-user"), session: LeaseHTTP.session())
    }
    func testFreshPublicationLeaseReturnsItemOnlyFromNewGrant() async throws {
        LeaseHTTP.reset()
        let coordinator = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let first = try await coordinator.ensureWithItem(InodeID("snapshot-file"), handle: "open-1")
        XCTAssertTrue(LeaseHTTP.didRequestItem, "the combined path must opt into the item snapshot on the wire")
        XCTAssertNotNil(first.fence)
        XCTAssertEqual(first.item?.id, InodeID("snapshot-file"))
        XCTAssertEqual(first.item?.contentVersion, "cv-7")
        XCTAssertEqual(first.item?.metadataVersion, "9")

        let localLeaseHit = try await coordinator.ensureWithItem(InodeID("snapshot-file"), handle: "open-2")
        XCTAssertEqual(localLeaseHit.fence, first.fence)
        XCTAssertNil(localLeaseHit.item, "a cached lease must force caller to refresh metadata under that lease")
        await coordinator.close(InodeID("snapshot-file"), handle: "open-1")
        await coordinator.close(InodeID("snapshot-file"), handle: "open-2")
        await coordinator.releaseIfUnused(InodeID("snapshot-file"))
    }

    func testLegacyPublicationGrantWithoutItemRemainsHeldForFallbackLookup() async throws {
        LeaseHTTP.reset()
        LeaseHTTP.omitItemInLeaseResponse()
        let coordinator = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let first = try await coordinator.ensureWithItem(InodeID("legacy-file"), handle: "open-1")
        XCTAssertNotNil(first.fence)
        XCTAssertNil(first.item)
        let second = try await coordinator.ensureWithItem(InodeID("legacy-file"), handle: "open-2")
        XCTAssertEqual(second.fence, first.fence)
        XCTAssertNil(second.item)
        await coordinator.close(InodeID("legacy-file"), handle: "open-1")
        await coordinator.close(InodeID("legacy-file"), handle: "open-2")
        await coordinator.releaseIfUnused(InodeID("legacy-file"))
    }
    func testTwoDevicesSameUserAreExclusiveUntilFinalHandleCloses() async throws {
        LeaseHTTP.reset()
        let a = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let b = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let id = InodeID("shared-file")
        let first = try await a.ensure(id, handle: "app-1")
        let same = try await a.ensure(id, handle: "app-2")
        XCTAssertEqual(first, same)
        do { _ = try await b.ensure(id, handle: "other-mac"); XCTFail("second Mac must not write") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
        await a.close(id, handle: "app-1"); await a.releaseIfUnused(id)
        do { _ = try await b.ensure(id); XCTFail("second local handle must retain lease") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
        await a.close(id, handle: "app-2"); await a.releaseIfUnused(id)
        let next = try await b.ensure(id, handle: "other-mac")
        XCTAssertNotEqual(first, next)
        await a.shutdown(); await b.shutdown()
    }
    func testLostLeaseNeverSilentlyReacquiresAndStaleReleaseCannotFreeNewOwner() async throws {
        LeaseHTTP.reset()
        let clientA = client(), clientB = client()
        let a = DistributedLeaseCoordinator(gateway: clientA, filespace: "fs")
        let b = DistributedLeaseCoordinator(gateway: clientB, filespace: "fs")
        let id = InodeID("project")
        let acquired = try await a.ensure(id, handle: "old")
        let fence = try XCTUnwrap(acquired)
        LeaseHTTP.expire(id.rawValue)
        let replacement = try await b.ensure(id, handle: "new")
        XCTAssertNotEqual(fence, replacement)
        await a.renew(id)
        let count = LeaseHTTP.requestCount
        do { _ = try await a.ensure(id); XCTFail("lost lease must stay lost") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
        XCTAssertEqual(LeaseHTTP.requestCount, count, "no implicit reacquisition after lease loss")
        await a.close(id, handle: "old"); await a.releaseIfUnused(id)
        let stillHeld = try await b.ensure(id)
        XCTAssertEqual(stillHeld, replacement, "stale DELETE cannot release another device")
        await a.shutdown(); await b.shutdown()
    }
    func testConcurrentLocalOpensShareOneAcquisition() async throws {
        LeaseHTTP.reset()
        let a = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let fences = try await withThrowingTaskGroup(of: Int?.self) { group in
            for i in 0..<20 { group.addTask { try await a.ensure(InodeID("film"), handle: "handle-\(i)") } }
            var values: [Int?] = []; for try await value in group { values.append(value) }; return values
        }
        XCTAssertEqual(Set(fences.compactMap { $0 }).count, 1)
        XCTAssertEqual(LeaseHTTP.requestCount, 1)
        await a.shutdown()
    }
    func testExplicitRecoveryRequiresClosedEditingHandles() async throws {
        LeaseHTTP.reset()
        let a = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let id = InodeID("recover")
        _ = try await a.ensure(id, handle: "editor")
        do { try await a.resetForRecovery(id); XCTFail("open editor must block recovery reset") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
        await a.close(id, handle: "editor")
        try await a.resetForRecovery(id)
        _ = try await a.ensure(id)
        await a.shutdown()
    }
}

extension DistributedLeaseTests {
    func testFlushResultCannotReleaseLeaseOverNewlyStagedBytes() async throws {
        LeaseHTTP.reset()
        let a = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let b = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let id = InodeID("new-generation")
        _ = try await a.ensure(id, handle: "write")
        await a.close(id, handle: "write")
        let released = await a.releaseIfUnused(id, isDurable: { false })
        XCTAssertFalse(released)
        do { _ = try await b.ensure(id); XCTFail("pending bytes must retain lease") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
        _ = await a.releaseIfUnused(id, isDurable: { true })
        _ = try await b.ensure(id)
        await a.shutdown(); await b.shutdown()
    }
}

extension DistributedLeaseTests {
    func testDisconnectedSessionCannotReacquireFromLateUpload() async throws {
        LeaseHTTP.reset()
        let coordinator = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        _ = try await coordinator.ensure(InodeID("upload"))
        await coordinator.shutdown()
        let count = LeaseHTTP.requestCount
        do { _ = try await coordinator.ensure(InodeID("upload")); XCTFail("late upload must retain journal") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notConnected) }
        XCTAssertEqual(count, LeaseHTTP.requestCount)
    }
}

extension DistributedLeaseTests {
    func testReplayBarrierWaitsForDeadOwnerWithoutBlockingWritableOpen() async throws {
        LeaseHTTP.reset()
        let old = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let restarted = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let id = InodeID("crash-replay")
        let originalFence = try await old.ensure(id, handle: "dead-editor")
        let waiting = Task { try await restarted.ensureForUpload(id, maxWaitMs: 1_000) }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while LeaseHTTP.requestCount < 2 && ContinuousClock.now < deadline { await Task.yield() }
        XCTAssertGreaterThanOrEqual(LeaseHTTP.requestCount, 2)
        let began = ContinuousClock.now
        do { _ = try await restarted.ensure(id, handle: "new-editor"); XCTFail("Open must report another owner") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
        XCTAssertLessThan(began.duration(to: .now), .milliseconds(300), "background replay wait must not hold the lease gate")
        // The real server expires this only at TTL; the fixture advances that
        // external state explicitly instead of relying on scheduler sleeps.
        LeaseHTTP.expire(id.rawValue)
        let replayFence = try await waiting.value
        XCTAssertNotEqual(replayFence, originalFence)
        await old.shutdown(); await restarted.shutdown()
    }

    func testReplayBarrierIsBoundedWhenAnotherEditorKeepsLease() async throws {
        LeaseHTTP.reset()
        let editor = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let replay = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let id = InodeID("active-editor")
        let original = try await editor.ensure(id, handle: "editor")
        let began = ContinuousClock.now
        do { _ = try await replay.ensureForUpload(id, maxWaitMs: 100); XCTFail("A continuously held lease must not be stolen") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
        XCTAssertLessThan(began.duration(to: .now), .seconds(1))
        let stillOwned = try await editor.ensure(id)
        XCTAssertEqual(stillOwned, original)
        await editor.shutdown(); await replay.shutdown()
    }

    func testReplayBarrierCancellationAndStickyLostLease() async throws {
        LeaseHTTP.reset()
        let first = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let second = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let id = InodeID("cancel-replay")
        _ = try await first.ensure(id, handle: "old")
        let pending = Task { try await second.ensureForUpload(id, maxWaitMs: 5_000) }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while LeaseHTTP.requestCount < 2 && ContinuousClock.now < deadline { await Task.yield() }
        pending.cancel()
        do { _ = try await pending.value; XCTFail("Cancelled upload wait should stop") }
        catch is CancellationError {} catch { XCTFail("Expected cancellation, got \(error)") }
        LeaseHTTP.expire(id.rawValue)
        _ = try await second.ensure(id, handle: "new")
        await first.renew(id)
        let before = LeaseHTTP.requestCount
        do { _ = try await first.ensureForUpload(id, maxWaitMs: 5_000); XCTFail("A true lost lease must stay sticky") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
        XCTAssertEqual(LeaseHTTP.requestCount, before, "lost authority must not start a new acquisition loop")
        await first.shutdown(); await second.shutdown()
    }
}

extension DistributedLeaseTests {
    func testShutdownDuringInitialAcquisitionReleasesLateFenceWithoutRenewing() async throws {
        LeaseHTTP.reset()
        LeaseHTTP.suspendNextAcquisition()
        let ending = DistributedLeaseCoordinator(gateway: client(), filespace: "fs", ttlMs: 60_000)
        let next = DistributedLeaseCoordinator(gateway: client(), filespace: "fs")
        let id = InodeID("shutdown-during-acquire")
        let acquiring = Task { try await ending.ensure(id, handle: "editor") }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !LeaseHTTP.hasPendingAcquisition && ContinuousClock.now < deadline { await Task.yield() }
        XCTAssertTrue(LeaseHTTP.hasPendingAcquisition)
        await ending.shutdown()
        LeaseHTTP.completeAcquisition()
        do { _ = try await acquiring.value; XCTFail("Disconnected coordinator cannot publish a late fence") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notConnected) }
        XCTAssertEqual(LeaseHTTP.requestCount, 2, "late grant must receive a fenced release")
        await ending.renewAll()
        XCTAssertEqual(LeaseHTTP.requestCount, 2, "shutdown coordinator must not restart renewal")
        let replacement = try await next.ensure(id, handle: "replacement")
        XCTAssertNotNil(replacement, "another client may acquire after late-fence cleanup")
        await next.shutdown()
    }
}
