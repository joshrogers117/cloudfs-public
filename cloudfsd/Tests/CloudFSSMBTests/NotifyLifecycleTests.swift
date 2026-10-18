// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Darwin
import CloudFSCore
@testable import CloudFSSMB

final class NotifyLifecycleTests: XCTestCase {
    private func pair(_ engine: MemoryEngine = MemoryEngine()) throws -> (NotifySession, ConnectionWriter, Int32, Int32) {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        let writer = ConnectionWriter(fd: fds[0])
        return (NotifySession(writer: writer, table: NodeTable(engine: engine)), writer, fds[0], fds[1])
    }
    private func pending(_ mid: UInt64 = 1) -> NotifySession.Pending {
        NotifySession.Pending(messageId: mid, asyncId: mid + 10, sessionId: 1,
            fileId: SMBFileId(persistent: mid, volatile: 1), dir: .root, completionFilter: 1)
    }
    private func readable(_ fd: Int32, milliseconds: Int32 = 50) -> Bool {
        var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        return poll(&item, 1, milliseconds) > 0
    }
    private func publish(_ item: NotifySession.Pending, session: NotifySession, writer: ConnectionWriter) {
        var bytes = ByteWriter()
        SMB2Header(command: .changeNotify, messageId: item.messageId, status: NTStatus.pending.rawValue,
                   flags: [.serverToRedir, .asyncCommand], sessionId: item.sessionId, asyncId: item.asyncId).encode(into: &bytes)
        bytes.bytes(errorBody())
        XCTAssertTrue(writer.writeScatter([DirectTCP.frame(length: bytes.count), bytes.data]))
        session.didPublishInterims([bytes.data])
    }
    private func response(_ fd: Int32) throws -> SMB2Header {
        func exact(_ count: Int) throws -> Data {
            var bytes = [UInt8](repeating: 0, count: count)
            var offset = 0
            while offset < count {
                guard readable(fd, milliseconds: 1000) else { throw NSError(domain: "notify-test-timeout", code: 1) }
                let received = bytes.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!.advanced(by: offset), count-offset) }
                guard received > 0 else { throw NSError(domain: "notify-test-read", code: Int(errno)) }
                offset += received
            }
            return Data(bytes)
        }
        let prefix = try exact(4)
        let length = try XCTUnwrap(DirectTCP.length(prefix: prefix))
        var reader = ByteReader(try exact(length))
        return try SMB2Header.decode(&reader)
    }

    func testLocalCompletionWaitsForInterimPublication() throws {
        let (session, _, server, client) = try pair()
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        session.register(pending(), generation: 0)
        session.postLocalChange(.root)
        XCTAssertFalse(readable(client), "Completion must not reach the socket before the PENDING frame is published")
    }

    func testCancellationWaitsForInterimPublication() throws {
        let (session, _, server, client) = try pair()
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        session.register(pending(), generation: 0)
        session.cancel(asyncId: 11, messageId: 1)
        XCTAssertFalse(readable(client), "CANCELLED must follow its interim, including a cancellation during response assembly")
    }

    func testHistoricalPagesDoNotCompleteQuietWatch() throws {
        let engine = MemoryEngine()
        engine.notificationCheckpointHook = { _ in "high-water-900" }
        engine.changePageHook = { anchor in ([], [InodeID("historical-tombstone")], anchor == "" ? "1" : "2", true) }
        let server = SMBServer(engine: engine, shareName: "notify", credential: (user: "cfs", password: "pw"))
        let client = SMBTestClient()
        defer { client.close(); server.stop() }
        try client.connect(port: server.start()); _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw"); _ = try client.treeConnect(share: "notify")
        let directory = try client.create(path: "")
        let interim = try client.changeNotifyRequest(fileId: directory.fileId)
        XCTAssertEqual(interim.header.status, NTStatus.pending.rawValue)
        XCTAssertNil(client.readAsyncResponse(timeoutMs: 450), "Historical pagination is not a new publication")
    }

    func testDeferredCompletionPublishesExactlyOnceAfterItsInterim() throws {
        let (session, writer, server, client) = try pair()
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        let item = pending()
        session.register(item, generation: 0)
        session.postLocalChange(.root)
        session.postLocalChange(.root)
        session.cancel(asyncId: item.asyncId, messageId: item.messageId)
        XCTAssertFalse(readable(client))
        publish(item, session: session, writer: writer)
        let interim = try response(client), completion = try response(client)
        XCTAssertEqual(interim.status, NTStatus.pending.rawValue)
        XCTAssertEqual(completion.status, NTStatus.notifyEnumDir.rawValue)
        XCTAssertEqual(completion.messageId, interim.messageId)
        XCTAssertEqual(completion.asyncId, interim.asyncId)
        XCTAssertFalse(readable(client), "First completion wins and is emitted only once")
    }

    func testDeferredCancelAndShutdownPreserveOrdering() throws {
        let (session, writer, server, client) = try pair()
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        let item = pending()
        session.register(item, generation: 0); session.cancel(asyncId: item.asyncId, messageId: item.messageId)
        session.postLocalChange(.root)
        publish(item, session: session, writer: writer)
        XCTAssertEqual(try response(client).status, NTStatus.pending.rawValue)
        XCTAssertEqual(try response(client).status, NTStatus.cancelled.rawValue)
        let discarded = pending(2)
        session.register(discarded, generation: 0); session.postLocalChange(.root); session.shutdown()
        publish(discarded, session: session, writer: writer)
        XCTAssertEqual(try response(client).status, NTStatus.pending.rawValue)
        XCTAssertFalse(readable(client), "Shutdown must discard unpublished completions")
    }

    func testCompoundMutationCannotOvertakePendingResponse() throws {
        let engine = MemoryEngine()
        let server = SMBServer(engine: engine, shareName: "notify", credential: (user: "cfs", password: "pw"))
        let client = SMBTestClient()
        defer { client.close(); server.stop() }
        try client.connect(port: server.start()); _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw"); _ = try client.treeConnect(share: "notify")
        let directory = try client.create(path: "")
        var body = ByteWriter(); body.u16(32); body.u16(0); body.u32(65536)
        body.u64(directory.fileId.persistent); body.u64(directory.fileId.volatile); body.u32(1); body.u32(0)
        let parts = try client.compound([(.changeNotify, body.data), (.create, client.createBody(path: "same-compound.txt"))])
        XCTAssertEqual(parts.map(\.header.status), [NTStatus.pending.rawValue, NTStatus.success.rawValue])
        let completion = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 1000))
        XCTAssertEqual(completion.header.status, NTStatus.notifyEnumDir.rawValue)
        XCTAssertEqual(completion.header.messageId, parts.first?.header.messageId)
    }

    func testGenerationDuringBaselineStillCompletesWatch() async throws {
        let engine = MemoryEngine(), gate = NotifyTestGate(), generation = NotifyTestCounter()
        let entered = expectation(description: "baseline started")
        engine.changeGenerationHook = { await generation.current }
        engine.notificationCheckpointHook = { _ in entered.fulfill(); await gate.wait(); return "already-includes-publication" }
        let (session, writer, server, client) = try pair(engine)
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        let item = pending(); session.register(item, generation: 0); publish(item, session: session, writer: writer)
        XCTAssertEqual(try response(client).status, NTStatus.pending.rawValue)
        await fulfillment(of: [entered], timeout: 1)
        _ = await generation.advance(); await gate.release()
        XCTAssertEqual(try response(client).status, NTStatus.notifyEnumDir.rawValue)
    }

    func testCancelledBaselineCannotCompleteReplacementWatch() async throws {
        let engine = MemoryEngine(), gate = NotifyTestGate(), calls = NotifyTestCounter()
        let entered = expectation(description: "old baseline started")
        engine.notificationCheckpointHook = { _ in
            if await calls.advance() == 1 { entered.fulfill(); await gate.wait(); return "old-checkpoint" }
            return "stable-new-checkpoint"
        }
        let (session, writer, server, client) = try pair(engine)
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        let old = pending(); session.register(old, generation: 0); publish(old, session: session, writer: writer)
        XCTAssertEqual(try response(client).status, NTStatus.pending.rawValue)
        await fulfillment(of: [entered], timeout: 1)
        session.cancel(asyncId: old.asyncId, messageId: old.messageId)
        XCTAssertEqual(try response(client).status, NTStatus.cancelled.rawValue)
        let fresh = pending(2); session.register(fresh, generation: 0); publish(fresh, session: session, writer: writer)
        XCTAssertEqual(try response(client).status, NTStatus.pending.rawValue)
        await gate.release()
        XCTAssertFalse(readable(client, milliseconds: 350), "Cancelled baseline must not finish the next watcher")
        session.postLocalChange(.root)
        let completion = try response(client)
        XCTAssertEqual(completion.status, NTStatus.notifyEnumDir.rawValue)
        XCTAssertEqual(completion.messageId, fresh.messageId)
    }

    func testStableGenerationStillDetectsCheckpointChange() async throws {
        let engine = MemoryEngine(), token = NotifyTestCounter()
        let baseline = expectation(description: "baseline captured"); baseline.assertForOverFulfill = false
        engine.notificationCheckpointHook = { _ in let value = await token.current; baseline.fulfill(); return String(value) }
        let (session, writer, server, client) = try pair(engine)
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        let item = pending(); session.register(item, generation: 0); publish(item, session: session, writer: writer)
        XCTAssertEqual(try response(client).status, NTStatus.pending.rawValue)
        await fulfillment(of: [baseline], timeout: 1)
        XCTAssertFalse(readable(client, milliseconds: 150))
        _ = await token.advance()
        XCTAssertEqual(try response(client).status, NTStatus.notifyEnumDir.rawValue)
    }

    func testFailedCheckpointRetriesWithoutEventAndStopsAfterCancel() async throws {
        let engine = MemoryEngine(), calls = NotifyTestCounter()
        engine.notificationCheckpointHook = { _ in
            _ = await calls.advance()
            throw EngineError(.gatewayError, "Injected checkpoint failure")
        }
        let (session, writer, server, client) = try pair(engine)
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        let item = pending(); session.register(item, generation: 0); publish(item, session: session, writer: writer)
        XCTAssertEqual(try response(client).status, NTStatus.pending.rawValue)
        XCTAssertFalse(readable(client, milliseconds: 350), "Failed baselines cannot become change events")
        let beforeCancel = await calls.current
        XCTAssertGreaterThanOrEqual(beforeCancel, 2)
        XCTAssertLessThanOrEqual(beforeCancel, 5, "Checkpoint failures must wait between retries")
        session.cancel(asyncId: item.asyncId, messageId: item.messageId)
        XCTAssertEqual(try response(client).status, NTStatus.cancelled.rawValue)
        XCTAssertFalse(readable(client, milliseconds: 250))
        let afterCancel = await calls.current
        XCTAssertLessThanOrEqual(afterCancel, beforeCancel + 1, "Cancellation must stop polling even after checkpoint errors")
    }

    func testPublicationBeforeDetachedPollerStartsIsNotSwallowed() async throws {
        let engine = MemoryEngine(), gate = NotifyTestGate(), calls = NotifyTestCounter(), generation = NotifyTestCounter()
        let entered = expectation(description: "first asynchronous generation read")
        engine.notificationCheckpointHook = { _ in "includes-new-publication" }
        engine.changeGenerationHook = {
            if await calls.advance() == 1 { entered.fulfill(); await gate.wait() }
            return await generation.current
        }
        let (session, writer, server, client) = try pair(engine)
        defer { session.shutdown(); Darwin.close(server); Darwin.close(client) }
        // The request-handler generation at registration is0. The old detached
        // poller instead snapshots1 after PENDING, then misses this publication.
        let item = pending(); session.register(item, generation: 0); publish(item, session: session, writer: writer)
        XCTAssertEqual(try response(client).status, NTStatus.pending.rawValue)
        await fulfillment(of: [entered], timeout: 1)
        _ = await generation.advance(); await gate.release()
        XCTAssertEqual(try response(client).status, NTStatus.notifyEnumDir.rawValue)
    }

    func testRequestCapturesGenerationBeforePublishingInterim() async throws {
        let engine = MemoryEngine(), gate = NotifyTestGate(), calls = NotifyTestCounter(), generation = NotifyTestCounter()
        let captured = expectation(description: "request generation captured")
        engine.notificationCheckpointHook = { _ in "already-includes-peer-change" }
        engine.changeGenerationHook = {
            let value = await generation.current
            if await calls.advance() == 1 { captured.fulfill(); await gate.wait() }
            return value
        }
        let server = SMBServer(engine: engine, shareName: "notify", credential: (user: "cfs", password: "pw"))
        let client = SMBTestClient()
        defer { client.close(); server.stop() }
        try client.connect(port: server.start()); _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw"); _ = try client.treeConnect(share: "notify")
        let directory = try client.create(path: "")
        var body = ByteWriter(); body.u16(32); body.u16(0); body.u32(65536)
        body.u64(directory.fileId.persistent); body.u64(directory.fileId.volatile); body.u32(1); body.u32(0)
        try client.sendOnly(.changeNotify, body: body.data)
        await fulfillment(of: [captured], timeout: 1)
        XCTAssertNil(client.readAsyncResponse(timeoutMs: 75), "PENDING cannot precede its generation snapshot")
        _ = await generation.advance(); await gate.release()
        XCTAssertEqual(client.readAsyncResponse(timeoutMs: 1000)?.header.status, NTStatus.pending.rawValue)
        XCTAssertEqual(client.readAsyncResponse(timeoutMs: 1000)?.header.status, NTStatus.notifyEnumDir.rawValue)
    }
}

private actor NotifyTestCounter {
    private(set) var current: UInt64 = 0
    func advance() -> UInt64 { current += 1; return current }
}
private actor NotifyTestGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var released = false
    func wait() async {
        if released { return }
        await withCheckedContinuation { continuation = $0 }
    }
    func release() { released = true; continuation?.resume(); continuation = nil }
}
