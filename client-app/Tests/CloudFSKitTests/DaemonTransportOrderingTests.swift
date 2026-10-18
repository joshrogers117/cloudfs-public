// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Testing
@testable import CloudFSKit

@Suite(.serialized, .timeLimit(.minutes(1)))
struct DaemonTransportOrderingTests {
    @Test func delayedSeedCannotRollBackLiveCompletion() async throws {
        let daemon = FakeDaemon()
        let gate = ReplyGate()
        daemon.onResult("events.subscribe", json: #"{"subscribed":true}"#)
        daemon.pushNotifications(after: "events.subscribe", [transferNote(done: 100, state: "done")])
        daemon.onResult("transfers.current") { _ in
            gate.wait()
            return #"[{"id":"t1","filespace":"fs1","path":"movie.mov","direction":"download","bytesDone":10,"bytesTotal":100,"state":"active"}]"#
        }
        try daemon.start()
        defer { gate.open(); daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        var stream = client.transferUpdates(filespace: "fs1").makeAsyncIterator()
        let live = await stream.next()
        #expect(live?.first?.state == .completed)
        // The seed reply is held until a real completion is consumed. This makes
        // the old snapshot-overwrites-live bug deterministic, without sleeps.
        gate.open()
        let seeded = await stream.next()
        #expect(seeded?.first?.state == .completed)
        #expect(seeded?.first?.bytesDone == 100)
        await client.disconnect()
    }

    @Test func completionHistoryIsBoundedAndClearDoesNotHideFailuresOrActiveWork() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("events.subscribe", json: #"{"subscribed":true}"#)
        daemon.onResult("transfers.current", json: "[]")
        daemon.onResult("transfers.pause", json: "{}")
        daemon.pushNotifications(after: "transfers.current",
            (0..<300).map { transferNote(id: "done\($0)", done: 100, state: "done") }
            + [transferNote(id: "failed-old", done: 2, state: "error"),
               transferNote(id: "failed", done: 3, state: "error"),
               transferNote(id: "active", done: 20, state: "active")])
        daemon.pushNotifications(after: "transfers.pause", [transferNote(id: "active", done: 50, state: "active")])
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        var updates = client.transferUpdates(filespace: "fs1").makeAsyncIterator()
        var latest: [Transfer] = []
        while let value = await updates.next() {
            latest = value
            if value.contains(where: { $0.id == "active" }) { break }
        }
        #expect(latest.filter { $0.state == .completed }.count == 128)
        #expect(latest.filter { $0.state == .failed }.map(\.id) == ["failed"])
        try await client.clearCompletedTransfers(filespace: "fs1")
        let cleared = await updates.next()
        #expect(cleared?.contains(where: { $0.state == .completed }) == false)
        #expect(cleared?.contains(where: { $0.id == "failed" }) == true)
        #expect(cleared?.contains(where: { $0.id == "active" }) == true)
        try await client.pauseTransfers(filespace: "fs1")
        while let value = await updates.next() {
            if value.contains(where: { $0.id == "active" && $0.bytesDone == 50 }) {
                #expect(!value.contains(where: { $0.state == .completed }))
                break
            }
        }
        await client.disconnect()
    }

    @Test func successfulNewUploadResolvesOldFailureForOnlyThatFile() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("events.subscribe", json: #"{"subscribed":true}"#)
        daemon.onResult("transfers.current", json: "[]")
        daemon.pushNotifications(after: "transfers.current", [
            transferNote(id: "old-upload", direction: "upload", done: 2, state: "error"),
            transferNote(id: "other-upload", path: "other.mov", direction: "upload", done: 2, state: "error"),
            transferNote(id: "new-upload", direction: "upload", done: 100, state: "done"),
            transferNote(id: "active", done: 5, state: "active")
        ])
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        var updates = client.transferUpdates(filespace: "fs1").makeAsyncIterator()
        while let value = await updates.next() {
            guard value.contains(where: { $0.id == "active" }) else { continue }
            #expect(!value.contains(where: { $0.id == "old-upload" }))
            #expect(value.contains(where: { $0.id == "other-upload" && $0.state == .failed }))
            #expect(value.contains(where: { $0.id == "new-upload" && $0.state == .completed }))
            break
        }
        await client.disconnect()
    }

    @Test func clearingDuringDelayedSeedCannotResurrectSuccess() async throws {
        let daemon = FakeDaemon()
        let gate = ReplyGate()
        daemon.onResult("events.subscribe", json: #"{"subscribed":true}"#)
        daemon.pushNotifications(after: "events.subscribe", [transferNote(done: 100, state: "done")])
        daemon.onResult("transfers.current") { _ in
            gate.wait()
            return #"[{"id":"t1","filespace":"fs1","path":"movie.mov","direction":"download","bytesDone":10,"bytesTotal":100,"state":"active"}]"#
        }
        try daemon.start()
        defer { gate.open(); daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        var updates = client.transferUpdates(filespace: "fs1").makeAsyncIterator()
        #expect(await updates.next()?.first?.state == .completed)
        try await client.clearCompletedTransfers(filespace: "fs1")
        #expect(await updates.next()?.isEmpty == true)
        gate.open()
        #expect(await updates.next()?.isEmpty == true)
        await client.disconnect()
    }

    @Test func optionalPausedStateRemainsCompatibleWithOlderDaemons() throws {
        let decoder = JSONDecoder()
        let old = try decoder.decode(EngineFilespace.self, from: Data(#"{"id":"fs","name":"Space","status":"connected"}"#.utf8))
        #expect(old.paused == nil)
        let paused = try decoder.decode(EngineFilespace.self, from: Data(#"{"id":"fs","name":"Space","status":"connected","paused":true}"#.utf8))
        #expect(paused.paused == true)
    }

    @Test func concurrentSubscribersShareConnectionAndSubscription() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("events.subscribe", json: #"{"subscribed":true}"#)
        daemon.onResult("transfers.current", json: "[]")
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        await withTaskGroup(of: Bool.self) { group in
            for index in 0..<32 {
                group.addTask {
                    var updates = client.transferUpdates(filespace: "fs\(index)").makeAsyncIterator()
                    return await updates.next() != nil
                }
            }
            for await delivered in group { #expect(delivered) }
        }
        #expect(daemon.connectionCount == 1)
        #expect(daemon.requestCount("events.subscribe") == 1)
        #expect(daemon.requestCount("transfers.current") == 32)
        await client.disconnect()
    }

    @Test func releasingIdleConnectionClosesPeerWithoutAnotherFrame() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("probe", json: "{}")
        let (closed, didClose) = AsyncStream<Void>.makeStream()
        daemon.onClientDisconnect { didClose.yield(()); didClose.finish() }
        try daemon.start()
        defer { daemon.stop() }
        var connection: UnixSocketConnection? = UnixSocketConnection(path: daemon.path)
        weak var weakConnection = connection
        let generation = try await connection!.connect(notificationHandler: { _, _ in })
        _ = try await connection!.call(method: "probe", params: .object([:]), generation: generation)
        connection = nil
        var events = closed.makeAsyncIterator()
        _ = await events.next()
        #expect(weakConnection == nil)
    }

    @Test func orderedNotificationsDrainBeforeEOF() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("burst", json: "{}")
        daemon.pushNotifications(after: "burst", (0..<128).map {
            #"{"jsonrpc":"2.0","method":"tick","params":{"index":\#($0)}}"#
        })
        daemon.closeClient(after: "burst")
        try daemon.start()
        defer { daemon.stop() }
        let connection = UnixSocketConnection(path: daemon.path)
        let gate = AsyncGate()
        let (entered, enteredContinuation) = AsyncStream<Void>.makeStream()
        let (delivered, values) = AsyncStream<Int>.makeStream()
        let generation = try await connection.connect(notificationHandler: { frame, _ in
            guard let value = frame.params?["index"]?.intValue else { return }
            if value == 0 {
                enteredContinuation.yield(())
                await gate.wait()
            }
            values.yield(value)
        }, closeHandler: { _ in values.finish() })
        _ = try await connection.call(method: "burst", params: .object([:]), generation: generation)
        var started = entered.makeAsyncIterator()
        _ = await started.next()
        // Later notifications and EOF must wait for the first handler to finish.
        #expect(await connection.isConnectionOpen)
        await gate.open()
        var received: [Int] = []
        for await value in delivered { received.append(value) }
        #expect(received == Array(0..<128))
        #expect(!(await connection.isConnectionOpen))
    }

    @Test func delayedOldReaderCannotCloseReconnectedPeer() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("old", json: "{}")
        daemon.onResult("new", json: #"{"ok":true}"#)
        daemon.pushNotifications(after: "old", [#"{"jsonrpc":"2.0","method":"hold","params":{}}"#])
        try daemon.start()
        defer { daemon.stop() }
        let connection = UnixSocketConnection(path: daemon.path)
        let gate = AsyncGate()
        let (entered, didEnter) = AsyncStream<Void>.makeStream()
        let first = try await connection.connect(notificationHandler: { _, _ in
            didEnter.yield(())
            await gate.wait()
        })
        _ = try await connection.call(method: "old", params: .object([:]), generation: first)
        var waiting = entered.makeAsyncIterator()
        _ = await waiting.next()
        await connection.close()
        let second = try await connection.connect(notificationHandler: { _, _ in })
        #expect(second != first)
        let reply = try await connection.call(method: "new", params: .object([:]), generation: second)
        #expect(reply.result?["ok"] == .bool(true))
        await gate.open()
        let final = try await connection.call(method: "new", params: .object([:]), generation: second)
        #expect(final.result?["ok"] == .bool(true))
        #expect(await connection.isConnectionOpen)
        await connection.close()
    }

    @Test func peerEOFCompletesExistingTransferStream() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("events.subscribe", json: #"{"subscribed":true}"#)
        daemon.onResult("transfers.current", json: "[]")
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        var updates = client.transferUpdates(filespace: "fs1").makeAsyncIterator()
        #expect(await updates.next() != nil)
        daemon.dropClient()
        #expect(await updates.next() == nil)
        // Stream termination is the reconnect signal; no timing-based sleep.
        var reconnected = client.transferUpdates(filespace: "fs1").makeAsyncIterator()
        #expect(await reconnected.next() != nil)
        #expect(daemon.requestCount("events.subscribe") == 2)
        await client.disconnect()
    }

    @Test func subscriptionErrorFinishesStreamWithoutFetchingSeed() async throws {
        let daemon = FakeDaemon()
        daemon.onError("events.subscribe", errorJSON: #"{"code":-32603,"message":"cannot subscribe"}"#)
        daemon.onResult("transfers.current", json: "[]")
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        var updates = client.transferUpdates(filespace: "fs1").makeAsyncIterator()
        #expect(await updates.next() == nil)
        #expect(daemon.requestCount("transfers.current") == 0)
        await client.disconnect()
    }
}

private func transferNote(id: String = "t1", path: String = "movie.mov", direction: String = "download", done: Int, state: String) -> String {
    #"{"jsonrpc":"2.0","method":"transfer","params":{"filespace":"fs1","transfer":{"id":"\#(id)","filespace":"fs1","path":"\#(path)","direction":"\#(direction)","bytesDone":\#(done),"bytesTotal":100,"state":"\#(state)"}}}"#
}

/// A gate for the fake daemon's dedicated POSIX serving thread, not an executor.
private final class ReplyGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var isOpen = false
    func wait() {
        condition.lock()
        defer { condition.unlock() }
        while !isOpen { condition.wait() }
    }
    func open() {
        condition.lock()
        isOpen = true
        condition.broadcast()
        condition.unlock()
    }
}

private actor AsyncGate {
    private var isOpen = false
    private var waiting: [CheckedContinuation<Void, Never>] = []
    func wait() async {
        if isOpen { return }
        await withCheckedContinuation { waiting.append($0) }
    }
    func open() {
        isOpen = true
        for continuation in waiting { continuation.resume() }
        waiting.removeAll()
    }
}
