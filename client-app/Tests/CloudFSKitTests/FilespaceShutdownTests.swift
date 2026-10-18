// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Testing
@testable import CloudFSKit

@Suite(.timeLimit(.minutes(1)))
struct FilespaceShutdownTests {
    private final class Trace: @unchecked Sendable {
        let lock = NSLock()
        var values: [String] = []
        func add(_ value: String) { lock.withLock { values.append(value) } }
        var snapshot: [String] { lock.withLock { values } }
    }

    @Test func quitWaitsForEveryFlushBeforeUnmountingAndResumesPausedWrites() async throws {
        let daemon = FakeDaemon(), trace = Trace()
        let release = DispatchSemaphore(value: 0)
        daemon.onResult("filespace.list", json: #"[{"id":"a","name":"A","status":"connected","mountPath":"/a","paused":true},{"id":"b","name":"B","status":"connected","mountPath":"/b"}]"#)
        daemon.onResult("transfers.resume") { p in trace.add("resume:" + p["filespace"]!.stringValue!); return "{}" }
        daemon.onResult("flush") { p in
            let id = p["filespace"]!.stringValue!
            trace.add("flush:" + id)
            if id == "b", trace.snapshot.filter({ $0 == "flush:b" }).count == 1 {
                _ = release.wait(timeout: .now() + 5)
            }
            return #"{"path":"","inSync":true,"pendingUploads":0,"pendingBytes":0}"#
        }
        daemon.onResult("unmount") { p in
            let id = p["filespace"]!.stringValue!
            trace.add("unmount:" + id)
            return #"{"id":"\#(id)","name":"Test","status":"disconnected"}"#
        }
        try daemon.start()
        defer { release.signal(); daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        let draining = Task { try await FilespaceShutdown.drain(client) }
        let deadline = ContinuousClock.now + .seconds(3)
        while !trace.snapshot.contains("flush:b"), ContinuousClock.now < deadline { await Task.yield() }
        #expect(trace.snapshot == ["resume:a", "flush:a", "flush:b"])
        #expect(daemon.requestCount("unmount") == 0)
        release.signal()
        try await draining.value
        #expect(trace.snapshot == ["resume:a", "flush:a", "flush:b", "unmount:a", "unmount:b", "flush:a", "flush:b"])
        await client.disconnect()
    }

    @Test func lateWriteDuringAnotherFilespaceFlushMustCommitAfterEveryUnmount() async throws {
        let daemon = FakeDaemon(), trace = Trace()
        let lateWriteCommitted = DispatchSemaphore(value: 0)
        daemon.onResult("filespace.list", json: #"[{"id":"a","name":"A","status":"connected","mountPath":"/a"},{"id":"b","name":"B","status":"connected","mountPath":"/b"}]"#)
        daemon.onResult("flush") { p in
            let id = p["filespace"]!.stringValue!
            trace.add("flush:" + id)
            if id == "b", trace.snapshot.filter({ $0 == "flush:b" }).count == 1 {
                // A remains mounted while B drains: an editor's new A write
                // is locally acknowledged after A's first remote barrier.
                trace.add("late-write:a")
            }
            if id == "a", trace.snapshot.contains("late-write:a") {
                trace.add("waiting-for-late-commit:a")
                _ = lateWriteCommitted.wait(timeout: .now() + 5)
                trace.add("late-commit:a")
            }
            return #"{"path":"","inSync":true,"pendingUploads":0,"pendingBytes":0}"#
        }
        daemon.onResult("unmount") { p in
            let id = p["filespace"]!.stringValue!
            trace.add("unmount:" + id)
            return #"{"id":"\#(id)","name":"Test","status":"disconnected"}"#
        }
        try daemon.start()
        defer { lateWriteCommitted.signal(); daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        let draining = Task {
            try await FilespaceShutdown.drain(client)
            trace.add("drain-returned")
        }
        let deadline = ContinuousClock.now + .seconds(3)
        while !trace.snapshot.contains("waiting-for-late-commit:a"), ContinuousClock.now < deadline { await Task.yield() }
        #expect(trace.snapshot == ["flush:a", "flush:b", "late-write:a", "unmount:a", "unmount:b", "flush:a", "waiting-for-late-commit:a"])
        #expect(!trace.snapshot.contains("drain-returned"))
        lateWriteCommitted.signal()
        try await draining.value
        #expect(trace.snapshot.suffix(3) == ["late-commit:a", "flush:b", "drain-returned"])
        await client.disconnect()
    }

    @Test func failedFlushPreservesVolumesAndRestoresPause() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("filespace.list", json: #"[{"id":"a","name":"A","status":"connected","mountPath":"/a","paused":true}]"#)
        daemon.onResult("transfers.resume", json: "{}")
        daemon.onResult("transfers.pause", json: "{}")
        daemon.onError("flush", errorJSON: #"{"code":-32000,"message":"Upload failed; journal retained"}"#)
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        await #expect(throws: EngineError.self) { try await FilespaceShutdown.drain(client) }
        #expect(daemon.requestCount("transfers.resume") == 1)
        #expect(daemon.requestCount("transfers.pause") == 1)
        #expect(daemon.requestCount("unmount") == 0)
        await client.disconnect()
    }
}
