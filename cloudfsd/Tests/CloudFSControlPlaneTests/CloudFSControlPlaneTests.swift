// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSControlPlane
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

final class CloudFSControlPlaneTests: XCTestCase {

    func testClosedControlPeerThrowsInsteadOfSignalling() throws {
        let (sender, peer) = try makeSocketPair()
        defer { sender.close(); peer.close() }
        #if !canImport(Glibc)
        var protected: Int32 = 0
        var size = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(getsockopt(sender.fd, SOL_SOCKET, SO_NOSIGPIPE, &protected, &size), 0)
        // Avoid killing the test runner itself if this protection regresses.
        guard protected == 1 else { return XCTFail("control socket can raise SIGPIPE") }
        #endif
        peer.close()
        XCTAssertNoThrow(try sender.writeAll([]))
        XCTAssertThrowsError(try sender.writeAll([1, 2, 3])) { error in
            guard case POSIXSocketError.errno("write", EPIPE) = error else {
                return XCTFail("expected EPIPE, got \(error)")
            }
        }
    }

    // MARK: - Frozen helper (kept from the foundation suite)

    func testRpcErrorMapsEngineErrorOneToOne() {
        let resp = rpcError(for: EngineError(.conflict, "version conflict",
                                             data: ["expected": .int(4), "actual": .int(5)]),
                            id: .number(3))
        XCTAssertEqual(resp.id, .number(3))
        XCTAssertEqual(resp.error?.code, -32021)
        XCTAssertEqual(resp.error?.message, "version conflict")
        XCTAssertNil(resp.result)
    }

    func testUnknownErrorBecomesInternal() {
        struct Boom: Error {}
        let resp = rpcError(for: Boom(), id: .string("x"))
        XCTAssertEqual(resp.error?.code, -32603)
    }

    func testStubServeThrows() async {
        let cp = StubControlPlane()
        do {
            try await cp.serve(socketPath: "/tmp/cloudfsd.sock", engine: MockEngine())
            XCTFail("expected unimplemented")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .unimplemented)
        } catch { XCTFail("wrong error: \(error)") }
    }

    // MARK: - Framing (split / coalesced / CRLF / empty lines)

    func testFrameDecoderSplitsAndCoalesces() throws {
        var dec = FrameDecoder()
        // One frame split across three pushes yields nothing until the newline.
        XCTAssertTrue(try dec.push(Array("{\"a\":".utf8)).isEmpty)
        XCTAssertTrue(try dec.push(Array("1}".utf8)).isEmpty)
        var frames = try dec.push(Array("\n".utf8))
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(String(data: frames[0], encoding: .utf8), "{\"a\":1}")

        // Three frames coalesced into one chunk all come back together.
        frames = try dec.push(Array("{\"x\":1}\n{\"y\":2}\n{\"z\":3}\n".utf8))
        XCTAssertEqual(frames.map { String(data: $0, encoding: .utf8) },
                       ["{\"x\":1}", "{\"y\":2}", "{\"z\":3}"])

        // CRLF tolerated, blank keep-alive lines dropped.
        frames = try dec.push(Array("{\"q\":1}\r\n\n".utf8))
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(String(data: frames[0], encoding: .utf8), "{\"q\":1}")
    }

    func testFrameDecoderRejectsOverlongLine() {
        var dec = FrameDecoder()
        let huge = [UInt8](repeating: 0x41, count: FrameDecoder.maxFrameBytes + 1)
        XCTAssertThrowsError(try dec.push(huge))
    }

    // MARK: - Round-trip every ControlMethod against the mock engine

    func testEveryControlMethodRoundTrips() async throws {
        let harness = try Harness()
        defer { harness.tearDown() }

        // (method, params, assert on the decoded result CodableValue)
        for method in ControlMethod.allCases {
            let (params, id) = Self.sampleRequest(for: method)
            // events.* are exercised separately (they stream).
            if method == .eventsSubscribe || method == .eventsUnsubscribe { continue }
            let resp = try await harness.call(method: method.rawValue, id: id, params: params)
            XCTAssertEqual(resp.id, id, "\(method) echoes id")
            XCTAssertNil(resp.error, "\(method) should succeed: \(String(describing: resp.error))")
            XCTAssertNotNil(resp.result, "\(method) returns a result")
        }
    }

    func testStatusOmittedReturnsArray() async throws {
        let harness = try Harness()
        defer { harness.tearDown() }
        let resp = try await harness.call(method: "status", id: .number(1), params: .object([:]))
        guard case .array = resp.result else {
            return XCTFail("status{} must return an array, got \(String(describing: resp.result))")
        }
    }

    func testStatusWithFilespaceReturnsObject() async throws {
        let harness = try Harness()
        defer { harness.tearDown() }
        let resp = try await harness.call(method: "status", id: .number(1),
                                          params: .object(["filespace": .string("space-1")]))
        guard case .object = resp.result else {
            return XCTFail("status{filespace} must return one object, got \(String(describing: resp.result))")
        }
    }

    // MARK: - Error-code mapping over the wire

    func testEngineErrorMapsToWireCode() async throws {
        let engine = MockEngine()
        engine.flushError = EngineError(.syncTimeout, "deadline",
                                        data: ["pendingUploads": .int(2), "pendingBytes": .int(99)])
        let harness = try Harness(engine: engine)
        defer { harness.tearDown() }
        let resp = try await harness.call(method: "flush", id: .number(7),
                                          params: .object(["filespace": .string("s"), "path": .string("/a"),
                                                           "wait": .bool(true)]))
        XCTAssertEqual(resp.error?.code, -32050)
        XCTAssertEqual(resp.id, .number(7))
        XCTAssertNil(resp.result)
    }

    func testUnknownMethodIsInvalidParams() async throws {
        let harness = try Harness()
        defer { harness.tearDown() }
        let resp = try await harness.call(method: "does.not.exist", id: .number(1), params: .object([:]))
        XCTAssertEqual(resp.error?.code, -32602)
    }

    func testMalformedParamsIsInvalidParams() async throws {
        let harness = try Harness()
        defer { harness.tearDown() }
        // pin requires `path`; omit it.
        let resp = try await harness.call(method: "pin", id: .number(1),
                                          params: .object(["filespace": .string("s")]))
        XCTAssertEqual(resp.error?.code, -32602)
    }

    func testNotificationGetsNoReply() async throws {
        let harness = try Harness()
        defer { harness.tearDown() }
        // A request with no id is a notification: server must send nothing for it.
        // Send the notification, then a real request; we should read ONLY the reply.
        try harness.writeFrame(.init(id: nil, method: "filespace.list", params: .object([:])))
        let resp = try await harness.call(method: "system.version", id: .number(42), params: .object([:]))
        XCTAssertEqual(resp.id, .number(42))   // not the notification
        XCTAssertNil(resp.error)
    }

    // MARK: - Coalesced frames in a single write are each answered

    func testMultipleFramesInOnePacket() async throws {
        let harness = try Harness()
        defer { harness.tearDown() }
        let a = RPCRequest(id: .number(1), method: "filespace.list", params: .object([:]))
        let b = RPCRequest(id: .number(2), method: "system.version", params: .object([:]))
        var bytes = try FrameEncoder.encode(a)
        bytes.append(try FrameEncoder.encode(b))
        harness.client.writeRaw(bytes)
        let r1 = try await harness.readResponse()
        let r2 = try await harness.readResponse()
        XCTAssertEqual(Set([r1.id, r2.id]), Set([.number(1), .number(2)]))
    }

    // MARK: - Event-stream delivery to a subscriber

    func testSubscribeDeliversNotifications() async throws {
        let engine = MockEngine()
        let xfer = Transfer(id: "t1", filespace: "space-1", path: "/clip.mov",
                            direction: .download, bytesDone: 10, bytesTotal: 100, state: .active)
        engine.events = [
            .transfer(filespace: "space-1", transfer: xfer),
            .cache(filespace: "space-1", cache: MockEngine.sampleCache),
        ]
        let harness = try Harness(engine: engine)
        defer { harness.tearDown() }

        // Subscribe; first frame back is the ack.
        let ack = try await harness.call(method: "events.subscribe", id: .number(1),
                                         params: .object([:]))
        XCTAssertNil(ack.error)

        // Then two notifications stream in (no id).
        let n1 = try await harness.readNotification()
        let n2 = try await harness.readNotification()
        let methods = Set([n1.method, n2.method])
        XCTAssertEqual(methods, ["transfer", "cache"])

        // The transfer notification carries the right shape.
        let transferNote = (n1.method == "transfer") ? n1 : n2
        guard case let .object(obj) = transferNote.params,
              case .string("space-1")? = obj["filespace"],
              case let .object(t)? = obj["transfer"],
              case .string("t1")? = t["id"] else {
            return XCTFail("transfer notification shape wrong: \(transferNote.params)")
        }
    }

    func testUnsubscribeAcks() async throws {
        let harness = try Harness()
        defer { harness.tearDown() }
        _ = try await harness.call(method: "events.subscribe", id: .number(1), params: .object([:]))
        let resp = try await harness.call(method: "events.unsubscribe", id: .number(2), params: .object([:]))
        XCTAssertNil(resp.error)
        guard case let .object(o) = resp.result, case .bool(false)? = o["subscribed"] else {
            return XCTFail("unsubscribe should return {subscribed:false}")
        }
    }

    // MARK: - Real bound socket end-to-end

    func testAbandonedRequestsKeepListenerResponsive() async throws {
        let path = "/tmp/cfsd-abandon-\(UInt32.random(in: 0..<0xFFFFFF)).sock"
        let server = UnixSocketControlPlane()
        let serveTask = Task { try await server.serve(socketPath: path, engine: MockEngine()) }
        try await waitForFile(path)
        let request = try FrameEncoder.encode(RPCRequest(id: .number(99), method: "system.version", params: .object([:])))
        for _ in 0..<40 {
            let abandoned = try connectUnix(path)
            try abandoned.writeAll(Array(request))
            abandoned.close()
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        let client = try connectUnix(path)
        defer { client.close() }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        XCTAssertEqual(setsockopt(client.fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)), 0)
        do {
            try client.writeAll(Array(request))
            let response = try await readOneResponse(from: client)
            XCTAssertEqual(response.id, .number(99))
            XCTAssertNil(response.error)
        } catch { XCTFail("listener stopped responding after client disconnects: \(error)") }
        await server.stop()
        serveTask.cancel()
    }

    func testRealBoundSocketRoundTrip() async throws {
        // `sun_path` holds at most 103 bytes + NUL, so use a SHORT path (the long
        // per-test temp dir would overflow it). A random suffix avoids collisions.
        let path = "/tmp/cfsd-\(UInt32.random(in: 0..<0xFFFFFF)).sock"
        let server = UnixSocketControlPlane()
        let serveTask = Task { try await server.serve(socketPath: path, engine: MockEngine()) }
        // Wait for the socket file to appear.
        try await waitForFile(path)
        // Verify mode 0600.
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)

        let client = try connectUnix(path)
        defer { client.close() }
        let req = RPCRequest(id: .number(99), method: "system.version", params: .object([:]))
        try client.writeAll([UInt8](try FrameEncoder.encode(req)))
        let resp = try await readOneResponse(from: client)
        XCTAssertEqual(resp.id, .number(99))
        XCTAssertNil(resp.error)

        await server.stop()
        serveTask.cancel()
        XCTAssertFalse(FileManager.default.fileExists(atPath: path), "stop() unlinks the socket")
    }

    // MARK: - Fixtures

    /// Build a representative params object + id for each method.
    static func sampleRequest(for m: ControlMethod) -> (CodableValue, RPCID) {
        let fs: CodableValue = .object(["filespace": .string("space-1")])
        let fsPath: CodableValue = .object(["filespace": .string("space-1"), "path": .string("/a/b")])
        let id = RPCID.number(1)
        switch m {
        case .filespaceList:        return (.object([:]), id)
        case .filespaceConnect:     return (.object(["filespace": .string("space-1")]), id)
        case .filespaceDisconnect:  return (fs, id)
        case .filespaceSetConnection:
            return (.object(["filespace": .string("space-1"), "state": .string("connected")]), id)
        case .snapshotMount: return (.object(["filespace": .string("space-1"), "snapshotId": .string("snap-1")]), id)
        case .snapshotUnmount: return (.object(["mountId": .string("snapshot-1")]), id)
        case .snapshotMounts: return (fs, id)
        case .mount:                return (fs, id)
        case .unmount:              return (fs, id)
        case .status:               return (fs, id)
        case .cacheInfo:            return (fs, id)
        case .cacheSetSize:         return (.object(["filespace": .string("space-1"), "bytes": .int(1024)]), id)
        case .cacheSetLocation:     return (.object(["filespace": .string("space-1"), "path": .string("/cache")]), id)
        case .cacheClear:           return (fs, id)
        case .pin:                  return (fsPath, id)
        case .unpin:                return (fsPath, id)
        case .pinList:              return (fs, id)
        case .prefetch:             return (fsPath, id)
        case .evict:                return (fsPath, id)
        case .linkCreate:           return (fsPath, id)
        case .linkResolve:
            return (.object(["filespace": .string("space-1"), "itemId": .string("ino-x")]), id)
        case .transfersCurrent:     return (fs, id)
        case .transfersPause:       return (fs, id)
        case .transfersResume:      return (fs, id)
        case .recoveryList:         return (fs, id)
        case .recoveryRetry:
            return (.object(["filespace": .string("space-1"), "itemId": .string("ino-x")]), id)
        case .recoveryExport, .recoveryComplete:
            return (.object(["filespace": .string("space-1"), "itemId": .string("ino-x"),
                             "destination": .string("/tmp/recovered.mov")]), id)
        case .syncState:            return (fsPath, id)
        case .flush:                return (fsPath, id)
        case .dataReadRange:
            return (.object(["filespace": .string("space-1"), "itemId": .string("ino-x"),
                             "version": .string("v1"), "offset": .int(0), "length": .int(1024)]), id)
        case .dataLookup:
            return (.object(["filespace": .string("space-1"), "itemId": .string("ino-x")]), id)
        case .dataEnumerate:
            return (.object(["filespace": .string("space-1"), "container": .string("root")]), id)
        case .dataEnumerateChanges:
            return (.object(["filespace": .string("space-1"), "container": .string("root"),
                             "anchor": .string("a1")]), id)
        case .eventsSubscribe:      return (.object([:]), id)
        case .eventsUnsubscribe:    return (.object([:]), id)
        case .systemVersion:        return (.object([:]), id)
        }
    }
}
