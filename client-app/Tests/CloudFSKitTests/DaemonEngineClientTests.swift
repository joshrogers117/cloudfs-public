// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// DaemonEngineClient exercised against an in-process FakeDaemon over a real temp
// Unix socket — no live cloudfsd. Every test carries a fail-fast time limit so a
// framing/await bug can never hang the suite.

@Suite(.serialized, .timeLimit(.minutes(1)))
struct DaemonEngineClientTests {

    /// Spin up a fake daemon, run `body`, then tear down.
    private func withDaemon(_ configure: (FakeDaemon) -> Void,
                            _ body: (DaemonEngineClient) async throws -> Void) async throws {
        let daemon = FakeDaemon()
        configure(daemon)
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        // Give the listener a moment to be ready for connect.
        try await Task.sleep(for: .milliseconds(50))
        try await body(client)
        await client.disconnect()
    }

    // MARK: Framing + a representative method round-trip

    @Test(.timeLimit(.minutes(1)))
    func cacheInfoRoundTrip() async throws {
        try await withDaemon({ d in
            d.onResult("cache.info", json: #"""
            {"filespace":"fs1","location":"/cache","sizeBytes":100,"usedBytes":100,"pinnedBytes":20,"maxBytes":1000,"freeOnVolumeBytes":5000,"hitRate":0.9}
            """#)
        }) { client in
            let info = try await client.cacheInfo(filespace: "fs1")
            #expect(info.filespace == "fs1")
            #expect(info.maxBytes == 1000)
            #expect(info.pinnedBytes == 20)
            #expect(abs(info.hitRate - 0.9) < 0.0001)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func pinRoundTripEchoesParams() async throws {
        try await withDaemon({ d in
            // Echo back the path the client sent, proving params framing works.
            d.onResult("pin") { params in
                let path = params["path"]?.stringValue ?? "?"
                return #"{"path":"\#(path)","pinned":true,"recursive":false,"blocks":7}"#
            }
        }) { client in
            let state = try await client.pin(filespace: "fs1", path: "ShowA/clip.mov", recursive: false)
            #expect(state.path == "ShowA/clip.mov")
            #expect(state.pinned == true)
            #expect(state.blocks == 7)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func pinListDecodesByteAccounting() async throws {
        try await withDaemon({ d in
            // pin.list returns the appended per-pin byte accounting (CONTRACTS §4.1).
            // Echo the filespace the client sent back into a pin path so we can
            // assert on the result (no #expect inside the daemon handler closure —
            // it runs off the test task tree).
            d.onResult("pin.list") { params in
                // Single-line JSON: the daemon frames responses as newline-delimited,
                // so an embedded newline would truncate the frame.
                let fs = params["filespace"]?.stringValue ?? "?"
                return #"[{"path":"\#(fs)/timeline.prproj","pinned":true,"recursive":false,"blocks":128,"cachedBytes":67108864,"totalBytes":134217728,"cacheState":"pinning"},{"path":"\#(fs)/final.mov","pinned":true,"recursive":true,"blocks":256,"cachedBytes":268435456,"totalBytes":268435456,"cacheState":"pinned"}]"#
            }
        }) { client in
            let pins = try await client.pinList(filespace: "fs1")
            #expect(pins.count == 2)
            #expect(pins[0].path == "fs1/timeline.prproj")   // filespace echoed → params framed
            #expect(pins[0].cachedBytes == 67108864)
            #expect(pins[0].totalBytes == 134217728)
            #expect(pins[0].cacheState == .pinning)
            #expect(pins[1].cacheState == .pinned)
            // Display projection folds correctly.
            let item = PinnedItem(from: pins[0])
            #expect(item.state == .pinning)
            #expect(item.cachedBytes == 67108864)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func pinListToleratesOlderDaemonOmittingByteFields() async throws {
        try await withDaemon({ d in
            // Older daemon: only the original four fields, no byte accounting.
            d.onResult("pin.list", json: #"[{"path":"a/b.mov","pinned":true,"recursive":false,"blocks":4}]"#)
        }) { client in
            let pins = try await client.pinList(filespace: "fs1")
            #expect(pins.count == 1)
            #expect(pins[0].cachedBytes == nil)
            #expect(pins[0].totalBytes == nil)
            #expect(pins[0].cacheState == nil)
            // The projection defaults to .pinning when bytes are unknown (not yet
            // known-resident), since the engine reports two states only.
            #expect(PinnedItem(from: pins[0]).state == .pinning)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func cacheSetSizeRoundTrip() async throws {
        try await withDaemon({ d in
            d.onResult("cache.setSize") { params in
                let bytes = params["bytes"]?.intValue ?? 0
                return #"{"filespace":"fs1","location":"/cache","sizeBytes":\#(bytes),"usedBytes":\#(bytes),"pinnedBytes":0,"maxBytes":\#(bytes),"freeOnVolumeBytes":9999,"hitRate":0.5}"#
            }
        }) { client in
            let info = try await client.cacheSetSize(filespace: "fs1", bytes: 4242)
            #expect(info.maxBytes == 4242)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func cacheClearComputesFreedBytesFromInfoDelta() async throws {
        try await withDaemon({ d in
            // `cache.clear` calls `cache.info` FIRST (the "before" reading), then
            // the actual `cache.clear` RPC — the wire result is a `CacheInfo` (same
            // shape as setSize/setLocation), so `freedBytes` must be derived from
            // the usedBytes delta, not decoded off the wire.
            d.onResult("cache.info", json: #"""
            {"filespace":"fs1","location":"/cache","sizeBytes":1000,"usedBytes":1000,"pinnedBytes":200,"maxBytes":5000,"freeOnVolumeBytes":9999,"hitRate":0.5}
            """#)
            d.onResult("cache.clear", json: #"""
            {"filespace":"fs1","location":"/cache","sizeBytes":200,"usedBytes":200,"pinnedBytes":200,"maxBytes":5000,"freeOnVolumeBytes":9999,"hitRate":0.5}
            """#)
        }) { client in
            let result = try await client.cacheClear(filespace: "fs1")
            #expect(result.freedBytes == 800)
            #expect(result.info.usedBytes == 200)
            #expect(result.info.pinnedBytes == 200)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func cacheClearNeverReportsNegativeFreedBytes() async throws {
        try await withDaemon({ d in
            // A concurrent admission racing the clear could make usedBytes go UP
            // between the "before" read and the clear's result — freedBytes must
            // clamp at 0, never go negative.
            d.onResult("cache.info", json: #"""
            {"filespace":"fs1","location":"/cache","sizeBytes":100,"usedBytes":100,"pinnedBytes":0,"maxBytes":5000,"freeOnVolumeBytes":9999,"hitRate":0.5}
            """#)
            d.onResult("cache.clear", json: #"""
            {"filespace":"fs1","location":"/cache","sizeBytes":150,"usedBytes":150,"pinnedBytes":0,"maxBytes":5000,"freeOnVolumeBytes":9999,"hitRate":0.5}
            """#)
        }) { client in
            let result = try await client.cacheClear(filespace: "fs1")
            #expect(result.freedBytes == 0)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func currentTransfersMapsToGUIModel() async throws {
        try await withDaemon({ d in
            d.onResult("transfers.current", json: #"""
            [{"id":"t1","filespace":"fs1","path":"a/b/clip.mov","direction":"upload","bytesDone":50,"bytesTotal":100,"state":"active"}]
            """#)
        }) { client in
            let ts = try await client.currentTransfers(filespace: "fs1")
            #expect(ts.count == 1)
            #expect(ts[0].id == "t1")
            #expect(ts[0].kind == .upload)
            #expect(ts[0].state == .active)
            #expect(ts[0].fileName == "clip.mov")   // lastPathComponent mapping
            #expect(ts[0].bytesTotal == 100)
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func pauseResumeReturnVoidWithoutError() async throws {
        try await withDaemon({ d in
            d.onResult("transfers.pause", json: #"{"paused":true}"#)
            d.onResult("transfers.resume", json: #"{"paused":false}"#)
        }) { client in
            try await client.pauseTransfers(filespace: "fs1")
            try await client.resumeTransfers(filespace: "fs1")
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func setConnectionStateSendsState() async throws {
        try await withDaemon({ d in
            d.onResult("filespace.setConnectionState") { params in
                let state = params["state"]?.stringValue ?? "?"
                return #"{"id":"fs1","name":"FS One","status":"\#(state)","mountPath":null,"rootPoint":null,"role":"Admin"}"#
            }
        }) { client in
            try await client.setConnectionState(false, filespace: "fs1")  // → "disconnected"
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func mountUnmountRoundTrip() async throws {
        try await withDaemon({ d in
            d.onResult("mount", json: #"{"id":"fs1","name":"FS","status":"connected","mountPath":"/Volumes/fs","rootPoint":null,"role":null}"#)
            d.onResult("unmount", json: #"{"id":"fs1","name":"FS","status":"connected","mountPath":null,"rootPoint":null,"role":null}"#)
        }) { client in
            let mounted = try await client.mount(filespace: "fs1", at: "/Volumes/fs", name: "Filespace One")
            #expect(mounted.mountPath == "/Volumes/fs")
            let unmounted = try await client.unmount(filespace: "fs1", force: false)
            #expect(unmounted.mountPath == nil)
        }
    }

    @Test func stableLinkRPCPreservesIdentityAndProjectedPath() async throws {
        try await withDaemon({ daemon in
            daemon.onResult("link.create") { params in
                guard params["filespace"]?.stringValue == "fs1", params["path"]?.stringValue == "Show A/100% cut.mov" else { return "null" }
                return #"{"filespace":"fs1","itemId":"ino-stable"}"#
            }
            daemon.onResult("link.resolve") { params in
                guard params["filespace"]?.stringValue == "fs1", params["itemId"]?.stringValue == "ino-stable" else { return "null" }
                return #"{"filespace":"fs1","path":"Renamed/100% cut.mov"}"#
            }
        }) { client in
            let created = try await client.createItemLink(filespace: "fs1", path: "Show A/100% cut.mov")
            #expect(created.itemId == "ino-stable")
            let resolved = try await client.resolveItemLink(filespace: "fs1", itemID: created.itemId)
            #expect(resolved.path == "Renamed/100% cut.mov")
        }
    }

    @Test func stableLinkRejectsMismatchedFilespace() async throws {
        try await withDaemon({ daemon in
            daemon.onResult("link.create", json: #"{"filespace":"different","itemId":"ino-stable"}"#)
            daemon.onResult("link.resolve", json: #"{"filespace":"different","path":"secret.mov"}"#)
        }) { client in
            await #expect(throws: EngineError.self) { try await client.createItemLink(filespace: "fs1", path: "a") }
            await #expect(throws: EngineError.self) { try await client.resolveItemLink(filespace: "fs1", itemID: "ino-stable") }
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func flushWaitRoundTrip() async throws {
        try await withDaemon({ d in
            d.onResult("flush", json: #"{"path":"out","inSync":true,"pendingUploads":0,"pendingBytes":0}"#)
        }) { client in
            let st = try await client.flush(filespace: "fs1", path: "out", wait: true, timeoutMs: 5000)
            #expect(st.inSync == true)
            #expect(st.pendingUploads == 0)
        }
    }

    // MARK: Error mapping (CONTROL-API §2)

    @Test func recoveryRoundTripsKeepIdentityAndDestination() async throws {
        try await withDaemon({ daemon in
            daemon.onResult("recovery.list") { params in
                let fs = params["filespace"]?.stringValue ?? "missing"
                return #"[{"id":"retained-1","path":"\#(fs)/edit.prproj","bytes":1234,"reason":"version conflict","kind":"conflict","canRetry":false,"canExport":true}]"#
            }
            daemon.onResult("recovery.retry") { params in
                params["itemId"]?.stringValue == "retained-1" && params["filespace"]?.stringValue == "fs1" ? "{}" : "null"
            }
            daemon.onResult("recovery.complete", json: "{}")
            daemon.onResult("recovery.export") { params in
                // A percent sign and spaces must survive the local RPC unchanged.
                let destination = params["destination"]?.stringValue ?? "missing"
                let item = params["itemId"]?.stringValue ?? "missing"
                return #"{"path":"\#(destination)","bytes":1234,"sha256":"\#(item)"}"#
            }
        }) { client in
            let items = try await client.recoveryItems(filespace: "fs1")
            #expect(items.count == 1)
            #expect(items[0].path == "fs1/edit.prproj")
            #expect(!items[0].canRetry && items[0].canExport)
            try await client.retryRecovery(filespace: "fs1", itemID: "retained-1")
            let copy = try await client.exportRecovery(filespace: "fs1", itemID: "retained-1", destination: "/tmp/My 100% edit.prproj")
            #expect(copy.path == "/tmp/My 100% edit.prproj")
            #expect(copy.bytes == 1234 && copy.sha256 == "retained-1")
            try await client.completeRecovery(filespace: "fs1", itemID: "retained-1", destination: copy.path)
        }
    }

    @Test func recoveryExportFailureIsNotSuccess() async throws {
        try await withDaemon({ daemon in
            daemon.onError("recovery.export", errorJSON: #"{"code":-32027,"message":"local journal retained"}"#)
        }) { client in
            await #expect(throws: (any Error).self) {
                try await client.exportRecovery(filespace: "fs1", itemID: "x", destination: "/tmp/recovered")
            }
        }
    }

    @Test func failedTransferKeepsPathAndReason() async throws {
        try await withDaemon({ daemon in
            daemon.onResult("transfers.current", json: #"[{"id":"t1","filespace":"fs1","path":"edit/clip.mov","direction":"upload","bytesDone":0,"bytesTotal":100,"state":"error","error":"Upload blocked; journal retained"}]"#)
        }) { client in
            let transfers = try await client.currentTransfers(filespace: "fs1")
            #expect(transfers.first?.state == .failed)
            #expect(transfers.first?.path == "edit/clip.mov")
            #expect(transfers.first?.error == "Upload blocked; journal retained")
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func conflictErrorMapsWithData() async throws {
        try await withDaemon({ d in
            d.onError("cache.setSize",
                      errorJSON: #"{"code":-32021,"message":"version conflict","data":{"expected":4,"actual":5,"reason":"headroom"}}"#)
        }) { client in
            do {
                _ = try await client.cacheSetSize(filespace: "fs1", bytes: 1)
                Issue.record("expected throw")
            } catch let EngineError.conflict(expected, actual, reason) {
                #expect(expected == 4)
                #expect(actual == 5)
                #expect(reason == "headroom")
            }
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func syncTimeoutErrorMaps() async throws {
        try await withDaemon({ d in
            d.onError("flush",
                      errorJSON: #"{"code":-32050,"message":"sync timeout","data":{"pendingUploads":3,"pendingBytes":900}}"#)
        }) { client in
            do {
                _ = try await client.flush(filespace: "fs1", path: "out", wait: true, timeoutMs: 10)
                Issue.record("expected throw")
            } catch let EngineError.syncTimeout(uploads, bytes) {
                #expect(uploads == 3)
                #expect(bytes == 900)
            }
        }
    }

    @Test(.timeLimit(.minutes(1)))
    func notConnectedErrorMaps() async throws {
        try await withDaemon({ d in
            d.onError("evict", errorJSON: #"{"code":-32010,"message":"filespace not mounted"}"#)
        }) { client in
            do {
                _ = try await client.evict(filespace: "fs1", path: "x")
                Issue.record("expected throw")
            } catch let e as EngineError {
                guard case .notConnected = e else { Issue.record("wrong: \(e)"); return }
            }
        }
    }

    // MARK: Event-stream delivery (CONTROL-API §6)

    @Test(.timeLimit(.minutes(1)))
    func transferEventStreamDelivers() async throws {
        try await withDaemon({ d in
            d.onResult("events.subscribe", json: #"{"subscribed":true}"#)
            // The seed snapshot the client fetches on subscribe.
            d.onResult("transfers.current", json: "[]")
            // After subscribe, push two transfer notifications.
            d.pushNotifications(after: "events.subscribe", [
                #"{"jsonrpc":"2.0","method":"transfer","params":{"filespace":"fs1","transfer":{"id":"t9","filespace":"fs1","path":"big.mov","direction":"download","bytesDone":10,"bytesTotal":100,"state":"active"}}}"#,
                #"{"jsonrpc":"2.0","method":"transfer","params":{"filespace":"fs1","transfer":{"id":"t9","filespace":"fs1","path":"big.mov","direction":"download","bytesDone":100,"bytesTotal":100,"state":"done"}}}"#,
            ])
        }) { client in
            var sawActive = false
            var sawDone = false
            // Consume the stream until we observe the "done" snapshot (fail-fast
            // via the @Test time limit if it never arrives).
            for await snapshot in client.transferUpdates(filespace: "fs1") {
                if let t = snapshot.first(where: { $0.id == "t9" }) {
                    if t.state == .active { sawActive = true }
                    if t.state == .completed { sawDone = true; break }
                }
            }
            #expect(sawActive || sawDone)   // at least one event folded in
            #expect(sawDone)
        }
    }

    // MARK: Transport unavailability (no daemon)

    @Test(.timeLimit(.minutes(1)))
    func connectFailureSurfacesAsUnavailable() async throws {
        let client = DaemonEngineClient(socketPath: "/tmp/cfs-does-not-exist-\(UUID().uuidString.prefix(6)).sock")
        do {
            _ = try await client.cacheInfo(filespace: "fs1")
            Issue.record("expected throw")
        } catch let e as EngineError {
            guard case .unavailable = e else { Issue.record("wrong: \(e)"); return }
        }
        await client.disconnect()
    }

    // MARK: Reconnect after the daemon drops mid-session (regression)

    /// After the cloudfsd socket drops (daemon restart/crash), the reader thread
    /// closes the underlying connection but the client used to leave its own
    /// `connected` flag set — so every later call short-circuited `ensureConnected`
    /// and threw `.unavailable("not connected")` forever, until app relaunch.
    /// The next engine call must transparently reconnect instead.
    @Test(.timeLimit(.minutes(1)))
    func reconnectsAfterPeerDropsMidSession() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("cache.info", json: #"""
        {"filespace":"fs1","location":"/cache","sizeBytes":100,"usedBytes":100,"pinnedBytes":20,"maxBytes":1000,"freeOnVolumeBytes":5000,"hitRate":0.9}
        """#)
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        try await Task.sleep(for: .milliseconds(50))

        // First call establishes the connection.
        let first = try await client.cacheInfo(filespace: "fs1")
        #expect(first.maxBytes == 1000)

        // Daemon drops the peer (restart/crash). Give the client's reader thread a
        // moment to observe EOF and flip the underlying connection closed.
        daemon.dropClient()
        try await Task.sleep(for: .milliseconds(100))

        // The next call must transparently reconnect and succeed — NOT throw
        // `.unavailable` forever.
        let second = try await client.cacheInfo(filespace: "fs1")
        #expect(second.maxBytes == 1000)

        await client.disconnect()
    }

    /// The transfer event subscription state must be cleared on reconnect so a new
    /// stream re-subscribes against the fresh connection. Here we drop the peer and
    /// confirm a request/response call works again (which fails if the stale
    /// `connected`/subscription state blocks `ensureConnected`).
    @Test(.timeLimit(.minutes(1)))
    func reconnectAfterDropResubscribesCleanly() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("events.subscribe", json: #"{"subscribed":true}"#)
        daemon.onResult("transfers.current", json: "[]")
        daemon.onResult("cache.info", json: #"""
        {"filespace":"fs1","location":"/cache","sizeBytes":1,"usedBytes":1,"pinnedBytes":0,"maxBytes":42,"freeOnVolumeBytes":9,"hitRate":0.1}
        """#)
        try daemon.start()
        defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        try await Task.sleep(for: .milliseconds(50))

        _ = try await client.cacheInfo(filespace: "fs1")     // connect + subscribe path
        daemon.dropClient()
        try await Task.sleep(for: .milliseconds(100))

        // Reconnects and the call succeeds against the fresh connection.
        let info = try await client.cacheInfo(filespace: "fs1")
        #expect(info.maxBytes == 42)

        await client.disconnect()
    }

    /// A user-initiated `disconnect()` must NOT auto-reconnect: after disconnect,
    /// the next call should attempt a fresh connect to whatever socket exists. We
    /// assert disconnect is honored by pointing at a now-stopped daemon — the call
    /// fails as `.unavailable` rather than silently reusing a live connection.
    @Test(.timeLimit(.minutes(1)))
    func explicitDisconnectDoesNotAutoReconnectToDeadSocket() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("cache.info", json: #"""
        {"filespace":"fs1","location":"/cache","sizeBytes":1,"usedBytes":1,"pinnedBytes":0,"maxBytes":7,"freeOnVolumeBytes":9,"hitRate":0.1}
        """#)
        try daemon.start()
        let client = DaemonEngineClient(socketPath: daemon.path)
        try await Task.sleep(for: .milliseconds(50))

        _ = try await client.cacheInfo(filespace: "fs1")     // connect
        await client.disconnect()                            // user-initiated close
        daemon.stop()                                        // socket is now gone
        try await Task.sleep(for: .milliseconds(50))

        // After an explicit disconnect, the next call re-attempts connect (it does
        // not silently reuse a stale live socket), so against a dead socket it
        // surfaces `.unavailable` — proving disconnect was honored.
        do {
            _ = try await client.cacheInfo(filespace: "fs1")
            Issue.record("expected throw after disconnect to dead socket")
        } catch let e as EngineError {
            guard case .unavailable = e else { Issue.record("wrong: \(e)"); return }
        }
        await client.disconnect()
    }

    // MARK: NullEngineClient (offline default)

    @Test(.timeLimit(.minutes(1)))
    func nullEngineIsUnavailable() async throws {
        let null = NullEngineClient()
        #expect(null.isAvailable == false)
        do {
            _ = try await null.cacheInfo(filespace: "fs1")
            Issue.record("expected throw")
        } catch let e as EngineError {
            guard case .unavailable = e else { Issue.record("wrong: \(e)"); return }
        }
        // Its stream finishes immediately.
        var count = 0
        for await _ in null.transferUpdates(filespace: "fs1") { count += 1 }
        #expect(count == 0)
    }
}

// MARK: - EngineFactory selection

@Suite(.timeLimit(.minutes(1)))
struct EngineFactoryTests {

    @Test func envSocketSelectsDaemon() {
        let (engine, path) = EngineFactory.makeEngine(env: ["CLOUDFS_SOCKET": "/tmp/x.sock"])
        #expect(engine is DaemonEngineClient)
        #expect(path == "/tmp/x.sock")
    }

    @Test func missingDefaultSocketSelectsNull() {
        let (engine, path) = EngineFactory.makeEngine(env: [:], fileExists: { _ in false })
        #expect(engine is NullEngineClient)
        #expect(path == nil)
    }

    @Test func presentDefaultSocketSelectsDaemon() {
        // Only the legacy default socket exists (no group-container socket).
        let def = EngineFactory.defaultSocketPath
        let (engine, path) = EngineFactory.makeEngine(env: [:], fileExists: { $0 == def })
        #expect(engine is DaemonEngineClient)
        #expect(path == def)
    }

    /// M7: the launch-agent daemon binds the provisioned socket — when it is live
    /// it wins over the legacy default.
    @Test func liveProvisionedSocketIsPreferredOverDefault() {
        guard let ps = EngineFactory.provisionedSocketPath else { return }
        let (engine, path) = EngineFactory.makeEngine(env: [:], fileExists: { _ in true })
        #expect(engine is DaemonEngineClient)
        #expect(path == ps)
    }
}

// MARK: - JSON-RPC framing + error mapping (no socket)

@Suite struct JSONRPCFramingTests {

    @Test func requestEncodesNewlineDelimitableObject() throws {
        let req = RPCRequest(id: 7, method: "cache.setSize", params: .params(["bytes": .int(100)]))
        let data = try JSONEncoder().encode(req)
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(obj?["jsonrpc"] as? String == "2.0")
        #expect(obj?["id"] as? Int == 7)
        #expect(obj?["method"] as? String == "cache.setSize")
    }

    @Test func responseFrameDecodes() throws {
        let line = #"{"jsonrpc":"2.0","id":7,"result":{"path":"p","pinned":true,"recursive":false,"blocks":1}}"#
        let frame = try JSONDecoder().decode(RPCFrame.self, from: Data(line.utf8))
        #expect(frame.id == 7)
        #expect(frame.error == nil)
        let pin = try #require(frame.result).decode(PinState.self)
        #expect(pin.pinned == true)
    }

    @Test func notificationFrameHasNoID() throws {
        let line = #"{"jsonrpc":"2.0","method":"transfer","params":{"filespace":"f"}}"#
        let frame = try JSONDecoder().decode(RPCFrame.self, from: Data(line.utf8))
        #expect(frame.id == nil)
        #expect(frame.method == "transfer")
        #expect(frame.params?["filespace"]?.stringValue == "f")
    }

    @Test func errorBodyMapsByCode() throws {
        // Decode an error body off the wire and confirm it maps to .locked.
        let line = #"{"code":-32022,"message":"locked","data":{"heldBy":"mara","expiresAt":"soon"}}"#
        let body = try JSONDecoder().decode(RPCErrorBody.self, from: Data(line.utf8))
        let mapped = EngineError.from(body)
        guard case let .locked(heldBy, expiresAt) = mapped else {
            Issue.record("not .locked: \(mapped)"); return
        }
        #expect(heldBy == "mara")
        #expect(expiresAt == "soon")
    }
}
