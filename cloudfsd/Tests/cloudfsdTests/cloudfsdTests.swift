// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
// @testable (not a plain import): the FilespaceKeyResolver tests below compare resolved key
// bytes via `masterRawBytes`, which is internal to CloudFSCrypto (deliberately not public —
// only the CTR spike-compat path and now these tests need raw access).
@testable import CloudFSCrypto
import CloudFSCache
import CloudFSGateway
import CloudFSMount
import CloudFSControlPlane
import CloudFSTransfer
@testable import cloudfsd

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Fail-fast timeout (a deadlock MUST fail, never hang) -----------------

private struct TestTimeout: Error {}

/// Race `body` against a deadline; XCTFail + throw if the deadline wins so a hung
/// async path FAILS fast instead of wedging the SwiftPM `.build` lock.
private func withTestTimeout(_ seconds: Double = 20,
                             file: StaticString = #filePath, line: UInt = #line,
                             _ body: @escaping @Sendable () async throws -> Void) async throws {
    let box = OneShotResult()
    let work = Task { do { try await body() } catch { box.resume(.failure(error)) }; box.resume(.success(())) }
    let timer = Task {
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
        box.resume(.failure(TestTimeout()))
    }
    defer { work.cancel(); timer.cancel() }
    do { try await box.value }
    catch is TestTimeout {
        XCTFail("test exceeded \(seconds)s deadline — likely a deadlock", file: file, line: line)
        throw TestTimeout()
    }
}

private final class OneShotResult: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Void, Error>?
    private var waiter: CheckedContinuation<Void, Error>?
    func resume(_ r: Result<Void, Error>) {
        lock.lock()
        if result != nil { lock.unlock(); return }
        result = r; let w = waiter; waiter = nil; lock.unlock()
        w?.resume(with: r)
    }
    var value: Void {
        get async throws {
            try await withCheckedThrowingContinuation { cont in
                lock.lock()
                if let r = result { lock.unlock(); cont.resume(with: r); return }
                waiter = cont; lock.unlock()
            }
        }
    }
}

// MARK: - URLProtocol gateway stub --------------------------------------------
//
// Answers the gateway's /v1 routes AND the presigned blob GET/PUTs from one
// in-memory table so the real HttpGatewayClient + RealTransferEngine run end to
// end with no live server. Presign returns a self-describing blob URL keyed by the
// object key; a GET on it serves the ciphertext a prior PUT stored.

final class GWStub: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) private static var routes: [String: (URLRequest) -> (Int, String)] = [:]
    nonisolated(unsafe) private static var blobs: [String: Data] = [:]
    /// Per-route request count ("METHOD path") so tests can assert the engine made
    /// exactly N gateway round-trips (P4 manifest-cache regression).
    nonisolated(unsafe) private static var counts: [String: Int] = [:]
    /// P2: injected latency per blob GET (simulated object-store TTFB) + per-key GET
    /// counts, so cold-throughput tests are deterministic and dedup is assertable.
    nonisolated(unsafe) private static var blobGetLatencyMs: Int = 0
    nonisolated(unsafe) private static var blobGetCounts: [String: Int] = [:]
    private static let lock = NSLock()

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        routes = [:]; blobs = [:]; counts = [:]
        blobGetLatencyMs = 0; blobGetCounts = [:]
    }
    static func setBlobGetLatency(ms: Int) {
        lock.lock(); defer { lock.unlock() }; blobGetLatencyMs = ms
    }
    static func totalBlobGets() -> Int {
        lock.lock(); defer { lock.unlock() }; return blobGetCounts.values.reduce(0, +)
    }
    static func on(_ key: String, status: Int = 200, json: String) {
        lock.lock(); defer { lock.unlock() }
        routes[key] = { _ in (status, json) }
    }
    /// Request-aware route (e.g. to branch on ?parent= for namespace listings).
    static func on(_ key: String, handler: @escaping (URLRequest) -> (Int, String)) {
        lock.lock(); defer { lock.unlock() }
        routes[key] = handler
    }
    /// How many times the stub served the route `"METHOD path"`.
    static func count(_ key: String) -> Int {
        lock.lock(); defer { lock.unlock() }; return counts[key] ?? 0
    }

    static func session() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [GWStub.self]
        return URLSession(configuration: cfg)
    }

    static func bodyData(_ req: URLRequest) -> Data? {
        if let b = req.httpBody { return b }
        guard let s = req.httpBodyStream else { return nil }
        s.open(); defer { s.close() }
        var data = Data(); let n = 4096
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: n); defer { buf.deallocate() }
        while s.hasBytesAvailable { let r = s.read(buf, maxLength: n); if r <= 0 { break }; data.append(buf, count: r) }
        return data.isEmpty ? nil : data
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        let req = request
        let method = req.httpMethod ?? "GET"
        let url = req.url!
        let path = url.path

        // Blob plane: presigned GET/PUT carry ?key=<objectKey>.
        if path == "/blob", let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let key = comps.queryItems?.first(where: { $0.name == "key" })?.value {
            Self.lock.lock()
            if method == "PUT" {
                Self.blobs[key] = Self.bodyData(req) ?? Data()
                Self.lock.unlock()
                finish(200, Data())
                return
            } else {
                Self.blobGetCounts[key, default: 0] += 1
                let data = Self.blobs[key]
                let latency = Self.blobGetLatencyMs
                Self.lock.unlock()
                let respond = { [self] in
                    if let data { finish(200, data) } else { finish(404, Data("missing".utf8)) }
                }
                if latency > 0 {
                    DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(latency), execute: respond)
                } else {
                    respond()
                }
                return
            }
        }

        // Presign: return a blob URL embedding the requested key.
        if path.hasSuffix("/presign") {
            let body = Self.bodyData(req)
            let key = (try? JSONDecoder().decode([String: CodableValue].self, from: body ?? Data()))
                .flatMap { v -> String? in if case let .string(s)? = v["key"] { return s } else { return nil } } ?? "k"
            let enc = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key
            finish(200, Data(#"{"url":"https://blob.test/blob?key=\#(enc)","expiresIn":300}"#.utf8))
            return
        }

        // Metadata routes (count each served request for P4 round-trip assertions).
        Self.lock.lock()
        let routeKey = "\(method) \(path)"
        Self.counts[routeKey, default: 0] += 1
        let route = Self.routes[routeKey]
        Self.lock.unlock()
        if let route { let (s, j) = route(req); finish(s, Data(j.utf8)); return }
        // Test namespaces are writable unless a fault/permission route overrides it.
        if method == "GET", path.hasSuffix("/access") {
            finish(200, Data(#"{"read":true,"write":true}"#.utf8)); return
        }
        // Existing single-client fixtures expose the lease contract; the dedicated
        // DistributedLeaseTests below exercise ownership and stale fences.
        if path.hasSuffix("/locks") {
            if method == "DELETE" { finish(200, Data(#"{"released":true}"#.utf8)); return }
            if method == "POST" {
                let body = Self.bodyData(req) ?? Data()
                let values = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
                let leasePath = values?["path"] as? String ?? "file"
                let payload: [String: Any] = ["granted": true, "path": leasePath, "fence": 1,
                                             "purpose": "publication",
                                             "expiresAt": Date().timeIntervalSince1970 * 1000 + 60_000]
                finish(200, try! JSONSerialization.data(withJSONObject: payload)); return
            }
        }
        finish(404, Data(#"{"error":"not found"}"#.utf8))
    }

    private func finish(_ status: Int, _ body: Data) {
        let resp = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1",
                                   headerFields: ["content-type": "application/json"])!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }
}

// MARK: - Fixtures -------------------------------------------------------------

private let keyBytes = Data((0..<32).map { UInt8($0) })

/// Stub the namespace LISTING route ("GET /items?parent=…") so Engine.resolveInode
/// can walk control-plane PATHS to inodes (M8). These tests' id convention is
/// "id == path"; every ancestor directory is synthesized.
private func stubNamespaceListing(filespace: String, files: [(path: String, size: Int)]) {
    var children: [String: [(id: String, name: String, isDir: Bool, size: Int)]] = [:]
    for (path, size) in files {
        let segs = path.split(separator: "/").map(String.init)
        var parent = "root", acc = ""
        for (i, seg) in segs.enumerated() {
            acc = acc.isEmpty ? seg : acc + "/" + seg
            let isDir = i < segs.count - 1
            if !(children[parent]?.contains(where: { $0.id == acc }) ?? false) {
                children[parent, default: []].append((acc, seg, isDir, isDir ? 0 : size))
            }
            parent = acc
        }
    }
    GWStub.on("GET /v1/filespaces/\(filespace)/items") { req in
        let comps = URLComponents(url: req.url!, resolvingAgainstBaseURL: false)
        let parent = comps?.queryItems?.first(where: { $0.name == "parent" })?.value ?? "root"
        let items = (children[parent] ?? []).map {
            #"{"id":"\#($0.id)","parent":"\#(parent)","name":"\#($0.name)","isDir":\#($0.isDir),"size":\#($0.size),"contentVersion":"cv1","version":1}"#
        }.joined(separator: ",")
        return (200, #"{"items":[\#(items)],"cursor":null}"#)
    }
}

private func makeEngine(filespace: String = "fs1") throws -> (CloudFSEngine, String) {
    GWStub.reset()
    let cacheDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("cfsd-test-\(UUID().uuidString)").path
    let cfg = EngineConfig(cacheDir: cacheDir, cacheSizeBytes: 64 << 20,
                           controlSocketPath: "/tmp/unused.sock",
                           gatewayBaseURL: "https://gw.test")
    let gwCfg = GatewayClientConfig(baseURL: "https://gw.test", token: "tok")
    let gateway = HttpGatewayClient(config: gwCfg, session: GWStub.session())
    let key = try FilespaceKey(masterKeyBytes: keyBytes)
    // Route BOTH the gateway and the presigned-blob byte plane through GWStub so no
    // request hits the network.
    let engine = CloudFSEngine(config: cfg, gateway: gateway, blobSession: GWStub.session(),
                               cipherMode: .aes256gcm, key: key)
    return (engine, cacheDir)
}

// MARK: - Tests ----------------------------------------------------------------

private final class MetadataMutationFixture: @unchecked Sendable {
    private let lock = NSLock()
    private var version = 1
    private var content = "empty"
    private var calls: [String] = []
    private var expected: [Int] = []
    var mutations: [String] { lock.withLock { calls } }
    var expectedVersions: [Int] { lock.withLock { expected } }
    func remoteEdit() { lock.withLock { version += 1; content = "remote" } }
    func handle(_ request: URLRequest) -> (Int, String) {
        lock.withLock {
            let method = request.httpMethod ?? "GET"
            if method == "PUT" {
                let body = (try? JSONSerialization.jsonObject(with: GWStub.bodyData(request) ?? Data())) as? [String: Any]
                let base = body?["expectedVersion"] as? Int ?? -1
                expected.append(base)
                guard base == version else { return (409, #"{"error":"version_conflict"}"#) }
                version += 1; content = "content-\(version)"; calls.append(method)
            } else if method == "PATCH" { version += 1; calls.append(method) }
            else if method == "DELETE" { calls.append(method); return (200, #"{"deleted":true}"#) }
            return (200, #"{"id":"atomic","parent":"root","name":"saved.txt","isDir":false,"size":5,"contentVersion":"\#(content)","version":\#(version)}"#)
        }
    }
}

private final class AtomicReplacementFixture: @unchecked Sendable {
    private let lock = NSLock()
    private var versions = ["source": 1, "target": 1]
    private var calls: [String] = []
    let reject: Bool
    init(reject: Bool) { self.reject = reject }
    var mutations: [String] { lock.withLock { calls } }
    func handle(_ request: URLRequest) -> (Int, String) {
        lock.withLock {
            let id = request.url!.lastPathComponent, method = request.httpMethod ?? "GET"
            let body = (try? JSONSerialization.jsonObject(with: GWStub.bodyData(request) ?? Data())) as? [String: Any]
            if method == "PUT" {
                guard body?["expectedVersion"] as? Int == versions[id] else { return (409, #"{"error":"version_conflict"}"#) }
                versions[id, default: 0] += 1; calls.append("PUT " + id)
            } else if method == "PATCH" {
                calls.append("PATCH " + id)
                let replace = body?["replace"] as? [String: Any]
                guard body?["expectedVersion"] as? Int == versions["source"],
                      replace?["id"] as? String == "target", replace?["expectedVersion"] as? Int == versions["target"],
                      versions["source"] == 2, versions["target"] == 2 else { return (409, #"{"error":"version_conflict"}"#) }
                if reject { return (409, #"{"error":"locked","locked":true}"#) }
                versions[id, default: 0] += 1
            }
            let version = versions[id] ?? 1
            return (200, #"{"id":"\#(id)","parent":"root","name":"\#(id).txt","isDir":false,"size":3,"contentVersion":"bytes-\#(id)","version":\#(version)}"#)
        }
    }
}

final class CloudFSEngineTests: XCTestCase {

    override func setUp() { super.setUp(); GWStub.reset() }

    private actor LastKernelWrite {
        var transfer: RealTransferEngine?
        func install(_ engine: RealTransferEngine) { transfer = engine }
        func stage() async throws {
            guard let transfer else { throw EngineError(.internal, "test not configured") }
            try await transfer.stageReplace(filespace: "fs1", itemID: "last-save", data: Data("Late edit".utf8), baseVersion: nil, fence: nil)
        }
    }

    private func checkLastKernelWrite(disconnect: Bool, rejectCommit: Bool = false) async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-final-drain-\(UUID())").path
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let late = LastKernelWrite()
        let backend = RecordingMountBackend(onUnmount: { _ in try await late.stage() })
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "t"), session: GWStub.session())
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: directory, cacheSizeBytes: 8 << 20,
            controlSocketPath: "/tmp/unused.sock", gatewayBaseURL: "https://gw.test"),
            gateway: gateway, mount: backend, key: try FilespaceKey(masterKeyBytes: keyBytes), blob: BlobTransport(session: GWStub.session()))
        _ = try await engine.mount(MountParams(filespace: "fs1", at: directory + "/volume"))
        let transfer = try await engine.sessionFor("fs1").transfer
        await late.install(transfer)
        GWStub.on("PUT /v1/filespaces/fs1/blocks/last-save", status: rejectCommit ? 409 : 200,
            json: rejectCommit ? #"{"error":"conflict"}"# : #"{"id":"last-save","parent":"root","name":"last-save","isDir":false,"size":9,"contentVersion":"cv1","version":1}"#)
        // The first barrier is clear; the backend delivers one last acknowledged
        // edit while macOS is tearing down its mounted volume.
        _ = try await engine.flush(FlushParams(filespace: "fs1", path: "", wait: true, timeoutMs: 1000))
        do {
            if disconnect { _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs1", drain: true)) }
            else { _ = try await engine.unmount(UnmountParams(filespace: "fs1", force: false)) }
            XCTAssertFalse(rejectCommit, "a failed last commit must prevent successful shutdown")
        } catch {
            guard rejectCommit else { throw error }
            let records = try await engine.filespaceList()
            XCTAssertEqual(records.count, 1, "failed shutdown retains its session")
            XCTAssertNil(records.first?.mountPath, "the removed kernel mount must not look connected")
        }
        let state = try await transfer.syncState(filespace: "fs1", path: "")
        XCTAssertEqual(state.inSync, !rejectCommit)
        XCTAssertEqual(GWStub.count("PUT /v1/filespaces/fs1/blocks/last-save"), 1,
                       "shutdown must cross the late edit's remote barrier")
    }

    func testUnmountDrainsLastWriteDeliveredDuringKernelTeardown() async throws {
        try await checkLastKernelWrite(disconnect: false)
    }
    func testDrainingDisconnectCommitsLastWriteBeforeDroppingSession() async throws {
        try await checkLastKernelWrite(disconnect: true)
    }
    func testFinalUnmountCommitFailureRetainsUnMountedSessionAndJournal() async throws {
        try await checkLastKernelWrite(disconnect: false, rejectCommit: true)
    }

    func testPauseSurvivesStatusQueriesAndFreshMountResumesTransfers() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-pause-\(UUID())").path
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let backend = RecordingMountBackend()
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "t"), session: GWStub.session())
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: directory, cacheSizeBytes: 8 << 20,
            controlSocketPath: "/tmp/unused.sock", gatewayBaseURL: "https://gw.test"),
            gateway: gateway, mount: backend, key: try FilespaceKey(masterKeyBytes: keyBytes), blob: BlobTransport(session: GWStub.session()))
        let mountPoint = directory + "/volume"
        _ = try await engine.mount(MountParams(filespace: "fs1", at: mountPoint))
        _ = try await engine.transfersPause(FilespaceOnlyParams(filespace: "fs1"))
        let paused = try await engine.filespaceList()
        XCTAssertEqual(paused.first?.paused, true, "a restarted GUI must discover the real pause state")
        let same = try await engine.mount(MountParams(filespace: "fs1", at: mountPoint))
        XCTAssertEqual(same.paused, true, "opening an existing volume must not undo Pause")
        _ = try await engine.unmount(UnmountParams(filespace: "fs1", force: false))
        let reconnected = try await engine.mount(MountParams(filespace: "fs1", at: mountPoint))
        XCTAssertEqual(reconnected.paused, false)
        let session = try await engine.sessionFor("fs1")
        GWStub.on("PUT /v1/filespaces/fs1/blocks/after-reconnect",
            json: #"{"id":"after-reconnect","parent":"root","name":"after-reconnect","isDir":false,"size":5,"contentVersion":"cv1","version":1}"#)
        try await session.transfer.stageReplace(filespace: "fs1", itemID: "after-reconnect", data: Data("Saved".utf8), baseVersion: nil, fence: nil)
        let flushed = try await engine.flush(FlushParams(filespace: "fs1", path: "", wait: true, timeoutMs: 3000))
        XCTAssertTrue(flushed.inSync, "reconnecting must restart actual uploads, not only change a label")
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs1", drain: true))
    }

    func testRecoveryBridgeRetainsConflictUntilVerifiedCopyAndClosedHandles() async throws {
        try await withTestTimeout {
            let (engine, directory) = try makeEngine()
            defer { try? FileManager.default.removeItem(atPath: directory) }
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let transfer = try await engine.sessionFor("fs1").transfer
            let bytes = Data("A preserved edit that must never disappear".utf8)
            // An unsupported CAS version forces a terminal conflict after staging.
            try await transfer.stageReplace(filespace: "fs1", itemID: "edited", data: bytes,
                                             baseVersion: "unsupported", fence: nil)
            do {
                _ = try await engine.flush(FlushParams(filespace: "fs1", path: "/", wait: true, timeoutMs: 5000))
                XCTFail("the conflict must not report durable success")
            } catch {}
            let items = try await engine.recoveryList(FilespaceOnlyParams(filespace: "fs1"))
            XCTAssertEqual(items.map(\.id), ["edited"])
            XCTAssertFalse(items[0].canRetry)
            let destination = URL(fileURLWithPath: directory).appendingPathComponent("saved-copy.txt").path
            let parameters = RecoveryExportParams(filespace: "fs1", itemId: "edited", destination: destination)
            let saved = try await engine.recoveryExport(parameters)
            XCTAssertEqual(saved.bytes, bytes.count)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: saved.path)), bytes)
            let retainedState = try await engine.syncState(SyncStateParams(filespace: "fs1", path: "/"))
            XCTAssertFalse(retainedState.inSync)
            try await engine.beginWrite(filespace: "fs1", id: "edited", handle: "editor")
            do { try await engine.recoveryComplete(parameters); XCTFail("an open editor must block completion") }
            catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }
            await engine.endWrite(filespace: "fs1", id: "edited", handle: "editor")
            try await engine.recoveryComplete(parameters)
            let finalState = try await engine.syncState(SyncStateParams(filespace: "fs1", path: "/"))
            XCTAssertTrue(finalState.inSync)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: destination)), bytes)
        }
    }

    // version is the frozen contract.
    func testSystemVersion() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            let v = try await engine.systemVersion()
            XCTAssertEqual(v.api, ControlAPI.version)
            XCTAssertEqual(v.engine, CloudFSEngine.engineVersion)
        }
    }

    // Calls before connect surface notConnected (CLI exit 23).
    func testNotConnectedBeforeConnect() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            do { _ = try await engine.cacheInfo(CacheInfoParams(filespace: "fs1")); XCTFail("expected notConnected") }
            catch let e as EngineError { XCTAssertEqual(e.kind, .notConnected); XCTAssertEqual(e.exitCode, 23) }
        }
    }

    // connect → list → status → cache.info delegation.
    func testConnectStatusCacheDelegation() async throws {
        try await withTestTimeout {
            let (engine, dir) = try makeEngine()
            let fs = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            XCTAssertEqual(fs.id, "fs1")
            XCTAssertEqual(fs.status, .connected)

            let list = try await engine.filespaceList()
            XCTAssertEqual(list.map(\.id), ["fs1"])

            let statuses = try await engine.status(StatusParams(filespace: "fs1"))
            XCTAssertEqual(statuses.count, 1)
            XCTAssertEqual(statuses[0].connection, .connected)
            XCTAssertEqual(statuses[0].health, .green)

            let info = try await engine.cacheInfo(CacheInfoParams(filespace: "fs1"))
            XCTAssertEqual(info.filespace, "fs1")
            XCTAssertTrue(info.location.hasPrefix(dir))
            XCTAssertEqual(info.maxBytes, 64 << 20)
        }
    }

    // cache.setSize / setLocation / clear delegate to the real DiskBlockCache.
    func testCacheSetSizeLocationClear() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))

            let resized = try await engine.cacheSetSize(CacheSetSizeParams(filespace: "fs1", bytes: 10 << 20))
            XCTAssertEqual(resized.maxBytes, 10 << 20)

            let newLoc = FileManager.default.temporaryDirectory
                .appendingPathComponent("cfsd-relocate-\(UUID().uuidString)").path
            let moved = try await engine.cacheSetLocation(CacheSetLocationParams(filespace: "fs1", path: newLoc))
            XCTAssertEqual(moved.location, URL(fileURLWithPath: newLoc).standardizedFileURL.path)

            let cleared = try await engine.cacheClear(CacheClearParams(filespace: "fs1"))
            XCTAssertEqual(cleared.usedBytes, 0)
        }
    }

    // MARK: - cache.clear must never touch an uncommitted staged/dirty write
    //
    // `DiskBlockCache.clear()` only evicts blocks from its OWN content-addressed
    // `blocks/` store (committed/downloaded content, CloudFSCacheTests
    // `testClearKeepsPinned` covers the pin side). A staged write instead lives in
    // the `WriteBackJournal`'s wholly separate `staging/` tree until its commit
    // lands (WriteBackJournal.swift, RealTransferEngine.stageWrite) — the two never
    // share storage, so a clear cannot admit/evict staged bytes even in principle.
    // This pins that separation end-to-end: a clear mid-write must (a) still evict
    // the old committed block (freedBytes > 0 via usedBytes dropping), (b) leave the
    // staged write fully readable (read-your-own-writes), and (c) let the write
    // commit normally once transfers resume, with the COMMITTED bytes reading back
    // correctly afterward.
    func testCacheClearPreservesUncommittedStagedWrite() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("root/doc.txt")

            // Committed (OLD) content — read it once so its block is resident and
            // UNPINNED in the cache (an eviction candidate for the clear below).
            let oldText = Data("AAAA".utf8)
            let (oldCT, oldHash) = try await crypto.encryptBlock(oldText, itemID: itemID, blockIndex: 0)
            try await blobPut(oldHash.objectKey, oldCT, on: engine)
            let blocksRoute = "GET /v1/filespaces/fs1/blocks/root/doc.txt"
            GWStub.on(blocksRoute,
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(oldHash.hex)","objectKey":"\#(oldHash.objectKey)","offset":0,"length":\#(oldText.count)}]"#)
            GWStub.on("GET /v1/filespaces/fs1/items/root/doc.txt",
                json: #"{"id":"root/doc.txt","parent":"root","name":"doc.txt","isDir":false,"size":\#(oldText.count),"contentVersion":"cv1","version":3}"#)
            GWStub.on("PUT /v1/filespaces/fs1/blocks/root/doc.txt",
                json: #"{"id":"root/doc.txt","parent":"root","name":"doc.txt","isDir":false,"size":6,"contentVersion":"cv2","version":4}"#)

            let dp = await engine.dataPath(for: "fs1")
            let (ref0, _) = try await dp.readRange(itemID, version: "cv1", offset: 0,
                                                   length: oldText.count, alignment: 1 << 20)
            _ = try Data(contentsOf: URL(fileURLWithPath: try XCTUnwrap(ref0.path)))
            let before = try await engine.cacheInfo(CacheInfoParams(filespace: "fs1"))
            XCTAssertGreaterThan(before.usedBytes, 0, "the read admitted the old block into the cache")

            // Pause the upload pool, then stage a NEW write — it must sit dirty
            // (journaled, uncommitted) while we clear.
            _ = try await engine.transfersPause(FilespaceOnlyParams(filespace: "fs1"))
            let newText = Data("BBBBBB".utf8)
            _ = try await dp.writeRange(itemID, offset: 0, data: newText, baseVersion: "3")

            // Clear: the old committed block is evicted…
            let cleared = try await engine.cacheClear(CacheClearParams(filespace: "fs1"))
            XCTAssertLessThan(cleared.usedBytes, before.usedBytes, "clear evicted the old committed block")

            // …but the staged write is untouched: read-your-own-writes still serves
            // the JUST-WRITTEN bytes, not stale or empty content.
            let (ref1, _) = try await dp.readRange(itemID, version: "cv1", offset: 0,
                                                   length: newText.count, alignment: 1 << 20)
            let got1 = try Data(contentsOf: URL(fileURLWithPath: try XCTUnwrap(ref1.path)))
            XCTAssertEqual(got1.prefix(newText.count), newText,
                "a cache clear must never disturb an uncommitted staged write")

            // Resume; the write must still commit durably…
            _ = try await engine.transfersResume(FilespaceOnlyParams(filespace: "fs1"))
            let st = try await engine.flush(FlushParams(filespace: "fs1", path: "root/doc.txt",
                                                        wait: true, timeoutMs: 5000))
            XCTAssertTrue(st.inSync, "the staged write must still commit after a mid-flight cache clear")

            // …and read back correctly afterward (mirror the real gateway's post-commit manifest).
            let (_, newHash) = try await crypto.encryptBlock(newText, itemID: itemID, blockIndex: 0)
            let gwKey = "blocks/fs1::fs1/\(newHash.hex)"   // the upload's gateway key scheme
            GWStub.on(blocksRoute,
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(newHash.hex)","objectKey":"\#(gwKey)","offset":0,"length":\#(newText.count)}]"#)
            let (ref2, _) = try await dp.readRange(itemID, version: "cv1", offset: 0,
                                                   length: newText.count, alignment: 1 << 20)
            let got2 = try Data(contentsOf: URL(fileURLWithPath: try XCTUnwrap(ref2.path)))
            XCTAssertEqual(got2.prefix(newText.count), newText,
                "the committed content must read back correctly after the mid-write clear")
        }
    }

    // End-to-end: connect → prefetch (download+decrypt) → pin → status → flush.
    func testPrefetchPinFlushPipeline() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))

            // Seed an item: encrypt 2 blocks, stash the ciphertext in the blob stub,
            // and serve its manifest + item via the gateway routes.
            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("projectA/clip.mov")
            let blockSize = 1 << 20
            let plaintext = Data((0..<(blockSize + 4096)).map { UInt8($0 & 0xff) })
            var refs: [BlockRef] = []
            var off = 0, idx = 0
            while off < plaintext.count {
                let end = min(off + blockSize, plaintext.count)
                let chunk = plaintext.subdata(in: off..<end)
                let (ct, hash) = try await crypto.encryptBlock(chunk, itemID: itemID, blockIndex: idx)
                // Pre-store the ciphertext so a presigned GET on its objectKey serves it.
                try await blobPut(hash.objectKey, ct, on: engine)
                refs.append(BlockRef(hash: hash, offset: off, length: chunk.count))
                off = end; idx += 1
            }
            let blocksJSON = refs.enumerated().map { (i, r) in
                #"{"chunkIdx":\#(i),"blockIdx":0,"blockHash":"\#(r.hash.hex)","objectKey":"\#(r.hash.objectKey)","offset":\#(r.offset),"length":\#(r.length)}"#
            }.joined(separator: ",")
            GWStub.on("GET /v1/filespaces/fs1/blocks/projectA/clip.mov", json: "[\(blocksJSON)]")
            GWStub.on("GET /v1/filespaces/fs1/items/projectA/clip.mov",
                json: #"{"id":"projectA/clip.mov","parent":"projectA","name":"clip.mov","isDir":false,"size":\#(plaintext.count),"contentVersion":"cv1","version":1}"#)
            stubNamespaceListing(filespace: "fs1", files: [("projectA/clip.mov", plaintext.count)])

            // prefetch: downloads + decrypts both blocks into the cache (queuedBlocks
            // == the manifest's block count). This drives presign → range-GET →
            // decrypt → cache admit for every block under the path.
            let ack = try await engine.prefetch(PathParams(filespace: "fs1", path: "projectA/clip.mov"))
            XCTAssertEqual(ack.queuedBlocks, refs.count)
            let direct = try await engine.dataPath(for: "fs1").readBytes(itemID, version: "cv1",
                                                                          offset: blockSize - 3, length: 8)
            XCTAssertEqual(direct, plaintext.subdata(in: (blockSize - 3)..<(blockSize + 5)),
                           "bounded SMB assembly must slice across authenticated block boundaries exactly")

            // Cache info reflects the now-resident bytes (both blocks admitted).
            let info = try await engine.cacheInfo(CacheInfoParams(filespace: "fs1"))
            XCTAssertGreaterThan(info.usedBytes, 0)

            // A second prefetch is a full cache HIT → nothing re-queued.
            let ack2 = try await engine.prefetch(PathParams(filespace: "fs1", path: "projectA/clip.mov"))
            XCTAssertEqual(ack2.queuedBlocks, 0)

            // No staged writes → flush reports in-sync immediately (the durability
            // barrier path; wait:false drains + returns the current SyncState).
            let sync = try await engine.flush(FlushParams(filespace: "fs1", path: "projectA/clip.mov", wait: false))
            XCTAssertTrue(sync.inSync)
            XCTAssertEqual(sync.pendingUploads, 0)
        }
    }

    // GAP CLOSED: prefetch(path) registers the path→block association, so pin(path)
    // now resolves those blocks and pins them (no more not_found); unpin reverses it.
    func testPrefetchThenPinUnpin() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))

            // Seed a 2-block item: ciphertext in the blob stub, manifest + item routes.
            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("projectB/render.exr")
            let blockSize = 1 << 20
            let plaintext = Data((0..<(blockSize + 2048)).map { UInt8($0 & 0xff) })
            var refs: [BlockRef] = []
            var off = 0, idx = 0
            while off < plaintext.count {
                let end = min(off + blockSize, plaintext.count)
                let chunk = plaintext.subdata(in: off..<end)
                let (ct, hash) = try await crypto.encryptBlock(chunk, itemID: itemID, blockIndex: idx)
                try await blobPut(hash.objectKey, ct, on: engine)
                refs.append(BlockRef(hash: hash, offset: off, length: chunk.count))
                off = end; idx += 1
            }
            let blocksJSON = refs.enumerated().map { (i, r) in
                #"{"chunkIdx":\#(i),"blockIdx":0,"blockHash":"\#(r.hash.hex)","objectKey":"\#(r.hash.objectKey)","offset":\#(r.offset),"length":\#(r.length)}"#
            }.joined(separator: ",")
            GWStub.on("GET /v1/filespaces/fs1/blocks/projectB/render.exr", json: "[\(blocksJSON)]")
            GWStub.on("GET /v1/filespaces/fs1/items/projectB/render.exr",
                json: #"{"id":"projectB/render.exr","parent":"projectB","name":"render.exr","isDir":false,"size":\#(plaintext.count),"contentVersion":"cv1","version":1}"#)
            stubNamespaceListing(filespace: "fs1", files: [("projectB/render.exr", plaintext.count)])

            // prefetch makes the blocks resident AND registers the path→block map.
            let ack = try await engine.prefetch(PathParams(filespace: "fs1", path: "projectB/render.exr"))
            XCTAssertEqual(ack.queuedBlocks, refs.count)

            // pin(path) now resolves the path's blocks and pins them (gap closed).
            let pin = try await engine.pin(PinParams(filespace: "fs1", path: "projectB/render.exr", recursive: false))
            XCTAssertTrue(pin.pinned)
            XCTAssertEqual(pin.blocks, refs.count)

            // pin.list reflects the new pin; cache reports the pinned bytes.
            let pins = try await engine.pinList(FilespaceOnlyParams(filespace: "fs1"))
            XCTAssertEqual(pins.map(\.path), ["projectB/render.exr"])
            XCTAssertEqual(pins.first?.blocks, refs.count)
            // Per-item byte accounting + cache-state surface through the engine
            // (CONTRACTS.md §4): a freshly-pinned, fully-resident item is `.pinned`
            // and its cached/total bytes equal the cache's pinnedBytes.
            let info = try await engine.cacheInfo(CacheInfoParams(filespace: "fs1"))
            XCTAssertGreaterThan(info.pinnedBytes, 0)
            XCTAssertEqual(pins.first?.cacheState, .pinned)
            XCTAssertEqual(pins.first?.cachedBytes, UInt64(info.pinnedBytes))
            XCTAssertEqual(pins.first?.totalBytes, UInt64(info.pinnedBytes))

            // unpin reverses it: not pinned, pinnedBytes back to zero.
            let unpinned = try await engine.unpin(PinParams(filespace: "fs1", path: "projectB/render.exr", recursive: false))
            XCTAssertFalse(unpinned.pinned)
            XCTAssertEqual(unpinned.blocks, refs.count)   // blocks it WAS holding
            let after = try await engine.cacheInfo(CacheInfoParams(filespace: "fs1"))
            XCTAssertEqual(after.pinnedBytes, 0)
            let emptyPins = try await engine.pinList(FilespaceOnlyParams(filespace: "fs1"))
            XCTAssertTrue(emptyPins.isEmpty)
        }
    }

    // pin/unpin delegate to the cache: pinning a path with no resident blocks is a
    // notFound (CLI exit 20); unpin of an unpinned path is idempotent.
    func testPinDelegation() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            do {
                _ = try await engine.pin(PinParams(filespace: "fs1", path: "nope.bin", recursive: false))
                XCTFail("expected notFound for an unregistered path")
            } catch let e as EngineError {
                XCTAssertEqual(e.kind, .notFound)
                XCTAssertEqual(e.exitCode, 20)
            }
            // Idempotent unpin returns pinned:false without error.
            let unpinned = try await engine.unpin(PinParams(filespace: "fs1", path: "nope.bin", recursive: false))
            XCTAssertFalse(unpinned.pinned)
        }
    }

    // transfers pause/resume + current delegate to the transfer engine.
    func testTransfersPauseResume() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let paused = try await engine.transfersPause(FilespaceOnlyParams(filespace: "fs1"))
            XCTAssertTrue(paused.paused)
            let resumed = try await engine.transfersResume(FilespaceOnlyParams(filespace: "fs1"))
            XCTAssertFalse(resumed.paused)
            let current = try await engine.transfersCurrent(FilespaceOnlyParams(filespace: "fs1"))
            XCTAssertTrue(current.isEmpty)
        }
    }

    // events.subscribe yields a transfer notification driven by a real prefetch.
    func testEventsStreamYieldsTransfer() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))

            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("a.bin")
            let chunk = Data((0..<2048).map { UInt8($0 & 0xff) })
            let (ct, hash) = try await crypto.encryptBlock(chunk, itemID: itemID, blockIndex: 0)
            try await blobPut(hash.objectKey, ct, on: engine)
            GWStub.on("GET /v1/filespaces/fs1/blocks/a.bin",
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":0,"length":\#(chunk.count)}]"#)
            GWStub.on("GET /v1/filespaces/fs1/items/a.bin",
                json: #"{"id":"a.bin","parent":"root","name":"a.bin","isDir":false,"size":\#(chunk.count),"contentVersion":"cv","version":1}"#)
            stubNamespaceListing(filespace: "fs1", files: [("a.bin", chunk.count)])

            let stream = engine.events(EventsSubscribeParams(filespace: "fs1", kinds: [.transfer]))
            // Drive a prefetch concurrently; collect the first transfer notification.
            async let first: EventNotification? = {
                for await ev in stream { return ev }
                return nil
            }()
            _ = try await engine.prefetch(PathParams(filespace: "fs1", path: "a.bin"))
            let ev = await first
            guard case let .transfer(fs, t)? = ev else { XCTFail("expected a transfer event, got \(String(describing: ev))"); return }
            XCTAssertEqual(fs, "fs1")
            XCTAssertEqual(t.path, "a.bin")
            XCTAssertEqual(t.direction, .download)
        }
    }

    // mount via the default (stub) backend refuses cleanly; the session still connects.
    func testMountStubRefusesButSessionLives() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            do {
                // makeEngine() injects no backend, so the engine uses the no-op
                // stub (the daemon wires the real SMB backend); the stub refuses.
                _ = try await engine.mount(MountParams(filespace: "fs1", at: "/tmp/cfsd-mnt"))
                XCTFail("stub backend should refuse to mount")
            } catch let e as EngineError {
                XCTAssertEqual(e.kind, .notConnected)   // stub backend's refusal kind
            }
            // The metadata session survives a mount refusal.
            let list = try await engine.filespaceList()
            XCTAssertEqual(list.map(\.id), ["fs1"])
        }
    }

    // disconnect tears the session down (subsequent calls are notConnected).
    func testDisconnect() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let d = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs1"))
            XCTAssertEqual(d.status, .disconnected)
            do { _ = try await engine.cacheInfo(CacheInfoParams(filespace: "fs1")); XCTFail("expected notConnected") }
            catch let e as EngineError { XCTAssertEqual(e.kind, .notConnected) }
        }
    }
}

// MARK: - Data-path test (read assembles plaintext from the cache) -------------

final class CloudFSDataPathTests: XCTestCase {

    override func setUp() { super.setUp(); GWStub.reset() }

    func testReadRangeAssemblesPlaintext() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))

            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("doc.txt")
            let plaintext = Data("hello cloud-fs data path".utf8)
            let (ct, hash) = try await crypto.encryptBlock(plaintext, itemID: itemID, blockIndex: 0)
            try await blobPut(hash.objectKey, ct, on: engine)
            GWStub.on("GET /v1/filespaces/fs1/blocks/doc.txt",
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":0,"length":\#(plaintext.count)}]"#)
            GWStub.on("GET /v1/filespaces/fs1/items/doc.txt",
                json: #"{"id":"doc.txt","parent":"root","name":"doc.txt","isDir":false,"size":\#(plaintext.count),"contentVersion":"cv","version":1}"#)

            let dp = await engine.dataPath(for: "fs1")
            let (ref, range) = try await dp.readRange(itemID, version: "cv", offset: 0,
                                                      length: plaintext.count, alignment: 1 << 20)
            XCTAssertEqual(range.offset, 0)
            let path = try XCTUnwrap(ref.path)
            let got = try Data(contentsOf: URL(fileURLWithPath: path))
            XCTAssertEqual(got, plaintext)

            let spillRoot = engine.plaintextSpillDir()
            let filesBefore = try FileManager.default.contentsOfDirectory(atPath: spillRoot.path)
            let direct = try await dp.readBytes(itemID, version: "cv", offset: 3, length: 8)
            XCTAssertEqual(direct, plaintext.subdata(in: 3..<11))
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: spillRoot.path), filesBefore,
                           "the SMB fast path must not create plaintext files")
            do {
                _ = try await dp.readBytes(itemID, version: "cv", offset: 0, length: (1 << 20) + 1)
                XCTFail("in-process assembly has a hard request size bound")
            } catch let error as EngineError { XCTAssertEqual(error.kind, .invalidParams) }
            do {
                _ = try await dp.readRange(itemID, version: "cv", offset: Int.max - 1, length: 1, alignment: 1 << 20)
                XCTFail("alignment overflow must fail without a trap or leaked spill")
            } catch let error as EngineError { XCTAssertEqual(error.kind, .invalidParams) }
            XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: spillRoot.path), filesBefore)

            // Outstanding reads must not alias, even before either consumer has
            // copied/deleted its file. Exercise the same range from many handles.
            let readPaths = try await withThrowingTaskGroup(of: String.self) { group in
                for _ in 0..<16 {
                    group.addTask {
                        let (other, _) = try await dp.readRange(itemID, version: "cv", offset: 0,
                                                              length: plaintext.count, alignment: 1 << 20)
                        return try XCTUnwrap(other.path)
                    }
                }
                var paths: [String] = []
                for try await path in group { paths.append(path) }
                return paths
            }
            XCTAssertEqual(Set(readPaths + [path]).count, 17)
            try FileManager.default.removeItem(atPath: path)
            for other in readPaths {
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: other)), plaintext)
                try FileManager.default.removeItem(atPath: other)
            }

            // lookup delegates to the gateway item.
            let meta = try await dp.lookup(itemID)
            XCTAssertEqual(meta.id, itemID)
            XCTAssertEqual(meta.size, plaintext.count)
        }
    }

    // MARK: P4 — resolved-manifest cache eliminates redundant gateway round-trips
    //
    // FINDING P4: the read path resolved the block manifest repeatedly and uncached.
    // `getResolvedBlockManifest` is 2 round-trips (GET /blocks/:id + GET /items/:id),
    // and the data path re-fetched the manifest a SECOND time in `readRange`. The fix
    // caches the resolved manifest per (itemID, contentVersion) on the engine. We
    // assert that two resolves of the SAME version hit the gateway exactly ONCE, and
    // that a contentVersion change forces a refresh.

    func testResolvedManifestCachedAcrossSameVersionReads() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let itemID = InodeID("clip.mov")
            let blocksRoute = "GET /v1/filespaces/fs1/blocks/clip.mov"
            GWStub.on(blocksRoute,
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"aa","objectKey":"blocks/o::fs1/aa","offset":0,"length":16}]"#)
            GWStub.on("GET /v1/filespaces/fs1/items/clip.mov",
                json: #"{"id":"clip.mov","parent":"root","name":"clip.mov","isDir":false,"size":16,"contentVersion":"cv1","version":1}"#)

            // First resolve: a cache MISS → exactly one GET /blocks.
            let m1 = try await engine.resolvedManifest(filespace: "fs1", itemID: itemID, contentVersion: "cv1")
            XCTAssertEqual(m1.manifest.blocks.count, 1)
            XCTAssertEqual(GWStub.count(blocksRoute), 1)

            // Second + third resolves of the SAME version: cache HITS → NO new fetch.
            _ = try await engine.resolvedManifest(filespace: "fs1", itemID: itemID, contentVersion: "cv1")
            _ = try await engine.resolvedManifest(filespace: "fs1", itemID: itemID, contentVersion: "cv1")
            XCTAssertEqual(GWStub.count(blocksRoute), 1,
                           "same (item, version) must resolve with ONE gateway fetch, not three")
        }
    }

    func testContentVersionChangeRefreshesManifest() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let itemID = InodeID("edit.mov")
            let blocksRoute = "GET /v1/filespaces/fs1/blocks/edit.mov"
            GWStub.on(blocksRoute,
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"aa","objectKey":"blocks/o::fs1/aa","offset":0,"length":16}]"#)
            GWStub.on("GET /v1/filespaces/fs1/items/edit.mov",
                json: #"{"id":"edit.mov","parent":"root","name":"edit.mov","isDir":false,"size":16,"contentVersion":"cv1","version":1}"#)

            // Resolve at cv1 (1 fetch), then re-resolve at cv1 (cached, still 1 fetch).
            _ = try await engine.resolvedManifest(filespace: "fs1", itemID: itemID, contentVersion: "cv1")
            _ = try await engine.resolvedManifest(filespace: "fs1", itemID: itemID, contentVersion: "cv1")
            XCTAssertEqual(GWStub.count(blocksRoute), 1)

            // The file was EDITED → a NEW contentVersion. Resolving at cv2 must refresh
            // (a stale block map can never be reused), i.e. exactly one more fetch.
            _ = try await engine.resolvedManifest(filespace: "fs1", itemID: itemID, contentVersion: "cv2")
            XCTAssertEqual(GWStub.count(blocksRoute), 2,
                           "a contentVersion change must force a manifest refresh")

            // Re-resolving cv2 is now cached; the OLD cv1 entry was invalidated (a
            // refetch of cv1 would be a fresh miss). cv2 stays at 2 total fetches.
            _ = try await engine.resolvedManifest(filespace: "fs1", itemID: itemID, contentVersion: "cv2")
            XCTAssertEqual(GWStub.count(blocksRoute), 2, "cv2 is cached after its refresh")
        }
    }

    // P4 end-to-end: two readRanges of the SAME (item, version) do NOT grow the
    // read-side (engine-cached) manifest fetches without bound — the engine cache
    // serves the second read's manifest, so the only repeated /blocks fetch is the
    // transfer engine's own ensureRange resolve (out of this fix's scope), NOT a
    // second redundant readRange fetch.
    func testRepeatedReadRangeReusesCachedManifest() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))

            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("seq.mov")
            let plaintext = Data("p4 byte-range playback".utf8)
            let (ct, hash) = try await crypto.encryptBlock(plaintext, itemID: itemID, blockIndex: 0)
            try await blobPut(hash.objectKey, ct, on: engine)
            let blocksRoute = "GET /v1/filespaces/fs1/blocks/seq.mov"
            GWStub.on(blocksRoute,
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":0,"length":\#(plaintext.count)}]"#)
            GWStub.on("GET /v1/filespaces/fs1/items/seq.mov",
                json: #"{"id":"seq.mov","parent":"root","name":"seq.mov","isDir":false,"size":\#(plaintext.count),"contentVersion":"cv","version":1}"#)

            let dp = await engine.dataPath(for: "fs1")
            _ = try await dp.readRange(itemID, version: "cv", offset: 0, length: plaintext.count, alignment: 1 << 20)
            let afterFirst = GWStub.count(blocksRoute)
            _ = try await dp.readRange(itemID, version: "cv", offset: 0, length: plaintext.count, alignment: 1 << 20)
            let afterSecond = GWStub.count(blocksRoute)

            // Pre-fix, each readRange did its OWN redundant /blocks fetch (so the
            // second read added >=2). With the engine cache, the second read's
            // assemble-side manifest is served from cache, so the increment is bounded
            // to the transfer engine's single ensureRange resolve (at most 1).
            XCTAssertLessThanOrEqual(afterSecond - afterFirst, 1,
                "second read of the same version must NOT issue a redundant readRange manifest fetch")
        }
    }

    // MARK: - Audit B1: create-through-mount reaches the backend (no silent loss)
    //
    // Previously the adapter's write(id:nil) made NO namespace call — it minted a
    // local-only inode whose id ("/render.dat") never matched the backend scheme
    // ("root/render.dat"), so the commit 403'd/500'd and the bytes were lost while the
    // VFS write already acked "saved". This drives the REAL HttpGatewayClient: a new
    // file created through the data path must POST /items first, adopt the gateway id,
    // encrypt + commit under THAT id, and a read-back recovers the bytes.
    func testCreateThroughMountReachesBackendAndRoundTrips() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))

            // The backend mints the path-derived id "root/render.dat" on create.
            GWStub.on("POST /v1/filespaces/fs1/items",
                json: #"{"id":"root/render.dat","parent":"root","name":"render.dat","isDir":false,"size":0,"contentVersion":"cv0","version":1}"#)
            // The block-map commit (PUT /blocks/root%2Frender.dat) echoes the new item.
            GWStub.on("PUT /v1/filespaces/fs1/blocks/root/render.dat",
                json: #"{"id":"root/render.dat","parent":"root","name":"render.dat","isDir":false,"size":12,"contentVersion":"cv1","version":2}"#)

            let dp = await engine.dataPath(for: "fs1")
            // write(id:nil) — a brand-new file from Finder/create.
            let payload = Data("brand new!!!".utf8)   // 12 bytes
            let tmp = NSTemporaryDirectory() + "cfs-create-\(UUID().uuidString)"
            try payload.write(to: URL(fileURLWithPath: tmp))
            let fields = ItemMetadata(id: InodeID("/render.dat"), parent: .root, name: "render.dat",
                                      isDir: false, size: 0, contentVersion: "", metadataVersion: "")
            let created = try await dp.write(id: nil, fields: fields,
                                             contents: CacheFileRef(fd: nil, path: tmp), baseVersion: nil)
            // The adapter adopted the GATEWAY id, not the local "/render.dat".
            XCTAssertEqual(created.id, InodeID("root/render.dat"))
            // It POSTed the create (B1 — reaches the backend).
            XCTAssertEqual(GWStub.count("POST /v1/filespaces/fs1/items"), 1,
                           "create-through-mount must POST /items, not mint a local-only inode")

            // Drain the async upload; the commit must land under the backend id.
            let st = try await engine.flush(FlushParams(filespace: "fs1", path: "root/render.dat", wait: true, timeoutMs: 5000))
            XCTAssertTrue(st.inSync)
            XCTAssertEqual(GWStub.count("PUT /v1/filespaces/fs1/blocks/root/render.dat"), 1,
                           "the commit must target the backend id (encryption is bound to it)")
        }
    }

    /// Audit B1: delete reaches the gateway (DELETE /items/:id), not a phantom.
    func testDeleteThroughMountReachesBackend() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            GWStub.on("DELETE /v1/filespaces/fs1/items/root/gone.mov", json: #"{"deleted":true}"#)
            let dp = await engine.dataPath(for: "fs1")
            try await dp.delete(InodeID("root/gone.mov"), baseVersion: "1", recursive: false)
            XCTAssertEqual(GWStub.count("DELETE /v1/filespaces/fs1/items/root/gone.mov"), 1,
                           "delete must reach the gateway namespace, not phantom-ack")
        }
    }

    // MARK: - Audit B17: rename/move through the data path reaches the gateway move RPC
    //
    // Opaque ids make rename a single-row metadata update — the item's id (and thus its
    // encrypted blocks) is unchanged. Drives the real HttpGatewayClient: a rename PATCHes
    // /items/:id and adopts the returned (unchanged-id, new-name) metadata.
    func testRenameThroughMountReachesGateway() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            GWStub.on("GET /v1/filespaces/fs1/items/ino-abc",
                json: #"{"id":"ino-abc","parent":"root","name":"old.mov","isDir":false,"size":42,"contentVersion":"cv2","version":2}"#)
            // The backend returns the SAME id with the new (parent, name) on a move.
            GWStub.on("PATCH /v1/filespaces/fs1/items/ino-abc",
                json: #"{"id":"ino-abc","parent":"ino-dest","name":"new.mov","isDir":false,"size":42,"contentVersion":"cv2","version":3}"#)
            let dp = await engine.dataPath(for: "fs1")
            let moved = try await dp.rename(InodeID("ino-abc"), newParent: InodeID("ino-dest"), newName: "new.mov")
            // The id is STABLE across the rename (so the file's blocks stay decryptable).
            XCTAssertEqual(moved.id, InodeID("ino-abc"))
            XCTAssertEqual(moved.name, "new.mov")
            XCTAssertEqual(moved.parent, InodeID("ino-dest"))
            XCTAssertEqual(GWStub.count("PATCH /v1/filespaces/fs1/items/ino-abc"), 1,
                           "rename must reach the gateway move RPC, not phantom-ack")
        }
    }

    func testAtomicSaveReplacementDrainsOldTargetBeforeDelete() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let state = MetadataMutationFixture()
            GWStub.on("DELETE /v1/filespaces/fs1/items/atomic", handler: state.handle)
            GWStub.on("PUT /v1/filespaces/fs1/blocks/atomic", handler: state.handle)
            GWStub.on("GET /v1/filespaces/fs1/blocks/atomic", status: 404, json: #"{"error":"not found"}"#)
            let (_, transfer, _) = try await engine.sessionFor("fs1")
            try await transfer.stageReplace(filespace: "fs1", itemID: "atomic", data: Data("old".utf8), baseVersion: "1", fence: nil)
            let dp = await engine.dataPath(for: "fs1")
            try await dp.delete("atomic", baseVersion: "1", recursive: false)
            XCTAssertEqual(state.mutations, ["PUT", "DELETE"])
            let synced = try await transfer.syncState(filespace: "fs1", path: "atomic")
            XCTAssertTrue(synced.inSync, "Our own replacement must not leave old target bytes in recovery")
        }
    }

    func testAtomicReplacementDrainsBothInodesAndNeverDeletesBeforeRename() async throws {
        try await withTestTimeout {
            for reject in [false, true] {
                GWStub.reset()
                let (engine, _) = try makeEngine()
                _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
                let state = AtomicReplacementFixture(reject: reject)
                for id in ["source", "target"] {
                    GWStub.on("GET /v1/filespaces/fs1/items/\(id)", handler: state.handle)
                    GWStub.on("PUT /v1/filespaces/fs1/blocks/\(id)", handler: state.handle)
                    GWStub.on("GET /v1/filespaces/fs1/blocks/\(id)", status: 404, json: #"{"error":"not found"}"#)
                }
                GWStub.on("PATCH /v1/filespaces/fs1/items/source", handler: state.handle)
                let (_, transfer, _) = try await engine.sessionFor("fs1")
                for id in ["source", "target"] {
                    try await transfer.stageReplace(filespace: "fs1", itemID: InodeID(id), data: Data(id.prefix(3).utf8), baseVersion: "1", fence: nil)
                }
                let dp = await engine.dataPath(for: "fs1")
                let target = ItemMetadata(id: "target", parent: .root, name: "target.txt", isDir: false, size: 0, contentVersion: "empty", metadataVersion: "1")
                do {
                    _ = try await dp.rename("source", newParent: nil, newName: "target.txt", replacing: target)
                    XCTAssertFalse(reject)
                } catch let error as EngineError { XCTAssertTrue(reject); XCTAssertEqual(error.kind, .locked) }
                XCTAssertEqual(Set(state.mutations.prefix(2)), Set(["PUT source", "PUT target"]))
                XCTAssertEqual(state.mutations.last, "PATCH source")
                XCTAssertEqual(GWStub.count("DELETE /v1/filespaces/fs1/items/target"), 0)
                let sync = try await transfer.syncState(filespace: "fs1", path: "")
                XCTAssertTrue(sync.inSync, "A rejected replacement retains both already-published files")
            }
        }
    }

    func testAtomicSaveRenameDrainsUploadAndPreservesOpenHandleRevision() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let state = MetadataMutationFixture()
            for method in ["GET", "PATCH"] {
                GWStub.on("\(method) /v1/filespaces/fs1/items/atomic", handler: state.handle)
            }
            GWStub.on("PUT /v1/filespaces/fs1/blocks/atomic", handler: state.handle)
            GWStub.on("GET /v1/filespaces/fs1/blocks/atomic", status: 404, json: #"{"error":"not found"}"#)
            let (_, transfer, _) = try await engine.sessionFor("fs1")
            try await transfer.stageReplace(filespace: "fs1", itemID: "atomic", data: Data("saved".utf8), baseVersion: "1", fence: nil)
            let dp = await engine.dataPath(for: "fs1")
            let moved = try await dp.rename("atomic", newParent: nil, newName: "saved.txt")
            XCTAssertEqual(moved.metadataVersion, "3")
            XCTAssertEqual(state.mutations, ["PUT", "PATCH"])
            // An already-open handle still has revision 1. Our own content and
            // rename revisions are safe to advance through; a remote save isn't.
            try await transfer.stageReplace(filespace: "fs1", itemID: "atomic", data: Data("next".utf8), baseVersion: "1", fence: nil)
            let synced = try await transfer.flush(filespace: "fs1", path: "atomic", wait: true, timeoutMs: 5000)
            XCTAssertTrue(synced.inSync)
            XCTAssertEqual(state.expectedVersions, [1, 3])
            state.remoteEdit()
            _ = try await dp.rename("atomic", newParent: nil, newName: "moved-again.txt")
            try await transfer.stageReplace(filespace: "fs1", itemID: "atomic", data: Data("stale".utf8), baseVersion: "1", fence: nil)
            do {
                _ = try await transfer.flush(filespace: "fs1", path: "atomic", wait: true, timeoutMs: 5000)
                XCTFail("A remote content edit must remain a conflict")
            } catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        }
    }

    // MARK: - Audit B3: read-your-own-writes through the data path
    //
    // A write staged but not yet committed must read back its NEW bytes, not the OLD
    // committed manifest. Drives the real adapter: stage via write(), then readRange
    // returns the staged plaintext (the overlay), even though the gateway still serves
    // the pre-edit manifest.
    func testReadYourOwnWritesOverlaysStagedBytes() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("root/doc.txt")

            // The committed (OLD) content the gateway serves.
            let oldText = Data("old committed content".utf8)
            let (oldCT, oldHash) = try await crypto.encryptBlock(oldText, itemID: itemID, blockIndex: 0)
            try await blobPut(oldHash.objectKey, oldCT, on: engine)
            GWStub.on("GET /v1/filespaces/fs1/blocks/root/doc.txt",
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(oldHash.hex)","objectKey":"\#(oldHash.objectKey)","offset":0,"length":\#(oldText.count)}]"#)
            GWStub.on("GET /v1/filespaces/fs1/items/root/doc.txt",
                json: #"{"id":"root/doc.txt","parent":"root","name":"doc.txt","isDir":false,"size":\#(oldText.count),"contentVersion":"cv1","version":3}"#)
            // Hold the upload so the new write stays dirty (uncommitted) during the read.
            GWStub.on("PUT /v1/filespaces/fs1/blocks/root/doc.txt",
                json: #"{"id":"root/doc.txt","parent":"root","name":"doc.txt","isDir":false,"size":7,"contentVersion":"cv2","version":4}"#)

            let dp = await engine.dataPath(for: "fs1")
            // Pause the pool so the staged write does NOT commit before we read it.
            _ = try await engine.transfersPause(FilespaceOnlyParams(filespace: "fs1"))
            let newText = Data("NEWVAL!".utf8)   // 7 bytes
            let tmp = NSTemporaryDirectory() + "cfs-ryow-\(UUID().uuidString)"
            try newText.write(to: URL(fileURLWithPath: tmp))
            let fields = ItemMetadata(id: itemID, parent: .root, name: "doc.txt", isDir: false,
                                      size: newText.count, contentVersion: "cv1", metadataVersion: "3")
            _ = try await dp.write(id: itemID, fields: fields,
                                   contents: CacheFileRef(fd: nil, path: tmp), baseVersion: "3")

            // Read it back: the overlay serves the JUST-WRITTEN bytes, not the old
            // committed content (read-your-own-writes).
            let (ref, _) = try await dp.readRange(itemID, version: "cv1", offset: 0,
                                                  length: newText.count, alignment: 1 << 20)
            let got = try Data(contentsOf: URL(fileURLWithPath: try XCTUnwrap(ref.path)))
            XCTAssertEqual(got, newText, "a write-then-read must return the new staged bytes, not the old commit")
            _ = try await engine.transfersResume(FilespaceOnlyParams(filespace: "fs1"))
        }
    }

    // MARK: - M6: per-filespace master keys

    /// Each filespace session must encrypt/decrypt with ITS OWN key (production:
    /// Keychain item per filespace id). One static key for every session silently
    /// serves garbage the moment two filespaces differ — this pins the seam.
    func testPerFilespaceKeysBindCryptoPerSession() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let keyA = Data((0..<32).map { UInt8($0) })
            let keyB = Data((0..<32).map { UInt8(31 - $0) })
            let cacheDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("cfsd-keys-\(UUID().uuidString)").path
            let cfg = EngineConfig(cacheDir: cacheDir, cacheSizeBytes: 64 << 20,
                                   controlSocketPath: "/tmp/unused.sock",
                                   gatewayBaseURL: "https://gw.test")
            let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "tok"),
                                            session: GWStub.session())
            // Recording provider: fsA → keyA, fsB → keyB.
            final class Calls: @unchecked Sendable {
                private let lock = NSLock(); private var seen: Set<String> = []
                func note(_ fs: String) { lock.lock(); seen.insert(fs); lock.unlock() }
                func snapshot() -> Set<String> { lock.lock(); defer { lock.unlock() }; return seen }
            }
            let calls = Calls()
            let engine = CloudFSEngine(
                config: cfg, gateway: gateway,
                blobSession: GWStub.session(),
                keyProvider: { fs in
                    calls.note(fs)
                    return try? FilespaceKey(masterKeyBytes: fs == "fsA" ? keyA : keyB)
                })
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fsA"))
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fsB"))
            XCTAssertEqual(calls.snapshot(), ["fsA", "fsB"], "provider consulted per filespace")

            // Seed ONE block encrypted under keyA for an item in EACH filespace.
            let cryptoA = try AESGCMBlockCrypto(masterKeyBytes: keyA)
            let itemID = InodeID("doc.txt")
            let pt = Data("key-bound content".utf8)
            let (ct, hash) = try await cryptoA.encryptBlock(pt, itemID: itemID, blockIndex: 0)
            try await blobPut(hash.objectKey, ct, on: engine)
            for fs in ["fsA", "fsB"] {
                GWStub.on("GET /v1/filespaces/\(fs)/blocks/doc.txt",
                    json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":0,"length":\#(pt.count)}]"#)
                GWStub.on("GET /v1/filespaces/\(fs)/items/doc.txt",
                    json: #"{"id":"doc.txt","parent":"root","name":"doc.txt","isDir":false,"size":\#(pt.count),"contentVersion":"cv","version":1}"#)
            }

            // fsA (keyA) decrypts the keyA block fine…
            let dpA = await engine.dataPath(for: "fsA")
            let (refA, _) = try await dpA.readRange(itemID, version: "cv",
                                                    offset: 0, length: pt.count, alignment: 1 << 20)
            let gotA = try Data(contentsOf: URL(fileURLWithPath: try XCTUnwrap(refA.path)))
            XCTAssertEqual(gotA.prefix(pt.count), pt)

            // …and fsB (keyB) must REFUSE the keyA block (GCM auth), never serve garbage.
            let dpB = await engine.dataPath(for: "fsB")
            do {
                _ = try await dpB.readRange(itemID, version: "cv",
                                            offset: 0, length: pt.count, alignment: 1 << 20)
                XCTFail("a block encrypted under another filespace's key must not decrypt")
            } catch { /* expected: authentication failure surfaces as an error */ }
        }
    }

    // MARK: - P3: read-after-commit must serve the NEW bytes (stale-manifest repro)
    //
    // The audit's stale read-after-write trace, built as the demanded repro and kept
    // as the regression test. The failure chain (pre-fix): a read warms the engine's
    // manifest cache under contentVersion cv1 → a write commits (gateway now serves a
    // NEW manifest; cv changed) → the mount still pins cv1 (the async commit's new
    // version never came back) → the staging overlay drops at commit → the next read
    // resolves cv1, HITS the stale cached manifest, and serves the PRE-COMMIT bytes.
    // The fix: the commit's returned metadata flows back (onCommit) and every cached
    // manifest for the item is invalidated BEFORE the overlay drops, so a stale
    // version key re-resolves the CURRENT manifest from the gateway.
    func testReadAfterCommitServesNewBytesNotStaleManifest() async throws {
        try await withTestTimeout {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("root/doc.txt")

            // Committed (OLD) content, manifest A, contentVersion "cv1".
            let oldText = Data("AAAA".utf8)
            let (oldCT, oldHash) = try await crypto.encryptBlock(oldText, itemID: itemID, blockIndex: 0)
            try await blobPut(oldHash.objectKey, oldCT, on: engine)
            let blocksRoute = "GET /v1/filespaces/fs1/blocks/root/doc.txt"
            GWStub.on(blocksRoute,
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(oldHash.hex)","objectKey":"\#(oldHash.objectKey)","offset":0,"length":\#(oldText.count)}]"#)
            GWStub.on("GET /v1/filespaces/fs1/items/root/doc.txt",
                json: #"{"id":"root/doc.txt","parent":"root","name":"doc.txt","isDir":false,"size":\#(oldText.count),"contentVersion":"cv1","version":3}"#)
            GWStub.on("PUT /v1/filespaces/fs1/blocks/root/doc.txt",
                json: #"{"id":"root/doc.txt","parent":"root","name":"doc.txt","isDir":false,"size":6,"contentVersion":"cv2","version":4}"#)

            let dp = await engine.dataPath(for: "fs1")

            // 1. Read under cv1 → OLD bytes; the engine's manifest cache now holds
            //    manifest A keyed under cv1.
            let (ref1, _) = try await dp.readRange(itemID, version: "cv1", offset: 0,
                                                   length: oldText.count, alignment: 1 << 20)
            let got1 = try Data(contentsOf: URL(fileURLWithPath: try XCTUnwrap(ref1.path)))
            XCTAssertEqual(got1.prefix(oldText.count), oldText)

            // 2. Write NEW content through the ranged path and let the commit land.
            let newText = Data("BBBBBB".utf8)   // fully covers the committed extent
            _ = try await dp.writeRange(itemID, offset: 0, data: newText, baseVersion: "3")
            let st = try await engine.flush(FlushParams(filespace: "fs1", path: "root/doc.txt",
                                                        wait: true, timeoutMs: 5000))
            XCTAssertTrue(st.inSync, "the commit must land (staging overlay drops)")

            // 3. The REAL gateway now serves manifest B — mirror that in the stub.
            let (_, newHash) = try await crypto.encryptBlock(newText, itemID: itemID, blockIndex: 0)
            let gwKey = "blocks/fs1::fs1/\(newHash.hex)"   // the upload's gateway key scheme
            GWStub.on(blocksRoute,
                json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(newHash.hex)","objectKey":"\#(gwKey)","offset":0,"length":\#(newText.count)}]"#)

            // 4. Read again with the STALE pinned version (cv1 — exactly what an
            //    open handle or unexpired metadata still carries). Pre-fix this hit
            //    the stale cached manifest A and returned "AAAA".
            let (ref2, _) = try await dp.readRange(itemID, version: "cv1", offset: 0,
                                                   length: newText.count, alignment: 1 << 20)
            let got2 = try Data(contentsOf: URL(fileURLWithPath: try XCTUnwrap(ref2.path)))
            XCTAssertEqual(got2.prefix(newText.count), newText,
                "a post-commit read must serve the committed NEW bytes, never the stale cached manifest")
        }
    }

    // MARK: - P1 ACCEPTANCE: whole-file materialization streams to disk
    //
    // Josh's acceptance (adapted to the daemon, the appex being shelved): a FULL read
    // of a file much larger than any sane buffer — and 2× the engine's cache budget —
    // must complete with the daemon's memory bounded in the tens of MB, because the
    // assembly streams block-by-block into the spill file (P1) and residency is made
    // in bounded windows (no fetch/evict thrash against the cache budget).
    //
    // 128 MiB file, 64 MiB cache budget, real AES-GCM, real HttpGatewayClient against
    // the stub. Pre-P1, readRange accumulated the WHOLE range in one Data: peak RSS
    // delta ≥ 128 MiB. Post-P1 it is ~one block. The 48 MiB ceiling cleanly separates
    // the two while absorbing allocator noise.
    func testWholeFileReadStreamsWithBoundedMemory() async throws {
        try await withTestTimeout(120) {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("bigread.mov")
            let bs = 1 << 20
            let blocks = 128                       // 128 MiB total, cache budget is 64 MiB
            let fileSize = blocks * bs

            // Seed: per-block deterministic plaintext (first byte == index) so the
            // round-trip is verifiable without holding the file in test RAM either.
            var manifestRows: [String] = []
            for i in 0..<blocks {
                let pt = Data(repeating: UInt8(i & 0xff), count: bs)
                let (ct, hash) = try await crypto.encryptBlock(pt, itemID: itemID, blockIndex: i)
                try await blobPut(hash.objectKey, ct, on: engine)
                manifestRows.append(
                    #"{"chunkIdx":\#(i),"blockIdx":\#(i),"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":\#(i * bs),"length":\#(bs)}"#)
            }
            GWStub.on("GET /v1/filespaces/fs1/blocks/bigread.mov", json: "[\(manifestRows.joined(separator: ","))]")
            GWStub.on("GET /v1/filespaces/fs1/items/bigread.mov",
                json: #"{"id":"bigread.mov","parent":"root","name":"bigread.mov","isDir":false,"size":\#(fileSize),"contentVersion":"cv","version":1}"#)

            let dp = await engine.dataPath(for: "fs1")

            // ===== THE READ: the whole 128 MiB in one call, RSS sampled throughout =====
            let sampler = RSSSampler()
            let (ref, range) = try await dp.readRange(itemID, version: "cv", offset: 0,
                                                      length: fileSize, alignment: bs)
            let peakDelta = sampler.stop()

            XCTAssertEqual(range.length, fileSize, "the full file must be materialized")
            let path = try XCTUnwrap(ref.path)
            let attrs = try FileManager.default.attributesOfItem(atPath: path)
            XCTAssertEqual(attrs[.size] as? Int, fileSize, "spill file holds the whole image")

            // Round-trip spot check: every block's first byte is its index (GCM already
            // authenticated each block during assembly).
            let fh = try Foundation.FileHandle(forReadingFrom: URL(fileURLWithPath: path))
            defer { try? fh.close() }
            for i in 0..<blocks {
                try fh.seek(toOffset: UInt64(i * bs))
                XCTAssertEqual(try fh.read(upToCount: 1)?.first, UInt8(i & 0xff), "block \(i) content")
            }

            // ===== THE BOUND: tens of MB, not the file size =====
            print("P1-acceptance[read]: 128 MiB whole-file read, peak RSS delta = \(peakDelta >> 20) MiB")
            XCTAssertLessThan(peakDelta, 48 << 20,
                "streaming assembly must keep memory ~one block; peak delta was \(peakDelta >> 20) MiB for a 128 MiB read")
            try? FileManager.default.removeItem(atPath: path)
        }
    }

    // MARK: - P2 ACCEPTANCE: cold sequential read sustains real-time throughput
    //
    // Josh's acceptance ("cold sequential playback of a ProRes 422 clip sustains
    // real-time bitrate"), made deterministic for CI: every blob GET carries a
    // 40 ms injected latency (object-store TTFB). A player-style sequential read
    // (1 MiB at a time, the FUSE rwsize shape) must beat real time by a wide margin:
    //   • WITHOUT read-ahead the bound is hard: 1 block per 40 ms ≈ 25 MiB/s serial.
    //   • ProRes 422 1080p30 needs ≈ 20 MiB/s.
    //   • WITH daemon-side read-ahead (16-block window, 8-way fan-out, in-flight
    //     dedup) the pipeline should sustain ≥ 60 MiB/s (expected ~150+).
    // Also asserts every block was fetched EXACTLY once — the read-ahead and the
    // foreground reads never duplicate a GET (in-flight dedup) and never re-fetch
    // the whole file (the old requestDownload storm).
    func testColdSequentialReadSustainsRealTimeThroughput() async throws {
        try await withTestTimeout(120) {
            let (engine, _) = try makeEngine()
            _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
            let crypto = try AESGCMBlockCrypto(masterKeyBytes: keyBytes)
            let itemID = InodeID("seqplay.mov")
            let bs = 1 << 20
            let blocks = 48                            // 48 MiB < the 64 MiB cache budget
            var manifestRows: [String] = []
            for i in 0..<blocks {
                let pt = Data(repeating: UInt8(i & 0xff), count: bs)
                let (ct, hash) = try await crypto.encryptBlock(pt, itemID: itemID, blockIndex: i)
                try await blobPut(hash.objectKey, ct, on: engine)
                manifestRows.append(
                    #"{"chunkIdx":\#(i),"blockIdx":\#(i),"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":\#(i * bs),"length":\#(bs)}"#)
            }
            GWStub.on("GET /v1/filespaces/fs1/blocks/seqplay.mov", json: "[\(manifestRows.joined(separator: ","))]")
            GWStub.on("GET /v1/filespaces/fs1/items/seqplay.mov",
                json: #"{"id":"seqplay.mov","parent":"root","name":"seqplay.mov","isDir":false,"size":\#(blocks * bs),"contentVersion":"cv","version":1}"#)
            GWStub.setBlobGetLatency(ms: 40)

            let dp = await engine.dataPath(for: "fs1")
            let t0 = Date()
            for i in 0..<blocks {
                let (ref, range) = try await dp.readRange(itemID, version: "cv",
                                                          offset: i * bs, length: bs, alignment: bs)
                XCTAssertEqual(range.length, bs)
                let p = try XCTUnwrap(ref.path)
                let fh = try Foundation.FileHandle(forReadingFrom: URL(fileURLWithPath: p))
                XCTAssertEqual(try fh.read(upToCount: 1)?.first, UInt8(i & 0xff), "block \(i) content")
                try? fh.close()
                try? FileManager.default.removeItem(atPath: p)
            }
            let wall = Date().timeIntervalSince(t0)
            let mibPerSec = Double(blocks) / wall
            print("P2-acceptance: cold sequential 48 MiB @40 ms/GET injected latency → " +
                  String(format: "%.0f", mibPerSec) +
                  " MiB/s (no-read-ahead bound ≈ 25 MiB/s; ProRes 422 ≈ 20 MiB/s)")
            XCTAssertGreaterThan(mibPerSec, 60,
                "daemon-side read-ahead must lift cold sequential reads well past real time")
            // Exactly-once fetching: dedup + no full-file prefetch storms.
            XCTAssertEqual(GWStub.totalBlobGets(), blocks,
                "every block fetched exactly once (got \(GWStub.totalBlobGets()) GETs for \(blocks) blocks)")
        }
    }

    // MARK: - P2: crash remount (persisted mount intents)

    func testMountIntentPersistsAndRemountsAfterCrash() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let cacheDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("cfsd-remount-\(UUID().uuidString)").path
            let cfg = EngineConfig(cacheDir: cacheDir, cacheSizeBytes: 8 << 20,
                                   controlSocketPath: "/tmp/unused.sock",
                                   gatewayBaseURL: "https://gw.test")
            let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "t"),
                                            session: GWStub.session())
            let mountPoint = try KernelMountTable.canonicalMountPath("/tmp/cfs-remount-test-\(UInt32.random(in: 0..<1_000_000))")

            // Engine #1 mounts (recording backend returns immediately, like a live mount).
            let backend1 = RecordingMountBackend()
            let engine1 = CloudFSEngine(config: cfg, gateway: gateway, mount: backend1,
                                        key: try FilespaceKey(masterKeyBytes: keyBytes))
            _ = try await engine1.mount(MountParams(filespace: "fs1", at: mountPoint, rootPoint: nil))
            XCTAssertEqual(backend1.snapshotMounts().map(\.at), [mountPoint])
            XCTAssertTrue(FileManager.default.fileExists(atPath: cacheDir + "/mounts.json"),
                          "the mount intent must persist to disk")

            // "Crash": engine1 is dropped with NO unmount/shutdown. Engine #2 on the
            // SAME cache dir re-establishes the mount from the persisted intent.
            let backend2 = RecordingMountBackend()
            let engine2 = CloudFSEngine(config: cfg, gateway: gateway, mount: backend2,
                                        key: try FilespaceKey(masterKeyBytes: keyBytes))
            await engine2.remountPersisted()
            let deadline = Date().addingTimeInterval(5)
            while Date() < deadline {
                if backend2.snapshotMounts().contains(where: { $0.at == mountPoint }) { break }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            XCTAssertTrue(backend2.snapshotMounts().contains(where: { $0.filespace == "fs1" && $0.at == mountPoint }),
                          "a crashed daemon's mount must re-establish on the next start")

            // A GRACEFUL unmount clears the intent — no remount after a clean stop.
            _ = try await engine2.unmount(UnmountParams(filespace: "fs1", force: false))
            XCTAssertFalse(FileManager.default.fileExists(atPath: cacheDir + "/mounts.json"),
                           "a graceful unmount must clear the persisted intent")
        }
    }
}

/// A MountBackend that records calls and returns immediately (stands in for a live
/// FUSE mount in remount tests).
final class RecordingMountBackend: MountBackend, @unchecked Sendable {
    private let onUnmount: (@Sendable (FilespaceID) async throws -> Void)?
    init(onUnmount: (@Sendable (FilespaceID) async throws -> Void)? = nil) { self.onUnmount = onUnmount }
    private let lock = NSLock()
    private var mounts: [(filespace: String, at: String)] = []
    private var unmounted: [String] = []
    var kind: String { "recording" }
    var isAvailable: Bool { true }
    func mount(filespace: FilespaceID, displayName: String?, at mountPoint: String,
               engine: any EngineDataPath) async throws {
        record { self.mounts.append((filespace, mountPoint)) }
    }
    func unmount(filespace: FilespaceID, force: Bool) async throws {
        record { self.unmounted.append(filespace) }
        try await onUnmount?(filespace)
    }
    /// Synchronous locked mutation (NSLock is unavailable directly in async funcs).
    private func record(_ body: () -> Void) {
        lock.lock(); body(); lock.unlock()
    }
    func snapshotMounts() -> [(filespace: String, at: String)] {
        lock.lock(); defer { lock.unlock() }; return mounts
    }
}

// MARK: - RSS sampler (peak resident-size delta across a measured window) ------

/// Samples the process's resident size on a dedicated thread every ~2 ms and tracks
/// the peak. `stop()` returns peak-minus-baseline. A thread (not a Task) so sampling
/// never competes with the async work under measurement for executor time.
final class RSSSampler: @unchecked Sendable {
    private let lock = NSLock()
    private let baseline: Int
    private var peak: Int
    private var running = true

    init() {
        baseline = Self.resident()
        peak = baseline
        Thread.detachNewThread { [weak self] in
            while true {
                guard let self else { return }
                self.lock.lock()
                let go = self.running
                self.lock.unlock()
                if !go { return }
                let r = Self.resident()
                self.lock.lock()
                if r > self.peak { self.peak = r }
                self.lock.unlock()
                usleep(2_000)
            }
        }
    }

    /// Stop sampling; returns the peak resident-size delta over the baseline.
    func stop() -> Int {
        lock.lock(); defer { lock.unlock() }
        running = false
        return max(0, peak - baseline)
    }

    static func resident() -> Int {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) { ip in
            ip.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? Int(info.resident_size) : 0
    }
}

// MARK: - Daemon start/stop smoke ---------------------------------------------

final class CloudFSDaemonTests: XCTestCase {
    /// Keep parser tests independent of the developer machine's daemon.env and
    /// process environment. Tests that exercise an env file pass it explicitly.
    private func parseDaemonConfig(_ args: [String], environment: [String: String] = [:]) throws -> DaemonConfig {
        if args.contains("--env-file") {
            return try DaemonConfig.parse(args, environment: environment)
        }
        let emptyEnv = NSTemporaryDirectory() + "cfsd-isolated-env-\(UUID().uuidString).env"
        try "".write(toFile: emptyEnv, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: emptyEnv) }
        return try DaemonConfig.parse(["--env-file", emptyEnv] + args, environment: environment)
    }


    func testSocketPathLengthValidation() throws {
        // 103 is allowed; 104 is rejected (AF_UNIX sun_path).
        XCTAssertNoThrow(try DaemonConfig.validateSocketPath(String(repeating: "a", count: 103)))
        XCTAssertThrowsError(try DaemonConfig.validateSocketPath(String(repeating: "a", count: 104))) { err in
            XCTAssertEqual((err as? EngineError)?.kind, .invalidParams)
        }
    }

    func testDaemonStartOnceAndShutdown() async throws {
        try await withTestTimeout(25) {
            // Short temp socket paths (well under 103 bytes).
            let n = UInt32.random(in: 0..<1_000_000)
            let sock = "/tmp/cfsd-\(n).sock"
            let finderSock = "/tmp/cfsd-\(n)-f.sock"   // M8: the appex's second listener
            let cacheDir = FileManager.default.temporaryDirectory
                .appendingPathComponent("cfsd-daemon-\(UUID().uuidString)").path
            let engineCfg = EngineConfig(cacheDir: cacheDir, cacheSizeBytes: 8 << 20,
                                         controlSocketPath: sock, gatewayBaseURL: "https://gw.test")
            let cfg = DaemonConfig(engine: engineCfg, keyFilePath: nil, autoConnectFilespace: nil,
                                   finderSocketPath: finderSock)
            let daemon = Daemon(config: cfg)
            try await daemon.startOnce()
            // Both socket files exist once bound.
            XCTAssertTrue(FileManager.default.fileExists(atPath: sock), "socket should be bound")
            XCTAssertTrue(FileManager.default.fileExists(atPath: finderSock), "finder socket should be bound")
            await daemon.shutdown()
            XCTAssertFalse(FileManager.default.fileExists(atPath: sock), "socket should be removed on shutdown")
            XCTAssertFalse(FileManager.default.fileExists(atPath: finderSock), "finder socket should be removed on shutdown")
        }
    }

    /// M7 — the agent-launched daemon reads its provisioning from an env FILE the
    /// app writes (the bundled agent plist is static); flags/process-env still win.
    func testConfigEnvFileProvidesDefaultsButFlagsWin() throws {
        let envFile = NSTemporaryDirectory() + "cfsd-envfile-\(UUID().uuidString).env"
        try """
        # written by the app on sign-in
        CLOUDFS_GATEWAY=https://gateway.example.invalid
        CLOUDFS_SOCKET=/tmp/agent-test.sock
        CLOUDFS_TOKEN_FILE=/tmp/agent-token.txt
        CLOUDFS_FINDER_SOCKET=/tmp/agent-finder.sock
        CLOUDFS_KEY_FILE=/tmp/optional-key.hex
        CLOUDFS_KEY_FILE_OPTIONAL=1
        """.write(toFile: envFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: envFile) }

        // Env file supplies everything when no flags are passed…
        let cfg = try parseDaemonConfig(["--env-file", envFile])
        XCTAssertEqual(cfg.engine.gatewayBaseURL, "https://gateway.example.invalid")
        XCTAssertEqual(cfg.engine.controlSocketPath, "/tmp/agent-test.sock")
        XCTAssertEqual(cfg.engine.tokenFilePath, "/tmp/agent-token.txt")
        XCTAssertEqual(cfg.finderSocketPath, "/tmp/agent-finder.sock")
        XCTAssertEqual(cfg.keyFilePath, "/tmp/optional-key.hex")
        XCTAssertFalse(cfg.keyFileRequired, "the app's default key.hex path is optional and may fall through to gateway fetch")
        let explicitlyConfiguredKey = try parseDaemonConfig(["--env-file", envFile],
                                                             environment: ["CLOUDFS_KEY_FILE": "/tmp/operator-key.hex",
                                                                            "CLOUDFS_KEY_FILE_FILESPACE": "fsY",
                                                                            "CLOUDFS_KEY_FILE_GATEWAY": "https://gw.example",
                                                                            "CLOUDFS_KEY_FILE_ORG": "orgY"])
        XCTAssertEqual(explicitlyConfiguredKey.keyFilePath, "/tmp/operator-key.hex")
        XCTAssertTrue(explicitlyConfiguredKey.keyFileRequired, "an operator-provided process environment key path is required")
        let requiredKeyEnv = NSTemporaryDirectory() + "cfsd-required-key-env-\(UUID().uuidString).env"
        try "CLOUDFS_KEY_FILE=/tmp/operator-key.hex\nCLOUDFS_KEY_FILE_FILESPACE=fsY\nCLOUDFS_KEY_FILE_GATEWAY=https://gw.example\nCLOUDFS_KEY_FILE_ORG=orgY\n".write(toFile: requiredKeyEnv, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: requiredKeyEnv) }
        let requiredFromEnvFile = try parseDaemonConfig(["--env-file", requiredKeyEnv], environment: [:])
        XCTAssertTrue(requiredFromEnvFile.keyFileRequired, "a manually configured env-file key path is required unless marked optional")

        // …and an explicit flag beats the env file.
        let cfg2 = try parseDaemonConfig(["--env-file", envFile, "--gateway", "https://other.example"])
        XCTAssertEqual(cfg2.engine.gatewayBaseURL, "https://other.example")
        XCTAssertEqual(cfg2.engine.controlSocketPath, "/tmp/agent-test.sock", "non-overridden keys still flow")
    }

    func testConfigParseFlagsAndEnvDefaults() throws {
        let emptyEnv = NSTemporaryDirectory() + "cfsd-empty-env-\(UUID().uuidString).env"
        try "".write(toFile: emptyEnv, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: emptyEnv) }
        let cfg = try parseDaemonConfig(["--control-socket", "/tmp/x.sock",
                                          "--cache-dir", "/tmp/c",
                                          "--cache-size", "1048576",
                                          "--gateway", "http://localhost:9999",
                                          "--filespace", "fsX",
                                          "--env-file", emptyEnv], environment: [:])
        XCTAssertEqual(cfg.engine.controlSocketPath, "/tmp/x.sock")
        XCTAssertEqual(cfg.engine.cacheDir, "/tmp/c")
        XCTAssertEqual(cfg.engine.cacheSizeBytes, 1048576)
        XCTAssertEqual(cfg.engine.gatewayBaseURL, "http://localhost:9999")
        XCTAssertEqual(cfg.autoConnectFilespace, "fsX")
        XCTAssertEqual(cfg.keyFileFilespace, "fsX", "a single-filespace daemon can infer the filespace portion of a local binding")
        let explicitlyBound = try parseDaemonConfig(["--key-file", "/tmp/key.hex",
                                                       "--filespace", "fsX",
                                                       "--key-filespace", "fsY",
                                                       "--key-gateway", "https://gw.example",
                                                       "--key-org", "orgY",
                                                       "--env-file", emptyEnv], environment: [:])
        XCTAssertEqual(explicitlyBound.keyFileFilespace, "fsY")
        XCTAssertEqual(explicitlyBound.keyFileGateway, "https://gw.example")
        XCTAssertEqual(explicitlyBound.keyFileOrganization, "orgY")
        XCTAssertTrue(explicitlyBound.keyFileRequired)
        XCTAssertThrowsError(try parseDaemonConfig(["--key-file", "/tmp/key.hex", "--env-file", emptyEnv], environment: [:]),
                             "an explicit key file without all deployment bindings must fail config parsing")
    }

    func testReadAheadBudgetConfigurationIsBounded() throws {
        XCTAssertEqual(try parseDaemonConfig([]).engine.readAheadBudgetMiB, 64)
        for accepted in ["8", "128", "64"] {
            XCTAssertEqual(try parseDaemonConfig(["--read-ahead-budget-mib", accepted]).engine.readAheadBudgetMiB, Int(accepted))
        }
        for invalid in ["7", "129", "0", "-1", "garbage", ""] {
            XCTAssertThrowsError(try parseDaemonConfig(["--read-ahead-budget-mib", invalid]), invalid)
        }
        let envFile = NSTemporaryDirectory() + "cfsd-budget-\(UUID().uuidString).env"
        try "CLOUDFS_READ_AHEAD_BUDGET_MIB=96\n".write(toFile: envFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: envFile) }
        XCTAssertEqual(try parseDaemonConfig(["--env-file", envFile]).engine.readAheadBudgetMiB, 96)
        XCTAssertEqual(try parseDaemonConfig(["--env-file", envFile, "--read-ahead-budget-mib", "8"]).engine.readAheadBudgetMiB, 8)
    }

    func testTransferConcurrencyConfigurationIsBoundedAndFlagsOverrideFile() throws {
        let envFile = NSTemporaryDirectory() + "cfsd-concurrency-\(UUID().uuidString).env"
        try "CLOUDFS_UPLOAD_CONCURRENCY=16\nCLOUDFS_DOWNLOAD_CONCURRENCY=12\n".write(toFile: envFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: envFile) }
        let config = try parseDaemonConfig(["--env-file", envFile, "--upload-concurrency", "64"])
        XCTAssertEqual(config.engine.uploadConcurrency, 64)
        XCTAssertEqual(config.engine.downloadConcurrency, 12)
        for flag in ["--upload-concurrency", "--download-concurrency"] {
            for invalid in ["0", "65", "-1", "many"] {
                XCTAssertThrowsError(try parseDaemonConfig([flag, invalid]))
            }
        }
    }

    func testExplicitEnvironmentNeverFallsBackToRegularDeployment() throws {
        let envFile = NSTemporaryDirectory() + "cfsd-empty-\(UUID().uuidString).env"
        XCTAssertThrowsError(try DaemonConfig.loadEnvFile(envFile)) { error in
            XCTAssertEqual((error as? EngineError)?.kind, .invalidParams)
        }
        try "# isolated environment\n".write(toFile: envFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(atPath: envFile) }
        XCTAssertEqual(try DaemonConfig.loadEnvFile(envFile), [:])
    }

    // Audit B15 (TLS policy): a non-loopback http:// gateway is refused unless opted in.
    func testRejectsPlaintextHttpGatewayOnNonLoopback() {
        let args = ["--control-socket", "/tmp/x.sock", "--gateway", "http://gw.example.com:8787"]
        XCTAssertThrowsError(try parseDaemonConfig(args)) { e in
            XCTAssertEqual((e as? EngineError)?.kind, .invalidParams)
        }
    }
    func testAllowsLoopbackHttpGateway() throws {
        // localhost / 127.0.0.1 http is fine for dev.
        _ = try parseDaemonConfig(["--gateway", "http://127.0.0.1:8787"])
        _ = try parseDaemonConfig(["--gateway", "http://localhost:8787"])
    }
    func testAllowsHttpsGateway() throws {
        _ = try parseDaemonConfig(["--gateway", "https://gw.example.com"])
    }
    func testAllowInsecureHttpOverridesTLSPolicy() throws {
        let cfg = try parseDaemonConfig(["--gateway", "http://gw.example.com:8787", "--allow-insecure-http"])
        XCTAssertEqual(cfg.engine.gatewayBaseURL, "http://gw.example.com:8787")
    }
    func testTLSPolicyHelperDirectly() {
        XCTAssertNoThrow(try DaemonConfig.validateGatewayTLS("https://x.example", allowInsecure: false))
        XCTAssertNoThrow(try DaemonConfig.validateGatewayTLS("http://localhost", allowInsecure: false))
        XCTAssertThrowsError(try DaemonConfig.validateGatewayTLS("http://x.example", allowInsecure: false))
        XCTAssertNoThrow(try DaemonConfig.validateGatewayTLS("http://x.example", allowInsecure: true))
    }

    // MARK: Auth B-1 (spec §6.4 D1) — live bearer-token re-read between requests

    /// Write a 0600 token file the live provider can load (the loader REJECTS
    /// group/other-readable files, and an atomic rewrite mints a fresh temp file
    /// whose mode isn't guaranteed).
    private func writeTokenFile(_ path: String, _ token: String,
                                mode: Int = 0o600, mtime: Date? = nil) throws {
        try (token + "\n").write(toFile: path, atomically: true, encoding: .utf8)
        var attrs: [FileAttributeKey: Any] = [.posixPermissions: mode]
        if let mtime { attrs[.modificationDate] = mtime }
        try FileManager.default.setAttributes(attrs, ofItemAtPath: path)
    }

    /// The app renews the daemon token by atomically REWRITING token.txt (backend
    /// soft-expires the prior token ~10 min later); the daemon must serve the new
    /// token on its NEXT request — no restart (a restart unmounts the volume).
    /// The huge maxAge proves the FILE-MTIME check (not cache expiry) triggers the
    /// re-read, i.e. pickup happens within one request cycle.
    func testLiveTokenProviderPicksUpRewrittenTokenFile() throws {
        let tmp = NSTemporaryDirectory() + "cfsd-live-tok-\(UUID().uuidString).txt"
        try writeTokenFile(tmp, "tok-old")
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let provider = LiveBearerTokenProvider(filespace: nil, filePath: tmp, maxAge: 3600)
        XCTAssertEqual(provider.current(), "tok-old")

        // Renewal: rewrite + explicit mtime bump so the test never depends on
        // filesystem timestamp granularity.
        try writeTokenFile(tmp, "tok-new", mtime: Date().addingTimeInterval(5))
        XCTAssertEqual(provider.current(), "tok-new",
                       "a rewritten token.txt must be served on the very next request — no daemon restart")
    }

    /// The staleness fallback (a Keychain-side rotation has no mtime to observe):
    /// once the cache is older than maxAge the provider re-reads even when the
    /// file's mtime looks unchanged.
    func testLiveTokenProviderStaleCacheReloadsWithoutMtimeChange() throws {
        let tmp = NSTemporaryDirectory() + "cfsd-live-tok-\(UUID().uuidString).txt"
        try writeTokenFile(tmp, "tok-1")
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let provider = LiveBearerTokenProvider(filespace: nil, filePath: tmp, maxAge: 0)
        XCTAssertEqual(provider.current(), "tok-1")

        // In-place rewrite (same inode, mode preserved), restoring the recorded
        // mtime — the zero maxAge alone must trigger the re-read.
        let orig = try FileManager.default.attributesOfItem(atPath: tmp)[.modificationDate] as? Date
        try Data("tok-2\n".utf8).write(to: URL(fileURLWithPath: tmp))
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600, .modificationDate: orig ?? Date()], ofItemAtPath: tmp)
        XCTAssertEqual(provider.current(), "tok-2")
    }

    /// A renewal that leaves token.txt group/other-readable is REJECTED by the
    /// loader (audit B15); the provider keeps serving the LAST-GOOD token (still
    /// valid through the backend's soft-cutover window) instead of going anonymous
    /// mid-flight.
    func testLiveTokenProviderKeepsLastGoodTokenWhenRereadFails() throws {
        let tmp = NSTemporaryDirectory() + "cfsd-live-tok-\(UUID().uuidString).txt"
        try writeTokenFile(tmp, "tok-good")
        defer { try? FileManager.default.removeItem(atPath: tmp) }

        let provider = LiveBearerTokenProvider(filespace: nil, filePath: tmp, maxAge: 0)
        XCTAssertEqual(provider.current(), "tok-good")

        try writeTokenFile(tmp, "tok-leaky", mode: 0o644, mtime: Date().addingTimeInterval(5))
        XCTAssertEqual(provider.current(), "tok-good",
                       "a bad-mode token file must not strip auth off the running daemon")
    }

    /// END-TO-END regression for B-1: the SAME HttpGatewayClient instance (the one
    /// the daemon builds once at startup — never reconstructed) sends the NEW bearer
    /// after token.txt is rewritten between requests.
    func testHttpGatewayClientSendsRenewedTokenWithoutReconstruction() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let tmp = NSTemporaryDirectory() + "cfsd-live-tok-\(UUID().uuidString).txt"
            try ("tok-before" + "\n").write(toFile: tmp, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp)
            defer { try? FileManager.default.removeItem(atPath: tmp) }

            final class AuthLog: @unchecked Sendable {
                private let lock = NSLock()
                private var seen: [String] = []
                func add(_ s: String?) { lock.lock(); seen.append(s ?? "<none>"); lock.unlock() }
                var all: [String] { lock.lock(); defer { lock.unlock() }; return seen }
            }
            let log = AuthLog()
            GWStub.on("GET /v1/filespaces/fsL/items/x") { req in
                log.add(req.value(forHTTPHeaderField: "Authorization"))
                return (200, #"{"id":"x","parent":"root","name":"x","isDir":false,"size":0,"contentVersion":"cv","etag":null,"version":1,"updatedSeq":1,"deleted":false}"#)
            }

            // The exact wiring Daemon.init now uses: live provider → tokenProvider closure.
            let tokens = LiveBearerTokenProvider(filespace: nil, filePath: tmp, maxAge: 3600)
            let client = HttpGatewayClient(
                config: GatewayClientConfig(baseURL: "https://gw.test") { tokens.current() },
                session: GWStub.session())

            _ = try await client.getItem(filespace: "fsL", id: "x")

            // The app's renewal: atomic rewrite of token.txt (mtime bumped explicitly
            // so the test never depends on filesystem timestamp granularity).
            try ("tok-after" + "\n").write(toFile: tmp, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600, .modificationDate: Date().addingTimeInterval(5)],
                ofItemAtPath: tmp)

            _ = try await client.getItem(filespace: "fsL", id: "x")
            XCTAssertEqual(log.all, ["Bearer tok-before", "Bearer tok-after"],
                           "the running daemon must pick up a renewed token.txt without rebuilding the client")
            GWStub.reset()
        }
    }

    // MARK: - ONBOARDING.md "Key model" — FilespaceKeyResolver (build step 2)

    func testResolverFetchesFromGatewayWhenNoLocalKeyAndCachesForNextCall() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let raw = Data((0..<32).map { UInt8($0 &+ 7) })
            let materialB64 = raw.base64EncodedString()
            let route = "GET /v1/filespaces/\(fs)/key"
            GWStub.on(route, json: #"{"keyId":"kid-1","format":"plain-v1","material":"\#(materialB64)"}"#)

            let resolver = FilespaceKeyResolver()
            let gateway = keyResolverTestGatewayClient()
            let resolved = await resolver.resolve(filespace: fs, localKey: nil, gatewayURL: "https://gw.test", organization: "org-test", gateway: gateway)
            XCTAssertNotNil(resolved, "no local key + a working gateway fetch must still yield a usable key")
            XCTAssertEqual(resolved?.masterRawBytes, raw)
            XCTAssertEqual(GWStub.count(route), 1, "the envelope was fetched exactly once")

            // Second resolve for the SAME filespace must NOT hit the network again — either the
            // Keychain write landed (read-back hit) or (Keychain unavailable in this environment)
            // the in-memory fallback served it. Either way, zero additional gateway round-trips.
            let resolvedAgain = await resolver.resolve(filespace: fs, localKey: nil, gatewayURL: "https://gw.test", organization: "org-test", gateway: gateway)
            XCTAssertEqual(resolvedAgain?.masterRawBytes, raw)
            XCTAssertEqual(GWStub.count(route), 1, "a cached key (Keychain or in-memory fallback) must never re-fetch")
            GWStub.reset()
        }
    }

    /// Migration safety (ONBOARDING.md): "local sources keep precedence" — an operator-provisioned
    /// `--key-file` key must win over a fetch even when the gateway ALSO has (a possibly
    /// different) key on offer. No route is stubbed at all, so any fetch attempt would 404 and
    /// the assertion on the route count catches a precedence regression.
    func testLocalKeyWinsOverGatewayFetch() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let localRaw = Data((0..<32).map { UInt8($0 &+ 100) })
            let localKey = try FilespaceKey(masterKeyBytes: localRaw)
            let route = "GET /v1/filespaces/\(fs)/key"

            let resolver = FilespaceKeyResolver(keychainReader: { _ in
                XCTFail("An explicit local key must not trigger a potentially blocking Keychain query")
                return nil
            })
            let resolved = await resolver.resolve(filespace: fs, localKey: localKey,
                                                  localKeyFilespace: fs,
                                                  localKeyGateway: "https://GW.TEST:443/",
                                                  localKeyOrganization: "org-test",
                                                  gatewayURL: "https://gw.test",
                                                  organization: "org-test",
                                                  gateway: keyResolverTestGatewayClient())
            XCTAssertEqual(resolved?.masterRawBytes, localRaw)
            XCTAssertEqual(GWStub.count(route), 0, "a local key must short-circuit BEFORE any gateway call")
            GWStub.reset()
        }
    }

    func testBoundLocalKeyDoesNotBleedIntoAnotherFilespace() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let sourceFS = freshFilespaceIDForKeyResolverTests()
            let requestedFS = sourceFS
            let localRaw = Data((0..<32).map { UInt8($0 &+ 31) })
            let remoteRaw = Data((0..<32).map { UInt8($0 &+ 91) })
            let route = "GET /v1/filespaces/\(requestedFS)/key"
            GWStub.on(route, json: #"{"keyId":"kid-other","format":"plain-v1","material":"\#(remoteRaw.base64EncodedString())"}"#)

            let localKey = try FilespaceKey(masterKeyBytes: localRaw)
            let resolver = FilespaceKeyResolver(keychainReader: { _ in nil })
            let resolved = await resolver.resolve(filespace: requestedFS, localKey: localKey,
                                                  localKeyFilespace: sourceFS,
                                                  localKeyGateway: "https://other.example",
                                                  localKeyOrganization: "org-test",
                                                  gatewayURL: "https://gw.test",
                                                  organization: "org-test",
                                                  gateway: keyResolverTestGatewayClient())
            XCTAssertEqual(resolved?.masterRawBytes, remoteRaw,
                           "a key for the same filespace on another gateway must not be used")
            XCTAssertEqual(GWStub.count(route), 1)
            GWStub.reset()
        }
    }

    func testUnboundLocalKeyNeverBecomesDaemonWideFallback() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let localRaw = Data((0..<32).map { UInt8($0 &+ 14) })
            let remoteRaw = Data((0..<32).map { UInt8($0 &+ 64) })
            let route = "GET /v1/filespaces/\(fs)/key"
            GWStub.on(route, json: #"{"keyId":"kid-scoped","format":"plain-v1","material":"\#(remoteRaw.base64EncodedString())"}"#)

            let localKey = try FilespaceKey(masterKeyBytes: localRaw)
            let resolver = FilespaceKeyResolver(keychainReader: { _ in nil })
            let resolved = await resolver.resolve(filespace: fs, localKey: localKey,
                                                  localKeyFilespace: nil,
                                                  localKeyGateway: nil,
                                                  localKeyOrganization: nil,
                                                  gatewayURL: "https://gw.test",
                                                  organization: "org-test",
                                                  gateway: keyResolverTestGatewayClient())
            XCTAssertEqual(resolved?.masterRawBytes, remoteRaw,
                           "an unbound legacy key is not authority for an arbitrary filespace")
            XCTAssertEqual(GWStub.count(route), 1)
            GWStub.reset()
        }
    }

    func testExplicitRequiredKeyFileFailureDoesNotFallBackToGateway() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let route = "GET /v1/filespaces/\(fs)/key"
            let resolver = FilespaceKeyResolver(keychainReader: { _ in
                XCTFail("a required local key failure must not fall through to Keychain")
                return nil
            })
            let resolved = await resolver.resolve(filespace: fs, localKey: nil,
                                                  localKeyFilespace: fs,
                                                  localKeyGateway: "https://gw.test",
                                                  localKeyOrganization: "org-test",
                                                  gatewayURL: "https://gw.test",
                                                  organization: "org-test",
                                                  requireBoundLocalKey: true,
                                                  gateway: keyResolverTestGatewayClient())
            XCTAssertNil(resolved)
            XCTAssertEqual(GWStub.count(route), 0, "explicitly required missing key files fail closed without a gateway substitute")
            GWStub.reset()
        }
    }

    func testPresentInvalidBoundOptionalKeyFileFailsClosed() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let path = NSTemporaryDirectory() + "cfsd-invalid-key-\(UUID().uuidString).hex"
            try "this is not a valid key".write(toFile: path, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
            defer { try? FileManager.default.removeItem(atPath: path) }
            let loaded = Daemon.loadKey(path)
            XCTAssertNil(loaded.key)
            XCTAssertTrue(loaded.invalidPresent, "present invalid files must be distinguishable from an absent optional file")

            let route = "GET /v1/filespaces/\(fs)/key"
            let resolver = FilespaceKeyResolver(keychainReader: { _ in
                XCTFail("an invalid bound key file must not fall through to Keychain")
                return nil
            })
            let resolved = await resolver.resolve(filespace: fs, localKey: loaded.key,
                                                  localKeyFilespace: fs,
                                                  localKeyGateway: "https://gw.test",
                                                  localKeyOrganization: "org-test",
                                                  localKeyFileInvalid: loaded.invalidPresent,
                                                  gatewayURL: "https://gw.test",
                                                  organization: "org-test",
                                                  gateway: keyResolverTestGatewayClient())
            XCTAssertNil(resolved)
            XCTAssertEqual(GWStub.count(route), 0, "an invalid bound file cannot be replaced by a different gateway key")
            GWStub.reset()
        }
    }

    func testRequiredKeyFileDoesNotBlockOtherFilespaces() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let requiredFS = freshFilespaceIDForKeyResolverTests()
            let otherFS = freshFilespaceIDForKeyResolverTests()
            let otherRaw = Data((0..<32).map { UInt8($0 &+ 46) })
            let route = "GET /v1/filespaces/\(otherFS)/key"
            GWStub.on(route, json: #"{"keyId":"kid-other","format":"plain-v1","material":"\#(otherRaw.base64EncodedString())"}"#)
            let resolver = FilespaceKeyResolver(keychainReader: { _ in nil })
            let resolved = await resolver.resolve(filespace: otherFS, localKey: nil,
                                                  localKeyFilespace: requiredFS,
                                                  localKeyGateway: "https://gw.test",
                                                  localKeyOrganization: "org-test",
                                                  gatewayURL: "https://gw.test",
                                                  organization: "org-test",
                                                  requireBoundLocalKey: true,
                                                  gateway: keyResolverTestGatewayClient())
            XCTAssertEqual(resolved?.masterRawBytes, otherRaw,
                           "a required missing key fails closed for its bound target only; other filespaces resolve independently")
            XCTAssertEqual(GWStub.count(route), 1)
            GWStub.reset()
        }
    }

    func testRequiredKeyFileDoesNotBlockDifferentOrganization() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let otherRaw = Data((0..<32).map { UInt8($0 &+ 126) })
            let route = "GET /v1/filespaces/\(fs)/key"
            GWStub.on(route, json: #"{"keyId":"kid-other-org","format":"plain-v1","material":"\#(otherRaw.base64EncodedString())"}"#)
            let resolver = FilespaceKeyResolver(keychainReader: { _ in nil })
            let resolved = await resolver.resolve(filespace: fs, localKey: nil,
                                                  localKeyFilespace: fs,
                                                  localKeyGateway: "https://gw.test",
                                                  localKeyOrganization: "org-bound",
                                                  gatewayURL: "https://gw.test",
                                                  organization: "org-requested",
                                                  requireBoundLocalKey: true,
                                                  gateway: keyResolverTestGatewayClient())
            XCTAssertEqual(resolved?.masterRawBytes, otherRaw,
                           "the required-file fail-closed rule applies only to the complete gateway/org/filespace tuple")
            XCTAssertEqual(GWStub.count(route), 1)
            GWStub.reset()
        }
    }

    func testSameFilespaceIDUsesSeparateGatewayKeysAndKeychainAccounts() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let firstRaw = Data((0..<32).map { UInt8($0 &+ 8) })
            let secondRaw = Data((0..<32).map { UInt8($0 &+ 108) })
            let route = "GET /v1/filespaces/\(fs)/key"
            let resolver = FilespaceKeyResolver(keychainReader: { account in
                XCTAssertTrue(account.hasPrefix("v2."), "only deployment-scoped Keychain accounts are queried")
                return nil
            })
            GWStub.on(route) { request in
                let host = request.url?.host
                let bytes = host == "one.example" ? firstRaw : secondRaw
                return (200, #"{"keyId":"kid","format":"plain-v1","material":"\#(bytes.base64EncodedString())"}"#)
            }

            let first = await resolver.resolve(filespace: fs, localKey: nil,
                                               gatewayURL: "https://one.example/",
                                               organization: "org-one",
                                               gateway: keyResolverTestGatewayClient(baseURL: "https://one.example"))
            let second = await resolver.resolve(filespace: fs, localKey: nil,
                                                gatewayURL: "https://two.example",
                                                organization: "org-two",
                                                gateway: keyResolverTestGatewayClient(baseURL: "https://two.example"))
            XCTAssertEqual(first?.masterRawBytes, firstRaw)
            XCTAssertEqual(second?.masterRawBytes, secondRaw,
                           "a legacy filespace-ID-only key must not override another server's gateway key")
            let firstAccount = FilespaceKeyResolver.keychainAccount(gatewayURL: "https://one.example/", organization: "org-one", filespace: fs)
            let secondAccount = FilespaceKeyResolver.keychainAccount(gatewayURL: "https://two.example", organization: "org-one", filespace: fs)
            XCTAssertNotEqual(firstAccount, secondAccount, "same filespace IDs on different deployments get separate accounts")
            XCTAssertNotEqual(firstAccount, fs, "legacy ID-only Keychain entries are never queried")
            XCTAssertNotEqual(firstAccount,
                              FilespaceKeyResolver.keychainAccount(gatewayURL: "https://one.example/", organization: "org-two", filespace: fs),
                              "organizations on one gateway also get separate accounts")
            XCTAssertEqual(FilespaceKeyResolver.keychainAccount(gatewayURL: "https://one.example/", organization: "org-one", filespace: fs),
                           FilespaceKeyResolver.keychainAccount(gatewayURL: "https://ONE.EXAMPLE:443", organization: "org-one", filespace: fs),
                           "cosmetic URL differences share one per-deployment account")
            GWStub.reset()
        }
    }

    /// Forward-compat contract: an envelope in a format this daemon doesn't understand must be
    /// REJECTED, not guessed at — a future "device-wrapped-v1" must never be silently treated as
    /// raw key bytes.
    func testUnknownEnvelopeFormatIsRejected() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let route = "GET /v1/filespaces/\(fs)/key"
            GWStub.on(route, json: #"{"keyId":"kid-2","format":"device-wrapped-v1","material":null}"#)

            let resolver = FilespaceKeyResolver()
            let resolved = await resolver.resolve(filespace: fs, localKey: nil, gatewayURL: "https://gw.test", organization: "org-test", gateway: keyResolverTestGatewayClient())
            XCTAssertNil(resolved, "an unrecognized envelope format must be refused, never guessed at")
            GWStub.reset()
        }
    }

    /// No local source AND the gateway fetch itself fails (network/auth/server error — simulated
    /// here as an unstubbed route, which GWStub answers 404) → the resolver must give up cleanly
    /// (nil), which is what the daemon turns into the loud, NAMED-reason FATAL.
    func testFetchFailureWithNoLocalKeyReturnsNil() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            // Deliberately NOT stubbing "GET /v1/filespaces/\(fs)/key" — GWStub 404s it.
            let resolver = FilespaceKeyResolver()
            let resolved = await resolver.resolve(filespace: fs, localKey: nil, gatewayURL: "https://gw.test", organization: "org-test", gateway: keyResolverTestGatewayClient())
            XCTAssertNil(resolved, "no local key + a failed fetch must surface as a clean failure (the daemon logs FATAL)")
            GWStub.reset()
        }
    }

    /// A malformed envelope (right format, but missing/invalid material) is refused the same way
    /// as an unknown format — never crash, never fabricate key bytes.
    func testMalformedMaterialIsRejected() async throws {
        try await withTestTimeout {
            GWStub.reset()
            let fs = freshFilespaceIDForKeyResolverTests()
            let route = "GET /v1/filespaces/\(fs)/key"
            GWStub.on(route, json: #"{"keyId":"kid-3","format":"plain-v1","material":"not-valid-base64!!"}"#)

            let resolver = FilespaceKeyResolver()
            let resolved = await resolver.resolve(filespace: fs, localKey: nil, gatewayURL: "https://gw.test", organization: "org-test", gateway: keyResolverTestGatewayClient())
            XCTAssertNil(resolved)
            GWStub.reset()
        }
    }
}

// MARK: - FilespaceKeyResolver test helpers -------------------------------------
// Free functions (not instance methods) so `withTestTimeout`'s `@Sendable` closure never
// captures the non-Sendable XCTestCase `self`.

/// A fresh, never-used filespace id so `FilespaceKey.fromKeychain` reliably misses (no stale item
/// from a prior test run/account) — the resolver tests want a CONTROLLED miss on the local
/// sources so the gateway-fetch tier actually exercises.
private func freshFilespaceIDForKeyResolverTests() -> FilespaceID { "fkres-\(UUID().uuidString)" }

private func keyResolverTestGatewayClient(baseURL: String = "https://gw.test") -> HttpGatewayClient {
    HttpGatewayClient(config: GatewayClientConfig(baseURL: baseURL, token: "tok"),
                      session: GWStub.session())
}

// MARK: - blob helper ----------------------------------------------------------

/// Store a block's ciphertext in the gateway stub's blob plane under its objectKey
/// (a presigned GET on that key then serves it). Goes through a presign+PUT so the
/// path mirrors the real engine, but we just register the bytes directly here.
private func blobPut(_ objectKey: String, _ data: Data, on engine: CloudFSEngine) async throws {
    // Drive a PUT through the stub's blob plane so a later GET serves the bytes.
    let enc = objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? objectKey
    var req = URLRequest(url: URL(string: "https://blob.test/blob?key=\(enc)")!)
    req.httpMethod = "PUT"
    req.httpBody = data
    _ = try await GWStub.session().data(for: req)
}

final class MountedRootProjectionTests: XCTestCase {
    func testSharedFolderMapsSyntheticRootWithoutListingUnreadableAncestors() async throws {
        let (engine, directory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
        GWStub.on("GET /v1/filespaces/fs1/items/ino-shared", json: #"{"id":"ino-shared","parent":"ino-hidden-parent","name":"Shared","isDir":true,"size":0,"contentVersion":"cv1","version":1}"#)
        GWStub.on("GET /v1/filespaces/fs1/items") { request in
            let parent = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == "parent" }?.value
            guard parent == "ino-shared" else { return (403, #"{"error":"forbidden"}"#) }
            return (200, #"{"items":[{"id":"ino-child","parent":"ino-shared","name":"clip.mov","isDir":false,"size":10,"contentVersion":"cv1","version":1}],"cursor":null}"#)
        }
        GWStub.on("GET /v1/filespaces/fs1/items/ino-sibling", status: 403, json: #"{"error":"forbidden"}"#)
        let base = await engine.dataPath(for: "fs1")
        let projection = RootedDataPath(base: base, roots: [FilespaceMountRoot(id: "ino-shared", name: "Shared", mountAsRoot: true)], directRoot: InodeID("ino-shared"))
        let root = try await projection.lookup(.root)
        XCTAssertEqual(root.id, .root); XCTAssertNil(root.parent)
        let listing = try await projection.enumerate(container: .root, page: nil)
        XCTAssertEqual(listing.items.map(\.id), [InodeID("ino-child")])
        XCTAssertEqual(listing.items.first?.parent, .root)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs1/items/root"), 0)
        do { _ = try await projection.lookup(InodeID("ino-sibling")); XCTFail("server must still deny siblings") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        do { try await projection.delete(.root, baseVersion: "1", recursive: true); XCTFail("mounted root is protected") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
    }

    func testMultipleSharedRootsRemainVisibleAndDuplicateNamesAreReachable() async throws {
        let (engine, directory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
        var roots: [FilespaceMountRoot] = []
        for id in ["ino-a", "ino-b"] {
            roots.append(FilespaceMountRoot(id: id, name: "Media", mountAsRoot: false))
            GWStub.on("GET /v1/filespaces/fs1/items/\(id)", json: "{\"id\":\"\(id)\",\"parent\":\"hidden\",\"name\":\"Media\",\"isDir\":true,\"size\":0,\"contentVersion\":\"cv1\",\"version\":1}")
        }
        let projection = RootedDataPath(base: await engine.dataPath(for: "fs1"), roots: roots, directRoot: nil)
        let listing = try await projection.enumerate(container: .root, page: nil)
        XCTAssertEqual(Set(listing.items.map(\.id)), Set([InodeID("ino-a"), InodeID("ino-b")]))
        XCTAssertEqual(Set(listing.items.map(\.name)).count, 2)
        XCTAssertTrue(listing.items.allSatisfy { $0.parent == .root })
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs1/items/root"), 0)
        let root = try await projection.lookup(.root)
        XCTAssertTrue(root.isDir)
    }

    func testRevokedSharedRootDoesNotHideOtherRootsAndNetworkErrorsStillSurface() async throws {
        let (engine, directory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
        let roots = ["ino-revoked", "ino-live"].map { FilespaceMountRoot(id: $0, name: $0, mountAsRoot: false) }
        GWStub.on("GET /v1/filespaces/fs1/items/ino-revoked", status: 404, json: #"{"error":"not found"}"#)
        GWStub.on("GET /v1/filespaces/fs1/items/ino-live", json: #"{"id":"ino-live","parent":"hidden","name":"Media","isDir":true,"size":0,"contentVersion":"cv1","version":1}"#)
        let projection = RootedDataPath(base: await engine.dataPath(for: "fs1"), roots: roots, directRoot: nil)
        let listing = try await projection.enumerate(container: .root, page: nil)
        XCTAssertEqual(listing.items.map(\.id), [InodeID("ino-live")])
        let newItem = ItemMetadata(id: "new", parent: .root, name: "new", isDir: false, size: 0, contentVersion: "", metadataVersion: "1")
        do { _ = try await projection.write(id: nil, fields: newItem, contents: nil, baseVersion: nil); XCTFail("virtual root is not writable") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        do { _ = try await projection.writeRange(.root, offset: 0, data: Data([1]), baseVersion: nil); XCTFail("virtual root is not writable") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        do { _ = try await projection.rename("ino-live", newParent: nil, newName: "renamed"); XCTFail("shared root protected") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        GWStub.on("GET /v1/filespaces/fs1/items/ino-revoked", status: 503, json: #"{"error":"unavailable"}"#)
        do { _ = try await projection.enumerate(container: .root, page: nil); XCTFail("network failure must not silently hide a root") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .gatewayError) }
    }

    func testReadOnlyWriteAndTruncateFailBeforeStagingAndFreshOpenRechecksGrant() async throws {
        let (engine, directory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
        _ = try await engine.transfersPause(FilespaceOnlyParams(filespace: "fs1"))
        let access = "GET /v1/filespaces/fs1/items/ino-readonly/access"
        GWStub.on(access, json: #"{"read":true,"write":false}"#)
        let adapter = await engine.dataPath(for: "fs1")
        do { _ = try await adapter.writeRange("ino-readonly", offset: 0, data: Data("unsyncable".utf8), baseVersion: "1"); XCTFail("read-only write must not ACK") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        do { try await adapter.truncate("ino-readonly", newSize: 0, baseVersion: "1"); XCTFail("read-only truncate must not ACK") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        let (_, transfer, _) = try await engine.sessionFor("fs1")
        let staged = await transfer.stagedState(filespace: "fs1", itemID: "ino-readonly")
        XCTAssertNil(staged)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs1/blocks/ino-readonly"), 0)
        GWStub.on(access, json: #"{"read":true,"write":true}"#)
        try await adapter.authorizeWrite("ino-readonly", refresh: true)
        try await adapter.authorizeWrite("ino-readonly", refresh: false)
        XCTAssertEqual(GWStub.count(access), 3, "hot writes use the bounded positive cache")
        GWStub.on(access, json: #"{"read":true,"write":false}"#)
        do { try await adapter.authorizeWrite("ino-readonly", refresh: true); XCTFail("a new OPEN must check permission again") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        do { try await adapter.authorizeWrite("ino-readonly", refresh: false); XCTFail("failed fresh check must clear earlier grant") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
    }

    func testMountDiscoveryParsesOpaqueRootsAndDeniesAnEmptyGrantSet() async throws {
        let (engine, directory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        GWStub.on("GET /v1/filespaces/fs1/mount-roots", json: #"{"roots":[{"id":"ino-uuid","name":"Shared","mountAsRoot":true}]}"#)
        let roots = try await engine.sessionGateway().mountRoots(filespace: "fs1")
        XCTAssertEqual(roots, [FilespaceMountRoot(id: "ino-uuid", name: "Shared", mountAsRoot: true)])
        GWStub.on("GET /v1/filespaces/fs1/mount-roots", json: #"{"roots":[]}"#)
        do { _ = try await engine.mount(MountParams(filespace: "fs1")); XCTFail("empty access set must not mount the whole filespace") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
    }

    func testPathBarrierCannotReportOpaqueDirtyInodeAsSynced() async throws {
        let (engine, directory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs1"))
        _ = try await engine.transfersPause(FilespaceOnlyParams(filespace: "fs1"))
        GWStub.on("GET /v1/filespaces/fs1/blocks/ino-7c170e1e", status: 404, json: #"{"error":"not_found"}"#)
        let (_, transfer, _) = try await engine.sessionFor("fs1")
        try await transfer.stageWrite(filespace: "fs1", itemID: "ino-7c170e1e", offset: 0, data: Data("not yet synced".utf8))
        let state = try await engine.syncState(SyncStateParams(filespace: "fs1", path: "/Shots/clip.mov"))
        XCTAssertFalse(state.inSync)
        XCTAssertEqual(state.path, "/Shots/clip.mov")
        do {
            _ = try await engine.flush(FlushParams(filespace: "fs1", path: "/Shots", wait: true, timeoutMs: 1))
            XCTFail("opaque inode must remain included in the durability barrier")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .syncTimeout) }
    }
}
