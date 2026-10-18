// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import CloudFSTransfer

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - Stubbed presigned-URL byte plane (no live R2)
//
// The engine fetches/uploads block ciphertext over a plain URLSession against a
// gateway-minted presigned URL. This URLProtocol answers those byte transfers
// from an in-memory map keyed by the URL the mock gateway minted, and can be told
// to fail the first N attempts on a given URL to exercise retry/backoff.

final class BlobURLProtocol: URLProtocol, @unchecked Sendable {
    struct Body { var data: Data; var status: Int }
    nonisolated(unsafe) private static var getMap: [String: Data] = [:]
    nonisolated(unsafe) private static var putUrls: Set<String> = []
    nonisolated(unsafe) private static var puts: [String: Data] = [:]
    nonisolated(unsafe) private static var failFirst: [String: Int] = [:]   // url → remaining forced failures
    nonisolated(unsafe) private static var getCount: [String: Int] = [:]
    // PUT gate (supersession tests): while armed, every PUT blocks on this
    // semaphore until the test releases it, and each entry signals `putEntered`
    // so the test can deterministically wait until a PUT is in-flight before
    // superseding the upload that owns it.
    nonisolated(unsafe) private static var putGate: DispatchSemaphore?
    private static let putEntered = DispatchSemaphore(value: 0)
    private static let lock = NSLock()

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        getMap = [:]; putUrls = []; puts = [:]; failFirst = [:]; getCount = [:]
        putGate = nil
        // Drain any stale entered-signals from a prior test.
        while putEntered.wait(timeout: .now()) == .success {}
    }

    /// Arm the PUT gate: subsequent PUTs block until `releasePUTs()` is called.
    static func armPUTGate() {
        lock.lock(); defer { lock.unlock() }
        putGate = DispatchSemaphore(value: 0)
    }
    /// Release all gated PUTs (and disarm the gate so later PUTs pass through).
    static func releasePUTs(_ count: Int = 64) {
        lock.lock(); let g = putGate; putGate = nil; lock.unlock()
        if let g { for _ in 0..<count { g.signal() } }
    }
    /// Block until a gated PUT has entered (in-flight), or time out.
    static func waitForPUTInFlight(timeout: DispatchTimeInterval = .seconds(5)) -> Bool {
        putEntered.wait(timeout: .now() + timeout) == .success
    }
    static func serveGET(_ url: String, _ data: Data) {
        lock.lock(); defer { lock.unlock() }; getMap[url] = data
    }
    static func failFirst(_ n: Int, on url: String) {
        lock.lock(); defer { lock.unlock() }; failFirst[url] = n
    }
    static func putBody(_ url: String) -> Data? {
        lock.lock(); defer { lock.unlock() }; return puts[url]
    }
    static func getCount(_ url: String) -> Int {
        lock.lock(); defer { lock.unlock() }; return getCount[url] ?? 0
    }

    override class func canInit(with request: URLRequest) -> Bool {
        // Only intercept the blob host; gateway calls are mocked separately.
        request.url?.host == "blob.test"
    }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        let url = request.url!.absoluteString
        let method = request.httpMethod ?? "GET"
        Self.lock.lock()
        // Count EVERY GET attempt (including the forced-503 retries) so retry tests
        // can assert the full attempt count.
        if method == "GET" { Self.getCount[url, default: 0] += 1 }
        // Forced-failure budget (transient 503) for retry tests.
        if let remaining = Self.failFirst[url], remaining > 0 {
            Self.failFirst[url] = remaining - 1
            Self.lock.unlock()
            respond(status: 503, body: Data("{\"error\":\"slow down\"}".utf8))
            return
        }
        if method == "PUT" {
            var body = Data()
            if let b = request.httpBody { body = b }
            else if let s = request.httpBodyStream { body = Self.drain(s) }
            Self.puts[url] = body
            let gate = Self.putGate
            Self.lock.unlock()
            // Supersession tests: hold the PUT in-flight until the test releases it.
            if let gate {
                Self.putEntered.signal()     // tell the test a PUT is in-flight
                gate.wait()                  // block until releasePUTs()
            }
            respond(status: 200, body: Data())
            return
        }
        let data = Self.getMap[url]
        Self.lock.unlock()
        if let data { respond(status: 200, body: data) }
        else { respond(status: 404, body: Data("{\"error\":\"no block\"}".utf8)) }
    }

    private static func drain(_ stream: InputStream) -> Data {
        stream.open(); defer { stream.close() }
        var data = Data(); let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
        defer { buf.deallocate() }
        while stream.hasBytesAvailable {
            let n = stream.read(buf, maxLength: 4096); if n <= 0 { break }
            data.append(buf, count: n)
        }
        return data
    }

    private func respond(status: Int, body: Data) {
        let resp = HTTPURLResponse(url: request.url!, statusCode: status,
                                   httpVersion: "HTTP/1.1", headerFields: [:])!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: body)
        client?.urlProtocolDidFinishLoading(self)
    }
}

// MARK: - Mock GatewayClient
//
// Implements the GatewayClient seam in-memory: serves a fixed manifest per item,
// mints a deterministic blob.test presigned URL per (block-hash, method), and
// records every putBlockManifest so the upload path can be asserted.

final class MockGateway: GatewayClient, @unchecked Sendable {
    private let lock = NSLock()
    var manifests: [InodeID: BlockManifest] = [:]
    /// Optional GATEWAY-AUTHORITATIVE object keys per block hash. When set for a
    /// hash, `getResolvedBlockManifest` surfaces THIS key (e.g. the real
    /// `blocks/<org>::<fs>/…` scheme) instead of the content-address `hash.objectKey`,
    /// proving the engine presigns the gateway's key, not a client-built one.
    var gatewayObjectKeys: [BlockHash: String] = [:]
    private(set) var presignCalls: [(key: String, method: PresignMethod)] = []
    private(set) var presignBatches: [[String]] = []
    private(set) var putManifests: [BlockManifest] = []
    /// Records every CAS commit's (expectedVersion, fence) so the daemon-side B4/B5
    /// threading can be asserted, and lets a test inject a 409 by version mismatch.
    private(set) var putExpectedVersions: [Int?] = []
    private(set) var putFences: [Int?] = []
    /// Server-side version per item (incremented on each successful commit). When a
    /// commit presents an expectedVersion != the stored version, the mock throws a
    /// 409-equivalent `.conflict`, mirroring the real gateway's optimistic concurrency.
    var versions: [InodeID: Int] = [:]
    var enforceExpectedVersion = false
    /// Items created via createItem (audit B1), so the daemon create-through-mount
    /// path can be asserted against the gateway namespace.
    private(set) var createdItems: [ItemMetadata] = []
    private(set) var deletedItems: [(id: InodeID, recursive: Bool)] = []
    var failManifestForMissing = true
    var rateLimitFirstPresigns = 0
    /// Opt-in simulated control-plane latency (ms) for write presign batches and
    /// receipt verification. Zero keeps the protocol defaults (`unimplemented`).
    var simulatedWriteAuthLatencyMs = 0
    var simulatedVerifyLatencyMs = 0
    private(set) var writeAuthBatchSizes: [Int] = []
    private(set) var verifyBatchSizes: [Int] = []

    func presignWriteBatch(filespace: FilespaceID, keys: [(key: String, itemID: InodeID)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        let delay = simulatedWriteAuthLatencyMs
        guard delay > 0 else { throw EngineError(.unimplemented, "Write batch presigning is unavailable") }
        lock.withLock { writeAuthBatchSizes.append(keys.count) }
        try await Task.sleep(for: .milliseconds(delay))
        return keys.map { key in
            let enc = key.key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key.key
            return PresignBatchResult(key: key.key, url: "https://blob.test/PUT?key=\(enc)", error: nil)
        }
    }
    func verifyUploadedBlocks(filespace: FilespaceID, itemID: InodeID, blocks: [UploadedBlockVerification]) async throws {
        let delay = simulatedVerifyLatencyMs
        guard delay > 0 else { throw EngineError(.unimplemented, "Background object verification is unavailable") }
        lock.withLock { verifyBatchSizes.append(blocks.count) }
        try await Task.sleep(for: .milliseconds(delay))
    }

    func presignBatch(filespace: FilespaceID, keys: [(key: String, method: PresignMethod)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        lock.withLock { presignBatches.append(keys.map(\.key)) }
        var results: [PresignBatchResult] = []
        for key in keys {
            do {
                let signed = try await presign(filespace: filespace, key: key.key, method: key.method, expiresIn: expiresIn)
                results.append(PresignBatchResult(key: key.key, url: signed.url, error: nil))
            } catch { results.append(PresignBatchResult(key: key.key, url: nil, error: String(describing: error))) }
        }
        return results
    }

    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL {
        try lock.withLock {
            presignCalls.append((key, method))
            if rateLimitFirstPresigns > 0 {
                rateLimitFirstPresigns -= 1
                throw EngineError(.gatewayError, "rate_limited", data: ["retryAfter": .string("0.01")])
            }
        }
        // The key is `chunks/<shard>/<hash>`; encode it + method into a stable URL.
        let enc = key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key
        return PresignedURL(url: "https://blob.test/\(method.rawValue)?key=\(enc)", expiresIn: 300)
    }
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest {
        let m = lock.withLock { manifests[itemID] }
        guard let m else {
            if failManifestForMissing { throw EngineError(.notFound, "no manifest for \(itemID.rawValue)") }
            return BlockManifest(itemID: itemID, blocks: [], contentVersion: "")
        }
        return m
    }
    func getResolvedBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> ResolvedBlockManifest {
        let m = try await getBlockManifest(filespace: filespace, itemID: itemID)
        // Surface the gateway's object key for each block (overriding the content
        // address when one is configured) — the key the engine MUST presign.
        let overrides = lock.withLock { gatewayObjectKeys }
        var keys: [BlockHash: String] = [:]
        for b in m.blocks { keys[b.hash] = overrides[b.hash] ?? b.hash.objectKey }
        return ResolvedBlockManifest(manifest: m, objectKeys: keys)
    }
    func uploadObjectKey(filespace: FilespaceID, blockHash: BlockHash) async -> String {
        // Mirror the content-address scheme the existing write assertions expect.
        blockHash.objectKey
    }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata {
        return try await putBlockManifest(manifest, filespace: filespace, expectedVersion: nil, fence: nil)
    }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata {
        try lock.withLock {
            putExpectedVersions.append(expectedVersion)
            putFences.append(fence)
            let stored = versions[manifest.itemID] ?? 1
            if enforceExpectedVersion, let ev = expectedVersion, ev != stored {
                throw EngineError(.conflict, "version conflict", data: ["expected": .int(ev), "actual": .int(stored)])
            }
            let next = stored + 1
            versions[manifest.itemID] = next
            putManifests.append(manifest); manifests[manifest.itemID] = manifest
            return ItemMetadata(id: manifest.itemID, parent: .root, name: manifest.itemID.rawValue,
                                isDir: false, size: manifest.size, contentVersion: "cv-\(manifest.size)",
                                metadataVersion: "\(next)")
        }
    }
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata {
        // Mirror the backend's path-derived id scheme so the daemon adopts a "root/…"
        // id (the crypto + commit then bind to the SAME id every other client uses).
        let id = InodeID("\(parent.rawValue)/\(name)")
        let item = ItemMetadata(id: id, parent: parent, name: name, isDir: isDir, size: size,
                                contentVersion: "cv-0", metadataVersion: "1")
        lock.withLock { createdItems.append(item); versions[id] = 1 }
        return item
    }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws {
        lock.withLock { deletedItems.append((id, recursive)); manifests[id] = nil }
    }
    // Explicit (toolchain existential-dispatch safety, like the other ops).
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata {
        ItemMetadata(id: id, parent: newParent ?? .root, name: newName, isDir: false, size: 0, contentVersion: "cv", metadataVersion: "2")
    }
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { ([], nil) }
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata {
        ItemMetadata(id: id, parent: .root, name: id.rawValue, isDir: false, size: 0, contentVersion: "", metadataVersion: "")
    }
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { (0, [], nil) }
}

// MARK: - Fail-fast deadline guard
//
// Race every async test body against a hard deadline so a regression that
// deadlocks FAILS (with a clear message) instead of hanging the whole suite and
// wedging the shared SwiftPM `.build` lock. Body wins → returns normally; timer
// wins → XCTFail + throw so the run always terminates.

private struct TestTimeout: Error {}

/// One-shot result relay (first `resume` wins) so the guard can return on
/// whichever of body/timer fires first WITHOUT awaiting the loser — a TaskGroup
/// always drains its children, and `await`ing a non-cancellable hung body would
/// re-hang the very guard meant to catch it.
private final class TestOneShot: @unchecked Sendable {
    private let lock = NSLock()
    private var result: Result<Void, Error>?
    private var waiter: CheckedContinuation<Void, Error>?
    func resume(_ r: Result<Void, Error>) {
        lock.lock()
        if result != nil { lock.unlock(); return }
        result = r
        let w = waiter; waiter = nil
        lock.unlock()
        w?.resume(with: r)
    }
    var value: Void {
        get async throws {
            try await withCheckedThrowingContinuation { cont in
                lock.lock()
                if let r = result { lock.unlock(); cont.resume(with: r); return }
                waiter = cont
                lock.unlock()
            }
        }
    }
}

private func withTestTimeout(_ seconds: Double = 20,
                             file: StaticString = #filePath, line: UInt = #line,
                             _ body: @escaping @Sendable () async throws -> Void) async throws {
    let box = TestOneShot()
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

// MARK: - Test fixtures

final class CloudFSTransferTests: XCTestCase {

    // 32-byte test master key.
    private static let keyBytes = Data((0..<32).map { UInt8($0) })

    private static func makeCrypto() throws -> AESGCMBlockCrypto {
        try AESGCMBlockCrypto(masterKeyBytes: Self.keyBytes)
    }

    private static func makeCache() throws -> DiskBlockCache {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("cfs-xfer-\(UUID().uuidString)")
        return try DiskBlockCache(filespace: "fs", directory: dir, maxBytes: 64 << 20)
    }

    private static func blobSession() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [BlobURLProtocol.self]
        return URLSession(configuration: cfg)
    }

    /// Fast retry policy: no real wall-clock sleeps.
    private static func fastPolicy(maxAttempts: Int = 4) -> RetryPolicy {
        RetryPolicy(maxAttempts: maxAttempts, baseDelayMs: 1, maxDelayMs: 1) { _ in }
    }

    private static func makeEngine(cache: BlockCache, crypto: BlockCrypto, gateway: GatewayClient,
                                   maxAttempts: Int = 4, concurrency: Int = 4) -> RealTransferEngine {
        let blob = BlobTransport(session: blobSession(), policy: fastPolicy(maxAttempts: maxAttempts))
        return RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                                  blob: blob, prefetchConcurrency: concurrency)
    }

    /// Encrypt `plaintext` into `count`-byte blocks, register each block's
    /// ciphertext with the blob stub (so a GET serves it) and build the manifest.
    /// Returns (manifest, plaintext-blocks).
    @discardableResult
    private static func seedItem(_ itemID: InodeID, plaintext: Data, blockSize: Int,
                                 crypto: AESGCMBlockCrypto, gateway: MockGateway) async throws -> BlockManifest {
        var refs: [BlockRef] = []
        var offset = 0, idx = 0
        while offset < plaintext.count {
            let end = min(offset + blockSize, plaintext.count)
            let chunk = plaintext.subdata(in: offset..<end)
            let (ct, hash) = try await crypto.encryptBlock(chunk, itemID: itemID, blockIndex: idx)
            let url = "https://blob.test/GET?key=" +
                (hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? hash.objectKey)
            BlobURLProtocol.serveGET(url, ct)
            refs.append(BlockRef(hash: hash, offset: offset, length: chunk.count))
            offset = end; idx += 1
        }
        let m = BlockManifest(itemID: itemID, blocks: refs, contentVersion: "cv")
        gateway.manifests[itemID] = m
        return m
    }

    /// The engine caches the CIPHERTEXT of each block (content-addressed by
    /// `SHA256(ciphertext) == ref.hash`), decrypting only on the way out to the
    /// VFS. Helper to (re)compute a block's ciphertext for cache-pre-warm /
    /// readBlock assertions.
    private static func ciphertext(of plaintextChunk: Data, itemID: InodeID,
                                   blockIndex: Int, crypto: AESGCMBlockCrypto) async throws -> Data {
        try await crypto.encryptBlock(plaintextChunk, itemID: itemID, blockIndex: blockIndex).ciphertext
    }

    override func setUp() { super.setUp(); BlobURLProtocol.reset() }

    // MARK: 0. Stub still throws (foundation contract preserved)

    func testStubStillThrowsAndStreamEmpty() async throws {
        try await withTestTimeout {
            let t = StubTransferEngine()
            do { _ = try await t.prefetch(filespace: "fs", path: "/a", itemID: InodeID("/a")); XCTFail("expected throw") }
            catch let e as EngineError { XCTAssertEqual(e.kind, .unimplemented) }
            catch { XCTFail("wrong error: \(error)") }
            var n = 0
            for await _ in t.progressEvents(filespace: "fs") { n += 1 }
            XCTAssertEqual(n, 0)
        }
    }

    // MARK: 1. Cache HIT serves without any presign / GET

    func testCacheHitServesWithoutFetch() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 64
            let plaintext = Data((0..<128).map { UInt8($0 & 0xff) })
            let manifest = try await Self.seedItem("clip", plaintext: plaintext, blockSize: bs, crypto: crypto, gateway: gateway)
            // Pre-warm the cache with both blocks. The engine caches CIPHERTEXT
            // keyed by `ref.hash == SHA256(ciphertext)`, so warm it the same way.
            for i in manifest.blocks.indices {
                let r = manifest.blocks[i]
                let chunk = plaintext.subdata(in: r.offset..<(r.offset + r.length))
                let ct = try await Self.ciphertext(of: chunk, itemID: "clip", blockIndex: i, crypto: crypto)
                try await cache.putBlock(r.hash, plaintext: ct)
            }
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway)

            try await engine.ensureRange(filespace: "fs", itemID: "clip", offset: 0, length: plaintext.count)

            // No presign was minted (everything served from cache).
            XCTAssertTrue(gateway.presignCalls.isEmpty, "cache hit must not presign")
            // And no block GET hit the blob plane.
            let url0 = "https://blob.test/GET?key=" +
                (manifest.blocks[0].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
            XCTAssertEqual(BlobURLProtocol.getCount(url0), 0)
        }
    }

    // MARK: 2. Cache MISS → presign → GET → decrypt → cache → serve

    func testCacheMissFetchesDecryptsAndCaches() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 64
            let plaintext = Data((0..<200).map { UInt8(($0 * 7) & 0xff) })
            let manifest = try await Self.seedItem("v.mov", plaintext: plaintext, blockSize: bs, crypto: crypto, gateway: gateway)
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway)

            // Cold: nothing resident.
            for r in manifest.blocks { let hit = await cache.contains(r.hash); XCTAssertFalse(hit) }

            try await engine.ensureRange(filespace: "fs", itemID: "v.mov", offset: 0, length: plaintext.count)

            // Each block was presigned for GET and is now resident (as ciphertext,
            // content-addressed by ref.hash) and decrypts back to the right bytes.
            XCTAssertEqual(gateway.presignCalls.count, manifest.blocks.count)
            XCTAssertTrue(gateway.presignCalls.allSatisfy { $0.method == .GET })
            for (i, r) in manifest.blocks.enumerated() {
                let storedCT = try await cache.readBlock(r.hash)
                let ct = try XCTUnwrap(storedCT)
                let decoded = try await crypto.decryptBlock(ct, itemID: "v.mov", blockIndex: i)
                XCTAssertEqual(decoded, plaintext.subdata(in: r.offset..<(r.offset + r.length)))
            }
            // A second ensureRange is a pure cache hit → no new presigns.
            let before = gateway.presignCalls.count
            try await engine.ensureRange(filespace: "fs", itemID: "v.mov", offset: 0, length: plaintext.count)
            XCTAssertEqual(gateway.presignCalls.count, before)
        }
    }

    // MARK: 2a. The engine presigns the GATEWAY's objectKey, not a client-built one
    //
    // Regression for the engine↔gateway object-key mismatch: the gateway/store owns
    // the block object key (`blocks/<org>::<fs>/…`); the engine must presign THAT key,
    // not reconstruct `chunks/<shard>/<hash>` from the block hash (which is the on-disk
    // cache key only). We seed the manifest with a DISTINCT gateway key per block and
    // assert every presign used the gateway key — and never the content-address form.
    func testEngineUsesGatewayObjectKeyNotClientConstructed() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 64
            let plaintext = Data((0..<200).map { UInt8(($0 * 5) & 0xff) })   // 4 blocks
            // Build the manifest + ciphertext, but serve each block's blob at the
            // GATEWAY key URL (not the content-address URL) and register the override.
            var refs: [BlockRef] = []
            var gatewayKeys: [BlockHash: String] = [:]
            var offset = 0, idx = 0
            while offset < plaintext.count {
                let end = min(offset + bs, plaintext.count)
                let chunk = plaintext.subdata(in: offset..<end)
                let (ct, hash) = try await crypto.encryptBlock(chunk, itemID: "gk.mov", blockIndex: idx)
                // The gateway's authoritative key — deliberately UNLIKE `hash.objectKey`.
                let gwKey = "blocks/acme::fs1/\(hash.hex)"
                gatewayKeys[hash] = gwKey
                let url = "https://blob.test/GET?key=" +
                    (gwKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? gwKey)
                BlobURLProtocol.serveGET(url, ct)
                refs.append(BlockRef(hash: hash, offset: offset, length: chunk.count))
                offset = end; idx += 1
            }
            gateway.manifests["gk.mov"] = BlockManifest(itemID: "gk.mov", blocks: refs, contentVersion: "cv")
            gateway.gatewayObjectKeys = gatewayKeys
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway)

            try await engine.ensureRange(filespace: "fs", itemID: "gk.mov", offset: 0, length: plaintext.count)

            // Every block fetched, decrypting correctly — proves the GET hit the
            // gateway-keyed blob URL (the only one served).
            for (i, r) in refs.enumerated() {
                let stored = try await cache.readBlock(r.hash)
                let ct = try XCTUnwrap(stored)
                let decoded = try await crypto.decryptBlock(ct, itemID: "gk.mov", blockIndex: i)
                XCTAssertEqual(decoded, plaintext.subdata(in: r.offset..<(r.offset + r.length)))
            }
            // The presign keys are EXACTLY the gateway keys — never a `chunks/…` key.
            let presignedKeys = Set(gateway.presignCalls.map(\.key))
            XCTAssertEqual(presignedKeys, Set(gatewayKeys.values),
                           "engine must presign the gateway's objectKey")
            XCTAssertFalse(gateway.presignCalls.contains { $0.key.hasPrefix("chunks/") },
                           "engine must NOT presign a client-reconstructed chunks/ key")
        }
    }

    // MARK: 2b. Range read only fetches the touched blocks

    func testRangeReadFetchesOnlyTouchedBlocks() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 100
            let plaintext = Data((0..<500).map { UInt8($0 & 0xff) })   // 5 blocks of 100
            let manifest = try await Self.seedItem("big", plaintext: plaintext, blockSize: bs, crypto: crypto, gateway: gateway)
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway)

            // Read [250,350): touches blocks 2 and 3 only.
            try await engine.ensureRange(filespace: "fs", itemID: "big", offset: 250, length: 100)
            XCTAssertEqual(gateway.presignCalls.count, 2)
            let resident0 = await cache.contains(manifest.blocks[0].hash)
            let resident2 = await cache.contains(manifest.blocks[2].hash)
            let resident3 = await cache.contains(manifest.blocks[3].hash)
            let resident4 = await cache.contains(manifest.blocks[4].hash)
            XCTAssertFalse(resident0); XCTAssertTrue(resident2)
            XCTAssertTrue(resident3); XCTAssertFalse(resident4)
        }
    }

    // MARK: 3. Concurrent prefetch warms every block

    func testPrefetchWarmsAllBlocksConcurrently() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 32
            let plaintext = Data((0..<32 * 10).map { UInt8($0 & 0xff) })   // 10 blocks
            let manifest = try await Self.seedItem("seq.bin", plaintext: plaintext, blockSize: bs, crypto: crypto, gateway: gateway)
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway, concurrency: 4)

            let ack = try await engine.prefetch(filespace: "fs", path: "seq.bin", itemID: InodeID("seq.bin"))
            XCTAssertEqual(ack.queuedBlocks, manifest.blocks.count)
            XCTAssertEqual(ack.path, "seq.bin")
            for r in manifest.blocks {
                let hit = await cache.contains(r.hash)
                XCTAssertTrue(hit, "block \(r.hash) should be warm after prefetch")
            }
            // Already-warm prefetch queues nothing.
            let again = try await engine.prefetch(filespace: "fs", path: "seq.bin", itemID: InodeID("seq.bin"))
            XCTAssertEqual(again.queuedBlocks, 0)
        }
    }

    // MARK: 3a. P2 — concurrent fetches of the same block dedup in flight

    func testConcurrentEnsureRangeDedupsInFlightBlockFetch() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 64
            let plaintext = Data((0..<64).map { UInt8($0) })   // 1 block
            let manifest = try await Self.seedItem("dedup.bin", plaintext: plaintext, blockSize: bs,
                                                   crypto: crypto, gateway: gateway)
            let url = "https://blob.test/GET?key=" +
                (manifest.blocks[0].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway)
            // 8 concurrent reads of the same cold block → exactly ONE network GET.
            try await withThrowingTaskGroup(of: Void.self) { group in
                for _ in 0..<8 {
                    group.addTask {
                        try await engine.ensureRange(filespace: "fs", itemID: "dedup.bin",
                                                     offset: 0, length: plaintext.count)
                    }
                }
                try await group.waitForAll()
            }
            XCTAssertEqual(BlobURLProtocol.getCount(url), 1,
                           "concurrent fetches of one block must collapse to a single GET")
        }
    }

    // MARK: 4. Write → stage → encrypt → upload → flush{wait} → synced

    func testWriteStagesEncryptsUploadsAndFlushCommits() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                                            blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                                            blockSize: 100)
            let payload = Data((0..<250).map { UInt8(($0 * 3) & 0xff) })   // 3 blocks at bs=100

            try await engine.stageWrite(filespace: "fs", itemID: "out.mov", offset: 0, data: payload)

            // Before flush, syncState shows pending work (ack-local, not yet durable).
            // (Race-free: stageWrite returns immediately; the upload runs async.)
            let final = try await engine.flush(filespace: "fs", path: "out.mov", wait: true, timeoutMs: 5000)
            XCTAssertTrue(final.inSync)
            XCTAssertEqual(final.pendingUploads, 0)
            XCTAssertEqual(final.pendingBytes, 0)

            // The manifest was CAS'd with 3 blocks covering the whole payload.
            XCTAssertEqual(gateway.putManifests.count, 1)
            let committed = try XCTUnwrap(gateway.putManifests.first)
            XCTAssertEqual(committed.itemID, "out.mov")
            XCTAssertEqual(committed.blocks.count, 3)
            XCTAssertEqual(committed.size, payload.count)
            // Each block was presigned for PUT and the ciphertext landed in the blob store.
            XCTAssertTrue(gateway.presignCalls.allSatisfy { $0.method == .PUT })
            for r in committed.blocks {
                let url = "https://blob.test/PUT?key=" +
                    (r.hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
                XCTAssertNotNil(BlobURLProtocol.putBody(url), "block \(r.hash) must have been PUT")
            }

            // Round-trip: the uploaded blocks are decryptable back to the original bytes.
            var rebuilt = Data()
            for (i, r) in committed.blocks.enumerated() {
                let url = "https://blob.test/PUT?key=" +
                    (r.hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
                let ct = try XCTUnwrap(BlobURLProtocol.putBody(url))
                rebuilt.append(try await crypto.decryptBlock(ct, itemID: "out.mov", blockIndex: i))
            }
            XCTAssertEqual(rebuilt, payload)
        }
    }

    // MARK: 4c. A 2nd stageWrite over an in-flight upload commits the NEWEST bytes,
    // and publishes NO phantom `.error` event (Findings 1 + 3).
    //
    // Upload task A is held mid-PUT by the blob gate. A second stageWrite supersedes
    // A (cancels it) and installs task B with the new image. A's cancelled PUT
    // surfaces as URLError(.cancelled) — which the pre-fix BlobTransport swallowed as
    // a transient `.networkError`, retried to exhaustion, then (in the generic catch)
    // cleared B's `uploads[key]` handle, poisoned B's staging `lastError`, and
    // published a phantom `.error` for a write B is actually committing. With the
    // ownership token, the superseded A mutates/publishes NOTHING; B commits image #2.
    func testSecondWriteSupersedesInFlightUploadNewestBytesWinNoPhantomError() async throws {
        try await withTestTimeout(30) {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                                            blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                                            blockSize: 1 << 20)   // one block per image
            let itemID: InodeID = "race.mov"

            // Distinct images so their block hashes differ (no dedup collision) and
            // so we can tell which one was committed durably.
            let image1 = Data(repeating: 0x11, count: 4096)
            let image2 = Data(repeating: 0x22, count: 4096)

            // Subscribe BEFORE any work so no event can be missed.
            let stream = engine.progressEvents(filespace: "fs")
            let errorSeen = Task { () -> Bool in
                for await t in stream {
                    if t.direction == .upload && t.state == .error { return true }
                    if t.direction == .upload && t.state == .done { return false }
                }
                return false
            }

            // Gate every PUT so task A blocks mid-upload of image #1.
            BlobURLProtocol.armPUTGate()
            try await engine.stageWrite(filespace: "fs", itemID: itemID, offset: 0, data: image1)

            // Wait until A's PUT is actually in-flight (A is committed to uploading #1).
            let inFlight = await Task.detached { BlobURLProtocol.waitForPUTInFlight() }.value
            XCTAssertTrue(inFlight, "task A's PUT should be in-flight before we supersede it")

            // Supersede: a 2nd stageWrite cancels A and installs task B with image #2.
            try await engine.stageWrite(filespace: "fs", itemID: itemID, offset: 0, data: image2)

            // Release all gated PUTs so A's cancelled PUT unwinds and B can finish.
            BlobURLProtocol.releasePUTs()

            // Block until B is durably committed.
            let final = try await engine.flush(filespace: "fs", path: itemID.rawValue, wait: true, timeoutMs: 10_000)
            XCTAssertTrue(final.inSync, "flush must see image #2 durably committed")
            XCTAssertEqual(final.pendingUploads, 0)

            // The DURABLE image is #2 (newest), never the stale #1.
            let committed = try XCTUnwrap(gateway.putManifests.last)
            XCTAssertEqual(committed.size, image2.count)
            var rebuilt = Data()
            for (i, r) in committed.blocks.enumerated() {
                let url = "https://blob.test/PUT?key=" +
                    (r.hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
                let ct = try XCTUnwrap(BlobURLProtocol.putBody(url))
                rebuilt.append(try await crypto.decryptBlock(ct, itemID: itemID, blockIndex: i))
            }
            XCTAssertEqual(rebuilt, image2, "the committed/durable image must be the NEWEST bytes")

            // No phantom upload `.error` was published for the superseded task.
            let sawError = await errorSeen.value
            XCTAssertFalse(sawError, "a superseded upload must publish no phantom .error event")
        }
    }

    func testStaleSMBMetadataAfterOurCommitUsesLatestLocalVersionButStillRejectsRemoteChanges() async throws {
        for externalChange in [false, true] {
            BlobURLProtocol.reset()
            let gateway = MockGateway()
            gateway.enforceExpectedVersion = true
            gateway.versions["movie"] = 1
            let engine = Self.makeEngine(cache: try Self.makeCache(), crypto: try Self.makeCrypto(), gateway: gateway)
            try await engine.stageWrite(filespace: "fs", itemID: "movie", offset: 0, data: Data("first".utf8), baseVersion: "1", fence: nil)
            _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
            if externalChange { gateway.versions["movie"] = 3 }
            // SMB NodeTable can retain version 1 for its TTL even though OUR first
            // write committed version 2. Only a known local lineage can advance it.
            try await engine.stageReplace(filespace: "fs", itemID: "movie", data: Data("second".utf8), baseVersion: "1", fence: nil)
            if externalChange {
                do { _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000); XCTFail("remote edit must conflict") }
                catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
                XCTAssertEqual(gateway.putManifests.count, 1)
            } else {
                let state = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000)
                XCTAssertTrue(state.inSync)
                XCTAssertEqual(gateway.putManifests.count, 2)
            }
            XCTAssertEqual(gateway.putExpectedVersions, [1, 2])
        }
    }

    // MARK: 4b. syncState reflects pending staged bytes before flush

    func testSyncStatePendingThenClear() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            // A blob plane that fails forever so the upload stays pending until we look.
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(),
                                    policy: RetryPolicy(maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1) { _ in }),
                blockSize: 100)
            // Force every PUT to 503 so the (single-attempt) upload fails and stays staged.
            // We assert pending via a separate item that we never let drain.
            let payload = Data(repeating: 9, count: 150)
            // Hold pause so the upload parks before doing any network work.
            _ = try await engine.pause(filespace: "fs")
            try await engine.stageWrite(filespace: "fs", itemID: "p.dat", offset: 0, data: payload)
            // Give the parked uploader a tick to register the staged image.
            try await Task.sleep(nanoseconds: 30_000_000)
            let pending = try await engine.syncState(filespace: "fs", path: "p.dat")
            XCTAssertFalse(pending.inSync)
            XCTAssertEqual(pending.pendingUploads, 1)
            XCTAssertEqual(pending.pendingBytes, 150)
            _ = try await engine.resume(filespace: "fs")
        }
    }

    // MARK: 5. Transient error on GET → retried, then succeeds

    func testTransientErrorRetriedThenSucceeds() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 64
            let plaintext = Data((0..<64).map { UInt8($0) })   // 1 block
            let manifest = try await Self.seedItem("flaky", plaintext: plaintext, blockSize: bs, crypto: crypto, gateway: gateway)
            let url = "https://blob.test/GET?key=" +
                (manifest.blocks[0].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
            BlobURLProtocol.failFirst(2, on: url)   // first 2 GETs → 503, 3rd succeeds
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway, maxAttempts: 4)

            try await engine.ensureRange(filespace: "fs", itemID: "flaky", offset: 0, length: bs)

            XCTAssertEqual(BlobURLProtocol.getCount(url), 3)   // 2 fails + 1 success
            let resident = await cache.contains(manifest.blocks[0].hash)
            XCTAssertTrue(resident)
        }
    }

    // MARK: 5b. Transient error beyond budget → surfaces an error

    func testTransientErrorExceedingBudgetThrows() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 64
            let plaintext = Data((0..<64).map { UInt8($0) })
            let manifest = try await Self.seedItem("dead", plaintext: plaintext, blockSize: bs, crypto: crypto, gateway: gateway)
            let url = "https://blob.test/GET?key=" +
                (manifest.blocks[0].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
            BlobURLProtocol.failFirst(10, on: url)   // always fails
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway, maxAttempts: 3)
            do {
                try await engine.ensureRange(filespace: "fs", itemID: "dead", offset: 0, length: bs)
                XCTFail("expected throw after exhausting retries")
            } catch let e as EngineError {
                XCTAssertEqual(e.kind, .gatewayError)
            }
        }
    }

    // MARK: 6. Progress events are emitted for downloads

    func testProgressEventsEmittedForDownload() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 50
            let plaintext = Data((0..<200).map { UInt8($0 & 0xff) })   // 4 blocks
            _ = try await Self.seedItem("prog.bin", plaintext: plaintext, blockSize: bs, crypto: crypto, gateway: gateway)
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway, concurrency: 2)

            // Subscribe BEFORE the work starts. `progressEvents` registers the
            // subscriber synchronously, so the stream below is attached the moment
            // we obtain it — no terminal `.done` can be published and missed.
            let stream = engine.progressEvents(filespace: "fs")
            let collector = Task { () -> [Transfer] in
                var seen: [Transfer] = []
                for await t in stream {
                    seen.append(t)
                    if t.direction == .download && t.state == .done { break }
                }
                return seen
            }
            try await engine.ensureRange(filespace: "fs", itemID: "prog.bin", offset: 0, length: plaintext.count)

            let events = await collector.value
            XCTAssertFalse(events.isEmpty)
            XCTAssertTrue(events.contains { $0.state == .active }, "expected an active progress event")
            let done = try XCTUnwrap(events.last { $0.state == .done })
            XCTAssertEqual(done.direction, .download)
            XCTAssertEqual(done.bytesDone, plaintext.count)
            XCTAssertEqual(done.bytesTotal, plaintext.count)
        }
    }

    // MARK: 7. pause / resume gate the pool flag

    func testPauseResume() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway)
            let p = try await engine.pause(filespace: "fs")
            XCTAssertTrue(p.paused)
            let r = try await engine.resume(filespace: "fs")
            XCTAssertFalse(r.paused)
        }
    }

    // MARK: 8. flush{wait} with a too-short deadline → sync_timeout

    func testFlushWaitTimesOut() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            // Slow blob plane: real sleeps so the upload cannot finish within the deadline.
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(),
                                    policy: RetryPolicy(maxAttempts: 6, baseDelayMs: 200, maxDelayMs: 400)),
                blockSize: 100)
            // Pause so the uploader parks indefinitely, then flush with a tiny timeout.
            _ = try await engine.pause(filespace: "fs")
            try await engine.stageWrite(filespace: "fs", itemID: "slow.mov", offset: 0, data: Data(repeating: 1, count: 150))
            do {
                _ = try await engine.flush(filespace: "fs", path: "slow.mov", wait: true, timeoutMs: 50)
                XCTFail("expected sync_timeout")
            } catch let e as EngineError {
                XCTAssertEqual(e.kind, .syncTimeout)
                XCTAssertEqual(e.data?["pendingUploads"], .int(1))
            }
            _ = try await engine.resume(filespace: "fs")
        }
    }

    // MARK: 9. flush wait:false returns immediately with current state

    func testFlushNoWaitReturnsCurrentState() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let engine = Self.makeEngine(cache: cache, crypto: crypto, gateway: gateway)
            // No staged writes for this item → in sync.
            let state = try await engine.flush(filespace: "fs", path: "nothing", wait: false, timeoutMs: nil)
            XCTAssertTrue(state.inSync)
            XCTAssertEqual(state.pendingUploads, 0)
        }
    }

    // MARK: - Audit B2: durable write-back journal (no data loss on crash)

    private static func makeJournalDir() -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("cfs-journal-\(UUID().uuidString)")
        return dir.path
    }

    /// A staged write is persisted to the journal + fsync'd BEFORE stageWrite returns,
    /// so a crash (a fresh engine with the SAME journal) replays it and drives it to
    /// the bucket — the bytes are not lost with daemon RAM. This is the core of B2.
    func testStagedWriteSurvivesCrashAndReplays() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let journalDir = Self.makeJournalDir()
            // "Crashed" engine: it stages (durably) but NEVER commits (we never flush
            // and let the engine fall out of scope without the upload landing — we
            // gate the blob so the PUT can't complete).
            let crashed = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: 100, journal: WriteBackJournal(cacheDir: journalDir))
            _ = try await crashed.pause(filespace: "fs")
            let payload = Data((0..<150).map { UInt8(($0 * 9) & 0xff) })
            try await crashed.stageWrite(filespace: "fs", itemID: "saved.mov", offset: 0,
                                         data: payload, baseVersion: nil, fence: nil)
            // The journal file exists on disk the instant stageWrite returned.
            XCTAssertTrue(FileManager.default.fileExists(atPath: journalDir + "/staging"),
                          "stageWrite must persist to the journal before acking")
            // Simulate the crash: drop the gated upload and stand up a NEW engine on
            // the SAME journal + cache + gateway.
            let gateway2 = MockGateway()
            let recovered = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway2,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: 100, journal: WriteBackJournal(cacheDir: journalDir))
            try await recovered.replayJournal()
            // The replayed write drives to a real commit.
            let state = try await recovered.flush(filespace: "fs", path: "saved.mov", wait: true, timeoutMs: 5000)
            XCTAssertTrue(state.inSync)
            XCTAssertEqual(gateway2.putManifests.count, 1, "the replayed write must commit on the new engine")
            // And the recovered bytes round-trip.
            let committed = try XCTUnwrap(gateway2.putManifests.first)
            var rebuilt = Data()
            for (i, r) in committed.blocks.enumerated() {
                let url = "https://blob.test/PUT?key=" +
                    (r.hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
                let ct = try XCTUnwrap(BlobURLProtocol.putBody(url))
                rebuilt.append(try await crypto.decryptBlock(ct, itemID: "saved.mov", blockIndex: i))
            }
            XCTAssertEqual(rebuilt, payload)
        }
    }

    /// A successful commit CLEARS the journal entry — a later replay must not re-drive
    /// an already-durable write.
    func testJournalEntryClearedAfterCommit() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let journalDir = Self.makeJournalDir()
            let journal = WriteBackJournal(cacheDir: journalDir)
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: 100, journal: journal)
            try await engine.stageWrite(filespace: "fs", itemID: "done.mov", offset: 0,
                                        data: Data(repeating: 7, count: 120), baseVersion: nil, fence: nil)
            _ = try await engine.flush(filespace: "fs", path: "done.mov", wait: true, timeoutMs: 5000)
            // After a durable commit, replay finds nothing to re-drive.
            let entries = try await journal.replay()
            XCTAssertTrue(entries.isEmpty, "a committed write must clear its journal entry")
        }
    }

    /// Audit B2 (no retry): a transient 503 on the block PUT must be RETRIED (the bytes
    /// stay staged + journaled), not parked in RAM forever. After the transient budget,
    /// the same staged write commits.
    func testTransientUploadFailureIsRetriedNotDropped() async throws {
        try await withTestTimeout(30) {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let journalDir = Self.makeJournalDir()
            // BlobTransport itself retries within an attempt; to exercise the ENGINE's
            // retry loop we make the blob transport give up fast (1 attempt) and fail
            // the PUT's first 2 tries, so the engine must re-drive.
            let payload = Data((0..<80).map { UInt8($0 & 0xff) })   // 1 block at bs=100
            let (_, hash) = try await crypto.encryptBlock(payload, itemID: "retry.mov", blockIndex: 0)
            let putURL = "https://blob.test/PUT?key=" +
                (hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
            BlobURLProtocol.failFirst(2, on: putURL)
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(),
                                    policy: RetryPolicy(maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1) { _ in }),
                blockSize: 100, journal: WriteBackJournal(cacheDir: journalDir),
                maxUploadRetries: 6, retryBaseDelayMs: 10)
            try await engine.stageWrite(filespace: "fs", itemID: "retry.mov", offset: 0,
                                        data: payload, baseVersion: nil, fence: nil)
            let state = try await engine.flush(filespace: "fs", path: "retry.mov", wait: true, timeoutMs: 5000)
            XCTAssertTrue(state.inSync, "the barrier must span retry backoff and replacement upload tasks")
            XCTAssertEqual(gateway.putManifests.count, 1, "a transient failure must be retried before flush succeeds")
        }
    }

    // MARK: - Audit B4: daemon-side optimistic concurrency (CAS commit)

    /// stageWrite threads the base version into the commit as `expectedVersion`; the
    /// gateway enforces it. A concurrent bump → the commit gets `.conflict`, the
    /// staging is KEPT (nothing lost), and a conflict event is published.
    func testCommitThreadsExpectedVersionAndConflictKeepsStaging() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            gateway.enforceExpectedVersion = true
            // Pretend the server already moved to version 5 (a teammate committed).
            gateway.versions["proj.prproj"] = 5
            let journalDir = Self.makeJournalDir()
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: 100, journal: WriteBackJournal(cacheDir: journalDir),
                maxUploadRetries: 0)
            // Subscribe so we can observe the terminal conflict event.
            let stream = engine.progressEvents(filespace: "fs")
            // We based our edit on version 3 → CAS mismatch (server is at 5).
            try await engine.stageWrite(filespace: "fs", itemID: "proj.prproj", offset: 0,
                                        data: Data(repeating: 1, count: 50), baseVersion: "3", fence: nil)
            // Drain events until the terminal error (conflict) arrives.
            var sawConflict = false
            for await t in stream {
                if t.state == .error { sawConflict = t.error?.contains("conflict") ?? false; break }
                if t.state == .done { break }
            }
            XCTAssertTrue(sawConflict, "a CAS mismatch must publish a terminal conflict event")
            // The commit carried expectedVersion=3.
            XCTAssertEqual(gateway.putExpectedVersions.last, 3)
            // The staged bytes are KEPT (read-your-own-writes still serves them).
            let staged = await engine.stagedState(filespace: "fs", itemID: "proj.prproj")
            XCTAssertEqual(staged?.size, 50, "a conflict must NOT discard the local edit")
            XCTAssertEqual(staged?.dirtyLengths[0], 50)
        }
    }

    /// On the happy path the CAS commit succeeds and threads the right expectedVersion.
    func testCommitSucceedsWhenBaseVersionMatches() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            gateway.enforceExpectedVersion = true
            gateway.versions["ok.prproj"] = 4
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: 100, journal: WriteBackJournal(cacheDir: Self.makeJournalDir()))
            try await engine.stageWrite(filespace: "fs", itemID: "ok.prproj", offset: 0,
                                        data: Data(repeating: 2, count: 60), baseVersion: "4", fence: nil)
            let state = try await engine.flush(filespace: "fs", path: "ok.prproj", wait: true, timeoutMs: 5000)
            XCTAssertTrue(state.inSync)
            XCTAssertEqual(gateway.putExpectedVersions.last, 4)
            XCTAssertEqual(gateway.putManifests.count, 1)
        }
    }

    // MARK: - Audit B3: read-your-own-writes (stagedState + stagedBlock)

    /// stagedState/stagedBlock return the just-written plaintext blocks before they
    /// commit, so the read path can overlay them (a write-then-read on the mount sees
    /// the new bytes). P1: the bytes page back from the JOURNAL (RAM was dropped once
    /// the block was durably journaled).
    func testStagedStateServesReadYourOwnWritesFromJournal() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            BlobURLProtocol.armPUTGate()   // hold the upload so the write stays dirty
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: 100, journal: WriteBackJournal(cacheDir: Self.makeJournalDir()))
            let payload = Data((0..<90).map { UInt8(($0 * 11) & 0xff) })
            try await engine.stageWrite(filespace: "fs", itemID: "live.mov", offset: 0,
                                        data: payload, baseVersion: nil, fence: nil)
            // Before the upload commits, the staged bytes are readable verbatim —
            // paged from the journal file (the engine dropped the RAM copy).
            let maybeStaged = await engine.stagedState(filespace: "fs", itemID: "live.mov")
            let staged = try XCTUnwrap(maybeStaged)
            XCTAssertEqual(staged.size, payload.count)
            XCTAssertEqual(staged.dirtyLengths[0], payload.count)
            let block0 = try await engine.stagedBlock(filespace: "fs", itemID: "live.mov", blockIndex: 0)
            XCTAssertEqual(block0, payload, "read-your-own-writes must serve the staged plaintext")
            BlobURLProtocol.releasePUTs()
        }
    }

    // MARK: - P3: the commit's new metadata flows back BEFORE the overlay drops

    func testOnCommitFiresWithGatewayMetadataBeforeStagingClears() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            gateway.versions["v.prproj"] = 3
            // Record the callback's metadata AND whether the staging overlay was
            // still present when it fired (the no-stale-window ordering guarantee).
            final class Recorder: @unchecked Sendable {
                private let lock = NSLock()
                private var meta: ItemMetadata?
                private var overlayPresentAtCommit: Bool?
                func record(meta m: ItemMetadata, overlayPresent p: Bool) {
                    lock.lock(); meta = m; overlayPresentAtCommit = p; lock.unlock()
                }
                func snapshot() -> (meta: ItemMetadata?, present: Bool?) {
                    lock.lock(); defer { lock.unlock() }; return (meta, overlayPresentAtCommit)
                }
            }
            let rec = Recorder()
            // Thread-safe late-bound engine reference for the @Sendable callback.
            final class EngineBox: @unchecked Sendable {
                private let lock = NSLock()
                private var engine: RealTransferEngine?
                func set(_ e: RealTransferEngine) { lock.lock(); engine = e; lock.unlock() }
                func get() -> RealTransferEngine? { lock.lock(); defer { lock.unlock() }; return engine }
            }
            let box = EngineBox()
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: 100, journal: WriteBackJournal(cacheDir: Self.makeJournalDir()),
                onCommit: { fs, item, meta in
                    let present = await box.get()?.stagedState(filespace: fs, itemID: item) != nil
                    rec.record(meta: meta, overlayPresent: present)
                })
            box.set(engine)
            try await engine.stageWrite(filespace: "fs", itemID: "v.prproj", offset: 0,
                                        data: Data(repeating: 1, count: 60), baseVersion: "3", fence: nil)
            let st = try await engine.flush(filespace: "fs", path: "v.prproj", wait: true, timeoutMs: 5000)
            XCTAssertTrue(st.inSync)
            let (meta, present) = rec.snapshot()
            XCTAssertEqual(meta?.metadataVersion, "4", "onCommit must carry the gateway's POST-commit metadata")
            XCTAssertEqual(present, true,
                "onCommit must fire while the staging overlay still serves reads (no stale window)")
        }
    }

    // MARK: - P1 ACCEPTANCE: a large sequential staged write keeps RAM flat
    //
    // The write-side twin of the streaming-read bound: a 64 MiB sequential write
    // (64 × 1 MiB NFS-style callbacks) must NOT accumulate 64 MiB of dirty blocks in
    // daemon RAM — each block's bytes drop to the journal (the byte store) the moment
    // they are durably recorded, and page back in one at a time for upload. Pre-P1,
    // the dirty map held every block's bytes until commit: peak RSS delta ≥ 64 MiB.
    func testLargeSequentialStagedWriteKeepsRAMFlatViaJournal() async throws {
        try await withTestTimeout(120) {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 1 << 20
            let blocks = 64
            let journalDir = Self.makeJournalDir()
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: bs, journal: WriteBackJournal(cacheDir: journalDir))
            // Park the uploader so the measurement window contains ONLY staging work
            // (the upload pages blocks one at a time anyway, but its PUT bodies land
            // in the in-memory blob stub, which would pollute the RSS reading).
            _ = try await engine.pause(filespace: "fs")

            // ===== THE WRITE: 64 sequential 1 MiB callbacks, RSS sampled throughout =====
            let sampler = RSSSampler2()
            for i in 0..<blocks {
                let payload = Data(repeating: UInt8(i & 0xff), count: bs)
                try await engine.stageWrite(filespace: "fs", itemID: "render.mov", offset: i * bs,
                                            data: payload, baseVersion: nil, fence: nil)
            }
            let peakDelta = sampler.stop()

            // All 64 blocks staged; bytes live in the JOURNAL, not RAM.
            let maybeState = await engine.stagedState(filespace: "fs", itemID: "render.mov")
            let state = try XCTUnwrap(maybeState)
            XCTAssertEqual(state.size, blocks * bs)
            XCTAssertEqual(state.dirtyLengths.count, blocks)
            // Spot-check: a staged block pages back from the journal byte-exact.
            let block7 = try await engine.stagedBlock(filespace: "fs", itemID: "render.mov", blockIndex: 7)
            XCTAssertEqual(block7, Data(repeating: 7, count: bs))

            // ===== THE BOUND: tens of MB, not the 64 MiB written =====
            print("P1-acceptance[write]: 64 MiB sequential staged write, peak RSS delta = \(peakDelta >> 20) MiB")
            XCTAssertLessThan(peakDelta, 32 << 20,
                "staging must spill to the journal; peak RSS delta was \(peakDelta >> 20) MiB for a 64 MiB write")

            // And the staged write still drives to a complete, correct commit.
            _ = try await engine.resume(filespace: "fs")
            let final = try await engine.flush(filespace: "fs", path: "render.mov", wait: true, timeoutMs: 60_000)
            XCTAssertTrue(final.inSync)
            let committed = try XCTUnwrap(gateway.putManifests.last)
            XCTAssertEqual(committed.size, blocks * bs)
            XCTAssertEqual(committed.blocks.count, blocks)
        }
    }

    func testEightMiBWriteRequestsKeepMemoryBoundedAndReplayEveryBlock() async throws {
        try await withTestTimeout(120) {
            let journalDir = Self.makeJournalDir()
            let journal = WriteBackJournal(cacheDir: journalDir)
            let engine = RealTransferEngine(cache: try Self.makeCache(), crypto: try Self.makeCrypto(),
                gateway: MockGateway(), blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                journal: journal)
            _ = try await engine.pause(filespace: "fs")
            let requestBytes = 8 << 20, requests = 16
            let sampler = RSSSampler2()
            for index in 0..<requests {
                try await engine.stageWrite(filespace: "fs", itemID: "large-requests", offset: index * requestBytes,
                                            data: Data(repeating: UInt8(index), count: requestBytes), baseVersion: nil, fence: nil)
            }
            let peakDelta = sampler.stop()
            print("P1-acceptance[8MiB-write]: 128 MiB staged, peak RSS delta = \(peakDelta >> 20) MiB")
            XCTAssertLessThan(peakDelta, 64 << 20, "large requests must remain bounded, not retain the complete staged file")
            let reopened = WriteBackJournal(cacheDir: journalDir)
            let entries = try await reopened.replay()
            let entry = try XCTUnwrap(entries.first)
            XCTAssertEqual(entry.size, requests * requestBytes)
            XCTAssertEqual(entry.blockLengths.count, 128)
            for index in 0..<128 {
                XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "large-requests", blockIndex: index),
                               Data(repeating: UInt8(index / 8), count: 1 << 20))
            }
            // Drain the paused uploader without retaining a 128 MiB mock-object
            // fixture after this staging/replay memory check has completed.
            try await engine.stageTruncate(filespace: "fs", itemID: "large-requests", newSize: 0, baseVersion: nil, fence: nil)
            _ = try await engine.resume(filespace: "fs")
            _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 60_000)
        }
    }

    // MARK: - P0 ACCEPTANCE: dirty-block writes on a 50 GB file
    //
    // The contract this whole rework exists for (Josh's acceptance test): write 1 MiB
    // at a RANDOM unaligned offset into a 50 GB file. The engine must:
    //   • download ≈ the touched blocks only (the 2 boundary blocks it must RMW-seed)
    //     — never the file;
    //   • hold ≈ the dirty blocks in RAM (staged bytes ≤ 2 blocks);
    //   • journal ∝ the bytes written (≤ 2 block files on disk);
    //   • upload ONLY the dirty blocks + ONE manifest CAS that REUSES the other
    //     51,198 committed refs verbatim.
    //
    // The 50 GB file is synthetic: a 51,200-block manifest whose blocks are NOT
    // seeded in the blob stub — any attempt to fetch a block outside the touched
    // pair 404s and fails the test (the strongest possible "did not download the
    // file" assertion). Only the two boundary blocks are served.
    func testAcceptance_RandomMidFileWriteInto50GBTouchesOnlyItsBlocks() async throws {
        try await withTestTimeout(60) {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = kDefaultBlockSize                      // 1 MiB production block size
            let itemID: InodeID = "prores-50gb.mov"
            let totalBlocks = 50 * 1024                     // 50 GiB / 1 MiB
            let fileSize = totalBlocks * bs

            // Build the 50 GB manifest WITHOUT materializing 50 GB: deterministic
            // per-index fake hashes; real plaintext/ciphertext only for the 2 blocks
            // the write touches.
            let writeOffset = 31_415 * bs + 262_144         // random-ish, UNALIGNED (block 31415+31416)
            let writeLen = 1 << 20                          // 1 MiB → straddles exactly 2 blocks
            let firstTouched = writeOffset / bs
            let touchedIndices = Set(firstTouched...((writeOffset + writeLen - 1) / bs))
            XCTAssertEqual(touchedIndices.count, 2, "an unaligned 1 MiB write straddles 2 blocks")

            var refs: [BlockRef] = []
            refs.reserveCapacity(totalBlocks)
            var touchedPlaintext: [Int: Data] = [:]
            for i in 0..<totalBlocks {
                if touchedIndices.contains(i) {
                    // Real, servable block (the RMW seed fetch must succeed).
                    let pt = Data(repeating: UInt8(i & 0xff), count: bs)
                    let (ct, hash) = try await crypto.encryptBlock(pt, itemID: itemID, blockIndex: i)
                    let url = "https://blob.test/GET?key=" +
                        (hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
                    BlobURLProtocol.serveGET(url, ct)
                    touchedPlaintext[i] = pt
                    refs.append(BlockRef(hash: hash, offset: i * bs, length: bs))
                } else {
                    // Unservable sentinel: fetching ANY of these blocks 404s → the
                    // upload/staging path provably never touches them.
                    refs.append(BlockRef(hash: BlockHash(hex: String(format: "%064x", i)),
                                         offset: i * bs, length: bs))
                }
            }
            gateway.manifests[itemID] = BlockManifest(itemID: itemID, blocks: refs, contentVersion: "cv-50g")
            gateway.versions[itemID] = 7
            gateway.enforceExpectedVersion = true

            let journalDir = Self.makeJournalDir()
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: bs, journal: WriteBackJournal(cacheDir: journalDir))

            // ===== THE WRITE: 1 MiB at an unaligned offset into the "50 GB" file =====
            let payload = Data((0..<writeLen).map { UInt8(($0 &* 31) & 0xff) })
            let stagedSize = try await engine.stageWrite(filespace: "fs", itemID: itemID,
                                                         offset: writeOffset, data: payload,
                                                         baseVersion: "7", fence: nil)
            XCTAssertEqual(stagedSize, fileSize, "an interior write keeps the 50 GB logical size")

            // --- RAM stays flat: the staging holds ≈ the 2 dirty blocks, not the file.
            let maybeOverlay = await engine.stagedState(filespace: "fs", itemID: itemID)
            let overlay = try XCTUnwrap(maybeOverlay)
            XCTAssertEqual(overlay.dirtyLengths.count, 2, "exactly the touched blocks are staged")
            let stagedBytes = overlay.dirtyLengths.values.reduce(0, +)
            XCTAssertLessThanOrEqual(stagedBytes, 2 * bs, "staged bytes ≤ 2 blocks for a 1 MiB write")

            // --- Payload I/O stays sparse. One original block-map snapshot is also
            // retained for exact partial-write recovery after restart.
            let entryDirs = try FileManager.default.contentsOfDirectory(atPath: journalDir + "/staging")
            XCTAssertEqual(entryDirs.count, 1)
            let entryPath = journalDir + "/staging/" + entryDirs[0]
            let journalFiles = try FileManager.default.contentsOfDirectory(atPath: entryPath)
            let payloadFiles = journalFiles.filter { $0.hasPrefix("block-") && !$0.hasPrefix("block-base-") }
            XCTAssertEqual(payloadFiles.count, 2,
                           "the journal persists ONLY the touched blocks")
            let journalBytes = payloadFiles.reduce(0) { sum, f in
                sum + ((try? FileManager.default.attributesOfItem(atPath: entryPath + "/" + f)[.size] as? Int) ?? 0)
            }
            XCTAssertLessThanOrEqual(journalBytes, 2 * bs + 4096,
                                     "journal payload disk I/O tracks changed bytes, never the 50GB file")
            XCTAssertEqual(journalFiles.filter { $0.hasPrefix("block-base-") }.count, 1,
                           "preserve one original manifest, not unchanged file payloads")

            // ===== COMMIT: drain the async upload =====
            let state = try await engine.flush(filespace: "fs", path: itemID.rawValue, wait: true, timeoutMs: 30_000)
            XCTAssertTrue(state.inSync)

            // --- Download ≈ touched blocks: exactly 2 GETs were presigned (the RMW
            // seeds); every other block would have 404'd if touched.
            let getPresigns = gateway.presignCalls.filter { $0.method == .GET }
            XCTAssertEqual(getPresigns.count, 2, "RMW must fetch exactly the 2 boundary blocks, got \(getPresigns.count)")

            // --- Upload = dirty blocks only + 1 manifest CAS.
            let putPresigns = gateway.presignCalls.filter { $0.method == .PUT }
            XCTAssertEqual(putPresigns.count, 2, "only the 2 dirty blocks are PUT, got \(putPresigns.count)")
            XCTAssertEqual(gateway.putManifests.count, 1, "exactly one manifest CAS")
            XCTAssertEqual(gateway.putExpectedVersions.last, 7, "the CAS carries the base version")

            // --- The committed manifest REUSES all 51,198 untouched refs verbatim.
            let committed = try XCTUnwrap(gateway.putManifests.first)
            XCTAssertEqual(committed.blocks.count, totalBlocks)
            XCTAssertEqual(committed.size, fileSize)
            var reused = 0, changed = 0
            for (i, ref) in committed.blocks.enumerated() {
                if touchedIndices.contains(i) {
                    XCTAssertNotEqual(ref.hash, refs[i].hash, "a dirty block gets a new content address")
                    changed += 1
                } else {
                    XCTAssertEqual(ref.hash, refs[i].hash, "untouched block \(i) must reuse its committed ref")
                    reused += 1
                }
            }
            XCTAssertEqual(changed, 2)
            XCTAssertEqual(reused, totalBlocks - 2)

            // --- Round-trip: the 2 new blocks decrypt to seed-spliced-with-payload.
            var expected = touchedPlaintext[firstTouched]! + touchedPlaintext[firstTouched + 1]!
            let spliceLo = writeOffset - firstTouched * bs
            expected.replaceSubrange(spliceLo..<(spliceLo + writeLen), with: payload)
            var got = Data()
            for i in touchedIndices.sorted() {
                let url = "https://blob.test/PUT?key=" +
                    (committed.blocks[i].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
                let ct = try XCTUnwrap(BlobURLProtocol.putBody(url))
                got.append(try await crypto.decryptBlock(ct, itemID: itemID, blockIndex: i))
            }
            XCTAssertEqual(got, expected,
                           "the dirty blocks must be the committed seed with the write spliced in")
        }
    }

    // (RSSSampler2: this target's copy of the resident-size sampler — test targets
    // cannot share helpers without a support module.)

    // MARK: - P0: ranged write to a NEW file (no committed manifest) stays cheap

    func testRangedWriteToNewFileHasNoManifestAndNoSeedFetch() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()           // failManifestForMissing=true → .notFound
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: 100)
            // Two ranged callbacks (an NFS-style split write) on a brand-new item.
            try await engine.stageWrite(filespace: "fs", itemID: "new.bin", offset: 0,
                                        data: Data(repeating: 1, count: 100), baseVersion: nil, fence: nil)
            try await engine.stageWrite(filespace: "fs", itemID: "new.bin", offset: 100,
                                        data: Data(repeating: 2, count: 50), baseVersion: nil, fence: nil)
            let state = try await engine.flush(filespace: "fs", path: "new.bin", wait: true, timeoutMs: 5000)
            XCTAssertTrue(state.inSync)
            // No GET ever happened (nothing to seed from), and the commit covers both writes.
            XCTAssertTrue(gateway.presignCalls.allSatisfy { $0.method == .PUT },
                          "a new file must not fetch anything")
            let committed = try XCTUnwrap(gateway.putManifests.last)
            XCTAssertEqual(committed.size, 150)
            XCTAssertEqual(committed.blocks.count, 2)
        }
    }

    // MARK: - P0: write-beyond-EOF gap blocks read back / upload as zeros

    func testGrowthGapBlocksUploadAsZeros() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 100
            // Committed file: 1 full block [0,100).
            let basePT = Data(repeating: 0xAB, count: 100)
            let baseManifest = try await Self.seedItem("gap.bin", plaintext: basePT, blockSize: bs, crypto: crypto, gateway: gateway)
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: bs)
            // Sparse write far past EOF: [350, 400) → block 3 dirty; block 1,2 = holes.
            try await engine.stageWrite(filespace: "fs", itemID: "gap.bin", offset: 350,
                                        data: Data(repeating: 0xCD, count: 50), baseVersion: nil, fence: nil)
            let state = try await engine.flush(filespace: "fs", path: "gap.bin", wait: true, timeoutMs: 5000)
            XCTAssertTrue(state.inSync)
            let committed = try XCTUnwrap(gateway.putManifests.last)
            XCTAssertEqual(committed.size, 400)
            XCTAssertEqual(committed.blocks.count, 4)
            // Block 0 reused (untouched committed ref). Blocks 1-2 zeros, block 3 the write.
            XCTAssertEqual(committed.blocks[0].hash, baseManifest.blocks[0].hash)
            for (i, expected) in [(1, Data(repeating: 0, count: 100)),
                                  (2, Data(repeating: 0, count: 100)),
                                  (3, Data(repeating: 0, count: 50) + Data(repeating: 0xCD, count: 50))] {
                let url = "https://blob.test/PUT?key=" +
                    (committed.blocks[i].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
                let ct = try XCTUnwrap(BlobURLProtocol.putBody(url), "block \(i) must have been PUT")
                let pt = try await crypto.decryptBlock(ct, itemID: "gap.bin", blockIndex: i)
                XCTAssertEqual(pt, expected, "block \(i) content")
            }
        }
    }

    // MARK: - P4: truncate

    /// Shrink: committed 250 bytes (100+100+50) truncated to 120 → the commit reuses
    /// block 0 verbatim, RMW-trims block 1 to 20 bytes, and drops block 2. Network
    /// cost = ONE block fetch + ONE block PUT, never the file.
    func testTruncateShrinkReusesHeadTrimsBoundaryDropsTail() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 100
            let basePT = Data((0..<250).map { UInt8($0 & 0xff) })
            let baseManifest = try await Self.seedItem("cut.bin", plaintext: basePT, blockSize: bs,
                                                       crypto: crypto, gateway: gateway)
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: bs, journal: WriteBackJournal(cacheDir: Self.makeJournalDir()))

            try await engine.stageTruncate(filespace: "fs", itemID: "cut.bin", newSize: 120,
                                           baseVersion: nil, fence: nil)
            let st = try await engine.flush(filespace: "fs", path: "cut.bin", wait: true, timeoutMs: 5000)
            XCTAssertTrue(st.inSync)

            let committed = try XCTUnwrap(gateway.putManifests.last)
            XCTAssertEqual(committed.size, 120)
            XCTAssertEqual(committed.blocks.count, 2)
            XCTAssertEqual(committed.blocks[0].hash, baseManifest.blocks[0].hash, "head block reused verbatim")
            XCTAssertEqual(committed.blocks[1].length, 20)
            let url1 = "https://blob.test/PUT?key=" +
                (committed.blocks[1].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
            let ct1 = try XCTUnwrap(BlobURLProtocol.putBody(url1))
            let pt1 = try await crypto.decryptBlock(ct1, itemID: "cut.bin", blockIndex: 1)
            XCTAssertEqual(pt1, basePT.subdata(in: 100..<120), "boundary block trimmed to the alive bytes")
        }
    }

    /// THE resurrection guard: truncate 10 → 4, then write [8,10). The committed
    /// bytes [4,8) are DEAD — the committed file must become base[0..4] + zeros[4..8]
    /// + the new bytes, never the pre-truncate content.
    func testTruncateThenGrowReadsZerosNotResurrectedBytes() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 100
            let basePT = Data((1...10).map { UInt8($0) })   // [1..10]
            try await Self.seedItem("res.bin", plaintext: basePT, blockSize: bs, crypto: crypto, gateway: gateway)
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: bs, journal: WriteBackJournal(cacheDir: Self.makeJournalDir()))

            try await engine.stageTruncate(filespace: "fs", itemID: "res.bin", newSize: 4,
                                           baseVersion: nil, fence: nil)
            try await engine.stageWrite(filespace: "fs", itemID: "res.bin", offset: 8,
                                        data: Data([0xEE, 0xEE]), baseVersion: nil, fence: nil)

            // Read-your-own-writes BEFORE commit: trimmed + zeros + new bytes.
            let maybeState = await engine.stagedState(filespace: "fs", itemID: "res.bin")
            let state = try XCTUnwrap(maybeState)
            XCTAssertEqual(state.size, 10)
            XCTAssertEqual(state.committedLimit, 4, "the truncate kill-line must reach readers")

            let st = try await engine.flush(filespace: "fs", path: "res.bin", wait: true, timeoutMs: 5000)
            XCTAssertTrue(st.inSync)
            let committed = try XCTUnwrap(gateway.putManifests.last)
            XCTAssertEqual(committed.size, 10)
            XCTAssertEqual(committed.blocks.count, 1)
            let url = "https://blob.test/PUT?key=" +
                (committed.blocks[0].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
            let ct = try XCTUnwrap(BlobURLProtocol.putBody(url))
            let pt = try await crypto.decryptBlock(ct, itemID: "res.bin", blockIndex: 0)
            XCTAssertEqual(pt, Data([1, 2, 3, 4, 0, 0, 0, 0, 0xEE, 0xEE]),
                "dead committed bytes [4,8) must be ZEROS, never resurrected old content")
        }
    }

    /// write-then-truncate: staged tail blocks beyond the boundary are dropped and
    /// the staged boundary block is trimmed (no orphaned upload, no oversize image).
    func testWriteThenTruncateDropsAndTrimsStagedBlocks() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 100
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: bs, journal: WriteBackJournal(cacheDir: Self.makeJournalDir()))
            // New file: write 250 bytes (3 staged blocks), then truncate to 120.
            try await engine.stageWrite(filespace: "fs", itemID: "wt.bin", offset: 0,
                                        data: Data(repeating: 7, count: 250), baseVersion: nil, fence: nil)
            try await engine.stageTruncate(filespace: "fs", itemID: "wt.bin", newSize: 120,
                                           baseVersion: nil, fence: nil)
            let maybeState = await engine.stagedState(filespace: "fs", itemID: "wt.bin")
            let state = try XCTUnwrap(maybeState)
            XCTAssertEqual(state.size, 120)
            XCTAssertEqual(state.dirtyLengths.count, 2, "staged blocks beyond the boundary are dropped")
            XCTAssertEqual(state.dirtyLengths[1], 20, "the staged boundary block is trimmed")

            let st = try await engine.flush(filespace: "fs", path: "wt.bin", wait: true, timeoutMs: 5000)
            XCTAssertTrue(st.inSync)
            let committed = try XCTUnwrap(gateway.putManifests.last)
            XCTAssertEqual(committed.size, 120)
            XCTAssertEqual(committed.blocks.count, 2)
        }
    }

    // MARK: - P0: short committed tail + growth forces a single-block RMW (extend)

    func testGrowingPastShortTailExtendsOnlyThatBlock() async throws {
        try await withTestTimeout {
            let crypto = try Self.makeCrypto()
            let cache = try Self.makeCache()
            let gateway = MockGateway()
            let bs = 100
            // Committed: 1.5 blocks — block 0 full, block 1 SHORT (50 bytes).
            let basePT = Data((0..<150).map { UInt8($0 & 0xff) })
            let baseManifest = try await Self.seedItem("tail.bin", plaintext: basePT, blockSize: bs, crypto: crypto, gateway: gateway)
            let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway,
                blob: BlobTransport(session: Self.blobSession(), policy: Self.fastPolicy()),
                blockSize: bs)
            // Append a fresh block 2: [200, 300). Block 1 (short tail) is NOT written,
            // but the file now extends past it → it must be zero-extended to 100 bytes
            // by an RMW of THAT BLOCK ONLY (the `extend` plan).
            try await engine.stageWrite(filespace: "fs", itemID: "tail.bin", offset: 200,
                                        data: Data(repeating: 0xEE, count: 100), baseVersion: nil, fence: nil)
            let state = try await engine.flush(filespace: "fs", path: "tail.bin", wait: true, timeoutMs: 5000)
            XCTAssertTrue(state.inSync)
            let committed = try XCTUnwrap(gateway.putManifests.last)
            XCTAssertEqual(committed.size, 300)
            XCTAssertEqual(committed.blocks.count, 3)
            // Block 0 reused verbatim; block 1 re-encrypted as oldTail+zeros; block 2 new.
            XCTAssertEqual(committed.blocks[0].hash, baseManifest.blocks[0].hash)
            let url1 = "https://blob.test/PUT?key=" +
                (committed.blocks[1].hash.objectKey.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!)
            let ct1 = try XCTUnwrap(BlobURLProtocol.putBody(url1), "the grown tail block must be re-PUT")
            let pt1 = try await crypto.decryptBlock(ct1, itemID: "tail.bin", blockIndex: 1)
            XCTAssertEqual(pt1, basePT.subdata(in: 100..<150) + Data(repeating: 0, count: 50),
                           "the short tail is zero-extended, preserving its committed bytes")
        }
    }
}

// MARK: - RSS sampler (peak resident-size delta across a measured window) ------
//
// Samples the process's resident size on a dedicated thread every ~2 ms and tracks
// the peak. `stop()` returns peak-minus-baseline. A thread (not a Task) so sampling
// never competes with the async work under measurement for executor time.

final class RSSSampler2: @unchecked Sendable {
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
