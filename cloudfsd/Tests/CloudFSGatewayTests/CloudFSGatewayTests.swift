// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSGateway

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - URLProtocol stub
//
// Answers requests from an in-memory route table with responses shaped per
// backend/API.md — no live server. Handlers are keyed "METHOD /path"; each
// returns (status, json[, headers]). Records every request for assertions on
// method / path / query / headers / body.

final class StubURLProtocol: URLProtocol, @unchecked Sendable {

    struct Stub { let status: Int; let json: String; let headers: [String: String]; var error: URLError.Code? = nil }
    struct Recorded {
        let method: String
        let url: URL
        let headers: [String: String]
        let body: Data?
    }

    nonisolated(unsafe) private static var routes: [String: (URLRequest) -> Stub] = [:]
    nonisolated(unsafe) private static var recorded: [Recorded] = []
    private static let lock = NSLock()

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        routes = [:]; recorded = []
    }

    static func on(_ key: String, _ handler: @escaping (URLRequest) -> Stub) {
        lock.lock(); defer { lock.unlock() }
        routes[key] = handler
    }
    static func on(_ key: String, status: Int = 200, json: String, headers: [String: String] = [:]) {
        on(key) { _ in Stub(status: status, json: json, headers: headers) }
    }

    static var requests: [Recorded] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }

    private static func record(_ req: URLRequest) {
        lock.lock(); defer { lock.unlock() }
        recorded.append(Recorded(
            method: req.httpMethod ?? "GET",
            url: req.url!,
            headers: req.allHTTPHeaderFields ?? [:],
            body: bodyData(of: req)))
    }

    private static func lookup(_ req: URLRequest) -> Stub? {
        lock.lock(); defer { lock.unlock() }
        let method = req.httpMethod ?? "GET"
        let path = req.url?.path ?? ""
        return routes["\(method) \(path)"].map { $0(req) }
    }

    /// URLProtocol moves `httpBody` to a stream; read whichever is present.
    private static func bodyData(of req: URLRequest) -> Data? {
        if let b = req.httpBody { return b }
        guard let stream = req.httpBodyStream else { return nil }
        stream.open(); defer { stream.close() }
        var data = Data()
        let bufSize = 4096
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: bufSize)
        defer { buf.deallocate() }
        while stream.hasBytesAvailable {
            let read = stream.read(buf, maxLength: bufSize)
            if read <= 0 { break }
            data.append(buf, count: read)
        }
        return data.isEmpty ? nil : data
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.record(request)
        guard let stub = Self.lookup(request) else {
            let resp = HTTPURLResponse(url: request.url!, statusCode: 404,
                                       httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(#"{"error":"not found"}"#.utf8))
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        if let error = stub.error {
            client?.urlProtocol(self, didFailWithError: URLError(error))
            return
        }
        var headers = stub.headers
        headers["content-type"] = "application/json"
        let resp = HTTPURLResponse(url: request.url!, statusCode: stub.status,
                                   httpVersion: "HTTP/1.1", headerFields: headers)!
        client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(stub.json.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

extension URLSession {
    static func stubbed() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: cfg)
    }
}

// MARK: - Tests

final class CloudFSGatewayTests: XCTestCase {

    private func makeClient(token: String = "tok-123") -> HttpGatewayClient {
        StubURLProtocol.reset()
        let cfg = GatewayClientConfig(baseURL: "https://gw.test", token: token)
        return HttpGatewayClient(config: cfg, session: .stubbed())
    }

    private func query(_ r: StubURLProtocol.Recorded) -> [URLQueryItem] {
        URLComponents(url: r.url, resolvingAgainstBaseURL: false)?.queryItems ?? []
    }

    /// HTTP header lookup is case-insensitive; Foundation canonicalizes the body
    /// content-type key to "Content-Type".
    private func contentType(_ r: StubURLProtocol.Recorded) -> String? {
        r.headers.first { $0.key.lowercased() == "content-type" }?.value
    }

    func testCloseOpenHandleRequiresAcknowledgementButAcceptsIdempotentNotFound() async throws {
        let client = makeClient()
        let path = "/v1/filespaces/fs/open-handles"
        StubURLProtocol.on("POST \(path)", json: #"{"closed":true}"#)
        try await client.closeOpenHandle(filespace: "fs", handle: "00000000-0000-0000-0000-000000000001")

        StubURLProtocol.reset()
        StubURLProtocol.on("POST \(path)", json: #"{"closed":false,"reason":"not_found"}"#)
        try await client.closeOpenHandle(filespace: "fs", handle: "00000000-0000-0000-0000-000000000001")

        StubURLProtocol.reset()
        StubURLProtocol.on("POST \(path)", json: #"{"closed":false,"reason":"forbidden"}"#)
        do {
            try await client.closeOpenHandle(filespace: "fs", handle: "00000000-0000-0000-0000-000000000001")
            XCTFail("a denied close must be observable to the retrying open coordinator")
        } catch let error as EngineError {
            XCTAssertEqual(error.kind, .permissionDenied)
        }

        StubURLProtocol.reset()
        StubURLProtocol.on("POST \(path)", json: #"{"unexpected":true}"#)
        do {
            try await client.closeOpenHandle(filespace: "fs", handle: "00000000-0000-0000-0000-000000000001")
            XCTFail("malformed close responses cannot be treated as an acknowledged release")
        } catch let error as EngineError {
            XCTAssertEqual(error.kind, .gatewayError)
        }
    }

    func testDirectorySnapshotSuccessFallbackAndAuthoritativeDenials() async throws {
        let client = makeClient()
        let path = "/v1/filespaces/fs/open-handles"
        let handle = "00000000-0000-0000-0000-000000000001"
        StubURLProtocol.on("POST \(path)", json:
            #"{"granted":true,"directory":{"id":"dir","parent":"root","name":"Folder","isDir":true,"size":0,"contentVersion":"v1","version":3},"items":[{"id":"file","parent":"dir","name":"a.txt","isDir":false,"size":9,"contentVersion":"v2","version":4}]}"#)
        let snapshotResult = try await client.directorySnapshot(filespace: "fs", id: "dir",
            handle: handle, access: .read, sharing: [.read, .write, .delete])
        let snapshot = try XCTUnwrap(snapshotResult)
        XCTAssertEqual(snapshot.directory.name, "Folder")
        XCTAssertEqual(snapshot.items.map(\.name), ["a.txt"])
        let request = try XCTUnwrap(StubURLProtocol.requests.first)
        let body = try XCTUnwrap(request.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["action"] as? String, "directory-snapshot")
        XCTAssertEqual(json["id"] as? String, "dir")
        XCTAssertEqual(json["handleId"] as? String, handle)
        XCTAssertEqual(json["accessMask"] as? Int, Int(OpenFileAccess.read.rawValue))
        let expectedShareMask = Int(OpenFileSharing.read.rawValue | OpenFileSharing.write.rawValue | OpenFileSharing.delete.rawValue)
        XCTAssertEqual(json["shareMask"] as? Int, expectedShareMask)

        StubURLProtocol.reset()
        StubURLProtocol.on("POST \(path)", status: 400, json: #"{"error":"invalid_open_handle"}"#)
        let unsupported = try await client.directorySnapshot(filespace: "fs", id: "dir",
            handle: handle, access: .read, sharing: [.read])
        XCTAssertNil(unsupported, "only the known old-gateway unknown-action response falls back")

        StubURLProtocol.reset()
        StubURLProtocol.on("POST \(path)", json: #"{"granted":false,"reason":"sharing_violation"}"#)
        do {
            _ = try await client.directorySnapshot(filespace: "fs", id: "dir", handle: handle,
                access: .read, sharing: [.read])
            XCTFail("share denial must remain authoritative")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }

        StubURLProtocol.reset()
        let items = (0..<501).map { #"{"id":"f\#($0)","parent":"dir","name":"f\#($0)","isDir":false,"size":0,"contentVersion":"v","version":1}"# }.joined(separator: ",")
        StubURLProtocol.on("POST \(path)", json:
            #"{"granted":true,"directory":{"id":"dir","parent":"root","name":"Folder","isDir":true,"size":0,"contentVersion":"v1","version":1},"items":[\#(items)]}"#)
        do {
            _ = try await client.directorySnapshot(filespace: "fs", id: "dir", handle: handle,
                access: .read, sharing: [.read])
            XCTFail("oversized successful payloads must be rejected")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .gatewayError) }
    }

    func testDirectorySnapshotRejectsMalformedGrantedResponse() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/open-handles", json:
            #"{"granted":true,"items":[]}"#)
        do {
            _ = try await client.directorySnapshot(filespace: "fs", id: "dir",
                handle: "00000000-0000-0000-0000-000000000001", access: .read, sharing: [.read])
            XCTFail("a granted response without directory metadata is malformed")
        } catch let error as EngineError {
            XCTAssertEqual(error.kind, .gatewayError)
        }
    }

    func testAcquireOpenHandleCarriesOptionalRequiredStreamAndDecodesResult() async throws {
        let client = makeClient(), path = "/v1/filespaces/fs/open-handles"
        StubURLProtocol.on("POST \(path)", json: #"{"granted":true,"expiresAt":42,"stream":{"exists":true,"size":11}}"#)
        let lease = try await client.acquireOpenHandle(filespace: "fs", id: InodeID("item"),
            handle: "00000000-0000-0000-0000-000000000001", access: .read,
            sharing: [.read, .write, .delete], ttlMs: 90_000,
            stream: OpenHandleStreamRequest(name: "com.apple.provenance", required: true))
        XCTAssertEqual(lease.stream, OpenHandleStreamInfo(exists: true, size: 11))
        let body = try XCTUnwrap(StubURLProtocol.requests.first?.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let stream = try XCTUnwrap(json["stream"] as? [String: Any])
        XCTAssertEqual(stream["name"] as? String, "com.apple.provenance")
        XCTAssertEqual(stream["required"] as? Bool, true)

        StubURLProtocol.reset()
        StubURLProtocol.on("POST \(path)", json: #"{"granted":true}"#)
        let legacy = try await client.acquireOpenHandle(filespace: "fs", id: InodeID("item"),
            handle: "00000000-0000-0000-0000-000000000002", access: .read,
            sharing: [.read, .write, .delete], ttlMs: 90_000,
            stream: OpenHandleStreamRequest(name: "com.apple.provenance", required: true))
        XCTAssertNil(legacy.stream, "older gateways omit stream metadata and trigger the list fallback")
    }

    func testTransientGETRecoversWithoutReplayingMutations() async throws {
        for (method, status) in [("GET", 408), ("GET", 429), ("GET", 500), ("GET", 502), ("GET", 503), ("GET", 504), ("HEAD", 503)] {
            let client = makeClient()
            var count = 0
            StubURLProtocol.on("\(method) /retry") { _ in
                count += 1
                return .init(status: count == 1 ? status : 200,
                             json: count == 1 ? #"{"error":"transient"}"# : #"{"ok":true}"#, headers: [:])
            }
            let result = try await client.send(method, path: "/retry")
            XCTAssertEqual(result, Data(#"{"ok":true}"#.utf8))
            XCTAssertEqual(StubURLProtocol.requests.count, 2)
        }
        for method in ["POST", "PUT", "PATCH", "DELETE"] {
            let client = makeClient()
            StubURLProtocol.on("\(method) /mutation", status: 500, json: #"{"error":"transient"}"#)
            do { _ = try await client.send(method, path: "/mutation"); XCTFail("expected failure") }
            catch let error as EngineError { XCTAssertEqual(error.data?["status"], .int(500)) }
            XCTAssertEqual(StubURLProtocol.requests.count, 1, "A mutation may already have committed")
        }
    }

    func testPersistentTransientGETFailsAfterThreeAttemptsWithStatus() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /retry", status: 503, json: #"{"error":"busy"}"#)
        do { _ = try await client.send("GET", path: "/retry"); XCTFail("expected failure") }
        catch let error as EngineError {
            XCTAssertEqual(error.kind, .gatewayError)
            XCTAssertEqual(error.data?["status"], .int(503))
            XCTAssertEqual(error.data?["error"], .string("busy"))
        }
        XCTAssertEqual(StubURLProtocol.requests.count, 3)
    }

    func testTransientNetworkResetRetriesGETButNeverPOST() async throws {
        let client = makeClient()
        var count = 0
        StubURLProtocol.on("GET /retry") { _ in
            count += 1
            return .init(status: 200, json: "ok", headers: [:], error: count == 1 ? .networkConnectionLost : nil)
        }
        let result = try await client.send("GET", path: "/retry")
        XCTAssertEqual(result, Data("ok".utf8))
        XCTAssertEqual(StubURLProtocol.requests.count, 2)
        StubURLProtocol.reset()
        StubURLProtocol.on("POST /mutation") { _ in .init(status: 200, json: "", headers: [:], error: .networkConnectionLost) }
        do { _ = try await client.send("POST", path: "/mutation"); XCTFail("expected failure") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .networkError) }
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
    }

    func testCancellationDuringRetryDelayDoesNotSendAnotherRequest() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /retry", status: 429, json: #"{"error":"rate_limited"}"#, headers: ["Retry-After":"60"])
        let read = Task { try await client.send("GET", path: "/retry") }
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while StubURLProtocol.requests.isEmpty, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(1))
        }
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
        read.cancel()
        do { _ = try await read.value; XCTFail("expected cancellation") }
        catch is CancellationError {}
        catch { XCTFail("cancellation must remain cancellation, got \(error)") }
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
    }

    func testAuthorizationConflictNotFoundAndDecodeFailuresAreNeverRetried() async throws {
        for status in [401, 403, 404, 409] {
            let client = makeClient()
            StubURLProtocol.on("GET /retry", status: status, json: #"{"error":"fixture"}"#)
            do { _ = try await client.send("GET", path: "/retry"); XCTFail("expected failure") }
            catch let error as EngineError { XCTAssertEqual(error.data?["status"], .int(status)) }
            XCTAssertEqual(StubURLProtocol.requests.count, 1)
        }
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/items/file", json: "not-json")
        do { _ = try await client.getItem(filespace: "fs", id: "file"); XCTFail("expected decoding failure") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .gatewayError) }
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
    }

    func testRetryAfterSupportsSecondsAndHTTPDateWithShortCap() {
        let now = Date(timeIntervalSince1970: 0)
        XCTAssertEqual(HttpGatewayClient.readRetryDelay(retry: 0, retryAfter: nil), .milliseconds(100))
        XCTAssertEqual(HttpGatewayClient.readRetryDelay(retry: 1, retryAfter: "invalid"), .milliseconds(250))
        XCTAssertEqual(HttpGatewayClient.readRetryDelay(retry: 0, retryAfter: "0.5"), .milliseconds(500))
        XCTAssertEqual(HttpGatewayClient.readRetryDelay(retry: 1, retryAfter: "120"), .seconds(1))
        XCTAssertEqual(HttpGatewayClient.readRetryDelay(retry: 0, retryAfter: "Thu, 01 Jan 1970 00:00:30 GMT", now: now), .seconds(1))
        XCTAssertEqual(HttpGatewayClient.readRetryDelay(retry: 1, retryAfter: "Thu, 01 Jan 1970 00:00:00 GMT", now: now), .milliseconds(250))
        XCTAssertEqual(HttpGatewayClient.readRetryDelay(retry: 0, retryAfter: "nan"), .milliseconds(100))
    }

    func testTransportCancellationAndCertificateErrorsAreNeverRetried() async throws {
        for code in [URLError.Code.cancelled, .serverCertificateUntrusted] {
            let client = makeClient()
            StubURLProtocol.on("GET /retry") { _ in .init(status: 200, json: "", headers: [:], error: code) }
            do { _ = try await client.send("GET", path: "/retry"); XCTFail("expected transport failure") }
            catch is CancellationError { XCTAssertEqual(code, .cancelled) }
            catch let error as EngineError {
                XCTAssertEqual(code, .serverCertificateUntrusted)
                XCTAssertEqual(error.kind, .networkError)
                XCTAssertEqual(error.data?["domain"], .string(NSURLErrorDomain))
                XCTAssertEqual(error.data?["code"], .int(code.rawValue))
            }
            XCTAssertEqual(StubURLProtocol.requests.count, 1)
        }
    }

    // MARK: Stub still throws unimplemented (foundation contract)

    func testStubThrowsUnimplemented() async {
        let g = StubGatewayClient()
        do {
            _ = try await g.presign(filespace: "fs1", key: "blocks/o::fs1/x", method: .GET, expiresIn: 120)
            XCTFail("expected unimplemented")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .unimplemented)
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testPresignMethodRawValues() {
        XCTAssertEqual(PresignMethod.GET.rawValue, "GET")
        XCTAssertEqual(PresignMethod.PUT.rawValue, "PUT")
    }

    // MARK: presign happy path — method, path, bearer, body, clamp echo

    func testPresignHappyPath() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/active-edit/presign",
            json: #"{"url":"https://r2.example/signed?sig=abc","expiresIn":300}"#)

        let signed = try await client.presign(
            filespace: "active-edit",
            key: "blocks/acme::active-edit/chunks/ab/abcd",
            method: .GET, expiresIn: 600)

        XCTAssertEqual(signed.url, "https://r2.example/signed?sig=abc")
        XCTAssertEqual(signed.expiresIn, 300)   // server-side TTL clamp echoed

        let req = try XCTUnwrap(StubURLProtocol.requests.first { $0.url.path.hasSuffix("/presign") })
        XCTAssertEqual(req.method, "POST")
        XCTAssertEqual(req.headers["Authorization"], "Bearer tok-123")
        // URLSession canonicalizes the body header key to "Content-Type"; the
        // client sets it lowercase but Foundation normalizes the case on the wire.
        XCTAssertEqual(contentType(req)?.lowercased(), "application/json")
        // Body carries key + method + requested expiresIn.
        let body = try XCTUnwrap(req.body)
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(obj["key"] as? String, "blocks/acme::active-edit/chunks/ab/abcd")
        XCTAssertEqual(obj["method"] as? String, "GET")
        XCTAssertEqual(obj["expiresIn"] as? Int, 600)
    }

    func testPresignPutMethodSent() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/presign",
            json: #"{"url":"https://r2/put","expiresIn":900}"#)
        _ = try await client.presign(filespace: "fs", key: "blocks/o::fs/k", method: .PUT, expiresIn: nil)
        let req = try XCTUnwrap(StubURLProtocol.requests.first)
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: req.body!) as? [String: Any])
        XCTAssertEqual(obj["method"] as? String, "PUT")
        XCTAssertNil(obj["expiresIn"])   // omitted when nil
    }

    // MARK: batch presign (Audit B23)

    func testPresignBatchHappyPath() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/presign/batch",
            json: #"{"urls":[{"key":"blocks/o::fs/a","url":"https://r2/a"},{"key":"blocks/o::fs/b","error":"forbidden"}],"expiresIn":300}"#)

        let out = try await client.presignBatch(
            filespace: "fs",
            keys: [("blocks/o::fs/a", .GET), ("blocks/o::fs/b", .PUT)],
            expiresIn: 600)

        XCTAssertEqual(out.count, 2)
        XCTAssertEqual(out[0], PresignBatchResult(key: "blocks/o::fs/a", url: "https://r2/a", error: nil))
        XCTAssertEqual(out[1], PresignBatchResult(key: "blocks/o::fs/b", url: nil, error: "forbidden"))

        // The request hit the BATCH endpoint with a `keys` array (one round-trip, not two).
        let req = try XCTUnwrap(StubURLProtocol.requests.first { $0.url.path.hasSuffix("/presign/batch") })
        XCTAssertEqual(req.method, "POST")
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: req.body!) as? [String: Any])
        let keys = try XCTUnwrap(obj["keys"] as? [[String: Any]])
        XCTAssertEqual(keys.count, 2)
        XCTAssertEqual(keys[0]["key"] as? String, "blocks/o::fs/a")
        XCTAssertEqual(keys[1]["method"] as? String, "PUT")
    }

    // MARK: error envelope → typed EngineError

    func testForbiddenMapsToPermissionDenied() async {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/presign", status: 403,
            json: #"{"error":"forbidden_scope","reason":"need fs:write"}"#)
        do {
            _ = try await client.presign(filespace: "fs", key: "blocks/o::fs/k", method: .PUT, expiresIn: nil)
            XCTFail("expected throw")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .permissionDenied)
            XCTAssertTrue(e.message.contains("forbidden_scope"))
            XCTAssertTrue(e.message.contains("need fs:write"))
            XCTAssertEqual(e.data?["error"], .string("forbidden_scope"))
            XCTAssertEqual(e.data?["reason"], .string("need fs:write"))
            XCTAssertEqual(e.data?["status"], .int(403))
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testUnauthorizedMapsToPermissionDenied() async {
        let client = makeClient(token: "")
        StubURLProtocol.on("GET /v1/filespaces/fs/items/x", status: 401,
            json: #"{"error":"no_token"}"#)
        do {
            _ = try await client.getItem(filespace: "fs", id: "x")
            XCTFail("expected throw")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .permissionDenied)
            XCTAssertEqual(e.data?["error"], .string("no_token"))
            XCTAssertEqual(e.data?["status"], .int(401))
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testNotFoundMapsToNotFound() async {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/items/missing", status: 404,
            json: #"{"error":"no such item"}"#)
        do {
            _ = try await client.getItem(filespace: "fs", id: "missing")
            XCTFail("expected throw")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .notFound)
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testConflictCarriesExpectedActual() async {
        let client = makeClient()
        StubURLProtocol.on("PUT /v1/filespaces/fs/blocks/item1", status: 409,
            json: #"{"error":"conflict","conflict":true,"expected":3,"actual":4}"#)
        let manifest = BlockManifest(
            itemID: "item1",
            blocks: [BlockRef(hash: BlockHash(hex: "deadbeef"), offset: 0, length: 16)],
            contentVersion: "cv-16-1")
        do {
            _ = try await client.putBlockManifest(manifest, filespace: "fs", etag: nil)
            XCTFail("expected throw")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .conflict)
            XCTAssertEqual(e.data?["conflict"], .bool(true))
            XCTAssertEqual(e.data?["expected"], .int(3))
            XCTAssertEqual(e.data?["actual"], .int(4))
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testRateLimitedMapsToGatewayError() async {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/presign", status: 429,
            json: #"{"error":"rate_limited"}"#, headers: ["Retry-After": "2"])
        do {
            _ = try await client.presign(filespace: "fs", key: "blocks/o::fs/k", method: .GET, expiresIn: nil)
            XCTFail("expected throw")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .gatewayError)
            XCTAssertEqual(e.data?["retryAfter"], .string("2"))
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testServerErrorMapsToGatewayError() async {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/items/x", status: 500,
            json: #"{"error":"boom"}"#)
        do {
            _ = try await client.getItem(filespace: "fs", id: "x")
            XCTFail("expected throw")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .gatewayError)
        } catch { XCTFail("wrong error: \(error)") }
    }

    // MARK: block map round-trip

    func testGetBlockManifestDecodesBlocksAndContentVersion() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/blocks/item1",
            json: #"""
            [{"chunkIdx":0,"blockIdx":0,"blockHash":"aa11","objectKey":"chunks/aa/aa11","offset":0,"length":1048576},
             {"chunkIdx":1,"blockIdx":0,"blockHash":"bb22","objectKey":"chunks/bb/bb22","offset":1048576,"length":512}]
            """#)
        // getBlockManifest also fetches the owning Item for contentVersion.
        StubURLProtocol.on("GET /v1/filespaces/fs/items/item1",
            json: #"{"id":"item1","parent":"root","name":"clip.mov","isDir":false,"size":1049088,"contentVersion":"cv-1049088-7","etag":"e","version":3,"updatedSeq":7,"deleted":false}"#)

        let manifest = try await client.getBlockManifest(filespace: "fs", itemID: "item1")
        XCTAssertEqual(manifest.itemID, "item1")
        XCTAssertEqual(manifest.blocks.count, 2)
        XCTAssertEqual(manifest.blocks[0].hash.hex, "aa11")
        XCTAssertEqual(manifest.blocks[1].offset, 1048576)
        XCTAssertEqual(manifest.blocks[1].length, 512)
        XCTAssertEqual(manifest.contentVersion, "cv-1049088-7")
        XCTAssertEqual(manifest.size, 1049088)
    }

    func testBlockManifestEscapesSlashInInodeID() async throws {
        // An inode id is an opaque SINGLE path segment that may contain `/`
        // (e.g. "root/A001.mov"). It MUST be percent-encoded to `%2F` in the URL so
        // the gateway sees one component; otherwise `blocks/root/A001.mov` routes as
        // itemId "root" and returns an empty/wrong manifest (the real-gateway mount bug).
        let client = makeClient()
        // Stub matches on the DECODED path (so the route key uses a literal slash);
        // the assertion below checks the RAW url carries `%2F`.
        StubURLProtocol.on("GET /v1/filespaces/fs/blocks/root/A001.mov",
            json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"ab93","objectKey":"blocks/acme::fs/ab93","offset":0,"length":1048576}]"#)
        StubURLProtocol.on("GET /v1/filespaces/fs/items/root/A001.mov",
            json: #"{"id":"root/A001.mov","parent":"root","name":"A001.mov","isDir":false,"size":1048576,"contentVersion":"cv-1","etag":null,"version":2,"updatedSeq":7,"deleted":false}"#)

        let resolved = try await client.getResolvedBlockManifest(filespace: "fs", itemID: "root/A001.mov")
        XCTAssertEqual(resolved.manifest.blocks.count, 1)
        XCTAssertEqual(resolved.objectKey(for: BlockHash(hex: "ab93")), "blocks/acme::fs/ab93")

        // The blocks request URL must encode the slash as %2F (not a bare `/`).
        let blocksReq = try XCTUnwrap(StubURLProtocol.requests.first {
            $0.method == "GET" && $0.url.absoluteString.contains("/blocks/")
        })
        XCTAssertTrue(blocksReq.url.absoluteString.contains("root%2FA001.mov"),
                      "inode id slash must be %2F-encoded, got \(blocksReq.url.absoluteString)")
        XCTAssertFalse(blocksReq.url.absoluteString.contains("blocks/root/A001.mov"),
                       "a bare slash routes as itemId 'root' → empty manifest")
    }

    func testPutBlockManifestSendsBlocksAndReturnsItem() async throws {
        let client = makeClient()
        StubURLProtocol.on("PUT /v1/filespaces/fs/blocks/item1",
            json: #"{"id":"item1","parent":"root","name":"clip.mov","isDir":false,"size":16,"contentVersion":"cv-16-2","etag":"new","version":4,"updatedSeq":9,"deleted":false}"#)
        let manifest = BlockManifest(
            itemID: "item1",
            blocks: [BlockRef(hash: BlockHash(hex: "deadbeef"), offset: 0, length: 16)],
            contentVersion: "cv-16-1")

        let item = try await client.putBlockManifest(manifest, filespace: "fs", etag: "new")
        XCTAssertEqual(item.id, "item1")
        XCTAssertEqual(item.contentVersion, "cv-16-2")
        XCTAssertEqual(item.metadataVersion, "4")   // API `version` → metadataVersion

        let req = try XCTUnwrap(StubURLProtocol.requests.first { $0.method == "PUT" })
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: req.body!) as? [String: Any])
        XCTAssertEqual(obj["etag"] as? String, "new")
        let blocks = try XCTUnwrap(obj["blocks"] as? [[String: Any]])
        XCTAssertEqual(blocks.count, 1)
        XCTAssertEqual(blocks[0]["blockHash"] as? String, "deadbeef")
        // The registered objectKey MUST be the gateway/store scheme
        // (`blocks/<org>::<fs>/<hash>`), NOT the content-address cache key — it has to
        // equal the key the block was presign-PUT under so a later read fetches it.
        // The non-JWS test token has no `org` claim → org falls back to the fs id.
        XCTAssertEqual(blocks[0]["objectKey"] as? String, "blocks/fs::fs/deadbeef")
        XCTAssertEqual(blocks[0]["length"] as? Int, 16)
    }

    func testUploadObjectKeyUsesOrgFromTokenClaim() async throws {
        // A real JWS carries an `org` claim; the upload/manifest key MUST be
        // `blocks/<org>::<fs>/<hash>` (the presign-confinement prefix), decoded from
        // the token client-side (signature is the gateway's job).
        func b64url(_ s: String) -> String {
            Data(s.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let jws = "\(b64url(#"{"alg":"HS256"}"#)).\(b64url(#"{"sub":"u","org":"acme","scp":[]}"#)).sig"
        let client = makeClient(token: jws)
        let key = await client.uploadObjectKey(filespace: "edit1", blockHash: BlockHash(hex: "ab93"))
        XCTAssertEqual(key, "blocks/acme::edit1/ab93")
    }

    // MARK: items + opaque cursor pagination follow

    func testListItemsReturnsOpaqueCursor() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/items",
            json: #"""
            {"items":[{"id":"a","parent":"root","name":"ShowA","isDir":true,"size":0,"contentVersion":"cv-0-1","etag":null,"version":1,"updatedSeq":1,"deleted":false}],"cursor":"CURSOR2"}
            """#)
        let (items, cursor) = try await client.listItems(filespace: "fs", parent: .root, cursor: nil)
        XCTAssertEqual(items.map(\.name), ["ShowA"])
        XCTAssertEqual(items.first?.isDir, true)
        XCTAssertEqual(cursor, "CURSOR2")

        let req = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(req.headers["Authorization"], "Bearer tok-123")
        let q = query(req)
        XCTAssertTrue(q.contains { $0.name == "parent" && $0.value == "root" })
        XCTAssertTrue(q.contains { $0.name == "limit" && $0.value == "500" })
        XCTAssertFalse(q.contains { $0.name == "cursor" })   // none on first page
    }

    func testListItemsFollowsCursorOnSecondPage() async throws {
        let client = makeClient()
        // Caller drives pagination by passing the opaque cursor back as ?cursor=.
        StubURLProtocol.on("GET /v1/filespaces/fs/items") { req in
            let cursor = URLComponents(url: req.url!, resolvingAgainstBaseURL: false)?
                .queryItems?.first { $0.name == "cursor" }?.value
            if cursor == nil {
                return .init(status: 200, json: #"""
                {"items":[{"id":"a","parent":"root","name":"p1","isDir":false,"size":1,"contentVersion":"x","etag":"e","version":1,"updatedSeq":1,"deleted":false}],"cursor":"C2"}
                """#, headers: [:])
            } else {
                return .init(status: 200, json: #"""
                {"items":[{"id":"b","parent":"root","name":"p2","isDir":false,"size":2,"contentVersion":"y","etag":"e","version":1,"updatedSeq":2,"deleted":false}],"cursor":null}
                """#, headers: [:])
            }
        }

        var all: [ItemMetadata] = []
        var cursor: String? = nil
        repeat {
            let page = try await client.listItems(filespace: "fs", parent: .root, cursor: cursor)
            all.append(contentsOf: page.items)
            cursor = page.cursor
        } while cursor != nil

        XCTAssertEqual(all.map(\.name), ["p1", "p2"])
        // Page 2 carried the opaque cursor through as ?cursor=C2.
        let reqs = StubURLProtocol.requests.filter { $0.url.path == "/v1/filespaces/fs/items" }
        XCTAssertEqual(reqs.count, 2)
        let secondQ = query(reqs[1])
        XCTAssertTrue(secondQ.contains { $0.name == "cursor" && $0.value == "C2" })
    }

    func testListItemsNullCursorBecomesNil() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/items",
            json: #"{"items":[],"cursor":null}"#)
        let (_, cursor) = try await client.listItems(filespace: "fs", parent: .root, cursor: nil)
        XCTAssertNil(cursor)
    }

    // MARK: getItem

    func testGetItemDecodes() async throws {
        let client = makeClient()
        // An inode id like "projectA/timeline.prproj" is one opaque segment; the
        // client `%2F`-encodes the slash on the wire, but the stub keys on URL.path
        // (DECODED), so the literal-slash key still matches the request.
        StubURLProtocol.on("GET /v1/filespaces/fs/items/projectA/timeline.prproj",
            json: #"{"id":"projectA/timeline.prproj","parent":"projectA","name":"timeline.prproj","isDir":false,"size":42,"contentVersion":"cv-42-3","etag":"e","version":2,"updatedSeq":5,"deleted":false}"#)
        let item = try await client.getItem(filespace: "fs", id: "projectA/timeline.prproj")
        XCTAssertEqual(item.id, "projectA/timeline.prproj")
        XCTAssertEqual(item.parent, "projectA")
        XCTAssertEqual(item.size, 42)
        XCTAssertEqual(item.metadataVersion, "2")
    }

    // MARK: changes — numeric since cursor + anchor

    func testChangesNumericCursorAndAnchor() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/changes",
            json: #"""
            {"anchor":42,"items":[{"id":"a","parent":"root","name":"x","isDir":false,"size":1,"contentVersion":"cv-1-1","etag":"e","version":1,"updatedSeq":40,"deleted":false}],"cursor":40}
            """#)
        let (anchor, items, cursor) = try await client.changes(filespace: "fs", since: nil)
        XCTAssertEqual(anchor, 42)
        XCTAssertEqual(items.map(\.name), ["x"])
        XCTAssertEqual(cursor, 40)
        // No since on first poll.
        let req = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertFalse(query(req).contains { $0.name == "since" })
    }

    func testChangesForwardsSinceCursor() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/changes",
            json: #"{"anchor":42,"items":[],"cursor":null}"#)
        let (_, _, cursor) = try await client.changes(filespace: "fs", since: 40)
        XCTAssertNil(cursor)   // tail of feed
        let req = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertTrue(query(req).contains { $0.name == "since" && $0.value == "40" })
    }

    /// Audit (tombstone projection): the tombstone-aware feed splits deleted items
    /// into `deleted` so a sync consumer removes them instead of resurrecting them.
    func testChangesWithDeletionsSplitsTombstones() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/changes",
            json: #"""
            {"anchor":50,"items":[
              {"id":"root/live.mov","parent":"root","name":"live.mov","isDir":false,"size":1,"contentVersion":"cv","version":1,"updatedSeq":48,"deleted":false},
              {"id":"root/gone.mov","parent":"root","name":"gone.mov","isDir":false,"size":1,"contentVersion":"cv","version":2,"updatedSeq":49,"deleted":true}
            ],"cursor":null}
            """#)
        let (anchor, updated, deleted, cursor) = try await client.changesWithDeletions(filespace: "fs", since: nil)
        XCTAssertEqual(anchor, 50)
        XCTAssertEqual(updated.map(\.name), ["live.mov"])
        XCTAssertEqual(deleted, [InodeID("root/gone.mov")])
        XCTAssertNil(cursor)
    }

    // MARK: - Audit B1: createItem / deleteItem on the wire

    func testCreateItemPostsAndReturnsGatewayId() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/items",
            json: #"{"id":"root/new.mov","parent":"root","name":"new.mov","isDir":false,"size":0,"contentVersion":"cv0","version":1,"updatedSeq":5,"deleted":false}"#)
        let item = try await client.createItem(filespace: "fs", parent: "root", name: "new.mov", isDir: false, size: 0)
        XCTAssertEqual(item.id, InodeID("root/new.mov"))
        let req = try XCTUnwrap(StubURLProtocol.requests.first { $0.method == "POST" })
        XCTAssertTrue(req.url.path.hasSuffix("/items"))
    }

    func testDeleteItemSendsDelete() async throws {
        let client = makeClient()
        StubURLProtocol.on("DELETE /v1/filespaces/fs/items/root/x.mov", json: #"{"deleted":true}"#)
        try await client.deleteItem(filespace: "fs", id: "root/x.mov", recursive: false)
        let req = try XCTUnwrap(StubURLProtocol.requests.first { $0.method == "DELETE" })
        XCTAssertTrue(req.url.path.contains("/items/"))
    }

    // Audit B17: rename/move PATCHes /items/:id {parent?, name} and keeps the opaque id stable.
    func testRenameItemPatchesAndKeepsId() async throws {
        let client = makeClient()
        StubURLProtocol.on("PATCH /v1/filespaces/fs/items/ino-1",
            json: #"{"id":"ino-1","parent":"ino-dst","name":"renamed.mov","isDir":false,"size":7,"contentVersion":"cv","version":4,"updatedSeq":12,"deleted":false}"#)
        let moved = try await client.renameItem(filespace: "fs", id: "ino-1", newParent: "ino-dst", newName: "renamed.mov")
        XCTAssertEqual(moved.id, InodeID("ino-1")) // id stable across rename
        XCTAssertEqual(moved.name, "renamed.mov")
        XCTAssertEqual(moved.parent, InodeID("ino-dst"))
        let req = try XCTUnwrap(StubURLProtocol.requests.first { $0.method == "PATCH" })
        let body = try XCTUnwrap(req.body)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["name"] as? String, "renamed.mov")
        XCTAssertEqual(json["parent"] as? String, "ino-dst")
    }

    /// A pure rename (no move) sends a nil parent so the body omits it.
    func testRenameItemNilParentOmitsParent() async throws {
        let client = makeClient()
        StubURLProtocol.on("PATCH /v1/filespaces/fs/items/ino-2",
            json: #"{"id":"ino-2","parent":"root","name":"b.mov","isDir":false,"size":1,"contentVersion":"cv","version":2,"updatedSeq":3,"deleted":false}"#)
        _ = try await client.renameItem(filespace: "fs", id: "ino-2", newParent: nil, newName: "b.mov")
        let req = try XCTUnwrap(StubURLProtocol.requests.first { $0.method == "PATCH" })
        let json = try JSONSerialization.jsonObject(with: try XCTUnwrap(req.body)) as? [String: Any]
        XCTAssertNil(json?["parent"] ?? nil, "a pure rename omits parent (nil)")
    }

    // MARK: - Audit B4: CAS commit threads expectedVersion + fence

    func testPutBlockManifestThreadsExpectedVersionAndFence() async throws {
        let client = makeClient()
        StubURLProtocol.on("PUT /v1/filespaces/fs/blocks/root/cut.mov",
            json: #"{"id":"root/cut.mov","parent":"root","name":"cut.mov","isDir":false,"size":4,"contentVersion":"cv2","version":3,"updatedSeq":9,"deleted":false}"#)
        let manifest = BlockManifest(itemID: "root/cut.mov",
                                     blocks: [BlockRef(hash: BlockHash(hex: "ab"), offset: 0, length: 4)],
                                     contentVersion: "")
        _ = try await client.putBlockManifest(manifest, filespace: "fs", expectedVersion: 2, fence: 7)
        let req = try XCTUnwrap(StubURLProtocol.requests.first { $0.method == "PUT" })
        let body = try XCTUnwrap(req.body)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["expectedVersion"] as? Int, 2)
        XCTAssertEqual(json["fence"] as? Int, 7)
    }

    /// A 409 from the CAS commit maps to `.conflict` with expected/actual surfaced.
    func testCasConflictMapsToConflict() async {
        let client = makeClient()
        StubURLProtocol.on("PUT /v1/filespaces/fs/blocks/root/cut.mov", status: 409,
            json: #"{"error":"version conflict","conflict":true,"expected":2,"actual":5}"#)
        let manifest = BlockManifest(itemID: "root/cut.mov",
                                     blocks: [BlockRef(hash: BlockHash(hex: "ab"), offset: 0, length: 4)],
                                     contentVersion: "")
        do {
            _ = try await client.putBlockManifest(manifest, filespace: "fs", expectedVersion: 2, fence: nil)
            XCTFail("expected conflict")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .conflict)
        } catch { XCTFail("wrong error: \(error)") }
    }

    // MARK: token refresh — provider is consulted per request

    func testTokenProviderConsultedPerRequest() async throws {
        StubURLProtocol.reset()
        let counter = TokenCounter()
        let cfg = GatewayClientConfig(baseURL: "https://gw.test") { await counter.next() }
        let client = HttpGatewayClient(config: cfg, session: .stubbed())
        StubURLProtocol.on("GET /v1/filespaces/fs/items/x",
            json: #"{"id":"x","parent":"root","name":"x","isDir":false,"size":0,"contentVersion":"cv","etag":null,"version":1,"updatedSeq":1,"deleted":false}"#)

        _ = try await client.getItem(filespace: "fs", id: "x")
        _ = try await client.getItem(filespace: "fs", id: "x")

        let reqs = StubURLProtocol.requests
        XCTAssertEqual(reqs[0].headers["Authorization"], "Bearer tok-1")
        XCTAssertEqual(reqs[1].headers["Authorization"], "Bearer tok-2")
    }
}

/// Issues a fresh "tok-N" each call so token-refresh can be observed.
private actor TokenCounter {
    private var n = 0
    func next() -> String { n += 1; return "tok-\(n)" }
}

extension CloudFSGatewayTests {
    func testLeaseTransportIncludesUniqueClientIdentityAndFencedRelease() async throws {
        let client = makeClient()
        let other = HttpGatewayClient(config: client.config, session: .stubbed())
        XCTAssertNotEqual(client.clientID, other.clientID)
        StubURLProtocol.on("POST /v1/filespaces/fs/locks", json: #"{"granted":true,"path":"inode","purpose":"publication","fence":17,"expiresAt":1234567890000}"#)
        StubURLProtocol.on("DELETE /v1/filespaces/fs/locks", json: #"{"released":true}"#)
        let lease = try await client.acquireFileLease(filespace: "fs", id: InodeID("inode"), ttlMs: 60_000, purpose: .publication)
        XCTAssertEqual(lease.fence, 17)
        XCTAssertEqual(lease.purpose, .publication)
        _ = try await client.renewFileLease(filespace: "fs", id: InodeID("inode"), fence: 17, ttlMs: 60_000)
        try await client.releaseFileLease(filespace: "fs", id: InodeID("inode"), fence: 17)
        for request in StubURLProtocol.requests {
            XCTAssertEqual(request.headers.first { $0.key.lowercased() == "x-cloudfs-client-id" }?.value, client.clientID)
        }
        let acquisition = try XCTUnwrap(StubURLProtocol.requests[0].body)
        let acquisitionBody = try JSONSerialization.jsonObject(with: acquisition) as! [String: Any]
        XCTAssertEqual(acquisitionBody["purpose"] as? String, "publication")
        XCTAssertNil(acquisitionBody["includeItem"], "the legacy lease call must preserve its original wire shape")
        let renewal = try XCTUnwrap(StubURLProtocol.requests[1].body)
        let body = try JSONSerialization.jsonObject(with: renewal) as! [String: Any]
        XCTAssertEqual(body["fence"] as? Int, 17); XCTAssertEqual(body["renew"] as? Bool, true)
        XCTAssertEqual(query(StubURLProtocol.requests[2]).first { $0.name == "fence" }?.value, "17")
    }
    func testNewObjectPresignDeclaresOwningInode() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/presign", json: #"{"url":"https://bucket.test/object","expiresIn":300}"#)
        _ = try await client.presignWrite(filespace: "fs", key: "blocks/org::fs/hash", itemID: InodeID("edited-file"), expiresIn: nil)
        let body = try JSONSerialization.jsonObject(with: XCTUnwrap(StubURLProtocol.requests.last?.body)) as! [String: Any]
        XCTAssertEqual(body["itemId"] as? String, "edited-file")
        XCTAssertEqual(body["method"] as? String, "PUT")
    }
    func testLockedCommitPreservesTypedConflictAndHolder() async throws {
        let client = makeClient()
        StubURLProtocol.on("PUT /v1/filespaces/fs/blocks/inode", status: 409,
                           json: #"{"error":"locked","locked":true,"heldBy":"other-device","reason":"fence-stale"}"#)
        do {
            _ = try await client.putBlockManifest(BlockManifest(itemID: InodeID("inode"), blocks: [], contentVersion: ""),
                                                  filespace: "fs", expectedVersion: 1, fence: 2)
            XCTFail("expected lock refusal")
        } catch let error as EngineError {
            XCTAssertEqual(error.kind, .locked)
            XCTAssertEqual(error.data?["heldBy"], .string("other-device"))
        }
    }
}

extension CloudFSGatewayTests {
    func testImmutableUploadContractPreservesRequiredHeadersAndVerificationURL() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/presign", json:#"{"url":"https://bucket.test/put","expiresIn":300,"headers":{"if-none-match":"*","x-amz-checksum-sha256":"digest"},"verificationUrl":"https://bucket.test/get"}"#)
        let result=try await client.presignWrite(filespace:"fs",key:"blocks/org::fs/hash",itemID:InodeID("inode"),expiresIn:nil)
        XCTAssertEqual(result.headers?["if-none-match"],"*")
        XCTAssertEqual(result.headers?["x-amz-checksum-sha256"],"digest")
        XCTAssertEqual(result.verificationUrl,"https://bucket.test/get")
    }
}

extension CloudFSGatewayTests {
    func testBatchPresignRetainsImmutableUploadContract() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/fs/presign/batch",json:#"{"urls":[{"key":"block","url":"https://bucket.test/put","headers":{"if-none-match":"*"},"verificationUrl":"https://bucket.test/get"}],"expiresIn":300}"#)
        let results=try await client.presignBatch(filespace:"fs",keys:[(key:"block",method:.PUT)],expiresIn:nil)
        XCTAssertEqual(results.first?.headers?["if-none-match"],"*")
        XCTAssertEqual(results.first?.verificationUrl,"https://bucket.test/get")
    }
}
