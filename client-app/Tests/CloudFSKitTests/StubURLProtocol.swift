// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - StubURLProtocol
//
// A URLProtocol that answers requests from an in-memory route table, so
// HttpGatewayClient can be tested with responses shaped per API.md WITHOUT a live
// server. Register handlers keyed by "METHOD path"; each returns (status, json).

final class StubURLProtocol: URLProtocol, @unchecked Sendable {

    struct Stub { let status: Int; let json: String; let headers: [String: String] }

    // Route table is per-process; guarded so test cases can set it serially.
    nonisolated(unsafe) private static var routes: [String: (URLRequest) -> Stub] = [:]
    nonisolated(unsafe) private static var recorded: [URLRequest] = []
    // Captured request bodies keyed by "METHOD path" (last one wins). URLSession
    // delivers bodies as httpBodyStream, so we read+record them here.
    nonisolated(unsafe) private static var bodies: [String: Data] = [:]
    private static let lock = NSLock()

    static func reset() {
        lock.lock(); defer { lock.unlock() }
        routes = [:]; recorded = []; bodies = [:]
    }

    /// The recorded JSON body for the given "METHOD /path", if any.
    static func body(for key: String) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return bodies[key]
    }

    /// Register a handler. `key` is "METHOD /path" (path only, no host/query).
    static func on(_ key: String, _ handler: @escaping (URLRequest) -> Stub) {
        lock.lock(); defer { lock.unlock() }
        routes[key] = handler
    }

    static func on(_ key: String, status: Int = 200, json: String, headers: [String: String] = [:]) {
        on(key) { _ in Stub(status: status, json: json, headers: headers) }
    }

    static var requests: [URLRequest] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }

    static func lookup(_ req: URLRequest) -> Stub? {
        lock.lock(); defer { lock.unlock() }
        recorded.append(req)
        let method = req.httpMethod ?? "GET"
        let path = req.url?.path ?? ""
        let key = "\(method) \(path)"
        // Capture the body (httpBody or, more commonly under URLSession, the stream).
        if let data = req.httpBody {
            bodies[key] = data
        } else if let stream = req.httpBodyStream {
            bodies[key] = Self.readStream(stream)
        }
        return routes[key].map { $0(req) }
    }

    private static func readStream(_ stream: InputStream) -> Data {
        stream.open(); defer { stream.close() }
        var data = Data()
        let bufSize = 4096
        var buf = [UInt8](repeating: 0, count: bufSize)
        while stream.hasBytesAvailable {
            let n = stream.read(&buf, maxLength: bufSize)
            if n > 0 { data.append(buf, count: n) } else { break }
        }
        return data
    }

    // MARK: URLProtocol

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let stub = Self.lookup(request) else {
            let resp = HTTPURLResponse(url: request.url!, statusCode: 404,
                                       httpVersion: "HTTP/1.1", headerFields: nil)!
            client?.urlProtocol(self, didReceive: resp, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(#"{"error":"not found"}"#.utf8))
            client?.urlProtocolDidFinishLoading(self)
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
    /// A session whose only protocol is the stub — no real network access.
    static func stubbed() -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [StubURLProtocol.self]
        return URLSession(configuration: cfg)
    }
}
