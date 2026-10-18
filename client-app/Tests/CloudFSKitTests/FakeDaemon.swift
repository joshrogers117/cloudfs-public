// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
@testable import CloudFSKit

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// MARK: - FakeDaemon
//
// An in-process fake cloudfsd: binds a temp Unix-domain socket, accepts ONE
// client connection, reads newline-delimited JSON-RPC requests, and replies via a
// route table — and can push id-less event notifications. This lets us test
// DaemonEngineClient's framing, a method round-trip, error mapping, and event
// delivery with NO real daemon. Pure POSIX so there are no dependencies.

final class FakeDaemon: @unchecked Sendable {

    let path: String
    private var listenFD: Int32 = -1
    private var clientFD: Int32 = -1
    private var thread: Thread?
    private let lock = NSLock()

    /// method → handler that returns the raw JSON for `result` (or nil to emit an
    /// error). For an error, set `errorFor[method]`.
    private var resultFor: [String: @Sendable (JSONValue) -> String] = [:]
    private var errorFor: [String: String] = [:]   // method → error JSON body (e.g. {"code":-32021,...})
    /// Notifications to push after a given request method arrives.
    private var pushAfter: [String: [String]] = [:]
    private var closeAfter: Set<String> = []
    private var requestCounts: [String: Int] = [:]
    private var acceptedConnections = 0
    private var clientDidDisconnect: (@Sendable () -> Void)?

    init() {
        // Keep the path short (sun_path ≤ 104) — /tmp, not the long temp dir.
        self.path = "/tmp/cfs-fake-\(UUID().uuidString.prefix(8)).sock"
    }

    // MARK: Configuration (call before start)

    func onResult(_ method: String, _ handler: @escaping @Sendable (JSONValue) -> String) {
        lock.lock(); resultFor[method] = handler; lock.unlock()
    }
    func onResult(_ method: String, json: String) {
        onResult(method) { _ in json }
    }
    func onError(_ method: String, errorJSON: String) {
        lock.lock(); errorFor[method] = errorJSON; lock.unlock()
    }
    /// After receiving `method`, push these notification lines (full JSON-RPC
    /// notification objects, no trailing newline needed).
    func pushNotifications(after method: String, _ notifications: [String]) {
        lock.lock(); pushAfter[method] = notifications; lock.unlock()
    }

    func onClientDisconnect(_ callback: @escaping @Sendable () -> Void) {
        lock.withLock { clientDidDisconnect = callback }
    }
    func closeClient(after method: String) {
        lock.withLock { _ = closeAfter.insert(method) }
    }
    func requestCount(_ method: String) -> Int { lock.withLock { requestCounts[method, default: 0] } }
    var connectionCount: Int { lock.withLock { acceptedConnections } }

    // MARK: Lifecycle

    func start() throws {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Err.fail("socket") }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            path.withCString { cs in
                ptr.withMemoryRebound(to: CChar.self, capacity: maxLen) { dst in
                    strncpy(dst, cs, maxLen - 1)
                }
            }
        }
        let bindResult = withUnsafePointer(to: &addr) { a in
            a.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else { close(fd); throw Err.fail("bind: \(String(cString: strerror(errno)))") }
        guard listen(fd, 1) == 0 else { close(fd); throw Err.fail("listen") }
        listenFD = fd

        let t = Thread { [weak self] in self?.serve(listeningFD: fd) }
        t.name = "fake.daemon"
        t.stackSize = 512 * 1024
        thread = t
        t.start()
    }

    func stop() {
        lock.withLock {
            stopped = true
            // The serving thread owns both closes. Shutdown wakes blocking I/O;
            // a second close after fd reuse could destroy another test's socket.
            if clientFD >= 0 { _ = shutdown(clientFD, SHUT_RDWR) }
            if listenFD >= 0 { _ = shutdown(listenFD, SHUT_RDWR) }
        }
        unlink(path)
    }

    /// Drop the peer without transferring descriptor ownership out of serve().
    func dropClient() {
        lock.withLock {
            if clientFD >= 0 { _ = shutdown(clientFD, SHUT_RDWR) }
        }
    }

    private var stopped = false

    // MARK: Serve loop

    private func serve(listeningFD: Int32) {
        defer {
            lock.withLock {
                if listenFD == listeningFD { listenFD = -1 }
                close(listeningFD)
            }
        }
        // Accept connections sequentially: when one client drops (EOF or
        // `dropClient()`), loop back and accept the next. This lets a client
        // reconnect after the peer drops, exercising the reconnect path.
        while true {
            let cfd = accept(listeningFD, nil, nil)
            guard cfd >= 0 else { return }   // listen fd closed by stop()
            lock.lock()
            if stopped { lock.unlock(); close(cfd); return }
            clientFD = cfd
            acceptedConnections += 1
            lock.unlock()
            #if canImport(Darwin)
            var noSignal: Int32 = 1
            _ = setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
            #endif

            var buffer = Data()
            let chunkSize = 8 * 1024
            var chunk = [UInt8](repeating: 0, count: chunkSize)
            while true {
                let n = chunk.withUnsafeMutableBytes { read(cfd, $0.baseAddress, chunkSize) }
                if n <= 0 { break }
                buffer.append(contentsOf: chunk[0..<n])
                while let nl = buffer.firstIndex(of: 0x0A) {
                    let line = buffer.subdata(in: buffer.startIndex..<nl)
                    buffer.removeSubrange(buffer.startIndex...nl)
                    if !line.isEmpty { handleLine(line, cfd: cfd) }
                }
            }
            // This client ended; close our side and loop to accept the next.
            lock.lock()
            if clientFD == cfd { clientFD = -1 }
            let wasStopped = stopped
            let disconnected = clientDidDisconnect
            close(cfd)
            lock.unlock()
            disconnected?()
            if wasStopped { return }
        }
    }

    private func handleLine(_ line: Data, cfd: Int32) {
        guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              let method = obj["method"] as? String else { return }
        let id = obj["id"]
        let params = (obj["params"] as? [String: Any]) ?? [:]
        let paramsValue = (try? JSONValue(jsonObject: params)) ?? .object([:])

        lock.lock()
        let errBody = errorFor[method]
        let resultHandler = resultFor[method]
        let notes = pushAfter[method] ?? []
        let shouldClose = closeAfter.contains(method)
        requestCounts[method, default: 0] += 1
        lock.unlock()

        // Reply (if this is a request, i.e. has id).
        if let id {
            let idJSON = jsonForID(id)
            let response: String
            if let errBody {
                response = #"{"jsonrpc":"2.0","id":\#(idJSON),"error":\#(errBody)}"#
            } else if let resultHandler {
                response = #"{"jsonrpc":"2.0","id":\#(idJSON),"result":\#(resultHandler(paramsValue))}"#
            } else {
                response = #"{"jsonrpc":"2.0","id":\#(idJSON),"result":{}}"#
            }
            writeLine(response, cfd: cfd)
        }
        // Push any configured notifications.
        for note in notes { writeLine(note, cfd: cfd) }
        if shouldClose { _ = shutdown(cfd, SHUT_RDWR) }
    }

    private func jsonForID(_ id: Any) -> String {
        if let i = id as? Int { return String(i) }
        if let s = id as? String { return "\"\(s)\"" }
        if let n = id as? NSNumber { return n.stringValue }
        return "null"
    }

    private func writeLine(_ s: String, cfd: Int32) {
        var data = Data(s.utf8)
        data.append(0x0A)
        data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var off = 0
            while off < raw.count {
                let w = write(cfd, base.advanced(by: off), raw.count - off)
                if w > 0 { off += w } else { break }
            }
        }
    }

    enum Err: Error { case fail(String) }
}

// Build a JSONValue from a Foundation JSON object (for echoing params in handlers).
private extension JSONValue {
    init(jsonObject: Any) throws {
        let data = try JSONSerialization.data(withJSONObject: jsonObject)
        self = try JSONDecoder().decode(JSONValue.self, from: data)
    }
}
