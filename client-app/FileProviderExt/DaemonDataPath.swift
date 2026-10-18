// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

#if canImport(Darwin)
import Darwin
#endif

// MARK: - Wire types (mirror cloudfsd CONTROL-API §7 data-path results)
//
// The appex is a separate process from the daemon, so it can't share the Swift
// `CloudFSCore` types directly — these Codable mirrors match the daemon's JSON exactly.
// FD-passing over JSON is impossible across processes, so `WireRange` only ever carries
// a `path` (the daemon materializes the decrypted bytes into the App Group container).

struct WireItem: Decodable {
    let id: String
    let parent: String?
    let name: String
    let isDir: Bool
    let size: Int
    let contentVersion: String
    let metadataVersion: String
}

struct WireRange: Decodable {
    let path: String?
    let fd: Int32?
    let offset: Int
    let length: Int
}

struct WireEnumerate: Decodable {
    let items: [WireItem]
    let nextPage: String?
}

struct WireChanges: Decodable {
    let updated: [WireItem]
    let deleted: [String]
    let newAnchor: String
    let moreComing: Bool
}

// MARK: - Blocking JSON-RPC over a Unix-domain socket
//
// File Provider fetch/enumerate work runs on a background queue behind a completion
// handler, so a *blocking* request/response client is the natural fit — no actor, no
// async bridging. One short-lived connection per call keeps the sandboxed extension
// stateless (no reconnect logic, no shared fd): the cost is a local UDS connect, which
// is negligible next to an R2 fetch.

enum DaemonError: LocalizedError {
    case connect(String)
    case io(String)
    case server(code: Int, message: String)
    case decode(String)
    case noPath

    var errorDescription: String? {
        switch self {
        case .connect(let m): return "daemon connect failed: \(m)"
        case .io(let m):      return "daemon io: \(m)"
        case .server(let c, let m): return "daemon error \(c): \(m)"
        case .decode(let m):  return "daemon decode: \(m)"
        case .noPath:         return "daemon returned no materialized path"
        }
    }
}

struct DaemonRPC {
    let socketPath: String

    /// Send one request, block for the correlated response, decode `result` into `R`.
    func call<R: Decodable>(_ method: String, _ params: [String: JSON], as: R.Type) throws -> R {
        let fd = try open()
        defer { close(fd) }

        let req = JSON.object([
            "jsonrpc": .string("2.0"),
            "id": .int(1),
            "method": .string(method),
            "params": .object(params),
        ])
        var payload = try JSONEncoder().encode(req)
        payload.append(0x0A)   // newline frame
        try writeAll(fd, payload)

        let line = try readLine(fd)
        let frame: RPCResult<R>
        do { frame = try JSONDecoder().decode(RPCResult<R>.self, from: line) }
        catch { throw DaemonError.decode("\(method): \(error)") }

        if let e = frame.error { throw DaemonError.server(code: e.code, message: e.message) }
        guard let result = frame.result else { throw DaemonError.decode("\(method): missing result") }
        return result
    }

    private struct RPCResult<R: Decodable>: Decodable {
        let result: R?
        let error: RPCErr?
    }
    private struct RPCErr: Decodable { let code: Int; let message: String }

    // MARK: POSIX socket plumbing

    private func open() throws -> Int32 {
        let maxLen = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
        guard socketPath.utf8.count < maxLen else {
            throw DaemonError.connect("socket path too long (\(socketPath.utf8.count) ≥ \(maxLen))")
        }
        let sock = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { throw DaemonError.connect(String(cString: strerror(errno))) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            socketPath.withCString { cstr in
                ptr.withMemoryRebound(to: CChar.self, capacity: maxLen) { dst in
                    strncpy(dst, cstr, maxLen - 1)
                }
            }
        }
        let rc = withUnsafePointer(to: &addr) { aptr in
            aptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saptr in
                Darwin.connect(sock, saptr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else {
            let msg = String(cString: strerror(errno))
            Darwin.close(sock)
            throw DaemonError.connect("connect(\(socketPath)): \(msg)")
        }
        return sock
    }

    private func close(_ fd: Int32) { _ = Darwin.close(fd) }

    private func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            var off = 0
            while off < raw.count {
                let n = Darwin.write(fd, base.advanced(by: off), raw.count - off)
                if n > 0 { off += n; continue }
                if n < 0 && errno == EINTR { continue }
                throw DaemonError.io("write: \(String(cString: strerror(errno)))")
            }
        }
    }

    /// Read until the first newline frame terminator (the daemon writes one JSON object
    /// per line). Bounded buffer growth; throws on EOF before a complete line.
    private func readLine(_ fd: Int32) throws -> Data {
        var buf = Data()
        var chunk = [UInt8](repeating: 0, count: 16 * 1024)
        while true {
            let n = chunk.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if n > 0 {
                buf.append(contentsOf: chunk[0..<n])
                if let nl = buf.firstIndex(of: 0x0A) { return buf.subdata(in: buf.startIndex..<nl) }
            } else if n == 0 {
                throw DaemonError.io("eof before response")
            } else {
                if errno == EINTR { continue }
                throw DaemonError.io("read: \(String(cString: strerror(errno)))")
            }
        }
    }
}

// MARK: - Typed data-path facade (one per filespace/domain)

/// The appex's view of the daemon for a single filespace. Maps File Provider operations
/// onto the daemon's out-of-process data-path RPCs (CONTROL-API §7).
struct DaemonDataPath {
    let filespace: String
    let rpc: DaemonRPC

    init(filespace: String, socketPath: String = CloudFSAppGroup.daemonSocketPath) {
        self.filespace = filespace
        self.rpc = DaemonRPC(socketPath: socketPath)
    }

    func lookup(_ itemId: String) throws -> WireItem {
        try rpc.call("data.lookup", ["filespace": .string(filespace), "itemId": .string(itemId)],
                     as: WireItem.self)
    }

    func enumerate(container: String, page: String?) throws -> WireEnumerate {
        var p: [String: JSON] = ["filespace": .string(filespace), "container": .string(container)]
        if let page { p["page"] = .string(page) }
        return try rpc.call("data.enumerate", p, as: WireEnumerate.self)
    }

    func enumerateChanges(container: String, anchor: String) throws -> WireChanges {
        try rpc.call("data.enumerateChanges",
                     ["filespace": .string(filespace), "container": .string(container),
                      "anchor": .string(anchor)],
                     as: WireChanges.self)
    }

    func readRange(itemId: String, version: String, offset: Int, length: Int, alignment: Int) throws -> WireRange {
        try rpc.call("data.readRange",
                     ["filespace": .string(filespace), "itemId": .string(itemId),
                      "version": .string(version), "offset": .int(offset),
                      "length": .int(length), "alignment": .int(alignment)],
                     as: WireRange.self)
    }
}

// MARK: - Minimal JSON value (encode requests / build params)

/// A tiny encodable JSON tree — just enough to build request params. (Responses use
/// concrete Decodable types above, so no general decoder is needed here.)
indirect enum JSON: Encodable {
    case string(String)
    case int(Int)
    case bool(Bool)
    case object([String: JSON])
    case array([JSON])
    case null

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .int(let i):    try c.encode(i)
        case .bool(let b):   try c.encode(b)
        case .object(let o): try c.encode(o)
        case .array(let a):  try c.encode(a)
        case .null:          try c.encodeNil()
        }
    }
}
