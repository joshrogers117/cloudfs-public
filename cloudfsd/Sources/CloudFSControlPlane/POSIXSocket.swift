// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSControlPlane — thin POSIX Unix-domain-socket wrappers (CONTROL-API.md §1).
//
// Just enough of the C socket API, surfaced as throwing Swift, to bind/listen/
// accept on an `AF_UNIX` stream socket and to read/write raw bytes on a connection
// FD. The server (Server.swift) layers framing + dispatch on top. We also accept
// a pre-connected FD (e.g. one half of `socketpair()`) so tests drive the read
// loop in-process with no filesystem socket at all.

import Foundation
#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

/// A raw connection file descriptor. Closing is idempotent and thread-safe enough
/// for our single-owner-per-connection use (the read loop owns reads; writes are
/// serialized through the connection's writer).
final class SocketFD: @unchecked Sendable {
    let fd: Int32
    private let closed = NSLock()
    private var isClosed = false

    init(_ fd: Int32) throws {
        #if !canImport(Glibc)
        // A GUI/Finder client can disconnect while a reply is in flight. Keep
        // that EPIPE local to the connection instead of terminating the daemon.
        var one: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one,
                         socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            let error = errno
            _ = cfs_close(fd)
            throw POSIXSocketError.errno("setsockopt(SO_NOSIGPIPE)", error)
        }
        #endif
        self.fd = fd
    }

    /// Read up to `max` bytes. Returns [] on clean EOF, throws on hard error.
    /// Retries `EINTR`.
    func read(max: Int = 64 * 1024) throws -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: max)
        while true {
            let n = buf.withUnsafeMutableBytes { ptr in
                cfs_read(fd, ptr.baseAddress, max)
            }
            if n < 0 {
                if errno == EINTR { continue }
                throw POSIXSocketError.errno("read", errno)
            }
            if n == 0 { return [] }  // EOF
            return Array(buf[0..<n])
        }
    }

    /// Write all of `bytes`, looping over short writes. Retries `EINTR`.
    func writeAll(_ bytes: [UInt8]) throws {
        guard !bytes.isEmpty else { return }
        var off = 0
        try bytes.withUnsafeBytes { raw in
            let base = raw.baseAddress!
            while off < bytes.count {
                let n = cfs_write(fd, base + off, bytes.count - off)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw POSIXSocketError.errno("write", errno)
                }
                if n == 0 { throw POSIXSocketError.errno("write", EPIPE) }
                off += n
            }
        }
    }

    func close() {
        closed.lock(); defer { closed.unlock() }
        if isClosed { return }
        isClosed = true
        _ = cfs_close(fd)
    }
}

enum POSIXSocketError: Error, CustomStringConvertible {
    case errno(String, Int32)
    case message(String)
    var description: String {
        switch self {
        case let .errno(op, e): return "\(op): \(String(cString: strerror(e))) (errno \(e))"
        case let .message(m):   return m
        }
    }
}

/// An `AF_UNIX` listening socket bound at `path`, mode `0600`.
final class UnixListener: @unchecked Sendable {
    let fd: Int32
    let path: String

    /// Bind + listen. Removes any stale socket file at `path` first. Sets mode 0600
    /// so filesystem permissions are the auth for the local channel (§1).
    init(path: String, backlog: Int32 = 64) throws {
        guard path.utf8.count < 104 else {  // sun_path is 104 on Darwin (incl. NUL)
            throw POSIXSocketError.message("socket path too long (>103 bytes): \(path)")
        }
        // Ensure the parent directory exists (only create when missing — calling
        // createDirectory unconditionally can stall on some mounts).
        let dir = (path as NSString).deletingLastPathComponent
        if !dir.isEmpty {
            var isDir: ObjCBool = false
            let exists = FileManager.default.fileExists(atPath: dir, isDirectory: &isDir)
            if !(exists && isDir.boolValue) {
                try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            }
        }
        unlink(path)  // clear a stale socket; ignore ENOENT

        let s = socket(AF_UNIX, cfs_sock_stream, 0)
        guard s >= 0 else { throw POSIXSocketError.errno("socket", errno) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)  // NUL terminator already present (zeroed)
        }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bindRC = withUnsafePointer(to: &addr) { ap in
            ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
                bind(s, sp, size)
            }
        }
        guard bindRC == 0 else {
            let e = errno; _ = cfs_close(s); throw POSIXSocketError.errno("bind", e)
        }
        // Restrict to the owning user before anyone can connect.
        chmod(path, 0o600)
        guard listen(s, backlog) == 0 else {
            let e = errno; _ = cfs_close(s); unlink(path); throw POSIXSocketError.errno("listen", e)
        }
        self.fd = s
        self.path = path
    }

    /// Block until a client connects; returns its connection FD. Retries `EINTR`.
    /// Throws when the listener has been closed (so the accept loop can exit).
    func accept() throws -> SocketFD {
        while true {
            let c = cfs_accept(fd, nil, nil)
            if c < 0 {
                if errno == EINTR || errno == ECONNABORTED { continue }
                throw POSIXSocketError.errno("accept", errno)
            }
            // On Darwin, configuring a peer that already disconnected can fail
            // with EINVAL. SocketFD closes that accepted FD; reject only that
            // connection and keep accepting clients on the healthy listener.
            do { return try SocketFD(c) }
            catch { continue }
        }
    }

    func close() {
        _ = cfs_close(fd)
        unlink(path)
    }
}

// Small indirections so the same source compiles against Darwin and Glibc without
// `#if` at every call site, and so `socket`/`read` are unambiguous.
#if canImport(Glibc)
private let cfs_sock_stream = Int32(SOCK_STREAM.rawValue)
#else
private let cfs_sock_stream = SOCK_STREAM
#endif

@inline(__always) private func cfs_read(_ fd: Int32, _ buf: UnsafeMutableRawPointer?, _ n: Int) -> Int {
    read(fd, buf, n)
}
@inline(__always) private func cfs_write(_ fd: Int32, _ buf: UnsafeRawPointer?, _ n: Int) -> Int {
    #if canImport(Glibc)
    send(fd, buf, n, Int32(MSG_NOSIGNAL))
    #else
    write(fd, buf, n)
    #endif
}
@inline(__always) private func cfs_close(_ fd: Int32) -> Int32 { close(fd) }
@inline(__always) private func cfs_accept(_ fd: Int32, _ a: UnsafeMutablePointer<sockaddr>?, _ l: UnsafeMutablePointer<socklen_t>?) -> Int32 {
    accept(fd, a, l)
}

/// Run a blocking body on a fresh, dedicated OS thread. Blocking `accept`/`read`
/// syscalls MUST NOT run on the Swift cooperative thread pool — it has only a few
/// threads and parking them on a syscall starves all other async work (and can
/// deadlock when listener, connections, and the peer all block at once). A real
/// thread per long-lived blocking loop keeps the cooperative pool free.
func runOnBlockingThread(name: String, _ body: @escaping @Sendable () -> Void) {
    let t = Thread { body() }
    t.name = name
    t.stackSize = 512 * 1024
    t.start()
}

/// Create a connected `AF_UNIX` stream pair (for in-process tests + the GUI bridge).
func makeSocketPair() throws -> (SocketFD, SocketFD) {
    var fds = [Int32](repeating: 0, count: 2)
    let rc = fds.withUnsafeMutableBufferPointer { p in
        socketpair(AF_UNIX, cfs_sock_stream, 0, p.baseAddress)
    }
    guard rc == 0 else { throw POSIXSocketError.errno("socketpair", errno) }
    let first: SocketFD
    do { first = try SocketFD(fds[0]) }
    catch { _ = cfs_close(fds[1]); throw error }
    do { return (first, try SocketFD(fds[1])) }
    catch { first.close(); throw error }
}
