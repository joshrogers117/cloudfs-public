// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

// POSIX socket calls are qualified through these thin wrappers so they are never
// shadowed by Foundation's instance methods (e.g. `close(_:)`). On Darwin the
// global functions live in `Darwin`, on Linux in `Glibc`.
@inline(__always) private func posixSocket(_ d: Int32, _ t: Int32, _ p: Int32) -> Int32 {
    #if canImport(Darwin)
    return Darwin.socket(d, t, p)
    #else
    return Glibc.socket(d, t, p)
    #endif
}
@inline(__always) private func posixConnect(_ s: Int32, _ a: UnsafePointer<sockaddr>, _ l: socklen_t) -> Int32 {
    #if canImport(Darwin)
    return Darwin.connect(s, a, l)
    #else
    return Glibc.connect(s, a, l)
    #endif
}
@inline(__always) private func posixClose(_ fd: Int32) {
    #if canImport(Darwin)
    _ = Darwin.close(fd)
    #else
    _ = Glibc.close(fd)
    #endif
}
@inline(__always) private func posixWrite(_ fd: Int32, _ buf: UnsafeRawPointer, _ n: Int) -> Int {
    #if canImport(Darwin)
    return Darwin.write(fd, buf, n)
    #else
    return Glibc.write(fd, buf, n)
    #endif
}
@inline(__always) private func posixRead(_ fd: Int32, _ buf: UnsafeMutableRawPointer?, _ n: Int) -> Int {
    #if canImport(Darwin)
    return Darwin.read(fd, buf, n)
    #else
    return Glibc.read(fd, buf, n)
    #endif
}

// MARK: - UnixSocketConnection
//
// A minimal newline-delimited JSON-RPC 2.0 client over an AF_UNIX stream socket.
// It owns one fd, a background reader that splits on `\n`, correlates responses
// to pending requests by `id`, and routes id-less notifications to a handler.
//
// This is deliberately POSIX-level (socket/connect/read/write) so it has zero
// dependencies and is testable against any UDS path — including an in-process
// temp-socket fake responder (see the tests). The same wire works whether the
// peer is the real cloudfsd or the test fake.
//
// Concurrency: an `actor` guards all mutable state (the fd, the id counter, the
// pending-request table). The blocking POSIX reads run on a detached thread and
// hand complete lines back into the actor.

actor UnixSocketConnection {

    private let path: String
    private var fd: Int32 = -1
    private var nextID = 0
    private var pending: [Int: CheckedContinuation<RPCFrame, Error>] = [:]
    private var readerThread: Thread?
    private var isOpen = false
    private var generation: UInt64 = 0

    /// Handler for server→client notifications (id-less frames). Set before
    /// subscribing to the event stream.
    private var notificationHandler: (@Sendable (RPCFrame, UInt64) async -> Void)?
    private var closeHandler: (@Sendable (UInt64) async -> Void)?

    init(path: String) {
        self.path = path
    }

    deinit {
        // App-level client replacement may drop an idle connection without an
        // explicit disconnect. Wake its reader; the bridge still owns the close.
        if fd >= 0 { _ = shutdown(fd, SHUT_RDWR) }
    }

    /// Whether the underlying fd is currently open. Flips to `false` the moment
    /// the reader thread sees EOF/error (`readerDidEnd` → `close`), so callers can
    /// detect a dropped peer (daemon restart/crash) and reconnect.
    var isConnectionOpen: Bool { isOpen }

    // MARK: Lifecycle

    /// Connect to the socket. Throws `.unavailable` if the socket is absent or
    /// refuses — the GUI analog of CLI exit 42 (a transport condition).
    @discardableResult
    func connect(notificationHandler: @escaping @Sendable (RPCFrame, UInt64) async -> Void,
                 closeHandler: @escaping @Sendable (UInt64) async -> Void = { _ in }) throws -> UInt64 {
        guard !isOpen else { return generation }

        // sockaddr_un.sun_path is bounded (104 on Darwin); guard up-front.
        let maxPathLen = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
        guard path.utf8.count < maxPathLen else {
            throw EngineError.unavailable("socket path too long (\(path.utf8.count) ≥ \(maxPathLen))")
        }

        let sock = posixSocket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw EngineError.unavailable("socket() failed: \(String(cString: strerror(errno)))")
        }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            path.withCString { cstr in
                ptr.withMemoryRebound(to: CChar.self, capacity: maxPathLen) { dst in
                    strncpy(dst, cstr, maxPathLen - 1)
                }
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { aptr in
            aptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saptr in
                posixConnect(sock, saptr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            let msg = String(cString: strerror(errno))
            posixClose(sock)
            throw EngineError.unavailable("connect(\(path)) failed: \(msg)")
        }

        #if canImport(Darwin)
        var noSignal: Int32 = 1
        _ = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
        #endif
        fd = sock
        generation &+= 1
        self.notificationHandler = notificationHandler
        self.closeHandler = closeHandler
        isOpen = true
        startReader()
        return generation
    }

    /// Close the connection and fail any in-flight requests.
    func close() {
        guard isOpen else { return }
        isOpen = false
        // The reader bridge owns close(fd). Shutdown wakes its blocking read without
        // allowing this descriptor number to be reused while that thread uses it.
        if fd >= 0 { _ = shutdown(fd, SHUT_RDWR); fd = -1 }
        for (_, cont) in pending { cont.resume(throwing: EngineError.unavailable("connection closed")) }
        pending.removeAll()
        notificationHandler = nil
        closeHandler = nil
    }

    // MARK: Request / response

    /// Send a request and await the correlated response frame.
    func call(method: String, params: JSONValue, generation expectedGeneration: UInt64? = nil) async throws -> RPCFrame {
        try Task.checkCancellation()
        guard isOpen, expectedGeneration == nil || expectedGeneration == generation else {
            throw EngineError.unavailable("connection changed")
        }
        nextID += 1
        let id = nextID
        let req = RPCRequest(id: id, method: method, params: params)
        let line: Data
        do {
            var d = try JSONEncoder().encode(req)
            d.append(0x0A) // '\n'
            line = d
        } catch {
            throw EngineError.internalError("encode \(method): \(error)")
        }

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (cont: CheckedContinuation<RPCFrame, Error>) in
                pending[id] = cont
                if !writeAll(line) {
                    pending[id] = nil
                    cont.resume(throwing: EngineError.unavailable("write failed"))
                }
            }
        } onCancel: {
            Task { await self.cancelRequest(id) }
        }
    }

    private func cancelRequest(_ id: Int) {
        pending.removeValue(forKey: id)?.resume(throwing: CancellationError())
    }

    /// Send an id-less notification (no reply expected) — e.g. for one-way pings.
    /// Not used by the GUI flow but kept for completeness/symmetry.
    func notify(method: String, params: JSONValue) throws {
        guard isOpen else { throw EngineError.unavailable("not connected") }
        struct Note: Encodable { let jsonrpc = "2.0"; let method: String; let params: JSONValue }
        var d = try JSONEncoder().encode(Note(method: method, params: params))
        d.append(0x0A)
        _ = writeAll(d)
    }

    // MARK: Internals

    private func writeAll(_ data: Data) -> Bool {
        guard fd >= 0 else { return false }
        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            guard let base = raw.baseAddress else { return true }
            var off = 0
            let total = raw.count
            while off < total {
                let n = posixWrite(fd, base.advanced(by: off), total - off)
                if n > 0 { off += n; continue }
                if n < 0 && errno == EINTR { continue }
                return false
            }
            return true
        }
    }

    /// Deliver a fully-decoded frame: resolve a pending call by id, or route a
    /// notification. Called on the actor from the reader bridge.
    private func deliver(_ frame: RPCFrame, generation readerGeneration: UInt64) async {
        guard isOpen, generation == readerGeneration else { return }
        if let id = frame.id {
            if let cont = pending.removeValue(forKey: id) { cont.resume(returning: frame) }
        } else if frame.method != nil {
            await notificationHandler?(frame, readerGeneration)
        }
    }

    private func readerDidEnd(generation readerGeneration: UInt64) async {
        guard isOpen, generation == readerGeneration else { return }
        let handler = closeHandler
        close()
        await handler?(readerGeneration)
    }

    private func startReader() {
        let capturedFD = fd
        let capturedGeneration = generation
        let (frames, continuation) = AsyncStream<RPCFrame>.makeStream()
        // One consumer preserves wire order, including the terminal EOF. A Task
        // per frame can deliver done before active, or EOF before a final reply.
        Task.detached(priority: .utility) { [weak self] in
            defer { posixClose(capturedFD) }
            for await frame in frames {
                if let self {
                    await self.deliver(frame, generation: capturedGeneration)
                } else {
                    // Drain until the blocking reader exits before retiring fd.
                    _ = shutdown(capturedFD, SHUT_RDWR)
                }
            }
            await self?.readerDidEnd(generation: capturedGeneration)
        }
        let thread = Thread {
            defer { continuation.finish() }
            var buffer = Data()
            let chunkSize = 16 * 1024
            var chunk = [UInt8](repeating: 0, count: chunkSize)
            while true {
                let n = chunk.withUnsafeMutableBytes { posixRead(capturedFD, $0.baseAddress, chunkSize) }
                if n > 0 {
                    buffer.append(contentsOf: chunk[0..<n])
                    while let nl = buffer.firstIndex(of: 0x0A) {
                        let lineData = buffer.subdata(in: buffer.startIndex..<nl)
                        buffer.removeSubrange(buffer.startIndex...nl)
                        guard !lineData.isEmpty else { continue }
                        if let frame = try? JSONDecoder().decode(RPCFrame.self, from: lineData) {
                            continuation.yield(frame)
                        }
                    }
                } else if n == 0 {
                    break
                } else {
                    if errno == EINTR { continue }
                    break
                }
            }
        }
        thread.name = "cloudfs.uds.reader"
        thread.stackSize = 256 * 1024
        readerThread = thread
        thread.start()
    }
}
