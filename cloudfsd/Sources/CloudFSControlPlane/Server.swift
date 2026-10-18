// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSControlPlane — the real UDS JSON-RPC server (CONTROL-API.md, DESIGN.md §6).
//
// `UnixSocketControlPlane` binds the Unix-domain socket (mode 0600), accepts
// connections, and runs one read loop per connection that:
//   1. frames newline-delimited JSON (FrameDecoder, tolerant of split/coalesced),
//   2. decodes each frame into an `RPCRequest`,
//   3. dispatches the `ControlMethod` to the injected `Engine` (Dispatcher),
//   4. writes the `RPCResponse` back, and
//   5. on `events.subscribe`, pumps the engine's `AsyncStream<EventNotification>`
//      out to that connection as JSON-RPC notifications until it unsubscribes or
//      disconnects.
//
// Concurrency: one `Connection` actor serializes all writes to its FD (responses
// AND event notifications can race otherwise). The reads happen on a detached
// blocking task (POSIX `read` is synchronous); each decoded frame is dispatched on
// the cooperative pool. Disconnect (EOF / error) tears the connection down cleanly.

import Foundation
import CloudFSCore

/// Run an async closure to completion from a synchronous (dedicated-thread) context,
/// blocking the calling thread until it finishes. Used by the connection read loop —
/// which lives on its own OS thread — to drive the actor-isolated handler and wait
/// for the reply to be written before reading the next frame (preserving order).
func awaitOnActor(_ body: @escaping @Sendable () async -> Void) {
    let sem = DispatchSemaphore(value: 0)
    Task { await body(); sem.signal() }
    sem.wait()
}

public final class UnixSocketControlPlane: ControlPlane, @unchecked Sendable {
    private let state = ServerState()

    public init() {}

    /// Bind `socketPath` and serve until `stop()`. Returns only after the accept
    /// loop ends (i.e. after `stop()`), so callers run it in its own Task.
    public func serve(socketPath: String, engine: any Engine) async throws {
        let listener = try UnixListener(path: socketPath)
        await state.setListener(listener)

        // Accept loop on a dedicated OS thread (accept() blocks; keep it off the
        // cooperative pool). Each accepted FD becomes a Connection.
        let state = self.state
        runOnBlockingThread(name: "cloudfsd.control.accept") {
            while true {
                let conn: SocketFD
                do {
                    conn = try listener.accept()
                } catch {
                    // accept() fails once the listener FD is closed by stop().
                    break
                }
                let connection = Connection(fd: conn, engine: engine, server: state)
                connection.start()
                Task { await state.add(connection) }
            }
        }

        // Park until stop() flips the flag and closes the listener.
        await state.waitUntilStopped()
    }

    public func stop() async {
        await state.stop()
    }

    /// Test seam: run the connection read loop on a single, already-connected FD
    /// (e.g. one half of `socketpair()`), bypassing the filesystem listener. The
    /// returned `Connection` lets a test close it; the server tracks it so `stop()`
    /// also tears it down. Mirrors the per-connection path `serve()` uses.
    func serveConnection(fd: SocketFD, engine: any Engine) async -> Connection {
        let connection = Connection(fd: fd, engine: engine, server: state)
        await state.add(connection)
        connection.start()
        return connection
    }
}

/// Shared, actor-isolated server state: the run flag, the listener, the live
/// connection set, and the stop signal.
actor ServerState {
    private(set) var isRunning = true
    private var listener: UnixListener?
    private var connections = Set<ObjectIdentifier>()
    private var connectionByID = [ObjectIdentifier: Connection]()
    private var stopWaiters = [CheckedContinuation<Void, Never>]()

    func setListener(_ l: UnixListener) { listener = l }

    func add(_ c: Connection) {
        let id = ObjectIdentifier(c)
        connections.insert(id)
        connectionByID[id] = c
    }

    func remove(_ c: Connection) {
        let id = ObjectIdentifier(c)
        connections.remove(id)
        connectionByID[id] = nil
    }

    /// Park the `serve()` caller until `stop()` is invoked.
    func waitUntilStopped() async {
        if !isRunning { return }
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            stopWaiters.append(c)
        }
    }

    func stop() async {
        guard isRunning else { return }
        isRunning = false
        listener?.close()      // unblocks accept()
        listener = nil
        // Close every live connection.
        let conns = connectionByID.values
        for c in conns { await c.close() }
        connections.removeAll()
        connectionByID.removeAll()
        for w in stopWaiters { w.resume() }
        stopWaiters.removeAll()
    }
}

/// One connected client. Owns its FD, its frame decoder, and (optionally) an event
/// subscription pump. All writes to the FD go through this actor so response and
/// notification frames never interleave mid-line.
actor Connection {
    private let fd: SocketFD
    private let engine: any Engine
    private unowned let server: ServerState
    private var subscriptionTask: Task<Void, Never>?
    private var isOpen = true

    init(fd: SocketFD, engine: any Engine, server: ServerState) {
        self.fd = fd
        self.engine = engine
        self.server = server
    }

    /// Spawn the blocking read loop on a dedicated OS thread (the `read()` syscall
    /// blocks; keeping it off the cooperative pool avoids starving async work). The
    /// thread frames bytes, then dispatches each frame onto this actor and waits for
    /// it to complete before reading the next one — so per-connection request order
    /// (and thus response order) is preserved.
    nonisolated func start() {
        let fd = self.fd
        runOnBlockingThread(name: "cloudfsd.control.conn") { [self] in
            var decoder = FrameDecoder()
            while true {
                let chunk: [UInt8]
                do { chunk = try fd.read() } catch { break }
                if chunk.isEmpty { break }   // clean EOF
                let frames: [Data]
                do {
                    frames = try decoder.push(chunk)
                } catch {
                    awaitOnActor { await self.sendError(error, id: nil) }
                    break
                }
                for frame in frames {
                    awaitOnActor { await self.handle(frame) }
                }
            }
            awaitOnActor { await self.close() }
        }
    }

    /// Decode one frame into an RPCRequest and dispatch it.
    private func handle(_ frame: Data) async {
        let req: RPCRequest
        do {
            req = try JSONDecoder().decode(RPCRequest.self, from: frame)
        } catch {
            // Parse error: JSON-RPC -32700, but we have no id. Reply best-effort.
            let resp = RPCResponse(id: nil, error: RPCError(code: -32700, message: "parse error"))
            await write(resp)
            return
        }
        let outcome = await Dispatcher.dispatch(req, engine: engine)
        switch outcome {
        case .silent:
            return
        case let .reply(resp):
            await write(resp)
        case let .subscribe(params, resp):
            await write(resp)
            startSubscription(params)
        case let .unsubscribe(resp):
            stopSubscription()
            await write(resp)
        }
    }

    /// Pump the engine's event stream out as notifications until cancelled.
    private func startSubscription(_ params: EventsSubscribeParams) {
        subscriptionTask?.cancel()
        let stream = engine.events(params)
        subscriptionTask = Task { [weak self] in
            for await event in stream {
                if Task.isCancelled { break }
                await self?.writeNotification(event)
            }
        }
    }

    private func stopSubscription() {
        subscriptionTask?.cancel()
        subscriptionTask = nil
    }

    private func writeNotification(_ event: EventNotification) async {
        guard isOpen else { return }
        do {
            let note = try notificationFrame(for: event)
            let bytes = try FrameEncoder.encode(note)
            try fd.writeAll([UInt8](bytes))
        } catch {
            await close()
        }
    }

    private func write(_ resp: RPCResponse) async {
        guard isOpen else { return }
        do {
            let bytes = try FrameEncoder.encode(resp)
            try fd.writeAll([UInt8](bytes))
        } catch {
            await close()
        }
    }

    private func sendError(_ error: any Error, id: RPCID?) async {
        await write(rpcError(for: error, id: id))
    }

    func close() async {
        guard isOpen else { return }
        isOpen = false
        subscriptionTask?.cancel()
        subscriptionTask = nil
        fd.close()   // unblocks the read loop's blocking read() → thread exits
        await server.remove(self)
    }
}
