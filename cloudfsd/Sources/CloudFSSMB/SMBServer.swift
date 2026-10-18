// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — the loopback SMB2 server. One TCP listener on 127.0.0.1:<ephemeral>
// mounted by the macOS built-in smbfs client. Dialect 2.1 (large-MTU multi-credit
// I/O, no leasing/encryption/multichannel). Thread-per-connection with a
// per-connection writer lock. Ordering is per HANDLE for READ and WRITE and per
// CONNECTION for everything else: independent READs overlap (SMBLimits.readSlots)
// on copied handle state; ordinary disk WRITEs run on a per-handle serial lane
// (SMBLimits.writeSlots concurrent lanes) so a slow durable commit on one file
// never stalls reads or writes on another. Every other command (CLOSE, SET_INFO,
// FLUSH, LOCK, IOCTL, CREATE, compounds, stream/directory handles, teardown)
// first drains ALL in-flight reads and writes. Already-pipelined contiguous
// standalone WRITEs can share one durable engine transaction (8 MiB maximum),
// retaining an individual response for each request.
//
// P1a scope: transport + compound dispatch + credit/MessageId ledger + the
// NEGOTIATE → SESSION_SETUP → TREE_CONNECT handshake + ECHO/LOGOFF/TREE_DISCONNECT.
// Data-path commands (CREATE/READ/QUERY_DIRECTORY/QUERY_INFO/CLOSE) land in P1b.

import Foundation
import CloudFSCore

public final class SMBServer: @unchecked Sendable {

    let table: NodeTable
    let ntlm: NTLMServer
    let shareName: String
    let serverGuid: Data
    let lockTable = LockTable()
    private let logSMB = ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] != nil

    private let lock = NSLock()
    private var listenFD: Int32 = -1
    private var connectionFDs: Set<Int32> = []
    private var stopped = false
    public private(set) var port: UInt16 = 0

    /// `credential` is the synthetic per-mount NTLMv2 identity `mount_smbfs` uses.
    public init(engine: any EngineDataPath,
                shareName: String,
                credential: (user: String, password: String),
                nodeTTL: Duration = .seconds(2),
                remotePresentationIDs: Bool = ProcessInfo.processInfo.environment["CLOUDFS_SMB_REMOTE_ID_EPOCHS"] != "0") {
        self.table = NodeTable(engine: engine, ttl: nodeTTL,
                               remotePresentationIDs: remotePresentationIDs)
        self.shareName = shareName
        self.ntlm = NTLMServer(username: credential.user, password: credential.password,
                               targetName: "CLOUDFS")
        var guid = Data(count: 16)
        for i in 0..<16 { guid[i] = UInt8.random(in: .min ... .max) }
        self.serverGuid = guid
    }

    // MARK: lifecycle

    @discardableResult
    public func start() throws -> UInt16 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw EngineError(.internal, "smb: socket() failed: \(errnoStr())") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bindRC = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindRC == 0 else { close(fd); throw EngineError(.internal, "smb: bind() failed: \(errnoStr())") }
        guard listen(fd, 16) == 0 else { close(fd); throw EngineError(.internal, "smb: listen() failed: \(errnoStr())") }

        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &bound) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { _ = getsockname(fd, $0, &len) }
        }
        lock.lock()
        listenFD = fd
        port = UInt16(bigEndian: bound.sin_port)
        stopped = false
        lock.unlock()

        Thread.detachNewThread { [weak self] in self?.acceptLoop(fd) }
        return port
    }

    public func stop() {
        lock.lock()
        stopped = true
        if listenFD >= 0 { close(listenFD); listenFD = -1 }
        // The connection thread owns close(). Closing here as well lets its
        // eventual second close hit a descriptor reused by a NEW mount.
        for fd in connectionFDs { shutdown(fd, SHUT_RDWR) }
        lock.unlock()
    }

    private func isStopped() -> Bool { lock.lock(); defer { lock.unlock() }; return stopped }

    // MARK: accept / connection loops

    private func acceptLoop(_ fd: Int32) {
        while !isStopped() {
            var addr = sockaddr()
            var len = socklen_t(MemoryLayout<sockaddr>.size)
            let conn = accept(fd, &addr, &len)
            guard conn >= 0 else { if isStopped() { return }; continue }
            var one: Int32 = 1
            setsockopt(conn, IPPROTO_TCP, TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            lock.lock()
            if stopped { lock.unlock(); close(conn); return }
            connectionFDs.insert(conn)
            lock.unlock()
            Thread.detachNewThread { [weak self] in
                self?.connectionLoop(conn)
                self?.lock.lock(); self?.connectionFDs.remove(conn); self?.lock.unlock()
                close(conn)
            }
        }
    }

    private func connectionLoop(_ fd: Int32) {
        let logging = logSMB
        if logging { SMBLog.line("connection \(fd) opened") }
        let profile = ProcessInfo.processInfo.environment["CLOUDFS_PROFILE_READS"] != nil ? SMBReadProfile() : nil
        let writeProfile = ProcessInfo.processInfo.environment["CLOUDFS_PROFILE_WRITES"] != nil ? SMBWriteProfile() : nil
        let state = SMBConnectionState()
        let writer = ConnectionWriter(fd: fd)
        let reader = SMBFrameReader(fd: fd)
        var pendingMessage: Data?
        let readers = DispatchGroup()
        let queue = DispatchQueue(label: "cloudfs.smb.read.\(fd)", qos: .userInitiated, attributes: .concurrent)
        // Per-handle write lanes. The frame loop NEVER waits for an execution
        // slot: it always enqueues a coalesced batch on its handle's lane.
        // Memory bound: queued write payload is limited by the credits the client
        // holds. Each response grants at most 512 credits (grantCredits) and one
        // credit covers 64 KiB, so one grant window is 512 * 64 KiB = 32 MiB, plus
        // the single <= 8 MiB batch being assembled. There is no server-side
        // ledger capping the cumulative window, so a byte budget
        // (SMBLimits.maximumQueuedWriteBytes, 128 MiB = 4 windows) is a safety
        // valve that only a non-conforming client can reach; only then does the
        // loop block. At most SMBLimits.writeSlots lane workers EXECUTE at once.
        let writers = DispatchGroup()
        let queuedBytes = SMBByteBudget(limit: SMBLimits.maximumQueuedWriteBytes)
        // Lanes are keyed by the underlying NODE (file), not the handle: every
        // data write to one file serializes, and reads on any handle of that file
        // wait for that file's earlier pending writes.
        var lanes: [InodeID: SMBHandleLane] = [:]
        func lane(for node: InodeID) -> SMBHandleLane {
            if let existing = lanes[node] { return existing }
            let created = SMBHandleLane(label: "cloudfs.smb.write.\(fd).\(lanes.count)")
            lanes[node] = created; return created
        }
        // Reads parked behind a same-file write wait here WITHOUT holding a read
        // slot, so a slow write can never exhaust slots and stall other files.
        // Non-blocking admission: a FIFO per scheduler, drained when a running
        // task finishes. No thread ever parks on a semaphore for a slot, so the
        // GCD pool cannot be exhausted by queued reads or lanes.
        let readScheduler = SMBTaskScheduler(limit: SMBLimits.readSlots, queue: queue)
        let laneQueue = DispatchQueue(label: "cloudfs.smb.lane.\(fd)", qos: .userInitiated, attributes: .concurrent)
        let laneScheduler = SMBTaskScheduler(limit: SMBLimits.writeSlots, queue: laneQueue)
        @Sendable func runLane(_ handleLane: SMBHandleLane) {
            // Runs under laneScheduler (<= writeSlots at once); one run per lane.
            guard var work = handleLane.popFirst() else { return }   // already merged away
            // Only reads issued before this write on this file gate it.
            handleLane.waitReadsGone(work.reads)
            // Frames that arrived while we waited or while a previous write ran
            // join this durable transaction under the same bounds/validation.
            var merged = 1
            while let next = handleLane.popMergeable(into: work) {
                work.requests.append(contentsOf: next.requests); work.bytes += next.bytes; merged += 1
            }
            let ok: Bool
            let writeState = state.snapshotForRead(work.requests[0].fileId,
                                                   treeId: work.requests[0].header.treeId)
            if work.requests.count > 1 {
                ok = respondWriteBatch(work.requests, bytes: work.bytes, state: writeState, writer: writer, connection: fd)
                if ok { writeProfile?.batched(requests: work.requests.count, bytes: work.bytes) }
            } else {
                ok = respond(work.message, state: writeState, writer: writer,
                             writeProfile: writeProfile, fd: fd, resetLastOpen: false)
            }
            if let updated = writeState.open(work.requests[0].fileId,
                                             treeId: work.requests[0].header.treeId) {
                state.propagateWriteSize(from: work.requests[0].fileId,
                                         newSize: updated.size,
                                         treeId: work.requests[0].header.treeId)
            }
            let more = handleLane.endWrite(count: merged)
            queuedBytes.release(work.bytes)
            for _ in 0..<merged { writers.leave() }
            if more { laneScheduler.submit { runLane(handleLane) } }   // fair: back of the FIFO
            if !ok { shutdown(fd, SHUT_RDWR) }
        }
        state.notify = NotifySession(writer: writer, table: table)
        defer {
            readers.wait(); writers.wait()
            if let profile { SMBLog.line(profile.summary()) }
            if let writeProfile { SMBLog.line(writeProfile.summary()) }
            state.notify?.shutdown(); writer.invalidate()
            let opens = state.closeAll()
            for open in opens { lockTable.releaseAll(owner: open.fileId) }
            let table = self.table
            Task {
                let engine = await table.engineRef()
                for open in opens {
                    if open.remoteOpenRetained {
                        await engine.releaseAllRanges(open.node, handle: open.leaseHandle)
                        if open.writeLease { await engine.endWrite(open.node, handle: open.leaseHandle) }
                        await engine.endOpen(open.node, handle: open.leaseHandle)
                    }
                    await table.endLocalOpen(open.node, handle: open.leaseHandle)
                }
            }
        }
        while !isStopped() {
            guard let message = pendingMessage ?? reader.next(blocking: true) else {
                if logging { SMBLog.line("connection \(fd) closed (EOF/err)") }
                return
            }
            pendingMessage = nil
            profileMessage(message, connection: fd, phase: "command-received")
            // Only independent READ messages may overlap. Compounds, related
            // handles, metadata, mutations and CLOSE retain their original order.
            var r = ByteReader(message)
            if let hdr = try? SMB2Header.decode(&r), hdr.command == .read,
               hdr.nextCommand == 0, !hdr.flags.contains(.relatedOps),
               (try? r.u16()) == 49 {
                _ = try? r.u16()
                let length = Int((try? r.u32()) ?? 0)
                _ = try? r.u64()
                let fileId = readFileId(&r)
                if state.authenticated, !fileId.isRelated, state.hasTree(hdr.treeId) {
                    let opened = state.open(fileId, treeId: hdr.treeId)
                    let handleLane = (opened.map { !$0.isDir && $0.streamName == nil } ?? false)
                        ? lane(for: opened!.node) : nil
                    let ticket = handleLane?.beginRead()
                    let responseOrder = state.appleClient ? opened?.readIntegrity.responses : nil
                    let responseTicket = responseOrder?.reserve()
                    readers.enter()
                    let body: @Sendable () -> Void = { [self] in
                        defer { handleLane?.endRead(ticket!.id); readers.leave() }
                        let snapshot = state.snapshotForRead(fileId, treeId: hdr.treeId)
                        let started = profile?.begin()
                        let success: Bool
                        if let responseTicket, let responseOrder {
                            // Apple's async-read cleanup can replace an earlier
                            // failure with a later successful reply. Prepare I/O
                            // concurrently, but publish in request order and
                            // keep a failed handle failed until CLOSE/reopen.
                            let parts = handleCompound(message, state: snapshot, connection: fd)
                            success = responseOrder.publish(responseTicket) {
                                respondAppleRead(parts, request: message, open: snapshot.open(fileId), writer: writer, connection: fd)
                            }
                        } else {
                            success = respond(message, state: snapshot, writer: writer, fd: fd)
                        }
                        if let started { profile?.finish(length: length, started: started, fd: fd) }
                        if !success { shutdown(fd, SHUT_RDWR) }
                    }
                    // Behind an unfinished same-file write: park it (no slot held).
                    if let handleLane, handleLane.deferRead(upTo: ticket!.writes, {
                        readScheduler.submit(body)
                    }) { continue }
                    readScheduler.submit(body)
                    continue
                }
            }
            // Ordinary disk WRITE: per-handle serial lane, loop continues at once.
            if let first = SMBWriteRequest(message), state.authenticated, state.hasTree(first.header.treeId),
               let open = state.open(first.fileId, treeId: first.header.treeId),
               !open.isDir, open.streamName == nil {
                var requests = [first], bytes = first.payload.count
                // Never wait for more credits or another not-yet-started request.
                // Every noneligible packet is kept as the next ordered command.
                while requests.count < 16, bytes < SMBLimits.maximumWriteBytes,
                      let next = reader.next(blocking: false) {
                    guard let request = SMBWriteRequest(next), request.follows(first, bytes: bytes),
                          !requests.contains(where: { $0.header.messageId == request.header.messageId }) else {
                        pendingMessage = next; break
                    }
                    SMBLog.profile(connection: fd, messageId: request.header.messageId,
                                   command: .write, phase: "command-received")
                    requests.append(request); bytes += request.payload.count
                }
                queuedBytes.acquire(bytes)
                if isStopped() { queuedBytes.release(bytes); return }
                state.lastOpen = nil   // loop-thread only; lane workers never touch it
                let handleLane = lane(for: open.node)
                writers.enter()
                if handleLane.enqueue(SMBPendingWrite(requests: requests, bytes: bytes, message: message)) {
                    laneScheduler.submit { runLane(handleLane) }
                }
                continue
            }
            // Everything else keeps the conservative behavior: a queued CLOSE must
            // not destroy a handle used by an earlier read or write, and a
            // mutation must not run beneath either.
            readers.wait(); writers.wait()
            if !respond(message, state: state, writer: writer, writeProfile: writeProfile, fd: fd) { return }
            // CLOSE (possibly compounded) may have removed opens: drop their lanes.
            var hr = ByteReader(message)
            if !lanes.isEmpty, let h = try? SMB2Header.decode(&hr),
               h.command == .close || h.nextCommand != 0 {
                let live = state.openNodes()
                lanes = lanes.filter { live.contains($0.key) }
            }
        }
    }

    private func respondWriteBatch(_ requests: [SMBWriteRequest], bytes: Int,
                                   state: SMBConnectionState, writer: ConnectionWriter,
                                   connection: Int32) -> Bool {
        let first = requests[0]
        var combined = Data(capacity: bytes)
        for request in requests { combined.append(request.payload) }
        // Same handle, ordered contiguous range and flags: one existing engine
        // call preserves ACL/lease/CAS and durable journal semantics for all bytes.
        let started = DispatchTime.now().uptimeNanoseconds
        for request in requests {
            SMBLog.profile(connection: connection, messageId: request.header.messageId,
                           command: .write, phase: "dispatch-start")
        }
        let (status, failure, _) = handleWrite(first.header, body: first.body(with: combined), state: state)
        for request in requests {
            SMBLog.profile(connection: connection, messageId: request.header.messageId,
                           command: .write, phase: "dispatch-finish",
                           elapsedNanoseconds: DispatchTime.now().uptimeNanoseconds &- started)
        }
        for request in requests {
            let header = request.header
            let response = SMB2Header(command: .write, messageId: header.messageId,
                creditCharge: max(header.creditCharge, 1),
                creditReqGrant: grantCredits(request: header.creditReqGrant, charge: header.creditCharge),
                status: status.rawValue, flags: [.serverToRedir], treeId: header.treeId, sessionId: header.sessionId)
            var body = ByteWriter(); response.encode(into: &body)
            body.bytes(status == .success ? writeResponse(count: request.payload.count) : failure)
            // Every success is sent AFTER the shared engine durability barrier.
            // Disconnect here loses only the response, never acknowledged bytes.
            SMBLog.profile(connection: connection, messageId: header.messageId, command: .write, phase: "response-write-start")
            let written = writer.writeScatter([DirectTCP.frame(length: body.count), body.data])
            SMBLog.profile(connection: connection, messageId: header.messageId, command: .write, phase: written ? "response-written" : "response-write-failed")
            if !written { return false }
        }
        return true
    }

    private func respond(_ message: Data, state: SMBConnectionState, writer: ConnectionWriter,
                         writeProfile: SMBWriteProfile? = nil, fd: Int32 = -1,
                         resetLastOpen: Bool = true) -> Bool {
        guard let parts = handleCompound(message, state: state, resetLastOpen: resetLastOpen,
                                         connection: fd >= 0 ? fd : nil) else { return true }
        if let writeProfile { writeProfile.beforeAcknowledgement(message, fd: fd) }
        let total = parts.reduce(0) { $0 + $1.count }
        // Complete frames serialize under the writer lock, including notifications.
        // SMB MessageId identifies independently completing standalone reads.
        profileResponse(parts, connection: fd >= 0 ? fd : nil, phase: "response-write-start")
        let written = writer.writeScatter([DirectTCP.frame(length: total)] + parts)
        profileResponse(parts, connection: fd >= 0 ? fd : nil, phase: written ? "response-written" : "response-write-failed")
        guard written else { return false }
        state.notify?.didPublishInterims(parts)
        return true
    }

    private func respondAppleRead(_ prepared: [Data]?, request: Data, open: SMBOpen?, writer: ConnectionWriter,
                                  connection: Int32) -> Bool {
        guard var parts = prepared, let first = parts.first else { return true }
        var reader = ByteReader(first)
        guard var header = try? SMB2Header.decode(&reader) else { return false }
        if let status = NTStatus(rawValue: header.status), status != .success, status != .endOfFile {
            open?.readIntegrity.fail(status)
        }
        if header.status == NTStatus.success.rawValue, parts.count > 1,
           let open, open.readIntegrity.status == nil {
            // Preparation may have waited behind an earlier cloud READ. Recheck
            // admission at publication, after that wait, before exposing bytes.
            var requestReader = ByteReader(request)
            _ = try? SMB2Header.decode(&requestReader); _ = try? requestReader.u32()
            let length = (try? requestReader.u32()) ?? 0
            let offset = (try? requestReader.u64()) ?? 0
            let failure: NTStatus? = Self.bridgeSync {
                do { try await self.checkRangeAccess(open, offset: offset, length: UInt64(length), write: false); return nil }
                catch let error as EngineError { return error.kind == .locked ? .fileLockConflict : ntStatus(for: error) }
                catch { return .unsuccessful }
            }
            if let failure { open.readIntegrity.fail(failure) }
        }
        if let failure = open?.readIntegrity.status {
            header.status = failure.rawValue
            var response = ByteWriter(); header.encode(into: &response); response.bytes(errorBody())
            parts = [response.data] // Discard bytes prepared before another READ failed.
        }
        let total = parts.reduce(0) { $0 + $1.count }
        profileResponse(parts, connection: connection, phase: "response-write-start")
        let written = writer.writeScatter([DirectTCP.frame(length: total)] + parts)
        profileResponse(parts, connection: connection, phase: written ? "response-written" : "response-write-failed")
        return written
    }

    // MARK: compound dispatch

    /// Narrowly recognize a self-contained metadata probe whose whole lifecycle
    /// can be represented by one authoritative backend directory snapshot.
    /// Any uncertainty deliberately falls back to the ordinary open path.
    private func isDirectorySnapshotCompound(_ message: Data, expectedSessionId: UInt64) -> Bool {
        var frames: [(SMB2Header, Data)] = []
        var cursor = 0
        while cursor + SMB2Header.size <= message.count {
            let slice = message.subdata(in: cursor..<message.count)
            var reader = ByteReader(slice)
            guard let header = try? SMB2Header.decode(&reader) else { return false }
            let next = Int(header.nextCommand)
            if next > 0, (next < SMB2Header.size || next > slice.count) { return false }
            let end = next > 0 ? next : slice.count
            let body = slice.subdata(in: SMB2Header.size..<end)
            frames.append((header, body))
            if next <= 0 {
                cursor = message.count
                break
            }
            cursor += next
        }
        guard cursor == message.count, frames.count == 3 else { return false }
        let (create, createBody) = frames[0]
        let (query, queryBody) = frames[1]
        let (close, closeBody) = frames[2]
        guard create.command == .create, query.command == .queryDirectory, close.command == .close,
              create.nextCommand > 0, query.nextCommand > 0, close.nextCommand == 0,
              !create.flags.contains(.relatedOps),
              query.flags.contains(.relatedOps), close.flags.contains(.relatedOps),
              create.treeId != UInt32.max, create.sessionId == expectedSessionId,
              (query.treeId == UInt32.max || query.treeId == create.treeId),
              (close.treeId == UInt32.max || close.treeId == create.treeId),
              (query.sessionId == UInt64.max || query.sessionId == create.sessionId),
              (close.sessionId == UInt64.max || close.sessionId == create.sessionId),
              let request = parseCreate(createBody),
              request.disposition == CreateDisposition.open.rawValue,
              request.options == CreateOptions.directoryFile,
              request.shareAccess & ~UInt32(0x7) == 0,
              request.contexts.isEmpty,
              SMBAccess.openFileAccess(SMBAccess.expanded(request.desiredAccess)).rawValue <= OpenFileAccess.read.rawValue,
              Self.snapshotCreateHasNoContexts(createBody),
              SMBStreams.parse(request.name).stream == nil,
              !SMBPath.components(request.name).isEmpty,
              SMBPath.components(request.name).allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }),
              Self.isLiteralSingleEntryQuery(queryBody),
              Self.isRelatedPlainClose(closeBody)
        else { return false }
        return true
    }

    private static func snapshotCreateHasNoContexts(_ body: Data) -> Bool {
        var reader = ByteReader(body)
        guard (try? reader.u16()) == 57,
              (try? reader.take(1 + 1 + 4 + 8 + 8 + 4 + 4 + 4 + 4 + 4 + 2 + 2)) != nil
        else { return false }
        guard let contextOffset = try? reader.u32(), let contextLength = try? reader.u32() else { return false }
        return contextOffset == 0 && contextLength == 0
    }

    private static func isLiteralSingleEntryQuery(_ body: Data) -> Bool {
        var reader = ByteReader(body)
        guard (try? reader.u16()) == 33,
              (try? reader.u8()) == FileInfoClass.idBothDirectoryInformation.rawValue,
              (try? reader.u8()) == 0x03 else { return false }
        _ = try? reader.u32()
        guard (try? reader.u64()) == UInt64.max, (try? reader.u64()) == UInt64.max,
              let nameOffset = try? reader.u16(), let nameLength = try? reader.u16() else { return false }
        _ = try? reader.u32()
        let relative = Int(nameOffset) - SMB2Header.size
        guard nameLength > 0, relative >= 0, relative + Int(nameLength) <= body.count else { return false }
        let pattern = SMBString.decodeUTF16le(body.subdata(in: relative..<(relative + Int(nameLength))))
        return !pattern.isEmpty && pattern != "." && pattern != ".." &&
            !pattern.contains(where: { "*?<>\"/\\".contains($0) })
    }

    private static func isRelatedPlainClose(_ body: Data) -> Bool {
        var reader = ByteReader(body)
        guard (try? reader.u16()) == 24, (try? reader.u16()) == 0 else { return false }
        _ = try? reader.u32()
        return (try? reader.u64()) == UInt64.max && (try? reader.u64()) == UInt64.max
    }

    /// Process a (possibly compound) request message and return the response parts
    /// (to be framed + scatter-written in order), or nil if the message was
    /// unparseable at the transport level. The parts model lets the READ fast path
    /// keep the big payload as its own buffer instead of concatenating it.
    private func handleCompound(_ message: Data, state: SMBConnectionState,
                                resetLastOpen: Bool = true, connection: Int32? = nil) -> [Data]? {
        // RELATED FileId is scoped to this compound, never a previous request.
        // A failed Finder xattr CREATE must not let its related CLOSE consume an
        // unrelated open movie handle from an earlier request.
        if resetLastOpen { state.lastOpen = nil }
        let directorySnapshotCompound = isDirectorySnapshotCompound(message, expectedSessionId: state.sessionId)
        var parts: [Data] = []
        var cursor = 0
        var previousTreeId: UInt32?
        while cursor + SMB2Header.size <= message.count {
            let slice = message.subdata(in: cursor..<message.count)
            var r = ByteReader(slice)
            guard let hdr = try? SMB2Header.decode(&r) else { break }
            let next = Int(hdr.nextCommand)
            // The command payload runs from end-of-header to the next header
            // (or end of message).
            let bodyEnd = next > 0 ? min(next, slice.count) : slice.count
            let body = slice.subdata(in: SMB2Header.size..<max(SMB2Header.size, bodyEnd))

            if logSMB {
                SMBLog.line("recv \(hdr.command) mid=\(hdr.messageId) tid=\(hdr.treeId) sid=\(hdr.sessionId) next=\(next)")
            }
            let inheritedTree: UInt32?
            if hdr.treeId == UInt32.max, hdr.flags.contains(.relatedOps) {
                inheritedTree = previousTreeId
            } else {
                inheritedTree = hdr.treeId
            }
            let needsTree = Self.commandRequiresTree(hdr.command)
            let validTree = inheritedTree.flatMap { state.hasTree($0) ? $0 : nil }
            state.currentRequestTreeId = needsTree ? validTree : nil
            let (status, respBody, extra): (NTStatus, Data, DispatchExtra)
            if needsTree && !state.authenticated {
                status = .userSessionDeleted
                respBody = errorBody()
                extra = DispatchExtra()
                previousTreeId = nil
            } else if needsTree && validTree == nil {
                status = .networkNameDeleted
                respBody = errorBody()
                extra = DispatchExtra()
                previousTreeId = nil
            } else {
                let started = DispatchTime.now().uptimeNanoseconds
                SMBLog.profile(connection: connection, messageId: hdr.messageId, command: hdr.command, phase: "dispatch-start")
                state.directorySnapshotCandidate = directorySnapshotCompound && hdr.command == .create
                (status, respBody, extra) = dispatch(hdr, body: body, state: state, profileConnection: connection)
                state.directorySnapshotCandidate = false
                SMBLog.profile(connection: connection, messageId: hdr.messageId, command: hdr.command,
                               phase: "dispatch-finish", elapsedNanoseconds: DispatchTime.now().uptimeNanoseconds &- started)
            }
            let responseTree = extra.treeId ?? validTree
            if needsTree, state.authenticated, let validTree { previousTreeId = validTree }
            if hdr.command == .treeConnect, status == .success, let connectedTree = extra.treeId {
                previousTreeId = connectedTree
            }

            if logSMB {
                SMBLog.line("\(hdr.command) mid=\(hdr.messageId) req=\(body.count)B -> \(String(format: "0x%08X", status.rawValue)) (\(respBody.count)B)")
            }

            // CANCEL and self-completed async ops emit no inline response here.
            if extra.suppressResponse {
                if next <= 0 { break }
                cursor += next
                continue
            }

            var respFlags: SMB2HeaderFlags = [.serverToRedir]
            var respStatus = status.rawValue
            var respAsyncId: UInt64 = 0
            if let asyncId = extra.asyncPending {
                // Interim response: async header + STATUS_PENDING; the real
                // completion frame is written later by the notify session.
                respFlags.insert(.asyncCommand)
                respAsyncId = asyncId
                respStatus = NTStatus.pending.rawValue
            }
            var respHdr = SMB2Header(command: hdr.command,
                                     messageId: hdr.messageId,
                                     creditCharge: max(hdr.creditCharge, 1),
                                     creditReqGrant: grantCredits(request: hdr.creditReqGrant,
                                                                  charge: hdr.creditCharge),
                                     status: respStatus,
                                     flags: respFlags,
                                     treeId: responseTree ?? hdr.treeId,
                                     sessionId: extra.sessionId ?? hdr.sessionId,
                                     asyncId: respAsyncId)
            if hdr.flags.contains(.relatedOps) { respHdr.flags.insert(.relatedOps) }

            var chunk = ByteWriter()
            respHdr.encode(into: &chunk)
            chunk.bytes(respBody)
            var chunkData = chunk.data

            // READ fast path: for a STANDALONE read (the whole message is this one
            // command — macOS never compounds large reads), emit [header+fixed] and
            // the payload as SEPARATE parts so the ≤1 MiB payload is scatter-written
            // straight from its buffer, not copied through response assembly.
            if let payload = extra.readPayload, cursor == 0, next <= 0 {
                parts.append(chunkData)
                parts.append(payload)
                break
            }
            // Compound read (rare) must embed the payload so NextCommand stays correct.
            if let payload = extra.readPayload { chunkData.append(payload) }
            // 8-byte align each response in a compound and set NextCommand.
            let hasMore = next > 0 && (cursor + next) < message.count
            if hasMore {
                let padded = (chunkData.count + 7) & ~7
                if padded > chunkData.count { chunkData.append(Data(count: padded - chunkData.count)) }
                // Patch NextCommand (bytes 20..<24 of the header).
                patchU32(&chunkData, at: 20, UInt32(chunkData.count))
            }
            parts.append(chunkData)

            if next <= 0 { break }
            cursor += next
        }
        guard !parts.isEmpty else { return nil }
        return parts
    }

    private static func commandRequiresTree(_ command: SMB2Command) -> Bool {
        switch command {
        case .negotiate, .sessionSetup, .treeConnect, .logoff, .echo, .cancel:
            return false
        default:
            return true
        }
    }

    private func profileMessage(_ message: Data, connection: Int32?, phase: String) {
        guard SMBLog.profileEnabled else { return }
        var cursor = 0
        while cursor + SMB2Header.size <= message.count {
            var reader = ByteReader(message.subdata(in: cursor..<message.count))
            guard let header = try? SMB2Header.decode(&reader) else { break }
            SMBLog.profile(connection: connection, messageId: header.messageId, command: header.command, phase: phase)
            let next = Int(header.nextCommand)
            if next <= 0 || cursor + next >= message.count { break }
            cursor += next
        }
    }

    private func profileResponse(_ parts: [Data], connection: Int32?, phase: String) {
        guard SMBLog.profileEnabled else { return }
        for part in parts {
            var reader = ByteReader(part)
            guard let header = try? SMB2Header.decode(&reader) else { continue }
            SMBLog.profile(connection: connection, messageId: header.messageId, command: header.command, phase: phase)
        }
    }

    /// Extra header fields a handler may set (assigned session/tree ids), plus
    /// async-notify control: `asyncPending` makes the reply an interim
    /// STATUS_PENDING async response; `suppressResponse` emits nothing (CANCEL).
    struct DispatchExtra {
        var sessionId: UInt64?
        var treeId: UInt32?
        var asyncPending: UInt64? = nil
        var suppressResponse: Bool = false
        /// READ fast path: the payload, kept OUT of `respBody` so it can be
        /// scatter-written straight from its buffer instead of copied through
        /// response assembly. `respBody` then carries only the 16-byte fixed part.
        var readPayload: Data? = nil
    }

    private func dispatch(_ hdr: SMB2Header, body: Data, state: SMBConnectionState,
                          profileConnection: Int32? = nil)
        -> (NTStatus, Data, DispatchExtra) {
        switch hdr.command {
        case .negotiate:      return (.success, handleNegotiate(body), DispatchExtra())
        case .sessionSetup:   return handleSessionSetup(hdr, body: body, state: state)
        case .treeConnect:    return handleTreeConnect(hdr, body: body, state: state)
        case .treeDisconnect:
            let tree = hdr.treeId == UInt32.max ? state.currentRequestTreeId : hdr.treeId
            guard let tree, state.hasTree(tree) else { return (.networkNameDeleted, errorBody(), DispatchExtra()) }
            closeTree(tree, sessionId: hdr.sessionId, state: state)
            return (.success, structOnly(4), DispatchExtra())
        case .logoff:
            for tree in state.activeTreeIds { closeTree(tree, sessionId: hdr.sessionId, state: state) }
            state.authenticated = false
            return (.success, structOnly(4), DispatchExtra())
        case .echo:           return (.success, structOnly(4), DispatchExtra())
        case .create:         return handleCreate(hdr, body: body, state: state, profileConnection: profileConnection)
        case .close:          return handleClose(hdr, body: body, state: state)
        case .read:           return handleRead(hdr, body: body, state: state)
        case .write:          return handleWrite(hdr, body: body, state: state)
        case .flush:          return handleFlush(hdr, body: body, state: state)
        case .queryDirectory: return handleQueryDirectory(hdr, body: body, state: state)
        case .queryInfo:      return handleQueryInfo(hdr, body: body, state: state)
        case .setInfo:        return handleSetInfo(hdr, body: body, state: state)
        case .lock:           return handleLock(hdr, body: body, state: state)
        case .changeNotify:   return handleChangeNotify(hdr, body: body, state: state)
        case .cancel:         return handleCancel(hdr, body: body, state: state)
        case .ioctl:
            // No FSCTLs supported yet; the mac client feature-gates these off our
            // (absent) capability advertisements, so a clean decline is correct.
            return (.notSupported, errorBody(), DispatchExtra())
        default:
            // Write path (P2) etc. land later; decline cleanly.
            return (.notImplemented, errorBody(), DispatchExtra())
        }
    }

    /// Release all FIDs for one tree through the normal CLOSE handler before
    /// invalidating that tree. Used by TREE_DISCONNECT and LOGOFF.
    private func closeTree(_ tree: UInt32, sessionId: UInt64, state: SMBConnectionState) {
        state.currentRequestTreeId = tree
        for open in state.activeOpens(forTree: tree) {
            var closeBody = ByteWriter()
            closeBody.u16(24); closeBody.u16(0); closeBody.u32(0)
            closeBody.u64(open.fileId.persistent); closeBody.u64(open.fileId.volatile)
            let closeHeader = SMB2Header(command: .close, treeId: tree, sessionId: sessionId)
            let (closeStatus, _, _) = handleClose(closeHeader, body: closeBody.data, state: state)
            if closeStatus != .success {
                SMBLog.line("tree cleanup close failed tid=\(tree) fid=\(open.fileId.volatile) status=\(closeStatus.rawValue)")
            }
        }
        _ = state.disconnectTree(tree)
        state.currentRequestTreeId = nil
    }

    /// Run an async engine operation and BLOCK the calling connection thread until
    /// it completes — the hard-mount stall (latency hidden by cache + read-ahead),
    /// identical to the NFS server's bridge.
    static func bridgeSync<T: Sendable>(_ op: @escaping @Sendable () async -> T) -> T {
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox<T>()
        Task.detached { box.value = await op(); sem.signal() }
        sem.wait()
        return box.value!
    }
    final class ResultBox<T>: @unchecked Sendable { var value: T? }

    // MARK: credit policy

    /// Grant enough credits to keep the client's window healthy. A request with
    /// CreditCharge N consumes N credits (a multi-credit 1 MiB read charges
    /// ceil(1MiB/64KiB)=16), so we must grant back AT LEAST the charge or the
    /// window shrinks and large I/O eventually stalls. Honor the client's request,
    /// floor at the charge (min 1), clamp to a sane band.
    private func grantCredits(request: UInt16, charge: UInt16) -> UInt16 {
        let want = max(request, max(charge, 1))
        return min(want, 512)
    }
}

// MARK: - Per-connection outbound writer

/// Serializes whole-frame writes on a connection. In P1a only the request thread
/// writes; from P5 (CHANGE_NOTIFY) completions are produced off-thread and must
/// interleave whole frames — this lock is the seam for that.
/// Same-handle READ results publish in arrival order for Apple's pipelined
/// client. Engine I/O remains concurrent and at most readSlots workers wait.
/// Per-handle ordering is essential: a read parked behind a write must not hold
/// back another file's workers and exhaust slots needed to finish that write.
final class SMBReadResponseOrder: @unchecked Sendable {
    private let condition = NSCondition()
    private var issued: UInt64 = 0
    private var next: UInt64 = 0
    func reserve() -> UInt64 {
        condition.lock(); defer { condition.unlock() }
        let ticket = issued; issued &+= 1; return ticket
    }
    func publish(_ ticket: UInt64, _ body: () -> Bool) -> Bool {
        condition.lock(); defer { condition.unlock() }
        while ticket != next { condition.wait() }
        defer { next &+= 1; condition.broadcast() }
        return body()
    }
}

final class ConnectionWriter: @unchecked Sendable {
    private let fd: Int32
    private var valid = true
    private let lock = NSLock()
    init(fd: Int32) { self.fd = fd }
    func invalidate() { lock.withLock { valid = false } }

    @discardableResult
    func write(_ payload: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard valid else { return false }
        return Self.writeAll(fd, payload)
    }

    /// Write several buffers back-to-back under one lock, without concatenating
    /// them into a single Data. The big READ payload is thus written straight from
    /// its own buffer to the socket — no re-copy through response assembly.
    @discardableResult
    func writeScatter(_ parts: [Data]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard valid else { return false }
        for part in parts where !part.isEmpty {
            if !Self.writeAll(fd, part) { return false }
        }
        return true
    }

    private static func writeAll(_ fd: Int32, _ payload: Data) -> Bool {
        payload.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return true }   // empty → nothing to do
            var off = 0
            while off < raw.count {
                let n = Foundation.write(fd, base.advanced(by: off), raw.count - off)
                if n > 0 { off += n; continue }
                if n < 0 && errno == EINTR { continue }
                return false
            }
            return true
        }
    }
}

// MARK: - Small helpers shared by handlers

/// A minimal SMB2 error response body ([MS-SMB2] §2.2.2): StructureSize=9,
/// ErrorContextCount=0, Reserved, ByteCount=0, one padding byte.
func errorBody() -> Data {
    var w = ByteWriter()
    w.u16(9); w.u8(0); w.u8(0); w.u32(0)
    return w.data
}

/// A fixed-size response that is just its StructureSize field (+ the low bit that
/// several SMB2 responses set) — used by ECHO/LOGOFF/TREE_DISCONNECT whose bodies
/// are `StructureSize(2) + Reserved(2)`.
func structOnly(_ structureSize: UInt16) -> Data {
    var w = ByteWriter()
    w.u16(structureSize); w.u16(0)
    return w.data
}

/// Patch a little-endian u32 at an absolute byte offset within `data`.
func patchU32(_ data: inout Data, at offset: Int, _ v: UInt32) {
    let le = v.littleEndian
    withUnsafeBytes(of: le) { raw in
        for i in 0..<4 { data[data.startIndex + offset + i] = raw[i] }
    }
}

/// Windows FILETIME (100 ns ticks since 1601-01-01) for a Unix epoch seconds value.
func filetime(unixSeconds: Double) -> UInt64 {
    let epochDeltaSeconds = 11_644_473_600.0   // 1601→1970
    let ticks = (unixSeconds + epochDeltaSeconds) * 10_000_000.0
    return ticks > 0 ? UInt64(ticks) : 0
}

func nowFiletime() -> UInt64 { filetime(unixSeconds: Date().timeIntervalSince1970) }

func errnoStr() -> String { String(cString: strerror(errno)) }

/// Diagnostic log sink. Writes to CLOUDFS_SMB_LOGFILE if set (survives the
/// `swift test` subprocess stderr capture), else stderr.
enum SMBLog {
    private static let lock = NSLock()
    static var profileEnabled: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["CLOUDFS_PROFILE_GATEWAY"] == "1" && environment["CLOUDFS_LOG_SMB"] == "1"
    }
    static func line(_ s: String) {
        let msg = "cloudfsd[smb]: \(s)\n"
        lock.lock(); defer { lock.unlock() }
        if let path = ProcessInfo.processInfo.environment["CLOUDFS_SMB_LOGFILE"] {
            if let fh = FileHandle(forWritingAtPath: path) {
                fh.seekToEndOfFile(); fh.write(Data(msg.utf8)); try? fh.close()
            } else {
                FileManager.default.createFile(atPath: path, contents: Data(msg.utf8))
            }
        } else {
            FileHandle.standardError.write(Data(msg.utf8))
        }
    }

    static func profile(connection: Int32?, messageId: UInt64, command: SMB2Command,
                        phase: String, elapsedNanoseconds: UInt64? = nil) {
        guard profileEnabled else { return }
        let timestamp = Date().timeIntervalSince1970
        let elapsed = elapsedNanoseconds.map { " elapsed_ms=\(Double($0) / 1_000_000)" } ?? ""
        line("profile ts=\(String(format: "%.6f", timestamp)) conn=\(connection.map(String.init) ?? "-") mid=\(messageId) cmd=\(command) phase=\(phase)\(elapsed)")
    }
}

/// Opt-in measurements for the actual kernel request shape and read pipeline.
private final class SMBReadProfile: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0, bytes = 0, queuedCount = 0, maxQueued = 0, active = 0, peak = 0
    private var seconds = 0.0
    private var sizes: [Int: Int] = [:]
    func begin() -> Date {
        lock.lock(); active += 1; peak = max(peak, active); lock.unlock()
        return Date()
    }
    func finish(length: Int, started: Date, fd: Int32) {
        var peek = [UInt8](repeating: 0, count: 4096)
        let queued = recv(fd, &peek, peek.count, MSG_PEEK | MSG_DONTWAIT)
        lock.lock(); defer { lock.unlock() }
        active -= 1; count += 1; bytes += length; sizes[length, default: 0] += 1
        seconds += Date().timeIntervalSince(started)
        if queued > 0 { queuedCount += 1; maxQueued = max(maxQueued, queued) }
    }
    func summary() -> String {
        lock.lock(); defer { lock.unlock() }
        return "READ_PROFILE count=\(count) bytes=\(bytes) serviceSeconds=\(seconds) queuedAfterRead=\(queuedCount) maxQueuedBytes=\(maxQueued) peakConcurrent=\(peak) sizes=\(sizes)"
    }
}

/// Counts queued bytes before WRITE acknowledgement; proves whether the client
/// pipelines requests without credit from the response about to be sent.
private final class SMBWriteProfile: @unchecked Sendable {
    private let lock = NSLock()
    private var writes = 0, bytes = 0, queued = 0, maxQueued = 0
    private var batches: [Int: Int] = [:]
    func batched(requests: Int, bytes: Int) {
        lock.lock(); defer { lock.unlock() }
        self.writes += requests; self.bytes += bytes; batches[requests, default: 0] += 1
    }
    func beforeAcknowledgement(_ message: Data, fd: Int32) {
        var reader = ByteReader(message)
        guard let header = try? SMB2Header.decode(&reader), header.command == .write,
              header.nextCommand == 0, (try? reader.u16()) == 49 else { return }
        _ = try? reader.u16()
        let length = Int((try? reader.u32()) ?? 0)
        var peek = [UInt8](repeating: 0, count: 4096)
        let available = recv(fd, &peek, peek.count, MSG_PEEK | MSG_DONTWAIT)
        lock.lock(); defer { lock.unlock() }
        writes += 1; bytes += length
        if available > 0 { queued += 1; maxQueued = max(maxQueued, available) }
    }
    func summary() -> String {
        lock.lock(); defer { lock.unlock() }
        return "WRITE_PROFILE count=\(writes) bytes=\(bytes) queuedBeforeACK=\(queued) maxQueuedBytes=\(maxQueued) batches=\(batches)"
    }
}

// MARK: - Per-file ordering lane

/// A write (or merged group of adjacent writes) waiting on a lane.
struct SMBPendingWrite {
    var requests: [SMBWriteRequest]
    var bytes: Int
    let message: Data
    var reads: Set<UInt64> = []
    var readSeq: UInt64 = 0
}

/// Orders READ and WRITE on one FILE without serializing the connection.
/// WRITEs queue in `pending` and run on `queue` (serial, so they stay ordered
/// among themselves). A READ captures the number of writes issued so far and is
/// parked (holding no read slot) until exactly those finish; a WRITE captures the
/// set of reads in flight and waits for exactly those. Every wait targets only
/// EARLIER arrivals, so the dependency graph is acyclic. Adjacent queued writes
/// with no read between them merge into one engine call.
final class SMBHandleLane: @unchecked Sendable {
    private let cond = NSCondition()
    private var active = false
    private var writesIssued: UInt64 = 0, writesDone: UInt64 = 0
    private var activeReads: Set<UInt64> = [], nextRead: UInt64 = 0
    private var pending: [SMBPendingWrite] = []
    private var deferred: [(target: UInt64, run: @Sendable () -> Void)] = []

    init(label: String) {}

    func beginRead() -> (id: UInt64, writes: UInt64) {
        cond.lock(); defer { cond.unlock() }
        let id = nextRead; nextRead &+= 1; activeReads.insert(id)
        return (id, writesIssued)
    }
    func endRead(_ id: UInt64) {
        cond.lock(); activeReads.remove(id); cond.broadcast(); cond.unlock()
    }
    /// True if parked (run is invoked once `target` writes have finished).
    func deferRead(upTo target: UInt64, _ run: @escaping @Sendable () -> Void) -> Bool {
        cond.lock(); defer { cond.unlock() }
        if writesDone >= target { return false }
        deferred.append((target, run)); return true
    }
    /// True if the lane was idle and must now be scheduled (one run at a time,
    /// which is what keeps a lane's writes ordered).
    func enqueue(_ item: SMBPendingWrite) -> Bool {
        cond.lock(); defer { cond.unlock() }
        var item = item
        writesIssued += 1
        item.reads = activeReads; item.readSeq = nextRead
        pending.append(item)
        if active { return false }
        active = true; return true
    }
    func popFirst() -> SMBPendingWrite? {
        cond.lock(); defer { cond.unlock() }
        return pending.isEmpty ? nil : pending.removeFirst()
    }
    /// Next queued write if it may join `work`: same extent rules as loop-side
    /// batching (same session/tree/handle/flags, contiguous, <=16 requests,
    /// <=8 MiB, distinct MessageIds) and no read began between the two.
    func popMergeable(into work: SMBPendingWrite) -> SMBPendingWrite? {
        cond.lock(); defer { cond.unlock() }
        guard let next = pending.first, next.readSeq == work.readSeq,
              work.requests.count + next.requests.count <= 16,
              work.bytes + next.bytes <= SMBLimits.maximumWriteBytes else { return nil }
        let first = work.requests[0]
        var bytes = work.bytes
        var ids = Set(work.requests.map { $0.header.messageId })
        for request in next.requests {
            guard request.follows(first, bytes: bytes), ids.insert(request.header.messageId).inserted else { return nil }
            bytes += request.payload.count
        }
        return pending.removeFirst()
    }
    func waitReadsGone(_ reads: Set<UInt64>) {
        cond.lock(); defer { cond.unlock() }
        while !activeReads.isDisjoint(with: reads) { cond.wait() }
    }
    /// Returns true if more writes are queued (the lane stays active and the
    /// caller must resubmit it); otherwise the lane goes idle.
    func endWrite(count: Int) -> Bool {
        cond.lock()
        writesDone += UInt64(count)
        let more = !pending.isEmpty
        if !more { active = false }
        let ready = deferred.filter { $0.target <= writesDone }
        deferred.removeAll { $0.target <= writesDone }
        // Submit the earlier parked reads before a newly arriving READ can see
        // writesDone and bypass them. Otherwise all read slots could wait for
        // an earlier ordered response whose worker has not been scheduled yet.
        for item in ready { item.run() }
        cond.broadcast(); cond.unlock()
        return more
    }
}

/// Blocks the frame loop only if queued write payload exceeds `limit` (never in
/// normal operation). An empty queue always admits one batch.
final class SMBByteBudget: @unchecked Sendable {
    private let cond = NSCondition()
    private let limit: Int
    private var used = 0
    init(limit: Int) { self.limit = limit }
    func acquire(_ bytes: Int) {
        cond.lock(); defer { cond.unlock() }
        while used > 0 && used + bytes > limit { cond.wait() }
        used += bytes
    }
    func release(_ bytes: Int) { cond.lock(); used -= bytes; cond.broadcast(); cond.unlock() }
}

/// Runs at most `limit` tasks at once on `queue`; the rest wait in a FIFO that a
/// finishing task drains. Submitting never blocks and parks no thread.
final class SMBTaskScheduler: @unchecked Sendable {
    private let lock = NSLock()
    private let limit: Int
    private let queue: DispatchQueue
    private var running = 0
    private var fifo: [@Sendable () -> Void] = []
    init(limit: Int, queue: DispatchQueue) { self.limit = limit; self.queue = queue }
    func submit(_ work: @escaping @Sendable () -> Void) {
        lock.lock()
        if running < limit { running += 1; lock.unlock(); start(work) }
        else { fifo.append(work); lock.unlock() }
    }
    private func start(_ work: @escaping @Sendable () -> Void) {
        queue.async { [self] in
            work()
            lock.lock()
            if fifo.isEmpty { running -= 1; lock.unlock() }
            else { let next = fifo.removeFirst(); lock.unlock(); start(next) }
        }
    }
}
