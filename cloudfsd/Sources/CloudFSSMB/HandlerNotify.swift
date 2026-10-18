// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — SMB2 CHANGE_NOTIFY ([MS-SMB2] §2.2.35/§2.2.36) + CANCEL.
//
// This is what gives Finder LIVE directory updates — the headline reason for the
// SMB cutover (NFSv3 had no equivalent). The flow is asynchronous:
//   1. client sends CHANGE_NOTIFY on an open directory handle;
//   2. we reply with an interim STATUS_PENDING async response (AsyncId) and DON'T
//      block the connection thread;
//   3. when the directory changes we send a SECOND frame (same AsyncId) completing
//      the notify — with STATUS_NOTIFY_ENUM_DIR ("re-enumerate"), the simplest
//      correct completion that makes Finder re-read the folder.
// Changes are seen two ways: LOCAL SMB mutations post directly (instant), and
// OUT-OF-BAND (other-client) changes via engine generation wakes and a stable
// notification checkpoint (active only while a notify is pending). Historical
// change-feed pages are never interpreted as new watch events.

import Foundation
import CloudFSCore

/// Per-connection async-notify registry. Completions are written off the request
/// thread through the connection's serialized `ConnectionWriter`.
public final class NotifySession: @unchecked Sendable {
    private let writer: ConnectionWriter
    private let table: NodeTable
    private let lock = NSLock()
    private var pending: [Pending] = []
    private struct Poller {
        let id: UUID
        var task: Task<Void, Never>?
    }
    private var pollers: [InodeID: Poller] = [:]
    private var stopped = false

    struct Pending {
        let messageId: UInt64
        let asyncId: UInt64
        let sessionId: UInt64
        let fileId: SMBFileId
        let dir: InodeID
        let completionFilter: UInt32
        var interimPublished = false
        var deferredStatus: NTStatus?
    }

    init(writer: ConnectionWriter, table: NodeTable) {
        self.writer = writer
        self.table = table
    }

    // MARK: registration

    func register(_ p: Pending, generation: UInt64) {
        lock.lock()
        guard !stopped else { lock.unlock(); return }
        pending.append(p)
        let id: UUID?
        if p.completionFilter != 0 && pollers[p.dir] == nil {
            let reserved = UUID()
            pollers[p.dir] = Poller(id: reserved, task: nil)
            id = reserved
        } else { id = nil }
        lock.unlock()
        if let id { startPoller(p.dir, id: id, generation: generation) }
    }

    /// Called only after the complete response frame has reached ConnectionWriter.
    /// A local mutation or remote checkpoint can finish during compound assembly;
    /// retain that result until its own interim PENDING is actually published.
    func didPublishInterims(_ parts: [Data]) {
        for part in parts {
            var reader = ByteReader(part)
            guard let header = try? SMB2Header.decode(&reader),
                  header.command == .changeNotify, header.status == NTStatus.pending.rawValue,
                  header.flags.contains(.asyncCommand) else { continue }
            lock.lock()
            guard let index = pending.firstIndex(where: {
                $0.messageId == header.messageId && $0.asyncId == header.asyncId && $0.sessionId == header.sessionId
            }) else { lock.unlock(); continue }
            pending[index].interimPublished = true
            let ready: Pending?
            if pending[index].deferredStatus != nil { ready = pending.remove(at: index) }
            else { ready = nil }
            lock.unlock()
            if let ready, let status = ready.deferredStatus { send(ready, status: status) }
        }
    }

    // MARK: completion paths

    /// Local SMB mutation under `dir` — complete its pending notifies instantly.
    func postLocalChange(_ dir: InodeID) {
        complete({ $0.dir == dir && $0.completionFilter != 0 }, status: .notifyEnumDir)
    }

    /// CANCEL: match by AsyncId (async CANCEL) or MessageId; complete CANCELLED.
    func cancel(asyncId: UInt64, messageId: UInt64) {
        complete({ ($0.asyncId == asyncId && asyncId != 0) || $0.messageId == messageId }, status: .cancelled)
    }

    /// Handle CLOSE of a directory handle: drop and complete (CANCELLED) its notifies.
    func closeHandle(_ fileId: SMBFileId) {
        complete({ $0.fileId == fileId }, status: .cancelled)
    }

    func shutdown() {
        lock.lock()
        stopped = true
        let tasks = pollers.values.compactMap(\.task); pollers.removeAll()
        pending.removeAll()
        lock.unlock()
        for t in tasks { t.cancel() }
    }

    private func complete(_ pred: (Pending) -> Bool, status: NTStatus,
                          poller: (dir: InodeID, id: UUID)? = nil) {
        lock.lock()
        // A cancelled baseline may finish after a replacement watcher starts.
        // Only the currently reserved poller may complete that directory's watch.
        if let poller, pollers[poller.dir]?.id != poller.id { lock.unlock(); return }
        var matched: [Pending] = []
        var retained: [Pending] = []
        for var item in pending {
            if pred(item) && item.deferredStatus == nil {
                if item.interimPublished { matched.append(item) }
                else { item.deferredStatus = status; retained.append(item) }
            } else { retained.append(item) }
        }
        pending = retained
        var toStop: [Task<Void, Never>] = []
        for (dir, poller) in pollers where !pending.contains(where: {
            $0.dir == dir && $0.completionFilter != 0 && $0.deferredStatus == nil
        }) {
            if let task = poller.task { toStop.append(task) }
            pollers[dir] = nil
        }
        lock.unlock()
        for task in toStop { task.cancel() }
        for item in matched { send(item, status: status) }
    }

    private func hasPending(_ dir: InodeID, poller: UUID) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !stopped && pollers[dir]?.id == poller && pending.contains {
            $0.dir == dir && $0.completionFilter != 0 && $0.deferredStatus == nil
        }
    }

    // MARK: wire

    /// CHANGE_NOTIFY response ([MS-SMB2] §2.2.36): StructureSize=9,
    /// OutputBufferOffset(2), OutputBufferLength(4), Buffer. We send an empty
    /// buffer with STATUS_NOTIFY_ENUM_DIR. Error completions use SMB2 ERROR.
    private func send(_ p: Pending, status: NTStatus) {
        if ProcessInfo.processInfo.environment["CLOUDFS_LOG_SMB"] == "1" {
            SMBLog.line("changeNotify completion mid=\(p.messageId) async=\(p.asyncId) -> \(String(format: "0x%08X", status.rawValue))")
        }
        var respHdr = SMB2Header(command: .changeNotify, messageId: p.messageId,
                                 creditCharge: 1, creditReqGrant: 1, status: status.rawValue,
                                 flags: [.serverToRedir, .asyncCommand],
                                 sessionId: p.sessionId, asyncId: p.asyncId)
        respHdr.treeId = 0
        var body = ByteWriter()
        if status == .notifyEnumDir {
            body.u16(9); body.u16(UInt16(SMB2Header.size + 8)); body.u32(0)   // empty buffer
        } else {
            body.bytes(errorBody())
        }
        var chunk = ByteWriter()
        respHdr.encode(into: &chunk)
        chunk.bytes(body.data)
        var framed = DirectTCP.frame(length: chunk.count)
        framed.append(chunk.data)
        writer.write(framed)
    }

    // MARK: poller (out-of-band changes)

    private func startPoller(_ dir: InodeID, id: UUID, generation: UInt64) {
        let task = Task<Void, Never>.detached { [weak self] in await self?.pollLoop(dir, id: id, generation: generation) }
        lock.lock()
        guard !stopped, pollers[dir]?.id == id else { lock.unlock(); task.cancel(); return }
        pollers[dir]?.task = task
        lock.unlock()
    }

    private func pollLoop(_ dir: InodeID, id: UUID, generation: UInt64) async {
        let engine = await table.engineRef()
        var checkpoint: String?
        while !Task.isCancelled, hasPending(dir, poller: id) {
            if checkpoint == nil {
                // Failure is not an empty baseline and never a synthetic event.
                // Retry only after the bounded/cancellable engine waiter below.
                checkpoint = try? await engine.notificationCheckpoint(container: dir)
            }
            guard !Task.isCancelled, hasPending(dir, poller: id) else { return }
            let observed = await engine.waitForChanges(after: generation)
            guard !Task.isCancelled, hasPending(dir, poller: id) else { return }
            // Preserve this wake even when the checkpoint already includes the
            // publication: it may have arrived during baseline acquisition.
            if observed != generation {
                await completeRemoteChange(dir, poller: id)
                return
            }
            guard let baseline = checkpoint else { continue }
            guard let current = try? await engine.notificationCheckpoint(container: dir) else { continue }
            if current != baseline {
                await completeRemoteChange(dir, poller: id)
                return
            }
        }
    }

    private func completeRemoteChange(_ dir: InodeID, poller: UUID) async {
        guard !Task.isCancelled, hasPending(dir, poller: poller) else { return }
        // A client re-enumerates immediately after ENUM_DIR; never give it the
        // warm snapshot that preceded this notification.
        await table.invalidateMeta(dir)
        await table.invalidateListing(dir)
        guard !Task.isCancelled else { return }
        complete({ $0.dir == dir && $0.completionFilter != 0 }, status: .notifyEnumDir,
                 poller: (dir, poller))
    }

}

// MARK: - handlers

extension SMBServer {
    /// CHANGE_NOTIFY request ([MS-SMB2] §2.2.35): StructureSize=32, Flags(2),
    /// OutputBufferLength(4), FileId(16), CompletionFilter(4),
    /// Reserved(4). We register a pending notify and reply STATUS_PENDING (async).
    func handleChangeNotify(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        var r = ByteReader(body)
        // There is no reserved field between Flags and OutputBufferLength.
        // FileId starts at byte 8 in the exact 32-byte fixed request body.
        guard (try? r.u16()) == 32,
              let flags = try? r.u16(), flags & ~UInt16(1) == 0,
              let outputLength = try? r.u32(), outputLength <= 1 << 20,
              let persistent = try? r.u64(), let volatile = try? r.u64(),
              let completionFilter = try? r.u32(), (try? r.u32()) != nil else {
            return (.invalidParameter, errorBody(), DispatchExtra())
        }
        let fileId = SMBFileId(persistent: persistent, volatile: volatile)
        guard let open = state.open(fileId) else { return (.fileClosed, errorBody(), DispatchExtra()) }
        guard open.isDir else { return (.invalidParameter, errorBody(), DispatchExtra()) }
        // FILE_LIST_DIRECTORY shares the FILE_READ_DATA bit. A metadata-only
        // open must not gain visibility by subscribing to directory changes.
        guard open.hasAccess(SMBAccess.readData) else { return (.accessDenied, errorBody(), DispatchExtra()) }
        guard let notify = state.notify else { return (.notSupported, errorBody(), DispatchExtra()) }
        let asyncId = state.newAsyncId()
        // Capture the in-memory wake generation before registration/PENDING.
        // A detached poller must not start with a later generation and swallow
        // a peer publication that arrived after this request was acknowledged.
        // No gateway/checkpoint I/O is performed on this synchronous path.
        let generation: UInt64 = Self.bridgeSync {
            let engine = await self.table.engineRef()
            return await engine.changeGeneration()
        }
        // Reserved is ignored. Unknown filter bits are ignored; with no valid
        // bits the request stays pending until CANCEL or directory CLOSE.
        notify.register(NotifySession.Pending(messageId: hdr.messageId, asyncId: asyncId,
                                              sessionId: hdr.sessionId, fileId: open.fileId, dir: open.node,
                                              completionFilter: completionFilter & 0x0fff), generation: generation)
        // Interim STATUS_PENDING async response; the completion frame follows later.
        return (.pending, errorBody(), DispatchExtra(asyncPending: asyncId))
    }

    /// CANCEL ([MS-SMB2] §2.2.30): no response of its own — it completes the
    /// referenced pending op with STATUS_CANCELLED.
    func handleCancel(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        state.notify?.cancel(asyncId: hdr.asyncId, messageId: hdr.messageId)
        return (.success, Data(), DispatchExtra(suppressResponse: true))
    }
}
