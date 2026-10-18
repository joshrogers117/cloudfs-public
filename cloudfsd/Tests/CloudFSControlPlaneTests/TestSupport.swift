// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
@testable import CloudFSControlPlane

#if canImport(Glibc)
import Glibc
#else
import Darwin
#endif

// MARK: - In-process harness over a socketpair

/// Drives the real `Connection` read loop over one half of a `socketpair()`, with
/// the test holding the other half. No filesystem socket — fully in-process.
final class Harness {
    let server = UnixSocketControlPlane()
    let client: SocketFD            // the test's end
    private let connection: Connection
    private var rxBuffer = [UInt8]()

    init(engine: any Engine = MockEngine()) throws {
        let (a, b) = try makeSocketPair()
        self.client = a
        // Block synchronously so `init` returns with the connection live.
        let srv = server
        let conn = Self.startSync { await srv.serveConnection(fd: b, engine: engine) }
        self.connection = conn
    }

    func tearDown() {
        client.close()
        let srv = server
        Self.startSync { await srv.stop() }
    }

    // -- writing --

    func writeFrame(_ req: RPCRequest) throws {
        try client.writeAll([UInt8](try FrameEncoder.encode(req)))
    }

    /// Encode params into an RPCRequest, send it, and read back one response frame.
    func call(method: String, id: RPCID, params: CodableValue) async throws -> RPCResponse {
        try writeFrame(RPCRequest(id: id, method: method, params: params))
        return try await readResponse()
    }

    // -- reading (decodes newline frames off the client FD) --

    func readResponse() async throws -> RPCResponse {
        let data = try await nextFrame()
        return try JSONDecoder().decode(RPCResponse.self, from: data)
    }

    func readNotification() async throws -> RPCNotification {
        let data = try await nextFrame()
        return try JSONDecoder().decode(RPCNotification.self, from: data)
    }

    /// Pull the next complete newline-framed JSON object from the client FD.
    /// Reads are blocking; we hop them onto a detached task so the test stays async.
    private func nextFrame() async throws -> Data {
        // Drain anything already buffered.
        if let f = takeBufferedFrame() { return f }
        let client = self.client
        while true {
            let chunk = try await blockingRead(client)
            if chunk.isEmpty { throw HarnessError.eof }
            rxBuffer.append(contentsOf: chunk)
            if let f = takeBufferedFrame() { return f }
        }
    }

    private func takeBufferedFrame() -> Data? {
        guard let nl = rxBuffer.firstIndex(of: 0x0A) else { return nil }
        let frame = Array(rxBuffer[0..<nl])
        rxBuffer.removeFirst(nl + 1)
        return frame.isEmpty ? takeBufferedFrame() : Data(frame)
    }

    enum HarnessError: Error { case eof }

    /// Run an async closure to completion synchronously (used only in init/tearDown).
    @discardableResult
    static func startSync<T>(_ body: @escaping @Sendable () async -> T) -> T {
        let box = Box<T>()
        let sem = DispatchSemaphore(value: 0)
        Task.detached { box.value = await body(); sem.signal() }
        sem.wait()
        return box.value!
    }
    final class Box<T>: @unchecked Sendable { var value: T? }
}

// MARK: - SocketFD test conveniences

extension SocketFD {
    /// Write raw bytes (used to send pre-encoded coalesced frames).
    func writeRaw(_ data: Data) {
        try? writeAll([UInt8](data))
    }
}

// MARK: - Real-socket client helpers (for the bound-socket test)

func connectUnix(_ path: String) throws -> SocketFD {
    #if canImport(Glibc)
    let stream = Int32(SOCK_STREAM.rawValue)
    #else
    let stream = SOCK_STREAM
    #endif
    let fd = socket(AF_UNIX, stream, 0)
    guard fd >= 0 else { throw POSIXSocketError.errno("socket", errno) }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    let bytes = Array(path.utf8)
    withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }
    let size = socklen_t(MemoryLayout<sockaddr_un>.size)
    let rc = withUnsafePointer(to: &addr) { ap in
        ap.withMemoryRebound(to: sockaddr.self, capacity: 1) { sp in
            connect(fd, sp, size)
        }
    }
    guard rc == 0 else { let e = errno; close(fd); throw POSIXSocketError.errno("connect", e) }
    return try SocketFD(fd)
}

func readOneResponse(from fd: SocketFD) async throws -> RPCResponse {
    var buf = [UInt8]()
    while true {
        let chunk = try await blockingRead(fd)
        if chunk.isEmpty { throw Harness.HarnessError.eof }
        buf.append(contentsOf: chunk)
        if let nl = buf.firstIndex(of: 0x0A) {
            return try JSONDecoder().decode(RPCResponse.self, from: Data(buf[0..<nl]))
        }
    }
}

/// Blocking `read()` on a dedicated OS thread (mirrors the server). Keeps the
/// cooperative pool free so the server's in-flight async work isn't starved.
func blockingRead(_ fd: SocketFD) async throws -> [UInt8] {
    try await withCheckedThrowingContinuation { (c: CheckedContinuation<[UInt8], Error>) in
        let t = Thread {
            do { c.resume(returning: try fd.read()) }
            catch { c.resume(throwing: error) }
        }
        t.start()
    }
}

func waitForFile(_ path: String, timeout: TimeInterval = 5) async throws {
    let deadline = Date().addingTimeInterval(timeout)
    while !FileManager.default.fileExists(atPath: path) {
        if Date() > deadline { throw Harness.HarnessError.eof }
        try await Task.sleep(nanoseconds: 5_000_000)
    }
}

// MARK: - Mock Engine

/// A fully-canned `Engine`. Every management method returns a representative value
/// so the round-trip suite exercises encode/decode for the whole surface. Optional
/// error hooks let a test force a specific `EngineError` per method.
final class MockEngine: Engine, @unchecked Sendable {
    func snapshotMount(_ p: SnapshotMountParams) async throws -> SnapshotMount {
        SnapshotMount(mountId: "snapshot-1", filespace: p.filespace, snapshotId: p.snapshotId, name: "Snapshot", mountPath: "/snap", status: .mounted)
    }
    func snapshotUnmount(_ p: SnapshotUnmountParams) async throws -> SnapshotMount {
        SnapshotMount(mountId: p.mountId, filespace: "space-1", snapshotId: "snap-1", name: "Snapshot", status: .unmounted)
    }
    func snapshotMounts(_ p: SnapshotMountsParams) async throws -> [SnapshotMount] { [] }

    var events: [EventNotification] = []
    var flushError: EngineError?

    static let sampleCache = CacheInfo(filespace: "space-1", location: "/cache", sizeBytes: 100,
                                       usedBytes: 100, pinnedBytes: 10, maxBytes: 1000,
                                       freeOnVolumeBytes: 5000, hitRate: 0.9)
    static let sampleFilespace = EngineFilespace(id: "space-1", name: "Space One", status: .connected,
                                                 mountPath: "/Volumes/space-1", rootPoint: nil, role: "owner")
    static let sampleStatus = EngineStatus(filespace: "space-1", connection: .connected,
                                           mountPath: "/Volumes/space-1", latencyMsToBucket: 12.5,
                                           pendingUploads: 0, pendingBytes: 0, cache: sampleCache, health: .green)
    static let sampleSync = SyncState(path: "/a/b", inSync: true, pendingUploads: 0, pendingBytes: 0)

    func filespaceList() async throws -> [EngineFilespace] { [Self.sampleFilespace] }
    func connect(_ p: FilespaceConnectParams) async throws -> EngineFilespace { Self.sampleFilespace }
    func disconnect(_ p: FilespaceDisconnectParams) async throws -> EngineFilespace { Self.sampleFilespace }
    func setConnectionState(_ p: FilespaceSetConnectionParams) async throws -> EngineFilespace { Self.sampleFilespace }
    func mount(_ p: MountParams) async throws -> EngineFilespace { Self.sampleFilespace }
    func unmount(_ p: UnmountParams) async throws -> EngineFilespace {
        var fs = Self.sampleFilespace; fs.mountPath = nil; return fs
    }
    func status(_ p: StatusParams) async throws -> [EngineStatus] { [Self.sampleStatus] }
    func cacheInfo(_ p: CacheInfoParams) async throws -> CacheInfo { Self.sampleCache }
    func cacheSetSize(_ p: CacheSetSizeParams) async throws -> CacheInfo {
        var c = Self.sampleCache; c.maxBytes = p.bytes; return c
    }
    func cacheSetLocation(_ p: CacheSetLocationParams) async throws -> CacheInfo {
        var c = Self.sampleCache; c.location = p.path; return c
    }
    func cacheClear(_ p: CacheClearParams) async throws -> CacheInfo {
        var c = Self.sampleCache; c.usedBytes = c.pinnedBytes; return c
    }
    func pin(_ p: PinParams) async throws -> PinState {
        PinState(path: p.path, pinned: true, recursive: p.recursive ?? false, blocks: 3)
    }
    func unpin(_ p: PinParams) async throws -> PinState {
        PinState(path: p.path, pinned: false, recursive: p.recursive ?? false, blocks: 0)
    }
    func pinList(_ p: FilespaceOnlyParams) async throws -> [PinState] {
        [PinState(path: "/a", pinned: true, recursive: false, blocks: 2)]
    }
    func prefetch(_ p: PathParams) async throws -> PrefetchAck { PrefetchAck(path: p.path, queuedBlocks: 4) }
    func evict(_ p: PathParams) async throws -> EvictAck { EvictAck(path: p.path, evictedBlocks: 4, freedBytes: 4096) }
    func transfersCurrent(_ p: FilespaceOnlyParams) async throws -> [Transfer] {
        [Transfer(id: "t1", filespace: p.filespace, path: "/a", direction: .upload,
                  bytesDone: 5, bytesTotal: 10, state: .active)]
    }
    func transfersPause(_ p: FilespaceOnlyParams) async throws -> PauseResult { PauseResult(paused: true) }
    func transfersResume(_ p: FilespaceOnlyParams) async throws -> PauseResult { PauseResult(paused: false) }
    func linkCreate(_ p: LinkCreateParams) async throws -> LinkCreateResult {
        LinkCreateResult(filespace: p.filespace, itemId: "ino-x")
    }
    func linkResolve(_ p: LinkResolveParams) async throws -> LinkResolveResult {
        LinkResolveResult(filespace: p.filespace, path: "a/b")
    }
    func recoveryList(_ p: FilespaceOnlyParams) async throws -> [RecoveryItem] {
        [RecoveryItem(id: "ino-x", bytes: 42, reason: "Upload failed", kind: "upload", canRetry: true)]
    }
    func recoveryRetry(_ p: RecoveryItemParams) async throws {}
    func recoveryExport(_ p: RecoveryExportParams) async throws -> RecoveryExportResult {
        RecoveryExportResult(path: p.destination, bytes: 42)
    }
    func recoveryComplete(_ p: RecoveryExportParams) async throws {}
    func syncState(_ p: SyncStateParams) async throws -> SyncState { Self.sampleSync }
    func flush(_ p: FlushParams) async throws -> SyncState {
        if let e = flushError { throw e }
        return Self.sampleSync
    }
    func dataReadRange(_ p: DataReadRangeParams) async throws -> DataReadRangeResult {
        DataReadRangeResult(path: "/tmp/mock-range", offset: p.offset, length: p.length)
    }
    static let sampleItem = ItemMetadata(id: "ino-x", parent: .root, name: "clip.mov", isDir: false,
                                         size: 1024, contentVersion: "cv-1", metadataVersion: "mv-1")
    func dataLookup(_ p: DataLookupParams) async throws -> ItemMetadata { Self.sampleItem }
    func dataEnumerate(_ p: DataEnumerateParams) async throws -> DataEnumerateResult {
        DataEnumerateResult(items: [Self.sampleItem], nextPage: nil)
    }
    func dataEnumerateChanges(_ p: DataEnumerateChangesParams) async throws -> DataEnumerateChangesResult {
        DataEnumerateChangesResult(updated: [Self.sampleItem], deleted: [], newAnchor: "a2", moreComing: false)
    }
    func systemVersion() async throws -> SystemVersionResult {
        SystemVersionResult(engine: "1.2.3-test", api: ControlAPI.version)
    }
    func events(_ p: EventsSubscribeParams) -> AsyncStream<EventNotification> {
        let canned = events
        return AsyncStream { cont in
            for e in canned { cont.yield(e) }
            cont.finish()
        }
    }
}
