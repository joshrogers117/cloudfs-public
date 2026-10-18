// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
import CloudFSTransfer
@testable import cloudfsd

private actor ShutdownGate {
    var entered = false
    private var released = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    // Deliberately ignores cancellation: a remote CAS can already have committed.
    func wait() async {
        entered = true
        guard !released else { return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() { released = true; let all = waiters; waiters = []; for waiter in all { waiter.resume() } }
}
private actor ShutdownFlag {
    var value = false
    func set() { value = true }
}
private actor ShutdownGateway: GatewayClient {
    let commitGate: ShutdownGate?
    let readGate: ShutdownGate?
    private var failCommits: Bool
    private var failedClosesRemaining: Int
    var commits = 0
    private(set) var openedHandles: Set<String> = []
    private(set) var closedHandles: Set<String> = []
    private var activeOpenHandles: [String:(inode:InodeID,access:OpenFileAccess,sharing:OpenFileSharing)] = [:]
    private(set) var renewedBatches: [[String]] = []
    private(set) var deleteInitiator: String?
    private(set) var renameInitiator: String?
    init(commitGate: ShutdownGate? = nil, readGate: ShutdownGate? = nil,
         failCommits: Bool = false, failedCloses: Int = 0) {
        self.commitGate = commitGate; self.readGate = readGate
        self.failCommits = failCommits; self.failedClosesRemaining = failedCloses
    }
    nonisolated var supportsOpenHandles: Bool { true }
    func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String, access: OpenFileAccess,
                           sharing: OpenFileSharing, ttlMs: Int) async throws -> OpenHandleLease {
        for existing in activeOpenHandles.values where existing.inode == id {
            if existing.access.rawValue & ~sharing.rawValue != 0
                || access.rawValue & ~existing.sharing.rawValue != 0 {
                return OpenHandleLease(granted: false, reason: "sharing_violation")
            }
        }
        openedHandles.insert(handle)
        activeOpenHandles[handle] = (id,access,sharing)
        return OpenHandleLease(granted: true)
    }
    func renewOpenHandle(filespace: FilespaceID, handle: String, ttlMs: Int) async throws -> OpenHandleLease {
        OpenHandleLease(granted: openedHandles.contains(handle) && !closedHandles.contains(handle))
    }
    func renewOpenHandles(filespace: FilespaceID, handles: [String], ttlMs: Int) async throws -> [OpenHandleRenewal] {
        renewedBatches.append(handles)
        return handles.map { OpenHandleRenewal(handleId: $0, granted: openedHandles.contains($0) && !closedHandles.contains($0)) }
    }
    func closeOpenHandle(filespace: FilespaceID, handle: String) async throws {
        if failedClosesRemaining > 0 {
            failedClosesRemaining -= 1
            throw EngineError(.networkError, "controlled close failure")
        }
        if openedHandles.contains(handle) { closedHandles.insert(handle); activeOpenHandles[handle] = nil }
    }
    func setFailCommits(_ value: Bool) { failCommits = value }
    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL {
        var url = URLComponents(string: "https://blob.test/blob")!
        url.queryItems = [URLQueryItem(name: "key", value: key)]
        return PresignedURL(url: url.url!.absoluteString, expiresIn: 300)
    }
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest {
        await readGate?.wait()
        throw EngineError(.notFound, "new file")
    }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata {
        await commitGate?.wait()
        if failCommits {
            throw EngineError(.networkError, "controlled commit failure")
        }
        commits += 1
        return ItemMetadata(id: manifest.itemID, parent: .root, name: "file", isDir: false,
                            size: manifest.size, contentVersion: "committed", metadataVersion: String(commits + 1))
    }
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws { throw EngineError.unimplemented() }
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { ([], nil) }
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata {
        ItemMetadata(id: id, parent: .root, name: "file", isDir: false, size: 0, contentVersion: "", metadataVersion: "1")
    }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool, openHandle: String?) async throws {
        deleteInitiator = openHandle
    }
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String,
                    expectedVersion: Int, replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata {
        renameInitiator = openHandle
        return ItemMetadata(id: id, parent: newParent, name: newName, isDir: false, size: 0,
                            contentVersion: "", metadataVersion: String(expectedVersion + 1))
    }
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { (0, [], nil) }
}
private extension CloudFSEngine {
    func transferForShutdownTest() throws -> RealTransferEngine { try require("fs").transfer }
}

final class DisconnectShutdownTests: XCTestCase {
    private func until(seconds: Int = 5, _ predicate: () async -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(seconds))
        while !(await predicate()), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(1)) }
        let result = await predicate(); XCTAssertTrue(result)
        if !result { throw EngineError(.internal, "shutdown test timed out") }
    }
    private func fixture(_ gateway: ShutdownGateway) throws -> (CloudFSEngine, URL) {
        GWStub.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("shutdown-\(UUID())")
        let session = GWStub.session()
        addTeardownBlock { session.invalidateAndCancel(); try? FileManager.default.removeItem(at: root) }
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: root.path, cacheSizeBytes: 4 << 20,
            controlSocketPath: root.appendingPathComponent("socket").path, gatewayBaseURL: "https://gw.test"),
            gateway: gateway, blobSession: session, key: try FilespaceKey(masterKeyBytes: Data(repeating: 7, count: 32)))
        return (engine, root)
    }
    func testForcedDisconnectWaitsForLateCommitBeforeReconnectCanReuseJournal() async throws {
        let gate = ShutdownGate(), gateway = ShutdownGateway(commitGate: gate)
        let (engine, root) = try fixture(gateway)
        addTeardownBlock { await gate.release() }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let old = try await engine.transferForShutdownTest()
        try await old.stageReplace(filespace: "fs", itemID: "file", data: Data("old bytes".utf8), baseVersion: "1", fence: nil)
        try await until { await gate.entered }
        let disconnected = ShutdownFlag()
        let disconnect = Task {
            let value = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
            await disconnected.set(); return value
        }
        try await until {
            do { _ = try await old.resume(filespace: "fs"); return false }
            catch let error as EngineError { return error.kind == .notConnected }
            catch { return false }
        }
        let connected = ShutdownFlag()
        let reconnect = Task {
            let value = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
            await connected.set(); return value
        }
        for _ in 0..<20 { await Task.yield() }
        let disconnectedEarly = await disconnected.value, connectedEarly = await connected.value
        XCTAssertFalse(disconnectedEarly); XCTAssertFalse(connectedEarly)
        let journalRoot = root.appendingPathComponent("fs")
        let journal = WriteBackJournal(cacheDir: journalRoot.path)
        XCTAssertEqual(try journal.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("old bytes".utf8))
        await gate.release()
        _ = try await disconnect.value; _ = try await reconnect.value
        let fresh = try await engine.transferForShutdownTest()
        XCTAssertFalse(old === fresh)
        _ = try await fresh.pause(filespace: "fs")
        try await fresh.stageReplace(filespace: "fs", itemID: "file", data: Data("new acknowledged bytes".utf8), baseVersion: "2", fence: nil)
        // Old-session entry points cannot reopen its journal or restart uploads.
        do { try await old.stageReplace(filespace: "fs", itemID: "file", data: Data("stale".utf8), baseVersion: "1", fence: nil); XCTFail("closed session wrote") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notConnected) }
        do { _ = try await old.stagedBlock(filespace: "fs", itemID: "file", blockIndex: 0); XCTFail("closed session read the new journal") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notConnected) }
        do { try await old.ensureRange(filespace: "fs", itemID: "file", offset: 0, length: 1); XCTFail("closed session issued a read") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notConnected) }
        await old.shutdown(filespace: "fs")
        XCTAssertEqual(try WriteBackJournal(cacheDir: journalRoot.path).readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("new acknowledged bytes".utf8))
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
        let replay = try await WriteBackJournal(cacheDir: journalRoot.path).replay()
        XCTAssertEqual(replay.first?.blockLengths, [0: 22])
    }
    func testDisconnectDrainsAnAlreadyAdmittedStageButRejectsQueuedStaging() async throws {
        let gate = ShutdownGate(), gateway = ShutdownGateway(readGate: gate)
        let (engine, root) = try fixture(gateway)
        addTeardownBlock { await gate.release() }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let transfer = try await engine.transferForShutdownTest()
        let stage = Task { try await transfer.stageWrite(filespace: "fs", itemID: "file", offset: 0, data: Data("retained".utf8), baseVersion: "1", fence: nil) }
        try await until { await gate.entered }
        let finished = ShutdownFlag()
        let disconnect = Task { _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false)); await finished.set() }
        try await until {
            do { _ = try await transfer.resume(filespace: "fs"); return false } catch { return true }
        }
        let done = await finished.value; XCTAssertFalse(done)
        do { try await transfer.stageTruncate(filespace: "fs", itemID: "file", newSize: 0, baseVersion: "1", fence: nil); XCTFail("closed session admitted truncate") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notConnected) }
        await gate.release()
        let written = try await stage.value; XCTAssertEqual(written, 8)
        _ = try await disconnect.value
        let journal = WriteBackJournal(cacheDir: root.appendingPathComponent("fs").path)
        XCTAssertEqual(try journal.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("retained".utf8))
        let commits = await gateway.commits; XCTAssertEqual(commits, 0)
    }

    func testForcedDisconnectKeepsOpenReferenceForStagedUnlinkedRecovery() async throws {
        let gate = ShutdownGate(), gateway = ShutdownGateway(commitGate: gate)
        let (engine, root) = try fixture(gateway)
        addTeardownBlock { await gate.release() }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let handle = UUID().uuidString
        try await engine.beginOpen(filespace: "fs", id: "file", handle: handle,
                                   access: [.write], sharing: [])
        let openedAfterAcquire = await gateway.openedHandles
        XCTAssertTrue(openedAfterAcquire.contains(handle))
        let transfer = try await engine.transferForShutdownTest()
        try await transfer.stageReplace(filespace: "fs", itemID: "file", data: Data("retained after unlink".utf8),
                                        baseVersion: "1", fence: nil)
        try await until { await gate.entered }

        let disconnected = ShutdownFlag()
        let disconnect = Task {
            let value = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
            await disconnected.set(); return value
        }
        try await until {
            do { _ = try await transfer.resume(filespace: "fs"); return false }
            catch let error as EngineError { return error.kind == .notConnected }
            catch { return false }
        }
        await gate.release()
        _ = try await disconnect.value

        let opened = await gateway.openedHandles
        let closed = await gateway.closedHandles
        XCTAssertTrue(opened.contains(handle))
        XCTAssertFalse(closed.contains(handle), "dirty journal recovery still depends on the retained inode")
        let journal = WriteBackJournal(cacheDir: root.appendingPathComponent("fs").path)
        XCTAssertEqual(try journal.readBlock(filespace: "fs", itemID: "file", blockIndex: 0),
                       Data("retained after unlink".utf8))
    }

    func testEndOpenWaitsForDurableFlushAndRemoteReleaseBeforeExclusiveDeleteOpen() async throws {
        let gate = ShutdownGate(), gateway = ShutdownGateway(commitGate: gate)
        let (engine, _) = try fixture(gateway)
        addTeardownBlock { await gate.release() }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let oldHandle = UUID().uuidString
        try await engine.beginOpen(filespace: "fs", id: "file", handle: oldHandle,
                                   access: [.write], sharing: [.read, .write, .delete])
        let transfer = try await engine.transferForShutdownTest()
        try await transfer.stageReplace(filespace: "fs", itemID: "file", data: Data("old descriptor bytes".utf8),
                                        baseVersion: "1", fence: nil)
        try await until { await gate.entered }

        let closeFinished = ShutdownFlag()
        let closing = Task {
            await engine.endOpen(filespace: "fs", id: "file", handle: oldHandle)
            await closeFinished.set()
        }
        let secondCloseFinished = ShutdownFlag()
        let secondClosing = Task {
            await engine.endOpen(filespace: "fs", id: "file", handle: oldHandle)
            await secondCloseFinished.set()
        }
        for _ in 0..<20 { await Task.yield() }
        let returnedBeforeFlush = await closeFinished.value, secondReturnedBeforeFlush = await secondCloseFinished.value
        XCTAssertFalse(returnedBeforeFlush, "SMB CLOSE must not release its descriptor while acknowledged data is undurable")
        XCTAssertFalse(secondReturnedBeforeFlush, "a concurrent endOpen must await the shared close attempt")

        let deleteHandle = UUID().uuidString
        do {
            try await engine.beginOpen(filespace: "fs", id: "file", handle: deleteHandle,
                                       access: [.delete], sharing: [])
            XCTFail("an exclusive delete open must wait while the old durable reference is still active")
        } catch let error as EngineError {
            XCTAssertEqual(error.kind, .locked)
        }

        await gate.release()
        await closing.value; await secondClosing.value
        let closed = await gateway.closedHandles
        XCTAssertTrue(closed.contains(oldHandle), "endOpen must close the remote reference before it returns")
        try await engine.beginOpen(filespace: "fs", id: "file", handle: deleteHandle,
                                   access: [.delete], sharing: [])
        await engine.endOpen(filespace: "fs", id: "file", handle: deleteHandle)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
    }

    func testFailedFirstEndOpenFlushKeepsReferenceUntilRetryIsDurable() async throws {
        let gate = ShutdownGate(), gateway = ShutdownGateway(commitGate: gate, failCommits: true)
        let (engine, _) = try fixture(gateway)
        addTeardownBlock { await gate.release() }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let oldHandle = UUID().uuidString
        try await engine.beginOpen(filespace: "fs", id: "file", handle: oldHandle,
                                   access: [.write], sharing: [.read, .write, .delete])
        let transfer = try await engine.transferForShutdownTest()
        try await transfer.stageReplace(filespace: "fs", itemID: "file", data: Data("recovery bytes".utf8),
                                        baseVersion: "1", fence: nil)
        try await until { await gate.entered }

        let closing = Task { await engine.endOpen(filespace: "fs", id: "file", handle: oldHandle) }
        await gate.release()
        await closing.value // the controlled first upload fails, so endOpen returns with a retry armed
        let initiallyClosed = await gateway.closedHandles.contains(oldHandle)
        XCTAssertFalse(initiallyClosed, "a failed flush must leave the retained open reference active")

        let deleteHandle = UUID().uuidString
        do {
            try await engine.beginOpen(filespace: "fs", id: "file", handle: deleteHandle,
                                       access: [.delete], sharing: [])
            XCTFail("exclusive delete must remain denied until journal recovery is durable")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }

        await gateway.setFailCommits(false)
        try await transfer.stageReplace(filespace: "fs", itemID: "file", data: Data("recovery bytes".utf8),
                                        baseVersion: "1", fence: nil)
        _ = try await transfer.flush(filespace: "fs", path: "file", wait: true, timeoutMs: 5_000)
        try await until(seconds: 8) { await gateway.closedHandles.contains(oldHandle) }
        try await engine.beginOpen(filespace: "fs", id: "file", handle: deleteHandle,
                                   access: [.delete], sharing: [])
        await engine.endOpen(filespace: "fs", id: "file", handle: deleteHandle)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
    }

    func testTransientRemoteCloseFailureKeepsReferenceUntilRetryAcknowledges() async throws {
        let gateway = ShutdownGateway(failedCloses: 1)
        let (engine, _) = try fixture(gateway)
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let oldHandle = UUID().uuidString
        try await engine.beginOpen(filespace: "fs", id: "file", handle: oldHandle,
                                   access: [.write], sharing: [.read, .write, .delete])

        await engine.endOpen(filespace: "fs", id: "file", handle: oldHandle)
        let initiallyClosed = await gateway.closedHandles.contains(oldHandle)
        XCTAssertFalse(initiallyClosed, "a failed remote close acknowledgement must keep the local lease active")
        let deleteHandle = UUID().uuidString
        do {
            try await engine.beginOpen(filespace: "fs", id: "file", handle: deleteHandle,
                                       access: [.delete], sharing: [])
            XCTFail("exclusive delete must remain denied while the close acknowledgement is missing")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .locked) }

        try await until(seconds: 8) { await gateway.closedHandles.contains(oldHandle) }
        try await engine.beginOpen(filespace: "fs", id: "file", handle: deleteHandle,
                                   access: [.delete], sharing: [])
        await engine.endOpen(filespace: "fs", id: "file", handle: deleteHandle)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
    }

    func testReachabilityGatewayForwardsOpenLifecycleAndInitiatorHandles() async throws {
        let gateway = ShutdownGateway()
        let wrapped = ReachabilityGateway(base: gateway, tracker: GatewayReachabilityTracker())
        XCTAssertTrue(wrapped.supportsOpenHandles)
        let handle = UUID().uuidString
        let lease = try await wrapped.acquireOpenHandle(filespace: "fs", id: "file", handle: handle,
            access: [.delete], sharing: [.delete], ttlMs: 90_000)
        XCTAssertTrue(lease.granted)
        let renewals = try await wrapped.renewOpenHandles(filespace: "fs", handles: [handle], ttlMs: 90_000)
        XCTAssertEqual(renewals, [OpenHandleRenewal(handleId: handle, granted: true)])
        try await wrapped.deleteItem(filespace: "fs", id: "file", recursive: false, openHandle: handle)
        _ = try await wrapped.renameItem(filespace: "fs", id: "file", newParent: "parent", newName: "moved",
                                         expectedVersion: 1, replacing: nil, openHandle: handle)
        try await wrapped.closeOpenHandle(filespace: "fs", handle: handle)

        let opened = await gateway.openedHandles
        let closed = await gateway.closedHandles
        let batches = await gateway.renewedBatches
        let deleteInitiator = await gateway.deleteInitiator
        let renameInitiator = await gateway.renameInitiator
        XCTAssertTrue(opened.contains(handle))
        XCTAssertTrue(closed.contains(handle))
        XCTAssertEqual(batches, [[handle]])
        XCTAssertEqual(deleteInitiator, handle)
        XCTAssertEqual(renameInitiator, handle)
    }
}
