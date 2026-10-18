// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB P5: byte-range locks + CHANGE_NOTIFY.

import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class NotifyLockTests: XCTestCase {
    private func connected(_ engine: MemoryEngine) throws -> (SMBServer, SMBTestClient) {
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: "pw"))
        let port = try server.start()
        let client = SMBTestClient()
        try client.connect(port: port)
        _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "cloudfs")
        return (server, client)
    }

    func testByteRangeLockConflictAndRelease() throws {
        let engine = MemoryEngine()
        engine.seed("f.bin", data: Data(repeating: 0, count: 1000))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let a = try client.create(path: "f.bin")
        let b = try client.create(path: "f.bin")   // second handle on the same node

        // A takes an exclusive lock on [0,100).
        XCTAssertEqual(try client.lock(fileId: a.fileId, offset: 0, length: 100, flags: 2), NTStatus.success.rawValue)
        // B's overlapping exclusive lock is refused.
        XCTAssertEqual(try client.lock(fileId: b.fileId, offset: 50, length: 100, flags: 2),
                       NTStatus.lockNotGranted.rawValue)
        // A releases; B can now take it.
        XCTAssertEqual(try client.lock(fileId: a.fileId, offset: 0, length: 100, flags: 4 /* UNLOCK */), NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId: b.fileId, offset: 50, length: 100, flags: 2), NTStatus.success.rawValue)

        // Closing A's handle releases any of its remaining locks (none here).
        try client.close(fileId: a.fileId)
        try client.close(fileId: b.fileId)
    }

    func testChangeNotifyCompletesOnLocalMutation() throws {
        let engine = MemoryEngine()
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        // Watch the root directory.
        let dir = try client.create(path: "")
        let interim = try client.changeNotifyRequest(fileId: dir.fileId)
        XCTAssertEqual(interim.header.status, NTStatus.pending.rawValue, "expected interim STATUS_PENDING")
        XCTAssertTrue(interim.header.flags.contains(.asyncCommand), "interim must be an async response")

        // Trigger a local change: create a file under root (send raw so we can
        // collect the async completion which arrives ahead of the create response).
        try client.sendOnly(.create, body: client.createBody(path: "fresh.txt"))

        // Among the next frames, one must be the CHANGE_NOTIFY completion.
        var sawNotify = false
        for _ in 0..<3 {
            guard let resp = client.readAsyncResponse(timeoutMs: 2000) else { break }
            if resp.header.command == .changeNotify {
                XCTAssertEqual(resp.header.status, NTStatus.notifyEnumDir.rawValue,
                               "completion should be STATUS_NOTIFY_ENUM_DIR")
                sawNotify = true
                break
            }
        }
        XCTAssertTrue(sawNotify, "CHANGE_NOTIFY did not complete after a local mutation")
    }

    func testCancelCompletesNotify() throws {
        let engine = MemoryEngine()
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let dir = try client.create(path: "")
        _ = try client.changeNotifyRequest(fileId: dir.fileId)
        // Closing the watched handle cancels the pending notify (STATUS_CANCELLED).
        // Send the close RAW: its cancellation frame arrives ahead of the close
        // response, so we must read both frames ourselves rather than via close().
        var cw = ByteWriter(); cw.u16(24); cw.u16(0); cw.u32(0)
        cw.u64(dir.fileId.persistent); cw.u64(dir.fileId.volatile)
        try client.sendOnly(.close, body: cw.data)
        var sawCancel = false
        for _ in 0..<3 {
            guard let resp = client.readAsyncResponse(timeoutMs: 1500) else { break }
            if resp.header.command == .changeNotify, resp.header.status == NTStatus.cancelled.rawValue {
                XCTAssertEqual(resp.body, Data([9, 0, 0, 0, 0, 0, 0, 0]))
                sawCancel = true; break
            }
        }
        XCTAssertTrue(sawCancel, "notify was not cancelled on handle close")
    }
}

extension NotifyLockTests {
    func testLocksConflictAcrossSeparateSMBConnectionsAndReleaseOnDisconnect() throws {
        let engine = MemoryEngine(); engine.seed("shared.bin", data: Data(count: 100))
        let (server, first) = try connected(engine)
        let second = SMBTestClient()
        defer { first.close(); second.close(); server.stop() }
        try second.connect(port: server.port)
        _ = try second.negotiate(); try second.sessionSetup(user: "cfs", password: "pw")
        _ = try second.treeConnect(share: "cloudfs")
        let a = try first.create(path: "shared.bin"), b = try second.create(path: "shared.bin")
        XCTAssertNotEqual(a.fileId, b.fileId, "connections must not alias first handle")
        XCTAssertEqual(try first.lock(fileId: a.fileId, offset: 0, length: 50, flags: 2), NTStatus.success.rawValue)
        XCTAssertEqual(try second.lock(fileId: b.fileId, offset: 0, length: 50, flags: 2), NTStatus.lockNotGranted.rawValue)
        first.close()
        var result = NTStatus.lockNotGranted.rawValue
        for _ in 0..<100 {
            result = try second.lock(fileId: b.fileId, offset: 0, length: 50, flags: 2)
            if result == NTStatus.success.rawValue { break }
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertEqual(result, NTStatus.success.rawValue, "connection shutdown must release all locks")
    }

    func testMultiRangeFailureDoesNotLeavePartialLocks() {
        let table = LockTable(), id = InodeID("file")
        let a = SMBFileId(persistent: 1, volatile: 1), b = SMBFileId(persistent: 2, volatile: 1)
        XCTAssertTrue(table.acquire(id, offset: 100, length: 100, exclusive: true, owner: a))
        XCTAssertFalse(table.acquireAll(id, ranges: [
            LockRange(offset: 0, length: 20, exclusive: true, owner: b),
            LockRange(offset: 120, length: 20, exclusive: true, owner: b)
        ]))
        XCTAssertFalse(table.hasRanges(owner: b))
    }

    func testNewRemoteChildAppearsDespiteWarmDirectoryCache() async throws {
        let engine = MemoryEngine()
        let shared = NodeTable(engine: engine, ttl: .seconds(60))
        _ = try await shared.children(of: .root)
        engine.seed("remote.bin", data: Data([1, 2, 3]))
        let found = try await shared.child(of: .root, named: "remote.bin")
        XCTAssertEqual(found?.name, "remote.bin")
    }
}


extension NotifyLockTests {
    func testSameHandleExclusiveOverlapIsNotAnIdempotentSMBLock() throws {
        let engine=MemoryEngine(); engine.seed("same-fid.bin",data:Data(repeating:7,count:1024))
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        // Apple's BRL client can reuse one read-only SMB FID across processes.
        let a=try client.create(path:"same-fid.bin",desiredAccess:SMBAccess.readData)
        let b=try client.create(path:"same-fid.bin",desiredAccess:SMBAccess.readData)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:2),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:2),NTStatus.lockNotGranted.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:50,length:100,flags:2),NTStatus.lockNotGranted.rawValue)
        // Failed partial acquisition must not reserve its previously free tail.
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:100,length:50,flags:2),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:100,flags:2),NTStatus.lockNotGranted.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:4),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:4),NTStatus.rangeNotLocked.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:2),NTStatus.success.rawValue)
        try client.close(fileId:a.fileId)
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:100,flags:2),NTStatus.success.rawValue)
        try client.close(fileId:b.fileId)
    }

    func testSharedCoholdersRemainCompatibleButBlockSameHandleExclusiveAcquisition() throws {
        let engine=MemoryEngine(); engine.seed("shared-fid.bin",data:Data(count:1024))
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        let a=try client.create(path:"shared-fid.bin"), b=try client.create(path:"shared-fid.bin")
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:1),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:50,length:100,flags:1),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:75,length:50,flags:1),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:25,length:10,flags:2),NTStatus.lockNotGranted.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:150,length:10,flags:2),NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId:b.fileId,offset:75,length:5).status,NTStatus.success.rawValue)
        try client.close(fileId:a.fileId); try client.close(fileId:b.fileId)
    }

    func testSameHandleBatchOverlapFailsWithoutRemovingPreexistingLocks() throws {
        let engine=MemoryEngine(); engine.seed("batch-overlap.bin",data:Data(count:1024))
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        let a=try client.create(path:"batch-overlap.bin"), b=try client.create(path:"batch-overlap.bin")
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:16,flags:2),NTStatus.success.rawValue)
        var body=ByteWriter(); body.u16(48); body.u16(2); body.u32(0)
        body.u64(a.fileId.persistent); body.u64(a.fileId.volatile)
        for offset: UInt64 in [128,8] { body.u64(offset); body.u64(16); body.u32(0x12); body.u32(0) }
        XCTAssertEqual(try client.request(.lock,body:body.data).header.status,NTStatus.lockNotGranted.rawValue)
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:128,length:16,flags:2),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:16,flags:2),NTStatus.lockNotGranted.rawValue)
        try client.close(fileId:a.fileId); try client.close(fileId:b.fileId)

        let table=LockTable(), id=InodeID("batch"), owner=SMBFileId(persistent:1,volatile:1)
        XCTAssertFalse(table.acquireAll(id,ranges:[
            LockRange(offset:32,length:32,exclusive:true,owner:owner),
            LockRange(offset:48,length:32,exclusive:true,owner:owner)
        ]))
        XCTAssertFalse(table.hasRanges(owner:owner))
    }

    func testRemoteRangeFailureRollsBackOnlyNewLocalReservation() throws {
        let engine=MemoryEngine(); engine.seed("remote-denied.bin",data:Data(count:1024))
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        let a=try client.create(path:"remote-denied.bin"), b=try client.create(path:"remote-denied.bin")
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:32,length:32,flags:2),NTStatus.success.rawValue)
        engine.rangeAcquireHook={throw EngineError(.locked,"Injected remote denial")}
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:128,length:32,flags:2),NTStatus.lockNotGranted.rawValue)
        engine.rangeAcquireHook=nil
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:128,length:32,flags:2),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:40,length:1,flags:2),NTStatus.lockNotGranted.rawValue)
        try client.close(fileId:a.fileId); try client.close(fileId:b.fileId)
    }

    func testMandatoryRangeIoChecksAndExactUnlockAcrossHandles() throws {
        let engine=MemoryEngine(); engine.seed("locked.bin",data:Data(repeating:7,count:1024))
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        let a=try client.create(path:"locked.bin"), b=try client.create(path:"locked.bin")
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:1),NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId:b.fileId,offset:0,length:5).status,NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId:a.fileId,offset:0,length:5).status,NTStatus.success.rawValue)
        XCTAssertEqual(try client.write(fileId:a.fileId,offset:0,data:Data([8])).status,NTStatus.fileLockConflict.rawValue,
                       "a shared lock forbids writes even through its owning handle")
        XCTAssertEqual(try client.write(fileId:b.fileId,offset:0,data:Data([8])).status,NTStatus.fileLockConflict.rawValue)
        XCTAssertEqual(try client.write(fileId:b.fileId,offset:100,data:Data([8])).status,NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:99,flags:4),NTStatus.rangeNotLocked.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:4),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:2),NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId:b.fileId,offset:0,length:5).status,NTStatus.fileLockConflict.rawValue)
        XCTAssertEqual(try client.read(fileId:a.fileId,offset:0,length:5).status,NTStatus.success.rawValue)
        XCTAssertEqual(try client.write(fileId:a.fileId,offset:0,data:Data([9])).status,NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId:b.fileId,offset:100,length:5).status,NTStatus.success.rawValue)
        try client.close(fileId:a.fileId)
        XCTAssertEqual(try client.read(fileId:b.fileId,offset:0,length:5).status,NTStatus.success.rawValue)
        try client.close(fileId:b.fileId)
    }
    func testOversizedRangeBatchIsRejectedBeforeAdmission() throws {
        let engine=MemoryEngine(); engine.seed("batch.bin",data:Data(count:1024))
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        let opened=try client.create(path:"batch.bin")
        var body=ByteWriter(); body.u16(48); body.u16(65); body.u32(0)
        body.u64(opened.fileId.persistent); body.u64(opened.fileId.volatile)
        for n in 0..<65 { body.u64(UInt64(n)); body.u64(1); body.u32(0x12); body.u32(0) }
        XCTAssertEqual(try client.request(.lock,body:body.data).header.status,NTStatus.invalidParameter.rawValue)
        XCTAssertEqual(try client.lock(fileId:opened.fileId,offset:0,length:1,flags:2),NTStatus.success.rawValue)
        try client.close(fileId:opened.fileId)
    }

    func testDuplicateSharedLocksRetainRemoteProtectionUntilFinalUnlock() throws {
        let engine=MemoryEngine(); engine.seed("shared-count.bin",data:Data(count:1024))
        let releases=RangeReleaseRecorder(); engine.rangeReleaseHook={ releases.append($0) }
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        let a=try client.create(path:"shared-count.bin"), b=try client.create(path:"shared-count.bin")
        for _ in 0..<2 { XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:1),NTStatus.success.rawValue) }
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:4),NTStatus.success.rawValue)
        XCTAssertEqual(releases.calls,[[]],"a local decrement validates the lease but releases no remote range")
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:100,flags:2),NTStatus.lockNotGranted.rawValue)
        XCTAssertEqual(try client.write(fileId:a.fileId,offset:0,data:Data([8])).status,NTStatus.fileLockConflict.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:4),NTStatus.success.rawValue)
        XCTAssertEqual(releases.calls.count,2)
        XCTAssertEqual(releases.calls[1].map(\.offset),[0])
        XCTAssertEqual(releases.calls[1].map(\.length),[100])
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:100,flags:2),NTStatus.success.rawValue)
        try client.close(fileId:a.fileId); try client.close(fileId:b.fileId)
    }

    func testDuplicateUnlockBatchCannotConsumeMoreSharedLocksThanHeld() throws {
        let engine=MemoryEngine(); engine.seed("unlock-count.bin",data:Data(count:1024))
        let releases=RangeReleaseRecorder(); engine.rangeReleaseHook={ releases.append($0) }
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        let a=try client.create(path:"unlock-count.bin"), b=try client.create(path:"unlock-count.bin")
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:1),NTStatus.success.rawValue)
        var body=ByteWriter(); body.u16(48); body.u16(2); body.u32(0)
        body.u64(a.fileId.persistent); body.u64(a.fileId.volatile)
        for _ in 0..<2 { body.u64(0); body.u64(100); body.u32(4); body.u32(0) }
        XCTAssertEqual(try client.request(.lock,body:body.data).header.status,NTStatus.rangeNotLocked.rawValue)
        XCTAssertTrue(releases.calls.isEmpty,"invalid unlock batch must not reach the remote authority")
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:100,flags:2),NTStatus.lockNotGranted.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:1),NTStatus.success.rawValue)
        XCTAssertEqual(try client.request(.lock,body:body.data).header.status,NTStatus.success.rawValue)
        XCTAssertEqual(releases.calls.count,1)
        XCTAssertEqual(releases.calls.first?.count,1,"two local unlocks release one remote union member")
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:100,flags:2),NTStatus.success.rawValue)
        try client.close(fileId:a.fileId); try client.close(fileId:b.fileId)
    }

    func testDeniedDuplicateSharedAcquisitionRollsBackOnlyItsOwnCount() throws {
        let engine=MemoryEngine(); engine.seed("denied-shared.bin",data:Data(count:1024))
        let (server,client)=try connected(engine); defer { server.stop(); client.close() }
        let a=try client.create(path:"denied-shared.bin"), b=try client.create(path:"denied-shared.bin")
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:1),NTStatus.success.rawValue)
        engine.rangeAcquireHook={ throw EngineError(.locked,"Injected remote denial") }
        var body=ByteWriter(); body.u16(48); body.u16(2); body.u32(0)
        body.u64(a.fileId.persistent); body.u64(a.fileId.volatile)
        for _ in 0..<2 { body.u64(0); body.u64(100); body.u32(1); body.u32(0) }
        XCTAssertEqual(try client.request(.lock,body:body.data).header.status,NTStatus.lockNotGranted.rawValue)
        engine.rangeAcquireHook=nil
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:100,flags:2),NTStatus.lockNotGranted.rawValue)
        XCTAssertEqual(try client.lock(fileId:a.fileId,offset:0,length:100,flags:4),NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId:b.fileId,offset:0,length:100,flags:2),NTStatus.success.rawValue,
                       "failed duplicate reservations must not survive the original lock's one unlock")
        try client.close(fileId:a.fileId); try client.close(fileId:b.fileId)
    }

    func testSharedMultiplicityIsBoundedAndCloseRemovesEveryReservation() {
        let table=LockTable(), id=InodeID("bounded"), owner=SMBFileId(persistent:1,volatile:1)
        for _ in 0..<256 { XCTAssertTrue(table.acquire(id,offset:0,length:1,exclusive:false,owner:owner)) }
        XCTAssertFalse(table.acquire(id,offset:0,length:1,exclusive:false,owner:owner))
        XCTAssertEqual(table.heldRanges(id,owner:owner).count,256)
        table.releaseAll(owner:owner)
        XCTAssertFalse(table.hasRanges(owner:owner))
        XCTAssertTrue(table.acquire(id,offset:0,length:1,exclusive:true,owner:owner))
    }

}

private final class RangeReleaseRecorder: @unchecked Sendable {
    private let mutex=NSLock()
    private var recorded:[[FileLockRange]]=[]
    var calls:[[FileLockRange]] { mutex.withLock { recorded } }
    func append(_ ranges:[FileLockRange]) { mutex.withLock { recorded.append(ranges) } }
}
