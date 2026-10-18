// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB P2: the write path over a real socket — CREATE dispositions, WRITE,
// FLUSH, SET_INFO (truncate/rename/delete-on-close), mkdir.

import XCTest
import CloudFSCore
@testable import CloudFSSMB

private final class LockedSMBStatuses: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [UInt32] = []
    func append(_ status: UInt32) { lock.withLock { stored.append(status) } }
    var values: [UInt32] { lock.withLock { stored } }
}

final class WritePathTests: XCTestCase {
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

    private let FILE_CREATE: UInt32 = 2
    private let FILE_OPEN: UInt32 = 1
    private let FILE_OVERWRITE_IF: UInt32 = 5
    private let DIRECTORY_FILE: UInt32 = 0x01
    private let NON_DIRECTORY: UInt32 = 0x40

    func testBasicMetadataRoundTripsAndUnsupportedMutationsFail() throws {
        let engine = MemoryEngine(); engine.seed("metadata.txt", data: Data(repeating: 1, count: 100))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        let open = try client.create(path: "metadata.txt")
        let times: [UInt64] = [1000,2000,3000,4000].map { filetime(unixSeconds: Double($0)) }
        var payload = ByteWriter(); for time in times { payload.u64(time) }; payload.u32(2); payload.u32(0)
        XCTAssertEqual(try client.setInfo(fileId: open.fileId, infoType: 1, infoClass: 4, data: payload.data), NTStatus.success.rawValue)
        var result = ByteReader(try client.queryInfo(fileId: open.fileId, infoType: 1, infoClass: 4).buffer)
        for time in times { XCTAssertEqual(try result.u64(), time) }
        XCTAssertEqual(try result.u32(), 2)
        let basicInfoWrites = engine.basicInfoWriteCount
        XCTAssertEqual(try client.setInfo(fileId: open.fileId, infoType: 1, infoClass: 4, data: Data(repeating: 0, count: 40)), NTStatus.success.rawValue)
        XCTAssertEqual(engine.basicInfoWriteCount, basicInfoWrites,
                       "all-zero FileBasicInformation is a no-op unless the scoped AAPL quirk applies")
        var unchanged = ByteReader(try client.queryInfo(fileId: open.fileId, infoType: 1, infoClass: 4).buffer)
        for time in times { XCTAssertEqual(try unchanged.u64(), time) }
        XCTAssertEqual(try unchanged.u32(), 2, "Standard zero attributes must remain no-change")
        XCTAssertEqual(try client.setInfo(fileId: open.fileId, infoType: 1, infoClass: 4, data: Data([0])), NTStatus.invalidParameter.rawValue)
        XCTAssertEqual(try client.setInfo(fileId: open.fileId, infoType: 3, infoClass: 0, data: Data()), NTStatus.notSupported.rawValue)
        var unsupported = ByteWriter(); for _ in 0..<4 { unsupported.u64(0) }; unsupported.u32(0x400); unsupported.u32(0)
        XCTAssertEqual(try client.setInfo(fileId: open.fileId, infoType: 1, infoClass: 4, data: unsupported.data), NTStatus.notSupported.rawValue)
        var alloc = ByteWriter(); alloc.u64(30)
        XCTAssertEqual(try client.setInfo(fileId: open.fileId, infoType: 1, infoClass: 19, data: alloc.data), NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: open.fileId, offset: 0, length: 100).data.count, 30)
        // A rejected metadata update must not change the stored hidden flag.
        engine.denyWrites = true
        XCTAssertEqual(try client.setInfo(fileId: open.fileId, infoType: 1, infoClass: 4, data: payload.data), NTStatus.accessDenied.rawValue)
        try client.close(fileId: open.fileId)
    }

    func testWritableFileCreateRefreshesMetadataOnlyOnceUnderLease() async throws {
        let engine = MemoryEngine(); engine.seed("fast-open.txt", data: Data("bytes".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        _ = try await server.table.meta(.root) // Exclude the initial root cache fill.
        let priorLookups = engine.lookupCount
        let opened = try client.create(path: "fast-open.txt", desiredAccess: SMBAccess.all)
        XCTAssertEqual(opened.status, NTStatus.success.rawValue)
        XCTAssertEqual(engine.lookupCount - priorLookups, 1,
                       "the writable CREATE needs one fresh metadata read after it holds the lease")
        try client.close(fileId: opened.fileId)
    }

    func testFreshLeaseItemSkipsSeparateAuthorizationAndMetadataLookup() async throws {
        let engine = MemoryEngine(); engine.seed("fresh-grant.txt", data: Data("bytes".utf8))
        engine.returnWriteSnapshot = true
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        _ = try await server.table.meta(.root)
        let priorLookups = engine.lookupCount
        let priorAuthorizations = engine.authorizeWriteCallCount
        let priorSnapshots = engine.writeSnapshotCallCount
        let opened = try client.create(path: "fresh-grant.txt", desiredAccess: SMBAccess.all)
        XCTAssertEqual(opened.status, NTStatus.success.rawValue)
        XCTAssertEqual(engine.writeSnapshotCallCount - priorSnapshots, 1)
        XCTAssertEqual(engine.lookupCount - priorLookups, 0,
                       "fresh metadata returned with the publication grant replaces the post-lease GET")
        XCTAssertEqual(engine.authorizeWriteCallCount - priorAuthorizations, 0,
                       "the opt-in grant rechecks read/write ACLs atomically with the returned item")
        try client.close(fileId: opened.fileId)
    }

    func testNamespaceFailureStatusesRemainActionable() {
        XCTAssertEqual(ntStatus(for: EngineError(.conflict, data: ["error": .string("directory_not_empty")])), .directoryNotEmpty)
        XCTAssertEqual(ntStatus(for: EngineError(.invalidParams, data: ["error": .string("invalid_parent")])), .objectPathNotFound)
    }

    private func flags(_ value: UInt32) -> Data {
        var body = ByteWriter(); for _ in 0..<4 { body.u64(0) }; body.u32(value); body.u32(0)
        return body.data
    }

    func testReadOnlyContentProtectionAllowsAuthorizedClearAndPreservesBytes() throws {
        let engine = MemoryEngine(); engine.seed("locked.txt", data: Data("original".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        let before = try client.create(path: "locked.txt")
        XCTAssertEqual(try client.setInfo(fileId: before.fileId, infoType: 1, infoClass: 4, data: flags(1)), NTStatus.success.rawValue)
        // Existing handles also cannot overwrite, truncate, or mark it deleted.
        XCTAssertEqual(try client.write(fileId: before.fileId, offset: 0, data: Data([99])).status, NTStatus.accessDenied.rawValue)
        XCTAssertEqual(try client.setEndOfFile(fileId: before.fileId, size: 1), NTStatus.accessDenied.rawValue)
        XCTAssertEqual(try client.setInfo(fileId: before.fileId, infoType: 1, infoClass: 13, data: Data([1])), NTStatus.cannotDelete.rawValue)
        let read = try client.create(path: "locked.txt", desiredAccess: 0x0012_0089)
        XCTAssertEqual(read.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: read.fileId, offset: 0, length: 8).data, Data("original".utf8))
        XCTAssertEqual(try client.create(path: "locked.txt").status, NTStatus.accessDenied.rawValue)
        XCTAssertEqual(try client.createEx(path: "locked.txt", disposition: 4).status, NTStatus.accessDenied.rawValue)
        XCTAssertEqual(try client.createEx(path: "locked.txt:AFP_Resource:$DATA", disposition: 3).status, NTStatus.accessDenied.rawValue)
        // The editor can open only WRITE_ATTRIBUTES to clear the DOS flag. A
        // read handle cannot promote itself and backend ACL remains authoritative.
        XCTAssertEqual(try client.setInfo(fileId: read.fileId, infoType: 1, infoClass: 4, data: flags(0x80)), NTStatus.accessDenied.rawValue)
        let metadata = try client.create(path: "locked.txt", desiredAccess: 0x0012_0180)
        XCTAssertEqual(metadata.status, NTStatus.success.rawValue)
        engine.denyWrites = true
        XCTAssertEqual(try client.setInfo(fileId: metadata.fileId, infoType: 1, infoClass: 4, data: flags(0x80)), NTStatus.accessDenied.rawValue)
        engine.denyWrites = false
        XCTAssertEqual(try client.setInfo(fileId: metadata.fileId, infoType: 1, infoClass: 4, data: flags(0x80)), NTStatus.success.rawValue)
        XCTAssertEqual(try client.write(fileId: before.fileId, offset: 0, data: Data([99])).status, NTStatus.success.rawValue)
        for handle in [before.fileId, read.fileId, metadata.fileId] { try client.close(fileId: handle) }
    }

    func testAppleAttributeClearQuirkIsLimitedToRelatedAttributeOnlyOpen() throws {
        let engine = MemoryEngine(); engine.seed("apple.txt", data: Data("keep".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        let initial = try client.create(path: "apple.txt", wantAAPL: true)
        XCTAssertEqual(try client.setInfo(fileId: initial.fileId, infoType: 1, infoClass: 4, data: flags(1)), NTStatus.success.rawValue)
        // Even an AAPL client cannot clear flags by an ordinary all-zero SET.
        XCTAssertEqual(try client.setInfo(fileId: initial.fileId, infoType: 1, infoClass: 4, data: Data(repeating: 0, count: 40)), NTStatus.success.rawValue)
        func queryAttributes() throws -> UInt32 {
            var response = ByteReader(try client.queryInfo(fileId: initial.fileId, infoType: 1, infoClass: 4).buffer)
            for _ in 0..<4 { _ = try response.u64() }; return try response.u32()
        }
        XCTAssertEqual(try queryAttributes(), 1)
        var create = client.createBody(path: "apple.txt")
        patchU32(&create, at: 24, SMBAccess.writeAttributes | 0x0010_0080)
        patchU32(&create, at: 36, 1)
        var basic = ByteWriter(); basic.u16(33); basic.u8(1); basic.u8(4)
        basic.u32(40); basic.u16(96); basic.u16(0); basic.u32(0)
        basic.u64(UInt64.max); basic.u64(UInt64.max); basic.zeros(40)
        var close = ByteWriter(); close.u16(24); close.u16(0); close.u32(0)
        close.u64(UInt64.max); close.u64(UInt64.max)
        let replies = try client.compound([(.create, create), (.setInfo, basic.data), (.close, close.data)])
        XCTAssertEqual(replies.map { $0.header.status }, [0,0,0])
        XCTAssertEqual(try queryAttributes(), FileAttributes.normal)
        try client.close(fileId: initial.fileId)
    }

    func testHandleRightsConstrainMutationAndReadWithoutChangingBackendRights() throws {
        let engine = MemoryEngine(); engine.seed("rights.txt", data: Data("data".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        let read = try client.create(path: "rights.txt", desiredAccess: 0x8000_0000)
        XCTAssertEqual(read.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.write(fileId: read.fileId, offset: 0, data: Data([99])).status, NTStatus.accessDenied.rawValue)
        XCTAssertEqual(try client.setEndOfFile(fileId: read.fileId, size: 0), NTStatus.accessDenied.rawValue)
        XCTAssertEqual(try client.setInfo(fileId: read.fileId, infoType: 1, infoClass: 13, data: Data([1])), NTStatus.accessDenied.rawValue)
        let append = try client.create(path: "rights.txt", desiredAccess: SMBAccess.appendData)
        XCTAssertEqual(try client.read(fileId: append.fileId, offset: 0, length: 4).status, NTStatus.accessDenied.rawValue)
        XCTAssertEqual(try client.write(fileId: append.fileId, offset: 0, data: Data([99])).status, NTStatus.accessDenied.rawValue)
        XCTAssertEqual(try client.write(fileId: append.fileId, offset: 4, data: Data([99])).status, NTStatus.success.rawValue)
        let full = try client.create(path: "rights.txt")
        XCTAssertEqual(try client.setInfo(fileId: full.fileId, infoType: 1, infoClass: 13, data: Data()), NTStatus.invalidParameter.rawValue)
        XCTAssertEqual(try client.setInfo(fileId: full.fileId, infoType: 1, infoClass: 20, data: Data(repeating: 0, count: 9)), NTStatus.invalidParameter.rawValue)
        for handle in [read.fileId, append.fileId, full.fileId] { try client.close(fileId: handle) }
    }

    func testDirectoryDeletionNeverRecursesAndRechecksChildrenAtClose() throws {
        let engine = MemoryEngine(); let directory = engine.seedDir("project")
        engine.seed("edit.bin", parent: directory, data: Data("keep".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        let open = try client.createEx(path: "project", disposition: 1, options: CreateOptions.directoryFile)
        XCTAssertEqual(try client.setInfo(fileId: open.fileId, infoType: 1, infoClass: 13, data: Data([1])), NTStatus.directoryNotEmpty.rawValue)
        try client.close(fileId: open.fileId)
        let racedDirectory = engine.seedDir("raced")
        let raced = try client.createEx(path: "raced", disposition: 1, options: CreateOptions.directoryFile)
        XCTAssertEqual(try client.setInfo(fileId: raced.fileId, infoType: 1, infoClass: 13, data: Data([1])), NTStatus.success.rawValue)
        engine.seed("late.bin", parent: racedDirectory, data: Data("late".utf8))
        var close = ByteWriter(); close.u16(24); close.u16(0); close.u32(0)
        close.u64(raced.fileId.persistent); close.u64(raced.fileId.volatile)
        XCTAssertEqual(try client.request(.close, body: close.data).header.status, NTStatus.directoryNotEmpty.rawValue)
        for path in ["project/edit.bin", "raced/late.bin"] {
            let child = try client.create(path: path)
            XCTAssertEqual(child.status, NTStatus.success.rawValue)
            XCTAssertEqual(try client.read(fileId: child.fileId, offset: 0, length: 4).data.count, 4)
            try client.close(fileId: child.fileId)
        }
    }

    func testBasicInfoSentinelsNeverBecomeOverflowingDates() throws {
        for value in [UInt64.max, UInt64.max - 1, UInt64.max - 2] {
            var payload = ByteWriter(); payload.u64(0); payload.u64(0); payload.u64(value); payload.u64(0); payload.u32(0); payload.u32(0)
            XCTAssertThrowsError(try SMBAttrs.parseBasicInfo(payload.data, isDir: false))
        }
        XCTAssertEqual(try SMBAttrs.parseBasicInfo(Data(repeating: 0, count: 40), isDir: false), BasicFileInfo())
    }

    func testCreateWriteReadBack() throws {
        let engine = MemoryEngine()
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        // CREATE a new file.
        let created = try client.createEx(path: "new.txt", disposition: FILE_CREATE, options: NON_DIRECTORY)
        XCTAssertEqual(created.status, NTStatus.success.rawValue)

        // WRITE into it.
        let payload = Data("hello smb write path".utf8)
        let w = try client.write(fileId: created.fileId, offset: 0, data: payload)
        XCTAssertEqual(w.status, NTStatus.success.rawValue)
        XCTAssertEqual(w.count, UInt32(payload.count))
        XCTAssertEqual(try client.flush(fileId: created.fileId), NTStatus.success.rawValue)
        try client.close(fileId: created.fileId)

        // Re-open and READ back.
        let open = try client.create(path: "new.txt")
        XCTAssertEqual(open.status, NTStatus.success.rawValue)
        XCTAssertEqual(open.size, UInt64(payload.count))
        let read = try client.read(fileId: open.fileId, offset: 0, length: UInt32(payload.count))
        XCTAssertEqual(read.data, payload)
        try client.close(fileId: open.fileId)
    }

    func testOpenHandlesKeepReplacedInodeDataAndStreamsUntilClose() throws {
        let engine = MemoryEngine()
        engine.seed("target.bin", data: Data("old-target".utf8))
        _ = engine.seed("source.bin", data: Data("new-source".utf8))
        let oldID = InodeID("root/target.bin")
        engine.seedStream(oldID, name: "com.example.note", data: Data("old-stream".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }

        let old = try client.create(path: "target.bin")
        let oldStream = try client.createEx(path: "target.bin:com.example.note:$DATA", disposition: 1)
        XCTAssertEqual(oldStream.status, NTStatus.success.rawValue)
        let replacement = try client.create(path: "source.bin")
        XCTAssertEqual(try client.rename(fileId: replacement.fileId, to: "target.bin", replace: true), NTStatus.success.rawValue)

        XCTAssertTrue(engine.isDetached(oldID))
        XCTAssertEqual(try client.read(fileId: old.fileId, offset: 0, length: 32).data, Data("old-target".utf8))
        XCTAssertEqual(try client.write(fileId: old.fileId, offset: 10, data: Data("+written".utf8)).status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: old.fileId, offset: 0, length: 32).data, Data("old-target+written".utf8))
        XCTAssertEqual(try client.read(fileId: oldStream.fileId, offset: 0, length: 32).data, Data("old-stream".utf8))
        XCTAssertEqual(try client.write(fileId: oldStream.fileId, offset: 10, data: Data("+write".utf8)).status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: oldStream.fileId, offset: 0, length: 32).data, Data("old-stream+write".utf8))

        let current = try client.create(path: "target.bin")
        XCTAssertEqual(try client.read(fileId: current.fileId, offset: 0, length: 32).data, Data("new-source".utf8))
        for handle in [old.fileId, oldStream.fileId, current.fileId, replacement.fileId] { try client.close(fileId: handle) }
        XCTAssertEqual(engine.openReferenceCount(oldID), 0)
        XCTAssertFalse(engine.hasRetainedItem(oldID))
    }

    func testUnlinkRemovesNameButPreservesOtherOpenHandleThroughClose() throws {
        let engine = MemoryEngine(); engine.seed("unlink.bin", data: Data("before".utf8))
        let id = InodeID("root/unlink.bin")
        engine.seedStream(id, name: "com.example.note", data: Data("stream".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }

        let deleting = try client.create(path: "unlink.bin")
        let survivor = try client.create(path: "unlink.bin")
        let stream = try client.createEx(path: "unlink.bin:com.example.note:$DATA", disposition: 1)
        XCTAssertEqual(stream.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.setDisposition(fileId: deleting.fileId, delete: true), NTStatus.success.rawValue)
        try client.close(fileId: deleting.fileId)

        XCTAssertTrue(engine.isDetached(id))
        XCTAssertEqual(try client.create(path: "unlink.bin").status, NTStatus.objectNameNotFound.rawValue)
        XCTAssertEqual(try client.read(fileId: survivor.fileId, offset: 0, length: 32).data, Data("before".utf8))
        XCTAssertEqual(try client.write(fileId: survivor.fileId, offset: 6, data: Data("+after".utf8)).status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: survivor.fileId, offset: 0, length: 32).data, Data("before+after".utf8))
        XCTAssertEqual(try client.read(fileId: stream.fileId, offset: 0, length: 32).data, Data("stream".utf8))
        try client.close(fileId: survivor.fileId)
        XCTAssertTrue(engine.isDetached(id), "the named-stream handle still owns the detached inode")
        try client.close(fileId: stream.fileId)
        XCTAssertEqual(engine.openReferenceCount(id), 0)
        XCTAssertFalse(engine.hasRetainedItem(id))
    }

    func testShareAccessEnforcedForOpensDeleteAndReplacement() throws {
        let engine = MemoryEngine()
        engine.seed("held.bin", data: Data("held".utf8))
        engine.seed("stage.bin", data: Data("stage".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }

        let metadataOnly = try client.create(path: "held.bin", desiredAccess: 0x80, shareAccess: 0x01)
        XCTAssertEqual(metadataOnly.status, NTStatus.success.rawValue)
        let dataReader = try client.create(path: "held.bin", desiredAccess: SMBAccess.readData, shareAccess: 0)
        XCTAssertEqual(dataReader.status, NTStatus.success.rawValue,
                       "read-attributes access must not be counted as FILE_READ_DATA")
        try client.close(fileId: metadataOnly.fileId)
        try client.close(fileId: dataReader.fileId)

        let held = try client.create(path: "held.bin", desiredAccess: SMBAccess.readData, shareAccess: 0x03)
        XCTAssertEqual(try client.create(path: "held.bin", desiredAccess: SMBAccess.readData).status, NTStatus.success.rawValue)
        let noDeleteShare = try client.create(path: "held.bin", desiredAccess: SMBAccess.all, shareAccess: 0x03)
        XCTAssertEqual(noDeleteShare.status, NTStatus.sharingViolation.rawValue)

        // A read-only data handle with no delete sharing allows another read open,
        // but it must prevent a peer from replacing its namespace entry.
        let source = try client.create(path: "stage.bin")
        XCTAssertEqual(try client.rename(fileId: source.fileId, to: "held.bin", replace: true), NTStatus.sharingViolation.rawValue)
        try client.close(fileId: held.fileId)
        try client.close(fileId: source.fileId)
    }

    func testDeleteAndRenameAllowedThroughOwnShareZeroHandle() throws {
        let engine = MemoryEngine()
        engine.seed("delete-own.bin", data: Data("delete".utf8))
        engine.seed("rename-own.bin", data: Data("rename".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }

        let deleteHandle = try client.create(path: "delete-own.bin", desiredAccess: SMBAccess.delete, shareAccess: 0)
        XCTAssertEqual(deleteHandle.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.setDisposition(fileId: deleteHandle.fileId, delete: true), NTStatus.success.rawValue)
        try client.close(fileId: deleteHandle.fileId)
        XCTAssertEqual(try client.create(path: "delete-own.bin").status, NTStatus.objectNameNotFound.rawValue)

        let renameHandle = try client.create(path: "rename-own.bin", desiredAccess: SMBAccess.delete, shareAccess: 0)
        XCTAssertEqual(renameHandle.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.rename(fileId: renameHandle.fileId, to: "rename-own-moved.bin", replace: false), NTStatus.success.rawValue)
        XCTAssertTrue(engine.snapshotNames().contains("rename-own-moved.bin"), "rename must retain the source entry")
        try client.close(fileId: renameHandle.fileId)
        let moved = try client.create(path: "rename-own-moved.bin")
        XCTAssertEqual(moved.status, NTStatus.success.rawValue)
        XCTAssertEqual(moved.size, UInt64(Data("rename".utf8).count))
        let read = try client.read(fileId: moved.fileId, offset: 0, length: 32)
        XCTAssertEqual(read.status, NTStatus.success.rawValue)
        XCTAssertEqual(read.data, Data("rename".utf8))
        try client.close(fileId: moved.fileId)
    }

    func testConcurrentDeniedCreatesCompleteAndReleaseShareReservations() throws {
        let engine = MemoryEngine(); engine.seed("denied-open.bin", data: Data("held".utf8))
        let server = SMBServer(engine: engine, shareName: "cloudfs", credential: (user: "cfs", password: "pw"))
        let port = try server.start(); defer { server.stop() }
        engine.denyWrites = true
        let statuses = LockedSMBStatuses()
        DispatchQueue.concurrentPerform(iterations: 4) { _ in
            let client = SMBTestClient()
            defer { client.close() }
            do {
                try client.connect(port: port)
                _ = try client.negotiate()
                try client.sessionSetup(user: "cfs", password: "pw")
                _ = try client.treeConnect(share: "cloudfs")
                let result = try client.create(path: "denied-open.bin", desiredAccess: SMBAccess.writeData, shareAccess: 0)
                statuses.append(result.status)
                if result.status == NTStatus.success.rawValue { try client.close(fileId: result.fileId) }
            } catch {
                statuses.append(NTStatus.unsuccessful.rawValue)
            }
        }
        let denied = statuses.values
        XCTAssertEqual(denied.count, 4)
        XCTAssertTrue(denied.allSatisfy { $0 == NTStatus.accessDenied.rawValue || $0 == NTStatus.sharingViolation.rawValue }, "unexpected concurrent CREATE statuses: \(denied)")

        engine.denyWrites = false
        let retry = SMBTestClient(); defer { retry.close() }
        try retry.connect(port: port); _ = try retry.negotiate()
        try retry.sessionSetup(user: "cfs", password: "pw"); _ = try retry.treeConnect(share: "cloudfs")
        let reopened = try retry.create(path: "denied-open.bin", desiredAccess: SMBAccess.writeData, shareAccess: 0)
        XCTAssertEqual(reopened.status, NTStatus.success.rawValue, "failed concurrent CREATEs must release all local and remote share references")
        try retry.close(fileId: reopened.fileId)
    }

    func testConnectionDisconnectReleasesOpenLifetime() async throws {
        let engine = MemoryEngine(); engine.seed("disconnect.bin", data: Data("open".utf8))
        let id = InodeID("root/disconnect.bin")
        let (server, client) = try connected(engine); defer { server.stop() }
        _ = try client.create(path: "disconnect.bin")
        XCTAssertEqual(engine.openReferenceCount(id), 1)
        client.close()
        for _ in 0..<100 where engine.openReferenceCount(id) != 0 {
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertEqual(engine.openReferenceCount(id), 0)
    }


    func testMaximumNegotiatedWriteRoundTripsAndOversizedWriteCannotModifyFile() throws {
        let engine = MemoryEngine()
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let created = try client.createEx(path: "bounded-large-write.bin", disposition: FILE_CREATE, options: NON_DIRECTORY)
        XCTAssertEqual(created.status, NTStatus.success.rawValue)
        let payload = Data((0..<SMBLimits.maximumWriteBytes).map { UInt8(truncatingIfNeeded: $0 / 257) })
        let write = try client.write(fileId: created.fileId, offset: 0, data: payload)
        XCTAssertEqual(write.status, NTStatus.success.rawValue)
        XCTAssertEqual(write.count, UInt32(payload.count))
        XCTAssertEqual(try client.flush(fileId: created.fileId), NTStatus.success.rawValue)
        // READ remains bounded at 1 MiB. Validate every large-WRITE byte through
        // independent slices rather than silently widening the read memory window.
        for offset in stride(from: 0, to: payload.count, by: 1 << 20) {
            let read = try client.read(fileId: created.fileId, offset: UInt64(offset), length: 1 << 20)
            XCTAssertEqual(read.data, payload.subdata(in: offset..<(offset + (1 << 20))))
        }
        let oversized = try client.write(fileId: created.fileId, offset: 0,
                                         data: Data(repeating: 99, count: SMBLimits.maximumWriteBytes + 1))
        XCTAssertEqual(oversized.status, NTStatus.invalidParameter.rawValue)
        let unchanged = try client.read(fileId: created.fileId, offset: 0, length: 1 << 20)
        XCTAssertEqual(unchanged.data, payload.prefix(1 << 20))
        try client.close(fileId: created.fileId)
        let reopened = try client.create(path: "bounded-large-write.bin")
        XCTAssertEqual(reopened.size, UInt64(payload.count))
        try client.close(fileId: reopened.fileId)
    }

    func testCreateCollisionAndOpenIf() throws {
        let engine = MemoryEngine()
        engine.seed("exists.txt", data: Data("x".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        // FILE_CREATE on an existing name → collision.
        let clash = try client.createEx(path: "exists.txt", disposition: FILE_CREATE)
        XCTAssertEqual(clash.status, NTStatus.objectNameCollision.rawValue)

        // FILE_OPEN on a missing name → not found.
        let missing = try client.createEx(path: "nope.txt", disposition: FILE_OPEN)
        XCTAssertEqual(missing.status, NTStatus.objectNameNotFound.rawValue)
    }

    func testMkdir() throws {
        let engine = MemoryEngine()
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let mk = try client.createEx(path: "newdir", disposition: FILE_CREATE, options: DIRECTORY_FILE)
        XCTAssertEqual(mk.status, NTStatus.success.rawValue)
        try client.close(fileId: mk.fileId)

        // It shows up in the listing as a directory.
        let root = try client.create(path: "")
        let listing = try client.queryDirectory(fileId: root.fileId, restart: true)
        XCTAssertEqual(listing.items.first { $0.name == "newdir" }?.isDir, true)
    }

    func testTruncateViaSetEndOfFile() throws {
        let engine = MemoryEngine()
        engine.seed("big.bin", data: Data(repeating: 7, count: 1000))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let open = try client.create(path: "big.bin")
        XCTAssertEqual(try client.setEndOfFile(fileId: open.fileId, size: 100), NTStatus.success.rawValue)
        try client.close(fileId: open.fileId)

        let reopen = try client.create(path: "big.bin")
        XCTAssertEqual(reopen.size, 100)
        try client.close(fileId: reopen.fileId)
    }

    func testRename() throws {
        let engine = MemoryEngine()
        engine.seed("old.txt", data: Data("data".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let open = try client.create(path: "old.txt")
        XCTAssertEqual(try client.rename(fileId: open.fileId, to: "renamed.txt", replace: false),
                       NTStatus.success.rawValue)
        try client.close(fileId: open.fileId)

        let root = try client.create(path: "")
        let names = Set(try client.queryDirectory(fileId: root.fileId, restart: true).items.map(\.name))
        XCTAssertTrue(names.contains("renamed.txt"))
        XCTAssertFalse(names.contains("old.txt"))
    }

    func testAtomicRenameFailurePreservesDestinationAndMissingParentFails() throws {
        let engine = MemoryEngine(); engine.seed("save.tmp", data: Data("new".utf8)); engine.seed("project.txt", data: Data("old".utf8))
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        let source = try client.create(path: "save.tmp")
        engine.denyDeletes = true
        XCTAssertEqual(try client.rename(fileId: source.fileId, to: "project.txt", replace: true), NTStatus.accessDenied.rawValue)
        let old = try client.create(path: "project.txt")
        XCTAssertEqual(try client.read(fileId: old.fileId, offset: 0, length: 3).data, Data("old".utf8))
        try client.close(fileId: old.fileId)
        XCTAssertEqual(try client.rename(fileId: source.fileId, to: "missing/new.txt", replace: false), NTStatus.objectPathNotFound.rawValue)
        engine.denyDeletes = false
        XCTAssertEqual(try client.rename(fileId: source.fileId, to: "project.txt", replace: true), NTStatus.success.rawValue)
        let updated = try client.create(path: "project.txt")
        XCTAssertEqual(try client.read(fileId: updated.fileId, offset: 0, length: 3).data, Data("new".utf8))
        try client.close(fileId: updated.fileId); try client.close(fileId: source.fileId)
    }

    func testDeleteOnClose() throws {
        let engine = MemoryEngine()
        engine.seed("doomed.txt", data: Data("bye".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let open = try client.create(path: "doomed.txt")
        XCTAssertEqual(try client.setDisposition(fileId: open.fileId, delete: true), NTStatus.success.rawValue)
        try client.close(fileId: open.fileId)   // deletion happens here

        let root = try client.create(path: "")
        let names = Set(try client.queryDirectory(fileId: root.fileId, restart: true).items.map(\.name))
        XCTAssertFalse(names.contains("doomed.txt"))
    }
}


extension WritePathTests {
    func testDeleteOnCloseFailureIsReturnedAndFileRemainsVisible() throws {
        let engine = MemoryEngine()
        engine.seed("keep.txt", data: Data("preserved".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let open = try client.create(path: "keep.txt")
        XCTAssertEqual(try client.setDisposition(fileId: open.fileId, delete: true), NTStatus.success.rawValue)
        engine.denyDeletes = true
        var close = ByteWriter(); close.u16(24); close.u16(0); close.u32(0)
        close.u64(open.fileId.persistent); close.u64(open.fileId.volatile)
        XCTAssertEqual(try client.request(.close, body: close.data).header.status, NTStatus.accessDenied.rawValue)
        let root = try client.create(path: "")
        XCTAssertTrue(try client.queryDirectory(fileId: root.fileId, restart: true).items.contains { $0.name == "keep.txt" })
    }
}
