// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB P1b: browse + read the volume over a real socket. Exercises CREATE
// (open + MxAc/AAPL contexts), QUERY_DIRECTORY, READ, QUERY_INFO, CLOSE.

import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class DataPathTests: XCTestCase {
    func testReadErrorsUseCanonicalErrorBodyAndOrdinaryClientsCanRetry() throws {
        let engine = MemoryEngine()
        engine.seed("error.bin", data: Data("abc".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let open = try client.create(path: "error.bin")
        engine.rangeAccessHook = { throw EngineError(.locked, "Injected conflict") }
        let denied = try client.request(.read, body: client.readBody(fileId: open.fileId, offset: 0, length: 3))
        XCTAssertEqual(denied.header.status, NTStatus.fileLockConflict.rawValue)
        XCTAssertEqual(denied.body, errorBody(), "Failure must not use a success-shaped READ response")
        engine.rangeAccessHook = nil
        XCTAssertEqual(try client.read(fileId: open.fileId, offset: 0, length: 3).data, Data("abc".utf8))
        let eof = try client.request(.read, body: client.readBody(fileId: open.fileId, offset: 3, length: 1))
        XCTAssertEqual(eof.header.status, NTStatus.endOfFile.rawValue)
        XCTAssertEqual(eof.body, errorBody())
    }

    func testAppleReadChecksAdmissionAtPublicationAndFailsClosedUntilReopen() throws {
        let engine = MemoryEngine()
        engine.seed("protected.bin", data: Data("abc".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        _ = try client.create(path: "", wantAAPL: true)
        let open = try client.create(path: "protected.bin")
        let check = PublicationAdmissionFault()
        engine.rangeAccessHook = { try await check.check() }
        let denied = try client.request(.read, body: client.readBody(fileId: open.fileId, offset: 0, length: 3))
        XCTAssertEqual(denied.header.status, NTStatus.fileLockConflict.rawValue)
        XCTAssertEqual(denied.body, errorBody())
        engine.rangeAccessHook = nil
        XCTAssertEqual(try client.read(fileId: open.fileId, offset: 0, length: 3).status, NTStatus.fileLockConflict.rawValue)
        try client.close(fileId: open.fileId)
        let reopened = try client.create(path: "protected.bin")
        XCTAssertEqual(try client.read(fileId: reopened.fileId, offset: 3, length: 1).status, NTStatus.endOfFile.rawValue)
        XCTAssertEqual(try client.read(fileId: reopened.fileId, offset: 0, length: 3).data, Data("abc".utf8), "EOF must not poison an open")
    }
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

    func testBrowseRootListsSeededItems() throws {
        let engine = MemoryEngine()
        engine.seed("alpha.txt", data: Data("aaa".utf8))
        engine.seed("beta.mov", data: Data(repeating: 7, count: 4096))
        _ = engine.seedDir("projects")
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let root = try client.create(path: "")
        XCTAssertEqual(root.status, NTStatus.success.rawValue)

        let listing = try client.queryDirectory(fileId: root.fileId, restart: true)
        XCTAssertEqual(listing.status, NTStatus.success.rawValue)
        let names = Set(listing.items.map(\.name))
        XCTAssertTrue(names.contains("alpha.txt"))
        XCTAssertTrue(names.contains("beta.mov"))
        XCTAssertTrue(names.contains("projects"))
        XCTAssertTrue(names.contains("."))
        XCTAssertTrue(names.contains(".."))
        // Directory flag round-trips.
        XCTAssertEqual(listing.items.first { $0.name == "projects" }?.isDir, true)
        XCTAssertEqual(listing.items.first { $0.name == "beta.mov" }?.size, 4096)

        // Second page → NO_MORE_FILES.
        let page2 = try client.queryDirectory(fileId: root.fileId, restart: false)
        XCTAssertEqual(page2.status, NTStatus.noMoreFiles.rawValue)
        try client.close(fileId: root.fileId)
    }

    func testNestedQueryDirectoryReportsSelfAndParentFileIDs() throws {
        let engine = MemoryEngine()
        let parent = engine.seedDir("parent")
        _ = engine.seedDir("child", parent: parent)
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let parentOpen = try client.create(path: "parent")
        let childOpen = try client.create(path: "parent/child")
        let listing = try client.queryDirectory(fileId: childOpen.fileId, restart: true)
        XCTAssertEqual(listing.status, NTStatus.success.rawValue)
        let dot = try XCTUnwrap(listing.items.first { $0.name == "." })
        let dotDot = try XCTUnwrap(listing.items.first { $0.name == ".." })
        let childFileID = try internalFileID(client, childOpen.fileId)
        let parentFileID = try internalFileID(client, parentOpen.fileId)

        XCTAssertEqual(dot.fileId, childFileID)
        XCTAssertEqual(dotDot.fileId, parentFileID)
        XCTAssertNotEqual(dot.fileId, NodeTable.rootFileId)
        XCTAssertNotEqual(dotDot.fileId, NodeTable.rootFileId)
    }

    func testExactNameQueryDoesNotFetchDotEntryMetadata() async throws {
        let engine = MemoryEngine()
        engine.seed("target.bin", data: Data([1]))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let root = try client.create(path: "")
        await server.table.invalidateMeta(.root)
        let lookupCounter = LookupCounter()
        engine.lookupSnapshotHook = { await lookupCounter.record() }

        let result = try client.queryDirectory(fileId: root.fileId, restart: true,
                                               pattern: "target.bin")
        XCTAssertEqual(result.status, NTStatus.success.rawValue)
        XCTAssertEqual(result.items.map(\.name), ["target.bin"])
        let lookups = await lookupCounter.count
        XCTAssertEqual(lookups, 0,
                       "an exact-name stat should not fetch directory or parent metadata for filtered dot rows")
    }

    private func internalFileID(_ client: SMBTestClient, _ fileId: SMBFileId) throws -> UInt64 {
        let result = try client.queryInfo(fileId: fileId, infoType: 1,
                                          infoClass: FileInfoClass.internalInformation.rawValue)
        XCTAssertEqual(result.status, NTStatus.success.rawValue)
        var reader = ByteReader(result.buffer)
        return try reader.u64()
    }

    func testReadFileByteExact() throws {
        let engine = MemoryEngine()
        var payload = Data()
        for i in 0..<(3 * 1024) { payload.append(UInt8(i & 0xFF)) }
        engine.seed("clip.bin", data: payload)
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let open = try client.create(path: "clip.bin")
        XCTAssertEqual(open.status, NTStatus.success.rawValue)
        XCTAssertEqual(open.size, UInt64(payload.count))

        // Full read.
        let full = try client.read(fileId: open.fileId, offset: 0, length: UInt32(payload.count))
        XCTAssertEqual(full.status, NTStatus.success.rawValue)
        XCTAssertEqual(full.data, payload)

        // Mid-file ranged read.
        let mid = try client.read(fileId: open.fileId, offset: 1000, length: 512)
        XCTAssertEqual(mid.data, payload.subdata(in: 1000..<1512))

        // Read past EOF → END_OF_FILE.
        let eof = try client.read(fileId: open.fileId, offset: UInt64(payload.count), length: 16)
        XCTAssertEqual(eof.status, NTStatus.endOfFile.rawValue)
        try client.close(fileId: open.fileId)
    }

    func testPipelinedReadsOverlapWithinBoundAndCloseWaitsForEveryResponse() throws {
        let engine = MemoryEngine()
        let bytes = Data((0..<4096).map { UInt8($0 & 255) })
        engine.seed("pipeline.bin", data: bytes)
        engine.readDelayNs = 40_000_000
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let opened = try client.create(path: "pipeline.bin")
        var requests: [UInt64: Int] = [:]
        for i in 0..<12 {
            let mid = try client.sendOnly(.read, body: client.readBody(fileId: opened.fileId, offset: UInt64(i * 128), length: 128))
            requests[mid] = i * 128
        }
        var close = ByteWriter(); close.u16(24); close.u16(0); close.u32(0)
        close.u64(opened.fileId.persistent); close.u64(opened.fileId.volatile)
        let closeMid = try client.sendOnly(.close, body: close.data)
        for index in 0..<13 {
            let response = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
            XCTAssertEqual(response.header.status, NTStatus.success.rawValue)
            if response.header.messageId == closeMid {
                XCTAssertEqual(index, 12, "CLOSE must wait for every preceding read response")
            } else {
                let offset = try XCTUnwrap(requests.removeValue(forKey: response.header.messageId))
                var r = ByteReader(response.body); _ = try r.u16()
                let dataOffset = Int(try r.u8()) - SMB2Header.size; _ = try r.u8()
                let count = Int(try r.u32())
                XCTAssertEqual(response.body.subdata(in: dataOffset..<(dataOffset + count)), bytes.subdata(in: offset..<(offset + 128)))
            }
        }
        XCTAssertTrue(requests.isEmpty)
        XCTAssertGreaterThan(engine.readConcurrency.peak, 1)
        XCTAssertLessThanOrEqual(engine.readConcurrency.peak, SMBLimits.readSlots)
        XCTAssertEqual(engine.readConcurrency.active, 0)
        let closed = try client.read(fileId: opened.fileId, offset: 0, length: 1)
        XCTAssertEqual(closed.status, NTStatus.fileClosed.rawValue)
    }

    func testReadOnlyExistingFileCannotOpenForWriteOrTruncate() throws {
        let engine = MemoryEngine()
        let payload = Data("original movie data".utf8)
        engine.seed("clip.bin", data: payload)
        engine.denyWrites = true
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let read = try client.create(path: "clip.bin", desiredAccess: 0x0012_0089)
        XCTAssertEqual(read.status, NTStatus.success.rawValue)
        for disposition: UInt32 in [1, 4] { // OPEN write and OVERWRITE
            var body = client.createBody(path: "clip.bin")
            patchU32(&body, at: 24, 0x0012_019F) // includes WRITE_DATA, APPEND, EA, ATTR
            patchU32(&body, at: 36, disposition)
            let denied = try client.request(.create, body: body)
            XCTAssertEqual(denied.header.status, NTStatus.accessDenied.rawValue)
        }
        let after = try client.read(fileId: read.fileId, offset: 0, length: UInt32(payload.count))
        XCTAssertEqual(after.data, payload)
    }

    func testFailedCompoundStreamProbeDoesNotCloseUnrelatedOpenFile() throws {
        let engine = MemoryEngine()
        let payload = Data("movie data".utf8)
        engine.seed("clip.bin", data: payload)
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let original = try client.create(path: "clip.bin")
        var create = client.createBody(path: "clip.bin:com.apple.quarantine")
        patchU32(&create, at: 36, 1) // OPEN existing (this xattr does not exist)
        var close = ByteWriter()
        close.u16(24); close.u16(0); close.u32(0)
        close.u64(UInt64.max); close.u64(UInt64.max)
        let replies = try client.compound([(.create, create), (.close, close.data)])
        XCTAssertEqual(replies[0].header.status, NTStatus.objectNameNotFound.rawValue)
        let read = try client.read(fileId: original.fileId, offset: 0, length: UInt32(payload.count))
        XCTAssertEqual(read.status, NTStatus.success.rawValue)
        XCTAssertEqual(read.data, payload)
    }

    func testDelayedReadDoesNotExposeBytesAfterCompletionLockCheckFails() throws {
        actor Admission {
            var checks = 0
            func check() throws {
                checks += 1
                if checks > 1 { throw EngineError(.locked, "A remote exclusive lock was acquired while downloading") }
            }
        }
        let engine = MemoryEngine(); engine.seed("delayed.bin", data: Data("private edit".utf8))
        engine.readDelayNs = 25_000_000
        let admission = Admission(); engine.rangeAccessHook = { try await admission.check() }
        let (server, client) = try connected(engine); defer { server.stop(); client.close() }
        let opened = try client.create(path: "delayed.bin", desiredAccess: 0x0012_0089)
        let result = try client.read(fileId: opened.fileId, offset: 0, length: 12)
        XCTAssertEqual(result.status, NTStatus.fileLockConflict.rawValue)
        XCTAssertTrue(result.data.isEmpty, "Denied completion must never leak a payload")
        try client.close(fileId: opened.fileId)
    }

    func testOversizeReadOffsetReturnsErrorWithoutCrashingConnection() throws {
        let engine = MemoryEngine()
        engine.seed("x", data: Data("data".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let original = try client.create(path: "x")
        let invalid = try client.read(fileId: original.fileId, offset: UInt64.max, length: 4)
        XCTAssertEqual(invalid.status, NTStatus.invalidParameter.rawValue)
        let valid = try client.read(fileId: original.fileId, offset: 0, length: 4)
        XCTAssertEqual(valid.data, Data("data".utf8))
    }

    func testCreateAnswersAAPLandMxAc() throws {
        let engine = MemoryEngine()
        engine.seed("x", data: Data("y".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        // A CREATE requesting AAPL + MxAc must still succeed (contexts answered).
        let open = try client.create(path: "x", wantMxAc: true, wantAAPL: true)
        XCTAssertEqual(open.status, NTStatus.success.rawValue)
        try client.close(fileId: open.fileId)
    }

    func testQueryInfoStandardAndFsAttribute() throws {
        let engine = MemoryEngine()
        engine.seed("doc.txt", data: Data(repeating: 1, count: 100))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let open = try client.create(path: "doc.txt")
        // FileStandardInformation (class 5): EndOfFile at offset 8.
        let std = try client.queryInfo(fileId: open.fileId, infoType: 0x01, infoClass: 0x05)
        XCTAssertEqual(std.status, NTStatus.success.rawValue)
        var r = ByteReader(std.buffer)
        _ = try r.u64()                          // AllocationSize
        XCTAssertEqual(try r.u64(), 100)         // EndOfFile

        // FileFsAttributeInformation (fs class 5): must advertise case-sensitive.
        let fsa = try client.queryInfo(fileId: open.fileId, infoType: 0x02, infoClass: 0x05)
        XCTAssertEqual(fsa.status, NTStatus.success.rawValue)
        var fr = ByteReader(fsa.buffer)
        let flags = try fr.u32()
        XCTAssertNotEqual(flags & FSAttributeFlags.caseSensitiveSearch, 0)
        XCTAssertNotEqual(flags & FSAttributeFlags.namedStreams, 0, "named streams advertised as of P4")
        try client.close(fileId: open.fileId)
    }

    func testCreateMissingFileReturnsNotFound() throws {
        let engine = MemoryEngine()
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let open = try client.create(path: "nope.txt")
        XCTAssertEqual(open.status, NTStatus.objectNameNotFound.rawValue)
    }
}

private actor PublicationAdmissionFault {
    private var checks = 0
    func check() throws {
        checks += 1
        if checks == 3 { throw EngineError(.locked, "Revoked while waiting to publish") }
    }
}

private actor LookupCounter {
    private(set) var count = 0
    func record() { count += 1 }
}
