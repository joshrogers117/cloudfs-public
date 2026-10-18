// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB P4c: named streams (xattrs) over the wire — create/write/read/list/
// delete a stream on a base file, and the empty-AfpInfo delete convention.

import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class StreamTests: XCTestCase {
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

    private let FILE_OPEN_IF: UInt32 = 3

    func testFinderInfoCreationCanReadEmptyStreamBeforeItsFirstWrite() throws {
        let engine = MemoryEngine()
        engine.seed("doc", data: Data("body".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let open = try client.createEx(path: "doc:AFP_AfpInfo:$DATA", disposition: FILE_OPEN_IF)
        XCTAssertEqual(open.status, NTStatus.success.rawValue)
        let empty = try client.read(fileId: open.fileId, offset: 0, length: 60)
        XCTAssertEqual(empty.status, NTStatus.endOfFile.rawValue)
        XCTAssertTrue(empty.data.isEmpty)
        var metadata = Data(repeating: 0, count: 60)
        metadata.replaceSubrange(16..<24, with: Data("TESTCFS ".utf8))
        XCTAssertEqual(try client.write(fileId: open.fileId, offset: 0, data: metadata).status, NTStatus.success.rawValue)
        try client.close(fileId: open.fileId)
        let reopened = try client.createEx(path: "doc:AFP_AfpInfo:$DATA", disposition: 1)
        XCTAssertEqual(try client.read(fileId: reopened.fileId, offset: 0, length: 60).data, metadata)
    }

    func testWriteReadListDeleteStream() throws {
        let engine = MemoryEngine()
        engine.seed("doc.txt", data: Data("body".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        // Write an xattr via the named-stream path "doc.txt:com.apple.foo:$DATA".
        let payload = Data("hello xattr".utf8)
        let open = try client.createEx(path: "doc.txt:com.apple.foo:$DATA", disposition: FILE_OPEN_IF)
        XCTAssertEqual(open.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.write(fileId: open.fileId, offset: 0, data: payload).status, NTStatus.success.rawValue)
        try client.close(fileId: open.fileId)

        // Read it back.
        let ro = try client.createEx(path: "doc.txt:com.apple.foo:$DATA", disposition: 1 /* OPEN */)
        XCTAssertEqual(ro.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: ro.fileId, offset: 0, length: 64).data, payload)
        try client.close(fileId: ro.fileId)

        // FileStreamInformation (class 22) lists it (plus the main ::$DATA stream).
        let base = try client.create(path: "doc.txt")
        let info = try client.queryInfo(fileId: base.fileId, infoType: 0x01, infoClass: 22)
        XCTAssertEqual(info.status, NTStatus.success.rawValue)
        let names = Self.parseStreamNames(info.buffer)
        XCTAssertTrue(names.contains(":com.apple.foo:$DATA"), "streams were \(names)")
        XCTAssertTrue(names.contains("::$DATA"), "main data stream missing")
        try client.close(fileId: base.fileId)

        // The base file listing must NOT show the xattr as a file (no ._ pollution).
        let root = try client.create(path: "")
        let dir = try client.queryDirectory(fileId: root.fileId, restart: true)
        XCTAssertFalse(dir.items.map(\.name).contains { $0.hasPrefix("._") })
    }

    func testStreamReadFailureCannotOverwriteExistingResourceFork() throws {
        let engine = MemoryEngine()
        engine.seed("doc", data: Data("file".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let open = try client.createEx(path: "doc:AFP_Resource:$DATA", disposition: FILE_OPEN_IF)
        let original = Data("original resource fork".utf8)
        XCTAssertEqual(try client.write(fileId: open.fileId, offset: 0, data: original).status, NTStatus.success.rawValue)
        engine.streamReadError = EngineError(.networkError, "injected disconnected storage")
        XCTAssertNotEqual(try client.write(fileId: open.fileId, offset: 4, data: Data("changed".utf8)).status, NTStatus.success.rawValue)
        XCTAssertNotEqual(try client.read(fileId: open.fileId, offset: 0, length: 64).status, NTStatus.success.rawValue)
        engine.streamReadError = nil
        XCTAssertEqual(try client.read(fileId: open.fileId, offset: 0, length: 64).data, original)
    }

    func testReadingMissingXattrReturnsNotFound() throws {
        let engine = MemoryEngine()
        engine.seed("f", data: Data("x".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let open = try client.createEx(path: "f:com.apple.absent:$DATA", disposition: 1 /* OPEN */)
        XCTAssertEqual(open.status, NTStatus.objectNameNotFound.rawValue)
    }

    func testFailedStreamListFallbackReleasesRemoteAndLocalOpenReservations() throws {
        let engine = MemoryEngine()
        let id = engine.seed("doc", data: Data("body".utf8))
        engine.streamListError = EngineError(.networkError, "injected stream metadata failure")
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let failed = try client.createEx(path: "doc:com.apple.provenance:$DATA", disposition: 1,
                                         desiredAccess: 0x1, shareAccess: 0x7)
        XCTAssertEqual(failed.status, NTStatus.unsuccessful.rawValue)
        XCTAssertEqual(engine.openReferenceCount(id), 0, "remote open acquired before the list failure must be cleaned up")

        engine.streamListError = nil
        let next = try client.createEx(path: "doc", disposition: 1, desiredAccess: 0x2,
                                       shareAccess: 0x6)
        XCTAssertEqual(next.status, NTStatus.success.rawValue,
                       "the failed stream probe must not retain a local read reservation that blocks this writer")
        XCTAssertEqual(engine.openReferenceCount(id), 1)
        try client.close(fileId: next.fileId)
        XCTAssertEqual(engine.openReferenceCount(id), 0)
    }

    func testWritableStreamCreateChecksCollisionAfterWriteLease() throws {
        let engine = MemoryEngine()
        let id = engine.seed("doc", data: Data("body".utf8))
        engine.seedStream(id, name: "existing", data: Data("old".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let result = try client.createEx(path: "doc:existing:$DATA", disposition: 2,
                                         desiredAccess: SMBAccess.writeData, shareAccess: 0x7)
        XCTAssertEqual(result.status, NTStatus.objectNameCollision.rawValue)
        XCTAssertEqual(engine.streamLifecycleEvents, ["beginWrite", "listStreams"],
                       "writable CREATE must list the stream only after acquiring its write lease")
        XCTAssertEqual(engine.openReferenceCount(id), 0, "a collision must release the temporary open")
    }

    func testStreamTruncateAndOverwriteDoNotChangeTheMainDataFork() throws {
        let engine = MemoryEngine(), main = Data("original main contents".utf8)
        engine.seed("doc", data: main)
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let fork = try client.createEx(path: "doc:AFP_Resource:$DATA", disposition: FILE_OPEN_IF)
        XCTAssertEqual(try client.write(fileId: fork.fileId, offset: 0, data: Data([1, 2, 3, 4])).status, NTStatus.success.rawValue)
        let before = try client.queryInfo(fileId: fork.fileId, infoType: 1, infoClass: 5)
        var beforeInfo = ByteReader(before.buffer); _ = try beforeInfo.u64()
        XCTAssertEqual(try beforeInfo.u64(), 4, "stream EOF must not be the carrier file's size")
        var length = ByteWriter(); length.u64(2)
        XCTAssertEqual(try client.setInfo(fileId: fork.fileId, infoType: 1, infoClass: 20, data: length.data), NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: fork.fileId, offset: 0, length: 10).data, Data([1, 2]))
        let after = try client.queryInfo(fileId: fork.fileId, infoType: 1, infoClass: 18)
        var allInfo = ByteReader(Data(after.buffer.dropFirst(40))); _ = try allInfo.u64()
        XCTAssertEqual(try allInfo.u64(), 2, "all-info EOF must retain the stream truncation")
        try client.close(fileId: fork.fileId)
        let replacement = try client.createEx(path: "doc:AFP_Resource:$DATA", disposition: 5)
        XCTAssertEqual(try client.read(fileId: replacement.fileId, offset: 0, length: 10).status, NTStatus.endOfFile.rawValue)
        try client.close(fileId: replacement.fileId)
        let ordinary = try client.create(path: "doc")
        XCTAssertEqual(try client.read(fileId: ordinary.fileId, offset: 0, length: 100).data, main)
    }

    func testResourceForkCanCrossFormerFourMiBLimitOverSMB() throws {
        let engine = MemoryEngine(); engine.seed("doc", data: Data("main".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let fork = try client.createEx(path: "doc:AFP_Resource:$DATA", disposition: FILE_OPEN_IF)
        for index in 0..<6 {
            let bytes = Data(repeating: UInt8(index + 1), count: 1 << 20)
            XCTAssertEqual(try client.write(fileId: fork.fileId, offset: UInt64(index << 20), data: bytes).status, NTStatus.success.rawValue)
        }
        XCTAssertEqual(try client.read(fileId: fork.fileId, offset: 5 << 20, length: 1 << 20).data, Data(repeating: 6, count: 1 << 20))
    }

    func testTwoOpenStreamHandlesObserveEachOthersGrowthAndTruncation() throws {
        let engine = MemoryEngine(); engine.seed("doc", data: Data("main".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let first = try client.createEx(path: "doc:AFP_Resource:$DATA", disposition: FILE_OPEN_IF)
        let second = try client.createEx(path: "doc:AFP_Resource:$DATA", disposition: FILE_OPEN_IF)
        XCTAssertEqual(try client.write(fileId: first.fileId, offset: 0, data: Data([1, 2, 3, 4])).status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: second.fileId, offset: 0, length: 10).data, Data([1, 2, 3, 4]))
        var info = ByteReader(try client.queryInfo(fileId: second.fileId, infoType: 1, infoClass: 5).buffer)
        _ = try info.u64(); XCTAssertEqual(try info.u64(), 4)
        var size = ByteWriter(); size.u64(1)
        XCTAssertEqual(try client.setInfo(fileId: second.fileId, infoType: 1, infoClass: 20, data: size.data), NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: first.fileId, offset: 0, length: 10).data, Data([1]))
        XCTAssertEqual(try client.read(fileId: first.fileId, offset: 1, length: 10).status, NTStatus.endOfFile.rawValue)
        info = ByteReader(try client.queryInfo(fileId: first.fileId, infoType: 1, infoClass: 5).buffer)
        _ = try info.u64(); XCTAssertEqual(try info.u64(), 1)
    }

    func testNamedStreamsAdvertised() throws {
        let engine = MemoryEngine()
        engine.seed("f", data: Data("x".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let open = try client.create(path: "f")
        let fsa = try client.queryInfo(fileId: open.fileId, infoType: 0x02, infoClass: 0x05)
        var r = ByteReader(fsa.buffer)
        XCTAssertNotEqual(try r.u32() & FSAttributeFlags.namedStreams, 0, "FILE_NAMED_STREAMS must be set")
    }

    static func parseStreamNames(_ buf: Data) -> [String] {
        var out: [String] = []
        var cursor = 0
        while cursor + 24 <= buf.count {
            let slice = buf.subdata(in: cursor..<buf.count)
            var r = ByteReader(slice)
            let next = Int((try? r.u32()) ?? 0)
            let nameLen = Int((try? r.u32()) ?? 0)
            _ = try? r.u64(); _ = try? r.u64()
            let name = (try? r.take(nameLen)).map { SMBString.decodeUTF16le($0) } ?? ""
            out.append(name)
            if next == 0 { break }
            cursor += next
        }
        return out
    }
}
