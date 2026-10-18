// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class DirectorySnapshotSMBTests: XCTestCase {
    private func connected(_ engine: MemoryEngine) throws -> (SMBServer, SMBTestClient) {
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: "pw"))
        let client = SMBTestClient()
        try client.connect(port: server.start())
        _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "cloudfs")
        return (server, client)
    }

    private func directoryCreateBody(path: String, access: UInt32 = 0x0000_0001,
                                     disposition: UInt32 = 1) -> Data {
        let name = SMBString.utf16le(path)
        var w = ByteWriter()
        w.u16(57); w.u8(0); w.u8(0); w.u32(2); w.u64(0); w.u64(0)
        w.u32(access); w.u32(0); w.u32(0x07); w.u32(disposition); w.u32(0x0000_0001)
        w.u16(UInt16(SMB2Header.size + 56)); w.u16(UInt16(name.count)); w.u32(0); w.u32(0)
        w.bytes(name)
        return w.data
    }

    private func queryBody(pattern: String = "old.txt") -> Data {
        let name = SMBString.utf16le(pattern)
        var w = ByteWriter()
        w.u16(33); w.u8(0x25); w.u8(0x03); w.u32(0)
        w.u64(UInt64.max); w.u64(UInt64.max)
        w.u16(UInt16(SMB2Header.size + 32)); w.u16(UInt16(name.count)); w.u32(4096)
        w.bytes(name)
        return w.data
    }

    private func relatedCloseBody() -> Data {
        var w = ByteWriter()
        w.u16(24); w.u16(0); w.u32(0); w.u64(UInt64.max); w.u64(UInt64.max)
        return w.data
    }

    func testReadOnlyCreateQueryCloseUsesOneTransientSnapshotAndNoRemoteOpen() throws {
        let engine = MemoryEngine()
        let directory = engine.seedDir("folder")
        _ = engine.seed("old.txt", parent: directory, data: Data("old".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        let responses = try client.compound([
            (.create, directoryCreateBody(path: "folder")),
            (.queryDirectory, queryBody()),
            (.close, relatedCloseBody())
        ])
        XCTAssertEqual(responses.map(\.header.status), Array(repeating: NTStatus.success.rawValue, count: 3))
        XCTAssertEqual(engine.directorySnapshotCallCount, 1)
        XCTAssertEqual(engine.beginOpenCallCount, 0, "the transient backend snapshot must not retain a remote open")
        XCTAssertEqual(engine.endOpenCallCount, 0, "the snapshot transaction already closed its temporary remote handle")
        XCTAssertTrue(responses[1].body.range(of: SMBString.utf16le("old.txt")) != nil,
                      "the related QUERY_DIRECTORY must use the CREATE snapshot")

        // The compound CLOSE must also release the local reservation.
        let ordinary = try client.create(path: "folder", desiredAccess: 0x0000_0001)
        XCTAssertEqual(ordinary.status, NTStatus.success.rawValue)
        try client.close(fileId: ordinary.fileId)
    }

    func testSnapshotFastPathRejectsWrongSessionPersistentWritableAndWildcardRequests() throws {
        func run(access: UInt32 = 0x0000_0001, disposition: UInt32 = 1,
                 pattern: String = "old.txt", wrongSession: Bool = false) throws -> (MemoryEngine, [SMBTestClient.Response]) {
            let engine = MemoryEngine()
            let directory = engine.seedDir("folder")
            _ = engine.seed("old.txt", parent: directory, data: Data("old".utf8))
            let (server, client) = try connected(engine)
            defer { server.stop(); client.close() }
            let responses = try client.compound([
                (.create, directoryCreateBody(path: "folder", access: access, disposition: disposition)),
                (.queryDirectory, queryBody(pattern: pattern)),
                (.close, relatedCloseBody())
            ], mutateHeader: { index, header in
                if wrongSession && index == 0 { header.sessionId &+= 1 }
            })
            return (engine, responses)
        }

        let (wrongSessionEngine, _) = try run(wrongSession: true)
        XCTAssertEqual(wrongSessionEngine.directorySnapshotCallCount, 0)

        let (persistentEngine, persistentResponses) = try run(disposition: 2)
        XCTAssertEqual(persistentResponses.first?.header.status, NTStatus.objectNameCollision.rawValue)
        XCTAssertEqual(persistentEngine.directorySnapshotCallCount, 0)
        XCTAssertEqual(persistentEngine.beginOpenCallCount, 1)
        XCTAssertEqual(persistentEngine.endOpenCallCount, 1)

        let (writableEngine, _) = try run(access: 0x0000_0002)
        XCTAssertEqual(writableEngine.directorySnapshotCallCount, 0)
        XCTAssertEqual(writableEngine.beginOpenCallCount, 1)
        XCTAssertEqual(writableEngine.endOpenCallCount, 1)

        let (wildcardEngine, _) = try run(pattern: "*.txt")
        XCTAssertEqual(wildcardEngine.directorySnapshotCallCount, 0)
        XCTAssertEqual(wildcardEngine.beginOpenCallCount, 1)
        XCTAssertEqual(wildcardEngine.endOpenCallCount, 1)
    }
}
