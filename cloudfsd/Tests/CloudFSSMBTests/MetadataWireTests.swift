// SPDX-License-Identifier: AGPL-3.0-or-later
// Wire assertions independent of SMBTestClient.setInfo's status-only helper.
import Foundation
import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class MetadataWireTests: XCTestCase {
    private func connected(_ engine: MemoryEngine) throws -> (SMBServer, SMBTestClient) {
        let server = SMBServer(engine: engine, shareName: "cloudfs", credential: (user: "cfs", password: "pw"))
        let client = SMBTestClient()
        try client.connect(port: server.start())
        _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "cloudfs")
        return (server, client)
    }

    /// MS-SMB2 2.2.39: fixed bytes 0..31, FileId at16, payload at32
    /// (absolute SMB-header offset96). Do not share the production writer/parser.
    private func setInfoPacket(_ id: SMBFileId, infoClass: UInt8, payload: [UInt8]) -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        bytes[0] = 33; bytes[2] = 1; bytes[3] = infoClass
        let size = UInt32(payload.count)
        for index in 0..<4 { bytes[4 + index] = UInt8(truncatingIfNeeded: size >> (8 * index)) }
        bytes[8] = 96
        for index in 0..<8 {
            bytes[16 + index] = UInt8(truncatingIfNeeded: id.persistent >> (8 * index))
            bytes[24 + index] = UInt8(truncatingIfNeeded: id.volatile >> (8 * index))
        }
        return Data(bytes + payload)
    }

    private func assertError(_ response: SMBTestClient.Response, status: NTStatus,
                             file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(response.header.command, .setInfo, file: file, line: line)
        XCTAssertEqual(response.header.status, status.rawValue, file: file, line: line)
        // MS-SMB2 2.2.2: StructureSize9, no contexts, reserved0, ByteCount0.
        // A failed SET_INFO must not carry its two-byte success structure.
        XCTAssertEqual(response.body, Data([9, 0, 0, 0, 0, 0, 0, 0]), file: file, line: line)
    }

    func testAccessDeniedSetInfoHasErrorBody() throws {
        let engine = MemoryEngine(); let inode = engine.seed("denied.bin", data: Data(count: 16))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let opened = try client.create(path: "denied.bin", desiredAccess: 0x80 /* FILE_READ_ATTRIBUTES */)
        XCTAssertEqual(opened.status, NTStatus.success.rawValue)
        let response = try client.request(.setInfo, body: setInfoPacket(opened.fileId, infoClass: 20,
            payload: [8, 0, 0, 0, 0, 0, 0, 0]))
        assertError(response, status: .accessDenied)
        XCTAssertEqual(engine.contents[inode]?.count, 16)
    }

    func testRangeConflictSetInfoHasErrorBody() throws {
        let engine = MemoryEngine(); let inode = engine.seed("locked.bin", data: Data(count: 16))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let opened = try client.create(path: "locked.bin")
        XCTAssertEqual(opened.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.lock(fileId: opened.fileId, offset: 0, length: 16, flags: 1), NTStatus.success.rawValue)
        let response = try client.request(.setInfo, body: setInfoPacket(opened.fileId, infoClass: 20,
            payload: [8, 0, 0, 0, 0, 0, 0, 0]))
        assertError(response, status: .fileLockConflict)
        XCTAssertEqual(engine.contents[inode]?.count, 16)
    }

    func testUnsupportedSetInfoHasErrorBody() throws {
        let engine = MemoryEngine(); engine.seed("unsupported.bin", data: Data(count: 16))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let opened = try client.create(path: "unsupported.bin")
        XCTAssertEqual(opened.status, NTStatus.success.rawValue)
        let response = try client.request(.setInfo, body: setInfoPacket(opened.fileId, infoClass: 0xff, payload: []))
        assertError(response, status: .notSupported)
    }

    func testSuccessfulSetInfoRetainsTwoByteSuccessBody() throws {
        let engine = MemoryEngine(); let inode = engine.seed("success.bin", data: Data(count: 16))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let opened = try client.create(path: "success.bin")
        XCTAssertEqual(opened.status, NTStatus.success.rawValue)
        let response = try client.request(.setInfo, body: setInfoPacket(opened.fileId, infoClass: 20,
            payload: [8, 0, 0, 0, 0, 0, 0, 0]))
        XCTAssertEqual(response.header.status, NTStatus.success.rawValue)
        XCTAssertEqual(response.body, Data([2, 0])) // MS-SMB2 2.2.40
        XCTAssertEqual(engine.contents[inode]?.count, 8)
    }
}
