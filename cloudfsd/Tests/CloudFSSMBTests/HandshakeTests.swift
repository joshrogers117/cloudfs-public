// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB P1a: drive the real server over a real loopback socket through the
// NEGOTIATE → SESSION_SETUP (two NTLM legs) → TREE_CONNECT handshake. Everything
// but the kernel smbfs client is exercised.

import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class HandshakeTests: XCTestCase {
    private func startServer() throws -> (SMBServer, UInt16, MemoryEngine) {
        let engine = MemoryEngine()
        engine.seed("hello.txt", data: Data("hi".utf8))
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: "pw-\(UUID().uuidString)"))
        let port = try server.start()
        return (server, port, engine)
    }

    func testNegotiateReturnsDialect21() throws {
        let (server, port, _) = try startServer()
        defer { server.stop() }
        let client = SMBTestClient()
        try client.connect(port: port)
        defer { client.close() }

        let resp = try client.negotiate()
        XCTAssertEqual(resp.header.status, NTStatus.success.rawValue)
        var r = ByteReader(resp.body)
        XCTAssertEqual(try r.u16(), 65)                         // StructureSize
        _ = try r.u16()                                         // SecurityMode
        XCTAssertEqual(try r.u16(), SMB2Dialect.smb21.rawValue) // negotiated 2.1
        _ = try r.u16()                                         // ctx count
        _ = try r.take(16)                                      // ServerGuid
        XCTAssertEqual(try r.u32() & SMB2Capabilities.leasing, 0, "must NOT advertise leasing")
        XCTAssertEqual(try r.u32(), 1 << 20)                    // MaxTransact = 1 MiB
        XCTAssertEqual(try r.u32(), 1 << 20)                    // MaxRead = 1 MiB
        XCTAssertEqual(try r.u32(), UInt32(SMBLimits.maximumWriteBytes))
        XCTAssertLessThan(SMBLimits.maximumWriteBytes + SMB2Header.size + 48, SMBLimits.maximumFrameBytes)
    }

    func testFullHandshakeAuthenticates() throws {
        let engine = MemoryEngine()
        let password = "s3cr3t"
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: password))
        let port = try server.start()
        defer { server.stop() }

        let client = SMBTestClient()
        try client.connect(port: port)
        defer { client.close() }

        _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: password)   // precondition-checks both legs
        XCTAssertNotEqual(client.sessionId, 0)

        let tree = try client.treeConnect(share: "cloudfs")
        XCTAssertEqual(tree.header.status, NTStatus.success.rawValue)
        XCTAssertNotEqual(client.treeId, 0)
        var r = ByteReader(tree.body)
        XCTAssertEqual(try r.u16(), 16)     // StructureSize
        XCTAssertEqual(try r.u8(), 0x01)    // ShareType = DISK
    }

    func testWrongPasswordRejected() throws {
        let engine = MemoryEngine()
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: "correct-horse"))
        let port = try server.start()
        defer { server.stop() }

        let client = SMBTestClient()
        try client.connect(port: port)
        defer { client.close() }

        _ = try client.negotiate()
        // Manually drive leg 1 + a wrong-password leg 2 (bypass the precondition helper).
        XCTAssertThrowsError(try client.sessionSetup(user: "cfs", password: "WRONG-PASSWORD")) { _ in }
    }

    func testEchoAnswered() throws {
        let (server, port, _) = try startServer()
        defer { server.stop() }
        let client = SMBTestClient()
        try client.connect(port: port)
        defer { client.close() }
        _ = try client.negotiate()

        var w = ByteWriter(); w.u16(4); w.u16(0)   // ECHO request: StructureSize=4, Reserved
        let resp = try client.request(.echo, body: w.data)
        XCTAssertEqual(resp.header.status, NTStatus.success.rawValue)
    }
}
