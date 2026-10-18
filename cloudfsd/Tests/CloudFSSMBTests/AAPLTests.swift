// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB: AAPL SUPPORTS_READ_DIR_ATTR overlay — when the client negotiates
// AAPL, QUERY_DIRECTORY entries repurpose EaSize/ShortName/Reserved2 to carry the
// resource-fork size, FinderInfo, and POSIX mode (Apple smb_2.h). The entry size
// stays 104 bytes; only the values of those fields change.

import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class AAPLTests: XCTestCase {
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

    /// With AAPL negotiated, the first dir entry (".") must carry the overlay:
    /// EaSize (offset 64) = max access; Reserved2 (offset 94) = a POSIX dir mode.
    func testReadDirAttrOverlayActiveWhenAAPLNegotiated() throws {
        let engine = MemoryEngine()
        engine.seed("clip.mov", data: Data(repeating: 3, count: 4096))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }

        // Open root WITH an AAPL ServerQuery context (as the mac kernel does).
        let root = try client.create(path: "", wantMxAc: true, wantAAPL: true)
        XCTAssertEqual(root.status, NTStatus.success.rawValue)
        let buf = try client.rawQueryDirectory(fileId: root.fileId)
        XCTAssertGreaterThanOrEqual(buf.count, 104)

        func u32(_ off: Int) -> UInt32 {
            buf.subdata(in: off..<off+4).withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
        }
        func u16(_ off: Int) -> UInt16 {
            buf.subdata(in: off..<off+2).withUnsafeBytes { UInt16(littleEndian: $0.loadUnaligned(as: UInt16.self)) }
        }
        // First entry is "." (a directory).
        XCTAssertEqual(u32(64), 0x001F_01FF, "EaSize must carry max access under AAPL")
        XCTAssertEqual(u16(94), 0o040700, "Reserved2 must carry the POSIX dir mode under AAPL")
        // The listing is still non-empty and well-formed (name at offset 104 = ".").
        let nameLen = Int(u32(60))
        let name = SMBString.decodeUTF16le(buf.subdata(in: 104..<104+nameLen))
        XCTAssertEqual(name, ".")
    }

    /// Without AAPL, those fields stay zero (standard FileIdBothDirectoryInformation).
    func testNoOverlayWhenAAPLNotNegotiated() throws {
        let engine = MemoryEngine()
        engine.seed("f", data: Data("x".utf8))
        let (server, client) = try connected(engine)
        defer { server.stop(); client.close() }
        let root = try client.create(path: "")   // no AAPL context
        let buf = try client.rawQueryDirectory(fileId: root.fileId)
        func u32(_ off: Int) -> UInt32 {
            buf.subdata(in: off..<off+4).withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
        }
        XCTAssertEqual(u32(64), 0, "EaSize must be zero without AAPL")
    }
}
