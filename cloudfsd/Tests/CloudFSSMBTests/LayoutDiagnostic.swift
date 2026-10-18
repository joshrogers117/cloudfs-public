// SPDX-License-Identifier: AGPL-3.0-or-later
// Byte-level layout verification of FileIdBothDirectoryInformation against the
// [MS-FSCC] §2.4.17 field offsets, decoded independently of the packer/parser.

import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class LayoutDiagnostic: XCTestCase {
    func testFirstEntryFieldOffsets() throws {
        let engine = MemoryEngine()
        engine.seed("readme.txt", data: Data(repeating: 9, count: 1234))
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: "pw"))
        let port = try server.start(); defer { server.stop() }
        let client = SMBTestClient(); try client.connect(port: port); defer { client.close() }
        _ = try client.negotiate(); try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "cloudfs")
        let root = try client.create(path: "")
        let buf = try client.rawQueryDirectory(fileId: root.fileId)

        func u32(_ off: Int) -> UInt32 {
            buf.subdata(in: off..<off+4).withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
        }
        func u64(_ off: Int) -> UInt64 {
            buf.subdata(in: off..<off+8).withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(as: UInt64.self)) }
        }
        // MS-FSCC §2.4.17 offsets for entry 0.
        let next = u32(0)
        let attrs = u32(56)          // FileAttributes
        let nameLen = u32(60)        // FileNameLength
        let fileId = u64(96)         // FileId
        let nameOff = 104
        let nameBytes = buf.subdata(in: nameOff..<nameOff + Int(nameLen))
        let name = SMBString.decodeUTF16le(nameBytes)

        print("LAYOUT next=\(next) attrs=0x\(String(attrs, radix: 16)) nameLen=\(nameLen) fileId=\(fileId) name='\(name)'")
        // Entry 0 is "." (a directory).
        XCTAssertEqual(name, ".", "first entry name at offset 104 must be '.'")
        XCTAssertEqual(attrs & 0x10, 0x10, "'.' must have DIRECTORY attribute at offset 56")
        XCTAssertEqual(next, 112, "NextEntryOffset for '.' (104+2 padded to 8) must be 112")
    }
}
