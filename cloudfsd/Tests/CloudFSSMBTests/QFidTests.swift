// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class QFidTests: XCTestCase {
    func testCreateQFidIsStableAndMatchesFileInternalInformation() throws {
        let engine = MemoryEngine()
        _ = engine.seedDir("child")
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: "pw"))
        let port = try server.start()
        let client = SMBTestClient()
        try client.connect(port: port)
        defer { server.stop(); client.close() }
        _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "cloudfs")

        let root = try createQFid(client, path: "")
        let child = try createQFid(client, path: "child")
        let repeatedChild = try createQFid(client, path: "child")
        defer {
            try? client.close(fileId: root.fileId)
            try? client.close(fileId: child.fileId)
            try? client.close(fileId: repeatedChild.fileId)
        }

        XCTAssertEqual(root.diskFileID, try internalFileID(client, root.fileId))
        XCTAssertEqual(child.diskFileID, try internalFileID(client, child.fileId))
        XCTAssertNotEqual(root.diskFileID, 0, "root must have a stable nonzero node file-id")
        XCTAssertNotEqual(child.diskFileID, 0)
        XCTAssertNotEqual(root.diskFileID, child.diskFileID)
        XCTAssertEqual(child.diskFileID, repeatedChild.diskFileID,
                       "multiple opens of one inode must report the same DiskFileId")
        XCTAssertNotEqual(root.volumeID, 0)
        XCTAssertEqual(root.volumeID, child.volumeID,
                       "all QFid responses from one mounted share use one VolumeId")
        XCTAssertEqual(root.reserved, Data(repeating: 0, count: 16))
        XCTAssertEqual(child.reserved, Data(repeating: 0, count: 16))
        XCTAssertEqual(root.payload.count, 32)
        XCTAssertEqual(child.payload.count, 32)
    }

    func testRemoteRenameRotatesNewPathIDAndKeepsHeldHandleIdentity() async throws {
        let engine = MemoryEngine()
        let original = engine.seed("source.bin", data: Data("old source".utf8))
        let replacement = engine.seed("replacement.bin", data: Data("replacement".utf8))
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: "pw"),
                               remotePresentationIDs: true)
        let port = try server.start()
        let client = SMBTestClient()
        try client.connect(port: port)
        defer { server.stop(); client.close() }
        _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "cloudfs")

        let root = try createQFid(client, path: "")
        let sourceBefore = try createQFid(client, path: "source.bin")
        let replacementBefore = try createQFid(client, path: "replacement.bin")
        defer {
            try? client.close(fileId: root.fileId)
            try? client.close(fileId: sourceBefore.fileId)
            try? client.close(fileId: replacementBefore.fileId)
        }
        XCTAssertEqual(sourceBefore.diskFileID, try internalFileID(client, sourceBefore.fileId))
        XCTAssertEqual(replacementBefore.diskFileID, try internalFileID(client, replacementBefore.fileId))

        let moved = try await engine.rename(replacement, newParent: .root, newName: "source.bin",
                                            replacing: try await engine.lookup(original))
        await server.table.invalidateListing(.root) // model a received directory-change notification
        let sourceAfter = try createQFid(client, path: "source.bin")
        defer { try? client.close(fileId: sourceAfter.fileId) }
        XCTAssertEqual(sourceAfter.diskFileID, try internalFileID(client, sourceAfter.fileId))
        XCTAssertNotEqual(sourceAfter.diskFileID, replacementBefore.diskFileID)
        XCTAssertEqual(try internalFileID(client, replacementBefore.fileId), replacementBefore.diskFileID,
                       "an already-open SMB handle retains its original QFid/index identity")
        XCTAssertEqual(try client.read(fileId: replacementBefore.fileId, offset: 0, length: 64).data,
                       Data("replacement".utf8), "the held SMB FID continues to address the moved backend inode")

        let (_, entries) = try client.queryDirectory(fileId: root.fileId, restart: true)
        XCTAssertEqual(entries.first { $0.name == "source.bin" }?.fileId, sourceAfter.diskFileID,
                       "directory entries and fresh opens expose the same presentation ID")

        XCTAssertEqual(try client.rename(fileId: sourceAfter.fileId, to: "local.bin", replace: false),
                       NTStatus.success.rawValue)
        let localAfter = try createQFid(client, path: "local.bin")
        defer { try? client.close(fileId: localAfter.fileId) }
        XCTAssertEqual(localAfter.diskFileID, sourceAfter.diskFileID,
                       "a local SMB rename keeps the existing presentation ID")
        let (_, entriesAfterLocalRename) = try client.queryDirectory(fileId: root.fileId, restart: true)
        XCTAssertFalse(entriesAfterLocalRename.contains { $0.name == "source.bin" },
                       "a restarted directory query must not expose the pre-commit name")
        let localEntries = entriesAfterLocalRename.filter { $0.name == "local.bin" }
        XCTAssertEqual(localEntries.count, 1,
                       "the post-commit listing must not duplicate a moved entry from its cached snapshot")
        XCTAssertEqual(localEntries.first?.fileId, localAfter.diskFileID)

        _ = engine.seed("replacement.bin", data: Data("new owner".utf8))
        await server.table.invalidateListing(.root)
        let reusedName = try createQFid(client, path: "replacement.bin")
        defer { try? client.close(fileId: reusedName.fileId) }
        XCTAssertNotEqual(reusedName.diskFileID, replacementBefore.diskFileID,
                          "reusing the old pathname does not alias the moved inode's old ID")
        XCTAssertNotEqual(moved.id, original)
    }

    private struct QFidReply {
        var diskFileID: UInt64
        var volumeID: UInt64
        var reserved: Data
        var payload: Data
        var fileId: SMBFileId
    }

    private func createQFid(_ client: SMBTestClient, path: String) throws -> QFidReply {
        let name = SMBString.utf16le(path)
        let contexts = requestedContexts()
        var request = ByteWriter()
        request.u16(57); request.u8(0); request.u8(0); request.u32(2)
        request.u64(0); request.u64(0)
        request.u32(SMBAccess.all); request.u32(0); request.u32(0x07)
        request.u32(1); request.u32(0)
        let nameOffset = SMB2Header.size + 56
        request.u16(UInt16(name.isEmpty ? 0 : nameOffset))
        request.u16(UInt16(name.count))
        let paddedNameLength = (name.count + 7) & ~7
        let contextsOffset = name.isEmpty ? nameOffset : nameOffset + paddedNameLength
        request.u32(UInt32(contextsOffset)); request.u32(UInt32(contexts.count))
        request.bytes(name)
        if !name.isEmpty, paddedNameLength > name.count { request.zeros(paddedNameLength - name.count) }
        request.bytes(contexts)

        let response = try client.request(.create, body: request.data)
        XCTAssertEqual(response.header.status, NTStatus.success.rawValue, "CREATE path: \(path)")
        let responseBody = response.body
        XCTAssertGreaterThanOrEqual(responseBody.count, 88)
        var bodyReader = ByteReader(responseBody)
        _ = try bodyReader.u16(); _ = try bodyReader.u8(); _ = try bodyReader.u8(); _ = try bodyReader.u32()
        for _ in 0..<4 { _ = try bodyReader.u64() }
        _ = try bodyReader.u64(); _ = try bodyReader.u64()
        _ = try bodyReader.u32(); _ = try bodyReader.u32()
        let persistent = try bodyReader.u64()
        let volatile = try bodyReader.u64()
        let contextOffset = Int(try bodyReader.u32())
        let contextLength = Int(try bodyReader.u32())
        XCTAssertEqual(contextOffset, SMB2Header.size + 88)
        XCTAssertGreaterThanOrEqual(contextLength, 48)
        let contextStart = contextOffset - SMB2Header.size
        let contextData = responseBody.subdata(in: contextStart..<(contextStart + contextLength))
        var contextNames = Set<String>()
        var qfidPayload: Data?
        var cursor = 0
        while cursor + 16 <= contextData.count {
            var contextReader = ByteReader(contextData.subdata(in: cursor..<contextData.count))
            let next = Int(try contextReader.u32())
            let contextNameOffset = Int(try contextReader.u16())
            let nameLength = Int(try contextReader.u16())
            _ = try contextReader.u16() // Reserved
            let dataOffset = Int(try contextReader.u16())
            let dataLength = Int(try contextReader.u32())
            let contextName = String(data: contextData.subdata(
                in: (cursor + contextNameOffset)..<(cursor + contextNameOffset + nameLength)), encoding: .ascii)
            if let contextName { contextNames.insert(contextName) }
            if contextName == CreateContextName.queryOnDiskId {
                XCTAssertEqual(dataLength, 32)
                qfidPayload = contextData.subdata(in: (cursor + dataOffset)..<(cursor + dataOffset + dataLength))
            }
            if next == 0 { break }
            XCTAssertGreaterThanOrEqual(next, 16)
            XCTAssertEqual(next % 8, 0)
            cursor += next
        }
        XCTAssertEqual(contextNames, [CreateContextName.queryOnDiskId, "MxAc", "AAPL"])
        let payload = try XCTUnwrap(qfidPayload, "CREATE response did not return QFid context")
        var payloadReader = ByteReader(payload)
        let diskFileID = try payloadReader.u64()
        let volumeID = try payloadReader.u64()
        let reserved = try payloadReader.take(16)
        return QFidReply(diskFileID: diskFileID, volumeID: volumeID, reserved: reserved,
                         payload: payload,
                         fileId: SMBFileId(persistent: persistent, volatile: volatile))
    }

    private func internalFileID(_ client: SMBTestClient, _ fileId: SMBFileId) throws -> UInt64 {
        let result = try client.queryInfo(fileId: fileId, infoType: 1,
                                          infoClass: FileInfoClass.internalInformation.rawValue)
        XCTAssertEqual(result.status, NTStatus.success.rawValue)
        XCTAssertEqual(result.buffer.count, 8)
        var reader = ByteReader(result.buffer)
        return try reader.u64()
    }

    private func requestedContexts() -> Data {
        var aapl = ByteWriter()
        aapl.u32(AAPL.commandServerQuery); aapl.u32(0); aapl.u64(0x03); aapl.u64(0)
        let contexts = [
            createContext(name: CreateContextName.queryOnDiskId, data: Data()),
            createContext(name: "MxAc", data: Data()),
            createContext(name: "AAPL", data: aapl.data),
        ]
        var chained = Data()
        for index in contexts.indices {
            var context = contexts[index]
            if index + 1 < contexts.count {
                let offset = UInt32(context.count)
                for byte in 0..<4 { context[byte] = UInt8((offset >> UInt32(byte * 8)) & 0xff) }
            }
            chained.append(context)
        }
        return chained
    }

    private func createContext(name: String, data: Data) -> Data {
        let nameBytes = Data(name.utf8)
        let paddedNameLength = (nameBytes.count + 7) & ~7
        var context = ByteWriter()
        context.u32(0)
        context.u16(16)
        context.u16(UInt16(nameBytes.count))
        context.u16(0)
        context.u16(UInt16(16 + paddedNameLength))
        context.u32(UInt32(data.count))
        context.bytes(nameBytes)
        if paddedNameLength > nameBytes.count { context.zeros(paddedNameLength - nameBytes.count) }
        context.bytes(data)
        while context.count % 8 != 0 { context.u8(0) }
        return context.data
    }
}
