// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixed-offset wire fixtures intentionally do not use SMBTestClient's notify
// builder: a mirrored parser/builder offset error previously hid incompatibility
// with every 32-byte request sent by the macOS kernel.
import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class NotifyWireTests: XCTestCase {
    private func connected(_ engine: MemoryEngine = MemoryEngine()) throws -> (SMBServer, SMBTestClient) {
        let server = SMBServer(engine: engine, shareName: "notify",
                               credential: (user: "cfs", password: "pw"))
        let port = try server.start()
        let client = SMBTestClient()
        try client.connect(port: port)
        _ = try client.negotiate()
        try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "notify")
        return (server, client)
    }

    private func fixture(_ fileId: SMBFileId, flags: UInt16 = 0,
                         outputLength: UInt32 = 65536, filter: UInt32 = 1,
                         reserved: UInt32 = 0) -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        func put(_ value: UInt64, at offset: Int, count: Int) {
            for index in 0..<count { bytes[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
        }
        put(32, at: 0, count: 2)
        put(UInt64(flags), at: 2, count: 2)
        put(UInt64(outputLength), at: 4, count: 4)
        put(fileId.persistent, at: 8, count: 8)
        put(fileId.volatile, at: 16, count: 8)
        put(UInt64(filter), at: 24, count: 4)
        put(UInt64(reserved), at: 28, count: 4)
        return Data(bytes)
    }

    func testExact32ByteRequestCompletesAfterMutation() throws {
        let (server, client) = try connected()
        defer { client.close(); server.stop() }
        let directory = try client.create(path: "")
        let body = fixture(directory.fileId)
        XCTAssertEqual(body.count, 32)
        let interim = try client.request(.changeNotify, body: body)
        XCTAssertEqual(interim.header.status, NTStatus.pending.rawValue)
        guard interim.header.status == NTStatus.pending.rawValue else { return }
        XCTAssertTrue(interim.header.flags.contains(.asyncCommand))
        try client.sendOnly(.create, body: client.createBody(path: "arrived.txt"))
        var completion: SMBTestClient.Response?
        for _ in 0..<2 {
            if let response = client.readAsyncResponse(timeoutMs: 2000), response.header.command == .changeNotify {
                completion = response
                break
            }
        }
        XCTAssertEqual(completion?.header.status, NTStatus.notifyEnumDir.rawValue)
        XCTAssertEqual(completion?.header.asyncId, interim.header.asyncId)
        XCTAssertEqual(completion?.header.messageId, interim.header.messageId)
    }

    func testAllTruncatedFixedFieldsAreRejected() throws {
        let (server, client) = try connected()
        defer { client.close(); server.stop() }
        let directory = try client.create(path: "")
        let body = fixture(directory.fileId)
        for count in 0..<32 {
            XCTAssertEqual(try client.request(.changeNotify, body: Data(body.prefix(count))).header.status,
                           NTStatus.invalidParameter.rawValue, "truncated at byte \(count)")
        }
    }

    func testZeroOutputAndUnknownFilterBitsAndReservedAreAccepted() throws {
        let (server, client) = try connected()
        defer { client.close(); server.stop() }
        let directory = try client.create(path: "")
        let response = try client.request(.changeNotify,
            body: fixture(directory.fileId, flags: 1, outputLength: 0, filter: 0x8000_0fff, reserved: .max))
        XCTAssertEqual(response.header.status, NTStatus.pending.rawValue)
    }

    func testUnknownOnlyFilterRemainsPendingUntilClose() throws {
        let (server, client) = try connected()
        defer { client.close(); server.stop() }
        let directory = try client.create(path: "")
        XCTAssertEqual(try client.request(.changeNotify,
            body: fixture(directory.fileId, filter: 0x8000_0000)).header.status, NTStatus.pending.rawValue)
        try client.sendOnly(.create, body: client.createBody(path: "unrelated.txt"))
        let created = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 2000))
        XCTAssertEqual(created.header.command, .create)
        XCTAssertEqual(created.header.status, NTStatus.success.rawValue)
        XCTAssertNil(client.readAsyncResponse(timeoutMs: 150), "No valid filter bit means no change completion")
        var close = ByteWriter(); close.u16(24); close.u16(0); close.u32(0)
        close.u64(directory.fileId.persistent); close.u64(directory.fileId.volatile)
        try client.sendOnly(.close, body: close.data)
        let cancelled = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 2000))
        XCTAssertEqual(cancelled.header.command, .changeNotify)
        XCTAssertEqual(cancelled.header.status, NTStatus.cancelled.rawValue)
        XCTAssertEqual(cancelled.body, Data([9, 0, 0, 0, 0, 0, 0, 0]), "Cancelled async requests need the SMB2 ERROR layout")
    }

    func testBoundsAndDirectoryAccessAreChecked() throws {
        let (server, client) = try connected()
        defer { client.close(); server.stop() }
        let directory = try client.create(path: "")
        for body in [fixture(directory.fileId, flags: 2), fixture(directory.fileId, outputLength: (1 << 20) + 1)] {
            XCTAssertEqual(try client.request(.changeNotify, body: body).header.status, NTStatus.invalidParameter.rawValue)
        }
        let attributesOnly = try client.create(path: "", desiredAccess: 0x80 /* FILE_READ_ATTRIBUTES */)
        XCTAssertEqual(try client.request(.changeNotify, body: fixture(attributesOnly.fileId)).header.status,
                       NTStatus.accessDenied.rawValue)
        try client.close(fileId: directory.fileId)
        XCTAssertEqual(try client.request(.changeNotify, body: fixture(directory.fileId)).header.status,
                       NTStatus.fileClosed.rawValue)
    }

    func testRemoteCompletionInvalidatesWarmDirectorySnapshot() async throws {
        let engine = MemoryEngine()
        let generation = NotifyWireGeneration()
        let registered = expectation(description: "remote notification baseline registered")
        registered.assertForOverFulfill = false
        engine.changeGenerationHook = { await generation.value }
        engine.changeEnumerationHook = { _ in registered.fulfill() }
        let (server, client) = try connected(engine)
        defer { client.close(); server.stop() }
        let directory = try client.create(path: "")
        let before = try await server.table.children(of: .root)
        XCTAssertTrue(before.isEmpty)
        XCTAssertEqual(try client.request(.changeNotify, body: fixture(directory.fileId)).header.status,
                       NTStatus.pending.rawValue)
        await fulfillment(of: [registered], timeout: 2)
        engine.seed("peer-created.txt", data: Data("new".utf8))
        await generation.advance()
        let completion = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 2000))
        XCTAssertEqual(completion.header.status, NTStatus.notifyEnumDir.rawValue)
        let after = try client.queryDirectory(fileId: directory.fileId, restart: true)
        XCTAssertEqual(after.status, NTStatus.success.rawValue)
        XCTAssertEqual(after.items.map(\.name).filter { $0 != "." && $0 != ".." }, ["peer-created.txt"],
                       "A notification must precede a fresh directory snapshot")
    }
}

private actor NotifyWireGeneration {
    private(set) var value: UInt64 = 0
    func advance() { value += 1 }
}
