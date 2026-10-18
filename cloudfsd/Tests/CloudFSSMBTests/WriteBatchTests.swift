// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSTransfer
@testable import CloudFSSMB

final class WriteBatchTests: XCTestCase {
    private func connected(_ engine: MemoryEngine) throws -> (SMBServer, SMBTestClient, SMBFileId) {
        engine.seed("batch", data: Data())
        let server = SMBServer(engine: engine, shareName: "cloudfs", credential: (user: "cfs", password: "pw"))
        let client = SMBTestClient(); try client.connect(port: server.start())
        _ = try client.negotiate(); try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "cloudfs")
        let file = try client.create(path: "batch")
        return (server, client, file.fileId)
    }

    func testPipelineHasNoSuccessResponseBeforeSharedDurabilityAndCloseStaysOrdered() async throws {
        let engine = MemoryEngine(), entered = expectation(description: "durability entered"), gate = WriteGate()
        engine.beforeWrite = { _, data in entered.fulfill(); await gate.wait(bytes: data.count) }
        let (server, client, file) = try connected(engine)
        defer { server.stop(); client.close(); Task { await gate.release() } }
        let chunks = (0..<8).map { Data(repeating: UInt8($0 + 1), count: 4096) }
        var close = ByteWriter(); close.u16(24); close.u16(0); close.u32(0)
        close.u64(file.persistent); close.u64(file.volatile)
        let commands: [(SMB2Command, Data)] = chunks.enumerated().map { (.write, client.writeBody(fileId: file, offset: UInt64($0.offset * 4096), data: $0.element)) }
        let ids = try client.sendPipeline(commands + [(SMB2Command.close, close.data)])
        await fulfillment(of: [entered], timeout: 2)
        XCTAssertNil(client.readAsyncResponse(timeoutMs: 30), "neither WRITE nor later CLOSE may acknowledge ahead of durability")
        await gate.release()
        for (index, id) in ids.enumerated() {
            let reply = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 2000))
            XCTAssertEqual(reply.header.messageId, id); XCTAssertEqual(reply.header.status, NTStatus.success.rawValue)
            if index < chunks.count {
                var body = ByteReader(reply.body); _ = try body.u16(); _ = try body.u16()
                XCTAssertEqual(try body.u32(), 4096, "each response reports its original request's count")
            }
        }
        let writeSizes = await gate.sizes()
        XCTAssertEqual(writeSizes, [8 * 4096], "the pipeline must share one existing durable engine call")
        let reopened = try client.create(path: "batch")
        let actual = try client.read(fileId: reopened.fileId, offset: 0, length: 8 * 4096)
        XCTAssertEqual(actual.data, chunks.reduce(into: Data()) { $0.append($1) })
    }

    func testFailedSharedWriteReturnsOnlyFailuresAndPreservesOriginalBytes() throws {
        let engine = MemoryEngine()
        engine.beforeWrite = { _, _ in throw EngineError(.syncFailed, "injected disk barrier failure") }
        let (server, client, file) = try connected(engine)
        defer { server.stop(); client.close() }
        let ids = try client.sendPipeline((0..<8).map { (.write, client.writeBody(fileId: file,
            offset: UInt64($0 * 4096), data: Data(repeating: 7, count: 4096))) })
        for id in ids {
            let response = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 2000))
            XCTAssertEqual(response.header.messageId, id)
            XCTAssertNotEqual(response.header.status, NTStatus.success.rawValue)
        }
        let read = try client.read(fileId: file, offset: 0, length: 1)
        XCTAssertTrue(read.data.isEmpty)
    }

    func testOverlappingWritesAndFlagChangesRemainSeparateAndOrdered() throws {
        let engine = MemoryEngine(), recorder = BatchRecorder()
        engine.beforeWrite = { offset, data in recorder.record(offset, data) }
        let (server, client, file) = try connected(engine)
        defer { server.stop(); client.close() }
        let commands: [(SMB2Command, Data)] = [
            (.write, client.writeBody(fileId: file, offset: 0, data: Data("aaaa".utf8))),
            (.write, client.writeBody(fileId: file, offset: 2, data: Data("bb".utf8))),
            (.write, client.writeBody(fileId: file, offset: 4, data: Data("cc".utf8), flags: 1)),
            (.write, client.writeBody(fileId: file, offset: 6, data: Data("dd".utf8))) ]
        for id in try client.sendPipeline(commands) {
            let response = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 2000))
            XCTAssertEqual(response.header.messageId, id); XCTAssertEqual(response.header.status, NTStatus.success.rawValue)
        }
        XCTAssertEqual(recorder.offsets(), [0, 2, 4, 6])
        XCTAssertEqual(try client.read(fileId: file, offset: 0, length: 8).data, Data("aabbccdd".utf8))
    }

    func testPartialNextFrameDoesNotWaitForCreditOrDiscardItsBytes() throws {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[0]); close(pair[1]) }
        let reader = SMBFrameReader(fd: pair[0]), payload = Data(repeating: 9, count: 4096)
        var frame = DirectTCP.frame(length: payload.count); frame.append(payload)
        _ = frame.prefix(17).withUnsafeBytes { write(pair[1], $0.baseAddress!, $0.count) }
        let start = Date()
        XCTAssertNil(reader.next(blocking: false))
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.1, "partial successor must not hold prior ACK hostage")
        _ = frame.dropFirst(17).withUnsafeBytes { write(pair[1], $0.baseAddress!, $0.count) }
        XCTAssertEqual(reader.next(blocking: true), payload)
        XCTAssertNil(reader.next(blocking: false), "a one-request client needs no successor before receiving its ACK")
    }

    func testSuccessfulBatchACKsReplayFromRealJournalAfterConnectionCloses() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("smb-durable-batch-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let journal = WriteBackJournal(cacheDir: root.path), engine = MemoryEngine()
        engine.beforeWrite = { offset, bytes in
            // The fixture's aligned writes map to immutable 4 KiB journal blocks.
            var touched: [Int: Data] = [:]
            for start in stride(from: 0, to: bytes.count, by: 4096) {
                touched[(offset + start) / 4096] = bytes.subdata(in: start..<(start + 4096))
            }
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "9",
                size: offset + bytes.count, touched: touched, baseCaptured: true)
        }
        let (server, client, file) = try connected(engine)
        defer { server.stop(); client.close() }
        let ids = try client.sendPipeline((0..<8).map { (.write, client.writeBody(fileId: file,
            offset: UInt64($0 * 4096), data: Data(repeating: UInt8($0 + 1), count: 4096))) })
        for id in ids {
            let response = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 2000))
            XCTAssertEqual(response.header.messageId, id); XCTAssertEqual(response.header.status, NTStatus.success.rawValue)
        }
        client.close(); server.stop()
        let reopened = WriteBackJournal(cacheDir: root.path), entries = try await reopened.replay()
        XCTAssertEqual(entries.first?.baseVersion, "9"); XCTAssertEqual(entries.first?.size, 8 * 4096)
        for index in 0..<8 {
            XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: index),
                           Data(repeating: UInt8(index + 1), count: 4096))
        }
    }

    func testBatchEligibilityPreservesIdentityAndEnforcesCombinedMemoryBound() throws {
        let client = SMBTestClient(), file = SMBFileId(persistent: 1, volatile: 2)
        func packet(offset: UInt64, bytes: Int, header: SMB2Header = SMB2Header(command: .write, messageId: 1)) -> Data {
            var w = ByteWriter(); header.encode(into: &w)
            w.bytes(client.writeBody(fileId: file, offset: offset, data: Data(repeating: 1, count: bytes)))
            return w.data
        }
        let first = try XCTUnwrap(SMBWriteRequest(packet(offset: 0, bytes: 4 << 20)))
        let second = try XCTUnwrap(SMBWriteRequest(packet(offset: 4 << 20, bytes: 4 << 20)))
        XCTAssertTrue(second.follows(first, bytes: 4 << 20))
        let over = try XCTUnwrap(SMBWriteRequest(packet(offset: 8 << 20, bytes: 1)))
        XCTAssertFalse(over.follows(first, bytes: 8 << 20))
        XCTAssertNil(SMBWriteRequest(packet(offset: UInt64.max, bytes: 1)))
        XCTAssertNil(SMBWriteRequest(packet(offset: 0, bytes: 1,
            header: SMB2Header(command: .write, messageId: 2, flags: [.relatedOps]))))
        let otherSession = try XCTUnwrap(SMBWriteRequest(packet(offset: 4 << 20, bytes: 1,
            header: SMB2Header(command: .write, messageId: 2, sessionId: 123))))
        XCTAssertFalse(otherSession.follows(first, bytes: 4 << 20))
        var badOffset = packet(offset: 0, bytes: 1)
        badOffset[SMB2Header.size + 2] = 0; badOffset[SMB2Header.size + 3] = 0
        XCTAssertNil(SMBWriteRequest(badOffset), "header bytes are not a writable payload")
    }
}

private actor WriteGate {
    private var continuation: CheckedContinuation<Void, Never>?
    private var released = false
    private var writes: [Int] = []
    func wait(bytes: Int) async { writes.append(bytes); if !released { await withCheckedContinuation { continuation = $0 } } }
    func release() { released = true; continuation?.resume(); continuation = nil }
    func sizes() -> [Int] { writes }
}
private final class BatchRecorder: @unchecked Sendable {
    private let lock = NSLock(); private var values: [Int] = []
    func record(_ offset: Int, _ data: Data) { lock.withLock { values.append(offset) } }
    func offsets() -> [Int] { lock.withLock { values } }
}
