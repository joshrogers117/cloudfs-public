// SPDX-License-Identifier: AGPL-3.0-or-later
// Per-handle READ/WRITE ordering and cross-handle overlap on one connection.
import XCTest
import CloudFSCore
@testable import CloudFSSMB

final class ConcurrencyTests: XCTestCase {
    private func connected(_ engine: MemoryEngine, files: [String], data: Data = Data()) throws -> (SMBServer, SMBTestClient, [SMBFileId]) {
        for f in files { engine.seed(f, data: data) }
        let server = SMBServer(engine: engine, shareName: "cloudfs", credential: (user: "cfs", password: "pw"))
        let client = SMBTestClient(); try client.connect(port: server.start())
        _ = try client.negotiate(); try client.sessionSetup(user: "cfs", password: "pw")
        _ = try client.treeConnect(share: "cloudfs")
        _ = try client.create(path: "", wantAAPL: true)
        return (server, client, try files.map { try client.create(path: $0).fileId })
    }
    private func closeBody(_ f: SMBFileId) -> Data {
        var w = ByteWriter(); w.u16(24); w.u16(0); w.u32(0); w.u64(f.persistent); w.u64(f.volatile); return w.data
    }
    private func readPayload(_ r: SMBTestClient.Response) throws -> Data {
        var b = ByteReader(r.body); _ = try b.u16()
        let off = Int(try b.u8()) - SMB2Header.size; _ = try b.u8()
        let n = Int(try b.u32())
        return r.body.subdata(in: off..<(off + n))
    }
    private let slow = Data(repeating: 0xAA, count: 4096)

    func testWriteReleaseSubmitsEarlierParkedReadBeforeNewReadCanBypass() throws {
        let client = SMBTestClient()
        var frame = ByteWriter(); SMB2Header(command: .write, messageId: 1).encode(into: &frame)
        frame.bytes(client.writeBody(fileId: SMBFileId(persistent: 1, volatile: 1), offset: 0, data: Data([1])))
        let request = try XCTUnwrap(SMBWriteRequest(frame.data))
        let lane = SMBHandleLane(label: "submission-race")
        XCTAssertTrue(lane.enqueue(SMBPendingWrite(requests: [request], bytes: 1, message: frame.data)))
        _ = lane.popFirst()
        let oldRead = lane.beginRead()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let finished = DispatchSemaphore(value: 0), arrived = DispatchSemaphore(value: 0)
        XCTAssertTrue(lane.deferRead(upTo: oldRead.writes) {
            entered.signal()
            _ = release.wait(timeout: .now() + 2)
        })
        DispatchQueue.global().async { _ = lane.endWrite(count: 1); finished.signal() }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        DispatchQueue.global().async {
            let next = lane.beginRead()
            lane.endRead(next.id)
            arrived.signal()
        }
        let bypass = arrived.wait(timeout: .now() + .milliseconds(100))
        release.signal()
        XCTAssertEqual(finished.wait(timeout: .now() + 2), .success)
        if bypass != .success { XCTAssertEqual(arrived.wait(timeout: .now() + 2), .success) }
        lane.endRead(oldRead.id)
        XCTAssertEqual(bypass, .timedOut, "Later reads must not fill all workers before an earlier parked read is submitted")
    }

    func testSlowWriteOnOneHandleDoesNotDelayReadOnAnother() throws {
        let engine = MemoryEngine()
        engine.beforeWrite = { [slow] _, data in if data == slow { try await Task.sleep(nanoseconds: 600_000_000) } }
        let (server, client, ids) = try connected(engine, files: ["a", "b"], data: Data("bee".utf8))
        defer { server.stop(); client.close() }
        let start = Date()
        let sent = try client.sendPipeline([(.write, client.writeBody(fileId: ids[0], offset: 0, data: slow)),
                                            (.read, client.readBody(fileId: ids[1], offset: 0, length: 3))])
        let first = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
        XCTAssertEqual(first.header.messageId, sent[1], "read on B must answer before the slow write on A")
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.4)
        XCTAssertEqual(try readPayload(first), Data("bee".utf8))
        let second = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
        XCTAssertEqual(second.header.messageId, sent[0]); XCTAssertEqual(second.header.status, NTStatus.success.rawValue)
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start), 0.55)
    }

    func testReadPipelinedBehindWriteOnSameHandleSeesWrittenBytes() throws {
        let engine = MemoryEngine()
        engine.beforeWrite = { [slow] _, data in if data == slow { try await Task.sleep(nanoseconds: 300_000_000) } }
        let (server, client, ids) = try connected(engine, files: ["a"])
        defer { server.stop(); client.close() }
        let sent = try client.sendPipeline([(.write, client.writeBody(fileId: ids[0], offset: 0, data: slow)),
                                            (.read, client.readBody(fileId: ids[0], offset: 0, length: 4096))])
        var byId: [UInt64: SMBTestClient.Response] = [:]
        for _ in 0..<2 { let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000)); byId[r.header.messageId] = r }
        XCTAssertEqual(byId[sent[0]]?.header.status, NTStatus.success.rawValue)
        XCTAssertEqual(try readPayload(try XCTUnwrap(byId[sent[1]])), slow)
    }

    func testWritesOnSameHandleStayOrderedAndContiguousOnesCoalesce() throws {
        let engine = MemoryEngine(), rec = Recorder()
        engine.beforeWrite = { off, data in rec.add(off, data.count) }
        let (server, client, ids) = try connected(engine, files: ["a"])
        defer { server.stop(); client.close() }
        // Contiguous pipelined writes: one engine call. Then a gap: a second, later call.
        let cmds: [(SMB2Command, Data)] = [
            (.write, client.writeBody(fileId: ids[0], offset: 0, data: Data(repeating: 1, count: 4096))),
            (.write, client.writeBody(fileId: ids[0], offset: 4096, data: Data(repeating: 2, count: 4096))),
            (.write, client.writeBody(fileId: ids[0], offset: 100_000, data: Data(repeating: 3, count: 10)))]
        let sent = try client.sendPipeline(cmds)
        var seen: [UInt64] = []
        for _ in 0..<3 {
            let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
            XCTAssertEqual(r.header.status, NTStatus.success.rawValue); seen.append(r.header.messageId)
        }
        XCTAssertEqual(seen, sent, "responses of one handle's writes complete in order")
        let calls = rec.calls()
        XCTAssertEqual(calls.map(\.0), calls.map(\.0).sorted())
        XCTAssertEqual(calls.first?.0, 0)
        XCTAssertEqual(calls.last?.0, 100_000)
        XCTAssertEqual(calls.reduce(0) { $0 + $1.1 }, 8192 + 10)
        XCTAssertLessThan(calls.count, 3, "contiguous pipelined writes still coalesce")
    }

    func testCloseAfterPendingWriteWaitsAndWriteIsAcknowledged() throws {
        let engine = MemoryEngine()
        engine.beforeWrite = { [slow] _, data in if data == slow { try await Task.sleep(nanoseconds: 400_000_000) } }
        let (server, client, ids) = try connected(engine, files: ["a"])
        defer { server.stop(); client.close() }
        let sent = try client.sendPipeline([(.write, client.writeBody(fileId: ids[0], offset: 0, data: slow)),
                                            (.close, closeBody(ids[0]))])
        let r1 = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
        let r2 = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
        XCTAssertEqual([r1.header.messageId, r2.header.messageId], sent)
        XCTAssertEqual(r1.header.status, NTStatus.success.rawValue)
        XCTAssertEqual(r2.header.status, NTStatus.success.rawValue)
        XCTAssertEqual(engine.contents.values.first { $0 == slow }, slow)
    }

    func testSetInfoWaitsForInFlightWriteAndRead() throws {
        let engine = MemoryEngine()
        engine.readDelayNs = 200_000_000
        engine.beforeWrite = { [slow] _, data in if data == slow { try await Task.sleep(nanoseconds: 300_000_000) } }
        let (server, client, ids) = try connected(engine, files: ["a", "b"], data: Data("x".utf8))
        defer { server.stop(); client.close() }
        var eof = ByteWriter(); eof.u64(5)
        var info = ByteWriter()
        info.u16(33); info.u8(1); info.u8(20); info.u32(8); info.u16(UInt16(SMB2Header.size + 32)); info.u16(0); info.u32(0)
        info.u64(ids[0].persistent); info.u64(ids[0].volatile); info.bytes(eof.data)
        let sent = try client.sendPipeline([(.write, client.writeBody(fileId: ids[0], offset: 0, data: slow)),
                                            (.read, client.readBody(fileId: ids[1], offset: 0, length: 1)),
                                            (.setInfo, info.data)])
        var order: [UInt64] = []
        for _ in 0..<3 { order.append(try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000)).header.messageId) }
        XCTAssertEqual(order.last, sent[2], "SET_INFO answers only after the write and the read")
        let id = engine.items.values.first { $0.name == "a" }!.id
        XCTAssertEqual(engine.contents[id]?.count, 5, "truncate ran after the write, not before it")
    }

    func testFailedWriteBatchFailsEveryRequest() throws {
        let engine = MemoryEngine()
        engine.beforeWrite = { _, _ in throw EngineError(.syncFailed, "injected") }
        let (server, client, ids) = try connected(engine, files: ["a", "b"])
        defer { server.stop(); client.close() }
        let sent = try client.sendPipeline((0..<4).map { (.write, client.writeBody(fileId: ids[0],
            offset: UInt64($0 * 512), data: Data(repeating: 9, count: 512))) } +
            [(.write, client.writeBody(fileId: ids[1], offset: 0, data: Data(repeating: 9, count: 512)))])
        var got = Set<UInt64>()
        for _ in 0..<5 {
            let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
            XCTAssertNotEqual(r.header.status, NTStatus.success.rawValue); got.insert(r.header.messageId)
        }
        XCTAssertEqual(got, Set(sent))
        XCTAssertTrue(engine.contents.values.allSatisfy { $0.isEmpty })
    }

    func testEightReadsOnDistinctHandlesRunConcurrently() throws {
        let engine = MemoryEngine()
        engine.readDelayNs = 300_000_000
        let names = (0..<8).map { "f\($0)" }
        let (server, client, ids) = try connected(engine, files: names, data: Data(repeating: 1, count: 64))
        defer { server.stop(); client.close() }
        let start = Date()
        _ = try client.sendPipeline(ids.map { (.read, client.readBody(fileId: $0, offset: 0, length: 64)) })
        for _ in 0..<8 { XCTAssertEqual(try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000)).header.status, NTStatus.success.rawValue) }
        XCTAssertLessThan(Date().timeIntervalSince(start), 0.55, "8 slots: one latency, not two")
        XCTAssertEqual(engine.readConcurrency.peak, 8)
    }

    func testBackloggedWriterNeverStallsReadsOnAnotherHandle() throws {
        let engine = MemoryEngine()
        engine.readDelayNs = 100_000_000
        engine.beforeWrite = { _, _ in try await Task.sleep(nanoseconds: 400_000_000) }
        let (server, client, ids) = try connected(engine, files: ["a", "b"], data: Data(repeating: 5, count: 64))
        defer { server.stop(); client.close() }
        // 12 non-contiguous (so never coalesced) batches outstanding on A: 4.8 s of backlog.
        let writes = try client.sendPipeline((0..<12).map { (.write, client.writeBody(fileId: ids[0],
            offset: UInt64($0 * 8192), data: Data(repeating: 1, count: 512))) })
        var pendingWrites = Set(writes)
        for _ in 0..<5 {
            let started = Date()
            let rid = try client.sendOnly(.read, body: client.readBody(fileId: ids[1], offset: 0, length: 64))
            while true {
                let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
                if r.header.messageId == rid {
                    XCTAssertEqual(r.header.status, NTStatus.success.rawValue); break
                }
                pendingWrites.remove(r.header.messageId)
            }
            XCTAssertLessThan(Date().timeIntervalSince(started), 0.25, "read must take ~read latency, not a write commit")
        }
        XCTAssertGreaterThanOrEqual(pendingWrites.count, 8, "writes were still backlogged while reads completed")
        while !pendingWrites.isEmpty {
            let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 5000))
            XCTAssertEqual(r.header.status, NTStatus.success.rawValue); pendingWrites.remove(r.header.messageId)
        }
    }

    func testTwoHandlesOnOneFileSerializeWritesAndSeeEachOthersBytes() throws {
        let engine = MemoryEngine(), calls = Recorder()
        let firstCall = Flag()
        engine.beforeWrite = { off, data in
            calls.add(off, data.count)
            if firstCall.take() { try await Task.sleep(nanoseconds: 150_000_000) }
        }
        let (server, client, _) = try connected(engine, files: ["f"])
        defer { server.stop(); client.close() }
        let a = try client.create(path: "f").fileId, b = try client.create(path: "f").fileId
        XCTAssertNotEqual(a, b)
        let chunk = { (v: UInt8) in Data(repeating: v, count: 4096) }
        let sent = try client.sendPipeline([
            (.write, client.writeBody(fileId: a, offset: 0, data: chunk(1))),
            (.write, client.writeBody(fileId: b, offset: 4096, data: chunk(2))),
            (.write, client.writeBody(fileId: a, offset: 8192, data: chunk(3))),
            (.write, client.writeBody(fileId: b, offset: 12288, data: chunk(4)))])
        var order: [UInt64] = []
        for _ in 0..<4 {
            let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
            XCTAssertEqual(r.header.status, NTStatus.success.rawValue); order.append(r.header.messageId)
        }
        XCTAssertEqual(order, sent, "all writes to one file serialize across handles")
        XCTAssertEqual(calls.calls().map(\.0), [0, 4096, 8192, 12288])
        var expected = Data(); for v in 1...4 { expected.append(chunk(UInt8(v))) }
        for h in [a, b] {
            let r = try client.read(fileId: h, offset: 0, length: 16384)
            XCTAssertEqual(r.data, expected, "both handles observe all bytes")
        }
        XCTAssertEqual(try client.create(path: "f").size, 16384, "cached size never regresses")
    }

    func testReadsParkedBehindSlowWriteDoNotExhaustSlotsForOtherFiles() throws {
        let engine = MemoryEngine()
        engine.readDelayNs = 50_000_000
        engine.beforeWrite = { [slow] _, data in if data == slow { try await Task.sleep(nanoseconds: 700_000_000) } }
        let (server, client, ids) = try connected(engine, files: ["a", "b"], data: Data(repeating: 5, count: 64))
        defer { server.stop(); client.close() }
        let start = Date()
        var cmds: [(SMB2Command, Data)] = [(.write, client.writeBody(fileId: ids[0], offset: 0, data: slow))]
        for _ in 0..<10 { cmds.append((.read, client.readBody(fileId: ids[0], offset: 0, length: 16))) }
        for _ in 0..<3 { cmds.append((.read, client.readBody(fileId: ids[1], offset: 0, length: 16))) }
        let sent = try client.sendPipeline(cmds)
        let bIds = Set(sent.suffix(3)), aIds = Set(sent.dropLast(3))
        var done: [UInt64: TimeInterval] = [:]
        for _ in 0..<sent.count {
            let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 5000))
            XCTAssertEqual(r.header.status, NTStatus.success.rawValue)
            done[r.header.messageId] = Date().timeIntervalSince(start)
        }
        for id in bIds { XCTAssertLessThan(try XCTUnwrap(done[id]), 0.35, "other file's reads flow") }
        for id in aIds { XCTAssertGreaterThanOrEqual(try XCTUnwrap(done[id]), 0.65, "same-file reads wait for the write") }
    }

    func testFramesArrivingDuringLaneWriteCoalesceIntoNextEngineCall() throws {
        let engine = MemoryEngine(), calls = Recorder(), first = Flag()
        engine.beforeWrite = { off, data in
            calls.add(off, data.count)
            if first.take() { try await Task.sleep(nanoseconds: 400_000_000) }
        }
        let (server, client, ids) = try connected(engine, files: ["a"])
        defer { server.stop(); client.close() }
        var sent = [try client.sendOnly(.write, body: client.writeBody(fileId: ids[0], offset: 0, data: Data(repeating: 1, count: 4096)))]
        Thread.sleep(forTimeInterval: 0.1)
        for i in 1...6 {   // separate frames, spaced so the loop cannot batch them itself
            sent.append(try client.sendOnly(.write, body: client.writeBody(fileId: ids[0],
                offset: UInt64(i * 4096), data: Data(repeating: UInt8(i + 1), count: 4096))))
            Thread.sleep(forTimeInterval: 0.02)
        }
        var seen: [UInt64] = []
        for _ in 0..<7 {
            let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 3000))
            XCTAssertEqual(r.header.status, NTStatus.success.rawValue); seen.append(r.header.messageId)
        }
        XCTAssertEqual(seen, sent)
        let c = calls.calls()
        XCTAssertEqual(c.count, 2, "6 queued frames became one durable call: \(c)")
        XCTAssertEqual(c.last?.0, 4096); XCTAssertEqual(c.last?.1, 6 * 4096)
    }

    func testManyParkedReadsNeitherStarveThreadsNorExceedReadSlots() throws {
        let engine = MemoryEngine()
        engine.readDelayNs = 30_000_000
        engine.beforeWrite = { [slow] _, data in if data == slow { try await Task.sleep(nanoseconds: 500_000_000) } }
        let (server, client, ids) = try connected(engine, files: ["a", "b"], data: Data(repeating: 5, count: 64))
        defer { server.stop(); client.close() }
        let start = Date()
        var cmds: [(SMB2Command, Data)] = [(.write, client.writeBody(fileId: ids[0], offset: 0, data: slow))]
        for _ in 0..<64 { cmds.append((.read, client.readBody(fileId: ids[0], offset: 0, length: 16))) }
        for _ in 0..<3 { cmds.append((.read, client.readBody(fileId: ids[1], offset: 0, length: 16))) }
        let sent = try client.sendPipeline(cmds)
        let bIds = Set(sent.suffix(3))
        var done: [UInt64: TimeInterval] = [:]
        for _ in 0..<sent.count {
            let r = try XCTUnwrap(client.readAsyncResponse(timeoutMs: 8000), "connection must not hang")
            XCTAssertEqual(r.header.status, NTStatus.success.rawValue)
            done[r.header.messageId] = Date().timeIntervalSince(start)
        }
        for id in bIds { XCTAssertLessThan(try XCTUnwrap(done[id]), 0.3, "frame loop and other files unaffected") }
        XCTAssertLessThanOrEqual(engine.readConcurrency.peak, SMBLimits.readSlots)
        XCTAssertGreaterThan(engine.readConcurrency.peak, 1)
    }

    func testTruncateViaOneHandleLowersSiblingEOF() throws {
        let engine = MemoryEngine()
        let (server, client, _) = try connected(engine, files: ["f"])
        defer { server.stop(); client.close() }
        let a = try client.create(path: "f").fileId, b = try client.create(path: "f").fileId
        XCTAssertEqual(try client.write(fileId: a, offset: 0, data: Data(repeating: 7, count: 8192)).status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: a, offset: 4096, length: 4096).data.count, 4096)
        XCTAssertEqual(try client.setEndOfFile(fileId: b, size: 100), NTStatus.success.rawValue)
        let past = try client.read(fileId: a, offset: 4096, length: 4096)
        XCTAssertEqual(past.status, NTStatus.endOfFile.rawValue, "A must see the new EOF")
        XCTAssertEqual(try client.read(fileId: a, offset: 0, length: 4096).data.count, 100)
    }
}

private final class Flag: @unchecked Sendable {
    private let lock = NSLock(); private var fired = false
    func take() -> Bool { lock.withLock { defer { fired = true }; return !fired } }
}

private final class Recorder: @unchecked Sendable {
    private let lock = NSLock(); private var v: [(Int, Int)] = []
    func add(_ o: Int, _ n: Int) { lock.withLock { v.append((o, n)) } }
    func calls() -> [(Int, Int)] { lock.withLock { v } }
}
