// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
@testable import CloudFSTransfer

final class ImmutablePayloadTests: XCTestCase {
    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-exclusive-payload-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root
    }

    func testExclusivePayloadNeverOverwritesOrUnlinksCollisionOrSymlink() throws {
        let root = try directory(), existing = root.appendingPathComponent("existing")
        let original = Data("prior durable bytes".utf8)
        try original.write(to: existing)
        XCTAssertThrowsError(try WriteBackJournal.writeImmutablePayload(Data("replacement".utf8), to: existing))
        XCTAssertEqual(try Data(contentsOf: existing), original)
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: existing)
        XCTAssertThrowsError(try WriteBackJournal.writeImmutablePayload(Data("replacement".utf8), to: link))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: link.path), existing.path)
        XCTAssertEqual(try Data(contentsOf: existing), original)
    }

    func testShortWritesAndEINTRFinishBeforeTheSingleExplicitPayloadSync() throws {
        let root = try directory(), file = root.appendingPathComponent("fresh")
        let expected = Data((0..<65).map { UInt8($0) })
        var calls = 0, syncs = 0
        try WriteBackJournal.writeImmutablePayload(expected, to: file, writeChunk: { fd, bytes, length in
            calls += 1
            if calls == 1 { errno = EINTR; return -1 }
            return write(fd, bytes, min(3, length))
        }, syncFile: { fd in
            syncs += 1
            var status = stat()
            XCTAssertEqual(fstat(fd, &status), 0)
            XCTAssertEqual(status.st_size, Int64(expected.count))
            return fsync(fd)
        })
        XCTAssertEqual(try Data(contentsOf: file), expected)
        XCTAssertEqual(calls, 23); XCTAssertEqual(syncs, 1)
        let permissions = try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(permissions?.intValue, 0o600)
    }

    func testZeroProgressWriteFailsInsteadOfLoopingOrReachingSync() throws {
        let file = try directory().appendingPathComponent("failed")
        var synced = false
        XCTAssertThrowsError(try WriteBackJournal.writeImmutablePayload(Data("data".utf8), to: file,
            writeChunk: { _, _, _ in 0 }, syncFile: { _ in synced = true; return 0 }))
        XCTAssertFalse(synced)
        XCTAssertEqual(try Data(contentsOf: file).count, 0)
    }

    func testPartialWriteAndPayloadSyncFailureLeavePreviousAcknowledgedHeadAndReplayIntact() async throws {
        for mode in [PayloadFailure.Mode.partialWrite, .sync] {
            let root = try directory(), fault = PayloadFailure()
            let journal = WriteBackJournal(cacheDir: root.path, payloadWriter: { try fault.write($0, to: $1) })
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8,
                touched: [0: Data("original".utf8)], baseCaptured: true)
            let entry = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: root.appendingPathComponent("staging"), includingPropertiesForKeys: nil).first)
            let before = try Data(contentsOf: entry.appendingPathComponent("meta"))
            fault.arm(mode)
            do {
                try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8,
                    touched: [0: Data("modified".utf8)], baseCaptured: true)
                XCTFail("payload failure may not be acknowledged")
            } catch let error as EngineError {
                XCTAssertEqual(mode, .partialWrite)
                XCTAssertEqual(error.data?["diskFull"], .bool(true))
            } catch let error as POSIXError {
                XCTAssertEqual(error.code, .EIO)
            }
            XCTAssertEqual(try Data(contentsOf: entry.appendingPathComponent("meta")), before)
            XCTAssertEqual(try journal.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("original".utf8))
            let reopened = WriteBackJournal(cacheDir: root.path)
            let replay = try await reopened.replay()
            XCTAssertEqual(replay.first?.baseVersion, "1")
            XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("original".utf8))
            // Failure happened before head publication; a subsequent fresh UUID
            // payload can safely succeed without inheriting its partial orphan.
            fault.arm(nil)
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8,
                touched: [0: Data("repaired".utf8)], baseCaptured: true)
            let final = WriteBackJournal(cacheDir: root.path)
            _ = try await final.replay()
            XCTAssertEqual(try final.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("repaired".utf8))
        }
    }

    func testLaterStreamingPayloadSyncFailureCannotPublishEarlierReplacementChunks() async throws {
        let root = try directory()
        let original: [Int: Data] = [0: Data("old-head".utf8), 1: Data("old-tail".utf8)]
        let seed = WriteBackJournal(cacheDir: root.path)
        try await seed.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "7", size: 16,
                                    touched: original, baseCaptured: true)
        let entry = try XCTUnwrap(FileManager.default.contentsOfDirectory(
            at: root.appendingPathComponent("staging"), includingPropertiesForKeys: nil).first)
        let head = try Data(contentsOf: entry.appendingPathComponent("meta"))
        let fault = StreamingPayloadFailure()
        let journal = WriteBackJournal(cacheDir: root.path, payloadWriter: { try fault.write($0, to: $1) })
        let replacement = [Data("new-first".utf8), Data("new-second".utf8)]
        let interrupted = PayloadChunks(replacement)
        do {
            _ = try await journal.recordReplaceStreaming(filespace: "fs", itemID: "file", baseVersion: "7",
                                                         nextChunk: { interrupted.next() })
            XCTFail("second payload sync failure must prevent replacement acknowledgement")
        } catch let error as POSIXError {
            XCTAssertEqual(error.code, .EIO)
        }
        XCTAssertEqual(fault.completedPayloads, 1, "the first replacement payload really synchronized")
        XCTAssertEqual(try Data(contentsOf: entry.appendingPathComponent("meta")), head)
        let reopened = WriteBackJournal(cacheDir: root.path)
        let oldEntries = try await reopened.replay()
        XCTAssertEqual(oldEntries.count, 1)
        XCTAssertEqual(oldEntries.first?.size, 16)
        XCTAssertEqual(oldEntries.first?.baseVersion, "7")
        XCTAssertEqual(oldEntries.first?.blockLengths, [0: 8, 1: 8])
        for (index, bytes) in original {
            XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: index), bytes)
        }

        // Payload failure is before publication, so retry on the same journal is
        // safe even while complete and incomplete unreferenced UUID files remain.
        fault.disable()
        let retried = PayloadChunks(replacement)
        let lengths = try await journal.recordReplaceStreaming(filespace: "fs", itemID: "file", baseVersion: "7",
                                                               nextChunk: { retried.next() })
        XCTAssertEqual(lengths, [0: 9, 1: 10])
        let final = WriteBackJournal(cacheDir: root.path)
        let newEntries = try await final.replay()
        XCTAssertEqual(newEntries.first?.size, 19)
        XCTAssertEqual(newEntries.first?.committedLimit, 0)
        XCTAssertEqual(newEntries.first?.blockLengths, lengths)
        for (index, bytes) in replacement.enumerated() {
            XCTAssertEqual(try final.readBlock(filespace: "fs", itemID: "file", blockIndex: index), bytes)
        }
    }
}

private final class PayloadChunks: @unchecked Sendable {
    private let lock = NSLock()
    private let chunks: [Data]
    private var index = 0
    init(_ chunks: [Data]) { self.chunks = chunks }
    func next() -> Data? {
        lock.withLock {
            guard index < chunks.count else { return nil }
            defer { index += 1 }
            return chunks[index]
        }
    }
}

private final class StreamingPayloadFailure: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    private var completed = 0
    private var enabled = true
    var completedPayloads: Int { lock.withLock { completed } }
    func disable() { lock.withLock { enabled = false } }
    func write(_ data: Data, to url: URL) throws {
        let fail = lock.withLock {
            count += 1
            return enabled && count == 2
        }
        if fail {
            try WriteBackJournal.writeImmutablePayload(data, to: url, syncFile: { _ in errno = EIO; return -1 })
        } else {
            try WriteBackJournal.writeImmutablePayload(data, to: url)
        }
        lock.withLock { completed += 1 }
    }
}

private final class PayloadFailure: @unchecked Sendable {
    enum Mode { case partialWrite, sync }
    private let lock = NSLock()
    private var mode: Mode?
    func arm(_ value: Mode?) { lock.withLock { mode = value } }
    func write(_ data: Data, to url: URL) throws {
        switch lock.withLock({ mode }) {
        case .partialWrite:
            var calls = 0
            try WriteBackJournal.writeImmutablePayload(data, to: url, writeChunk: { fd, bytes, count in
                calls += 1
                if calls == 1 { return Darwin.write(fd, bytes, min(3, count)) }
                errno = ENOSPC; return -1
            })
        case .sync:
            try WriteBackJournal.writeImmutablePayload(data, to: url, syncFile: { _ in errno = EIO; return -1 })
        case nil:
            try WriteBackJournal.writeImmutablePayload(data, to: url)
        }
    }
}
