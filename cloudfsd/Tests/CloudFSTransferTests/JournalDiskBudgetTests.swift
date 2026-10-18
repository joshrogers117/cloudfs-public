// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import CloudFSTransfer

final class JournalDiskBudgetTests: XCTestCase {
    private func root() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("journal-budget-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }
    private func assertFull(_ body: () throws -> Void) {
        XCTAssertThrowsError(try body()) { error in
            XCTAssertEqual((error as? EngineError)?.data?["diskFull"], .bool(true))
        }
    }
    func testSharedReservationsIncludeDisconnectedJournalsAndReplacementPeak() throws {
        let root = try root()
        let old = root.appendingPathComponent("old/staging/item")
        try FileManager.default.createDirectory(at: old, withIntermediateDirectories: true)
        let payload = old.appendingPathComponent("block-0")
        try Data(repeating: 1, count: 8192).write(to: payload)
        let initial = try JournalDiskBudget(cacheRoot: root, availableBytes: { _ in Int.max }).snapshot().usedBytes
        let budget = JournalDiskBudget(cacheRoot: root, limitBytes: initial + 8192,
            freeSpaceReserveBytes: 0, availableBytes: { _ in Int.max })
        XCTAssertEqual(try budget.snapshot().usedBytes, initial)
        assertFull { try budget.write(to: payload, length: 8192, replacing: true) { XCTFail("must reserve old + replacement") } }
        let a = root.appendingPathComponent("a")
        let b = root.appendingPathComponent("b")
        try budget.write(to: a, length: 4096) {
            assertFull { try budget.write(to: b, length: 4096) { XCTFail("shared reservation bypassed") } }
            try Data(repeating: 2, count: 4096).write(to: a)
        }
        XCTAssertEqual(try budget.snapshot().reservedBytes, 0)
        XCTAssertEqual(try budget.snapshot().usedBytes, initial + 4096)
    }
    func testFreeSpaceReserveAndShortWriteAccounting() throws {
        let root = try root()
        let denied = JournalDiskBudget(cacheRoot: root, limitBytes: 1 << 20,
            freeSpaceReserveBytes: 8192, availableBytes: { _ in 10_000 })
        assertFull { try denied.write(to: root.appendingPathComponent("x"), length: 4096) { XCTFail() } }
        let budget = JournalDiskBudget(cacheRoot: root, limitBytes: 16384,
            freeSpaceReserveBytes: 0, availableBytes: { _ in Int.max })
        let partial = root.appendingPathComponent("partial")
        XCTAssertThrowsError(try budget.write(to: partial, length: 8192) {
            try Data(repeating: 1, count: 1).write(to: partial)
            throw POSIXError(.ENOSPC)
        })
        XCTAssertEqual(try budget.snapshot().usedBytes, 4096)
        XCTAssertEqual(try budget.snapshot().reservedBytes, 0)
        try FileManager.default.removeItem(at: partial); budget.removed(partial)
        XCTAssertEqual(try budget.snapshot().usedBytes, 0)
    }
    func testRejectedReplacementPreservesAcknowledgedBytesAcrossRestart() async throws {
        let root = try root(), cache = root.appendingPathComponent("fs")
        let budget = JournalDiskBudget(cacheRoot: root, limitBytes: 128 << 10,
            freeSpaceReserveBytes: 0, availableBytes: { _ in Int.max })
        let journal = WriteBackJournal(cacheDir: cache.path, diskBudget: budget)
        let id = InodeID("file")
        try await journal.recordReplace(filespace: "fs", itemID: id, baseVersion: nil,
                                        size: 4096, blocks: [0: Data(repeating: 7, count: 4096)])
        let before = try budget.snapshot().usedBytes
        do {
            try await journal.recordReplace(filespace: "fs", itemID: id, baseVersion: nil,
                size: 256 << 10, blocks: [0: Data(repeating: 8, count: 256 << 10)])
            XCTFail("over-budget write acknowledged")
        } catch { XCTAssertEqual((error as? EngineError)?.data?["diskFull"], .bool(true)) }
        XCTAssertEqual(try budget.snapshot().usedBytes, before)
        let reopened = WriteBackJournal(cacheDir: cache.path, diskBudget: budget)
        let entries = try await reopened.replay()
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: id, blockIndex: 0), Data(repeating: 7, count: 4096))
        await journal.clear(filespace: "fs", itemID: id)
        XCTAssertLessThan(try budget.snapshot().usedBytes, before)
    }
    func testMetadataAdmissionFailureKeepsOldHeadAndAllowsRetryAfterSpaceIsFreed() async throws {
        let root = try root(), cache = root.appendingPathComponent("fs")
        let original = WriteBackJournal(cacheDir: cache.path)
        let id = InodeID("file")
        try await original.recordReplace(filespace: "fs", itemID: id, baseVersion: nil,
            size: 4096, blocks: [0: Data(repeating: 7, count: 4096)])
        let otherCache = root.appendingPathComponent("other")
        let otherOriginal = WriteBackJournal(cacheDir: otherCache.path)
        try await otherOriginal.recordReplace(filespace: "other", itemID: id, baseVersion: nil,
            size: 65536, blocks: [0: Data(repeating: 1, count: 65536)])
        let baseline = try JournalDiskBudget(cacheRoot: root).snapshot().usedBytes
        let budget = JournalDiskBudget(cacheRoot: root, limitBytes: baseline + 8192,
            freeSpaceReserveBytes: 0, availableBytes: { _ in Int.max })
        let journal = WriteBackJournal(cacheDir: cache.path, diskBudget: budget)
        do {
            try await journal.recordBlocks(filespace: "fs", itemID: id, baseVersion: nil,
                size: 8192, touched: [1: Data(repeating: 8, count: 4096)])
            XCTFail("temporary metadata overhead must be reserved")
        } catch { XCTAssertEqual((error as? EngineError)?.data?["diskFull"], .bool(true)) }
        XCTAssertEqual(try journal.readBlock(filespace: "fs", itemID: id, blockIndex: 0), Data(repeating: 7, count: 4096))
        XCTAssertNil(try journal.readBlock(filespace: "fs", itemID: id, blockIndex: 1))
        // Another filespace completes its remote commit and retires its journal.
        let other = WriteBackJournal(cacheDir: otherCache.path, diskBudget: budget)
        await other.clear(filespace: "other", itemID: id)
        XCTAssertLessThan(try budget.snapshot().usedBytes, baseline)
        do { try await journal.recordBlocks(filespace: "fs", itemID: id, baseVersion: nil, size: 0, touched: [:], removed: [0]) }
        catch { XCTFail("retry failed after freeing capacity: \(error)") }
        XCTAssertNil(try journal.readBlock(filespace: "fs", itemID: id, blockIndex: 0))
    }
    func testConcurrentFilespacesCannotMultiplyBudget() async throws {
        let root = try root()
        let budget = JournalDiskBudget(cacheRoot: root, limitBytes: 100 << 10,
            freeSpaceReserveBytes: 0, availableBytes: { _ in Int.max })
        let journals = (0..<4).map { WriteBackJournal(cacheDir: root.appendingPathComponent("fs\($0)").path, diskBudget: budget) }
        let successes = await withTaskGroup(of: Bool.self) { group in
            for (i, journal) in journals.enumerated() {
                group.addTask {
                    do {
                        try await journal.recordReplace(filespace: "fs\(i)", itemID: InodeID("x"), baseVersion: nil,
                            size: 64 << 10, blocks: [0: Data(repeating: UInt8(i), count: 64 << 10)])
                        return true
                    } catch { return false }
                }
            }
            var count = 0
            for await succeeded in group { if succeeded { count += 1 } }
            return count
        }
        XCTAssertLessThanOrEqual(successes, 1)
        XCTAssertLessThanOrEqual(try budget.snapshot().usedBytes, 100 << 10)
        XCTAssertEqual(try budget.snapshot().reservedBytes, 0)
    }
}
