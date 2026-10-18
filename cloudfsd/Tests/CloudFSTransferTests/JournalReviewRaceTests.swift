// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import XCTest
import CloudFSCore
@testable import CloudFSTransfer

final class JournalReviewRaceTests: XCTestCase {
    func testFailedClearCannotMergeOldDirtyBlocksIntoANewStagingSession() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-journal-clear-race-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let journal = WriteBackJournal(cacheDir: root.path)
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8,
                                       touched: [0: Data("oldA".utf8), 1: Data("oldB".utf8)])
        let dir = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: root.appendingPathComponent("staging"), includingPropertiesForKeys: nil).first)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path) }
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: dir.path)
        await journal.clear(filespace: "fs", itemID: "file")
        XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appendingPathComponent("meta").path), "fixture must retain failed removal")
        do {
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "2", size: 8,
                                           touched: [1: Data("newB".utf8)])
            XCTFail("new staging must be refused until the old committed record can be safely retired")
        } catch let error as EngineError {
            XCTAssertEqual(error.kind, .syncFailed)
        }
        let oldReplay = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(oldReplay.first?.baseVersion, "1", "restart must retain the old CAS base until a new publication succeeds")
        XCTAssertEqual(oldReplay.first?.blockLengths, [0: 4, 1: 4])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "2", size: 8,
                                       touched: [1: Data("newB".utf8)])
        let replay = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(replay.first?.baseVersion, "2")
        XCTAssertEqual(replay.first?.blockLengths, [1: 4], "a new edit cannot inherit acknowledged-and-cleared prior dirty blocks")
    }
    func testReadersNeverLoseAnAcknowledgedGenerationDuringReplacement() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-journal-read-race-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let journal = WriteBackJournal(cacheDir: root.path)
        let length = 64 * 1024
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: length,
                                       touched: [0: Data(repeating: 1, count: length)])
        let errors = ReviewErrors()
        let readers = (0..<8).map { _ in Task.detached {
            for _ in 0..<2500 {
                do {
                    let bytes = try journal.readBlock(filespace: "fs", itemID: "file", blockIndex: 0)
                    if bytes?.count != length { errors.add("wrong size") }
                } catch { errors.add(String(describing: error)) }
            }
        } }
        for index in 0..<256 {
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: length,
                                           touched: [0: Data(repeating: UInt8(index % 256), count: length)])
        }
        for reader in readers { await reader.value }
        XCTAssertEqual(errors.all(), [])
    }
}
private final class ReviewErrors: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String] = []
    func add(_ value: String) { lock.withLock { values.append(value) } }
    func all() -> [String] { lock.withLock { values } }
}
