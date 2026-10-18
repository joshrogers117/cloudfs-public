// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CryptoKit
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import CloudFSTransfer

/// Independent adversarial review of the on-disk durability contract. These tests
/// edit persisted bytes between processes, rather than trusting in-memory state.
final class JournalWALReviewTests: XCTestCase {
    private func temporaryDirectory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-wal-review-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root
    }

    private func entryDirectory(_ root: URL, item: String = "file") throws -> URL {
        let slug = Data("fs\u{0}\(item)".utf8).map { String(format: "%02x", $0) }.joined()
        return root.appendingPathComponent("staging").appendingPathComponent(slug)
    }

    private func head(_ directory: URL) throws -> [String: Any] {
        let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent("meta"))) as? [String: Any])
        let payload = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(envelope["payload"] as? String)))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: payload) as? [String: Any])
    }

    private func metadataFile(_ directory: URL, checkpoint: Bool) throws -> URL {
        let wal = try XCTUnwrap(try head(directory)["wal"] as? [String: Any])
        let name: String
        if checkpoint {
            name = try XCTUnwrap((wal["checkpoint"] as? [String: Any])?["file"] as? String)
        } else { name = try XCTUnwrap(wal["log"] as? String) }
        return directory.appendingPathComponent(name)
    }

    private func seed(_ root: URL, item: InodeID = "file") async throws -> WriteBackJournal {
        let journal = WriteBackJournal(cacheDir: root.path)
        try await journal.recordBlocks(filespace: "fs", itemID: item, baseVersion: "original", size: 8,
            touched: [0: Data("head".utf8), 1: Data("tail".utf8)], baseCaptured: true)
        try await journal.recordBlocks(filespace: "fs", itemID: item, baseVersion: "original", size: 8,
            touched: [0: Data("next".utf8)], baseCaptured: true)
        return journal
    }

    private func assertReplayFails(_ root: URL, file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await WriteBackJournal(cacheDir: root.path).replay()
            XCTFail("Corrupt committed state must fail closed", file: file, line: line)
        } catch let error as EngineError {
            XCTAssertEqual(error.kind, .syncFailed, file: file, line: line)
        } catch { XCTFail("Unexpected error: \(error)", file: file, line: line) }
    }

    func testCommittedCheckpointAndDeltaDamageNeverBecomeAnOlderSuccessfulImage() async throws {
        for checkpoint in [false, true] {
            for damage in ["missing", "truncated", "corrupt"] {
                let root = try temporaryDirectory()
                _ = try await seed(root)
                let directory = try entryDirectory(root)
                let file = try metadataFile(directory, checkpoint: checkpoint)
                var data = try Data(contentsOf: file)
                XCTAssertFalse(data.isEmpty)
                switch damage {
                case "missing": try FileManager.default.removeItem(at: file)
                case "truncated": try data.dropLast().write(to: file)
                default:
                    data[data.startIndex + data.count / 2] ^= 1
                    try data.write(to: file)
                }
                let before = try Data(contentsOf: directory.appendingPathComponent("meta"))
                await assertReplayFails(root)
                XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("meta")), before)
                XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("committed").path))
            }
        }
    }

    func testUnacknowledgedDeltaTailIsIgnoredThenSafelyReplacedByANewCommit() async throws {
        let root = try temporaryDirectory()
        _ = try await seed(root)
        let directory = try entryDirectory(root)
        let file = try metadataFile(directory, checkpoint: false)
        let handle = try FileHandle(forWritingTo: file)
        try handle.seekToEnd(); try handle.write(contentsOf: Data(repeating: 0xff, count: 4096)); try handle.close()
        let reopened = WriteBackJournal(cacheDir: root.path)
        let before = try await reopened.replay()
        XCTAssertEqual(before.first?.size, 8)
        XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("next".utf8))
        try await reopened.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "original", size: 12,
            touched: [2: Data("last".utf8)], baseCaptured: true)
        let verified = WriteBackJournal(cacheDir: root.path)
        let after = try await verified.replay()
        XCTAssertEqual(after.first?.blockLengths, [0: 4, 1: 4, 2: 4])
        XCTAssertEqual(try verified.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("next".utf8))
        XCTAssertEqual(try verified.readBlock(filespace: "fs", itemID: "file", blockIndex: 1), Data("tail".utf8))
        XCTAssertEqual(try verified.readBlock(filespace: "fs", itemID: "file", blockIndex: 2), Data("last".utf8))
    }

    func testMetadataSymlinksAreRejectedEvenWhenTheirTargetBytesMatch() async throws {
        for checkpoint in [false, true] {
            let root = try temporaryDirectory()
            _ = try await seed(root)
            let directory = try entryDirectory(root)
            let file = try metadataFile(directory, checkpoint: checkpoint)
            let outside = root.appendingPathComponent("outside-metadata")
            try FileManager.default.moveItem(at: file, to: outside)
            try FileManager.default.createSymbolicLink(at: file, withDestinationURL: outside)
            await assertReplayFails(root)
            XCTAssertTrue(FileManager.default.fileExists(atPath: outside.path))
        }
    }

    func testAValidDeltaLogFromAnotherFileCannotBeSubstituted() async throws {
        let root = try temporaryDirectory()
        _ = try await seed(root, item: "file")
        _ = try await seed(root, item: "other")
        let directory = try entryDirectory(root)
        let other = try entryDirectory(root, item: "other")
        let destination = try metadataFile(directory, checkpoint: false)
        try Data(contentsOf: metadataFile(other, checkpoint: false)).write(to: destination)
        await assertReplayFails(root)
    }

    func testResealedHeadCannotEscapeTheJournalDirectory() async throws {
        let root = try temporaryDirectory()
        _ = try await seed(root)
        let directory = try entryDirectory(root)
        var body = try head(directory)
        var wal = try XCTUnwrap(body["wal"] as? [String: Any])
        wal["log"] = "delta-../../outside"
        body["wal"] = wal
        let payload = try JSONSerialization.data(withJSONObject: body)
        let checksum = SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()
        let envelope = try JSONSerialization.data(withJSONObject: ["payload": payload.base64EncodedString(), "sha256": checksum])
        try envelope.write(to: directory.appendingPathComponent("meta"))
        await assertReplayFails(root)
    }

    func testOriginalBaseAndTruncateStateSurviveCheckpointRotation() async throws {
        let root = try temporaryDirectory(), journal = WriteBackJournal(cacheDir: root.path)
        let hash = BlockHash(hex: String(repeating: "a", count: 64))
        let original = ResolvedBlockManifest(manifest: BlockManifest(itemID: "file",
            blocks: [BlockRef(hash: hash, offset: 0, length: 8)], contentVersion: "before-team-edit"),
            objectKeys: [hash: "old/object/key"])
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "base", size: 8,
            touched: [0: Data("head".utf8), 1: Data("tail".utf8)], base: original, baseCaptured: true)
        for index in 0..<(WriteBackJournal.checkpointInterval + 3) {
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "base", size: 4,
                committedLimit: 4, touched: [0: Data(repeating: UInt8(index % 256), count: 4)], removed: [1], baseCaptured: true)
        }
        let reopened = WriteBackJournal(cacheDir: root.path)
        let entries = try await reopened.replay()
        let recovered = try XCTUnwrap(entries.first)
        XCTAssertEqual(recovered.baseVersion, "base")
        XCTAssertEqual(recovered.base?.manifest.contentVersion, "before-team-edit")
        XCTAssertEqual(recovered.base?.objectKey(for: hash), "old/object/key")
        XCTAssertEqual(recovered.size, 4)
        XCTAssertEqual(recovered.committedLimit, 4)
        XCTAssertEqual(recovered.blockLengths, [0: 4])
        XCTAssertNil(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: 1))
        let directory = try entryDirectory(root)
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        XCTAssertEqual(names.filter { $0.hasPrefix("map-") }.count, 1)
        XCTAssertEqual(names.filter { $0.hasPrefix("delta-") }.count, 1)
    }
}
