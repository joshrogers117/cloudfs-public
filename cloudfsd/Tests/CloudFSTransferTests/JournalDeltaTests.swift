// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CryptoKit
import CloudFSCore
@testable import CloudFSTransfer

final class JournalDeltaTests: XCTestCase {
    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-delta-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root
    }
    private func entry(_ root: URL) throws -> URL {
        try XCTUnwrap(FileManager.default.contentsOfDirectory(at: root.appendingPathComponent("staging"), includingPropertiesForKeys: nil).first)
    }
    private func head(_ directory: URL) throws -> [String: Any] {
        let envelope = try JSONSerialization.jsonObject(with: Data(contentsOf: directory.appendingPathComponent("meta"))) as! [String: Any]
        return try JSONSerialization.jsonObject(with: Data(base64Encoded: envelope["payload"] as! String)!) as! [String: Any]
    }
    private func put(_ journal: WriteBackJournal, _ index: Int, _ value: String) async throws {
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "7", size: (index + 1) * 4,
                                       touched: [index: Data(value.utf8)], baseCaptured: true)
    }

    func testPublicationFaultsPreserveLastACKAndRefuseAmbiguousContinuation() async throws {
        for phase in [WriteBackJournal.PublicationPhase.logSynced, .headRenamed, .fullSynced] {
            let root = try directory(), fault = DeltaFault()
            let journal = WriteBackJournal(cacheDir: root.path, publicationFault: { try fault.hit($0) })
            try await put(journal, 0, "old!")
            fault.arm(phase)
            do { try await put(journal, 1, "new!"); XCTFail("the fault must prevent a successful ACK") }
            catch is InjectedDeltaFailure {}
            // The prior acknowledged block is still readable in this process.
            XCTAssertEqual(try journal.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("old!".utf8))
            do { try await put(journal, 2, "next"); XCTFail("never append using a possibly stale head") }
            catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
            let reopened = WriteBackJournal(cacheDir: root.path)
            let replay = try await reopened.replay()
            XCTAssertEqual(replay.first?.baseVersion, "7")
            XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("old!".utf8))
            // Rename can have landed even if the caller never received an ACK.
            let expectedCount = phase == .logSynced ? 1 : 2
            XCTAssertEqual(replay.first?.blockLengths.count, expectedCount)
            try await put(reopened, 2, "next")
            let twiceReopened = WriteBackJournal(cacheDir: root.path)
            _ = try await twiceReopened.replay()
            XCTAssertEqual(try twiceReopened.readBlock(filespace: "fs", itemID: "file", blockIndex: 2), Data("next".utf8))
        }
    }

    func testUnacknowledgedTailIsIgnoredThenReplacedWithoutLosingCommittedPrefix() async throws {
        let root = try directory(), journal = WriteBackJournal(cacheDir: root.path)
        try await put(journal, 0, "zero"); try await put(journal, 1, "one!")
        let dir = try entry(root), wal = try XCTUnwrap(head(dir)["wal"] as? [String: Any])
        let log = dir.appendingPathComponent(wal["log"] as! String)
        let file = try FileHandle(forWritingTo: log)
        try file.seekToEnd(); try file.write(contentsOf: Data(repeating: 0xff, count: 900)); try file.close()
        let reopened = WriteBackJournal(cacheDir: root.path)
        let recovered = try await reopened.replay()
        XCTAssertEqual(recovered.first?.blockLengths, [0: 4, 1: 4])
        try await put(reopened, 2, "two!")
        let after = WriteBackJournal(cacheDir: root.path)
        let recoveredAfter = try await after.replay()
        XCTAssertEqual(recoveredAfter.first?.blockLengths, [0: 4, 1: 4, 2: 4])
        for (i, value) in ["zero", "one!", "two!"].enumerated() {
            XCTAssertEqual(try after.readBlock(filespace: "fs", itemID: "file", blockIndex: i), Data(value.utf8))
        }
    }

    func testCommittedLogLossTruncationAndSameLengthCorruptionFailClosed() async throws {
        for damage in 0..<3 {
            let root = try directory(), journal = WriteBackJournal(cacheDir: root.path)
            try await put(journal, 0, "zero"); try await put(journal, 1, "one!")
            let dir = try entry(root), wal = try XCTUnwrap(head(dir)["wal"] as? [String: Any])
            let log = dir.appendingPathComponent(wal["log"] as! String)
            if damage == 0 { try FileManager.default.removeItem(at: log) }
            else {
                var bytes = try Data(contentsOf: log)
                if damage == 1 { bytes.removeLast() } else { bytes[bytes.count / 2] ^= 0x40 }
                try bytes.write(to: log)
            }
            do { _ = try await WriteBackJournal(cacheDir: root.path).replay(); XCTFail("committed metadata may not disappear") }
            catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
            XCTAssertTrue(FileManager.default.fileExists(atPath: dir.appendingPathComponent("meta").path))
        }
    }

    func testCompactionFailureKeepsPreviousCheckpointAndEveryAcknowledgedBlock() async throws {
        let root = try directory(), fault = DeltaFault()
        let journal = WriteBackJournal(cacheDir: root.path, publicationFault: { try fault.hit($0) })
        for index in 0...WriteBackJournal.checkpointInterval { try await put(journal, index, "safe") }
        let dir = try entry(root), before = try Data(contentsOf: dir.appendingPathComponent("meta"))
        fault.arm(.checkpointSynced)
        do { try await put(journal, WriteBackJournal.checkpointInterval + 1, "lost"); XCTFail("no ACK before the new checkpoint head") }
        catch is InjectedDeltaFailure {}
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("meta")), before)
        do { try await put(journal, 999, "next"); XCTFail("failed compaction must poison continuation") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        let reopened = WriteBackJournal(cacheDir: root.path)
        let recovered = try await reopened.replay()
        XCTAssertEqual(recovered.first?.blockLengths.count, WriteBackJournal.checkpointInterval + 1)
        for index in 0...WriteBackJournal.checkpointInterval {
            XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: index), Data("safe".utf8))
        }
        try await put(reopened, WriteBackJournal.checkpointInterval + 1, "good")
        let after = try head(dir), wal = after["wal"] as! [String: Any]
        XCTAssertEqual(wal["sequence"] as? Int, 0)
        XCTAssertEqual(after["blocks"] as? String, "cloudfs-journal-v2")
        let final = WriteBackJournal(cacheDir: root.path)
        let finalEntries = try await final.replay()
        XCTAssertEqual(finalEntries.first?.blockLengths.count, WriteBackJournal.checkpointInterval + 2)
    }

    func testPreviousDecoderRejectsV2EvenWithSameSizeLegacyDataAfterDurablePublication() async throws {
        struct PreviousBlock: Decodable { let file: String; let length: Int; let sha256: String }
        struct PreviousMeta: Decodable {
            let filespace: String; let itemID: String; let baseVersion: String?
            let size: Int?; let committedLimit: Int?; let blocks: [Int: PreviousBlock]?
        }
        struct PreviousEnvelope: Decodable { let payload: Data; let sha256: String }
        let root = try directory(), fault = DeltaFault()
        let journal = WriteBackJournal(cacheDir: root.path, publicationFault: { try fault.hit($0) })
        try await put(journal, 0, "old!")
        let dir = try entry(root)
        try Data("stale!!!".utf8).write(to: dir.appendingPathComponent("data"))
        fault.arm(.fullSynced)
        do { try await put(journal, 1, "new!"); XCTFail("simulate interrupted post-durability cleanup") }
        catch is InjectedDeltaFailure {}
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent("data")).count, 8)
        let disk = try Data(contentsOf: dir.appendingPathComponent("meta"))
        let envelope = try JSONDecoder().decode(PreviousEnvelope.self, from: disk)
        // Match both decoding branches in the previous loadMeta implementation.
        // Neither may reach its nil-blocks + same-size wholeData fallback.
        XCTAssertThrowsError(try JSONDecoder().decode(PreviousMeta.self, from: envelope.payload))
        XCTAssertThrowsError(try JSONDecoder().decode(PreviousMeta.self, from: disk))
        let reopened = WriteBackJournal(cacheDir: root.path)
        let recovered = try await reopened.replay()
        XCTAssertEqual(recovered.first?.blockLengths, [0: 4, 1: 4])
        XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: 1), Data("new!".utf8))
    }

    func testFullMapV1JournalMigratesWithoutLosingItsCASBaseOrSparseBlocks() async throws {
        let root = try directory()
        let slug = Data("fs\u{0}file".utf8).map { String(format: "%02x", $0) }.joined()
        let dir = root.appendingPathComponent("staging").appendingPathComponent(slug)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let bytes = Data("old!".utf8), file = "block-4-legacy"
        try bytes.write(to: dir.appendingPathComponent(file))
        let sha = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        let meta: [String: Any] = ["filespace": "fs", "itemID": "file", "baseVersion": "7", "size": 20,
            "baseCaptured": true, "blocks": ["4": ["file": file, "length": 4, "sha256": sha]]]
        let payload = try JSONSerialization.data(withJSONObject: meta)
        let envelope: [String: Any] = ["payload": payload.base64EncodedString(),
            "sha256": SHA256.hash(data: payload).map { String(format: "%02x", $0) }.joined()]
        try JSONSerialization.data(withJSONObject: envelope).write(to: dir.appendingPathComponent("meta"))
        try Data().write(to: dir.appendingPathComponent("committed"))
        let journal = WriteBackJournal(cacheDir: root.path)
        _ = try await journal.replay()
        try await put(journal, 5, "new!")
        let reopened = WriteBackJournal(cacheDir: root.path), entries = try await reopened.replay()
        XCTAssertEqual(entries.first?.blockLengths, [4: 4, 5: 4]); XCTAssertEqual(entries.first?.baseVersion, "7")
        XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: 4), bytes)
        XCTAssertEqual(try head(dir)["journalFormat"] as? Int, 2)
    }
}

private struct InjectedDeltaFailure: Error {}
private final class DeltaFault: @unchecked Sendable {
    private let lock = NSLock()
    private var phase: WriteBackJournal.PublicationPhase?
    func arm(_ value: WriteBackJournal.PublicationPhase) { lock.withLock { phase = value } }
    func hit(_ value: WriteBackJournal.PublicationPhase) throws {
        if lock.withLock({ phase == value }) { throw InjectedDeltaFailure() }
    }
}
