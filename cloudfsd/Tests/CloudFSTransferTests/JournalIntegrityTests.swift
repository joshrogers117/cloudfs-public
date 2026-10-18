// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import CloudFSTransfer

final class JournalIntegrityTests: XCTestCase {
    private func temporaryDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cfs-integrity-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        return dir
    }
    private func blockFile(in root: URL) throws -> URL {
        let directory = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: root.appendingPathComponent("staging"), includingPropertiesForKeys: nil).first)
        return try XCTUnwrap(FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).first { $0.lastPathComponent.hasPrefix("block-") })
    }

    func testReplayRejectsMissingTruncatedAndSameLengthCorruptBlocks() async throws {
        for damage in 0..<3 {
            let root = try temporaryDirectory()
            let journal = WriteBackJournal(cacheDir: root.path)
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8,
                                            touched: [0: Data("original".utf8)])
            let file = try blockFile(in: root)
            switch damage {
            case 0: try FileManager.default.removeItem(at: file)
            case 1: try Data("short".utf8).write(to: file)
            default: try Data("modified".utf8).write(to: file)
            }
            do {
                _ = try await WriteBackJournal(cacheDir: root.path).replay()
                XCTFail("damage \(damage) must not be interpreted as zeroes or acknowledged")
            } catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
            XCTAssertThrowsError(try journal.readBlock(filespace: "fs", itemID: "file", blockIndex: 0))
            XCTAssertTrue(FileManager.default.fileExists(atPath: file.deletingLastPathComponent().appendingPathComponent("meta").path))
        }
    }

    func testOriginalBaseSnapshotIsImmutableAndDamageFailsReplay() async throws {
        let root = try temporaryDirectory(), journal = WriteBackJournal(cacheDir: root.path)
        let hash = BlockHash(hex: String(repeating: "a", count: 64))
        let original = ResolvedBlockManifest(manifest: BlockManifest(itemID: "file",
            blocks: [BlockRef(hash: hash, offset: 0, length: 8)], contentVersion: "original"),
            objectKeys: [hash: "original/object"])
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8,
            touched: [0: Data("edit".utf8)], base: original, baseCaptured: true)
        let replacement = ResolvedBlockManifest(manifest: BlockManifest(itemID: "file", blocks: [], contentVersion: "other"), objectKeys: [:])
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8,
            touched: [0: Data("next".utf8)], base: replacement, baseCaptured: true)
        let recovered = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(recovered.first?.base?.manifest.contentVersion, "original")
        XCTAssertEqual(recovered.first?.base?.objectKey(for: hash), "original/object")
        let directory = try blockFile(in: root).deletingLastPathComponent()
        let bases = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("block-base-") }
        XCTAssertEqual(bases.count, 1, "partial writes retain one original manifest, not one per write")
        try Data("damaged".utf8).write(to: XCTUnwrap(bases.first))
        do { _ = try await WriteBackJournal(cacheDir: root.path).replay(); XCTFail("never reconstruct unchanged bytes from a damaged base") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("meta").path))
    }

    func testUnpublishedGenerationIsIgnoredDuringReplay() async throws {
        let root = try temporaryDirectory()
        let journal = WriteBackJournal(cacheDir: root.path)
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 3,
                                       touched: [0: Data("old".utf8)])
        let file = try blockFile(in: root)
        // Simulates interruption after writing payload but before manifest rename.
        try Data("unacknowledged".utf8).write(to: file.deletingLastPathComponent().appendingPathComponent("block-0-interrupted"))
        let recovered = WriteBackJournal(cacheDir: root.path)
        let entries = try await recovered.replay()
        XCTAssertEqual(entries.first?.blockLengths, [0: 3])
        XCTAssertEqual(try recovered.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("old".utf8))
    }

    func testPublishedMapPreservesEveryAppendAndBoundsInterruptedGenerationCleanup() async throws {
        let root = try temporaryDirectory(), journal = WriteBackJournal(cacheDir: root.path)
        var expected: [Int: Data] = [0: Data("head".utf8), 1: Data("tail".utf8)]
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8, touched: expected)
        let directory = try blockFile(in: root).deletingLastPathComponent()
        let oldHead = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .first { $0.lastPathComponent.hasPrefix("block-0-") })
        let reader = FailingReader()
        do {
            _ = try await journal.recordReplaceStreaming(filespace: "fs", itemID: "file", baseVersion: "1", nextChunk: { try reader.next() })
            XCTFail("failed input cannot replace the published map")
        } catch is SourceReadFailure {}
        let explicitOrphan = directory.appendingPathComponent("block-999-unpublished")
        try Data("unacknowledged".utf8).write(to: explicitOrphan)
        expected[0] = Data("next".utf8)
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8, touched: [0: expected[0]!])
        XCTAssertFalse(FileManager.default.fileExists(atPath: oldHead.path), "known replaced generation is removed after publication")
        XCTAssertTrue(FileManager.default.fileExists(atPath: explicitOrphan.path), "unrelated cleanup can wait without changing durability")
        for index in 2..<132 {
            let bytes = Data(repeating: UInt8(index), count: 4)
            expected[index] = bytes
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: (index + 1) * 4,
                                           touched: [index: bytes])
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: explicitOrphan.path), "periodic sweep collects interrupted generations")
        let reopened = WriteBackJournal(cacheDir: root.path)
        let entries = try await reopened.replay()
        XCTAssertEqual(entries.first?.blockLengths.count, expected.count)
        for (index, bytes) in expected {
            XCTAssertEqual(try reopened.readBlock(filespace: "fs", itemID: "file", blockIndex: index), bytes)
        }
        let payloads = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("block-") }
        XCTAssertEqual(payloads.count, expected.count, "only the final immutable generations remain")
        await journal.clear(filespace: "fs", itemID: "file")
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "2", size: 3, touched: [0: Data("new".utf8)])
        let afterClear = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(afterClear.first?.blockLengths, [0: 3], "a new edit must not resurrect the prior cached map")
    }

    func testAppendCannotReplaceMissingCommittedManifestAfterReopen() async throws {
        let root = try temporaryDirectory(), journal = WriteBackJournal(cacheDir: root.path)
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 3, touched: [0: Data("old".utf8)])
        let directory = try blockFile(in: root).deletingLastPathComponent()
        try FileManager.default.removeItem(at: directory.appendingPathComponent("meta"))
        do {
            try await WriteBackJournal(cacheDir: root.path).recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1",
                                                                       size: 6, touched: [1: Data("new".utf8)])
            XCTFail("missing acknowledged metadata must never be treated as a brand-new image")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory.appendingPathComponent("committed").path))
    }

    func testInterruptedStreamingReplacementPreservesAcknowledgedVersion() async throws {
        let root = try temporaryDirectory()
        let journal = WriteBackJournal(cacheDir: root.path)
        try await journal.recordReplace(filespace: "fs", itemID: "file", baseVersion: "1", size: 3,
                                        blocks: [0: Data("old".utf8)])
        let reader = FailingReader()
        do {
            _ = try await journal.recordReplaceStreaming(filespace: "fs", itemID: "file", baseVersion: "1",
                                                         nextChunk: { try reader.next() })
            XCTFail("source read error must propagate")
        } catch is SourceReadFailure {}
        let recovered = WriteBackJournal(cacheDir: root.path)
        let entries = try await recovered.replay()
        XCTAssertEqual(entries.first?.size, 3)
        XCTAssertEqual(try recovered.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), Data("old".utf8))
    }

    func testEmptyReplacementAndTruncateSurviveRestart() async throws {
        let root = try temporaryDirectory()
        let journal = WriteBackJournal(cacheDir: root.path)
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 8,
                                        touched: [0: Data("head".utf8), 1: Data("tail".utf8)])
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 2,
                                        committedLimit: 2, touched: [0: Data("he".utf8)], removed: [1])
        var entries = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(entries.first?.size, 2)
        XCTAssertEqual(entries.first?.blockLengths, [0: 2])
        _ = try await journal.recordReplaceStreaming(filespace: "fs", itemID: "file", baseVersion: "1", nextChunk: { nil })
        entries = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(entries.first?.size, 0)
        XCTAssertEqual(entries.first?.committedLimit, 0)
        XCTAssertEqual(entries.first?.blockLengths, [:])
    }

    func testMalformedManifestFailsRecoveryWithoutDeletingEvidence() async throws {
        let root = try temporaryDirectory()
        let journal = WriteBackJournal(cacheDir: root.path)
        try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: nil, size: 3, touched: [0: Data("old".utf8)])
        let meta = try blockFile(in: root).deletingLastPathComponent().appendingPathComponent("meta")
        try Data("{broken".utf8).write(to: meta)
        do { _ = try await WriteBackJournal(cacheDir: root.path).replay(); XCTFail("malformed metadata must fail closed") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        XCTAssertEqual(try Data(contentsOf: meta), Data("{broken".utf8))
    }

    func testLostOrChecksumDamagedManifestCannotDisappearFromRecovery() async throws {
        for remove in [false, true] {
            let root = try temporaryDirectory()
            let journal = WriteBackJournal(cacheDir: root.path)
            try await journal.recordBlocks(filespace: "fs", itemID: "file", baseVersion: "1", size: 3, touched: [0: Data("old".utf8)])
            let meta = try blockFile(in: root).deletingLastPathComponent().appendingPathComponent("meta")
            if remove { try FileManager.default.removeItem(at: meta) }
            else {
                var envelope = try JSONSerialization.jsonObject(with: Data(contentsOf: meta)) as! [String: Any]
                let payload = Data(base64Encoded: envelope["payload"] as! String)!
                var body = try JSONSerialization.jsonObject(with: payload) as! [String: Any]
                body["size"] = 300 // valid JSON corruption; recorded checksum must reject it
                envelope["payload"] = try JSONSerialization.data(withJSONObject: body).base64EncodedString()
                try JSONSerialization.data(withJSONObject: envelope).write(to: meta)
            }
            do { _ = try await WriteBackJournal(cacheDir: root.path).replay(); XCTFail("acknowledged entry must not vanish or change extent") }
            catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        }
    }

    func testConcurrentPartialWritesReplayAllAcknowledgedBytes() async throws {
        let root = try temporaryDirectory()
        let journal = WriteBackJournal(cacheDir: root.path)
        let cache = try DiskBlockCache(filespace: "fs", directory: root.appendingPathComponent("cache"), maxBytes: 1 << 20)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
        let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: MockGateway(), blockSize: 64, journal: journal)
        _ = try await engine.pause(filespace: "fs")
        try await withThrowingTaskGroup(of: Void.self) { group in
            for index in 0..<32 {
                group.addTask {
                    _ = try await engine.stageWrite(filespace: "fs", itemID: "file", offset: index * 2,
                                                     data: Data([UInt8(index), UInt8(index)]))
                }
            }
            try await group.waitForAll()
        }
        let recovered = WriteBackJournal(cacheDir: root.path)
        _ = try await recovered.replay()
        let expected = Data((0..<32).flatMap { [UInt8($0), UInt8($0)] })
        XCTAssertEqual(try recovered.readBlock(filespace: "fs", itemID: "file", blockIndex: 0), expected)
        let staged = try await engine.stagedBlock(filespace: "fs", itemID: "file", blockIndex: 0)
        XCTAssertEqual(staged, expected)
    }

    func testDamagedAcknowledgedWriteCannotCommitOrServeZeroes() async throws {
        let root = try temporaryDirectory()
        let cache = try DiskBlockCache(filespace: "fs", directory: root.appendingPathComponent("cache"), maxBytes: 1 << 20)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
        let gateway = MockGateway()
        let engine = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway, blockSize: 64,
                                        journal: WriteBackJournal(cacheDir: root.path), maxUploadRetries: 0)
        _ = try await engine.pause(filespace: "fs")
        try await engine.stageWrite(filespace: "fs", itemID: "file", offset: 0, data: Data("safe bytes".utf8))
        try Data("short".utf8).write(to: blockFile(in: root))
        do { _ = try await engine.stagedBlock(filespace: "fs", itemID: "file", blockIndex: 0); XCTFail("corrupt bytes must fail reads") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        _ = try await engine.resume(filespace: "fs")
        do { _ = try await engine.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 2000); XCTFail("corrupt bytes must not commit") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        XCTAssertTrue(gateway.putManifests.isEmpty)
        let state = try await engine.syncState(filespace: "fs", path: "/")
        XCTAssertFalse(state.inSync)
    }
}

private struct SourceReadFailure: Error {}
private final class FailingReader: @unchecked Sendable {
    private var calls = 0
    func next() throws -> Data? {
        calls += 1
        if calls == 1 { return Data("new".utf8) }
        throw SourceReadFailure()
    }
}
