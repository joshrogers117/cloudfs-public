// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CryptoKit
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import CloudFSTransfer

final class RecoveryTests: XCTestCase {
    private func directory() throws -> URL {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cloudfs-recovery-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: root) }
        return root
    }
    private func engine(_ root: URL, gateway: MockGateway = MockGateway()) throws -> RealTransferEngine {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.protocolClasses = [BlobURLProtocol.self]
        let session = URLSession(configuration: cfg)
        addTeardownBlock { session.invalidateAndCancel() }
        return RealTransferEngine(cache: try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20),
            crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32)), gateway: gateway,
            blob: BlobTransport(session: session), blockSize: 4, prefetchConcurrency: 8,
            journal: WriteBackJournal(cacheDir: root.path), maxUploadRetries: 0)
    }

    func testConcurrentDownloadWindowBatchesAuthorizationAndFetchesEachBlockOnce() async throws {
        BlobURLProtocol.reset()
        let root = try directory(), gateway = MockGateway()
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
        var refs: [BlockRef] = []
        for index in 0..<80 {
            let (ciphertext, hash) = try await crypto.encryptBlock(Data(repeating: UInt8(index), count: 4), itemID: "file", blockIndex: index)
            let signed = try await gateway.presign(filespace: "fs", key: hash.objectKey, method: .GET, expiresIn: nil)
            BlobURLProtocol.serveGET(signed.url, ciphertext)
            refs.append(BlockRef(hash: hash, offset: index * 4, length: 4))
        }
        gateway.manifests["file"] = BlockManifest(itemID: "file", blocks: refs, contentVersion: "v1")
        let transfer = try engine(root, gateway: gateway)
        try await transfer.ensureRange(filespace: "fs", itemID: "file", offset: 0, length: 320)
        XCTAssertEqual(gateway.presignBatches.flatMap { $0 }.count, 80)
        XCTAssertTrue(gateway.presignBatches.contains { $0.count > 1 }, "concurrent reads must share authorization RPCs")
        // Metadata authorization is bounded independently of the eight payload
        // workers. Larger batches prepare URLs without downloading extra bytes.
        XCTAssertLessThanOrEqual(gateway.presignBatches.map(\.count).max() ?? 0, 32)
        for ref in refs {
            let signed = try await gateway.presign(filespace: "fs", key: ref.hash.objectKey, method: .GET, expiresIn: nil)
            XCTAssertEqual(BlobURLProtocol.getCount(signed.url), 1)
        }
    }

    func testFailedPrefetchCannotRemainAsGhostActiveDownload() async throws {
        BlobURLProtocol.reset()
        let root = try directory(), gateway = MockGateway()
        let hash = BlockHash(hex: String(repeating: "a", count: 64))
        gateway.manifests["damaged"] = BlockManifest(itemID: "damaged", blocks: [BlockRef(hash: hash, offset: 0, length: 4)], contentVersion: "1")
        let url = try await gateway.presign(filespace: "fs", key: hash.objectKey, method: .GET, expiresIn: nil)
        BlobURLProtocol.serveGET(url.url, Data("not a valid encrypted block".utf8))
        let transfer = try engine(root, gateway: gateway)
        do { _ = try await transfer.prefetch(filespace: "fs", path: "/damaged", itemID: "damaged"); XCTFail("invalid data must fail") }
        catch {}
        let active = try await transfer.current(filespace: "fs")
        XCTAssertTrue(active.isEmpty, "failed prefetch must publish terminal error instead of remaining active")
    }

    func testVerifiedWindowIsBoundedAndCannotCrossCryptoIdentityOrLength() async throws {
        let window = VerifiedBlockWindow(limit: 8)
        let first = VerifiedBlockWindow.Key(filespace: "fs", itemID: "file", index: 0, hash: BlockHash(hex: "a"))
        let second = VerifiedBlockWindow.Key(filespace: "fs", itemID: "file", index: 1, hash: BlockHash(hex: "b"))
        let third = VerifiedBlockWindow.Key(filespace: "fs", itemID: "file", index: 2, hash: BlockHash(hex: "c"))
        await window.insert(Data("abcd".utf8), for: first)
        await window.insert(Data("efgh".utf8), for: second)
        let wrongLength = await window.get(first, length: 3)
        let wrongInode = await window.get(.init(filespace: "fs", itemID: "other", index: 0, hash: first.hash), length: 4)
        XCTAssertNil(wrongLength); XCTAssertNil(wrongInode)
        await window.insert(Data("ijkl".utf8), for: third)
        let evicted = await window.get(first, length: 4)
        let resident = await window.get(second, length: 4)
        let count = await window.byteCount
        XCTAssertNil(evicted); XCTAssertEqual(resident, Data("efgh".utf8)); XCTAssertEqual(count, 8)
        await window.insert(Data(repeating: 1, count: 9), for: first)
        let afterOversize = await window.byteCount
        XCTAssertEqual(afterOversize, 8)
    }

    func testDownloadedPlaintextReusesValidationButWrongAADStillFails() async throws {
        BlobURLProtocol.reset()
        let root = try directory(), gateway = MockGateway()
        let crypto = CountingBlockCrypto()
        let (ciphertext, hash) = try await crypto.encryptBlock(Data("data".utf8), itemID: "file", blockIndex: 0)
        let ref = BlockRef(hash: hash, offset: 0, length: 4)
        let manifest = BlockManifest(itemID: "file", blocks: [ref], contentVersion: "1")
        gateway.manifests["file"] = manifest
        let signed = try await gateway.presign(filespace: "fs", key: hash.objectKey, method: .GET, expiresIn: nil)
        BlobURLProtocol.serveGET(signed.url, ciphertext)
        let cfg = URLSessionConfiguration.ephemeral; cfg.protocolClasses = [BlobURLProtocol.self]
        let session = URLSession(configuration: cfg); defer { session.invalidateAndCancel() }
        let transfer = RealTransferEngine(cache: try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20),
            crypto: crypto, gateway: gateway, blob: BlobTransport(session: session), blockSize: 4)
        let resolved = try await gateway.getResolvedBlockManifest(filespace: "fs", itemID: "file")
        try await transfer.ensureBlocks(resolved: resolved, filespace: "fs", itemID: "file", offset: 0, length: 4)
        for _ in 0..<3 {
            let bytes = try await transfer.plaintextBlock(ref, resolved: resolved, blockIndex: 0, filespace: "fs", itemID: "file")
            XCTAssertEqual(bytes, Data("data".utf8))
        }
        let decrypts = await crypto.decrypts
        XCTAssertEqual(decrypts, 1, "assembly reuses authenticated download bytes")
        do {
            _ = try await transfer.plaintextBlock(ref, resolved: resolved, blockIndex: 1, filespace: "fs", itemID: "file")
            XCTFail("a different crypto block index must authenticate independently")
        } catch {}
    }

    func testPresignThrottlingRetriesTheBlockWithoutRestartingTheUpload() async throws {
        BlobURLProtocol.reset()
        let root = try directory(), gateway = MockGateway()
        gateway.rateLimitFirstPresigns = 2
        let transfer = try engine(root, gateway: gateway)
        try await transfer.stageReplace(filespace: "fs", itemID: "file", data: Data("data".utf8), baseVersion: "1", fence: nil)
        let state = try await transfer.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 3000)
        XCTAssertTrue(state.inSync, "rate-limited signing is retried inside one upload attempt even with zero upload retries")
        XCTAssertEqual(gateway.presignCalls.count, 3)
        XCTAssertEqual(gateway.putManifests.count, 1)
    }

    func testExportIsExclusiveKeepsJournalAndCompletionRequiresUnchangedSnapshot() async throws {
        let root = try directory(), engine = try engine(root)
        let stream = engine.progressEvents(filespace: "fs")
        let terminal = Task { () -> Transfer? in
            for await event in stream where event.error == "Upload cancelled after verified local recovery" { return event }
            return nil
        }
        _ = try await engine.pause(filespace: "fs")
        try await engine.stageReplace(filespace: "fs", itemID: "file", data: Data("original".utf8), baseVersion: "1", fence: nil)
        let first = root.appendingPathComponent("first.bin")
        let result = try await engine.exportRecovery(filespace: "fs", itemID: "file", destination: first.path)
        XCTAssertEqual(try Data(contentsOf: first), Data("original".utf8))
        XCTAssertEqual(result.bytes, 8)
        XCTAssertEqual(result.sha256, SHA256.hash(data: Data("original".utf8)).map { String(format: "%02x", $0) }.joined())
        let before = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertEqual(before.count, 1, "export alone must not clear the retained write")
        do { _ = try await engine.exportRecovery(filespace: "fs", itemID: "file", destination: first.path); XCTFail("cannot overwrite an existing recovery file") }
        catch {}
        try await engine.stageReplace(filespace: "fs", itemID: "file", data: Data("new edit".utf8), baseVersion: "1", fence: nil)
        do { try await engine.completeRecovery(filespace: "fs", itemID: "file", destination: first.path); XCTFail("newer local writes must not be discarded") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .conflict) }
        let second = root.appendingPathComponent("second.bin")
        _ = try await engine.exportRecovery(filespace: "fs", itemID: "file", destination: second.path)
        try Data("tampered".utf8).write(to: second)
        do { try await engine.completeRecovery(filespace: "fs", itemID: "file", destination: second.path); XCTFail("a modified export cannot authorize completion") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        try FileManager.default.removeItem(at: second)
        try FileManager.default.createSymbolicLink(at: second, withDestinationURL: first)
        do { try await engine.completeRecovery(filespace: "fs", itemID: "file", destination: second.path); XCTFail("a symlink cannot authorize completion") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .syncFailed) }
        let final = root.appendingPathComponent("final.bin")
        _ = try await engine.exportRecovery(filespace: "fs", itemID: "file", destination: final.path)
        try await engine.completeRecovery(filespace: "fs", itemID: "file", destination: final.path)
        let state = await engine.stagedState(filespace: "fs", itemID: "file")
        XCTAssertNil(state)
        let after = try await WriteBackJournal(cacheDir: root.path).replay()
        XCTAssertTrue(after.isEmpty)
        XCTAssertEqual(try Data(contentsOf: final), Data("new edit".utf8))
        let cancellation = await terminal.value
        XCTAssertEqual(cancellation?.state, .error, "verified local export is not a remote upload commit")
        let remaining = try await engine.current(filespace: "fs")
        XCTAssertTrue(remaining.isEmpty)
    }

    func testPartialExportAfterRestartUsesOriginalBaseAndRetryPreservesCAS() async throws {
        BlobURLProtocol.reset()
        let root = try directory(), gateway = MockGateway()
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
        let cache = try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20)
        var refs: [BlockRef] = []
        for (index, text) in ["abcd", "efgh"].enumerated() {
            let (ciphertext, hash) = try await crypto.encryptBlock(Data(text.utf8), itemID: "file", blockIndex: index)
            try await cache.putBlock(hash, plaintext: ciphertext)
            refs.append(BlockRef(hash: hash, offset: index * 4, length: 4))
        }
        gateway.manifests["file"] = BlockManifest(itemID: "file", blocks: refs, contentVersion: "old")
        gateway.versions["file"] = 1; gateway.enforceExpectedVersion = true
        let first = try engine(root, gateway: gateway)
        _ = try await first.pause(filespace: "fs")
        try await first.stageWrite(filespace: "fs", itemID: "file", offset: 1, data: Data("X".utf8), baseVersion: "1", fence: nil)
        // A teammate replaces the remote file after our acknowledged partial write.
        gateway.manifests["file"] = BlockManifest(itemID: "file", blocks: [], contentVersion: "different")
        gateway.versions["file"] = 2
        let recovered = try engine(root, gateway: gateway)
        _ = try await recovered.pause(filespace: "fs")
        try await recovered.replayJournal()
        let readState = await recovered.stagedState(filespace: "fs", itemID: "file")
        XCTAssertEqual(readState?.baseCaptured, true)
        XCTAssertEqual(readState?.originalBase?.manifest.contentVersion, "old", "ordinary reads must use the same original base as recovery export")
        let output = root.appendingPathComponent("after-restart.bin")
        _ = try await recovered.exportRecovery(filespace: "fs", itemID: "file", destination: output.path)
        XCTAssertEqual(try Data(contentsOf: output), Data("aXcdefgh".utf8), "unchanged bytes must come from our original base, never the new remote version")
        _ = try await recovered.resume(filespace: "fs")
        do { _ = try await recovered.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000); XCTFail("remote edit must conflict") } catch {}
        let errors = try await recovered.recoveryItems(filespace: "fs")
        XCTAssertEqual(errors.first?.kind, "conflict")
        XCTAssertEqual(errors.first?.canExport, true)
        try await recovered.retryRecovery(filespace: "fs", itemID: "file")
        do { _ = try await recovered.flush(filespace: "fs", path: "/", wait: true, timeoutMs: 5000); XCTFail("retry cannot overwrite newer remote content") } catch {}
        XCTAssertEqual(gateway.putExpectedVersions, [1, 1])
        XCTAssertEqual(gateway.versions["file"], 2)
    }
}

private actor CountingBlockCrypto: BlockCrypto {
    nonisolated let mode = CipherMode.aes256gcm
    private let base = try! AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 7, count: 32))
    private(set) var decrypts = 0
    func encryptBlock(_ plaintext: Data, itemID: InodeID, blockIndex: Int) async throws -> (ciphertext: Data, hash: BlockHash) {
        try await base.encryptBlock(plaintext, itemID: itemID, blockIndex: blockIndex)
    }
    func decryptBlock(_ ciphertext: Data, itemID: InodeID, blockIndex: Int) async throws -> Data {
        decrypts += 1
        return try await base.decryptBlock(ciphertext, itemID: itemID, blockIndex: blockIndex)
    }
}
