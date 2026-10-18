// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSGateway
import CloudFSCrypto
import CloudFSCache
@testable import CloudFSTransfer

private actor StreamGatewayFixture: GatewayClient {
    var streams: [String: StreamManifest] = [:]
    var inline: [String: Data] = [:]
    var frozen: [String: StreamManifest] = [:]
    var updates: [StreamManifestUpdate] = []
    var puts = 0
    var reads = 0
    var failCommit = false
    var failPUT = false
    var manifestUnavailable = false
    var commitAttempts = 0
    func missingManifestEndpoint() { manifestUnavailable = true }
    func seed(_ name: String, bytes: Data, size: Int) { inline[name] = bytes; streams[name] = StreamManifest(size: size, version: 7, legacy: true) }
    func failure(commit: Bool = false, put: Bool = false) { failCommit = commit; failPUT = put }
    func freeze() { frozen = streams }
    func stats() -> (puts: Int, reads: Int, commits: Int) { (puts, reads, updates.count) }
    func saved(_ name: String) -> StreamManifest { streams[name] ?? StreamManifest(size: 0, version: 0, exists: false) }
    private func ranged(_ value: StreamManifest, offset: Int, length: Int) -> StreamManifest {
        var result = value
        result.blocks = value.blocks.filter { $0.index >= offset / (1 << 20) && $0.index * (1 << 20) < offset + length }
        return result
    }
    func streamManifest(filespace: FilespaceID, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        if manifestUnavailable { throw EngineError(.notFound, "Endpoint or inode unavailable") }
        return ranged(saved(name), offset: offset, length: length)
    }
    func snapshotStreamManifest(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        ranged(frozen[name] ?? StreamManifest(size: 0, version: 0, exists: false), offset: offset, length: length)
    }
    func updateStreamManifest(filespace: FilespaceID, id: InodeID, name: String, update: StreamManifestUpdate) async throws -> StreamManifest {
        commitAttempts += 1
        if failCommit { throw EngineError(.conflict, "injected stream CAS failure") }
        let old = saved(name)
        guard update.expectedVersion == old.version, update.fence == 41 else { throw EngineError(.conflict) }
        var refs = Dictionary(uniqueKeysWithValues: old.blocks.filter { $0.index * (1 << 20) < update.size }.map { ($0.index, $0) })
        for block in update.blocks {
            let url = "https://blob.test/" + block.objectKey
            guard let bytes = BlobURLProtocol.putBody(url), !bytes.isEmpty else { throw EngineError(.syncFailed, "unverified object") }
            BlobURLProtocol.serveGET(url, bytes); refs[block.index] = block
        }
        let result = StreamManifest(size: update.size, version: old.version + 1, blocks: refs.values.sorted { $0.index < $1.index })
        streams[name] = result; inline[name] = nil; updates.append(update)
        var header = result; header.blocks = []; return header
    }
    func readStream(filespace: FilespaceID, id: InodeID, name: String) async throws -> Data {
        guard let bytes = inline[name] else { throw EngineError(.notFound) }; return bytes
    }
    func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int) async throws { seed(name, bytes: data, size: plaintextSize) }
    func deleteStream(filespace: FilespaceID, id: InodeID, name: String) async throws {
        streams[name] = StreamManifest(size: 0, version: saved(name).version + 1, exists: false); inline[name] = nil
    }
    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL {
        if method == .PUT { puts += 1 } else { reads += 1 }
        let url = "https://blob.test/" + key
        if method == .PUT && failPUT { BlobURLProtocol.failFirst(1, on: url) }
        return PresignedURL(url: url, expiresIn: 60)
    }
    func snapshotPresign(filespace: FilespaceID, snapshotID: String, itemID: InodeID, keys: [String]) async throws -> [PresignBatchResult] {
        let allowed = Set(frozen.values.flatMap { $0.blocks.map(\.objectKey) })
        guard keys.allSatisfy(allowed.contains) else { throw EngineError(.permissionDenied) }
        return keys.map { PresignBatchResult(key: $0, url: "https://blob.test/" + $0, error: nil) }
    }
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest { throw EngineError.unimplemented() }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws { throw EngineError.unimplemented() }
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { throw EngineError.unimplemented() }
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { throw EngineError.unimplemented() }
}

/// Small content-addressed cache used to prove that uploaded stream ciphertext
/// can satisfy later authenticated partial writes without another blob GET.
private actor StreamCipherCache: BlockCache {
    private var blocks: [BlockHash: Data] = [:]
    func contains(_ hash: BlockHash) async -> Bool { blocks[hash] != nil }
    func readBlock(_ hash: BlockHash) async throws -> Data? { blocks[hash] }
    func putBlock(_ hash: BlockHash, plaintext: Data) async throws { blocks[hash] = plaintext }
    func info(filespace: FilespaceID) async throws -> CacheInfo { throw EngineError.unimplemented() }
    func setSize(filespace: FilespaceID, bytes: Int) async throws -> CacheInfo { throw EngineError.unimplemented() }
    func setLocation(filespace: FilespaceID, path: String) async throws -> CacheInfo { throw EngineError.unimplemented() }
    func clear(filespace: FilespaceID) async throws -> CacheInfo { throw EngineError.unimplemented() }
    func registerPath(_ path: String, blocks: [BlockHash]) async throws { throw EngineError.unimplemented() }
    func pin(_ path: String, recursive: Bool) async throws -> PinState { throw EngineError.unimplemented() }
    func unpin(_ path: String, recursive: Bool) async throws -> PinState { throw EngineError.unimplemented() }
    func pinList(filespace: FilespaceID) async throws -> [PinState] { throw EngineError.unimplemented() }
    func evict(_ path: String) async throws -> EvictAck { throw EngineError.unimplemented() }
}

final class ChunkedStreamTests: XCTestCase {
    private func fixture() throws -> (ChunkedStreamStore, StreamGatewayFixture, AESGCMBlockCrypto, BlobTransport) {
        BlobURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral; configuration.protocolClasses = [BlobURLProtocol.self]
        let session = URLSession(configuration: configuration)
        addTeardownBlock { BlobURLProtocol.releasePUTs(); session.invalidateAndCancel() }
        let blob = BlobTransport(session: session, policy: RetryPolicy(maxAttempts: 1)), gateway = StreamGatewayFixture()
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 67, count: 32))
        return (ChunkedStreamStore(filespace: "fs", gateway: gateway, crypto: crypto, blob: blob), gateway, crypto, blob)
    }
    func testSeventyTwoMiBForkUsesBoundedDeltasAndPartialWriteTouchesOnlyItsChunks() async throws {
        let (store, gateway, _, _) = try fixture(), block = 1 << 20
        for part in 0..<9 {
            let size = try await store.write("inode", name: "AFP_Resource", offset: part * 8 * block, data: Data(repeating: UInt8(part + 1), count: 8 * block), fence: 41)
            XCTAssertEqual(size, (part + 1) * 8 * block)
        }
        let stats = await gateway.stats(); XCTAssertEqual(stats.puts, 72); XCTAssertEqual(stats.reads, 0); XCTAssertEqual(stats.commits, 9)
        let updates = await gateway.updates; XCTAssertTrue(updates.allSatisfy { $0.blocks.count == 8 })
        for part in 0..<9 {
            let read = try await store.read("inode", name: "AFP_Resource", offset: part * 8 * block, length: 8 * block)
            XCTAssertEqual(read, Data(repeating: UInt8(part + 1), count: 8 * block))
        }
        let before = await gateway.stats()
        _ = try await store.write("inode", name: "AFP_Resource", offset: 3 * block - 1, data: Data([77, 88]), fence: 41)
        let after = await gateway.stats(); XCTAssertEqual(after.puts - before.puts, 2); XCTAssertEqual(after.reads - before.reads, 2)
        let bytes = try await store.read("inode", name: "AFP_Resource", offset: 3 * block - 2, length: 4)
        XCTAssertEqual(bytes, Data([1, 77, 88, 1]))
    }
    func testMissingManifestEndpointCannotAuthorizeCreationOrTruncation() async throws {
        let (store, gateway, _, _) = try fixture()
        await gateway.missingManifestEndpoint()
        do { _ = try await store.write("inode", name: "fork", offset: 0, data: Data([1]), fence: 41); XCTFail("Unknown stream metadata accepted") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notFound) }
        do { try await store.truncate("inode", name: "fork", size: 0, fence: 41); XCTFail("Unknown stream truncated") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notFound) }
        let stats = await gateway.stats(), attempts = await gateway.commitAttempts
        XCTAssertEqual(stats.puts, 0, "No object upload before stream metadata is known")
        XCTAssertEqual(attempts, 0, "No manifest mutation against an unavailable or older route")
    }
    func testSparseExtensionTruncateAndRegrowthNeverResurrectDiscardedBytes() async throws {
        let (store, gateway, _, _) = try fixture(), block = 1 << 20
        _ = try await store.write("inode", name: "fork", offset: 0, data: Data([1, 2, 3]), fence: 41)
        let huge = 1 << 40
        _ = try await store.write("inode", name: "fork", offset: huge + 5, data: Data([4, 5]), fence: 41)
        let hole = try await store.read("inode", name: "fork", offset: block * 100, length: 1024)
        XCTAssertEqual(hole, Data(repeating: 0, count: 1024))
        let count = await gateway.saved("fork").blocks.count; XCTAssertEqual(count, 2)
        try await store.truncate("inode", name: "fork", size: 2, fence: 41)
        try await store.truncate("inode", name: "fork", size: huge + 7, fence: 41)
        let beginning = try await store.read("inode", name: "fork", offset: 0, length: 5)
        let end = try await store.read("inode", name: "fork", offset: huge, length: 7)
        XCTAssertEqual(beginning, Data([1, 2, 0, 0, 0])); XCTAssertEqual(end, Data(repeating: 0, count: 7))
    }
    func testFailedPUTOrCommitCannotAcknowledgeOrReplacePreviouslyCommittedFork() async throws {
        let (store, gateway, _, _) = try fixture(), original = Data(repeating: 31, count: 1 << 20)
        _ = try await store.write("inode", name: "fork", offset: 0, data: original, fence: 41)
        for put in [true, false] {
            await gateway.failure(commit: !put, put: put)
            do { _ = try await store.write("inode", name: "fork", offset: 7, data: Data([92]), fence: 41); XCTFail("Failed mutation acknowledged") } catch {}
            await gateway.failure()
            let read = try await store.read("inode", name: "fork", offset: 0, length: original.count)
            XCTAssertEqual(read, original)
        }
        let commits = await gateway.stats().commits; XCTAssertEqual(commits, 1)
    }
    func testLegacyMigrationPreservesUntouchedBytesAndUsesSeparateCryptoIdentity() async throws {
        let (store, gateway, crypto, _) = try fixture(), original = Data(repeating: 61, count: (2 << 20) + 17)
        let sealed = try await crypto.encryptBlock(original, itemID: "inode", blockIndex: ChunkedStreamStore.legacyIndex("fork"))
        await gateway.seed("fork", bytes: sealed.ciphertext, size: original.count)
        _ = try await store.write("inode", name: "fork", offset: (1 << 20) - 1, data: Data([3, 4]), fence: 41)
        var expected = original; expected.replaceSubrange((1 << 20) - 1...(1 << 20), with: [3, 4])
        let read = try await store.read("inode", name: "fork", offset: 0, length: expected.count); XCTAssertEqual(read, expected)
        let manifest = await gateway.saved("fork"); XCTAssertFalse(manifest.legacy); XCTAssertEqual(manifest.blocks.count, 3)
        let first = try XCTUnwrap(manifest.blocks.first), bytes = try XCTUnwrap(BlobURLProtocol.putBody("https://blob.test/" + first.objectKey))
        do { _ = try await crypto.decryptBlock(bytes, itemID: ChunkedStreamStore.cryptoIdentity("inode", name: "different"), blockIndex: 0); XCTFail("stream name not authenticated") } catch {}
        XCTAssertNotEqual(ChunkedStreamStore.cryptoIdentity("a:b", name: "c"), ChunkedStreamStore.cryptoIdentity("a", name: "b:c"))
    }
    func testHeldUploadCannotPublishAndConcurrentMutationsSerializeAfterDurableCommit() async throws {
        let (store, gateway, _, _) = try fixture()
        BlobURLProtocol.armPUTGate()
        let first = Task { try await store.write("inode", name: "fork", offset: 0, data: Data([1, 2]), fence: 41) }
        XCTAssertTrue(BlobURLProtocol.waitForPUTInFlight())
        let second = Task { try await store.write("inode", name: "fork", offset: 2, data: Data([3]), fence: 41) }
        let commits = await gateway.stats().commits; XCTAssertEqual(commits, 0)
        BlobURLProtocol.releasePUTs()
        _ = try await first.value; _ = try await second.value
        let read = try await store.read("inode", name: "fork", offset: 0, length: 3); XCTAssertEqual(read, Data([1, 2, 3]))
        let versions = await gateway.updates.map(\.expectedVersion); XCTAssertEqual(versions, [0, 1])
    }
    func testConcurrentIdenticalProvenanceWritesReuseCacheButValidateEveryCAS() async throws {
        BlobURLProtocol.reset()
        let configuration = URLSessionConfiguration.ephemeral; configuration.protocolClasses = [BlobURLProtocol.self]
        let session = URLSession(configuration: configuration)
        addTeardownBlock { BlobURLProtocol.releasePUTs(); session.invalidateAndCancel() }
        let gateway = StreamGatewayFixture()
        let cache = StreamCipherCache()
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 67, count: 32))
        let store = ChunkedStreamStore(filespace: "fs", gateway: gateway, crypto: crypto,
                                       blob: BlobTransport(session: session, policy: RetryPolicy(maxAttempts: 1)),
                                       cache: cache)
        let provenance = Data("11-byte-tag".utf8)
        _ = try await store.replace("inode", name: "com.apple.provenance", data: provenance, fence: 41)
        async let first = store.replace("inode", name: "com.apple.provenance", data: provenance, fence: 41)
        async let second = store.replace("inode", name: "com.apple.provenance", data: provenance, fence: 41)
        _ = try await (first, second)
        let stats = await gateway.stats()
        XCTAssertEqual(stats.puts, 1, "the initial durable block upload is sufficient")
        XCTAssertEqual(stats.reads, 0, "uploaded ciphertext should seed the verified block cache")
        XCTAssertEqual(stats.commits, 3, "identical writes still validate and commit the fenced manifest CAS")
        let verified = try await store.read("inode", name: "com.apple.provenance", offset: 0, length: 32)
        XCTAssertEqual(verified, provenance)
        await gateway.failure(commit: true)
        do {
            try await store.replace("inode", name: "com.apple.provenance", data: provenance, fence: 41)
            XCTFail("an identical write must not bypass a failed fenced manifest commit")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .conflict) }
        await gateway.failure()
        do {
            try await store.replace("inode", name: "com.apple.provenance", data: provenance, fence: 42)
            XCTFail("an identical write must still reject a stale fence")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .conflict) }
        let finalStats = await gateway.stats()
        XCTAssertEqual(finalStats.puts, 1)
        XCTAssertEqual(finalStats.reads, 0)
        XCTAssertEqual(finalStats.commits, 3)
        let attempts = await gateway.commitAttempts
        XCTAssertEqual(attempts, 5, "all identical writes must reach manifest CAS validation")
    }
    func testCorruptedCiphertextCannotBecomeZerosOrSeedASuccessfulPartialWrite() async throws {
        let (store, gateway, _, _) = try fixture()
        _ = try await store.write("inode", name: "fork", offset: 0, data: Data(repeating: 5, count: 1 << 20), fence: 41)
        let manifest = await gateway.saved("fork"), block = try XCTUnwrap(manifest.blocks.first)
        let url = "https://blob.test/" + block.objectKey
        var cipher = try XCTUnwrap(BlobURLProtocol.putBody(url)); cipher[cipher.count - 1] ^= 1
        BlobURLProtocol.serveGET(url, cipher)
        do { _ = try await store.read("inode", name: "fork", offset: 0, length: 10); XCTFail("corruption was returned as bytes") } catch {}
        do { _ = try await store.write("inode", name: "fork", offset: 7, data: Data([3]), fence: 41); XCTFail("corrupt base was silently replaced") } catch {}
        let stats = await gateway.stats(); XCTAssertEqual(stats.puts, 1); XCTAssertEqual(stats.commits, 1)
        let after = await gateway.saved("fork"); XCTAssertEqual(after, manifest)
        do { try await store.truncate("inode", name: "fork", size: Int.max, fence: 41); XCTFail("unsafe integer extent accepted") } catch {}
    }

    func testSnapshotReadsFrozenChunksAfterLiveForkReplacementAndDeletion() async throws {
        let (store, gateway, crypto, blob) = try fixture()
        _ = try await store.write("inode", name: "fork", offset: 0, data: Data([1, 2, 3]), fence: 41)
        await gateway.freeze()
        let frozen = ChunkedStreamStore(filespace: "fs", gateway: SnapshotReadGateway(base: gateway, filespace: "fs", snapshotID: "s"), crypto: crypto, blob: blob)
        _ = try await store.write("inode", name: "fork", offset: 0, data: Data([9, 8, 7]), fence: 41)
        try await store.delete("inode", name: "fork", fence: 41)
        let historical = try await frozen.read("inode", name: "fork", offset: 0, length: 3); XCTAssertEqual(historical, Data([1, 2, 3]))
        do { _ = try await store.read("inode", name: "fork", offset: 0, length: 3); XCTFail("Deleted stream still readable") } catch {}
        _ = try await store.write("inode", name: "fork", offset: 0, data: Data([4]), fence: 41)
        let version = await gateway.updates.last?.expectedVersion; XCTAssertEqual(version, 3)
    }
}
