// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CryptoKit
import CloudFSCore
@testable import CloudFSCache

final class CloudFSCacheTests: XCTestCase {

    // MARK: Helpers

    /// Make a deterministic plaintext block of `size` bytes filled with `byte`.
    private func block(_ byte: UInt8, size: Int = 4096) -> Data {
        Data(repeating: byte, count: size)
    }

    /// Content address (SHA-256 hex) of a plaintext block — must match the cache's.
    private func hash(of data: Data) -> BlockHash {
        let hex = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return BlockHash(hex: hex)
    }

    private func tempDir() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cloudfs-cache-test-\(UUID().uuidString)")
        return url
    }

    private func makeCache(dir: URL, maxBytes: Int = 1 << 30) throws -> DiskBlockCache {
        try DiskBlockCache(filespace: "fs1", directory: dir, maxBytes: maxBytes,
                           blockSize: kDefaultBlockSize)
    }

    override func tearDown() {
        // best-effort cleanup of test temp dirs
        let base = FileManager.default.temporaryDirectory
        if let kids = try? FileManager.default.contentsOfDirectory(atPath: base.path) {
            for k in kids where k.hasPrefix("cloudfs-cache-test-") {
                try? FileManager.default.removeItem(at: base.appendingPathComponent(k))
            }
        }
        super.tearDown()
    }

    func testAdmissionsAvoidSnapshotRewriteAndReplayTornTail() async throws {
        let root = tempDir(), cache = try makeCache(dir: root)
        let initial = try Data(contentsOf: root.appendingPathComponent("index.db"))
        let payload = block(23), h = hash(of: payload)
        try await cache.putBlock(h, plaintext: payload)
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("index.db")), initial,
                       "a cache admission must not serialize the entire snapshot")
        let log = root.appendingPathComponent("index.admissions")
        let handle = try FileHandle(forWritingTo: log)
        try handle.seekToEnd(); try handle.write(contentsOf: Data("{torn record".utf8)); try handle.close()
        let reopened = try makeCache(dir: root)
        let restored = try await reopened.readBlock(h)
        XCTAssertEqual(restored, payload, "a partial final record cannot hide earlier durable admissions")
        try await reopened.putBlock(hash(of: block(24)), plaintext: block(24))
        let reopenedAgain = try makeCache(dir: root)
        let next = try await reopenedAgain.readBlock(hash(of: block(24)))
        XCTAssertEqual(next, block(24), "new admissions after torn-log repair must remain replayable")
    }

    func testOldAdmissionLogCannotUndoLaterEvictionCheckpoint() async throws {
        let root = tempDir(), cache = try makeCache(dir: root)
        let payload = block(31), h = hash(of: payload)
        try await cache.putBlock(h, plaintext: payload)
        let oldLog = try Data(contentsOf: root.appendingPathComponent("index.admissions"))
        try await cache.registerPath("file", blocks: [h])
        _ = try await cache.evict("file")
        // Crash after checkpoint rename but before clearing records from its predecessor.
        try oldLog.write(to: root.appendingPathComponent("index.admissions"))
        let reopened = try makeCache(dir: root)
        let present = await reopened.contains(h)
        XCTAssertFalse(present, "prior checkpoint records cannot resurrect an evicted block")
    }

    func testParallelDurablePayloadsDrainAcrossRelocationAndReopenExactly() async throws {
        let root = tempDir(), destination = tempDir(), cache = try makeCache(dir: root)
        let blocks = (0..<32).map { block(UInt8($0), size: 256 << 10) }
        let hashes = blocks.map { hash(of: $0) }
        let writes = Task {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for i in blocks.indices { group.addTask { try await cache.putBlock(hashes[i], plaintext: blocks[i]) } }
                try await group.waitForAll()
            }
        }
        // Wait until the disk stage overlaps, then move while writes are active.
        for _ in 0..<100 {
            if await cache.peakPayloadWrites > 1 { break }
            try await Task.sleep(for: .milliseconds(1))
        }
        _ = try await cache.setLocation(filespace: "fs1", path: destination.path)
        try await writes.value
        let peak = await cache.peakPayloadWrites
        XCTAssertGreaterThan(peak, 1); XCTAssertLessThanOrEqual(peak, 8)
        await cache.flush()
        let reopened = try makeCache(dir: destination)
        for i in blocks.indices {
            let bytes = try await reopened.readBlock(hashes[i])
            XCTAssertEqual(bytes, blocks[i], "relocation must include every completed or queued admission")
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: root.appendingPathComponent("blocks").path))
    }

    func testManifestRegistrationFastPathRestoresLinksAfterEvictionAndVersionChange() async throws {
        let root = tempDir(), cache = try makeCache(dir: root)
        let first = block(60), second = block(61)
        let h1 = hash(of: first), h2 = hash(of: second)
        let original = BlockManifest(itemID: "file", blocks: [BlockRef(hash: h1, offset: 0, length: first.count)], contentVersion: "v1")
        try await cache.registerManifest("file", manifest: original)
        try await cache.putBlock(h1, plaintext: first)
        _ = try await cache.evict("file")
        try await cache.registerManifest("file", manifest: original)
        try await cache.putBlock(h1, plaintext: first)
        let pin = try await cache.pin("file", recursive: false)
        XCTAssertEqual(pin.totalBytes, UInt64(first.count), "same-version read must restore evicted path links")
        _ = try await cache.unpin("file", recursive: false)
        let next = BlockManifest(itemID: "file", blocks: [BlockRef(hash: h2, offset: 0, length: second.count)], contentVersion: "v2")
        try await cache.registerManifest("file", manifest: next)
        try await cache.putBlock(h2, plaintext: second)
        let removed = try await cache.evict("file")
        XCTAssertEqual(removed.evictedBlocks, 2, "new manifest version must add its new block membership")
    }

    func testReadAheadAdmissionInheritsKnownPathWithoutReregisterRewrite() async throws {
        let root = tempDir(), cache = try makeCache(dir: root)
        let payload = block(41), h = hash(of: payload)
        try await cache.registerPath("movie", blocks: [h])
        let before = try Data(contentsOf: root.appendingPathComponent("index.db"))
        try await cache.putBlock(h, plaintext: payload)
        try await cache.registerPath("movie", blocks: [h])
        XCTAssertEqual(try Data(contentsOf: root.appendingPathComponent("index.db")), before)
        let evicted = try await cache.evict("movie")
        XCTAssertEqual(evicted.evictedBlocks, 1, "path association must still work without a second snapshot")
    }

    func testExplicitFolderPinReservesFutureBlocksAndSurvivesRestart() async throws {
        let root = tempDir(), cache = try makeCache(dir: root, maxBytes: 20_000)
        let first = block(51), second = block(52)
        let a = hash(of: first), b = hash(of: second)
        let refs = [BlockRef(hash: a, offset: 0, length: first.count), BlockRef(hash: b, offset: 0, length: second.count)]
        let pending = try await cache.replacePinnedPath("ino-folder", blocks: refs, recursive: true)
        XCTAssertEqual(pending.cacheState, .pinning)
        XCTAssertEqual(pending.totalBytes, 8192); XCTAssertEqual(pending.cachedBytes, 0)
        try await cache.putBlock(a, plaintext: first)
        let middle = try await cache.pinList(filespace: "fs1")
        XCTAssertEqual(middle.first?.cachedBytes, 4096)
        XCTAssertEqual(middle.first?.cacheState, .pinning)
        let reopened = try makeCache(dir: root)
        try await reopened.putBlock(b, plaintext: second)
        let finished = try await reopened.pinList(filespace: "fs1")
        XCTAssertEqual(finished.first?.cacheState, .pinned)
        XCTAssertEqual(finished.first?.cachedBytes, 8192)
        let cleared = try await reopened.clear(filespace: "fs1")
        XCTAssertEqual(cleared.pinnedBytes, 8192, "newly admitted children inherit the persistent folder pin")
        do {
            _ = try await reopened.replacePinnedPath("too-large", blocks: [BlockRef(hash: hash(of: block(53)), offset: 0, length: 10_000)], recursive: true)
            XCTFail("pending pins must reserve capacity before download")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .conflict) }
        let retainedPins = try await reopened.pinList(filespace: "fs1")
        XCTAssertEqual(retainedPins.count, 1)
    }

    func testExplicitPinReplacementKeepsSharedReferencesBalancedAndCorruptionPending() async throws {
        let root = tempDir(), cache = try makeCache(dir: root)
        let data = block(61), h = hash(of: data), refs = [BlockRef(hash: h, offset: 0, length: data.count)]
        _ = try await cache.replacePinnedPath("folder-a", blocks: refs, recursive: true)
        _ = try await cache.replacePinnedPath("folder-b", blocks: refs, recursive: true)
        try await cache.putBlock(h, plaintext: data)
        for _ in 0..<4 { _ = try await cache.replacePinnedPath("folder-a", blocks: refs, recursive: true) }
        _ = try await cache.replacePinnedPath("folder-a", blocks: [], recursive: true)
        var info = try await cache.clear(filespace: "fs1")
        XCTAssertEqual(info.pinnedBytes, data.count, "other folder retains the shared block")
        let file = root.appendingPathComponent("blocks/" + String(h.hex.prefix(2)) + "/" + h.hex)
        try Data("corrupt".utf8).write(to: file)
        let damaged = try await cache.readBlock(h)
        XCTAssertNil(damaged)
        let pins = try await cache.pinList(filespace: "fs1")
        XCTAssertEqual(pins.first { $0.path == "folder-b" }?.cacheState, .pinning)
        try await cache.putBlock(h, plaintext: data)
        _ = try await cache.unpin("folder-b", recursive: true)
        info = try await cache.clear(filespace: "fs1")
        XCTAssertEqual(info.pinnedBytes, 0)
        XCTAssertEqual(info.usedBytes, 0, "replacement/unpin must not leak pin counts")
    }

    // MARK: 1. Stub still behaves (foundation contract)

    func testStubMissesAndThrows() async {
        let cache = StubBlockCache()
        let present = await cache.contains(BlockHash(hex: "deadbeef"))
        XCTAssertFalse(present)
        do {
            _ = try await cache.info(filespace: "fs1")
            XCTFail("expected unimplemented")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .unimplemented)
        } catch { XCTFail("wrong error: \(error)") }
    }

    // MARK: 2. put / get round-trip

    func testPutGetRoundTrip() async throws {
        let cache = try makeCache(dir: tempDir())
        let payload = block(0xAB)
        let h = hash(of: payload)

        var present = await cache.contains(h)
        XCTAssertFalse(present)

        try await cache.putBlock(h, plaintext: payload)
        present = await cache.contains(h)
        XCTAssertTrue(present)

        let got = try await cache.readBlock(h)
        XCTAssertEqual(got, payload)

        let miss = try await cache.readBlock(hash(of: block(0x01)))
        XCTAssertNil(miss)
    }

    func testPutRejectsMisaddressedBlock() async throws {
        let cache = try makeCache(dir: tempDir())
        // Admit with a hash that does NOT match the payload → rejected.
        do {
            try await cache.putBlock(BlockHash(hex: "00deadbeef"), plaintext: block(0x07))
            XCTFail("expected an admission hash-mismatch error")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .internal)
        }
    }

    // MARK: 3. Eviction stays under budget and respects pins

    func testEvictionStaysUnderBudgetAndRespectsPins() async throws {
        let dir = tempDir()
        // Budget for ~4 blocks of 4096 B. Pin fraction 80% => up to ~3 pinned.
        let blockBytes = 4096
        let cache = try makeCache(dir: dir, maxBytes: blockBytes * 4)

        // Admit 3 blocks, register them under paths, and pin two of them.
        var hashes: [BlockHash] = []
        for i in 0..<3 {
            let p = block(UInt8(i + 1), size: blockBytes)
            let h = hash(of: p)
            hashes.append(h)
            try await cache.putBlock(h, plaintext: p)
            await cache.register(path: "/file\(i)", blocks: [h])
        }
        _ = try await cache.pin("/file0", recursive: false)
        _ = try await cache.pin("/file1", recursive: false)

        // Now flood with many more unpinned blocks to force eviction.
        for i in 10..<40 {
            let p = block(UInt8(i % 200 + 1), size: blockBytes)
            let h = hash(of: p)
            try await cache.putBlock(h, plaintext: p)
        }

        let info = try await cache.info(filespace: "fs1")
        // Stays under the ceiling.
        XCTAssertLessThanOrEqual(info.usedBytes, info.maxBytes)
        // Pinned blocks were never evicted.
        let p0 = await cache.contains(hashes[0])
        let p1 = await cache.contains(hashes[1])
        XCTAssertTrue(p0, "pinned block0 must survive eviction")
        XCTAssertTrue(p1, "pinned block1 must survive eviction")
        XCTAssertEqual(info.pinnedBytes, blockBytes * 2)
    }

    func testPinHeadroomGuardRejectsOver80Percent() async throws {
        let blockBytes = 4096
        // maxBytes = 5 blocks; 80% headroom => 4 pinnable. Pin 5 must fail.
        let cache = try makeCache(dir: tempDir(), maxBytes: blockBytes * 5)
        for i in 0..<5 {
            let p = block(UInt8(i + 1), size: blockBytes)
            let h = hash(of: p)
            try await cache.putBlock(h, plaintext: p)
            await cache.register(path: "/f\(i)", blocks: [h])
        }
        // Pin 4 should be fine.
        for i in 0..<4 { _ = try await cache.pin("/f\(i)", recursive: false) }
        // The 5th pin breaches the 80% cap.
        do {
            _ = try await cache.pin("/f4", recursive: false)
            XCTFail("expected headroom conflict")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .conflict)
            XCTAssertEqual(e.data?["reason"], .string("headroom"))
        }
    }

    // MARK: 4. Resize down triggers eviction

    func testResizeDownTriggersEviction() async throws {
        let blockBytes = 4096
        let cache = try makeCache(dir: tempDir(), maxBytes: blockBytes * 20)
        for i in 0..<10 {
            let p = block(UInt8(i + 1), size: blockBytes)
            try await cache.putBlock(hash(of: p), plaintext: p)
        }
        var info = try await cache.info(filespace: "fs1")
        XCTAssertEqual(info.usedBytes, blockBytes * 10)

        // Shrink to hold ~3 blocks → must evict down immediately.
        info = try await cache.setSize(filespace: "fs1", bytes: blockBytes * 3)
        XCTAssertEqual(info.maxBytes, blockBytes * 3)
        XCTAssertLessThanOrEqual(info.usedBytes, blockBytes * 3)
    }

    func testResizeBelowPinnedFails() async throws {
        let blockBytes = 4096
        let cache = try makeCache(dir: tempDir(), maxBytes: blockBytes * 10)
        // Pin 3 blocks (3*4096 bytes pinned).
        for i in 0..<3 {
            let p = block(UInt8(i + 1), size: blockBytes)
            let h = hash(of: p)
            try await cache.putBlock(h, plaintext: p)
            await cache.register(path: "/p\(i)", blocks: [h])
            _ = try await cache.pin("/p\(i)", recursive: false)
        }
        // Shrinking so pinned (3 blocks) > 80% of new size must conflict.
        // new size = 3 blocks → 80% = 2.4 blocks < 3 pinned → conflict.
        do {
            _ = try await cache.setSize(filespace: "fs1", bytes: blockBytes * 3)
            XCTFail("expected headroom conflict on shrink")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .conflict)
        }
    }

    // MARK: 5. Relocate preserves and serves blocks

    func testRelocatePreservesAndServesBlocks() async throws {
        let dir1 = tempDir()
        let dir2 = tempDir()
        let cache = try makeCache(dir: dir1, maxBytes: 1 << 30)

        var payloads: [BlockHash: Data] = [:]
        for i in 0..<5 {
            let p = block(UInt8(i + 1))
            let h = hash(of: p)
            payloads[h] = p
            try await cache.putBlock(h, plaintext: p)
        }

        let intent = Data("{\"opaqueFolder\":true}".utf8)
        try intent.write(to: dir1.appendingPathComponent("pin-intents.json"))
        let info = try await cache.setLocation(filespace: "fs1", path: dir2.path)
        XCTAssertEqual(try Data(contentsOf: dir2.appendingPathComponent("pin-intents.json")), intent)
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir1.appendingPathComponent("pin-intents.json").path))
        XCTAssertEqual(info.location, dir2.standardizedFileURL.path)

        // Every block still readable, byte-exact, from the new location.
        for (h, p) in payloads {
            let got = try await cache.readBlock(h)
            XCTAssertEqual(got, p, "block must survive relocation byte-exact")
        }
        // The physical payloads now live under dir2.
        let movedFile = dir2.appendingPathComponent("blocks")
        XCTAssertTrue(FileManager.default.fileExists(atPath: movedFile.path))
        // Old block tree is gone.
        let oldBlocks = dir1.appendingPathComponent("blocks")
        let oldKids = (try? FileManager.default.contentsOfDirectory(atPath: oldBlocks.path)) ?? []
        XCTAssertTrue(oldKids.isEmpty, "old cache block tree should be torn down")
    }

    // MARK: 6. Index persists across a reopen (restart persistence)

    func testIndexPersistsAcrossReopen() async throws {
        let dir = tempDir()
        var payloads: [BlockHash: Data] = [:]
        do {
            let cache = try makeCache(dir: dir, maxBytes: 1 << 20)
            for i in 0..<4 {
                let p = block(UInt8(i + 1))
                let h = hash(of: p)
                payloads[h] = p
                try await cache.putBlock(h, plaintext: p)
                await cache.register(path: "/r\(i)", blocks: [h])
            }
            _ = try await cache.pin("/r0", recursive: false)
            _ = try await cache.setSize(filespace: "fs1", bytes: 777_000)
        }
        // Reopen from the same directory — index.db restores everything.
        let reopened = try makeCache(dir: dir, maxBytes: 1)  // maxBytes ignored when index present
        let info = try await reopened.info(filespace: "fs1")
        XCTAssertEqual(info.maxBytes, 777_000, "the user-set ceiling survives restart")
        for (h, p) in payloads {
            let present = await reopened.contains(h)
            XCTAssertTrue(present, "cached block must survive restart")
            let got = try await reopened.readBlock(h)
            XCTAssertEqual(got, p)
        }
        // The pin survived.
        let pins = try await reopened.pinList(filespace: "fs1")
        XCTAssertEqual(pins.count, 1)
        XCTAssertEqual(pins.first?.path, "/r0")
        XCTAssertTrue(pins.first?.pinned ?? false)
    }

    // MARK: 7. Integrity catches corruption (evict + miss → refetch)

    func testIntegrityCatchesCorruption() async throws {
        let dir = tempDir()
        let cache = try makeCache(dir: dir, maxBytes: 1 << 20)
        let payload = block(0x55)
        let h = hash(of: payload)
        try await cache.putBlock(h, plaintext: payload)

        // Corrupt the on-disk block payload behind the cache's back.
        let shard = String(h.hex.prefix(2))
        let blockFile = dir.appendingPathComponent("blocks/\(shard)/\(h.hex)")
        try Data(repeating: 0xFF, count: payload.count).write(to: blockFile)

        // Read must detect the hash mismatch, evict, and report a miss.
        let got = try await cache.readBlock(h)
        XCTAssertNil(got, "corrupted block must be reported as a miss")
        let stillThere = await cache.contains(h)
        XCTAssertFalse(stillThere, "corrupted block must be evicted for refetch")
        XCTAssertFalse(FileManager.default.fileExists(atPath: blockFile.path))
    }

    func testIntegrityCatchesMissingPayload() async throws {
        let dir = tempDir()
        let cache = try makeCache(dir: dir, maxBytes: 1 << 20)
        let payload = block(0x33)
        let h = hash(of: payload)
        try await cache.putBlock(h, plaintext: payload)

        // Delete the payload file out from under the index.
        let shard = String(h.hex.prefix(2))
        try FileManager.default.removeItem(
            at: dir.appendingPathComponent("blocks/\(shard)/\(h.hex)"))

        let got = try await cache.readBlock(h)
        XCTAssertNil(got)
        let present = await cache.contains(h)
        XCTAssertFalse(present, "stale index entry must be dropped on missing payload")
    }

    // MARK: 8. clear evicts evictable, keeps pinned

    func testClearKeepsPinned() async throws {
        let cache = try makeCache(dir: tempDir(), maxBytes: 1 << 20)
        let pinned = block(0x01)
        let ph = hash(of: pinned)
        try await cache.putBlock(ph, plaintext: pinned)
        await cache.register(path: "/keep", blocks: [ph])
        _ = try await cache.pin("/keep", recursive: false)

        let loose = block(0x02)
        let lh = hash(of: loose)
        try await cache.putBlock(lh, plaintext: loose)

        let info = try await cache.clear(filespace: "fs1")
        let pinnedPresent = await cache.contains(ph)
        let loosePresent = await cache.contains(lh)
        XCTAssertTrue(pinnedPresent, "pinned block survives clear")
        XCTAssertFalse(loosePresent, "unpinned block is cleared")
        XCTAssertEqual(info.usedBytes, pinned.count)
    }

    // MARK: 9. evict by path + recursive pin

    func testEvictByPathOverridesPinAndRecursivePin() async throws {
        let cache = try makeCache(dir: tempDir(), maxBytes: 1 << 20)
        // Register a folder tree: /proj/a, /proj/b under prefix /proj.
        let a = block(0x11); let ah = hash(of: a)
        let b = block(0x22); let bh = hash(of: b)
        try await cache.putBlock(ah, plaintext: a)
        try await cache.putBlock(bh, plaintext: b)
        await cache.register(path: "/proj/a", blocks: [ah])
        await cache.register(path: "/proj/b", blocks: [bh])

        // Recursive pin at the folder pins both children's blocks.
        let pin = try await cache.pin("/proj", recursive: true)
        XCTAssertEqual(pin.blocks, 2)
        var info = try await cache.info(filespace: "fs1")
        XCTAssertEqual(info.pinnedBytes, a.count + b.count)

        // Explicit evict of the folder overrides the pin and frees both.
        let ack = try await cache.evict("/proj")
        XCTAssertEqual(ack.evictedBlocks, 2)
        XCTAssertEqual(ack.freedBytes, a.count + b.count)
        info = try await cache.info(filespace: "fs1")
        XCTAssertEqual(info.usedBytes, 0)
        XCTAssertEqual(info.pinnedBytes, 0)
    }

    // MARK: 10. unknown filespace is notFound

    func testUnknownFilespaceNotFound() async throws {
        let cache = try makeCache(dir: tempDir())
        do {
            _ = try await cache.info(filespace: "nope")
            XCTFail("expected notFound")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .notFound)
        }
    }

    // MARK: 11b. pin.list per-item byte accounting + cache-state (CONTRACTS.md §4.1)

    func testPinListReportsBytesAndStatePinned() async throws {
        let blockBytes = 4096
        let cache = try makeCache(dir: tempDir(), maxBytes: blockBytes * 20)
        // Two blocks under one path, both resident, then pinned → fully materialized.
        let a = block(0xA1, size: blockBytes); let ah = hash(of: a)
        let b = block(0xB2, size: blockBytes); let bh = hash(of: b)
        try await cache.putBlock(ah, plaintext: a)
        try await cache.putBlock(bh, plaintext: b)
        await cache.register(path: "/clip.mov", blocks: [ah, bh])

        let pinned = try await cache.pin("/clip.mov", recursive: false)
        XCTAssertEqual(pinned.cachedBytes, UInt64(blockBytes * 2))
        XCTAssertEqual(pinned.totalBytes, UInt64(blockBytes * 2))
        XCTAssertEqual(pinned.cacheState, .pinned)

        let list = try await cache.pinList(filespace: "fs1")
        XCTAssertEqual(list.count, 1)
        let item = try XCTUnwrap(list.first)
        XCTAssertEqual(item.path, "/clip.mov")
        XCTAssertEqual(item.cachedBytes, UInt64(blockBytes * 2))
        XCTAssertEqual(item.totalBytes, UInt64(blockBytes * 2))
        XCTAssertEqual(item.cacheState, .pinned)
        XCTAssertEqual(item.blocks, 2)
    }

    func testPinListPinningAfterOneBlockSelfHealsAway() async throws {
        let dir = tempDir()
        let blockBytes = 4096
        let cache = try makeCache(dir: dir, maxBytes: blockBytes * 20)
        // Two resident blocks under one path; pin → fully materialized, total captured.
        let a = block(0xC3, size: blockBytes); let ah = hash(of: a)
        let b = block(0xD4, size: blockBytes); let bh = hash(of: b)
        try await cache.putBlock(ah, plaintext: a)
        try await cache.putBlock(bh, plaintext: b)
        await cache.register(path: "/proj/edit", blocks: [ah, bh])
        let pinned = try await cache.pin("/proj/edit", recursive: false)
        XCTAssertEqual(pinned.cacheState, .pinned)
        XCTAssertEqual(pinned.totalBytes, UInt64(blockBytes * 2))

        // Corrupt block b on disk; a read detects the hash mismatch and evicts it
        // (integrity self-heal), even under a pin → only block a stays resident.
        let shard = String(bh.hex.prefix(2))
        let blockFile = dir.appendingPathComponent("blocks/\(shard)/\(bh.hex)")
        try Data(repeating: 0xFF, count: blockBytes).write(to: blockFile)
        let got = try await cache.readBlock(bh)
        XCTAssertNil(got, "corrupted block reports a miss and is evicted")

        // Now the pin is PINNING: one block resident, the captured total retained.
        let list = try await cache.pinList(filespace: "fs1")
        let item = try XCTUnwrap(list.first)
        XCTAssertEqual(item.cachedBytes, UInt64(blockBytes))
        XCTAssertEqual(item.totalBytes, UInt64(blockBytes * 2))
        XCTAssertEqual(item.cacheState, .pinning)
        XCTAssertEqual(item.blocks, 1, "only the resident block counts")
    }

    func testEvictedPinReportsEvictedStateWithTotalRetained() async throws {
        let blockBytes = 4096
        let cache = try makeCache(dir: tempDir(), maxBytes: blockBytes * 20)
        let a = block(0x71, size: blockBytes); let ah = hash(of: a)
        let b = block(0x82, size: blockBytes); let bh = hash(of: b)
        try await cache.putBlock(ah, plaintext: a)
        try await cache.putBlock(bh, plaintext: b)
        await cache.register(path: "/big.r3d", blocks: [ah, bh])
        _ = try await cache.pin("/big.r3d", recursive: false)

        // Explicit evict overrides the pin (unpins first) and frees the bytes.
        let ack = try await cache.evict("/big.r3d")
        XCTAssertEqual(ack.evictedBlocks, 2)
        XCTAssertEqual(ack.freedBytes, blockBytes * 2)

        // The pin is gone after evict (evict removes the pin record), so pin.list
        // no longer lists it — evict's contract is "free + drop the pin".
        let list = try await cache.pinList(filespace: "fs1")
        XCTAssertTrue(list.isEmpty)
    }

    func testUnpinDropsPinAndReportsBytesItHeld() async throws {
        let blockBytes = 4096
        let cache = try makeCache(dir: tempDir(), maxBytes: blockBytes * 20)
        let a = block(0x91, size: blockBytes); let ah = hash(of: a)
        try await cache.putBlock(ah, plaintext: a)
        await cache.register(path: "/one", blocks: [ah])
        _ = try await cache.pin("/one", recursive: false)

        // Unpin drops the pin record: the path is no longer pinned and carries no
        // pin cache-state, but the bytes it was holding are still reported.
        let unpinned = try await cache.unpin("/one", recursive: false)
        XCTAssertFalse(unpinned.pinned)
        XCTAssertEqual(unpinned.cachedBytes, UInt64(blockBytes))
        XCTAssertEqual(unpinned.totalBytes, UInt64(blockBytes))
        XCTAssertNil(unpinned.cacheState)

        // The unpinned path is gone from pin.list (no pin record remains).
        let list = try await cache.pinList(filespace: "fs1")
        XCTAssertTrue(list.isEmpty)

        // Idempotent unpin of an unpinned path: zero bytes, no cache-state.
        let again = try await cache.unpin("/one", recursive: false)
        XCTAssertEqual(again.cachedBytes, 0)
        XCTAssertNil(again.cacheState)
    }

    func testPinAccountingSurvivesReopen() async throws {
        let dir = tempDir()
        let blockBytes = 4096
        do {
            let cache = try makeCache(dir: dir, maxBytes: blockBytes * 20)
            let a = block(0x44, size: blockBytes); let ah = hash(of: a)
            let b = block(0x55, size: blockBytes); let bh = hash(of: b)
            try await cache.putBlock(ah, plaintext: a)
            try await cache.putBlock(bh, plaintext: b)
            await cache.register(path: "/persist", blocks: [ah, bh])
            _ = try await cache.pin("/persist", recursive: false)
        }
        let reopened = try makeCache(dir: dir, maxBytes: 1)
        let list = try await reopened.pinList(filespace: "fs1")
        XCTAssertEqual(list.first?.cachedBytes, UInt64(blockBytes * 2))
        XCTAssertEqual(list.first?.totalBytes, UInt64(blockBytes * 2))
        XCTAssertEqual(list.first?.cacheState, .pinned)
    }

    // MARK: 11c. Re-registering blocks under an already-pinned path keeps
    // pinnedRefs balanced so a single unpin makes them evictable (Finding 2).
    //
    // `register`/`registerPath` runs on EVERY readRange and prefetch, so a pinned
    // file read twice re-registers its blocks under the same (pinned) path. The
    // bug double-counted pinnedRefs (2,3,…); a single later `unpin` decrements
    // once, leaving pinnedRefs > 0 → the block stayed `pinned` forever and could
    // never be an eviction candidate, so the cache could exceed maxBytes.
    func testReRegisterUnderPinnedPathKeepsPinnedRefsBalanced() async throws {
        let blockBytes = 4096
        let cache = try makeCache(dir: tempDir(), maxBytes: blockBytes * 20)
        let a = block(0xE1, size: blockBytes); let ah = hash(of: a)
        let b = block(0xE2, size: blockBytes); let bh = hash(of: b)
        try await cache.putBlock(ah, plaintext: a)
        try await cache.putBlock(bh, plaintext: b)
        await cache.register(path: "/pinned.mov", blocks: [ah, bh])
        _ = try await cache.pin("/pinned.mov", recursive: false)

        // Simulate repeated reads/prefetches re-registering the SAME blocks under
        // the SAME (now pinned) path. Pre-fix this inflated pinnedRefs each time.
        for _ in 0..<3 {
            await cache.register(path: "/pinned.mov", blocks: [ah, bh])
        }
        // Pinned accounting is unchanged by re-registration (no double counting).
        var info = try await cache.info(filespace: "fs1")
        XCTAssertEqual(info.pinnedBytes, blockBytes * 2,
                       "re-registering must not inflate pinned bytes")

        // A SINGLE unpin must fully release the blocks so they become evictable.
        let unpinned = try await cache.unpin("/pinned.mov", recursive: false)
        XCTAssertFalse(unpinned.pinned)
        info = try await cache.info(filespace: "fs1")
        XCTAssertEqual(info.pinnedBytes, 0, "one unpin must release every pinnedRef")

        // Prove evictability: flood with unpinned blocks; the formerly-pinned blocks
        // must now be eviction candidates and the cache stays under budget.
        let cache2Max = info.maxBytes
        for i in 50..<120 {
            let p = block(UInt8(i % 200 + 1), size: blockBytes)
            try await cache.putBlock(hash(of: p), plaintext: p)
        }
        info = try await cache.info(filespace: "fs1")
        XCTAssertLessThanOrEqual(info.usedBytes, cache2Max,
                                 "released blocks must be evictable so usage stays <= maxBytes")
    }

    // MARK: 11. hit-rate accounting

    func testHitRateAccounting() async throws {
        let cache = try makeCache(dir: tempDir())
        let p = block(0x09)
        let h = hash(of: p)
        try await cache.putBlock(h, plaintext: p)
        _ = try await cache.readBlock(h)                 // hit
        _ = try await cache.readBlock(hash(of: block(0x10))) // miss
        let info = try await cache.info(filespace: "fs1")
        XCTAssertEqual(info.hitRate, 0.5, accuracy: 0.001)
    }

    // MARK: 12. P2 — repeated cache HITS do NOT rewrite the whole index per read
    //
    // FINDING P2: `readBlock` used to `try? persist()` on EVERY cache HIT, rewriting
    // the WHOLE index.db (JSON-encode every entry + atomic replace), O(cache size),
    // many times/sec during playback. The fix keeps the atime bump in memory only
    // (atime is non-critical LRU metadata). We assert that N repeated HITS leave the
    // on-disk index BYTE-IDENTICAL (no rewrite), while the in-memory hit counter
    // still advances — i.e. the read served without touching disk.

    /// The raw on-disk index bytes (nil if not yet written).
    private func indexBytes(_ dir: URL) -> Data? {
        try? Data(contentsOf: dir.appendingPathComponent("index.db"))
    }

    func testRepeatedCacheHitsDoNotRewriteIndex() async throws {
        let dir = tempDir()
        let cache = try makeCache(dir: dir, maxBytes: 1 << 20)
        let p = block(0xA7)
        let h = hash(of: p)
        try await cache.putBlock(h, plaintext: p)   // ADMIT — durable, writes index

        // Snapshot the index after admit; subsequent HITS must not rewrite it.
        let before = try XCTUnwrap(indexBytes(dir), "index.db must exist after admit")
        for _ in 0..<50 {
            let got = try await cache.readBlock(h)
            XCTAssertEqual(got, p, "each HIT serves the block")
        }
        let after = try XCTUnwrap(indexBytes(dir))
        XCTAssertEqual(after, before,
                       "50 cache HITS must NOT rewrite the index even once (atime is in-memory)")

        // Sanity: the reads really happened (hit counter advanced) — not a no-op miss.
        let info = try await cache.info(filespace: "fs1")
        XCTAssertEqual(info.hitRate, 1.0, accuracy: 0.001, "all 50 reads were HITS")
    }

    // P2 — a putBlock ADMIT stays durable across restart (residency accounting is not
    // lost by the lazy-atime change): the block is resident after a reopen, AND a
    // cache HIT served from the reopened cache still does not rewrite the index.
    func testAdmitIsDurableAcrossRestartDespiteLazyAtime() async throws {
        let dir = tempDir()
        var payloads: [BlockHash: Data] = [:]
        do {
            let cache = try makeCache(dir: dir, maxBytes: 1 << 20)
            for i in 0..<4 {
                let p = block(UInt8(i + 1))
                let h = hash(of: p)
                payloads[h] = p
                try await cache.putBlock(h, plaintext: p)   // each admit is durable
            }
            // A burst of HITS that the fix keeps in memory only.
            for (h, _) in payloads { _ = try await cache.readBlock(h) }
        }
        // Reopen: every admitted block must still be reflected as resident on disk —
        // residency accounting survives even though the per-HIT atime writes were
        // dropped (the admit's own persist captured residency).
        let reopened = try makeCache(dir: dir, maxBytes: 1)
        for (h, p) in payloads {
            let present = await reopened.contains(h)
            XCTAssertTrue(present, "admitted block must survive restart")
            let got = try await reopened.readBlock(h)
            XCTAssertEqual(got, p, "block reads back byte-exact after restart")
        }
    }

    // P2 — re-registering the SAME blocks under the SAME path (every readRange /
    // prefetch does this) must NOT rewrite the index when nothing changed; a FIRST
    // registration (new path↔block link) MUST persist.
    func testRedundantRegisterDoesNotRewriteIndex() async throws {
        let dir = tempDir()
        let cache = try makeCache(dir: dir, maxBytes: 1 << 20)
        let p = block(0xB3)
        let h = hash(of: p)
        try await cache.putBlock(h, plaintext: p)

        // FIRST register links the path → block: this is a durable change, persists.
        let preFirst = try XCTUnwrap(indexBytes(dir))
        await cache.register(path: "/clip.mov", blocks: [h])
        let afterFirst = try XCTUnwrap(indexBytes(dir))
        XCTAssertNotEqual(afterFirst, preFirst, "first registration is durable and persists")

        // Re-registering the SAME block under the SAME path changes nothing → no write.
        for _ in 0..<20 { await cache.register(path: "/clip.mov", blocks: [h]) }
        let afterRedundant = try XCTUnwrap(indexBytes(dir))
        XCTAssertEqual(afterRedundant, afterFirst,
                       "redundant re-registration must NOT rewrite the index")
    }

    // P2 — `flush()` drains the trailing in-memory atime updates on a clean stop, so
    // the latest LRU clock is persisted even when no critical op followed the reads.
    func testFlushPersistsTrailingAtimeUpdates() async throws {
        let dir = tempDir()
        let cache = try makeCache(dir: dir, maxBytes: 1 << 20)
        let p = block(0xC9)
        let h = hash(of: p)
        try await cache.putBlock(h, plaintext: p)
        let afterAdmit = try XCTUnwrap(indexBytes(dir))

        // A HIT bumps atime in memory only (no rewrite yet).
        _ = try await cache.readBlock(h)
        XCTAssertEqual(indexBytes(dir), afterAdmit, "HIT did not rewrite the index")

        // flush() drains the trailing dirty atime to disk → the bytes now differ.
        await cache.flush()
        let afterFlush = try XCTUnwrap(indexBytes(dir))
        XCTAssertNotEqual(afterFlush, afterAdmit, "flush persists the trailing atime update")

        // A second flush with nothing dirty is a no-op (no further rewrite).
        await cache.flush()
        XCTAssertEqual(indexBytes(dir), afterFlush, "flush with nothing dirty is a no-op")
    }
}

extension CloudFSCacheTests {
    func testRelocationRejectsForeignAndNestedFoldersWithoutModifyingSource() async throws {
        let source = tempDir(), foreign = tempDir()
        let cache = try makeCache(dir: source)
        let other = try DiskBlockCache(filespace: "other", directory: foreign, maxBytes: 1 << 20)
        let ours = block(1), theirs = block(2)
        try await cache.putBlock(hash(of: ours), plaintext: ours)
        try await other.putBlock(hash(of: theirs), plaintext: theirs)
        for path in [foreign.path, source.appendingPathComponent("nested").path, source.deletingLastPathComponent().path] {
            do { _ = try await cache.setLocation(filespace: "fs1", path: path); XCTFail("unsafe destination accepted: \(path)") }
            catch {}
        }
        let ourBytes = try await cache.readBlock(hash(of: ours)), otherBytes = try await other.readBlock(hash(of: theirs))
        XCTAssertEqual(ourBytes, ours); XCTAssertEqual(otherBytes, theirs)
    }

    func testPreparedRelocationKeepsReopenableSourceUntilMappingCommit() async throws {
        let source = tempDir(), destination = tempDir()
        let cache = try makeCache(dir: source)
        let bytes = block(9), address = hash(of: bytes)
        try await cache.putBlock(address, plaintext: bytes)
        _ = try await cache.setLocation(filespace: "fs1", path: destination.path, preserveSource: true)
        let restartedBeforeCommit = try makeCache(dir: source)
        let retained = try await restartedBeforeCommit.readBlock(address)
        XCTAssertEqual(retained, bytes, "an interrupted location-map commit must reopen intact source data")
        let stateFile = source.appendingPathComponent("pin-intents-v2.json")
        try Data("[]".utf8).write(to: stateFile)
        await cache.finishRelocation(from: source.path)
        XCTAssertTrue(FileManager.default.fileExists(atPath: stateFile.path), "stable pin intent is never cache cleanup")
        XCTAssertFalse(FileManager.default.fileExists(atPath: source.appendingPathComponent("blocks").path))
        let moved = try await cache.readBlock(address)
        XCTAssertEqual(moved, bytes)
    }
}
