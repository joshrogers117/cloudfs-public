// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
import CloudFSTransfer
@testable import cloudfsd

final class OfflineCheckpointTests: XCTestCase {
    func testRestartEnumeratesUnopenedPinnedFileAndReadsRandomRangesAndForksWithoutNetwork() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("offline-test-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: dir) }
        let key = Data((0..<32).map(UInt8.init)), crypto = try AESGCMBlockCrypto(masterKeyBytes: key)
        let cache = try DiskBlockCache(filespace: "fs", directory: dir.appendingPathComponent("cache"), maxBytes: 1 << 24, blockSize: 1 << 20)
        let bytes = Data((0..<8192).map { UInt8($0 % 251) }), file: InodeID = "file"
        var refs: [BlockRef] = []
        for index in 0..<2 {
            let cipher = try await crypto.encryptBlock(bytes[(index*4096)..<((index+1)*4096)], itemID: file, blockIndex: index)
            try await cache.putBlock(cipher.hash, plaintext: cipher.ciphertext)
            refs.append(BlockRef(hash: cipher.hash, offset: index*4096, length: 4096))
        }
        let forkBytes = Data("fork123".utf8), streamName = "AFP_Resource"
        let fork = try await crypto.encryptBlock(forkBytes, itemID: ChunkedStreamStore.cryptoIdentity(file,name:streamName), blockIndex: 4)
        try await cache.putBlock(fork.hash, plaintext: fork.ciphertext)
        let legacy = try await crypto.encryptBlock(Data("finder".utf8), itemID: file, blockIndex: ChunkedStreamStore.legacyIndex("AFP_AfpInfo"))
        let directory = ItemMetadata(id: "folder", parent: .root, name: "Projects", isDir: true, size: 0, contentVersion: "d", metadataVersion: "1")
        let metadata = ItemMetadata(id: file, parent: "folder", name: "cold.mov", isDir: false, size: bytes.count, contentVersion: "v1", metadataVersion: "1")
        let now = Date(), checkpoint = OfflineCheckpoint(format: 1, identity: "account", filespace: "fs", path: "Projects",
            roots: [FilespaceMountRoot(id:"folder",name:"Projects",mountAsRoot:true)], createdAt: now, expiresAt: now.addingTimeInterval(3600), anchor: 5, visibility: "visibility",
            entries: [OfflineEntry(item: directory, manifest: nil, streams: [:]), OfflineEntry(item: metadata,
                manifest: BlockManifest(itemID:file,blocks:refs,contentVersion:"v1"), streams: [streamName:OfflineStream(size:4*(1<<20)+7,blocks:[StreamBlock(index:4,hash:fork.hash.hex,length:7,objectKey:"blocks/"+fork.hash.hex)],inlineCiphertext:nil),
                    "AFP_AfpInfo":OfflineStream(size:6,blocks:[],inlineCiphertext:legacy.ciphertext)])])
        try await checkpoint.save(directory: dir, crypto: crypto); await cache.flush()
        let restored = try await OfflineCheckpoint.load(directory: dir,path:"Projects",identity:"account",crypto:crypto)
        let reopened = try DiskBlockCache(filespace:"fs",directory:dir.appendingPathComponent("cache"),maxBytes:1<<24,blockSize:1<<20)
        let view = OfflineDataPath(checkpoint:restored,cache:reopened,crypto:crypto,fileURL:OfflineCheckpoint.url(directory:dir,path:"Projects"),spillDir:dir.appendingPathComponent("spill").path)
        let children = try await view.enumerate(container:"folder",page:nil)
        XCTAssertEqual(children.items.map(\.name),["cold.mov"]); XCTAssertNil(children.nextPage)
        let middle = try await view.readBytes(file,version:"v1",offset:4000,length:200); XCTAssertEqual(middle,bytes[4000..<4200])
        let tail = try await view.readBytes(file,version:"v1",offset:8000,length:300); XCTAssertEqual(tail,bytes[8000..<8192])
        let forkRead = try await view.readStreamRange(file,name:streamName,offset:4*(1<<20)-3,length:10); XCTAssertEqual(forkRead,Data(repeating:0,count:3)+forkBytes)
        let legacyRead = try await view.readStream(file,name:"AFP_AfpInfo"); XCTAssertEqual(legacyRead,Data("finder".utf8))
        do { _ = try await view.writeRange(file,offset:0,data:Data([1]),baseVersion:"1"); XCTFail("offline write") }
        catch let e as EngineError { XCTAssertEqual(e.kind,.permissionDenied) }
        do { _ = try await OfflineCheckpoint.load(directory:dir,path:"Projects",identity:"another-account",crypto:crypto); XCTFail("identity crossed") } catch {}
        do { _ = try await OfflineCheckpoint.load(directory:dir,path:"Projects",identity:"account",crypto:crypto,now:now.addingTimeInterval(3601)); XCTFail("expired copy") } catch {}
        let encrypted = try Data(contentsOf:OfflineCheckpoint.url(directory:dir,path:"Projects"))
        XCTAssertNil(encrypted.range(of:Data("cold.mov".utf8)))
        try FileManager.default.removeItem(at:OfflineCheckpoint.url(directory:dir,path:"Projects"))
        do { _ = try await view.lookup(file); XCTFail("invalidated copy remained readable") } catch {}
    }
    func testCorruptionAndMissingPayloadHaveDistinctOutcomesAndNeverFabricateZeros() async throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("offline-corrupt-"+UUID().uuidString)
        defer {try? FileManager.default.removeItem(at:dir)}
        let crypto=try AESGCMBlockCrypto(masterKeyBytes:Data(repeating:7,count:32))
        let cache=try DiskBlockCache(filespace:"fs",directory:dir,maxBytes:1<<20,blockSize:4096)
        let sealed=try await crypto.encryptBlock(Data(repeating:4,count:10),itemID:"file",blockIndex:0)
        try await cache.putBlock(sealed.hash,plaintext:sealed.ciphertext)
        let paths=FileManager.default.enumerator(at:dir,includingPropertiesForKeys:nil)!.allObjects.compactMap{$0 as? URL}
        let payload=try XCTUnwrap(paths.first { $0.lastPathComponent == sealed.hash.hex })
        try Data("damaged".utf8).write(to:payload)
        do {_ = try await cache.readBlockForOffline(sealed.hash);XCTFail("corrupt payload accepted")}
        catch let e as EngineError {XCTAssertEqual(e.data?["reason"],.string("offline_corrupt"))}
        try FileManager.default.removeItem(at:payload)
        let missing = try await cache.readBlockForOffline(sealed.hash); XCTAssertNil(missing)
    }
}
