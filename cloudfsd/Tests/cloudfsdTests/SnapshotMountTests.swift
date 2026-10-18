// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSCrypto
import CloudFSCache
import CloudFSGateway
import CloudFSTransfer
import CloudFSMount
@testable import cloudfsd

final class SnapshotMountTests: XCTestCase {
    private let prefix = "/v1/filespaces/fs/snapshots/saved"
    private let folder = #"{"id":"folder","parent":"private-root","name":"Media","isDir":true,"size":0,"contentVersion":"folder-v1"}"#
    private let file = #"{"id":"clip","parent":"folder","name":"clip.mov","isDir":false,"size":4,"contentVersion":"original"}"#
    private func fixture() throws -> (CloudFSEngine, SnapshotTestMount, URL) {
        GWStub.reset()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("snapshot-test-" + UUID().uuidString)
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "test"), session: GWStub.session())
        let backend = SnapshotTestMount()
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: directory.path, cacheSizeBytes: 16 << 20,
                                                       controlSocketPath: "/tmp/unused", gatewayBaseURL: "https://gw.test"),
                                   gateway: gateway, mount: backend)
        GWStub.on("GET \(prefix)/mount-roots", json: #"{"snapshot":{"id":"saved","scope":"folder","label":"Before edits"},"roots":[{"id":"folder","name":"Media","mountAsRoot":true}],"streamsCaptured":true}"#)
        GWStub.on("GET \(prefix)/items/folder", json: folder)
        GWStub.on("GET \(prefix)/items/clip", json: file)
        GWStub.on("GET \(prefix)/page", json: "{\"items\":[\(file)],\"cursor\":null}")
        return (engine, backend, directory)
    }
    func testSnapshotAutoConnectCompletesWithoutReenteringLifecycleGate() async throws {
        let (engine, _, directory) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let finished = expectation(description: "Disconnected source connects and mounts its snapshot")
        let task = Task {
            defer { finished.fulfill() }
            do {
                let mounted = try await engine.snapshotMount(SnapshotMountParams(filespace: "fs", snapshotId: "saved", at: directory.appendingPathComponent("mounted").path))
                XCTAssertEqual(mounted.status, .mounted)
                _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: true))
            } catch { XCTFail("Snapshot auto-connect failed: \(error)") }
        }
        await fulfillment(of: [finished], timeout: 5)
        task.cancel()
    }
    func testIndependentReadOnlyProjectionAndShutdown() async throws {
        let (engine, backend, directory) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let record = try await engine.snapshotMount(SnapshotMountParams(filespace: "fs", snapshotId: "saved", at: directory.appendingPathComponent("mounted").path))
        XCTAssertNotEqual(record.mountId, "fs"); XCTAssertTrue(record.readOnly)
        XCTAssertEqual(record.name, "Before edits")
        let recordedPath = await backend.path(record.mountId)
        let data = try XCTUnwrap(recordedPath)
        XCTAssertTrue(data.isReadOnly)
        let children = try await data.enumerate(container: .root, page: nil)
        XCTAssertEqual(children.items.map(\.name), ["clip.mov"])
        XCTAssertEqual(children.items.first?.parent, .root)
        for mutation in [
            { try await data.beginWrite(InodeID("clip"), handle: "h") },
            { _ = try await data.writeRange(InodeID("clip"), offset: 0, data: Data([1]), baseVersion: nil) },
            { try await data.truncate(InodeID("clip"), newSize: 0, baseVersion: nil) },
            { try await data.delete(InodeID("clip"), baseVersion: "original", recursive: false) },
            { _ = try await data.rename(InodeID("clip"), newParent: nil, newName: "renamed") },
            { try await data.writeStream(InodeID("clip"), name: "AFP_Resource", data: Data([1])) },
            { try await data.deleteStream(InodeID("clip"), name: "AFP_Resource") }
        ] as [() async throws -> Void] {
            do { try await mutation(); XCTFail("Snapshot mutation succeeded") }
            catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        }
        let all = try await engine.filespaceList()
        XCTAssertEqual(all.first { $0.id == record.mountId }?.sourceFilespace, "fs")
        let sync = try await engine.flush(FlushParams(filespace: record.mountId, path: "", wait: true))
        XCTAssertTrue(sync.inSync)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: true))
        let remaining = await backend.path(record.mountId)
        XCTAssertNil(remaining)
        let snapshots = try await engine.snapshotMounts(SnapshotMountsParams())
        XCTAssertTrue(snapshots.isEmpty)
    }
    func testExternalEjectBusyEjectAndAccessRevocation() async throws {
        let (engine, backend, directory) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        let p = SnapshotMountParams(filespace: "fs", snapshotId: "saved", at: directory.appendingPathComponent("mounted").path)
        let mounted = try await engine.snapshotMount(p)
        await backend.setBusy(true)
        do { _ = try await engine.snapshotUnmount(SnapshotUnmountParams(mountId: mounted.mountId)); XCTFail("busy must remain mounted") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .conflict) }
        let busyPath = await backend.path(mounted.mountId)
        XCTAssertNotNil(busyPath)
        await backend.setBusy(false)
        await backend.externalEject(mounted.mountId)
        let ejected = try await engine.snapshotMounts(SnapshotMountsParams())
        XCTAssertEqual(ejected.first?.status, .unmounted)
        _ = try await engine.snapshotMount(p)
        GWStub.on("GET \(prefix)/mount-roots", status: 403, json: #"{"error":"forbidden"}"#)
        let revoked = try await engine.snapshotMounts(SnapshotMountsParams())
        XCTAssertEqual(revoked.first?.status, .unavailable)
        let revokedPath = await backend.path(mounted.mountId)
        XCTAssertNil(revokedPath)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }
    func testCachedHistoricalBytesCannotBypassRevocation() async throws {
        GWStub.reset()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("snapshot-cache-test-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let key = try FilespaceKey(masterKeyBytes: Data(repeating: 7, count: 32))
        let crypto = try makeBlockCrypto(mode: .aes256gcm, key: key, blockSize: 1 << 20)
        let original = Data("old!".utf8)
        let (encrypted, hash) = try await crypto.encryptBlock(original, itemID: InodeID("clip"), blockIndex: 0)
        let cache = try DiskBlockCache(filespace: "fs", directory: directory, maxBytes: 16 << 20)
        try await cache.putBlock(hash, plaintext: encrypted)
        let live = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "test"), session: GWStub.session())
        let gateway = SnapshotReadGateway(base: live, filespace: "fs", snapshotID: "saved")
        let transfer = RealTransferEngine(cache: cache, crypto: crypto, gateway: gateway)
        let view = try SnapshotDataPath(filespace: "fs", gateway: gateway, transfer: transfer, crypto: crypto, spillDir: directory.appendingPathComponent("spill").path)
        GWStub.on("GET \(prefix)/items/clip", json: file)
        GWStub.on("GET \(prefix)/blocks/clip", json: "{\"item\":\(file),\"blocks\":[{\"chunkIdx\":0,\"blockIdx\":0,\"blockHash\":\"\(hash.hex)\",\"objectKey\":\"old-object\",\"offset\":0,\"length\":4}],\"cursor\":null}")
        let read = try await view.readBytes(InodeID("clip"), version: "ignored-live-version", offset: 0, length: 4)
        XCTAssertEqual(read, original)
        GWStub.on("GET \(prefix)/items/clip", status: 404, json: #"{"error":"snapshot_item_unavailable"}"#)
        do { _ = try await view.readBytes(InodeID("clip"), version: "original", offset: 0, length: 4); XCTFail("cached bytes must be denied after revocation") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .notFound) }
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/items/clip"), 0)
    }
    func testFinderInfoIsDecryptedWithOriginalInodeAndTamperingFailsClosed() async throws {
        let key = try FilespaceKey(masterKeyBytes: Data(repeating: 8, count: 32))
        let crypto = try makeBlockCrypto(mode: .aes256gcm, key: key, blockSize: 1 << 20)
        var info = Data(repeating: 0, count: 60)
        info.replaceSubrange(16..<48, with: Data((0..<32).map(UInt8.init)))
        var index: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in "AFP_AfpInfo".utf8 { index ^= UInt64(byte); index = index &* 0x0000_0100_0000_01B3 }
        let (encrypted, _) = try await crypto.encryptBlock(info, itemID: InodeID("original-inode"), blockIndex: Int(index & 0x7FFF_FFFF))
        let item = ItemMetadata(id: InodeID("original-inode"), parent: InodeID("folder"), name: "clip.mov", isDir: false,
                                size: 4, contentVersion: "original", metadataVersion: "1", rsrcForkSize: 9, finderInfoCiphertext: encrypted)
        let decoded = try await decryptMacMetadata(item, crypto: crypto)
        XCTAssertEqual(decoded.finderInfo, Data((0..<32).map(UInt8.init)))
        XCTAssertEqual(decoded.rsrcForkSize, 9)
        XCTAssertNil(decoded.finderInfoCiphertext)
        var corrupted = encrypted; corrupted[corrupted.count - 1] ^= 1
        let bad = ItemMetadata(id: item.id, parent: item.parent, name: item.name, isDir: false, size: 4,
                               contentVersion: "original", metadataVersion: "1", finderInfoCiphertext: corrupted)
        do { _ = try await decryptMacMetadata(bad, crypto: crypto); XCTFail("Tampered Finder metadata must not be projected") } catch {}
        let wrongIdentity = ItemMetadata(id: InodeID("another-inode"), parent: item.parent, name: item.name, isDir: false, size: 4,
                                         contentVersion: "original", metadataVersion: "1", finderInfoCiphertext: encrypted)
        do { _ = try await decryptMacMetadata(wrongIdentity, crypto: crypto); XCTFail("Finder metadata cannot cross inode identities") } catch {}
    }

    func testOlderSnapshotCannotSilentlyOmitMacForks() async throws {
        let (engine, _, directory) = try fixture()
        defer { try? FileManager.default.removeItem(at: directory) }
        GWStub.on("GET \(prefix)/mount-roots", json: #"{"snapshot":{"id":"saved","scope":"folder"},"roots":[{"id":"folder","name":"Media","mountAsRoot":true}],"streamsCaptured":false}"#)
        do { _ = try await engine.snapshotMount(SnapshotMountParams(filespace: "fs", snapshotId: "saved")); XCTFail("legacy incomplete snapshot must be explicit") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .conflict) }
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }
}

private actor SnapshotTestMount: MountBackend {
    nonisolated let kind = "test"
    nonisolated let isAvailable = true
    private var paths: [String: any EngineDataPath] = [:]
    private var busy = false
    func mount(filespace: FilespaceID, displayName: String?, at mountPoint: String, engine: any EngineDataPath) async throws { paths[filespace] = engine }
    func unmount(filespace: FilespaceID, force: Bool) async throws {
        if busy && !force { throw EngineError(.conflict, "Volume is busy") }
        paths[filespace] = nil
    }
    func reconcile(filespace: FilespaceID, at path: String) async throws -> Bool? { paths[filespace] != nil }
    func path(_ id: String) -> (any EngineDataPath)? { paths[id] }
    func setBusy(_ value: Bool) { busy = value }
    func externalEject(_ id: String) { paths[id] = nil }
}
