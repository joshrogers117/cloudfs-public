// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSCache
import CloudFSMount
import CloudFSGateway
import CloudFSCrypto
import CloudFSTransfer
@testable import cloudfsd

private final class PinNamespace: @unchecked Sendable {
    struct Node: Codable, Sendable {
        var id: String; var parent: String?; var name: String; var isDir: Bool
        var size: Int; var contentVersion: String; var version: Int
    }
    private let mutex = NSLock()
    private var nodes: [String: Node] = [:]
    private var seq = 0
    let key = Data((0..<32).map(UInt8.init))
    init() {
        GWStub.reset()
        addDirectory("root", parent: nil, name: "")
        GWStub.on("GET /v1/filespaces/fs/items") { [self] request in
            let query = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems ?? []
            let parent = query.first { $0.name == "parent" }?.value ?? "root"
            let offset = query.first { $0.name == "cursor" }?.value.flatMap(Int.init) ?? 0
            let children = mutex.withLock { nodes.values.filter { $0.parent == parent }.sorted { $0.id < $1.id } }
            // One child per page catches traversal that silently drops later pages.
            let rows = offset < children.count ? [children[offset]] : []
            let encoded = String(data: try! JSONEncoder().encode(rows), encoding: .utf8)!
            let next = offset + 1 < children.count ? "\"\(offset + 1)\"" : "null"
            return (200, "{\"items\":\(encoded),\"cursor\":\(next)}")
        }
        GWStub.on("GET /v1/filespaces/fs/changes") { [self] _ in
            let anchor = mutex.withLock { seq }
            return (200, "{\"anchor\":\(anchor),\"items\":[],\"cursor\":null}")
        }
    }
    private func register(_ node: Node) {
        mutex.withLock { nodes[node.id] = node; seq += 1 }
        GWStub.on("GET /v1/filespaces/fs/items/\(node.id)") { [self] _ in
            guard let item = mutex.withLock({ nodes[node.id] }) else { return (404, "{\"error\":\"not found\"}") }
            return (200, String(data: try! JSONEncoder().encode(item), encoding: .utf8)!)
        }
    }
    func addDirectory(_ id: String, parent: String?, name: String) {
        register(Node(id: id, parent: parent, name: name, isDir: true, size: 0, contentVersion: "dir", version: 1))
    }
    func rename(_ id: String, name: String) {
        mutex.withLock { nodes[id]?.name = name; seq += 1 }
    }
    func remove(_ id: String) { mutex.withLock { nodes[id] = nil; seq += 1 } }
    @discardableResult
    func addFile(_ id: String, parent: String, name: String, size: Int = 256, byte: UInt8 = 3) async throws -> BlockHash {
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: key)
        let (ciphertext, hash) = try await crypto.encryptBlock(Data(repeating: byte, count: size), itemID: InodeID(id), blockIndex: 0)
        var components = URLComponents(string: "https://blob.test/blob")!
        components.queryItems = [URLQueryItem(name: "key", value: hash.objectKey)]
        var request = URLRequest(url: components.url!); request.httpMethod = "PUT"; request.httpBody = ciphertext
        _ = try await GWStub.session().data(for: request)
        let version = mutex.withLock { (nodes[id]?.version ?? 0) + 1 }
        register(Node(id: id, parent: parent, name: name, isDir: false, size: size, contentVersion: "v\(version)", version: version))
        GWStub.on("GET /v1/filespaces/fs/blocks/\(id)", json: "[{\"chunkIdx\":0,\"blockIdx\":0,\"blockHash\":\"\(hash.hex)\",\"objectKey\":\"\(hash.objectKey)\",\"offset\":0,\"length\":\(size)}]")
        return hash
    }
    func engine(cacheDir: String? = nil, size: Int = 1 << 20, mount: any MountBackend = StubMountBackend(), offline: Bool = false) throws -> (CloudFSEngine, String) {
        let directory = cacheDir ?? FileManager.default.temporaryDirectory.appendingPathComponent("recursive-pin-\(UUID())").path
        let config = EngineConfig(cacheDir: directory, cacheSizeBytes: size, controlSocketPath: directory + "/control.sock", gatewayBaseURL: "https://gw.test")
        let payload = Data(#"{"sub":"owner","org":"org","typ":"session"}"#.utf8).base64EncodedString()
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: offline ? "header." + payload + ".signature" : "owner"), session: GWStub.session())
        return (CloudFSEngine(config: config, gateway: gateway, mount: mount, key: try FilespaceKey(masterKeyBytes: key), blob: BlobTransport(session: GWStub.session())), directory)
    }
}

final class RecursivePinTests: XCTestCase {
    private func settled(_ engine: CloudFSEngine, where predicate: (PinState) -> Bool) async throws -> PinState {
        for _ in 0..<300 {
            if let state = try await engine.pinList(FilespaceOnlyParams(filespace: "fs")).first, predicate(state) { return state }
            try await Task.sleep(for: .milliseconds(10))
        }
        let states = try await engine.pinList(FilespaceOnlyParams(filespace: "fs"))
        XCTFail("pin never reached expected state: \(states)")
        throw EngineError(.syncTimeout)
    }
    private func stop(_ engine: CloudFSEngine) async throws {
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
    }

    func testCompletePinReopensReadOnlyAfterRestartWithoutAnyGatewayOrBlobRequest() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Projects")
        _ = try await ns.addFile("file", parent: "folder", name: "new-open.mov", size: 256, byte: 71)
        GWStub.on("GET /v1/filespaces/fs/changes", json: #"{"anchor":5,"items":[],"cursor":null,"visibility":"acl-v1"}"#)
        for id in ["folder","file"] { GWStub.on("GET /v1/filespaces/fs/items/\(id)/streams", json: #"{"streams":[]}"#) }
        let (engine, directory) = try ns.engine(offline: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await engine.pin(PinParams(filespace: "fs", path: "Projects", recursive: true))
        let pinned = try await settled(engine) { $0.offlineReady == true }
        XCTAssertNotNil(pinned.offlineExpiresAt)
        try await stop(engine)
        GWStub.reset() // Any attempted gateway request now fails.
        let mount = CapturedLinkMount()
        let (restarted, _) = try ns.engine(cacheDir: directory, mount: mount, offline: true)
        let record = try await restarted.mount(MountParams(filespace: "fs", at: directory + "-offline", offlinePin: "Projects"))
        XCTAssertEqual(record.status, .offline); XCTAssertEqual(record.readOnly, true)
        let captured = await mount.dataPath, view = try XCTUnwrap(captured)
        let listing = try await view.enumerate(container: .root, page: nil)
        XCTAssertEqual(listing.items.map(\.name), ["new-open.mov"])
        let bytes = try await view.readBytes("file", version: listing.items[0].contentVersion, offset: 77, length: 100)
        XCTAssertEqual(bytes, Data(repeating: 71, count: 100)); XCTAssertTrue(view.isReadOnly)
        XCTAssertEqual(GWStub.totalBlobGets(), 0)
        for route in ["GET /v1/filespaces/fs/changes", "GET /v1/filespaces/fs/items/file", "GET /v1/filespaces/fs/blocks/file", "GET /v1/filespaces/fs/mount-roots"] { XCTAssertEqual(GWStub.count(route), 0) }
        try await stop(restarted)
    }

    func testColdRecursivePinReturnsPromptlyAndWalksEveryPage() async throws {
        let ns = PinNamespace(); ns.addDirectory("opaque-folder", parent: "root", name: "Projects")
        ns.addDirectory("different-subtree", parent: "opaque-folder", name: "Subfolder")
        _ = try await ns.addFile("one", parent: "opaque-folder", name: "a.mov")
        _ = try await ns.addFile("two", parent: "different-subtree", name: "b.mov")
        let (engine, directory) = try ns.engine(); defer { try? FileManager.default.removeItem(atPath: directory) }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        GWStub.setBlobGetLatency(ms: 250)
        let start = ContinuousClock.now
        let initial = try await engine.pin(PinParams(filespace: "fs", path: "/Projects", recursive: true))
        XCTAssertEqual(initial.cacheState, .pinning)
        XCTAssertLessThan(start.duration(to: .now), .milliseconds(200))
        let ready = try await settled(engine) { $0.cacheState == .pinned && $0.blocks == 2 }
        XCTAssertEqual(ready.totalBytes, 512)
        XCTAssertNil(ready.failureReason)
        try await stop(engine)
    }

    func testRemoteNewChangedDeletedChildrenReplaceExactMembership() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Work")
        let oldHash = try await ns.addFile("old", parent: "folder", name: "old.txt")
        _ = try await ns.addFile("edit", parent: "folder", name: "edit.txt")
        let (engine, _) = try ns.engine(); _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await engine.pin(PinParams(filespace: "fs", path: "Work", recursive: true))
        _ = try await settled(engine) { $0.cacheState == .pinned && $0.blocks == 2 }
        ns.remove("old")
        _ = try await ns.addFile("edit", parent: "folder", name: "edit.txt", size: 512, byte: 8)
        _ = try await ns.addFile("fresh", parent: "folder", name: "new.txt", byte: 9)
        await engine.refreshPins("fs")
        let ready = try await settled(engine) { $0.cacheState == .pinned && $0.totalBytes == 768 }
        XCTAssertEqual(ready.blocks, 2)
        _ = try await engine.cacheClear(CacheClearParams(filespace: "fs"))
        let (cache, _, _) = try await engine.sessionFor("fs")
        let obsolete = try await cache.readBlock(oldHash)
        XCTAssertNil(obsolete, "deleted child must no longer hold old blocks pinned")
        try await stop(engine)
    }

    func testUnpinDuringDownloadCannotResurrectIntentOrPinRefs() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Slow")
        _ = try await ns.addFile("slow", parent: "folder", name: "movie.mov")
        let (engine, _) = try ns.engine(); _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        GWStub.setBlobGetLatency(ms: 300)
        _ = try await engine.pin(PinParams(filespace: "fs", path: "Slow", recursive: true))
        for _ in 0..<100 { if GWStub.totalBlobGets() > 0 { break }; try await Task.sleep(for: .milliseconds(5)) }
        _ = try await engine.unpin(PinParams(filespace: "fs", path: "Slow", recursive: true))
        try await Task.sleep(for: .milliseconds(400))
        let pins = try await engine.pinList(FilespaceOnlyParams(filespace: "fs"))
        XCTAssertTrue(pins.isEmpty)
        let info = try await engine.cacheInfo(CacheInfoParams(filespace: "fs"))
        XCTAssertEqual(info.pinnedBytes, 0)
        try await stop(engine)
    }

    func testHeadroomFailurePersistsAcrossRestartAndRetriesAfterResize() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Large")
        _ = try await ns.addFile("large", parent: "folder", name: "large.mov", size: 4096)
        let (first, directory) = try ns.engine(size: 128)
        _ = try await first.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await first.pin(PinParams(filespace: "fs", path: "Large", recursive: true))
        let failed = try await settled(first) { $0.failureReason != nil }
        XCTAssertEqual(failed.cacheState, .pinning)
        XCTAssertEqual(GWStub.totalBlobGets(), 0, "reserve cache capacity before starting downloads")
        try await stop(first)
        let (second, _) = try ns.engine(cacheDir: directory, size: 128)
        _ = try await second.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await settled(second) { $0.failureReason != nil }
        _ = try await second.cacheSetSize(CacheSetSizeParams(filespace: "fs", bytes: 64 << 10))
        await second.refreshPins("fs")
        let ready = try await settled(second) { $0.cacheState == .pinned && $0.failureReason == nil }
        XCTAssertEqual(ready.totalBytes, 4096)
        try await stop(second)
    }

    func testRestartRestoresRecursiveIntentAndPinsNewChild() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Keep")
        _ = try await ns.addFile("before", parent: "folder", name: "first")
        let (first, directory) = try ns.engine()
        _ = try await first.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await first.pin(PinParams(filespace: "fs", path: "Keep", recursive: true))
        _ = try await settled(first) { $0.cacheState == .pinned && $0.blocks == 1 }
        try await stop(first)
        _ = try await ns.addFile("after", parent: "folder", name: "second")
        let (second, _) = try ns.engine(cacheDir: directory)
        _ = try await second.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await settled(second) { $0.cacheState == .pinned && $0.blocks == 2 }
        try await stop(second)
    }

    func testPinProjectedRootNeverTraversesOutsideSharedFolder() async throws {
        let ns = PinNamespace(); ns.addDirectory("granted", parent: "root", name: "Shared")
        ns.addDirectory("private", parent: "root", name: "Private")
        _ = try await ns.addFile("allowed", parent: "granted", name: "clip.mov")
        _ = try await ns.addFile("secret", parent: "private", name: "secret.mov")
        GWStub.on("GET /v1/filespaces/fs/mount-roots", json: "{\"roots\":[{\"id\":\"granted\",\"name\":\"Shared\",\"mountAsRoot\":true}]}")
        let (engine, _) = try ns.engine(); _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await engine.pin(PinParams(filespace: "fs", path: "/", recursive: true))
        _ = try await settled(engine) { $0.cacheState == .pinned && $0.blocks == 1 }
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/items/secret"), 0)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/items/private"), 0)
        try await stop(engine)
    }
}

extension RecursivePinTests {
    func testRenamedPinnedFolderUpdatesPathAndFinderUnpinUsesNewName() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Before")
        _ = try await ns.addFile("child", parent: "folder", name: "movie")
        let (engine, _) = try ns.engine(); _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await engine.pin(PinParams(filespace: "fs", path: "Before", recursive: true))
        _ = try await settled(engine) { $0.cacheState == .pinned }
        ns.rename("folder", name: "After")
        await engine.refreshPins("fs")
        let renamed = try await settled(engine) { $0.path == "After" && $0.cacheState == .pinned }
        XCTAssertEqual(renamed.blocks, 1)
        let pins = try await engine.pinList(FilespaceOnlyParams(filespace: "fs"))
        XCTAssertEqual(pins.map(\.path), ["After"])
        ns.rename("folder", name: "Latest")
        // The name changes again; unpin must also work before a monitor rescan.
        _ = try await engine.unpin(PinParams(filespace: "fs", path: "Latest", recursive: true))
        let empty = try await engine.pinList(FilespaceOnlyParams(filespace: "fs"))
        XCTAssertTrue(empty.isEmpty)
        try await stop(engine)
    }

    func testRelocatedCacheSizePinsAndOriginalWriteJournalSurviveRestart() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Keep")
        let hash = try await ns.addFile("file", parent: "folder", name: "movie", size: 4096)
        let (first, directory) = try ns.engine()
        let destination = FileManager.default.temporaryDirectory.appendingPathComponent("relocated-engine-\(UUID())")
        defer { try? FileManager.default.removeItem(atPath: directory); try? FileManager.default.removeItem(at: destination) }
        _ = try await first.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await first.pin(PinParams(filespace: "fs", path: "Keep", recursive: true))
        _ = try await settled(first) { $0.cacheState == .pinned }
        _ = try await first.transfersPause(FilespaceOnlyParams(filespace: "fs"))
        let adapter = await first.dataPath(for: "fs")
        _ = try await adapter.writeRange("file", offset: 0, data: Data("pending".utf8), baseVersion: "1")
        _ = try await first.cacheSetSize(CacheSetSizeParams(filespace: "fs", bytes: 2 << 20))
        _ = try await first.cacheSetLocation(CacheSetLocationParams(filespace: "fs", path: destination.path))
        let stable = URL(fileURLWithPath: directory).appendingPathComponent("fs")
        XCTAssertTrue(FileManager.default.fileExists(atPath: stable.appendingPathComponent("pin-intents-v2.json").path))
        let journal = try await WriteBackJournal(cacheDir: stable.path).replay()
        XCTAssertEqual(journal.count, 1, "relocation never moves the live write journal")
        try await stop(first)
        GWStub.on("PUT /v1/filespaces/fs/blocks/file", status: 409, json: "{\"error\":\"conflict\",\"conflict\":true}")
        let (second, _) = try ns.engine(cacheDir: directory, size: 1 << 20)
        _ = try await second.connect(FilespaceConnectParams(filespace: "fs"))
        let info = try await second.cacheInfo(CacheInfoParams(filespace: "fs"))
        XCTAssertEqual(info.location, destination.resolvingSymlinksInPath().path)
        XCTAssertEqual(info.maxBytes, 2 << 20)
        let (cache, _, _) = try await second.sessionFor("fs")
        let retained = try await cache.readBlock(hash)
        XCTAssertNotNil(retained, "restart reads the relocated cache rather than silently creating a new old-path cache")
        _ = try await settled(second) { $0.cacheState == .pinned && $0.path == "Keep" }
        let recovered = URL(fileURLWithPath: directory).appendingPathComponent("recover.bin")
        _ = try await second.recoveryExport(RecoveryExportParams(filespace: "fs", itemId: "file", destination: recovered.path))
        var expected = Data(repeating: UInt8(3), count: 4096); expected.replaceSubrange(0..<7, with: Data("pending".utf8))
        XCTAssertEqual(try Data(contentsOf: recovered), expected)
        try await stop(second)
    }

    func testFailedCacheMappingCommitRollsBackWithoutLosingPins() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Keep")
        _ = try await ns.addFile("file", parent: "folder", name: "movie")
        let (engine, directory) = try ns.engine()
        let destination = FileManager.default.temporaryDirectory.appendingPathComponent("failed-relocation-\(UUID())")
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await engine.pin(PinParams(filespace: "fs", path: "Keep", recursive: true))
        _ = try await settled(engine) { $0.cacheState == .pinned }
        let old = try await engine.cacheInfo(CacheInfoParams(filespace: "fs"))
        try FileManager.default.createDirectory(atPath: directory + "/cache-preferences.json", withIntermediateDirectories: false)
        do {
            _ = try await engine.cacheSetLocation(CacheSetLocationParams(filespace: "fs", path: destination.path))
            XCTFail("mapping write must fail rather than pretending relocation persisted")
        } catch {}
        let after = try await engine.cacheInfo(CacheInfoParams(filespace: "fs"))
        XCTAssertEqual(after.location, URL(fileURLWithPath: old.location).resolvingSymlinksInPath().path)
        let pins = try await engine.pinList(FilespaceOnlyParams(filespace: "fs"))
        XCTAssertEqual(pins.first?.cacheState, .pinned)
        try await stop(engine)
    }
}


extension RecursivePinTests {
    func testPinReusedPathTargetsReplacementInodeBeforeRenamePoll() async throws {
        let ns = PinNamespace()
        ns.addDirectory("original", parent: "root", name: "Before")
        _ = try await ns.addFile("old-child", parent: "original", name: "old", size: 256)
        let (engine, _) = try ns.engine()
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        _ = try await engine.pin(PinParams(filespace: "fs", path: "Before", recursive: true))
        _ = try await settled(engine) { $0.cacheState == .pinned }
        ns.rename("original", name: "After")
        ns.addDirectory("replacement", parent: "root", name: "Before")
        _ = try await ns.addFile("new-child", parent: "replacement", name: "new", size: 1024, byte: 19)
        let pending = try await engine.pin(PinParams(filespace: "fs", path: "Before", recursive: true))
        XCTAssertEqual(pending.cacheState, .pinning)
        let result = try await settled(engine) { $0.cacheState == .pinned && $0.totalBytes == 1024 }
        XCTAssertEqual(result.path, "Before")
        XCTAssertEqual(result.blocks, 1)
        try await stop(engine)
    }

    func testExplicitSubfolderRootPinStaysRelativeAndExcludesOutsideChildren() async throws {
        let ns = PinNamespace()
        ns.addDirectory("project", parent: "root", name: "Project")
        _ = try await ns.addFile("visible", parent: "project", name: "inside")
        _ = try await ns.addFile("outside", parent: "root", name: "outside")
        let (engine, _) = try ns.engine()
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs", rootPoint: "project"))
        _ = try await engine.pin(PinParams(filespace: "fs", path: "/", recursive: true))
        let result = try await settled(engine) { $0.cacheState == .pinned }
        XCTAssertEqual(result.path, "")
        XCTAssertEqual(result.blocks, 1)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/outside"), 0)
        ns.rename("project", name: "Renamed")
        await engine.refreshPins("fs")
        try await Task.sleep(for: .milliseconds(100))
        let refreshed = try await engine.pinList(FilespaceOnlyParams(filespace: "fs"))
        XCTAssertEqual(refreshed.map(\.path), [""])
        try await stop(engine)
    }
}

final class LinkProjectionTests: XCTestCase {
    func testCreatedLinkFollowsStableIdentityAcrossFolderAndFileRenames() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Before")
        _ = try await ns.addFile("file", parent: "folder", name: "old.mov")
        let (engine, _) = try ns.engine()
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let link = try await engine.linkCreate(LinkCreateParams(filespace: "fs", path: "Before/old.mov"))
        XCTAssertEqual(link.itemId, "file")
        ns.rename("folder", name: "After"); ns.rename("file", name: "new.mov")
        let target = try await engine.linkResolve(link)
        XCTAssertEqual(target.path, "After/new.mov")
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }

    func testSameLinkResolvesRelativeToRecipientFolderGrantWithoutAncestorAccess() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Shared")
        _ = try await ns.addFile("file", parent: "folder", name: "clip.mov")
        let (sender, _) = try ns.engine()
        _ = try await sender.connect(FilespaceConnectParams(filespace: "fs"))
        let link = try await sender.linkCreate(LinkCreateParams(filespace: "fs", path: "Shared/clip.mov"))
        GWStub.on("GET /v1/filespaces/fs/mount-roots", json: "{\"roots\":[{\"id\":\"folder\",\"name\":\"Shared\",\"mountAsRoot\":true}]}")
        GWStub.on("GET /v1/filespaces/fs/items/root", status: 403, json: "{\"error\":\"permission_denied\"}")
        let (recipient, _) = try ns.engine()
        _ = try await recipient.connect(FilespaceConnectParams(filespace: "fs"))
        let target = try await recipient.linkResolve(link)
        XCTAssertEqual(target.path, "clip.mov")
        let roundTrip = try await recipient.linkCreate(LinkCreateParams(filespace: "fs", path: target.path))
        XCTAssertEqual(roundTrip.itemId, link.itemId)
        let root = try await recipient.linkResolve(LinkResolveParams(filespace: "fs", itemId: "folder"))
        XCTAssertEqual(root.path, "")
        _ = try await sender.disconnect(FilespaceDisconnectParams(filespace: "fs"))
        _ = try await recipient.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }

    func testDuplicateGrantedFolderNamesProduceActualProjectedPath() async throws {
        let ns = PinNamespace()
        ns.addDirectory("first", parent: "root", name: "Shared")
        ns.addDirectory("second", parent: "root", name: "Shared")
        _ = try await ns.addFile("file", parent: "second", name: "Shared")
        GWStub.on("GET /v1/filespaces/fs/mount-roots", json: "{\"roots\":[{\"id\":\"first\",\"name\":\"Shared\",\"mountAsRoot\":false},{\"id\":\"second\",\"name\":\"Shared\",\"mountAsRoot\":false}]}")
        let (engine, _) = try ns.engine()
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let target = try await engine.linkResolve(LinkResolveParams(filespace: "fs", itemId: "file"))
        XCTAssertEqual(target.path, "Shared (second)/Shared")
        let link = try await engine.linkCreate(LinkCreateParams(filespace: "fs", path: target.path))
        XCTAssertEqual(link.itemId, "file")
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }

    func testLinkCannotEscapeExplicitMountProjectionEvenWithFilespaceAdminAccess() async throws {
        let ns = PinNamespace(); ns.addDirectory("folder", parent: "root", name: "Mounted")
        _ = try await ns.addFile("outside", parent: "root", name: "outside.mov")
        let (engine, _) = try ns.engine()
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs", rootPoint: "folder"))
        do {
            _ = try await engine.linkResolve(LinkResolveParams(filespace: "fs", itemId: "outside"))
            XCTFail("An authorized inode outside this volume cannot produce a reveal path")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        do {
            _ = try await engine.linkCreate(LinkCreateParams(filespace: "fs", path: "../outside.mov"))
            XCTFail("A link path cannot escape the mounted root")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .invalidParams) }
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }

    func testRevokedOrDeletedInodeLinkNeverResolvesToStaleLocalPath() async throws {
        let ns = PinNamespace()
        _ = try await ns.addFile("file", parent: "root", name: "clip.mov")
        let (engine, _) = try ns.engine()
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let link = try await engine.linkCreate(LinkCreateParams(filespace: "fs", path: "clip.mov"))
        GWStub.on("GET /v1/filespaces/fs/items/file", status: 403, json: "{\"error\":\"permission_denied\"}")
        do {
            _ = try await engine.linkResolve(link)
            XCTFail("Link must recheck permission every time")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        ns.remove("file")
        GWStub.on("GET /v1/filespaces/fs/items/file", status: 404, json: "{\"error\":\"not_found\"}")
        do {
            _ = try await engine.linkResolve(link)
            XCTFail("Deleted item cannot reveal stale namespace")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .notFound) }
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }
}


private actor CapturedLinkMount: MountBackend {
    nonisolated var kind: String { "captured-test" }
    nonisolated var isAvailable: Bool { true }
    var dataPath: (any EngineDataPath)?
    var mountCount = 0
    func mount(filespace: FilespaceID, displayName: String?, at mountPoint: String, engine: any EngineDataPath) async throws {
        mountCount += 1
        dataPath = engine
    }
    func unmount(filespace: FilespaceID, force: Bool) async throws { dataPath = nil }
}

extension LinkProjectionTests {
    func testMountedLinksKeepActualProjectionAfterDuplicateGrantRevokedAndRootRenamed() async throws {
        let ns = PinNamespace()
        ns.addDirectory("first", parent: "root", name: "Shared")
        ns.addDirectory("second", parent: "root", name: "Shared")
        _ = try await ns.addFile("file", parent: "second", name: "clip.mov")
        GWStub.on("GET /v1/filespaces/fs/mount-roots", json: "{\"roots\":[{\"id\":\"first\",\"name\":\"Shared\",\"mountAsRoot\":false},{\"id\":\"second\",\"name\":\"Shared\",\"mountAsRoot\":false}]}")
        let mount = CapturedLinkMount()
        let (mounted, directory) = try ns.engine(mount: mount)
        // Inspect the mount's captured adapter; recreating it after the grant
        // change would mask the difference between links and the live volume.
        _ = try await mounted.mount(MountParams(filespace: "fs", at: directory + "-volume"))
        let adapter = await mount.dataPath!
        let link = try await mounted.linkCreate(LinkCreateParams(filespace: "fs", path: "Shared (second)/clip.mov"))
        GWStub.on("GET /v1/filespaces/fs/mount-roots", json: "{\"roots\":[{\"id\":\"second\",\"name\":\"Shared\",\"mountAsRoot\":true}]}")
        GWStub.on("GET /v1/filespaces/fs/items/first", status: 403, json: "{\"error\":\"permission_denied\"}")
        _ = try await mounted.mount(MountParams(filespace: "fs"))
        let mountCount = await mount.mountCount
        XCTAssertEqual(mountCount, 1, "Repeated mount must retain the original adapter and projection")
        var listing = try await adapter.enumerate(container: .root, page: nil)
        var resolved = try await mounted.linkResolve(link)
        XCTAssertEqual(listing.items.map(\.name), ["Shared (second)"])
        XCTAssertEqual(resolved.path, listing.items[0].name + "/clip.mov")
        let recreated = try await mounted.linkCreate(LinkCreateParams(filespace: "fs", path: resolved.path))
        XCTAssertEqual(recreated.itemId, link.itemId)
        ns.rename("second", name: "Renamed")
        listing = try await adapter.enumerate(container: .root, page: nil)
        resolved = try await mounted.linkResolve(link)
        XCTAssertEqual(listing.items.map(\.name), ["Shared (second)"])
        XCTAssertEqual(resolved.path, "Shared (second)/clip.mov", "Granted top-level aliases remain stable until remount")
        let renamed = try await mounted.linkCreate(LinkCreateParams(filespace: "fs", path: resolved.path))
        XCTAssertEqual(renamed.itemId, link.itemId)
        do {
            _ = try await mounted.mount(MountParams(filespace: "fs", rootPoint: "second"))
            XCTFail("Changing an active projection must require unmount")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .conflict) }
        _ = try await mounted.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }
}

extension LinkProjectionTests {
    func testRenamingGrantToSiblingNameKeepsMountedAliasesDistinct() async throws {
        let ns = PinNamespace()
        ns.addDirectory("first", parent: "root", name: "First")
        ns.addDirectory("second", parent: "root", name: "Second")
        _ = try await ns.addFile("file", parent: "second", name: "clip.mov")
        GWStub.on("GET /v1/filespaces/fs/mount-roots", json: "{\"roots\":[{\"id\":\"first\",\"name\":\"First\",\"mountAsRoot\":false},{\"id\":\"second\",\"name\":\"Second\",\"mountAsRoot\":false}]}")
        let mount = CapturedLinkMount()
        let (engine, directory) = try ns.engine(mount: mount)
        _ = try await engine.mount(MountParams(filespace: "fs", at: directory + "-volume"))
        let adapter = await mount.dataPath!
        ns.rename("second", name: "First")
        let listing = try await adapter.enumerate(container: .root, page: nil)
        XCTAssertEqual(Set(listing.items.map(\.name)), Set(["First", "Second"]))
        let target = try await engine.linkResolve(LinkResolveParams(filespace: "fs", itemId: "file"))
        XCTAssertEqual(target.path, "Second/clip.mov")
        let link = try await engine.linkCreate(LinkCreateParams(filespace: "fs", path: target.path))
        XCTAssertEqual(link.itemId, "file")
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }
}

private actor EjectableMount: MountBackend {
    nonisolated var kind: String { "ejectable-test" }
    nonisolated var isAvailable: Bool { true }
    var present = false
    var mountCount = 0
    var unmountCount = 0
    var staleCleanups = 0
    func mount(filespace: FilespaceID, displayName: String?, at mountPoint: String, engine: any EngineDataPath) async throws {
        present = true; mountCount += 1
    }
    func unmount(filespace: FilespaceID, force: Bool) async throws {
        precondition(present, "engine must reconcile stale mount before unmounting")
        present = false; unmountCount += 1
    }
    func reconcile(filespace: FilespaceID, at mountPoint: String) async throws -> Bool? {
        if !present { staleCleanups += 1 }
        return present
    }
    func eject() { present = false }
}

final class MountReconciliationTests: XCTestCase {
    func testExternalEjectClearsListAndIntentThenReconnects() async throws {
        let ns = PinNamespace(), backend = EjectableMount()
        let (engine, directory) = try ns.engine(mount: backend)
        _ = try await engine.mount(MountParams(filespace: "fs", at: directory + "-volume"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory + "/mounts.json"))
        await backend.eject()
        let listing = try await engine.filespaceList()
        XCTAssertNil(listing.first?.mountPath)
        XCTAssertFalse(FileManager.default.fileExists(atPath: directory + "/mounts.json"))
        let remounted = try await engine.mount(MountParams(filespace: "fs", at: directory + "-volume"))
        XCTAssertNotNil(remounted.mountPath)
        let count = await backend.mountCount
        XCTAssertEqual(count, 2)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
    }

    func testReconnectAndDisconnectReconcileWithoutPriorList() async throws {
        let ns = PinNamespace(), backend = EjectableMount()
        let (engine, directory) = try ns.engine(mount: backend)
        let params = MountParams(filespace: "fs", at: directory + "-volume")
        _ = try await engine.mount(params)
        await backend.eject()
        _ = try await engine.mount(params)
        let count = await backend.mountCount
        XCTAssertEqual(count, 2, "idempotent mount must not return a stale path")
        await backend.eject()
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs"))
        let unmounts = await backend.unmountCount
        XCTAssertEqual(unmounts, 0, "an absent/foreign volume must never receive umount")
        let listed = try await engine.filespaceList()
        XCTAssertTrue(listed.isEmpty)
    }
}
