// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import cloudfsd

final class DirectorySnapshotProjectionTests: XCTestCase {
    func testDirectRootSnapshotProjectsRootAndParentIdentity() async throws {
        let (base, shared, child) = fixture()
        let rooted = RootedDataPath(base: base,
            roots: [FilespaceMountRoot(id: shared.id.rawValue, name: shared.name, mountAsRoot: true)],
            directRoot: shared.id)

        let result = try await rooted.directorySnapshot(.root, handle: "h", access: .read, sharing: [.read])
        let snapshot = try XCTUnwrap(result)
        XCTAssertEqual(base.lastSnapshotID, shared.id)
        XCTAssertEqual(snapshot.directory.id, .root)
        XCTAssertNil(snapshot.directory.parent)
        XCTAssertEqual(snapshot.items.map(\.id), [child.id])
        XCTAssertEqual(snapshot.items[0].parent, .root)
    }

    func testNamedGrantSnapshotKeepsGrantIdentityAndProjectsItsParent() async throws {
        let (base, shared, child) = fixture()
        let rooted = RootedDataPath(base: base,
            roots: [FilespaceMountRoot(id: shared.id.rawValue, name: "Shared alias", mountAsRoot: false)],
            directRoot: nil)

        let result = try await rooted.directorySnapshot(shared.id, handle: "h", access: .read, sharing: [.read])
        let snapshot = try XCTUnwrap(result)
        XCTAssertEqual(base.lastSnapshotID, shared.id)
        XCTAssertEqual(snapshot.directory.id, shared.id)
        XCTAssertEqual(snapshot.directory.parent, .root)
        XCTAssertEqual(snapshot.directory.name, "Shared alias")
        XCTAssertEqual(snapshot.items.map(\.id), [child.id])
        XCTAssertEqual(snapshot.items[0].parent, shared.id)
    }

    func testAggregateVirtualRootDoesNotRequestOneNamespaceSnapshot() async throws {
        let (base, _, _) = fixture()
        let rooted = RootedDataPath(base: base,
            roots: [FilespaceMountRoot(id: "shared-a", name: "A", mountAsRoot: false),
                    FilespaceMountRoot(id: "shared-b", name: "B", mountAsRoot: false)],
            directRoot: nil)

        let snapshot = try await rooted.directorySnapshot(.root, handle: "h", access: .read, sharing: [.read])
        XCTAssertNil(snapshot)
        XCTAssertNil(base.lastSnapshotID)
    }

    private func fixture() -> (SnapshotPath, ItemMetadata, ItemMetadata) {
        let shared = ItemMetadata(id: "shared", parent: .root, name: "Shared", isDir: true,
                                  size: 0, contentVersion: "d1", metadataVersion: "1")
        let child = ItemMetadata(id: "child", parent: shared.id, name: "file.txt", isDir: false,
                                 size: 4, contentVersion: "f1", metadataVersion: "1")
        let root = ItemMetadata(id: .root, parent: nil, name: "", isDir: true,
                                size: 0, contentVersion: "r1", metadataVersion: "1")
        return (SnapshotPath(snapshot: DirectorySnapshot(directory: shared, items: [child]),
                             metadata: [root.id: root, shared.id: shared, child.id: child]), shared, child)
    }
}

private final class SnapshotPath: EngineDataPath, @unchecked Sendable {
    let snapshot: DirectorySnapshot
    let metadata: [InodeID: ItemMetadata]
    private(set) var lastSnapshotID: InodeID?

    init(snapshot: DirectorySnapshot, metadata: [InodeID: ItemMetadata]) {
        self.snapshot = snapshot
        self.metadata = metadata
    }

    var isReadOnly: Bool { false }
    var plaintextSpillDir: String { NSTemporaryDirectory() }
    func directorySnapshot(_ id: InodeID, handle: String, access: OpenFileAccess,
                           sharing: OpenFileSharing) async throws -> DirectorySnapshot? {
        lastSnapshotID = id
        return snapshot
    }
    func lookup(_ id: InodeID) async throws -> ItemMetadata {
        guard let item = metadata[id] else { throw EngineError(.notFound) }
        return item
    }
    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef { throw EngineError(.unimplemented) }
    func readRange(_ id: InodeID, version: String, offset: Int, length: Int,
                   alignment: Int) async throws -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int)) {
        throw EngineError(.unimplemented)
    }
    func write(id: InodeID?, fields: ItemMetadata, contents: CacheFileRef?,
               baseVersion: String?) async throws -> ItemMetadata { throw EngineError(.unimplemented) }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws { throw EngineError(.unimplemented) }
    func enumerate(container: InodeID, page: String?) async throws -> (items: [ItemMetadata], nextPage: String?) {
        ([], nil)
    }
    func enumerateChanges(container: InodeID, anchor: String) async throws
        -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool) {
        ([], [], anchor, false)
    }
    func setContentPolicy(_ id: InodeID, policy: ContentPolicy) async throws {}
    func requestDownload(_ id: InodeID, range: (offset: Int, length: Int)?) async throws -> PrefetchAck {
        PrefetchAck(path: id.rawValue, queuedBlocks: 0)
    }
    func evict(_ id: InodeID) async throws -> EvictAck { EvictAck(path: id.rawValue, evictedBlocks: 0, freedBytes: 0) }
}
