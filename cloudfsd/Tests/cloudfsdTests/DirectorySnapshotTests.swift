// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSCrypto
import CloudFSGateway
import CloudFSSMB
@testable import cloudfsd

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class DirectorySnapshotTests: XCTestCase {
    private func makeEngine() throws -> (CloudFSEngine, String) {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("directory-snapshot-\(UUID())").path
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "snapshot-test"),
                                        session: GWStub.session())
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: dir, cacheSizeBytes: 8 << 20,
            controlSocketPath: "/tmp/unused-directory-snapshot.sock", gatewayBaseURL: "https://gw.test"),
            gateway: gateway, blobSession: GWStub.session(),
            key: try FilespaceKey(masterKeyBytes: Data(repeating: 3, count: 32)))
        return (engine, dir)
    }

    private func snapshotJSON(id: String, parent: String, name: String) -> String {
        #"{"granted":true,"directory":{"id":"\#(id)","parent":"\#(parent)","name":"\#(name)","isDir":true,"size":0,"contentVersion":"dir-v1","version":1},"items":[{"id":"child","parent":"\#(id)","name":"clip.mov","isDir":false,"size":10,"contentVersion":"file-v1","version":2}]}"#
    }

    private func routeSnapshot(_ id: String = "share", parent: String = "hidden", name: String = "Actual") {
        GWStub.on("POST /v1/filespaces/fs/open-handles", json: snapshotJSON(id: id, parent: parent, name: name))
    }

    func testBoundedSnapshotAdoptionRejectsStaleEpochAndWarmsChildren() async throws {
        GWStub.reset()
        let (engine, directory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        GWStub.on("GET /v1/filespaces/fs/mount-roots", status: 404, json: #"{"error":"not found"}"#)
        GWStub.on("GET /v1/filespaces/fs/items/root", json: #"{"id":"root","parent":null,"name":"","isDir":true,"size":0,"contentVersion":"root-v1","version":1}"#)
        GWStub.on("GET /v1/filespaces/fs/items") { request in
            let parent = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == "parent" }?.value
            guard parent == "root" else { return (500, #"{"error":"unexpected_listing"}"#) }
            return (200, #"{"items":[{"id":"share","parent":"root","name":"Share","isDir":true,"size":0,"contentVersion":"dir-v1","version":1}],"cursor":null}"#)
        }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let configuredGateway = await engine.sessionGateway()
        XCTAssertTrue(configuredGateway.supportsOpenHandles)
        routeSnapshot("share", parent: "root", name: "Share")
        let path = EngineDataPathAdapter(filespace: "fs", engine: engine)
        let table = NodeTable(engine: path)
        let resolved = try await table.resolve(components: ["Share"])
        let target = try XCTUnwrap(resolved)
        let firstHandle = UUID().uuidString
        let staleReservation = await table.reserveDirectorySnapshotOpen(target, handle: firstHandle,
            access: .read, sharing: [.read, .write, .delete])
        let stale = try XCTUnwrap(staleReservation)
        let conflictingReservation = await table.reserveDirectorySnapshotOpen(target, handle: UUID().uuidString,
            access: .write, sharing: [])
        XCTAssertNil(conflictingReservation, "local share reservation must remain held during snapshot")
        let staleSnapshotResult = try await path.directorySnapshot(target.id, handle: firstHandle,
            access: .read, sharing: [.read, .write, .delete])
        XCTAssertEqual(GWStub.count("POST /v1/filespaces/fs/open-handles"), 1)
        let staleSnapshot = try XCTUnwrap(staleSnapshotResult)
        await table.invalidateListing(target.id)
        let staleAdoption = await table.adoptDirectorySnapshot(staleSnapshot, reservation: stale)
        XCTAssertNil(staleAdoption, "a directory listing invalidated during the HTTP request cannot be installed")
        await table.endLocalOpen(target.id, handle: firstHandle)

        let handle = UUID().uuidString
        let currentReservation = await table.reserveDirectorySnapshotOpen(target, handle: handle,
            access: .read, sharing: [.read, .write, .delete])
        let current = try XCTUnwrap(currentReservation)
        let snapshotResult = try await path.directorySnapshot(target.id, handle: handle,
            access: .read, sharing: [.read, .write, .delete])
        let snapshot = try XCTUnwrap(snapshotResult)
        let adoptedSnapshot = await table.adoptDirectorySnapshot(snapshot, reservation: current)
        let pinned = try XCTUnwrap(adoptedSnapshot)
        XCTAssertEqual(pinned.items.map { $0.metadata.name }, ["clip.mov"])
        let children = try await table.presentationChildren(of: target.id)
        XCTAssertEqual(children.map { $0.metadata.name }, ["clip.mov"])
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/items"), 1,
                       "the snapshot supplies the query-directory children without another list request")
        await table.invalidateListing(target.id)
        XCTAssertEqual(pinned.items.map { $0.metadata.name }, ["clip.mov"],
                       "the SMB open keeps its immutable query view after cache invalidation")
        await table.endLocalOpen(target.id, handle: handle)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: true))
    }

    func testRootedSnapshotProjectsDirectAndNamedGrantsButNotAggregateRoot() async throws {
        GWStub.reset()
        let (engine, directory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        GWStub.on("GET /v1/filespaces/fs/mount-roots", status: 404, json: #"{"error":"not found"}"#)
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        routeSnapshot("share", parent: "hidden", name: "Actual")
        let base = EngineDataPathAdapter(filespace: "fs", engine: engine)
        let handle = UUID().uuidString

        let direct = RootedDataPath(base: base,
            roots: [FilespaceMountRoot(id: "share", name: "Mounted Alias", mountAsRoot: true)],
            directRoot: InodeID("share"))
        let directSnapshotResult = try await direct.directorySnapshot(.root, handle: handle,
            access: .read, sharing: [.read, .write, .delete])
        let directSnapshot = try XCTUnwrap(directSnapshotResult)
        XCTAssertEqual(directSnapshot.directory.id, .root)
        XCTAssertNil(directSnapshot.directory.parent)
        XCTAssertEqual(directSnapshot.items.first?.parent, .root)

        GWStub.reset()
        let (aggregateEngine, aggregateDirectory) = try makeEngine()
        defer { try? FileManager.default.removeItem(atPath: aggregateDirectory) }
        GWStub.on("GET /v1/filespaces/fs/mount-roots", status: 404, json: #"{"error":"not found"}"#)
        _ = try await aggregateEngine.connect(FilespaceConnectParams(filespace: "fs"))
        routeSnapshot("share", parent: "hidden", name: "Actual")
        let aggregate = RootedDataPath(base: EngineDataPathAdapter(filespace: "fs", engine: aggregateEngine),
            roots: [FilespaceMountRoot(id: "share", name: "Mounted Alias", mountAsRoot: false)], directRoot: nil)
        let aggregateRootSnapshot = try await aggregate.directorySnapshot(.root, handle: UUID().uuidString,
            access: .read, sharing: [.read, .write, .delete])
        XCTAssertNil(aggregateRootSnapshot, "aggregate virtual root has no single backend namespace snapshot")
        XCTAssertEqual(GWStub.count("POST /v1/filespaces/fs/open-handles"), 0)
        let namedRootSnapshot = try await aggregate.directorySnapshot("share", handle: UUID().uuidString,
            access: .read, sharing: [.read, .write, .delete])
        let namedRoot = try XCTUnwrap(namedRootSnapshot)
        XCTAssertEqual(namedRoot.directory.name, "Mounted Alias")
        XCTAssertEqual(namedRoot.directory.parent, .root)
        XCTAssertEqual(namedRoot.items.first?.parent, InodeID("share"))
        _ = try await aggregateEngine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: true))
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: true))
    }
}
