// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CloudFSCore
import CloudFSGateway
@testable import cloudfsd

final class ChangeFeedPaginationTests: XCTestCase {
    func testNotificationCheckpointUsesHighWaterThroughReachabilityAndVirtualRoot() async throws {
        let engine = fixture()
        GWStub.on("GET /v1/filespaces/fs/changes") { request in
            let query = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems
            XCTAssertEqual(query?.first(where: { $0.name == "limit" })?.value, "1")
            return (200, #"{"anchor":1203,"items":[],"cursor":1,"visibility":"member-read"}"#)
        }
        let roots = [FilespaceMountRoot(id: "shared", name: "Shared", mountAsRoot: false)]
        let projection = MountRootSnapshot(roots)
        let rooted = RootedDataPath(base: await engine.dataPath(for: "fs"), roots: roots,
                                    directRoot: nil, projection: projection)
        let first = try await rooted.notificationCheckpoint(container: .root)
        let second = try await rooted.notificationCheckpoint(container: .root)
        XCTAssertEqual(first, second, "An unchanged virtual-root folder snapshot must stay quiet")
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/changes"), 2)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/items/root"), 0, "Never enumerate a forbidden real root")
        projection.set([])
        let revoked = try await rooted.notificationCheckpoint(container: .root)
        XCTAssertNotEqual(revoked, first, "Local grant projection changes must invalidate the virtual root")
        GWStub.on("GET /v1/filespaces/fs/changes", status: 403, json: #"{"error":"forbidden"}"#)
        do { _ = try await rooted.notificationCheckpoint(container: .root); XCTFail("revoked access became an empty token") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
    }

    private func fixture() -> CloudFSEngine {
        GWStub.reset()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("change-feed-\(UUID())")
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "test"),
                                        session: GWStub.session())
        return CloudFSEngine(config: EngineConfig(cacheDir: directory.path, cacheSizeBytes: 8 << 20,
            controlSocketPath: "/tmp/unused", gatewayBaseURL: "https://gw.test"), gateway: gateway)
    }

    private func installPagedFeed() -> (updated: Set<InodeID>, deleted: Set<InodeID>) {
        // Match the backend's 500-row default. Tombstones straddle both page
        // boundaries so jumping to the global anchor loses updates AND removals.
        let count = 1_203
        let deletedSequences: Set<Int> = [500, 501, 1_000, 1_001, 1_203]
        let rows = (1...count).map { sequence in
            #"{"id":"item-\#(sequence)","parent":"shared","name":"item-\#(sequence)","isDir":false,"size":0,"version":1,"updatedSeq":\#(sequence),"deleted":\#(deletedSequences.contains(sequence))}"#
        }
        GWStub.on("GET /v1/filespaces/fs/changes") { request in
            let query = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems
            let since = query?.first { $0.name == "since" }?.value.flatMap(Int.init) ?? 0
            let end = min(since + 500, count)
            let page = since < count ? Array(rows[since..<end]) : []
            let cursor = end < count ? String(end) : "null"
            return (200, "{\"anchor\":\(count),\"items\":[\(page.joined(separator: ","))],\"cursor\":\(cursor)}")
        }
        return (Set((1...count).filter { !deletedSequences.contains($0) }.map { InodeID("item-\($0)") }),
                Set(deletedSequences.map { InodeID("item-\($0)") }))
    }

    func testControlDataPathDeliversEveryPageBeforeAdvancingToHighWaterAnchor() async throws {
        let engine = fixture()
        let expected = installPagedFeed()
        var anchor = "0"
        var anchors: [String] = []
        var updated: [InodeID] = []
        var deleted: [InodeID] = []
        for _ in 0..<4 {
            let page = try await engine.dataEnumerateChanges(DataEnumerateChangesParams(
                filespace: "fs", container: .root, anchor: anchor))
            updated.append(contentsOf: page.updated.map(\.id))
            deleted.append(contentsOf: page.deleted)
            anchor = page.newAnchor
            anchors.append(anchor)
            if !page.moreComing { break }
        }
        XCTAssertEqual(anchors, ["500", "1000", "1203"])
        XCTAssertEqual(Set(updated), expected.updated)
        XCTAssertEqual(Set(deleted), expected.deleted)
        XCTAssertEqual(updated.count, expected.updated.count, "pagination must not replay updates")
        XCTAssertEqual(deleted.count, expected.deleted.count, "pagination must not replay tombstones")
        let caughtUp = try await engine.dataEnumerateChanges(DataEnumerateChangesParams(
            filespace: "fs", container: .root, anchor: anchor))
        XCTAssertTrue(caughtUp.updated.isEmpty)
        XCTAssertTrue(caughtUp.deleted.isEmpty)
        XCTAssertEqual(caughtUp.newAnchor, "1203")
        XCTAssertFalse(caughtUp.moreComing)
    }

    func testRootedDataPathPreservesContinuationAcrossTheProjection() async throws {
        let engine = fixture()
        let expected = installPagedFeed()
        let base = await engine.dataPath(for: "fs")
        let rooted = RootedDataPath(base: base,
            roots: [FilespaceMountRoot(id: "shared", name: "Shared", mountAsRoot: true)], directRoot: "shared")
        var anchor = "0"
        var updated: [InodeID] = [], deleted: [InodeID] = []
        for _ in 0..<4 {
            let page = try await rooted.enumerateChanges(container: .root, anchor: anchor)
            XCTAssertTrue(page.updated.allSatisfy { $0.parent == .root })
            updated.append(contentsOf: page.updated.map(\.id))
            deleted.append(contentsOf: page.deleted)
            anchor = page.newAnchor
            if !page.moreComing { break }
        }
        XCTAssertEqual(Set(updated), expected.updated)
        XCTAssertEqual(Set(deleted), expected.deleted)
        XCTAssertEqual(anchor, "1203")
    }

    func testEmptyFilteredPageStillContinuesToLaterVisibleChanges() async throws {
        let engine = fixture()
        GWStub.on("GET /v1/filespaces/fs/changes") { request in
            let query = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)?.queryItems
            let since = query?.first { $0.name == "since" }?.value.flatMap(Int.init) ?? 0
            if since == 0 { return (200, #"{"anchor":501,"items":[],"cursor":500}"#) }
            if since == 500 {
                return (200, #"{"anchor":501,"items":[{"id":"visible","parent":"root","name":"visible","isDir":false,"size":0,"deleted":true}],"cursor":null}"#)
            }
            return (200, #"{"anchor":501,"items":[],"cursor":null}"#)
        }
        let first = try await engine.dataEnumerateChanges(DataEnumerateChangesParams(
            filespace: "fs", container: .root, anchor: "0"))
        XCTAssertTrue(first.updated.isEmpty)
        XCTAssertTrue(first.deleted.isEmpty)
        XCTAssertTrue(first.moreComing)
        XCTAssertEqual(first.newAnchor, "500")
        let second = try await engine.dataEnumerateChanges(DataEnumerateChangesParams(
            filespace: "fs", container: .root, anchor: first.newAnchor))
        XCTAssertEqual(second.deleted, [InodeID("visible")])
        XCTAssertEqual(second.newAnchor, "501")
        XCTAssertFalse(second.moreComing)
    }
}
