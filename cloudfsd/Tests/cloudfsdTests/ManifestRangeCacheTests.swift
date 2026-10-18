// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import cloudfsd

final class ManifestRangeCacheTests: XCTestCase {
    func testRetainExactVersionKeepsOnlyCoherentCachedSlices() async throws {
        GWStub.reset()
        let cache = ManifestRangeCache()
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { request in
            let query = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!.queryItems!
            let requested = query.first { $0.name == "contentVersion" }?.value ?? ""
            return (200, #"{"format":2,"item":{"id":"file","name":"file","isDir":false,"size":1,"contentVersion":"\#(requested)","version":1},"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"a","objectKey":"blocks/a","offset":0,"length":1}],"nextOffset":null}"#)
        }
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: false)
        _ = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0)
        _ = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v2", offset: 0)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 2)

        cache.retainExactVersion(filespace: "fs", itemID: "file", version: "v1")
        _ = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 2,
                       "same-version metadata changes should retain an exact coherent slice")
        _ = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v2", offset: 0)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 3,
                       "a prior content version must be pruned")
    }

    func testRetainExactVersionDropsRefreshResultStoredUnderOldRequestKey() async throws {
        GWStub.reset()
        let cache = ManifestRangeCache()
        let item = #"{"id":"file","parent":"root","name":"file","isDir":false,"size":1,"contentVersion":"v2","version":2}"#
        GWStub.on("GET /v1/filespaces/fs/items/file", json: item)
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { request in
            let query = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!.queryItems!
            let requested = query.first { $0.name == "contentVersion" }?.value ?? ""
            if requested == "v1" { return (409, #"{"error":"version_conflict","actual":"v2"}"#) }
            return (200, #"{"format":2,"item":\#(item),"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"b","objectKey":"blocks/b","offset":0,"length":1}],"nextOffset":null}"#)
        }
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: false)
        _ = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0, refreshStaleVersion: true)
        cache.retainExactVersion(filespace: "fs", itemID: "file", version: "v2")
        _ = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0, refreshStaleVersion: true)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 4,
                       "refresh-on-conflict data cannot survive under a stale requested-version key")
    }

    func testRetainExactVersionCancelsPendingFetchBeforeMetadataEventCanReuseIt() async throws {
        GWStub.reset()
        let cache = ManifestRangeCache()
        let started = expectation(description: "manifest fetch in flight")
        let release = DispatchSemaphore(value: 0)
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { _ in
            if GWStub.count("GET /v1/filespaces/fs/blocks/file/range") == 1 {
                started.fulfill()
                _ = release.wait(timeout: .now() + 5)
            }
            return (200, #"{"format":2,"item":{"id":"file","name":"file","isDir":false,"size":1,"contentVersion":"v1","version":1},"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"a","objectKey":"blocks/a","offset":0,"length":1}],"nextOffset":null}"#)
        }
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: true)
        let reader = Task { try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0) }
        await fulfillment(of: [started], timeout: 3)
        cache.retainExactVersion(filespace: "fs", itemID: "file", version: "v1")
        release.signal()
        let value = try await reader.value
        XCTAssertEqual(value.item.contentVersion, "v1")
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 2,
                       "a pending request is cancelled conservatively and retried after metadata changes")
    }

    func testMetadataCommitRetainsReadSliceButStillDropsLegacyResolvedManifest() async throws {
        GWStub.reset()
        let item = #"{"id":"file","parent":"root","name":"file","isDir":false,"size":1,"contentVersion":"v1","version":1}"#
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range", json: #"{"format":2,"item":\#(item),"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"a","objectKey":"blocks/a","offset":0,"length":1}],"nextOffset":null}"#)
        GWStub.on("GET /v1/filespaces/fs/blocks/file", json: #"[{"chunkIdx":0,"blockIdx":0,"blockHash":"a","objectKey":"blocks/a","offset":0,"length":1}]"#)
        GWStub.on("GET /v1/filespaces/fs/items/file", json: item)
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: false)
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("manifest-retain-\(UUID())")
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: root.path, cacheSizeBytes: 1 << 20,
            controlSocketPath: root.appendingPathComponent("socket").path, gatewayBaseURL: "https://gw.test"),
            gateway: gateway, blobSession: GWStub.session())

        _ = try await engine.manifestRanges.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0)
        _ = try await engine.resolvedManifest(filespace: "fs", itemID: "file", contentVersion: "v1")
        _ = try await engine.resolvedManifest(filespace: "fs", itemID: "file", contentVersion: "v1")
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file"), 1)

        await engine.noteCommitted(filespace: "fs", itemID: "file", meta: ItemMetadata(id: "file", parent: "root", name: "renamed", isDir: false,
            size: 1, contentVersion: "v1", metadataVersion: "2"))
        _ = try await engine.manifestRanges.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 1,
                       "metadata-only update should retain the verified current-version range slice")
        _ = try await engine.resolvedManifest(filespace: "fs", itemID: "file", contentVersion: "v1")
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file"), 2,
                       "legacy resolved manifests remain fully invalidated without an exact response-key proof")
    }

    func testChangeNotificationDuringFetchRetriesWithoutPublishingInvalidatedResponse() async throws {
        GWStub.reset()
        let cache = ManifestRangeCache()
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { _ in
            let first = GWStub.count("GET /v1/filespaces/fs/blocks/file/range") == 1
            if first { cache.invalidate(filespace: "fs", itemID: "file") }
            let name = first ? "old-name" : "current-name"
            return (200, #"{"format":2,"item":{"id":"file","name":"\#(name)","isDir":false,"size":1,"contentVersion":"v1","version":1},"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"a","objectKey":"blocks/a","offset":0,"length":1}],"nextOffset":null}"#)
        }
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: true)
        let value = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0, refreshStaleVersion: true)
        XCTAssertEqual(value.item.name, "current-name")
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 2)
        let cached = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0, refreshStaleVersion: true)
        XCTAssertEqual(cached.item.name, "current-name")
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 2)
    }

    func testPermissionDenialIsNotRetried() async throws {
        GWStub.reset()
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range", status: 403, json: #"{"error":"forbidden"}"#)
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "member"), session: GWStub.session(), streamingManifests: true)
        do {
            _ = try await ManifestRangeCache().get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0)
            XCTFail("Denied metadata must not become readable")
        } catch let error as EngineError { XCTAssertEqual(error.kind, .permissionDenied) }
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 1)
    }

    func testReaderCancellationDuringInvalidationDoesNotRetry() async throws {
        GWStub.reset()
        let cache = ManifestRangeCache()
        let started = expectation(description: "manifest request in flight")
        let release = DispatchSemaphore(value: 0)
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { _ in
            started.fulfill()
            _ = release.wait(timeout: .now() + 5)
            cache.invalidate(filespace: "fs", itemID: "file")
            return (200, #"{"format":2,"item":{"id":"file","name":"file","isDir":false,"size":1,"contentVersion":"v1","version":1},"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"a","objectKey":"blocks/a","offset":0,"length":1}],"nextOffset":null}"#)
        }
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: true)
        let reader = Task { try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0) }
        await fulfillment(of: [started], timeout: 3)
        reader.cancel(); release.signal()
        do { _ = try await reader.value; XCTFail("Reader cancellation must propagate") }
        catch { XCTAssertTrue(error is CancellationError) }
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 1)
    }

    func testInvalidationFencesOnlyAffectedInflightRequests() async throws {
        for target: InodeID in ["other", "file"] {
            GWStub.reset(); let cache = ManifestRangeCache()
            GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { _ in
                cache.invalidate(filespace: "fs", itemID: target)
                return (200, #"{"format":2,"item":{"id":"file","name":"file","isDir":false,"size":1,"contentVersion":"v1","version":1},"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"a","objectKey":"blocks/a","offset":0,"length":1}],"nextOffset":null}"#)
            }
            let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: true)
            do {
                _ = try await cache.get(gateway: gateway, filespace: "fs", itemID: "file", version: "v1", offset: 0)
                XCTAssertEqual(target, "other")
            } catch {
                XCTAssertEqual(target, "file")
                XCTAssertEqual((error as? EngineError)?.kind, .conflict)
                XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 3)
            }
        }
    }
}
