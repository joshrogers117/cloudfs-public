// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSMount holds the mount-adapter protocol + a no-op stub. The production
// backend (SMBLoopbackMountBackend) and its VFS mapping live in CloudFSSMB and are
// exercised there. These tests cover the stub / default-backend contract.

import XCTest
import CloudFSCore
@testable import CloudFSMount

final class CloudFSMountTests: XCTestCase {

    func testStubBackendIsUnavailableAndRefusesMount() async {
        let b = StubMountBackend()
        XCTAssertEqual(b.kind, "stub")
        XCTAssertFalse(b.isAvailable)
        do {
            try await b.mount(filespace: "fs1", displayName: nil, at: "/tmp/mnt", engine: MockEngine())
            XCTFail("stub must refuse to mount")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .notConnected)
        } catch { XCTFail("wrong error: \(error)") }
    }

    func testDefaultBackendIsStub() {
        // No backend injected → the no-op stub (headless/CI). The daemon wires the
        // real SMBLoopbackMountBackend explicitly.
        XCTAssertEqual(defaultMountBackend().kind, "stub")
    }
}

/// Minimal `EngineDataPath` stub for the mount tests (all ops unused here).
private struct MockEngine: EngineDataPath {
    var plaintextSpillDir: String { NSTemporaryDirectory() }
    func lookup(_ id: InodeID) async throws -> ItemMetadata { throw EngineError(.notFound) }
    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef { throw EngineError(.notFound) }
    func readRange(_ id: InodeID, version: String, offset: Int, length: Int,
                   alignment: Int) async throws -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int)) {
        throw EngineError(.notFound)
    }
    func write(id: InodeID?, fields: ItemMetadata, contents: CacheFileRef?,
               baseVersion: String?) async throws -> ItemMetadata { throw EngineError(.notFound) }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws { throw EngineError(.notFound) }
    func enumerate(container: InodeID, page: String?) async throws
        -> (items: [ItemMetadata], nextPage: String?) { ([], nil) }
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
