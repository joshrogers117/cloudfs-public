// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
@testable import CloudFSCore

final class NotificationCheckpointTests: XCTestCase {
    func testFallbackDrainsEveryHistoricalPageIncludingFilteredEmptyPages() async throws {
        let engine = CheckpointOnlyEngine(mode: .paged)
        let token = try await engine.notificationCheckpoint(container: .root)
        XCTAssertEqual(token, "1203")
        let anchors = await engine.requested
        XCTAssertEqual(anchors, ["", "500", "1000"])
    }

    func testFallbackRejectsNonprogressAndCycles() async throws {
        for mode in [CheckpointOnlyEngine.Mode.stalled, .cycle] {
            let engine = CheckpointOnlyEngine(mode: mode)
            do { _ = try await engine.notificationCheckpoint(container: .root); XCTFail("invalid cursor accepted") }
            catch let error as EngineError { XCTAssertEqual(error.kind, .gatewayError) }
            let count = await engine.requested.count
            XCTAssertLessThanOrEqual(count, 3)
        }
    }

    func testFallbackHasFinitePageBudget() async throws {
        let engine = CheckpointOnlyEngine(mode: .endless)
        do { _ = try await engine.notificationCheckpoint(container: .root); XCTFail("unbounded pagination") }
        catch let error as EngineError { XCTAssertEqual(error.kind, .gatewayError) }
        let count = await engine.requested.count
        XCTAssertEqual(count, 256)
    }

    func testFallbackChecksCancellationAfterPageResponse() async throws {
        let engine = CheckpointOnlyEngine(mode: .cancel)
        let work = Task { try await engine.notificationCheckpoint(container: .root) }
        do { _ = try await work.value; XCTFail("cancelled final page accepted") }
        catch is CancellationError {}
        let count = await engine.requested.count
        XCTAssertEqual(count, 1)
    }
}

private actor CheckpointOnlyEngine: EngineDataPath {
    enum Mode { case paged, stalled, cycle, endless, cancel }
    let mode: Mode
    private(set) var requested: [String] = []
    init(mode: Mode) { self.mode = mode }
    func enumerateChanges(container: InodeID, anchor: String) async throws
        -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool) {
        requested.append(anchor)
        switch mode {
        case .paged:
            return ([], [], anchor == "" ? "500" : anchor == "500" ? "1000" : "1203", anchor != "1000")
        case .stalled: return ([], [], anchor, true)
        case .cycle: return ([], [], anchor == "" ? "a" : "", true)
        case .endless: return ([], [], String(requested.count), true)
        case .cancel: withUnsafeCurrentTask { $0?.cancel() }; return ([], [], "final", false)
        }
    }
    func lookup(_ id: InodeID) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func enumerate(container: InodeID, page: String?) async throws -> (items: [ItemMetadata], nextPage: String?) { throw EngineError.unimplemented() }
    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef { throw EngineError.unimplemented() }
    func readRange(_ id: InodeID, version: String, offset: Int, length: Int, alignment: Int) async throws -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int)) { throw EngineError.unimplemented() }
    func write(id: InodeID?, fields: ItemMetadata, contents: CacheFileRef?, baseVersion: String?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws { throw EngineError.unimplemented() }
    func setContentPolicy(_ id: InodeID, policy: ContentPolicy) async throws { throw EngineError.unimplemented() }
    func requestDownload(_ id: InodeID, range: (offset: Int, length: Int)?) async throws -> PrefetchAck { throw EngineError.unimplemented() }
    func evict(_ id: InodeID) async throws -> EvictAck { throw EngineError.unimplemented() }
}
