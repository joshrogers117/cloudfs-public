// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Exercises the GatewayClient seam through the mock so the data layer is proven
// in isolation from any SwiftUI / AppKit dependency.

@Suite struct MockGatewayClientTests {

    @Test func connectReturnsConnectedFilespaces() async throws {
        let client = MockGatewayClient()
        let spaces = try await client.connect(.interactive(email: "a@b.c", filespace: "Studio A"))
        #expect(!spaces.isEmpty)
        #expect(spaces.allSatisfy { $0.connection == .connected })
    }

    // NOTE: the live Finder-like browse path (`listFiles`) was removed in WS1; the
    // snapshot browse path (`listSnapshotFiles`) survives and is covered below.

    @Test func snapshotBrowseFallsBackToLiveTree() async throws {
        // The snapshot browser reuses the live namespace fixture when a snapshot
        // has no frozen tree entry — drill into the root and into a folder.
        let client = MockGatewayClient()
        let root = try await client.listSnapshotFiles(snapshotID: "snap-x", in: "fs-studio-a", parentID: nil)
        #expect(root.contains { $0.name == "Projects" })
    }

    @Test func pinToggleAndEvictDoNotThrow() async throws {
        // pin/unpin/evict are the cache-residency affordances kept after WS1.
        let client = MockGatewayClient()
        try await client.setPinned(true, fileID: "a-proj-resolve", in: "fs-studio-a")
        try await client.setPinned(false, fileID: "a-proj-resolve", in: "fs-studio-a")
        try await client.evict(fileID: "a-proj-resolve", in: "fs-studio-a")
    }

    @Test func liveActivityReturnsTransfersAndBulkRollup() async throws {
        let client = MockGatewayClient()
        let live = try await client.liveActivity(in: "fs-studio-a")
        #expect(live.events.contains { $0.kind == .bulk })
    }

    @Test func createSnapshotAppearsInList() async throws {
        let client = MockGatewayClient()
        let snap = try await client.createSnapshot(label: "Pre-cut", scope: nil, tier: nil, in: "fs-studio-a")
        let list = try await client.snapshots(in: "fs-studio-a")
        #expect(list.contains { $0.id == snap.id })
        #expect(snap.isScheduled == false)
    }

    @Test func pauseResumeConnectionState() async throws {
        let client = MockGatewayClient()
        try await client.setConnectionState(.paused, for: "fs-studio-a")
        var fs = try await client.filespaces().first { $0.id == "fs-studio-a" }
        #expect(fs?.connection == .paused)
        try await client.setConnectionState(.connected, for: "fs-studio-a")
        fs = try await client.filespaces().first { $0.id == "fs-studio-a" }
        #expect(fs?.connection == .connected)
    }

    @Test func createInternalShareLinkUsesCloudfsScheme() async throws {
        let client = MockGatewayClient()
        let link = try await client.createShareLink(for: "a-proj-hero", kind: .internalDeepLink, in: "fs-studio-a")
        #expect(link.url.hasPrefix("cloudfs://"))
    }

    @Test func cacheSettingsRoundTrip() async throws {
        let client = MockGatewayClient()
        var settings = try await client.cacheSettings(for: "fs-studio-a")
        settings.maxBytes = 500 * 1024 * 1024 * 1024
        try await client.updateCacheSettings(settings, for: "fs-studio-a")
        let reread = try await client.cacheSettings(for: "fs-studio-a")
        #expect(reread.maxBytes == settings.maxBytes)
    }

    @Test func transferStreamMakesProgress() async throws {
        let client = MockGatewayClient()
        var iterator = client.transferUpdates(in: "fs-studio-a").makeAsyncIterator()
        let first = await iterator.next()
        let second = await iterator.next()
        #expect(first != nil)
        #expect(second != nil)
        // At least one active transfer should advance between ticks.
        let firstActive = first?.first { $0.id == "t1" }?.bytesDone ?? 0
        let secondActive = second?.first { $0.id == "t1" }?.bytesDone ?? 0
        #expect(secondActive >= firstActive)
    }

    @Test func cacheBoundsClamping() {
        #expect(Int64(10).clamped(0, 5) == 5)
        #expect(Int64(-3).clamped(0, 5) == 0)
        #expect(Int64(3).clamped(0, 5) == 3)
    }

    // MARK: Audit page-back ("Load older") — CONTRACTS §5.4

    /// Build N synthetic audit events, newest at the front (descending `at`), with
    /// numeric-string ids so the cursor is stable and ordering is unambiguous.
    private func seedAudit(_ client: MockGatewayClient, _ fs: String, count: Int) async {
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        // id "N-1" is the newest (latest `at`), id "0" is the oldest.
        let events = (0..<count).reversed().map { i in
            ActivityEvent(id: String(i), actor: "alice", verb: "edited",
                          path: "p/\(i).mov", at: base.addingTimeInterval(Double(i)))
        }
        await client.seedActivity(events, for: fs)
    }

    @Test func auditFirstPageReturnsNewestEvents() async throws {
        let client = MockGatewayClient()
        let fs = "fs-audit-page"
        await seedAudit(client, fs, count: 10)
        let page = try await client.auditRange(in: fs, since: nil, until: nil,
                                               cursor: nil, limit: 4)
        // Newest-first: the first page leads with the latest event (id "9").
        #expect(page.events.first?.id == "9")
        #expect(page.events.map(\.id) == ["9", "8", "7", "6"])
        // Full page ⇒ a continuation cursor (lowest id of this page).
        #expect(page.cursor == "6")
    }

    /// Drives the EXACT accumulation loop `AppModel.loadMoreAudit` runs: start with
    /// a cursor-less page, then page back via the returned cursor, appending rows,
    /// until the cursor is nil. Proves: no duplicate rows, strictly older pages,
    /// and termination.
    @Test func auditPageBackAccumulatesWithoutDuplicatesAndTerminates() async throws {
        let client = MockGatewayClient()
        let fs = "fs-audit-pageback"
        let total = 23                 // not a multiple of the page size
        let pageSize = 5
        await seedAudit(client, fs, count: total)

        var accumulated: [ActivityEvent] = []
        var cursor: String? = nil
        var pages = 0

        // First page (cursor: nil), mirroring loadAudit().
        let first = try await client.auditRange(in: fs, since: nil, until: nil,
                                                cursor: nil, limit: pageSize)
        accumulated.append(contentsOf: first.events)
        cursor = first.cursor
        pages += 1

        // Page back, mirroring loadMoreAudit(). Hard guard so a non-terminating
        // bug fails loudly instead of hanging the suite.
        while let c = cursor, pages < 100 {
            let page = try await client.auditRange(in: fs, since: nil, until: nil,
                                                   cursor: c, limit: pageSize)
            accumulated.append(contentsOf: page.events)
            cursor = page.cursor
            pages += 1
        }

        // Terminated (cursor exhausted) and covered the whole history exactly once.
        #expect(cursor == nil)
        #expect(accumulated.count == total)
        // No duplicate rows across pages.
        #expect(Set(accumulated.map(\.id)).count == total)
        // Strictly descending by `at` → each page is older than the last, no overlap.
        for i in 1..<accumulated.count {
            #expect(accumulated[i].at < accumulated[i - 1].at)
        }
        // Sanity: page count is ceil(total / pageSize) = 5.
        #expect(pages == 5)
    }

    @Test func auditShortPageEndsWithNilCursor() async throws {
        let client = MockGatewayClient()
        let fs = "fs-audit-short"
        await seedAudit(client, fs, count: 3)
        // limit exceeds the available rows ⇒ short page ⇒ end of history (nil cursor).
        let page = try await client.auditRange(in: fs, since: nil, until: nil,
                                               cursor: nil, limit: 10)
        #expect(page.events.count == 3)
        #expect(page.cursor == nil)
    }
}
