// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Pure logic behind the Pinned Items view (WS2): the PinState → PinnedItem
// projection (CONTRACTS §4.3), the per-item derivations, the filespace-wide
// PinnedSummary rollup, the display sort, and the offline fixture. No SwiftUI —
// the view renders whatever these compute.
//
// Cache state is two-valued: a pinned path is either `.pinned` (fully resident)
// or `.pinning` (still materializing). An unpinned/evicted path has no pin record,
// so it never appears in the list.

@Suite(.timeLimit(.minutes(1)))
struct PinnedSummaryTests {

    private let MiB: UInt64 = 1024 * 1024
    private let GiB: UInt64 = 1024 * 1024 * 1024

    private func item(_ path: String, cached: UInt64, total: UInt64,
                      state: PinCacheState, recursive: Bool = false) -> PinnedItem {
        PinnedItem(from: PinState(path: path, pinned: true, recursive: recursive,
                                  blocks: 0, cachedBytes: cached, totalBytes: total,
                                  cacheState: state))
    }

    // MARK: PinnedItem(from:) projection (CONTRACTS §4.3)

    @Test func projectionCarriesByteAccountingAndState() {
        let p = PinState(path: "Proxies/Reel1.mov", pinned: true, recursive: true,
                         blocks: 128, cachedBytes: 64 * MiB, totalBytes: 128 * MiB,
                         cacheState: .pinning)
        let i = PinnedItem(from: p)
        #expect(i.id == "Proxies/Reel1.mov")
        #expect(i.path == "Proxies/Reel1.mov")
        #expect(i.recursive)
        #expect(i.cachedBytes == 64 * MiB)
        #expect(i.totalBytes == 128 * MiB)
        #expect(i.state == .pinning)
    }

    @Test func projectionToleratesOlderDaemonOmittingAppendedFields() {
        // Older daemon: cachedBytes/totalBytes/cacheState all nil. The projection
        // derives the same two-state result the engine would: fully resident →
        // pinned, otherwise pinning.
        let pinnedOnly = PinState(path: "a", pinned: true, recursive: false, blocks: 1)
        #expect(PinnedItem(from: pinnedOnly).cachedBytes == 0)
        #expect(PinnedItem(from: pinnedOnly).totalBytes == 0)
        // 0 of 0 known bytes → still pinning (not yet known-resident).
        #expect(PinnedItem(from: pinnedOnly).state == .pinning)
        // Fully resident with bytes known → pinned.
        let resident = PinState(path: "c", pinned: true, recursive: false, blocks: 1,
                                cachedBytes: 4 * MiB, totalBytes: 4 * MiB)
        #expect(PinnedItem(from: resident).state == .pinned)
        // Partially resident with bytes known → pinning.
        let partial = PinState(path: "d", pinned: true, recursive: false, blocks: 1,
                               cachedBytes: 1 * MiB, totalBytes: 4 * MiB)
        #expect(PinnedItem(from: partial).state == .pinning)
    }

    // MARK: Per-item derivations

    @Test func residentFractionAndPercent() {
        let half = item("x", cached: 50 * MiB, total: 100 * MiB, state: .pinning)
        #expect(abs(half.residentFraction - 0.5) < 0.0001)
        #expect(half.residentPercent == 50)
    }

    @Test func residentFractionGuardsZeroTotal() {
        let zero = item("x", cached: 0, total: 0, state: .pinning)
        #expect(zero.residentFraction == 0)   // no NaN
        #expect(zero.residentPercent == 0)
    }

    @Test func residentFractionClampsOverflow() {
        // Defensive: cached > total should never exceed 1.0.
        let over = item("x", cached: 200 * MiB, total: 100 * MiB, state: .pinned)
        #expect(over.residentFraction == 1.0)
    }

    @Test func displayNameIsLastPathComponent() {
        #expect(item("Projects/Cut.fcpbundle", cached: 0, total: 1, state: .pinned).displayName == "Cut.fcpbundle")
        #expect(item("Proxies", cached: 0, total: 1, state: .pinned).displayName == "Proxies")
    }

    // MARK: Display sort (pinned → pinning, then size, then path)

    @Test func sortGroupsByStateThenSize() {
        let items = [
            item("pinning-small", cached: 0, total: 1 * MiB, state: .pinning),
            item("pinning-big", cached: 1 * GiB, total: 4 * GiB, state: .pinning),
            item("pinned-small", cached: 1 * MiB, total: 1 * MiB, state: .pinned),
            item("pinned-big", cached: 9 * GiB, total: 9 * GiB, state: .pinned),
        ]
        let sorted = items.sortedForDisplay().map(\.path)
        // pinned first (largest pinned first), then pinning (largest pinning first).
        #expect(sorted == ["pinned-big", "pinned-small", "pinning-big", "pinning-small"])
    }

    @Test func sortIsDeterministicOnTies() {
        let a = item("z-same", cached: 1, total: 10 * MiB, state: .pinned)
        let b = item("a-same", cached: 1, total: 10 * MiB, state: .pinned)
        // Equal state + size → tiebreak by path ascending.
        #expect([a, b].sortedForDisplay().map(\.path) == ["a-same", "z-same"])
    }

    // MARK: PinnedSummary rollup

    @Test func summaryAggregatesBytesAndCounts() {
        let items = [
            item("p", cached: 2 * GiB, total: 2 * GiB, state: .pinned),
            item("q", cached: 1 * GiB, total: 4 * GiB, state: .pinning),
            item("r", cached: 0, total: 1 * GiB, state: .pinning),
        ]
        let s = PinnedSummary(items: items)
        #expect(s.itemCount == 3)
        #expect(s.totalCachedBytes == 3 * GiB)          // 2 + 1 + 0
        #expect(s.totalBytes == 7 * GiB)                // 2 + 4 + 1
        #expect(s.pinnedCount == 1)
        #expect(s.pinningCount == 2)
        #expect(abs(s.residentFraction - 3.0 / 7.0) < 0.0001)
        #expect(!s.isEmpty)
    }

    @Test func emptySummaryIsZeroAndEmpty() {
        let s = PinnedSummary(items: [])
        #expect(s.isEmpty)
        #expect(s.itemCount == 0)
        #expect(s.totalCachedBytes == 0)
        #expect(s.totalBytes == 0)
        #expect(s.residentFraction == 0)   // no divide-by-zero
    }

    // MARK: Cache-state display vocabulary

    @Test func cacheStateLabelsAndSortRank() {
        #expect(PinCacheState.pinned.displayLabel == "Pinned")
        #expect(PinCacheState.pinning.displayLabel == "Pinning")
        #expect(PinCacheState.pinned.sortRank < PinCacheState.pinning.sortRank)
    }

    // MARK: Offline fixture (Mock / no-daemon fallback)

    @Test func fixtureSpansBothCacheStates() {
        let states = Set(PinnedItem.fixtures().map(\.state))
        #expect(states == [.pinned, .pinning])
    }

    @Test func fixtureIsInternallyConsistent() {
        for item in PinnedItem.fixtures() {
            #expect(item.cachedBytes <= item.totalBytes)        // never over-resident
            switch item.state {
            case .pinned:  #expect(item.cachedBytes == item.totalBytes)
            case .pinning: #expect(item.cachedBytes < item.totalBytes)
            }
        }
    }

    // MARK: - PinnedSort (Pinned table's Name / Size / Status columns)

    @Test func defaultSortIsNameAscending() {
        #expect(PinnedSort.default.field == .name)
        #expect(PinnedSort.default.direction == .ascending)
    }

    @Test func sortByNameAscendingIsCaseInsensitiveAndLocaleAware() {
        let items = [
            item("Zebra.mov", cached: 0, total: 1, state: .pinned),
            item("apple.mov", cached: 0, total: 1, state: .pinned),
            item("Banana.mov", cached: 0, total: 1, state: .pinned),
        ]
        let sorted = PinnedSort(field: .name, direction: .ascending).apply(to: items)
        #expect(sorted.map(\.displayName) == ["apple.mov", "Banana.mov", "Zebra.mov"])
    }

    @Test func sortByNameDescendingReverses() {
        let items = [
            item("a", cached: 0, total: 1, state: .pinned),
            item("b", cached: 0, total: 1, state: .pinned),
            item("c", cached: 0, total: 1, state: .pinned),
        ]
        let sorted = PinnedSort(field: .name, direction: .descending).apply(to: items)
        #expect(sorted.map(\.path) == ["c", "b", "a"])
    }

    @Test func sortBySizeOrdersByTotalBytes() {
        let items = [
            item("small", cached: 0, total: 1 * MiB, state: .pinned),
            item("large", cached: 0, total: 9 * GiB, state: .pinned),
            item("mid", cached: 0, total: 1 * GiB, state: .pinned),
        ]
        let ascending = PinnedSort(field: .size, direction: .ascending).apply(to: items)
        #expect(ascending.map(\.path) == ["small", "mid", "large"])
        let descending = PinnedSort(field: .size, direction: .descending).apply(to: items)
        #expect(descending.map(\.path) == ["large", "mid", "small"])
    }

    @Test func sortByStatusGroupsPinnedBeforePinning() {
        let items = [
            item("pinning-1", cached: 1, total: 4, state: .pinning),
            item("pinned-1", cached: 1, total: 1, state: .pinned),
            item("pinning-2", cached: 1, total: 8, state: .pinning),
        ]
        let ascending = PinnedSort(field: .status, direction: .ascending).apply(to: items)
        #expect(ascending.first?.state == .pinned)
        #expect(ascending.map(\.path) == ["pinned-1", "pinning-1", "pinning-2"])  // tie → path
    }

    @Test func sortTiesBreakOnPathForDeterminism() {
        let items = [
            item("z-tie", cached: 5, total: 10, state: .pinned),
            item("a-tie", cached: 5, total: 10, state: .pinned),
        ]
        #expect(PinnedSort(field: .size, direction: .ascending).apply(to: items).map(\.path)
                == ["a-tie", "z-tie"])
    }

    @Test func tappedSameFieldTogglesDirection() {
        let asc = PinnedSort(field: .size, direction: .ascending)
        #expect(asc.tapped(.size).direction == .descending)
        #expect(asc.tapped(.size).tapped(.size).direction == .ascending)
    }

    @Test func tappedDifferentFieldSwitchesAndResetsAscending() {
        let sizeDescending = PinnedSort(field: .size, direction: .descending)
        let result = sizeDescending.tapped(.name)
        #expect(result.field == .name)
        #expect(result.direction == .ascending)
    }
}
