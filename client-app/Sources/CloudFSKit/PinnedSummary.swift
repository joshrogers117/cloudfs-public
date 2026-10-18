// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - Pinned-view pure logic (WS2 — owned by the pinned-view agent)
//
// Lives in CloudFSKit (no SwiftUI) so the Pinned Items view's *derivations* —
// the total-cache-used summary, the per-state counts, the cache-state display
// vocabulary, and the sample fixture that drives the Mock/no-daemon path — are
// unit-testable in isolation. `PinnedItemsView` renders whatever these compute;
// the math + labels never live inside a SwiftUI body.
//
// `PinnedItem` itself (the row projection of `PinState`) is defined in
// EngineClient.swift per CONTRACTS §4.3; this file only adds the projections
// around it (summary, labels, fixtures), all additive.

// MARK: - PinCacheState — display vocabulary

extension PinCacheState {

    /// Human label for the cache-state chip ("Pinned" / "Pinning").
    public var displayLabel: String {
        switch self {
        case .pinned:  return "Pinned"
        case .pinning: return "Pinning"
        }
    }

    /// One-line explanation surfaced as the chip's tooltip / VoiceOver detail.
    public var explanation: String {
        switch self {
        case .pinned:  return "Fully resident locally — kept on disk, never evicted."
        case .pinning: return "Pin set — still materializing the data onto disk."
        }
    }

    /// Stable sort rank so the flat list groups the most-resident pins first
    /// (pinned → pinning), independent of the engine's return order.
    public var sortRank: Int {
        switch self {
        case .pinned:  return 0
        case .pinning: return 1
        }
    }
}

// MARK: - PinnedItem derivations

extension PinnedItem {
    public var needsAttention: Bool { failureReason?.isEmpty == false }
    public var statusLabel: String { needsAttention ? "Needs attention" : state.displayLabel }
    public var statusRank: Int { needsAttention ? 2 : state.sortRank }

    /// Fraction of the item that is resident locally (0…1). 0 when the total is
    /// unknown/zero so the gauge degrades gracefully (shows empty, not NaN).
    public var residentFraction: Double {
        guard totalBytes > 0 else { return 0 }
        return min(1, Double(cachedBytes) / Double(totalBytes))
    }

    /// Resident-percentage as an integer 0…100 (for labels / accessibility).
    public var residentPercent: Int {
        Int((residentFraction * 100).rounded())
    }

    /// The last path component (file/folder name) for the row's primary label;
    /// the full `path` remains the secondary line.
    public var displayName: String {
        let name = (path as NSString).lastPathComponent
        return name.isEmpty ? path : name
    }

    /// Sort key for a stable, sensible default order: by cache state (most
    /// resident first), then largest item first, then path for determinism.
    public func ordersBefore(_ other: PinnedItem) -> Bool {
        if statusRank != other.statusRank {
            return statusRank < other.statusRank
        }
        if totalBytes != other.totalBytes {
            return totalBytes > other.totalBytes
        }
        return path < other.path
    }
}

extension Array where Element == PinnedItem {
    /// The Pinned-view default ordering (see `PinnedItem.ordersBefore`).
    public func sortedForDisplay() -> [PinnedItem] {
        sorted { $0.ordersBefore($1) }
    }
}

// MARK: - PinnedSort — the sortable-table column state + comparator
//
// Drives the Pinned view's Name / Size / Status column headers. Pure value type
// (field + direction) with an `apply(to:)` comparator, so the sort behavior is
// unit-testable without SwiftUI. Default is Name ascending.

public struct PinnedSort: Sendable, Equatable {

    public enum Field: String, Sendable, CaseIterable, Identifiable {
        case name, size, status
        public var id: String { rawValue }

        /// Column header label.
        public var label: String {
            switch self {
            case .name:   return "Name"
            case .size:   return "Size"
            case .status: return "Status"
            }
        }
    }

    public enum Direction: Sendable, Equatable {
        case ascending, descending

        public var toggled: Direction { self == .ascending ? .descending : .ascending }
    }

    public var field: Field
    public var direction: Direction

    public init(field: Field, direction: Direction) {
        self.field = field
        self.direction = direction
    }

    /// The table's default ordering: Name ascending.
    public static let `default` = PinnedSort(field: .name, direction: .ascending)

    /// Tapping a column header: tapping the ALREADY-active column reverses its
    /// direction (the familiar Finder-list-view gesture); tapping a different
    /// column switches the sort to it, starting ascending.
    public func tapped(_ field: Field) -> PinnedSort {
        if self.field == field {
            return PinnedSort(field: field, direction: direction.toggled)
        }
        return PinnedSort(field: field, direction: .ascending)
    }

    /// Apply this sort to a row set. Each field has its own natural comparator;
    /// ties always break on `path` ascending so the order is deterministic
    /// regardless of the engine's return order.
    public func apply(to items: [PinnedItem]) -> [PinnedItem] {
        let ascending: (PinnedItem, PinnedItem) -> Bool
        switch field {
        case .name:
            ascending = {
                $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending
            }
        case .size:
            ascending = { $0.totalBytes < $1.totalBytes }
        case .status:
            ascending = { $0.statusRank < $1.statusRank }
        }
        let sorted = items.sorted { a, b in
            if ascending(a, b) { return true }
            if ascending(b, a) { return false }
            return a.path < b.path
        }
        return direction == .ascending ? sorted : sorted.reversed()
    }
}

// MARK: - PinnedSummary — the filespace-wide "total cache used" rollup

/// Aggregate accounting across every pinned item in a filespace. Drives the
/// summary strip at the top of `PinnedItemsView` (total cached / total pinned
/// size + per-state counts). Pure value type; recomputed from `[PinnedItem]`.
public struct PinnedSummary: Sendable, Equatable {
    /// Number of pinned items (rows).
    public let itemCount: Int
    /// Σ cachedBytes — total bytes resident locally across all pins.
    public let totalCachedBytes: UInt64
    /// Σ totalBytes — full size of everything pinned (resident or not).
    public let totalBytes: UInt64
    /// Per-state row counts (for the legend / "3 pinning" sub-labels).
    public let pinnedCount: Int
    public let pinningCount: Int
    public let needsAttentionCount: Int

    public init(items: [PinnedItem]) {
        self.itemCount = items.count
        self.totalCachedBytes = items.reduce(0) { $0 + $1.cachedBytes }
        self.totalBytes = items.reduce(0) { $0 + $1.totalBytes }
        self.pinnedCount  = items.filter { $0.state == .pinned && !$0.needsAttention }.count
        self.pinningCount = items.filter { $0.state == .pinning && !$0.needsAttention }.count
        self.needsAttentionCount = items.filter(\.needsAttention).count
    }

    /// Fraction of the pinned set that is resident locally (0…1).
    public var residentFraction: Double {
        guard totalBytes > 0 else { return 0 }
        return min(1, Double(totalCachedBytes) / Double(totalBytes))
    }

    /// `true` when there is nothing pinned — the view shows its empty state.
    public var isEmpty: Bool { itemCount == 0 }
}

// MARK: - Fixtures (Mock / no-daemon path)
//
// `EngineClient.pinList` is `.unavailable` without a daemon and the gateway has
// no pin-list route, so the Pinned view falls back to this fixture. It mirrors
// realistic post-house pins so the pane builds, previews, and demos offline.

extension PinnedItem {

    /// A small, plausible set of pinned items spanning both cache states,
    /// used by the Mock/no-daemon fallback and SwiftUI previews.
    public static func fixtures() -> [PinnedItem] {
        let GiB: UInt64 = 1024 * 1024 * 1024
        let MiB: UInt64 = 1024 * 1024
        return [
            // Fully resident pinned project bundle.
            PinnedItem(from: PinState(
                path: "Projects/Director Cut.fcpbundle", pinned: true, recursive: true,
                blocks: 1240, cachedBytes: 1240 * MiB, totalBytes: 1240 * MiB,
                cacheState: .pinned)),
            // Recursively-pinned proxies folder, fully resident.
            PinnedItem(from: PinState(
                path: "Proxies", pinned: true, recursive: true,
                blocks: 3600, cachedBytes: 3600 * MiB, totalBytes: 3600 * MiB,
                cacheState: .pinned)),
            // Pinning: large camera-original subtree still materializing onto disk.
            PinnedItem(from: PinState(
                path: "Footage/ProRes Proxy", pinned: true, recursive: true,
                blocks: 9000, cachedBytes: 6 * GiB, totalBytes: 14 * GiB,
                cacheState: .pinning)),
            // Pinning: single file still streaming in.
            PinnedItem(from: PinState(
                path: "Footage/A001_C003.R3D", pinned: true, recursive: false,
                blocks: 2048, cachedBytes: 1 * GiB, totalBytes: 4 * GiB,
                cacheState: .pinning)),
        ]
    }
}
