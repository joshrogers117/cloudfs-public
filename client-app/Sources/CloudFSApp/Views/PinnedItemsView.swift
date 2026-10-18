// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - PinnedItemsView  (WS2 — owned by the pinned-view agent)
//
// A FILESPACE-WIDE sortable table of every pinned item: Name / Size / Status
// columns, each cache state (pinned / pinning) as a chip + a resident bar, with
// a per-row UNPIN action. Above the table, a summary strip rolls up the whole
// pinned set against the engine cache ceiling; header actions jump to Cache
// settings or unpin everything (behind a confirmation). An inviting empty state
// covers "nothing pinned" and points at the real way to pin — Finder, not a
// removed in-app Files browser.
//
// It is driven entirely from `AppModel.pinned` (the @Observable
// `PinnedFeatureModel` in AppModel+Pinned.swift), which prefers the engine
// (`EngineClient.pinList(filespace:)` → `[PinState]` → `[PinnedItem]`) and falls
// back to a Mock/demo fixture ONLY in `.mock` mode — HTTP mode with no reachable
// daemon shows an honest "needs the local engine" state instead of fabricating
// pins for a real account. Unpin reuses the `AppModel.setPinned(false,…)` seam
// (CONTRACTS §1.1); unpinning drops the keep-local pin so the item leaves the
// list. Everything is tokenized via Theme/Components for visual consistency
// with the rest of the app.

struct PinnedItemsView: View {
    @Environment(AppModel.self) private var model
    @State private var showUnpinAllConfirm = false
    @State private var showClearCacheConfirm = false
    @State private var isClearingCache = false

    private var pinned: PinnedFeatureModel { model.pinned }

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Pinned files",
                       subtitle: "Keep the files you work on in this Mac’s local cache.",
                       trailing: AnyView(headerTrailing))
            content
        }
        .background(Theme.bg)
        .task(id: model.selectedFilespaceID) {
            await model.loadPinnedItems()
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(3)) } catch { break }
                await model.loadPinnedItems(showLoading: false)
            }
        }
        // Re-pull when a global Refresh is requested (View ▸ Refresh / toolbar).
        .task(id: model.refreshToken) { await model.loadPinnedItems() }
        .confirmationDialog(
            "Unpin \(pinned.items.count) item\(pinned.items.count == 1 ? "" : "s")?",
            isPresented: $showUnpinAllConfirm, titleVisibility: .visible) {
            Button("Unpin All", role: .destructive) {
                Task { await model.unpinAll(pinned.items) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Files stay in the filespace; they just stop being kept local.")
        }
        // Shares the SAME confirm + action path as the Cache settings pane's
        // Usage card (AppModel.clearCache) — reference-design parity: clearing
        // the cache from either surface reaches identical daemon semantics.
        .confirmationDialog(
            "Clear the local cache?",
            isPresented: $showClearCacheConfirm, titleVisibility: .visible) {
            Button("Clear Cache", role: .destructive) {
                Task {
                    isClearingCache = true
                    _ = await model.clearCache()
                    isClearingCache = false
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Pinned files stay on this Mac, and unsynced changes are never discarded.")
        }
    }

    @ViewBuilder private var headerTrailing: some View {
        HStack(spacing: Theme.Space.md) {
            Button("Manage cache size") { model.section = .cache }
                .cfButton(.subtle, size: .small)
            if pinned.state.hasContent {
                // Same recipe as `.cfButton(.subtle)` (borderless, low-emphasis)
                // but tinted destructive — chaining `.foregroundStyle` on top of
                // `.cfButton(.subtle)` wouldn't win, since that modifier already
                // sets `Theme.accent` internally, closer to the label.
                Button("Unpin all") { showUnpinAllConfirm = true }
                    .buttonStyle(.borderless).controlSize(.small)
                    .foregroundStyle(Theme.Status.error)
            }
        }
    }

    private var refreshButton: some View {
        IconButton(IconSet.refresh, label: "Refresh pinned items") {
            Task { await model.loadPinnedItems() }
        }
    }

    // MARK: Routed content (LOADING / ERROR / EMPTY / LOADED)

    @ViewBuilder private var content: some View {
        if case .loaded(let items) = pinned.state {
            loadedBody(items)
        } else {
            StatePane(state: pinned.state, loadingText: "Reading pinned items…",
                      empty: EmptyState(symbol: IconSet.pin, title: "No pinned files", hint: "Right-click a file or folder in Finder and choose Pin to This Mac."),
                      retry: { Task { await model.loadPinnedItems() } }) { items in loadedBody(items) }
        }
    }

    private func loadedBody(_ items: [PinnedItem]) -> some View {
        let sorted = pinned.sort.apply(to: items)
        return ScrollView {
            VStack(alignment: .leading, spacing: Theme.Space.xl) {
                PinnedSummaryCard(summary: pinned.summary, cacheState: model.cacheState)
                Card("Pinned items") {
                    VStack(spacing: 0) {
                        if !sorted.isEmpty {
                        PinnedColumnHeader(sort: pinned.sort) { field in
                            pinned.sort = pinned.sort.tapped(field)
                        }
                        Divider().overlay(Theme.divider)
                        }
                        if sorted.isEmpty {
                            EmptyState(symbol: IconSet.pin, title: "No pinned files", hint: "Right-click a file or folder in Finder and choose Pin to This Mac to keep it available in the local cache.").frame(minHeight: 230)
                        }
                        ForEach(Array(sorted.enumerated()), id: \.element.id) { index, item in
                            if index > 0 { Divider().overlay(Theme.divider) }
                            PinnedItemRow(
                                item: item,
                                isBusy: pinned.busyPaths.contains(item.path),
                                onUnpin: { Task { await model.unpinItem(item) } },
                                onShowInFinder: { model.showPinnedInFinder(item) },
                                onRetry: { Task { await model.retryPin(item) } },
                                onOpenOffline: { Task { await model.openOfflinePin(item) } })
                        }
                    }
                }
            }
            .padding(Theme.Space.xxl)
        }
    }
}

// MARK: - Column header (sort buttons)

/// The table's Name / Size / Status header row. Each label is a button; the
/// active column shows a chevron for its direction (up = ascending). Mirrors
/// the row layout so columns line up with `PinnedItemRow`'s content.
struct PinnedColumnHeader: View {
    let sort: PinnedSort
    let onTap: (PinnedSort.Field) -> Void

    var body: some View {
        HStack(spacing: Theme.Space.lg) {
            // Leading glyph column (folder/doc) has no header label.
            Color.clear.frame(width: Theme.Metric.leadingIconWidth)

            headerButton(.name, alignment: .leading)

            Spacer(minLength: Theme.Space.md)

            headerButton(.size, alignment: .trailing)
                .frame(width: Theme.Metric.metadataColumnWidth, alignment: .trailing)

            headerButton(.status, alignment: .leading)

            // Trailing action column has no header label.
            Color.clear.frame(width: 96)
        }
        .padding(.vertical, Theme.Space.sm)
    }

    private func headerButton(_ field: PinnedSort.Field, alignment: HorizontalAlignment) -> some View {
        Button { onTap(field) } label: {
            HStack(spacing: Theme.Space.xxs) {
                Text(field.label)
                if sort.field == field {
                    Image(systemName: sort.direction == .ascending
                          ? IconSet.sortAscending : IconSet.sortDescending)
                }
            }
        }
        .buttonStyle(.plain)
        .font(Theme.Font.sectionLabel)
        .tracking(0.5)
        .foregroundStyle(sort.field == field ? Theme.textSecondary : Theme.textTertiary)
        .accessibilityLabel("Sort by \(field.label)\(sort.field == field ? ", \(sort.direction == .ascending ? "ascending" : "descending")" : "")")
    }
}

// MARK: - Summary strip (filespace-wide "total cache used")

struct PinnedSummaryCard: View {
    let summary: PinnedSummary
    /// The engine's cache reading — when loaded, the strip relates the pinned
    /// set to the cache ceiling (the reference design's unified gauge + a
    /// "Remaining pinning" stat); when unavailable, it falls back to the
    /// resident-bytes-only summary that needs no daemon.
    let cacheState: LoadState<CacheSettings>

    var body: some View {
        Card("Pinned cache") {
            if let cache = cacheState.value {
                withCacheContext(cache)
            } else {
                residentOnly
            }
        }
    }

    // MARK: With engine cache context (loaded)

    private func withCacheContext(_ cache: CacheSettings) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.lg) {
            HStack(alignment: .top, spacing: Theme.Space.xxl) {
                VStack(alignment: .leading, spacing: Theme.Space.md) {
                    CacheGauge(usedFraction: cache.usedFraction, pinnedFraction: cache.pinnedFraction)
                        .frame(height: Theme.Metric.gaugeHeight)
                        .accessibilityLabel("Cache \(Int(cache.usedFraction * 100)) percent used, \(Int(cache.pinnedFraction * 100)) percent pinned")
                    Text("Pinned \(ByteFormat.string(cache.pinnedBytes)) · Cache size \(ByteFormat.string(cache.maxBytes)) · \(ByteFormat.string(max(0, cache.maxBytes - cache.usedBytes))) free")
                        .font(Theme.Font.monoMicro).foregroundStyle(Theme.textSecondary)
                }
                Divider().overlay(Theme.divider).frame(height: 40)
                stat(ByteFormat.string(cache.remainingPinningBytes), "remaining pinning", mono: true)
            }
            legendRow
        }
    }

    // MARK: Resident-bytes-only (no daemon)

    private var residentOnly: some View {
        VStack(alignment: .leading, spacing: Theme.Space.lg) {
            HStack(alignment: .firstTextBaseline, spacing: Theme.Space.xl) {
                stat(ByteFormat.string(Int64(clamping: summary.totalCachedBytes)),
                     "resident locally")
                stat("of \(ByteFormat.string(Int64(clamping: summary.totalBytes)))",
                     "total pinned size", mono: true, secondary: true)
                Spacer()
                Text("\(summary.itemCount) item\(summary.itemCount == 1 ? "" : "s")")
                    .font(Theme.Font.mono).foregroundStyle(Theme.textSecondary)
            }
            ResidentBar(fraction: summary.residentFraction)
                .frame(height: Theme.Metric.gaugeHeightSmall)
                .accessibilityLabel("Pinned set \(Int((summary.residentFraction * 100).rounded())) percent resident locally")
            legendRow
        }
    }

    // MARK: Shared per-state legend — only non-zero buckets, so the strip stays quiet.

    @ViewBuilder private var legendRow: some View {
        HStack(spacing: Theme.Space.xl) {
            if summary.pinnedCount > 0 {
                legend(PinStateStyle.pinned.tint, PinCacheState.pinned.displayLabel, summary.pinnedCount)
            }
            if summary.pinningCount > 0 {
                legend(PinStateStyle.pinning.tint, PinCacheState.pinning.displayLabel, summary.pinningCount)
            }
            if summary.needsAttentionCount > 0 {
                legend(Theme.Status.warn, "Needs attention", summary.needsAttentionCount)
            }
            Spacer()
        }
    }

    private func stat(_ value: String, _ label: String,
                      mono: Bool = false, secondary: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
            Text(value)
                .font(mono ? Theme.Font.mono : Theme.Font.monoTitle)
                .foregroundStyle(secondary ? Theme.textSecondary : Theme.textPrimary)
            Text(label.uppercased())
                .font(Theme.Font.sectionLabel).tracking(0.5)
                .foregroundStyle(Theme.textTertiary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
    }

    private func legend(_ color: Color, _ label: String, _ count: Int) -> some View {
        HStack(spacing: Theme.Space.sm) {
            Circle().fill(color).frame(width: Theme.Metric.legendSwatch, height: Theme.Metric.legendSwatch)
                .overlay(Circle().strokeBorder(Theme.border, lineWidth: 0.5))
            Text("\(count) \(label.lowercased())")
                .font(Theme.Font.monoMicro).foregroundStyle(Theme.textSecondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(count) \(label)")
    }
}

// MARK: - Row

struct PinnedItemRow: View {
    let item: PinnedItem
    let isBusy: Bool
    let onUnpin: () -> Void
    var onShowInFinder: (() -> Void)? = nil
    var onRetry: (() -> Void)? = nil
    var onOpenOffline: (() -> Void)? = nil

    var body: some View {
        HStack(spacing: Theme.Space.lg) {
            // Leading glyph: folder for recursive subtree pins, doc for files.
            Image(systemName: item.recursive ? IconSet.folder : IconSet.document)
                .font(Theme.IconRole.rowLeading.font)
                .foregroundStyle(Theme.textTertiary)
                .frame(width: Theme.Metric.leadingIconWidth)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(item.displayName)
                    .font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                    .lineLimit(1).truncationMode(.middle)
                Text(item.path)
                    .font(Theme.Font.monoPath).foregroundStyle(Theme.textTertiary)
                    .lineLimit(1).truncationMode(.middle).help(item.path)
                if let reason = item.failureReason, !reason.isEmpty {
                    Text(reason).font(Theme.Font.caption).foregroundStyle(Theme.Status.warn)
                        .lineLimit(2).help(reason)
                }
                if item.offlineReady, let expires = item.offlineExpiresAt {
                    Text("Offline copy ready until " + expires.formatted(date: .abbreviated, time: .shortened))
                        .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                } else if let reason = item.offlineFailureReason, !reason.isEmpty {
                    Text("Offline copy: " + reason).font(Theme.Font.caption).foregroundStyle(Theme.Status.warn).lineLimit(2)
                }
                // Per-item resident progress (cached vs total).
                ResidentBar(fraction: item.residentFraction)
                    .frame(height: Theme.Metric.progressBarHeight)
            }

            Spacer(minLength: Theme.Space.md)

            // Size column: cached / total (e.g. "6 GB / 14 GB").
            VStack(alignment: .trailing, spacing: Theme.Space.xxs) {
                Text(ByteFormat.string(Int64(clamping: item.cachedBytes)))
                    .font(Theme.Font.mono).foregroundStyle(Theme.textPrimary)
                Text("/ \(ByteFormat.string(Int64(clamping: item.totalBytes)))")
                    .font(Theme.Font.monoMicro).foregroundStyle(Theme.textTertiary)
            }
            .frame(width: Theme.Metric.metadataColumnWidth, alignment: .trailing)
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(ByteFormat.string(Int64(clamping: item.cachedBytes))) of \(ByteFormat.string(Int64(clamping: item.totalBytes))) resident")

            CacheStateChip(state: item.state, failureReason: item.failureReason)

            actions
        }
        .padding(.vertical, Theme.Space.md)
        .opacity(isBusy ? 0.5 : 1)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(item.displayName), \(item.statusLabel), \(item.residentPercent) percent resident")
    }

    @ViewBuilder private var actions: some View {
        if isBusy {
            ProgressView().controlSize(.small).frame(width: 128, alignment: .trailing)
        } else {
            // Unpin is the single action: it removes the keep-local pin, so the
            // item leaves the list (an unpinned path has no pin record).
            HStack(spacing: Theme.Space.xs) {
                if let onOpenOffline, item.offlineReady {
                    IconButton("wifi.slash", label: "Open read-only offline copy of \(item.displayName)", tint: Theme.textSecondary, action: onOpenOffline)
                }
                if let onRetry, item.failureReason?.isEmpty == false || item.offlineFailureReason?.isEmpty == false {
                    IconButton(IconSet.refresh, label: "Retry pinning \(item.displayName)",
                               tint: Theme.Status.warn, action: onRetry)
                }
                if let onShowInFinder {
                    IconButton(IconSet.revealInFinder, label: "Show \(item.displayName) in Finder",
                               tint: Theme.textSecondary, action: onShowInFinder)
                }
                IconButton(IconSet.unpin, label: "Unpin \(item.displayName)",
                           tint: Theme.textSecondary, action: onUnpin)
            }
            .frame(width: 128, alignment: .trailing)
        }
    }
}

// MARK: - Cache-state chip

struct CacheStateChip: View {
    let state: PinCacheState
    var failureReason: String? = nil

    var body: some View {
        let failed = failureReason?.isEmpty == false
        let style = failed ? PinStateStyle.Style(symbol: "exclamationmark.triangle.fill", tint: Theme.Status.warn) : PinStateStyle.style(for: state)
        HStack(spacing: Theme.Space.xs) {
            Image(systemName: style.symbol).font(Theme.Font.monoMicro)
                .accessibilityHidden(true)
            Text(failed ? "Needs attention" : state.displayLabel).font(Theme.Font.monoMicro)
        }
        .foregroundStyle(style.tint)
        .padding(.horizontal, Theme.Space.sm)
        .padding(.vertical, Theme.Space.xxs)
        .background(style.tint.opacity(0.14), in: Capsule())
        .overlay(Capsule().strokeBorder(style.tint.opacity(0.30), lineWidth: 0.5))
        .help(failureReason ?? state.explanation)
        .accessibilityLabel(failed ? "Needs attention: \(failureReason ?? "")" : state.displayLabel)
    }
}

/// Cache-state visual vocabulary (symbol + tint), kept next to the chip so the
/// pinned / pinning look tunes in one place.
enum PinStateStyle {
    struct Style { let symbol: String; let tint: Color }

    static let pinned  = Style(symbol: "pin.fill",                tint: Theme.Status.ok)
    static let pinning = Style(symbol: "circle.lefthalf.filled",  tint: Theme.accent)

    static func style(for state: PinCacheState) -> Style {
        switch state {
        case .pinned:  return pinned
        case .pinning: return pinning
        }
    }
}

// MARK: - Resident bar (cached / total fill)

struct ResidentBar: View {
    let fraction: Double

    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width
            ZStack(alignment: .leading) {
                Capsule().fill(Theme.surfaceInset)
                    .overlay(Capsule().strokeBorder(Theme.border, lineWidth: 0.5))
                Capsule().fill(Theme.accent)
                    .frame(width: w * min(1, max(0, fraction)))
                    .motionAnimation(Theme.Motion.value, value: fraction)
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Preview

#Preview("Pinned — loaded") {
    let model = AppModel(gateway: MockGatewayClient())
    return PinnedItemsView()
        .environment(model)
        .frame(width: 820, height: 620)
        .task {
            model.pinned.items = PinnedItem.fixtures().sortedForDisplay()
            model.pinned.state = .loaded(model.pinned.items)
            model.cacheState = .loaded(CacheSettings(
                maxBytes: 200_000_000_000, usedBytes: 60_000_000_000,
                pinnedBytes: 40_000_000_000, location: "/Volumes/Scratch/cloudfs-cache",
                prefetchEnabled: true, prefetchDepth: 8))
        }
}

#Preview("Pinned — empty") {
    let model = AppModel(gateway: MockGatewayClient())
    return PinnedItemsView()
        .environment(model)
        .frame(width: 820, height: 620)
        .task { model.pinned.state = .loaded([]) }
}

#Preview("Pinned — needs local engine") {
    let model = AppModel(gateway: MockGatewayClient(), mode: .http("https://example.com"))
    return PinnedItemsView()
        .environment(model)
        .frame(width: 820, height: 620)
        .task {
            model.pinned.state = .failed("Pinned files need the local engine. Start cloudfsd, then try again.")
        }
}
