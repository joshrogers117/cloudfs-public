// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit
import UniformTypeIdentifiers

// MARK: - CacheSettingsView
//
// The "superpower" panel (spec §3.7 / docs §5.4): the user-resizable cache
// ceiling, a relocatable cache-location picker, prefetch controls, and a usage
// gauge breaking down used vs pinned. These operate on the ENGINE-owned cache
// (the only one we can size/move — the File Provider materialized store can't be
// relocated or hard-capped). Defaults: 25 GB min, 10 TiB max,
// up to 80% usable for pinning.

struct CacheSettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var settingsTab = "Local settings"
    @State private var showClearConfirm = false
    @State private var isClearing = false
    @State private var lastFreedBytes: Int64?
    @State private var draftCacheBytes: Int64?
    @State private var isSaving = false

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Filespace settings")
            Picker("Settings", selection: $settingsTab) {
                Text("General").tag("General")
                Text("Local settings").tag("Local settings")
            }.pickerStyle(.segmented).labelsHidden().frame(width: 290).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 24).padding(.bottom, 20)
            if settingsTab == "General" {
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        if let fs = model.selectedFilespace {
                            Card("Filespace") {
                                KeyValueRow(key: "Name", value: fs.name)
                                KeyValueRow(key: "Cloud provider", value: fs.storageBackend)
                                KeyValueRow(key: "Region", value: fs.region)
                                KeyValueRow(key: "Used storage", value: fs.storageDisplay)
                            }
                            if model.canManageFilespaceSettings, let url = model.consoleLinks.filespaceSettings(id: fs.id) {
                                Link("Manage filespace in the web console", destination: url).cfButton(.secondary)
                            }
                        }
                    }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
                }
            } else { content }
        }
        .background(Theme.bg)
        .onChange(of: model.selectedFilespaceID) { _, _ in
            draftCacheBytes = nil
            lastFreedBytes = nil
        }
        .confirmationDialog(
            "Clear the local cache?",
            isPresented: $showClearConfirm, titleVisibility: .visible) {
            Button("Clear Cache", role: .destructive) { Task { await runClearCache() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Pinned files stay on this Mac, and unsynced changes are never discarded.")
        }
    }

    private func runClearCache() async {
        isClearing = true
        lastFreedBytes = nil
        lastFreedBytes = await model.clearCache()
        isClearing = false
    }

    @ViewBuilder private var content: some View {
        switch model.cacheState {
        case .idle, .loading:
            LoadingPane(text: "Reading cache status…")
        case .failed(let msg):
            ErrorPane(message: msg) { Task { await model.refreshForSelection() } }
        case .loaded(let cache):
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Space.xl) {
                    gauge(cache)
                    sizeCard(cache)
                    locationCard(cache)
                    streamingCard
                }
                .frame(maxWidth: 780, alignment: .leading)
                .padding(Theme.Space.xxl)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    // MARK: Usage gauge

    private func gauge(_ cache: CacheSettings) -> some View {
        Card("Usage") {
            CacheGauge(usedFraction: cache.usedFraction, pinnedFraction: cache.pinnedFraction)
                .frame(height: Theme.Metric.gaugeHeight)
                .accessibilityLabel("Cache \(Int(cache.usedFraction * 100)) percent used, \(Int(cache.pinnedFraction * 100)) percent pinned")
            // Legend order matches the bar's visual segments left→right:
            // Pinned (accent gold, leading) → Used (green) → Free (track).
            HStack(spacing: Theme.Space.xl) {
                legend(Theme.accent, "Pinned", ByteFormat.string(cache.pinnedBytes))
                legend(Theme.Status.ok.opacity(0.9), "Used", ByteFormat.string(cache.usedBytes))
                legend(Theme.surfaceInset, "Free", ByteFormat.string(max(0, cache.maxBytes - cache.usedBytes)))
                Spacer()
                Text("Ceiling \(ByteFormat.string(cache.maxBytes))")
                    .font(Theme.Font.mono).foregroundStyle(Theme.textSecondary)
            }
            if model.isEngineConnected {
                HStack(spacing: Theme.Space.md) {
                    if let freed = lastFreedBytes {
                        Text("Freed \(ByteFormat.string(freed))")
                            .font(Theme.Font.monoMicro).foregroundStyle(Theme.textTertiary)
                    }
                    Spacer()
                    if isClearing {
                        ProgressView().controlSize(.small)
                    } else {
                        Button("Clear cache…") { showClearConfirm = true }
                            .cfButton(.secondary, size: .small)
                            .disabled(isSaving)
                    }
                }
            }
        }
    }

    private func legend(_ color: Color, _ label: String, _ value: String) -> some View {
        HStack(spacing: Theme.Space.sm) {
            RoundedRectangle(cornerRadius: Theme.Radius.xs).fill(color)
                .frame(width: Theme.Metric.legendSwatch, height: Theme.Metric.legendSwatch)
                .overlay(RoundedRectangle(cornerRadius: Theme.Radius.xs).strokeBorder(Theme.border, lineWidth: 0.5))
            Text(label).font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
            Text(value).font(Theme.Font.monoMicro).foregroundStyle(Theme.textPrimary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label) \(value)")
    }

    // MARK: Size slider

    private func sizeCard(_ cache: CacheSettings) -> some View {
        Card("Maximum cache size") {
            let displayedBytes = draftCacheBytes ?? cache.maxBytes
            let binding = Binding<Double>(
                get: { log2(Double(displayedBytes)) },
                set: { newLog in
                    // Preview locally while dragging. Resizing the real cache
                    // can evict blocks, so apply once when interaction ends.
                    draftCacheBytes = (Int64((pow(2, newLog) / 1_000_000_000).rounded()) * 1_000_000_000)
                        .clamped(CacheSettings.minBytes, CacheSettings.maxAllowed)
                })
            HStack {
                Text(ByteFormat.string(displayedBytes))
                    .font(Theme.Font.monoTitle)
                    .foregroundStyle(Theme.textPrimary)
                Spacer()
                if isSaving { ProgressView().controlSize(.small).accessibilityLabel("Saving cache settings") }
            }
            // Log-scale slider: 25 GB → 10 TiB
            Slider(value: binding,
                   in: log2(Double(CacheSettings.minBytes))...log2(Double(CacheSettings.maxAllowed)),
                   onEditingChanged: { editing in
                       guard !editing, let bytes = draftCacheBytes else { return }
                       var updated = cache
                       updated.maxBytes = bytes
                       draftCacheBytes = nil
                       saveCache(updated)
                   })
                .tint(Theme.accent)
                .accessibilityLabel("Maximum cache size")
                .accessibilityValue(ByteFormat.string(displayedBytes))
                .disabled(isSaving || isClearing || (model.isHttpMode && !model.isEngineConnected))
            HStack {
                Text(ByteFormat.string(CacheSettings.minBytes))
                Spacer()
                Text(ByteFormat.string(CacheSettings.maxAllowed))
            }
            .font(Theme.Font.monoMicro).foregroundStyle(Theme.textTertiary)
            Text("Up to \(Int(CacheSettings.pinningCeilingFraction * 100))% of the cache may be used for pins; the rest stays free for the live working set. Cache must live on SSD/NVMe (APFS).")
                .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
        }
    }

    // MARK: Location picker

    private func locationCard(_ cache: CacheSettings) -> some View {
        Card("Cache location") {
            HStack(spacing: Theme.Space.lg) {
                Image(systemName: IconSet.externalDrive).foregroundStyle(Theme.accent)
                    .accessibilityHidden(true)
                Text(cache.location).font(Theme.Font.monoPath)
                    .foregroundStyle(Theme.textPrimary).lineLimit(1).truncationMode(.middle)
                    .help(cache.location)
                Spacer()
                Button("Relocate…") { chooseLocation(cache) }
                    .cfButton(.secondary, size: .small)
                    .disabled(isSaving || isClearing || (model.isHttpMode && !model.isEngineConnected))
            }
            Text("Move downloaded files to a faster or larger local drive. Your pins move with the cache; pending uploads stay protected separately on this Mac.")
                .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
        }
    }

    private func chooseLocation(_ cache: CacheSettings) {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Use as Cache Location"
        if panel.runModal() == .OK, let url = panel.url {
            var c = cache
            c.location = url.path
            saveCache(c)
        }
    }

    private func saveCache(_ value: CacheSettings) {
        isSaving = true
        Task {
            await model.updateCache(value)
            isSaving = false
        }
    }

    // MARK: Streaming

    private var streamingCard: some View {
        Card("Streaming") {
            Text("CloudFS downloads the parts of each file you use and automatically reads ahead to keep playback moving. Pin a file or folder to keep a local copy available.")
                .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}
