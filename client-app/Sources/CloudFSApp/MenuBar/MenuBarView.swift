// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - MenuBarView
//
// The NSStatusItem / MenuBarExtra surface (docs §5.7): current filespace +
// connection state, a cache-usage gauge, pause/resume sync, recent activity, and
// quick links (open the main window to a section, reveal the mount). This is
// what Finder can't show — the aggregate picture. Tokenized via Theme.*.

struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    private let hInset = Theme.Space.lg     // consistent horizontal section inset
    private let vInset = Theme.Space.md     // consistent vertical section inset

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if model.isSignedIn {
                header
                Divider()
                cacheSection
                Divider()
                transfersSummary
                Divider()
                activitySection
                Divider()
                quickLinks
            } else {
                signedOut
            }
        }
        .padding(.vertical, Theme.Space.md)
        .task { if !model.isSignedIn { await model.bootstrap() } }
    }

    // MARK: Header (filespace + status + pause)

    private var header: some View {
        HStack(spacing: Theme.Space.md) {
            BrandMark(chrome: true, size: 18)
                .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.xs))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(model.selectedFilespace?.name ?? "CloudFS")
                    .font(Theme.Font.body.weight(.semibold)).lineLimit(1)
                HStack(spacing: Theme.Space.sm) {
                    if let fs = model.selectedFilespace {
                        StatusDot(color: fs.connection.dotColor, size: 7)
                        Text(fs.connection.label).font(Theme.Font.micro)
                            .foregroundStyle(Theme.textSecondary)
                    }
                }
            }
            Spacer()
            IconButton(model.selectedFilespace?.connection == .paused ? IconSet.playFill : IconSet.pauseFill,
                       label: model.selectedFilespace?.connection == .paused ? "Resume sync" : "Pause sync",
                       role: .action, tint: Theme.accent) {
                Task { await model.togglePauseSync() }
            }
        }
        .padding(.horizontal, hInset).padding(.bottom, Theme.Space.sm)
    }

    // MARK: Cache gauge

    @ViewBuilder private var cacheSection: some View {
        if let cache = model.cache {
            VStack(alignment: .leading, spacing: Theme.Space.sm) {
                HStack {
                    Label("Cache", systemImage: IconSet.cache).font(Theme.Font.caption)
                    Spacer()
                    Text("\(ByteFormat.string(cache.usedBytes)) / \(ByteFormat.string(cache.maxBytes))")
                        .font(Theme.Font.monoMicro).foregroundStyle(Theme.textSecondary)
                }
                CacheGauge(usedFraction: cache.usedFraction, pinnedFraction: cache.pinnedFraction)
                    .frame(height: Theme.Metric.gaugeHeightSmall)
                    .accessibilityLabel("Cache \(Int(cache.usedFraction * 100)) percent used")
            }
            .padding(.horizontal, hInset).padding(.vertical, vInset)
        }
    }

    // MARK: Transfers summary

    private var transfersSummary: some View {
        HStack(spacing: Theme.Space.xl) {
            stat(IconSet.uploadOutline, "\(model.activeUploadCount)", "up")
            stat(IconSet.downloadOutline, "\(model.activeDownloadCount)", "down")
            Spacer()
            Text(ByteFormat.rate(model.aggregateThroughput))
                .font(Theme.Font.mono).foregroundStyle(Theme.textSecondary)
        }
        .padding(.horizontal, hInset).padding(.vertical, vInset)
    }

    private func stat(_ symbol: String, _ value: String, _ label: String) -> some View {
        HStack(spacing: Theme.Space.xs) {
            Image(systemName: symbol).font(Theme.Font.caption)
            Text(value).font(Theme.Font.mono.weight(.semibold))
            Text(label).font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
    }

    // MARK: Recent activity

    @ViewBuilder private var activitySection: some View {
        VStack(alignment: .leading, spacing: Theme.Space.xs) {
            SectionLabel("Recent activity").padding(.bottom, Theme.Space.xxs)
            if model.recentActivity.isEmpty {
                Text("No recent activity").font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
            } else {
                ForEach(model.recentActivity.prefix(3)) { ev in
                    HStack(spacing: Theme.Space.sm) {
                        Text(ev.actor).font(Theme.Font.micro.weight(.medium))
                            .foregroundStyle(Theme.textPrimary)
                        Text(ev.verb).font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
                        Text(ev.path).font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                            .lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: Theme.Space.sm)
                        Text(RelativeTime.string(ev.at))
                            .font(Theme.Font.monoMicro).foregroundStyle(Theme.textTertiary)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(ev.actor) \(ev.verb) \(ev.path)")
                }
            }
        }
        .padding(.horizontal, hInset).padding(.vertical, vInset)
    }

    // MARK: Quick links

    private var quickLinks: some View {
        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
            menuButton("Open CloudFS", IconSet.window) { openMain(.dashboard) }
            menuButton("Activity & Transfers", IconSet.activity) { openMain(.activity) }
            menuButton("Cache Settings", IconSet.cache) { openMain(.cache) }
            menuButton("Snapshots", IconSet.snapshots) { openMain(.snapshots) }
            Divider().padding(.vertical, Theme.Space.xxs)
            menuButton("Quit CloudFS", IconSet.quit) { NSApplication.shared.terminate(nil) }
        }
        .padding(.horizontal, Theme.Space.md).padding(.top, Theme.Space.xs)
    }

    private func menuButton(_ title: String, _ symbol: String, action: @escaping () -> Void) -> some View {
        MenuRowButton(title: title, symbol: symbol, action: action)
    }

    private func openMain(_ section: NavSection) {
        model.section = section
        openWindow(id: "main")
        NSApplication.shared.activate(ignoringOtherApps: true)
    }

    // MARK: Signed out

    private var signedOut: some View {
        VStack(spacing: Theme.Space.md) {
            Icon(IconSet.brand, role: .action).foregroundStyle(Theme.accent)
                .accessibilityHidden(true)
            Text("Not connected").font(Theme.Font.body)
            Button("Open CloudFS to connect") {
                openWindow(id: "main")
                NSApplication.shared.activate(ignoringOtherApps: true)
            }
            .cfButton(.primary)
        }
        .frame(maxWidth: .infinity).padding(Theme.Space.xl)
    }
}

// MARK: - Menu row button with a hover affordance

private struct MenuRowButton: View {
    let title: String
    let symbol: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: symbol).font(Theme.Font.body)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, Theme.Space.sm)
                .padding(.vertical, Theme.Space.xs)
                .background(hovering ? Theme.hover : .clear,
                            in: RoundedRectangle(cornerRadius: Theme.Radius.sm))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
