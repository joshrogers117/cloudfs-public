// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - AuditLogView  (WS3 — owned by the activity-split agent)
//
// The HISTORICAL audit-log surface (.audit section). This is the DURABLE record:
// an append-only, hash-chained history read from the DO ring and, for older
// ranges, the R2-archived segments (CONTRACTS §5.4) via
// `GatewayClient.auditRange(in:since:until:cursor:limit:)`.
//
// Designed to stay responsive over LARGE histories:
//   • a bounded page (`ActivityFeatureModel.auditPageSize`) is fetched at a time,
//   • rows render lazily (`LazyVStack`), and
//   • page-back is cursor-driven ("Load older") rather than loading everything.
// A time-window picker constrains the `since` bound the reader must scan; a
// free-text field narrows the rendered rows client-side. The LIVE in-flight
// surface is the separate `LiveActivityView`.

struct AuditLogView: View {
    @Environment(AppModel.self) private var model

    private var feature: ActivityFeatureModel { model.liveLog }

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "History",
                       subtitle: "Search past file changes and team activity.")
            controls
            content
        }
        .background(Theme.bg)
        .task(id: model.selectedFilespaceID) { await reload() }
        .task(id: model.refreshToken) { await reload() }
    }

    // MARK: Filter controls (time window + free-text)

    private var controls: some View {
        @Bindable var feature = model.liveLog
        return HStack(spacing: Theme.Space.lg) {
            // Time-window scope — bounds the `since` the reader scans.
            Picker("Range", selection: $feature.auditWindow) {
                ForEach(AuditWindow.allCases) { window in
                    Text(window.rawValue).tag(window)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 280)
            .onChange(of: feature.auditWindow) { Task { await reload() } }

            // Free-text narrow over actor / action / path (client-side).
            HStack(spacing: Theme.Space.sm) {
                Image(systemName: IconSet.search)
                    .font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
                    .accessibilityHidden(true)
                TextField("Filter by actor, action or path", text: $feature.auditSearch)
                    .textFieldStyle(.plain)
                    .font(Theme.Font.caption)
                    .foregroundStyle(Theme.textPrimary)
                if !feature.auditSearch.isEmpty {
                    IconButton(IconSet.clearSearch, label: "Clear filter", role: .badge,
                               tint: Theme.textTertiary) { feature.auditSearch = "" }
                }
            }
            .padding(.horizontal, Theme.Space.md)
            .frame(height: 28)
            .background(Theme.surfaceInset, in: RoundedRectangle(cornerRadius: Theme.Radius.sm))
            .overlay(RoundedRectangle(cornerRadius: Theme.Radius.sm).strokeBorder(Theme.border))
        }
        .padding(.horizontal, Theme.Space.xxl)
        .padding(.vertical, Theme.Space.lg)
        .overlay(Divider().overlay(Theme.divider), alignment: .bottom)
    }

    // MARK: Content (lazy, paged)

    @ViewBuilder private var content: some View {
        switch feature.auditState {
        case .idle, .loading:
            LoadingPane(text: "Loading audit history…")
        case .failed(let msg):
            ErrorPane(message: msg) { Task { await reload() } }
        case .loaded:
            loadedBody
        }
    }

    @ViewBuilder private var loadedBody: some View {
        let rows = feature.filteredAuditEvents
        if rows.isEmpty {
            EmptyState(symbol: IconSet.audit,
                       title: feature.auditSearch.isEmpty ? "No audit events in this range"
                                                          : "No events match your filter",
                       hint: feature.auditSearch.isEmpty
                           ? "Choose a wider time range or check back after your team makes changes."
                           : "Try a different actor, action or path — or clear the filter.")
        } else {
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(rows) { event in
                        AuditRow(event: event)
                        Divider().overlay(Theme.divider)
                    }
                    footer
                }
                .padding(.horizontal, Theme.Space.xxl)
                .padding(.vertical, Theme.Space.lg)
            }
        }
    }

    // Cursor-driven page-back footer. Auto-loads the next page when it appears so
    // scrolling near the bottom pulls more history; also offers an explicit button.
    @ViewBuilder private var footer: some View {
        if feature.canLoadMoreAudit {
            HStack {
                Spacer()
                if feature.auditLoadingMore {
                    InlineLoading(text: "Loading older events…").fixedSize()
                } else {
                    Button {
                        Task { await model.loadMoreAudit() }
                    } label: {
                        Label("Load older events", systemImage: IconSet.chevronDown)
                    }
                    .cfButton(.subtle, size: .small)
                }
                Spacer()
            }
            .padding(.top, Theme.Space.lg)
            .task(id: feature.auditCursor) {
                // Prefetch the next page as the footer scrolls into view, while a
                // cursor remains. Keeps large histories paging smoothly.
                await model.loadMoreAudit()
            }
        } else if !feature.filteredAuditEvents.isEmpty {
            Text("End of recorded history")
                .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                .frame(maxWidth: .infinity)
                .padding(.top, Theme.Space.lg)
                .accessibilityLabel("End of recorded history")
        }
    }

    private func reload() async {
        await model.loadAudit(since: feature.auditWindow.since)
    }
}

// MARK: - AuditRow
//
// One historical record. Reads as a record (not a live ticker): absolute,
// monospaced timestamp, the actor/action/path, and a verb chip. Bulk rollups are
// flagged so a sweeping operation stands out in the permanent log too.

struct AuditRow: View {
    let event: ActivityEvent

    private var isBulk: Bool { event.kind == .bulk }

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Space.lg) {
            // Fixed-width timestamp column so rows align cleanly down the log.
            Text(Self.timestamp.string(from: event.at))
                .font(Theme.Font.monoMicro)
                .foregroundStyle(Theme.textTertiary)
                .frame(width: 120, alignment: .leading)
                .help(event.at.formatted(date: .long, time: .standard))

            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                HStack(spacing: Theme.Space.sm) {
                    Text(event.actor).font(Theme.Font.caption.weight(.semibold))
                        .lineLimit(1).truncationMode(.middle).help(event.actor)
                        .foregroundStyle(Theme.textPrimary)
                    VerbChip(verb: event.verb)
                    if isBulk { BulkBadge(op: event.bulkOp, count: event.bulkCount) }
                }
                Text(event.path.isEmpty ? "Filespace event" : event.path)
                    .font(Theme.Font.monoPath)
                    .foregroundStyle(Theme.textSecondary)
                    .lineLimit(1).truncationMode(.middle).help(event.path)
            }
            Spacer(minLength: Theme.Space.md)
            Text(RelativeTime.string(event.at))
                .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
        }
        .padding(.vertical, Theme.Space.md)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityText)
    }

    private static let timestamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MMM d, HH:mm:ss"
        return f
    }()

    private var accessibilityText: String {
        let when = event.at.formatted(date: .abbreviated, time: .standard)
        if isBulk, let count = event.bulkCount {
            return "\(when): \(event.actor) \(event.verb) \(event.path), bulk operation affecting \(count) items"
        }
        return "\(when): \(event.actor) \(event.verb) \(event.path)"
    }
}

// MARK: - VerbChip  (the audit action token)

struct VerbChip: View {
    let verb: String
    var body: some View {
        Text(verb)
            .font(Theme.Font.micro)
            .padding(.horizontal, Theme.Space.sm).padding(.vertical, Theme.Space.xxs)
            .background(Theme.surfaceInset, in: Capsule())
            .foregroundStyle(Theme.textSecondary)
            .overlay(Capsule().strokeBorder(Theme.border))
            .accessibilityHidden(true)
    }
}
