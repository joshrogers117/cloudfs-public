// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - LiveActivityView  (WS3 — owned by the activity-split agent)
//
// The LIVE feed surface (.activity section). EPHEMERAL by design: in-flight
// transfers + the DO hot ring + rolled-up bulk ops (e.g. large deletes), from the
// `GatewayClient.liveActivity(in:)` seam (CONTRACTS §5.3). Reflects what is
// happening *right now* — it is NOT the durable record. The durable, queryable
// history lives in the separate `AuditLogView` (audit reader = `auditRange`).
//
// Transfers tick forward via the engine/mock AsyncStream (`AppModel.transfers` /
// `transfersState`, kept warm by `refreshForSelection`). The live event ring +
// bulk rollups come from `liveLog.live` / `liveLog.liveState` via
// `loadLiveActivity()`. Tokenized via Theme.*; EMPTY / LOADING / ERROR via
// LoadState. The shared row components (`TransferRow`, `ProgressBar`,
// `ActivityRow`, `InlineLoading`, `InlineEmpty`) live here and are reused by
// `AuditLogView`.

struct LiveActivityView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Activity",
                       subtitle: "\(model.activeUploadCount) uploading · \(model.activeDownloadCount) downloading · \(ByteFormat.rate(model.aggregateThroughput))")

            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Space.xl) {
                    RecoverySection()
                    if model.canReadWorkspaceActivity { ephemeralBanner }
                    Card("Transfers") { transfersBody }
                    if model.canReadWorkspaceActivity { Card("Live activity") { activityBody } }
                }
                .padding(Theme.Space.xxl)
            }
        }
        .background(Theme.bg)
        .task(id: model.selectedFilespaceID) { await model.loadLiveActivity() }
        // Re-pull when a global Refresh is requested (View ▸ Refresh / toolbar).
        .task(id: model.refreshToken) { await model.loadLiveActivity() }
        .task(id: model.selectedFilespaceID) {
            while !Task.isCancelled {
                await model.loadRecoveryItems()
                do { try await Task.sleep(for: .seconds(3)) } catch { break }
            }
        }
    }

    // A persistent reminder that this surface is live + ephemeral, and where the
    // durable record lives. Keeps the Live ⇄ Audit distinction explicit in the UI.
    private var ephemeralBanner: some View {
        HStack {
            Text("Recent changes appear below.")
                .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            Spacer()
            Button("View history") { model.go(to: .audit) }
                .cfButton(.subtle, size: .small)
        }
    }

    @ViewBuilder private var transfersBody: some View {
        switch model.transfersState {
        case .idle, .loading:
            InlineLoading(text: "Loading transfers…")
        case .failed(let msg):
            Banner(kind: .error, title: "Couldn’t load transfers", detail: msg,
                   actionTitle: "Retry") { Task { await model.refreshForSelection() } }
        case .loaded(let transfers):
            if transfers.isEmpty {
                InlineEmpty(symbol: IconSet.transfersIdle, title: "No active transfers",
                            hint: "Up- and downloads will appear here while they run.")
            } else {
                VStack(spacing: Theme.Space.lg) {
                    ForEach(transfers) { transfer in
                        TransferRow(transfer: transfer)
                            .transition(.move(edge: .top).combined(with: .opacity))
                    }
                }
                .motionAnimation(Theme.Motion.list, value: transfers.map(\.id))
            }
        }
    }

    @ViewBuilder private var activityBody: some View {
        switch model.liveLog.liveState {
        case .idle, .loading:
            InlineLoading(text: "Loading live activity…")
        case .failed(let msg):
            Banner(kind: .error, title: "Couldn’t load activity", detail: msg,
                   actionTitle: "Retry") { Task { await model.loadLiveActivity() } }
        case .loaded(let live):
            if live.events.isEmpty {
                InlineEmpty(symbol: IconSet.activityIdle, title: "No recent activity",
                            hint: "Edits, locks, uploads and bulk operations across your team show up here as they happen.")
            } else {
                VStack(spacing: 0) {
                    ForEach(live.events) { event in
                        ActivityRow(event: event)
                            .transition(.move(edge: .top).combined(with: .opacity))
                    }
                }
                .motionAnimation(Theme.Motion.list, value: live.events.map(\.id))
            }
        }
    }
}

// MARK: - LivePulse  (a small breathing dot signalling "live / real-time")

struct LivePulse: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var on = false
    var body: some View {
        Circle()
            .fill(Theme.Status.ok)
            .frame(width: 8, height: 8)
            .opacity(on ? 1 : 0.35)
            .onAppear {
                guard !reduceMotion else { return }
                withAnimation(.easeInOut(duration: 1.1).repeatForever(autoreverses: true)) {
                    on = true
                }
            }
            .accessibilityHidden(true)
    }
}

// MARK: - TransferRow

struct TransferRow: View {
    let transfer: Transfer

    private var barTint: Color {
        switch transfer.state {
        case .completed: return Theme.Status.ok
        case .failed:    return Theme.Status.error
        case .paused:    return Theme.Status.paused
        default:         return Theme.accent
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.sm) {
            HStack(spacing: Theme.Space.md) {
                Image(systemName: transfer.kind == .upload ? IconSet.upload : IconSet.downloadFill)
                    .foregroundStyle(transfer.kind == .upload ? Theme.Status.warn : Theme.accent)
                    .accessibilityHidden(true)
                Text(transfer.fileName).font(Theme.Font.body).foregroundStyle(Theme.textPrimary).lineLimit(1)
                Spacer(minLength: Theme.Space.md)
                Text(stateText).font(Theme.Font.mono).foregroundStyle(Theme.textSecondary)
            }
            ProgressBar(fraction: transfer.fraction, tint: barTint)
                .frame(height: Theme.Metric.progressBarHeight)
            if let error = transfer.error, transfer.state == .failed {
                Text(error).font(Theme.Font.caption).foregroundStyle(Theme.Status.error)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Text("\(ByteFormat.string(transfer.bytesDone)) / \(ByteFormat.string(transfer.bytesTotal))")
                Spacer()
                if transfer.state == .active { Text(ByteFormat.rate(transfer.throughputBytesPerSec)) }
            }
            .font(Theme.Font.monoMicro).foregroundStyle(Theme.textTertiary)
        }
        .padding(.vertical, Theme.Space.xs)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(transfer.kind == .upload ? "Upload" : "Download") \(transfer.fileName), \(stateText)")
    }

    private var stateText: String {
        switch transfer.state {
        case .completed: return "Done"
        case .queued:    return "Queued"
        case .paused:    return "Paused"
        case .failed:    return "Failed"
        case .active:    return "\(Int(transfer.fraction * 100))%"
        }
    }
}

// MARK: - ProgressBar (themed, rounded, animates value)

struct ProgressBar: View {
    let fraction: Double
    var tint: Color = Theme.accent
    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .leading) {
                Capsule().fill(Theme.surfaceInset)
                Capsule().fill(tint)
                    .frame(width: max(0, min(1, fraction)) * geo.size.width)
                    .motionAnimation(Theme.Motion.value, value: fraction)
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - ActivityRow
//
// Renders a single ActivityEvent. A rolled-up BULK op (CONTRACTS §5.3 — e.g. an
// N-file "large delete" collapsed into one row) is shown distinctly: a warning-
// tinted glyph avatar plus a "× N items" count chip, so a sweeping operation is
// never mistaken for a single edit.

struct ActivityRow: View {
    let event: ActivityEvent

    private var isBulk: Bool { event.kind == .bulk }

    var body: some View {
        HStack(spacing: Theme.Space.lg) {
            avatar
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                (Text(event.actor).foregroundStyle(Theme.textPrimary).bold()
                 + Text(" \(event.verb) ").foregroundStyle(Theme.textSecondary)
                 + Text(event.path).foregroundStyle(Theme.textSecondary))
                    .font(Theme.Font.caption).lineLimit(1)
                if isBulk {
                    HStack(spacing: Theme.Space.sm) {
                        BulkBadge(op: event.bulkOp, count: event.bulkCount)
                    }
                }
            }
            Spacer()
            Text(RelativeTime.string(event.at)).font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
        }
        .padding(.vertical, Theme.Space.sm)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(accessibilityText)
    }

    @ViewBuilder private var avatar: some View {
        ZStack {
            Circle()
                .fill(isBulk ? Theme.Status.warn.opacity(0.18) : Theme.surfaceInset)
                .frame(width: Theme.Metric.avatar, height: Theme.Metric.avatar)
            if isBulk {
                Image(systemName: IconSet.trash)
                    .font(Theme.Font.monoMicro)
                    .foregroundStyle(Theme.Status.warn)
            } else {
                Text(initials).font(Theme.Font.monoMicro.weight(.semibold)).foregroundStyle(Theme.textSecondary)
            }
        }
        .accessibilityHidden(true)
    }

    private var initials: String {
        let parts = event.actor.split(separator: " ")
        return parts.prefix(2).compactMap { $0.first.map(String.init) }.joined().uppercased()
    }

    private var accessibilityText: String {
        if isBulk, let count = event.bulkCount {
            return "\(event.actor) \(event.verb) \(event.path), bulk operation affecting \(count) items, \(RelativeTime.string(event.at))"
        }
        return "\(event.actor) \(event.verb) \(event.path), \(RelativeTime.string(event.at))"
    }
}

// MARK: - BulkBadge  (a count chip for a rolled-up bulk op)

struct BulkBadge: View {
    let op: String?
    let count: Int?
    var body: some View {
        let label = op?.replacingOccurrences(of: "-", with: " ") ?? "bulk"
        let countText = count.map { " · \($0.formatted()) items" } ?? ""
        Text("\(label)\(countText)")
            .font(Theme.Font.micro)
            .padding(.horizontal, Theme.Space.sm).padding(.vertical, Theme.Space.xxs)
            .background(Theme.Status.warn.opacity(0.16), in: Capsule())
            .foregroundStyle(Theme.Status.warn)
            .overlay(Capsule().strokeBorder(Theme.Status.warn.opacity(0.30)))
            .accessibilityLabel("\(label)\(countText)")
    }
}

// MARK: - Inline loading / empty (for use inside cards)

struct InlineLoading: View {
    var text: String = "Loading…"
    var body: some View {
        HStack(spacing: Theme.Space.md) {
            ProgressView().controlSize(.small).tint(Theme.accent)
            Text(text).font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, Theme.Space.xs)
        .accessibilityLabel(text)
    }
}

struct InlineEmpty: View {
    let symbol: String
    let title: String
    var hint: String? = nil
    var body: some View {
        HStack(spacing: Theme.Space.md) {
            Image(systemName: symbol).font(Theme.Font.body).foregroundStyle(Theme.textTertiary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(title).font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                if let hint {
                    Text(hint).font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                }
            }
            Spacer()
        }
        .padding(.vertical, Theme.Space.xs)
        .accessibilityElement(children: .combine)
    }
}
