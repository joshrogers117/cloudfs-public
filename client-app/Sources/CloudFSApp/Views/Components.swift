// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - Shared state components (loading / empty / error / banner)
//
// All built on Theme tokens + the pure `LoadState`/`BannerKind` selectors in
// CloudFSKit, so EMPTY / LOADING / ERROR look identical everywhere.

// MARK: Banner — inline info/success/warning/error notice

struct Banner: View {
    let kind: BannerKind
    let title: String
    var detail: String? = nil
    /// Optional inline action (e.g. "Retry", "Dismiss").
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil

    private var tint: Color {
        switch kind {
        case .info:    return Theme.info
        case .success: return Theme.Status.ok
        case .warning: return Theme.Status.warn
        case .error:   return Theme.Status.error
        }
    }

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Space.md) {
            Image(systemName: kind.symbolName)
                .foregroundStyle(tint)
                .font(Theme.Font.body)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(title).font(Theme.Font.caption).foregroundStyle(Theme.textPrimary)
                if let detail {
                    Text(detail).font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
                }
            }
            Spacer(minLength: Theme.Space.md)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .cfButton(.subtle, size: .small)
                    .font(Theme.Font.caption)
            }
        }
        .padding(Theme.Space.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: Theme.Radius.sm))
        .overlay(
            RoundedRectangle(cornerRadius: Theme.Radius.sm)
                .strokeBorder(tint.opacity(0.28), lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(kind.accessibilityPrefix): \(title)\(detail.map { ", \($0)" } ?? "")")
    }
}

// MARK: LoadingPane — tasteful centered progress

struct LoadingPane: View {
    var text: String = "Loading…"
    var body: some View {
        VStack(spacing: Theme.Space.lg) {
            ProgressView()
                .controlSize(.large)
                .tint(Theme.accent)
            Text(text).font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }
}

// MARK: ErrorPane — centered failure state with retry

struct ErrorPane: View {
    let message: String
    var retry: (() -> Void)? = nil
    var body: some View {
        VStack(spacing: Theme.Space.lg) {
            Image(systemName: IconSet.errorOutline)
                .font(Theme.Font.emptyGlyph)
                .foregroundStyle(Theme.Status.warn)
            Text("Couldn’t load").font(Theme.Font.headline).foregroundStyle(Theme.textPrimary)
            Text(message).font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                .multilineTextAlignment(.center).frame(maxWidth: 360)
            if let retry {
                Button("Try Again", action: retry)
                    .cfButton(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(Theme.Space.xl)
        .accessibilityElement(children: .combine)
    }
}

// MARK: EmptyState — inviting empty pane (icon + title + hint)

struct EmptyState: View {
    let symbol: String
    let title: String
    var hint: String? = nil
    var body: some View {
        VStack(spacing: Theme.Space.md) {
            Image(systemName: symbol)
                .font(Theme.Font.emptyGlyph)
                .foregroundStyle(Theme.textTertiary)
            Text(title).font(Theme.Font.headline).foregroundStyle(Theme.textSecondary)
            if let hint {
                Text(hint).font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
                    .multilineTextAlignment(.center).frame(maxWidth: 320)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(Theme.Space.xl)
        .accessibilityElement(children: .combine)
    }
}

// MARK: StatePane — routes a LoadState to the right presentation
//
// `content` is shown when loaded-with-content; `emptyState` when loaded-but-empty.
// Keeps every pane's empty/loading/error wiring identical.

struct StatePane<Value: Collection & Sendable, Content: View>: View {
    let state: LoadState<Value>
    let loadingText: String
    let empty: EmptyState
    var retry: (() -> Void)? = nil
    @ViewBuilder let content: (Value) -> Content

    var body: some View {
        switch state {
        case .idle, .loading:
            LoadingPane(text: loadingText)
        case .failed(let msg):
            ErrorPane(message: msg, retry: retry)
        case .loaded(let value):
            if value.isEmpty { empty }
            else { content(value) }
        }
    }
}

// MARK: - CacheGauge (stacked used / pinned / free)
//
// Shared by CacheSettingsView (the full "Usage" card) and the Dashboard's
// Pinned & cache card (a condensed version of the same reading), so it lives
// here rather than under one specific pane.

struct CacheGauge: View {
    let usedFraction: Double
    let pinnedFraction: Double

    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width
            ZStack(alignment: .leading) {
                // Track
                Capsule().fill(Theme.surfaceInset)
                    .overlay(Capsule().strokeBorder(Theme.border, lineWidth: 0.5))
                // Used (green), with pinned overlaid as the accent leading portion
                Capsule()
                    .fill(Theme.Status.ok.opacity(0.85))
                    .frame(width: w * min(1, usedFraction))
                    .motionAnimation(Theme.Motion.value, value: usedFraction)
                Capsule()
                    .fill(Theme.accent)
                    .frame(width: w * min(1, pinnedFraction))
                    .motionAnimation(Theme.Motion.value, value: pinnedFraction)
                // 80% pinning-ceiling marker
                Capsule()
                    .fill(Theme.markerLine)
                    .frame(width: Theme.Metric.markerWidth)
                    .offset(x: w * CacheSettings.pinningCeilingFraction)
                    .help("80% pinning ceiling")
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Skeleton row (subtle shimmer placeholder)

struct SkeletonRow: View {
    var height: CGFloat = Theme.Metric.rowHeight
    @State private var shimmer = false
    var body: some View {
        RoundedRectangle(cornerRadius: Theme.Radius.sm)
            .fill(Theme.surface)
            .frame(height: height * 0.5)
            .opacity(shimmer ? 0.45 : 0.85)
            .frame(height: height)
            .onAppear {
                withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) {
                    shimmer = true
                }
            }
            .accessibilityHidden(true)
    }
}
