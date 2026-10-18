// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI

// MARK: - Shared pane chrome
//
// All built from Theme tokens so every pane shares one rhythm.

/// Standard header for each detail pane.
struct PaneHeader: View {
    let title: String
    var subtitle: String? = nil
    var trailing: AnyView? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.lg) {
            HStack(alignment: .center, spacing: Theme.Space.lg) {
                Text(title).font(.system(size: 22, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary).layoutPriority(1)
                Spacer(minLength: Theme.Space.md)
                if let trailing { trailing }
            }
            if let subtitle {
                Text(subtitle).font(Theme.Font.caption)
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.horizontal, Theme.Space.xxl)
        .padding(.top, Theme.Space.xxl)
        .padding(.bottom, Theme.Space.xxl)
        .background(Theme.bg)
    }
}

// (Centered empty states now use the richer `EmptyState` in Components.swift.)

/// A simple labeled card container, built on the shared `themedCard()` style.
struct Card<Content: View>: View {
    let title: String?
    @ViewBuilder var content: Content
    init(_ title: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title; self.content = content()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.lg) {
            if let title { SectionLabel(title) }
            content
        }
        .themedCard()
    }
}
