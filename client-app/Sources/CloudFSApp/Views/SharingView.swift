// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - SharingView
//
// The copy-link surface: lists existing internal `cloudfs://` deep links and
// external guest links, with copy + revoke. Distinguishes the two share kinds
// per research/02 (internal navigation aid vs. external view/download link).
// Fully tokenized (Theme.*) + hover rows.

struct SharingView: View {
    @Environment(AppModel.self) private var model
    @State private var copiedID: String?
    @State private var query = ""
    @State private var showCreate = false

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Guest links", trailing: AnyView(HStack(spacing: 12) {
                Button(model.sharing.copiedRoot ? "Copied" : "Copy link for members") { Task { await model.copyFilespaceLink() } }
                    .cfButton(.subtle, size: .small).disabled(model.sharing.creating)
                if model.canManageGuestLinks && !model.shareLinks.isEmpty {
                    Button("Create guest link") { showCreate = true }.cfButton(.primary)
                }
            }))
            if !model.shareLinks.isEmpty {
            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(Theme.textSecondary)
                TextField("Search links", text: $query).textFieldStyle(.plain)
            }.padding(11).background(Theme.surface, in: RoundedRectangle(cornerRadius: 8))
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Theme.border)).padding(.horizontal, 24).padding(.bottom, 20)
            }
            if let error = model.sharing.error {
                Banner(kind: .error, title: "Link action failed", detail: error).padding(Theme.Space.lg)
            }
            content
        }
        .background(Theme.bg)
        .sheet(isPresented: $showCreate) {
            if model.canManageGuestLinks, let id = model.selectedFilespaceID { CreateGuestLinkSheet(filespaceID: id) }
        }
        .onChange(of: model.selectedFilespaceID) { _, _ in showCreate = false; query = "" }
    }

    @ViewBuilder private var content: some View {
        if model.shareLinksState.isInitial {
            LoadingPane(text: "Loading shared links…")
        } else if let error = model.shareLinksState.errorMessage {
            ErrorPane(message: error) { Task { await model.refreshForSelection() } }
        } else if model.shareLinks.isEmpty {
            VStack(spacing: 20) {
                Spacer()
                Image(systemName: "link").font(.system(size: 34)).foregroundStyle(Theme.textSecondary)
                    .frame(width: 84, height: 84).background(Theme.surface, in: RoundedRectangle(cornerRadius: 22))
                Text("No guest links yet").font(.system(size: 24, weight: .semibold))
                Text(model.canManageGuestLinks ? "Share a file or folder with someone outside your workspace." : "Guest links created by your administrator appear here.")
                    .font(Theme.Font.body).foregroundStyle(Theme.textSecondary).multilineTextAlignment(.center).frame(maxWidth: 380)
                if model.canManageGuestLinks {
                    Button("Create guest link") { showCreate = true }.cfButton(.primary)
                }
                Spacer()
            }.frame(maxWidth: .infinity)
        } else {
            ScrollView {
                VStack(spacing: Theme.Space.lg) {
                    if !query.isEmpty && !model.shareLinks.contains(where: { $0.path.localizedCaseInsensitiveContains(query) }) {
                        EmptyState(symbol: "magnifyingglass", title: "No matching links", hint: "Try another file or folder name.")
                    }
                    ForEach(model.shareLinks.filter { query.isEmpty || $0.path.localizedCaseInsensitiveContains(query) }) { link in
                        ShareLinkRow(link: link, copied: copiedID == link.id,
                                     onCopy: { copy(link) },
                                     onRevoke: { Task { await model.revokeShare(link) } })
                            .disabled(model.sharing.busyIDs.contains(link.id))
                    }
                }
                .padding(Theme.Space.xxl)
            }
        }
    }

    private func copy(_ link: CloudShareLink) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(link.url, forType: .string)
        withAnimation(.easeInOut(duration: 0.15)) { copiedID = link.id }
        Task {
            try? await Task.sleep(for: .seconds(2))
            withAnimation(.easeInOut(duration: 0.15)) { copiedID = nil }
        }
    }

}

struct ShareLinkRow: View {
    let link: CloudShareLink
    let copied: Bool
    let onCopy: () -> Void
    let onRevoke: () -> Void
    @State private var hovering = false

    private var isGuest: Bool { link.kind == .guestLink }

    var body: some View {
        HStack(spacing: Theme.Space.lg) {
            Icon(isGuest ? IconSet.guestLink : IconSet.internalLink, role: .action)
                .foregroundStyle(isGuest ? Theme.Status.warn : Theme.accent)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Theme.Space.xs) {
                Text(link.path).font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                    .lineLimit(1).truncationMode(.middle).help(link.path)
                Text(link.url.isEmpty ? "The URL is shown only when this guest link is created." : link.url).font(Theme.Font.monoPath).foregroundStyle(Theme.textTertiary)
                    .lineLimit(1).truncationMode(.middle).help(link.url)
                HStack(spacing: Theme.Space.md) {
                    Tag(link.kind.rawValue)
                    if link.canEdit { Tag("edit") } else if link.canDownload { Tag("view/download") }
                    if let exp = link.expiresAt {
                        Tag(exp < Date() ? "expired" : "expires \(RelativeTime.string(exp))",
                            warn: exp < Date())
                    }
                }
            }
            Spacer(minLength: Theme.Space.md)
            Button(action: onCopy) {
                Label(copied ? "Copied" : "Copy",
                      systemImage: copied ? IconSet.copied : IconSet.copy)
            }
            .cfButton(.secondary, size: .small)
            .disabled(link.url.isEmpty)
            .accessibilityLabel(copied ? "Link copied" : "Copy link")
            if isGuest {
                IconButton(IconSet.trash, label: "Revoke link", role: .badge,
                           tint: Theme.Status.error, action: onRevoke)
            }
        }
        .padding(Theme.Space.lg)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.Radius.md))
        .overlay((hovering ? Theme.hover : .clear)
            .clipShape(RoundedRectangle(cornerRadius: Theme.Radius.md)).allowsHitTesting(false))
        .overlay(RoundedRectangle(cornerRadius: Theme.Radius.md).strokeBorder(Theme.border))
        .onHover { hovering = $0 }
        .motionAnimation(Theme.Motion.hover, value: hovering)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(link.kind.rawValue) for \(link.path)")
    }
}

struct Tag: View {
    let text: String
    var warn = false
    init(_ text: String, warn: Bool = false) { self.text = text; self.warn = warn }
    var body: some View {
        Text(text)
            .font(Theme.Font.micro)
            .padding(.horizontal, Theme.Space.sm).padding(.vertical, Theme.Space.xxs)
            .background(Theme.surfaceInset, in: Capsule())
            .foregroundStyle(warn ? Theme.Status.error : Theme.textSecondary)
            .overlay(Capsule().strokeBorder(Theme.border))
            .accessibilityLabel(text)
    }
}
