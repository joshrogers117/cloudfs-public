// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

struct CreateGuestLinkSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let filespaceID: String
    @State private var trail: [(id: String, name: String)] = [("root", "Filespace")]
    @State private var items: [FileNode] = []
    @State private var selected: FileNode?
    @State private var cursor: String?
    @State private var loading = false
    @State private var creating = false
    @State private var error: String?
    @State private var result: CloudShareLink?
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                Text(result == nil ? "Create guest link" : "Guest link created").font(Theme.Font.title)
                Spacer()
                Button { dismiss() } label: { Image(systemName: "xmark") }.buttonStyle(.plain).disabled(creating).accessibilityLabel("Close guest link")
            }
            if let result {
                Text("Anyone with this link can read the selected item until the link expires or you revoke it.")
                    .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                Text(result.url).font(Theme.Font.mono).textSelection(.enabled).padding(14).frame(maxWidth: .infinity, alignment: .leading).background(Theme.surface, in: RoundedRectangle(cornerRadius: 8))
                if let expires = result.expiresAt { Text("Expires \(expires.formatted())").font(Theme.Font.caption) }
                Button(copied ? "Copied" : "Copy link") {
                    NSPasteboard.general.clearContents(); NSPasteboard.general.setString(result.url, forType: .string); copied = true
                }.cfButton(.primary)
            } else {
                Text("Select a file or folder. Anyone with the generated link will be able to read it.")
                    .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                HStack {
                    Button("Back") { trail.removeLast() }.cfButton(.subtle).disabled(trail.count == 1 || loading || creating)
                    Text(trail.map(\.name).joined(separator: " / ")).lineLimit(1).truncationMode(.middle)
                }
                ScrollView {
                    LazyVStack(spacing: 4) {
                        ForEach(items) { item in
                            HStack {
                                Button { selected = item } label: {
                                    HStack {
                                        Image(systemName: item.isDirectory ? "folder" : "doc")
                                        Text(item.name).lineLimit(1)
                                        Spacer()
                                        if selected?.id == item.id { Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.accent) }
                                    }.padding(10).contentShape(Rectangle())
                                }.buttonStyle(.plain)
                                if item.isDirectory {
                                    Button { trail.append((item.id, item.name)) } label: { Image(systemName: "chevron.right") }
                                        .buttonStyle(.plain).padding(10).accessibilityLabel("Open \(item.name)")
                                }
                            }.background(selected?.id == item.id ? Theme.selection : .clear, in: RoundedRectangle(cornerRadius: 7))
                        }
                        if loading { ProgressView().controlSize(.small).padding() }
                        if !loading && items.isEmpty && error == nil { Text("This folder is empty.").foregroundStyle(Theme.textSecondary).padding(30) }
                        if cursor != nil { Button("Load more") { Task { await load(more: true) } }.disabled(loading) }
                    }
                }.frame(height: 260).disabled(creating)
                if let error { Banner(kind: .error, title: "Could not create link", detail: error) }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.cfButton(.secondary).disabled(creating)
                    Button(creating ? "Creating…" : "Create guest link") { Task { await create() } }.cfButton(.primary)
                        .disabled(selected == nil || creating || loading)
                }
            }
        }.padding(28).frame(width: 560).background(Theme.bg)
            .task(id: trail.last?.id) { selected = nil; items = []; cursor = nil; await load(more: false) }
    }

    private func load(more: Bool) async {
        guard let parent = trail.last?.id else { return }
        loading = true; error = nil
        defer { if trail.last?.id == parent { loading = false } }
        do {
            let page = try await model.gateway.listDirectory(in: filespaceID, parentID: parent, cursor: more ? cursor : nil)
            guard !Task.isCancelled, trail.last?.id == parent else { return }
            items = more ? items + page.items : page.items
            cursor = page.cursor
        } catch { if !Task.isCancelled { self.error = error.localizedDescription } }
    }

    private func create() async {
        guard model.canManageGuestLinks, model.selectedFilespaceID == filespaceID, let selected else { return }
        creating = true; error = nil
        defer { creating = false }
        do {
            var link = try await model.gateway.createShareLink(for: selected.id, kind: .guestLink, in: filespaceID)
            link.path = (trail.dropFirst().map(\.name) + [selected.name]).joined(separator: "/")
            result = link
            if model.selectedFilespaceID == filespaceID {
                model.shareLinks.insert(link, at: 0); model.shareLinksState = .loaded(model.shareLinks)
            }
        } catch { self.error = error.localizedDescription }
    }
}
