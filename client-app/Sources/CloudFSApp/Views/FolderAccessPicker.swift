// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

/// Selects a real namespace folder. Pagination stays server-side, so granting
/// access never downloads an entire large filespace or requires an opaque ID.
struct FolderAccessPicker: View {
    @Environment(AppModel.self) private var model
    @Binding var inodeId: String
    @Binding var inodePath: String
    @State private var trail: [Folder] = []
    @State private var children: [FileNode] = []
    @State private var cursor: String?
    @State private var loading = false
    @State private var error: String?
    private struct Folder: Identifiable { let id: String; let name: String; let path: String }
    private var current: Folder? { trail.last }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if model.members.administration.roots.count > 1 {
                Menu("Managed folders") {
                    ForEach(model.members.administration.roots) { root in
                        Button(root.name) { trail = [.init(id: root.inodeId, name: root.name, path: root.path)] }
                    }
                }.menuStyle(.borderlessButton)
            }
            HStack(spacing: 5) {
                ForEach(Array(trail.enumerated()), id: \.element.id) { index, folder in
                    if index > 0 { Image(systemName: "chevron.right").font(.system(size: 9)) }
                    Button(folder.name) { trail = Array(trail.prefix(index + 1)) }
                        .buttonStyle(.borderless).lineLimit(1)
                }
            }.font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(children.filter(\.isDirectory)) { folder in
                        Button {
                            guard let current else { return }
                            let path = current.path == "/" ? "/\(folder.name)" : "\(current.path)/\(folder.name)"
                            trail.append(.init(id: folder.id, name: folder.name, path: path))
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "folder")
                                Text(folder.name).lineLimit(1)
                                Spacer()
                                Image(systemName: "chevron.right").font(.system(size: 10))
                            }.padding(9).contentShape(Rectangle())
                        }.buttonStyle(.plain)
                    }
                    if loading { ProgressView().controlSize(.small).padding(12) }
                    else if let error {
                        Text(error).font(Theme.Font.caption).foregroundStyle(Theme.Status.error).padding(8)
                        Button("Try again") { Task { await load(more: false) } }
                    } else if cursor != nil {
                        Button("Load more folders") { Task { await load(more: true) } }.padding(8)
                    } else if children.filter(\.isDirectory).isEmpty {
                        Text("No subfolders").font(Theme.Font.caption).foregroundStyle(Theme.textSecondary).padding(16)
                    }
                }
            }
            .frame(height: 140)
            .background(Theme.surfaceInset, in: RoundedRectangle(cornerRadius: 7))
            HStack {
                Button("Use this folder") { if let current { inodeId = current.id; inodePath = current.path } }
                    .cfButton(.secondary, size: .small).disabled(current == nil || loading || error != nil)
                Spacer()
                Label(inodeId.isEmpty ? "Choose a folder" : inodePath,
                      systemImage: inodeId.isEmpty ? "folder" : "checkmark.circle")
                    .font(Theme.Font.caption).foregroundStyle(inodeId.isEmpty ? Theme.textSecondary : Theme.accent)
                    .lineLimit(1).truncationMode(.middle).help(inodePath)
            }
        }
        .onAppear {
            if let root = model.members.administration.roots.first {
                trail = [.init(id: root.inodeId, name: root.name, path: root.path)]
            }
        }
        .task(id: current?.id) { await load(more: false) }
    }

    private func load(more: Bool) async {
        guard let space = model.selectedFilespaceID, let current else { return }
        let folder = current.id
        loading = true; error = nil
        if !more { children = []; cursor = nil }
        do {
            let page = try await model.gateway.listManagedFolders(in: space, parentID: folder, cursor: more ? cursor : nil)
            guard self.current?.id == folder, model.selectedFilespaceID == space, !Task.isCancelled else { return }
            children = more ? children + page.items : page.items
            cursor = page.cursor
            model.members.knownFolderPaths["\(space):\(folder)"] = current.path
        } catch {
            guard self.current?.id == folder, model.selectedFilespaceID == space, !Task.isCancelled else { return }
            self.error = error.localizedDescription
        }
        loading = false
    }
}
