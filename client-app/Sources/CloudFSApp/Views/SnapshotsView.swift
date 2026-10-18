// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - SnapshotsView (WS4 — owned by the snapshot agent)
//
// Browse server-side GFS snapshots and self-service restore, Time-Machine style:
//
//   1. DEEP lazy folder-tree browse of the selected snapshot — each folder loads
//      its own level on expand via the snapshot deep-browse seam (no whole-tree
//      load), so you can drill arbitrarily deep into a point in time.
//   2. MULTI-SELECT of files/folders + a "Restore selected to live filespace"
//      action. Restores are NON-DESTRUCTIVE: items come back as NEW current
//      versions, nothing is overwritten wholesale, newer items are left untouched,
//      and locked items are skipped (never clobbered).
//   3. A real "Create snapshot now" action wired to the manual-create seam.
//
// All state lives in `AppModel.snaps` (SnapshotsFeatureModel); the view stays a
// declarative projection. Drives entirely from the Mock client offline.

struct SnapshotsView: View {
    @Environment(AppModel.self) private var model
    @State private var selected: Snapshot?
    @State private var showCreateSheet = false

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Snapshots",
                       subtitle: "Open a saved version in Finder or recover files to your filespace.")
            HStack(spacing: 12) {
                Text("Saved recovery points").font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                if model.canManageSnapshotSchedules, let fs = model.selectedFilespace, let url = model.consoleLinks.filespaceSettings(id: fs.id, section: "snapshots") {
                    Link("Schedules", destination: url).cfButton(.subtle)
                }
                Spacer()
                if model.canManageFolderAccess && !model.snapshots.isEmpty { createButton }
            }.padding(.horizontal, 24).padding(.bottom, 20)
            if let error = model.snaps.lastError {
                Banner(kind: .error, title: "Snapshot action needs attention", detail: error)
                    .padding(Theme.Space.lg)
            } else if let name = model.snaps.lastCreatedSnapshotName {
                Banner(kind: .success, title: "Snapshot created", detail: name).padding(Theme.Space.lg)
            }
            content
        }
        .background(Theme.bg)
        .sheet(isPresented: Binding(get: { showCreateSheet && model.canManageFolderAccess }, set: { showCreateSheet = $0 })) {
            CreateSnapshotSheet { label, scope in
                await model.takeManualSnapshot(label: label, scope: scope)
            }
        }
        .onChange(of: model.selectedFilespaceID) { _, _ in selected = nil; model.snaps.mounts = [] }
        .task(id: model.selectedFilespaceID) {
            await model.loadGrants()
            guard model.isHttpMode else { model.snaps.mounts = []; return }
            while !Task.isCancelled {
                await model.refreshSnapshotMounts()
                do { try await Task.sleep(for: .seconds(5)) } catch { return }
            }
        }
    }

    // MARK: Header action — Create snapshot now

    private var createButton: some View {
        Button {
            showCreateSheet = true
        } label: {
            Label("Create snapshot now", systemImage: IconSet.newSnapshot)
        }
        .cfButton(.primary, size: .small)
        .disabled(model.selectedFilespaceID == nil || model.snaps.isWorking || !model.canManageFolderAccess)
        .help(model.canManageFolderAccess ? "Create a snapshot of folders you administer" : "Folder administrator access is required to create snapshots")
    }

    @ViewBuilder private var content: some View {
        switch model.snapshotsState {
        case .idle, .loading:
            LoadingPane(text: "Loading snapshots…")
        case .failed(let msg):
            ErrorPane(message: msg) { Task { await model.refreshForSelection() } }
        case .loaded(let snaps):
            if snaps.isEmpty {
                VStack(spacing: 18) {
                    Spacer()
                    Image(systemName: "archivebox").font(.system(size: 42)).foregroundStyle(Theme.textSecondary)
                        .frame(width: 88, height: 88).background(Theme.surface, in: RoundedRectangle(cornerRadius: 24))
                    Text("No snapshots yet").font(.system(size: 22, weight: .semibold))
                    Text(model.canManageFolderAccess ? "Create a snapshot to save a recovery point for your filespace." : "Saved recovery points will appear here when available.")
                        .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                    if model.canManageFolderAccess { createButton }
                    Spacer()
                }.frame(maxWidth: .infinity).padding(24)
            } else {
                HSplitView {
                    snapshotList
                        .frame(minWidth: Theme.Metric.snapshotListMin,
                               idealWidth: Theme.Metric.snapshotListIdeal, maxWidth: 300)
                    snapshotDetail
                        .frame(maxWidth: .infinity)
                }
            }
        }
    }

    // MARK: Snapshot list (left) — keeps creation timestamps

    private var snapshotList: some View {
        ScrollView {
            LazyVStack(spacing: 4) {
                ForEach(model.snapshots) { snap in
                    Button {
                        selected = snap
                        Task { await selectSnapshot() }
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: snap.isScheduled ? IconSet.scheduled : IconSet.manual)
                                .foregroundStyle(Theme.accent)
                            VStack(alignment: .leading, spacing: 5) {
                                Text(snap.name).font(Theme.Font.body.weight(.medium))
                                    .foregroundStyle(Theme.textPrimary).lineLimit(2)
                                if model.snaps.mounts.contains(where: { $0.snapshotId == snap.id && $0.isMounted }) {
                                    Label("Mounted", systemImage: "externaldrive").font(Theme.Font.micro).foregroundStyle(Theme.accent)
                                }
                                Text("\(snap.retentionTier) · \(RelativeTime.string(snap.takenAt))")
                                    .font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
                            }
                            Spacer(minLength: 0)
                        }.padding(12).frame(maxWidth: .infinity, alignment: .leading)
                            .background(selected?.id == snap.id ? Theme.selection : .clear,
                                        in: RoundedRectangle(cornerRadius: 8))
                            .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                        .accessibilityAddTraits(selected?.id == snap.id ? .isSelected : [])
                }
            }.padding(10)
        }.background(Theme.bgSidebar)
    }

    // MARK: Snapshot detail (right) — metadata + deep tree + multi-restore

    private var snapshotDetail: some View {
        Group {
            if let snap = selected {
                ScrollView {
                    VStack(alignment: .leading, spacing: Theme.Space.xl) {
                        metadataCard(snap)
                        finderMountCard(snap)
                        restoreIntentCard
                        browseCard(snap)
                        resultCard
                    }
                    .padding(Theme.Space.xxl)
                }
                .id(snap.id)
                .transition(.opacity)
                .safeAreaInset(edge: .bottom) { restoreBar(snap) }
            } else {
                EmptyState(symbol: IconSet.snapshots,
                           title: "Select a snapshot",
                           hint: "Pick a point in time on the left to browse its folder tree and restore files or folders back into the live filespace.")
            }
        }
        .background(Theme.bg)
        // Cross-fade when switching the selected snapshot; instant on Reduce Motion.
        .motionAnimation(Theme.Motion.section, value: selected?.id)
    }

    private func metadataCard(_ snap: Snapshot) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(snap.name).font(.system(size: 21, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text(snap.takenAt.formatted(date: .complete, time: .shortened))
                .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
            HStack(spacing: 12) {
                Tag(snap.isScheduled ? "Scheduled" : "Manual")
                if snap.sizeBytes > 0 { Text(ByteFormat.string(snap.sizeBytes)).font(Theme.Font.caption).foregroundStyle(Theme.textTertiary) }
                if let scope = snap.scope, scope != "root" {
                    Text(model.members.administration.roots.first(where: { $0.inodeId == scope })?.path ?? "Folder snapshot")
                        .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                }
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private func finderMountCard(_ snapshot: Snapshot) -> some View {
        let mounted = model.isHttpMode ? model.snaps.mounts.first { $0.snapshotId == snapshot.id } : nil
        let busy = model.snaps.mountInProgress == snapshot.id
        return Card("Open in Finder") {
            VStack(alignment: .leading, spacing: Theme.Space.md) {
                HStack(spacing: 8) {
                    Image(systemName: "lock.fill").foregroundStyle(Theme.textSecondary)
                    Text(mounted?.isMounted == true ? "Mounted · Read-only" : "Read-only snapshot")
                        .font(Theme.Font.body.weight(.medium)).foregroundStyle(Theme.textPrimary)
                    if busy { ProgressView().controlSize(.small) }
                }
                Text("Browse and copy files from this point in time. Edit your copy in the live filespace or another writable folder.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                if mounted?.status == "unavailable" {
                    Text("This snapshot is no longer available. It may have been deleted or your access may have changed.")
                        .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                }
                HStack {
                    Button {
                        Task { await model.openSnapshotInFinder(snapshot) }
                    } label: {
                        Label(mounted?.isMounted == true ? "Open in Finder" : "Mount snapshot", systemImage: "folder")
                    }.cfButton(.primary, size: .small)
                    if mounted?.isMounted == true {
                        Button {
                            Task { await model.ejectSnapshot(snapshot) }
                        } label: { Label("Eject", systemImage: "eject") }
                            .cfButton(.secondary, size: .small)
                    }
                }.disabled(model.snaps.mountInProgress != nil || !model.isEngineConnected || model.isSigningOut)
                if !model.isHttpMode {
                    Text("Sign in to a workspace to mount snapshots in Finder.")
                        .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                } else if !model.engine.isAvailable {
                    Text("Connect the CloudFS background service to mount snapshots.")
                        .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                }
            }
        }
    }

    private var restoreIntentCard: some View {
        Text("Restore earlier content as a new current version. Newly created files stay in place, and files locked by another editor are skipped.")
            .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: Deep lazy folder-tree browse

    private func browseCard(_ snap: Snapshot) -> some View {
        Card("Browse this point in time") {
            let root = model.snaps.loadedChildren(of: nil)
            if root == nil && model.snaps.loadingFolders.contains(SnapshotsFeatureModel.rootKey) {
                HStack(spacing: Theme.Space.md) {
                    ProgressView().controlSize(.small)
                    Text("Loading snapshot root…")
                        .font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
                }
            } else if let nodes = root, nodes.isEmpty {
                Text("This snapshot's root is empty.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
            } else if root == nil {
                Button("Retry loading this snapshot") {
                    Task { await model.loadSnapshotChildren(snapshotID: snap.id, folderID: nil) }
                }.cfButton(.secondary, size: .small)
            } else {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(root ?? []) { node in
                        SnapshotTreeRow(snapshot: snap, node: node, depth: 0)
                    }
                }
            }
        }
    }

    // MARK: Multi-select restore bar (pinned to the bottom of the detail pane)

    @ViewBuilder
    private func restoreBar(_ snap: Snapshot) -> some View {
        let count = model.snaps.selectionCount
        if count > 0 {
            VStack(alignment: .leading, spacing: Theme.Space.md) {
                VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                    Text("\(count) item\(count == 1 ? "" : "s") selected")
                        .font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                    Text("Restores earlier content as a new current version.")
                        .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                }
                HStack(spacing: Theme.Space.md) {
                    Button("Clear") { model.snaps.selected = [:] }
                        .cfButton(.subtle, size: .small)
                        .disabled(model.snaps.isWorking)
                    Spacer(minLength: 0)
                    if model.snaps.isWorking {
                        ProgressView().controlSize(.small)
                    } else {
                        Button {
                            Task { await model.restoreSelected(fromSnapshot: snap.id) }
                        } label: {
                            Label("Restore to filespace", systemImage: IconSet.recreated)
                        }
                        .cfButton(.primary, size: .small)
                        .help("Restore selected items to the live filespace")
                    }
                }
            }
            .padding(.horizontal, Theme.Space.xxl)
            .padding(.vertical, Theme.Space.lg)
            .background(.ultraThinMaterial)
            .overlay(Divider().overlay(Theme.divider), alignment: .top)
            .transition(.move(edge: .bottom).combined(with: .opacity))
            .motionAnimation(Theme.Motion.section, value: count)
        }
    }

    // MARK: Result / error feedback

    @ViewBuilder
    private var resultCard: some View {
        if let err = model.snaps.lastError {
            Banner(kind: .error, title: "Restore failed", detail: err)
        }
        if let name = model.snaps.lastCreatedSnapshotName {
            Banner(kind: .success, title: "Created snapshot",
                   detail: "“\(name)” is now available to browse and restore.")
        }
        if let r = model.snaps.lastRestoreResult {
            Card("Restore result") { restoreResultView(r) }
        }
    }

    @ViewBuilder
    private func restoreResultView(_ r: RestoreResult) -> some View {
        let skipped = r.skippedPermissions ?? r.forbidden?.count ?? 0
        let conflicted = r.hasConflicts || skipped > 0 || r.streamsCaptured == false
        Banner(
            kind: conflicted ? .warning : .success,
            title: conflicted
                ? "Restored \(r.totalApplied) item(s) as new versions; \(r.conflicts.count + skipped) skipped"
                : "Restored \(r.totalApplied) item(s) as new current versions")
        VStack(alignment: .leading, spacing: Theme.Space.xs) {
            if skipped > 0 {
                resultLine("lock", "\(skipped) item(s) skipped because edit access is unavailable", tint: Theme.Status.warn)
            }
            if r.streamsCaptured == false {
                resultLine("info.circle", "This older snapshot did not capture Mac resource forks or Finder metadata.", tint: Theme.Status.warn)
            }
            if !r.recreated.isEmpty {
                resultLine(IconSet.recreated, "\(r.recreated.count) re-created (deleted since snapshot)")
            }
            if !r.newerThanSnapshot.isEmpty {
                resultLine(IconSet.clock, "\(r.newerThanSnapshot.count) newer item(s) left untouched")
            }
            ForEach(r.conflicts) { c in
                resultLine(IconSet.locked, "Skipped \(c.id)\(c.heldBy.map { " — held by \($0)" } ?? "")",
                           tint: Theme.Status.warn)
            }
        }
        .padding(.top, Theme.Space.xxs)
    }

    private func resultLine(_ symbol: String, _ text: String, tint: Color = Theme.textTertiary) -> some View {
        HStack(spacing: Theme.Space.sm) {
            Image(systemName: symbol).font(Theme.Font.micro).foregroundStyle(tint)
            Text(text).font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
        }
    }

    // MARK: Selection lifecycle

    private func selectSnapshot() async {
        guard let snap = selected else {
            model.snaps.resetBrowse(for: nil)
            return
        }
        await model.beginSnapshotBrowse(snap.id)
    }
}

// MARK: - SnapshotTreeRow — one lazily-expandable node in the snapshot tree
//
// A folder shows a disclosure chevron; expanding it lazily loads (and caches) its
// own level via the deep-browse seam. Every row carries a multi-select checkbox.
// Recursion is bounded by the user's expansion — nothing loads until asked.

private struct SnapshotTreeRow: View {
    @Environment(AppModel.self) private var model
    let snapshot: Snapshot
    let node: FileNode
    let depth: Int

    private var isExpanded: Bool { model.snaps.expanded.contains(node.id) }
    private var isLoading: Bool { model.snaps.loadingFolders.contains(node.id) }
    private var isSelected: Bool { model.snaps.isSelected(node) }
    private var children: [FileNode]? { model.snaps.children[node.id] }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            row
            if node.isDirectory && isExpanded {
                if isLoading && children == nil {
                    HStack(spacing: Theme.Space.sm) {
                        ProgressView().controlSize(.small)
                        Text("Loading…").font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                    }
                    .padding(.leading, indent(depth + 1))
                    .padding(.vertical, Theme.Space.xs)
                } else if let kids = children {
                    if kids.isEmpty {
                        Text("Empty folder")
                            .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                            .padding(.leading, indent(depth + 1))
                            .padding(.vertical, Theme.Space.xs)
                    } else {
                        ForEach(kids) { child in
                            SnapshotTreeRow(snapshot: snapshot, node: child, depth: depth + 1)
                        }
                    }
                }
            }
        }
    }

    private var row: some View {
        HStack(spacing: Theme.Space.md) {
            // Multi-select checkbox.
            Button {
                model.snaps.toggleSelection(node)
            } label: {
                Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                    .foregroundStyle(isSelected ? Theme.accent : Theme.textTertiary)
            }
            .buttonStyle(.plain)
            .help(isSelected ? "Deselect" : "Select for restore")
            .accessibilityLabel(isSelected ? "Selected for restore" : "Not selected")

            // Disclosure chevron (folders only) — toggles lazy expansion.
            Group {
                if node.isDirectory {
                    Button {
                        Task { await model.toggleSnapshotFolder(snapshotID: snapshot.id, folder: node) }
                    } label: {
                        Image(systemName: isExpanded ? IconSet.chevronDown : IconSet.chevronRight)
                            .font(Theme.Font.micro)
                            .foregroundStyle(Theme.textSecondary)
                            .frame(width: Theme.Metric.disclosureWidth)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(isExpanded ? "Collapse \(node.name)" : "Expand \(node.name)")
                } else {
                    Color.clear.frame(width: Theme.Metric.disclosureWidth)
                }
            }

            Image(systemName: node.isDirectory ? IconSet.folder : IconSet.document)
                .foregroundStyle(node.isDirectory ? Theme.accent : Theme.textSecondary)
                .accessibilityHidden(true)

            Text(node.name)
                .font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                .lineLimit(1).truncationMode(.middle).help(node.name)

            Spacer(minLength: Theme.Space.md)

            if node.lockedBy != nil {
                Image(systemName: IconSet.locked)
                    .font(Theme.Font.micro).foregroundStyle(Theme.Status.warn)
                    .help("Locked by \(node.lockedBy ?? "another editor")")
            }
            if node.isDirectory {
                if node.childCount > 0 {
                    Text("\(node.childCount) item\(node.childCount == 1 ? "" : "s")")
                        .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                }
            } else {
                Text(ByteFormat.string(node.sizeBytes))
                    .font(Theme.Font.mono).foregroundStyle(Theme.textTertiary)
            }
        }
        .padding(.leading, indent(depth))
        .padding(.vertical, Theme.Space.xxs)
        .contentShape(Rectangle())
        // Tapping a folder row toggles expansion; tapping a file toggles selection.
        .onTapGesture {
            if node.isDirectory {
                Task { await model.toggleSnapshotFolder(snapshotID: snapshot.id, folder: node) }
            } else {
                model.snaps.toggleSelection(node)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func indent(_ depth: Int) -> CGFloat {
        CGFloat(depth) * Theme.Metric.indentPerLevel
    }
}

// MARK: - CreateSnapshotSheet — label the manual snapshot before taking it

private struct CreateSnapshotSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var label = ""
    let onCreate: (String?, String?) async -> Bool
    @State private var scope = ""
    @State private var scopePath = ""
    @State private var working = false

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.xl) {
            VStack(alignment: .leading, spacing: Theme.Space.xs) {
                Text("Create snapshot now").font(Theme.Font.headline)
                    .foregroundStyle(Theme.textPrimary)
                Text("Captures the selected folder and its contents as a point in time you can open in Finder or restore later.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: Theme.Space.xs) {
                SectionLabel("Include")
                FolderAccessPicker(inodeId: $scope, inodePath: $scopePath)
                Text("Only folders you administer are available.")
                    .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
            }
            VStack(alignment: .leading, spacing: Theme.Space.xs) {
                SectionLabel("Label (optional)")
                TextField("e.g. Before client review", text: $label)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(create)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .cfButton(.secondary, size: .regular)
                    .keyboardShortcut(.cancelAction)
                    .disabled(working)
                Button("Create snapshot") { create() }
                    .cfButton(.primary, size: .regular)
                    .keyboardShortcut(.defaultAction)
                    .disabled(working || scope.isEmpty || !model.canManageFolderAccess)
                if working { ProgressView().controlSize(.small) }
            }
            if let error = model.snaps.lastError {
                Banner(kind: .error, title: "Couldn’t create snapshot", detail: error)
            }
        }
        .padding(Theme.Space.xxl)
        .frame(width: 420)
        .background(Theme.bg)
        .onAppear {
            scope = model.members.administration.canDelegateAdmin ? "root" : model.members.administration.roots.first?.inodeId ?? ""
            scopePath = model.members.administration.canDelegateAdmin ? "/" : model.members.administration.roots.first?.path ?? ""
        }
    }

    private func create() {
        guard !working, !scope.isEmpty, model.canManageFolderAccess else { return }
        working = true
        Task {
            if await onCreate(label.isEmpty ? nil : label, scope) { dismiss() }
            working = false
        }
    }
}
