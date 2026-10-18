// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - FilespacesView
//
// The filespace list + connect/login surface: shows every filespace the member
// has access to with connection status, storage backend, region, and size.
// Fully tokenized (Theme.*); hover + selected styling.

struct FilespacesView: View {
    @Environment(AppModel.self) private var model
    @State private var showInvite = false

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Filespaces (\(model.filespaces.count))",
                       trailing: AnyView(workspaceActions))
            content
        }
        .background(Theme.bg)
        .sheet(isPresented: Binding(get: { showInvite && model.canInviteMembers }, set: { showInvite = $0 })) {
            InviteSheet(assignableRoles: model.members.currentRole.assignableRoles()) { request in
                let invited = await model.inviteMember(request)
                if invited { model.members.tab = .members; model.section = .members }
                return invited
            }
        }
    }

    private var workspaceActions: some View {
        HStack(spacing: 10) {
            if model.canInviteMembers {
                Button { showInvite = true } label: {
                    Label("Invite members", systemImage: "person.badge.plus")
                }.cfButton(.secondary)
            }
            if model.canCreateFilespaces, !model.filespaces.isEmpty {
                Button { model.isCreatingFilespace = true } label: {
                    Label("Create filespace", systemImage: "plus.circle")
                }.cfButton(.primary)
            }
        }
    }

    @ViewBuilder private var content: some View {
        if model.filespaces.isEmpty {
            WorkspaceEmptyState()
        } else {
            ScrollView {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 150, maximum: 190), spacing: 24)], alignment: .leading, spacing: 24) {
                    ForEach(model.filespaces) { fs in
                        FilespaceCard(
                            fs: fs,
                            probe: model.onboarding.mountRows[fs.id],
                            onSelect: { model.select(fs.id) })
                    }
                }
                .padding(Theme.Space.xxl)
            }
        }
    }
}

/// Shared first-workspace state, including the return trip from web creation.
struct WorkspaceEmptyState: View {
    @Environment(AppModel.self) private var model
    @State private var refreshing = false

    var body: some View {
        VStack(spacing: Theme.Space.lg) {
            BrandMark(chrome: true, size: 90).padding(.bottom, 14)
            Text(model.canCreateFilespaces ? "Create your first filespace" : "Your workspace is ready")
                .font(.system(size: 26, weight: .semibold)).foregroundStyle(Theme.textPrimary)
            Text(model.canCreateFilespaces
                 ? "Set up a shared space for your team’s files. Create a filespace, then connect it here."
                 : "Ask your workspace administrator for filespace access, then refresh to connect it here.")
                .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                .multilineTextAlignment(.center).frame(maxWidth: 440)
                .padding(.bottom, 18)
            HStack(spacing: Theme.Space.md) {
                if model.canCreateFilespaces {
                    Button("Create filespace") { model.isCreatingFilespace = true }.cfButton(.primary, size: .large)
                }
                Button(refreshing ? "Refreshing…" : "Refresh filespaces") {
                    guard !refreshing else { return }
                    refreshing = true
                    Task {
                        await model.reloadFilespaces()
                        if model.isSignedIn, !model.isSigningOut,
                           model.selectedFilespace == nil, let first = model.filespaces.first {
                            model.select(first.id)
                        }
                        refreshing = false
                    }
                }
                .cfButton(.secondary, size: .large)
                .disabled(refreshing)
            }
        }
        .padding(Theme.Space.xxl)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct FilespaceCard: View {
    @Environment(AppModel.self) private var model
    let fs: Filespace
    /// The most recent verified-mount probe result for this filespace (from the
    /// first-run checklist, ONBOARDING.md §4), if one has ever run this session.
    /// Surfaced here — minimally — so a mounted-but-broken volume (probe failed)
    /// stays visible outside the checklist sheet, not just at first sign-in.
    var probe: MountRowState? = nil
    let onSelect: () -> Void

    @State private var hovering = false

    private var isMounted: Bool { fs.connection == .connected && !fs.mountPath.isEmpty }

    var body: some View {
        VStack(spacing: 12) {
            Button(action: onSelect) {
                VStack(spacing: 8) {
                    FilespaceDriveIllustration(size: 100)
                    Text(fs.name).font(Theme.Font.headline).foregroundStyle(Theme.textPrimary).lineLimit(1)
                    HStack(spacing: 6) {
                        StatusDot(color: fs.connection.dotColor, size: 6)
                        Text(fs.connection.label).font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                    }
                }.frame(maxWidth: .infinity).contentShape(Rectangle())
            }.buttonStyle(.plain).accessibilityLabel("\(fs.name), \(fs.connection.label)")
            if case .failed(let failure) = probe {
                Text(failure.title).font(Theme.Font.caption).foregroundStyle(Theme.Status.error)
            }
            if isMounted {
                Button("Open") { model.revealFilespaceInFinder(fs) }.cfButton(.secondary, size: .small)
            } else {
                Button("View filespace", action: onSelect).cfButton(.secondary, size: .small)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .top)
        .background(hovering ? Theme.hover : .clear, in: RoundedRectangle(cornerRadius: 12))
        .onHover { hovering = $0 }
    }
}
