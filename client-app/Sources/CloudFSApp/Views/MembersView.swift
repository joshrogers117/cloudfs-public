// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// Members and Groups use workspace roles. Folder access uses live capabilities
// returned by the gateway, so delegated standard members can manage their scope
// without gaining workspace-account or group-membership controls.

struct MembersView: View {
    @Environment(AppModel.self) private var model

    private var feature: MembersFeatureModel { model.members }

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: feature.tab == .access ? "Access and permissions" : feature.tab.rawValue,
                       subtitle: feature.tab == .access ? model.selectedFilespace?.name : model.workspaceDisplayName,
                       trailing: AnyView(headerTrailing))
            tabPicker
            if let error = feature.mutationError {
                Banner(kind: .error, title: "Change could not be saved", detail: error).padding(.horizontal, 20).padding(.top, 12)
            }
            content
        }
        .background(Theme.bg)
        .task(id: model.refreshToken) { await reload() }
        .task(id: model.selectedFilespaceID) { await model.loadGrants() }
        .onAppear { Task { await reload() } }
        .sheet(isPresented: Binding(get: { showInvite && model.canInviteMembers }, set: { showInvite = $0 })) {
            InviteSheet(assignableRoles: feature.currentRole.assignableRoles()) { request in
                await model.inviteMember(request)
            }
        }
        .sheet(item: $grantEditor) { editor in
            GrantEditorSheet(
                existing: editor.existing,
                members: feature.grantMembers,
                groups: feature.grantGroups,
                folders: grantableFolders) { request in
                guard model.selectedFilespaceID == editor.filespaceID,
                      model.navigationRequestID == editor.sessionID else { return false }
                return await model.setGrant(request)
            }
            .id(editor.id)
        }
        .onChange(of: model.selectedFilespaceID) { _, _ in grantEditor = nil }
        .onChange(of: model.navigationRequestID) { _, _ in grantEditor = nil }
    }

    /// Folders a grant can target — the active filespace's top-level nodes. The
    /// editor lets the admin type a path too, so this is a convenience picker, not
    /// an exhaustive tree.
    private var grantableFolders: [GrantEditorSheet.Folder] {
        // Distinct inode/path pairs already seen in grants, so re-granting on a
        // known folder is one tap. (The live namespace tree isn't loaded here.)
        var seen = Set<String>()
        var out: [GrantEditorSheet.Folder] = []
        for g in feature.grants where !seen.contains(g.inodeId) {
            seen.insert(g.inodeId)
            out.append(.init(inodeId: g.inodeId, path: g.inodePath))
        }
        return out.sorted { $0.path < $1.path }
    }

    private func reload() async {
        await model.loadMembers()
        await model.loadGrants()
    }

    // MARK: Header trailing (refresh + per-tab primary action)

    @ViewBuilder private var headerTrailing: some View {
        HStack(spacing: Theme.Space.md) {
            if model.canManageMembers {
                switch feature.tab {
                case .members:
                    if feature.canMutate { Button {
                        feature.mutationError = nil; showInvite = true
                    } label: { Label("Invite", systemImage: IconSet.inviteUser) }
                    .cfButton(.primary, size: .small)
                    .disabled(!model.isSignedIn) }
                case .groups:
                    if feature.canMutate {
                        Button {
                            feature.mutationError = nil
                            feature.showCreateGroup = true
                        } label: { Label("Create group", systemImage: "plus") }
                            .cfButton(.primary, size: .small)
                            .disabled(feature.isCreatingGroup)
                    }
                case .access:
                    Button {
                        presentGrantEditor()
                    } label: { Label("Grant access", systemImage: IconSet.addGrant) }
                    .cfButton(.primary, size: .small)
                    .disabled(!model.canManageFolderAccess)
                }
            }
        }
    }

    // MARK: Tab picker (Members | Access)

    private var tabPicker: some View {
        @Bindable var feature = feature
        return HStack(spacing: Theme.Space.sm) {
            ForEach(feature.currentRole.canManageMembers ? MembersFeatureModel.Tab.allCases : [.access]) { tab in
                let active = feature.tab == tab
                Button { feature.tab = tab } label: {
                    Text(tab.rawValue)
                        .font(Theme.Font.body.weight(active ? .semibold : .regular))
                        .foregroundStyle(active ? Theme.textPrimary : Theme.textSecondary)
                        .padding(.horizontal, Theme.Space.lg)
                        .padding(.vertical, Theme.Space.sm)
                        .background(active ? Theme.selection : .clear,
                                    in: RoundedRectangle(cornerRadius: Theme.Radius.sm))
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(active ? [.isButton, .isSelected] : .isButton)
            }
            Spacer()
        }
        .padding(.horizontal, Theme.Space.xxl)
        .padding(.vertical, Theme.Space.md)
        .background(Theme.bg)
        .overlay(Divider().overlay(Theme.divider), alignment: .bottom)
    }

    // MARK: Routed content

    @ViewBuilder private var content: some View {
        if !model.canManageMembers, case .loading = feature.grantsState {
            ProgressView("Loading folder permissions…").padding(24)
        } else if !model.canManageMembers, case .failed(let message) = feature.grantsState {
            VStack(spacing: 12) {
                Banner(kind: .error, title: "Permissions could not be loaded", detail: message)
                Button("Try again") { Task { await model.loadGrants() } }.cfButton(.secondary)
            }.padding(24)
        } else if !model.canManageMembers {
            EmptyState(symbol: IconSet.membersNav,
                       title: "No folders to manage",
                       hint: "A workspace admin can give you permission to manage access to a folder.")
        } else {
            switch feature.tab {
            case .members: membersTab
            case .groups: GroupsView()
            case .access:  accessTab
            }
        }
    }

    // MARK: - Members tab

    private var membersTab: some View {
        StatePane(state: feature.membersState,
                  loadingText: "Loading members…",
                  empty: EmptyState(
                    symbol: IconSet.members,
                    title: "No members yet",
                    hint: "Invite people to your org to give them access to filespaces."),
                  retry: { Task { await model.loadMembers() } }) { dir in
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Space.xl) {
                    if let invite = feature.lastInvite {
                        InviteResultCard(invite: invite) { model.members.lastInvite = nil }
                    }
                    MembersSummaryCard(summary: feature.summary)
                    Card("Directory") {
                        VStack(spacing: 0) {
                            ForEach(Array(dir.enumerated()), id: \.element.id) { index, member in
                                if index > 0 { Divider().overlay(Theme.divider) }
                                MemberRow(
                                    member: member,
                                    canMutate: feature.canMutate,
                                    assignableRoles: feature.currentRole.assignableRoles(),
                                    isBusy: feature.busyMemberIDs.contains(member.id),
                                    onChangeRole: { role in Task { await model.changeRole(role, for: member) } },
                                    onSuspend: { Task { await model.suspendMember(member) } },
                                    onReactivate: { Task { await model.reactivateMember(member) } },
                                    onDeprovision: { Task { await model.deprovisionMember(member) } })
                            }
                        }
                    }
                }
                .padding(Theme.Space.xxl)
            }
        }
    }

    // MARK: - Access tab

    private var accessTab: some View {
        Group {
            if model.selectedFilespace == nil {
                EmptyState(symbol: IconSet.folderGrant,
                           title: "No filespace selected",
                           hint: "Choose a filespace to view and edit its per-folder access.")
            } else {
                StatePane(state: feature.grantsState,
                          loadingText: "Loading access…",
                          empty: EmptyState(
                            symbol: IconSet.folderGrant,
                            title: "No grants yet",
                            hint: "Grant an existing member or group access to a folder you manage."),
                          retry: { Task { await model.loadGrants() } }) { grants in
                    ScrollView {
                        VStack(alignment: .leading, spacing: Theme.Space.xl) {
                            if !feature.administration.canDelegateAdmin {
                                Text("You manage access only within your delegated folders. Workspace accounts and administrator grants are managed by your workspace admin.")
                                    .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                            }
                            AccessSummaryCard(grants: grants,
                                              filespace: model.selectedFilespace?.name ?? "")
                            Card("Folder grants") {
                                VStack(spacing: 0) {
                                    ForEach(Array(grants.enumerated()), id: \.element.id) { index, grant in
                                        if index > 0 { Divider().overlay(Theme.divider) }
                                        GrantRow(
                                            grant: grant,
                                            canMutate: feature.administration.canModify(grant),
                                            isBusy: feature.busyGrantIDs.contains(grant.id),
                                            onEdit: { presentGrantEditor(existing: grant) },
                                            onRemove: { Task { await model.removeGrant(grant) } })
                                    }
                                }
                            }
                        }
                        .padding(Theme.Space.xxl)
                    }
                }
            }
        }
    }

    // MARK: Sheets

    @State private var showInvite = false
    @State private var grantEditor: GrantEditorPresentation?

    /// One immutable presentation value carries the selected grant and its
    /// authorization context into the sheet, including on its first opening.
    private struct GrantEditorPresentation: Identifiable {
        let id = UUID()
        let existing: AccessGrant?
        let filespaceID: String
        let sessionID: UUID
    }

    private func presentGrantEditor(existing: AccessGrant? = nil) {
        guard model.canManageFolderAccess, let filespaceID = model.selectedFilespaceID,
              existing.map({ feature.administration.canModify($0) }) ?? true else { return }
        feature.mutationError = nil
        grantEditor = GrantEditorPresentation(existing: existing, filespaceID: filespaceID,
                                               sessionID: model.navigationRequestID)
    }
}

// MARK: - Invite result card (raw token shown ONCE)

struct InviteResultCard: View {
    @Environment(AppModel.self) private var model
    private var inviteLink: String {
        guard let base = model.consoleLinks.base else { return invite.rawToken }
        var url = URLComponents(string: base.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/join")
        url?.queryItems = [URLQueryItem(name: "token", value: invite.joinToken ?? "\(model.settings.org).\(invite.rawToken)")]
        return url?.url?.absoluteString ?? invite.rawToken
    }
    let invite: InviteResult
    let onDismiss: () -> Void
    @State private var copied = false

    var body: some View {
        Card {
            HStack(alignment: .top, spacing: Theme.Space.md) {
                Image(systemName: IconSet.success).foregroundStyle(Theme.Status.ok)
                    .font(Theme.Font.body).accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Theme.Space.sm) {
                    Text(invite.emailSent ? "Invite emailed to \(invite.email)" : "Invite created for \(invite.email)")
                        .font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                    Text("Role: \(invite.role.displayName) · expires \(invite.expiresAt.formatted(date: .abbreviated, time: .omitted))")
                        .font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
                    if !invite.rawToken.isEmpty {
                        Text("Copy this invite link to share with your teammate.")
                            .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                        HStack(spacing: Theme.Space.sm) {
                            Text(inviteLink)
                                .font(Theme.Font.monoPath).foregroundStyle(Theme.textSecondary)
                                .lineLimit(1).truncationMode(.middle)
                                .padding(.horizontal, Theme.Space.sm)
                                .padding(.vertical, Theme.Space.xxs)
                                .background(Theme.surfaceInset, in: RoundedRectangle(cornerRadius: Theme.Radius.xs))
                            Button {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(inviteLink, forType: .string)
                                copied = true
                            } label: {
                                Label(copied ? "Copied" : "Copy",
                                      systemImage: copied ? IconSet.copied : IconSet.copy)
                            }
                            .cfButton(.secondary, size: .small)
                        }
                    }
                }
                Spacer()
                IconButton(IconSet.clearSearch, label: "Dismiss", action: onDismiss)
            }
        }
    }
}

// MARK: - Members summary strip

struct MembersSummaryCard: View {
    let summary: MembersSummary

    var body: some View {
        Card("Org directory") {
            HStack(alignment: .firstTextBaseline, spacing: Theme.Space.xxl) {
                stat("\(summary.total)", "members")
                stat("\(summary.adminCount)", "admins")
                if summary.suspendedCount > 0 { stat("\(summary.suspendedCount)", "suspended") }
                if summary.serviceAccountCount > 0 { stat("\(summary.serviceAccountCount)", "service") }
                Spacer()
            }
        }
    }

    private func stat(_ value: String, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
            Text(value).font(Theme.Font.monoTitle).foregroundStyle(Theme.textPrimary)
            Text(label.uppercased()).font(Theme.Font.sectionLabel).tracking(0.5)
                .foregroundStyle(Theme.textTertiary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
    }
}

// MARK: - Access summary strip

struct AccessSummaryCard: View {
    let grants: [AccessGrant]
    let filespace: String

    private var adminCount: Int { grants.filter { $0.level == .admin }.count }
    private var editCount: Int { grants.filter { $0.level == .edit }.count }
    private var readCount: Int { grants.filter { $0.level == .read }.count }

    var body: some View {
        Card("Access in \(filespace)") {
            HStack(alignment: .firstTextBaseline, spacing: Theme.Space.xxl) {
                stat("\(grants.count)", "grants")
                if adminCount > 0 { stat("\(adminCount)", "admin") }
                if editCount > 0 { stat("\(editCount)", "edit") }
                if readCount > 0 { stat("\(readCount)", "read") }
                Spacer()
            }
        }
    }

    private func stat(_ value: String, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: Theme.Space.xxs) {
            Text(value).font(Theme.Font.monoTitle).foregroundStyle(Theme.textPrimary)
            Text(label.uppercased()).font(Theme.Font.sectionLabel).tracking(0.5)
                .foregroundStyle(Theme.textTertiary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
    }
}
