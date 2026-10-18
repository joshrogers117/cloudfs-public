// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - Members & Access view components
//
// Rows + chips + sheets for MembersView, kept here so the pane file stays focused
// on layout/routing. All tokenized via Theme/Components; the visual vocabulary for
// roles / statuses / levels tunes in one place (RoleChip / StatusBadge / LevelChip).

// MARK: - Role chip

struct RoleChip: View {
    let role: OrgRole

    private var tint: Color {
        switch role {
        case .owner:      return Theme.accent
        case .admin:      return Theme.accent
        case .spaceAdmin: return Theme.Status.busy
        case .standard:   return Theme.textTertiary
        }
    }

    private var symbol: String {
        switch role {
        case .owner:      return IconSet.roleOwner
        case .admin:      return IconSet.roleAdmin
        case .spaceAdmin: return IconSet.roleAdmin
        case .standard:   return IconSet.roleStandard
        }
    }

    var body: some View {
        HStack(spacing: Theme.Space.xs) {
            Image(systemName: symbol).font(Theme.Font.monoMicro).accessibilityHidden(true)
            Text(role.displayName).font(Theme.Font.monoMicro)
        }
        .foregroundStyle(tint)
        .padding(.horizontal, Theme.Space.sm)
        .padding(.vertical, Theme.Space.xxs)
        .background(tint.opacity(0.14), in: Capsule())
        .overlay(Capsule().strokeBorder(tint.opacity(0.30), lineWidth: 0.5))
        .help(role.explanation)
        .accessibilityLabel("Role: \(role.displayName)")
    }
}

// MARK: - Status badge (active / suspended / deprovisioned)

struct StatusBadge: View {
    let status: MemberStatus

    private var color: Color {
        switch status {
        case .active:        return Theme.Status.ok
        case .suspended:     return Theme.Status.paused
        case .deprovisioned: return Theme.Status.idle
        }
    }

    var body: some View {
        HStack(spacing: Theme.Space.xs) {
            StatusDot(color: color, size: 7)
            Text(status.displayName).font(Theme.Font.monoMicro).foregroundStyle(Theme.textSecondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Status: \(status.displayName)")
    }
}

// MARK: - Level chip (read / edit / admin)

struct LevelChip: View {
    let level: GrantLevel

    private var tint: Color {
        switch level {
        case .read:  return Theme.textTertiary
        case .edit:  return Theme.accent
        case .admin: return Theme.Status.busy
        }
    }

    var body: some View {
        Text(level.displayName.uppercased())
            .font(Theme.Font.monoMicro.weight(.semibold)).tracking(0.4)
            .foregroundStyle(tint)
            .padding(.horizontal, Theme.Space.sm)
            .padding(.vertical, Theme.Space.xxs)
            .background(tint.opacity(0.14), in: Capsule())
            .overlay(Capsule().strokeBorder(tint.opacity(0.30), lineWidth: 0.5))
            .help(level.explanation)
            .accessibilityLabel("Access level: \(level.displayName)")
    }
}

// MARK: - Avatar bubble

struct MemberAvatar: View {
    let member: OrgMember

    var body: some View {
        ZStack {
            Circle().fill(Theme.surfaceInset)
                .overlay(Circle().strokeBorder(Theme.border, lineWidth: 0.5))
            if member.isServiceAccount {
                Image(systemName: IconSet.serviceAccount)
                    .font(Theme.Font.monoMicro).foregroundStyle(Theme.textSecondary)
            } else {
                Text(member.initials).font(Theme.Font.monoMicro.weight(.semibold))
                    .foregroundStyle(Theme.textSecondary)
            }
        }
        .frame(width: Theme.Metric.avatar, height: Theme.Metric.avatar)
        .accessibilityHidden(true)
    }
}

// MARK: - Member row

struct MemberRow: View {
    let member: OrgMember
    let canMutate: Bool
    let assignableRoles: [OrgRole]
    let isBusy: Bool
    let onChangeRole: (OrgRole) -> Void
    let onSuspend: () -> Void
    let onReactivate: () -> Void
    let onDeprovision: () -> Void

    var body: some View {
        HStack(spacing: Theme.Space.lg) {
            MemberAvatar(member: member)

            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                HStack(spacing: Theme.Space.sm) {
                    Text(member.displayName)
                        .font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                        .lineLimit(1).truncationMode(.tail)
                    if member.isServiceAccount {
                        Text("Service")
                            .font(Theme.Font.monoMicro).foregroundStyle(Theme.textTertiary)
                            .padding(.horizontal, Theme.Space.xs).padding(.vertical, 1)
                            .background(Theme.surfaceInset, in: Capsule())
                    }
                }
                Text(member.email)
                    .font(Theme.Font.monoPath).foregroundStyle(Theme.textTertiary)
                    .lineLimit(1).truncationMode(.middle).help(member.email)
            }

            Spacer(minLength: Theme.Space.md)

            RoleChip(role: member.role)
            StatusBadge(status: member.status)
                .frame(width: 110, alignment: .leading)

            actions
        }
        .padding(.vertical, Theme.Space.md)
        .opacity(isBusy ? 0.5 : 1)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(member.displayName), \(member.role.displayName), \(member.status.displayName)")
    }

    @ViewBuilder private var actions: some View {
        if isBusy {
            ProgressView().controlSize(.small).frame(width: 28)
        } else if canMutate {
            Menu {
                // Change role — only roles the caller may assign.
                if !assignableRoles.isEmpty {
                    Menu("Change Role") {
                        ForEach(assignableRoles) { role in
                            Button {
                                onChangeRole(role)
                            } label: {
                                Label(role.displayName,
                                      systemImage: role == member.role ? IconSet.copied : IconSet.changeRole)
                            }
                            .disabled(role == member.role)
                        }
                    }
                }
                Divider()
                switch member.status {
                case .active:
                    Button { onSuspend() } label: { Label("Suspend", systemImage: IconSet.suspend) }
                    Button(role: .destructive) { onDeprovision() } label: {
                        Label("Deprovision", systemImage: IconSet.deprovision)
                    }
                case .suspended:
                    Button { onReactivate() } label: { Label("Reactivate", systemImage: IconSet.reactivate) }
                    Button(role: .destructive) { onDeprovision() } label: {
                        Label("Deprovision", systemImage: IconSet.deprovision)
                    }
                case .deprovisioned:
                    Button { onReactivate() } label: { Label("Reactivate", systemImage: IconSet.reactivate) }
                }
            } label: {
                Icon(IconSet.rowActions, role: .action).foregroundStyle(Theme.textSecondary)
            }
            .menuStyle(.borderlessButton)
            .frame(width: 28, alignment: .trailing)
            .fixedSize()
            .help("Member actions")
            .accessibilityLabel("Actions for \(member.displayName)")
        } else {
            Color.clear.frame(width: 28)
        }
    }
}

// MARK: - Grant row

struct GrantRow: View {
    let grant: AccessGrant
    let canMutate: Bool
    let isBusy: Bool
    let onEdit: () -> Void
    let onRemove: () -> Void

    private var principalSymbol: String {
        switch grant.principalType {
        case .user:           return IconSet.account
        case .group:          return IconSet.group
        case .serviceAccount: return IconSet.serviceAccount
        }
    }

    var body: some View {
        HStack(spacing: Theme.Space.lg) {
            Image(systemName: principalSymbol)
                .font(Theme.IconRole.rowLeading.font)
                .foregroundStyle(Theme.textTertiary)
                .frame(width: Theme.Metric.leadingIconWidth)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                HStack(spacing: Theme.Space.sm) {
                    Text(grant.principalLabel)
                        .font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                        .lineLimit(1).truncationMode(.tail)
                    if grant.mountAsRoot {
                        Image(systemName: IconSet.mountRoot)
                            .font(Theme.Font.monoMicro).foregroundStyle(Theme.accent)
                            .help("Mounted as root — confined to this subtree")
                    }
                    if grant.active == false {
                        Text("Inactive delegation").font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
                    } else if grant.isExpired() {
                        Text("Expired").font(Theme.Font.monoMicro).foregroundStyle(Theme.Status.error)
                    } else if let exp = grant.expiresAt {
                        HStack(spacing: 2) {
                            Image(systemName: IconSet.expires).font(Theme.Font.monoMicro)
                            Text(exp.formatted(date: .abbreviated, time: .omitted)).font(Theme.Font.monoMicro)
                        }
                        .foregroundStyle(Theme.textTertiary)
                        .help("Access expires \(exp.formatted(date: .long, time: .omitted))")
                    }
                }
                HStack(spacing: Theme.Space.xs) {
                    Image(systemName: IconSet.folder).font(Theme.Font.monoMicro)
                    Text(grant.inodePath)
                        .font(Theme.Font.monoPath).lineLimit(1).truncationMode(.middle)
                }
                .foregroundStyle(Theme.textTertiary).help(grant.inodePath)
            }

            Spacer(minLength: Theme.Space.md)

            Text(grant.principalType.displayName)
                .font(Theme.Font.monoMicro).foregroundStyle(Theme.textTertiary)
                .frame(width: 90, alignment: .leading)
            LevelChip(level: grant.level)

            actions
        }
        .padding(.vertical, Theme.Space.md)
        .opacity(isBusy ? 0.5 : 1)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(grant.principalLabel) has \(grant.level.displayName) on \(grant.inodePath)")
    }

    @ViewBuilder private var actions: some View {
        if isBusy {
            ProgressView().controlSize(.small).frame(width: 56)
        } else if canMutate {
            HStack(spacing: Theme.Space.sm) {
                IconButton(IconSet.rename, label: "Edit grant", action: onEdit)
                IconButton(IconSet.removeGrant, label: "Remove access for \(grant.principalLabel)",
                           tint: Theme.Status.error, action: onRemove)
            }
            .frame(width: 56, alignment: .trailing)
        } else {
            Color.clear.frame(width: 56)
        }
    }
}

// MARK: - Invite sheet

struct InviteSheet: View {
    let assignableRoles: [OrgRole]
    let onSubmit: (InviteRequest) async -> Bool

    @Environment(AppModel.self) private var model
    @State private var submitting = false
    @Environment(\.dismiss) private var dismiss
    @State private var email = ""
    @State private var role: OrgRole = .standard

    private var request: InviteRequest { InviteRequest(email: email, role: role) }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.xl) {
            Text("Invite a member").font(Theme.Font.title).foregroundStyle(Theme.textPrimary)

            VStack(alignment: .leading, spacing: Theme.Space.md) {
                SectionLabel("Email")
                TextField("name@company.com", text: $email)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: .infinity)

                SectionLabel("Role")
                Picker("Role", selection: $role) {
                    ForEach(assignableRoles) { r in Text(r.displayName).tag(r) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                Text(role.explanation).font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
            }

            if let error = model.members.mutationError {
                Text(error).font(Theme.Font.caption).foregroundStyle(Theme.Status.error)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.cfButton(.secondary).disabled(submitting)
                Button(submitting ? "Creating invite…" : "Create invite") {
                    submitting = true
                    Task { if await onSubmit(request) { dismiss() }; submitting = false }
                }
                .cfButton(.primary)
                .disabled(!request.isValid || submitting)
            }
        }
        .padding(Theme.Space.xxl)
        .frame(width: 460)
        .background(Theme.bg)
        .onAppear { if let first = assignableRoles.first(where: { $0 == .standard }) ?? assignableRoles.last { role = first } }
    }
}

// MARK: - Grant editor sheet (add / edit a folder ACL grant)

struct GrantEditorSheet: View {
    struct Folder: Identifiable, Hashable { let inodeId: String; let path: String; var id: String { inodeId } }

    let existing: AccessGrant?
    let members: [OrgMember]
    let groups: [MemberGroup]
    let folders: [Folder]
    let onSubmit: (GrantRequest) async -> Bool

    @Environment(AppModel.self) private var model
    @State private var submitting = false
    @Environment(\.dismiss) private var dismiss

    @State private var principalType: PrincipalType = .user
    @State private var principalId = ""
    @State private var inodeId = ""
    @State private var inodePath = ""
    @State private var level: GrantLevel = .read
    @State private var mountAsRoot = false

    init(existing: AccessGrant?, members: [OrgMember], groups: [MemberGroup], folders: [Folder],
         onSubmit: @escaping (GrantRequest) async -> Bool) {
        self.existing = existing
        self.members = members
        self.groups = groups
        self.folders = folders
        self.onSubmit = onSubmit
        _principalType = State(initialValue: existing?.principalType ?? .user)
        _principalId = State(initialValue: existing?.principalId ?? "")
        _inodeId = State(initialValue: existing?.inodeId ?? "")
        _inodePath = State(initialValue: existing?.inodePath ?? "")
        _level = State(initialValue: existing?.level ?? .read)
        _mountAsRoot = State(initialValue: existing?.mountAsRoot ?? false)
    }

    private var isEditing: Bool { existing != nil }

    /// The selectable principals for the chosen type (user/service vs group).
    private var principalOptions: [(id: String, label: String)] {
        switch principalType {
        case .group:
            return groups.map { ($0.id, $0.name) }
        case .user:
            return members.filter { !$0.isServiceAccount }.map { ($0.id, "\($0.displayName) · \($0.email)") }
        case .serviceAccount:
            return members.filter { $0.isServiceAccount }.map { ($0.id, $0.displayName) }
        }
    }

    private var principalLabel: String {
        principalOptions.first { $0.id == principalId }?.label ?? principalId
    }

    private var request: GrantRequest {
        GrantRequest(inodeId: inodeId, inodePath: inodePath.isEmpty ? inodeId : inodePath,
                     principalType: principalType, principalId: principalId,
                     principalLabel: principalLabel, level: level, mountAsRoot: mountAsRoot, expiresAt: existing?.expiresAt)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.xl) {
            Text(isEditing ? "Edit access" : "Grant access")
                .font(Theme.Font.title).foregroundStyle(Theme.textPrimary)

            VStack(alignment: .leading, spacing: Theme.Space.lg) {
                // Principal type
                VStack(alignment: .leading, spacing: Theme.Space.sm) {
                    SectionLabel("Who can access")
                    Picker("Type", selection: $principalType) {
                        ForEach(PrincipalType.allCases, id: \.self) { t in
                            Text(t.displayName).tag(t)
                        }
                    }
                    .pickerStyle(.segmented).labelsHidden()
                    .disabled(isEditing)   // changing principal on an existing grant = a new grant

                    if principalOptions.isEmpty {
                        Text("No members available for this type.").font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                    } else {
                        Picker("Principal", selection: $principalId) {
                            Text("Choose…").tag("")
                            ForEach(principalOptions, id: \.id) { opt in
                                Text(opt.label).tag(opt.id)
                            }
                        }
                        .labelsHidden()
                        .disabled(isEditing)
                    }
                }

                VStack(alignment: .leading, spacing: Theme.Space.sm) {
                    SectionLabel("Folder")
                    if isEditing {
                        Label(inodePath, systemImage: "folder").font(Theme.Font.body)
                    } else {
                        FolderAccessPicker(inodeId: $inodeId, inodePath: $inodePath)
                    }
                }

                // Level
                VStack(alignment: .leading, spacing: Theme.Space.sm) {
                    SectionLabel("Access level")
                    Picker("Level", selection: $level) {
                        ForEach(model.members.administration.grantableLevels) { l in
                            Text(l.displayName).tag(l)
                        }
                    }
                    .pickerStyle(.segmented).labelsHidden()
                    Text(level == .admin
                         ? "Read and edit this folder and manage its members’ read or edit access. Does not grant a workspace role or permission to appoint other folder admins."
                         : level.explanation)
                        .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Toggle(isOn: $mountAsRoot) {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Show only this folder").font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                        Text("This folder becomes the top level of their filespace.")
                            .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                    }
                }
                .toggleStyle(.switch).tint(Theme.accent)
            }

            if let error = model.members.mutationError {
                Text(error).font(Theme.Font.caption).foregroundStyle(Theme.Status.error)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.cfButton(.secondary).disabled(submitting)
                Button(submitting ? "Saving…" : (isEditing ? "Save" : "Grant access")) {
                    submitting = true
                    Task { if await onSubmit(request) { dismiss() }; submitting = false }
                }
                .cfButton(.primary)
                .disabled(!request.isValid || submitting)
            }
        }
        .padding(Theme.Space.xxl)
        .frame(width: 500)
        .background(Theme.bg)
    }
}

// MARK: - Previews

#Preview("Members — directory") {
    let model = AppModel(gateway: MockGatewayClient())
    return MembersView()
        .environment(model)
        .frame(width: 860, height: 620)
        .task {
            model.members.currentRole = .admin
            await model.loadMembers()
            await model.loadGrants()
        }
}
