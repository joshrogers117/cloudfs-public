// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

struct GroupsView: View {
    @Environment(AppModel.self) private var model
    @State private var newGroupName = ""
    @State private var groupToDelete: MemberGroup?
    @FocusState private var nameFocused: Bool
    private var feature: MembersFeatureModel { model.members }
    private var selected: MemberGroup? { feature.groups.first { $0.id == feature.selectedGroupID } }

    var body: some View {
        VStack(spacing: 0) {
            if feature.showCreateGroup { createForm }
            content
        }
        .confirmationDialog("Delete group?", isPresented: Binding(
            get: { groupToDelete != nil }, set: { if !$0 { groupToDelete = nil } }),
                            presenting: groupToDelete) { group in
            Button("Delete \(group.name)", role: .destructive) {
                Task { await model.deleteGroup(group) }
                groupToDelete = nil
            }
            Button("Cancel", role: .cancel) { groupToDelete = nil }
        } message: { group in
            Text("Members lose access provided by \(group.name). Their individual access and other groups stay unchanged.")
        }
    }

    private var createForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Create a group").font(Theme.Font.headline)
            Text("Group members share any folder access you grant to the group.")
                .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            HStack(spacing: 10) {
                TextField("Group name, for example Editorial", text: $newGroupName)
                    .textFieldStyle(.roundedBorder).focused($nameFocused)
                    .onSubmit { create() }
                Button(feature.isCreatingGroup ? "Creating…" : "Create") { create() }
                    .cfButton(.primary)
                    .disabled(newGroupName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || feature.isCreatingGroup)
                Button("Cancel") { feature.showCreateGroup = false; newGroupName = "" }
                    .cfButton(.secondary).disabled(feature.isCreatingGroup)
            }
        }
        .padding(20).background(Theme.surfaceInset)
        .onAppear { nameFocused = true }
    }

    private func create() {
        guard feature.canMutate else { return }
        Task {
            if await model.createGroup(name: newGroupName) {
                newGroupName = ""; feature.showCreateGroup = false
            }
        }
    }

    @ViewBuilder private var content: some View {
        switch feature.groupsState {
        case .idle, .loading:
            LoadingPane(text: "Loading groups…")
        case .failed(let error):
            ErrorPane(message: error) { Task { await model.loadGroups() } }
        case .loaded(let groups):
            if groups.isEmpty {
                EmptyState(symbol: IconSet.group, title: "Bring your team together",
                           hint: feature.canMutate ? "Create a group, add members, then grant the group access to folders." : "Your workspace administrator can create groups and add members.")
            } else {
                HStack(spacing: 0) {
                    groupList(groups).frame(width: 220)
                    Divider().overlay(Theme.divider)
                    if let selected {
                        GroupMembersDetail(group: selected, onDelete: { groupToDelete = selected })
                            .id(selected.id)
                    } else {
                        EmptyState(symbol: IconSet.group, title: "Choose a group", hint: "Select a group to see its members.")
                    }
                }
            }
        }
    }

    private func groupList(_ groups: [MemberGroup]) -> some View {
        ScrollView {
            VStack(spacing: 5) {
                ForEach(groups) { group in
                    Button { feature.selectedGroupID = group.id } label: {
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: IconSet.group).frame(width: 22).padding(.top, 2)
                            VStack(alignment: .leading, spacing: 5) {
                                Text(group.name).font(Theme.Font.body.weight(.medium)).lineLimit(2)
                                Text(groupSummary(group)).font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                            }
                            Spacer(minLength: 0)
                        }
                        .foregroundStyle(Theme.textPrimary).padding(12)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(group.id == feature.selectedGroupID ? Theme.selection : .clear,
                                    in: RoundedRectangle(cornerRadius: 8))
                        .contentShape(Rectangle())
                    }.buttonStyle(.plain)
                        .accessibilityAddTraits(group.id == feature.selectedGroupID ? [.isSelected] : [])
                }
            }.padding(12)
        }.background(Theme.bgSidebar)
    }

    private func groupSummary(_ group: MemberGroup) -> String {
        let suffix = group.source == .scim ? " · Directory managed" : ""
        guard feature.canMutate else { return group.source == .scim ? "Directory managed" : "Workspace group" }
        switch feature.groupMemberships[group.id] {
        case .loaded(let ids): return "\(ids.count) member\(ids.count == 1 ? "" : "s")\(suffix)"
        case .failed: return "Membership unavailable"
        default: return "Loading members…"
        }
    }
}

private struct GroupMembersDetail: View {
    @Environment(AppModel.self) private var model
    let group: MemberGroup
    let onDelete: () -> Void
    @State private var selectedMemberID = ""
    @State private var search = ""
    private var feature: MembersFeatureModel { model.members }
    private var busy: Bool { feature.busyGroupIDs.contains(group.id) }
    private var editable: Bool { group.isEditable(by: feature.currentRole) }
    private var memberIDs: [String] { feature.groupMemberships[group.id]?.value ?? [] }
    private var availableMembers: [OrgMember] {
        feature.members.filter { $0.status == .active && !memberIDs.contains($0.id) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack(alignment: .firstTextBaseline, spacing: 12) {
                    Text(group.name).font(Theme.Font.title).foregroundStyle(Theme.textPrimary)
                    Spacer(minLength: 0)
                    if editable {
                        Button("Delete group", role: .destructive, action: onDelete)
                            .cfButton(.subtle, size: .small).foregroundStyle(Theme.Status.error).disabled(busy)
                    }
                }
                if group.source == .scim {
                    Label("Managed by your identity provider. Update membership there to keep this group in sync.", systemImage: "lock")
                        .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text("Members inherit folder permissions granted to this group.")
                        .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                }
                if !feature.canMutate {
                    Text("Only workspace owners and admins can view or change group membership.")
                        .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                } else {
                    membershipContent
                }
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    @ViewBuilder private var membershipContent: some View {
        switch feature.groupMemberships[group.id] ?? .idle {
        case .idle, .loading:
            InlineLoading(text: "Loading members…")
        case .failed(let error):
            Text(error).font(Theme.Font.caption).foregroundStyle(Theme.Status.error)
            Button("Try again") { Task { await model.loadGroups() } }.cfButton(.secondary)
        case .loaded(let ids):
            if editable {
                addMemberForm
                Divider().overlay(Theme.divider)
            }
            HStack {
                Text("Members (\(ids.count))").font(Theme.Font.headline)
                Spacer()
                if busy { ProgressView().controlSize(.small) }
            }
            if ids.isEmpty {
                Text("No members yet. Add a teammate to share the group’s access.")
                    .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
            } else {
                TextField("Search group members", text: $search).textFieldStyle(.roundedBorder)
                ForEach(filteredIDs(ids), id: \.self) { id in
                    memberRow(id)
                }
            }
        }
    }

    private var addMemberForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Add a member").font(Theme.Font.headline)
            if case .failed(let error) = feature.membersState {
                Text("Member directory unavailable: \(error)").font(Theme.Font.caption).foregroundStyle(Theme.Status.error)
                Button("Reload directory") { Task { await model.loadMembers() } }.cfButton(.secondary)
            } else if availableMembers.isEmpty {
                Text("All active workspace members are already in this group.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            } else {
                HStack(spacing: 8) {
                    Picker("Member", selection: $selectedMemberID) {
                        Text("Choose a member…").tag("")
                        ForEach(availableMembers) { member in
                            Text("\(member.displayName) · \(member.email)").tag(member.id)
                        }
                    }.labelsHidden().frame(maxWidth: .infinity)
                    Button("Add") {
                        let id = selectedMemberID
                        Task {
                            await model.updateGroupMembership(userID: id, group: group, adding: true)
                            if feature.groupMemberships[group.id]?.value?.contains(id) == true { selectedMemberID = "" }
                        }
                    }.cfButton(.primary).disabled(selectedMemberID.isEmpty || busy)
                }.disabled(busy)
            }
        }
    }

    private func filteredIDs(_ ids: [String]) -> [String] {
        ids.filter { id in
            guard !search.isEmpty else { return true }
            let member = feature.members.first { $0.id == id }
            return "\(member?.displayName ?? id) \(member?.email ?? "")".localizedCaseInsensitiveContains(search)
        }
        .sorted { left, right in
            let a = feature.members.first { $0.id == left }?.displayName ?? left
            let b = feature.members.first { $0.id == right }?.displayName ?? right
            return a.localizedCaseInsensitiveCompare(b) == .orderedAscending
        }
    }

    private func memberRow(_ id: String) -> some View {
        let member = feature.members.first { $0.id == id }
        return HStack(spacing: 12) {
            Image(systemName: member?.isServiceAccount == true ? IconSet.serviceAccount : "person.crop.circle")
                .foregroundStyle(Theme.textSecondary)
            VStack(alignment: .leading, spacing: 3) {
                Text(member?.displayName ?? "Unavailable member").font(Theme.Font.body)
                Text(member?.email ?? id).font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                if let member, member.status != .active {
                    Text(member.status.displayName).font(Theme.Font.micro).foregroundStyle(Theme.Status.warn)
                }
            }
            Spacer(minLength: 0)
            if editable {
                Button("Remove") {
                    Task { await model.updateGroupMembership(userID: id, group: group, adding: false) }
                }.cfButton(.secondary, size: .small).disabled(busy)
                    .accessibilityLabel("Remove \(member?.displayName ?? id) from \(group.name)")
            }
        }
        .padding(.vertical, 5)
    }
}
