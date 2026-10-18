// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import Observation
import CloudFSKit

// Members and Groups use workspace roles. Folder access uses live capabilities
// returned by the gateway, so delegated standard members can manage their scope
// without gaining workspace-account or group-membership controls.

@MainActor
@Observable
final class MembersFeatureModel {
    /// The signed-in caller's org role. Defaults to `.standard` (fail closed: the
    /// Members section stays hidden until `currentUserRole()` resolves it higher).
    var currentRole: OrgRole = .standard

    /// Org directory + its load state (EMPTY / LOADING / ERROR presentation).
    var members: [OrgMember] = []
    var membersState: LoadState<[OrgMember]> = .idle

    /// Directory groups (grant targets in the Access editor).
    var groups: [MemberGroup] = []
    var groupsState: LoadState<[MemberGroup]> = .idle
    var groupMemberships: [String: LoadState<[String]>] = [:]
    var selectedGroupID: String?
    var busyGroupIDs: Set<String> = []
    var isCreatingGroup = false
    var showCreateGroup = false
    var groupsLoadGeneration = UUID()

    /// The active filespace's ACL grants + load state.
    var administration = FolderAdministration()
    var administrationFilespaceID: String?
    var administrationSessionID: UUID?
    var grantsLoadGeneration = UUID()
    var grantMembers: [OrgMember] = []
    var grantGroups: [MemberGroup] = []
    var grants: [AccessGrant] = []
    var grantsState: LoadState<[AccessGrant]> = .idle

    /// Member ids with a mutation in flight (disables that row's actions).
    var busyMemberIDs: Set<String> = []
    /// Grant ids with a mutation in flight.
    var busyGrantIDs: Set<String> = []

    /// The most-recent invite result — surfaced once so the admin can copy the
    /// raw token before it is lost (it is never recoverable later).
    var lastInvite: InviteResult?
    var mutationError: String?
    var knownFolderPaths: [String: String] = [:]

    /// Which sub-surface the Members pane is showing.
    var tab: Tab = .members
    enum Tab: String, CaseIterable, Identifiable { case members = "Members", groups = "Groups", access = "Access"
        var id: String { rawValue } }

    /// Directory rollup powering the summary strip.
    var summary: MembersSummary { MembersSummary(members: members) }

    /// Whether the caller may mutate the directory / ACLs (vs read-only).
    var canMutate: Bool { currentRole.canMutateMembers }

    init() {}
}

extension AppModel {

    /// True when the signed-in caller may SEE the Members & Access section. Drives
    /// the sidebar item's visibility + the route gate. Owner/admin/space_admin only.
    var canManageMembers: Bool { isSignedIn && (members.currentRole.canManageMembers || canManageFolderAccess) }
    var canManageFolderAccess: Bool { isSignedIn && members.administrationFilespaceID == selectedFilespaceID && members.administrationSessionID == navigationRequestID && members.administration.canManageAccess }

    /// True when the signed-in caller may create a NEW filespace (sidebar "+" /
    /// the workspace-overflow "Create filespace…"). Narrower than
    /// `canManageMembers` — see `OrgRole.canCreateFilespaces` for why
    /// space_admin is excluded here but not from the Members gate.
    var canCreateFilespaces: Bool { isSignedIn && members.currentRole.canCreateFilespaces }
    var canInviteMembers: Bool { isSignedIn && members.currentRole.canMutateMembers }
    var canManageGuestLinks: Bool { isSignedIn && members.currentRole.canManageGuestLinks }
    var canManageFilespaceSettings: Bool { isSignedIn && members.currentRole.canManageFilespaceSettings }
    var canManageSnapshotSchedules: Bool { isSignedIn && members.currentRole.canManageSnapshotSchedules }
    var canReadWorkspaceActivity: Bool { isSignedIn && members.currentRole.canReadWorkspaceActivity }

    func canAccess(_ section: NavSection) -> Bool {
        guard isSignedIn else { return false }
        switch section {
        case .members: return canManageMembers
        case .sharing: return canManageGuestLinks
        case .audit: return canReadWorkspaceActivity
        default: return true
        }
    }

    /// Resolve the caller's org role from the gateway (GET /v1/auth/me). Called on
    /// sign-in / bootstrap so the nav gate is correct before the user opens Members.
    func loadCurrentUserRole() async {
        members.administration = FolderAdministration()
        members.administrationFilespaceID = nil
        let session = navigationRequestID
        let role = (try? await gateway.currentUserRole()) ?? .standard
        guard isSignedIn, navigationRequestID == session else { return }
        members.currentRole = role
        if !canInviteMembers { members.members = []; members.groups = []; members.lastInvite = nil }
        if !canManageGuestLinks { shareLinks = []; shareLinksState = .loaded([]) }
        if !canReadWorkspaceActivity {
            recentActivity = []; activityState = .loaded([])
            liveLog.live = LiveActivity(transfers: [], events: []); liveLog.auditEvents = []
            liveLog.liveState = .idle; liveLog.auditState = .loaded([])
        }
        if !canCreateFilespaces { isCreatingFilespace = false }
        await loadGrants()
        if !canAccess(section) { section = .dashboard }
    }

    /// Load the org directory + groups for the Members tab. Folds the directory
    /// into `members.membersState`/`members.members` (sorted for display).
    func loadMembers() async {
        guard members.currentRole.canManageMembers else {
            members.members = []; members.groups = []; members.tab = .access
            await loadGrants()
            return
        }
        members.membersState = .loading
        do {
            let dir = try await gateway.listMembers()
            guard canInviteMembers else { return }
            members.members = dir.sortedForDirectory()
            members.membersState = .loaded(members.members)
        } catch {
            members.members = []
            members.membersState = .failed(error.localizedDescription)
        }
        await loadGroups()
    }

    /// Load the active filespace's per-folder ACL grants for the Access tab.
    func loadGrants() async {
        let generation = UUID(), session = navigationRequestID
        members.grantsLoadGeneration = generation
        if members.administrationFilespaceID != selectedFilespaceID || members.administrationSessionID != session {
            members.administration = FolderAdministration()
            members.administrationFilespaceID = nil
        }
        members.grantMembers = []; members.grantGroups = []
        members.grants = []
        guard isSignedIn, let id = selectedFilespaceID else {
            members.grantsState = .loaded([]); return
        }
        members.grantsState = .loading
        do {
            let administration = try await gateway.accessManagement(in: id)
            guard selectedFilespaceID == id, isSignedIn, navigationRequestID == session,
                  members.grantsLoadGeneration == generation else { return }
            members.administration = administration
            members.administrationFilespaceID = id
            members.administrationSessionID = session
            members.grantMembers = administration.members
            members.grantGroups = administration.groups
            members.grants = administration.grants.map { grant in
                var resolved = grant
                if let user = administration.members.first(where: { $0.id == grant.principalId }) {
                    resolved.principalLabel = user.displayName
                } else if let group = administration.groups.first(where: { $0.id == grant.principalId }) {
                    resolved.principalLabel = group.name
                }
                return resolved
            }.sortedForAccessEditor()
            if !members.currentRole.canManageMembers { members.tab = .access }
            members.grantsState = .loaded(members.grants)
        } catch {
            guard selectedFilespaceID == id, navigationRequestID == session,
                  members.grantsLoadGeneration == generation else { return }
            members.administration = FolderAdministration()
            members.administrationFilespaceID = nil
            members.grantsState = .failed(error.localizedDescription)
        }
    }

    // MARK: Directory mutations (admin only)

    /// Invite a new user. Stashes the result so the view can surface the raw token
    /// once, then reloads the directory.
    @discardableResult
    func inviteMember(_ request: InviteRequest) async -> Bool {
        guard members.canMutate else { return false }
        members.mutationError = nil
        do {
            members.lastInvite = try await gateway.invite(request)
            await loadMembers()
            return true
        } catch {
            members.mutationError = error.localizedDescription
            return false
        }
    }

    func changeRole(_ role: OrgRole, for member: OrgMember) async {
        await mutateMember(member) { await self.guarded { try await self.gateway.setRole(role, forMember: member.id) } }
    }

    func suspendMember(_ member: OrgMember) async {
        await mutateMember(member) { await self.guarded { try await self.gateway.suspendMember(member.id) } }
    }

    func reactivateMember(_ member: OrgMember) async {
        await mutateMember(member) { await self.guarded { try await self.gateway.reactivateMember(member.id) } }
    }

    func deprovisionMember(_ member: OrgMember) async {
        await mutateMember(member) { await self.guarded { try await self.gateway.deprovisionMember(member.id) } }
    }

    /// Shared directory-mutation wrapper: gate on admin, flag the row busy, run the
    /// op, then reload + clear busy. Always clears the flag.
    private func mutateMember(_ member: OrgMember, _ op: @MainActor () async -> Void) async {
        guard members.canMutate else { return }
        members.busyMemberIDs.insert(member.id)
        await op()
        await loadMembers()
        members.busyMemberIDs.remove(member.id)
    }

    // MARK: Grant mutations (admin only)

    /// Add or update a per-folder ACL grant, then reload.
    @discardableResult
    func setGrant(_ request: GrantRequest) async -> Bool {
        guard canManageFolderAccess, members.administration.grantableLevels.contains(request.level), let id = selectedFilespaceID else { return false }
        members.mutationError = nil
        do {
            _ = try await gateway.setGrant(request, in: id)
            members.knownFolderPaths["\(id):\(request.inodeId)"] = request.inodePath
            await loadGrants()
            return true
        } catch {
            members.mutationError = error.localizedDescription
            return false
        }
    }

    /// Revoke a grant (remove a principal's access on the inode), then reload.
    func removeGrant(_ grant: AccessGrant) async {
        guard canManageFolderAccess, members.administration.canModify(grant), let id = selectedFilespaceID else { return }
        members.busyGrantIDs.insert(grant.id)
        members.mutationError = nil
        do { try await gateway.removeGrant(grant, in: id) }
        catch { members.mutationError = error.localizedDescription }
        await loadGrants()
        members.busyGrantIDs.remove(grant.id)
    }

    /// Swallow gateway errors for fire-and-forget directory mutations (the reload
    /// after surfaces any state that didn't stick).
    private func guarded(_ op: () async throws -> Void) async {
        members.mutationError = nil
        do { try await op() } catch { members.mutationError = error.localizedDescription }
    }
}
