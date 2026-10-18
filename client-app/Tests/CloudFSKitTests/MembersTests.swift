// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Pure logic behind the Members & Access view: the org-role admin gate + role-
// assignment ladder (no privilege escalation), the per-folder ACL grant level
// ladder (read < edit < admin), the directory + access summaries/sorts, invite
// validation, and grant expiry — plus the offline fixtures that drive the Mock.
// No SwiftUI — the MembersView renders whatever these compute.

@Suite(.timeLimit(.minutes(1)))
struct MembersTests {

    // MARK: Org role — wire values + ladder

    @Test func orgRoleWireValuesMatchBackend() {
        // Must match permissions.ts OrgRole exactly (owner|admin|space_admin|standard).
        #expect(OrgRole.owner.rawValue == "owner")
        #expect(OrgRole.admin.rawValue == "admin")
        #expect(OrgRole.spaceAdmin.rawValue == "space_admin")
        #expect(OrgRole.standard.rawValue == "standard")
    }

    @Test func orgRoleIsOrderedByPrivilege() {
        #expect(OrgRole.owner > OrgRole.admin)
        #expect(OrgRole.admin > OrgRole.spaceAdmin)
        #expect(OrgRole.spaceAdmin > OrgRole.standard)
    }

    // MARK: Admin gating (the nav + view policy)

    @Test func onlyAdminsCanManageMembers() {
        #expect(OrgRole.owner.canManageMembers)
        #expect(OrgRole.admin.canManageMembers)
        #expect(!OrgRole.spaceAdmin.canManageMembers)
        #expect(!OrgRole.standard.canManageMembers)
        #expect(OrgRole.owner.canMutateMembers)
        #expect(OrgRole.admin.canMutateMembers)
        #expect(!OrgRole.spaceAdmin.canMutateMembers)
        #expect(!OrgRole.standard.canMutateMembers)
    }

    // MARK: Role-assignment ladder (no privilege escalation)

    @Test func cannotAssignAboveYourOwnRole() {
        // Admin may not mint an owner; space_admin may not mint admin/owner.
        #expect(!OrgRole.admin.canAssign(.owner))
        #expect(!OrgRole.spaceAdmin.canAssign(.admin))
        #expect(!OrgRole.spaceAdmin.canAssign(.owner))
        // …but may assign at or below their level.
        #expect(OrgRole.admin.canAssign(.admin))
        #expect(OrgRole.admin.canAssign(.standard))
        #expect(!OrgRole.spaceAdmin.canAssign(.spaceAdmin))
    }

    @Test func onlyOwnerCanMintAnotherOwner() {
        #expect(OrgRole.owner.canAssign(.owner))
        #expect(!OrgRole.admin.canAssign(.owner))
        #expect(!OrgRole.spaceAdmin.canAssign(.owner))
        #expect(!OrgRole.standard.canAssign(.owner))
    }

    @Test func standardUserCanAssignNothing() {
        #expect(OrgRole.standard.assignableRoles().isEmpty)
    }

    @Test func assignableRolesNeverExceedCallerRank() {
        for caller in OrgRole.allCases {
            for assignable in caller.assignableRoles() {
                #expect(assignable.rank <= caller.rank,
                        "\(caller) must not assign higher \(assignable)")
            }
        }
    }

    // MARK: Member status

    @Test func memberStatusWireValuesAndActiveFlag() {
        // Mirrors org-do.ts UserStatus.
        #expect(MemberStatus.active.rawValue == "active")
        #expect(MemberStatus.suspended.rawValue == "suspended")
        #expect(MemberStatus.deprovisioned.rawValue == "deprovisioned")
        #expect(MemberStatus.active.isActive)
        #expect(!MemberStatus.suspended.isActive)
        #expect(!MemberStatus.deprovisioned.isActive)
    }

    // MARK: Member projections

    @Test func memberInitialsFromName() {
        #expect(OrgMember(id: "1", email: "a@b.c", displayName: "Mara Patel",
                          role: .admin, status: .active).initials == "MP")
        #expect(OrgMember(id: "2", email: "x@y.z", displayName: "Casey",
                          role: .owner, status: .active).initials == "C")
        // Falls back to the email's first letter when no name letters exist.
        #expect(OrgMember(id: "3", email: "render@svc", displayName: "",
                          role: .standard, status: .active).initials == "R")
    }

    @Test func directorySortPutsActiveAdminsFirst() {
        let m = [
            OrgMember(id: "s", email: "s@x", displayName: "Suspended Admin", role: .admin, status: .suspended),
            OrgMember(id: "a", email: "a@x", displayName: "Active Standard", role: .standard, status: .active),
            OrgMember(id: "o", email: "o@x", displayName: "Owner", role: .owner, status: .active),
            OrgMember(id: "d", email: "d@x", displayName: "Gone", role: .standard, status: .deprovisioned),
        ]
        let order = m.sortedForDirectory().map(\.id)
        // active before non-active; within active, owner (rank 3) before standard.
        #expect(order.first == "o")
        #expect(order[1] == "a")
        // suspended + deprovisioned sink below all active rows.
        #expect(Set(order.suffix(2)) == ["s", "d"])
    }

    // MARK: MembersSummary rollup

    @Test func summaryCountsRolesStatusesAndServiceAccounts() {
        let s = MembersSummary(members: OrgMember.fixtures())
        #expect(s.total == 8)
        // owner + admin + space_admin = 3 admins.
        #expect(s.adminCount == 3)
        #expect(s.suspendedCount == 1)
        #expect(s.deprovisionedCount == 1)
        #expect(s.serviceAccountCount == 1)
        #expect(!s.isEmpty)
    }

    @Test func emptySummaryIsZeroAndEmpty() {
        let s = MembersSummary(members: [])
        #expect(s.isEmpty)
        #expect(s.total == 0)
        #expect(s.adminCount == 0)
    }

    // MARK: Grant level ladder (permissions.ts read < edit < admin)

    @Test func grantLevelLadderMatchesBackendRanks() {
        // permissions.ts LEVEL_RANK = { read: 1, edit: 2, admin: 3 }.
        #expect(GrantLevel.read.rank == 1)
        #expect(GrantLevel.edit.rank == 2)
        #expect(GrantLevel.admin.rank == 3)
        #expect(GrantLevel.read < GrantLevel.edit)
        #expect(GrantLevel.edit < GrantLevel.admin)
    }

    @Test func grantLevelWireValues() {
        #expect(GrantLevel.read.rawValue == "read")
        #expect(GrantLevel.edit.rawValue == "edit")
        #expect(GrantLevel.admin.rawValue == "admin")
    }

    @Test func principalTypeWireValues() {
        // permissions.ts PrincipalType = user | group | service_account.
        #expect(PrincipalType.user.rawValue == "user")
        #expect(PrincipalType.group.rawValue == "group")
        #expect(PrincipalType.serviceAccount.rawValue == "service_account")
    }

    // MARK: Grant expiry + sort

    @Test func grantExpiryIsHonored() {
        let past = AccessGrant(id: "g", inodeId: "i", inodePath: "p", principalType: .user,
                               principalId: "u", principalLabel: "U", level: .read,
                               expiresAt: Date().addingTimeInterval(-3600))
        let future = AccessGrant(id: "g2", inodeId: "i", inodePath: "p", principalType: .user,
                                 principalId: "u", principalLabel: "U", level: .read,
                                 expiresAt: Date().addingTimeInterval(3600))
        let perm = AccessGrant(id: "g3", inodeId: "i", inodePath: "p", principalType: .user,
                               principalId: "u", principalLabel: "U", level: .read)
        #expect(past.isExpired())
        #expect(!future.isExpired())
        #expect(!perm.isExpired())   // nil expiresAt == permanent
    }

    @Test func accessEditorSortsByFolderThenLevel() {
        let grants = [
            AccessGrant(id: "1", inodeId: "b", inodePath: "Beta", principalType: .user,
                        principalId: "u1", principalLabel: "Z", level: .read),
            AccessGrant(id: "2", inodeId: "a", inodePath: "Alpha", principalType: .user,
                        principalId: "u2", principalLabel: "B", level: .read),
            AccessGrant(id: "3", inodeId: "a", inodePath: "Alpha", principalType: .group,
                        principalId: "g1", principalLabel: "A", level: .admin),
        ]
        let order = grants.sortedForAccessEditor().map(\.id)
        // Alpha folder first; within Alpha, admin (rank 3) before read.
        #expect(order == ["3", "2", "1"])
    }

    // MARK: Invite validation

    @Test func inviteEmailIsNormalizedAndValidated() {
        let good = InviteRequest(email: "  Mara@Acme.TV ", role: .standard)
        #expect(good.normalizedEmail == "mara@acme.tv")
        #expect(good.isValid)

        #expect(!InviteRequest(email: "", role: .standard).isValid)
        #expect(!InviteRequest(email: "no-at-sign", role: .standard).isValid)
        #expect(!InviteRequest(email: "@nodomain.com", role: .standard).isValid)
        #expect(!InviteRequest(email: "user@nodot", role: .standard).isValid)
        #expect(!InviteRequest(email: "user@trailing.", role: .standard).isValid)
    }

    @Test func grantRequestValidity() {
        #expect(GrantRequest(inodeId: "i", inodePath: "p", principalType: .user,
                             principalId: "u", principalLabel: "U", level: .read).isValid)
        #expect(!GrantRequest(inodeId: "", inodePath: "p", principalType: .user,
                              principalId: "u", principalLabel: "U", level: .read).isValid)
        #expect(!GrantRequest(inodeId: "i", inodePath: "p", principalType: .user,
                              principalId: "  ", principalLabel: "U", level: .read).isValid)
    }

    // MARK: Offline fixtures (Mock / no-backend fallback)

    @Test func memberFixturesSpanEveryRoleAndStatus() {
        let members = OrgMember.fixtures()
        #expect(Set(members.map(\.role)) == Set(OrgRole.allCases))
        #expect(Set(members.map(\.status)) == Set(MemberStatus.allCases))
        // At least one service account for the Access editor's service principal.
        #expect(members.contains { $0.isServiceAccount })
    }

    @Test func grantFixturesSpanTheLadderAndPrincipalKinds() {
        let grants = AccessGrant.fixtures()
        #expect(Set(grants.map(\.level)) == [.read, .edit, .admin])
        #expect(grants.contains { $0.principalType == .group })
        #expect(grants.contains { $0.principalType == .user })
        #expect(grants.contains { $0.mountAsRoot })       // a RootPoint grant
        #expect(grants.contains { $0.expiresAt != nil })  // an expiring grant
    }
}

// MARK: - Mock seam (Members & Access through the GatewayClient)

@Suite(.timeLimit(.minutes(1)))
struct MockMembersSeamTests {

    @Test func currentRoleDefaultsToAdminForOfflineDemo() async throws {
        // The Mock reports admin so the section is visible + editable offline.
        let client = MockGatewayClient()
        #expect(try await client.currentUserRole() == .admin)
    }

    @Test func listMembersAndGroupsReturnFixtures() async throws {
        let client = MockGatewayClient()
        let members = try await client.listMembers()
        let groups = try await client.listGroups()
        #expect(members.count == 8)
        #expect(groups.count == 3)
    }

    @Test func setRoleSuspendReactivateDeprovisionMutateDirectory() async throws {
        let client = MockGatewayClient()
        let target = try await client.listMembers().first { $0.role == .standard && $0.status == .active }!

        try await client.setRole(.spaceAdmin, forMember: target.id)
        #expect(try await client.listMembers().first { $0.id == target.id }?.role == .spaceAdmin)

        try await client.suspendMember(target.id)
        #expect(try await client.listMembers().first { $0.id == target.id }?.status == .suspended)

        try await client.reactivateMember(target.id)
        #expect(try await client.listMembers().first { $0.id == target.id }?.status == .active)

        try await client.deprovisionMember(target.id)
        #expect(try await client.listMembers().first { $0.id == target.id }?.status == .deprovisioned)
    }

    @Test func inviteAddsAPendingMember() async throws {
        let client = MockGatewayClient()
        let before = try await client.listMembers().count
        let result = try await client.invite(InviteRequest(email: "newbie@acme.tv", role: .standard))
        #expect(result.email == "newbie@acme.tv")
        #expect(!result.rawToken.isEmpty)            // the one-time token is surfaced
        #expect(try await client.listMembers().count == before + 1)
    }

    @Test func grantLifecycleAddUpdateRemove() async throws {
        let client = MockGatewayClient()
        let fs = "fs-studio-a"
        let before = try await client.listGrants(in: fs).count

        // Add a new grant.
        let added = try await client.setGrant(
            GrantRequest(inodeId: "a-proxies", inodePath: "Proxies", principalType: .user,
                         principalId: "usr-ed2", principalLabel: "Jules Tan", level: .read), in: fs)
        #expect(try await client.listGrants(in: fs).count == before + 1)
        #expect(added.level == .read)

        // Re-grant the same (inode, principal) upserts the level in place (no dupe).
        let updated = try await client.setGrant(
            GrantRequest(inodeId: "a-proxies", inodePath: "Proxies", principalType: .user,
                         principalId: "usr-ed2", principalLabel: "Jules Tan", level: .edit), in: fs)
        #expect(try await client.listGrants(in: fs).count == before + 1)   // still +1, not +2
        #expect(updated.level == .edit)

        // Remove it.
        try await client.removeGrant(updated, in: fs)
        #expect(try await client.listGrants(in: fs).count == before)
    }
}
