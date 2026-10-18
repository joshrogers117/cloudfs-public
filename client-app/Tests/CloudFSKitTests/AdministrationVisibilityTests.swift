// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
@testable import CloudFSKit

struct AdministrationVisibilityTests {
    @Test func regularUsersHaveNoWorkspaceAdministration() {
        let role = OrgRole.standard
        #expect(!role.canManageMembers)
        #expect(!role.canCreateFilespaces)
        #expect(!role.canManageFilespaceSettings)
        #expect(!role.canManageGuestLinks)
        #expect(!role.canManageSnapshotSchedules)
        #expect(!role.canReadWorkspaceActivity)
        #expect(role.assignableRoles().isEmpty)
    }

    @Test func filespaceAdministratorsCannotManageWorkspaceAccountsOrSchedules() {
        let role = OrgRole.spaceAdmin
        #expect(role.canManageFilespaceSettings)
        #expect(role.canManageGuestLinks)
        #expect(!role.canManageMembers)
        #expect(!role.canMutateMembers)
        #expect(!role.canCreateFilespaces)
        #expect(!role.canManageSnapshotSchedules)
        #expect(!role.canReadWorkspaceActivity)
        #expect(role.assignableRoles().isEmpty)
    }

    @Test func delegatedFolderAccessDoesNotBecomeWorkspaceAdministration() {
        let delegated = FolderAdministration(canManageAccess: true, canManageWorkspace: false)
        #expect(delegated.canManageAccess)
        #expect(!delegated.canManageWorkspace)
        #expect(!OrgRole.standard.canManageMembers)
        #expect(!OrgRole.standard.canManageGuestLinks)
    }
}
