// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
@testable import CloudFSKit

@Suite struct GroupManagementTests {
    @Test func onlyWorkspaceAdminsEditManualGroups() {
        let manual = MemberGroup(id: "manual", name: "Editorial")
        let synced = MemberGroup(id: "synced", name: "Company", source: .scim)
        #expect(manual.isEditable(by: .owner))
        #expect(manual.isEditable(by: .admin))
        #expect(!manual.isEditable(by: .spaceAdmin))
        #expect(!manual.isEditable(by: .standard))
        for role in OrgRole.allCases { #expect(!synced.isEditable(by: role)) }
    }

    @Test func mockGroupLifecycleKeepsMembershipCountsAccurate() async throws {
        let client = MockGatewayClient()
        let group = try await client.createGroup(name: "  Sound  ")
        #expect(group.name == "Sound")
        #expect(try await client.groupMembers(group.id).isEmpty)
        try await client.addGroupMember("usr-ed1", to: group.id)
        try await client.addGroupMember("usr-ed1", to: group.id)
        #expect(try await client.groupMembers(group.id) == ["usr-ed1"])
        #expect(try await client.listGroups().first { $0.id == group.id }?.memberCount == 1)
        try await client.removeGroupMember("usr-ed1", from: group.id)
        #expect(try await client.groupMembers(group.id).isEmpty)
        #expect(try await client.listGroups().first { $0.id == group.id }?.memberCount == 0)
        try await client.deleteGroup(group.id)
        #expect(try await !client.listGroups().contains { $0.id == group.id })
        await #expect(throws: MockGatewayClient.GroupError.self) { _ = try await client.groupMembers(group.id) }
    }

    @Test func directoryManagedGroupsCannotBeChangedInDemo() async throws {
        let client = MockGatewayClient()
        let original = try await client.groupMembers("grp-color")
        await #expect(throws: MockGatewayClient.GroupError.self) { try await client.addGroupMember("usr-owner", to: "grp-color") }
        await #expect(throws: MockGatewayClient.GroupError.self) { try await client.removeGroupMember("usr-ed1", from: "grp-color") }
        await #expect(throws: MockGatewayClient.GroupError.self) { try await client.deleteGroup("grp-color") }
        #expect(try await client.groupMembers("grp-color") == original)
    }

    @Test func groupRejectsEmptyNameAndUnknownMembers() async throws {
        let client = MockGatewayClient()
        await #expect(throws: MockGatewayClient.GroupError.self) { _ = try await client.createGroup(name: "  ") }
        await #expect(throws: MockGatewayClient.GroupError.self) { try await client.addGroupMember("unknown", to: "grp-editorial") }
    }
}
