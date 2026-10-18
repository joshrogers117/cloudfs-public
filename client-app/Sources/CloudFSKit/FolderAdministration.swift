// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

public struct ManagedFolder: Sendable, Hashable, Codable, Identifiable {
    public let inodeId: String
    public let name: String
    public let path: String
    public var id: String { inodeId }
    public init(inodeId: String, name: String, path: String) {
        self.inodeId = inodeId; self.name = name; self.path = path
    }
}

/// The gateway supplies capabilities and safe roots; a folder admin is still a
/// standard workspace member. Never infer these capabilities from a role label.
public struct FolderAdministration: Sendable {
    public let canManageAccess: Bool
    public let canDelegateAdmin: Bool
    public let canManageWorkspace: Bool
    public let roots: [ManagedFolder]
    public let grants: [AccessGrant]
    public let members: [OrgMember]
    public let groups: [MemberGroup]
    public init(canManageAccess: Bool = false, canDelegateAdmin: Bool = false,
                canManageWorkspace: Bool = false, roots: [ManagedFolder] = [],
                grants: [AccessGrant] = [], members: [OrgMember] = [], groups: [MemberGroup] = []) {
        self.canManageAccess = canManageAccess; self.canDelegateAdmin = canDelegateAdmin
        self.canManageWorkspace = canManageWorkspace; self.roots = roots
        self.grants = grants; self.members = members; self.groups = groups
    }
    public var grantableLevels: [GrantLevel] { canDelegateAdmin ? [.read, .edit, .admin] : [.read, .edit] }
    public func canModify(_ grant: AccessGrant) -> Bool { canManageAccess && grant.canModify == true }
}

extension GatewayClient {
    public func listManagedFolders(in filespaceID: String, parentID: String, cursor: String?) async throws -> DirectoryPage {
        throw HttpGatewayClient.GatewayError.unsupported("Folder administration requires an updated gateway.")
    }

    public func accessManagement(in filespaceID: String) async throws -> FolderAdministration {
        throw HttpGatewayClient.GatewayError.unsupported("Folder administration requires an updated gateway.")
    }
}
