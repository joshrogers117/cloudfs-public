// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - Members & Access domain + pure presentation logic
//
// The user/permission-management half of the product (it lives in the Mac app,
// NOT the web app). This file is the testable CORE: the org-role model + admin
// gating, the per-folder ACL grant level ladder (read < edit < admin), the member
// directory projections, and the offline fixtures that drive the Mock so the
// MembersView renders with no live backend.
//
// It is pure (no SwiftUI / no AppKit) so all of the access-control logic — "can
// this user manage members?", "which roles can a space_admin assign?", the grant
// ladder ordering, the directory rollup counts — is unit-testable in isolation.
// `MembersView` renders whatever these compute; the policy never lives in a body.
//
// Mirrors the backend (backend/src/{users,invites,permissions}.ts):
//   • OrgRole              owner | admin | space_admin | standard  (permissions.ts)
//   • MemberStatus         active | suspended | deprovisioned       (org-do.ts UserStatus)
//   • GrantLevel           read < edit < admin (strict ladder)       (permissions.ts Level)
//   • PrincipalType        user | group | service_account           (permissions.ts)

// MARK: - Org role (org-do.ts OrgRole)

/// The org-wide role ladder. Distinct from `MemberRole` (the per-FILESPACE label
/// on `Filespace.role`); this is the ORG identity used to gate the Members &
/// Access surface. Wire values match the backend exactly ("owner"/"admin"/…).
public enum OrgRole: String, Sendable, Codable, CaseIterable, Identifiable, Comparable {
    case owner
    case admin
    case spaceAdmin = "space_admin"
    case standard

    public var id: String { rawValue }

    /// Human label for chips / pickers.
    public var displayName: String {
        switch self {
        case .owner:      return "Owner"
        case .admin:      return "Admin"
        case .spaceAdmin: return "Filespace Admin"
        case .standard:   return "Standard"
        }
    }

    /// One-line explanation surfaced as a tooltip in the role picker.
    public var explanation: String {
        switch self {
        case .owner:      return "Full control of the org, billing, and every filespace."
        case .admin:      return "Manage members, filespaces, and per-folder access across the org."
        case .spaceAdmin: return "Read, edit, and manage access in every filespace. Cannot manage workspace accounts or storage."
        case .standard:   return "Work in filespaces they have been granted access to."
        }
    }

    /// Ordering rank (higher == more privileged). Drives `Comparable` + sort.
    public var rank: Int {
        switch self {
        case .owner:      return 3
        case .admin:      return 2
        case .spaceAdmin: return 1
        case .standard:   return 0
        }
    }

    public static func < (lhs: OrgRole, rhs: OrgRole) -> Bool { lhs.rank < rhs.rank }

    // MARK: Admin gating (the policy the nav + view read)

    /// Workspace directory and invitations require owner/admin. Folder access
    /// is independently granted by the server's access-management capability.
    public var canManageMembers: Bool { self == .owner || self == .admin }
    public var canManageFilespaceSettings: Bool { self == .owner || self == .admin || self == .spaceAdmin }
    public var canManageGuestLinks: Bool { canManageFilespaceSettings }
    public var canManageSnapshotSchedules: Bool { canManageMembers }
    public var canReadWorkspaceActivity: Bool { canManageMembers }

    /// Whether this role may mutate the org directory (invite / change role /
    /// suspend / deprovision). Same admin set as visibility — a standard user that
    /// somehow reaches the view is fully read-only.
    public var canMutateMembers: Bool { self == .owner || self == .admin }

    /// Whether this role may create NEW filespaces (web console `/filespaces/new`,
    /// and the sidebar's "+" affordance). Deliberately NARROWER than
    /// `canManageMembers`: per `explanation` above, owner/admin manage "filespaces
    /// … across the org" while space_admin only manages "members and access
    /// WITHIN ASSIGNED filespaces" — creating a new one is an org-wide action a
    /// space_admin doesn't get. (The web `CreateFilespace` screen has no role gate
    /// of its own yet, so this is the client's own best-available policy.)
    public var canCreateFilespaces: Bool {
        self == .owner || self == .admin
    }

    /// The roles this role is allowed to ASSIGN when inviting / changing a role.
    /// You can never grant a role above your own (no privilege escalation), and only
    /// the owner can mint another owner. Filespace admins cannot assign workspace roles.
    public func assignableRoles() -> [OrgRole] {
        switch self {
        case .owner:      return [.owner, .admin, .spaceAdmin, .standard]
        case .admin:      return [.admin, .spaceAdmin, .standard]
        case .spaceAdmin: return []
        case .standard:   return []
        }
    }

    public func canAssign(_ role: OrgRole) -> Bool { assignableRoles().contains(role) }
}

// MARK: - Member status (org-do.ts UserStatus)

public enum MemberStatus: String, Sendable, Codable, CaseIterable {
    case active
    case suspended
    case deprovisioned

    public var displayName: String {
        switch self {
        case .active:        return "Active"
        case .suspended:     return "Suspended"
        case .deprovisioned: return "Deprovisioned"
        }
    }

    /// Whether the account can currently sign in / sync.
    public var isActive: Bool { self == .active }
}

// MARK: - Principal kind (permissions.ts PrincipalType / org-do.ts UserKind)

/// Who a grant or member is. `user`/`serviceAccount` are individual identities;
/// `group` is a directory group (SCIM-synced or manual) a grant can target.
public enum PrincipalType: String, Sendable, Codable, CaseIterable {
    case user
    case group
    case serviceAccount = "service_account"

    public var displayName: String {
        switch self {
        case .user:           return "User"
        case .group:          return "Group"
        case .serviceAccount: return "Service Account"
        }
    }
}

// MARK: - OrgMember (org-do.ts User projection)

/// A row in the org directory. Projection of the backend `User` (users.ts) onto
/// the fields the Members list renders.
public struct OrgMember: Identifiable, Sendable, Hashable, Codable {
    public let id: String
    public var email: String
    public var displayName: String
    public var role: OrgRole
    public var status: MemberStatus
    public var principal: PrincipalType   // user vs service_account
    public var createdAt: Date

    public init(id: String, email: String, displayName: String, role: OrgRole,
                status: MemberStatus, principal: PrincipalType = .user,
                createdAt: Date = Date()) {
        self.id = id; self.email = email; self.displayName = displayName
        self.role = role; self.status = status; self.principal = principal
        self.createdAt = createdAt
    }

    /// First letter(s) for the avatar bubble — initials from the display name.
    public var initials: String {
        let parts = displayName.split(separator: " ").prefix(2)
        let letters = parts.compactMap { $0.first.map(String.init) }
        if letters.isEmpty { return email.first.map { String($0).uppercased() } ?? "?" }
        return letters.joined().uppercased()
    }

    public var isServiceAccount: Bool { principal == .serviceAccount }
}

extension Array where Element == OrgMember {
    /// Directory order: most-privileged role first, active before suspended/
    /// deprovisioned, then by name — so admins surface at the top and disabled
    /// accounts sink. Deterministic (name tiebreak) for stable rendering + tests.
    public func sortedForDirectory() -> [OrgMember] {
        sorted { a, b in
            if a.status.isActive != b.status.isActive { return a.status.isActive }
            if a.role.rank != b.role.rank { return a.role.rank > b.role.rank }
            return a.displayName.localizedCaseInsensitiveCompare(b.displayName) == .orderedAscending
        }
    }
}

// MARK: - MembersSummary — directory rollup (drives the summary strip)

/// Aggregate counts across the directory. Pure value type recomputed from
/// `[OrgMember]`; powers the "N members · M admins · K suspended" strip.
public struct MembersSummary: Sendable, Equatable {
    public let total: Int
    public let activeCount: Int
    public let suspendedCount: Int
    public let deprovisionedCount: Int
    public let adminCount: Int          // owner + admin + space_admin
    public let serviceAccountCount: Int

    public init(members: [OrgMember]) {
        self.total = members.count
        self.activeCount = members.filter { $0.status == .active }.count
        self.suspendedCount = members.filter { $0.status == .suspended }.count
        self.deprovisionedCount = members.filter { $0.status == .deprovisioned }.count
        self.adminCount = members.filter { $0.role.canManageFilespaceSettings }.count
        self.serviceAccountCount = members.filter { $0.isServiceAccount }.count
    }

    public var isEmpty: Bool { total == 0 }
}

// MARK: - Grant level (permissions.ts Level — strict read < edit < admin ladder)

public enum GrantLevel: String, Sendable, Codable, CaseIterable, Identifiable, Comparable {
    case read
    case edit
    case admin

    public var id: String { rawValue }

    public var displayName: String {
        switch self {
        case .read:  return "Read"
        case .edit:  return "Edit"
        case .admin: return "Folder admin"
        }
    }

    /// One-line explanation for the level picker tooltip (mirrors permissions.ts
    /// ACTION_MIN_LEVEL semantics).
    public var explanation: String {
        switch self {
        case .read:  return "List folders and download files."
        case .edit:  return "Read, plus create, modify, rename, and delete."
        case .admin: return "Edit, plus grant and revoke access on this subtree."
        }
    }

    /// Strict ladder rank (permissions.ts LEVEL_RANK: read 1 < edit 2 < admin 3).
    public var rank: Int {
        switch self {
        case .read:  return 1
        case .edit:  return 2
        case .admin: return 3
        }
    }

    public static func < (lhs: GrantLevel, rhs: GrantLevel) -> Bool { lhs.rank < rhs.rank }
}

// MARK: - MemberGroup (org-do.ts Group projection) — a grant target

/// A directory group a grant can target (group-union ACL, permissions.ts). Manual
/// or SCIM-synced.
public struct MemberGroup: Identifiable, Sendable, Hashable, Codable {
    public let id: String
    public var name: String
    public var source: Source            // manual vs scim
    public var memberCount: Int

    public enum Source: String, Sendable, Codable {
        case manual, scim
        public var displayName: String { self == .scim ? "SCIM" : "Manual" }
    }

    public func isEditable(by role: OrgRole) -> Bool {
        source == .manual && role.canMutateMembers
    }

    public init(id: String, name: String, source: Source = .manual, memberCount: Int = 0) {
        self.id = id; self.name = name; self.source = source; self.memberCount = memberCount
    }
}

// MARK: - AccessGrant (permissions.ts Grant projection) — one ACL row

/// One per-folder ACL grant: a principal (user / group / service account) holds a
/// `level` (read/edit/admin) on a folder inode. Projection of the backend `Grant`
/// (permissions.ts) onto what the Access editor renders + mutates.
public struct AccessGrant: Identifiable, Sendable, Hashable, Codable {
    public let id: String
    public var inodeId: String           // the folder node the grant attaches to
    public var inodePath: String         // display path of that folder (e.g. "Footage/ProRes")
    public var principalType: PrincipalType
    public var principalId: String
    public var principalLabel: String    // display name / email / group name
    public var level: GrantLevel
    public var mountAsRoot: Bool          // RootPoint — confine the principal to this subtree
    public var expiresAt: Date?          // expiring grant (nil == permanent)
    public var canModify: Bool?          // authoritative per-row capability
    public var active: Bool?             // false when delegation authority was revoked

    public init(id: String, inodeId: String, inodePath: String,
                principalType: PrincipalType, principalId: String, principalLabel: String,
                level: GrantLevel, mountAsRoot: Bool = false, expiresAt: Date? = nil,
                canModify: Bool? = nil, active: Bool? = nil) {
        self.id = id; self.inodeId = inodeId; self.inodePath = inodePath
        self.principalType = principalType; self.principalId = principalId
        self.principalLabel = principalLabel; self.level = level
        self.mountAsRoot = mountAsRoot; self.expiresAt = expiresAt
        self.canModify = canModify; self.active = active
    }

    /// True when the grant has lapsed (permissions.ts ignores it once expired).
    public func isExpired(now: Date = Date()) -> Bool {
        guard let expiresAt else { return false }
        return now >= expiresAt
    }
}

extension Array where Element == AccessGrant {
    /// Access-editor order: group by folder path, then highest level first, then
    /// principal label — so a folder's grants read top-down as admin → edit → read.
    public func sortedForAccessEditor() -> [AccessGrant] {
        sorted { a, b in
            if a.inodePath != b.inodePath {
                return a.inodePath.localizedCaseInsensitiveCompare(b.inodePath) == .orderedAscending
            }
            if a.level.rank != b.level.rank { return a.level.rank > b.level.rank }
            return a.principalLabel.localizedCaseInsensitiveCompare(b.principalLabel) == .orderedAscending
        }
    }
}

// MARK: - Invite input / result (invites.ts)

/// What the "invite a new user" form submits. `level`/`inodeId` carry an optional
/// scoped folder grant the invite promises on redeem (invites.ts InviteScope).
public struct InviteRequest: Sendable, Hashable {
    public var email: String
    public var role: OrgRole
    public var spaceId: String?
    public var inodeId: String?
    public var level: GrantLevel?

    public init(email: String, role: OrgRole, spaceId: String? = nil,
                inodeId: String? = nil, level: GrantLevel? = nil) {
        self.email = email; self.role = role
        self.spaceId = spaceId; self.inodeId = inodeId; self.level = level
    }

    /// Trimmed, lowercased email with a minimal `a@b.c` shape check — enough to
    /// disable the submit button on obvious garbage without over-validating.
    public var normalizedEmail: String {
        email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    public var isValid: Bool {
        let e = normalizedEmail
        guard let at = e.firstIndex(of: "@"), at != e.startIndex else { return false }
        let domain = e[e.index(after: at)...]
        return domain.contains(".") && !domain.hasSuffix(".") && !domain.hasPrefix(".")
    }
}

/// The result of creating an invite — the raw token is shown ONCE (invites.ts).
public struct InviteResult: Sendable, Hashable {
    public let inviteId: String
    public let email: String
    public let role: OrgRole
    /// The raw token to send the recipient — surfaced once so the admin can copy it.
    public let rawToken: String
    public let expiresAt: Date
    public let emailSent: Bool
    public let joinToken: String?

    public init(inviteId: String, email: String, role: OrgRole, rawToken: String, expiresAt: Date, emailSent: Bool = false, joinToken: String? = nil) {
        self.inviteId = inviteId; self.email = email; self.role = role
        self.rawToken = rawToken; self.expiresAt = expiresAt; self.emailSent = emailSent; self.joinToken = joinToken
    }
}

// MARK: - Grant input (POST /v1/filespaces/:fs/grants)

/// What add/edit-a-grant submits. Mirrors the POST body shape in API.md §grants.
public struct GrantRequest: Sendable, Hashable {
    public var inodeId: String
    public var inodePath: String
    public var principalType: PrincipalType
    public var principalId: String
    public var principalLabel: String
    public var level: GrantLevel
    public var mountAsRoot: Bool
    public var expiresAt: Date?

    public init(inodeId: String, inodePath: String, principalType: PrincipalType,
                principalId: String, principalLabel: String, level: GrantLevel,
                mountAsRoot: Bool = false, expiresAt: Date? = nil) {
        self.inodeId = inodeId; self.inodePath = inodePath
        self.principalType = principalType; self.principalId = principalId
        self.principalLabel = principalLabel; self.level = level
        self.mountAsRoot = mountAsRoot; self.expiresAt = expiresAt
    }

    public var isValid: Bool {
        !inodeId.trimmingCharacters(in: .whitespaces).isEmpty
            && !principalId.trimmingCharacters(in: .whitespaces).isEmpty
    }
}

// MARK: - Offline fixtures (Mock / no-backend path)
//
// The Members & Access surface drives entirely from these in Mock mode so the
// view builds, previews, and demos with no live gateway. ~7 members across every
// role + status, three groups, and a handful of folder grants spanning the ladder.

extension OrgMember {
    /// A realistic post-house org directory: an owner, admins, space admins,
    /// standard editors, a suspended freelancer, a deprovisioned alum, and a
    /// render-farm service account.
    public static func fixtures() -> [OrgMember] {
        func at(_ days: Double) -> Date { Date().addingTimeInterval(-days * 86_400) }
        return [
            OrgMember(id: "usr-owner", email: "casey@acme.tv", displayName: "Casey Owner",
                      role: .owner, status: .active, createdAt: at(420)),
            OrgMember(id: "usr-admin", email: "mara@acme.tv", displayName: "Mara Patel",
                      role: .admin, status: .active, createdAt: at(360)),
            OrgMember(id: "usr-spadmin", email: "devin@acme.tv", displayName: "Devin Kross",
                      role: .spaceAdmin, status: .active, createdAt: at(220)),
            OrgMember(id: "usr-ed1", email: "sasha@acme.tv", displayName: "Sasha Reyes",
                      role: .standard, status: .active, createdAt: at(140)),
            OrgMember(id: "usr-ed2", email: "jules@acme.tv", displayName: "Jules Tan",
                      role: .standard, status: .active, createdAt: at(95)),
            OrgMember(id: "usr-freelance", email: "rio@freelance.io", displayName: "Rio Vasquez",
                      role: .standard, status: .suspended, createdAt: at(60)),
            OrgMember(id: "usr-alum", email: "pat@acme.tv", displayName: "Pat Alvi",
                      role: .standard, status: .deprovisioned, createdAt: at(500)),
            OrgMember(id: "svc-render", email: "render-farm@svc.acme", displayName: "Render Farm",
                      role: .standard, status: .active, principal: .serviceAccount, createdAt: at(300)),
        ]
    }
}

extension MemberGroup {
    public static func fixtures() -> [MemberGroup] {
        [
            MemberGroup(id: "grp-editorial", name: "Editorial", source: .manual, memberCount: 5),
            MemberGroup(id: "grp-color", name: "Color & Finishing", source: .scim, memberCount: 3),
            MemberGroup(id: "grp-producers", name: "Producers", source: .manual, memberCount: 2),
        ]
    }
}

extension AccessGrant {
    /// Folder grants spanning the read/edit/admin ladder for both users and groups,
    /// keyed to the Studio A fixture tree so they read naturally in the editor.
    public static func fixtures() -> [AccessGrant] {
        func at(_ days: Double) -> Date { Date().addingTimeInterval(days * 86_400) }
        return [
            AccessGrant(id: "grant-1", inodeId: "a-projects", inodePath: "Projects",
                        principalType: .group, principalId: "grp-editorial", principalLabel: "Editorial",
                        level: .edit),
            AccessGrant(id: "grant-2", inodeId: "a-projects", inodePath: "Projects",
                        principalType: .user, principalId: "usr-spadmin", principalLabel: "Devin Kross",
                        level: .admin),
            AccessGrant(id: "grant-3", inodeId: "a-footage", inodePath: "Footage",
                        principalType: .group, principalId: "grp-color", principalLabel: "Color & Finishing",
                        level: .read),
            AccessGrant(id: "grant-4", inodeId: "a-footage", inodePath: "Footage",
                        principalType: .user, principalId: "usr-ed1", principalLabel: "Sasha Reyes",
                        level: .edit, mountAsRoot: true),
            AccessGrant(id: "grant-5", inodeId: "a-exports", inodePath: "Exports",
                        principalType: .user, principalId: "usr-freelance", principalLabel: "Rio Vasquez",
                        level: .read, expiresAt: at(14)),
        ]
    }
}
