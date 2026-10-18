// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - GatewayClient — THE SEAM
//
// This is the single async protocol the entire UI talks to. Today it is filled
// by `MockGatewayClient` (offline, fake data). Later it is filled by a real
// implementation that fans out to:
//
//   • the Cloudflare Worker + per-filespace Durable Object — for the metadata
//     authority: filespace list, namespace enumeration, locks, snapshots,
//     share links, remote-activity feed, auth/login (SSO/SAML at the Worker).
//   • the local `cloudfsd` engine (over NSXPC / localhost-TCP, behind its own
//     `EngineClient` protocol per docs §1.3) — for cache config, pin/prefetch,
//     transfer progress, and connection (disconnect/reconnect) control.
//
// Keeping both behind ONE protocol means the views never learn whether a given
// datum came from the cloud or the local daemon — exactly the decoupling the
// blueprint asks for. The real client will likely compose two sub-clients
// behind a single `GatewayClient` facade; the UI does not care.
//
// Everything is `async`/`throws` and `Sendable` so a real network/XPC
// implementation drops in without touching call sites. Streaming feeds
// (transfers, activity) are exposed as `AsyncStream` so the UI can subscribe to
// live updates (the real version is fed by the gateway change WebSocket +
// engine progress callbacks).

public protocol GatewayClient: Sendable {

    // --- Auth / session -----------------------------------------------------

    /// Log in and/or connect a filespace. Interactive path does SSO/SAML at the
    /// Worker; the service-token path is for headless/CLI use. Returns the
    /// connected filespace(s) the caller now has access to.
    func connect(_ credentials: Credentials) async throws -> [Filespace]

    /// Drop the session; the real impl revokes tokens and removes domains.
    func signOut() async throws

    // --- Filespaces ---------------------------------------------------------

    func filespaces() async throws -> [Filespace]
    func workspaceStorage() async throws -> WorkspaceStorage
    func createWorkspaceFilespace(name: String, storage: WorkspaceStorage) async throws -> String

    /// One page of live namespace entries for folder access selection.
    func listDirectory(in filespaceID: String, parentID: String, cursor: String?) async throws -> DirectoryPage

    /// Ids of the shared-folder roots the signed-in user can access right now
    /// (`GET /v1/filespaces/:fs/mount-roots`). Compared with the daemon's mounted
    /// projection to offer "New access available — Reconnect".
    func mountRootIds(in filespaceID: String) async throws -> [String]

    /// Pause/resume sync for a filespace (engine quiesce + domain disconnect).
    func setConnectionState(_ state: ConnectionState, for filespaceID: String) async throws

    // --- Cache residency (gateway fallback when no daemon) ------------------
    //
    // The live Finder-like file browser was removed (WS1); these cache-residency
    // affordances remain as the gateway fallback used by AppModel when no cloudfsd
    // engine is present (the engine is authoritative when connected).

    /// Pin (keep-local) / unpin a file or folder subtree.
    func setPinned(_ pinned: Bool, fileID: String, in filespaceID: String) async throws

    /// Kick a download / prefetch for a file (stays evictable).
    func prefetch(fileID: String, in filespaceID: String) async throws

    /// Evict a materialized file to free cache space.
    func evict(fileID: String, in filespaceID: String) async throws

    // --- Activity & transfers (live feeds) ----------------------------------

    func recentActivity(in filespaceID: String, limit: Int) async throws -> [ActivityEvent]

    /// LIVE activity feed (WS3) — in-flight transfers + the DO hot ring + rolled-up
    /// bulk ops (e.g. large deletes). Maps to `GET /v1/filespaces/:fs/activity/live`
    /// (CONTRACTS §5.3). The `.activity` (Live) section renders this; the `.audit`
    /// (history) section keeps using `auditRange`/`recentActivity`.
    func liveActivity(in filespaceID: String) async throws -> LiveActivity

    /// HISTORICAL audit reader (WS3) — pages back into the DO ring and, for older
    /// ranges, the R2-archived segments (CONTRACTS §5.4). Maps to
    /// `GET /v1/filespaces/:fs/audit?limit=&since=&until=&cursor=`. Returns a page
    /// of events plus a `cursor` to continue (nil at the end).
    func auditRange(in filespaceID: String, since: Date?, until: Date?,
                    cursor: String?, limit: Int) async throws -> AuditPage

    func currentTransfers(in filespaceID: String) async throws -> [Transfer]

    /// Live transfer-progress stream (real impl: engine progress callbacks).
    func transferUpdates(in filespaceID: String) -> AsyncStream<[Transfer]>

    /// Live remote-activity stream (real impl: gateway change WebSocket).
    func activityUpdates(in filespaceID: String) -> AsyncStream<ActivityEvent>

    func pauseTransfers(in filespaceID: String) async throws
    func resumeTransfers(in filespaceID: String) async throws

    // --- Snapshots ----------------------------------------------------------

    func snapshots(in filespaceID: String) async throws -> [Snapshot]

    /// Take a manual snapshot (WS4 — replaces the AppModel stub). Maps to
    /// `POST /v1/filespaces/:fs/snapshots` (CONTRACTS §6.3). Returns the created
    /// snapshot so the caller can refresh the list.
    func createSnapshot(label: String?, scope: String?, tier: String?,
                        in filespaceID: String) async throws -> Snapshot

    /// Browse the namespace as it was at a snapshot. WS4 drives deep lazy folder-
    /// tree expansion by calling this per-folder with that folder's `parentID`.
    func listSnapshotFiles(snapshotID: String, in filespaceID: String, parentID: String?) async throws -> [FileNode]

    /// Self-service restore of a file/folder from a snapshot. `path` is the inode
    /// path; `recursive` restores a whole subtree. Returns the `RestoreResult`
    /// (restored/recreated/conflicts/newerThanSnapshot). Non-destructive.
    func restore(path: String, recursive: Bool, fromSnapshot snapshotID: String, in filespaceID: String) async throws -> RestoreResult

    // --- Sharing ------------------------------------------------------------

    func shareLinks(in filespaceID: String) async throws -> [CloudShareLink]

    /// Mint a copy-link (internal `cloudfs://` deep link or external guest link).
    func createShareLink(for fileID: String, kind: ShareKind, in filespaceID: String) async throws -> CloudShareLink

    func revokeShareLink(_ linkID: String, in filespaceID: String) async throws

    // --- Cache settings (engine-owned) --------------------------------------

    func cacheSettings(for filespaceID: String) async throws -> CacheSettings

    func updateCacheSettings(_ settings: CacheSettings, for filespaceID: String) async throws

    // --- Members & Access (org users / roles / invites + per-folder ACL) -----
    //
    // The user/permission-management half of the product, surfaced in the Mac
    // app's "Members & Access" section. Maps to the backend multi-user modules
    // (backend/src/{users,invites,permissions}.ts):
    //   • org directory      GET/PATCH/DELETE /v1/orgs/:org/users[/:id]
    //   • groups             GET /v1/orgs/:org/groups
    //   • invites            POST/DELETE /v1/orgs/:org/invites
    //   • per-folder ACL      POST/DELETE /v1/filespaces/:fs/grants
    //   • current role        GET /v1/auth/me  (drives admin-gating in the UI)

    /// The signed-in caller's ORG role — drives whether the Members & Access
    /// section is visible/editable (owner/admin/space_admin) vs hidden (standard).
    /// `GET /v1/auth/me` → `role`. The Mock returns the demo admin role.
    func currentUserRole() async throws -> OrgRole

    /// List the org directory (humans + service accounts). Any member may read it
    /// (`users.ts`: read is open, write is admin-only).
    func listMembers() async throws -> [OrgMember]

    /// Directory groups a grant can target (group-union ACL). `GET …/groups`.
    func listGroups() async throws -> [MemberGroup]
    func createGroup(name: String) async throws -> MemberGroup
    func deleteGroup(_ groupID: String) async throws
    func groupMembers(_ groupID: String) async throws -> [String]
    func addGroupMember(_ userID: String, to groupID: String) async throws
    func removeGroupMember(_ userID: String, from groupID: String) async throws

    /// Invite a new user (email + role, optional scoped folder grant). Returns the
    /// created invite incl. the raw token shown ONCE. `POST …/invites`.
    func invite(_ request: InviteRequest) async throws -> InviteResult

    /// Change a member's org role. `PATCH …/users/:id { role }`.
    func setRole(_ role: OrgRole, forMember memberID: String) async throws

    /// Suspend a member (reversible — they can be reactivated). `PATCH …/users/:id { status:"suspended" }`.
    func suspendMember(_ memberID: String) async throws

    /// Reactivate a suspended member. `PATCH …/users/:id { status:"active" }`.
    func reactivateMember(_ memberID: String) async throws

    /// Deprovision (soft-delete) a member. `DELETE …/users/:id` (status → deprovisioned).
    func deprovisionMember(_ memberID: String) async throws

    /// The active filespace's per-folder ACL grants. The gateway exposes no bulk
    /// list-grants route, so the real client reads the space's known grants; the
    /// Mock returns the fixture set.
    func accessManagement(in filespaceID: String) async throws -> FolderAdministration
    func listManagedFolders(in filespaceID: String, parentID: String, cursor: String?) async throws -> DirectoryPage

    func listGrants(in filespaceID: String) async throws -> [AccessGrant]

    /// Add or update a per-folder ACL grant. `POST /v1/filespaces/:fs/grants`.
    /// Returns the persisted grant (with its server id).
    func setGrant(_ request: GrantRequest, in filespaceID: String) async throws -> AccessGrant

    /// Revoke a grant (remove a principal's access on the inode).
    /// `DELETE /v1/filespaces/:fs/grants?inodeId=&principalType=&principalId=`.
    func removeGrant(_ grant: AccessGrant, in filespaceID: String) async throws
}

extension GatewayClient {
    public func workspaceStorage() async throws -> WorkspaceStorage { throw EngineError.unavailable("Workspace storage is unavailable") }
    public func createWorkspaceFilespace(name: String, storage: WorkspaceStorage) async throws -> String { throw EngineError.unavailable("Filespace creation is unavailable") }
}
