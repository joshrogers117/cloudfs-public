// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - MockGatewayClient
//
// The offline fill for the GatewayClient seam. Returns plausible post-house
// fake data (filespaces, a media folder tree, live-ish transfers, snapshots,
// share links, cache stats) so the whole app builds and runs with NO Cloudflare
// account and NO running cloudfsd. Swap this for the real composite client and
// nothing in the UI changes.
//
// State lives in an `actor` so concurrent UI reads/writes are race-free.

public actor MockGatewayClient: GatewayClient {

    // MARK: Backing state

    public func workspaceStorage() async throws -> WorkspaceStorage {
        WorkspaceStorage(configured: true, provider: "r2", region: "auto", bucket: "preview-storage")
    }
    public func createWorkspaceFilespace(name: String, storage: WorkspaceStorage) async throws -> String {
        let id = "preview-" + UUID().uuidString.lowercased()
        spaces.append(Filespace(id: id, name: name.trimmingCharacters(in: .whitespacesAndNewlines), region: storage.regionLabel,
                                storageBackend: storage.providerLabel, connection: .disconnected, role: .admin, usedBytes: 0, memberCount: 1, mountPath: ""))
        return id
    }

    private var spaces: [Filespace]
    private var trees: [String: [String?: [FileNode]]]   // filespaceID -> parentID -> children
    private var activity: [String: [ActivityEvent]]
    private var transfers: [String: [Transfer]]
    private var snaps: [String: [Snapshot]]
    private var snapTrees: [String: [String?: [FileNode]]] // snapshotID -> parentID -> children
    private var links: [String: [CloudShareLink]]
    private var caches: [String: CacheSettings]

    // Members & Access state. `members`/`groups` are org-wide; `grants` is keyed by
    // filespaceID. Seeded from the offline fixtures so the MembersView renders fully.
    private var members: [OrgMember]
    private var groups: [MemberGroup]
    private var groupMemberships: [String: Set<String>] = [
        "grp-editorial": ["usr-owner", "usr-admin", "usr-spadmin", "usr-ed1", "usr-ed2"],
        "grp-color": ["usr-admin", "usr-ed1", "usr-ed2"],
        "grp-producers": ["usr-owner", "usr-admin"],
    ]
    private var grants: [String: [AccessGrant]]
    /// The demo caller's role — admin so the section is visible + editable offline.
    private var meRole: OrgRole = .admin

    public init(role: OrgRole = .admin) {
        self.meRole = role
        let fixtures = MockFixtures.build()
        self.spaces = fixtures.spaces
        self.trees = fixtures.trees
        self.activity = fixtures.activity
        self.transfers = fixtures.transfers
        self.snaps = fixtures.snapshots
        self.snapTrees = fixtures.snapshotTrees
        self.links = fixtures.links
        self.caches = fixtures.caches
        self.members = OrgMember.fixtures()
        self.groups = MemberGroup.fixtures()
        // Grants live on the editorial filespace's folders.
        self.grants = ["fs-studio-a": AccessGrant.fixtures()]
    }

    /// Test seam: replace the activity fixture for a filespace so the audit
    /// page-back contract can be exercised deterministically (used by the
    /// `auditRange` cursor/pagination tests).
    func seedActivity(_ events: [ActivityEvent], for filespaceID: String) {
        activity[filespaceID] = events
    }

    // MARK: Auth

    public func connect(_ credentials: Credentials) async throws -> [Filespace] {
        // Simulate a login round-trip + domain registration.
        try? await Task.sleep(for: .milliseconds(700))
        for i in spaces.indices { spaces[i].connection = .connected }
        return spaces
    }

    public func signOut() async throws {
        for i in spaces.indices { spaces[i].connection = .disconnected }
    }

    // MARK: Filespaces

    public func filespaces() async throws -> [Filespace] { spaces }

    public func setConnectionState(_ state: ConnectionState, for filespaceID: String) async throws {
        guard let idx = spaces.firstIndex(where: { $0.id == filespaceID }) else { return }
        spaces[idx].connection = state
    }

    public func listDirectory(in filespaceID: String, parentID: String, cursor: String?) async throws -> DirectoryPage {
        let parent: String? = parentID == "root" ? nil : parentID
        return DirectoryPage(items: trees[filespaceID]?[parent] ?? [])
    }

    // MARK: Cache residency (pin / prefetch / evict)

    public func setPinned(_ pinned: Bool, fileID: String, in filespaceID: String) async throws {
        mutateNode(fileID, in: filespaceID) { $0.state = pinned ? .pinned : .downloaded }
    }

    public func prefetch(fileID: String, in filespaceID: String) async throws {
        mutateNode(fileID, in: filespaceID) { if $0.state == .dataless { $0.state = .downloaded } }
    }

    public func evict(fileID: String, in filespaceID: String) async throws {
        mutateNode(fileID, in: filespaceID) { if $0.state == .downloaded { $0.state = .dataless } }
    }

    private func mutateNode(_ fileID: String, in filespaceID: String, _ body: (inout FileNode) -> Void) {
        guard var byParent = trees[filespaceID] else { return }
        for (parent, var nodes) in byParent {
            if let idx = nodes.firstIndex(where: { $0.id == fileID }) {
                body(&nodes[idx])
                byParent[parent] = nodes
                trees[filespaceID] = byParent
                return
            }
        }
    }

    // MARK: Activity & transfers

    public func recentActivity(in filespaceID: String, limit: Int) async throws -> [ActivityEvent] {
        Array((activity[filespaceID] ?? []).prefix(limit))
    }

    // WS3 LIVE feed: current transfers + the recent ring + one sample bulk rollup,
    // so the LiveActivityView builds against the mock without the real gateway.
    public func liveActivity(in filespaceID: String) async throws -> LiveActivity {
        let ring = Array((activity[filespaceID] ?? []).prefix(8))
        let bulk = ActivityEvent(
            id: "bulk-\(filespaceID)", actor: "bob@acme",
            verb: "deleted", path: "projectA/cache/", at: Date().addingTimeInterval(-90),
            kind: .bulk, bulkOp: "large-delete", bulkCount: 4203)
        return LiveActivity(transfers: transfers[filespaceID] ?? [],
                            events: [bulk] + ring)
    }

    // WS3 HISTORICAL audit reader — faithfully mirrors the real gateway's
    // NEWEST-FIRST + `cursor` page-back contract (CONTRACTS §5.4) so client paging
    // logic exercises the same shape it sees in production:
    //   • rows are returned newest-first (descending `at`, `id` as tiebreaker),
    //   • `cursor` is the EXCLUSIVE upper bound = the lowest-ordered `id` of the
    //     previous full page; page-back returns only strictly-older rows,
    //   • the continuation cursor is the lowest `id` of a FULL page (nil on a
    //     short/empty page → end of history), so the page-back loop terminates
    //     with no duplicate rows. (The mock has no R2; the whole fixture stands in
    //     for ring+archive.)
    public func auditRange(in filespaceID: String, since: Date?, until: Date?,
                           cursor: String?, limit: Int) async throws -> AuditPage {
        var events = activity[filespaceID] ?? []
        if let since { events = events.filter { $0.at >= since } }
        if let until { events = events.filter { $0.at <= until } }
        // Newest-first ordering. A total order is required for a stable cursor:
        // sort by `at` descending, breaking ties by `id` descending.
        events.sort { l, r in l.at != r.at ? l.at > r.at : l.id > r.id }
        // `cursor` is exclusive: keep only rows ordered strictly AFTER it.
        if let cursor, let at = events.firstIndex(where: { $0.id == cursor }) {
            events = Array(events.suffix(from: events.index(after: at)))
        }
        let page = Array(events.prefix(limit))
        // Full page → more may exist, continue from this page's lowest-ordered id.
        let next: String? = (page.count >= limit) ? page.last?.id : nil
        return AuditPage(events: page, cursor: next)
    }

    public func currentTransfers(in filespaceID: String) async throws -> [Transfer] {
        transfers[filespaceID] ?? []
    }

    // `nonisolated` so it satisfies the (nonisolated) protocol requirement; the
    // work hops back into the actor via `await self.tickTransfers`.
    public nonisolated func transferUpdates(in filespaceID: String) -> AsyncStream<[Transfer]> {
        // Drive the active transfers forward so the UI shows live progress bars.
        AsyncStream { continuation in
            let task = Task {
                while !Task.isCancelled {
                    let snapshot = await self.tickTransfers(filespaceID)
                    continuation.yield(snapshot)
                    try? await Task.sleep(for: .milliseconds(800))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    private func tickTransfers(_ filespaceID: String) -> [Transfer] {
        guard var list = transfers[filespaceID] else { return [] }
        for i in list.indices where list[i].state == .active {
            let step = max(1, list[i].throughputBytesPerSec * 8 / 10)
            list[i].bytesDone = min(list[i].bytesTotal, list[i].bytesDone + step)
            if list[i].bytesDone >= list[i].bytesTotal { list[i].state = .completed }
        }
        transfers[filespaceID] = list
        return list
    }

    public nonisolated func activityUpdates(in filespaceID: String) -> AsyncStream<ActivityEvent> {
        AsyncStream { continuation in
            let task = Task {
                let seed = await self.activity[filespaceID] ?? []
                var i = 0
                while !Task.isCancelled, !seed.isEmpty {
                    try? await Task.sleep(for: .seconds(6))
                    let base = seed[i % seed.count]
                    continuation.yield(ActivityEvent(
                        id: UUID().uuidString, actor: base.actor, verb: base.verb,
                        path: base.path, at: Date()))
                    i += 1
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public func pauseTransfers(in filespaceID: String) async throws {
        guard var list = transfers[filespaceID] else { return }
        for i in list.indices where list[i].state == .active { list[i].state = .paused }
        transfers[filespaceID] = list
    }

    public func resumeTransfers(in filespaceID: String) async throws {
        guard var list = transfers[filespaceID] else { return }
        for i in list.indices where list[i].state == .paused { list[i].state = .active }
        transfers[filespaceID] = list
    }

    // MARK: Snapshots

    public func snapshots(in filespaceID: String) async throws -> [Snapshot] {
        snaps[filespaceID] ?? []
    }

    // WS4 manual snapshot create: synthesize a manual snapshot, insert it at the
    // front of the list, and return it so the view can refresh.
    public func createSnapshot(label: String?, scope: String?, tier: String?,
                               in filespaceID: String) async throws -> Snapshot {
        try? await Task.sleep(for: .milliseconds(300))
        let snap = Snapshot(
            id: "snap-\(UUID().uuidString.prefix(8))",
            name: label ?? "Manual \(Date().formatted(date: .abbreviated, time: .shortened))",
            takenAt: Date(),
            sizeBytes: caches[filespaceID]?.usedBytes ?? 0,
            isScheduled: false,
            retentionTier: tier ?? "Manual", scope: scope)
        snaps[filespaceID, default: []].insert(snap, at: 0)
        return snap
    }

    public func listSnapshotFiles(snapshotID: String, in filespaceID: String, parentID: String?) async throws -> [FileNode] {
        snapTrees[snapshotID]?[parentID] ?? (trees[filespaceID]?[parentID] ?? [])
    }

    public func restore(path: String, recursive: Bool, fromSnapshot snapshotID: String, in filespaceID: String) async throws -> RestoreResult {
        try? await Task.sleep(for: .milliseconds(400))
        var list = activity[filespaceID] ?? []
        list.insert(ActivityEvent(id: UUID().uuidString, actor: "You",
                                  verb: recursive ? "restored subtree from snapshot" : "restored from snapshot",
                                  path: path, at: Date()),
                    at: 0)
        activity[filespaceID] = list
        // Simulate a realistic mixed result so the demo UI exercises every field.
        return RestoreResult(
            snapshotId: snapshotID,
            restored: [path],
            recreated: recursive ? ["\(path)/deleted-clip.mov"] : [],
            conflicts: [],
            newerThanSnapshot: recursive ? ["\(path)/new-since.mov"] : [])
    }

    // MARK: Sharing

    public func shareLinks(in filespaceID: String) async throws -> [CloudShareLink] {
        links[filespaceID] ?? []
    }

    public func createShareLink(for fileID: String, kind: ShareKind, in filespaceID: String) async throws -> CloudShareLink {
        let path = nodePath(fileID, in: filespaceID) ?? "/\(fileID)"
        let url: String
        switch kind {
        case .internalDeepLink:
            url = fileID.isEmpty ? DeepLink.build(spaceId: filespaceID, path: "")
                : DeepLink.buildItem(spaceId: filespaceID, itemId: fileID)
        case .guestLink:        url = "https://share.cloud-fs.example/g/\(UUID().uuidString.prefix(10))"
        }
        let link = CloudShareLink(
            id: UUID().uuidString, path: path, kind: kind, url: url,
            expiresAt: kind == .guestLink ? Date().addingTimeInterval(7 * 86_400) : nil,
            canDownload: true, canEdit: false)
        links[filespaceID, default: []].insert(link, at: 0)
        return link
    }

    public func revokeShareLink(_ linkID: String, in filespaceID: String) async throws {
        links[filespaceID]?.removeAll { $0.id == linkID }
    }

    private func nodePath(_ fileID: String, in filespaceID: String) -> String? {
        for (_, nodes) in trees[filespaceID] ?? [:] {
            if let node = nodes.first(where: { $0.id == fileID }) { return "/" + node.name }
        }
        return nil
    }

    // MARK: Cache

    public func cacheSettings(for filespaceID: String) async throws -> CacheSettings {
        caches[filespaceID] ?? MockFixtures.defaultCache()
    }

    public func updateCacheSettings(_ settings: CacheSettings, for filespaceID: String) async throws {
        caches[filespaceID] = settings
    }

    // MARK: Members & Access

    public func currentUserRole() async throws -> OrgRole { meRole }

    /// Test seam: pretend the signed-in caller has `role` so the admin-gating path
    /// (visible/editable vs hidden) can be exercised deterministically.
    func seedCurrentRole(_ role: OrgRole) { meRole = role }

    public func listMembers() async throws -> [OrgMember] { members }

    public func listGroups() async throws -> [MemberGroup] {
        groups.map { group in
            var result = group
            result.memberCount = groupMemberships[group.id]?.count ?? 0
            return result
        }
    }

    public enum GroupError: Error { case missingGroup, directoryManaged, invalidName, missingMember }

    public func createGroup(name: String) async throws -> MemberGroup {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw GroupError.invalidName }
        let group = MemberGroup(id: "grp-\(UUID().uuidString)", name: trimmed)
        groups.append(group)
        groupMemberships[group.id] = []
        return group
    }

    private func editableGroup(_ id: String) throws -> MemberGroup {
        guard let group = groups.first(where: { $0.id == id }) else { throw GroupError.missingGroup }
        guard group.source == .manual else { throw GroupError.directoryManaged }
        return group
    }

    public func deleteGroup(_ groupID: String) async throws {
        _ = try editableGroup(groupID)
        groups.removeAll { $0.id == groupID }
        groupMemberships[groupID] = nil
        for space in Array(grants.keys) {
            grants[space]?.removeAll { $0.principalType == .group && $0.principalId == groupID }
        }
    }

    public func groupMembers(_ groupID: String) async throws -> [String] {
        guard groups.contains(where: { $0.id == groupID }) else { throw GroupError.missingGroup }
        return Array(groupMemberships[groupID] ?? []).sorted()
    }

    public func addGroupMember(_ userID: String, to groupID: String) async throws {
        _ = try editableGroup(groupID)
        guard members.contains(where: { $0.id == userID }) else { throw GroupError.missingMember }
        groupMemberships[groupID, default: []].insert(userID)
    }

    public func removeGroupMember(_ userID: String, from groupID: String) async throws {
        _ = try editableGroup(groupID)
        groupMemberships[groupID]?.remove(userID)
    }

    public func invite(_ request: InviteRequest) async throws -> InviteResult {
        try? await Task.sleep(for: .milliseconds(250))
        let email = request.normalizedEmail
        let id = "inv-\(UUID().uuidString.prefix(8))"
        // Provision an inactive-looking pending member so the directory reflects the
        // invite immediately (matches the backend's create-on-redeem story closely
        // enough for the offline demo).
        let newMember = OrgMember(
            id: "usr-\(UUID().uuidString.prefix(8))",
            email: email,
            displayName: email.split(separator: "@").first.map(String.init) ?? email,
            role: request.role, status: .active)
        if !members.contains(where: { $0.email == email }) {
            members.append(newMember)
        }
        return InviteResult(
            inviteId: id, email: email, role: request.role,
            rawToken: "\(id).\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))",
            expiresAt: Date().addingTimeInterval(7 * 86_400))
    }

    public func setRole(_ role: OrgRole, forMember memberID: String) async throws {
        guard let idx = members.firstIndex(where: { $0.id == memberID }) else { return }
        members[idx].role = role
    }

    public func suspendMember(_ memberID: String) async throws {
        guard let idx = members.firstIndex(where: { $0.id == memberID }) else { return }
        members[idx].status = .suspended
    }

    public func reactivateMember(_ memberID: String) async throws {
        guard let idx = members.firstIndex(where: { $0.id == memberID }) else { return }
        members[idx].status = .active
    }

    public func deprovisionMember(_ memberID: String) async throws {
        guard let idx = members.firstIndex(where: { $0.id == memberID }) else { return }
        members[idx].status = .deprovisioned
    }

    public func listManagedFolders(in filespaceID: String, parentID: String, cursor: String?) async throws -> DirectoryPage {
        guard meRole.canManageFilespaceSettings else { return DirectoryPage(items: [], cursor: nil) }
        return try await listDirectory(in: filespaceID, parentID: parentID, cursor: cursor)
    }

    public func accessManagement(in filespaceID: String) async throws -> FolderAdministration {
        guard meRole.canManageFilespaceSettings else { return FolderAdministration() }
        let rows = (grants[filespaceID] ?? []).map { original in
            var grant = original; grant.canModify = true; grant.active = true; return grant
        }
        return FolderAdministration(canManageAccess: true, canDelegateAdmin: true,
                                    canManageWorkspace: meRole.canMutateMembers,
                                    roots: [ManagedFolder(inodeId: "root", name: "Filespace", path: "/")],
                                    grants: rows, members: members, groups: groups)
    }

    public func mountRootIds(in filespaceID: String) async throws -> [String] { ["root"] }

    public func listGrants(in filespaceID: String) async throws -> [AccessGrant] {
        grants[filespaceID] ?? []
    }

    public func setGrant(_ request: GrantRequest, in filespaceID: String) async throws -> AccessGrant {
        try? await Task.sleep(for: .milliseconds(200))
        var list = grants[filespaceID] ?? []
        // One grant per (inode, principal) — adding the same principal again updates
        // the level in place (mirrors the backend's upsert-on-POST semantics).
        if let idx = list.firstIndex(where: {
            $0.inodeId == request.inodeId
                && $0.principalType == request.principalType
                && $0.principalId == request.principalId
        }) {
            list[idx].level = request.level
            list[idx].mountAsRoot = request.mountAsRoot
            list[idx].expiresAt = request.expiresAt
            list[idx].inodePath = request.inodePath
            list[idx].principalLabel = request.principalLabel
            grants[filespaceID] = list
            return list[idx]
        }
        let grant = AccessGrant(
            id: "grant-\(UUID().uuidString.prefix(8))",
            inodeId: request.inodeId, inodePath: request.inodePath,
            principalType: request.principalType, principalId: request.principalId,
            principalLabel: request.principalLabel, level: request.level,
            mountAsRoot: request.mountAsRoot, expiresAt: request.expiresAt)
        list.append(grant)
        grants[filespaceID] = list
        return grant
    }

    public func removeGrant(_ grant: AccessGrant, in filespaceID: String) async throws {
        grants[filespaceID]?.removeAll { $0.id == grant.id }
    }
}
