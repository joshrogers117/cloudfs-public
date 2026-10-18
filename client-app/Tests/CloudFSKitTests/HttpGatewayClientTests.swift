// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Exercises HttpGatewayClient against StubURLProtocol with responses shaped per
// backend/API.md. No live server required.

@Suite(.serialized) struct HttpGatewayClientTests {

    private func makeClient(token: String = "tok-123", org: String = "acme") -> HttpGatewayClient {
        StubURLProtocol.reset()
        let cfg = GatewayConfig(baseURL: "https://gw.test", org: org, token: token)
        return HttpGatewayClient(config: cfg, session: .stubbed())
    }

    @Test func delegatedFolderCapabilitiesAndSafePathsDecodeWithoutWorkspacePromotion() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/access-management", json: #"{"canManageAccess":true,"canDelegateAdmin":false,"canManageWorkspace":false,"roots":[{"inodeId":"allowed","name":"Editorial","path":"/Editorial"}],"members":[{"id":"member","displayName":"Maya","email":"maya@example.test","role":"standard","status":"active","kind":"human"}],"groups":[{"id":"team","name":"Editors"}],"grants":[{"id":"grant","inodeId":"allowed","inodePath":"/Editorial","principalType":"user","principalId":"member","principalLabel":"Maya","level":"edit","canModify":true,"active":true},{"id":"protected","inodeId":"allowed","inodePath":"/Editorial","principalType":"group","principalId":"team","level":"admin","canModify":false,"active":true}]}"#)
        let access = try await client.accessManagement(in: "fs")
        #expect(access.canManageAccess && !access.canDelegateAdmin && !access.canManageWorkspace)
        #expect(access.grantableLevels == [.read, .edit])
        #expect(access.roots.map(\.inodeId) == ["allowed"])
        #expect(access.members.first?.role == .standard)
        #expect(access.grants.first?.principalLabel == "Maya")
        #expect(access.canModify(access.grants[0]))
        #expect(!access.canModify(access.grants[1]))
    }

    @Test func folderAdministrationFailsClosedWithoutCapabilityFields() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/access-management", json: #"{"grants":[]}"#)
        await #expect(throws: (any Error).self) { _ = try await client.accessManagement(in: "fs") }
    }

    @Test func delegatedFolderPickerUsesScopedEndpointAndPreservesCursor() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/access-management", json: #"{"items":[{"id":"child","name":"Dailies","isDir":true,"size":0}],"cursor":"next+cursor"}"#)
        let page = try await client.listManagedFolders(in: "fs", parentID: "allowed", cursor: "first/cursor")
        #expect(page.items.map(\.id) == ["child"])
        #expect(page.cursor == "next+cursor")
        let url = try #require(StubURLProtocol.requests.last?.url)
        let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        #expect(query?.first { $0.name == "parent" }?.value == "allowed")
        #expect(query?.first { $0.name == "cursor" }?.value == "first/cursor")
    }

    @Test func nativeCreationUsesConfiguredWorkspaceStorageWithoutCredentials() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/orgs/acme/storage/default", json: #"{"configured":true,"provider":"r2","region":"auto","bucket":"workspace","problems":[]}"#)
        StubURLProtocol.on("POST /v1/orgs/acme/spaces", json: #"{"id":"new-space","name":"Editorial"}"#)
        let storage = try await client.workspaceStorage()
        #expect(storage.providerLabel == "Cloudflare R2")
        #expect(try await client.createWorkspaceFilespace(name: " Editorial ", storage: storage) == "new-space")
        let data = try #require(StubURLProtocol.body(for: "POST /v1/orgs/acme/spaces"))
        let body = try #require(JSONSerialization.jsonObject(with: data) as? [String: String])
        #expect(body == ["name": "Editorial", "storageMode": "deployment", "region": "auto", "storageBackend": "Cloudflare R2"])
    }

    @Test func nativeCreationRejectsInvalidNameOrUnconfiguredStorageWithoutSubmitting() async {
        let client = makeClient()
        let storage = WorkspaceStorage(configured: true, provider: "r2", region: "auto", bucket: "workspace")
        await #expect(throws: (any Error).self) { _ = try await client.createWorkspaceFilespace(name: "  ", storage: storage) }
        await #expect(throws: (any Error).self) { _ = try await client.createWorkspaceFilespace(name: String(repeating: "a", count: 101), storage: storage) }
        let missing = WorkspaceStorage(configured: false, provider: "r2", region: "auto", bucket: "")
        await #expect(throws: (any Error).self) { _ = try await client.createWorkspaceFilespace(name: "Editorial", storage: missing) }
        #expect(StubURLProtocol.requests.isEmpty)
    }

    // MARK: Auth + reachability

    @Test func connectHitsHealthThenSpacesWithBearer() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/health", json: #"{"ok":true}"#)
        StubURLProtocol.on("GET /v1/orgs/acme/spaces",
            json: #"[{"id":"active-edit","name":"Active Edit","region":"ENAM","storageBackend":"Cloudflare R2","role":"Admin","usedBytes":1024,"memberCount":12}]"#)

        let spaces = try await client.connect(.serviceToken(token: "tok-123"))
        #expect(spaces.count == 1)
        #expect(spaces.first?.id == "active-edit")
        #expect(spaces.first?.role == .admin)

        // The spaces request must carry the bearer token.
        let spacesReq = StubURLProtocol.requests.first { $0.url?.path == "/v1/orgs/acme/spaces" }
        #expect(spacesReq?.value(forHTTPHeaderField: "Authorization") == "Bearer tok-123")
        // health is public (no auth required).
        let healthReq = StubURLProtocol.requests.first { $0.url?.path == "/v1/health" }
        #expect(healthReq != nil)
    }

    @Test func spacesDecodeServerRoleAndUsedBytesWhenPresent() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/orgs/acme/spaces",
            json: #"{"spaces":[{"id":"a","name":"A","role":"owner","usedBytes":2048},{"id":"b","name":"B","role":"space_admin","usedBytes":0},{"id":"c","name":"C","role":"folder_admin"}]}"#)
        let spaces = try await client.filespaces()
        #expect(spaces.map(\.role) == [.owner, .filespaceAdmin, .standard])
        #expect(spaces.allSatisfy { $0.roleReported })
        #expect(spaces[0].usedBytes == 2048)
        #expect(spaces[0].storageDisplay == ByteFormat.string(2048))
        #expect(spaces[1].storageDisplay == ByteFormat.string(0))   // zero is real, not "unavailable"
    }

    @Test func spacesWithoutRoleOrUsageDeriveRoleFromOrgRoleAndShowNotAvailable() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/orgs/acme/spaces", json: #"{"spaces":[{"id":"new","name":"Production"}]}"#)
        let space = try #require(try await client.filespaces().first)
        #expect(!space.roleReported)
        #expect(space.usedBytes < 0)
        #expect(space.storageDisplay == "Not available")
        #expect(space.displayRole(orgRole: .owner) == .owner)
        #expect(space.displayRole(orgRole: .spaceAdmin) == .filespaceAdmin)
        #expect(space.displayRole(orgRole: .standard) == .standard)
        #expect(space.displayRole(orgRole: nil) == .standard)
        // A server-reported role always wins over the org role.
        var reported = space; reported.roleReported = true; reported.role = .filespaceAdmin
        #expect(reported.displayRole(orgRole: .owner) == .filespaceAdmin)
    }

    @Test func memberRoleWireMapping() {
        #expect(MemberRole.fromWire("OWNER") == .owner)
        #expect(MemberRole.fromWire("Filespace Admin") == .filespaceAdmin)
        #expect(MemberRole.fromWire("folder_admin") == .standard)
        #expect(MemberRole.fromWire(nil) == nil)
        #expect(MemberRole.fromWire("bogus") == nil)
    }

    @Test func emptyWorkspaceRegistryIsValidAndDoesNotInventMounts() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/orgs/acme/spaces", json: #"{"spaces":[]}"#)
        #expect(try await client.filespaces().isEmpty)
        StubURLProtocol.on("GET /v1/orgs/acme/spaces", json: #"{"spaces":[{"id":"new","name":"Production"}]}"#)
        let space = try #require(try await client.filespaces().first)
        #expect(space.connection == .disconnected)
        #expect(space.mountPath.isEmpty)
    }

    @Test func folderPickerPreservesOpaqueCursorAndIgnoresDeletedItems() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/fs/items", json: #"{"items":[{"id":"a","name":"Projects","isDir":true,"size":0},{"id":"b","name":"Deleted","isDir":true,"size":0,"deleted":true}],"cursor":"page+2/=cursor"}"#)
        let page = try await client.listDirectory(in: "fs", parentID: "parent/id", cursor: "first+cursor")
        #expect(page.items.map(\.name) == ["Projects"])
        #expect(page.cursor == "page+2/=cursor")
        let url = try #require(StubURLProtocol.requests.last?.url)
        let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems
        #expect(query?.first(where: { $0.name == "parent" })?.value == "parent/id")
        #expect(query?.first(where: { $0.name == "cursor" })?.value == "first+cursor")
    }

    @Test func invitePreservesDeliveryStatusAndQualifiedJoinToken() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/orgs/acme/invites", status: 201,
                           json: #"{"rawToken":"inv.secret","joinToken":"acme.inv.secret","emailSent":false,"invite":{"id":"inv","email":"new@acme.tv","role":"standard"}}"#)
        let invite = try await client.invite(.init(email: "new@acme.tv", role: .standard))
        #expect(!invite.emailSent)
        #expect(invite.joinToken == "acme.inv.secret")
    }

    @Test func groupRegistryDoesNotInventMembershipCounts() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/orgs/acme/groups", json: #"[{"id":"grp-1","name":"Editorial","source":"manual"},{"id":"grp-2","name":"Company","source":"scim"}]"#)
        let groups = try await client.listGroups()
        #expect(groups.count == 2)
        #expect(groups[0].memberCount == -1)
        #expect(groups[1].source == .scim)
        StubURLProtocol.on("GET /v1/orgs/acme/groups", json: #"{"groups":[]}"#)
        #expect(try await client.listGroups().isEmpty)
    }

    @Test func malformedGroupRegistryFailsVisibly() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/orgs/acme/groups", json: #"{"unexpected":true}"#)
        await #expect(throws: (any Error).self) { _ = try await client.listGroups() }
    }

    @Test func createAndDeleteGroupUseBackendContract() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/orgs/acme/groups", status: 201, json: #"{"id":"grp-new","name":"Editorial","source":"manual"}"#)
        let group = try await client.createGroup(name: "  Editorial  ")
        #expect(group.id == "grp-new")
        #expect(group.memberCount == 0)
        let body = try #require(StubURLProtocol.body(for: "POST /v1/orgs/acme/groups"))
        let object = try #require(JSONSerialization.jsonObject(with: body) as? [String: String])
        #expect(object == ["name": "Editorial", "source": "manual"])
        StubURLProtocol.on("DELETE /v1/orgs/acme/groups/grp-new", json: #"{"ok":true}"#)
        try await client.deleteGroup(group.id)
        #expect(StubURLProtocol.requests.last?.httpMethod == "DELETE")
    }

    @Test func groupMembershipUsesIDsBodyAndQuery() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/orgs/acme/groups/grp-1/members", json: #"["usr-a","usr-b"]"#)
        #expect(try await client.groupMembers("grp-1") == ["usr-a", "usr-b"])
        StubURLProtocol.on("POST /v1/orgs/acme/groups/grp-1/members", json: #"{"ok":true}"#)
        try await client.addGroupMember("usr+c/=d", to: "grp-1")
        let body = try #require(StubURLProtocol.body(for: "POST /v1/orgs/acme/groups/grp-1/members"))
        #expect((try JSONSerialization.jsonObject(with: body) as? [String: String]) == ["userId": "usr+c/=d"])
        StubURLProtocol.on("DELETE /v1/orgs/acme/groups/grp-1/members", json: #"{"ok":true}"#)
        try await client.removeGroupMember("usr+c/=d", from: "grp-1")
        let url = try #require(StubURLProtocol.requests.last?.url)
        #expect(URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first?.value == "usr+c/=d")
    }

    // MARK: Error envelope decoding

    @Test func errorEnvelopeIsDecoded() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/health", json: #"{"ok":true}"#)
        StubURLProtocol.on("GET /v1/orgs/acme/spaces", status: 403,
            json: #"{"error":"cross_tenant","reason":"org mismatch"}"#)
        await #expect(throws: HttpGatewayClient.GatewayError.self) {
            _ = try await client.filespaces()
        }
        do {
            _ = try await client.filespaces()
            Issue.record("expected throw")
        } catch let HttpGatewayClient.GatewayError.http(status, code, reason) {
            #expect(status == 403)
            #expect(code == "cross_tenant")
            #expect(reason == "org mismatch")
        }
    }

    @Test func unauthorizedMapsToHttp401() async throws {
        let client = makeClient(token: "")
        StubURLProtocol.on("GET /v1/orgs/acme/spaces", status: 401,
            json: #"{"error":"no_token"}"#)
        do {
            _ = try await client.filespaces()
            Issue.record("expected throw")
        } catch let HttpGatewayClient.GatewayError.http(status, code, _) {
            #expect(status == 401)
            #expect(code == "no_token")
        }
    }

    // NOTE: the live Finder-like browse path (`listFiles` + cursor pagination) was
    // removed in WS1. The snapshot dir path (`listSnapshotFiles`) below still
    // exercises the WireItem decode + deleted-filter + fileNode mapping.

    // MARK: Snapshots

    @Test func snapshotsDecodeAndMap() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/active-edit/snapshots",
            json: #"[{"id":"snap-1","label":"Hourly 14:00","tier":"Hourly","createdAt":1700000000000,"scheduleId":"sched-a"},{"id":"snap-2","label":"Manual","tier":"Manual","createdAt":1700000000000}]"#)
        let snaps = try await client.snapshots(in: "active-edit")
        #expect(snaps.count == 2)
        #expect(snaps[0].isScheduled == true)
        #expect(snaps[1].isScheduled == false)
        #expect(snaps[0].retentionTier == "Hourly")
    }

    @Test func snapshotDirSendsParentRoot() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/active-edit/snapshots/snap-1/dir",
            json: #"[{"id":"a","parent":"root","name":"as-of","isDir":true,"size":0,"contentVersion":"x","etag":null,"version":1,"updatedSeq":1,"deleted":false}]"#)
        let files = try await client.listSnapshotFiles(snapshotID: "snap-1", in: "active-edit", parentID: nil)
        #expect(files.first?.name == "as-of")
        let req = StubURLProtocol.requests.first { $0.url?.path.hasSuffix("/snapshots/snap-1/dir") == true }
        let q = URLComponents(url: req!.url!, resolvingAgainstBaseURL: false)?.queryItems
        #expect(q?.contains { $0.name == "parent" && $0.value == "root" } == true)
    }

    // MARK: Activity (audit → ActivityEvent)

    @Test func auditMapsToActivity() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/active-edit/audit",
            json: #"[{"seq":5,"ts":1700000000000,"actorSub":"mara","action":"locked","decision":"allow","path":"ShowA/timeline.prproj"}]"#)
        let events = try await client.recentActivity(in: "active-edit", limit: 25)
        #expect(events.count == 1)
        #expect(events.first?.actor == "mara")
        #expect(events.first?.verb == "locked")
        #expect(events.first?.path == "ShowA/timeline.prproj")
        // limit query is forwarded.
        let req = StubURLProtocol.requests.first { $0.url?.path.hasSuffix("/audit") == true }
        let q = URLComponents(url: req!.url!, resolvingAgainstBaseURL: false)?.queryItems
        #expect(q?.contains { $0.name == "limit" && $0.value == "25" } == true)
    }

    // MARK: Live activity (GET …/activity/live, CONTRACTS §5.3)

    @Test func liveActivityDecodesTransfersAndBulkRollup() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/active-edit/activity/live", json: #"""
        {"transfers":[{"id":"t-91","path":"projectA/render.mov","direction":"upload","bytesDone":4194304,"bytesTotal":16777216,"state":"active"}],
         "events":[
           {"seq":12050,"type":"modify","path":"projectA/edit.prproj","actor":"alice@acme","ts":1749350400000,"kind":"single"},
           {"seq":12051,"type":"delete","path":"projectA/cache/","actor":"bob@acme","ts":1749350460000,"kind":"bulk","op":"large-delete","count":4203}
         ]}
        """#)
        let live = try await client.liveActivity(in: "active-edit")
        // Transfers map onto the GUI Transfer model.
        #expect(live.transfers.count == 1)
        #expect(live.transfers.first?.id == "t-91")
        #expect(live.transfers.first?.kind == .upload)
        #expect(live.transfers.first?.state == .active)
        #expect(live.transfers.first?.fileName == "render.mov")
        #expect(live.transfers.first?.bytesTotal == 16777216)
        // A single event stays .single.
        #expect(live.events.count == 2)
        let single = try #require(live.events.first { $0.id == "12050" })
        #expect(single.kind == .single)
        #expect(single.actor == "alice@acme")
        #expect(single.verb == "modify")
        // The bulk rollup carries op + count.
        let bulk = try #require(live.events.first { $0.id == "12051" })
        #expect(bulk.kind == .bulk)
        #expect(bulk.bulkOp == "large-delete")
        #expect(bulk.bulkCount == 4203)
        #expect(bulk.path == "projectA/cache/")
        // Bearer auth carried.
        let req = StubURLProtocol.requests.first { $0.url?.path.hasSuffix("/activity/live") == true }
        #expect(req?.value(forHTTPHeaderField: "Authorization") == "Bearer tok-123")
    }

    @Test func liveActivityToleratesEmptyPayload() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/active-edit/activity/live", json: #"{"transfers":[],"events":[]}"#)
        let live = try await client.liveActivity(in: "active-edit")
        #expect(live.transfers.isEmpty)
        #expect(live.events.isEmpty)
    }

    // MARK: Audit range paging (GET …/audit?since=&until=&cursor=&limit=, §5.4)

    @Test func auditRangeForwardsRangeAndPagesWhenFull() async throws {
        let client = makeClient()
        // Return a FULL page (limit == count) so a continuation cursor is emitted
        // at the lowest seq returned.
        StubURLProtocol.on("GET /v1/filespaces/active-edit/audit", json: #"""
        [{"seq":42,"ts":1749350400000,"actorSub":"mara","action":"modify","decision":"allow","path":"ShowA/a.mov"},
         {"seq":40,"ts":1749350300000,"actorSub":"leo","action":"delete","decision":"allow","path":"ShowA/b.mov"}]
        """#)
        let since = Date(timeIntervalSince1970: 1_749_000_000)
        let until = Date(timeIntervalSince1970: 1_749_400_000)
        let page = try await client.auditRange(in: "active-edit", since: since, until: until, cursor: nil, limit: 2)
        #expect(page.events.count == 2)
        #expect(page.events.first?.actor == "mara")
        // Full page → cursor is the lowest seq (40).
        #expect(page.cursor == "40")
        // Query params forwarded.
        let req = StubURLProtocol.requests.first { $0.url?.path.hasSuffix("/audit") == true }
        let q = URLComponents(url: req!.url!, resolvingAgainstBaseURL: false)?.queryItems ?? []
        #expect(q.contains { $0.name == "limit" && $0.value == "2" })
        #expect(q.contains { $0.name == "since" && $0.value == String(Int(since.timeIntervalSince1970 * 1000)) })
        #expect(q.contains { $0.name == "until" && $0.value == String(Int(until.timeIntervalSince1970 * 1000)) })
    }

    @Test func auditRangeShortPageEndsWithNilCursor() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/active-edit/audit", json: #"""
        [{"seq":7,"ts":1749350400000,"actorSub":"mara","action":"locked","decision":"allow","path":"x"}]
        """#)
        let page = try await client.auditRange(in: "active-edit", since: nil, until: nil, cursor: nil, limit: 50)
        #expect(page.events.count == 1)
        #expect(page.cursor == nil)   // short page → end of history
    }

    @Test func auditRangeForwardsCursor() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/filespaces/active-edit/audit", json: "[]")
        _ = try await client.auditRange(in: "active-edit", since: nil, until: nil, cursor: "40", limit: 10)
        let req = StubURLProtocol.requests.first { $0.url?.path.hasSuffix("/audit") == true }
        let q = URLComponents(url: req!.url!, resolvingAgainstBaseURL: false)?.queryItems ?? []
        #expect(q.contains { $0.name == "cursor" && $0.value == "40" })
    }

    // MARK: Manual snapshot create (POST …/snapshots, §6.3)

    @Test func createSnapshotPostsLabelAndDecodes201() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/active-edit/snapshots", status: 201, json: #"""
        {"id":"snap-new","label":"Before color pass","scope":"root","seqAnchor":12044,"tier":"Manual","createdAt":1749350400000,"immutableUntil":null,"scheduleId":null}
        """#)
        let snap = try await client.createSnapshot(label: "Before color pass", scope: nil, tier: nil, in: "active-edit")
        #expect(snap.id == "snap-new")
        #expect(snap.name == "Before color pass")
        #expect(snap.isScheduled == false)        // scheduleId null → manual
        #expect(snap.retentionTier == "Manual")
        // POST with bearer auth; body carries label and OMITS id (DO mints it).
        let key = "POST /v1/filespaces/active-edit/snapshots"
        let req = StubURLProtocol.requests.first { $0.url?.path == "/v1/filespaces/active-edit/snapshots" && $0.httpMethod == "POST" }
        #expect(req?.value(forHTTPHeaderField: "Authorization") == "Bearer tok-123")
        let bodyData = StubURLProtocol.body(for: key)
        let body = try #require(bodyData.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] })
        #expect(body["label"] as? String == "Before color pass")
        #expect(body["id"] == nil)
    }

    @Test func createSnapshotOmitsNilFields() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/active-edit/snapshots", status: 201, json: #"""
        {"id":"snap-x","label":null,"scope":null,"seqAnchor":1,"tier":null,"createdAt":1749350400000,"immutableUntil":null,"scheduleId":null}
        """#)
        let snap = try await client.createSnapshot(label: nil, scope: nil, tier: nil, in: "active-edit")
        #expect(snap.id == "snap-x")
        #expect(snap.retentionTier == "Manual")   // tier null → "Manual" default
        let bodyData = StubURLProtocol.body(for: "POST /v1/filespaces/active-edit/snapshots")
        let body = try #require(bodyData.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] })
        #expect(body.isEmpty)   // no label/scope/tier → empty body, DO uses defaults
    }

    // MARK: Sharing

    @Test func guestShareLinkPostsToOrgShares() async throws {
        let client = makeClient()
        // Audit (Mac share-create decode): the backend returns the NESTED envelope
        // `{ share: ShareLinkRecord, rawToken, shareUrl }` — the id/expiry live under
        // `share.*` and the browser URL is the top-level `shareUrl`. The old decode read
        // a flat `{id,url}` and always got an empty id + empty URL.
        StubURLProtocol.on("POST /v1/orgs/acme/shares",
            json: #"{"share":{"id":"shr-1","spaceId":"active-edit","inodeId":"ino-clip","level":"read","expiresAt":1700600000000},"rawToken":"shr-1.secret","shareUrl":"https://share.test/g/abc"}"#)
        let link = try await client.createShareLink(for: "ino-clip", kind: .guestLink, in: "active-edit")
        #expect(link.kind == .guestLink)
        #expect(link.id == "shr-1")              // from share.id (nested), not the empty top level
        #expect(link.url == "https://share.test/g/abc") // from the top-level shareUrl
        #expect(link.expiresAt != nil)
        #expect(link.canDownload == true && link.canEdit == false) // level "read" → download only
        let req = StubURLProtocol.requests.first { $0.url?.path == "/v1/orgs/acme/shares" }
        #expect(req?.httpMethod == "POST")
        #expect(req?.value(forHTTPHeaderField: "Authorization") == "Bearer tok-123")
    }

    @Test func internalLinkIsBuiltLocallyNoNetwork() async throws {
        let client = makeClient()
        let link = try await client.createShareLink(for: "ino-timeline",
                                                    kind: .internalDeepLink, in: "active-edit")
        #expect(link.kind == .internalDeepLink)
        #expect(link.url == "cloudfs://item/active-edit/ino-timeline")
        let root = try await client.createShareLink(for: "", kind: .internalDeepLink, in: "active-edit")
        #expect(root.url == "cloudfs://active-edit")
        // No network call was made for an internal deep link.
        #expect(StubURLProtocol.requests.isEmpty)
    }

    @Test func revokeShareDeletesById() async throws {
        let client = makeClient()
        StubURLProtocol.on("DELETE /v1/orgs/acme/shares/sh-9", json: #"{"revoked":1}"#)
        try await client.revokeShareLink("sh-9", in: "active-edit")
        let req = StubURLProtocol.requests.first { $0.url?.path == "/v1/orgs/acme/shares/sh-9" }
        #expect(req?.httpMethod == "DELETE")
    }

    @Test func shareLinksListDecodes() async throws {
        let client = makeClient()
        // Audit (Mac share-list decode): the LIST route returns bare `ShareLinkRecord`s
        // carrying `inodeId`/`level`/`expiresAt` (epoch-ms) — NOT a flat `path`/`url`/
        // `canDownload`. The old decode read those absent fields and produced an empty
        // path + the wrong perms. The path is surfaced as `/<inodeId>` (opaque).
        StubURLProtocol.on("GET /v1/orgs/acme/shares",
            json: #"{"shares":[{"id":"shr-1","spaceId":"active-edit","inodeId":"ino-x","level":"edit","expiresAt":1700600000000}]}"#)
        let links = try await client.shareLinks(in: "active-edit")
        #expect(links.count == 1)
        #expect(links.first?.id == "shr-1")
        #expect(links.first?.path == "/ino-x")
        #expect(links.first?.canEdit == true) // level "edit"
        // The list is scoped to this filespace via ?spaceId= (FINDING 6).
        let req = StubURLProtocol.requests.first { $0.url?.path == "/v1/orgs/acme/shares" }
        #expect(req?.url?.query?.contains("spaceId=active-edit") == true)
    }

    @Test func listGrantsDecodesFromFilespaceGrantsRoute() async throws {
        let client = makeClient()
        // Audit B28: the gateway now exposes GET /v1/filespaces/:fs/grants. The old
        // listGrants returned [] (the route 404'd before B28), so the Members & Access
        // tab rendered empty even when grants existed. Enumerate the real grants.
        StubURLProtocol.on("GET /v1/filespaces/active-edit/grants",
            json: #"{"grants":[{"inodeId":"ino-foot","principalType":"group","principalId":"grp-ed","level":"edit","mountAsRoot":true,"expiresAt":null},{"inodeId":"root","principalType":"user","principalId":"usr-1","level":"admin","mountAsRoot":false,"expiresAt":1700600000000}]}"#)
        let grants = try await client.listGrants(in: "active-edit")
        #expect(grants.count == 2)
        #expect(grants.first?.inodeId == "ino-foot")
        #expect(grants.first?.principalType == .group)
        #expect(grants.first?.level == .edit)
        #expect(grants.first?.mountAsRoot == true)
        #expect(grants.first?.expiresAt == nil)
        #expect(grants.last?.inodePath == "/")          // root → "/"
        #expect(grants.last?.level == .admin)
        #expect(grants.last?.expiresAt != nil)
    }

    // MARK: Engine-only operations are reported as unsupported (not silent)

    @Test func cacheOpsThrowUnsupported() async throws {
        let client = makeClient()
        await #expect(throws: HttpGatewayClient.GatewayError.self) {
            try await client.setPinned(true, fileID: "a", in: "active-edit")
        }
        await #expect(throws: HttpGatewayClient.GatewayError.self) {
            _ = try await client.cacheSettings(for: "active-edit")
        }
    }

    // MARK: Snapshot restore (POST …/snapshots/:id/restore)

    @Test(.timeLimit(.minutes(1))) func restorePostsPathAndDecodesResult() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/active-edit/snapshots/snap-7/restore",
            json: #"""
            {"snapshotId":"snap-7","restored":["ShowA/clip.mov"],"recreated":["ShowA/deleted.mov"],"conflicts":[],"newerThanSnapshot":["ShowA/new.mov"]}
            """#)

        let result = try await client.restore(path: "ShowA/clip.mov", recursive: false,
                                              fromSnapshot: "snap-7", in: "active-edit")
        #expect(result.snapshotId == "snap-7")
        #expect(result.restored == ["ShowA/clip.mov"])
        #expect(result.recreated == ["ShowA/deleted.mov"])
        #expect(result.newerThanSnapshot == ["ShowA/new.mov"])
        #expect(result.hasConflicts == false)
        #expect(result.totalApplied == 2)

        // Verify the request: POST, bearer auth, and body { path, recursive }.
        let key = "POST /v1/filespaces/active-edit/snapshots/snap-7/restore"
        let req = StubURLProtocol.requests.first {
            $0.url?.path == "/v1/filespaces/active-edit/snapshots/snap-7/restore"
        }
        #expect(req?.httpMethod == "POST")
        #expect(req?.value(forHTTPHeaderField: "Authorization") == "Bearer tok-123")
        let bodyData = StubURLProtocol.body(for: key)
        let body = try #require(bodyData.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] })
        #expect(body["path"] as? String == "ShowA/clip.mov")
        #expect(body["recursive"] as? Bool == false)
    }

    @Test(.timeLimit(.minutes(1))) func restoreRecursiveSendsRecursiveTrue() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/active-edit/snapshots/snap-7/restore",
            json: #"{"snapshotId":"snap-7","restored":["dir"],"recreated":[],"conflicts":[],"newerThanSnapshot":[]}"#)
        _ = try await client.restore(path: "dir", recursive: true, fromSnapshot: "snap-7", in: "active-edit")
        let bodyData = StubURLProtocol.body(for: "POST /v1/filespaces/active-edit/snapshots/snap-7/restore")
        let body = try #require(bodyData.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] })
        #expect(body["recursive"] as? Bool == true)
    }

    @Test(.timeLimit(.minutes(1))) func restoreLockConflict409Throws() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/active-edit/snapshots/snap-7/restore",
            status: 409, json: #"{"error":"locked","reason":"all targets exclusively leased"}"#)
        do {
            _ = try await client.restore(path: "p", recursive: false, fromSnapshot: "snap-7", in: "active-edit")
            Issue.record("expected throw on 409")
        } catch let HttpGatewayClient.GatewayError.http(status, code, _) {
            #expect(status == 409)
            #expect(code == "locked")
        }
    }

    @Test(.timeLimit(.minutes(1))) func restoreSurfacesConflictsInResult() async throws {
        let client = makeClient()
        // Partial success: some restored, some skipped because locked by another.
        StubURLProtocol.on("POST /v1/filespaces/active-edit/snapshots/snap-7/restore",
            json: #"""
            {"snapshotId":"snap-7","restored":["a"],"recreated":[],"conflicts":[{"id":"b","heldBy":"mara"}],"newerThanSnapshot":[]}
            """#)
        let result = try await client.restore(path: "dir", recursive: true, fromSnapshot: "snap-7", in: "active-edit")
        #expect(result.hasConflicts)
        #expect(result.conflicts.first?.id == "b")
        #expect(result.conflicts.first?.heldBy == "mara")
    }

    @Test(.timeLimit(.minutes(1))) func restoreUnknownSnapshot404Throws() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/active-edit/snapshots/nope/restore",
            status: 404, json: #"{"error":"not found","reason":"unknown snapshot"}"#)
        do {
            _ = try await client.restore(path: "p", recursive: false, fromSnapshot: "nope", in: "active-edit")
            Issue.record("expected throw on 404")
        } catch let HttpGatewayClient.GatewayError.http(status, _, _) {
            #expect(status == 404)
        }
    }

    // MARK: Members & Access (users / invites / grants — backend §org-multi-user + §grants)

    @Test func currentUserRoleReadsAuthMe() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/auth/me",
            json: #"{"userId":"u1","orgId":"acme","email":"a@b.c","role":"space_admin"}"#)
        #expect(try await client.currentUserRole() == .spaceAdmin)
    }

    @Test func currentUserRoleFailsClosedOnUnknownRole() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/auth/me", json: #"{"userId":"u1"}"#)
        // Absent role → standard (the Members section stays hidden).
        #expect(try await client.currentUserRole() == .standard)
    }

    @Test func listMembersDecodesUsersAndServiceAccounts() async throws {
        let client = makeClient()
        StubURLProtocol.on("GET /v1/orgs/acme/users",
            json: #"""
            [{"id":"usr-1","email":"mara@acme.tv","displayName":"Mara Patel","role":"admin","status":"active","kind":"human","createdAt":1700000000000},
             {"id":"svc-1","email":"render@svc.acme","displayName":"Render Farm","role":"standard","status":"suspended","kind":"service_account","createdAt":1700000000000}]
            """#)
        let members = try await client.listMembers()
        #expect(members.count == 2)
        #expect(members[0].role == .admin)
        #expect(members[0].status == .active)
        #expect(members[1].isServiceAccount)
        #expect(members[1].status == .suspended)
    }

    @Test func inviteSendsEmailAndRoleAndReturnsRawToken() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/orgs/acme/invites", status: 201,
            json: #"{"rawToken":"inv-abc.secret","invite":{"id":"inv-abc","email":"new@acme.tv","role":"standard","expiresAt":1700604800000}}"#)
        let result = try await client.invite(InviteRequest(email: "new@acme.tv", role: .standard))
        #expect(result.inviteId == "inv-abc")
        #expect(result.rawToken == "inv-abc.secret")
        #expect(result.role == .standard)

        let body = StubURLProtocol.body(for: "POST /v1/orgs/acme/invites").flatMap {
            try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
        }
        #expect(body?["email"] as? String == "new@acme.tv")
        #expect(body?["role"] as? String == "standard")
    }

    @Test func setRoleSendsPatchWithRoleBody() async throws {
        let client = makeClient()
        StubURLProtocol.on("PATCH /v1/orgs/acme/users/usr-1", json: #"{"id":"usr-1","role":"admin"}"#)
        try await client.setRole(.admin, forMember: "usr-1")
        let body = StubURLProtocol.body(for: "PATCH /v1/orgs/acme/users/usr-1").flatMap {
            try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
        }
        #expect(body?["role"] as? String == "admin")
    }

    @Test func suspendAndDeprovisionHitTheRightRoutes() async throws {
        let client = makeClient()
        StubURLProtocol.on("PATCH /v1/orgs/acme/users/usr-1", json: #"{"id":"usr-1","status":"suspended"}"#)
        StubURLProtocol.on("DELETE /v1/orgs/acme/users/usr-2", json: #"{"id":"usr-2","status":"deprovisioned"}"#)
        try await client.suspendMember("usr-1")
        try await client.deprovisionMember("usr-2")
        let suspendBody = StubURLProtocol.body(for: "PATCH /v1/orgs/acme/users/usr-1").flatMap {
            try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
        }
        #expect(suspendBody?["status"] as? String == "suspended")
        #expect(StubURLProtocol.requests.contains { $0.url?.path == "/v1/orgs/acme/users/usr-2" && $0.httpMethod == "DELETE" })
    }

    @Test func setGrantPostsAclBodyAndReturnsId() async throws {
        let client = makeClient()
        StubURLProtocol.on("POST /v1/filespaces/active-edit/grants", status: 201,
            json: #"{"id":"grant-xyz"}"#)
        let g = try await client.setGrant(
            GrantRequest(inodeId: "node-1", inodePath: "Footage", principalType: .group,
                         principalId: "grp-color", principalLabel: "Color", level: .edit,
                         mountAsRoot: true), in: "active-edit")
        #expect(g.id == "grant-xyz")
        #expect(g.level == .edit)
        let body = StubURLProtocol.body(for: "POST /v1/filespaces/active-edit/grants").flatMap {
            try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
        }
        #expect(body?["inodeId"] as? String == "node-1")
        #expect(body?["principalType"] as? String == "group")
        #expect(body?["level"] as? String == "edit")
        #expect(body?["mountAsRoot"] as? Bool == true)
    }

    @Test func removeGrantSendsDeleteWithPrincipalQuery() async throws {
        let client = makeClient()
        StubURLProtocol.on("DELETE /v1/filespaces/active-edit/grants", json: #"{"revoked":1}"#)
        let grant = AccessGrant(id: "g", inodeId: "node-1", inodePath: "Footage",
                                principalType: .user, principalId: "usr-9", principalLabel: "Sam",
                                level: .read)
        try await client.removeGrant(grant, in: "active-edit")
        let req = StubURLProtocol.requests.first {
            $0.url?.path == "/v1/filespaces/active-edit/grants" && $0.httpMethod == "DELETE"
        }
        let query = req?.url.flatMap { URLComponents(url: $0, resolvingAgainstBaseURL: false)?.queryItems } ?? []
        #expect(query.contains { $0.name == "inodeId" && $0.value == "node-1" })
        #expect(query.contains { $0.name == "principalType" && $0.value == "user" })
        #expect(query.contains { $0.name == "principalId" && $0.value == "usr-9" })
    }

    // MARK: Token provider + 401-retry-once (auth-spec C3 — device sessions)

    @Test func tokenProviderSuppliesBearerPerRequest() async throws {
        StubURLProtocol.reset()
        let cfg = GatewayConfig(baseURL: "https://gw.test", org: "acme", token: "")
        let client = HttpGatewayClient(config: cfg, session: .stubbed(),
                                       tokenProvider: { "provider-tok" })
        StubURLProtocol.on("GET /v1/orgs/acme/spaces", json: #"[]"#)
        _ = try await client.filespaces()
        let req = StubURLProtocol.requests.first { $0.url?.path == "/v1/orgs/acme/spaces" }
        #expect(req?.value(forHTTPHeaderField: "Authorization") == "Bearer provider-tok")
    }

    @Test func retriesOnceOn401WhenRecoveryProvidesFreshToken() async throws {
        StubURLProtocol.reset()
        let cfg = GatewayConfig(baseURL: "https://gw.test", org: "acme", token: "")
        let client = HttpGatewayClient(
            config: cfg, session: .stubbed(),
            tokenProvider: { "stale-tok" },
            unauthorizedRecovery: { "fresh-tok" })
        // First presentation of the stale token 401s; the recovered token passes.
        StubURLProtocol.on("GET /v1/orgs/acme/spaces") { req in
            if req.value(forHTTPHeaderField: "Authorization") == "Bearer fresh-tok" {
                return .init(status: 200, json: #"[]"#, headers: [:])
            }
            return .init(status: 401, json: #"{"error":"token_expired"}"#, headers: [:])
        }
        _ = try await client.filespaces()
        let calls = StubURLProtocol.requests.filter { $0.url?.path == "/v1/orgs/acme/spaces" }
        #expect(calls.count == 2)                              // exactly one retry
        #expect(calls.last?.value(forHTTPHeaderField: "Authorization") == "Bearer fresh-tok")
    }

    @Test func secondConsecutive401SurfacesNotLoops() async throws {
        StubURLProtocol.reset()
        let cfg = GatewayConfig(baseURL: "https://gw.test", org: "acme", token: "")
        let client = HttpGatewayClient(
            config: cfg, session: .stubbed(),
            tokenProvider: { "stale-tok" },
            unauthorizedRecovery: { "still-stale" })
        StubURLProtocol.on("GET /v1/orgs/acme/spaces", status: 401,
                           json: #"{"error":"token_expired"}"#)
        do {
            _ = try await client.filespaces()
            Issue.record("expected throw")
        } catch let HttpGatewayClient.GatewayError.http(status, code, _) {
            #expect(status == 401)
            #expect(code == "token_expired")
        }
        let calls = StubURLProtocol.requests.filter { $0.url?.path == "/v1/orgs/acme/spaces" }
        #expect(calls.count == 2)                              // one retry, then give up
    }

    @Test func no401RetryWithoutRecoveryHook() async throws {
        let client = makeClient()                              // fixed-token init: no hook
        StubURLProtocol.on("GET /v1/orgs/acme/spaces", status: 401,
                           json: #"{"error":"token_expired"}"#)
        await #expect(throws: HttpGatewayClient.GatewayError.self) {
            _ = try await client.filespaces()
        }
        let calls = StubURLProtocol.requests.filter { $0.url?.path == "/v1/orgs/acme/spaces" }
        #expect(calls.count == 1)
    }

    // MARK: DeviceAuthAPI wire shapes (auth-spec §2.3/§2.4/§2.7/§2.8)
    // Lives in this serialized suite because it shares StubURLProtocol's
    // process-wide route table.

    @Test func publicConfigDecodes() async throws {
        StubURLProtocol.reset()
        let api = DeviceAuthAPI(baseURL: "https://gw.test", session: .stubbed())
        StubURLProtocol.on("GET /v1/auth/config/public",
            json: #"{"mode":"builtin","oidcEnabled":false,"providerLabel":null,"webBaseUrl":"https://gw.test","productName":"cloud-fs"}"#)
        let cfg = try await api.publicConfig()
        #expect(cfg.mode == "builtin")
        #expect(cfg.webBaseUrl == "https://gw.test")
        // The probe is unauthenticated.
        let req = StubURLProtocol.requests.first { $0.url?.path == "/v1/auth/config/public" }
        #expect(req?.value(forHTTPHeaderField: "Authorization") == nil)
    }

    @Test func exchangePostsCodeAndVerifierAndDecodesSession() async throws {
        StubURLProtocol.reset()
        let api = DeviceAuthAPI(baseURL: "https://gw.test", session: .stubbed())
        StubURLProtocol.on("POST /v1/auth/device/token", status: 200, json: #"""
            {"refreshToken":"acme.dvt-1.sec","accessToken":"eyJ.access.1",
             "accessTtlSeconds":900,"orgId":"acme","orgName":"Acme Post",
             "account":{"email":"josh@acme.example","displayName":"Josh","role":"owner"},
             "device":{"id":"dev-1","name":"Josh's MacBook Pro"}}
            """#)
        let session = try await api.exchange(code: "acme.dac-1.s", codeVerifier: "ver-1")
        #expect(session.refreshToken == "acme.dvt-1.sec")
        #expect(session.accessToken == "eyJ.access.1")
        #expect(session.orgId == "acme")
        #expect(session.account?.email == "josh@acme.example")
        let body = try #require(StubURLProtocol.body(for: "POST /v1/auth/device/token"))
        let json = try #require(try JSONSerialization.jsonObject(with: body) as? [String: String])
        #expect(json["code"] == "acme.dac-1.s")
        #expect(json["codeVerifier"] == "ver-1")
    }

    @Test func refreshPostsTokenAndDecodesRotation() async throws {
        StubURLProtocol.reset()
        let api = DeviceAuthAPI(baseURL: "https://gw.test", session: .stubbed())
        StubURLProtocol.on("POST /v1/auth/device/refresh",
            json: #"{"refreshToken":"acme.dvt-1.next","accessToken":"eyJ.access.2","accessTtlSeconds":900}"#)
        let rotated = try await api.refresh(refreshToken: "acme.dvt-1.sec")
        #expect(rotated.refreshToken == "acme.dvt-1.next")
        #expect(rotated.accessToken == "eyJ.access.2")
        let body = try #require(StubURLProtocol.body(for: "POST /v1/auth/device/refresh"))
        let json = try #require(try JSONSerialization.jsonObject(with: body) as? [String: String])
        #expect(json["refreshToken"] == "acme.dvt-1.sec")
    }

    @Test func refreshErrorEnvelopeSurfacesTypedCode() async throws {
        StubURLProtocol.reset()
        let api = DeviceAuthAPI(baseURL: "https://gw.test", session: .stubbed())
        StubURLProtocol.on("POST /v1/auth/device/refresh", status: 401,
                           json: #"{"error":"refresh_reused"}"#)
        do {
            _ = try await api.refresh(refreshToken: "acme.dvt-1.stolen")
            Issue.record("expected throw")
        } catch let HttpGatewayClient.GatewayError.http(status, code, _) {
            #expect(status == 401)
            #expect(code == "refresh_reused")
        }
    }

    @Test func daemonTokenMintCarriesBearerAndDecodes() async throws {
        StubURLProtocol.reset()
        let api = DeviceAuthAPI(baseURL: "https://gw.test", session: .stubbed())
        StubURLProtocol.on("POST /v1/auth/device/daemon-token", status: 201, json: #"""
            {"id":"svc-1","token":"eyJ.daemon.1","expiresAt":1782600000000,
             "scopes":["fs:read","fs:write","fs:lock"]}
            """#)
        let minted = try await api.mintDaemonToken(accessToken: "eyJ.access.1")
        #expect(minted.token == "eyJ.daemon.1")
        #expect(minted.scopes == ["fs:read", "fs:write", "fs:lock"])
        #expect(minted.expiryDate == Date(timeIntervalSince1970: 1_782_600_000))
        let req = StubURLProtocol.requests.first { $0.url?.path == "/v1/auth/device/daemon-token" }
        #expect(req?.value(forHTTPHeaderField: "Authorization") == "Bearer eyJ.access.1")
    }
}

// MARK: - Deep-link grammar (API.md §6)

@Suite struct DeepLinkTests {

    @Test func buildEncodesSegments() {
        let url = DeepLink.build(spaceId: "active-edit", path: "ShowA/Edit/timeline.prproj")
        #expect(url == "cloudfs://active-edit/ShowA/Edit/timeline.prproj")
    }

    @Test func buildEncodesSpacesAndSpecialChars() {
        let url = DeepLink.build(spaceId: "active-edit", path: "Show A/Final Cut.mov")
        #expect(url == "cloudfs://active-edit/Show%20A/Final%20Cut.mov")
    }

    @Test func selectFalseAppendsQuery() {
        let url = DeepLink.build(spaceId: "fs", path: "a/b", select: false)
        #expect(url == "cloudfs://fs/a/b?select=0")
    }

    @Test func parseRoundTrips() {
        let parsed = DeepLink.parse("cloudfs://active-edit/Show%20A/Final%20Cut.mov")
        #expect(parsed?.spaceId == "active-edit")
        #expect(parsed?.path == "Show A/Final Cut.mov")
        #expect(parsed?.select == true)
    }

    @Test func parseHonorsSelectZero() {
        let parsed = DeepLink.parse("cloudfs://fs/a/b?select=0")
        #expect(parsed?.select == false)
    }

    @Test func parseRejectsWrongScheme() {
        #expect(DeepLink.parse("https://active-edit/a") == nil)
    }
}

// MARK: - Config / store selection

@Suite struct GatewayFactoryTests {

    @Test func envConfigChoosesHttp() {
        let env = ["CLOUDFS_GATEWAY_URL": "http://127.0.0.1:8787",
                   "CLOUDFS_GATEWAY_TOKEN": "tok",
                   "CLOUDFS_ORG": "acme"]
        let (_, mode) = GatewayFactory.makeClient(store: GatewaySettingsStore(defaults: isolatedDefaults()), env: env)
        #expect(mode.isHttp)
        #expect(mode == .http("http://127.0.0.1:8787"))
    }

    @Test func noConfigFallsBackToMock() {
        let (_, mode) = GatewayFactory.makeClient(store: GatewaySettingsStore(defaults: isolatedDefaults()), env: [:])
        #expect(mode == .mock)
    }

    @Test func envWithoutTokenIsNotUsable() {
        let env = ["CLOUDFS_GATEWAY_URL": "http://127.0.0.1:8787"]
        #expect(GatewayFactory.envConfig(env) == nil)
    }

    // A throwaway UserDefaults suite so tests don't touch the user's real prefs.
    private func isolatedDefaults() -> UserDefaults {
        let name = "test." + UUID().uuidString
        let d = UserDefaults(suiteName: name)!
        d.removePersistentDomain(forName: name)
        return d
    }
}
