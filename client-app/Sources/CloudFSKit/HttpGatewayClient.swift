// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// MARK: - HttpGatewayClient
//
// A real GatewayClient coded EXACTLY against backend/API.md: the /v1 routes, the
// `Authorization: Bearer <token>` header, the JSON request/response shapes, the
// `{ error, reason }` envelope, and the two cursor-pagination formats (opaque
// base64 for item listings, numeric updatedSeq for the change feed).
//
// What the gateway DOES own → wired here:
//   • filespaces           GET  /v1/orgs/:org/spaces
//   • listSnapshotFiles    GET  /v1/filespaces/:fs/snapshots/:id/dir?parent=
//   • snapshots            GET  /v1/filespaces/:fs/snapshots
//   • recentActivity       GET  /v1/filespaces/:fs/audit?limit=                  (AuditRecord→ActivityEvent)
//   • shareLinks           GET  /v1/orgs/:org/shares
//   • createShareLink      cloudfs:// built locally (§6) | POST /v1/orgs/:org/shares for guest
//   • revokeShareLink      DELETE /v1/orgs/:org/shares/:id
//   • connect              GET  /v1/health (reachability) + GET spaces
//
// What the gateway does NOT expose (client/engine-local per API.md) → no-ops here,
// kept to satisfy the protocol; the real cloudfsd EngineClient owns them:
//   • setPinned / prefetch / evict   (cache policy lives in cloudfsd, not the gateway)
//   • cacheSettings / updateCacheSettings  (engine-owned, §5.4)
//   • setConnectionState / pause/resume / transfers  (engine progress, not HTTP)

public final class HttpGatewayClient: GatewayClient, Sendable {

    /// Async bearer-token source, called per request — mirrors the daemon's
    /// `GatewayClientConfig.tokenProvider`. The device-session path injects the
    /// AuthSessionManager's short-lived access JWS here; the fixed-token init
    /// (Advanced service-account paste, tests) wraps the config token.
    public typealias TokenProvider = @Sendable () async -> String

    public let config: GatewayConfig
    private let session: URLSession
    private let tokenProvider: TokenProvider
    /// Optional 401 recovery hook (device sessions): called once per request on
    /// a 401; a non-nil fresh token triggers a single retry (auth-spec §1.5 —
    /// "on a race, one 401-triggered retry").
    private let unauthorizedRecovery: (@Sendable () async -> String?)?

    /// Fixed-token convenience init (legacy service-account token + tests).
    public convenience init(config: GatewayConfig, session: URLSession = .shared) {
        let fixed = config.token
        self.init(config: config, session: session,
                  tokenProvider: { fixed }, unauthorizedRecovery: nil)
    }

    public init(config: GatewayConfig, session: URLSession = .shared,
                tokenProvider: @escaping TokenProvider,
                unauthorizedRecovery: (@Sendable () async -> String?)? = nil) {
        self.config = config
        self.session = session
        self.tokenProvider = tokenProvider
        self.unauthorizedRecovery = unauthorizedRecovery
    }

    // MARK: - Errors

    public enum GatewayError: Error, Sendable, CustomStringConvertible, LocalizedError {
        case badURL
        case http(status: Int, code: String, reason: String?)
        case decoding(String)
        case transport(String)
        case unsupported(String)   // route the gateway doesn't expose

        public var description: String {
            switch self {
            case .badURL: return "Invalid gateway URL."
            case .http(let s, let code, let reason):
                return "HTTP \(s) \(code)\(reason.map { ": \($0)" } ?? "")"
            case .decoding(let m): return "Decoding failed: \(m)"
            case .transport(let m): return "Network error: \(m)"
            case .unsupported(let m): return "Not available over the gateway: \(m)"
            }
        }
        /// LocalizedError, so `error.localizedDescription` in the UI shows the
        /// real message instead of Foundation's "…GatewayError error 0." fallback
        /// (auth-spec §0.2 #3 — the recon-flagged cosmetic bug).
        public var errorDescription: String? { description }
    }

    private struct ErrorEnvelope: Decodable { let error: String?; let reason: String? }

    // MARK: - Request plumbing

    private func makeURL(path: String, query: [URLQueryItem] = []) throws -> URL {
        guard var comps = URLComponents(string: config.baseURL) else { throw GatewayError.badURL }
        // Append path onto whatever base path the URL already has.
        let basePath = comps.path.hasSuffix("/") ? String(comps.path.dropLast()) : comps.path
        comps.path = basePath + path
        if !query.isEmpty { comps.queryItems = query }
        guard let url = comps.url else { throw GatewayError.badURL }
        return url
    }

    private func send(
        _ method: String,
        path: String,
        query: [URLQueryItem] = [],
        body: Data? = nil,
        authed: Bool = true
    ) async throws -> Data {
        let url = try makeURL(path: path, query: query)
        var req = URLRequest(url: url)
        req.httpMethod = method
        if authed {
            let token = await tokenProvider()
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "content-type")
            req.httpBody = body
        }

        var data: Data
        var response: URLResponse
        do {
            (data, response) = try await session.data(for: req)
        } catch {
            throw GatewayError.transport(error.localizedDescription)
        }
        guard var http = response as? HTTPURLResponse else {
            throw GatewayError.transport("non-HTTP response")
        }
        // One 401-triggered retry when a recovery hook is wired (device-session
        // access JWS expired in flight; the hook force-refreshes once).
        if http.statusCode == 401, authed, let recover = unauthorizedRecovery,
           let fresh = await recover() {
            req.setValue("Bearer \(fresh)", forHTTPHeaderField: "Authorization")
            do {
                (data, response) = try await session.data(for: req)
            } catch {
                throw GatewayError.transport(error.localizedDescription)
            }
            guard let retried = response as? HTTPURLResponse else {
                throw GatewayError.transport("non-HTTP response")
            }
            http = retried
        }
        guard (200..<300).contains(http.statusCode) else {
            let env = try? Self.decoder.decode(ErrorEnvelope.self, from: data)
            throw GatewayError.http(
                status: http.statusCode,
                code: env?.error ?? "error",
                reason: env?.reason)
        }
        return data
    }

    private func sendJSON<T: Decodable>(
        _ type: T.Type,
        _ method: String,
        path: String,
        query: [URLQueryItem] = [],
        body: Data? = nil,
        authed: Bool = true
    ) async throws -> T {
        let data = try await send(method, path: path, query: query, body: body, authed: authed)
        do {
            return try Self.decoder.decode(T.self, from: data)
        } catch {
            throw GatewayError.decoding("\(type): \(error)")
        }
    }

    static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        return d
    }()
    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        return e
    }()

    private func encode(_ value: [String: Any]) -> Data {
        (try? JSONSerialization.data(withJSONObject: value)) ?? Data("{}".utf8)
    }

    // MARK: - Auth / session

    public func connect(_ credentials: Credentials) async throws -> [Filespace] {
        // The token is already in `config` (loaded from the Keychain at client
        // construction). connect() just proves reachability + lists spaces.
        _ = try await send("GET", path: "/v1/health", authed: false)
        return try await filespaces()
    }

    public func signOut() async throws {
        // Stateless bearer auth: nothing to revoke from the client side. The token
        // is cleared from the Keychain by the settings layer on sign-out.
    }

    // MARK: - Filespaces

    private struct SpacesEnvelope: Decodable {
        let spaces: [WireSpace]?
        let items: [WireSpace]?
        var list: [WireSpace] { spaces ?? items ?? [] }
    }
    // org-do.ts owns this shape; decode defensively across plausible field names.
    private struct WireSpace: Decodable {
        let id: String
        let name: String?
        let region: String?
        let backend: String?
        let storageBackend: String?
        let bucketProvider: String?
        let storageRegion: String?
        let role: String?
        let usedBytes: Int64?
        let size: Int64?
        let memberCount: Int?
        let members: Int?
    }

    public func filespaces() async throws -> [Filespace] {
        let org = config.org
        let path = "/v1/orgs/\(org)/spaces"
        // The registry may return either a bare array or an envelope.
        let data = try await send("GET", path: path)
        let wire: [WireSpace]
        if let env = try? Self.decoder.decode(SpacesEnvelope.self, from: data), env.spaces != nil || env.items != nil {
            wire = env.list
        } else if let arr = try? Self.decoder.decode([WireSpace].self, from: data) {
            wire = arr
        } else {
            throw GatewayError.decoding("spaces registry shape")
        }
        return wire.map { s in
            Filespace(
                id: s.id,
                name: s.name ?? s.id,
                region: s.storageRegion ?? s.region ?? "Automatic region",
                storageBackend: s.storageBackend ?? s.backend ?? (s.bucketProvider == "r2" ? "Cloudflare R2" : s.bucketProvider ?? "Deployment storage"),
                connection: .disconnected,
                role: MemberRole.fromWire(s.role) ?? .standard,
                usedBytes: s.usedBytes ?? s.size ?? -1,
                memberCount: s.memberCount ?? s.members ?? 0,
                mountPath: "",
                roleReported: MemberRole.fromWire(s.role) != nil)
        }
    }

    public func workspaceStorage() async throws -> WorkspaceStorage {
        try await sendJSON(WorkspaceStorage.self, "GET", path: "/v1/orgs/\(config.org)/storage/default")
    }

    public func createWorkspaceFilespace(name: String, storage: WorkspaceStorage) async throws -> String {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.count <= 100, storage.configured else {
            throw GatewayError.unsupported("Enter a filespace name and configure workspace storage first.")
        }
        struct Created: Decodable { let id: String }
        let created = try await sendJSON(Created.self, "POST", path: "/v1/orgs/\(config.org)/spaces", body: encode([
            "name": trimmed, "storageMode": "deployment", "region": storage.region, "storageBackend": storage.providerLabel,
        ]))
        guard !created.id.isEmpty else { throw GatewayError.decoding("Created filespace did not have an ID") }
        return created.id
    }

    private struct WireMountRoots: Decodable {
        struct Root: Decodable { let id: String }
        let roots: [Root]?
    }

    public func mountRootIds(in filespaceID: String) async throws -> [String] {
        let env = try await sendJSON(WireMountRoots.self, "GET", path: "/v1/filespaces/\(filespaceID)/mount-roots")
        return (env.roots ?? []).map(\.id).sorted()
    }

    public func setConnectionState(_ state: ConnectionState, for filespaceID: String) async throws {
        // Connection (disconnect/reconnect) is an engine/File-Provider concern, not
        // an HTTP route. No-op against the gateway.
    }

    // MARK: - Namespace items (Item shape, §4)

    struct WireItem: Decodable {
        let id: String
        let parent: String?
        let name: String
        let isDir: Bool
        let size: Int64
        let contentVersion: String?
        let etag: String?
        let version: Int?
        let updatedSeq: Int?
        let deleted: Bool?
    }
    static func fileNode(from item: WireItem) -> FileNode {
        FileNode(
            id: item.id,
            name: item.name,
            isDirectory: item.isDir,
            sizeBytes: item.size,
            modified: Date(),                 // Item has no mtime; gateway is metadata-only
            state: item.isDir ? .dataless
                : ((item.etag == nil) ? .uploading : .dataless),
            lockedBy: nil,                    // populated from a locks GET when needed
            isShared: false,
            childCount: 0)
    }

    private struct WireDirectoryPage: Decodable {
        let items: [WireItem]
        let cursor: String?
    }

    public func listDirectory(in filespaceID: String, parentID: String, cursor: String?) async throws -> DirectoryPage {
        var query = [URLQueryItem(name: "parent", value: parentID), URLQueryItem(name: "limit", value: "200")]
        if let cursor { query.append(URLQueryItem(name: "cursor", value: cursor)) }
        let page = try await sendJSON(WireDirectoryPage.self, "GET", path: "/v1/filespaces/\(filespaceID)/items", query: query)
        return DirectoryPage(items: page.items.filter { !($0.deleted ?? false) }.map(Self.fileNode(from:)), cursor: page.cursor)
    }

    public func listManagedFolders(in filespaceID: String, parentID: String, cursor: String?) async throws -> DirectoryPage {
        var query = [URLQueryItem(name: "parent", value: parentID)]
        if let cursor { query.append(URLQueryItem(name: "cursor", value: cursor)) }
        let page = try await sendJSON(WireDirectoryPage.self, "GET", path: "/v1/filespaces/\(filespaceID)/access-management", query: query)
        return DirectoryPage(items: page.items.filter { !($0.deleted ?? false) && $0.isDir }.map(Self.fileNode(from:)), cursor: page.cursor)
    }

    // MARK: - Cache / pin / prefetch / evict (engine-local, no gateway route)

    public func setPinned(_ pinned: Bool, fileID: String, in filespaceID: String) async throws {
        throw GatewayError.unsupported("pin is a cloudfsd cache policy, not a gateway route")
    }
    public func prefetch(fileID: String, in filespaceID: String) async throws {
        throw GatewayError.unsupported("prefetch is a cloudfsd cache op, not a gateway route")
    }
    public func evict(fileID: String, in filespaceID: String) async throws {
        throw GatewayError.unsupported("evict is a cloudfsd cache op, not a gateway route")
    }
    public func cacheSettings(for filespaceID: String) async throws -> CacheSettings {
        throw GatewayError.unsupported("cache settings are engine-owned (§5.4)")
    }
    public func updateCacheSettings(_ settings: CacheSettings, for filespaceID: String) async throws {
        throw GatewayError.unsupported("cache settings are engine-owned (§5.4)")
    }

    // MARK: - Activity (audit log → ActivityEvent)

    struct WireAudit: Decodable {
        let seq: Int?
        let ts: Double?
        let actorSub: String?
        let action: String?
        let decision: String?
        let path: String?
        let target: String?
    }

    public func recentActivity(in filespaceID: String, limit: Int) async throws -> [ActivityEvent] {
        let q = [URLQueryItem(name: "limit", value: String(limit))]
        let records = try await sendJSON([WireAudit].self, "GET",
                                         path: "/v1/filespaces/\(filespaceID)/audit",
                                         query: q)
        return records.map { r in
            let when = r.ts.map { Date(timeIntervalSince1970: $0 / 1000.0) } ?? Date()
            return ActivityEvent(
                id: r.seq.map(String.init) ?? UUID().uuidString,
                actor: r.actorSub ?? "system",
                verb: r.action ?? "changed",
                path: r.path ?? r.target ?? "",
                at: when)
        }
    }

    // MARK: - Live activity + audit range (WS3)

    /// Wire shape of `GET …/activity/live` (CONTRACTS §5.3): in-flight transfers
    /// from DO hot state + the rolling tail of recent activity events (incl.
    /// rolled-up bulk ops). Mirrors backend `LiveActivity`/`ActiveTransfer`/
    /// `LiveActivityEvent` (filespace-do.ts §5.3).
    struct WireLiveActivity: Decodable {
        let transfers: [WireLiveTransfer]?
        let events: [WireLiveEvent]?
    }
    struct WireLiveTransfer: Decodable {
        let id: String
        let path: String
        let direction: String?          // "upload" | "download"
        let bytesDone: Int64?
        let bytesTotal: Int64?
        let state: String?              // "active" | "completing"
    }
    struct WireLiveEvent: Decodable {
        let seq: Int?
        let type: String?               // "create" | "modify" | "delete" | ...
        let path: String?
        let actor: String?
        let ts: Double?
        let kind: String?               // "single" | "bulk"
        let op: String?                 // bulk only (e.g. "large-delete")
        let count: Int?                 // bulk only
    }

    private static func transfer(from t: WireLiveTransfer) -> Transfer {
        let name = (t.path as NSString).lastPathComponent.isEmpty ? t.path : (t.path as NSString).lastPathComponent
        return Transfer(
            id: t.id,
            fileName: name,
            kind: (t.direction == "download") ? .download : .upload,
            state: (t.state == "completing") ? .completed : .active,
            bytesDone: t.bytesDone ?? 0,
            bytesTotal: t.bytesTotal ?? 0,
            throughputBytesPerSec: 0,
            startedAt: Date())
    }

    private static func activityEvent(from e: WireLiveEvent) -> ActivityEvent {
        let when = e.ts.map { Date(timeIntervalSince1970: $0 / 1000.0) } ?? Date()
        let isBulk = (e.kind == "bulk")
        return ActivityEvent(
            id: e.seq.map(String.init) ?? UUID().uuidString,
            actor: e.actor ?? "system",
            verb: e.type ?? "changed",
            path: e.path ?? "",
            at: when,
            kind: isBulk ? .bulk : .single,
            bulkOp: isBulk ? e.op : nil,
            bulkCount: isBulk ? e.count : nil)
    }

    /// `GET /v1/filespaces/:fs/activity/live` (CONTRACTS §5.3) — decode
    /// `{ transfers, events }`; map bulk events (`kind:"bulk"`, `op`, `count`)
    /// onto `ActivityEvent`.
    public func liveActivity(in filespaceID: String) async throws -> LiveActivity {
        let wire = try await sendJSON(WireLiveActivity.self, "GET",
                                      path: "/v1/filespaces/\(filespaceID)/activity/live")
        return LiveActivity(
            transfers: (wire.transfers ?? []).map(Self.transfer(from:)),
            events: (wire.events ?? []).map(Self.activityEvent(from:)))
    }

    /// `GET /v1/filespaces/:fs/audit?since=&until=&cursor=&limit=` (CONTRACTS §5.4)
    /// — the DO reads its ring first, then transparently falls back to R2 segments
    /// for ranges older than the ring. The `AuditRecord` rows are projected onto
    /// `ActivityEvent`. The continuation cursor is the lowest `seq` returned so the
    /// caller can page further back with `cursor`/`until`; nil when exhausted.
    public func auditRange(in filespaceID: String, since: Date?, until: Date?,
                           cursor: String?, limit: Int) async throws -> AuditPage {
        var q: [URLQueryItem] = [URLQueryItem(name: "limit", value: String(limit))]
        if let since { q.append(URLQueryItem(name: "since", value: String(Int(since.timeIntervalSince1970 * 1000)))) }
        // `cursor` (a seq high-water from a prior page) pages further back; it maps
        // onto `until` (ms) when no explicit `until` was supplied, falling back to
        // the passed `until` otherwise.
        if let until {
            q.append(URLQueryItem(name: "until", value: String(Int(until.timeIntervalSince1970 * 1000))))
        }
        if let cursor { q.append(URLQueryItem(name: "cursor", value: cursor)) }

        let records = try await sendJSON([WireAudit].self, "GET",
                                         path: "/v1/filespaces/\(filespaceID)/audit",
                                         query: q)
        let events = records.map { r -> ActivityEvent in
            let when = r.ts.map { Date(timeIntervalSince1970: $0 / 1000.0) } ?? Date()
            return ActivityEvent(
                id: r.seq.map(String.init) ?? UUID().uuidString,
                actor: r.actorSub ?? "system",
                verb: r.action ?? "changed",
                path: r.path ?? r.target ?? "",
                at: when)
        }
        // A full page implies more history may exist; continue from the lowest seq
        // returned. A short page means we reached the end → nil cursor.
        let nextCursor: String? = (records.count >= limit)
            ? records.compactMap(\.seq).min().map(String.init)
            : nil
        return AuditPage(events: events, cursor: nextCursor)
    }

    // MARK: - Transfers (engine progress; not an HTTP route)

    public func currentTransfers(in filespaceID: String) async throws -> [Transfer] { [] }

    public func transferUpdates(in filespaceID: String) -> AsyncStream<[Transfer]> {
        // Real transfer progress comes from the cloudfsd EngineClient, not the
        // gateway. Emit one empty snapshot and finish.
        AsyncStream { continuation in
            continuation.yield([])
            continuation.finish()
        }
    }

    public func activityUpdates(in filespaceID: String) -> AsyncStream<ActivityEvent> {
        // API.md §9: WebSocket change pub/sub is not yet exposed; clients poll
        // …/changes. Poll the audit feed on an interval for new events.
        AsyncStream { continuation in
            let task = Task { [weak self] in
                guard let self else { continuation.finish(); return }
                var seen = Set<String>()
                while !Task.isCancelled {
                    if let events = try? await self.recentActivity(in: filespaceID, limit: 25) {
                        for e in events.reversed() where !seen.contains(e.id) {
                            seen.insert(e.id)
                            continuation.yield(e)
                        }
                    }
                    try? await Task.sleep(for: .seconds(10))
                }
                continuation.finish()
            }
            continuation.onTermination = { _ in task.cancel() }
        }
    }

    public func pauseTransfers(in filespaceID: String) async throws {}
    public func resumeTransfers(in filespaceID: String) async throws {}

    // MARK: - Snapshots (Snapshot shape, §4)

    struct WireSnapshot: Decodable {
        let id: String
        let label: String?
        let scope: String?
        let seqAnchor: Int?
        let tier: String?
        let createdAt: Double?
        let immutableUntil: Double?
        let scheduleId: String?
    }

    public func snapshots(in filespaceID: String) async throws -> [Snapshot] {
        let wire = try await sendJSON([WireSnapshot].self, "GET",
                                      path: "/v1/filespaces/\(filespaceID)/snapshots")
        return wire.map { s in
            Snapshot(
                id: s.id,
                name: s.label ?? s.id,
                takenAt: s.createdAt.map { Date(timeIntervalSince1970: $0 / 1000.0) } ?? Date(),
                sizeBytes: 0,                          // snapshots are metadata-only here
                isScheduled: s.scheduleId != nil,
                retentionTier: s.tier ?? "Manual", scope: s.scope)
        }
    }

    /// `POST /v1/filespaces/:fs/snapshots` (CONTRACTS §6.3) with
    /// `{ label?, scope?, tier? }` → 201 Snapshot. `id` is omitted so the DO mints
    /// a server-side id for the real manual snapshot. The 201 body is the
    /// `WireSnapshot` shape (same as the list route).
    public func createSnapshot(label: String?, scope: String?, tier: String?,
                               in filespaceID: String) async throws -> Snapshot {
        var fields: [String: Any] = [:]
        if let label { fields["label"] = label }
        if let scope { fields["scope"] = scope }
        if let tier { fields["tier"] = tier }
        let s = try await sendJSON(WireSnapshot.self, "POST",
                                   path: "/v1/filespaces/\(filespaceID)/snapshots",
                                   body: encode(fields))
        return Snapshot(
            id: s.id,
            name: s.label ?? s.id,
            takenAt: s.createdAt.map { Date(timeIntervalSince1970: $0 / 1000.0) } ?? Date(),
            sizeBytes: 0,
            isScheduled: s.scheduleId != nil,
            retentionTier: s.tier ?? "Manual", scope: s.scope)
    }

    public func listSnapshotFiles(snapshotID: String, in filespaceID: String, parentID: String?) async throws -> [FileNode] {
        var q: [URLQueryItem] = []
        if let parentID { q.append(URLQueryItem(name: "parent", value: parentID)) }
        else { q.append(URLQueryItem(name: "parent", value: "root")) }
        let items = try await sendJSON([WireItem].self, "GET",
                                       path: "/v1/filespaces/\(filespaceID)/snapshots/\(snapshotID)/dir",
                                       query: q)
        return items.filter { !($0.deleted ?? false) }.map(Self.fileNode(from:))
    }

    struct WireRestoreResult: Decodable {
        let snapshotId: String?
        let restored: [String]?
        let recreated: [String]?
        let conflicts: [WireConflict]?
        let newerThanSnapshot: [String]?
        let forbidden: [String]?
        let skippedPermissions: Int?
        let streamsCaptured: Bool?
        struct WireConflict: Decodable { let id: String; let heldBy: String? }
    }

    public func restore(path: String, recursive: Bool, fromSnapshot snapshotID: String, in filespaceID: String) async throws -> RestoreResult {
        // POST /v1/filespaces/:fs/snapshots/:id/restore  { path, recursive?, mode? }
        // → 200 RestoreResult · 409 (all targets locked) · 404 (unknown snapshot/path)
        let body = encode([
            "path": path,
            "recursive": recursive,
        ])
        let w = try await sendJSON(WireRestoreResult.self, "POST",
                                   path: "/v1/filespaces/\(filespaceID)/snapshots/\(snapshotID)/restore",
                                   body: body)
        return RestoreResult(
            snapshotId: w.snapshotId ?? snapshotID,
            restored: w.restored ?? [],
            recreated: w.recreated ?? [],
            conflicts: (w.conflicts ?? []).map { .init(id: $0.id, heldBy: $0.heldBy) },
            newerThanSnapshot: w.newerThanSnapshot ?? [], forbidden: w.forbidden, skippedPermissions: w.skippedPermissions, streamsCaptured: w.streamsCaptured)
    }

    // MARK: - Sharing

    /// A bare `ShareLinkRecord` as the LIST route returns it (sharing.ts §share). The
    /// record carries `inodeId`/`level`/`expiresAt` (epoch-ms) — NOT a `path`/`url`/
    /// `canDownload` (the old decode read those and always got nils, so every share
    /// showed an empty path + an empty URL + the wrong perms). There is no per-record
    /// URL on the list route (the browser URL is only minted ONCE at create time).
    struct WireShareRecord: Decodable {
        let id: String
        let inodeId: String?
        let level: String?       // "read" (download only) | "edit" | "admin"
        let expiresAt: Double?   // epoch MILLISECONDS
    }
    /// The CREATE route returns a nested envelope `{ share, rawToken, shareUrl }`
    /// (sharing.ts `createShareLink`) — the id/expiry live under `share.*` and the
    /// browser URL is the top-level `shareUrl`. Decoding the response AS a bare record
    /// (the old code) read `id`/`url` at the top level and got an empty id + empty URL.
    struct WireShareCreateEnvelope: Decodable {
        let share: WireShareRecord
        let shareUrl: String?
    }
    private struct SharesEnvelope: Decodable {
        let shares: [WireShareRecord]?
        let links: [WireShareRecord]?
        var list: [WireShareRecord] { shares ?? links ?? [] }
    }

    /// Map a wire `level` to the (canDownload, canEdit) the UI shows. A guest/external
    /// link is preview/download-only ("read") by contract; "edit"/"admin" allow edits.
    private static func sharePerms(_ level: String?) -> (download: Bool, edit: Bool) {
        switch level {
        case "edit", "admin": return (true, true)
        default: return (true, false) // "read" / unknown → download only
        }
    }
    /// The list route carries no `path`; surface the opaque inode id like the CLI does
    /// (`/<inodeId>`), with "root" → "/".
    private static func sharePath(_ inodeId: String?) -> String {
        guard let i = inodeId, !i.isEmpty else { return "" }
        return i == "root" ? "/" : "/\(i)"
    }

    public func shareLinks(in filespaceID: String) async throws -> [CloudShareLink] {
        let org = config.org
        // FINDING 6: the backend filters on ?spaceId= (not ?space=); scope the list to
        // this filespace so we don't surface another space's links. Pass it as a proper
        // query item (NOT embedded in the path, which URLComponents would %-encode).
        let data = try await send("GET", path: "/v1/orgs/\(org)/shares",
                                  query: [URLQueryItem(name: "spaceId", value: filespaceID)])
        let wire: [WireShareRecord]
        if let env = try? Self.decoder.decode(SharesEnvelope.self, from: data), !env.list.isEmpty {
            wire = env.list
        } else if let arr = try? Self.decoder.decode([WireShareRecord].self, from: data) {
            wire = arr
        } else {
            wire = []
        }
        return wire.map { w in
            let perms = Self.sharePerms(w.level)
            return CloudShareLink(
                id: w.id,
                path: Self.sharePath(w.inodeId),
                kind: .guestLink,
                url: "", // the list route returns no URL (shown only once at create)
                expiresAt: w.expiresAt.map { Date(timeIntervalSince1970: $0 / 1000.0) },
                canDownload: perms.download,
                canEdit: perms.edit)
        }
    }

    public func createShareLink(for fileID: String, kind: ShareKind, in filespaceID: String) async throws -> CloudShareLink {
        switch kind {
        case .internalDeepLink:
            // §6: cloudfs:// is built client-side, grants nothing, no gateway call.
            let url = fileID.isEmpty ? DeepLink.build(spaceId: filespaceID, path: "")
                : DeepLink.buildItem(spaceId: filespaceID, itemId: fileID)
            return CloudShareLink(
                id: UUID().uuidString, path: fileID, kind: .internalDeepLink,
                url: url, expiresAt: nil, canDownload: true, canEdit: true)
        case .guestLink:
            // External share = a scoped, time-limited grant (§6) via sharing.ts. The
            // backend reads `{ spaceId, inodeId }` (CreateShareInput); `canDownload`/
            // `canEdit` are NOT input fields (the level is fixed read for an external
            // link), so we don't send them.
            let org = config.org
            let body = encode([
                "spaceId": filespaceID,
                "inodeId": fileID,
            ])
            // Decode the NESTED { share, shareUrl } envelope, not a flat record.
            let env = try await sendJSON(WireShareCreateEnvelope.self, "POST",
                                         path: "/v1/orgs/\(org)/shares",
                                         body: body)
            let perms = Self.sharePerms(env.share.level)
            return CloudShareLink(
                id: env.share.id,
                path: env.share.inodeId.map { _ in fileID } ?? fileID,
                kind: .guestLink,
                url: env.shareUrl ?? "",
                expiresAt: env.share.expiresAt.map { Date(timeIntervalSince1970: $0 / 1000.0) },
                canDownload: perms.download,
                canEdit: perms.edit)
        }
    }

    public func revokeShareLink(_ linkID: String, in filespaceID: String) async throws {
        let org = config.org
        _ = try await send("DELETE", path: "/v1/orgs/\(org)/shares/\(linkID)")
    }

    // MARK: - Members & Access (users / invites / grants)
    //
    // Coded against backend/API.md §org-multi-user + §grants and the handlers in
    // backend/src/{users,invites,permissions}.ts. Org-scoped routes use config.org;
    // grant routes are per-filespace.

    /// `GET /v1/auth/me` → `{ role, … }`. Maps the wire role onto `OrgRole`;
    /// unknown/absent → `.standard` (fail closed: the Members section stays hidden).
    private struct WireMe: Decodable { let role: String?; let userId: String?; let email: String? }

    public func currentUserRole() async throws -> OrgRole {
        let me = try await sendJSON(WireMe.self, "GET", path: "/v1/auth/me")
        return OrgRole(rawValue: me.role ?? "standard") ?? .standard
    }

    /// org-do.ts `User` shape. `kind` distinguishes service accounts.
    private struct WireUser: Decodable {
        let id: String
        let email: String?
        let displayName: String?
        let role: String?
        let status: String?
        let kind: String?
        let createdAt: Double?
    }
    private struct UsersEnvelope: Decodable {
        let users: [WireUser]?
        let items: [WireUser]?
        var list: [WireUser] { users ?? items ?? [] }
    }

    private static func member(from u: WireUser) -> OrgMember {
        OrgMember(
            id: u.id,
            email: u.email ?? "",
            displayName: u.displayName ?? u.email ?? u.id,
            role: OrgRole(rawValue: u.role ?? "standard") ?? .standard,
            status: MemberStatus(rawValue: u.status ?? "active") ?? .active,
            principal: (u.kind == "service_account") ? .serviceAccount : .user,
            createdAt: u.createdAt.map { Date(timeIntervalSince1970: $0 / 1000.0) } ?? Date())
    }

    public func listMembers() async throws -> [OrgMember] {
        let org = config.org
        let data = try await send("GET", path: "/v1/orgs/\(org)/users")
        let wire: [WireUser]
        if let env = try? Self.decoder.decode(UsersEnvelope.self, from: data), !env.list.isEmpty {
            wire = env.list
        } else if let arr = try? Self.decoder.decode([WireUser].self, from: data) {
            wire = arr
        } else {
            wire = []
        }
        return wire.map(Self.member(from:))
    }

    /// org-do.ts `Group` shape.
    private struct WireGroup: Decodable {
        let id: String
        let name: String?
        let source: String?
        let memberCount: Int?
    }
    private struct GroupsEnvelope: Decodable {
        let groups: [WireGroup]?
        let items: [WireGroup]?
        var list: [WireGroup] { groups ?? items ?? [] }
    }

    private static func group(from wire: WireGroup) -> MemberGroup {
        MemberGroup(id: wire.id, name: wire.name ?? wire.id,
                    source: wire.source == "scim" ? .scim : .manual,
                    memberCount: wire.memberCount ?? -1)
    }

    public func listGroups() async throws -> [MemberGroup] {
        let data = try await send("GET", path: "/v1/orgs/\(config.org)/groups")
        let wire: [WireGroup]
        if let envelope = try? Self.decoder.decode(GroupsEnvelope.self, from: data),
           envelope.groups != nil || envelope.items != nil {
            wire = envelope.list
        } else {
            wire = try Self.decoder.decode([WireGroup].self, from: data)
        }
        return wire.map(Self.group(from:))
    }

    public func createGroup(name: String) async throws -> MemberGroup {
        let wire = try await sendJSON(WireGroup.self, "POST", path: "/v1/orgs/\(config.org)/groups",
                                      body: encode(["name": name.trimmingCharacters(in: .whitespacesAndNewlines), "source": "manual"]))
        var group = Self.group(from: wire)
        group.memberCount = 0
        return group
    }

    public func deleteGroup(_ groupID: String) async throws {
        _ = try await send("DELETE", path: "/v1/orgs/\(config.org)/groups/\(Self.pathComponent(groupID))")
    }

    public func groupMembers(_ groupID: String) async throws -> [String] {
        try await sendJSON([String].self, "GET", path: "/v1/orgs/\(config.org)/groups/\(Self.pathComponent(groupID))/members")
    }

    public func addGroupMember(_ userID: String, to groupID: String) async throws {
        _ = try await send("POST", path: "/v1/orgs/\(config.org)/groups/\(Self.pathComponent(groupID))/members",
                           body: encode(["userId": userID]))
    }

    public func removeGroupMember(_ userID: String, from groupID: String) async throws {
        _ = try await send("DELETE", path: "/v1/orgs/\(config.org)/groups/\(Self.pathComponent(groupID))/members",
                           query: [URLQueryItem(name: "userId", value: userID)])
    }

    private static func pathComponent(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed.subtracting(CharacterSet(charactersIn: "/?#%"))) ?? value
    }

    /// `POST /v1/orgs/:org/invites` → 201 `{ invite, rawToken }` (invites.ts).
    private struct WireInviteResult: Decodable {
        let rawToken: String?
        let emailSent: Bool?
        let joinToken: String?
        let invite: WireInvite?
        struct WireInvite: Decodable {
            let id: String?; let email: String?; let role: String?; let expiresAt: Double?
        }
    }

    public func invite(_ request: InviteRequest) async throws -> InviteResult {
        let org = config.org
        var fields: [String: Any] = [
            "email": request.normalizedEmail,
            "role": request.role.rawValue,
        ]
        // Optional scoped folder grant the invite promises on redeem (InviteScope).
        if let inodeId = request.inodeId, let level = request.level {
            fields["scope"] = [
                "spaceId": request.spaceId as Any,
                "inodeId": inodeId,
                "level": level.rawValue,
            ]
        }
        let w = try await sendJSON(WireInviteResult.self, "POST",
                                   path: "/v1/orgs/\(org)/invites",
                                   body: encode(fields))
        let inv = w.invite
        return InviteResult(
            inviteId: inv?.id ?? UUID().uuidString,
            email: inv?.email ?? request.normalizedEmail,
            role: OrgRole(rawValue: inv?.role ?? request.role.rawValue) ?? request.role,
            rawToken: w.rawToken ?? "",
            expiresAt: inv?.expiresAt.map { Date(timeIntervalSince1970: $0 / 1000.0) }
                ?? Date().addingTimeInterval(7 * 86_400), emailSent: w.emailSent ?? false, joinToken: w.joinToken)
    }

    public func setRole(_ role: OrgRole, forMember memberID: String) async throws {
        let org = config.org
        _ = try await send("PATCH", path: "/v1/orgs/\(org)/users/\(memberID)",
                           body: encode(["role": role.rawValue]))
    }

    public func suspendMember(_ memberID: String) async throws {
        let org = config.org
        _ = try await send("PATCH", path: "/v1/orgs/\(org)/users/\(memberID)",
                           body: encode(["status": "suspended"]))
    }

    public func reactivateMember(_ memberID: String) async throws {
        let org = config.org
        _ = try await send("PATCH", path: "/v1/orgs/\(org)/users/\(memberID)",
                           body: encode(["status": "active"]))
    }

    public func deprovisionMember(_ memberID: String) async throws {
        let org = config.org
        // DELETE soft-deletes (status → deprovisioned) per users.ts.
        _ = try await send("DELETE", path: "/v1/orgs/\(org)/users/\(memberID)")
    }

    /// One ACL row as `GET /v1/filespaces/:fs/grants` returns it (index.ts B28 +
    /// FilespaceDO.listGrants). The wire row carries NO synthetic `id`, no display
    /// `principalLabel`, and no human `inodePath` — only the opaque inode id; we
    /// synthesize a stable composite id and fall back to the raw ids for display.
    private struct WireGrant: Decodable {
        let id: String?
        let inodePath: String?
        let principalLabel: String?
        let canModify: Bool?
        let active: Bool?
        let inodeId: String
        let principalType: String
        let principalId: String
        let level: String
        let mountAsRoot: Bool?
        let expiresAt: Double?    // epoch MILLISECONDS or null
    }
    private struct WireGrantsEnvelope: Decodable { let grants: [WireGrant]? }

    public func listGrants(in filespaceID: String) async throws -> [AccessGrant] {
        // Audit B28: the gateway DOES now expose a bulk list-grants route
        // (`GET /v1/filespaces/:fs/grants`, fs:admin). The old code returned [] (the
        // route 404'd before B28), so the Members & Access tab always rendered empty
        // even when grants existed. Enumerate the real grants now.
        let data = try await send("GET", path: "/v1/filespaces/\(filespaceID)/grants")
        let env = try Self.decoder.decode(WireGrantsEnvelope.self, from: data)
        return (env.grants ?? []).map(Self.accessGrant(from:))
    }

    private static func accessGrant(from w: WireGrant) -> AccessGrant {
        AccessGrant(id: w.id ?? "\(w.inodeId):\(w.principalType):\(w.principalId)",
                    inodeId: w.inodeId, inodePath: w.inodePath ?? (w.inodeId == "root" ? "/" : "/\(w.inodeId)"),
                    principalType: PrincipalType(rawValue: w.principalType) ?? .user,
                    principalId: w.principalId, principalLabel: w.principalLabel ?? w.principalId,
                    level: GrantLevel(rawValue: w.level) ?? .read,
                    mountAsRoot: w.mountAsRoot ?? false,
                    expiresAt: w.expiresAt.map { Date(timeIntervalSince1970: $0 / 1000) },
                    canModify: w.canModify, active: w.active)
    }

    private struct WireFolderAdministration: Decodable {
        let canManageAccess: Bool
        let canDelegateAdmin: Bool
        let canManageWorkspace: Bool
        let roots: [ManagedFolder]
        let grants: [WireGrant]
        let members: [WireUser]
        let groups: [WireGroup]
    }
    public func accessManagement(in filespaceID: String) async throws -> FolderAdministration {
        let wire = try await sendJSON(WireFolderAdministration.self, "GET",
                                      path: "/v1/filespaces/\(filespaceID)/access-management")
        return FolderAdministration(canManageAccess: wire.canManageAccess,
                                    canDelegateAdmin: wire.canDelegateAdmin,
                                    canManageWorkspace: wire.canManageWorkspace,
                                    roots: wire.roots, grants: wire.grants.map(Self.accessGrant(from:)),
                                    members: wire.members.map(Self.member(from:)), groups: wire.groups.map(Self.group(from:)))
    }

    /// `POST /v1/filespaces/:fs/grants` → 201 `{ id }` (permissions.ts).
    private struct WireGrantId: Decodable { let id: String? }

    public func setGrant(_ request: GrantRequest, in filespaceID: String) async throws -> AccessGrant {
        var fields: [String: Any] = [
            "inodeId": request.inodeId,
            "principalType": request.principalType.rawValue,
            "principalId": request.principalId,
            "level": request.level.rawValue,
            "mountAsRoot": request.mountAsRoot,
        ]
        if let expiresAt = request.expiresAt {
            fields["expiresAt"] = Int(expiresAt.timeIntervalSince1970 * 1000)
        }
        let w = try await sendJSON(WireGrantId.self, "POST",
                                   path: "/v1/filespaces/\(filespaceID)/grants",
                                   body: encode(fields))
        return AccessGrant(
            id: w.id ?? UUID().uuidString,
            inodeId: request.inodeId, inodePath: request.inodePath,
            principalType: request.principalType, principalId: request.principalId,
            principalLabel: request.principalLabel, level: request.level,
            mountAsRoot: request.mountAsRoot, expiresAt: request.expiresAt)
    }

    public func removeGrant(_ grant: AccessGrant, in filespaceID: String) async throws {
        // DELETE /v1/filespaces/:fs/grants?inodeId=&principalType=&principalId=
        let q = [
            URLQueryItem(name: "inodeId", value: grant.inodeId),
            URLQueryItem(name: "principalType", value: grant.principalType.rawValue),
            URLQueryItem(name: "principalId", value: grant.principalId),
        ]
        _ = try await send("DELETE", path: "/v1/filespaces/\(filespaceID)/grants", query: q)
    }
}
