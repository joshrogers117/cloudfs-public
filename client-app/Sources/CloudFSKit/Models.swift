// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - Domain models
//
// These mirror the concepts in the cloud-fs spec: Filespaces (one File Provider
// domain each), files with File-Provider-style materialization states, transfer
// activity, snapshots, share links, and cache configuration. They are
// deliberately plain `Sendable` value types so the data layer stays decoupled
// from SwiftUI and is trivial to feed from either the mock or the real gateway.

// MARK: Connection / sync state

/// Per-filespace connection state. Mirrors `NSFileProviderManager`
/// `disconnect(reason:)` / `reconnect()` and the gateway reachability.
public enum ConnectionState: String, Sendable, Codable, CaseIterable {
    case connected      // domain registered, gateway reachable, sync live
    case connecting     // logging in / registering the domain
    case paused         // user hit pause-sync; engine quiesced
    case disconnected   // credentials expired or gateway unreachable
    case error          // unrecoverable; needs attention

    public var label: String {
        switch self {
        case .connected:    return "Connected"
        case .connecting:   return "Connecting…"
        case .paused:       return "Paused"
        case .disconnected: return "Disconnected"
        case .error:        return "Error"
        }
    }
}

// MARK: Filespace

/// A filespace == one workspace namespace == one `NSFileProviderDomain`.
public struct Filespace: Identifiable, Sendable, Hashable, Codable {
    public let id: String          // stable filespace UUID -> NSFileProviderDomain identifier
    public var name: String        // becomes the Finder sidebar label
    public var region: String      // R2/B2 bucket region (latency matters, per research)
    public var storageBackend: String   // "Cloudflare R2", "Backblaze B2", …
    public var connection: ConnectionState
    public var role: MemberRole
    /// True when the server actually reported `role` for this filespace. When false,
    /// `role` is only a placeholder and the UI derives the display role from the
    /// signed-in user's org role (`displayRole(orgRole:)`).
    public var roleReported: Bool
    public var usedBytes: Int64    // total namespace size as reported by the gateway; < 0 = not reported
    public var memberCount: Int
    public var mountPath: String   // ~/Library/CloudStorage/cloud-fs-<name>

    public init(id: String, name: String, region: String, storageBackend: String,
                connection: ConnectionState, role: MemberRole, usedBytes: Int64,
                memberCount: Int, mountPath: String, roleReported: Bool = true) {
        self.id = id; self.name = name; self.region = region
        self.storageBackend = storageBackend; self.connection = connection
        self.role = role; self.usedBytes = usedBytes; self.memberCount = memberCount
        self.mountPath = mountPath; self.roleReported = roleReported
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, region, storageBackend, connection, role, roleReported, usedBytes, memberCount, mountPath
    }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        region = try c.decode(String.self, forKey: .region)
        storageBackend = try c.decode(String.self, forKey: .storageBackend)
        connection = try c.decode(ConnectionState.self, forKey: .connection)
        role = try c.decode(MemberRole.self, forKey: .role)
        roleReported = try c.decodeIfPresent(Bool.self, forKey: .roleReported) ?? true
        usedBytes = try c.decode(Int64.self, forKey: .usedBytes)
        memberCount = try c.decode(Int.self, forKey: .memberCount)
        mountPath = try c.decode(String.self, forKey: .mountPath)
    }

    /// The role to show: the server-reported per-filespace role, else derived from
    /// the signed-in user's org role (mirrors the web console).
    public func displayRole(orgRole: OrgRole?) -> MemberRole {
        if roleReported { return role }
        guard let orgRole else { return role }
        return MemberRole(orgRole: orgRole)
    }

    /// "Current storage" text: formatted bytes when the server reported them.
    public var storageDisplay: String {
        usedBytes < 0 ? "Not available" : ByteFormat.string(usedBytes)
    }
}

/// Workspace role hierarchy (research/02 §Identity).
public enum MemberRole: String, Sendable, Codable, CaseIterable {
    case owner          = "Owner"
    case admin          = "Admin"
    case filespaceAdmin = "Filespace Admin"
    case standard       = "Standard User"

    public init(orgRole: OrgRole) {
        switch orgRole {
        case .owner: self = .owner
        case .admin: self = .admin
        case .spaceAdmin: self = .filespaceAdmin
        case .standard: self = .standard
        }
    }

    /// Server wire value (`owner|admin|space_admin|standard|folder_admin`, plus the
    /// display strings) → role. `folder_admin` is a standard member holding an
    /// admin-level folder grant, so it displays as a standard user. nil when absent/unknown.
    public static func fromWire(_ raw: String?) -> MemberRole? {
        guard let raw = raw?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return nil }
        switch raw.lowercased() {
        case "owner": return .owner
        case "admin": return .admin
        case "space_admin", "filespace admin", "filespace_admin": return .filespaceAdmin
        case "standard", "standard user", "folder_admin", "viewer": return .standard
        default: return nil
        }
    }
}

// MARK: Files

/// File-Provider materialization state for a file/folder. This is the cloud-badge
/// vocabulary the Files browser renders (docs §2.8, §5.5).
public enum MaterializationState: String, Sendable, Codable {
    case dataless    // placeholder, 0 bytes on disk — "in the cloud"
    case streaming   // partially materialized (byte-range streamed right now)
    case downloaded  // fully local, evictable
    case pinned      // keep-local, non-evictable (.downloadEagerlyAndKeepDownloaded)
    case uploading   // local edit draining to R2
}

public struct FileNode: Identifiable, Sendable, Hashable, Codable {
    public let id: String          // stable backend inode/object id (never path-derived)
    public var name: String
    public var isDirectory: Bool
    public var sizeBytes: Int64
    public var modified: Date
    public var state: MaterializationState
    public var lockedBy: String?   // remote write-lease holder (gateway DO authority)
    public var isShared: Bool
    public var childCount: Int     // for directories

    public init(id: String, name: String, isDirectory: Bool, sizeBytes: Int64,
                modified: Date, state: MaterializationState, lockedBy: String? = nil,
                isShared: Bool = false, childCount: Int = 0) {
        self.id = id; self.name = name; self.isDirectory = isDirectory
        self.sizeBytes = sizeBytes; self.modified = modified; self.state = state
        self.lockedBy = lockedBy; self.isShared = isShared; self.childCount = childCount
    }
}

// MARK: Activity / transfers

public enum TransferKind: String, Sendable, Codable {
    case upload, download
}

public enum TransferState: String, Sendable, Codable {
    case queued, active, completed, failed, paused
}

public struct Transfer: Identifiable, Sendable, Hashable, Codable {
    public let id: String
    public var fileName: String
    public var kind: TransferKind
    public var state: TransferState
    public var bytesDone: Int64
    public var bytesTotal: Int64
    public var throughputBytesPerSec: Int64
    public var startedAt: Date
    public var path: String?
    public var error: String?

    public var fraction: Double {
        guard bytesTotal > 0 else { return state == .completed ? 1 : 0 }
        return min(1, Double(bytesDone) / Double(bytesTotal))
    }

    public init(id: String, fileName: String, kind: TransferKind, state: TransferState,
                bytesDone: Int64, bytesTotal: Int64, throughputBytesPerSec: Int64,
                startedAt: Date, path: String? = nil, error: String? = nil) {
        self.id = id; self.fileName = fileName; self.kind = kind; self.state = state
        self.bytesDone = bytesDone; self.bytesTotal = bytesTotal
        self.throughputBytesPerSec = throughputBytesPerSec; self.startedAt = startedAt
        self.path = path; self.error = error
    }
}

/// A coarse remote-activity feed item ("who's editing what") — the menu-bar
/// recent-activity list and the Activity pane both render these.
public struct ActivityEvent: Identifiable, Sendable, Hashable, Codable {
    public let id: String
    public var actor: String       // member display name
    public var verb: String        // "edited", "locked", "uploaded", "restored"…
    public var path: String
    public var at: Date
    /// Whether this event is a single op or a rolled-up bulk op (WS3, CONTRACTS
    /// §5.3). `nil`/`.single` render as a normal row; `.bulk` carries `bulkOp` +
    /// `bulkCount` for the "N-file delete" rollup.
    public var kind: ActivityKind
    public var bulkOp: String?     // e.g. "large-delete" (bulk only)
    public var bulkCount: Int?     // items collapsed into the rollup (bulk only)

    public init(id: String, actor: String, verb: String, path: String, at: Date,
                kind: ActivityKind = .single, bulkOp: String? = nil, bulkCount: Int? = nil) {
        self.id = id; self.actor = actor; self.verb = verb; self.path = path; self.at = at
        self.kind = kind; self.bulkOp = bulkOp; self.bulkCount = bulkCount
    }
}

/// Single op vs. a rolled-up bulk op (WS3 live feed, CONTRACTS §5.3).
public enum ActivityKind: String, Sendable, Hashable, Codable {
    case single
    case bulk
}

/// The LIVE activity payload (WS3) — `GET …/activity/live` (CONTRACTS §5.3):
/// in-flight transfers + the DO hot ring + rolled-up bulk ops. Distinct from the
/// historical audit reader (`auditRange`).
public struct LiveActivity: Sendable, Hashable, Codable {
    public var transfers: [Transfer]
    public var events: [ActivityEvent]

    public init(transfers: [Transfer], events: [ActivityEvent]) {
        self.transfers = transfers; self.events = events
    }
}

/// One page of HISTORICAL audit events (WS3) — `GET …/audit` reading the DO ring
/// then falling back to R2 segments (CONTRACTS §5.4). `cursor` continues paging
/// back into history; nil when exhausted.
public struct AuditPage: Sendable, Hashable, Codable {
    public var events: [ActivityEvent]
    public var cursor: String?

    public init(events: [ActivityEvent], cursor: String? = nil) {
        self.events = events; self.cursor = cursor
    }
}

// MARK: Snapshots

public struct Snapshot: Identifiable, Sendable, Hashable, Codable {
    public let id: String
    public var name: String        // e.g. "Hourly 14:00" / "Daily 2026-06-03"
    public var takenAt: Date
    public var sizeBytes: Int64    // logical namespace size at that point
    public var isScheduled: Bool   // server-side schedule vs manual
    public var retentionTier: String // "Hourly", "Daily", "Weekly" (GFS)
    public var scope: String?

    public init(id: String, name: String, takenAt: Date, sizeBytes: Int64,
                isScheduled: Bool, retentionTier: String, scope: String? = nil) {
        self.id = id; self.name = name; self.takenAt = takenAt; self.sizeBytes = sizeBytes
        self.isScheduled = isScheduled; self.retentionTier = retentionTier; self.scope = scope
    }
}

/// The outcome of a snapshot restore (API.md `RestoreResult`). Non-destructive:
/// each restored item becomes a new current version; conflicts are items skipped
/// because another owner holds an exclusive lease (never clobbered).
public struct RestoreResult: Sendable, Hashable, Codable {
    public let snapshotId: String
    public var restored: [String]            // ids restored to the as-of state
    public var recreated: [String]           // ids re-created (deleted since snapshot)
    public var conflicts: [Conflict]         // skipped: exclusively locked by another owner
    public var forbidden: [String]?
    public var skippedPermissions: Int?
    public var streamsCaptured: Bool?
    public var newerThanSnapshot: [String]   // exist now but not in the snapshot (left untouched)

    public struct Conflict: Sendable, Hashable, Codable, Identifiable {
        public let id: String                // inode id
        public var heldBy: String?
        public init(id: String, heldBy: String?) { self.id = id; self.heldBy = heldBy }
    }

    public var totalApplied: Int { restored.count + recreated.count }
    public var hasConflicts: Bool { !conflicts.isEmpty }

    public init(snapshotId: String, restored: [String], recreated: [String],
                conflicts: [Conflict], newerThanSnapshot: [String], forbidden: [String]? = nil, skippedPermissions: Int? = nil, streamsCaptured: Bool? = nil) {
        self.snapshotId = snapshotId; self.restored = restored; self.recreated = recreated
        self.conflicts = conflicts; self.newerThanSnapshot = newerThanSnapshot; self.forbidden = forbidden
        self.skippedPermissions = skippedPermissions; self.streamsCaptured = streamsCaptured
    }
}

// MARK: Sharing

public enum ShareKind: String, Sendable, Codable {
    case internalDeepLink = "cloudfs:// link"   // opens in recipient's Finder
    case guestLink        = "Guest link"        // browser, temp email code, view/download only
}

public struct CloudShareLink: Identifiable, Sendable, Hashable, Codable {
    public let id: String
    public var path: String
    public var kind: ShareKind
    public var url: String
    public var expiresAt: Date?
    public var canDownload: Bool
    public var canEdit: Bool

    public init(id: String, path: String, kind: ShareKind, url: String,
                expiresAt: Date? = nil, canDownload: Bool = true, canEdit: Bool = false) {
        self.id = id; self.path = path; self.kind = kind; self.url = url
        self.expiresAt = expiresAt; self.canDownload = canDownload; self.canEdit = canEdit
    }
}

// MARK: Cache settings (the "superpower")

/// The engine-owned cache config — the only cache we can resize/relocate
/// (docs §5.4; ONBOARDING.md "Defaults"). Defaults: 25 GB (decimal) default,
/// 10 TiB max, up to 80% usable for pinning.
public struct CacheSettings: Sendable, Hashable, Codable {
    public var maxBytes: Int64          // user-set ceiling
    public var usedBytes: Int64         // current cache occupancy
    public var pinnedBytes: Int64       // portion held by pins (≤ 80% of max)
    public var location: String         // relocatable path (must be SSD/APFS)
    public var prefetchEnabled: Bool
    public var prefetchDepth: Int       // speculative blocks ahead of served range

    // Decimal 25 GB — matches cloudfsd's default cache-size (Daemon.swift), so a
    // freshly-provisioned daemon's ceiling lands exactly at the slider's floor
    // instead of below it.
    public static let minBytes: Int64  = 25_000_000_000                    // 25 GB
    public static let maxAllowed: Int64 = 10 * 1024 * 1024 * 1024 * 1024     // 10 TiB
    public static let pinningCeilingFraction = 0.80

    public var usedFraction: Double {
        guard maxBytes > 0 else { return 0 }
        return min(1, Double(usedBytes) / Double(maxBytes))
    }

    public var pinnedFraction: Double {
        guard maxBytes > 0 else { return 0 }
        return min(1, Double(pinnedBytes) / Double(maxBytes))
    }

    /// Bytes of the cache ceiling reserved for pins — the SAME 80% threshold
    /// `CacheGauge` draws as its marker line. One derivation so the gauge and any
    /// "remaining pinning" readout never disagree.
    public var pinningCeilingBytes: Int64 {
        guard maxBytes > 0 else { return 0 }
        return Int64((Double(maxBytes) * Self.pinningCeilingFraction).rounded())
    }

    /// How many more bytes could be pinned before hitting the 80% ceiling. Never
    /// negative — a cache that's already at or over the ceiling (e.g. after the
    /// user shrinks `maxBytes`) reads as zero remaining, not a negative number.
    public var remainingPinningBytes: Int64 {
        max(0, pinningCeilingBytes - pinnedBytes)
    }

    public init(maxBytes: Int64, usedBytes: Int64, pinnedBytes: Int64, location: String,
                prefetchEnabled: Bool, prefetchDepth: Int) {
        self.maxBytes = maxBytes; self.usedBytes = usedBytes; self.pinnedBytes = pinnedBytes
        self.location = location; self.prefetchEnabled = prefetchEnabled
        self.prefetchDepth = prefetchDepth
    }
}

// MARK: Credentials (login / connect flow)

/// Two auth paths per spec: interactive (email + filespace, SSO at the Worker
/// layer) and a service-account token (for headless / CLI / render nodes).
public enum Credentials: Sendable, Hashable {
    case interactive(email: String, filespace: String)
    case serviceToken(token: String)
}

// MARK: - Formatting helpers (shared by the views)

public enum ByteFormat {
    public static func string(_ bytes: Int64) -> String {
        // ByteCountFormatter renders 0 as "Zero KB" — render a clean "0 KB" instead
        // so queued/empty transfers and zero cache values read naturally.
        guard bytes > 0 else { return "0 KB" }
        let fmt = ByteCountFormatter()
        fmt.countStyle = .binary
        fmt.allowedUnits = [.useKB, .useMB, .useGB, .useTB]
        return fmt.string(fromByteCount: bytes)
    }

    public static func rate(_ bytesPerSec: Int64) -> String {
        guard bytesPerSec > 0 else { return "—" }
        return string(bytesPerSec) + "/s"
    }
}

extension Int64 {
    public func clamped(_ lo: Int64, _ hi: Int64) -> Int64 { Swift.min(hi, Swift.max(lo, self)) }
}

/// The folder picker advances the server's opaque cursor, including empty ACL-filtered pages.
public struct DirectoryPage: Sendable {
    public var items: [FileNode]
    public var cursor: String?
    public init(items: [FileNode], cursor: String? = nil) {
        self.items = items; self.cursor = cursor
    }
}

/// Public deployment-storage metadata; credentials never enter the creation UI.
public struct WorkspaceStorage: Sendable, Codable, Equatable {
    public let configured: Bool
    public let provider: String
    public let region: String
    public let bucket: String
    public let problems: [String]
    public init(configured: Bool, provider: String, region: String, bucket: String, problems: [String] = []) {
        self.configured = configured; self.provider = provider; self.region = region; self.bucket = bucket; self.problems = problems
    }
    public var providerLabel: String {
        switch provider { case "r2": return "Cloudflare R2"; case "s3": return "Amazon S3"; case "b2": return "Backblaze B2"; default: return provider }
    }
    public var regionLabel: String { region == "auto" ? "Automatic region" : region }
}
