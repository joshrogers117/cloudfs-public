// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - Dashboard — pure state derivation (client-app redesign lane 1)
//
// The per-filespace Dashboard's hero row flips between six honest states
// (connected / connecting / paused / not-mounted / probe-failed / demo). The
// *derivation* — which state a given (connection, mount path, mount-probe)
// triple maps to, plus the copy that goes with it — is pure logic with no
// SwiftUI dependency, so it's unit-tested here the same way
// `OnboardingChecklist` tests the checklist's row-state machine. `DashboardView`
// only renders whichever case is active.

// MARK: Hero state

public enum DashboardHeroState: Equatable, Sendable {
    /// Mounted and reachable — `mountPath` is real + non-empty.
    case connected(mountPath: String)
    /// Gateway/domain is registering — not mounted yet.
    case connecting
    /// User-paused sync; the mount itself may still be present.
    case paused
    /// Not mounted on this Mac right now (disconnected, errored, or connected
    /// with no local mount path yet) — a single honest "isn't mounted" bucket
    /// rather than pretending to distinguish causes the user can't act on.
    case notMounted
    /// Mock/offline (Demo) mode: no real daemon, so this is a clearly-labeled
    /// stand-in for "connected" rather than a verified state (mirrors
    /// `MountRowState.demo`'s honesty rule).
    case demo(mountPath: String)
    /// The first-run checklist's verified mount probe actually ran and failed —
    /// the hero flips to the failure, never a dead volume presented as success.
    case probeFailed(MountProbeFailure)
    /// Mounted, but the daemon sees recent gateway failures alongside successes.
    case degraded(mountPath: String)
    /// Mounted, but the gateway has been unreachable (no success in 30 s, a failure since).
    /// Never rendered as "connected".
    case offline(mountPath: String)

    /// Derive the hero state from the filespace's connection + mount path and
    /// (if one has run this session) the first-run checklist's verified-mount
    /// probe result for it. A failed probe always wins (it's the strongest,
    /// most specific signal); `.demo` next; otherwise the state follows the
    /// plain connection value.
    ///
    /// Note: `probe` is commonly `nil` outside the first run (the checklist
    /// only re-populates rows when it re-presents), so most steady-state
    /// dashboards fall straight through to the connection-based branches —
    /// never fabricating a probe result that was never actually run.
    public static func derive(connection: ConnectionState, mountPath: String,
                              probe: MountRowState?,
                              reachability: EngineReachability? = nil) -> DashboardHeroState {
        if case .failed(let failure) = probe { return .probeFailed(failure) }
        if probe == .demo { return .demo(mountPath: mountPath) }
        switch connection {
        case .connected:
            if mountPath.isEmpty { return .notMounted }
            switch reachability {
            case .offline: return .offline(mountPath: mountPath)
            case .degraded: return .degraded(mountPath: mountPath)
            case .online, nil: return .connected(mountPath: mountPath)
            }
        case .connecting:
            return .connecting
        case .paused:
            return .paused
        case .disconnected, .error:
            return .notMounted
        }
    }

    /// "«name» is connected" / "is connecting…" / etc. Never aspirational —
    /// mirrors the actual state exactly.
    public func headline(filespaceName: String) -> String {
        switch self {
        case .connected, .demo: return "\(filespaceName) is connected"
        case .connecting:       return "\(filespaceName) is connecting…"
        case .paused:           return "\(filespaceName) is paused"
        case .notMounted:       return "\(filespaceName) isn’t mounted"
        case .probeFailed(let failure): return failure.title
        case .degraded:         return "\(filespaceName) has connection problems"
        case .offline:          return "\(filespaceName) is offline"
        }
    }

    /// One-line explanatory sub-copy under the headline.
    public var subCopy: String {
        switch self {
        case .connected, .demo:
            return "Open this filespace in Finder to work with your files."
        case .connecting:
            return "Setting up your volume. This usually takes a few seconds."
        case .paused:
            return "Sync is paused, so changes won’t move until you resume it."
        case .notMounted:
            return "Connect this filespace to make it available in Finder."
        case .probeFailed(let failure):
            return failure.detail
        case .degraded:
            return "Some requests to the server are failing. Files you have open keep working and changes are kept on this Mac."
        case .offline:
            return "Can’t reach the server. Changes are kept on this Mac and upload when the connection returns."
        }
    }

    /// Whether the hero's primary CTA can actually open a real mount right now.
    public var canOpenInFinder: Bool {
        switch self {
        case .connected, .demo, .degraded, .offline: return true
        default: return false
        }
    }

    /// Whether the hero should render as the failure variant (warning tint,
    /// "Run checks again" in place of "Open in Finder").
    public var isProbeFailure: Bool {
        if case .probeFailed = self { return true }
        return false
    }
}

// MARK: - "Remaining upload" — engine-preferred, honest fallback

/// The Connection card's "Remaining upload" figure. Never a fabricated number:
/// unavailable renders as "—", not 0.
public enum DashboardUploadDisplay: Equatable, Sendable {
    case bytes(Int64)
    case unavailable
}

public enum DashboardDerivations {

    /// Prefer the engine's `sync.state` durability-barrier reading
    /// (`pendingBytes`, filespace-wide) when the daemon answered it; otherwise
    /// fall back to the client-side sum over queued/active transfers; otherwise
    /// (no engine AND no transfer data) the figure is genuinely unknown.
    public static func remainingUpload(engineSyncPendingBytes: Int64?,
                                       transfersLoaded: Bool,
                                       transferSumBytes: Int64) -> DashboardUploadDisplay {
        if let engineBytes = engineSyncPendingBytes { return .bytes(engineBytes) }
        if transfersLoaded { return .bytes(transferSumBytes) }
        return .unavailable
    }
}

extension Array where Element == Transfer {
    /// Σ (bytesTotal − bytesDone) over queued/active uploads — the client-side
    /// fallback for "Remaining upload" when the engine's `sync.state` barrier
    /// isn't available (no daemon, or the call itself failed).
    public var pendingUploadBytes: Int64 {
        filter { $0.kind == .upload && ($0.state == .active || $0.state == .queued) }
            .reduce(Int64(0)) { $0 + Swift.max(0, $1.bytesTotal - $1.bytesDone) }
    }
}

// MARK: - Connection card: truthful reachability + upload retry copy

/// What the Connection card's status row shows. `.unknown` = the daemon didn't
/// report reachability (older daemon, or nothing observed yet): the card then falls
/// back to the mount state and never claims more than that.
public enum ConnectionHealthDisplay: Equatable, Sendable {
    case online, degraded, offline, unknown

    public init(_ reachability: EngineReachability?) {
        switch reachability {
        case .online: self = .online
        case .degraded: self = .degraded
        case .offline: self = .offline
        case nil: self = .unknown
        }
    }

    public var label: String? {
        switch self {
        case .online: return "Online"
        case .degraded: return "Degraded"
        case .offline: return "Offline"
        case .unknown: return nil
        }
    }
}

public extension DashboardDerivations {

    /// First error carried by a not-yet-saved upload, if any.
    static func firstUploadError(_ transfers: [Transfer]) -> String? {
        transfers.first(where: {
            $0.kind == .upload && $0.state != .completed && ($0.error?.isEmpty == false)
        })?.error
    }

    /// The single durability line under the status dot. A staged upload that keeps
    /// failing must say so instead of "Saving changes to cloud" forever.
    static func durabilityLabel(isHttpMode: Bool, recoveryNeedsAttention: Bool, paused: Bool,
                                mountPathEmpty: Bool, inSync: Bool?, uploadError: String?,
                                health: ConnectionHealthDisplay) -> String {
        if !isHttpMode { return "Sample connection" }
        if recoveryNeedsAttention { return "Local changes need attention" }
        if paused { return "Transfers paused" }
        if mountPathEmpty { return "Not connected on this Mac" }
        if inSync != true, let uploadError, !uploadError.isEmpty {
            return "Uploads retrying — last error: \(uploadError)"
        }
        if health == .offline { return inSync == true ? "All changes saved to cloud" : "Offline — changes wait on this Mac" }
        if inSync == true { return "All changes saved to cloud" }
        if inSync == false { return "Saving changes to cloud" }
        return "Connected · checking uploads"
    }

    static func storageDetail(_ storage: StorageTelemetry?) -> String {
        guard let storage, let state = storage.reachability else { return "Storage · no recent requests" }
        if state == "degraded" { return "Storage · " + (storage.lastFailureReason ?? "request failed") }
        let duration = storage.requestDurationMs.map { " · \(Int($0.rounded())) ms/request" } ?? ""
        let down = ByteFormat.string(Int64(storage.downloadBytesPerSecond))
        let up = ByteFormat.string(Int64(storage.uploadBytesPerSecond))
        return "Storage · ↓ \(down)/s · ↑ \(up)/s" + duration + " · \(storage.retries) retries"
    }

    /// Compact detail for the status row: latency when online, last failure otherwise.
    static func connectionDetail(health: ConnectionHealthDisplay, latencyMs: Double?, lastFailureReason: String?) -> String? {
        switch health {
        case .online:
            guard let latencyMs else { return nil }
            return "Metadata · \(Int(latencyMs.rounded())) ms/request"
        case .degraded, .offline:
            return lastFailureReason.flatMap { $0.isEmpty ? nil : "Last error: \($0)" }
        case .unknown:
            return nil
        }
    }
}

// MARK: - "New access available" (grant roots changed since the volume was mounted)

public enum MountAccessChange {
    /// True when the user can now reach a shared-folder root that the mounted
    /// projection was not built from. `mounted == nil` (whole filespace / explicit
    /// folder / older daemon) never shows the hint; removed grants don't either —
    /// the daemon deliberately keeps its aliases until remount.
    public static func hasNewAccess(mountedRootIds: [String]?, currentRootIds: [String]) -> Bool {
        guard let mountedRootIds else { return false }
        return !Set(currentRootIds).subtracting(mountedRootIds).isEmpty
    }
}

// MARK: - Dashboard poll plan (what each 3-second tick refreshes)

public struct DashboardRefreshPlan: Equatable, Sendable {
    /// Re-read the daemon's mount table (`filespace.list`) WITHOUT auto-mounting, so a
    /// Finder eject flips the hero, sidebar "Open" and Disconnect within a tick.
    public var refreshMountState: Bool
    /// Compare the gateway's current grant roots with the mounted projection.
    public var checkNewAccess: Bool
    /// Fetch current cloud usage while the dashboard is visible. Daemon status
    /// contains local cache/transfer metrics, not the cloud namespace size.
    public var refreshUsage: Bool

    public static let accessCheckInterval: TimeInterval = 30

    /// A mount/unmount in flight owns the connection state; don't race it. The access
    /// check hits the gateway, so it is rate-limited.
    public static func make(operationInFlight: Bool, lastAccessCheck: Date?, now: Date,
                            lastUsageCheck: Date? = nil) -> DashboardRefreshPlan {
        let due = lastAccessCheck.map { now.timeIntervalSince($0) >= accessCheckInterval } ?? true
        let usageDue = lastUsageCheck.map { now.timeIntervalSince($0) >= accessCheckInterval } ?? true
        return DashboardRefreshPlan(refreshMountState: !operationInFlight,
                                    checkNewAccess: !operationInFlight && due,
                                    refreshUsage: !operationInFlight && usageDue)
    }
}
