// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - EngineClient — the local-engine seam (cloudfsd control plane)
//
// The GUI's engine-owned operations live behind THIS protocol. They are the
// methods the Cloudflare gateway does NOT own (cache, pins, prefetch/evict, live
// transfer progress, connection pause/resume, mount, sync barriers) — the ones
// HttpGatewayClient used to answer with `.unsupported`. The real implementation
// is `DaemonEngineClient`, which speaks newline-delimited JSON-RPC 2.0 over the
// cloudfsd Unix-domain socket (cloudfsd/CONTROL-API.md). The offline default is
// `NullEngineClient` (every op throws `.unavailable`), so the app still runs with
// no daemon.
//
// All ops take a `filespace` id, are `async throws` (errors map to `EngineError`),
// and `Sendable`. Live feeds are `AsyncStream`s fed by the JSON-RPC event stream.

public protocol EngineClient: Sendable {

    /// True when a daemon socket is reachable. (NullEngineClient is always false.)
    var isAvailable: Bool { get }

    // --- Connection (CONTROL-API §4) ----------------------------------------

    /// GUI pause/resume sync → `filespace.setConnectionState`.
    func setConnectionState(_ connected: Bool, filespace: String) async throws

    // --- Mount (CONTROL-API §5.1) -------------------------------------------

    /// `name` is the filespace DISPLAY NAME (M3): the daemon's NFS backend derives
    /// the Finder-sidebar hostname from it ("Edit 1" → "Edit-1.local").
    func mount(filespace: String, at path: String?, name: String?) async throws -> EngineFilespace
    func mountOffline(filespace: String, pinPath: String, name: String?) async throws -> EngineFilespace
    func unmount(filespace: String, force: Bool) async throws -> EngineFilespace

    /// What the daemon currently has connected/mounted (CONTROL-API `filespace.list`).
    /// The GUI overlays this onto the gateway registry so a filespace card shows Connected +
    /// its REAL mount path only when the local engine has it mounted (i.e. it matches Finder),
    /// instead of the gateway's optimistic "always connected". `NullEngineClient` returns []
    /// (no daemon ⇒ nothing is mounted locally).
    func filespaceList() async throws -> [EngineFilespace]

    /// Resolve an existing mounted path to a stable team-link identity.
    func createItemLink(filespace: String, path: String) async throws -> EngineItemLink
    /// Resolve a stable identity through this account's ACLs and mounted root.
    func resolveItemLink(filespace: String, itemID: String) async throws -> EngineLinkTarget

    func mountSnapshot(filespace: String, snapshotID: String, at path: String?, name: String?) async throws -> SnapshotMount
    func unmountSnapshot(mountID: String, force: Bool) async throws -> SnapshotMount
    func snapshotMounts(filespace: String?) async throws -> [SnapshotMount]

    // --- Pins / prefetch / evict (CONTROL-API §5.4) -------------------------

    func pin(filespace: String, path: String, recursive: Bool) async throws -> PinState
    func unpin(filespace: String, path: String, recursive: Bool) async throws -> PinState
    func prefetch(filespace: String, path: String) async throws -> PrefetchAck
    func evict(filespace: String, path: String) async throws -> EvictAck

    /// Enumerate every pin in a filespace (CONTROL-API `pin.list`). Powers the
    /// Pinned Items view (WS2). Each `PinState` carries per-item byte accounting +
    /// cache state (CONTRACTS §4.1). `NullEngineClient` throws `.unavailable`.
    func pinList(filespace: String) async throws -> [PinState]

    // --- Cache (CONTROL-API §5.3) -------------------------------------------

    func cacheInfo(filespace: String) async throws -> CacheInfo
    func cacheSetSize(filespace: String, bytes: Int64) async throws -> CacheInfo
    func cacheSetLocation(filespace: String, path: String) async throws -> CacheInfo

    /// Filespace-wide "Clear cache" (`cache.clear`): evicts every evictable block —
    /// the daemon itself protects pinned content and any not-yet-durable local
    /// write, so this is safe to call while reads/writes are in flight. Engine-only
    /// (cache is engine-owned, §5.4); `NullEngineClient` throws `.unavailable`.
    func cacheClear(filespace: String) async throws -> CacheClearResult

    // --- Transfers (CONTROL-API §5.5 + §6) ----------------------------------

    func currentTransfers(filespace: String) async throws -> [Transfer]
    func clearCompletedTransfers(filespace: String) async throws
    func pauseTransfers(filespace: String) async throws
    func resumeTransfers(filespace: String) async throws
    func recoveryItems(filespace: String) async throws -> [RecoveryItem]
    func retryRecovery(filespace: String, itemID: String) async throws
    func exportRecovery(filespace: String, itemID: String, destination: String) async throws -> RecoveryExportResult
    func completeRecovery(filespace: String, itemID: String, destination: String) async throws

    /// Live transfer snapshots, fed by the `transfer` event notifications.
    func transferUpdates(filespace: String) -> AsyncStream<[Transfer]>

    // --- Sync barriers (CONTROL-API §5.6) -----------------------------------

    func syncState(filespace: String, path: String) async throws -> SyncState
    /// `flush(wait: true)` is the durability barrier; may throw `.syncTimeout`/`.syncFailed`.
    func flush(filespace: String, path: String, wait: Bool, timeoutMs: Int?) async throws -> SyncState

    /// `status` for one filespace: gateway reachability, last success/failure and
    /// the mounted grant roots (CONTROL-API §3 `EngineStatus`). All newer fields are
    /// optional — an older daemon answers with just the legacy ones.
    func status(filespace: String) async throws -> EngineStatus
}

public extension EngineClient {
    /// Local presentation history; older/offline adapters have no retained stream.
    func clearCompletedTransfers(filespace: String) async throws {}
}

// MARK: - Engine wire shapes (CONTROL-API §3)
//
// Decodable mirrors of the JSON-RPC result objects. Kept here (not in Models)
// because they are the engine's view; the GUI maps them onto its own
// `CacheSettings` / `Transfer` types in AppModel.

public struct EngineFilespace: Sendable, Decodable, Equatable {
    public let id: String
    public let name: String
    public let status: String                 // "connected" | "connecting" | "disconnected"
    public let mountPath: String?
    public let rootPoint: String?
    public let role: String?
    public let paused: Bool?
    public let sourceFilespace: String?
    public let snapshotId: String?
    public let readOnly: Bool?
}

public struct CacheInfo: Sendable, Decodable, Equatable {
    public let filespace: String
    public let location: String
    public let sizeBytes: Int64
    public let usedBytes: Int64
    public let pinnedBytes: Int64
    public let maxBytes: Int64
    public let freeOnVolumeBytes: Int64
    public let hitRate: Double
}

public struct PinState: Sendable, Decodable, Equatable {
    public let path: String
    public let pinned: Bool
    public let recursive: Bool
    public let blocks: Int

    // --- APPENDED (WS2 T2.1, CONTRACTS §4.2). Optional for back-compat with
    //     older daemons that omit them. ---
    public let cachedBytes: UInt64?    // nil when an older engine omits it
    public let totalBytes: UInt64?
    public let cacheState: PinCacheState?
    public let failureReason: String?
    public let offlineReady: Bool?
    public let offlineExpiresAt: Date?
    public let offlineFailureReason: String?

    public init(path: String, pinned: Bool, recursive: Bool, blocks: Int,
                cachedBytes: UInt64? = nil, totalBytes: UInt64? = nil,
                cacheState: PinCacheState? = nil, failureReason: String? = nil, offlineReady: Bool? = nil, offlineExpiresAt: Date? = nil, offlineFailureReason: String? = nil) {
        self.path = path; self.pinned = pinned; self.recursive = recursive
        self.blocks = blocks; self.cachedBytes = cachedBytes
        self.totalBytes = totalBytes; self.cacheState = cacheState
        self.failureReason = failureReason
        self.offlineReady = offlineReady; self.offlineExpiresAt = offlineExpiresAt; self.offlineFailureReason = offlineFailureReason
    }
}

/// Per-pin cache residency (CONTRACTS §4.1/§4.2). Two states only: a pinned path
/// is either fully resident or still materializing. An unpinned/evicted path holds
/// no pin record, so it never appears in pin.list and has no cache-state.
public enum PinCacheState: String, Sendable, Decodable, Equatable {
    case pinned     // fully resident, non-evictable (cachedBytes == totalBytes)
    case pinning    // pin set, still materializing (0 <= cachedBytes < totalBytes)
}

/// The Pinned-view row projection of a `PinState` (CONTRACTS §4.3). The wire type
/// is `PinState[]`; `PinnedItem` is the display model the PinnedItemsView renders.
public struct PinnedItem: Identifiable, Sendable, Hashable {
    public var id: String { path }
    public let path: String
    public let recursive: Bool
    public let cachedBytes: UInt64     // 0 when the engine omitted it (→ .pinning display)
    public let totalBytes: UInt64
    public let state: PinCacheState    // pinned | pinning
    public let failureReason: String?
    public let offlineReady: Bool
    public let offlineExpiresAt: Date?
    public let offlineFailureReason: String?

    public init(from p: PinState) {
        self.path = p.path
        self.recursive = p.recursive
        let cached = p.cachedBytes ?? 0
        let total  = p.totalBytes ?? 0
        self.cachedBytes = cached
        self.totalBytes  = total
        // Prefer the engine's state; when an older daemon omits it, derive the same
        // two-state result it would: fully resident → pinned, otherwise pinning.
        self.state = p.cacheState ?? ((total > 0 && cached >= total) ? .pinned : .pinning)
        self.failureReason = p.failureReason
        self.offlineReady = p.offlineReady ?? false; self.offlineExpiresAt = p.offlineExpiresAt; self.offlineFailureReason = p.offlineFailureReason
    }
}

/// `cache.clear`'s client-side result. The wire RPC returns the post-clear
/// `CacheInfo` (CONTROL-API.md §5.3, matching `cache.setSize`/`cache.setLocation`'s
/// convention exactly); `freedBytes` is derived by the client from the `usedBytes`
/// delta across the call (a `cache.info` immediately before, minus the result), so
/// the wire contract stays unchanged for other callers (CLI `cache clear`).
public struct CacheClearResult: Sendable, Equatable {
    public let info: CacheInfo
    public let freedBytes: Int64
    public init(info: CacheInfo, freedBytes: Int64) { self.info = info; self.freedBytes = freedBytes }
}

public struct PrefetchAck: Sendable, Decodable, Equatable {
    public let path: String
    public let queuedBlocks: Int
}

public struct EvictAck: Sendable, Decodable, Equatable {
    public let path: String
    public let evictedBlocks: Int
    public let freedBytes: Int64
}

/// Gateway reachability as the daemon classified it (`EngineStatus.reachability`).
public enum EngineReachability: String, Sendable, Equatable {
    case online, degraded, offline
}

/// The slice of the daemon's `EngineStatus` the app uses. Every field beyond
/// `filespace` is optional so older daemons keep decoding.
/// Actual object-store requests; duration includes the response body, not network RTT.
public struct StorageTelemetry: Sendable, Codable, Equatable {
    public var reachability: String?
    public var lastSuccessAt: Int64?
    public var lastFailureAt: Int64?
    public var lastFailureReason: String?
    public var requestDurationMs: Double?
    public var requests: Int = 0
    public var retries: Int = 0
    public var failures: Int = 0
    public var activeRequests: Int = 0
    public var downloadBytesPerSecond: Double = 0
    public var uploadBytesPerSecond: Double = 0
    public init() {}
}

public struct EngineStatus: Sendable, Decodable, Equatable {
    public let filespace: String
    public let connection: String?
    public let latencyMsToBucket: Double?
    public let gatewayLatencyMs: Double?
    public let storage: StorageTelemetry?
    public let pendingUploads: Int?
    public let pendingBytes: Int64?
    public let lastSuccessAt: Int64?      // epoch ms
    public let lastFailureAt: Int64?      // epoch ms
    public let lastFailureReason: String?
    public let reachabilityRaw: String?
    /// Grant-root ids this mount's projection was built from (nil = whole filespace / explicit folder).
    public let mountedRootIds: [String]?

    public var reachability: EngineReachability? { reachabilityRaw.flatMap(EngineReachability.init(rawValue:)) }

    private enum CodingKeys: String, CodingKey {
        case filespace, connection, latencyMsToBucket, gatewayLatencyMs, storage, pendingUploads, pendingBytes
        case lastSuccessAt, lastFailureAt, lastFailureReason, mountedRootIds
        case reachabilityRaw = "reachability"
    }

    public init(filespace: String, connection: String? = nil, latencyMsToBucket: Double? = nil,
                pendingUploads: Int? = nil, pendingBytes: Int64? = nil,
                lastSuccessAt: Int64? = nil, lastFailureAt: Int64? = nil, lastFailureReason: String? = nil,
                reachability: EngineReachability? = nil, mountedRootIds: [String]? = nil,
                gatewayLatencyMs: Double? = nil, storage: StorageTelemetry? = nil) {
        self.filespace = filespace; self.connection = connection; self.latencyMsToBucket = latencyMsToBucket
        self.pendingUploads = pendingUploads; self.pendingBytes = pendingBytes
        self.lastSuccessAt = lastSuccessAt; self.lastFailureAt = lastFailureAt
        self.lastFailureReason = lastFailureReason; self.reachabilityRaw = reachability?.rawValue
        self.mountedRootIds = mountedRootIds
        self.gatewayLatencyMs = gatewayLatencyMs; self.storage = storage
    }
}

public struct SyncState: Sendable, Decodable, Equatable {
    public let path: String
    public let inSync: Bool
    public let pendingUploads: Int
    public let pendingBytes: Int64
}

/// The engine's `Transfer` shape (CONTROL-API §3). Mapped to the GUI `Transfer`
/// model by `EngineTransfer.toGUI()`.
public struct EngineTransfer: Sendable, Decodable, Equatable {
    public let id: String
    public let filespace: String
    public let path: String
    public let direction: String              // "download" | "upload"
    public let bytesDone: Int64
    public let bytesTotal: Int64
    public let state: String                  // "queued"|"active"|"paused"|"done"|"error"
    public let error: String?

    public func toGUI() -> Transfer {
        Transfer(
            id: id,
            fileName: (path as NSString).lastPathComponent.isEmpty ? path : (path as NSString).lastPathComponent,
            kind: direction == "upload" ? .upload : .download,
            state: Self.mapState(state),
            bytesDone: bytesDone,
            bytesTotal: bytesTotal,
            throughputBytesPerSec: 0,         // engine `transfer` events don't carry a rate; menu-bar derives it
            startedAt: Date(), path: path, error: error)
    }

    private static func mapState(_ s: String) -> TransferState {
        switch s {
        case "queued":  return .queued
        case "active":  return .active
        case "paused":  return .paused
        case "done":    return .completed
        case "error":   return .failed
        default:        return .queued
        }
    }
}

// MARK: - NullEngineClient (offline default)
//
// Used whenever no daemon socket is configured/reachable. Every op fails with
// `.unavailable` so callers can fall back gracefully; the live feed finishes
// immediately. This is what keeps Mock the default and the app fully offline.

public struct NullEngineClient: EngineClient {
    public init() {}
    public var isAvailable: Bool { false }

    private func unavailable() throws -> Never { throw EngineError.unavailable("no cloudfsd socket configured") }

    public func setConnectionState(_ connected: Bool, filespace: String) async throws { try unavailable() }
    public func mount(filespace: String, at path: String?, name: String?) async throws -> EngineFilespace { try unavailable() }
    public func unmount(filespace: String, force: Bool) async throws -> EngineFilespace { try unavailable() }
    public func filespaceList() async throws -> [EngineFilespace] { [] }  // no daemon ⇒ nothing mounted locally
    public func pin(filespace: String, path: String, recursive: Bool) async throws -> PinState { try unavailable() }
    public func unpin(filespace: String, path: String, recursive: Bool) async throws -> PinState { try unavailable() }
    public func prefetch(filespace: String, path: String) async throws -> PrefetchAck { try unavailable() }
    public func evict(filespace: String, path: String) async throws -> EvictAck { try unavailable() }
    public func pinList(filespace: String) async throws -> [PinState] { try unavailable() }
    public func status(filespace: String) async throws -> EngineStatus { try unavailable() }
    public func cacheInfo(filespace: String) async throws -> CacheInfo { try unavailable() }
    public func cacheSetSize(filespace: String, bytes: Int64) async throws -> CacheInfo { try unavailable() }
    public func cacheSetLocation(filespace: String, path: String) async throws -> CacheInfo { try unavailable() }
    public func cacheClear(filespace: String) async throws -> CacheClearResult { try unavailable() }
    public func currentTransfers(filespace: String) async throws -> [Transfer] { try unavailable() }
    public func pauseTransfers(filespace: String) async throws { try unavailable() }
    public func resumeTransfers(filespace: String) async throws { try unavailable() }
    public func transferUpdates(filespace: String) -> AsyncStream<[Transfer]> {
        AsyncStream { $0.finish() }
    }
    public func syncState(filespace: String, path: String) async throws -> SyncState { try unavailable() }
    public func flush(filespace: String, path: String, wait: Bool, timeoutMs: Int?) async throws -> SyncState { try unavailable() }
}

public extension EngineClient {
    func mountOffline(filespace: String, pinPath: String, name: String?) async throws -> EngineFilespace {
        throw EngineError.unavailable("Offline copies require an updated local engine.")
    }
}
