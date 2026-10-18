// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCore — the control-plane contract as typed Codable payloads. FROZEN.
//
// One Codable type per CONTROL-API.md method's params + result, plus the event
// notifications. `ControlMethod` is the closed set of method names. The CLI and
// the macOS GUI both wire against THESE types (and the wire frames in
// JSONRPC.swift). Implementers depend on this read-only.

import Foundation

// MARK: - Method names (the closed set — CONTROL-API.md §4–7)

public enum ControlMethod: String, Sendable, Codable, CaseIterable {
    // §4 filespace / connection
    case filespaceList          = "filespace.list"
    case filespaceConnect       = "filespace.connect"
    case filespaceDisconnect    = "filespace.disconnect"
    case filespaceSetConnection = "filespace.setConnectionState"
    // §5.1 mount
    case mount
    case unmount
    case snapshotMount = "snapshot.mount"
    case snapshotUnmount = "snapshot.unmount"
    case snapshotMounts = "snapshot.mounts"
    // §5.2 status
    case status
    // §5.3 cache
    case cacheInfo        = "cache.info"
    case cacheSetSize     = "cache.setSize"
    case cacheSetLocation = "cache.setLocation"
    case cacheClear       = "cache.clear"
    // §5.4 pin / prefetch / evict
    case pin
    case unpin
    case pinList = "pin.list"
    case prefetch
    case evict
    case linkCreate = "link.create"
    case linkResolve = "link.resolve"
    // §5.5 transfers
    case transfersCurrent = "transfers.current"
    case transfersPause   = "transfers.pause"
    case transfersResume  = "transfers.resume"
    case recoveryList = "recovery.list"
    case recoveryRetry = "recovery.retry"
    case recoveryExport = "recovery.export"
    case recoveryComplete = "recovery.complete"
    // §5.6 sync barriers
    case syncState = "sync.state"
    case flush
    // §6 events
    case eventsSubscribe   = "events.subscribe"
    case eventsUnsubscribe = "events.unsubscribe"
    // §7 data path (out-of-process clients — the File Provider appex streams byte ranges + reads
    // metadata/enumeration served from the daemon's cache & metadata sync; the in-process FUSE
    // mount calls EngineDataPath directly).
    case dataReadRange         = "data.readRange"
    case dataLookup            = "data.lookup"
    case dataEnumerate         = "data.enumerate"
    case dataEnumerateChanges  = "data.enumerateChanges"
    // §8 versioning
    case systemVersion = "system.version"
}

// MARK: - §7 data path (out-of-process: File Provider appex)

/// Read a decrypted byte range of an item, served from the daemon's cache (HIT) or fetched +
/// decrypted on MISS. The daemon materializes the range into a file a separate-process client
/// (the appex) can read (a path in the shared App-Group container, or an FD over NSXPC).
public struct DataReadRangeParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var itemId: InodeID
    public var version: String
    public var offset: Int
    public var length: Int
    public var alignment: Int?
    public init(filespace: FilespaceID, itemId: InodeID, version: String,
                offset: Int, length: Int, alignment: Int? = nil) {
        self.filespace = filespace; self.itemId = itemId; self.version = version
        self.offset = offset; self.length = length; self.alignment = alignment
    }
}

public struct DataReadRangeResult: Sendable, Codable, Equatable {
    public var path: String?   // App-Group/temp file holding the decrypted range (UDS/FFI)
    public var fd: Int32?      // or an FD (NSXPC) — CONTROL-API §7
    public var offset: Int     // the actual (block-snapped) range returned
    public var length: Int
    public init(path: String? = nil, fd: Int32? = nil, offset: Int, length: Int) {
        self.path = path; self.fd = fd; self.offset = offset; self.length = length
    }
}

/// Resolve one item's metadata by id (NSFileProviderReplicatedExtension.item(for:)). The appex
/// looks an item up before it materializes content; the daemon answers from its metadata sync.
public struct DataLookupParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var itemId: InodeID
    public init(filespace: FilespaceID, itemId: InodeID) {
        self.filespace = filespace; self.itemId = itemId
    }
}

/// List a container's children, one page at a time (NSFileProviderEnumerator.enumerateItems).
/// `page == nil` starts enumeration; a non-nil `nextPage` means more pages remain.
public struct DataEnumerateParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var container: InodeID
    public var page: String?
    public init(filespace: FilespaceID, container: InodeID, page: String? = nil) {
        self.filespace = filespace; self.container = container; self.page = page
    }
}
public struct DataEnumerateResult: Sendable, Codable, Equatable {
    public var items: [ItemMetadata]
    public var nextPage: String?
    public init(items: [ItemMetadata], nextPage: String? = nil) {
        self.items = items; self.nextPage = nextPage
    }
}

/// Replay changes to a container since `anchor` (NSFileProviderEnumerator.enumerateChanges).
/// The daemon owns the sync anchor; the appex passes back whatever `newAnchor` it last saw.
public struct DataEnumerateChangesParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var container: InodeID
    public var anchor: String
    public init(filespace: FilespaceID, container: InodeID, anchor: String) {
        self.filespace = filespace; self.container = container; self.anchor = anchor
    }
}
public struct DataEnumerateChangesResult: Sendable, Codable, Equatable {
    public var updated: [ItemMetadata]
    public var deleted: [InodeID]
    public var newAnchor: String
    public var moreComing: Bool
    public init(updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool) {
        self.updated = updated; self.deleted = deleted
        self.newAnchor = newAnchor; self.moreComing = moreComing
    }
}

// MARK: - §4 filespace / connection

public struct FilespaceConnectParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var rootPoint: String?
    public var mountAt: String?
    public init(filespace: FilespaceID, rootPoint: String? = nil, mountAt: String? = nil) {
        self.filespace = filespace; self.rootPoint = rootPoint; self.mountAt = mountAt
    }
}
public struct FilespaceDisconnectParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var drain: Bool?
    public init(filespace: FilespaceID, drain: Bool? = nil) { self.filespace = filespace; self.drain = drain }
}
public struct FilespaceSetConnectionParams: Sendable, Codable, Equatable {
    public enum State: String, Sendable, Codable { case connected, disconnected }
    public var filespace: FilespaceID
    public var state: State
    public init(filespace: FilespaceID, state: State) { self.filespace = filespace; self.state = state }
}

// MARK: - §5.1 mount

public struct MountParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var at: String?
    public var rootPoint: String?
    /// Display name for the volume (M3): the NFS backend derives the Bonjour
    /// hostname — the Finder sidebar entry — from this. Optional + additive:
    /// older callers omit it and the backend falls back to the filespace id.
    public var offlinePin: String?
    public var name: String?
    public init(filespace: FilespaceID, at: String? = nil, rootPoint: String? = nil,
                name: String? = nil, offlinePin: String? = nil) {
        self.filespace = filespace; self.at = at; self.rootPoint = rootPoint
        self.name = name; self.offlinePin = offlinePin
    }
}
public struct UnmountParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var force: Bool?
    public init(filespace: FilespaceID, force: Bool? = nil) { self.filespace = filespace; self.force = force }
}

// MARK: - §5.2 status

public struct StatusParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID?   // omitted => all
    public init(filespace: FilespaceID? = nil) { self.filespace = filespace }
}

// MARK: - §5.3 cache

public struct CacheInfoParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public init(filespace: FilespaceID) { self.filespace = filespace }
}
public struct CacheSetSizeParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var bytes: Int
    public init(filespace: FilespaceID, bytes: Int) { self.filespace = filespace; self.bytes = bytes }
}
public struct CacheSetLocationParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var path: String
    public init(filespace: FilespaceID, path: String) { self.filespace = filespace; self.path = path }
}
public struct CacheClearParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public init(filespace: FilespaceID) { self.filespace = filespace }
}

// MARK: - §5.4 pin / prefetch / evict

public struct PinParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var path: String
    public var recursive: Bool?
    public init(filespace: FilespaceID, path: String, recursive: Bool? = nil) {
        self.filespace = filespace; self.path = path; self.recursive = recursive
    }
}
public struct PathParams: Sendable, Codable, Equatable {   // prefetch / evict
    public var filespace: FilespaceID
    public var path: String
    public init(filespace: FilespaceID, path: String) { self.filespace = filespace; self.path = path }
}
public struct FilespaceOnlyParams: Sendable, Codable, Equatable {  // pin.list, transfers.*
    public var filespace: FilespaceID
    public init(filespace: FilespaceID) { self.filespace = filespace }
}

// MARK: - §5.5 transfers (results) + §5.6 sync

public struct PauseResult: Sendable, Codable, Equatable {
    public var paused: Bool
    public init(paused: Bool) { self.paused = paused }
}
public struct SyncStateParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var path: String
    public init(filespace: FilespaceID, path: String) { self.filespace = filespace; self.path = path }
}
public struct FlushParams: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var path: String
    public var wait: Bool?
    public var timeoutMs: Int?
    public init(filespace: FilespaceID, path: String, wait: Bool? = nil, timeoutMs: Int? = nil) {
        self.filespace = filespace; self.path = path; self.wait = wait; self.timeoutMs = timeoutMs
    }
}

// MARK: - §6 events (subscribe params + notification payloads)

public struct EventsSubscribeParams: Sendable, Codable, Equatable {
    public enum Kind: String, Sendable, Codable, CaseIterable {
        case transfer, activity, cache, mount
    }
    public var filespace: FilespaceID?
    public var kinds: [Kind]?
    public init(filespace: FilespaceID? = nil, kinds: [Kind]? = nil) {
        self.filespace = filespace; self.kinds = kinds
    }
}
public struct SubscribedResult: Sendable, Codable, Equatable {
    public var subscribed: Bool
    public init(subscribed: Bool) { self.subscribed = subscribed }
}

/// Notification payloads (CONTROL-API.md §6). The notification `method` field on
/// the wire is the `EventNotification.Kind` raw value.
public enum EventNotification: Sendable, Codable, Equatable {
    case transfer(filespace: FilespaceID, transfer: Transfer)
    case activity(filespace: FilespaceID, event: ActivityEvent)
    case cache(filespace: FilespaceID, cache: CacheInfo)
    case mount(filespace: FilespaceID, status: EngineStatus)

    public var method: String {
        switch self {
        case .transfer: return "transfer"
        case .activity: return "activity"
        case .cache:    return "cache"
        case .mount:    return "mount"
        }
    }
}

// MARK: - §8 versioning

public struct SystemVersionResult: Sendable, Codable, Equatable {
    public var engine: String
    public var api: String
    public init(engine: String, api: String) { self.engine = engine; self.api = api }
}

/// The version of THIS frozen contract (bump only on append; never break shapes).
public enum ControlAPI {
    public static let version = "1.0.0"
}
