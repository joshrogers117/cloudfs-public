// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCore — shared domain types. FROZEN (DESIGN.md §7 core-types).
//
// These are the cross-module value types every cloudfsd module consumes:
// identifiers, the block/inode/handle model, cache + transfer + sync shapes, and
// the engine-status/filespace records the control plane returns. They mirror the
// shapes in CONTROL-API.md §3 and the callers' existing types
// (cli/src/gateway/{client,types}.ts CacheInfo/SyncState/ChangeEvent;
// client-app GatewayClient). Implementers depend on this read-only.

import Foundation

// MARK: - Identifiers

/// Content address of an immutable encrypted block: SHA-256 of the ciphertext,
/// hex-encoded (DESIGN.md §3.1, key layout `chunks/<hash[:2]>/<hash>`).
public struct BlockHash: Hashable, Sendable, Codable, CustomStringConvertible {
    public let hex: String
    public init(hex: String) { self.hex = hex }
    public var description: String { hex }
    /// Sharded object-key prefix used in the bucket and on-disk cache.
    public var objectKey: String {
        let shard = hex.count >= 2 ? String(hex.prefix(2)) : "00"
        return "chunks/\(shard)/\(hex)"
    }
}

/// Stable inode id = the gateway's `Item.id` (e.g. "projectA/clip.mov", "root").
public struct InodeID: Hashable, Sendable, Codable, RawRepresentable, ExpressibleByStringLiteral {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
    public init(_ raw: String) { self.rawValue = raw }
    public init(stringLiteral value: String) { self.rawValue = value }
    public static let root = InodeID("root")
}

/// Opaque per-open file handle vended by the engine to a mount adapter.
public struct FileHandle: Hashable, Sendable, Codable, RawRepresentable {
    public let rawValue: UInt64
    public init(rawValue: UInt64) { self.rawValue = rawValue }
    public init(_ raw: UInt64) { self.rawValue = raw }
}

/// A filespace id (gateway space id).
public typealias FilespaceID = String

// MARK: - Block / inode model (DESIGN.md §3.1)

/// Default block size: 1 MiB (== rwsize == crypto unit == fetch-alignment unit).
public let kDefaultBlockSize: Int = 1 << 20

/// Bounded transfer windows, tuned against real object storage. Payloads remain
/// admitted by the transfer pools; increasing parallelism never bypasses checks.
public let kDefaultUploadConcurrency: Int = 32
/// Memory accounting for downloads: each active GET may transiently hold ~2 MiB
/// (ciphertext + plaintext), so 48 slots are ~96 MiB transient, on top of the
/// engine-wide speculative read-ahead byte budget (default 64 MiB, see
/// kDefaultReadAheadBudgetMiB). Slot pools are per filespace; the budget is
/// engine-wide.
public let kDefaultDownloadConcurrency: Int = 48
public let kMaxTransferConcurrency: Int = 64
/// Engine-wide cap on unfinished speculative plaintext, in MiB (valid 8...128).
public let kDefaultReadAheadBudgetMiB: Int = 64

/// One block's place in a file: ordered hashes form the manifest.
public struct BlockRef: Hashable, Sendable, Codable {
    public let hash: BlockHash
    public let offset: Int     // byte offset of this block within the file
    public let length: Int     // <= block size (tail block may be short)
    public init(hash: BlockHash, offset: Int, length: Int) {
        self.hash = hash; self.offset = offset; self.length = length
    }
}

/// The ordered block list for a file + the version derived from it.
public struct BlockManifest: Sendable, Codable {
    public let itemID: InodeID
    public let blocks: [BlockRef]
    public let contentVersion: String   // derived from the ordered block hashes
    public init(itemID: InodeID, blocks: [BlockRef], contentVersion: String) {
        self.itemID = itemID; self.blocks = blocks; self.contentVersion = contentVersion
    }
    public var size: Int { blocks.reduce(0) { $0 + $1.length } }
}

/// Metadata for an inode (the engine's view; superset of the gateway Item).
public struct ItemMetadata: Sendable, Codable, Equatable {
    public let id: InodeID
    public let parent: InodeID?
    public let name: String
    public let isDir: Bool
    public let size: Int
    public let contentVersion: String
    public let metadataVersion: String
    /// Real wall-clock create/modify times (SMB cutover). Nil for items whose
    /// gateway row predates the v13 migration; the mount then synthesizes a
    /// pseudo-mtime from `contentVersion`. Defaulted so existing call sites and
    /// the JSON-RPC decoders (which omit the keys) compile and decode unchanged.
    public let createdAt: Date?
    public let modifiedAt: Date?
    public let accessedAt: Date?
    public let changedAt: Date?
    public let fileAttributes: UInt32?
    /// AAPL readdir-attr enrichment (v14): resource-fork byte length and the raw
    /// 32-byte FinderInfo, so the mount can pack directory entries without a
    /// per-file stream probe. Nil when the item carries no such streams / wasn't
    /// enriched. Defaulted for the same backward-compat reasons.
    public let rsrcForkSize: Int?
    public let finderInfo: Data?
    public let finderInfoCiphertext: Data?
    public init(id: InodeID, parent: InodeID?, name: String, isDir: Bool,
                size: Int, contentVersion: String, metadataVersion: String,
                createdAt: Date? = nil, modifiedAt: Date? = nil,
                accessedAt: Date? = nil, changedAt: Date? = nil, fileAttributes: UInt32? = nil,
                rsrcForkSize: Int? = nil, finderInfo: Data? = nil, finderInfoCiphertext: Data? = nil) {
        self.id = id; self.parent = parent; self.name = name; self.isDir = isDir
        self.size = size; self.contentVersion = contentVersion
        self.metadataVersion = metadataVersion
        self.createdAt = createdAt; self.modifiedAt = modifiedAt
        self.accessedAt = accessedAt; self.changedAt = changedAt; self.fileAttributes = fileAttributes
        self.rsrcForkSize = rsrcForkSize; self.finderInfo = finderInfo; self.finderInfoCiphertext = finderInfoCiphertext
    }
}

/// Explicit metadata updates; nil leaves a field unchanged. Attribute bits are
/// validated by the SMB and gateway boundaries, never silently accepted.
public struct BasicFileInfo: Sendable, Equatable {
    public var createdAt: Date?
    public var modifiedAt: Date?
    public var accessedAt: Date?
    public var changedAt: Date?
    public var fileAttributes: UInt32?
    public init(createdAt: Date? = nil, modifiedAt: Date? = nil, accessedAt: Date? = nil,
                changedAt: Date? = nil, fileAttributes: UInt32? = nil) {
        self.createdAt = createdAt; self.modifiedAt = modifiedAt; self.accessedAt = accessedAt
        self.changedAt = changedAt; self.fileAttributes = fileAttributes
    }
}

/// A named stream's identity (SMB xattr / Apple metadata fork). `size` is the
/// byte length of the stream's contents.
public struct StreamInfo: Sendable, Codable, Equatable {
    public let name: String
    public let size: Int
    public init(name: String, size: Int) { self.name = name; self.size = size }
}

/// Reference to a materialized cache file handed back to a mount adapter.
/// Carries an FD (NSXPC) OR an App-Group/temp path (UDS/FFI) — CONTROL-API.md §7.
public struct CacheFileRef: Sendable, Codable {
    public var fd: Int32?
    public var path: String?
    public init(fd: Int32? = nil, path: String? = nil) { self.fd = fd; self.path = path }
}

// MARK: - Cache (CONTROL-API.md §3 CacheInfo — matches cli CacheInfo)

public struct CacheInfo: Sendable, Codable, Equatable {
    public var filespace: FilespaceID
    public var location: String
    public var sizeBytes: Int
    public var usedBytes: Int
    public var pinnedBytes: Int
    public var maxBytes: Int
    public var freeOnVolumeBytes: Int
    public var hitRate: Double            // 0...1
    /// Daemon-wide journal allocation; distinct from this filespace's data cache.
    public var pendingWriteUsedBytes: Int?
    public var pendingWriteReservedBytes: Int?
    public var pendingWriteLimitBytes: Int?
    public var pendingWriteFreeSpaceReserveBytes: Int?
    public init(filespace: FilespaceID, location: String, sizeBytes: Int, usedBytes: Int,
                pinnedBytes: Int, maxBytes: Int, freeOnVolumeBytes: Int, hitRate: Double) {
        self.filespace = filespace; self.location = location; self.sizeBytes = sizeBytes
        self.usedBytes = usedBytes; self.pinnedBytes = pinnedBytes; self.maxBytes = maxBytes
        self.freeOnVolumeBytes = freeOnVolumeBytes; self.hitRate = hitRate
    }
}

/// Per-pin cache-state (CONTROL-API.md §3 / §5.4, CONTRACTS.md §4.1):
/// `pinned`  — fully materialized & non-evictable (`cachedBytes == totalBytes`).
/// `pinning` — pin set but still materializing (`0 <= cachedBytes < totalBytes`).
/// An unpinned/evicted path holds no pin record, so it never appears here.
public enum PinCacheState: String, Sendable, Codable, Equatable {
    case pinned
    case pinning
}

public struct PinState: Sendable, Codable, Equatable {
    public var path: String
    public var pinned: Bool
    public var recursive: Bool
    public var blocks: Int

    // --- APPENDED (WS2 T2.1, CONTRACTS.md §4) — per-item byte accounting + state.
    // `cachedBytes` = Σ len over resident blocks of the pin; `totalBytes` = Σ len
    // over all blocks the pin covers (resident + accounted-evicted). Older engines
    // omit these; decoders tolerate the absence (the fields are optional).
    public var cachedBytes: UInt64?
    public var totalBytes: UInt64?
    public var cacheState: PinCacheState?
    public var failureReason: String?
    public var offlineReady: Bool?
    public var offlineExpiresAt: Date?
    public var offlineFailureReason: String?

    public init(path: String, pinned: Bool, recursive: Bool, blocks: Int,
                cachedBytes: UInt64? = nil, totalBytes: UInt64? = nil,
                cacheState: PinCacheState? = nil, failureReason: String? = nil) {
        self.path = path; self.pinned = pinned; self.recursive = recursive; self.blocks = blocks
        self.cachedBytes = cachedBytes; self.totalBytes = totalBytes; self.cacheState = cacheState
        self.failureReason = failureReason
        self.offlineReady = nil; self.offlineExpiresAt = nil; self.offlineFailureReason = nil
    }
}

public struct PrefetchAck: Sendable, Codable, Equatable {
    public var path: String
    public var queuedBlocks: Int
    public init(path: String, queuedBlocks: Int) { self.path = path; self.queuedBlocks = queuedBlocks }
}

public struct EvictAck: Sendable, Codable, Equatable {
    public var path: String
    public var evictedBlocks: Int
    public var freedBytes: Int
    public init(path: String, evictedBlocks: Int, freedBytes: Int) {
        self.path = path; self.evictedBlocks = evictedBlocks; self.freedBytes = freedBytes
    }
}

// MARK: - Sync barriers (CONTROL-API.md §3 SyncState — matches cli SyncState)

public struct SyncState: Sendable, Codable, Equatable {
    public var path: String
    public var inSync: Bool
    public var pendingUploads: Int
    public var pendingBytes: Int
    public init(path: String, inSync: Bool, pendingUploads: Int, pendingBytes: Int) {
        self.path = path; self.inSync = inSync
        self.pendingUploads = pendingUploads; self.pendingBytes = pendingBytes
    }
}

// MARK: - Transfers (CONTROL-API.md §3 Transfer)

public struct Transfer: Sendable, Codable, Equatable {
    public enum Direction: String, Sendable, Codable { case download, upload }
    public enum State: String, Sendable, Codable { case queued, active, paused, done, error }
    public var id: String
    public var filespace: FilespaceID
    public var path: String
    public var direction: Direction
    public var bytesDone: Int
    public var bytesTotal: Int
    public var state: State
    public var error: String?
    public init(id: String, filespace: FilespaceID, path: String, direction: Direction,
                bytesDone: Int, bytesTotal: Int, state: State, error: String? = nil) {
        self.id = id; self.filespace = filespace; self.path = path; self.direction = direction
        self.bytesDone = bytesDone; self.bytesTotal = bytesTotal; self.state = state; self.error = error
    }
}

// MARK: - Activity events (CONTROL-API.md §6 — shape == cli ChangeEvent)

public struct ActivityEvent: Sendable, Codable, Equatable {
    public enum Kind: String, Sendable, Codable {
        case create, modify, delete, rename, lock, unlock, upload
    }
    public var seq: Int
    public var type: Kind
    public var path: String
    public var actor: String
    public var ts: String   // ISO-8601
    public init(seq: Int, type: Kind, path: String, actor: String, ts: String) {
        self.seq = seq; self.type = type; self.path = path; self.actor = actor; self.ts = ts
    }
}

// MARK: - Filespace / status (CONTROL-API.md §3)

public struct EngineFilespace: Sendable, Codable, Equatable {
    public enum Status: String, Sendable, Codable { case connected, connecting, disconnected, offline }
    public var id: FilespaceID
    public var name: String
    public var status: Status
    public var mountPath: String?
    public var rootPoint: String?
    public var role: String?
    /// Transfer pause is independent of whether the Finder volume is mounted.
    public var paused: Bool?
    public var sourceFilespace: String?
    public var snapshotId: String?
    public var readOnly: Bool?
    public init(id: FilespaceID, name: String, status: Status,
                mountPath: String? = nil, rootPoint: String? = nil, role: String? = nil, paused: Bool? = nil,
                sourceFilespace: String? = nil, snapshotId: String? = nil, readOnly: Bool? = nil) {
        self.id = id; self.name = name; self.status = status
        self.mountPath = mountPath; self.rootPoint = rootPoint; self.role = role
        self.paused = paused
        self.sourceFilespace = sourceFilespace; self.snapshotId = snapshotId; self.readOnly = readOnly
    }
}

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

public struct EngineStatus: Sendable, Codable, Equatable {
    public enum Connection: String, Sendable, Codable {
        case connected, connecting, disconnected, offline
    }
    public enum Health: String, Sendable, Codable { case green, yellow, red }
    /// Gateway reachability derived from real request outcomes (additive; optional on the wire).
    public enum Reachability: String, Sendable, Codable { case online, degraded, offline }
    public var filespace: FilespaceID
    public var connection: Connection
    public var mountPath: String?
    /// Deprecated compatibility field: actual storage request duration (including body).
    public var latencyMsToBucket: Double?
    public var gatewayLatencyMs: Double?
    public var storage: StorageTelemetry?
    public var pendingUploads: Int
    public var pendingBytes: Int
    public var cache: CacheInfo
    public var health: Health
    // --- APPENDED (truthful connection state). All optional for back-compat. ---
    /// Epoch milliseconds of the last successful gateway round trip.
    public var lastSuccessAt: Int64?
    /// Epoch milliseconds of the most recent gateway transport/server failure.
    public var lastFailureAt: Int64?
    /// Short, secret-free description of the most recent failure.
    public var lastFailureReason: String?
    public var reachability: Reachability?
    /// Grant-root ids the mounted projection was built from; nil for a whole-filespace
    /// or explicit-folder mount (new grants cannot change those).
    public var mountedRootIds: [String]?
    public init(filespace: FilespaceID, connection: Connection, mountPath: String?,
                latencyMsToBucket: Double?, pendingUploads: Int, pendingBytes: Int,
                cache: CacheInfo, health: Health,
                lastSuccessAt: Int64? = nil, lastFailureAt: Int64? = nil,
                lastFailureReason: String? = nil, reachability: Reachability? = nil,
                mountedRootIds: [String]? = nil, gatewayLatencyMs: Double? = nil, storage: StorageTelemetry? = nil) {
        self.filespace = filespace; self.connection = connection; self.mountPath = mountPath
        self.latencyMsToBucket = latencyMsToBucket; self.pendingUploads = pendingUploads
        self.pendingBytes = pendingBytes; self.cache = cache; self.health = health
        self.lastSuccessAt = lastSuccessAt; self.lastFailureAt = lastFailureAt
        self.lastFailureReason = lastFailureReason; self.reachability = reachability
        self.mountedRootIds = mountedRootIds
        self.gatewayLatencyMs = gatewayLatencyMs; self.storage = storage
    }
}

// MARK: - Engine configuration (DESIGN.md §2.3 run line)

public struct EngineConfig: Sendable, Codable, Equatable {
    public var cacheDir: String
    public var cacheSizeBytes: Int
    public var controlSocketPath: String
    public var gatewayBaseURL: String
    public var tokenFilePath: String?
    public var blockSize: Int
    /// Optional to preserve decoding of older saved configurations.
    public var uploadConcurrency: Int?
    public var downloadConcurrency: Int?
    /// Engine-wide speculative read-ahead budget in MiB; nil = kDefaultReadAheadBudgetMiB.
    public var readAheadBudgetMiB: Int?
    public var pendingWriteLimitBytes: Int?
    public var pendingWriteReserveBytes: Int?
    public init(cacheDir: String, cacheSizeBytes: Int, controlSocketPath: String,
                gatewayBaseURL: String, tokenFilePath: String? = nil,
                blockSize: Int = kDefaultBlockSize, uploadConcurrency: Int? = nil,
                downloadConcurrency: Int? = nil, readAheadBudgetMiB: Int? = nil,
                pendingWriteLimitBytes: Int? = nil, pendingWriteReserveBytes: Int? = nil) {
        self.cacheDir = cacheDir; self.cacheSizeBytes = cacheSizeBytes
        self.controlSocketPath = controlSocketPath; self.gatewayBaseURL = gatewayBaseURL
        self.tokenFilePath = tokenFilePath; self.blockSize = blockSize
        self.uploadConcurrency = uploadConcurrency; self.downloadConcurrency = downloadConcurrency
        self.readAheadBudgetMiB = readAheadBudgetMiB
        self.pendingWriteLimitBytes = pendingWriteLimitBytes
        self.pendingWriteReserveBytes = pendingWriteReserveBytes
    }
}
