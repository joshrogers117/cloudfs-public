// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCore — the cross-module engine protocols. FROZEN (DESIGN.md §1.2, §6, §7).
//
// These are the seams the modules implement and consume. Each module ships its
// OWN protocol in its OWN target (BlockCrypto, BlockCache, TransferEngine,
// GatewayClient, MountBackend, ControlPlane). The two that need to live in Core —
// because multiple modules reference them — are the POSIX-ish `Engine` facade
// (what the mount + control plane both call) and `EngineDataPath` (the
// EngineClient §1.3 RPCs the mount adapter uses). All are `async`/`throws` so a
// real implementation drops in without touching call sites.

import Foundation

/// Pin/eviction policy for an inode (CONTROL-API.md §7 setContentPolicy).
public enum ContentPolicy: String, Sendable, Codable {
    case lazy            // download lazily, evict under pressure (media default)
    case pinned          // keep resident, non-evictable
}

/// Data operations admitted by an open file handle. Metadata-only rights do not
/// imply data read or write access.
public struct OpenFileAccess: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }
    public static let read = OpenFileAccess(rawValue: 1 << 0)
    public static let write = OpenFileAccess(rawValue: 1 << 1)
    public static let delete = OpenFileAccess(rawValue: 1 << 2)
}

/// Access categories a later open may share with this open.
public struct OpenFileSharing: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }
    public static let read = OpenFileSharing(rawValue: 1 << 0)
    public static let write = OpenFileSharing(rawValue: 1 << 1)
    public static let delete = OpenFileSharing(rawValue: 1 << 2)
}

/// An ACL-filtered, complete directory view captured atomically by the gateway.
/// Implementations return nil only when the bounded operation is unavailable or
/// the directory exceeds its snapshot limit; errors remain authoritative.
public struct DirectorySnapshot: Sendable, Equatable {
    public let directory: ItemMetadata
    public let items: [ItemMetadata]
    public init(directory: ItemMetadata, items: [ItemMetadata]) {
        self.directory = directory
        self.items = items
    }
}

/// The data-path RPCs a mount adapter (SMB / appex / FSKit) calls — the
/// EngineClient §1.3 surface (CONTROL-API.md §7). NOT used by the CLI.
public protocol EngineDataPath: Sendable {
    var isReadOnly: Bool { get }
    func changeGeneration() async -> UInt64
    func waitForChanges(after: UInt64) async -> UInt64
    /// Opaque current notification checkpoint, not a page continuation cursor.
    /// Equal checkpoints mean no newer durable namespace/visibility state.
    func notificationCheckpoint(container: InodeID) async throws -> String
    /// Retain a cross-device editing lease for one mount handle. Defaults are for
    /// isolated test/in-memory adapters; the production adapter requires leases.
    func beginWrite(_ id: InodeID, handle: String) async throws
    /// Acquire write authority and, when the backend can return it atomically,
    /// the fresh item metadata protected by that authority. Nil means callers
    /// must use the legacy authorization + lookup sequence.
    func beginWriteSnapshot(_ id: InodeID, handle: String) async throws -> ItemMetadata?
    func endWrite(_ id: InodeID, handle: String) async
    func acquireRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws
    func releaseRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws
    func releaseAllRanges(_ id: InodeID, handle: String) async
    func checkRangeAccess(_ id: InodeID, handle: String, offset: UInt64, length: UInt64, write: Bool) async throws

    /// Validate an existing inode before exposing a writable handle or staging bytes.
    /// Mounts request a fresh check on open; hot writes may reuse a short authorization.
    func authorizeWrite(_ id: InodeID, refresh: Bool) async throws
    /// Retain the backing inode for one successful open handle. Implementations
    /// enforce remote share compatibility and preserve detached inode data until
    /// the matching endOpen, expiry, or connection cleanup.
    func beginOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                   sharing: OpenFileSharing) async throws
    /// Acquire a retained open and resolve one named stream when the gateway
    /// supports it. Legacy implementations fall back to beginOpen + listStreams.
    /// A nil result means the named stream is absent; the open remains held when
    /// the request allowed absence so the caller can create it lazily.
    func beginStreamOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                         sharing: OpenFileSharing, name: String, required: Bool) async throws -> Int?
    /// One-transaction, temporary read-only open + ACL-filtered bounded
    /// directory snapshot + close. No remote handle survives the call.
    func directorySnapshot(_ id: InodeID, handle: String, access: OpenFileAccess,
                           sharing: OpenFileSharing) async throws -> DirectorySnapshot?
    func endOpen(_ id: InodeID, handle: String) async
    func setBasicInfo(_ id: InodeID, info: BasicFileInfo) async throws -> ItemMetadata
    func lookup(_ id: InodeID) async throws -> ItemMetadata
    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef
    /// In-process, bounded read for SMB (at most 1 MiB); avoids an IPC spill file.
    /// RPC callers continue using readRange and its CacheFileRef contract.
    func readBytes(_ id: InodeID, version: String, offset: Int, length: Int) async throws -> Data
    func readRange(_ id: InodeID, version: String, offset: Int, length: Int,
                   alignment: Int) async throws -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int))
    func write(id: InodeID?, fields: ItemMetadata, contents: CacheFileRef?,
               baseVersion: String?) async throws -> ItemMetadata
    /// P0 — block-aligned dirty-block write: stage `[offset, offset+data.count)` of an
    /// EXISTING item (creates go through `write(id: nil, …)`; whole-file replaces through
    /// `write(id:contents:)`). Only the touched blocks are staged/journaled/uploaded; a
    /// partially covered boundary block is seeded by a block-granular read-modify-write —
    /// never a whole-file download. Returns the staged logical file size after the write
    /// (`max(committed size, offset + data.count)`), which the caller projects into its
    /// metadata view.
    func writeRange(_ id: InodeID, offset: Int, data: Data, baseVersion: String?) async throws -> Int
    /// P4 — truncate to `newSize` (O_TRUNC / ftruncate). Shrink kills content beyond
    /// the boundary (zeros on regrowth — never resurrected bytes); growth zero-extends.
    /// Ack-local like writes; the async commit reuses unchanged committed refs.
    func truncate(_ id: InodeID, newSize: Int, baseVersion: String?) async throws
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws
    /// Delete through a currently open SMB handle. Implementations with remote
    /// share enforcement verify the handle and exclude only it from the share check.
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool, openHandle: String?) async throws
    /// Rename/move an item (audit B17). `newParent == nil` keeps the current parent (pure rename).
    /// Opaque ids make this a single-row metadata update; the id is unchanged. Returns the new metadata.
    func rename(_ id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata
    /// Replaces only the supplied destination inode in the same namespace transaction.
    func rename(_ id: InodeID, newParent: InodeID?, newName: String, replacing: ItemMetadata?) async throws -> ItemMetadata
    /// Rename through the caller's open source handle. Other open handles remain
    /// subject to FILE_SHARE_DELETE checks.
    func rename(_ id: InodeID, newParent: InodeID?, newName: String,
                replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata
    func enumerate(container: InodeID, page: String?) async throws -> (items: [ItemMetadata], nextPage: String?)
    func enumerateChanges(container: InodeID, anchor: String) async throws
        -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool)
    func setContentPolicy(_ id: InodeID, policy: ContentPolicy) async throws
    func requestDownload(_ id: InodeID, range: (offset: Int, length: Int)?) async throws -> PrefetchAck
    func evict(_ id: InodeID) async throws -> EvictAck
    /// Named streams, including large resource forks, support bounded range I/O.
    /// Production mutations acknowledge only after encrypted chunks and metadata
    /// are remotely durable. Whole-value methods remain for small legacy metadata.
    func readStreamRange(_ id: InodeID, name: String, offset: Int, length: Int) async throws -> Data
    func writeStreamRange(_ id: InodeID, name: String, offset: Int, data: Data) async throws -> Int
    func truncateStream(_ id: InodeID, name: String, size: Int) async throws
    func listStreams(_ id: InodeID) async throws -> [StreamInfo]
    func readStream(_ id: InodeID, name: String) async throws -> Data
    func writeStream(_ id: InodeID, name: String, data: Data) async throws
    func deleteStream(_ id: InodeID, name: String) async throws
    /// Audit B15 — a 0700, daemon-owned directory for transient DECRYPTED plaintext (read/stage
    /// spill). NOT the world-readable system /tmp. The real adapter returns a subdir of the cache
    /// root; the default is a 0700 subdir of the system temp (standalone/test).
    var plaintextSpillDir: String { get }
}

public extension EngineDataPath {
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool, openHandle: String?) async throws {
        try await delete(id, baseVersion: baseVersion, recursive: recursive)
    }

    /// Isolated in-memory adapters may omit remote inode retention.
    func beginOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                   sharing: OpenFileSharing) async throws {}
    func beginStreamOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                         sharing: OpenFileSharing, name: String, required: Bool) async throws -> Int? {
        try await beginOpen(id, handle: handle, access: access, sharing: sharing)
        return try await listStreams(id).first { $0.name == name }?.size
    }
    func directorySnapshot(_ id: InodeID, handle: String, access: OpenFileAccess,
                           sharing: OpenFileSharing) async throws -> DirectorySnapshot? { nil }
    func endOpen(_ id: InodeID, handle: String) async {}
    func setBasicInfo(_ id: InodeID, info: BasicFileInfo) async throws -> ItemMetadata {
        throw EngineError(.unimplemented, "Basic file metadata updates are unavailable")
    }
    func changeGeneration() async -> UInt64 { 0 }
    func waitForChanges(after: UInt64) async -> UInt64 {
        try? await Task.sleep(for: .milliseconds(2500))
        return after
    }
    func notificationCheckpoint(container: InodeID) async throws -> String {
        // Generic adapters may only expose a paged change feed. Production
        // overrides this with a bounded high-water query, independent of history.
        var anchor = ""
        var seen: Set<String> = [anchor]
        for _ in 0..<256 {
            try Task.checkCancellation()
            let page = try await enumerateChanges(container: container, anchor: anchor)
            try Task.checkCancellation()
            if !page.moreComing { return page.newAnchor }
            guard seen.insert(page.newAnchor).inserted else {
                throw EngineError(.gatewayError, "Notification checkpoint did not advance")
            }
            anchor = page.newAnchor
        }
        throw EngineError(.gatewayError, "Notification checkpoint exceeded page limit")
    }
    var isReadOnly: Bool { false }
    func readBytes(_ id: InodeID, version: String, offset: Int, length: Int) async throws -> Data {
        guard offset >= 0, length >= 0, length <= 1 << 20, offset <= Int.max - length else {
            throw EngineError(.invalidParams, "Invalid in-process read extent")
        }
        if length == 0 { return Data() }
        let (ref, range) = try await readRange(id, version: version, offset: offset, length: length, alignment: 0)
        guard let path = ref.path, let handle = Foundation.FileHandle(forReadingAtPath: path) else {
            throw EngineError(.syncFailed, "Materialized read data is unavailable")
        }
        defer { try? handle.close(); try? FileManager.default.removeItem(atPath: path) }
        let inner = offset - range.offset
        guard inner >= 0, range.length >= inner else { throw EngineError(.syncFailed, "Invalid materialized read extent") }
        let expected = min(length, range.length - inner)
        try handle.seek(toOffset: UInt64(inner))
        let bytes = try handle.read(upToCount: expected) ?? Data()
        guard bytes.count == expected else { throw EngineError(.syncFailed, "Materialized read data was truncated") }
        return bytes
    }

    func beginWrite(_ id: InodeID, handle: String) async throws {}
    func beginWriteSnapshot(_ id: InodeID, handle: String) async throws -> ItemMetadata? {
        try await beginWrite(id, handle: handle)
        return nil
    }
    func endWrite(_ id: InodeID, handle: String) async {}
    func acquireRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {}
    func releaseRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {}
    func releaseAllRanges(_ id: InodeID, handle: String) async {}
    func checkRangeAccess(_ id: InodeID, handle: String, offset: UInt64, length: UInt64, write: Bool) async throws {}


    func authorizeWrite(_ id: InodeID, refresh: Bool) async throws {
        throw EngineError(.unimplemented, "Write authorization is unavailable")
    }

    var plaintextSpillDir: String {
        let d = NSTemporaryDirectory() + "cloudfs-spill"
        try? FileManager.default.createDirectory(atPath: d, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        return d
    }
}

public extension EngineDataPath {
    /// Default: rename surfaces unimplemented (so a conformer that hasn't wired it doesn't
    /// silently phantom-succeed). The real `EngineDataPathAdapter` overrides it (audit B17).
    func rename(_ id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata {
        throw EngineError(.unimplemented, "rename is not wired on this EngineDataPath")
    }

    func rename(_ id: InodeID, newParent: InodeID?, newName: String, replacing: ItemMetadata?) async throws -> ItemMetadata {
        guard replacing == nil else { throw EngineError(.unimplemented, "Atomic replacement is unavailable") }
        return try await rename(id, newParent: newParent, newName: newName)
    }

    func rename(_ id: InodeID, newParent: InodeID?, newName: String,
                replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata {
        try await rename(id, newParent: newParent, newName: newName, replacing: replacing)
    }

    /// Default: ranged write surfaces unimplemented rather than phantom-acking (same
    /// pattern as `rename`). Real conformers state it directly (existential dispatch of a
    /// default-impl'd requirement faulted on some toolchains — see the B17 note).
    func writeRange(_ id: InodeID, offset: Int, data: Data, baseVersion: String?) async throws -> Int {
        throw EngineError(.unimplemented, "writeRange is not wired on this EngineDataPath")
    }

    /// Default: truncate surfaces unimplemented rather than phantom-acking.
    func truncate(_ id: InodeID, newSize: Int, baseVersion: String?) async throws {
        throw EngineError(.unimplemented, "truncate is not wired on this EngineDataPath")
    }

    // Compatibility fallback for in-memory/test adapters. The production adapter
    // overrides all three and never reads a whole resource fork for a range.
    func readStreamRange(_ id: InodeID, name: String, offset: Int, length: Int) async throws -> Data {
        guard offset >= 0, length >= 0, offset <= Int.max - length else { throw EngineError(.invalidParams) }
        let bytes = try await readStream(id, name: name)
        return offset >= bytes.count ? Data() : bytes.subdata(in: offset..<min(bytes.count, offset + length))
    }
    func writeStreamRange(_ id: InodeID, name: String, offset: Int, data: Data) async throws -> Int {
        guard offset >= 0, offset <= Int.max - data.count else { throw EngineError(.invalidParams) }
        var bytes: Data
        do { bytes = try await readStream(id, name: name) }
        catch let error as EngineError where error.kind == .notFound { bytes = Data() }
        if offset + data.count > bytes.count { bytes.append(Data(repeating: 0, count: offset + data.count - bytes.count)) }
        bytes.replaceSubrange(offset..<offset + data.count, with: data)
        try await writeStream(id, name: name, data: bytes)
        return bytes.count
    }
    func truncateStream(_ id: InodeID, name: String, size: Int) async throws {
        guard size >= 0 else { throw EngineError(.invalidParams) }
        var bytes: Data
        do { bytes = try await readStream(id, name: name) }
        catch let error as EngineError where error.kind == .notFound { bytes = Data() }
        if size > bytes.count { bytes.append(Data(repeating: 0, count: size - bytes.count)) }
        else { bytes = Data(bytes.prefix(size)) }
        try await writeStream(id, name: name, data: bytes)
    }

    /// Defaults: streams surface as absent/unimplemented so a conformer that
    /// hasn't wired them doesn't phantom-succeed (same pattern as rename/writeRange).
    func listStreams(_ id: InodeID) async throws -> [StreamInfo] { [] }
    func readStream(_ id: InodeID, name: String) async throws -> Data {
        throw EngineError(.notFound, "no such stream")
    }
    func writeStream(_ id: InodeID, name: String, data: Data) async throws {
        throw EngineError(.unimplemented, "writeStream is not wired on this EngineDataPath")
    }
    func deleteStream(_ id: InodeID, name: String) async throws {
        throw EngineError(.unimplemented, "deleteStream is not wired on this EngineDataPath")
    }
}

/// The management surface the control plane exposes (CONTROL-API.md §4–6). The
/// `ControlPlane` server is a thin transport over this; the executable wires a
/// concrete `Engine` that fans these out to cache/transfer/gateway/mount.
public protocol Engine: Sendable {
    // filespace / connection
    func filespaceList() async throws -> [EngineFilespace]
    func connect(_ p: FilespaceConnectParams) async throws -> EngineFilespace
    func disconnect(_ p: FilespaceDisconnectParams) async throws -> EngineFilespace
    func setConnectionState(_ p: FilespaceSetConnectionParams) async throws -> EngineFilespace
    // mount
    func mount(_ p: MountParams) async throws -> EngineFilespace
    func unmount(_ p: UnmountParams) async throws -> EngineFilespace
    func snapshotMount(_ p: SnapshotMountParams) async throws -> SnapshotMount
    func snapshotUnmount(_ p: SnapshotUnmountParams) async throws -> SnapshotMount
    func snapshotMounts(_ p: SnapshotMountsParams) async throws -> [SnapshotMount]
    // status
    func status(_ p: StatusParams) async throws -> [EngineStatus]
    // cache
    func cacheInfo(_ p: CacheInfoParams) async throws -> CacheInfo
    func cacheSetSize(_ p: CacheSetSizeParams) async throws -> CacheInfo
    func cacheSetLocation(_ p: CacheSetLocationParams) async throws -> CacheInfo
    func cacheClear(_ p: CacheClearParams) async throws -> CacheInfo
    // pin / prefetch / evict
    func pin(_ p: PinParams) async throws -> PinState
    func unpin(_ p: PinParams) async throws -> PinState
    func pinList(_ p: FilespaceOnlyParams) async throws -> [PinState]
    func prefetch(_ p: PathParams) async throws -> PrefetchAck
    func evict(_ p: PathParams) async throws -> EvictAck
    func linkCreate(_ p: LinkCreateParams) async throws -> LinkCreateResult
    func linkResolve(_ p: LinkResolveParams) async throws -> LinkResolveResult
    // transfers
    func transfersCurrent(_ p: FilespaceOnlyParams) async throws -> [Transfer]
    func transfersPause(_ p: FilespaceOnlyParams) async throws -> PauseResult
    func transfersResume(_ p: FilespaceOnlyParams) async throws -> PauseResult
    // Retained local writes: inspect, retry with the same base, or export a copy.
    func recoveryList(_ p: FilespaceOnlyParams) async throws -> [RecoveryItem]
    func recoveryRetry(_ p: RecoveryItemParams) async throws
    func recoveryExport(_ p: RecoveryExportParams) async throws -> RecoveryExportResult
    func recoveryComplete(_ p: RecoveryExportParams) async throws
    // sync barriers
    func syncState(_ p: SyncStateParams) async throws -> SyncState
    func flush(_ p: FlushParams) async throws -> SyncState
    // §7 data path (out-of-process): serve decrypted byte ranges + metadata/enumeration from the
    // cache & metadata sync to a SEPARATE client process (the File Provider appex). In-process
    // callers use EngineDataPath directly.
    func dataReadRange(_ p: DataReadRangeParams) async throws -> DataReadRangeResult
    func dataLookup(_ p: DataLookupParams) async throws -> ItemMetadata
    func dataEnumerate(_ p: DataEnumerateParams) async throws -> DataEnumerateResult
    func dataEnumerateChanges(_ p: DataEnumerateChangesParams) async throws -> DataEnumerateChangesResult
    // versioning
    func systemVersion() async throws -> SystemVersionResult
    // event stream: an async sequence of notifications the control plane fans out
    func events(_ p: EventsSubscribeParams) -> AsyncStream<EventNotification>
}
