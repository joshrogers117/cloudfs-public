// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — per-connection session/tree/open state. A loopback mount is a
// single client, so the model is deliberately small: one session, a small set
// of active trees (the client may issue diagnostic TREE_CONNECTs), a table of
// opens keyed by SMB FileId, and the NTLM handshake's
// in-flight server challenge. All access is serialized by the connection thread
// (thread-per-connection, like the NFS server), so plain mutable structs suffice.

import Foundation
import CloudFSCore

/// An SMB2 FileId: a 16-byte (persistent, volatile) pair. We mint monotonic
/// handle numbers with a random per-connection identity, so handles from different
/// TCP connections never alias in the shared byte-range lock table. Compound
/// RELATED-op propagation uses the 0xFFFFFFFFFFFFFFFF placeholder.
public struct SMBFileId: Hashable, Sendable {
    public var persistent: UInt64
    public var volatile: UInt64
    public init(persistent: UInt64, volatile: UInt64) {
        self.persistent = persistent; self.volatile = volatile
    }
    /// The "use the previous CREATE's handle" sentinel in a compound chain.
    public static let related = SMBFileId(persistent: .max, volatile: .max)
    public var isRelated: Bool { persistent == .max && volatile == .max }
}

/// One open handle. `dirCursor` tracks QUERY_DIRECTORY restart/resume; the fields
/// used only by later phases (deleteOnClose, streamName) are carried now so the
/// open struct is stable across phases.
public final class SMBOpen: @unchecked Sendable {
    public let fileId: SMBFileId
    public let node: InodeID
    public let isDir: Bool
    /// SMB-visible identity captured when this handle was opened. It remains
    /// fixed if the backend inode is later observed at a different location.
    public let presentationFileID: UInt64
    /// Tree that created this FID. SMB FileIds are connection-wide, but a
    /// request must still present the tree that owns the open.
    public var treeId: UInt32 = 0
    public var contentVersion: String
    public var size: Int
    // QUERY_DIRECTORY enumeration state. `dirEntries != nil` marks "already
    // enumerated"; `cachedEntries` holds the packed-ready snapshot and `dirIndex`
    // the resume position. A restart-scan re-enumerates.
    public var dirEntries: [ItemMetadata]?
    public var cachedEntries: [DirEntry] = []
    public var dirIndex: Int = 0
    /// Immutable children returned by the atomic directory-snapshot compound.
    /// QUERY_DIRECTORY must pack this captured view without a second backend
    /// enumeration after the temporary remote handle has closed.
    public var transientDirectorySnapshot: PresentedDirectorySnapshot?
    // Reserved for P2+ (delete-on-close, named streams). Present for struct stability.
    public var deleteOnClose = false
    public var streamName: String? = nil
    public var leaseHandle = UUID().uuidString
    public var writeLease = false
    public var rangeLease = false
    /// False only for a self-contained transient directory snapshot whose
    /// remote read handle was acquired and closed atomically in one gateway call.
    public var remoteOpenRetained = true
    public var grantedAccess: UInt32 = SMBAccess.all
    public var shareAccess: OpenFileSharing = [.read, .write, .delete]
    // Shared by immutable READ snapshots; a failed Apple pipelined read cannot
    // be followed by success on this handle until the client closes/reopens it.
    var readIntegrity = SMBReadIntegrityState()

    public func hasAccess(_ access: UInt32) -> Bool { grantedAccess & access != 0 }

    public init(fileId: SMBFileId, node: InodeID, isDir: Bool, contentVersion: String, size: Int,
                presentationFileID: UInt64 = 0) {
        self.fileId = fileId; self.node = node; self.isDir = isDir
        self.presentationFileID = presentationFileID
        self.contentVersion = contentVersion; self.size = size
    }
}

/// Per-connection state. Owned by the connection thread; the async engine bridge
/// (`bridgeSync`) blocks that thread while it runs, so there is no concurrent
/// access — hence `@unchecked Sendable`.
public final class SMBConnectionState: @unchecked Sendable {
    // Session
    public var sessionId: UInt64 = 0
    public var authenticated = false
    public var pendingServerChallenge: Data? = nil   // set between CHALLENGE and AUTHENTICATE
    public var negotiateFlags: UInt32 = 0

    // Tree connections are independently identified even when they name the
    // same share. `treeId` remains the latest successful ID for old call sites.
    public private(set) var treeId: UInt32 = 0
    private var activeTreeIDs: Set<UInt32> = []
    public var treeConnected: Bool { !activeTreeIDs.isEmpty }
    /// Effective tree for the command currently being dispatched. It is set
    /// from that command's header (or RELATED inheritance), never prior packets.
    public var currentRequestTreeId: UInt32? = nil

    public func connectTree() -> UInt32 {
        var candidate: UInt32
        repeat { candidate = UInt32.random(in: 1..<UInt32.max) }
        while activeTreeIDs.contains(candidate)
        activeTreeIDs.insert(candidate)
        treeId = candidate
        return candidate
    }

    public func hasTree(_ id: UInt32) -> Bool { activeTreeIDs.contains(id) }
    public var activeTreeIds: [UInt32] { Array(activeTreeIDs) }

    public func disconnectTree(_ id: UInt32) -> Bool {
        guard activeTreeIDs.remove(id) != nil else { return false }
        if treeId == id { treeId = activeTreeIDs.first ?? 0 }
        if currentRequestTreeId == id { currentRequestTreeId = nil }
        return true
    }

    public func activeOpens(forTree id: UInt32) -> [SMBOpen] {
        opens.values.filter { $0.treeId == id }
    }

    // Set when the client sends an AAPL ServerQuery (first root CREATE) and we
    // advertise SUPPORTS_READ_DIR_ATTR — thereafter QUERY_DIRECTORY entries carry
    // the AAPL overlay (rsrc-fork size + FinderInfo + POSIX mode) so Finder skips
    // a per-file stream probe.
    public var aaplReadDirAttr = false
    // Client identity observed from its CREATE context, independent of optional
    // server directory-attribute optimizations used for diagnostics.
    public var appleClient = false

    // Opens
    private var opens: [SMBFileId: SMBOpen] = [:]
    private var nodeCounts: [InodeID: Int] = [:]
    private var nextHandle: UInt64 = 1
    private let connectionIdentity = UInt64.random(in: 1...UInt64.max-1)
    public var lastOpen: SMBOpen? = nil              // for compound RELATED FileId propagation
    /// Set only by the strict CREATE/QDIR/CLOSE compound recognizer.
    var directorySnapshotCandidate = false

    // CHANGE_NOTIFY session (async notify registry + pollers), attached by the
    // connection loop with this connection's writer.
    public var notify: NotifySession? = nil
    private var nextAsyncId: UInt64 = 1
    public func newAsyncId() -> UInt64 { let a = nextAsyncId; nextAsyncId &+= 1; return a }

    public init() {}

    public func newFileId() -> SMBFileId {
        let h = nextHandle; nextHandle &+= 1
        return SMBFileId(persistent: connectionIdentity, volatile: h)
    }

    public func register(_ open: SMBOpen) {
        open.treeId = currentRequestTreeId ?? treeId
        if opens[open.fileId] == nil { nodeCounts[open.node, default: 0] += 1 }
        opens[open.fileId] = open
        lastOpen = open
    }

    /// Look up an open by FileId, resolving the compound RELATED sentinel to the
    /// most recently created handle in the same chain.
    public func open(_ fileId: SMBFileId, treeId requestedTreeId: UInt32? = nil) -> SMBOpen? {
        let effectiveTree = requestedTreeId ?? currentRequestTreeId
        if fileId.isRelated {
            guard let lastOpen, effectiveTree == nil || lastOpen.treeId == effectiveTree else { return nil }
            return lastOpen
        }
        guard let open = opens[fileId], effectiveTree == nil || open.treeId == effectiveTree else { return nil }
        return open
    }

    public func isOpenOnDifferentTree(_ fileId: SMBFileId) -> Bool {
        guard !fileId.isRelated, let open = opens[fileId], let currentRequestTreeId else { return false }
        return open.treeId != currentRequestTreeId
    }

    /// Standalone reads run against a private value snapshot. The connection
    /// thread remains the only owner of mutable opens/session state, and drains
    /// all read workers before CLOSE, WRITE, compound or session mutations.
    func snapshotForRead(_ fileId: SMBFileId, treeId: UInt32) -> SMBConnectionState {
        let snapshot = SMBConnectionState()
        snapshot.sessionId = sessionId; snapshot.authenticated = authenticated
        snapshot.treeId = self.treeId
        snapshot.activeTreeIDs = activeTreeIDs
        snapshot.currentRequestTreeId = treeId
        snapshot.aaplReadDirAttr = aaplReadDirAttr
        snapshot.appleClient = appleClient
        if let original = open(fileId, treeId: treeId) {
            let copy = SMBOpen(fileId: original.fileId, node: original.node, isDir: original.isDir,
                               contentVersion: original.contentVersion, size: original.size,
                               presentationFileID: original.presentationFileID)
            copy.streamName = original.streamName
            copy.treeId = original.treeId
            copy.grantedAccess = original.grantedAccess
            copy.shareAccess = original.shareAccess
            copy.leaseHandle = original.leaseHandle
            copy.remoteOpenRetained = original.remoteOpenRetained
            copy.transientDirectorySnapshot = original.transientDirectorySnapshot
            copy.readIntegrity = original.readIntegrity
            snapshot.register(copy)
        }
        return snapshot
    }

    /// Nodes that currently have at least one open (loop thread only).
    func openNodes() -> Set<InodeID> { Set(nodeCounts.keys) }

    /// After a data write through `fileId`, other disk handles of the same file
    /// must not keep a shorter EOF than the write produced. Called by the lane
    /// worker; same-file reads are parked behind that lane, so no reader runs.
    func propagateWriteSize(from fileId: SMBFileId, newSize: Int, treeId: UInt32) {
        guard let src = opens[fileId], src.treeId == treeId else { return }
        src.size = newSize
        guard nodeCounts[src.node, default: 0] > 1 else { return }
        for o in opens.values where o !== src && o.node == src.node && !o.isDir && o.streamName == nil {
            o.size = max(o.size, newSize)
        }
    }

    /// Make every other disk handle of `open`'s file report exactly its size
    /// (truncate path; SET_INFO has already drained all in-flight reads/writes).
    func syncSiblingSizes(from open: SMBOpen) {
        for o in opens.values where o !== open && o.node == open.node && !o.isDir && o.streamName == nil {
            o.size = open.size
        }
    }

    public func closeAll() -> [SMBOpen] {
        let held = Array(opens.values); opens.removeAll(); nodeCounts.removeAll(); lastOpen = nil; return held
    }

    public func close(_ fileId: SMBFileId) -> SMBOpen? {
        let resolved = fileId.isRelated ? lastOpen?.fileId : fileId
        guard let resolved else { return nil }
        if let open = opens[resolved], let currentRequestTreeId, open.treeId != currentRequestTreeId { return nil }
        let o = opens.removeValue(forKey: resolved)
        if let o, let n = nodeCounts[o.node] { if n <= 1 { nodeCounts[o.node] = nil } else { nodeCounts[o.node] = n - 1 } }
        if lastOpen?.fileId == resolved { lastOpen = nil }
        return o
    }
}

final class SMBReadIntegrityState: @unchecked Sendable {
    private let lock = NSLock()
    private var failure: NTStatus?
    let responses = SMBReadResponseOrder()
    var status: NTStatus? { lock.lock(); defer { lock.unlock() }; return failure }
    func fail(_ status: NTStatus) {
        lock.lock(); defer { lock.unlock() }
        if failure == nil { failure = status }
    }
}

/// Generic rights are expanded once on CREATE; later operations are constrained
/// by that handle as well as the gateway ACL. This never grants backend access.
enum SMBAccess {
    static let readData: UInt32 = 0x1
    static let writeData: UInt32 = 0x2
    static let appendData: UInt32 = 0x4
    static let writeAttributes: UInt32 = 0x100
    static let delete: UInt32 = 0x10000
    static let all: UInt32 = 0x001F01FF
    static func openFileAccess(_ granted: UInt32) -> OpenFileAccess {
        var access: OpenFileAccess = []
        if granted & (readData | 0x20) != 0 { access.insert(.read) } // FILE_READ_DATA or FILE_EXECUTE
        if granted & (writeData | appendData) != 0 { access.insert(.write) }
        if granted & delete != 0 { access.insert(.delete) }
        return access
    }
    static func expanded(_ requested: UInt32) -> UInt32 {
        var granted = requested & 0x0FFF_FFFF
        if requested & 0x8000_0000 != 0 { granted |= 0x0012_0089 }
        if requested & 0x4000_0000 != 0 { granted |= 0x0012_0116 }
        if requested & 0x2000_0000 != 0 { granted |= 0x0012_00A0 }
        if requested & 0x1000_0000 != 0 { granted |= all }
        return granted
    }
}
