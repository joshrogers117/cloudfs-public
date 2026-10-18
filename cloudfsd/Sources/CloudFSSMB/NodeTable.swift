// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — node table: SMB file-ids (u64, reported in directory enumeration
// and FileInternalInformation) ↔ engine inode ids, plus the attribute/listing
// caches the handlers lean on.
//
// SMB is stateful (CREATE opens a handle), so per-open state lives in
// OpenFileTable; this table holds the id↔u64 mapping and the short-TTL metadata
// caches that make Finder enumeration cheap. Remote edits surface within the TTL;
// local mutations invalidate eagerly so the client never reads its own stale meta.

import Foundation
import CloudFSCore

public struct DirectorySnapshotReservation: Sendable {
    public let metadata: ItemMetadata
    fileprivate let generation: UInt64
    fileprivate let revision: UInt64
}

public struct PresentedDirectoryEntry: Sendable {
    public let metadata: ItemMetadata
    public let fileID: UInt64
}

public struct PresentedDirectorySnapshot: Sendable {
    public let directory: ItemMetadata
    public let directoryFileID: UInt64
    public let parentFileID: UInt64
    public let items: [PresentedDirectoryEntry]
}

public actor NodeTable {
    private let engine: any EngineDataPath
    private let ttl: Duration
    private let clock = ContinuousClock()

    private var idByFileId: [UInt64: InodeID] = [:]
    // Canonical IDs are a pure function of the immutable backend inode ID.
    // Remote presentation epochs live in a disjoint high-bit namespace.
    private var fileIdByID: [InodeID: UInt64] = [:]
    private var presentationFileIdByID: [InodeID: UInt64] = [:]
    private var nextPresentationID: UInt64 = 1
    private let remotePresentationIDs: Bool

    private struct PresentedLocation: Equatable {
        let parent: InodeID?
        let parentEpoch: UInt64
        let name: String
    }
    private var presentedLocationByID: [InodeID: PresentedLocation] = [:]
    private var directoryEpochByID: [InodeID: UInt64] = [:]
    private var pendingLocalRenames: [InodeID: UInt64] = [:]
    private var nextRenameToken: UInt64 = 1
    private var renameWaiters: [InodeID: [CheckedContinuation<Void, Never>]] = [:]
    private var queuedRenames: [InodeID: [CheckedContinuation<UInt64, Never>]] = [:]

    private struct CachedMeta { var meta: ItemMetadata; var at: ContinuousClock.Instant }
    private var metaCache: [InodeID: CachedMeta] = [:]
    // Retain the last accepted remote metadata version/location across TTL and
    // explicit cache invalidations, so delayed replies cannot undo a rename.
    private var observedMetaByID: [InodeID: ItemMetadata] = [:]
    private var metadataRevisions: [InodeID: UInt64] = [:]
    private var nextMetadataRevision: UInt64 = 0

    private struct CachedListing { var items: [ItemMetadata]; var at: ContinuousClock.Instant }
    private struct ListingSnapshot { let items: [ItemMetadata]; let generation: UInt64 }
    private var listings: [InodeID: CachedListing] = [:]
    private var listingGenerations: [InodeID: UInt64] = [:]

    private struct LocalOpen {
        let handle: String
        let access: OpenFileAccess
        let sharing: OpenFileSharing
    }
    private var localOpens: [InodeID: [String: LocalOpen]] = [:]

    public static let rootFileId: UInt64 = 2

    public init(engine: any EngineDataPath, ttl: Duration = .seconds(2),
                remotePresentationIDs: Bool = true) {
        self.engine = engine
        self.ttl = ttl
        self.remotePresentationIDs = remotePresentationIDs
        idByFileId[Self.rootFileId] = .root
        fileIdByID[.root] = Self.rootFileId
        presentationFileIdByID[.root] = Self.rootFileId
        presentedLocationByID[.root] = PresentedLocation(parent: nil, parentEpoch: 0, name: "")
    }

    public func engineRef() -> any EngineDataPath { engine }

    // MARK: file-ids

    public func fileId(for id: InodeID) -> UInt64 {
        if let f = fileIdByID[id] { return f }
        var salt: UInt64 = 0
        var f = Self.canonicalFileID(for: id, salt: salt)
        while let owner = idByFileId[f], owner != id {
            // Detect the (extremely unlikely) 63-bit hash collision and probe
            // deterministically for this process. Never silently alias inodes.
            salt &+= 1
            f = Self.canonicalFileID(for: id, salt: salt)
        }
        idByFileId[f] = id
        fileIdByID[id] = f
        return f
    }

    private static func canonicalFileID(for id: InodeID, salt: UInt64) -> UInt64 {
        // FNV-1a is deliberately implemented here instead of Swift's Hasher,
        // whose seed is randomized for each process. Clearing the top bit
        // reserves a disjoint namespace for remote presentation epochs.
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in id.rawValue.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001b3
        }
        var remaining = salt
        for _ in 0..<8 {
            hash ^= remaining & 0xff
            hash &*= 0x100000001b3
            remaining >>= 8
        }
        var value = hash & 0x7fff_ffff_ffff_ffff
        if value == 0 || value == 1 || value == Self.rootFileId { value &+= 3 }
        return value
    }

    /// Return the SMB presentation ID for a newly observed path. The canonical
    /// backend inode stays unchanged. When enabled, a remote move or rename gets
    /// a new presentation ID while existing SMBOpen values retain their snapshot.
    public func presentationFileId(for meta: ItemMetadata) async -> UInt64 {
        await presentationMetadata(for: meta).fileID
    }

    /// Resolve metadata and its presentation ID together after any local rename
    /// affecting the inode or its current parent has committed.
    public func presentationMetadata(for meta: ItemMetadata) async ->
        (metadata: ItemMetadata, fileID: UInt64) {
        let startingRevision = metadataRevisions[meta.id, default: 0]
        while true {
            await waitForLocalRename(meta.id)
            let candidate = preferredPresentationMetadata(meta, revision: startingRevision)
            if let parent = candidate.parent { await waitForLocalRename(parent) }
            // A parent wait may have allowed another rename of this inode, or a
            // second parent move. Recheck both gates and the selected location.
            let current = preferredPresentationMetadata(meta, revision: startingRevision)
            if pendingLocalRenames[meta.id] != nil ||
                current.parent.map({ pendingLocalRenames[$0] != nil }) == true ||
                current.parent != candidate.parent {
                continue
            }
            if remotePresentationIDs { observePresentationLocation(current) }
            let stableID = fileId(for: meta.id)
            let presentationID = remotePresentationIDs
                ? presentationFileIdByID[meta.id] ?? stableID
                : stableID
            return (current, presentationID)
        }
    }

    /// Resolve the current parent ID for a directory enumeration's `..` row.
    /// Recheck the directory after looking up the parent so one response cannot
    /// combine a directory's pre-move metadata with a post-move parent ID.
    public func presentationParentFileID(for meta: ItemMetadata) async throws -> UInt64 {
        for _ in 0..<3 {
            let presented = await presentationMetadata(for: meta)
            guard let parent = presented.metadata.parent else { return Self.rootFileId }
            let parentMeta = try await self.meta(parent)
            let parentID = await presentationFileId(for: parentMeta)
            let current = preferredPresentationMetadata(presented.metadata,
                revision: metadataRevisions[meta.id, default: 0])
            if current.parent == parent && pendingLocalRenames[meta.id] == nil &&
                pendingLocalRenames[parent] == nil {
                return parentID
            }
        }
        throw EngineError(.gatewayError, "Directory parent changed repeatedly during presentation")
    }

    private func preferredPresentationMetadata(_ meta: ItemMetadata, revision: UInt64) -> ItemMetadata {
        guard let latest = metaCache[meta.id]?.meta ?? observedMetaByID[meta.id] else { return meta }
        if metadataRevisions[meta.id, default: 0] != revision ||
            Self.compareVersion(meta.metadataVersion, latest.metadataVersion) != .orderedDescending {
            return latest
        }
        return meta
    }

    private static func sameLocation(_ lhs: ItemMetadata, _ rhs: ItemMetadata) -> Bool {
        lhs.parent == rhs.parent && lhs.name.precomposedStringWithCanonicalMapping == rhs.name.precomposedStringWithCanonicalMapping
    }

    private static func compareVersion(_ lhs: String, _ rhs: String) -> ComparisonResult {
        guard let left = Int(lhs), let right = Int(rhs) else { return .orderedSame }
        if left == right { return .orderedSame }
        return left < right ? .orderedAscending : .orderedDescending
    }

    private func observePresentationLocation(_ meta: ItemMetadata) {
        guard remotePresentationIDs, pendingLocalRenames[meta.id] == nil,
              meta.parent.map({ pendingLocalRenames[$0] == nil }) ?? true else { return }
        let location = PresentedLocation(parent: meta.parent,
            parentEpoch: meta.parent.map { directoryEpochByID[$0, default: 0] } ?? 0,
            name: meta.name.precomposedStringWithCanonicalMapping)
        if let previous = presentedLocationByID[meta.id] {
            guard previous != location else { return }
            presentedLocationByID[meta.id] = location
            if meta.isDir { directoryEpochByID[meta.id, default: 0] &+= 1 }
            _ = allocateNewPresentationID(for: meta.id)
            return
        }
        presentedLocationByID[meta.id] = location
    }

    /// Block listing/open responses that observe a location while a local SMB
    /// rename is awaiting the engine. The successful local commit then preserves
    /// the pre-rename presentation ID, regardless of actor scheduling.
    public func beginLocalRename(_ id: InodeID) async -> UInt64 {
        if pendingLocalRenames[id] == nil {
            return reserveRenameToken(for: id)
        }
        return await withCheckedContinuation { continuation in
            queuedRenames[id, default: []].append(continuation)
        }
    }

    private func reserveRenameToken(for id: InodeID) -> UInt64 {
        let token = nextRenameToken
        nextRenameToken &+= 1
        pendingLocalRenames[id] = token
        return token
    }

    public func commitLocalRename(_ meta: ItemMetadata, token: UInt64) {
        commitLocalRename(meta, token: token, forgetting: [], invalidatingDirectories: [])
    }

    public func commitLocalRename(_ meta: ItemMetadata, token: UInt64,
                                  forgetting ids: [InodeID],
                                  invalidatingDirectories directories: [InodeID]) {
        guard pendingLocalRenames[meta.id] == token else { return }
        // A local rename is already represented by the SMB vnode operation.
        // Keep the directory epoch fixed so its descendants keep their IDs.
        if storeMeta(meta), let accepted = metaCache[meta.id]?.meta {
            presentedLocationByID[meta.id] = PresentedLocation(parent: accepted.parent,
                parentEpoch: accepted.parent.map { directoryEpochByID[$0, default: 0] } ?? 0,
                name: accepted.name.precomposedStringWithCanonicalMapping)
        }
        for id in ids { invalidateMeta(id) }
        for dir in Set(directories) { invalidateListing(dir) }
        finishLocalRename(meta.id, token: token)
    }

    public func cancelLocalRename(_ id: InodeID, token: UInt64) {
        guard pendingLocalRenames[id] == token else { return }
        finishLocalRename(id, token: token)
    }

    private func finishLocalRename(_ id: InodeID, token: UInt64) {
        guard pendingLocalRenames[id] == token else { return }
        if var queue = queuedRenames[id], !queue.isEmpty {
            let waiter = queue.removeFirst()
            queuedRenames[id] = queue.isEmpty ? nil : queue
            let nextToken = reserveRenameToken(for: id)
            waiter.resume(returning: nextToken)
            return
        }
        pendingLocalRenames[id] = nil
        let waiters = renameWaiters.removeValue(forKey: id) ?? []
        for waiter in waiters { waiter.resume() }
    }

    func queuedLocalRenameCount(_ id: InodeID) -> Int { queuedRenames[id]?.count ?? 0 }
    func localRenameWaiterCount(_ id: InodeID) -> Int { renameWaiters[id]?.count ?? 0 }

    private func waitForLocalRename(_ id: InodeID) async {
        guard pendingLocalRenames[id] != nil else { return }
        await withCheckedContinuation { continuation in
            renameWaiters[id, default: []].append(continuation)
        }
    }

    private func allocateNewPresentationID(for id: InodeID) -> UInt64 {
        let value: UInt64
        while true {
            let candidate = 0x8000_0000_0000_0000 | nextPresentationID
            nextPresentationID &+= 1
            if idByFileId[candidate] == nil {
                value = candidate
                break
            }
        }
        idByFileId[value] = id
        presentationFileIdByID[id] = value
        return value
    }

    public func id(forFileId f: UInt64) -> InodeID? { idByFileId[f] }

    // MARK: metadata

    public func meta(_ id: InodeID) async throws -> ItemMetadata {
        // The real (or authorized projected) root carries a directory mtime.
        // Fabricating a timeless root makes macOS retain negative root-name
        // lookups forever even after the backend publishes a new child.
        for _ in 0..<3 {
            if let e = metaCache[id], e.at.duration(to: clock.now) <= ttl { return e.meta }
            let revision = metadataRevisions[id, default: 0]
            let m = try await engine.lookup(id)
            // An older request must not undo a local mutation or a newer fill
            // that completed while the actor was waiting for the gateway.
            guard revision == metadataRevisions[id, default: 0] else { continue }
            if storeMeta(m) { return m }
            if let accepted = metaCache[id]?.meta ?? observedMetaByID[id] { return accepted }
        }
        throw EngineError(.gatewayError, "Metadata changed repeatedly during lookup")
    }

    public func staleMeta(_ id: InodeID) -> ItemMetadata? { metaCache[id]?.meta }
    @discardableResult
    public func storeMeta(_ m: ItemMetadata) -> Bool {
        let previous = metaCache[m.id]?.meta ?? (remotePresentationIDs ? observedMetaByID[m.id] : nil)
        if let previous {
            let versionOrder = Self.compareVersion(m.metadataVersion, previous.metadataVersion)
            if versionOrder == .orderedAscending ||
                (versionOrder == .orderedSame && !Self.sameLocation(m, previous)) {
                return false
            }
        }
        if m.isDir, previous?.metadataVersion != m.metadataVersion || previous?.modifiedAt != m.modifiedAt {
            // macOS invalidates negative names when it observes this newer
            // parent mtime. Do not then answer from an older child listing.
            invalidateListing(m.id)
        }
        nextMetadataRevision &+= 1
        metadataRevisions[m.id] = nextMetadataRevision
        metaCache[m.id] = CachedMeta(meta: m, at: clock.now)
        if remotePresentationIDs { observedMetaByID[m.id] = m }
        observePresentationLocation(m)
        return true
    }

    // MARK: directories

    public func children(of dir: InodeID) async throws -> [ItemMetadata] {
        try await childrenSnapshot(of: dir).items
    }

    /// Resolve a directory listing against local rename completions. If any
    /// child moved while its presentation ID was waiting, retry the whole list
    /// so one SMB response cannot contain duplicate or mixed old/new names.
    public func presentationChildren(of dir: InodeID) async throws ->
        [(metadata: ItemMetadata, fileID: UInt64)] {
        for _ in 0..<3 {
            let snapshot = try await childrenSnapshot(of: dir)
            var entries: [(metadata: ItemMetadata, fileID: UInt64)] = []
            var movedOut = false
            for child in snapshot.items {
                let presented = await presentationMetadata(for: child)
                guard presented.metadata.parent == dir else {
                    movedOut = true
                    break
                }
                entries.append(presented)
            }
            guard snapshot.generation == listingGenerations[dir, default: 0] else { continue }
            if movedOut {
                invalidateListing(dir)
                continue
            }
            var names: Set<String> = []
            if entries.contains(where: {
                !names.insert($0.metadata.name.precomposedStringWithCanonicalMapping).inserted
            }) {
                invalidateListing(dir)
                continue
            }
            return entries
        }
        throw EngineError(.gatewayError, "Directory changed repeatedly during presentation")
    }

    private func childrenSnapshot(of dir: InodeID) async throws -> ListingSnapshot {
        for _ in 0..<3 {
            if let e = listings[dir], e.at.duration(to: clock.now) <= ttl {
                return ListingSnapshot(items: e.items, generation: listingGenerations[dir, default: 0])
            }
            let generation = listingGenerations[dir, default: 0]
            let startedRevision = nextMetadataRevision
            var out: [ItemMetadata] = []
            var page: String? = nil
            repeat {
                let (items, next) = try await engine.enumerate(container: dir, page: page)
                out.append(contentsOf: items)
                page = next
            } while page != nil
            // Invalidation can run while enumeration awaits I/O. Restamping
            // that stale response would resurrect the invalidated snapshot.
            guard generation == listingGenerations[dir, default: 0] else { continue }
            var staleEntry = false
            for index in out.indices where metadataRevisions[out[index].id, default: 0] > startedRevision {
                let old = out[index]
                guard let newer = metaCache[old.id]?.meta, newer.parent == old.parent, newer.name == old.name else {
                    staleEntry = true
                    break
                }
                out[index] = newer
            }
            guard !staleEntry else { continue }
            for index in out.indices where metadataRevisions[out[index].id, default: 0] <= startedRevision {
                let candidate = out[index]
                guard storeMeta(candidate) else {
                    guard let accepted = metaCache[candidate.id]?.meta ?? observedMetaByID[candidate.id],
                          Self.sameLocation(candidate, accepted) else {
                        staleEntry = true
                        break
                    }
                    out[index] = accepted
                    continue
                }
            }
            guard !staleEntry else { continue }
            listings[dir] = CachedListing(items: out, at: clock.now)
            // A late concurrent response must not replace this completed fill.
            listingGenerations[dir, default: 0] &+= 1
            return ListingSnapshot(items: out, generation: listingGenerations[dir, default: 0])
        }
        throw EngineError(.gatewayError, "Directory changed repeatedly during enumeration")
    }

    public func child(of dir: InodeID, named name: String) async throws -> ItemMetadata? {
        let target = name.precomposedStringWithCanonicalMapping
        if let found = try await children(of: dir).first(where: {
            $0.name.precomposedStringWithCanonicalMapping == target
        }) { return found }
        // Another Mac can create a file while this directory listing is warm.
        // Do not turn that short cache window into a kernel negative-name cache.
        // Even an initially uncached request can have captured its snapshot
        // before a concurrent parent refresh. Confirm absence with a new request.
        invalidateListing(dir)
        return try await children(of: dir).first {
            $0.name.precomposedStringWithCanonicalMapping == target
        }
    }

    /// Resolve a share-relative path ("dir\\sub\\file", already '\'-split into
    /// components) to metadata, walking from root. Empty components (the root, or
    /// a trailing separator) resolve to the current node. Returns nil if any
    /// component is absent.
    public func resolve(components: [String]) async throws -> ItemMetadata? {
        var node = try await meta(.root)
        for comp in components where !comp.isEmpty {
            guard node.isDir, let next = try await child(of: node.id, named: comp) else { return nil }
            node = next
        }
        return node
    }

    public func invalidateListing(_ dir: InodeID) {
        listings[dir] = nil
        listingGenerations[dir, default: 0] &+= 1
    }
    public func invalidateMeta(_ id: InodeID) {
        metaCache[id] = nil
        nextMetadataRevision &+= 1
        metadataRevisions[id] = nextMetadataRevision
    }

    /// Reserve a locally visible open atomically with the SMB share-mode check.
    /// The remote open lifetime is acquired separately through EngineDataPath.
    public func beginLocalOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                               sharing: OpenFileSharing) -> Bool {
        let existing = localOpens[id, default: [:]].values
        guard existing.allSatisfy({ Self.shareCompatible(access, sharing, $0.access, $0.sharing) }) else {
            return false
        }
        localOpens[id, default: [:]][handle] = LocalOpen(handle: handle, access: access, sharing: sharing)
        return true
    }

    /// Reserve a local read-only directory open and capture the cache epochs
    /// that must remain stable while the gateway takes its bounded snapshot.
    public func reserveDirectorySnapshotOpen(_ candidate: ItemMetadata, handle: String,
                                             access: OpenFileAccess,
                                             sharing: OpenFileSharing) -> DirectorySnapshotReservation? {
        let current = metaCache[candidate.id]?.meta ?? observedMetaByID[candidate.id] ?? candidate
        guard candidate.isDir,
              pendingLocalRenames[candidate.id] == nil,
              candidate.parent.map({ pendingLocalRenames[$0] == nil }) ?? true,
              current.isDir, Self.sameLocation(candidate, current)
        else { return nil }
        let existing = localOpens[candidate.id, default: [:]].values
        guard existing.allSatisfy({ Self.shareCompatible(access, sharing, $0.access, $0.sharing) }) else { return nil }
        localOpens[candidate.id, default: [:]][handle] = LocalOpen(handle: handle, access: access, sharing: sharing)
        return DirectorySnapshotReservation(metadata: current,
            generation: listingGenerations[current.id, default: 0],
            revision: nextMetadataRevision)
    }

    /// Adopt only a complete, same-directory snapshot captured while both the
    /// directory's listing generation and metadata revision were unchanged.
    /// All validation and cache writes are actor-atomic.
    public func adoptDirectorySnapshot(_ snapshot: DirectorySnapshot,
                                       reservation: DirectorySnapshotReservation) -> PresentedDirectorySnapshot? {
        let directory = snapshot.directory
        guard snapshot.items.count <= 500,
              directory.id == reservation.metadata.id, directory.isDir,
              Self.sameLocation(directory, reservation.metadata),
              listingGenerations[directory.id, default: 0] == reservation.generation,
              nextMetadataRevision == reservation.revision,
              pendingLocalRenames[directory.id] == nil,
              directory.parent.map({ pendingLocalRenames[$0] == nil }) ?? true
        else { return nil }
        var names: Set<String> = []
        for child in snapshot.items {
            guard child.id != directory.id, child.parent == directory.id,
                  pendingLocalRenames[child.id] == nil,
                  names.insert(child.name.precomposedStringWithCanonicalMapping).inserted else { return nil }
            if let current = metaCache[child.id]?.meta ?? observedMetaByID[child.id],
               !Self.sameLocation(child, current) || Self.compareVersion(child.metadataVersion, current.metadataVersion) == .orderedAscending {
                return nil
            }
        }
        let parentMeta: ItemMetadata?
        if let parent = directory.parent {
            guard let currentParent = metaCache[parent]?.meta ?? observedMetaByID[parent],
                  pendingLocalRenames[parent] == nil else { return nil }
            parentMeta = currentParent
        } else {
            parentMeta = nil
        }
        guard storeMeta(directory) else { return nil }
        var acceptedItems: [PresentedDirectoryEntry] = []
        acceptedItems.reserveCapacity(snapshot.items.count)
        for child in snapshot.items {
            _ = storeMeta(child)
            guard let accepted = metaCache[child.id]?.meta ?? observedMetaByID[child.id],
                  let presented = snapshotPresentation(accepted) else { return nil }
            acceptedItems.append(PresentedDirectoryEntry(metadata: presented.metadata, fileID: presented.fileID))
        }
        guard let presentedDirectory = snapshotPresentation(metaCache[directory.id]?.meta ?? directory) else { return nil }
        let parentFileID: UInt64
        if let parentMeta {
            guard let presentedParent = snapshotPresentation(parentMeta) else { return nil }
            parentFileID = presentedParent.fileID
        } else {
            parentFileID = Self.rootFileId
        }
        listings[directory.id] = CachedListing(items: acceptedItems.map(\.metadata), at: clock.now)
        listingGenerations[directory.id, default: 0] &+= 1
        return PresentedDirectorySnapshot(directory: presentedDirectory.metadata,
            directoryFileID: presentedDirectory.fileID, parentFileID: parentFileID, items: acceptedItems)
    }

    private func snapshotPresentation(_ meta: ItemMetadata) -> (metadata: ItemMetadata, fileID: UInt64)? {
        guard pendingLocalRenames[meta.id] == nil,
              meta.parent.map({ pendingLocalRenames[$0] == nil }) ?? true else { return nil }
        let current = metaCache[meta.id]?.meta ?? observedMetaByID[meta.id] ?? meta
        guard Self.sameLocation(meta, current) else { return nil }
        observePresentationLocation(current)
        let stable = fileId(for: current.id)
        return (current, remotePresentationIDs ? (presentationFileIdByID[current.id] ?? stable) : stable)
    }

    public func endLocalOpen(_ id: InodeID, handle: String) {
        localOpens[id]?[handle] = nil
        if localOpens[id]?.isEmpty == true { localOpens[id] = nil }
    }

    /// Delete and rename require every other open to have shared delete access.
    public func allowsDelete(_ id: InodeID, excluding handle: String) -> Bool {
        localOpens[id, default: [:]].values
            .filter { $0.handle != handle }
            .allSatisfy { $0.sharing.contains(.delete) }
    }

    private static func shareCompatible(_ requested: OpenFileAccess, _ sharing: OpenFileSharing,
                                        _ existing: OpenFileAccess, _ existingSharing: OpenFileSharing) -> Bool {
        (requested.contains(.read) == false || existingSharing.contains(.read)) &&
        (requested.contains(.write) == false || existingSharing.contains(.write)) &&
        (requested.contains(.delete) == false || existingSharing.contains(.delete)) &&
        (existing.contains(.read) == false || sharing.contains(.read)) &&
        (existing.contains(.write) == false || sharing.contains(.write)) &&
        (existing.contains(.delete) == false || sharing.contains(.delete))
    }

    // MARK: mutations (P2)

    /// Create a file/dir named `name` under the directory addressed by
    /// `parentComponents`. Returns the created metadata, or nil if the parent path
    /// doesn't resolve. Invalidates the parent listing and caches the new meta so
    /// the client never reads its own stale directory view.
    public func createItem(parentComponents: [String], name: String, isDir: Bool)
        async throws -> ItemMetadata? {
        guard let parent = try await resolve(components: parentComponents), parent.isDir else { return nil }
        let fields = ItemMetadata(id: InodeID(""), parent: parent.id, name: name, isDir: isDir,
                                  size: 0, contentVersion: "", metadataVersion: "")
        let created = try await engine.write(id: nil, fields: fields, contents: nil, baseVersion: nil)
        invalidateListing(parent.id)
        storeMeta(created)
        return created
    }

    /// Project a post-write size into the cached metadata (so the next getattr
    /// reflects the write before the async upload commits) and drop the parent's
    /// stale listing (read-your-own-writes discipline).
    public func projectWrite(_ id: InodeID, newSize: Int) {
        guard let m = metaCache[id]?.meta else { return }
        let projected = ItemMetadata(id: id, parent: m.parent, name: m.name, isDir: m.isDir,
                                     size: newSize, contentVersion: m.contentVersion,
                                     metadataVersion: m.metadataVersion, createdAt: m.createdAt, modifiedAt: Date(),
                                     accessedAt: m.accessedAt, changedAt: Date(), fileAttributes: m.fileAttributes,
                                     rsrcForkSize: m.rsrcForkSize, finderInfo: m.finderInfo, finderInfoCiphertext: m.finderInfoCiphertext)
        storeMeta(projected)
        if let p = m.parent { invalidateListing(p) }
    }

    public func forget(_ id: InodeID, parent: InodeID?) {
        invalidateMeta(id)
        if let parent { invalidateListing(parent) }
    }
}

// MARK: - Path helpers

public enum SMBPath {
    /// Split an SMB path on backslashes, NFC-normalizing each component. Forward
    /// slashes are also accepted defensively. Leading/trailing separators collapse.
    public static func components(_ path: String) -> [String] {
        path.split(whereSeparator: { $0 == "\\" || $0 == "/" })
            .map { String($0).precomposedStringWithCanonicalMapping }
    }

    /// The final path component (the leaf name), or "" for the root.
    public static func leaf(_ path: String) -> String { components(path).last ?? "" }
}
