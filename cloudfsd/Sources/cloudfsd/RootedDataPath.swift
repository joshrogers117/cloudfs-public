// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// Projects only gateway-authorized mount roots into a volume. The gateway still
/// authorizes every real inode operation; projection never grants traversal to
/// unreadable ancestors. Multiple grants become named top-level folders.
final class MountRootSnapshot: @unchecked Sendable {
    private let lock = NSLock()
    private var value: [FilespaceMountRoot] = []
    private var aliases: [String: String] = [:]
    init(_ roots: [FilespaceMountRoot]) { update(roots) }
    func get() -> [FilespaceMountRoot] { lock.withLock { value } }
    func set(_ roots: [FilespaceMountRoot]) { lock.withLock { update(roots) } }
    private func update(_ roots: [FilespaceMountRoot]) {
        value = roots.map { root in
            var name = aliases[root.id] ?? root.name
            if aliases[root.id] == nil {
                if roots.filter({ $0.name == name }).count > 1 || aliases.values.contains(name) { name += " (\(root.id))" }
                while aliases.values.contains(name) { name += " (\(root.id))" }
                aliases[root.id] = name
            }
            return FilespaceMountRoot(id: root.id, name: name, mountAsRoot: root.mountAsRoot)
        }
    }
}

struct RootedDataPath: EngineDataPath {
    let base: any EngineDataPath
    private let initialRoots: [FilespaceMountRoot]
    private let projection: MountRootSnapshot?
    var roots: [FilespaceMountRoot] { projection?.get() ?? initialRoots }
    init(base: any EngineDataPath, roots: [FilespaceMountRoot], directRoot: InodeID?, projection: MountRootSnapshot? = nil) {
        self.base = base; initialRoots = roots; self.directRoot = directRoot; self.projection = projection
    }
    let directRoot: InodeID?
    var isReadOnly: Bool { base.isReadOnly }
    func changeGeneration() async -> UInt64 { await base.changeGeneration() }
    func waitForChanges(after: UInt64) async -> UInt64 { await base.waitForChanges(after: after) }
    func notificationCheckpoint(container: InodeID) async throws -> String {
        // Virtual-root enumerateChanges is a folder snapshot, not a delta. Use
        // the underlying filespace checkpoint, which includes ACL visibility.
        let actual = container == .root && directRoot == nil ? InodeID.root : try translate(container)
        let checkpoint = try await base.notificationCheckpoint(container: actual)
        guard container == .root, directRoot == nil else { return checkpoint }
        // Also detect an updated local grant projection before its next feed hint.
        let projected = roots.map { "\($0.id.utf8.count):\($0.id)\($0.name.utf8.count):\($0.name)" }.sorted().joined(separator: ";")
        return "\(checkpoint.utf8.count):\(checkpoint);roots:\(projected)"
    }
    var plaintextSpillDir: String { base.plaintextSpillDir }

    private var rootIDs: Set<InodeID> { Set(roots.map { InodeID($0.id) }) }
    private func translate(_ id: InodeID) throws -> InodeID {
        if id == .root {
            guard let directRoot else { throw EngineError(.permissionDenied, "Choose a shared folder inside this volume") }
            return directRoot
        }
        return id
    }
    private func protectRoot(_ id: InodeID) throws {
        if id == .root || rootIDs.contains(id) {
            throw EngineError(.permissionDenied, "A mounted shared root cannot be renamed or deleted from this volume")
        }
    }
    private func projected(_ item: ItemMetadata) -> ItemMetadata {
        let isDirect = item.id == directRoot
        let parent = item.parent == directRoot || rootIDs.contains(item.id) ? InodeID.root : item.parent
        var name = item.name
        if directRoot == nil, let root = roots.first(where: { $0.id == item.id.rawValue }) {
            // Granted top-level folders are mount aliases. Retain their captured
            // names until remount so revocation/rename cannot introduce collisions
            // or change paths independently of the live volume's namespace.
            name = root.name
            if roots.filter({ $0.name == name }).count > 1 { name += " (\(item.id.rawValue))" }
        }
        return ItemMetadata(id: isDirect ? .root : item.id, parent: isDirect ? nil : parent,
                            name: name, isDir: item.isDir, size: item.size,
                            contentVersion: item.contentVersion, metadataVersion: item.metadataVersion,
                            createdAt: item.createdAt, modifiedAt: item.modifiedAt, accessedAt: item.accessedAt, changedAt: item.changedAt, fileAttributes: item.fileAttributes,
                            rsrcForkSize: item.rsrcForkSize, finderInfo: item.finderInfo)
    }
    func acquireRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {
        try await base.acquireRanges(translate(id),handle:handle,ranges:ranges)
    }
    func releaseRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {
        try await base.releaseRanges(translate(id),handle:handle,ranges:ranges)
    }
    func releaseAllRanges(_ id: InodeID, handle: String) async {
        guard let actual=try? translate(id) else { return }; await base.releaseAllRanges(actual,handle:handle)
    }
    func checkRangeAccess(_ id: InodeID, handle: String, offset: UInt64, length: UInt64, write: Bool) async throws {
        try await base.checkRangeAccess(translate(id),handle:handle,offset:offset,length:length,write:write)
    }
    func beginWrite(_ id: InodeID, handle: String) async throws {
        try await base.beginWrite(translate(id), handle: handle)
    }
    func beginWriteSnapshot(_ id: InodeID, handle: String) async throws -> ItemMetadata? {
        guard let item = try await base.beginWriteSnapshot(translate(id), handle: handle) else { return nil }
        return projected(item)
    }
    func endWrite(_ id: InodeID, handle: String) async {
        guard let actual = try? translate(id) else { return }
        await base.endWrite(actual, handle: handle)
    }
    func authorizeWrite(_ id: InodeID, refresh: Bool) async throws {
        try await base.authorizeWrite(translate(id), refresh: refresh)
    }
    func beginOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                   sharing: OpenFileSharing) async throws {
        try await base.beginOpen(translate(id), handle: handle, access: access, sharing: sharing)
    }
    func beginStreamOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                         sharing: OpenFileSharing, name: String, required: Bool) async throws -> Int? {
        try await base.beginStreamOpen(translate(id), handle: handle, access: access,
                                       sharing: sharing, name: name, required: required)
    }
    func directorySnapshot(_ id: InodeID, handle: String, access: OpenFileAccess,
                           sharing: OpenFileSharing) async throws -> DirectorySnapshot? {
        // An aggregate virtual root is assembled from independent grants and
        // cannot be represented by one underlying namespace transaction.
        guard !(id == .root && directRoot == nil) else { return nil }
        let actual = try translate(id)
        guard let snapshot = try await base.directorySnapshot(actual, handle: handle,
            access: access, sharing: sharing) else { return nil }
        guard snapshot.directory.id == actual else {
            throw EngineError(.gatewayError, "Directory snapshot returned a different inode")
        }
        return DirectorySnapshot(directory: projected(snapshot.directory),
                                 items: snapshot.items.map(projected))
    }
    func endOpen(_ id: InodeID, handle: String) async {
        guard let actual = try? translate(id) else { return }
        await base.endOpen(actual, handle: handle)
    }
    func lookup(_ id: InodeID) async throws -> ItemMetadata {
        if id == .root, directRoot == nil {
            return ItemMetadata(id: .root, parent: nil, name: "Shared folders", isDir: true,
                                size: 0, contentVersion: "mount-roots", metadataVersion: "0")
        }
        return projected(try await base.lookup(translate(id)))
    }
    func enumerate(container: InodeID, page: String?) async throws -> (items: [ItemMetadata], nextPage: String?) {
        if container == .root, directRoot == nil {
            guard page == nil else { return ([], nil) }
            var items: [ItemMetadata] = []
            for root in roots {
                do { items.append(projected(try await base.lookup(InodeID(root.id)))) }
                catch let error as EngineError where error.kind == .notFound || error.kind == .permissionDenied {
                    // A removed/revoked grant must not hide other accessible folders.
                    continue
                }
            }
            return (items, nil)
        }
        let result = try await base.enumerate(container: translate(container), page: page)
        return (result.items.map(projected), result.nextPage)
    }
    func enumerateChanges(container: InodeID, anchor: String) async throws
        -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool) {
        // SMB uses per-directory listings for notifications. For a virtual root,
        // refresh its explicitly granted folders without querying the forbidden root.
        if container == .root, directRoot == nil {
            let result = try await enumerate(container: .root, page: nil)
            return (result.items, [], anchor, false)
        }
        let result = try await base.enumerateChanges(container: translate(container), anchor: anchor)
        return (result.updated.map(projected), result.deleted, result.newAnchor, result.moreComing)
    }
    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef {
        try await base.readContents(translate(id), version: version)
    }
    func readBytes(_ id: InodeID, version: String, offset: Int, length: Int) async throws -> Data {
        try await base.readBytes(translate(id), version: version, offset: offset, length: length)
    }
    func readRange(_ id: InodeID, version: String, offset: Int, length: Int, alignment: Int) async throws
        -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int)) {
        try await base.readRange(translate(id), version: version, offset: offset, length: length, alignment: alignment)
    }
    func write(id: InodeID?, fields: ItemMetadata, contents: CacheFileRef?, baseVersion: String?) async throws -> ItemMetadata {
        let translated = ItemMetadata(id: fields.id, parent: try fields.parent.map(translate), name: fields.name,
                                      isDir: fields.isDir, size: fields.size, contentVersion: fields.contentVersion,
                                      metadataVersion: fields.metadataVersion, createdAt: fields.createdAt, modifiedAt: fields.modifiedAt, accessedAt: fields.accessedAt, changedAt: fields.changedAt, fileAttributes: fields.fileAttributes)
        return projected(try await base.write(id: try id.map(translate), fields: translated, contents: contents, baseVersion: baseVersion))
    }
    func writeRange(_ id: InodeID, offset: Int, data: Data, baseVersion: String?) async throws -> Int {
        try await base.writeRange(translate(id), offset: offset, data: data, baseVersion: baseVersion)
    }
    func truncate(_ id: InodeID, newSize: Int, baseVersion: String?) async throws {
        try protectRoot(id); try await base.truncate(translate(id), newSize: newSize, baseVersion: baseVersion)
    }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws {
        try protectRoot(id); try await base.delete(id, baseVersion: baseVersion, recursive: recursive)
    }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool, openHandle: String?) async throws {
        try protectRoot(id)
        try await base.delete(translate(id), baseVersion: baseVersion, recursive: recursive, openHandle: openHandle)
    }
    func setBasicInfo(_ id: InodeID, info: BasicFileInfo) async throws -> ItemMetadata {
        try protectRoot(id)
        return projected(try await base.setBasicInfo(translate(id), info: info))
    }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata {
        try protectRoot(id)
        return projected(try await base.rename(id, newParent: try newParent.map(translate), newName: newName))
    }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String, replacing: ItemMetadata?) async throws -> ItemMetadata {
        try protectRoot(id)
        if let replacing { try protectRoot(replacing.id) }
        return projected(try await base.rename(id, newParent: try newParent.map(translate), newName: newName, replacing: replacing))
    }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String,
                replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata {
        try protectRoot(id)
        if let replacing { try protectRoot(replacing.id) }
        return projected(try await base.rename(translate(id), newParent: try newParent.map(translate),
                                               newName: newName, replacing: replacing, openHandle: openHandle))
    }
    func setContentPolicy(_ id: InodeID, policy: ContentPolicy) async throws {
        try await base.setContentPolicy(translate(id), policy: policy)
    }
    func requestDownload(_ id: InodeID, range: (offset: Int, length: Int)?) async throws -> PrefetchAck {
        try await base.requestDownload(translate(id), range: range)
    }
    func evict(_ id: InodeID) async throws -> EvictAck { try await base.evict(translate(id)) }
    func listStreams(_ id: InodeID) async throws -> [StreamInfo] {
        if id == .root, directRoot == nil { return [] }
        return try await base.listStreams(translate(id))
    }
    func readStreamRange(_ id: InodeID, name: String, offset: Int, length: Int) async throws -> Data { try await base.readStreamRange(translate(id), name: name, offset: offset, length: length) }
    func writeStreamRange(_ id: InodeID, name: String, offset: Int, data: Data) async throws -> Int { try await base.writeStreamRange(translate(id), name: name, offset: offset, data: data) }
    func truncateStream(_ id: InodeID, name: String, size: Int) async throws { try await base.truncateStream(translate(id), name: name, size: size) }
    func readStream(_ id: InodeID, name: String) async throws -> Data { try await base.readStream(translate(id), name: name) }
    func writeStream(_ id: InodeID, name: String, data: Data) async throws { try await base.writeStream(translate(id), name: name, data: data) }
    func deleteStream(_ id: InodeID, name: String) async throws { try await base.deleteStream(translate(id), name: name) }
}
