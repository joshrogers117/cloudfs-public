// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSCache
import CloudFSGateway
import CloudFSTransfer

struct EnginePinIntent: Codable, Sendable {
    var path: String
    /// Nil represents the mounted volume's authorized projected root set.
    var inode: String?
    var recursive: Bool
    var generation: UUID
    var failureReason: String?
    var offlineExpiresAt: Date?
    var offlineFailureReason: String?
}

/// Mutable state is confined to the composing CloudFSEngine actor.
final class EnginePinSession {
    var intents: [String: EnginePinIntent] = [:]
    var jobs: [String: Task<Void, Never>] = [:]
    var monitor: Task<Void, Never>?
    var preparing: Set<String> = []
    var lastAnchor: Int?
    var pollCount = 0
    var busy: Set<String> = []
    var waiters: [String: [CheckedContinuation<Void, Never>]] = [:]
    deinit { monitor?.cancel(); for task in jobs.values { task.cancel() } }
}

extension CloudFSEngine {
    func normalizePinPath(_ path: String) throws -> String {
        let parts = path.split(separator: "/").map(String.init)
        guard !parts.contains(".."), !parts.contains("."), !path.contains("\0") else {
            throw EngineError(.invalidParams, "Choose a path inside the filespace")
        }
        return parts.joined(separator: "/")
    }
    private func pinIntentURL(_ filespace: FilespaceID) async throws -> URL {
        _ = try require(filespace)
        let directory = stableStateDirectory(filespace)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return directory.appendingPathComponent("pin-intents-v2.json")
    }
    private func savePinIntents(_ filespace: FilespaceID) async throws {
        guard let state = pinSessions[filespace] else { return }
        let url = try await pinIntentURL(filespace)
        // Snapshot after the only suspension so an older async writer cannot
        // restore an intent removed by unpin while resolving the cache location.
        let data = try JSONEncoder().encode(state.intents.values.sorted { $0.path < $1.path })
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
    func restorePinIntents(_ filespace: FilespaceID) async throws {
        guard pinSessions[filespace] == nil else { return }
        let session = try require(filespace)
        let url = try await pinIntentURL(filespace)
        let location = try await session.cache.info(filespace: filespace).location
        guard (try? require(filespace)) === session else { throw CancellationError() }
        guard pinSessions[filespace] == nil else { return }
        let state = EnginePinSession()
        let legacy = URL(fileURLWithPath: location).appendingPathComponent("pin-intents.json")
        let source = FileManager.default.fileExists(atPath: url.path) ? url : legacy
        if FileManager.default.fileExists(atPath: source.path) {
            let records = try JSONDecoder().decode([EnginePinIntent].self, from: Data(contentsOf: source))
            for var intent in records {
                intent.generation = UUID() // invalidate every previous process's work
                state.intents[intent.path] = intent
            }
        }
        pinSessions[filespace] = state
        if !state.intents.isEmpty { try await savePinIntents(filespace) }
        startPinMonitor(filespace)
        refreshPins(filespace)
    }
    func stopPinMaintenance(_ filespace: FilespaceID) {
        guard let state = pinSessions.removeValue(forKey: filespace) else { return }
        state.monitor?.cancel()
        for job in state.jobs.values { job.cancel() }
        // Waiters belong to cancelled jobs and must wake to observe invalidation.
        for queued in state.waiters.values { for waiter in queued { waiter.resume() } }
        state.waiters.removeAll()
    }
    private func startPinMonitor(_ filespace: FilespaceID) {
        guard let state = pinSessions[filespace], state.monitor == nil else { return }
        // Service maintenance outlives the individual request that connected the
        // filespace; do not retain that request's task-local context.
        state.monitor = Task.detached(priority: .utility) { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(for: .seconds(5)) } catch { return }
                await self?.pollPins(filespace)
            }
        }
    }
    private func pollPins(_ filespace: FilespaceID) async {
        guard let state = pinSessions[filespace], !state.intents.isEmpty,
              let session = try? require(filespace), !session.paused else { return }
        state.pollCount += 1
        let pending = (try? await session.cache.pinList(filespace: filespace))?.contains { $0.cacheState == .pinning } ?? true
        var changed = state.lastAnchor == nil || state.pollCount % 12 == 0 || pending
            || state.intents.values.contains { $0.failureReason != nil || $0.offlineFailureReason != nil }
        do {
            let feed = try await gateway.changesWithDeletions(filespace: filespace, since: state.lastAnchor)
            changed = changed || state.lastAnchor != feed.anchor || !feed.updated.isEmpty || !feed.deleted.isEmpty
            state.lastAnchor = feed.anchor
        } catch { changed = true } // Folder-only accounts can still refresh their granted subtree.
        if changed { refreshPins(filespace) }
    }

    /// Polling follows remote membership as well as already-known block changes.
    /// One active job per intent prevents an expensive folder scan accumulating.
    func refreshPins(_ filespace: FilespaceID) {
        guard let state = pinSessions[filespace], let session = try? require(filespace), !session.paused else { return }
        for intent in state.intents.values where state.jobs[intent.path] == nil {
            state.jobs[intent.path] = Task { [weak self] in
                await self?.materializePin(filespace, intent: intent)
            }
        }
    }
    func suspendPinJobs(_ filespace: FilespaceID) {
        guard let state = pinSessions[filespace] else { return }
        for path in Array(state.intents.keys) {
            state.jobs[path]?.cancel(); state.jobs[path] = nil
            state.intents[path]?.generation = UUID()
        }
    }
    func retryPins(_ filespace: FilespaceID) async throws {
        guard let state = pinSessions[filespace] else { return }
        for path in Array(state.intents.keys) {
            state.jobs[path]?.cancel(); state.jobs[path] = nil
            state.intents[path]?.generation = UUID()
        }
        try await savePinIntents(filespace)
        refreshPins(filespace)
    }

    private func isCurrentPin(_ filespace: FilespaceID, _ intent: EnginePinIntent) -> Bool {
        !Task.isCancelled && pinSessions[filespace]?.intents[intent.path]?.generation == intent.generation
    }
    private func pinGate(_ filespace: FilespaceID, _ path: String) async throws {
        guard let state = pinSessions[filespace] else { throw CancellationError() }
        if state.busy.insert(path).inserted { return }
        await withCheckedContinuation { state.waiters[path, default: []].append($0) }
        guard pinSessions[filespace] === state else { throw CancellationError() }
    }
    private func leavePinGate(_ filespace: FilespaceID, _ path: String) {
        guard let state = pinSessions[filespace] else { return }
        if var queued = state.waiters[path], !queued.isEmpty {
            let next = queued.removeFirst(); state.waiters[path] = queued.isEmpty ? nil : queued; next.resume()
        } else { state.busy.remove(path) }
    }

    func pinMountRoots(_ filespace: FilespaceID) async throws -> [FilespaceMountRoot] {
        let session = try require(filespace)
        if session.record.mountPath != nil {
            // SMB captures this projection when the volume mounts. Its name
            // disambiguation must remain identical until remount, even after a
            // sibling grant is revoked. Item lookups still recheck current ACLs.
            return session.mountRoots ?? [FilespaceMountRoot(id: "root", name: filespace, mountAsRoot: true)]
        }
        let roots = try await gateway.mountRoots(filespace: filespace)
        if let requested = session.record.rootPoint, requested != "root" {
            // Explicit subfolder mounts use paths relative to that folder. The
            // metadata lookup rechecks its current permission before traversal.
            let root = try await gateway.getItem(filespace: filespace, id: InodeID(requested))
            guard root.isDir else { throw EngineError(.invalidParams, "Pin root must be a folder") }
            return [FilespaceMountRoot(id: requested, name: root.name, mountAsRoot: true)]
        }
        return roots
    }

    /// Resolve an actual inode only within the currently authorized projection.
    /// Stop at a granted root so folder-only users need no ancestor permission.
    func projectedPathForInode(_ filespace: FilespaceID, id: InodeID) async throws -> String {
        let roots = try await pinMountRoots(filespace)
        guard !roots.isEmpty else { throw EngineError(.permissionDenied, "No shared folders are available") }
        let direct = roots.count == 1 && roots[0].mountAsRoot ? roots[0].id : nil
        var current = id, parts: [String] = [], seen: Set<InodeID> = []
        while true {
            guard seen.count < 1024, seen.insert(current).inserted else {
                throw EngineError(.gatewayError, "Folder parents form a cycle or exceed the maximum depth")
            }
            let item = try await gateway.getItem(filespace: filespace, id: current)
            if current.rawValue == direct { return parts.reversed().joined(separator: "/") }
            if let root = roots.first(where: { $0.id == current.rawValue }) {
                if root.id != "root" {
                    let duplicate = roots.filter { $0.name == root.name }.count > 1
                    let projectedName = duplicate ? "\(root.name) (\(root.id))" : root.name
                    try validateProjectedName(projectedName)
                    parts.append(projectedName)
                }
                return parts.reversed().joined(separator: "/")
            }
            guard current != .root, let parent = item.parent else {
                throw EngineError(.permissionDenied, "This item is outside the mounted folders")
            }
            try validateProjectedName(item.name)
            parts.append(item.name)
            current = parent
        }
    }
    private func validateProjectedName(_ name: String) throws {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0") else {
            throw EngineError(.gatewayError, "The item has an invalid name")
        }
    }

    func setPinPolicy(filespace: FilespaceID, id: InodeID, policy: ContentPolicy) async throws {
        if policy == .pinned {
            let path = try await projectedPathForInode(filespace, id: id)
            let item = try await gateway.getItem(filespace: filespace, id: id)
            _ = try await pin(PinParams(filespace: filespace, path: path, recursive: item.isDir))
        } else {
            if pinSessions[filespace] == nil { try await restorePinIntents(filespace) }
            let paths = pinSessions[filespace]?.intents.values.filter { $0.inode == id.rawValue }.map(\.path) ?? []
            for path in paths { _ = try await unpin(PinParams(filespace: filespace, path: path)) }
            // Backward-compatible cleanup of old cache-only inode registrations.
            _ = try await require(filespace).cache.unpin(id.rawValue, recursive: false)
        }
    }

    public func pin(_ p: PinParams) async throws -> PinState {
        let session = try require(p.filespace)
        if pinSessions[p.filespace] == nil { try await restorePinIntents(p.filespace) }
        let path = try normalizePinPath(p.path)
        // Resolve projected paths into gateway-authoritative inode identities.
        let roots = try await pinMountRoots(p.filespace)
        if !(roots.count == 1 && roots[0].id == "root") {
            session.mountRoots = roots
            session.directMountRoot = roots.count == 1 && roots[0].mountAsRoot ? InodeID(roots[0].id) : nil
        }
        let projected = try await resolveInode(p.filespace, path: path)
        let virtualRoot = projected == .root && session.mountRoots != nil && session.directMountRoot == nil
        let actual = projected == .root ? (session.directMountRoot ?? projected) : projected
        let meta = virtualRoot ? nil : try await gateway.getItem(filespace: p.filespace, id: actual)
        let recursive = p.recursive ?? (meta?.isDir ?? true)
        if meta?.isDir == true, !recursive {
            throw EngineError(.invalidParams, "Pin folders recursively to keep their contents available")
        }
        if let existing = pinSessions[p.filespace]?.intents.values.first(where: {
            $0.path != path && $0.inode == (virtualRoot ? nil : actual.rawValue) && $0.recursive == recursive
        }) {
            refreshPins(p.filespace)
            return try await pinStatus(p.filespace, path: existing.path, intent: existing)
        }
        try await pinGate(p.filespace, path)
        defer { leavePinGate(p.filespace, path) }
        guard let state = pinSessions[p.filespace] else { throw CancellationError() }
        if let old = state.intents[path], old.failureReason == nil, old.recursive == recursive,
           old.inode == (virtualRoot ? nil : actual.rawValue) {
            return try await pinStatus(p.filespace, path: path, intent: old)
        }
        let previous = state.intents[path]
        let intent = EnginePinIntent(path: path, inode: virtualRoot ? nil : actual.rawValue,
                                     recursive: recursive, generation: UUID())
        state.jobs[path]?.cancel(); state.jobs[path] = nil
        state.intents[path] = intent; state.preparing.insert(path)
        do { try await savePinIntents(p.filespace) }
        catch { state.intents[path] = previous; state.preparing.remove(path); throw error }
        // Already-prefetched files can immediately show Pinned. Directory pins
        // remain Pinning until their complete remote membership is enumerated.
        var immediate: PinState?
        if meta?.isDir == false, previous == nil || previous?.inode == intent.inode {
            immediate = try? await session.cache.pin(path, recursive: recursive)
            if immediate?.cacheState == .pinned { state.preparing.remove(path) }
        }
        refreshPins(p.filespace)
        return immediate ?? PinState(path: path, pinned: true, recursive: recursive, blocks: 0,
                                     cachedBytes: 0, totalBytes: meta.flatMap { $0.isDir ? nil : UInt64($0.size) }, cacheState: .pinning)
    }

    public func unpin(_ p: PinParams) async throws -> PinState {
        let session = try require(p.filespace), path = try normalizePinPath(p.path)
        if pinSessions[p.filespace] == nil { try await restorePinIntents(p.filespace) }
        var paths = pinSessions[p.filespace]?.intents.keys.filter {
            $0 == path || p.recursive == true && (path.isEmpty || $0.hasPrefix(path + "/"))
        } ?? []
        // Finder can address a renamed pin before the next monitor refresh.
        if !paths.contains(path), let id = try? await resolveInode(p.filespace, path: path) {
            let actual = id == .root ? (session.directMountRoot ?? id) : id
            let aliases = pinSessions[p.filespace]?.intents.values.filter { $0.inode == actual.rawValue }.map(\.path) ?? []
            paths.append(contentsOf: aliases)
            if p.recursive == true {
                paths.append(contentsOf: pinSessions[p.filespace]?.intents.keys.filter { candidate in
                    aliases.contains { candidate.hasPrefix($0 + "/") }
                } ?? [])
            }
        }
        var result = PinState(path: path, pinned: false, recursive: p.recursive ?? false, blocks: 0)
        for candidate in Set(paths + [path]).sorted() {
            try await pinGate(p.filespace, candidate)
            do {
                guard let state = pinSessions[p.filespace] else { throw CancellationError() }
                try? FileManager.default.removeItem(at: OfflineCheckpoint.url(directory: stableStateDirectory(p.filespace), path: candidate))
                let old = state.intents.removeValue(forKey: candidate)
                do { try await savePinIntents(p.filespace) }
                catch { state.intents[candidate] = old; throw error }
                state.jobs[candidate]?.cancel(); state.jobs[candidate] = nil; state.preparing.remove(candidate)
                let removed = try await session.cache.unpin(candidate, recursive: false)
                result.blocks += removed.blocks
                result.cachedBytes = (result.cachedBytes ?? 0) + (removed.cachedBytes ?? 0)
                result.totalBytes = (result.totalBytes ?? 0) + (removed.totalBytes ?? 0)
                leavePinGate(p.filespace, candidate)
            } catch { leavePinGate(p.filespace, candidate); throw error }
        }
        return result
    }

    private func pinStatus(_ filespace: FilespaceID, path: String, intent: EnginePinIntent) async throws -> PinState {
        let cache = try require(filespace).cache
        var status = try await cache.pinList(filespace: filespace).first { $0.path == path }
            ?? PinState(path: path, pinned: true, recursive: intent.recursive, blocks: 0,
                        cachedBytes: 0, totalBytes: nil, cacheState: .pinning)
        if pinSessions[filespace]?.preparing.contains(path) == true || intent.failureReason != nil {
            status.cacheState = .pinning
        }
        status.failureReason = intent.failureReason
        status.offlineExpiresAt = intent.offlineExpiresAt
        status.offlineReady = (intent.offlineExpiresAt ?? .distantPast) > Date() && FileManager.default.fileExists(atPath: OfflineCheckpoint.url(directory: stableStateDirectory(filespace), path: path).path)
        status.offlineFailureReason = intent.offlineFailureReason
        return status
    }
    public func pinList(_ p: FilespaceOnlyParams) async throws -> [PinState] {
        if pinSessions[p.filespace] == nil { try await restorePinIntents(p.filespace) }
        let cached = try await require(p.filespace).cache.pinList(filespace: p.filespace)
        var result = Dictionary(uniqueKeysWithValues: cached.map { ($0.path, $0) })
        for intent in pinSessions[p.filespace]?.intents.values.sorted(by: { $0.path < $1.path }) ?? [] {
            result[intent.path] = try await pinStatus(p.filespace, path: intent.path, intent: intent)
        }
        return result.values.sorted { $0.path < $1.path }
    }

    private struct PinFile: Sendable { let id: InodeID; let resolved: ResolvedBlockManifest }
    private func pinMembership(_ filespace: FilespaceID, intent: EnginePinIntent) async throws -> (files: [PinFile], items: [ItemMetadata], roots: [FilespaceMountRoot]) {
        var stack: [InodeID]
        if let inode = intent.inode { stack = [InodeID(inode)] }
        else { stack = try await pinMountRoots(filespace).map { InodeID($0.id) } }
        let rootIDs = Set(stack)
        var capturedItems: [ItemMetadata] = []
        var listedMetadata: [InodeID: ItemMetadata] = [:]
        var visited: Set<InodeID> = [], files: [PinFile] = []
        var hashes: Set<BlockHash> = [], expectedBytes = 0
        let cap = Int(Double(try await require(filespace).cache.info(filespace: filespace).maxBytes) * 0.8)
        while let id = stack.popLast() {
            guard isCurrentPin(filespace, intent) else { throw CancellationError() }
            guard visited.insert(id).inserted else { continue }
            let item: ItemMetadata
            do {
                if let listed = listedMetadata.removeValue(forKey: id) { item = listed }
                else { item = try await gateway.getItem(filespace: filespace, id: id) }
            }
            catch let error as EngineError where !rootIDs.contains(id) && (error.kind == .notFound || error.kind == .permissionDenied) { continue }
            capturedItems.append(item)
            guard capturedItems.count <= 100_000 else { throw EngineError(.syncFailed, "Pin subtree exceeds 100,000 items") }
            if item.isDir {
                var cursor: String?, cursors: Set<String> = []
                repeat {
                    let page = try await gateway.listItems(filespace: filespace, parent: id, cursor: cursor)
                    stack.append(contentsOf: page.items.map(\.id))
                    for child in page.items { listedMetadata[child.id] = child }
                    cursor = page.cursor
                    if let cursor, !cursors.insert(cursor).inserted { throw EngineError(.gatewayError, "Folder listing repeated a page") }
                } while cursor != nil
            } else {
                let resolved: ResolvedBlockManifest
                do { resolved = try await gateway.getResolvedBlockManifest(filespace: filespace, itemID: id) }
                catch let error as EngineError where !rootIDs.contains(id) && (error.kind == .notFound || error.kind == .permissionDenied) { continue }
                for ref in resolved.manifest.blocks where hashes.insert(ref.hash).inserted {
                    let (sum, overflow) = expectedBytes.addingReportingOverflow(ref.length)
                    guard !overflow, sum <= cap else {
                        throw EngineError(.conflict, "This pin exceeds 80% of the cache. Increase the cache size or unpin another folder.", data: ["reason": .string("headroom")])
                    }
                    expectedBytes = sum
                }
                files.append(PinFile(id: id, resolved: resolved))
            }
        }
        return (files, capturedItems, capturedItems.filter { rootIDs.contains($0.id) }.map { FilespaceMountRoot(id: $0.id.rawValue, name: $0.name, mountAsRoot: true) })
    }

    private func materializePin(_ filespace: FilespaceID, intent original: EnginePinIntent) async {
        var intent = original
        defer {
            if isCurrentPin(filespace, intent) { pinSessions[filespace]?.jobs[intent.path] = nil }
        }
        do {
            let session = try require(filespace), cache = session.cache, transfer = session.transfer
            let offlineGeneration = metadataGeneration
            let offlineIdentity = await gateway.offlineIdentity(filespace: filespace)
            let before = offlineIdentity == nil ? nil : try? await gateway.changePage(filespace: filespace, since: nil)
            let membership = try await pinMembership(filespace, intent: intent)
            let files = membership.files
            let checkpointURL = OfflineCheckpoint.url(directory: stableStateDirectory(filespace), path: intent.path)
            try? FileManager.default.removeItem(at: checkpointURL)
            pinSessions[filespace]?.intents[intent.path]?.offlineExpiresAt = nil
            var checkpoint: OfflineCheckpoint?
            if let identity = offlineIdentity, let before, let visibility = before.visibility {
                do { checkpoint = try await captureOfflineMetadata(filespace, path: intent.path, identity: identity,
                    items: membership.items, manifests: Dictionary(uniqueKeysWithValues: files.map { ($0.id,$0.resolved.manifest) }),
                    roots: membership.roots, anchor: before.anchor, visibility: visibility) }
                catch { pinSessions[filespace]?.intents[intent.path]?.offlineFailureReason = (error as? EngineError)?.message ?? "Offline preparation failed" }
            }
            var offlineBlocks = checkpoint?.entries.flatMap { entry in entry.streams.values.flatMap { $0.blocks.map { BlockRef(hash: BlockHash(hex: $0.hash), offset: $0.index * ChunkedStreamStore.blockSize, length: $0.length) } } } ?? []
            let displayPath: String
            if let inode = intent.inode {
                displayPath = try await projectedPathForInode(filespace, id: InodeID(inode))
            } else { displayPath = intent.path }
            let oldPath = intent.path
            var gates: [String] = []
            do {
                for path in Set([oldPath, displayPath]).sorted() {
                    try await pinGate(filespace, path); gates.append(path)
                }
                guard isCurrentPin(filespace, intent), let state = pinSessions[filespace] else { throw CancellationError() }
                if let occupied = state.intents[displayPath], occupied.generation != intent.generation {
                    throw EngineError(.conflict, "Another pin already uses the renamed folder's path")
                }
                do {
                    _ = try await cache.replacePinnedPath(displayPath, blocks: files.flatMap { $0.resolved.manifest.blocks } + offlineBlocks,
                                                           recursive: intent.recursive, replacingPath: oldPath)
                } catch let error as EngineError where !offlineBlocks.isEmpty && error.data?["reason"] == .string("headroom") {
                    checkpoint = nil; offlineBlocks = []
                    state.intents[intent.path]?.offlineFailureReason = "Resource forks need more cache space for an offline copy"
                    _ = try await cache.replacePinnedPath(displayPath, blocks: files.flatMap { $0.resolved.manifest.blocks },
                                                           recursive: intent.recursive, replacingPath: oldPath)
                }
                if displayPath != oldPath {
                    state.intents[oldPath] = nil
                    intent.path = displayPath
                    state.intents[displayPath] = intent
                    state.jobs[displayPath] = state.jobs.removeValue(forKey: oldPath)
                }
                state.preparing.remove(oldPath); state.preparing.remove(displayPath)
                state.intents[displayPath]?.failureReason = nil
                try await savePinIntents(filespace)
                for path in gates.reversed() { leavePinGate(filespace, path) }
            } catch {
                for path in gates.reversed() { leavePinGate(filespace, path) }
                throw error
            }
            var offset = 0
            while offset < files.count {
                guard isCurrentPin(filespace, intent) else { throw CancellationError() }
                let batch = files[offset..<min(offset + 4, files.count)]
                try await withThrowingTaskGroup(of: Void.self) { group in
                    for file in batch {
                        group.addTask {
                            try await transfer.ensureBlocks(resolved: file.resolved, filespace: filespace,
                                                            itemID: file.id, offset: 0, length: file.resolved.manifest.size,
                                                            background: true)
                        }
                    }
                    try await group.waitForAll()
                }
                offset += batch.count
            }
            if let checkpoint {
                do {
                    for entry in checkpoint.entries {
                        for (name, stream) in entry.streams where stream.inlineCiphertext == nil {
                            var start = 0
                            while start < stream.size {
                                guard isCurrentPin(filespace, intent), !session.paused else { throw CancellationError() }
                                let length = min(ChunkedStreamStore.maximumRange, stream.size-start)
                                _ = try await session.streams.read(entry.item.id, name: name, offset: start, length: length)
                                start += length
                            }
                        }
                    }
                    var verified = Set<BlockHash>()
                    for ref in files.flatMap({ $0.resolved.manifest.blocks }) + offlineBlocks where verified.insert(ref.hash).inserted {
                        guard try await cache.readBlockForOffline(ref.hash) != nil else { throw EngineError(.syncFailed, "Offline content is incomplete; reconnect to retry") }
                    }
                    let after = try await gateway.changePage(filespace: filespace, since: checkpoint.anchor)
                    guard after.anchor == checkpoint.anchor, after.visibility == checkpoint.visibility,
                          await gateway.offlineIdentity(filespace: filespace) == checkpoint.identity,
                          isCurrentPin(filespace, intent) else { throw EngineError(.conflict, "Files or permissions changed while preparing offline content; retrying") }
                    guard intent.path == checkpoint.path else { throw EngineError(.conflict, "Pin moved while preparing offline content; retrying") }
                    let sealed = try await checkpoint.seal(crypto: session.crypto)
                    guard isCurrentPin(filespace, intent), metadataGeneration == offlineGeneration else { return }
                    try checkpoint.persist(sealed, directory: stableStateDirectory(filespace))
                    pinSessions[filespace]?.intents[intent.path]?.offlineExpiresAt = checkpoint.expiresAt
                    pinSessions[filespace]?.intents[intent.path]?.offlineFailureReason = nil
                } catch {
                    pinSessions[filespace]?.intents[intent.path]?.offlineFailureReason = (error as? EngineError)?.message ?? "Offline content is incomplete; reconnect to retry"
                }
                try? await savePinIntents(filespace)
            }
        } catch is CancellationError { return }
        catch {
            guard isCurrentPin(filespace, intent) else { return }
            if let engineError = error as? EngineError, engineError.kind == .notFound || engineError.kind == .permissionDenied {
                if let cache = try? require(filespace).cache {
                    do {
                        try await pinGate(filespace, intent.path)
                        if isCurrentPin(filespace, intent) {
                            _ = try? await cache.replacePinnedPath(intent.path, blocks: [], recursive: intent.recursive)
                        }
                        leavePinGate(filespace, intent.path)
                    } catch { return }
                }
            }
            pinSessions[filespace]?.intents[intent.path]?.failureReason = (error as? EngineError)?.message ?? error.localizedDescription
            try? await savePinIntents(filespace)
        }
    }
}
