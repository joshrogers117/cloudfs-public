// SPDX-License-Identifier: AGPL-3.0-or-later
// cloudfsd — the `EngineDataPath` adapter (wave-2b, owner: CORE).
//
// What a `MountBackend` (SMB / appex / FSKit) calls per VFS op (CONTROL-API.md
// §7). One adapter is bound to one filespace; it routes:
//   • lookup / enumerate / enumerateChanges  → GatewayClient metadata.
//   • readContents / readRange               → TransferEngine.ensureRange (download
//        miss = presign → range-GET → decrypt → cache), then assemble plaintext
//        from the cache and hand back a temp-file `CacheFileRef`.
//   • write                                  → TransferEngine.stageWrite (ack-local;
//        the encrypt-upload runs OFF this call so the VFS callback never blocks on
//        the network — DESIGN.md §1.2 "writes ack-local, never block a callback").
//   • requestDownload / evict / setContentPolicy → prefetch / cache evict / pin.
//
// readRange snaps `[offset,length)` out to 1 MiB block boundaries (one block is the
// minimum honest unit — a GCM tag covers a whole block) and returns the snapped
// `retrievedRange`.

import Foundation
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSTransfer
import CloudFSGateway

private protocol ReadRangeWriter: Sendable {
    func write(_ data: Data) throws
    func close()
    func discard()
}

/// A single read owns this sink; at most two aligned blocks fit a 1 MiB request.
private final class MemoryReadWriter: ReadRangeWriter, @unchecked Sendable {
    private(set) var bytes = Data()
    let limit: Int
    init(limit: Int) { self.limit = limit }
    func write(_ data: Data) throws {
        guard data.count <= limit - bytes.count else { throw EngineError(.syncFailed, "Read assembly exceeds its bounded buffer") }
        bytes.append(data)
    }
    func close() {}
    func discard() { bytes.removeAll() }
}

/// Each outstanding read owns a distinct 0600 file until its consumer unlinks it.
/// Exclusive/no-follow creation prevents readers from truncating another request
/// or following an unexpected symlink in the private spill directory.
private struct SpillWriter: ReadRangeWriter {
    let path: String
    private let handle: Foundation.FileHandle

    init(url: URL) throws {
        self.path = url.path
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw EngineError(.internal, "Cannot create a private read buffer (errno \(errno))") }
        self.handle = Foundation.FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    }
    func write(_ data: Data) throws { try handle.write(contentsOf: data) }
    func close() { try? handle.close() }
    func discard() { close(); try? FileManager.default.removeItem(atPath: path) }
}

struct EngineDataPathAdapter: EngineDataPath {
    let filespace: FilespaceID
    let engine: CloudFSEngine
    private static let logReads = ProcessInfo.processInfo.environment["CLOUDFS_LOG_READS"] != nil

    /// Audit B15: transient decrypted plaintext spills under the CACHE-ROOT-owned 0700 dir (not /tmp).
    var plaintextSpillDir: String { engine.plaintextSpillDir().path }

    // MARK: metadata (gateway) -------------------------------------------

    func beginOpen(_ id: InodeID, handle: String, access: OpenFileAccess, sharing: OpenFileSharing) async throws {
        try await engine.beginOpen(filespace:filespace,id:id,handle:handle,access:access,sharing:sharing)
    }
    func beginStreamOpen(_ id: InodeID, handle: String, access: OpenFileAccess,
                         sharing: OpenFileSharing, name: String, required: Bool) async throws -> Int? {
        try await engine.beginStreamOpen(filespace:filespace,id:id,handle:handle,access:access,
            sharing:sharing,name:name,required:required)
    }
    func directorySnapshot(_ id: InodeID, handle: String, access: OpenFileAccess,
                           sharing: OpenFileSharing) async throws -> DirectorySnapshot? {
        let gateway = await engine.sessionGateway()
        guard gateway.supportsOpenHandles else { return nil }
        guard let snapshot = try await gateway.directorySnapshot(filespace: filespace, id: id, handle: handle,
                                                                 access: access, sharing: sharing) else { return nil }
        let directory = try await enriched(overlayStagedSize(snapshot.directory))
        var items: [ItemMetadata] = []
        items.reserveCapacity(snapshot.items.count)
        for item in snapshot.items { items.append(try await enriched(overlayStagedSize(item))) }
        return DirectorySnapshot(directory: directory, items: items)
    }
    func endOpen(_ id: InodeID, handle: String) async {
        await engine.endOpen(filespace:filespace,id:id,handle:handle)
    }
    func beginWrite(_ id: InodeID, handle: String) async throws {
        try await engine.beginWrite(filespace: filespace, id: id, handle: handle)
    }
    func beginWriteSnapshot(_ id: InodeID, handle: String) async throws -> ItemMetadata? {
        guard let snapshot = try await engine.beginWriteSnapshot(filespace: filespace, id: id, handle: handle) else {
            return nil
        }
        return try await enriched(overlayStagedSize(snapshot))
    }
    func endWrite(_ id: InodeID, handle: String) async {
        await engine.endWrite(filespace: filespace, id: id, handle: handle)
    }
    func acquireRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {
        try await engine.rangeLockCoordinator(filespace).acquire(id,handle:handle,ranges:ranges)
    }
    func releaseRanges(_ id: InodeID, handle: String, ranges: [FileLockRange]) async throws {
        try await engine.rangeLockCoordinator(filespace).release(id,handle:handle,ranges:ranges)
    }
    func releaseAllRanges(_ id: InodeID, handle: String) async {
        guard let coordinator = try? await engine.rangeLockCoordinator(filespace) else { return }
        await coordinator.releaseAll(id,handle:handle)
    }
    func checkRangeAccess(_ id: InodeID, handle: String, offset: UInt64, length: UInt64, write: Bool) async throws {
        try await engine.checkRangeAccess(filespace:filespace,id:id,handle:handle,offset:offset,length:length,write:write)
    }
    func authorizeWrite(_ id: InodeID, refresh: Bool) async throws {
        try await engine.authorizeWrite(filespace: filespace, id: id, refresh: refresh)
    }

    func lookup(_ id: InodeID) async throws -> ItemMetadata {
        let meta = try await engine.sessionGateway().getItem(filespace: filespace, id: id)
        return try await enriched(overlayStagedSize(meta))
    }

    func enumerate(container: InodeID, page: String?) async throws
        -> (items: [ItemMetadata], nextPage: String?) {
        let (items, cursor) = try await engine.sessionGateway()
            .listItems(filespace: filespace, parent: container, cursor: page)
        var out: [ItemMetadata] = []
        out.reserveCapacity(items.count)
        for m in items { out.append(try await enriched(overlayStagedSize(m))) }
        engine.directoryPrefetch.listing(filespace: filespace,parent: container,items: out,firstPage: page == nil)
        return (out, cursor)
    }

    /// Read-your-own-writes for METADATA (M4 fix): while an item has dirty staged
    /// blocks, the gateway still reports the pre-commit size — a `stat` right after
    /// a write would show the OLD length (a fresh 65 MB copy listed as 0 bytes until
    /// its async upload committed). Overlay the STAGED logical size, exactly like
    /// the read path overlays staged bytes.
    private func overlayStagedSize(_ meta: ItemMetadata) async -> ItemMetadata {
        guard !meta.isDir,
              let (_, transfer, _) = try? await engine.sessionFor(filespace),
              let staged = await transfer.stagedState(filespace: filespace, itemID: meta.id)
        else { return meta }
        return ItemMetadata(id: meta.id, parent: meta.parent, name: meta.name, isDir: false,
                            size: staged.size, contentVersion: meta.contentVersion,
                            metadataVersion: meta.metadataVersion, createdAt: meta.createdAt, modifiedAt: meta.modifiedAt, accessedAt: meta.accessedAt, changedAt: meta.changedAt, fileAttributes: meta.fileAttributes,
                            rsrcForkSize: meta.rsrcForkSize, finderInfo: meta.finderInfo, finderInfoCiphertext: meta.finderInfoCiphertext)
    }

    private func enriched(_ meta: ItemMetadata) async throws -> ItemMetadata {
        guard meta.finderInfoCiphertext != nil else { return meta }
        let (_, _, crypto) = try await engine.sessionFor(filespace)
        return try await decryptMacMetadata(meta, crypto: crypto)
    }

    func changeGeneration() async -> UInt64 { await engine.changeGeneration(filespace) }
    func waitForChanges(after: UInt64) async -> UInt64 { await engine.waitForChanges(filespace, after: after) }
    func notificationCheckpoint(container: InodeID) async throws -> String {
        try await engine.sessionGateway().changeCheckpoint(filespace: filespace).token
    }

    func enumerateChanges(container: InodeID, anchor: String) async throws
        -> (updated: [ItemMetadata], deleted: [InodeID], newAnchor: String, moreComing: Bool) {
        let since = Int(anchor)
        // Audit (tombstone projection): the change feed carries deletions as Items
        // with `deleted:true`. Previously the adapter dropped that flag and returned
        // EVERY change in `updated` — so a consumer resurrected every deleted item and
        // deletions never propagated. Split tombstones into `deleted` properly.
        let (newAnchor, updated, deleted, cursor) = try await engine.sessionGateway()
            .changesWithDeletions(filespace: filespace, since: since)
        // `anchor` is the server's global high-water sequence, while `cursor`
        // is the last row in this page. Advancing to the high-water mark before
        // the final page would permanently skip later updates and tombstones,
        // including when permission filtering leaves the current page empty.
        return (updated, deleted, String(cursor ?? newAnchor), cursor != nil)
    }

    // MARK: read (transfer → cache → decrypt → temp file) ----------------

    func readContents(_ id: InodeID, version: String) async throws -> CacheFileRef {
        // P4 — size the whole-file read from the (cached) resolved manifest rather
        // than a dedicated getItem round-trip: the manifest's Σ block length IS the
        // content size, and `readRange` reuses this same cached manifest, so a
        // readContents costs ONE manifest resolve total.
        let resolved = try await engine.resolvedManifest(filespace: filespace, itemID: id,
                                                         contentVersion: version)
        let (ref, _) = try await readRange(id, version: version, offset: 0,
                                           length: max(resolved.manifest.size, 1), alignment: engine.dataBlockSize)
        return ref
    }

    func readBytes(_ id: InodeID, version: String, offset: Int, length: Int) async throws -> Data {
        guard offset >= 0, length >= 0, length <= 1 << 20, offset <= Int.max - length else {
            throw EngineError(.invalidParams, "Invalid in-process read extent")
        }
        if length == 0 { return Data() }
        let writer = MemoryReadWriter(limit: (1 << 20) + engine.dataBlockSize)
        let range = try await assembleRange(id, version: version, offset: offset, length: length,
                                             alignment: 0, writer: writer)
        let inner = offset - range.offset
        guard inner >= 0, inner <= writer.bytes.count else { throw EngineError(.syncFailed, "Invalid read assembly extent") }
        let count = min(length, writer.bytes.count - inner)
        return writer.bytes.subdata(in: inner..<(inner + count))
    }

    func readRange(_ id: InodeID, version: String, offset: Int, length: Int,
                   alignment: Int) async throws -> (ref: CacheFileRef, retrievedRange: (offset: Int, length: Int)) {
        let writer = try SpillWriter(url: spillFileURL(itemID: id, offset: offset, length: length))
        do {
            let range = try await assembleRange(id, version: version, offset: offset, length: length,
                                                 alignment: alignment, writer: writer)
            return (CacheFileRef(fd: nil, path: writer.path), range)
        } catch { writer.discard(); throw error }
    }

    private func assembleRange(_ id: InodeID, version: String, offset: Int, length: Int,
                               alignment: Int, writer: any ReadRangeWriter) async throws -> (offset: Int, length: Int) {
        let (cache, transfer, _) = try await engine.sessionFor(filespace)
        let blk = alignment > 0 ? alignment : engine.dataBlockSize
        // Validate rounding too: a legal offset+length can still overflow when
        // snapping its final byte to the next block boundary.
        guard offset >= 0, length >= 0, blk > 0 else { throw EngineError(.invalidParams, "Invalid read extent") }
        let end = offset.addingReportingOverflow(max(length, 1))
        let rounded = end.partialValue.addingReportingOverflow(blk - 1)
        guard !end.overflow, !rounded.overflow else { throw EngineError(.invalidParams, "Read extent overflows alignment") }
        let snappedOffset = (offset / blk) * blk
        let snappedEnd = (rounded.partialValue / blk) * blk
        let snappedLength = snappedEnd - snappedOffset

        // DEV/SMOKE observability: log each mount-driven range so the smoke can show
        // byte-range streaming (a tail read fetches only its blocks, not the whole
        // file). Off unless CLOUDFS_LOG_READS is set.
        if Self.logReads {
            FileHandleText.err("cloudfsd[read]: item=\(id.rawValue) req[\(offset),\(length)] -> snapped[\(snappedOffset),\(snappedLength)]")
        }

        // Audit B3 (read-your-own-writes): if this item has dirty blocks staged but
        // not yet uploaded, the committed manifest is STALE for those blocks. Assemble
        // the range per block: dirty image (zero-padded) → else committed block → else
        // zeros (a write-beyond-EOF hole). P0: the overlay is block-granular — a 1 MiB
        // dirty write on a 50 GB file overlays ONE block, not a whole-file image.
        if let staged = await transfer.stagedState(filespace: filespace, itemID: id) {
            engine.readAhead.cancel(filespace: filespace, itemID: id)
            do {
                let written = try await assembleStagedRange(staged, into: writer, id: id, version: version,
                                                            snappedOffset: snappedOffset,
                                                            snappedEnd: snappedEnd, blockSize: blk)
                writer.close()
                return (snappedOffset, written)
            } catch { writer.discard(); throw error }
        }

        let gateway = await engine.sessionGateway()
        if gateway.supportsManifestRanges {
            return try await assembleDemandRange(id, version: version, offset: offset, length: length,
                snappedOffset: snappedOffset, snappedEnd: snappedEnd, writer: writer, gateway: gateway, cache: cache, transfer: transfer)
        }

        do {
            // P4 — assemble the plaintext from the resolved manifest served by the
            // engine's actor-isolated per-(item, contentVersion) cache, eliminating the
            // REDUNDANT second `getBlockManifest` round-trip this call used to make on
            // every read.
            let resolved = try await engine.resolvedManifest(filespace: filespace, itemID: id,
                                                             contentVersion: version)
            let manifest = resolved.manifest
            // Observe direction before demand so a seek cancels obsolete work.
            // Completion schedules optional warming only AFTER requested bytes
            // have been authenticated and handed to the assembly sink.
            let readAheadTicket = engine.readAhead.observe(
                key: .init(filespace: filespace, itemID: id, version: version),
                offset: offset, length: length, fileSize: manifest.size, blockSize: engine.dataBlockSize)
            // Every tracked request retires, even if transfer/assembly throws or
            // its caller cancels. Successful completion below retires it first.
            defer { engine.readAhead.demandEnded(readAheadTicket) }

            // Associate this item's path with its block hashes so a later pin(path)/
            // evict(path) resolves them (the read just made (some of) them resident).
            try await cache.registerManifest(id.rawValue, manifest: manifest)

            // Measure verified byte delivery, excluding manifest registration.
            // Sustained streaming over a slow transport can justify a wider
            // bounded prediction; local cache hits keep the smaller window.
            let demandedBytesStarted = DispatchTime.now().uptimeNanoseconds
            // The blocks intersecting the snapped range, in offset order.
            let intersecting = manifest.blocks.enumerated().filter { (_, ref) in
                ref.offset < snappedEnd && ref.offset + ref.length > snappedOffset
            }
            var written = 0
            // P1: make residency WINDOWED — ensureRange a bounded run of blocks
            // (parallel fetch inside), append them, advance. A single up-front
            // ensureRange of a range far larger than the cache budget would evict
            // its own head while fetching its tail (fetch/evict thrash).
            var w = 0
            while w < intersecting.count {
                let window = Array(intersecting[w..<min(w + Self.assemblyWindowBlocks, intersecting.count)])
                let lo = window.first!.element.offset
                let hi = window.last!.element.offset + window.last!.element.length
                // Make the window resident (cache HIT serves; MISS downloads + decrypts-
                // verify). P2: pass the manifest we already hold — zero gateway cost.
                try await transfer.ensureBlocks(resolved: resolved, filespace: filespace,
                                                itemID: id, offset: lo, length: hi - lo)
                for (i, ref) in window {
                    // Audit B3 (silent corruption): a missing mid-range block must NOT be
                    // skipped — skipping shifted every later block's bytes down to fill the
                    // gap while still reporting the full length, so the app got data from the
                    // wrong offset (Resolve plays garbage frames). A block can vanish between
                    // ensureRange and assembly if the cache evicted it under budget pressure
                    // (enforceBudget runs after every admission). Treat it as a HARD MISS:
                    // re-fetch the exact block (bounded), and fail with EIO if it still can't
                    // be made resident, rather than serving shifted bytes.
                    let plaintext = try await transfer.plaintextBlock(ref, resolved: resolved, blockIndex: i,
                                                                       filespace: filespace, itemID: id)
                    try writer.write(plaintext)
                    written += plaintext.count
                }
                w += Self.assemblyWindowBlocks
            }
            writer.close()
            let fs = filespace // the optional task must not retain its owning engine
            let demandedBytesElapsed = DispatchTime.now().uptimeNanoseconds - demandedBytesStarted
            engine.readAhead.demandCompleted(readAheadTicket, elapsedNanoseconds: demandedBytesElapsed, progressOperation: { window, progress in
                try await transfer.ensureBlocks(resolved: resolved, filespace: fs, itemID: id,
                                                offset: window.offset, length: window.length, priority: .speculative,
                                                authorizationLookAheadBlocks: 32, progress: { progress($0) })
            })
            return (snappedOffset, written)
        } catch { writer.discard(); throw error }
    }

    /// Preserve enough independent demand to fill high-latency connections.
    /// The disk cache and authenticated handoff each enforce their own bounds;
    /// assembly revalidates disk hits when another reader evicted a handoff entry.
    static let assemblyWindowBlocks = 32

    private func assembleDemandRange(_ id: InodeID, version: String, offset: Int, length: Int,
        snappedOffset: Int, snappedEnd: Int, writer: any ReadRangeWriter, gateway: any GatewayClient,
        cache: any BlockCache, transfer: RealTransferEngine) async throws -> (offset: Int, length: Int) {
        do {
            let ranges = engine.manifestRanges, fs = filespace
            var page = try await ranges.get(gateway: gateway, filespace: fs, itemID: id, version: version, offset: snappedOffset, refreshStaleVersion: true)
            let currentVersion = page.item.contentVersion, fileSize = page.item.size
            let ticket = engine.readAhead.observe(key: .init(filespace: fs, itemID: id, version: currentVersion),
                offset: offset, length: length, fileSize: fileSize, blockSize: engine.dataBlockSize)
            defer { engine.readAhead.demandEnded(ticket) }
            let started = DispatchTime.now().uptimeNanoseconds
            let end = min(snappedEnd,fileSize)
            var cursor = snappedOffset
            while cursor < end {
                guard page.item.contentVersion == currentVersion, page.item.size == fileSize, page.start <= cursor, page.end > cursor else {
                    throw EngineError(.conflict, "File changed during the read; retry")
                }
                let selected = page.resolved.manifest.blocks.enumerated().filter { $0.element.offset < end && $0.element.offset+$0.element.length > cursor }
                var w = 0
                while w < selected.count {
                    let batch = Array(selected[w..<min(w+Self.assemblyWindowBlocks,selected.count)])
                    let hi = min(end,batch.last!.element.offset+batch.last!.element.length)
                    try await transfer.ensureBlocks(resolved: page.resolved, filespace: fs, itemID: id, offset: cursor, length: hi-cursor)
                    for (localIndex,ref) in batch {
                        let bytes = try await transfer.plaintextBlock(ref,resolved: page.resolved,blockIndex: page.resolved.firstBlockIndex+localIndex,filespace: fs,itemID: id)
                        let lo = max(cursor,ref.offset), high = min(end,ref.offset+ref.length)
                        guard lo == cursor else { throw EngineError(.syncFailed, "Missing file extent") }
                        try writer.write(bytes[(lo-ref.offset)..<(high-ref.offset)])
                        cursor = high
                    }
                    try await cache.registerPath(id.rawValue, blocks: batch.map { $0.element.hash })
                    w += Self.assemblyWindowBlocks
                }
                if cursor < end { page = try await ranges.get(gateway: gateway,filespace: fs,itemID: id,version: currentVersion,offset: cursor) }
            }
            writer.close()
            engine.readAhead.demandCompleted(ticket, elapsedNanoseconds: DispatchTime.now().uptimeNanoseconds-started, progressOperation: { window, progress in
                var next = window.offset, completed = 0
                let stop = min(fileSize,window.end)
                while next < stop {
                    try Task.checkCancellation()
                    let slice = try await ranges.get(gateway: gateway,filespace: fs,itemID: id,version: currentVersion,offset: next)
                    let high = min(stop,slice.end)
                    guard high > next else { throw EngineError(.syncFailed, "Incomplete prefetch extent") }
                    let previous = completed
                    try await transfer.ensureBlocks(resolved: slice.resolved,filespace: fs,itemID: id,offset: next,length: high-next,
                        priority: .speculative,authorizationLookAheadBlocks: 32,progress: { progress(previous+$0) })
                    completed += high-next; progress(completed); next = high
                }
            })
            if end > snappedOffset { scheduleDirectoryPrefetch(id,version: currentVersion) }
            return (snappedOffset,max(0,end-snappedOffset))
        } catch { writer.discard(); throw error }
    }

    private func scheduleDirectoryPrefetch(_ id: InodeID, version: String) {
        let fs = filespace
        engine.directoryPrefetch.readCompleted(filespace: fs,itemID: id,version: version,blockSize: engine.dataBlockSize) { [weak engine] item, bytes in
            guard let engine else { return }
            let gateway = await engine.sessionGateway()
            guard gateway.supportsManifestRanges else { return }
            let (_,transfer,_) = try await engine.sessionFor(fs)
            guard await transfer.stagedState(filespace: fs,itemID: item.id) == nil else { return }
            let slice = try await engine.manifestRanges.get(gateway: gateway,filespace: fs,itemID: item.id,version: item.contentVersion,offset: 0)
            let refs = slice.resolved.manifest.blocks.filter { $0.offset < bytes }
            // A legacy layout may have larger blocks than the reserved budget.
            guard !refs.isEmpty, refs.reduce(0, { $0+$1.length }) <= bytes else { return }
            try Task.checkCancellation()
            try await transfer.ensureBlocks(resolved: slice.resolved,filespace: fs,itemID: item.id,offset: 0,length: min(bytes,slice.end),priority: .speculative)
        }
    }

    /// Assemble `[snappedOffset, snappedEnd)` for an item with staged dirty blocks
    /// (read-your-own-writes, audit B3 / P0), STREAMING each block into `writer`
    /// (P1: one block in memory at a time). Per block index: the dirty image (paged
    /// from the journal, zero-padded to the block's logical extent) → else the
    /// committed manifest's block (fetched block-granularly; only when the overlay
    /// merges committed content) → else zeros. Never materializes anything outside
    /// the asked range. Returns the bytes written.
    private func assembleStagedRange(_ staged: StagedState, into writer: any ReadRangeWriter,
                                     id: InodeID, version: String,
                                     snappedOffset: Int, snappedEnd: Int, blockSize blk: Int) async throws -> Int {
        let (_, transfer, _) = try await engine.sessionFor(filespace)
        let size = staged.size
        var written = 0
        // The committed manifest is resolved LAZILY — only if some block in the range
        // is non-dirty and the overlay merges committed content. A brand-new file
        // (no committed manifest) must read back from its staging alone.
        var baseByOffset: [Int: BlockRef]? = nil
        var resolvedBase: ResolvedBlockManifest? = nil

        var i = snappedOffset / blk
        while i * blk < min(snappedEnd, size) {
            let bStart = i * blk
            let expectedLen = min(blk, size - bStart)
            if staged.dirtyLengths[i] != nil {
                guard var img = try await transfer.stagedBlock(filespace: filespace, itemID: id, blockIndex: i) else {
                    throw EngineError(.syncFailed, "Staged file changed while reading; retry the read")
                }
                if img.count < expectedLen { img.append(Data(repeating: 0, count: expectedLen - img.count)) }
                try writer.write(img.prefix(expectedLen))
                written += expectedLen
            } else if staged.mergesCommitted {
                if baseByOffset == nil {
                    guard staged.baseCaptured else {
                        throw EngineError(.syncFailed, "The original file image is unavailable; retained edits cannot safely be merged")
                    }
                    resolvedBase = staged.originalBase
                    baseByOffset = Dictionary(uniqueKeysWithValues: (staged.originalBase?.manifest.blocks ?? []).map { ($0.offset, $0) })
                }
                // P4: a truncate kills committed bytes beyond its boundary — trim the
                // merged block to the ALIVE extent (zeros past it), never resurrect.
                let usable = baseByOffset?[bStart].map { max(0, min($0.length, staged.committedLimit - bStart)) } ?? 0
                if usable > 0, let ref = baseByOffset?[bStart], let base = resolvedBase {
                    try await transfer.ensureBlocks(resolved: base, filespace: filespace,
                                                    itemID: id, offset: ref.offset, length: ref.length)
                    var pt = Data(try await transfer.plaintextBlock(ref, resolved: base, blockIndex: i,
                                                                    filespace: filespace, itemID: id).prefix(usable))
                    if pt.count < expectedLen { pt.append(Data(repeating: 0, count: expectedLen - pt.count)) }
                    try writer.write(pt.prefix(expectedLen))
                    written += expectedLen
                } else {
                    try writer.write(Data(repeating: 0, count: expectedLen))
                    written += expectedLen
                }
            } else {
                try writer.write(Data(repeating: 0, count: expectedLen))   // replace-hole → zeros
                written += expectedLen
            }
            i += 1
        }
        return written
    }

    /// A unique path belongs to one outstanding read. Its consumer removes it
    /// after copying; failure paths remove it before returning an error.
    private func spillFileURL(itemID: InodeID, offset: Int, length: Int) -> URL {
        URL(fileURLWithPath: plaintextSpillDir).appendingPathComponent("cloudfsd-read-\(UUID().uuidString)")
    }

    // MARK: write (stage, ack-local; upload runs off this call) ----------

    func write(id: InodeID?, fields: ItemMetadata, contents: CacheFileRef?,
               baseVersion: String?) async throws -> ItemMetadata {
        let (_, transfer, _) = try await engine.sessionFor(filespace)

        // Audit B1: a NEW item (id == nil — create/mkdir through the mount) MUST be
        // created in the backend namespace FIRST. Previously this minted a local-only
        // inode whose id ("/render.dat") never matched the backend's path scheme
        // ("root/render.dat"), so the later commit 403'd/500'd and the editor's bytes
        // were silently lost. We adopt the gateway-returned id ("root/…") as the
        // inode id used for staging + ENCRYPTION (the GCM key/nonce is HKDF-bound to
        // the itemID — a wrong id makes blocks undecryptable by other clients) + the
        // manifest commit.
        let item: ItemMetadata
        if id == nil {
            guard let parent = fields.parent else {
                throw EngineError(.invalidParams, "create requires a parent")
            }
            item = try await engine.sessionGateway().createItem(
                filespace: filespace, parent: parent, name: fields.name,
                isDir: fields.isDir, size: fields.size)
        } else {
            item = ItemMetadata(id: id!, parent: fields.parent, name: fields.name,
                                isDir: fields.isDir, size: fields.size,
                                contentVersion: fields.contentVersion,
                                metadataVersion: fields.metadataVersion)
        }

        if let contents {
            try await authorizeWrite(item.id, refresh: false)
            // `write(contents:)` is a WHOLE-FILE REPLACE: the file's entire new
            // content (may shrink). P1: STREAMED from the hand-off file in block-size
            // chunks — never `Data(contentsOf:)` (a 20 GB save must not be 20 GB of
            // RAM). Encrypt-upload is async. Thread the base INTEGER version
            // (Item.version, carried in metadataVersion) so the async commit can CAS
            // (audit B4) — the gateway compares it against the stored version and
            // 409s a concurrent save. A brand-new create has no base (the item we
            // just minted is version 1; an immediate first commit bumps to 2), so we
            // pass the created item's metadataVersion. The id is the
            // gateway-authoritative one, so encryption + commit are coherent.
            let base = baseVersion ?? item.metadataVersion
            let handle = UUID().uuidString
            try await beginWrite(item.id, handle: handle)
            do {
                let fence = try await engine.writeFence(filespace: filespace, id: item.id)
                try await transfer.stageReplace(filespace: filespace, itemID: item.id,
                                                contents: contents, baseVersion: base, fence: fence)
                await endWrite(item.id, handle: handle)
            } catch { await endWrite(item.id, handle: handle); throw error }
        }
        return item
    }

    /// P0 — block-aligned dirty-block write (the mount's hot write path). Stages only
    /// the touched blocks (boundary blocks RMW-seeded block-granularly in the transfer
    /// engine); the async uploader PUTs the dirty blocks and commits a manifest that
    /// reuses every unchanged committed ref. Returns the staged logical size.
    func writeRange(_ id: InodeID, offset: Int, data: Data, baseVersion: String?) async throws -> Int {
        try await authorizeWrite(id, refresh: false)
        let (_, transfer, _) = try await engine.sessionFor(filespace)
        let handle = UUID().uuidString
        try await beginWrite(id, handle: handle)
        do {
            let fence = try await engine.writeFence(filespace: filespace, id: id)
            let size = try await transfer.stageWrite(filespace: filespace, itemID: id, offset: offset,
                                                     data: data, baseVersion: baseVersion, fence: fence)
            await endWrite(id, handle: handle)
            return size
        } catch { await endWrite(id, handle: handle); throw error }
    }

    /// P4 — truncate (O_TRUNC / ftruncate): ack-local staging like writes; the async
    /// commit reuses committed refs below the boundary and rewrites only the boundary.
    func truncate(_ id: InodeID, newSize: Int, baseVersion: String?) async throws {
        try await authorizeWrite(id, refresh: false)
        let (_, transfer, _) = try await engine.sessionFor(filespace)
        let handle = UUID().uuidString
        try await beginWrite(id, handle: handle)
        do {
            let fence = try await engine.writeFence(filespace: filespace, id: id)
            try await transfer.stageTruncate(filespace: filespace, itemID: id, newSize: newSize,
                                             baseVersion: baseVersion, fence: fence)
            await endWrite(id, handle: handle)
        } catch { await endWrite(id, handle: handle); throw error }
    }

    func delete(_ id: InodeID, baseVersion: String, recursive: Bool) async throws {
        try await delete(id,baseVersion:baseVersion,recursive:recursive,openHandle:nil)
    }
    func delete(_ id: InodeID, baseVersion: String, recursive: Bool, openHandle: String?) async throws {
        // Audit B1: namespace deletes now reach the gateway (DELETE /items/:id). A
        // failure throws (→ EIO in Finder) rather than phantom-acking — never ack a
        // mutation we didn't perform.
        let (_, transfer, _) = try await engine.sessionFor(filespace)
        let gateway = await engine.sessionGateway()
        try await transfer.deleteItem(filespace: filespace, itemID: id) {
            try await gateway.deleteItem(filespace: filespace, id: id, recursive: recursive, openHandle: openHandle)
        }
    }

    func setBasicInfo(_ id: InodeID, info: BasicFileInfo) async throws -> ItemMetadata {
        let (_, transfer, _) = try await engine.sessionFor(filespace)
        let handle = UUID().uuidString
        try await beginWrite(id, handle: handle)
        do {
            let gateway = await engine.sessionGateway()
            let fence = try await engine.writeFence(filespace: filespace, id: id)
            let result = try await transfer.mutateMetadata(filespace: filespace, itemID: id) {
                let current = try await gateway.getItem(filespace: filespace, id: id)
                guard let version = Int(current.metadataVersion) else { throw EngineError(.conflict, "Missing metadata version") }
                let updated = try await gateway.setBasicInfo(filespace: filespace, id: id, info: info, expectedVersion: version, fence: fence)
                return (current, updated)
            }
            await engine.noteCommitted(filespace: filespace, itemID: id, meta: result)
            await endWrite(id, handle: handle)
            return result
        } catch { await endWrite(id, handle: handle); throw error }
    }

    func rename(_ id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata {
        try await rename(id, newParent: newParent, newName: newName, replacing: nil)
    }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String, replacing: ItemMetadata?) async throws -> ItemMetadata {
        try await rename(id,newParent:newParent,newName:newName,replacing:replacing,openHandle:nil)
    }
    func rename(_ id: InodeID, newParent: InodeID?, newName: String, replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata {
        let (_, transfer, _) = try await engine.sessionFor(filespace)
        let gateway = await engine.sessionGateway()
        let result = try await transfer.mutateMetadata(filespace: filespace, itemID: id, replacingID: replacing?.id) {
            // These reads happen only after mutateMetadata has drained and gated
            // both inodes. They are independent version checks for one atomic
            // compare-and-swap, so overlap the network round trips while retaining
            // the exact post-drain metadata used by the remote rename.
            let current: ItemMetadata
            let target: ItemMetadata?
            if let replacing {
                async let sourceRead = gateway.getItem(filespace: filespace, id: id)
                async let targetRead = gateway.getItem(filespace: filespace, id: replacing.id)
                (current, target) = try await (sourceRead, targetRead)
            } else {
                current = try await gateway.getItem(filespace: filespace, id: id)
                target = nil
            }
            guard let version = Int(current.metadataVersion) else { throw EngineError(.conflict, "Missing source version") }
            // Draining local target writes may advance its version. `target` above
            // is read after that drain, then CASed with the source in one RPC.
            let moved = try await gateway.renameItem(filespace: filespace, id: id, newParent: newParent,
                newName: newName, expectedVersion: version, replacing: target, openHandle: openHandle)
            return (current, moved)
        }
        await engine.noteCommitted(filespace: filespace, itemID: id, meta: result)
        return result
    }

    // MARK: policy / prefetch / evict ------------------------------------

    func setContentPolicy(_ id: InodeID, policy: ContentPolicy) async throws {
        try await engine.setPinPolicy(filespace: filespace, id: id, policy: policy)
    }

    func requestDownload(_ id: InodeID, range: (offset: Int, length: Int)?) async throws -> PrefetchAck {
        let (_, transfer, _) = try await engine.sessionFor(filespace)
        // P2: a RANGED request fetches exactly its blocks. (The old adapter DROPPED
        // the range and prefetched the whole file — so every read-ahead hint
        // hydrated the entire item and re-hit the gateway for its manifest.)
        if let range {
            let resolved = try await engine.sessionGateway().getResolvedBlockManifest(filespace: filespace, itemID: id)
            try await transfer.ensureBlocks(resolved: resolved, filespace: filespace, itemID: id,
                                            offset: range.offset, length: range.length, background: true)
            let blk = engine.dataBlockSize
            return PrefetchAck(path: id.rawValue,
                               queuedBlocks: (range.length + blk - 1) / blk)
        }
        return try await transfer.prefetch(filespace: filespace, path: id.rawValue, itemID: id)
    }

    func evict(_ id: InodeID) async throws -> EvictAck {
        await engine.readAhead.cancelAndWait(filespace: filespace, itemID: id)
        let (cache, _, _) = try await engine.sessionFor(filespace)
        return try await cache.evict(id.rawValue)
    }

    // MARK: named streams — remote-durable bounded chunk I/O
    func listStreams(_ id: InodeID) async throws -> [StreamInfo] {
        try await engine.sessionGateway().listStreams(filespace: filespace, id: id)
    }
    func readStreamRange(_ id: InodeID, name: String, offset: Int, length: Int) async throws -> Data {
        try await engine.streamStore(filespace).read(id, name: name, offset: offset, length: length)
    }
    func readStream(_ id: InodeID, name: String) async throws -> Data {
        let info = try await listStreams(id).first { $0.name == name }
        guard let info else { throw EngineError(.notFound, "No such stream") }
        guard info.size <= ChunkedStreamStore.maximumRange else { throw EngineError(.invalidParams, "Use ranged I/O for large named streams") }
        return try await readStreamRange(id, name: name, offset: 0, length: info.size)
    }
    func writeStreamRange(_ id: InodeID, name: String, offset: Int, data: Data) async throws -> Int {
        try await authorizeWrite(id, refresh: false)
        let handle = UUID().uuidString
        try await beginWrite(id, handle: handle)
        do {
            let fence = try await engine.writeFence(filespace: filespace, id: id)
            let size = try await engine.streamStore(filespace).write(id, name: name, offset: offset, data: data, fence: fence)
            await endWrite(id, handle: handle); return size
        } catch { await endWrite(id, handle: handle); throw error }
    }
    func writeStream(_ id: InodeID, name: String, data: Data) async throws {
        try await authorizeWrite(id, refresh: false)
        let handle = UUID().uuidString
        try await beginWrite(id, handle: handle)
        do {
            let fence = try await engine.writeFence(filespace: filespace, id: id)
            try await engine.streamStore(filespace).replace(id, name: name, data: data, fence: fence)
            await endWrite(id, handle: handle)
        } catch { await endWrite(id, handle: handle); throw error }
    }
    func truncateStream(_ id: InodeID, name: String, size: Int) async throws {
        try await authorizeWrite(id, refresh: false)
        let handle = UUID().uuidString
        try await beginWrite(id, handle: handle)
        do {
            let fence = try await engine.writeFence(filespace: filespace, id: id)
            try await engine.streamStore(filespace).truncate(id, name: name, size: size, fence: fence)
            await endWrite(id, handle: handle)
        } catch { await endWrite(id, handle: handle); throw error }
    }
    func deleteStream(_ id: InodeID, name: String) async throws {
        try await authorizeWrite(id, refresh: false)
        let handle = UUID().uuidString
        try await beginWrite(id, handle: handle)
        do {
            let fence = try await engine.writeFence(filespace: filespace, id: id)
            try await engine.streamStore(filespace).delete(id, name: name, fence: fence)
            await endWrite(id, handle: handle)
        } catch { await endWrite(id, handle: handle); throw error }
    }
}
