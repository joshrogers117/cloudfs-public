// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCache — DiskBlockCache: the real resizable/relocatable SSD block cache.
// (DESIGN.md §3) Owner: CACHE.
//
// An `actor` so the hot read path is concurrency-safe without a hand-rolled lock,
// while every mutation of the index/store is serialized. Block payloads live as
// content-addressed files under `<cache-dir>/blocks/<hash[:2]>/<hash>`; the index
// (`index.db`) holds len/atime/pin/refcount/path-associations and survives
// restart. Design points implemented here:
//
//  • 1 MiB content-addressed blocks on disk (key == BlockHash.objectKey).
//  • RESIZABLE: setSize enforces a max-bytes budget; shrinking evicts immediately.
//  • RELOCATABLE: setLocation moves blocks/ + index.db to a new dir, preserving
//    contents, then repoints — online, no data loss.
//  • PIN/UNPIN: pinned blocks are never eviction candidates; ~20% non-pinnable
//    headroom guard (a pin that would exceed 80% of maxBytes is rejected).
//  • 2-RANDOM pin-aware eviction when over budget (pick two evictable blocks,
//    drop the older-atime one), gated on usage > ceiling.
//  • INTEGRITY: each block's plaintext is verified against a stored SHA-256 on
//    read; a mismatch (corruption / torn write) evicts the block and reports a
//    miss so the caller re-fetches from R2 (self-healing).
//
// The path<->blocks association pins need is supplied by the engine/transfer
// layer via `register(path:blocks:)` (the protocol is content-addressed only, so
// the cache cannot derive a manifest itself). That entry point is internal; the
// public `BlockCache` protocol signature is unchanged.

import Foundation
import CloudFSCore
import CryptoKit

public actor DiskBlockCache: BlockCache {

    // MARK: Stored state

    private let filespace: FilespaceID
    private var rootDir: URL                 // the (relocatable) cache directory
    private var doc: IndexDocument           // the in-memory authoritative index
    private let blockSize: Int

    /// Rolling hit-rate counters (SPEC §3.7 stat).
    private var hits: Int = 0
    private var misses: Int = 0

    // P2 — coalesced index persistence. Previously `readBlock` (cache HIT),
    // `putBlock`, and `register` each did a synchronous `persist()` — a full
    // JSON re-serialization + atomic rewrite of the WHOLE index.db, O(cache size),
    // on EVERY block op. During Resolve playback `readRange` touches many blocks/sec,
    // so a 50 GB / ~50k-entry cache rewrote the entire index thousands of times a
    // second → crippling local I/O at 20-30 editors.
    //
    // Strategy (no timer/detached task — stays inside the actor's serial isolation):
    // critical, durability-bearing mutations (block ADMIT/EVICT, pin/unpin, resize/
    // relocate, integrity-drop) still flush SYNCHRONOUSLY so a crash never loses
    // admitted-block accounting or thinks an evicted block is resident. The
    // NON-critical atime/LRU bump on a cache HIT (and a redundant `register` that
    // changes nothing) only sets `dirty` and does NOT rewrite the index. Because
    // `persist()` always serializes the WHOLE current `doc` (including the latest
    // atimes), the very next critical op naturally folds the accumulated atime
    // updates into its write — so the LRU clock stays reasonably fresh on disk at
    // zero extra cost, and a pure read burst does no index I/O at all. `flush()`
    // (a clean disconnect/shutdown) drains a trailing `dirty`.
    private var dirty = false
    private var admissionsSinceCheckpoint = 0
    private var registeredManifestVersions: [String: String] = [:]
    // Immutable payload I/O may overlap; index publication stays actor-serial.
    // Relocation drains admitted writes and prevents new writes from choosing the
    // old directory while it copies/checkpoints the cache.
    private var activePayloadWrites = 0
    private(set) var peakPayloadWrites = 0
    private var relocating = false
    private var payloadWaiters: [CheckedContinuation<Void, Never>] = []
    private var relocationWaiters: [CheckedContinuation<Void, Never>] = []
    private var payloadDrain: CheckedContinuation<Void, Never>?

    private func beginPayloadWrite() async {
        while relocating || activePayloadWrites >= 8 {
            await withCheckedContinuation { payloadWaiters.append($0) }
        }
        activePayloadWrites += 1; peakPayloadWrites = max(peakPayloadWrites, activePayloadWrites)
    }
    private func endPayloadWrite() {
        activePayloadWrites -= 1
        if activePayloadWrites == 0 { payloadDrain?.resume(); payloadDrain = nil }
        if !relocating {
            let waiters = payloadWaiters; payloadWaiters.removeAll(); waiters.forEach { $0.resume() }
        }
    }
    private func beginRelocation() async {
        while relocating { await withCheckedContinuation { relocationWaiters.append($0) } }
        relocating = true
        if activePayloadWrites > 0 { await withCheckedContinuation { payloadDrain = $0 } }
    }
    private func endRelocation() {
        relocating = false
        let movers = relocationWaiters; relocationWaiters.removeAll(); movers.forEach { $0.resume() }
        let writers = payloadWaiters; payloadWaiters.removeAll(); writers.forEach { $0.resume() }
    }

    /// Fraction of `maxBytes` reservable as non-pinnable headroom (DESIGN §3.3:
    /// pins capped at 80%). A pin pushing pinnedBytes past this is rejected.
    private let pinnableFraction = 0.80

    private let fm = FileManager.default

    // MARK: Init / open (restart persistence)

    /// Open (or create) a cache rooted at `directory`. If an `index.db` is present
    /// it is loaded so the cache, pins, and the size/location settings survive a
    /// restart; otherwise a fresh index is created with `maxBytes`.
    public init(filespace: FilespaceID, directory: URL, maxBytes: Int,
                blockSize: Int = kDefaultBlockSize) throws {
        self.filespace = filespace
        self.rootDir = directory
        self.blockSize = blockSize
        try Self.ensureLayout(at: directory, fm: FileManager.default)
        if let loaded = BlockIndexStore.load(from: directory), loaded.filespace == filespace {
            self.doc = loaded
            // Consolidate replay, including an interrupted append, before admitting new blocks.
            try BlockIndexStore.save(&self.doc, to: directory)
        } else {
            self.doc = IndexDocument(filespace: filespace, maxBytes: maxBytes)
            try BlockIndexStore.save(&self.doc, to: directory)
        }
    }

    private static func ensureLayout(at dir: URL, fm: FileManager) throws {
        try fm.createDirectory(at: dir.appendingPathComponent("blocks"),
                               withIntermediateDirectories: true)
    }

    // MARK: Paths

    private func blockURL(_ hex: String, in dir: URL) -> URL {
        let shard = hex.count >= 2 ? String(hex.prefix(2)) : "00"
        return dir.appendingPathComponent("blocks/\(shard)/\(hex)")
    }
    private func blockURL(_ hex: String) -> URL { blockURL(hex, in: rootDir) }

    /// Durable, synchronous flush of the whole index to disk. Used by the critical
    /// (durability-bearing) ops; serializing the current `doc` also folds in any
    /// accumulated NON-critical atime updates, so it clears the `dirty` flag too.
    private func persist() throws {
        try BlockIndexStore.save(&doc, to: rootDir)
        dirty = false
        admissionsSinceCheckpoint = 0
    }

    /// Drain a trailing `dirty` (accumulated cache-HIT atime updates) to disk. Call
    /// on a clean disconnect/shutdown so the last LRU updates survive a graceful
    /// stop even when no critical op followed them. Synchronous; no detached task.
    public func flush() {
        guard dirty else { return }
        try? persist()
    }

    private func now() -> Double { Date().timeIntervalSince1970 }

    // MARK: - Block storage (the hot path)

    public func contains(_ hash: BlockHash) -> Bool {
        doc.blocks[hash.hex] != nil
    }

    /// Offline reads cannot heal corruption over the network. Preserve the
    /// distinction between an absent payload and a damaged content address.
    public func readBlockForOffline(_ hash: BlockHash) async throws -> Data? {
        guard doc.blocks[hash.hex] != nil, let bytes = try? Data(contentsOf: blockURL(hash.hex)) else { return nil }
        guard Self.sha256Hex(bytes) == hash.hex else { throw EngineError(.syncFailed, "Offline content checksum mismatch", data: ["reason": .string("offline_corrupt")]) }
        return bytes
    }

    public func readBlock(_ hash: BlockHash) async throws -> Data? {
        guard var entry = doc.blocks[hash.hex] else {
            misses += 1
            return nil
        }
        let url = blockURL(hash.hex)
        guard let data = try? Data(contentsOf: url) else {
            // Index says present but the payload is gone (torn write / external
            // delete): drop the stale entry and report a miss to force re-fetch.
            dropBlock(hash.hex)
            try? persist()
            misses += 1
            return nil
        }
        // INTEGRITY: verify content address. The block id IS SHA-256(plaintext)
        // for the cache's purposes; a mismatch means corruption → evict + miss.
        guard Self.sha256Hex(data) == hash.hex else {
            try? fm.removeItem(at: url)
            dropBlock(hash.hex)
            try? persist()
            misses += 1
            return nil
        }
        entry.lastAccess = now()
        doc.blocks[hash.hex] = entry
        hits += 1
        // P2 — a cache HIT only bumps atime (the LRU clock). That is NON-critical:
        // a restart with a slightly stale atime just reorders eviction candidates,
        // it never corrupts residency. So do NOT rewrite the whole index on every hit
        // (the crippling per-read O(cache size) cost); just mark dirty. The next
        // critical op's `persist()` serializes the current `doc` and folds these
        // atimes in for free; `flush()` drains a trailing burst on a clean stop.
        dirty = true
        return data
    }

    public func putBlock(_ hash: BlockHash, plaintext: Data) async throws {
        await beginPayloadWrite()
        defer { endPayloadWrite() }
        try Task.checkCancellation()
        let url = blockURL(hash.hex)
        // Hashing and atomic, fsync-backed immutable payload publication do not
        // touch actor state. Keep the durable index commit after this completes.
        try await Task.detached(priority: .userInitiated) {
            guard Self.sha256Hex(plaintext) == hash.hex else {
                throw EngineError(.internal, "block hash mismatch on admission for \(hash.hex)")
            }
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try plaintext.write(to: url, options: .atomic)
        }.value

        if var existing = doc.blocks[hash.hex] {
            existing.len = plaintext.count
            existing.lastAccess = now()
            doc.blocks[hash.hex] = existing
        } else {
            // Registration precedes read-ahead admission. Attach known paths now,
            // avoiding another full-index rewrite on each subsequent foreground read.
            let paths = Set(doc.pathBlocks.compactMap { $0.value.contains(hash.hex) ? $0.key : nil })
            let pins = doc.pins.values.filter { $0.blocks.contains(hash.hex) }.count
            doc.blocks[hash.hex] = BlockEntry(len: plaintext.count, lastAccess: now(),
                                              pinnedRefs: pins, paths: paths)
        }
        try BlockIndexStore.appendAdmission(hash: hash.hex, entry: doc.blocks[hash.hex]!, doc: doc, to: rootDir)
        admissionsSinceCheckpoint += 1
        dirty = true
        if admissionsSinceCheckpoint >= 128 { try persist() }
        // Stay under the ceiling after admission.
        try enforceBudget()
    }

    /// Drop a block's payload-bearing index entry and detach it from any paths.
    private func dropBlock(_ hex: String) {
        // A removed path link must be restored if the same manifest is read again.
        registeredManifestVersions.removeAll(keepingCapacity: true)
        doc.blocks.removeValue(forKey: hex)
        for (p, var set) in doc.pathBlocks where set.contains(hex) {
            if doc.pins[p]?.blocks.contains(hex) == true { continue }
            set.remove(hex)
            doc.pathBlocks[p] = set
        }
        // Pin membership survives corruption/missing payloads: status becomes
        // pinning, and re-admission restores the pin instead of silently forgetting it.
    }

    // MARK: - Path <-> block registration (internal; pins need it)

    /// Public seam (BlockCache protocol): associate a path with its block hashes so
    /// a later `pin`/`unpin`/`evict` by that path resolves to those blocks. Thin
    /// async-throws wrapper over the actor-isolated `register(path:blocks:)`.
    /// Content versions identify immutable ordered block maps. Register once per
    /// version, not once per small SMB range; eviction invalidates this fast path.
    public func registerManifest(_ path: String, manifest: BlockManifest) async throws {
        if !manifest.contentVersion.isEmpty, registeredManifestVersions[path] == manifest.contentVersion { return }
        register(path: path, blocks: manifest.blocks.map(\.hash))
        if registeredManifestVersions.count >= 512 { registeredManifestVersions.removeAll(keepingCapacity: true) }
        if !manifest.contentVersion.isEmpty { registeredManifestVersions[path] = manifest.contentVersion }
    }

    public func registerPath(_ path: String, blocks: [BlockHash]) async throws {
        register(path: path, blocks: blocks)
    }

    /// Associate a set of block hashes with a path so `pin`/`unpin`/`evict` can
    /// operate by path. Called by the engine/transfer layer as it materializes a
    /// file's manifest (via the public `registerPath` seam).
    func register(path: String, blocks: [BlockHash]) {
        var set = doc.pathBlocks[path] ?? []
        let pinned = doc.pins[path] != nil
        // P2 — `register`/`registerPath` runs on EVERY readRange and prefetch, so a
        // file read repeatedly re-registers the SAME blocks under the SAME path with
        // NOTHING to change. That used to rewrite the whole index each time. Track
        // whether this call actually mutated state; if not, skip the persist entirely.
        var changed = false
        for h in blocks {
            if !set.contains(h.hex) { changed = true }
            set.insert(h.hex)
            // Finding 2: only bump `pinnedRefs` when this block is NEWLY joining
            // THIS pin's set — mirror the `totalBytes` first-join guard below.
            // Without this, re-registering already-pinned blocks (every readRange /
            // prefetch re-registers) inflated `pinnedRefs` to 2,3,…, so a single
            // `unpin` (which decrements once) left `pinned` true forever and the
            // block could never be evicted → cache could exceed maxBytes.
            let newlyJoiningThisPin = !(doc.pins[path]?.blocks.contains(h.hex) ?? false)
            if pinned, newlyJoiningThisPin, var e = doc.blocks[h.hex], !inAnyOtherPin(h.hex, except: path) {
                // keep pinnedRefs coherent for newly-registered blocks under a pin
                e.pinnedRefs += 1
                doc.blocks[h.hex] = e
                changed = true
            }
            if pinned, var rec = doc.pins[path] {
                // Keep the pin's captured total coherent: count a block's bytes once
                // as it newly joins the pin set (CONTRACTS.md §4.1 totalBytes).
                if !rec.blocks.contains(h.hex) { rec.totalBytes += doc.blocks[h.hex]?.len ?? 0; changed = true }
                rec.blocks.insert(h.hex)
                doc.pins[path] = rec
            }
            if var e = doc.blocks[h.hex], !e.paths.contains(path) {
                e.paths.insert(path); doc.blocks[h.hex] = e; changed = true
            }
        }
        doc.pathBlocks[path] = set
        // P2 — only persist when this registration actually changed durable state
        // (a new path↔block link or a pin's accounting). A redundant re-registration
        // of already-known blocks under the same path is a no-op: skip the rewrite.
        // The pin-coherence mutations above ARE durability-bearing (eviction
        // eligibility), so flush them synchronously when present.
        if changed { try? persist() }
    }

    private func inAnyOtherPin(_ hex: String, except path: String) -> Bool {
        for (p, rec) in doc.pins where p != path { if rec.blocks.contains(hex) { return true } }
        return false
    }

    // MARK: - Info / resize / relocate (the superpower)

    public func info(filespace: FilespaceID) throws -> CacheInfo {
        try requireFilespace(filespace)
        return makeInfo()
    }

    private func makeInfo() -> CacheInfo {
        let used = doc.usedBytes
        let total = hits + misses
        return CacheInfo(
            filespace: filespace,
            location: rootDir.path,
            sizeBytes: used,
            usedBytes: used,
            pinnedBytes: doc.pinnedBytes,
            maxBytes: doc.maxBytes,
            freeOnVolumeBytes: freeOnVolume(),
            hitRate: total == 0 ? 0 : Double(hits) / Double(total)
        )
    }

    public func setSize(filespace: FilespaceID, bytes: Int) async throws -> CacheInfo {
        try requireFilespace(filespace)
        guard bytes >= 0 else { throw EngineError(.invalidParams, "cache size must be >= 0") }
        // A shrink that strands pinned content above the 80% headroom cap is a
        // headroom conflict (CONTROL-API.md §5.3).
        let pinnedCap = Int(Double(bytes) * pinnableFraction)
        if reservedPinBytes(doc.pins) > pinnedCap {
            throw EngineError(.conflict, "pinned bytes exceed 80% of the requested size",
                              data: ["reason": .string("headroom")])
        }
        doc.maxBytes = bytes
        try persist()
        try enforceBudget()      // shrink: evict down to the new ceiling now
        return makeInfo()
    }

    public func setLocation(filespace: FilespaceID, path: String) async throws -> CacheInfo {
        try await setLocation(filespace: filespace, path: path, preserveSource: false)
    }

    /// The engine retains the source until it commits its durable location map.
    /// Standalone callers keep the original move semantics via the overload above.
    public func setLocation(filespace: FilespaceID, path: String, preserveSource: Bool) async throws -> CacheInfo {
        await beginRelocation()
        defer { endRelocation() }
        try Task.checkCancellation()
        try requireFilespace(filespace)
        return try relocate(path: path, preserveSource: preserveSource, allowExistingSource: false)
    }

    public func rollbackRelocation(to path: String) async throws -> CacheInfo {
        await beginRelocation()
        defer { endRelocation() }
        try Task.checkCancellation()
        return try relocate(path: path, preserveSource: false, allowExistingSource: true)
    }

    private func relocate(path: String, preserveSource: Bool, allowExistingSource: Bool) throws -> CacheInfo {
        let expanded = (path as NSString).expandingTildeInPath
        guard expanded.hasPrefix("/") else { throw EngineError(.invalidParams, "Choose an absolute cache folder") }
        let dest = URL(fileURLWithPath: expanded).standardizedFileURL.resolvingSymlinksInPath()
        let old = rootDir.standardizedFileURL.resolvingSymlinksInPath()
        if dest.path == old.path { return makeInfo() }
        guard !dest.path.hasPrefix(old.path + "/"), !old.path.hasPrefix(dest.path + "/") else {
            throw EngineError(.invalidParams, "The new cache folder cannot contain, or be inside, the current cache")
        }
        if fm.fileExists(atPath: dest.path) {
            let entries = try fm.contentsOfDirectory(atPath: dest.path).filter { $0 != ".DS_Store" }
            if !entries.isEmpty {
                guard allowExistingSource, BlockIndexStore.load(from: dest)?.filespace == filespace else {
                    throw EngineError(.conflict, "Choose an empty folder; the destination already contains data")
                }
            }
        }
        // Checkpoint the retained source before copying. A process crash before
        // the engine's map commit must leave a complete, reopenable old cache.
        try persist()
        try Self.ensureLayout(at: dest, fm: fm)
        do {
            for hex in doc.blocks.keys {
                let src = blockURL(hex), dst = blockURL(hex, in: dest)
                guard fm.fileExists(atPath: src.path) else { continue }
                try fm.createDirectory(at: dst.deletingLastPathComponent(), withIntermediateDirectories: true)
                if fm.fileExists(atPath: dst.path) { try fm.removeItem(at: dst) }
                try fm.copyItem(at: src, to: dst)
            }
            // Compatibility only: new engine pin intents and the write journal
            // live in stable per-filespace state, outside the downloaded cache.
            let legacy = old.appendingPathComponent("pin-intents.json")
            if fm.fileExists(atPath: legacy.path) {
                try Data(contentsOf: legacy).write(to: dest.appendingPathComponent("pin-intents.json"), options: .atomic)
            }
            rootDir = dest
            do { try persist() } catch { rootDir = old; throw error }
        } catch {
            // Both the original index and original bytes remain usable. Leave
            // any partial destination for inspection; never erase user folders.
            rootDir = old
            throw error
        }
        if !preserveSource { finishRelocation(from: old.path) }
        return makeInfo()
    }

    /// Only known downloaded-cache artifacts are removed. Pending-write journals
    /// and pin-intents-v2.json intentionally stay in the stable original folder.
    public func finishRelocation(from path: String) {
        let old = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
        guard old.path != rootDir.standardizedFileURL.resolvingSymlinksInPath().path,
              BlockIndexStore.load(from: old)?.filespace == filespace else { return }
        for name in ["blocks", BlockIndexStore.fileName, BlockIndexStore.admissionsName, "pin-intents.json"] {
            try? fm.removeItem(at: old.appendingPathComponent(name))
        }
    }

    public func clear(filespace: FilespaceID) async throws -> CacheInfo {
        try requireFilespace(filespace)
        // Evict everything EVICTABLE (pinned blocks + their pins survive — §3.6).
        for (hex, entry) in doc.blocks where !entry.pinned {
            try? fm.removeItem(at: blockURL(hex))
            dropBlock(hex)
        }
        // Drop non-pinned path associations that no longer reference any block.
        for (p, set) in doc.pathBlocks {
            let live = set.filter { doc.blocks[$0] != nil }
            if live.isEmpty, doc.pins[p] == nil { doc.pathBlocks.removeValue(forKey: p) }
            else { doc.pathBlocks[p] = live }
        }
        try persist()
        return makeInfo()
    }

    // MARK: - Pin / unpin / list / evict

    /// Explicit subtree membership, independent of human paths or opaque inode IDs.
    /// Reserve the complete expected set before download; incoming blocks inherit
    /// these pins, and re-scans replace removed versions without leaking pin refs.
    public func replacePinnedPath(_ path: String, blocks: [BlockRef], recursive: Bool,
                                  replacingPath: String? = nil) async throws -> PinState {
        var lengths: [String: Int] = [:]
        for ref in blocks {
            guard ref.length >= 0, ref.length <= Int.max - 69 else { throw EngineError(.invalidParams, "Invalid pin extent") }
            lengths[ref.hash.hex] = max(lengths[ref.hash.hex] ?? 0, ref.length)
        }
        let (total, overflow) = lengths.values.reduce((0, false)) { partial, length in
            let (sum, overflow) = partial.0.addingReportingOverflow(length)
            return (sum, partial.1 || overflow)
        }
        guard !overflow else { throw EngineError(.invalidParams, "Pin extent is too large") }
        let record = PinRecord(path: path, recursive: recursive, blocks: Set(lengths.keys),
                               totalBytes: total, expectedLengths: lengths)
        var proposed = doc.pins
        if let old = replacingPath, old != path { proposed[old] = nil }
        proposed[path] = record
        let cap = Int(Double(doc.maxBytes) * pinnableFraction)
        guard reservedPinBytes(proposed) <= cap else {
            throw EngineError(.conflict, "Pin needs more cache space; increase cache size or unpin other items",
                              data: ["reason": .string("headroom")])
        }
        let replacedPaths = Set([path] + (replacingPath.map { [$0] } ?? []))
        for oldPath in replacedPaths {
            for hash in doc.pins[oldPath]?.blocks ?? [] {
                if var entry = doc.blocks[hash] {
                    entry.pinnedRefs = max(0, entry.pinnedRefs - 1)
                    entry.paths.remove(oldPath); doc.blocks[hash] = entry
                }
            }
            if oldPath != path { doc.pathBlocks[oldPath] = nil }
        }
        for hash in record.blocks {
            if var entry = doc.blocks[hash] {
                entry.pinnedRefs += 1; entry.paths.insert(path); doc.blocks[hash] = entry
            }
        }
        doc.pins = proposed
        doc.pathBlocks[path] = record.blocks
        try persist()
        let (cached, expected, state) = pinAccounting(record)
        return PinState(path: path, pinned: true, recursive: recursive, blocks: record.blocks.count,
                        cachedBytes: cached, totalBytes: expected, cacheState: state)
    }

    private func reservedPinBytes(_ records: [String: PinRecord]) -> Int {
        var sizes: [String: Int] = [:]
        for record in records.values {
            for hash in record.blocks {
                // Current AES-GCM raw encoding has69bytes overhead; compression can
                // only lower residency. Already cached blocks use actual disk size.
                let length = doc.blocks[hash]?.len ?? ((record.expectedLengths?[hash] ?? 0) + 69)
                sizes[hash] = max(sizes[hash] ?? 0, length)
            }
        }
        return sizes.values.reduce(0) { total, length in
            let (sum, overflow) = total.addingReportingOverflow(length)
            return overflow ? Int.max : sum
        }
    }

    public func pin(_ path: String, recursive: Bool) async throws -> PinState {
        if let existing = doc.pins[path] {
            let (cached, total, state) = pinAccounting(existing)
            return PinState(path: path, pinned: true, recursive: existing.recursive, blocks: existing.blocks.count,
                            cachedBytes: cached, totalBytes: total, cacheState: state)
        }
        let prefix = recursive ? path : nil
        let blocks = blockSet(forPath: path, recursivePrefix: prefix)
        guard !blocks.isEmpty || doc.pathBlocks[path] != nil else {
            throw EngineError(.notFound, "no cached blocks registered under \(path)")
        }
        // Headroom guard: a pin pushing pinnedBytes past 80% of maxBytes is
        // rejected (DESIGN §3.3 / CONTROL-API.md §5.3).
        let wouldPin = blocks.filter { (doc.blocks[$0]?.pinned ?? false) == false }
        let added = wouldPin.reduce(0) { $0 + (doc.blocks[$1]?.len ?? 0) }
        let pinnedCap = Int(Double(doc.maxBytes) * pinnableFraction)
        if reservedPinBytes(doc.pins) + added > pinnedCap {
            throw EngineError(.conflict, "pin would exceed the 80% pinnable headroom",
                              data: ["reason": .string("headroom")])
        }
        // Capture the full byte size the pin covers at pin time so the pin can
        // report a truthful `totalBytes` and `pinned` / `pinning` state while it
        // is still materializing (CONTRACTS.md §4.1).
        let total = blocks.reduce(0) { $0 + (doc.blocks[$1]?.len ?? 0) }
        doc.pins[path] = PinRecord(path: path, recursive: recursive, blocks: blocks, totalBytes: total)
        for hex in blocks {
            if var e = doc.blocks[hex] { e.pinnedRefs += 1; doc.blocks[hex] = e }
        }
        try persist()
        let (cached, totalBytes, state) = pinAccounting(doc.pins[path]!)
        return PinState(path: path, pinned: true, recursive: recursive, blocks: blocks.count,
                        cachedBytes: cached, totalBytes: totalBytes, cacheState: state)
    }

    public func unpin(_ path: String, recursive: Bool) async throws -> PinState {
        guard let rec = doc.pins.removeValue(forKey: path) else {
            // Idempotent unpin of an unpinned path: nothing pinned, nothing resident.
            // The path has no pin record, so it carries no pin cache-state.
            return PinState(path: path, pinned: false, recursive: recursive, blocks: 0,
                            cachedBytes: 0, totalBytes: 0, cacheState: nil)
        }
        // Report the bytes the pin WAS holding before dropping its refs.
        let (cached, total, _) = pinAccounting(rec)
        for hex in rec.blocks {
            if var e = doc.blocks[hex] { e.pinnedRefs = max(0, e.pinnedRefs - 1); doc.blocks[hex] = e }
        }
        try persist()
        // The path is no longer pinned, so it carries no pin cache-state and will
        // not appear in pin.list. The bytes it *was* holding are still reported.
        return PinState(path: path, pinned: false, recursive: rec.recursive, blocks: rec.blocks.count,
                        cachedBytes: cached, totalBytes: total, cacheState: nil)
    }

    public func pinList(filespace: FilespaceID) throws -> [PinState] {
        try requireFilespace(filespace)
        return doc.pins.values
            .sorted { $0.path < $1.path }
            .map { rec in
                let (cached, total, state) = pinAccounting(rec)
                return PinState(path: rec.path, pinned: true, recursive: rec.recursive,
                                blocks: rec.blocks.filter { doc.blocks[$0] != nil }.count,
                                cachedBytes: cached, totalBytes: total, cacheState: state)
            }
    }

    /// Per-pin byte accounting + cache-state (CONTRACTS.md §4.1 / CONTROL-API.md §3).
    /// `cachedBytes` = Σ len over the pin's RESIDENT blocks (entry still present).
    /// `totalBytes`  = the size the pin covers: the captured pin-time total, never
    ///   less than what is resident now (so re-registering more blocks only grows it).
    /// `cacheState`  = pinned (fully resident) | pinning (still materializing).
    private func pinAccounting(_ rec: PinRecord) -> (cachedBytes: UInt64, totalBytes: UInt64, state: PinCacheState) {
        let cached = rec.blocks.reduce(0) { total, hash in
            guard let entry = doc.blocks[hash] else { return total }
            return total + (rec.expectedLengths?[hash] ?? entry.len)
        }
        let total = max(rec.totalBytes, cached)
        // Two states only: a pin is `pinned` once fully resident, otherwise it is
        // still `pinning` (0 <= cachedBytes < totalBytes). An unpinned/evicted path
        // has no pin record and is never reported here.
        let allPresent = rec.blocks.allSatisfy { doc.blocks[$0] != nil }
        let state: PinCacheState = (allPresent && cached >= total) ? .pinned : .pinning
        return (UInt64(cached), UInt64(total), state)
    }

    public func evict(_ path: String) async throws -> EvictAck {
        // Evict the evictable blocks registered under `path` (and, if pinned,
        // unpin first so the evict is honored — an explicit evict overrides LRU).
        if let rec = doc.pins.removeValue(forKey: path) {
            for hex in rec.blocks {
                if var e = doc.blocks[hex] { e.pinnedRefs = max(0, e.pinnedRefs - 1); doc.blocks[hex] = e }
            }
        }
        let blocks = blockSet(forPath: path, recursivePrefix: path)
        var evicted = 0, freed = 0
        for hex in blocks {
            guard let entry = doc.blocks[hex], !entry.pinned else { continue }
            try? fm.removeItem(at: blockURL(hex))
            freed += entry.len
            evicted += 1
            dropBlock(hex)
        }
        try persist()
        return EvictAck(path: path, evictedBlocks: evicted, freedBytes: freed)
    }

    /// Blocks registered exactly at `path`, plus (if `recursivePrefix` is set)
    /// every path that is `prefix` or a child `prefix/...`.
    private func blockSet(forPath path: String, recursivePrefix prefix: String?) -> Set<String> {
        var out = doc.pathBlocks[path] ?? []
        if let prefix {
            let p = prefix.hasSuffix("/") ? prefix : prefix + "/"
            for (other, set) in doc.pathBlocks where other == prefix || other.hasPrefix(p) {
                out.formUnion(set)
            }
        }
        return out.filter { doc.blocks[$0] != nil }
    }

    // MARK: - 2-random, pin-aware, ceiling-gated eviction (DESIGN §3.6)

    /// Evict until usage is at or below the ceiling. Only EVICTABLE (unpinned)
    /// blocks are candidates; pinned blocks always survive. Policy is 2-random:
    /// sample two evictable blocks and evict the older-atime one (near-LRU at low
    /// bookkeeping cost). Gated on usage > maxBytes.
    private func enforceBudget() throws {
        var changed = false
        while doc.usedBytes > doc.maxBytes {
            guard let victim = pick2RandomVictim() else { break } // all remaining pinned
            if let e = doc.blocks[victim] {
                try? fm.removeItem(at: blockURL(victim))
                _ = e
                dropBlock(victim)
                changed = true
            } else { break }
        }
        if changed { try persist() }
    }

    private func pick2RandomVictim() -> String? {
        let candidates = doc.blocks.filter { !$0.value.pinned }
        if candidates.isEmpty { return nil }
        let keys = Array(candidates.keys)
        if keys.count == 1 { return keys[0] }
        let a = keys.randomElement()!
        var b = keys.randomElement()!
        if b == a { b = keys[(keys.firstIndex(of: a)! + 1) % keys.count] }
        let la = candidates[a]!.lastAccess
        let lb = candidates[b]!.lastAccess
        return la <= lb ? a : b   // evict the older (smaller atime)
    }

    // MARK: - Helpers

    private func requireFilespace(_ fs: FilespaceID) throws {
        guard fs == filespace else {
            throw EngineError(.notFound, "unknown filespace \(fs)")
        }
    }

    private func freeOnVolume() -> Int {
        if let vals = try? rootDir.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]),
           let cap = vals.volumeAvailableCapacityForImportantUsage {
            return Int(cap)
        }
        if let attrs = try? fm.attributesOfFileSystem(forPath: rootDir.path),
           let free = attrs[.systemFreeSize] as? NSNumber {
            return free.intValue
        }
        return 0
    }

    static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
