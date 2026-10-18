// SPDX-License-Identifier: AGPL-3.0-or-later
// Immutable payloads + checksummed checkpoint/delta metadata. The tiny atomic
// head is the commit point; no acknowledgement precedes its full-sync barrier.
import Foundation
import CryptoKit
import CloudFSCore
import CloudFSGateway

public struct JournalEntry: Sendable {
    public let filespace: FilespaceID
    public let itemID: InodeID
    public let baseVersion: String?
    public let size: Int
    public let blockLengths: [Int: Int]
    public let committedLimit: Int?
    public let wholeData: Data?
    public let base: ResolvedBlockManifest?
    public let baseCaptured: Bool
}

public actor WriteBackJournal {
    private let root: URL
    private let diskBudget: JournalDiskBudget?
    private let fm = FileManager.default
    private let writeProfile = WriteProfiler.shared
    /// Full sweeps collect interrupted, unpublished generations. Ordinary writes
    /// already know which old immutable payloads they replaced.
    private var publicationsSinceSweep: [String: Int] = [:]
    /// The remote commit succeeded but local removal failed. Never inherit these
    /// old dirty blocks into a later edit with a newer optimistic-concurrency base.
    private var retiredEntries: Set<String> = []
    private var failedPublications: Set<String> = []
    private var publicationTouchedHead = false
    private nonisolated let records = RecordCache()
    private let publicationFault: (@Sendable (PublicationPhase) throws -> Void)?
    private let payloadWriter: (@Sendable (Data, URL) throws -> Void)?

    enum PublicationPhase: Sendable, Equatable { case checkpointSynced, logSynced, headRenamed, fullSynced }
    static let checkpointInterval = 128
    private nonisolated static let maximumLogBytes = 16 << 20
    private nonisolated static let maximumDeltaBytes = 4 << 20
    private nonisolated static let maximumCheckpointBytes = 256 << 20

    private struct BlockRecord: Codable, Sendable, Equatable {
        let file: String
        let length: Int
        let sha256: String
    }
    private struct BaseSnapshot: Codable {
        let manifest: BlockManifest
        let objectKeys: [String: String]
    }
    private struct Meta: Codable, Sendable {
        let filespace: String
        let itemID: String
        let baseVersion: String?
        let size: Int?
        let committedLimit: Int?
        /// nil identifies the previous, unchecked journal format.
        var blocks: [Int: BlockRecord]?
        var base: BlockRecord?
        var baseCaptured: Bool?
        var journalFormat: Int? = nil
        var wal: WALHead? = nil
    }
    /// An incompatible blocks type forces older decoders to reject the head even
    /// when a legacy whole-file `data` orphan remains after interrupted cleanup.
    private struct V2DiskHead: Codable {
        let filespace: String
        let itemID: String
        let baseVersion: String?
        let size: Int?
        let committedLimit: Int?
        let blocks: String
        let base: BlockRecord?
        let baseCaptured: Bool?
        let journalFormat: Int
        let wal: WALHead
        init(_ meta: Meta, head: WALHead) {
            filespace = meta.filespace; itemID = meta.itemID; baseVersion = meta.baseVersion
            size = meta.size; committedLimit = meta.committedLimit
            blocks = "cloudfs-journal-v2"; base = meta.base; baseCaptured = meta.baseCaptured
            journalFormat = 2; wal = head
        }
        var metadata: Meta {
            Meta(filespace: filespace, itemID: itemID, baseVersion: baseVersion, size: size,
                 committedLimit: committedLimit, blocks: nil, base: base, baseCaptured: baseCaptured,
                 journalFormat: journalFormat, wal: wal)
        }
    }
    private struct WALHead: Codable, Sendable {
        let checkpoint: BlockRecord
        let log: String
        let bytes: Int
        let sequence: Int
        let tip: String
    }
    private struct Delta: Codable {
        let sequence: Int
        let previous: String
        let meta: Meta
        let removed: [Int]
    }
    private struct Envelope: Codable {
        let payload: Data
        let sha256: String
    }
    private final class RecordCache: @unchecked Sendable {
        let lock = NSLock()
        var metas: [String: Meta] = [:]
        func get(_ path: String) -> Meta? { lock.withLock { metas[path] } }
        func set(_ path: String, _ meta: Meta?) { lock.withLock { metas[path] = meta } }
        func withValue<T>(_ path: String, _ body: (Meta?) throws -> T) rethrows -> T {
            try lock.withLock { try body(metas[path]) }
        }
    }

    public init(cacheDir: String, diskBudget: JournalDiskBudget? = nil) {
        self.diskBudget = diskBudget
        root = URL(fileURLWithPath: cacheDir).appendingPathComponent("staging", isDirectory: true)
        publicationFault = nil
        payloadWriter = nil
    }
    /// Deterministic boundary faults; production always uses the public initializer.
    init(cacheDir: String, publicationFault: @escaping @Sendable (PublicationPhase) throws -> Void) {
        root = URL(fileURLWithPath: cacheDir).appendingPathComponent("staging", isDirectory: true)
        diskBudget = nil
        self.publicationFault = publicationFault
        payloadWriter = nil
    }
    /// Test-only injection of short-write/fsync failures before head publication.
    init(cacheDir: String, payloadWriter: @escaping @Sendable (Data, URL) throws -> Void) {
        root = URL(fileURLWithPath: cacheDir).appendingPathComponent("staging", isDirectory: true)
        publicationFault = nil
        diskBudget = nil
        self.payloadWriter = payloadWriter
    }
    nonisolated private func dir(_ filespace: FilespaceID, _ itemID: InodeID) -> URL {
        let slug = Data("\(filespace)\u{0}\(itemID.rawValue)".utf8).map { String(format: "%02x", $0) }.joined()
        return root.appendingPathComponent(slug, isDirectory: true)
    }
    nonisolated private static func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    nonisolated private static func damaged(_ message: String) -> EngineError {
        EngineError(.syncFailed, "Write recovery stopped: \(message). Local journal retained; do not delete the cache.")
    }

    public func recordBlocks(filespace: FilespaceID, itemID: InodeID, baseVersion: String?,
                             size: Int, committedLimit: Int? = nil, touched: [Int: Data],
                             removed: Set<Int> = [], base: ResolvedBlockManifest? = nil,
                             baseCaptured: Bool = false) throws {
        try record(filespace: filespace, itemID: itemID, baseVersion: baseVersion, size: size,
                   committedLimit: committedLimit, touched: touched, removed: removed, replace: false,
                   base: base, baseCaptured: baseCaptured)
    }

    public func recordReplace(filespace: FilespaceID, itemID: InodeID, baseVersion: String?,
                              size: Int, blocks: [Int: Data]) throws {
        try record(filespace: filespace, itemID: itemID, baseVersion: baseVersion, size: size,
                   committedLimit: 0, touched: blocks, removed: [], replace: true)
    }

    /// Stream an entire replacement into immutable generations, publishing only
    /// after the reader reaches EOF successfully. A read error leaves the previous
    /// acknowledged manifest (and every referenced block) intact.
    public func recordReplaceStreaming(filespace: FilespaceID, itemID: InodeID, baseVersion: String?,
                                        nextChunk: @Sendable () throws -> Data?) throws -> [Int: Int] {
        let d = dir(filespace, itemID)
        try removeRetiredEntryBeforeNewWrite(d)
        try createJournalDirectory(root)
        try createJournalDirectory(d)
        try Self.sync(root.deletingLastPathComponent())
        try Self.sync(root)
        var blocks: [Int: BlockRecord] = [:]
        var publishing = false
        defer { if !publishing { for record in blocks.values { try? removeJournalItem(d.appendingPathComponent(record.file)) } } }
        var size = 0
        while let chunk = try nextChunk() {
            try Task.checkCancellation()
            let file = "block-\(blocks.count)-\(UUID().uuidString)"
            try writePayload(chunk, to: d.appendingPathComponent(file))
            blocks[blocks.count] = BlockRecord(file: file, length: chunk.count, sha256: Self.digest(chunk))
            size += chunk.count
        }
        publishing = true
        try publish(blocks, filespace: filespace, itemID: itemID, baseVersion: baseVersion,
                    size: size, committedLimit: 0, at: d, base: nil, baseCaptured: true)
        return blocks.mapValues(\.length)
    }

    private func record(filespace: FilespaceID, itemID: InodeID, baseVersion: String?, size: Int,
                        committedLimit: Int?, touched: [Int: Data], removed: Set<Int>, replace: Bool,
                        base: ResolvedBlockManifest? = nil, baseCaptured: Bool = false) throws {
        let profileStart = writeProfile.start()
        defer { writeProfile.elapsed("journal.total", since: profileStart) }
        guard size >= 0, touched.keys.allSatisfy({ $0 >= 0 }) else {
            throw EngineError(.invalidParams, "invalid journal extent")
        }
        let d = dir(filespace, itemID)
        try removeRetiredEntryBeforeNewWrite(d)
        try writeProfile.measure("journal.directorySetup") {
            try createJournalDirectory(root)
            try createJournalDirectory(d)
            // Persist creation of both directories before acknowledging anything inside.
            try Self.sync(root.deletingLastPathComponent())
            try Self.sync(root)
        }
        var blocks: [Int: BlockRecord] = [:]
        var unpublished: [URL] = []
        var publishing = false
        defer { if !publishing { for url in unpublished { try? removeJournalItem(url) } } }
        var baseRecord: BlockRecord?
        var captured = replace
        if !replace, let previous = try writeProfile.measure("journal.metadataLoad", { try priorMetadata(d) }) {
            baseRecord = previous.base
            captured = previous.baseCaptured == true
            if let indexed = previous.blocks { blocks = indexed }
            else {
                // Import old block files once. Their historical bytes cannot be
                // retroactively verified, but all subsequent reads are checked.
                for file in try fm.contentsOfDirectory(at: d, includingPropertiesForKeys: nil) {
                    guard file.lastPathComponent.hasPrefix("block-"),
                          let index = Int(file.lastPathComponent.dropFirst(6)), index >= 0 else { continue }
                    let bytes = try Data(contentsOf: file)
                    blocks[index] = BlockRecord(file: file.lastPathComponent, length: bytes.count,
                                                sha256: Self.digest(bytes))
                }
            }
        }
        if !captured, baseCaptured {
            if let base {
                let snapshot = BaseSnapshot(manifest: base.manifest,
                    objectKeys: Dictionary(uniqueKeysWithValues: base.objectKeys.map { ($0.key.hex, $0.value) }))
                let bytes = try JSONEncoder().encode(snapshot)
                let file = "block-base-" + UUID().uuidString
                try writePayload(bytes, to: d.appendingPathComponent(file))
                unpublished.append(d.appendingPathComponent(file))
                baseRecord = BlockRecord(file: file, length: bytes.count, sha256: Self.digest(bytes))
            }
            captured = true
        }
        for index in removed { blocks[index] = nil }
        for (index, bytes) in touched {
            let file = "block-\(index)-\(UUID().uuidString)"
            try writeProfile.measure("journal.payloadWriteSync") { try writePayload(bytes, to: d.appendingPathComponent(file)) }
            unpublished.append(d.appendingPathComponent(file))
            let hash = writeProfile.measure("journal.payloadHash") { Self.digest(bytes) }
            blocks[index] = BlockRecord(file: file, length: bytes.count, sha256: hash)
        }
        publishing = true
        try publish(blocks, filespace: filespace, itemID: itemID, baseVersion: baseVersion,
                    size: size, committedLimit: committedLimit, at: d, base: baseRecord, baseCaptured: captured)
    }

    private func publish(_ blocks: [Int: BlockRecord], filespace: FilespaceID, itemID: InodeID,
                         baseVersion: String?, size: Int, committedLimit: Int?, at d: URL,
                         base: BlockRecord?, baseCaptured: Bool) throws {
        guard !failedPublications.contains(d.path) else {
            throw Self.damaged("publication failed; reopen and verify the journal before another edit")
        }
        publicationTouchedHead = false
        do {
            try publishTransaction(blocks, filespace: filespace, itemID: itemID, baseVersion: baseVersion,
                                   size: size, committedLimit: committedLimit, at: d, base: base, baseCaptured: baseCaptured)
        } catch {
            // The atomic head may already name the new prefix. Never append using
            // the old cached head (or truncate its log) after an ambiguous failure.
            if (error as? EngineError)?.data?["diskFull"] == .bool(true), !publicationTouchedHead {
                // Admission rejected before touching the head. The last ACK is
                // still authoritative; discard only unpublished generations and
                // allow a retry after capacity is available.
                let previous: Meta?
                do { previous = try priorMetadata(d) }
                catch { failedPublications.insert(d.path); throw Self.damaged("cannot verify the retained head after capacity rejection") }
                if let head = previous?.wal {
                    let log = d.appendingPathComponent(head.log)
                    let fd = open(log.path, O_WRONLY | O_NOFOLLOW)
                    if fd >= 0 {
                        if ftruncate(fd, off_t(head.bytes)) == 0 { _ = fsync(fd) }
                        close(fd)
                        try? diskBudget?.reconcile(log)
                    }
                }
                let retained = Set((previous?.blocks ?? [:]).values.map(\.file))
                    .union(previous?.base.map { [$0.file] } ?? [])
                    .union(previous?.wal.map { [$0.checkpoint.file, $0.log] } ?? [])
                    .union(["meta", "committed"])
                for file in (try? fm.contentsOfDirectory(at: d, includingPropertiesForKeys: nil)) ?? []
                    where !retained.contains(file.lastPathComponent) {
                    try? removeJournalItem(file)
                }
            } else { failedPublications.insert(d.path) }
            throw error
        }
    }

    private func publishTransaction(_ blocks: [Int: BlockRecord], filespace: FilespaceID, itemID: InodeID,
                         baseVersion: String?, size: Int, committedLimit: Int?, at d: URL,
                         base: BlockRecord?, baseCaptured: Bool) throws {
        // Make immutable payload names durable BEFORE publishing their references.
        try writeProfile.measure("journal.prePublishDirectorySync") { try Self.sync(d) }
        var meta = Meta(filespace: filespace, itemID: itemID.rawValue, baseVersion: baseVersion,
                        size: size, committedLimit: committedLimit, blocks: blocks,
                        base: base, baseCaptured: baseCaptured)
        let previous = try priorMetadata(d)
        let head = try writeProfile.measure("journal.deltaPublication") {
            try prepareWAL(meta, previous: previous, at: d)
        }
        // Readers keep the complete verified map in memory. The disk head's
        // incompatible marker makes old decoders reject it before legacy fallback.
        meta.journalFormat = 2; meta.wal = head
        let diskHead = V2DiskHead(meta, head: head)
        let encoded = try writeProfile.measure("journal.metadataEncode") {
            let payload = try JSONEncoder().encode(diskHead)
            let envelope = Envelope(payload: payload, sha256: Self.digest(payload))
            return try JSONEncoder().encode(envelope)
        }
        try writeProfile.measure("journal.metadataWriteSync") { try writeAndSync(encoded, to: d.appendingPathComponent("meta"), beforeWrite: { self.publicationTouchedHead = true }) }
        try publicationFault?(.headRenamed)
        try writeProfile.measure("journal.postPublishDirectorySync") { try Self.sync(d) }
        // Distinguishes an interrupted first publication from a later lost manifest.
        let marker = d.appendingPathComponent("committed")
        if !fm.fileExists(atPath: marker.path) {
            try writeAndSync(Data(), to: marker)
            try Self.sync(d)
        }
        // macOS fsync alone does not flush the drive's volatile write cache.
        // One full flush after the ordered payload/manifest/directory syncs is the
        // acknowledgement barrier for the entire transaction.
        try writeProfile.measure("journal.fullSync") { try Self.sync(d.appendingPathComponent("meta"), full: true) }
        try publicationFault?(.fullSynced)
        records.set(d.path, meta)
        // Garbage collection only after the new manifest is durable. An interruption
        // here merely leaves unreferenced generations that replay safely ignores.
        let cleanupStart = writeProfile.start()
        defer { writeProfile.elapsed("journal.cleanup", since: cleanupStart) }
        let retained = Set(blocks.values.map(\.file)).union(["meta", "committed", head.checkpoint.file, head.log])
            .union(base.map { [$0.file] } ?? [])
        let age = publicationsSinceSweep[d.path, default: 0]
        if previous == nil || age == 0 {
            // First publication/reopen, then every 128 successful publications:
            // bound orphan cleanup work without scanning an ever-growing directory
            // after every sequential write. Extra orphan files are safe to retain.
            for file in (try? fm.contentsOfDirectory(at: d, includingPropertiesForKeys: nil)) ?? []
            where !retained.contains(file.lastPathComponent) {
                try? removeJournalItem(file)
            }
        } else if let previous {
            let candidates = Set((previous.blocks ?? [:]).values.map(\.file))
                .union(previous.base.map { [$0.file] } ?? [])
                .union(previous.wal.map { [$0.checkpoint.file, $0.log] } ?? [])
            for file in candidates.subtracting(retained)
            where !file.contains("/") && (file.hasPrefix("block-") || file.hasPrefix("map-") || file.hasPrefix("delta-")) {
                try? removeJournalItem(d.appendingPathComponent(file))
            }
        }
        publicationsSinceSweep[d.path] = (age + 1) % 128
    }

    private func prepareWAL(_ meta: Meta, previous: Meta?, at d: URL) throws -> WALHead {
        if let previous, let head = previous.wal, head.sequence < Self.checkpointInterval {
            let old = previous.blocks ?? [:]
            let changed = (meta.blocks ?? [:]).filter { old[$0.key]?.file != $0.value.file }
            var deltaMeta = meta; deltaMeta.blocks = changed
            let delta = Delta(sequence: head.sequence + 1, previous: head.tip, meta: deltaMeta,
                              removed: old.keys.filter { meta.blocks?[$0] == nil })
            let payload = try JSONEncoder().encode(delta)
            if payload.count <= Self.maximumDeltaBytes,
               payload.count + 68 <= Self.maximumLogBytes - head.bytes {
                let tip = Self.digest(payload)
                var length = UInt32(payload.count).littleEndian
                var frame = withUnsafeBytes(of: &length) { Data($0) }
                frame.append(payload); frame.append(Data(tip.utf8))
                let fd = open(d.appendingPathComponent(head.log).path, O_WRONLY | O_NOFOLLOW)
                guard fd >= 0 else { throw Self.damaged("missing delta log") }
                defer { close(fd) }
                var stat = stat()
                guard fstat(fd, &stat) == 0, stat.st_size >= head.bytes else { throw Self.damaged("truncated committed delta log") }
                // Only bytes beyond the atomically committed prefix are discarded.
                guard ftruncate(fd, off_t(head.bytes)) == 0, lseek(fd, off_t(head.bytes), SEEK_SET) >= 0 else {
                    throw Self.damaged("cannot prepare delta append")
                }
                try budgetedWrite(to: d.appendingPathComponent(head.log), length: head.bytes + frame.count) {
                    try Self.writeAll(frame, fd: fd)
                }
                guard fsync(fd) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                try publicationFault?(.logSynced)
                return WALHead(checkpoint: head.checkpoint, log: head.log, bytes: head.bytes + frame.count,
                               sequence: delta.sequence, tip: tip)
            }
        }
        // A new immutable checkpoint/log pair bounds replay. Old names remain
        // reachable through the old head until the new head's full-sync succeeds.
        let bytes = try JSONEncoder().encode(meta)
        guard bytes.count <= Self.maximumCheckpointBytes else { throw Self.damaged("checkpoint exceeds supported metadata bound") }
        let checkpoint = BlockRecord(file: "map-" + UUID().uuidString, length: bytes.count, sha256: Self.digest(bytes))
        let log = "delta-" + UUID().uuidString
        try writeAndSync(bytes, to: d.appendingPathComponent(checkpoint.file))
        try writeAndSync(Data(), to: d.appendingPathComponent(log))
        try Self.sync(d)
        try publicationFault?(.checkpointSynced)
        return WALHead(checkpoint: checkpoint, log: log, bytes: 0, sequence: 0, tip: checkpoint.sha256)
    }

    private static func writeAll(_ bytes: Data, fd: Int32) throws {
        try bytes.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                offset += count
            }
        }
    }

    /// Explicit user-approved recovery completion. Unlike post-upload cleanup,
    /// removal errors must be reported before the in-memory staged image is dropped.
    public func discardVerified(filespace: FilespaceID, itemID: InodeID) throws {
        let d = dir(filespace, itemID)
        try removeJournalItem(d)
        try Self.sync(root)
        records.set(d.path, nil)
        publicationsSinceSweep[d.path] = nil
        failedPublications.remove(d.path)
    }

    public func clear(filespace: FilespaceID, itemID: InodeID) {
        let d = dir(filespace, itemID)
        retiredEntries.insert(d.path)
        // A restart before cleanup replays the old base and safely hits CAS.
        // In this live process, a later NEW edit may not reuse that retired map.
        try? removeRetiredEntryBeforeNewWrite(d)
    }

    private func removeRetiredEntryBeforeNewWrite(_ d: URL) throws {
        guard retiredEntries.contains(d.path) else { return }
        do {
            do { try removeJournalItem(d) }
            catch let error as CocoaError where error.code == .fileNoSuchFile {}
            try Self.sync(root)
        } catch {
            throw Self.damaged("cannot retire the previous committed journal before a new edit")
        }
        records.set(d.path, nil)
        publicationsSinceSweep[d.path] = nil
        failedPublications.remove(d.path)
        retiredEntries.remove(d.path)
    }

    public nonisolated func readBlock(filespace: FilespaceID, itemID: InodeID, blockIndex: Int) throws -> Data? {
        let d = dir(filespace, itemID)
        // Acquire the immutable payload's descriptor while holding the metadata
        // publication lock. Once open, a later publication may unlink its old name
        // safely: the descriptor still owns those exact bytes through verification.
        // Never hold this lock during the payload read or hashing work.
        let opened: (fd: Int32, record: BlockRecord?)? = try records.withValue(d.path) { cached in
            let meta = try cached ?? loadMeta(d)
            if let blocks = meta.blocks {
                guard let record = blocks[blockIndex] else { return nil }
                guard record.file.hasPrefix("block-"), !record.file.contains("/"),
                      record.length >= 0, record.length < Int.max else {
                    throw Self.damaged("invalid staged block record")
                }
                let fd = open(d.appendingPathComponent(record.file).path, O_RDONLY | O_NOFOLLOW)
                guard fd >= 0 else { throw Self.damaged("missing staged block \(record.file)") }
                return (fd, record)
            }
            // Read-only compatibility for existing journals, without inventing
            // missing bytes. Production replay refuses unchecked block manifests.
            let fd = open(d.appendingPathComponent("block-\(blockIndex)").path, O_RDONLY | O_NOFOLLOW)
            if fd < 0, errno == ENOENT { return nil }
            guard fd >= 0 else { throw Self.damaged("unreadable legacy staged block") }
            return (fd, nil)
        }
        guard let opened else { return nil }
        let handle = FileHandle(fileDescriptor: opened.fd, closeOnDealloc: false)
        defer { try? handle.close() }
        if let record = opened.record {
            let bytes: Data
            do { bytes = try handle.read(upToCount: record.length + 1) ?? Data() }
            catch { throw Self.damaged("unreadable staged block \(record.file)") }
            guard bytes.count == record.length, Self.digest(bytes) == record.sha256 else {
                throw Self.damaged("missing or corrupt staged block \(record.file)")
            }
            return bytes
        }
        return try handle.readToEnd() ?? Data()
    }

    public func replay() throws -> [JournalEntry] {
        guard fm.fileExists(atPath: root.path) else { return [] }
        var out: [JournalEntry] = []
        for d in try fm.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) {
            // A directory without a commit record is an interrupted FIRST write:
            // it was never acknowledged. Preserve it but do not invent an entry.
            guard fm.fileExists(atPath: d.appendingPathComponent("meta").path) else {
                if fm.fileExists(atPath: d.appendingPathComponent("committed").path) {
                    throw Self.damaged("missing committed manifest at \(d.path)")
                }
                continue
            }
            let meta = try loadMeta(d)
            guard d.standardizedFileURL.path == dir(meta.filespace, InodeID(meta.itemID)).standardizedFileURL.path else { throw Self.damaged("invalid entry identity") }
            var lengths: [Int: Int] = [:]
            if let blocks = meta.blocks {
                for (index, record) in blocks {
                    guard index >= 0 else { throw Self.damaged("negative block index") }
                    _ = try Self.readVerified(record, at: d)
                    lengths[index] = record.length
                }
            } else if fm.fileExists(atPath: d.appendingPathComponent("data").path) {
                let bytes = try Data(contentsOf: d.appendingPathComponent("data"))
                guard meta.size == nil || meta.size == bytes.count else { throw Self.damaged("truncated legacy image") }
                out.append(JournalEntry(filespace: meta.filespace, itemID: InodeID(meta.itemID),
                                        baseVersion: meta.baseVersion, size: bytes.count, blockLengths: [:],
                                        committedLimit: meta.committedLimit, wholeData: bytes, base: nil, baseCaptured: true))
                continue
            } else {
                for f in try fm.contentsOfDirectory(at: d, includingPropertiesForKeys: [.fileSizeKey]) {
                    guard f.lastPathComponent.hasPrefix("block-"),
                          let index = Int(f.lastPathComponent.dropFirst(6)), index >= 0 else { continue }
                    lengths[index] = try f.resourceValues(forKeys: [.fileSizeKey]).fileSize
                }
                // Old manifests do not record required blocks/checksums. Automatic
                // replay cannot distinguish a sparse hole from lost acknowledged
                // bytes, so preserve the record for explicit recovery.
                throw Self.damaged("legacy journal for \(meta.itemID) lacks block integrity records")
            }
            guard let size = meta.size, size >= 0, (meta.committedLimit ?? 0) >= 0 else {
                throw Self.damaged("invalid file size")
            }
            var resolvedBase: ResolvedBlockManifest?
            if let record = meta.base {
                let bytes = try Self.readVerified(record, at: d)
                let snapshot = try JSONDecoder().decode(BaseSnapshot.self, from: bytes)
                guard snapshot.manifest.itemID == InodeID(meta.itemID) else { throw Self.damaged("base snapshot identity mismatch") }
                resolvedBase = ResolvedBlockManifest(manifest: snapshot.manifest,
                    objectKeys: Dictionary(uniqueKeysWithValues: snapshot.objectKeys.map { (BlockHash(hex: $0.key), $0.value) }))
            }
            records.set(d.path, meta)
            out.append(JournalEntry(filespace: meta.filespace, itemID: InodeID(meta.itemID),
                                    baseVersion: meta.baseVersion, size: size, blockLengths: lengths,
                                    committedLimit: meta.committedLimit, wholeData: nil,
                                    base: resolvedBase, baseCaptured: meta.baseCaptured == true))
        }
        return out
    }

    private func priorMetadata(_ d: URL) throws -> Meta? {
        // This cache is installed only after the full durability barrier, or by
        // verified replay. Reusing its immutable references avoids decoding the
        // complete growing block map for each small write. Payload reads still
        // verify SHA/length, and restart always validates the on-disk envelope.
        if let published = records.get(d.path) { return published }
        guard fm.fileExists(atPath: d.appendingPathComponent("meta").path) else {
            if fm.fileExists(atPath: d.appendingPathComponent("committed").path) {
                throw Self.damaged("missing committed manifest at \(d.path)")
            }
            return nil
        }
        return try loadMeta(d)
    }

    nonisolated private func loadMeta(_ d: URL) throws -> Meta {
        do {
            let data = try Data(contentsOf: d.appendingPathComponent("meta"))
            if let envelope = try? JSONDecoder().decode(Envelope.self, from: data) {
                guard Self.digest(envelope.payload) == envelope.sha256 else {
                    throw Self.damaged("manifest checksum mismatch")
                }
                if let head = try? JSONDecoder().decode(V2DiskHead.self, from: envelope.payload) {
                    guard head.blocks == "cloudfs-journal-v2", head.journalFormat == 2 else {
                        throw Self.damaged("invalid journal version marker")
                    }
                    return try replayWAL(head.metadata, at: d)
                }
                // Also accept earlier development v2 heads that omitted blocks.
                let meta = try JSONDecoder().decode(Meta.self, from: envelope.payload)
                if meta.journalFormat != nil || meta.wal != nil { return try replayWAL(meta, at: d) }
                return meta
            }
            // Read-only compatibility; replay refuses unchecked per-block records.
            return try JSONDecoder().decode(Meta.self, from: data)
        }
        catch { throw Self.damaged("unreadable manifest at \(d.path)") }
    }

    nonisolated private func replayWAL(_ anchor: Meta, at d: URL) throws -> Meta {
        guard anchor.journalFormat == 2, anchor.blocks == nil, let head = anchor.wal,
              head.bytes >= 0, head.bytes <= Self.maximumLogBytes,
              head.sequence >= 0, head.sequence <= Self.checkpointInterval,
              Self.safeName(head.log, prefix: "delta-"),
              Self.safeName(head.checkpoint.file, prefix: "map-"),
              head.checkpoint.length >= 0, head.checkpoint.length <= Self.maximumCheckpointBytes else {
            throw Self.damaged("invalid delta head")
        }
        let checkpoint = try Self.readMetadata(d.appendingPathComponent(head.checkpoint.file),
                                              count: head.checkpoint.length, exact: true)
        guard Self.digest(checkpoint) == head.checkpoint.sha256 else { throw Self.damaged("checkpoint checksum mismatch") }
        var meta = try JSONDecoder().decode(Meta.self, from: checkpoint)
        guard meta.filespace == anchor.filespace, meta.itemID == anchor.itemID,
              meta.journalFormat == nil, meta.wal == nil, var blocks = meta.blocks else {
            throw Self.damaged("checkpoint identity or format mismatch")
        }
        let log = try Self.readMetadata(d.appendingPathComponent(head.log), count: head.bytes, exact: false)
        var cursor = 0, sequence = 0, tip = head.checkpoint.sha256
        while cursor < log.count {
            guard sequence < head.sequence, log.count - cursor >= 4 else { throw Self.damaged("incomplete delta frame") }
            let length = Int(log.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(fromByteOffset: cursor, as: UInt32.self)) })
            cursor += 4
            guard length > 0, length <= Self.maximumDeltaBytes, length <= log.count - cursor - 64 else {
                throw Self.damaged("invalid delta frame length")
            }
            let payload = log.subdata(in: cursor..<(cursor + length)); cursor += length
            let hash = String(data: log.subdata(in: cursor..<(cursor + 64)), encoding: .utf8); cursor += 64
            guard hash == Self.digest(payload) else { throw Self.damaged("delta checksum mismatch") }
            let delta = try JSONDecoder().decode(Delta.self, from: payload)
            guard delta.sequence == sequence + 1, delta.previous == tip,
                  delta.meta.filespace == anchor.filespace, delta.meta.itemID == anchor.itemID,
                  delta.meta.journalFormat == nil, delta.meta.wal == nil,
                  let changes = delta.meta.blocks, changes.keys.allSatisfy({ $0 >= 0 }),
                  delta.removed.allSatisfy({ $0 >= 0 }) else { throw Self.damaged("delta sequence or identity mismatch") }
            for index in delta.removed { blocks[index] = nil }
            blocks.merge(changes) { _, newer in newer }
            meta = delta.meta; sequence += 1; tip = hash!
        }
        guard sequence == head.sequence, tip == head.tip,
              meta.baseVersion == anchor.baseVersion, meta.size == anchor.size,
              meta.committedLimit == anchor.committedLimit,
              meta.base == anchor.base, meta.baseCaptured == anchor.baseCaptured else {
            throw Self.damaged("delta head does not match its committed image")
        }
        meta.blocks = blocks; meta.journalFormat = 2; meta.wal = head
        return meta
    }

    nonisolated private static func safeName(_ name: String, prefix: String) -> Bool {
        name.hasPrefix(prefix) && name.count > prefix.count && name.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45
        }
    }

    nonisolated private static func readMetadata(_ file: URL, count: Int, exact: Bool) throws -> Data {
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw damaged("missing journal metadata component") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        defer { try? handle.close() }
        var attributes = stat()
        guard fstat(fd, &attributes) == 0, attributes.st_mode & S_IFMT == S_IFREG,
              attributes.st_size >= count, !exact || attributes.st_size == count else {
            throw damaged("truncated journal metadata component")
        }
        let bytes = count == 0 ? Data() : try handle.read(upToCount: count) ?? Data()
        guard bytes.count == count else { throw damaged("short journal metadata read") }
        return bytes
    }
    nonisolated private static func readVerified(_ record: BlockRecord, at directory: URL) throws -> Data {
        guard record.file.hasPrefix("block-"), !record.file.contains("/"), record.length >= 0,
              let bytes = try? Data(contentsOf: directory.appendingPathComponent(record.file)),
              bytes.count == record.length, digest(bytes) == record.sha256 else {
            throw damaged("missing or corrupt staged block \(record.file)")
        }
        return bytes
    }
    private func writePayload(_ data: Data, to url: URL) throws {
        do {
            try budgetedWrite(to: url, length: data.count) {
                if let payloadWriter { try payloadWriter(data, url) }
                else { try Self.writeImmutablePayload(data, to: url) }
            }
        } catch {
            // This unique payload has never been published, so partial writes
            // can be removed without touching any acknowledged generation.
            try? removeJournalItem(url)
            throw error
        }
    }

    /// UUID payloads are not reachable until the separately atomic head names
    /// them. Write their final, exclusive name directly; an interrupted write is
    /// only an ignored orphan. Keep every explicit fsync and directory/head barrier.
    static func writeImmutablePayload(_ data: Data, to url: URL,
        writeChunk: (Int32, UnsafeRawPointer, Int) -> Int = { write($0, $1, $2) },
        syncFile: (Int32) -> Int32 = { fsync($0) }) throws {
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var closed = false
        defer { if !closed { close(fd) } }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = writeChunk(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0, errno == EINTR { continue }
                guard count > 0, count <= bytes.count - offset else {
                    throw POSIXError(count < 0 ? (POSIXErrorCode(rawValue: errno) ?? .EIO) : .EIO)
                }
                offset += count
            }
        }
        guard syncFile(fd) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let status = close(fd)
        closed = true
        guard status == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }

    private func budgetedWrite<T>(to url: URL, length: Int, replacing: Bool = false, _ body: () throws -> T) throws -> T {
        do {
            if let diskBudget { return try diskBudget.write(to: url, length: length, replacing: replacing, body) }
            return try body()
        } catch {
            if (error as? POSIXError)?.code == .ENOSPC || (error as? CocoaError)?.code == .fileWriteOutOfSpace {
                throw EngineError(.syncFailed, "Disk is full; pending journal data is retained. Free space and reconnect before retrying.",
                                  data: ["diskFull": .bool(true), "reason": .string("disk_full")])
            }
            throw error
        }
    }
    private func createJournalDirectory(_ url: URL) throws {
        guard !fm.fileExists(atPath: url.path) else { return }
        try budgetedWrite(to: url, length: 4096) {
            try fm.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
    }
    private func removeJournalItem(_ url: URL) throws {
        try fm.removeItem(at: url)
        diskBudget?.removed(url)
    }
    private func writeAndSync(_ data: Data, to url: URL, beforeWrite: (() -> Void)? = nil) throws {
        try budgetedWrite(to: url, length: data.count, replacing: true) {
            beforeWrite?()
            try data.write(to: url, options: .atomic)
            try Self.sync(url)
        }
    }
    private static func sync(_ url: URL, full: Bool = false) throws {
        let fd = open(url.path, O_RDONLY)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(fd) }
        guard fsync(fd) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        #if os(macOS)
        if full, fcntl(fd, F_FULLFSYNC) != 0 {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        #endif
    }
}
