// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCache — the on-disk block index (DESIGN.md §3.5 `index.db`).
//
// Maps blockHash -> { len, lastAccess, pinned, refcount } plus the path -> block
// associations pins need, and the per-filespace settings (maxBytes, location).
// It is the LRU access metadata that 2-random eviction consults and the pin flags.
// Persisted as a single JSON document next to the block store; rewritten
// atomically (write temp + rename). Survives restart so the cache, the pins, and
// the size/location settings all come back after a daemon bounce.

import Foundation
import CryptoKit
import CloudFSCore

/// One block's bookkeeping entry. `pinned` is derived (a block is pinned iff any
/// pinned path references it) but cached here so eviction is O(1) per candidate.
struct BlockEntry: Codable, Equatable {
    var len: Int                 // plaintext byte length on disk
    var lastAccess: Double       // unix epoch seconds; the LRU key for 2-random
    var pinnedRefs: Int          // number of pinned paths referencing this block
    var paths: Set<String>       // every path that has registered this block

    var pinned: Bool { pinnedRefs > 0 }

    init(len: Int, lastAccess: Double, pinnedRefs: Int = 0, paths: Set<String> = []) {
        self.len = len
        self.lastAccess = lastAccess
        self.pinnedRefs = pinnedRefs
        self.paths = paths
    }
}

/// A pin record: a path the user pinned, the recursive flag, and the set of block
/// hashes it covers (the engine/transfer layer registers these via `register`).
struct PinRecord: Codable, Equatable {
    var path: String
    var recursive: Bool
    var blocks: Set<String>   // block hashes (hex) under this path

    /// Full byte size the pin covers (Σ len over the pin's blocks at pin/register
    /// time). Captured so a pin that is still materializing can report `totalBytes`
    /// and a `pinning` cache-state until it is fully resident (CONTRACTS.md §4.1).
    /// Optional on decode so index.db files written by older daemons (which omit
    /// it) still load.
    var totalBytes: Int = 0
    var expectedLengths: [String: Int]?

    enum CodingKeys: String, CodingKey { case path, recursive, blocks, totalBytes, expectedLengths }

    init(path: String, recursive: Bool, blocks: Set<String>, totalBytes: Int = 0, expectedLengths: [String: Int]? = nil) {
        self.path = path; self.recursive = recursive; self.blocks = blocks; self.totalBytes = totalBytes
        self.expectedLengths = expectedLengths
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = try c.decode(String.self, forKey: .path)
        recursive = try c.decode(Bool.self, forKey: .recursive)
        blocks = try c.decode(Set<String>.self, forKey: .blocks)
        totalBytes = try c.decodeIfPresent(Int.self, forKey: .totalBytes) ?? 0
        expectedLengths = try c.decodeIfPresent([String: Int].self, forKey: .expectedLengths)
    }
}

/// The full on-disk index document. One per cache directory.
struct IndexDocument: Codable, Equatable {
    static let currentVersion = 1

    var checkpointID: String?
    var version: Int = IndexDocument.currentVersion
    var filespace: FilespaceID
    var maxBytes: Int
    /// blockHash hex -> entry
    var blocks: [String: BlockEntry]
    /// path -> pin record (only pinned paths live here)
    var pins: [String: PinRecord]
    /// path -> the block hashes registered under it (whether pinned or not), so a
    /// later pin can find the blocks to retain and evict-by-path knows the set.
    var pathBlocks: [String: Set<String>]

    init(filespace: FilespaceID, maxBytes: Int) {
        self.filespace = filespace
        self.maxBytes = maxBytes
        self.blocks = [:]
        self.pins = [:]
        self.pathBlocks = [:]
    }

    var usedBytes: Int { blocks.values.reduce(0) { $0 + $1.len } }
    var pinnedBytes: Int { blocks.values.reduce(0) { $0 + ($1.pinned ? $1.len : 0) } }
}

/// Load/save of the index document. Keeps no in-memory state of its own; the
/// actor owns the document and asks this to persist it. Atomic on save.
enum BlockIndexStore {
    static let fileName = "index.db"
    static let admissionsName = "index.admissions"
    private struct Admission: Codable {
        let checkpoint: String
        let hash: String
        let entry: BlockEntry
    }
    private struct CheckedRecord: Codable { let payload: Data; let sha256: String }
    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func load(from dir: URL) -> IndexDocument? {
        let url = dir.appendingPathComponent(fileName)
        guard let data = try? Data(contentsOf: url),
              var doc = try? JSONDecoder().decode(IndexDocument.self, from: data),
              doc.version == IndexDocument.currentVersion else { return nil }
        // Each admission is independently checked. A torn final append is ignored;
        // the cached object remains recoverable from the authoritative object store.
        // Checkpoint identity makes old records harmless after a crash between
        // publishing a new snapshot and clearing its old admission file.
        if let id = doc.checkpointID,
           let records = try? Data(contentsOf: dir.appendingPathComponent(admissionsName)) {
            var begin = records.startIndex
            while let newline = records[begin...].firstIndex(of: 10) {
                let line = records[begin..<newline]
                guard let envelope = try? JSONDecoder().decode(CheckedRecord.self, from: line),
                      digest(envelope.payload) == envelope.sha256,
                      let admission = try? JSONDecoder().decode(Admission.self, from: envelope.payload) else { break }
                if admission.checkpoint == id {
                    guard admission.entry.len >= 0, admission.entry.pinnedRefs >= 0 else { break }
                    doc.blocks[admission.hash] = admission.entry
                }
                begin = records.index(after: newline)
            }
        }
        return doc
    }

    /// A bounded append replaces a full O(cache-size) rewrite for each newly
    /// downloaded block. The snapshot remains authoritative for pins/settings.
    static func appendAdmission(hash: String, entry: BlockEntry, doc: IndexDocument, to dir: URL) throws {
        guard let id = doc.checkpointID else { throw EngineError(.internal, "Missing cache checkpoint") }
        let payload = try JSONEncoder().encode(Admission(checkpoint: id, hash: hash, entry: entry))
        var bytes = try JSONEncoder().encode(CheckedRecord(payload: payload, sha256: digest(payload)))
        bytes.append(10)
        let url = dir.appendingPathComponent(admissionsName)
        let fd = open(url.path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
        defer { try? handle.close() }
        try handle.write(contentsOf: bytes)
        try handle.synchronize()
    }

    /// Publish the full checkpoint before clearing old records. There is no sorted
    /// key or Foundation replaceItemAt metadata-copy work on the streaming path.
    static func save(_ doc: inout IndexDocument, to dir: URL) throws {
        var checkpoint = doc
        checkpoint.checkpointID = UUID().uuidString
        let url = dir.appendingPathComponent(fileName)
        try JSONEncoder().encode(checkpoint).write(to: url, options: .atomic)
        let handle = try FileHandle(forWritingTo: url)
        defer { try? handle.close() }
        try handle.synchronize()
        let fd = open(dir.path, O_RDONLY)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { close(fd) }
        guard fsync(fd) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        doc.checkpointID = checkpoint.checkpointID
        // Even a failure here is safe: old records carry the previous checkpoint.
        try Data().write(to: dir.appendingPathComponent(admissionsName), options: .atomic)
        guard fsync(fd) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    }
}
