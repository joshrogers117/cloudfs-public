// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSTransfer — prefetch / download / async upload seam. (DESIGN.md §4)
//
// Owner (next round): TRANSFER. Depends on CloudFSCache + CloudFSCrypto +
// CloudFSGateway (the DAG). Implements: byte-range GETs against presigned URLs
// over a warm HTTP/2 pool, multi-threaded prefetch + read-ahead, the staged
// write-back / async multipart encrypt-upload, retry/backoff (honor 429
// Retry-After; re-mint on presign expiry), and progress events.
//
// THIS FILE DEFINES THE PROTOCOL + A STUB. The real engine is the next round.

import Foundation
import CloudFSCore
import CloudFSGateway

/// P0/P1 — the dirty-block staging snapshot for read-your-own-writes (audit B3).
/// `dirtyLengths` maps blockIndex → the staged image's length; the BYTES are paged
/// in one block at a time via `stagedBlock` (P1: a snapshot of a 20 GB staged write
/// must not be 20 GB of RAM). An image may be shorter than the block's logical
/// extent (write-beyond-EOF) — the reader zero-pads to
/// `min(blockSize, size - blockIndex*blockSize)`. Non-dirty indices within `size`
/// are served from the committed manifest (or zeros where no committed block exists).
public struct StagedState: Sendable {
    /// The immutable committed image against which these local edits were made.
    /// nil with baseCaptured=true means an originally empty/new file.
    public let originalBase: ResolvedBlockManifest?
    public let baseCaptured: Bool
    public let size: Int
    public let dirtyLengths: [Int: Int]
    /// True when non-dirty in-size blocks come from the COMMITTED manifest (ranged
    /// edits). False after a whole-file replace: the staged content fully defines the
    /// file, so non-dirty in-size blocks are ZEROS — never the committed bytes.
    public let mergesCommitted: Bool
    /// P4 — how many committed bytes are still ALIVE (a truncate kills the committed
    /// content beyond it). A reader merging a committed block must trim it to
    /// `committedLimit - blockOffset` and zero-pad the rest.
    public let committedLimit: Int
    public init(size: Int, dirtyLengths: [Int: Int], mergesCommitted: Bool = true,
                committedLimit: Int = Int.max, originalBase: ResolvedBlockManifest? = nil,
                baseCaptured: Bool = false) {
        self.originalBase = originalBase; self.baseCaptured = baseCaptured
        self.size = size; self.dirtyLengths = dirtyLengths
        self.mergesCommitted = mergesCommitted; self.committedLimit = committedLimit
    }
}

public protocol TransferEngine: Sendable {
    func completeRecovery(filespace: FilespaceID, itemID: InodeID, destination: String) async throws
    func recoveryItems(filespace: FilespaceID) async throws -> [RecoveryItem]
    func retryRecovery(filespace: FilespaceID, itemID: InodeID) async throws
    func exportRecovery(filespace: FilespaceID, itemID: InodeID, destination: String) async throws -> RecoveryExportResult
    /// Ensure the byte range of an item is resident (download misses); used by read.
    func ensureRange(filespace: FilespaceID, itemID: InodeID, offset: Int, length: Int) async throws
    /// Queue prefetch of every block of an item; returns the queued count. `path`
    /// is display-only (transfer events, acks); `itemID` is the resolved inode —
    /// the caller (Engine) owns path→inode resolution.
    func prefetch(filespace: FilespaceID, path: String, itemID: InodeID) async throws -> PrefetchAck
    /// P0 — stage a RANGED write (ack-local) and enqueue async encrypt-upload of the
    /// DIRTY BLOCKS only. Only the blocks touched by `[offset, offset+data.count)` are
    /// staged; a partially covered block with committed content is seeded by fetching
    /// THAT block (read-modify-write), never the whole file. The staged logical size is
    /// `max(committed size, offset+data.count)` (ranged writes never shrink — truncate
    /// is a separate, not-yet-wired op). Returns the staged size after this write.
    /// `baseVersion` threads the optimistic-concurrency base for the commit CAS
    /// (audit B4); `fence` the writer's lease fence when held (audit B5).
    @discardableResult
    func stageWrite(filespace: FilespaceID, itemID: InodeID, offset: Int, data: Data,
                    baseVersion: String?, fence: Int?) async throws -> Int
    /// P0 — stage a WHOLE-FILE REPLACE (ack-local): `data` becomes the file's entire
    /// new content (size == data.count, may shrink). Every block of the new image is
    /// dirty; nothing is merged from the committed manifest. This is the semantics of
    /// `EngineDataPath.write(contents:)` (atomic-save / appex-style whole-file hand-off).
    func stageReplace(filespace: FilespaceID, itemID: InodeID, data: Data,
                      baseVersion: String?, fence: Int?) async throws
    /// P1 — whole-file replace STREAMED from a file (FileHandle, block-size chunks):
    /// the file's content is journaled block-by-block without ever holding the whole
    /// image in memory. This is what `EngineDataPath.write(contents:)` uses — never
    /// `Data(contentsOf:)` for content.
    func stageReplace(filespace: FilespaceID, itemID: InodeID, contents: CacheFileRef,
                      baseVersion: String?, fence: Int?) async throws
    /// P4 — stage a TRUNCATE to `newSize` (ack-local): the staged logical size becomes
    /// exactly `newSize`. A shrink drops staged blocks beyond the boundary and trims
    /// the boundary block; committed bytes beyond `newSize` are DEAD — they read back
    /// as zeros if the file later grows, never as resurrected old content. A growth
    /// truncate zero-extends. The async commit reuses unchanged committed refs below
    /// the boundary and rewrites only the boundary block.
    func stageTruncate(filespace: FilespaceID, itemID: InodeID, newSize: Int,
                       baseVersion: String?, fence: Int?) async throws
    /// The dirty-block staging snapshot for an item (read-your-own-writes, audit B3),
    /// or nil if nothing is dirty. Lengths only — bytes via `stagedBlock` (P1).
    func stagedState(filespace: FilespaceID, itemID: InodeID) async -> StagedState?
    /// One staged block's plaintext bytes (paged from the journal when spilled), or
    /// nil if that block isn't dirty.
    func stagedBlock(filespace: FilespaceID, itemID: InodeID, blockIndex: Int) async throws -> Data?
    /// Drain staged writes for a path; if `wait`, block until durably committed.
    func flush(filespace: FilespaceID, path: String, wait: Bool, timeoutMs: Int?) async throws -> SyncState
    func syncState(filespace: FilespaceID, path: String) async throws -> SyncState
    // transfers view + pause/resume
    func current(filespace: FilespaceID) async throws -> [Transfer]
    func pause(filespace: FilespaceID) async throws -> PauseResult
    func resume(filespace: FilespaceID) async throws -> PauseResult
    /// Stop optional verification before a disconnected session drops credentials.
    func stopBackgroundVerification(filespace: FilespaceID) async
    /// Permanently stop this session and drain every task that can touch its
    /// journal before another session opens the same filespace directory.
    func shutdown(filespace: FilespaceID) async
    /// Live progress notifications (download/upload) for the event stream.
    func progressEvents(filespace: FilespaceID) -> AsyncStream<Transfer>
}

public extension TransferEngine {
    func stopBackgroundVerification(filespace: FilespaceID) async {}
    func shutdown(filespace: FilespaceID) async { await stopBackgroundVerification(filespace: filespace) }
    func completeRecovery(filespace: FilespaceID, itemID: InodeID, destination: String) async throws { throw EngineError.unimplemented() }
    func recoveryItems(filespace: FilespaceID) async throws -> [RecoveryItem] { [] }
    func retryRecovery(filespace: FilespaceID, itemID: InodeID) async throws { throw EngineError.unimplemented() }
    func exportRecovery(filespace: FilespaceID, itemID: InodeID, destination: String) async throws -> RecoveryExportResult { throw EngineError.unimplemented() }

    /// Convenience: stage a write without optimistic-concurrency/lock context (the
    /// legacy 4-arg form). Existing call sites + tests keep compiling.
    @discardableResult
    func stageWrite(filespace: FilespaceID, itemID: InodeID, offset: Int, data: Data) async throws -> Int {
        try await stageWrite(filespace: filespace, itemID: itemID, offset: offset, data: data,
                             baseVersion: nil, fence: nil)
    }
}

/// Foundation stub: compiles green, throws `.unimplemented`.
public struct StubTransferEngine: TransferEngine {
    public init() {}
    public func ensureRange(filespace: FilespaceID, itemID: InodeID, offset: Int, length: Int) async throws { throw EngineError.unimplemented() }
    public func prefetch(filespace: FilespaceID, path: String, itemID: InodeID) async throws -> PrefetchAck { throw EngineError.unimplemented() }
    public func stageWrite(filespace: FilespaceID, itemID: InodeID, offset: Int, data: Data, baseVersion: String?, fence: Int?) async throws -> Int { throw EngineError.unimplemented() }
    public func stageReplace(filespace: FilespaceID, itemID: InodeID, data: Data, baseVersion: String?, fence: Int?) async throws { throw EngineError.unimplemented() }
    public func stageReplace(filespace: FilespaceID, itemID: InodeID, contents: CacheFileRef, baseVersion: String?, fence: Int?) async throws { throw EngineError.unimplemented() }
    public func stageTruncate(filespace: FilespaceID, itemID: InodeID, newSize: Int, baseVersion: String?, fence: Int?) async throws { throw EngineError.unimplemented() }
    public func stagedState(filespace: FilespaceID, itemID: InodeID) async -> StagedState? { nil }
    public func stagedBlock(filespace: FilespaceID, itemID: InodeID, blockIndex: Int) async throws -> Data? { nil }
    public func flush(filespace: FilespaceID, path: String, wait: Bool, timeoutMs: Int?) async throws -> SyncState { throw EngineError.unimplemented() }
    public func syncState(filespace: FilespaceID, path: String) async throws -> SyncState { throw EngineError.unimplemented() }
    public func current(filespace: FilespaceID) async throws -> [Transfer] { throw EngineError.unimplemented() }
    public func pause(filespace: FilespaceID) async throws -> PauseResult { throw EngineError.unimplemented() }
    public func resume(filespace: FilespaceID) async throws -> PauseResult { throw EngineError.unimplemented() }
    public func progressEvents(filespace: FilespaceID) -> AsyncStream<Transfer> {
        AsyncStream { $0.finish() }   // empty stream until implemented
    }
}
