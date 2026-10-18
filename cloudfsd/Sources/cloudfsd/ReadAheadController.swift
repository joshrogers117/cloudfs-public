// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// Optional work follows successful demand, never precedes it. This coordinator
/// owns speculation across every adapter belonging to one engine. It retains no
/// file contents or manifests except the closures of its strictly bounded tasks.
/// EngineDataPath has no open-handle ID: concurrent readers of one inode/version
/// share bounded contiguous coverage. Fully established streams tolerate macOS
/// cluster ordering within 64 MiB. Prediction grows from 16 to 32 MiB only
/// after sustained sequential coverage and an observed blocked demand read, and
/// to 64 MiB only after two further blocked demand reads at 32 MiB. Every tier
/// is capped by the engine-wide byte budget.
final class ReadAheadController: @unchecked Sendable {
    struct Key: Hashable, Sendable {
        let filespace: FilespaceID
        let itemID: InodeID
        let version: String
    }
    struct Ticket: Sendable {
        fileprivate let key: Key
        fileprivate let generation: UUID
        fileprivate let readID: UUID
    }
    struct Window: Equatable, Sendable {
        let offset: Int
        let length: Int
        var end: Int { offset + length }
    }
    struct Progress: Sendable {
        fileprivate let report: @Sendable (Int) -> Void
        /// Cumulative bytes whose block fetch has completed cache admission.
        func callAsFunction(_ completedBytes: Int) { report(completedBytes) }
    }
    typealias ProgressiveOperation = @Sendable (Window, Progress) async throws -> Void
    struct Snapshot: Sendable {
        let trackedStreams: Int
        let activeTasks: Int
        let reservedBytes: Int
        let activeDemands: Int
        let pendingRanges: Int
        let scheduledRanges: Int
    }
    private struct Stream {
        let generation: UUID
        var start: Int
        var end: Int
        var sequentialReads: Int
        var highLatency = false
        /// Successful demand completions that still blocked >= highLatencyNanoseconds
        /// after the 32 MiB tier was active. Two promote the stream to the wide tier.
        var blockedAtHighLatency = 0
        var scheduled: [Window] = []
        var fileSize: Int
        var blockSize: Int
        var touched: UInt64
        var latest: Window
        var demands: [UUID: Window] = [:]
        var pending: [Window] = []
        var tasks: Set<UUID> = []
    }
    private struct Work {
        let task: Task<Void, Never>
        let bytes: Int
        var completedBytes: Int = 0
        let key: Key
        let window: Window
        let ticket: Ticket
        let progressive: Bool
        let operation: ProgressiveOperation
    }
    private let lock = NSLock()
    private var streams: [Key: Stream] = [:]
    // Canceled tasks and their unfinished bytes remain here until cancellation
    // drains them. Verified/cached completions can release only their own bytes.
    // Rapid seeks cannot create an unbounded train of still-running work.
    private var work: [UUID: Work] = [:]
    private var reservedBytes = 0
    private var pausedFilespaces: Set<FilespaceID> = []
    let streamLimit: Int
    let taskLimit: Int
    let byteLimit: Int
    let idleNanoseconds: UInt64
    static let normalWindowBytes = 16 << 20
    static let maximumWindowBytes = 32 << 20
    static let maximumWindowBlocks = 32
    static let wideWindowBytes = 64 << 20
    static let wideWindowBlocks = 64
    static let blockedCompletionsForWideWindow = 2
    static let highLatencyNanoseconds: UInt64 = 25_000_000
    static let triggerBlocks = 4
    static let maximumReorderBytes = 64 << 20
    static let maximumScheduledRanges = 8
    static let maximumClusterBytes = 4 << 20
    static let pipelineBlocks = 4
    static let maximumTrackedDemands = 16
    private static let traceEnabled = ProcessInfo.processInfo.environment["CLOUDFS_LOG_READ_AHEAD"] == "1"
    private static let profileEnabled = ProcessInfo.processInfo.environment["CLOUDFS_PROFILE_WRITES"] == "1"

    /// Local opt-in diagnostics only: request extents and decisions, never
    /// credentials, object URLs or file contents. Disabled calls do not format.
    private func trace(_ event: String, key: Key, _ details: @autoclosure () -> String) {
        guard Self.traceEnabled else { return }
        let line = "CLOUDFS_READ_AHEAD event=\(event) fs=\(key.filespace) inode=\(key.itemID.rawValue) \(details())\n"
        FileHandle.standardError.write(Data(line.utf8))
    }

    init(streamLimit: Int = 64, taskLimit: Int = 32, byteLimit: Int = 64 << 20,
         idleNanoseconds: UInt64 = 5_000_000_000) {
        self.streamLimit = max(1, streamLimit)
        self.taskLimit = max(1, taskLimit)
        self.byteLimit = max(0, byteLimit)
        self.idleNanoseconds = idleNanoseconds
    }

    /// Observe the caller's actual extent, not its rounded block extent. A 64 KiB
    /// sequential reader should gain confidence; repeated reads of the same bytes
    /// should not. The returned ticket cannot launch anything until demand ends.
    func observe(key: Key, offset: Int, length: Int, fileSize: Int, blockSize: Int,
                 now: UInt64 = DispatchTime.now().uptimeNanoseconds) -> Ticket? {
        lock.withLock {
            guard !pausedFilespaces.contains(key.filespace) else { return nil }
            let obsolete = streams.keys.filter {
                $0.filespace == key.filespace && $0.itemID == key.itemID && $0 != key
            }
            for key in obsolete { remove(key, reason: "version") }
            let trigger = blockSize.multipliedReportingOverflow(by: Self.triggerBlocks)
            guard offset >= 0, length > 0, fileSize > offset, blockSize > 0,
                  length <= Int.max - offset, !trigger.overflow, length <= trigger.partialValue else {
                remove(key, reason: "invalid_or_large_extent")
                return nil
            }
            trace("observe", key: key, "offset=\(offset) length=\(length) end=\(streams[key]?.end ?? -1) inflight=\(streams[key]?.demands.count ?? 0)")
            let extent = Window(offset: offset, length: min(fileSize - offset, length))
            let readID = UUID()
            if var stream = streams[key] {
                // Callers sample the clock before acquiring this lock. An older
                // sample arriving later is normal concurrent scheduling, not idle.
                let expired = now >= stream.touched && now - stream.touched > idleNanoseconds
                let forward = offset <= stream.end && extent.end > stream.end
                let repeated = extent == stream.latest
                // macOS may finish one read cluster before issuing an earlier
                // cluster: there need not be a live overlapping SMB request. Once
                // real contiguous reads establish direction, tolerate clustering
                // within bounded coverage metadata. A gap by itself never raises
                // confidence or enlarges the speculative window.
                let established = stream.sequentialReads >= 2
                let overlappingDemand = !stream.demands.isEmpty
                // Reordering coverage is metadata, separate from bytes fetched.
                // Large sequential macOS reads can interleave clusters 40 MiB
                // apart. Only fully established direction gets the wider bound;
                // actual speculation has its separate 16/32 MiB latency bound.
                let tolerance = stream.sequentialReads >= 5 ? Self.maximumReorderBytes :
                    (established ? lookAheadBytes(stream) : trigger.partialValue)
                let acceptsReordering = established || overlappingDemand
                // A cluster starting at the horizon can contain several smaller
                // SMB requests. Its continuation gets one fixed cluster's slack,
                // never a sliding extension derived from newly pending bytes.
                let clusterLimit = established ? tolerance + min(trigger.partialValue, Self.maximumClusterBytes) : 0
                let forwardGap = acceptsReordering && offset > stream.end && offset - stream.end <= tolerance &&
                    (!established || extent.end - stream.end <= clusterLimit)
                let pendingExtension = established && offset > stream.end &&
                    extent.end - stream.end <= clusterLimit &&
                    stream.pending.contains { offset <= $0.end && extent.end >= $0.offset }
                let backfillTolerance = tolerance.addingReportingOverflow(extent.length)
                let backward = backfillTolerance.overflow ? Int.max : backfillTolerance.partialValue
                let recentBackfill = acceptsReordering && extent.end <= stream.end &&
                    offset >= stream.end - min(stream.end, backward) &&
                    extent.end >= stream.start - min(stream.start, tolerance)
                if !expired, stream.fileSize == fileSize, stream.blockSize == blockSize,
                   forward || repeated || forwardGap || pendingExtension || recentBackfill {
                    // Demand always proceeds; excessive readers merely opt out of
                    // this optional predictor instead of allocating unbounded IDs.
                    guard stream.demands.count < Self.maximumTrackedDemands else { return nil }
                    let previousEnd = stream.end
                    let previousPending = stream.pending
                    let ranges = Self.merged([Window(offset: stream.start, length: stream.end - stream.start)] +
                                             stream.pending + [extent])
                    guard let contiguous = ranges.first(where: { $0.offset <= stream.start && $0.end >= stream.end }) else { return nil }
                    let pending = ranges.filter { $0 != contiguous }
                    guard pending.count <= Self.pipelineBlocks else { return nil }
                    stream.start = contiguous.offset
                    stream.end = contiguous.end
                    stream.pending = pending
                    // Past contiguous demand needs no prediction bookkeeping.
                    stream.scheduled = stream.scheduled.compactMap { window in
                        guard window.end > stream.end else { return nil }
                        let start = max(window.offset, stream.end)
                        return Window(offset: start, length: window.end - start)
                    }
                    if stream.end > previousEnd {
                        // A gap alone cannot create confidence. Only newly joined
                        // contiguous requested coverage advances the prediction.
                        let joined = previousPending.filter { $0.offset >= previousEnd && $0.end <= stream.end }.count
                        stream.sequentialReads = min(6, stream.sequentialReads + 1 + joined)
                    }
                    stream.touched = max(stream.touched, now)
                    stream.latest = extent
                    stream.demands[readID] = extent
                    streams[key] = stream
                    trace("accepted", key: key, "offset=\(offset) end=\(stream.end) confidence=\(stream.sequentialReads) pending=\(stream.pending.map { $0.offset }) inflight=\(stream.demands.count)")
                    return Ticket(key: key, generation: stream.generation, readID: readID)
                }
                remove(key, reason: expired ? "idle" : "seek")
            }
            while streams.count >= streamLimit,
                  let oldest = streams.min(by: { $0.value.touched < $1.value.touched }) {
                remove(oldest.key, reason: "stream_capacity")
            }
            let generation = UUID()
            var stream = Self.fresh(generation: generation, extent: extent, fileSize: fileSize, blockSize: blockSize, now: now)
            stream.demands[readID] = extent
            streams[key] = stream
            trace("first", key: key, "offset=\(offset) end=\(stream.end)")
            return Ticket(key: key, generation: generation, readID: readID)
        }
    }

    private static func fresh(generation: UUID = UUID(), extent: Window, fileSize: Int,
                              blockSize: Int, now: UInt64) -> Stream {
        Stream(generation: generation, start: extent.offset, end: extent.end, sequentialReads: 1,
               fileSize: fileSize, blockSize: blockSize, touched: now, latest: extent)
    }

    private static func isWide(_ stream: Stream) -> Bool {
        stream.highLatency && stream.sequentialReads >= 6 &&
            stream.blockedAtHighLatency >= blockedCompletionsForWideWindow
    }

    private func lookAheadBytes(_ stream: Stream) -> Int {
        let wide = Self.isWide(stream)
        let high = stream.highLatency && stream.sequentialReads >= 6
        let tierBytes = wide ? Self.wideWindowBytes : (high ? Self.maximumWindowBytes : Self.normalWindowBytes)
        let maximumBytes = min(tierBytes, byteLimit)
        let maximumBlocks = wide ? Self.wideWindowBlocks : (high ? Self.maximumWindowBlocks : 16)
        // The wide tier needs one more doubling than the six-read step (32 blocks).
        let exponent = stream.sequentialReads - 1 + (wide ? 1 : 0)
        let blocks = min(maximumBlocks, 1 << exponent)
        let multiplied = stream.blockSize.multipliedReportingOverflow(by: blocks)
        return multiplied.overflow ? maximumBytes : min(maximumBytes, multiplied.partialValue)
    }

    private static func merged(_ ranges: [Window]) -> [Window] {
        var merged: [Window] = []
        for range in ranges.sorted(by: { $0.offset < $1.offset }) {
            if let previous = merged.last, range.offset <= previous.end {
                merged[merged.count - 1] = Window(offset: previous.offset, length: max(previous.end, range.end) - previous.offset)
            } else { merged.append(range) }
        }
        return merged
    }

    private static func uncovered(_ window: Window, by covered: [Window]) -> [Window] {
        var result: [Window] = []
        var cursor = window.offset
        for range in merged(covered) where range.end > cursor && range.offset < window.end {
            if range.offset > cursor {
                result.append(Window(offset: cursor, length: min(range.offset, window.end) - cursor))
            }
            cursor = max(cursor, min(range.end, window.end))
            if cursor == window.end { break }
        }
        if cursor < window.end { result.append(Window(offset: cursor, length: window.end - cursor)) }
        return result
    }

    /// Always call from defer, including error/cancellation. A successful
    /// demandCompleted has already retired the ID; otherwise abandon that
    /// prediction generation so failed reads cannot leave phantom work active.
    func demandEnded(_ ticket: Ticket?) {
        guard let ticket else { return }
        lock.withLock {
            guard let stream = streams[ticket.key], stream.generation == ticket.generation,
                  stream.demands[ticket.readID] != nil else { return }
            remove(ticket.key, reason: "failed_or_canceled_demand")
        }
    }

    /// Retire one successful demand. A first-read gap has no established
    /// direction and resets when overlapping demand ends. An established stream
    /// keeps bounded pending coverage across macOS cluster boundaries; subsequent
    /// far seeks, idle expiry and version changes still invalidate it.
    private func retire(_ ticket: Ticket) -> Stream? {
        guard var stream = streams[ticket.key], stream.generation == ticket.generation,
              stream.demands.removeValue(forKey: ticket.readID) != nil else { return nil }
        if stream.demands.isEmpty && !stream.pending.isEmpty && stream.sequentialReads < 2 {
            remove(ticket.key, reason: "unresolved_gap")
            streams[ticket.key] = Self.fresh(extent: stream.latest, fileSize: stream.fileSize,
                                           blockSize: stream.blockSize, now: stream.touched)
            return nil
        }
        streams[ticket.key] = stream
        trace("retired", key: ticket.key, "end=\(stream.end) inflight=\(stream.demands.count) pending=\(stream.pending.count)")
        return stream
    }

    /// Called only after bytes requested by the application have been verified
    /// and assembled. The operation must use speculative transfer priority.
    func demandCompleted(_ ticket: Ticket?, elapsedNanoseconds: UInt64 = 0,
                         operation: @escaping @Sendable (Window) async throws -> Void) {
        completed(ticket, elapsedNanoseconds: elapsedNanoseconds, progressive: false) { window, _ in
            try await operation(window)
        }
    }

    func demandCompleted(_ ticket: Ticket?, elapsedNanoseconds: UInt64 = 0,
                         progressOperation: @escaping ProgressiveOperation) {
        completed(ticket, elapsedNanoseconds: elapsedNanoseconds, progressive: true, operation: progressOperation)
    }

    private func completed(_ ticket: Ticket?, elapsedNanoseconds: UInt64, progressive: Bool,
                           operation: @escaping ProgressiveOperation) {
        guard let ticket else { return }
        lock.withLock {
            guard !pausedFilespaces.contains(ticket.key.filespace), var stream = retire(ticket) else { return }
            // A warm hit must not shrink a window justified by a blocked read.
            // Keep this evidence for the generation, even while work slots are
            // occupied. Failures never reach this successful-demand callback.
            if !stream.highLatency, stream.sequentialReads >= 6,
               elapsedNanoseconds >= Self.highLatencyNanoseconds {
                stream.highLatency = true
                streams[ticket.key] = stream
                trace("latency_window", key: ticket.key, "elapsedNanoseconds=\(elapsedNanoseconds) maximumBytes=\(Self.maximumWindowBytes)")
                Self.emitWindowProfile(Self.maximumWindowBytes, elapsedNanoseconds)
            } else if stream.highLatency, !Self.isWide(stream), elapsedNanoseconds >= Self.highLatencyNanoseconds {
                // Still blocked on the network at 32 MiB: only completed demand
                // reads count, never progress callbacks or warm (fast) hits.
                stream.blockedAtHighLatency += 1
                streams[ticket.key] = stream
                if Self.isWide(stream) {
                    trace("latency_window", key: ticket.key, "elapsedNanoseconds=\(elapsedNanoseconds) maximumBytes=\(Self.wideWindowBytes)")
                    Self.emitWindowProfile(Self.wideWindowBytes, elapsedNanoseconds)
                }
            }
            schedule(ticket: ticket, progressive: progressive, operation: operation)
        }
    }

    private static func emitWindowProfile(_ maximumBytes: Int, _ elapsedNanoseconds: UInt64) {
        guard profileEnabled else { return }
        let line = "CLOUDFS_READ_AHEAD_WINDOW maximumBytes=\(maximumBytes) elapsedNanoseconds=\(elapsedNanoseconds)\n"
        FileHandle.standardError.write(Data(line.utf8))
    }

    /// Called under the controller lock. A completed block frees only its own
    /// unfinished-byte reservation; a slow sibling cannot strand that capacity.
    /// Refill never passes the horizon of the latest actual requested extent.
    private func schedule(ticket: Ticket, progressive: Bool, operation: @escaping ProgressiveOperation) {
        guard !pausedFilespaces.contains(ticket.key.filespace), var stream = streams[ticket.key],
              stream.generation == ticket.generation,
              stream.sequentialReads >= 2,
              stream.tasks.count < (progressive ? taskLimit : 2), work.count < taskLimit else { return }
        let lookAhead = lookAheadBytes(stream)
        // Follow the latest accepted cluster instead of a global high-water
        // mark: a far-ahead kernel cluster must not suppress warming an
        // earlier cluster. Retained planned intervals avoid duplicate work.
        let requestedEnd = stream.latest.end
        let horizon = requestedEnd + min(stream.fileSize - requestedEnd, lookAhead)
        let remainder = requestedEnd % stream.blockSize
        let padding = remainder == 0 ? 0 : stream.blockSize - remainder
        let alignedStart = requestedEnd + min(stream.fileSize - requestedEnd, padding)
        guard alignedStart < horizon else { return }
        let coverage = stream.scheduled + stream.pending +
            [Window(offset: stream.start, length: stream.end - stream.start)]
        let candidates = Self.uncovered(Window(offset: alignedStart, length: horizon - alignedStart), by: coverage)
        // Pending demand can split a candidate inside a crypto block. That
        // block is already demanded: retain only complete future blocks.
        let aligned = candidates.compactMap { range -> Window? in
            let remainder = range.offset % stream.blockSize
            let padding = remainder == 0 ? 0 : stream.blockSize - remainder
            let start = range.offset + min(stream.fileSize - range.offset, padding)
            let end = range.end == stream.fileSize ? range.end : range.end - range.end % stream.blockSize
            return start < end ? Window(offset: start, length: end - start) : nil
        }
        guard let candidate = aligned.first else { return }
        let start = candidate.offset
        var length = min(byteLimit - reservedBytes, candidate.length)
        guard length > 0 else { return }
        // Reserve complete blocks except the actual final block at EOF.
        // Ciphertext adds a small envelope to transport's independent cap.
        if start + length < stream.fileSize { length -= length % stream.blockSize }
        guard length > 0 else { return }
        let window = Window(offset: start, length: length)
        let scheduled = Self.merged(stream.scheduled + [window])
        guard scheduled.count <= Self.maximumScheduledRanges else { return }
        let id = UUID()
        stream.tasks.insert(id)
        stream.scheduled = scheduled
        streams[ticket.key] = stream
        reservedBytes += length
        trace("schedule", key: ticket.key, "offset=\(start) length=\(length) end=\(stream.end) confidence=\(stream.sequentialReads) tasks=\(stream.tasks.count) reserved=\(reservedBytes)")
        let task = Task { [weak self] in
            var succeeded = false
            do {
                try Task.checkCancellation()
                let progress = Progress { [weak self] completed in self?.progress(id: id, completedBytes: completed) }
                try await operation(window, progress)
                succeeded = true
            } catch { /* Speculation never makes a requested read fail. */ }
            self?.finished(id: id, ticket: ticket, succeeded: succeeded)
        }
        work[id] = Work(task: task, bytes: length, key: ticket.key, window: window,
                        ticket: ticket, progressive: progressive, operation: operation)
    }

    private func progress(id: UUID, completedBytes: Int) {
        lock.withLock {
            guard var entry = work[id] else { return }
            let completed = min(entry.bytes, max(entry.completedBytes, completedBytes))
            let released = completed - entry.completedBytes
            guard released > 0 else { return }
            entry.completedBytes = completed
            work[id] = entry
            reservedBytes -= released
            trace("progress", key: entry.key, "completed=\(completed) released=\(released) reserved=\(reservedBytes) tasks=\(work.count)")
            if entry.progressive { schedule(ticket: entry.ticket, progressive: true, operation: entry.operation) }
        }
    }

    func setPaused(_ paused: Bool, filespace: FilespaceID) {
        lock.withLock {
            if paused {
                pausedFilespaces.insert(filespace)
                for key in streams.keys.filter({ $0.filespace == filespace }) { remove(key) }
            } else { pausedFilespaces.remove(filespace) }
        }
    }

    func cancel(filespace: FilespaceID, itemID: InodeID? = nil, exceptVersion: String? = nil) {
        lock.withLock {
            let keys = streams.keys.filter {
                $0.filespace == filespace && (itemID == nil || $0.itemID == itemID) &&
                    (exceptVersion == nil || $0.version != exceptVersion)
            }
            for key in keys { remove(key) }
        }
    }

    /// Explicit cache eviction waits for already-admitted optional work to end,
    /// otherwise its final cache admission could immediately undo the eviction.
    /// New foreground reads are still allowed to fetch the content normally.
    func cancelAndWait(filespace: FilespaceID, itemID: InodeID? = nil) async {
        let canceled = lock.withLock {
            let keys = streams.keys.filter { $0.filespace == filespace && (itemID == nil || $0.itemID == itemID) }
            for key in keys { remove(key) }
            let pending = work.values.filter { $0.key.filespace == filespace && (itemID == nil || $0.key.itemID == itemID) }
            for entry in pending { entry.task.cancel() }
            return pending.map(\.task)
        }
        for task in canceled { await task.value }
    }

    func snapshot() -> Snapshot {
        lock.withLock { Snapshot(trackedStreams: streams.count, activeTasks: work.count, reservedBytes: reservedBytes,
                                 activeDemands: streams.values.reduce(0) { $0 + $1.demands.count },
                                 pendingRanges: streams.values.reduce(0) { $0 + $1.pending.count },
                                 scheduledRanges: streams.values.reduce(0) { $0 + $1.scheduled.count }) }
    }

    private func remove(_ key: Key, reason: String = "lifecycle") {
        guard let stream = streams.removeValue(forKey: key) else { return }
        trace("reset", key: key, "reason=\(reason) start=\(stream.start) end=\(stream.end) inflight=\(stream.demands.count) tasks=\(stream.tasks.count) pending=\(stream.pending.map { $0.offset })")
        for id in stream.tasks { work[id]?.task.cancel() }
    }

    private func finished(id: UUID, ticket: Ticket, succeeded: Bool) {
        lock.withLock {
            guard let completed = work.removeValue(forKey: id) else { return }
            reservedBytes -= completed.bytes - completed.completedBytes
            trace("finished", key: ticket.key, "success=\(succeeded) bytes=\(completed.bytes) activeTasks=\(work.count)")
            guard var stream = streams[ticket.key], stream.generation == ticket.generation else { return }
            stream.tasks.remove(id)
            // A canceled/rejected/failed warm may be retried after another real
            // read. Clear only this failed reservation, preserving other history.
            if !succeeded {
                stream.scheduled = stream.scheduled.flatMap { Self.uncovered($0, by: [completed.window]) }
                // Subtraction can split a merged interval; retain a strict bound.
                if stream.scheduled.count > Self.maximumScheduledRanges { stream.scheduled.removeAll() }
            }
            streams[ticket.key] = stream
            if succeeded, completed.progressive {
                schedule(ticket: completed.ticket, progressive: true, operation: completed.operation)
            }
        }
    }

    deinit { for entry in work.values { entry.task.cancel() } }
}
