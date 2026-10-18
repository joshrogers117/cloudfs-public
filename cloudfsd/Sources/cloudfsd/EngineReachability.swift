// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

// Truthful connection state: per-filespace gateway reachability derived from the
// outcomes of the requests the engine already makes. Cheap by design: one lock,
// a handful of scalars per filespace, no extra network traffic.

/// Window used by the classification (and documented in CONTROL-API.md).
let kReachabilityWindowSeconds: TimeInterval = 30

final class GatewayReachabilityTracker: @unchecked Sendable {
    struct Snapshot: Equatable {
        var lastSuccessAt: Int64?
        var lastFailureAt: Int64?
        var lastFailureReason: String?
        var latencyMs: Double?
        var reachability: EngineStatus.Reachability?
    }
    private struct State {
        var lastSuccess: Date?
        var lastFailure: Date?
        var reason: String?
        var ewmaMs: Double?
    }
    private let lock = NSLock()
    private var states: [FilespaceID: State] = [:]

    func recordSuccess(_ fs: FilespaceID, latencyMs: Double?, now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        var s = states[fs] ?? State()
        s.lastSuccess = now
        if let latencyMs, latencyMs >= 0 {
            s.ewmaMs = s.ewmaMs.map { $0 * 0.8 + latencyMs * 0.2 } ?? latencyMs
        }
        states[fs] = s
    }

    func recordFailure(_ fs: FilespaceID, reason: String, now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        var s = states[fs] ?? State()
        s.lastFailure = now
        s.reason = reason
        states[fs] = s
    }

    func snapshot(_ fs: FilespaceID, now: Date = Date()) -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        guard let s = states[fs] else { return Snapshot() }
        return Snapshot(lastSuccessAt: s.lastSuccess.map(Self.ms), lastFailureAt: s.lastFailure.map(Self.ms),
                        lastFailureReason: s.reason, latencyMs: s.ewmaMs,
                        reachability: Self.classify(now: now, lastSuccess: s.lastSuccess, lastFailure: s.lastFailure))
    }

    private static func ms(_ d: Date) -> Int64 { Int64((d.timeIntervalSince1970 * 1000).rounded()) }

    /// offline = a failure newer than the last success (or no success) and no success in the
    /// window; degraded = a failure and a success both inside the window; else online. nil when
    /// nothing has been observed.
    static func classify(now: Date, lastSuccess: Date?, lastFailure: Date?,
                         window: TimeInterval = kReachabilityWindowSeconds) -> EngineStatus.Reachability? {
        if lastSuccess == nil && lastFailure == nil { return nil }
        let successRecent = lastSuccess.map { now.timeIntervalSince($0) <= window } ?? false
        if let failure = lastFailure {
            let failureAfterSuccess = lastSuccess.map { failure > $0 } ?? true
            if failureAfterSuccess && !successRecent { return .offline }
            if successRecent && now.timeIntervalSince(failure) <= window { return .degraded }
        }
        return .online
    }

    /// Only transport/server-side failures count; a semantic answer (404, 409, 403 ...) proves the
    /// gateway is reachable.
    static func failureReason(for error: Error) -> String? {
        if error is CancellationError { return nil }
        if let e = error as? EngineError {
            switch e.kind {
            case .networkError:
                // GatewayClient.send maps URLError.cancelled to EngineError(.networkError, "cancelled").
                if isCancellationMessage(e.message) { return nil }
                return sanitize("network: " + e.message)
            case .gatewayError: return sanitize("gateway: " + e.message)
            default: return nil
            }
        }
        if (error as? URLError)?.code == .cancelled { return nil }
        return sanitize("network: " + error.localizedDescription)
    }

    static func isCancellationMessage(_ message: String) -> Bool {
        // GatewayClient.send forwards `URLError.localizedDescription`; on macOS that is the
        // generic "The operation couldn't be completed. (NSURLErrorDomain error -999.)" for
        // NSURLErrorCancelled, not the word "cancelled". Match the code and the word.
        let m = message.trimmingCharacters(in: .whitespaces).lowercased()
        return m == "cancelled" || m == "canceled" || m.contains("error -999") || m.contains("cancel")
            || m.contains("nsurlerrordomain error -999")
    }

    /// A semantic HTTP-level answer (400/403/404/409...) proves the gateway is reachable.
    static func isGatewayAnswer(_ error: Error) -> Bool {
        guard let e = error as? EngineError else { return false }
        switch e.kind {
        case .invalidParams, .notFound, .conflict, .locked, .permissionDenied: return true
        default: return false
        }
    }

    /// Short and secret-free: strip URLs/tokens-looking text, collapse whitespace, cap length.
    static func sanitize(_ raw: String) -> String {
        var text = raw.replacingOccurrences(of: "https?://\\S+", with: "<url>", options: .regularExpression)
        text = text.replacingOccurrences(of: "(?i)(bearer|token|key|secret|signature|x-amz-[a-z-]*)[=: ]+\\S+", with: "$1=<redacted>", options: .regularExpression)
        text = text.replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
        return String(text.prefix(120))
    }
}

/// Observes every gateway call and forwards it unchanged. Every protocol requirement is
/// forwarded explicitly (never left to a protocol-extension default) so the wrapped
/// client's own overrides — batching, leases, streams — keep their behavior.
struct ReachabilityGateway: GatewayClient {
    let base: any GatewayClient
    let tracker: GatewayReachabilityTracker
    func offlineIdentity(filespace: FilespaceID) async -> String? { await base.offlineIdentity(filespace: filespace) }
    var supportsChangeNotifications: Bool { base.supportsChangeNotifications }
    func changeHints(filespace: FilespaceID) async throws -> AsyncThrowingStream<GatewayChangeHint, Error> {
        try await base.changeHints(filespace: filespace)
    }
    func changePage(filespace: FilespaceID, since: Int?) async throws -> GatewayChangePage {
        try await track(filespace) { try await base.changePage(filespace: filespace, since: since) }
    }
    func changeCheckpoint(filespace: FilespaceID) async throws -> GatewayChangeCheckpoint {
        try await track(filespace) { try await base.changeCheckpoint(filespace: filespace) }
    }

    @inline(__always)
    private func track<T>(_ fs: FilespaceID, latency: Bool = true, _ op: () async throws -> T) async throws -> T {
        let start = DispatchTime.now().uptimeNanoseconds
        do {
            let value = try await op()
            let ms = Double(DispatchTime.now().uptimeNanoseconds &- start) / 1_000_000
            tracker.recordSuccess(fs, latencyMs: latency ? ms : nil)
            return value
        } catch {
            // A cancelled request says nothing about the gateway (read-ahead cancel, flush timeout).
            if Task.isCancelled {
                // record nothing
            } else if let reason = GatewayReachabilityTracker.failureReason(for: error) {
                tracker.recordFailure(fs, reason: reason)
            } else if GatewayReachabilityTracker.isGatewayAnswer(error) {
                tracker.recordSuccess(fs, latencyMs: nil)   // semantic error: the gateway answered
            }
            throw error
        }
    }

    func snapshotStreams(filespace: FilespaceID, snapshotID: String, id: InodeID) async throws -> [StreamInfo] {
        try await track(filespace) { try await base.snapshotStreams(filespace: filespace, snapshotID: snapshotID, id: id) }
    }
    func snapshotStream(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String) async throws -> Data {
        try await track(filespace, latency: false) { try await base.snapshotStream(filespace: filespace, snapshotID: snapshotID, id: id, name: name) }
    }
    func snapshotMountInfo(filespace: FilespaceID, snapshotID: String) async throws -> SnapshotGatewayInfo {
        try await track(filespace) { try await base.snapshotMountInfo(filespace: filespace, snapshotID: snapshotID) }
    }
    func snapshotItem(filespace: FilespaceID, snapshotID: String, id: InodeID) async throws -> ItemMetadata {
        try await track(filespace) { try await base.snapshotItem(filespace: filespace, snapshotID: snapshotID, id: id) }
    }
    func snapshotItems(filespace: FilespaceID, snapshotID: String, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) {
        try await track(filespace) { try await base.snapshotItems(filespace: filespace, snapshotID: snapshotID, parent: parent, cursor: cursor) }
    }
    func snapshotManifest(filespace: FilespaceID, snapshotID: String, itemID: InodeID) async throws -> ResolvedBlockManifest {
        try await track(filespace) { try await base.snapshotManifest(filespace: filespace, snapshotID: snapshotID, itemID: itemID) }
    }
    func snapshotPresign(filespace: FilespaceID, snapshotID: String, itemID: InodeID, keys: [String]) async throws -> [PresignBatchResult] {
        try await track(filespace) { try await base.snapshotPresign(filespace: filespace, snapshotID: snapshotID, itemID: itemID, keys: keys) }
    }

    var supportsRangeLocks: Bool { base.supportsRangeLocks }
    func releaseReadPermit(filespace: FilespaceID, id: InodeID, handle: String, fence: Int) async throws {
        try await track(filespace) { try await base.releaseReadPermit(filespace:filespace,id:id,handle:handle,fence:fence) }
    }
    func acquireRanges(filespace: FilespaceID, id: InodeID, handle: String, ranges: [FileLockRange], fence: Int?, ttlMs: Int) async throws -> FileLease {
        try await track(filespace) { try await base.acquireRanges(filespace:filespace,id:id,handle:handle,ranges:ranges,fence:fence,ttlMs:ttlMs) }
    }
    func renewRanges(filespace: FilespaceID, id: InodeID, handle: String, fence: Int, ttlMs: Int) async throws -> FileLease {
        try await track(filespace) { try await base.renewRanges(filespace:filespace,id:id,handle:handle,fence:fence,ttlMs:ttlMs) }
    }
    func releaseRanges(filespace: FilespaceID, id: InodeID, handle: String, fence: Int, ranges: [FileLockRange]?) async throws {
        try await track(filespace) { try await base.releaseRanges(filespace:filespace,id:id,handle:handle,fence:fence,ranges:ranges) }
    }
    func checkRangeAccess(filespace: FilespaceID, id: InodeID, handle: String, range: FileLockRange, fence: Int?) async throws -> RangeAccess {
        try await track(filespace) { try await base.checkRangeAccess(filespace:filespace,id:id,handle:handle,range:range,fence:fence) }
    }

    var supportsOpenHandles: Bool { base.supportsOpenHandles }
    func directorySnapshot(filespace: FilespaceID, id: InodeID, handle: String,
                           access: OpenFileAccess, sharing: OpenFileSharing) async throws -> DirectorySnapshot? {
        try await track(filespace) {
            try await base.directorySnapshot(filespace: filespace, id: id, handle: handle,
                                             access: access, sharing: sharing)
        }
    }
    func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String,
                           access: OpenFileAccess, sharing: OpenFileSharing, ttlMs: Int) async throws -> OpenHandleLease {
        try await track(filespace) {
            try await base.acquireOpenHandle(filespace:filespace,id:id,handle:handle,access:access,sharing:sharing,ttlMs:ttlMs)
        }
    }
    func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String,
                           access: OpenFileAccess, sharing: OpenFileSharing, ttlMs: Int,
                           stream: OpenHandleStreamRequest?) async throws -> OpenHandleLease {
        try await track(filespace) {
            try await base.acquireOpenHandle(filespace:filespace,id:id,handle:handle,access:access,
                                             sharing:sharing,ttlMs:ttlMs,stream:stream)
        }
    }
    func renewOpenHandle(filespace: FilespaceID, handle: String, ttlMs: Int) async throws -> OpenHandleLease {
        try await track(filespace) { try await base.renewOpenHandle(filespace:filespace,handle:handle,ttlMs:ttlMs) }
    }
    func renewOpenHandles(filespace: FilespaceID, handles: [String], ttlMs: Int) async throws -> [OpenHandleRenewal] {
        try await track(filespace) { try await base.renewOpenHandles(filespace:filespace,handles:handles,ttlMs:ttlMs) }
    }
    func closeOpenHandle(filespace: FilespaceID, handle: String) async throws {
        try await track(filespace) { try await base.closeOpenHandle(filespace:filespace,handle:handle) }
    }

    var supportsFileLeases: Bool { base.supportsFileLeases }
    func acquireFileLease(filespace: FilespaceID, id: InodeID, ttlMs: Int, purpose: FileLeasePurpose) async throws -> FileLease {
        try await track(filespace) { try await base.acquireFileLease(filespace: filespace, id: id, ttlMs: ttlMs, purpose: purpose) }
    }
    func acquireFileLease(filespace: FilespaceID, id: InodeID, ttlMs: Int,
                          purpose: FileLeasePurpose, includeItem: Bool) async throws -> FileLease {
        try await track(filespace) {
            try await base.acquireFileLease(filespace: filespace, id: id, ttlMs: ttlMs,
                                            purpose: purpose, includeItem: includeItem)
        }
    }
    func renewFileLease(filespace: FilespaceID, id: InodeID, fence: Int, ttlMs: Int) async throws -> FileLease {
        try await track(filespace) { try await base.renewFileLease(filespace: filespace, id: id, fence: fence, ttlMs: ttlMs) }
    }
    func releaseFileLease(filespace: FilespaceID, id: InodeID, fence: Int) async throws {
        try await track(filespace) { try await base.releaseFileLease(filespace: filespace, id: id, fence: fence) }
    }

    func authorizeWrite(filespace: FilespaceID, id: InodeID) async throws {
        try await track(filespace) { try await base.authorizeWrite(filespace: filespace, id: id) }
    }
    func mountRoots(filespace: FilespaceID) async throws -> [FilespaceMountRoot] {
        try await track(filespace) { try await base.mountRoots(filespace: filespace) }
    }
    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL {
        try await track(filespace) { try await base.presign(filespace: filespace, key: key, method: method, expiresIn: expiresIn) }
    }
    func presignBatch(filespace: FilespaceID, keys: [(key: String, method: PresignMethod)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        try await track(filespace) { try await base.presignBatch(filespace: filespace, keys: keys, expiresIn: expiresIn) }
    }
    func presignWriteBatch(filespace: FilespaceID, keys: [(key: String, itemID: InodeID)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        try await track(filespace) { try await base.presignWriteBatch(filespace: filespace, keys: keys, expiresIn: expiresIn) }
    }
    func presignWrite(filespace: FilespaceID, key: String, itemID: InodeID, expiresIn: Int?) async throws -> PresignedURL {
        try await track(filespace) { try await base.presignWrite(filespace: filespace, key: key, itemID: itemID, expiresIn: expiresIn) }
    }
    func verifyUploadedBlocks(filespace: FilespaceID, itemID: InodeID, blocks: [UploadedBlockVerification]) async throws {
        try await track(filespace, latency: false) { try await base.verifyUploadedBlocks(filespace: filespace, itemID: itemID, blocks: blocks) }
    }
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest {
        try await track(filespace) { try await base.getBlockManifest(filespace: filespace, itemID: itemID) }
    }
    func getResolvedBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> ResolvedBlockManifest {
        try await track(filespace) { try await base.getResolvedBlockManifest(filespace: filespace, itemID: itemID) }
    }
    var supportsManifestRanges: Bool { base.supportsManifestRanges }
    func getBlockRange(filespace: FilespaceID, itemID: InodeID, contentVersion: String, offset: Int, length: Int) async throws -> ResolvedBlockRange {
        try await track(filespace) { try await base.getBlockRange(filespace: filespace, itemID: itemID, contentVersion: contentVersion, offset: offset, length: length) }
    }
    func uploadObjectKey(filespace: FilespaceID, blockHash: BlockHash) async -> String {
        await base.uploadObjectKey(filespace: filespace, blockHash: blockHash)
    }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, base prior: ResolvedBlockManifest?, blockSize: Int, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata {
        try await track(filespace) { try await base.putBlockManifest(manifest, filespace: filespace, base: prior, blockSize: blockSize, expectedVersion: expectedVersion, fence: fence) }
    }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata {
        try await track(filespace) { try await base.putBlockManifest(manifest, filespace: filespace, etag: etag) }
    }
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata {
        try await track(filespace) { try await base.putBlockManifest(manifest, filespace: filespace, expectedVersion: expectedVersion, fence: fence) }
    }
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata {
        try await track(filespace) { try await base.createItem(filespace: filespace, parent: parent, name: name, isDir: isDir, size: size) }
    }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws {
        try await track(filespace) { try await base.deleteItem(filespace: filespace, id: id, recursive: recursive) }
    }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool, openHandle: String?) async throws {
        try await track(filespace) {
            try await base.deleteItem(filespace:filespace,id:id,recursive:recursive,openHandle:openHandle)
        }
    }
    func setBasicInfo(filespace: FilespaceID, id: InodeID, info: BasicFileInfo, expectedVersion: Int, fence: Int?) async throws -> ItemMetadata {
        try await track(filespace) { try await base.setBasicInfo(filespace: filespace, id: id, info: info, expectedVersion: expectedVersion, fence: fence) }
    }
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata {
        try await track(filespace) { try await base.renameItem(filespace: filespace, id: id, newParent: newParent, newName: newName) }
    }
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String, expectedVersion: Int, replacing: ItemMetadata?) async throws -> ItemMetadata {
        try await track(filespace) { try await base.renameItem(filespace: filespace, id: id, newParent: newParent, newName: newName, expectedVersion: expectedVersion, replacing: replacing) }
    }
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String,
                    expectedVersion: Int, replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata {
        try await track(filespace) {
            try await base.renameItem(filespace:filespace,id:id,newParent:newParent,newName:newName,
                                      expectedVersion:expectedVersion,replacing:replacing,openHandle:openHandle)
        }
    }
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) {
        try await track(filespace) { try await base.listItems(filespace: filespace, parent: parent, cursor: cursor) }
    }
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata {
        try await track(filespace) { try await base.getItem(filespace: filespace, id: id) }
    }
    func streamManifest(filespace: FilespaceID, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        try await track(filespace) { try await base.streamManifest(filespace: filespace, id: id, name: name, offset: offset, length: length) }
    }
    func updateStreamManifest(filespace: FilespaceID, id: InodeID, name: String, update: StreamManifestUpdate) async throws -> StreamManifest {
        try await track(filespace) { try await base.updateStreamManifest(filespace: filespace, id: id, name: name, update: update) }
    }
    func snapshotStreamManifest(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest {
        try await track(filespace) { try await base.snapshotStreamManifest(filespace: filespace, snapshotID: snapshotID, id: id, name: name, offset: offset, length: length) }
    }
    func listStreams(filespace: FilespaceID, id: InodeID) async throws -> [StreamInfo] {
        try await track(filespace) { try await base.listStreams(filespace: filespace, id: id) }
    }
    func readStream(filespace: FilespaceID, id: InodeID, name: String) async throws -> Data {
        try await track(filespace, latency: false) { try await base.readStream(filespace: filespace, id: id, name: name) }
    }
    func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int) async throws {
        try await track(filespace, latency: false) { try await base.writeStream(filespace: filespace, id: id, name: name, data: data, plaintextSize: plaintextSize) }
    }
    func deleteStream(filespace: FilespaceID, id: InodeID, name: String) async throws {
        try await track(filespace) { try await base.deleteStream(filespace: filespace, id: id, name: name) }
    }
    func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int, fence: Int?) async throws {
        try await track(filespace, latency: false) { try await base.writeStream(filespace: filespace, id: id, name: name, data: data, plaintextSize: plaintextSize, fence: fence) }
    }
    func deleteStream(filespace: FilespaceID, id: InodeID, name: String, fence: Int?) async throws {
        try await track(filespace) { try await base.deleteStream(filespace: filespace, id: id, name: name, fence: fence) }
    }
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) {
        try await track(filespace) { try await base.changes(filespace: filespace, since: since) }
    }
    func changesWithDeletions(filespace: FilespaceID, since: Int?) async throws
        -> (anchor: Int, updated: [ItemMetadata], deleted: [InodeID], cursor: Int?) {
        try await track(filespace) { try await base.changesWithDeletions(filespace: filespace, since: since) }
    }
    func fetchMasterKeyEnvelope(filespace: FilespaceID) async throws -> FilespaceKeyEnvelope {
        try await track(filespace) { try await base.fetchMasterKeyEnvelope(filespace: filespace) }
    }
}
