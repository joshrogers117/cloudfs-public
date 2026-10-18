// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSGateway — HTTP client to the gateway (backend/API.md). (DESIGN.md §4, §6)
//
// Owner (next round): GATEWAY. cloudfsd is a CLIENT of the same gateway the
// macOS app + CLI use. This client mints presigned URLs (POST .../presign — the
// enforcement gate; key under blocks/<org>::<fs>/, TTL clamp [60,900]s,
// GET/HEAD/PUT only), reads/writes block maps (.../blocks/:itemId), enumerates
// the namespace (.../items), drives resumable uploads (.../uploads), and tails
// the change feed (.../changes). Bytes NEVER transit the gateway — presigned-URL
// range GETs / part PUTs go direct to R2/S3. Keeps a warm pre-minted URL pool +
// token refresh.

import Foundation
import CryptoKit

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

import CloudFSCore

/// HTTP method allowed for a presign (backend/API.md §presign).
public enum PresignMethod: String, Sendable, Codable { case GET, HEAD, PUT }

public struct PresignedURL: Sendable, Codable, Equatable {
    public var url: String
    public var expiresIn: Int   // seconds
    public var headers: [String: String]?
    public var verificationUrl: String?
    public init(url: String, expiresIn: Int, headers: [String: String]? = nil, verificationUrl: String? = nil) {
        self.url = url; self.expiresIn = expiresIn; self.headers = headers; self.verificationUrl = verificationUrl
    }
}

/// Exact identity of an already uploaded immutable ciphertext object. This is
/// optional verification metadata, never a file manifest or a durability receipt.
public struct UploadedBlockVerification: Sendable, Codable, Hashable {
    public let objectKey: String
    public let blockHash: String
    public let length: Int
    public init(objectKey: String, blockHash: String, length: Int) {
        self.objectKey = objectKey; self.blockHash = blockHash; self.length = length
    }
}

/// One entry in a batch-presign response (Audit B23). `url` is nil when the gateway refused that
/// specific key (e.g. ACL-forbidden / not-in-namespace), with `error` carrying the gateway's reason.
public struct PresignBatchResult: Sendable, Equatable {
    public var key: String
    public var url: String?
    public var error: String?
    public var headers: [String: String]?
    public var verificationUrl: String?
    public init(key: String, url: String?, error: String?, headers: [String: String]? = nil, verificationUrl: String? = nil) {
        self.key = key; self.url = url; self.error = error; self.headers = headers; self.verificationUrl = verificationUrl
    }
}

/// A `BlockManifest` paired with the gateway's AUTHORITATIVE per-block object keys.
///
/// The gateway/store owns the object-key scheme (backend/API.md §blocks: each block
/// carries an `objectKey`, e.g. `blocks/<org>::<fs>/…`). The engine MUST presign +
/// range-GET that exact key — it must NOT reconstruct a key client-side (the
/// `chunks/<shard>/<hash>` form on `BlockHash.objectKey` is the on-disk CACHE key, a
/// content address; it is NOT necessarily the bucket key). `objectKeys[hash]` is the
/// key to presign for block `hash`. Stays out of the frozen `CloudFSCore.BlockRef`
/// (which cannot grow a field without a contract bump) by carrying the mapping here.
public struct ResolvedBlockManifest: Sendable {
    public let manifest: BlockManifest
    /// blockHash → the gateway's object key for that block (what presign/GET targets).
    public let objectKeys: [BlockHash: String]
    /// Absolute encryption index of the first block in a bounded read slice.
    /// Complete manifests used for publication/recovery always start at zero.
    public let firstBlockIndex: Int
    public init(manifest: BlockManifest, objectKeys: [BlockHash: String], firstBlockIndex: Int = 0) {
        self.manifest = manifest; self.objectKeys = objectKeys; self.firstBlockIndex = firstBlockIndex
    }
    /// The object key to presign for `hash`. Falls back to the content-address form
    /// (`hash.objectKey`) only if the gateway did not supply one (legacy/stub).
    public func objectKey(for hash: BlockHash) -> String {
        objectKeys[hash] ?? hash.objectKey
    }
}

public struct ResolvedBlockRange: Sendable {
    public let item: ItemMetadata
    public let resolved: ResolvedBlockManifest
    public init(item: ItemMetadata, resolved: ResolvedBlockManifest) { self.item = item; self.resolved = resolved }
    public var start: Int { resolved.manifest.blocks.first?.offset ?? item.size }
    public var end: Int { resolved.manifest.blocks.last.map { $0.offset + $0.length } ?? item.size }
}

/// The OPAQUE wrapped-key envelope the gateway serves (ONBOARDING.md "Key model",
/// backend/API.md §key: `GET /v1/filespaces/:fs/key`). `format` is a closed-but-extensible tag
/// the caller MUST switch on and reject if unrecognized — this is the forward-compatibility seam
/// that lets a later zero-knowledge mode (per-device-wrapped blobs) slot in without a protocol
/// break. Never log/print `material` — it IS the filespace's decryption key.
public struct FilespaceKeyEnvelope: Sendable, Codable, Equatable {
    public var keyId: String
    public var format: String
    /// Present for `format == "plain-v1"`: base64, 32 raw AES-256 key bytes. A future wrapped
    /// format would carry its own payload field(s) here instead/in addition.
    public var material: String?
    public init(keyId: String, format: String, material: String?) {
        self.keyId = keyId; self.format = format; self.material = material
    }
}

public struct FilespaceMountRoot: Sendable, Codable, Equatable {
    public let id: String
    public let name: String
    public let mountAsRoot: Bool
    public init(id: String, name: String, mountAsRoot: Bool) {
        self.id = id; self.name = name; self.mountAsRoot = mountAsRoot
    }
}

/// Whole-inode lease. The fence must accompany every manifest commit.
public enum FileLeasePurpose: String, Sendable, Codable {
    case advisory
    case publication
}

public struct FileLease: Sendable, Codable, Equatable {
    public let granted: Bool
    public let path: String
    public let fence: Int?
    public let expiresAt: Double?
    public let heldBy: String?
    public let reason: String?
    public let purpose: FileLeasePurpose?
    /// Present only on an opt-in publication lease acquisition. The gateway
    /// supplies the regular Item wire shape, which HttpGatewayClient projects.
    public let item: ItemMetadata?
    public init(granted: Bool, path: String, fence: Int? = nil, expiresAt: Double? = nil,
                heldBy: String? = nil, reason: String? = nil, purpose: FileLeasePurpose? = nil,
                item: ItemMetadata? = nil) {
        self.granted = granted; self.path = path; self.fence = fence
        self.expiresAt = expiresAt; self.heldBy = heldBy; self.reason = reason; self.purpose = purpose
        self.item = item
    }
}

public protocol GatewayClient: Sendable {
    var supportsOpenHandles: Bool { get }
    func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String, access: OpenFileAccess, sharing: OpenFileSharing, ttlMs: Int) async throws -> OpenHandleLease
    func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String,
                           access: OpenFileAccess, sharing: OpenFileSharing, ttlMs: Int,
                           stream: OpenHandleStreamRequest?) async throws -> OpenHandleLease
    func renewOpenHandle(filespace: FilespaceID, handle: String, ttlMs: Int) async throws -> OpenHandleLease
    func renewOpenHandles(filespace: FilespaceID, handles: [String], ttlMs: Int) async throws -> [OpenHandleRenewal]
    func closeOpenHandle(filespace: FilespaceID, handle: String) async throws
    func directorySnapshot(filespace: FilespaceID, id: InodeID, handle: String,
                           access: OpenFileAccess, sharing: OpenFileSharing) async throws -> DirectorySnapshot?
    var supportsManifestRanges: Bool { get }
    func getBlockRange(filespace: FilespaceID, itemID: InodeID, contentVersion: String, offset: Int, length: Int) async throws -> ResolvedBlockRange
    func snapshotStreams(filespace: FilespaceID, snapshotID: String, id: InodeID) async throws -> [StreamInfo]
    func snapshotStream(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String) async throws -> Data
    func snapshotMountInfo(filespace: FilespaceID, snapshotID: String) async throws -> SnapshotGatewayInfo
    func snapshotItem(filespace: FilespaceID, snapshotID: String, id: InodeID) async throws -> ItemMetadata
    func snapshotItems(filespace: FilespaceID, snapshotID: String, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?)
    func snapshotManifest(filespace: FilespaceID, snapshotID: String, itemID: InodeID) async throws -> ResolvedBlockManifest
    func snapshotPresign(filespace: FilespaceID, snapshotID: String, itemID: InodeID, keys: [String]) async throws -> [PresignBatchResult]

    var supportsRangeLocks: Bool { get }
    func releaseReadPermit(filespace: FilespaceID, id: InodeID, handle: String, fence: Int) async throws
    func acquireRanges(filespace: FilespaceID, id: InodeID, handle: String, ranges: [FileLockRange], fence: Int?, ttlMs: Int) async throws -> FileLease
    func renewRanges(filespace: FilespaceID, id: InodeID, handle: String, fence: Int, ttlMs: Int) async throws -> FileLease
    func releaseRanges(filespace: FilespaceID, id: InodeID, handle: String, fence: Int, ranges: [FileLockRange]?) async throws
    func checkRangeAccess(filespace: FilespaceID, id: InodeID, handle: String, range: FileLockRange, fence: Int?) async throws -> RangeAccess

    var supportsFileLeases: Bool { get }
    func acquireFileLease(filespace: FilespaceID, id: InodeID, ttlMs: Int, purpose: FileLeasePurpose) async throws -> FileLease
    func acquireFileLease(filespace: FilespaceID, id: InodeID, ttlMs: Int, purpose: FileLeasePurpose,
                          includeItem: Bool) async throws -> FileLease
    func renewFileLease(filespace: FilespaceID, id: InodeID, fence: Int, ttlMs: Int) async throws -> FileLease
    func releaseFileLease(filespace: FilespaceID, id: InodeID, fence: Int) async throws

    func authorizeWrite(filespace: FilespaceID, id: InodeID) async throws
    func mountRoots(filespace: FilespaceID) async throws -> [FilespaceMountRoot]
    // presign — the enforcement gate (backend/API.md §presign)
    func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL
    /// Audit B23 — BATCH presign: mint many keys in ONE request (a multi-block read or a large copy
    /// shouldn't be N round-trips). Returns the per-key result in input order; a per-key failure is
    /// reported as `url == nil` (with the gateway's error string) rather than throwing the whole batch.
    /// Default impl falls back to N sequential single presigns so existing conformers keep working;
    /// `HttpGatewayClient` overrides it to hit `POST …/presign/batch`.
    func presignBatch(filespace: FilespaceID, keys: [(key: String, method: PresignMethod)], expiresIn: Int?) async throws -> [PresignBatchResult]
    /// Attribute a new encrypted object to an authorized inode before it is in a manifest.
    func presignWriteBatch(filespace: FilespaceID, keys: [(key: String, itemID: InodeID)], expiresIn: Int?) async throws -> [PresignBatchResult]
    func presignWrite(filespace: FilespaceID, key: String, itemID: InodeID, expiresIn: Int?) async throws -> PresignedURL
    /// Optional overlap of provider integrity verification with subsequent PUTs.
    /// The final manifest commit independently enforces every durability check.
    func verifyUploadedBlocks(filespace: FilespaceID, itemID: InodeID, blocks: [UploadedBlockVerification]) async throws
    // block map (backend/API.md §blocks)
    func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest
    /// Like `getBlockManifest`, but ALSO returns the gateway's authoritative per-block
    /// object keys so the engine presigns the exact bucket key (not a client-built one).
    /// Default impl pairs `getBlockManifest` with the content-address key fallback, so
    /// existing conformers keep working; the real `HttpGatewayClient` overrides it to
    /// surface the gateway's `objectKey`.
    func getResolvedBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> ResolvedBlockManifest
    /// The bucket object key under which a NEWLY-written block must be uploaded +
    /// recorded in the manifest. The store/gateway own the scheme (`blocks/<org>::<fs>/<hash>`,
    /// backend/API.md §presign confinement), so the engine MUST mint the key the
    /// gateway will accept on presign-PUT — not the content-address cache key
    /// (`chunks/<shard>/<hash>`, which the presign confinement 403s). Default returns
    /// the content-address key (stubs/tests); `HttpGatewayClient` overrides it.
    func uploadObjectKey(filespace: FilespaceID, blockHash: BlockHash) async -> String
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata
    /// Commit a block map with optimistic concurrency / lock context (audit B4/B5).
    /// `expectedVersion` is the version the write was based on (CAS); the gateway
    /// returns 409 (→ `EngineError.conflict`) on mismatch. `fence` is the writer's
    /// lease fence when it holds one. Default impl forwards to `putBlockManifest` so
    /// existing conformers keep compiling.
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID,
                          expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, base: ResolvedBlockManifest?,
                          blockSize: Int, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata
    // namespace (backend/API.md §items)
    /// Create a namespace item (file or directory) BEFORE staging bytes (audit B1):
    /// `POST /v1/filespaces/:fs/items {parent,name,isDir,size}`. Returns the Item the
    /// gateway minted — crucially its `id` ("root/…"), which the engine MUST adopt as
    /// the inode id for staging, ENCRYPTION (the GCM key/nonce is HKDF-bound to the
    /// itemID — a wrong id yields blocks no other client can decrypt), and the commit.
    func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata
    /// Delete a namespace item: `DELETE /v1/filespaces/:fs/items/:id`.
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool, openHandle: String?) async throws
    /// Rename/move a namespace item (audit B17): `PATCH /v1/filespaces/:fs/items/:id {parent?, name?}`.
    /// Opaque ids make this a single-row metadata update — the item's id is STABLE across the
    /// rename (so its GCM-bound blocks stay decryptable), only `(parent, name)` change. Returns the
    /// updated Item. `newParent == nil` keeps the current parent (a pure rename).
    func setBasicInfo(filespace: FilespaceID, id: InodeID, info: BasicFileInfo, expectedVersion: Int, fence: Int?) async throws -> ItemMetadata
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String, expectedVersion: Int, replacing: ItemMetadata?) async throws -> ItemMetadata
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String, expectedVersion: Int, replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata
    func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?)
    func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata
    // P4 — named streams (SMB xattrs). Blobs are pre-encrypted by the engine adapter.
    func streamManifest(filespace: FilespaceID, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest
    func updateStreamManifest(filespace: FilespaceID, id: InodeID, name: String, update: StreamManifestUpdate) async throws -> StreamManifest
    func snapshotStreamManifest(filespace: FilespaceID, snapshotID: String, id: InodeID, name: String, offset: Int, length: Int) async throws -> StreamManifest
    func listStreams(filespace: FilespaceID, id: InodeID) async throws -> [StreamInfo]
    func readStream(filespace: FilespaceID, id: InodeID, name: String) async throws -> Data
    /// `data` is the CIPHERTEXT to store; `plaintextSize` is the decrypted byte
    /// length the backend records as the stream's logical size (so the mount reports
    /// the real size without decrypting on every stat).
    func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int) async throws
    func deleteStream(filespace: FilespaceID, id: InodeID, name: String) async throws
    func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int, fence: Int?) async throws
    func deleteStream(filespace: FilespaceID, id: InodeID, name: String, fence: Int?) async throws
    // change feed (backend/API.md §changes) — keyset `since` cursor
    func offlineIdentity(filespace: FilespaceID) async -> String?
    var supportsChangeNotifications: Bool { get }
    func changeHints(filespace: FilespaceID) async throws -> AsyncThrowingStream<GatewayChangeHint, Error>
    func changePage(filespace: FilespaceID, since: Int?) async throws -> GatewayChangePage
    func changeCheckpoint(filespace: FilespaceID) async throws -> GatewayChangeCheckpoint
    func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?)
    /// Like `changes`, but separates tombstones (audit: the daemon used to project
    /// `deleted` out, so a consumer resurrected every deleted item and deletions
    /// never propagated). `updated` carries live upserts; `deleted` carries the ids of
    /// tombstoned items. Default impl forwards to `changes` with no deletions, so a
    /// conformer that doesn't distinguish keeps compiling.
    func changesWithDeletions(filespace: FilespaceID, since: Int?) async throws
        -> (anchor: Int, updated: [ItemMetadata], deleted: [InodeID], cursor: Int?)
    /// ONBOARDING.md "Key model" — fetch this filespace's server-held master-key envelope
    /// (`GET /v1/filespaces/:fs/key`, backend/API.md §key). Called by `FilespaceKeyResolver`
    /// (Daemon.swift) ONLY when neither matching deployment-scoped local source
    /// (Keychain / gateway-and-filespace-bound `--key-file`) has the key.
    /// Default impl throws `.unimplemented()` so stub/dev conformers (`LocalDevGateway`, test
    /// doubles) that don't back this keep compiling; `HttpGatewayClient` overrides it for real.
    func fetchMasterKeyEnvelope(filespace: FilespaceID) async throws -> FilespaceKeyEnvelope
}

public extension GatewayClient {
    func directorySnapshot(filespace: FilespaceID, id: InodeID, handle: String,
                           access: OpenFileAccess, sharing: OpenFileSharing) async throws -> DirectorySnapshot? { nil }
    var supportsManifestRanges: Bool { false }
    func getBlockRange(filespace: FilespaceID, itemID: InodeID, contentVersion: String, offset: Int, length: Int) async throws -> ResolvedBlockRange { throw EngineError.unimplemented() }
    func offlineIdentity(filespace: FilespaceID) async -> String? { nil }
    var supportsChangeNotifications: Bool { false }
    func changeHints(filespace: FilespaceID) async throws -> AsyncThrowingStream<GatewayChangeHint, Error> { throw EngineError.unimplemented() }
    func changePage(filespace: FilespaceID, since: Int?) async throws -> GatewayChangePage {
        let page = try await changesWithDeletions(filespace: filespace, since: since)
        return GatewayChangePage(anchor: page.anchor, updated: page.updated, deleted: page.deleted, cursor: page.cursor, visibility: nil)
    }
    func changeCheckpoint(filespace: FilespaceID) async throws -> GatewayChangeCheckpoint {
        try Task.checkCancellation()
        let page = try await changePage(filespace: filespace, since: nil)
        try Task.checkCancellation()
        guard page.anchor >= 0 else { throw EngineError(.gatewayError, "Invalid notification checkpoint") }
        return GatewayChangeCheckpoint(anchor: page.anchor, visibility: page.visibility)
    }

    func verifyUploadedBlocks(filespace: FilespaceID, itemID: InodeID, blocks: [UploadedBlockVerification]) async throws {
        throw EngineError(.unimplemented, "Background object verification is unavailable")
    }
    func presignWriteBatch(filespace: FilespaceID, keys: [(key: String, itemID: InodeID)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        throw EngineError(.unimplemented, "Write batch presigning is unavailable")
    }
    func presignWrite(filespace: FilespaceID, key: String, itemID: InodeID, expiresIn: Int?) async throws -> PresignedURL {
        try await presign(filespace: filespace, key: key, method: .PUT, expiresIn: expiresIn)
    }
    func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int, fence: Int?) async throws {
        try await writeStream(filespace: filespace, id: id, name: name, data: data, plaintextSize: plaintextSize)
    }
    func deleteStream(filespace: FilespaceID, id: InodeID, name: String, fence: Int?) async throws {
        try await deleteStream(filespace: filespace, id: id, name: name)
    }
    var supportsFileLeases: Bool { false } // isolated in-memory/local test gateways only
    func acquireFileLease(filespace: FilespaceID, id: InodeID, ttlMs: Int, purpose: FileLeasePurpose) async throws -> FileLease {
        throw EngineError(.unimplemented, "File leases are unavailable")
    }
    func acquireFileLease(filespace: FilespaceID, id: InodeID, ttlMs: Int, purpose: FileLeasePurpose,
                          includeItem: Bool) async throws -> FileLease {
        try await acquireFileLease(filespace: filespace, id: id, ttlMs: ttlMs, purpose: purpose)
    }
    func renewFileLease(filespace: FilespaceID, id: InodeID, fence: Int, ttlMs: Int) async throws -> FileLease {
        throw EngineError(.unimplemented, "File leases are unavailable")
    }
    func releaseFileLease(filespace: FilespaceID, id: InodeID, fence: Int) async throws {
        throw EngineError(.unimplemented, "File leases are unavailable")
    }

    func authorizeWrite(filespace: FilespaceID, id: InodeID) async throws {
        throw EngineError(.unimplemented, "Write authorization is unavailable")
    }

    func mountRoots(filespace: FilespaceID) async throws -> [FilespaceMountRoot] {
        [FilespaceMountRoot(id: "root", name: filespace, mountAsRoot: true)]
    }

    /// Default: derive the resolved manifest from `getBlockManifest`, mapping each
    /// block to the content-address key. Conformers that know the gateway's object
    /// keys (the real `HttpGatewayClient`) override this to thread the true key.
    func getResolvedBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> ResolvedBlockManifest {
        let manifest = try await getBlockManifest(filespace: filespace, itemID: itemID)
        var keys: [BlockHash: String] = [:]
        for b in manifest.blocks { keys[b.hash] = b.hash.objectKey }
        return ResolvedBlockManifest(manifest: manifest, objectKeys: keys)
    }

    /// Default: the content-address key (stubs/offline). The real gateway client
    /// overrides this with the `blocks/<org>::<fs>/<hash>` scheme the store requires.
    func uploadObjectKey(filespace: FilespaceID, blockHash: BlockHash) async -> String {
        blockHash.objectKey
    }

    /// Default: ignore the CAS/lock context and forward to the plain commit, so a
    /// conformer that hasn't adopted optimistic concurrency keeps working.
    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID,
                          expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata {
        try await putBlockManifest(manifest, filespace: filespace, etag: nil)
    }

    func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, base: ResolvedBlockManifest?,
                          blockSize: Int, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata {
        try await putBlockManifest(manifest, filespace: filespace, expectedVersion: expectedVersion, fence: fence)
    }

    /// Default: no tombstone distinction (every change is an upsert). The real
    /// `HttpGatewayClient` overrides this to split deleted items out.
    func changesWithDeletions(filespace: FilespaceID, since: Int?) async throws
        -> (anchor: Int, updated: [ItemMetadata], deleted: [InodeID], cursor: Int?) {
        let (anchor, items, cursor) = try await changes(filespace: filespace, since: since)
        return (anchor, items, [], cursor)
    }

    /// Default: rename is a real gateway op; a conformer without it (read-only dev/test
    /// gateways) surfaces unimplemented rather than silently succeeding.
    func setBasicInfo(filespace: FilespaceID, id: InodeID, info: BasicFileInfo, expectedVersion: Int, fence: Int?) async throws -> ItemMetadata {
        throw EngineError(.unimplemented, "Basic file metadata updates are unavailable")
    }
    func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool, openHandle: String?) async throws {
        try await deleteItem(filespace:filespace,id:id,recursive:recursive)
    }
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String, expectedVersion: Int, replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata {
        try await renameItem(filespace:filespace,id:id,newParent:newParent,newName:newName,expectedVersion:expectedVersion,replacing:replacing)
    }
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String, expectedVersion: Int, replacing: ItemMetadata?) async throws -> ItemMetadata {
        guard replacing == nil else { throw EngineError(.unimplemented, "Atomic replacement is unavailable") }
        return try await renameItem(filespace: filespace, id: id, newParent: newParent, newName: newName)
    }
    func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata {
        throw EngineError.unimplemented()
    }

    // Default stream impls so non-HTTP conformers (stubs/tests) compile; the real
    // HttpGatewayClient overrides them.
    func listStreams(filespace: FilespaceID, id: InodeID) async throws -> [StreamInfo] { [] }
    func readStream(filespace: FilespaceID, id: InodeID, name: String) async throws -> Data { throw EngineError(.notFound, "no such stream") }
    func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int) async throws { throw EngineError.unimplemented() }
    func deleteStream(filespace: FilespaceID, id: InodeID, name: String) async throws { throw EngineError.unimplemented() }

    /// Default batch presign: fall back to N sequential single presigns (correct, just not batched),
    /// so a conformer that hasn't adopted `/presign/batch` keeps working. The real `HttpGatewayClient`
    /// overrides this with the one-request batch endpoint.
    /// TODO(cloudfsd-batch): the transfer engine's read prefetch + upload paths still mint one URL per
    /// block (RealTransferEngine.fetchBlock / runUpload). Adopting this batch form on a multi-block
    /// read (ensureRange spanning several cache-miss blocks) would cut the per-op presign fan-out from
    /// N to 1 and charge one combined rate-limit consume. Deferred here as a focused, separately-
    /// testable engine change so it doesn't perturb the durability/commit path in this pass.
    func presignBatch(filespace: FilespaceID, keys: [(key: String, method: PresignMethod)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        var out: [PresignBatchResult] = []
        out.reserveCapacity(keys.count)
        for k in keys {
            do {
                let signed = try await presign(filespace: filespace, key: k.key, method: k.method, expiresIn: expiresIn)
                out.append(PresignBatchResult(key: k.key, url: signed.url, error: nil, headers: signed.headers, verificationUrl: signed.verificationUrl))
            } catch {
                out.append(PresignBatchResult(key: k.key, url: nil, error: String(describing: error)))
            }
        }
        return out
    }

    /// Default: not backed (dev/stub gateways don't hold a server-side key store). The real
    /// `HttpGatewayClient` overrides this to hit `GET /v1/filespaces/:fs/key`.
    func fetchMasterKeyEnvelope(filespace: FilespaceID) async throws -> FilespaceKeyEnvelope {
        throw EngineError.unimplemented()
    }
}

// MARK: - Configuration

/// Connection settings for the engine's gateway client. The bearer token is
/// supplied by a Sendable provider closure so the engine can refresh it (SSO /
/// service-account rotation, API.md §1) without rebuilding the client.
public struct GatewayClientConfig: Sendable {
    /// Worker origin, e.g. `https://gw.cloudfs.example` or `http://127.0.0.1:8787`.
    public var baseURL: String
    /// Returns the current bearer JWS for `Authorization: Bearer <token>`.
    /// Called per-request so token refresh is transparent.
    public var tokenProvider: @Sendable () async -> String
    /// Default directory-listing page size (API.md §3: default 500, max 2000).
    public var listLimit: Int
    /// Max pages followed by `listItems` internally (loop guard; unused when a
    /// single page is requested by the caller). 0 = single page.
    public var maxListPages: Int

    public init(
        baseURL: String,
        listLimit: Int = 500,
        maxListPages: Int = 0,
        tokenProvider: @escaping @Sendable () async -> String
    ) {
        self.baseURL = baseURL
        self.listLimit = listLimit
        self.maxListPages = maxListPages
        self.tokenProvider = tokenProvider
    }

    /// Convenience for a fixed (non-refreshing) token.
    public init(baseURL: String, token: String, listLimit: Int = 500, maxListPages: Int = 0) {
        self.init(baseURL: baseURL, listLimit: listLimit, maxListPages: maxListPages) { token }
    }
}

// MARK: - HttpGatewayClient

/// The real engine-facing `GatewayClient`: URLSession over the `/v1` routes the
/// engine needs (presign, block maps, items, change feed), `Authorization:
/// Bearer <token>` on every request, JSON bodies, and the `{ error, reason }`
/// envelope decoded into a typed `EngineError` (whose Kind maps 1:1 to the
/// control-plane wire codes + CLI exit codes — CloudFSCore/Errors.swift).
public final class HttpGatewayClient: GatewayClient, Sendable {

    public let config: GatewayClientConfig
    let session: URLSession
    public let clientID: String
    public let supportsChangeNotifications: Bool
    let streamingManifests: Bool
    public var supportsFileLeases: Bool { true }

    public init(config: GatewayClientConfig, session: URLSession = .shared, clientID: UUID = UUID(), changeNotifications: Bool = false, streamingManifests: Bool = false) {
        self.config = config
        self.supportsChangeNotifications = changeNotifications
        self.streamingManifests = streamingManifests
        self.clientID = clientID.uuidString.lowercased()
        self.session = session
    }

    public func directorySnapshot(filespace: FilespaceID, id: InodeID, handle: String,
                                  access: OpenFileAccess, sharing: OpenFileSharing) async throws -> DirectorySnapshot? {
        struct Body: Encodable {
            let action = "directory-snapshot"
            let id: String; let handleId: String; let accessMask: UInt8; let shareMask: UInt8
            let ttlMs = 10_000
        }
        struct Response: Decodable {
            let granted: Bool
            let reason: String?
            let directory: WireItem?
            let items: [WireItem]?
        }
        let body = try JSONEncoder().encode(Body(id: id.rawValue, handleId: handle,
            accessMask: access.rawValue, shareMask: sharing.rawValue))
        let response: Response
        do {
            response = try await sendJSON(Response.self, "POST",
                path: "/v1/filespaces/\(filespace)/open-handles", body: body)
        } catch let error as EngineError where error.kind == .invalidParams &&
            error.data?["status"] == .int(400) && error.data?["error"] == .string("invalid_open_handle") {
            // Older gateways reject the unknown action with their established
            // validation envelope. Do not hide any other malformed request.
            return nil
        }
        guard response.granted else {
            switch response.reason {
            case "snapshot_too_large": return nil
            case "not_found": throw EngineError(.notFound, "Directory was not found")
            case "forbidden": throw EngineError(.permissionDenied, "Directory access was denied")
            case "sharing_violation", "capacity": throw EngineError(.locked, "Directory open conflicts with another open")
            case "handle_conflict": throw EngineError(.conflict, "Directory snapshot handle is already in use")
            case "not_directory": throw EngineError(.invalidParams, "The requested item is not a directory")
            default: throw EngineError(.gatewayError, "Directory snapshot was denied")
            }
        }
        guard let directory = response.directory?.metadata,
              let items = response.items?.map(\.metadata), items.count <= 500 else {
            throw EngineError(.gatewayError, "Invalid bounded directory snapshot response")
        }
        return DirectorySnapshot(directory: directory, items: items)
    }

    // MARK: Request plumbing

    private struct ErrorEnvelope: Decodable {
        let error: String?
        let reason: String?
        let conflict: Bool?
        let locked: Bool?
        let heldBy: String?
        let expected: CodableValue?
        let actual: CodableValue?
    }

    private static let decoder = JSONDecoder()
    private static let encoder = JSONEncoder()

    private static let transientReadStatuses: Set<Int> = [408, 429, 500, 502, 503, 504]
    private static let transientReadURLErrors: Set<URLError.Code> = [
        .timedOut, .cannotFindHost, .cannotConnectToHost, .networkConnectionLost,
        .dnsLookupFailed, .notConnectedToInternet
    ]

    /// Two short backoffs bound a transient read outage without holding a mount
    /// indefinitely. Honor server cooldowns up to one second per retry; an
    /// exhausted request returns its original status/cooldown to the caller.
    static func readRetryDelay(retry: Int, retryAfter: String?, now: Date = Date()) -> Duration {
        let fallback: TimeInterval = retry == 0 ? 0.1 : 0.25
        guard let raw = retryAfter?.trimmingCharacters(in: .whitespacesAndNewlines) else {
            return .seconds(fallback)
        }
        let requested: TimeInterval?
        if let seconds = TimeInterval(raw), seconds.isFinite, seconds >= 0 {
            requested = seconds
        } else {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
            formatter.isLenient = false
            requested = formatter.date(from: raw)?.timeIntervalSince(now)
        }
        return .seconds(max(fallback, min(1, requested ?? fallback)))
    }

    func makeURL(path: String, query: [URLQueryItem]) throws -> URL {
        guard var comps = URLComponents(string: config.baseURL) else {
            throw EngineError(.invalidParams, "invalid gateway base URL: \(config.baseURL)")
        }
        let basePath = comps.path.hasSuffix("/") ? String(comps.path.dropLast()) : comps.path
        // `path` is ALREADY percent-encoded (inode-id segments carry `%2F` for an
        // embedded `/` — see `pathEscape`). Assign via `percentEncodedPath` so the
        // `%2F` is preserved verbatim; the plain `.path` setter would re-encode the
        // `%` to `%25`, double-encoding the segment and mis-routing at the gateway.
        comps.percentEncodedPath = basePath + path
        if !query.isEmpty { comps.queryItems = query }
        guard let url = comps.url else {
            throw EngineError(.invalidParams, "could not build gateway URL for \(path)")
        }
        return url
    }

    /// Issue a request, enforce the success/error envelope, return the raw body.
    func send(
        _ method: String,
        path: String,
        query: [URLQueryItem] = [],
        body: Data? = nil,
        contentType: String = "application/json"
    ) async throws -> Data {
        let url = try makeURL(path: path, query: query)
        let method = method.uppercased()
        // Only transport-level idempotence belongs here. In particular, a POST
        // returning 500 may already have committed and must never be replayed.
        let attempts = (method == "GET" || method == "HEAD") ? 3 : 1
        for attempt in 0..<attempts {
            try Task.checkCancellation()
            var req = URLRequest(url: url)
            req.httpMethod = method
            req.setValue(clientID, forHTTPHeaderField: "X-CloudFS-Client-ID")
            let token = await config.tokenProvider()
            try Task.checkCancellation()
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            if let body {
                req.setValue(contentType, forHTTPHeaderField: "content-type")
                req.httpBody = body
            }

            let data: Data
            let response: URLResponse
            let profileStart = ContinuousClock.now
            var profileStatus = 0
            defer {
                if ProcessInfo.processInfo.environment["CLOUDFS_PROFILE_GATEWAY"] == "1" {
                    // Fixed operation labels only: never URLs, inode IDs, stream
                    // names, credentials, request/response bodies or headers.
                    let parts = path.split(separator: "/")
                    let operation: String
                    if parts.count >= 4, parts[1] == "filespaces" {
                        switch parts[3] {
                        case "items":
                            if parts.count > 5, parts[5] == "streams" { operation = "stream" }
                            else if parts.count > 5 { operation = "item-detail" }
                            else { operation = parts.count > 4 ? "item" : "items" }
                        case "locks", "range-locks", "open-handles", "presign", "changes", "events": operation = String(parts[3])
                        default: operation = "filespace-other"
                        }
                    } else { operation = "other" }
                    let elapsed = profileStart.duration(to: .now).components
                    let ms = Double(elapsed.seconds) * 1000 + Double(elapsed.attoseconds) / 1e15
                    let line = String(format: "cloudfsd[gateway]: time=%.3f method=%@ operation=%@ status=%d elapsedMs=%.1f\n",
                        Date().timeIntervalSince1970, method, operation, profileStatus, ms)
                    FileHandle.standardError.write(Data(line.utf8))
                }
            }
            do {
                (data, response) = try await session.data(for: req)
                profileStatus = (response as? HTTPURLResponse)?.statusCode ?? 0
            } catch {
                if Task.isCancelled || error is CancellationError || (error as? URLError)?.code == .cancelled {
                    throw CancellationError()
                }
                if attempt + 1 < attempts, let urlError = error as? URLError,
                   Self.transientReadURLErrors.contains(urlError.code) {
                    try await Task.sleep(for: Self.readRetryDelay(retry: attempt, retryAfter: nil))
                    continue
                }
                let failure = error as NSError
                throw EngineError(.networkError, error.localizedDescription,
                    data: ["domain": .string(failure.domain), "code": .int(failure.code)])
            }
            try Task.checkCancellation()
            guard let http = response as? HTTPURLResponse else {
                throw EngineError(.networkError, "non-HTTP response from gateway")
            }
            if (200..<300).contains(http.statusCode) { return data }
            if attempt + 1 < attempts, Self.transientReadStatuses.contains(http.statusCode) {
                try await Task.sleep(for: Self.readRetryDelay(retry: attempt,
                    retryAfter: http.value(forHTTPHeaderField: "Retry-After")))
                continue
            }
            throw Self.mapError(status: http.statusCode, body: data, headers: http)
        }
        preconditionFailure("Every gateway request attempt returns or throws")
    }

    func sendJSON<T: Decodable>(
        _ type: T.Type,
        _ method: String,
        path: String,
        query: [URLQueryItem] = [],
        body: Data? = nil
    ) async throws -> T {
        let data = try await send(method, path: path, query: query, body: body)
        do {
            return try Self.decoder.decode(T.self, from: data)
        } catch {
            throw EngineError(.gatewayError, "decoding \(type) from gateway: \(error)")
        }
    }

    // MARK: Error mapping (API.md §2 envelope + status table → EngineError)

    static func mapError(status: Int, body: Data, headers http: HTTPURLResponse) -> EngineError {
        let env = try? decoder.decode(ErrorEnvelope.self, from: body)
        let code = env?.error
        let reason = env?.reason
        // Human detail carried through so the CLI/GUI can surface it.
        let detail = [code, reason].compactMap { $0 }.joined(separator: ": ")
        let message = detail.isEmpty ? "gateway HTTP \(status)" : detail

        var data: [String: CodableValue]? = ["status": .int(status)]
        if let code { data?["error"] = .string(code) }
        if let retry = http.value(forHTTPHeaderField: "Retry-After") { data?["retryAfter"] = .string(retry) }
        if let reason {
            var d = data ?? [:]; d["reason"] = .string(reason); data = d
        }

        let kind: EngineError.Kind
        switch status {
        case 400:
            kind = .invalidParams
        case 401, 403:
            kind = .permissionDenied
        case 404:
            kind = .notFound
        case 405:
            kind = .invalidParams           // disallowed verb / presign method
        case 409:
            // Optimistic-concurrency / incomplete-upload conflict (API.md §2).
            kind = env?.locked == true || code == "locked" ? .locked : .conflict
            var d = data ?? [:]
            d["conflict"] = .bool(env?.conflict ?? true)
            if let holder = env?.heldBy { d["heldBy"] = .string(holder) }
            if let e = env?.expected { d["expected"] = e }
            if let a = env?.actual { d["actual"] = a }
            data = d
        case 429, 503:
            // Rate limits and service unavailability can both carry a cooldown.
            kind = .gatewayError
        case 507:
            kind = .syncFailed
            var d = data ?? [:]; d["metadataCapacity"] = .bool(true); data = d
        case 500...599:
            kind = .gatewayError
        default:
            kind = .gatewayError
        }
        return EngineError(kind, message, data: data)
    }

    // MARK: Wire shapes (API.md §4)

    /// `Item` (API.md §4). Decoded then projected onto `CloudFSCore.ItemMetadata`.
    struct WireItem: Decodable {
        let id: String
        let parent: String?
        let name: String
        let isDir: Bool
        let size: Int
        let contentVersion: String?
        let etag: String?
        let version: Int?
        let updatedSeq: Int?
        let deleted: Bool?
        let createdAt: Int?          // ms epoch; absent on legacy rows
        let modifiedAt: Int?
        let accessedAt: Int?
        let changedAt: Int?
        let fileAttributes: UInt32?
        let rsrcForkSize: Int?       // AAPL enrichment (v14)
        let finderInfo: String?      // legacy plaintext FinderInfo
        let finderInfoCiphertext: String? // complete encrypted AFP_AfpInfo

        var metadata: ItemMetadata {
            ItemMetadata(
                id: InodeID(id),
                parent: parent.map { InodeID($0) },
                name: name,
                isDir: isDir,
                size: size,
                contentVersion: contentVersion ?? "",
                metadataVersion: version.map(String.init) ?? "",
                createdAt: createdAt.map { Date(timeIntervalSince1970: Double($0) / 1000) },
                modifiedAt: modifiedAt.map { Date(timeIntervalSince1970: Double($0) / 1000) },
                accessedAt: accessedAt.map { Date(timeIntervalSince1970: Double($0) / 1000) },
                changedAt: changedAt.map { Date(timeIntervalSince1970: Double($0) / 1000) }, fileAttributes: fileAttributes,
                rsrcForkSize: rsrcForkSize,
                finderInfo: finderInfo.flatMap { Data(base64Encoded: $0) },
                finderInfoCiphertext: finderInfoCiphertext.flatMap { Data(base64Encoded: $0) })
        }
    }

    /// `GET .../streams` → `{ streams: [{name,size}] }`.
    private struct StreamListWire: Decodable {
        struct Entry: Decodable { let name: String; let size: Int }
        let streams: [StreamInfo]
        private enum CodingKeys: String, CodingKey { case streams }
        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            let raw = try c.decode([Entry].self, forKey: .streams)
            streams = raw.map { StreamInfo(name: $0.name, size: $0.size) }
        }
    }

    /// `Block` (API.md §4): all numbers except `blockHash`/`objectKey`.
    struct WireBlock: Codable {
        let chunkIdx: Int
        let blockIdx: Int
        let blockHash: String
        let objectKey: String
        let offset: Int
        let length: Int
    }

    struct ItemsPage: Decodable { let items: [WireItem]; let cursor: String? }
    private struct ChangesPage: Decodable { let anchor: Int; let items: [WireItem]; let cursor: Int?; let visibility: String? }
    private struct PresignResponse: Decodable { let url: String; let expiresIn: Int; let headers: [String: String]?; let verificationUrl: String? }
    private struct PresignBatchResponse: Decodable {
        struct Entry: Decodable { let key: String; let url: String?; let error: String?; let headers: [String: String]?; let verificationUrl: String? }
        let urls: [Entry]
        let expiresIn: Int
    }

    // MARK: - upload object key (WRITE path — gateway scheme)

    /// Mint the bucket key a newly-written block must live under:
    /// `blocks/<org>::<fs>/<hash>` (backend/API.md §presign confinement). The `<org>`
    /// is the token's `org` claim (decoded client-side; the gateway re-verifies the
    /// signature). If the token can't be decoded, fall back to `<fs>::<fs>` shape so
    /// the prefix is still under `blocks/` (the presign confinement will then surface
    /// any mismatch as a clear 403, rather than us guessing a `chunks/` key it rejects).
    public func offlineIdentity(filespace: FilespaceID) async -> String? {
        let token = await config.tokenProvider(), parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        var encoded = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while encoded.count % 4 != 0 { encoded += "=" }
        guard let bytes = Data(base64Encoded: encoded), let claims = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let org = claims["org"] as? String, let subject = claims["sub"] as? String, let type = claims["typ"] as? String,
              !org.isEmpty, !subject.isEmpty, type != "guest" else { return nil }
        // This selects a previously authorized, authenticated encrypted local
        // checkpoint. It does not authenticate a network request or a new user.
        let identity = try? JSONEncoder().encode([config.baseURL,org,subject,type,claims["spc"] as? String ?? "",filespace])
        return identity.map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() }
    }

    public func uploadObjectKey(filespace: FilespaceID, blockHash: BlockHash) async -> String {
        let token = await config.tokenProvider()
        let org = Self.orgClaim(fromJWS: token) ?? filespace
        return "blocks/\(org)::\(filespace)/\(blockHash.hex)"
    }

    /// Decode the `org` claim from a JWS (HS256) payload WITHOUT verifying the
    /// signature — the gateway verifies; we only need the org to build the key.
    static func orgClaim(fromJWS token: String) -> String? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        var b64 = String(parts[1]).replacingOccurrences(of: "-", with: "+")
                                   .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        guard let data = Data(base64Encoded: b64),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let org = obj["org"] as? String else { return nil }
        return org
    }

    // MARK: - presign (THE enforcement gate, API.md §presign)

    public func presign(
        filespace: FilespaceID,
        key: String,
        method: PresignMethod,
        expiresIn: Int?
    ) async throws -> PresignedURL {
        var bodyObj: [String: CodableValue] = [
            "key": .string(key),
            "method": .string(method.rawValue),
        ]
        if let expiresIn { bodyObj["expiresIn"] = .int(expiresIn) }
        let body = try Self.encoder.encode(bodyObj)
        let resp = try await sendJSON(
            PresignResponse.self, "POST",
            path: "/v1/filespaces/\(filespace)/presign",
            body: body)
        return PresignedURL(url: resp.url, expiresIn: resp.expiresIn, headers: resp.headers, verificationUrl: resp.verificationUrl)
    }

    public func presignWrite(filespace: FilespaceID, key: String, itemID: InodeID, expiresIn: Int?) async throws -> PresignedURL {
        var body: [String: CodableValue] = ["key": .string(key), "method": .string("PUT"), "itemId": .string(itemID.rawValue)]
        if let expiresIn { body["expiresIn"] = .int(expiresIn) }
        let response = try await sendJSON(PresignResponse.self, "POST", path: "/v1/filespaces/\(filespace)/presign",
                                          body: Self.encoder.encode(body))
        return PresignedURL(url: response.url, expiresIn: response.expiresIn, headers: response.headers, verificationUrl: response.verificationUrl)
    }

    public func presignWriteBatch(filespace: FilespaceID, keys: [(key: String, itemID: InodeID)], expiresIn: Int?) async throws -> [PresignBatchResult] {
        guard !keys.isEmpty else { return [] }
        guard keys.count <= 32 else { throw EngineError(.invalidParams, "Write authorization batch exceeds 32 objects") }
        let entries: [CodableValue] = keys.map { .object(["key": .string($0.key), "method": .string("PUT"), "itemId": .string($0.itemID.rawValue)]) }
        var body: [String: CodableValue] = ["keys": .array(entries)]
        if let expiresIn { body["expiresIn"] = .int(expiresIn) }
        let result = try await sendJSON(PresignBatchResponse.self, "POST", path: "/v1/filespaces/\(pathEscape(filespace))/presign/batch", body: Self.encoder.encode(body))
        return result.urls.map { PresignBatchResult(key: $0.key, url: $0.url, error: $0.error, headers: $0.headers, verificationUrl: $0.verificationUrl) }
    }

    /// Audit B23 — batch presign against `POST …/presign/batch`: ONE request, ONE rate-limit consume
    /// (cost = #keys), per-key ACL + result. Overrides the protocol's sequential fallback.
    public func presignBatch(
        filespace: FilespaceID,
        keys: [(key: String, method: PresignMethod)],
        expiresIn: Int?
    ) async throws -> [PresignBatchResult] {
        guard !keys.isEmpty else { return [] }
        let keyObjs: [CodableValue] = keys.map { .object(["key": .string($0.key), "method": .string($0.method.rawValue)]) }
        var bodyObj: [String: CodableValue] = ["keys": .array(keyObjs)]
        if let expiresIn { bodyObj["expiresIn"] = .int(expiresIn) }
        let body = try Self.encoder.encode(bodyObj)
        let resp = try await sendJSON(
            PresignBatchResponse.self, "POST",
            path: "/v1/filespaces/\(filespace)/presign/batch",
            body: body)
        return resp.urls.map { PresignBatchResult(key: $0.key, url: $0.url, error: $0.error, headers: $0.headers, verificationUrl: $0.verificationUrl) }
    }

    // MARK: - block map (API.md §blocks)

    public func verifyUploadedBlocks(filespace: FilespaceID, itemID: InodeID, blocks: [UploadedBlockVerification]) async throws {
        guard !blocks.isEmpty, blocks.count <= 128 else { throw EngineError(.invalidParams, "Object verification requires 1–128 objects") }
        struct Body: Encodable { let blocks: [UploadedBlockVerification] }
        struct Response: Decodable { let verified: Int }
        let result = try await sendJSON(Response.self, "POST",
            path: "/v1/filespaces/\(pathEscape(filespace))/blocks/\(pathEscape(itemID.rawValue))/verify",
            body: Self.encoder.encode(Body(blocks: blocks)))
        guard result.verified >= 0, result.verified <= blocks.count else {
            throw EngineError(.gatewayError, "Invalid object verification response")
        }
    }

    public func getBlockManifest(
        filespace: FilespaceID,
        itemID: InodeID
    ) async throws -> BlockManifest {
        try await getResolvedBlockManifest(filespace: filespace, itemID: itemID).manifest
    }

    /// Fetch the manifest AND the gateway's authoritative per-block `objectKey`, so the
    /// engine presigns the exact bucket key the store uses (backend/API.md §blocks).
    /// This is the fix for the engine↔gateway object-key mismatch: the wire `Block`
    /// carries `objectKey` (`blocks/<org>::<fs>/…`), which is NOT the engine's
    /// content-address cache key (`chunks/<shard>/<hash>`). We thread the wire key
    /// through instead of reconstructing one client-side.
    public func getResolvedBlockManifest(
        filespace: FilespaceID,
        itemID: InodeID
    ) async throws -> ResolvedBlockManifest {
        if streamingManifests { return try await rangedManifest(filespace: filespace, itemID: itemID) }
        let blocks = try await sendJSON(
            [WireBlock].self, "GET",
            path: "/v1/filespaces/\(filespace)/blocks/\(pathEscape(itemID.rawValue))")
        var refs: [BlockRef] = []
        var keys: [BlockHash: String] = [:]
        for b in blocks {
            let hash = BlockHash(hex: b.blockHash)
            refs.append(BlockRef(hash: hash, offset: b.offset, length: b.length))
            keys[hash] = b.objectKey   // the gateway/store's real key — presign THIS
        }
        // The gateway returns the raw ordered Block[]; contentVersion lives on the
        // owning Item. Fetch is cheap relative to the block GETs that follow, and
        // the engine needs a coherent (manifest, contentVersion) pair.
        let item = try await getItem(filespace: filespace, id: itemID)
        let manifest = BlockManifest(itemID: itemID, blocks: refs, contentVersion: item.contentVersion)
        return ResolvedBlockManifest(manifest: manifest, objectKeys: keys)
    }

    public func putBlockManifest(
        _ manifest: BlockManifest,
        filespace: FilespaceID,
        etag: String?
    ) async throws -> ItemMetadata {
        // Project CloudFSCore BlockRefs back onto the wire Block[] shape. The
        // `objectKey` MUST be the gateway/store scheme (`blocks/<org>::<fs>/<hash>`),
        // NOT the content-address cache key — it has to equal the key the block was
        // presign-PUT under, so a later read presigns + GETs the same object.
        var wire: [WireBlock] = []
        for (i, b) in manifest.blocks.enumerated() {
            let objectKey = await uploadObjectKey(filespace: filespace, blockHash: b.hash)
            wire.append(WireBlock(
                chunkIdx: i, blockIdx: 0,
                blockHash: b.hash.hex,
                objectKey: objectKey,
                offset: b.offset, length: b.length))
        }
        struct Put: Encodable { let blocks: [WireBlock]; let etag: String? }
        let body = try Self.encoder.encode(Put(blocks: wire, etag: etag))
        let item = try await sendJSON(
            WireItem.self, "PUT",
            path: "/v1/filespaces/\(filespace)/blocks/\(pathEscape(manifest.itemID.rawValue))",
            body: body)
        return item.metadata
    }

    /// CAS commit (audit B4/B5): threads `expectedVersion` (optimistic concurrency)
    /// and an optional lease `fence` into the PUT body. The gateway returns 409 on a
    /// version mismatch or a lock conflict, which `mapError` turns into
    /// `EngineError.conflict`/`.locked` so the upload pipeline surfaces a real
    /// conflict instead of silently last-writer-wins.
    public func putBlockManifest(
        _ manifest: BlockManifest,
        filespace: FilespaceID,
        expectedVersion: Int?,
        fence: Int?
    ) async throws -> ItemMetadata {
        var wire: [WireBlock] = []
        for (i, b) in manifest.blocks.enumerated() {
            let objectKey = await uploadObjectKey(filespace: filespace, blockHash: b.hash)
            wire.append(WireBlock(
                chunkIdx: i, blockIdx: 0,
                blockHash: b.hash.hex,
                objectKey: objectKey,
                offset: b.offset, length: b.length))
        }
        struct Put: Encodable { let blocks: [WireBlock]; let expectedVersion: Int?; let fence: Int? }
        let body = try Self.encoder.encode(Put(blocks: wire, expectedVersion: expectedVersion, fence: fence))
        let item = try await sendJSON(
            WireItem.self, "PUT",
            path: "/v1/filespaces/\(filespace)/blocks/\(pathEscape(manifest.itemID.rawValue))",
            body: body)
        return item.metadata
    }

    public func acquireFileLease(filespace: FilespaceID, id: InodeID, ttlMs: Int, purpose: FileLeasePurpose) async throws -> FileLease {
        try await acquireFileLease(filespace: filespace, id: id, ttlMs: ttlMs,
                                   purpose: purpose, includeItem: false)
    }
    public func acquireFileLease(filespace: FilespaceID, id: InodeID, ttlMs: Int,
                                 purpose: FileLeasePurpose, includeItem: Bool) async throws -> FileLease {
        struct Acquire: Encodable {
            let path: String; let ttlMs: Int; let mode = "exclusive"
            let purpose: FileLeasePurpose; let includeItem: Bool?
        }
        struct Response: Decodable {
            let granted: Bool; let path: String; let fence: Int?
            let expiresAt: Double?; let heldBy: String?; let reason: String?
            let purpose: FileLeasePurpose?; let item: WireItem?
        }
        let response = try await sendJSON(Response.self, "POST", path: "/v1/filespaces/\(filespace)/locks",
            body: Self.encoder.encode(Acquire(path: id.rawValue, ttlMs: ttlMs, purpose: purpose,
                                              includeItem: includeItem ? true : nil)))
        return FileLease(granted: response.granted, path: response.path, fence: response.fence,
                         expiresAt: response.expiresAt, heldBy: response.heldBy,
                         reason: response.reason, purpose: response.purpose,
                         item: response.item?.metadata)
    }
    public func renewFileLease(filespace: FilespaceID, id: InodeID, fence: Int, ttlMs: Int) async throws -> FileLease {
        struct Renew: Encodable { let path: String; let ttlMs: Int; let fence: Int; let renew = true }
        return try await sendJSON(FileLease.self, "POST", path: "/v1/filespaces/\(filespace)/locks",
                                  body: Self.encoder.encode(Renew(path: id.rawValue, ttlMs: ttlMs, fence: fence)))
    }
    public func releaseFileLease(filespace: FilespaceID, id: InodeID, fence: Int) async throws {
        struct Released: Decodable { let released: Bool; let reason: String? }
        let result = try await sendJSON(Released.self, "DELETE", path: "/v1/filespaces/\(filespace)/locks",
                                       query: [URLQueryItem(name: "path", value: id.rawValue),
                                               URLQueryItem(name: "fence", value: String(fence))])
        guard result.released else { throw EngineError(.locked, result.reason ?? "The file lease changed") }
    }

    // MARK: - namespace items (API.md §items)

    /// Create a namespace item (audit B1) and adopt the gateway-minted id. The body
    /// is `{ parent, name, isDir, size }`; the response is the new `Item` (201).
    public func createItem(
        filespace: FilespaceID,
        parent: InodeID,
        name: String,
        isDir: Bool,
        size: Int
    ) async throws -> ItemMetadata {
        struct Create: Encodable { let parent: String; let name: String; let isDir: Bool; let size: Int }
        let body = try Self.encoder.encode(Create(parent: parent.rawValue, name: name, isDir: isDir, size: size))
        let item = try await sendJSON(
            WireItem.self, "POST",
            path: "/v1/filespaces/\(filespace)/items",
            body: body)
        return item.metadata
    }

    /// Delete a namespace item (audit B1): `DELETE /v1/filespaces/:fs/items/:id`,
    /// with `?recursive=true` for a non-empty directory.
    public func deleteItem(
        filespace: FilespaceID,
        id: InodeID,
        recursive: Bool
    ) async throws {
        try await deleteItem(filespace:filespace,id:id,recursive:recursive,openHandle:nil)
    }
    public func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool, openHandle: String?) async throws {
        var query = recursive ? [URLQueryItem(name: "recursive", value: "true")] : []
        if let openHandle { query.append(URLQueryItem(name:"openHandle",value:openHandle)) }
        _ = try await send("DELETE",
            path: "/v1/filespaces/\(filespace)/items/\(pathEscape(id.rawValue))",
            query: query)
    }

    /// Rename/move (audit B17): `PATCH /items/:id {parent?, name}`. The gateway updates only
    /// `(parent, name)` — the opaque id is unchanged, so the item's encrypted blocks (GCM key
    /// HKDF-bound to itemID) stay valid for every client.
    public func setBasicInfo(filespace: FilespaceID, id: InodeID, info: BasicFileInfo, expectedVersion: Int, fence: Int?) async throws -> ItemMetadata {
        struct Patch: Encodable {
            let createdAt: Int64?; let modifiedAt: Int64?; let accessedAt: Int64?; let changedAt: Int64?
            let fileAttributes: UInt32?; let expectedVersion: Int; let fence: Int?
        }
        func milliseconds(_ date: Date?) throws -> Int64? {
            guard let date else { return nil }
            let ms = date.timeIntervalSince1970 * 1000
            guard ms.isFinite, ms >= -11644473600000, ms <= 253402300799999 else { throw EngineError(.invalidParams, "Invalid file timestamp") }
            return Int64(ms.rounded())
        }
        let body = try Self.encoder.encode(Patch(createdAt: milliseconds(info.createdAt), modifiedAt: milliseconds(info.modifiedAt),
            accessedAt: milliseconds(info.accessedAt), changedAt: milliseconds(info.changedAt), fileAttributes: info.fileAttributes,
            expectedVersion: expectedVersion, fence: fence))
        let item = try await sendJSON(WireItem.self, "PATCH", path: "/v1/filespaces/\(filespace)/items/\(pathEscape(id.rawValue))/basic-info", body: body)
        return item.metadata
    }

    public func renameItem(
        filespace: FilespaceID,
        id: InodeID,
        newParent: InodeID?,
        newName: String
    ) async throws -> ItemMetadata {
        struct Patch: Encodable { let parent: String?; let name: String }
        let body = try Self.encoder.encode(Patch(parent: newParent?.rawValue, name: newName))
        let item = try await sendJSON(
            WireItem.self, "PATCH",
            path: "/v1/filespaces/\(filespace)/items/\(pathEscape(id.rawValue))",
            body: body)
        return item.metadata
    }

    public func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String, expectedVersion: Int, replacing: ItemMetadata?) async throws -> ItemMetadata {
        try await renameItem(filespace:filespace,id:id,newParent:newParent,newName:newName,expectedVersion:expectedVersion,replacing:replacing,openHandle:nil)
    }
    public func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String, expectedVersion: Int, replacing: ItemMetadata?, openHandle: String?) async throws -> ItemMetadata {
        struct Replacement: Encodable { let id: String; let expectedVersion: Int }
        struct Patch: Encodable { let parent: String?; let name: String; let expectedVersion: Int; let replace: Replacement?; let openHandle: String? }
        let replacement: Replacement?
        if let replacing {
            guard let version = Int(replacing.metadataVersion) else { throw EngineError(.conflict, "Missing replacement version") }
            replacement = Replacement(id: replacing.id.rawValue, expectedVersion: version)
        } else { replacement = nil }
        let body = try Self.encoder.encode(Patch(parent: newParent?.rawValue, name: newName, expectedVersion: expectedVersion, replace: replacement, openHandle: openHandle))
        return try await sendJSON(WireItem.self, "PATCH", path: "/v1/filespaces/\(filespace)/items/\(pathEscape(id.rawValue))", body: body).metadata
    }

    public func listItems(
        filespace: FilespaceID,
        parent: InodeID,
        cursor: String?
    ) async throws -> (items: [ItemMetadata], cursor: String?) {
        var query = [
            URLQueryItem(name: "parent", value: parent.rawValue),
            URLQueryItem(name: "limit", value: String(config.listLimit)),
        ]
        if let cursor, !cursor.isEmpty {
            query.append(URLQueryItem(name: "cursor", value: cursor))
        }
        let page = try await sendJSON(
            ItemsPage.self, "GET",
            path: "/v1/filespaces/\(filespace)/items",
            query: query)
        let cursor = (page.cursor?.isEmpty == false) ? page.cursor : nil
        return (page.items.map(\.metadata), cursor)
    }

    public func authorizeWrite(filespace: FilespaceID, id: InodeID) async throws {
        struct Access: Decodable { let read: Bool; let write: Bool }
        let access = try await sendJSON(Access.self, "GET",
            path: "/v1/filespaces/\(filespace)/items/\(pathEscape(id.rawValue))/access")
        guard access.read && access.write else {
            throw EngineError(.permissionDenied, "This shared folder is read-only")
        }
    }

    public func getItem(
        filespace: FilespaceID,
        id: InodeID
    ) async throws -> ItemMetadata {
        let item = try await sendJSON(
            WireItem.self, "GET",
            path: "/v1/filespaces/\(filespace)/items/\(pathEscape(id.rawValue))")
        return item.metadata
    }

    // MARK: - filespace master key (ONBOARDING.md "Key model", backend/API.md §key)

    public func mountRoots(filespace: FilespaceID) async throws -> [FilespaceMountRoot] {
        struct Response: Decodable { let roots: [FilespaceMountRoot] }
        do { return try await sendJSON(Response.self, "GET", path: "/v1/filespaces/\(filespace)/mount-roots").roots }
        catch let error as EngineError where error.kind == .notFound {
            // Older gateways lack discovery. Their ordinary root ACL check still
            // denies folder-only users; never synthesize permissions client-side.
            return [FilespaceMountRoot(id: "root", name: filespace, mountAsRoot: true)]
        }
    }

    public func fetchMasterKeyEnvelope(filespace: FilespaceID) async throws -> FilespaceKeyEnvelope {
        try await sendJSON(FilespaceKeyEnvelope.self, "GET", path: "/v1/filespaces/\(filespace)/key")
    }

    // MARK: - named streams (P4)

    private func streamsBase(_ filespace: FilespaceID, _ id: InodeID) -> String {
        "/v1/filespaces/\(filespace)/items/\(pathEscape(id.rawValue))/streams"
    }

    public func listStreams(filespace: FilespaceID, id: InodeID) async throws -> [StreamInfo] {
        try await sendJSON(StreamListWire.self, "GET", path: streamsBase(filespace, id)).streams
    }

    public func readStream(filespace: FilespaceID, id: InodeID, name: String) async throws -> Data {
        try await send("GET", path: "\(streamsBase(filespace, id))/\(pathEscape(name))")
    }

    public func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int) async throws {
        _ = try await send("PUT", path: "\(streamsBase(filespace, id))/\(pathEscape(name))",
                           query: [URLQueryItem(name: "size", value: String(plaintextSize))],
                           body: data, contentType: "application/octet-stream")
    }

    public func deleteStream(filespace: FilespaceID, id: InodeID, name: String) async throws {
        _ = try await send("DELETE", path: "\(streamsBase(filespace, id))/\(pathEscape(name))")
    }

    public func writeStream(filespace: FilespaceID, id: InodeID, name: String, data: Data, plaintextSize: Int, fence: Int?) async throws {
        var query = [URLQueryItem(name: "size", value: String(plaintextSize))]
        if let fence { query.append(URLQueryItem(name: "fence", value: String(fence))) }
        _ = try await send("PUT", path: "\(streamsBase(filespace, id))/\(pathEscape(name))",
                           query: query, body: data, contentType: "application/octet-stream")
    }
    public func deleteStream(filespace: FilespaceID, id: InodeID, name: String, fence: Int?) async throws {
        _ = try await send("DELETE", path: "\(streamsBase(filespace, id))/\(pathEscape(name))",
                           query: fence.map { [URLQueryItem(name: "fence", value: String($0))] } ?? [])
    }

    // MARK: - change feed (API.md §changes) — keyset `since` cursor

    public func changes(
        filespace: FilespaceID,
        since: Int?
    ) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) {
        var query: [URLQueryItem] = []
        if let since { query.append(URLQueryItem(name: "since", value: String(since))) }
        let page = try await sendJSON(
            ChangesPage.self, "GET",
            path: "/v1/filespaces/\(filespace)/changes",
            query: query)
        return (page.anchor, page.items.map(\.metadata), page.cursor)
    }

    /// Tombstone-aware change feed. The backend's `changesSince` returns Items WITH a
    /// `deleted` flag (it has dedicated N-F1 logic to deliver deletions to principals
    /// who could read the item). We split them so a sync consumer applies upserts and
    /// removals correctly instead of resurrecting every tombstone.
    public func changesWithDeletions(
        filespace: FilespaceID,
        since: Int?
    ) async throws -> (anchor: Int, updated: [ItemMetadata], deleted: [InodeID], cursor: Int?) {
        var query: [URLQueryItem] = []
        if let since { query.append(URLQueryItem(name: "since", value: String(since))) }
        let page = try await sendJSON(
            ChangesPage.self, "GET",
            path: "/v1/filespaces/\(filespace)/changes",
            query: query)
        var updated: [ItemMetadata] = []
        var deleted: [InodeID] = []
        for w in page.items {
            if w.deleted == true { deleted.append(InodeID(w.id)) }
            else { updated.append(w.metadata) }
        }
        return (page.anchor, updated, deleted, page.cursor)
    }

    public func changePage(filespace: FilespaceID, since: Int?) async throws -> GatewayChangePage {
        let query = since.map { [URLQueryItem(name: "since", value: String($0))] } ?? []
        let page = try await sendJSON(ChangesPage.self, "GET", path: "/v1/filespaces/\(filespace)/changes", query: query)
        return GatewayChangePage(anchor: page.anchor, updated: page.items.filter { $0.deleted != true }.map(\.metadata),
            deleted: page.items.filter { $0.deleted == true }.map { InodeID($0.id) }, cursor: page.cursor, visibility: page.visibility)
    }

    public func changeCheckpoint(filespace: FilespaceID) async throws -> GatewayChangeCheckpoint {
        // The existing ACL-filtered endpoint always returns the authoritative
        // high-water sequence and permission visibility, even on an empty page.
        // One row bounds work and payload; never traverse historical pages.
        try Task.checkCancellation()
        let checkpoint = try await sendJSON(GatewayChangeCheckpoint.self, "GET",
            path: "/v1/filespaces/\(pathEscape(filespace))/changes",
            query: [URLQueryItem(name: "limit", value: "1")])
        try Task.checkCancellation()
        guard checkpoint.anchor >= 0 else { throw EngineError(.gatewayError, "Invalid notification checkpoint") }
        return checkpoint
    }

    // MARK: Helpers

    /// Percent-encode a single path segment. Inode ids are opaque single segments
    /// that may contain `/` (e.g. `root/A001.mov`); the `/` MUST be encoded to `%2F`
    /// so the gateway sees one path component, not a sub-path — otherwise it routes
    /// `blocks/root/A001.mov` as itemId `root` and returns an empty/wrong manifest.
    /// `.urlPathAllowed` permits `/`, so we start from it and subtract `/` (and a few
    /// other segment-significant delimiters) from the allowed set.
    func pathEscape(_ segment: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/?#%")
        return segment.addingPercentEncoding(withAllowedCharacters: allowed) ?? segment
    }
}

/// Foundation stub: compiles green, throws `.unimplemented`.
public struct StubGatewayClient: GatewayClient {
    public init() {}
    public func presign(filespace: FilespaceID, key: String, method: PresignMethod, expiresIn: Int?) async throws -> PresignedURL { throw EngineError.unimplemented() }
    public func getBlockManifest(filespace: FilespaceID, itemID: InodeID) async throws -> BlockManifest { throw EngineError.unimplemented() }
    // Explicit (not via protocol-extension default): a default impl of a newly-added
    // requirement, dispatched through an `any GatewayClient` existential, can crash on
    // some toolchains (witness-table fault). Every conformer states it directly.
    public func uploadObjectKey(filespace: FilespaceID, blockHash: BlockHash) async -> String { blockHash.objectKey }
    public func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, etag: String?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    public func putBlockManifest(_ manifest: BlockManifest, filespace: FilespaceID, expectedVersion: Int?, fence: Int?) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    public func createItem(filespace: FilespaceID, parent: InodeID, name: String, isDir: Bool, size: Int) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    public func deleteItem(filespace: FilespaceID, id: InodeID, recursive: Bool) async throws { throw EngineError.unimplemented() }
    public func renameItem(filespace: FilespaceID, id: InodeID, newParent: InodeID?, newName: String) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    public func listItems(filespace: FilespaceID, parent: InodeID, cursor: String?) async throws -> (items: [ItemMetadata], cursor: String?) { throw EngineError.unimplemented() }
    public func getItem(filespace: FilespaceID, id: InodeID) async throws -> ItemMetadata { throw EngineError.unimplemented() }
    public func changes(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, items: [ItemMetadata], cursor: Int?) { throw EngineError.unimplemented() }
    public func changesWithDeletions(filespace: FilespaceID, since: Int?) async throws -> (anchor: Int, updated: [ItemMetadata], deleted: [InodeID], cursor: Int?) { throw EngineError.unimplemented() }
}
