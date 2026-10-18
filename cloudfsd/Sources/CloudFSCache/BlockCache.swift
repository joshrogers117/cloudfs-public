// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCache — the resizable/relocatable block cache seam. (DESIGN.md §3)
//
// Owner: CACHE. Implements the on-SSD block cache: 1 MiB content-addressed
// blocks, 2-random pin-aware eviction gated on size ceiling + min-free floor,
// live resize/relocate (the product superpower), the on-disk index (index.db) +
// integrity + restart persistence, the write-staging dir, and statfs.
//
// This file defines the PROTOCOL + a STUB. The real implementation is
// `DiskBlockCache` in BlockCacheImpl.swift (and its supporting files). The
// protocol's public signature is FROZEN per the seam contract — do not change it.

import Foundation
import CloudFSCore

public protocol BlockCache: Sendable {
    // --- block storage ---
    func contains(_ hash: BlockHash) async -> Bool
    /// Read a cached block's plaintext (already decrypted on admission), or nil on miss.
    func readBlockForOffline(_ hash: BlockHash) async throws -> Data?
    func readBlock(_ hash: BlockHash) async throws -> Data?
    /// Admit a block (plaintext payload + its content hash) into the cache.
    func putBlock(_ hash: BlockHash, plaintext: Data) async throws

    // --- info / resize / relocate (the superpower) ---
    func info(filespace: FilespaceID) async throws -> CacheInfo
    func setSize(filespace: FilespaceID, bytes: Int) async throws -> CacheInfo
    func setLocation(filespace: FilespaceID, path: String) async throws -> CacheInfo
    func clear(filespace: FilespaceID) async throws -> CacheInfo

    // --- path <-> block association (pins/evict operate by path) ---
    /// Associate a path (an item id) with the content hashes of its blocks, so a
    /// later `pin`/`unpin`/`evict` by that path resolves to those blocks. The
    /// engine/transfer layer calls this as it materializes a file's manifest
    /// (prefetch / open / read). Idempotent; safe to call repeatedly.
    func registerPath(_ path: String, blocks: [BlockHash]) async throws

    // --- pin / evict ---
    func pin(_ path: String, recursive: Bool) async throws -> PinState
    func unpin(_ path: String, recursive: Bool) async throws -> PinState
    func pinList(filespace: FilespaceID) async throws -> [PinState]
    func evict(_ path: String) async throws -> EvictAck
}

/// Foundation stub: compiles green, throws `.unimplemented`.
public struct StubBlockCache: BlockCache {
    public init() {}
    public func contains(_ hash: BlockHash) async -> Bool { false }
    public func readBlock(_ hash: BlockHash) async throws -> Data? { throw EngineError.unimplemented() }
    public func putBlock(_ hash: BlockHash, plaintext: Data) async throws { throw EngineError.unimplemented() }
    public func info(filespace: FilespaceID) async throws -> CacheInfo { throw EngineError.unimplemented() }
    public func setSize(filespace: FilespaceID, bytes: Int) async throws -> CacheInfo { throw EngineError.unimplemented() }
    public func setLocation(filespace: FilespaceID, path: String) async throws -> CacheInfo { throw EngineError.unimplemented() }
    public func clear(filespace: FilespaceID) async throws -> CacheInfo { throw EngineError.unimplemented() }
    public func registerPath(_ path: String, blocks: [BlockHash]) async throws { throw EngineError.unimplemented() }
    public func pin(_ path: String, recursive: Bool) async throws -> PinState { throw EngineError.unimplemented() }
    public func unpin(_ path: String, recursive: Bool) async throws -> PinState { throw EngineError.unimplemented() }
    public func pinList(filespace: FilespaceID) async throws -> [PinState] { throw EngineError.unimplemented() }
    public func evict(_ path: String) async throws -> EvictAck { throw EngineError.unimplemented() }
}

public extension BlockCache {
    func readBlockForOffline(_ hash: BlockHash) async throws -> Data? { try await readBlock(hash) }
}
