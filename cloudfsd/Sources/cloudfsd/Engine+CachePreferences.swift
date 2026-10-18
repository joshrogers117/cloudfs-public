// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Darwin
import CloudFSCore

struct EngineCachePreferences: Sendable, Codable {
    var location: String?
    var maxBytes: Int?
}

extension CloudFSEngine {
    /// Stable write-journal / pin-intent state is never moved with disposable
    /// downloaded blocks. The daemon's configured state root stays authoritative.
    func stableStateDirectory(_ filespace: FilespaceID) -> URL {
        URL(fileURLWithPath: config.cacheDir).appendingPathComponent(filespace, isDirectory: true)
    }
    private var cachePreferencesURL: URL {
        URL(fileURLWithPath: config.cacheDir).appendingPathComponent("cache-preferences.json")
    }
    func loadCachePreferences() throws -> [FilespaceID: EngineCachePreferences] {
        if let savedCachePreferences { return savedCachePreferences }
        guard FileManager.default.fileExists(atPath: cachePreferencesURL.path) else {
            savedCachePreferences = [:]; return [:]
        }
        let values = try JSONDecoder().decode([FilespaceID: EngineCachePreferences].self,
                                              from: Data(contentsOf: cachePreferencesURL))
        for value in values.values {
            if let location = value.location, !location.hasPrefix("/") {
                throw EngineError(.invalidParams, "Saved cache location must be an absolute path")
            }
            if let size = value.maxBytes, size < 0 { throw EngineError(.invalidParams, "Saved cache size is invalid") }
        }
        savedCachePreferences = values
        return values
    }
    private func persistCachePreference(_ filespace: FilespaceID, location: String?, maxBytes: Int) throws {
        var values = try loadCachePreferences()
        values[filespace] = EngineCachePreferences(location: location, maxBytes: maxBytes)
        try FileManager.default.createDirectory(at: cachePreferencesURL.deletingLastPathComponent(),
                                                withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try JSONEncoder().encode(values).write(to: cachePreferencesURL, options: .atomic)
        // Atomic rename makes the new value visible. If the following durability
        // barrier fails, retain both locations and keep using this published map;
        // rolling back cache bytes would leave the visible map pointing at a void.
        savedCachePreferences = values
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: cachePreferencesURL.path)
        try synchronizePreferenceFile(cachePreferencesURL, full: true)
        try synchronizePreferenceFile(cachePreferencesURL.deletingLastPathComponent(), full: false)
    }
    private func synchronizePreferenceFile(_ url: URL, full: Bool) throws {
        let descriptor = Darwin.open(url.path, O_RDONLY | O_CLOEXEC)
        guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { Darwin.close(descriptor) }
        guard Darwin.fsync(descriptor) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        if full, Darwin.fcntl(descriptor, F_FULLFSYNC) != 0, errno != ENOTSUP, errno != EINVAL {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
    }
    private func beginCachePreferenceChange(_ filespace: FilespaceID) async {
        if cachePreferenceBusy.insert(filespace).inserted { return }
        await withCheckedContinuation { cachePreferenceWaiters[filespace, default: []].append($0) }
    }
    private func endCachePreferenceChange(_ filespace: FilespaceID) {
        if var queued = cachePreferenceWaiters[filespace], !queued.isEmpty {
            let next = queued.removeFirst(); cachePreferenceWaiters[filespace] = queued.isEmpty ? nil : queued; next.resume()
        } else { cachePreferenceBusy.remove(filespace) }
    }
    public func cacheSetSize(_ p: CacheSetSizeParams) async throws -> CacheInfo {
        await beginCachePreferenceChange(p.filespace)
        defer { endCachePreferenceChange(p.filespace) }
        let cache = try require(p.filespace).cache
        let before = try await cache.info(filespace: p.filespace)
        let result = try await cache.setSize(filespace: p.filespace, bytes: p.bytes)
        do { try persistCachePreference(p.filespace, location: result.location, maxBytes: result.maxBytes) }
        catch {
            if savedCachePreferences?[p.filespace]?.maxBytes != result.maxBytes {
                _ = try? await cache.setSize(filespace: p.filespace, bytes: before.maxBytes)
            }
            throw error
        }
        try await retryPins(p.filespace)
        return result
    }
    public func cacheSetLocation(_ p: CacheSetLocationParams) async throws -> CacheInfo {
        await beginCachePreferenceChange(p.filespace)
        defer { endCachePreferenceChange(p.filespace) }
        let cache = try require(p.filespace).cache
        let before = try await cache.info(filespace: p.filespace)
        // Retain old bytes until the stable mapping is durably published. Pin
        // intent and write journals stay in stableStateDirectory throughout.
        let result = try await cache.setLocation(filespace: p.filespace, path: p.path, preserveSource: true)
        do { try persistCachePreference(p.filespace, location: result.location, maxBytes: result.maxBytes) }
        catch {
            if savedCachePreferences?[p.filespace]?.location != result.location {
                _ = try? await cache.rollbackRelocation(to: before.location)
            }
            throw error
        }
        if result.location != before.location { await cache.finishRelocation(from: before.location) }
        try await retryPins(p.filespace)
        return result
    }
}
