// SPDX-License-Identifier: AGPL-3.0-or-later
import FileProvider
import os

/// The production replicated File Provider extension.
///
/// Topology (the hybrid the spike validated): this appex is a **thin presentation shim**.
/// It owns no cache and does no network I/O — every metadata lookup, enumeration, and byte
/// fetch is forwarded to the persistent `cloudfsd` daemon over a Unix-domain socket in the
/// App Group container (CONTROL-API §7). The daemon owns the relocatable cache, crypto, and
/// gateway access; it materializes decrypted byte ranges into the shared container for the
/// sandboxed appex to read. Keeping the engine in the daemon preserves the relocatable cache
/// (a File-Provider-managed store can't live on an external volume) while Finder gets the
/// native cloud-storage UI.
///
/// One domain == one filespace: the domain identifier IS the filespace id, so the appex
/// recovers which filespace it serves from `domain.identifier.rawValue`, and the daemon
/// socket is shared across all domains (it multiplexes by the `filespace` RPC param).
final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension, NSFileProviderEnumerating {
    let domain: NSFileProviderDomain
    let manager: NSFileProviderManager?
    let dataPath: DaemonDataPath
    let displayName: String
    let log = Logger(subsystem: "dev.cloudfs.fileprovider", category: "ext")

    required init(domain: NSFileProviderDomain) {
        self.domain = domain
        self.manager = NSFileProviderManager(for: domain)
        self.displayName = domain.displayName
        self.dataPath = DaemonDataPath(filespace: domain.identifier.rawValue)
        super.init()
        log.log("init domain=\(domain.identifier.rawValue, privacy: .public) name=\(domain.displayName, privacy: .public) socket=\(CloudFSAppGroup.daemonSocketPath, privacy: .public)")
    }

    func invalidate() {
        log.log("invalidate domain=\(self.domain.identifier.rawValue, privacy: .public)")
    }

    // MARK: - Metadata

    func item(for identifier: NSFileProviderItemIdentifier,
              request: NSFileProviderRequest,
              completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        let progress = Progress(totalUnitCount: 1)
        if identifier == .rootContainer {
            completionHandler(CloudFSItem.root(displayName: displayName), nil)
            progress.completedUnitCount = 1
            return progress
        }
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            do {
                let item = try dataPath.lookup(identifier.rawValue)
                completionHandler(CloudFSItem(item), nil)
            } catch {
                log.error("item(for: \(identifier.rawValue, privacy: .public)) failed: \(error.localizedDescription, privacy: .public)")
                completionHandler(nil, NSFileProviderError(.noSuchItem))
            }
            progress.completedUnitCount = 1
        }
        return progress
    }

    // MARK: - Whole-file content

    func fetchContents(for itemIdentifier: NSFileProviderItemIdentifier,
                       version requestedVersion: NSFileProviderItemVersion?,
                       request: NSFileProviderRequest,
                       completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress {
        let progress = Progress(totalUnitCount: 100)
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            do {
                let meta = try dataPath.lookup(itemIdentifier.rawValue)
                let item = CloudFSItem(meta)
                // Whole file: one block-aligned range over [0, size). The daemon assembles +
                // decrypts and materializes the bytes into the App Group container.
                let range = try dataPath.readRange(itemId: itemIdentifier.rawValue,
                                                   version: contentVersionString(requestedVersion) ?? meta.contentVersion,
                                                   offset: 0, length: max(meta.size, 1), alignment: 0)
                let dest = try materialize(range, into: temporaryDirectory())
                progress.completedUnitCount = 100
                completionHandler(dest, item, nil)
            } catch {
                log.error("fetchContents \(itemIdentifier.rawValue, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                completionHandler(nil, nil, error)
            }
        }
        return progress
    }

    // MARK: - Enumeration

    func enumerator(for containerItemIdentifier: NSFileProviderItemIdentifier,
                    request: NSFileProviderRequest) throws -> NSFileProviderEnumerator {
        CloudFSEnumerator(container: containerItemIdentifier, dataPath: dataPath, log: log)
    }

    // MARK: - Mutations (out-of-process write path is a later stage → unsupported for now)

    func createItem(basedOn itemTemplate: NSFileProviderItem,
                    fields: NSFileProviderItemFields,
                    contents url: URL?,
                    options: NSFileProviderCreateItemOptions = [],
                    request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        completionHandler(nil, [], false, NSError(domain: NSCocoaErrorDomain, code: NSFeatureUnsupportedError))
        return Progress(totalUnitCount: 0)
    }

    func modifyItem(_ item: NSFileProviderItem,
                    baseVersion version: NSFileProviderItemVersion,
                    changedFields: NSFileProviderItemFields,
                    contents newContents: URL?,
                    options: NSFileProviderModifyItemOptions = [],
                    request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        completionHandler(nil, [], false, NSError(domain: NSCocoaErrorDomain, code: NSFeatureUnsupportedError))
        return Progress(totalUnitCount: 0)
    }

    func deleteItem(identifier: NSFileProviderItemIdentifier,
                    baseVersion version: NSFileProviderItemVersion,
                    options: NSFileProviderDeleteItemOptions = [],
                    request: NSFileProviderRequest,
                    completionHandler: @escaping (Error?) -> Void) -> Progress {
        completionHandler(NSError(domain: NSCocoaErrorDomain, code: NSFeatureUnsupportedError))
        return Progress(totalUnitCount: 0)
    }

    // MARK: - Materialization helpers (shared with the partial-fetch path)

    /// The File Provider system's temp dir (same volume as the replicated store, so a returned
    /// file is moved, not copied). Falls back to the process temp dir if the manager is absent.
    func temporaryDirectory() -> URL {
        (try? manager?.temporaryDirectoryURL()) ?? FileManager.default.temporaryDirectory
    }

    /// Copy the daemon-materialized range into a fresh file the system takes ownership of.
    ///
    /// CRITICAL (matches the daemon + spike contract): the daemon's file holds the range bytes
    /// PACKED from offset 0; `range.offset` is the absolute (block-snapped) offset in the original
    /// file. The returned file must place those bytes at their ABSOLUTE offset (a sparse hole over
    /// `[0, range.offset)`), or partial materialization fails with `VFSFileError 33` / EINVAL.
    func materialize(_ range: WireRange, into dir: URL) throws -> URL {
        guard let srcPath = range.path else { throw DaemonError.noPath }
        // The daemon's handoff file is ours to consume: delete it once copied so out-of-process
        // spills don't accumulate in the shared App Group container.
        defer { try? FileManager.default.removeItem(atPath: srcPath) }
        let bytes = try Data(contentsOf: URL(fileURLWithPath: srcPath))
        let dest = dir.appendingPathComponent(UUID().uuidString)
        FileManager.default.createFile(atPath: dest.path, contents: nil)
        let handle = try FileHandle(forWritingTo: dest)
        defer { try? handle.close() }
        if range.offset > 0 { try handle.seek(toOffset: UInt64(range.offset)) }  // sparse hole
        try handle.write(contentsOf: bytes)
        return dest
    }

    /// Decode a requested content version (the daemon's contentVersion string) from the
    /// system's `NSFileProviderItemVersion`, if present.
    func contentVersionString(_ v: NSFileProviderItemVersion?) -> String? {
        guard let v else { return nil }
        return String(data: v.contentVersion, encoding: .utf8)
    }
}
