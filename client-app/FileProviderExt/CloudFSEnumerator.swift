// SPDX-License-Identifier: AGPL-3.0-or-later
import FileProvider
import os

/// Enumerates a container's children and replays changes, both delegated to the daemon
/// (CONTROL-API §7 `data.enumerate` / `data.enumerateChanges`). The daemon owns the sync
/// anchor (an integer high-water mark over the gateway change feed); the appex just carries
/// it across calls. Blocking RPCs run off the calling thread on a utility queue.
final class CloudFSEnumerator: NSObject, NSFileProviderEnumerator {
    private let container: NSFileProviderItemIdentifier
    private let dataPath: DaemonDataPath
    private let log: Logger
    private let queue = DispatchQueue(label: "dev.cloudfs.fileprovider.enumerator", qos: .utility)

    init(container: NSFileProviderItemIdentifier, dataPath: DaemonDataPath, log: Logger) {
        self.container = container
        self.dataPath = dataPath
        self.log = log
    }

    func invalidate() {}

    /// The daemon's container id for this enumerator: the synthetic root maps to "root".
    private var containerID: String {
        container == .rootContainer || container == .workingSet
            ? "root" : container.rawValue
    }

    func enumerateItems(for observer: NSFileProviderEnumerationObserver,
                        startingAt page: NSFileProviderPage) {
        // The system's initial sentinels mean "start from the beginning" → cursor nil.
        // (The sentinels are bridged `NSData`; compare against the page's raw bytes.)
        let nameSentinel = NSFileProviderPage.initialPageSortedByName as Data
        let dateSentinel = NSFileProviderPage.initialPageSortedByDate as Data
        let initial = page.rawValue == nameSentinel || page.rawValue == dateSentinel
        let cursor = initial ? nil : String(data: page.rawValue, encoding: .utf8)
        let cid = containerID

        queue.async { [self] in
            do {
                let result = try dataPath.enumerate(container: cid, page: cursor)
                observer.didEnumerate(result.items.map { CloudFSItem($0) })
                if let next = result.nextPage, let data = next.data(using: .utf8) {
                    observer.finishEnumerating(upTo: NSFileProviderPage(data))
                } else {
                    observer.finishEnumerating(upTo: nil)
                }
            } catch {
                log.error("enumerateItems \(cid, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                observer.finishEnumeratingWithError(error)
            }
        }
    }

    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        let cid = containerID
        queue.async { [self] in
            // No dedicated "latest anchor" RPC yet: drain changes from the beginning purely
            // to learn the daemon's current high-water mark (items discarded). Cheap relative
            // to media I/O; a `data.syncAnchor` RPC can replace this later.
            if let changes = try? dataPath.enumerateChanges(container: cid, anchor: ""),
               let data = changes.newAnchor.data(using: .utf8) {
                completionHandler(NSFileProviderSyncAnchor(data))
            } else {
                completionHandler(nil)
            }
        }
    }

    func enumerateChanges(for observer: NSFileProviderChangeObserver,
                          from syncAnchor: NSFileProviderSyncAnchor) {
        let anchor = String(data: syncAnchor.rawValue, encoding: .utf8) ?? ""
        let cid = containerID
        queue.async { [self] in
            do {
                let changes = try dataPath.enumerateChanges(container: cid, anchor: anchor)
                if !changes.updated.isEmpty {
                    observer.didUpdate(changes.updated.map { CloudFSItem($0) })
                }
                if !changes.deleted.isEmpty {
                    observer.didDeleteItems(withIdentifiers: changes.deleted.map { NSFileProviderItemIdentifier($0) })
                }
                let next = changes.newAnchor.data(using: .utf8).map { NSFileProviderSyncAnchor($0) } ?? syncAnchor
                observer.finishEnumeratingChanges(upTo: next, moreComing: changes.moreComing)
            } catch {
                log.error("enumerateChanges \(cid, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                observer.finishEnumeratingWithError(error)
            }
        }
    }
}
