// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - FinderIntegration — shared logic for the Finder Sync extension (M8)
//
// The Finder Sync appex is SANDBOXED (extension-point requirement), so the only
// daemon rendezvous it can reach is the App Group container: the daemon binds a
// SECOND control socket there (`finder.sock`, CLOUDFS_FINDER_SOCKET — provisioned
// by the app in daemon.env). Everything here is pure logic shared by the app and
// the appex, fully unit-tested; the appex itself stays a thin FIFinderSync shim.

public enum FinderIntegration {

    /// The finder control socket INSIDE the App Group container — the only path
    /// a sandboxed appex may connect to. (The main control socket lives in the
    /// support dir, which the appex cannot reach; see DaemonProvisioning.)
    public static var finderSocketPath: String? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: EngineFactory.appGroupIdentifier)?
            .appendingPathComponent("finder.sock").path
    }

    /// Map an absolute path to (filespace id, path relative to the filespace root)
    /// against a mount table `[filespace id: mountPath]`. Longest mount prefix wins
    /// (defensive — mounts should never nest). Returns nil for paths outside every
    /// mount. The mount root itself maps to relativePath "".
    public static func resolve(path: String, mounts: [String: String])
        -> (filespace: String, relativePath: String)? {
        var best: (filespace: String, relativePath: String, mountLen: Int)?
        for (fs, mount) in mounts where !mount.isEmpty {
            let root = mount.hasSuffix("/") ? String(mount.dropLast()) : mount
            if path == root {
                if best == nil || root.count > best!.mountLen { best = (fs, "", root.count) }
            } else if path.hasPrefix(root + "/") {
                let rel = String(path.dropFirst(root.count + 1))
                if best == nil || root.count > best!.mountLen { best = (fs, rel, root.count) }
            }
        }
        return best.map { ($0.filespace, $0.relativePath) }
    }

    /// Use the same navigation link format as the app's Sharing panel.
    public static func shareLink(filespace: String, relativePath: String) -> URL? {
        let link = DeepLink.build(spaceId: filespace, path: relativePath)
        guard DeepLink.parse(link) != nil else { return nil }
        return URL(string: link)
    }

    /// Stable identity obtained from the daemon's mounted-path resolver.
    public static func shareItemLink(filespace: String, itemId: String) -> URL? {
        let link = DeepLink.buildItem(spaceId: filespace, itemId: itemId)
        guard DeepLink.parse(link)?.itemId == itemId else { return nil }
        return URL(string: link)
    }

    /// Badge identity for a path given the filespace's pin records.
    /// "pinned" (fully materialized) / "pinning" (materializing) / "" (cloud-only).
    /// A pin on a DIRECTORY badges everything under it (recursive pins cover their
    /// subtree; pin.list paths are filespace-relative).
    public static func badge(relativePath: String, pins: [PinRecord]) -> String {
        var state = ""
        for pin in pins {
            let covers = relativePath == pin.path
                || (pin.recursive && (pin.path.isEmpty || relativePath.hasPrefix(pin.path + "/")))
            guard covers else { continue }
            if pin.failureReason != nil { state = "attention"; continue }
            if pin.cacheState == "pinned" { return "pinned" }
            if pin.cacheState == "pinning", state != "attention" { state = "pinning" }
        }
        return state
    }

    /// Stateful context menu: "Pin" only when the selection contains an UNpinned
    /// item, "Unpin" only when it contains a pinned/pinning one. A mixed selection
    /// shows both (each action applies to its half); a selection that is entirely
    /// one state shows exactly one option.
    public static func menuActions(items: [(filespace: String, relativePath: String)],
                                   pins: [String: [PinRecord]]) -> (showPin: Bool, showUnpin: Bool) {
        var showPin = false, showUnpin = false
        for (fs, rel) in items {
            if badge(relativePath: rel, pins: pins[fs] ?? []).isEmpty { showPin = true }
            // An inherited folder pin cannot be removed by unpinning this child.
            // Offer Unpin only at an actual pin root, avoiding a no-op action.
            else if (pins[fs] ?? []).contains(where: { $0.path == rel }) { showUnpin = true }
        }
        return (showPin, showUnpin)
    }

    /// The slice of PinState the badge logic needs (decoupled so tests don't have
    /// to build full PinStates).
    public struct PinRecord: Sendable, Equatable {
        public let path: String
        public let recursive: Bool
        public let cacheState: String?
        public let failureReason: String?
        public init(path: String, recursive: Bool, cacheState: String?, failureReason: String? = nil) {
            self.path = path; self.recursive = recursive; self.cacheState = cacheState
            self.failureReason = failureReason
        }
    }
}
