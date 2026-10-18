// SPDX-License-Identifier: AGPL-3.0-or-later
import Cocoa
import FinderSync
import CloudFSKit

// MARK: - FinderSync — badges + Pin/Unpin/Copy-Link in Finder (M8)
//
// A deliberately THIN shim: all decisions live in CloudFSKit.FinderIntegration
// (unit-tested) and the daemon. The appex polls the daemon over the App-Group
// `finder.sock` (the only rendezvous its sandbox can reach) for the mount table
// and pin records, then answers Finder's badge queries from that snapshot.
//
// Badges: "pinned" (fully materialized, non-evictable) / "pinning" (materializing).
// Cloud-only files carry no badge — in a filespace of millions of items, badging
// the exceptional (locally guaranteed) state is the signal that matters.

final class FinderSync: FIFinderSync {

    private let engine: EngineClient
    private let state = StateStore()
    private var pollTask: Task<Void, Never>?

    override init() {
        if let sock = FinderIntegration.finderSocketPath {
            engine = DaemonEngineClient(socketPath: sock)
        } else {
            engine = NullEngineClient()
        }
        super.init()

        let controller = FIFinderSyncController.default()
        controller.setBadgeImage(
            NSImage(systemSymbolName: "pin.fill", accessibilityDescription: "Pinned")!,
            label: "Pinned", forBadgeIdentifier: "pinned")
        controller.setBadgeImage(
            NSImage(systemSymbolName: "arrow.down.circle", accessibilityDescription: "Pinning")!,
            label: "Pinning", forBadgeIdentifier: "pinning")
        controller.setBadgeImage(
            NSImage(systemSymbolName: "exclamationmark.circle", accessibilityDescription: "Needs attention")!,
            label: "Needs attention — open CloudFS", forBadgeIdentifier: "attention")

        startPolling()
    }

    deinit { pollTask?.cancel() }

    /// Refresh the mount table + pin records every few seconds. Mounts drive
    /// which directories Finder asks us about at all (directoryURLs).
    private func startPolling() {
        let engine = self.engine
        let state = self.state
        pollTask = Task.detached {
            while !Task.isCancelled {
                if let spaces = try? await engine.filespaceList() {
                    var mounts: [String: String] = [:]
                    for fs in spaces where fs.readOnly != true { if let mp = fs.mountPath { mounts[fs.id] = mp } }
                    var pins: [String: [FinderIntegration.PinRecord]] = [:]
                    for (fs, _) in mounts {
                        let list = (try? await engine.pinList(filespace: fs)) ?? []
                        pins[fs] = list.map {
                            FinderIntegration.PinRecord(path: $0.path, recursive: $0.recursive,
                                                        cacheState: $0.cacheState?.rawValue,
                                                        failureReason: $0.failureReason)
                        }
                    }
                    let changed = state.update(mounts: mounts, pins: pins)
                    if changed {
                        let urls = Set(mounts.values.map { URL(fileURLWithPath: $0) })
                        await MainActor.run {
                            FIFinderSyncController.default().directoryURLs = urls
                        }
                    }
                    // Finder does not necessarily re-request a badge when only
                    // background download progress changes. Refresh recent items.
                    let observed = state.observedURLs()
                    await MainActor.run {
                        let enabled = UserDefaults(suiteName: EngineFactory.appGroupIdentifier)?.object(forKey: "cloudfs.finderBadges") as? Bool ?? true
                        for url in observed {
                            let resolved = FinderIntegration.resolve(path: url.path, mounts: mounts)
                            let badge = enabled ? resolved.map { FinderIntegration.badge(relativePath: $0.relativePath, pins: pins[$0.filespace] ?? []) } ?? "" : ""
                            FIFinderSyncController.default().setBadgeIdentifier(badge, for: url)
                        }
                    }
                }
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }

    // MARK: Badges

    override func requestBadgeIdentifier(for url: URL) {
        state.remember(url)
        guard badgesEnabled else {
            FIFinderSyncController.default().setBadgeIdentifier("", for: url)
            return
        }
        let snapshot = state.snapshot()
        guard let (fs, rel) = FinderIntegration.resolve(path: url.path, mounts: snapshot.mounts)
        else { return }
        let badge = FinderIntegration.badge(relativePath: rel, pins: snapshot.pins[fs] ?? [])
        FIFinderSyncController.default().setBadgeIdentifier(badge, for: url)
    }

    /// Preferences → "Show cloud badges in Finder" writes this shared flag.
    private var badgesEnabled: Bool {
        UserDefaults(suiteName: EngineFactory.appGroupIdentifier)?
            .object(forKey: "cloudfs.finderBadges") as? Bool ?? true
    }

    // MARK: Context menu

    override var toolbarItemName: String { "cloud-fs" }
    override var toolbarItemToolTip: String { "cloud-fs: pin files for offline-fast access" }
    override var toolbarItemImage: NSImage {
        NSImage(systemSymbolName: "cloud", accessibilityDescription: "cloud-fs")!
    }

    override func menu(for menuKind: FIMenuKind) -> NSMenu? {
        guard menuKind == .contextualMenuForItems || menuKind == .toolbarItemMenu else { return nil }
        // STATEFUL: offer Pin only for unpinned items, Unpin only for pinned ones
        // (a mixed selection gets both, each acting on its half).
        let snapshot = state.snapshot()
        let resolved = (FIFinderSyncController.default().selectedItemURLs() ?? [])
            .compactMap { FinderIntegration.resolve(path: $0.path, mounts: snapshot.mounts) }
        guard !resolved.isEmpty else { return nil }
        let actions = FinderIntegration.menuActions(items: resolved, pins: snapshot.pins)
        let menu = NSMenu(title: "cloud-fs")
        func add(_ title: String, _ action: Selector) {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
            item.image = Self.menuIcon   // app icon tags our items in Finder's crowded menu
            menu.addItem(item)
        }
        if actions.showPin { add("Pin to This Mac", #selector(pinSelection(_:))) }
        if actions.showUnpin { add("Unpin", #selector(unpinSelection(_:))) }
        add("Copy cloud-fs Link", #selector(copyLink(_:)))
        return menu
    }

    /// The HOST APP's icon at menu size (Resources/AppIcon.icns — the cloudfs
    /// purple drive mark). The appex lives three hops below the app bundle.
    private static let menuIcon: NSImage = {
        let appURL = Bundle.main.bundleURL
            .deletingLastPathComponent()   // PlugIns
            .deletingLastPathComponent()   // Contents
            .deletingLastPathComponent()   // CloudFSApp.app
        let icon = NSWorkspace.shared.icon(forFile: appURL.path)
        icon.size = NSSize(width: 16, height: 16)
        return icon
    }()

    @objc private func pinSelection(_ sender: AnyObject?) { setPinned(true) }
    @objc private func unpinSelection(_ sender: AnyObject?) { setPinned(false) }

    private func setPinned(_ pinned: Bool) {
        let urls = FIFinderSyncController.default().selectedItemURLs() ?? []
        let snapshot = state.snapshot()
        let engine = self.engine
        let state = self.state
        for url in urls {
            guard let (fs, rel) = FinderIntegration.resolve(path: url.path, mounts: snapshot.mounts)
            else { continue }
            // In a mixed selection each action applies only to its half: Pin skips
            // already-pinned items, Unpin skips unpinned ones.
            let isPinned = !FinderIntegration.badge(relativePath: rel, pins: snapshot.pins[fs] ?? []).isEmpty
            guard isPinned != pinned else { continue }
            let isDir = (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
            Task.detached {
                do {
                    if pinned { _ = try await engine.pin(filespace: fs, path: rel, recursive: isDir) }
                    else { _ = try await engine.unpin(filespace: fs, path: rel, recursive: isDir) }
                    // Publish only after the engine accepted the persistent intent.
                    state.applyLocal(filespace: fs, path: rel, pinned: pinned, recursive: isDir)
                    await MainActor.run {
                        FIFinderSyncController.default().setBadgeIdentifier(pinned ? "pinning" : "", for: url)
                    }
                } catch {
                    let message = error.localizedDescription
                    await MainActor.run {
                        let alert = NSAlert()
                        alert.messageText = pinned ? "Couldn't pin this item" : "Couldn't unpin this item"
                        alert.informativeText = message
                        alert.runModal()
                    }
                }
            }
        }
    }

    @objc private func copyLink(_ sender: AnyObject?) {
        let snapshot = state.snapshot()
        let selected = (FIFinderSyncController.default().selectedItemURLs() ?? []).compactMap {
            FinderIntegration.resolve(path: $0.path, mounts: snapshot.mounts)
        }
        guard !selected.isEmpty else { return }
        let engine = self.engine
        Task.detached {
            do {
                var links: [String] = []
                for (filespace, path) in selected {
                    let url: URL?
                    if path.isEmpty {
                        url = FinderIntegration.shareLink(filespace: filespace, relativePath: "")
                    } else {
                        let item = try await engine.createItemLink(filespace: filespace, path: path)
                        url = FinderIntegration.shareItemLink(filespace: item.filespace, itemId: item.itemId)
                    }
                    guard let url else { throw EngineError.decoding("Could not create a valid team link.") }
                    links.append(url.absoluteString)
                }
                // Replace the clipboard only after every selected item resolves.
                let text = links.joined(separator: "\n")
                await MainActor.run {
                    let pasteboard = NSPasteboard.general
                    pasteboard.clearContents()
                    pasteboard.setString(text, forType: .string)
                }
            } catch {
                let message = error.localizedDescription
                await MainActor.run {
                    let alert = NSAlert()
                    alert.messageText = "Couldn't copy this link"
                    alert.informativeText = "The item may have moved or you may no longer have access. " + message
                    alert.runModal()
                }
            }
        }
    }

}

// MARK: - StateStore — lock-guarded snapshot the sync callbacks can read

/// Finder calls the FIFinderSync overrides on arbitrary threads while the poll
/// task writes from a background task; a tiny lock-guarded store keeps Swift-6
/// concurrency honest without actor-hop latency in the badge hot path.
private final class StateStore: @unchecked Sendable {
    struct Snapshot {
        var mounts: [String: String] = [:]                              // fs id → mountPath
        var pins: [String: [FinderIntegration.PinRecord]] = [:]        // fs id → pin records
    }
    private var current = Snapshot()
    private var observed: [URL] = []
    private let lock = NSLock()

    func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    func remember(_ url: URL) {
        lock.lock(); defer { lock.unlock() }
        observed.removeAll { $0 == url }
        observed.append(url)
        if observed.count > 512 { observed.removeFirst(observed.count - 512) }
    }
    func observedURLs() -> [URL] {
        lock.lock(); defer { lock.unlock() }
        return observed
    }

    /// Returns true when the MOUNT TABLE changed (the caller then re-registers
    /// directoryURLs with Finder; pin-only changes don't need that).
    func update(mounts: [String: String], pins: [String: [FinderIntegration.PinRecord]]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let mountsChanged = current.mounts != mounts
        current = Snapshot(mounts: mounts, pins: pins)
        return mountsChanged
    }

    /// Optimistic local mutation after a user pin/unpin — keeps the context menu
    /// and badges truthful in the window before the next daemon poll lands.
    func applyLocal(filespace: String, path: String, pinned: Bool, recursive: Bool) {
        lock.lock(); defer { lock.unlock() }
        var pins = current.pins[filespace] ?? []
        pins.removeAll { $0.path == path }
        if pinned {
            pins.append(FinderIntegration.PinRecord(path: path, recursive: recursive,
                                                    cacheState: "pinning"))
        }
        current.pins[filespace] = pins
    }
}
