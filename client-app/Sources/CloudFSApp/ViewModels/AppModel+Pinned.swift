// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import Observation
import CloudFSKit

// MARK: - PinnedFeatureModel  (WS2 — owned by the pinned-view agent)
//
// The Pinned Items feature state, factored into its OWN @Observable model + file
// so the WS2 agent never touches AppModel.swift (FROZEN) or the other feature
// files. `AppModel.pinned` holds the single instance; `PinnedItemsView` reads it.
//
// Load path is engine-preferred: when a cloudfsd socket is present we call
// `EngineClient.pinList(filespace:)` → `[PinState]` → `[PinnedItem]`. With no
// daemon (Mock / offline) the engine throws `.unavailable` and the gateway has
// no pin-list route, so we fall back to `PinnedItem.fixtures()` so the pane
// builds, previews, and demos fully offline. Per-row Unpin is the single action:
// it reuses `AppModel.setPinned(false,…)` (survives WS1, CONTRACTS §1.1) to drop
// the keep-local pin, then we reload — the unpinned path has no pin record, so it
// leaves the list.

@MainActor
@Observable
final class PinnedFeatureModel {
    /// The flat list of pinned items (display projection of `[PinState]`),
    /// already sorted for display. Kept alongside `state` so derived summaries
    /// (the total-cache-used strip) read it directly.
    var items: [PinnedItem] = []
    /// EMPTY / LOADING / ERROR presentation state for the pane.
    var state: LoadState<[PinnedItem]> = .idle
    /// The set of paths with an Unpin in flight (disables that row's button +
    /// shows a spinner) so the user can't double-fire a mutation.
    var busyPaths: Set<String> = []

    /// The sortable table's current column + direction (Name / Size / Status).
    /// Defaults to Name ascending; tapping a header updates this in place.
    var sort: PinnedSort = .default

    /// Filespace-wide rollup powering the summary strip.
    var summary: PinnedSummary { PinnedSummary(items: items) }

    init() {}
}

extension AppModel {

    /// Load the pinned-items list for the selected filespace. Engine-preferred
    /// (`pinList`); with no engine we branch on `mode` — Mock/demo serves the
    /// offline fixture so the pane previews and demos fully offline, but HTTP
    /// mode with no daemon reachable shows an HONEST "needs the local engine"
    /// state rather than fabricated fixture data (there's no gateway pin-list
    /// route to fall back to for a real account). Folds the result into
    /// `pinned.state` + `pinned.items` (sorted for display).
    func loadPinnedItems(showLoading: Bool = true) async {
        guard let id = selectedFilespaceID else {
            pinned.items = []
            pinned.state = .loaded([])
            return
        }
        if showLoading { pinned.state = .loading }
        let raw: [PinState]
        if isEngineConnected {
            // Engine-preferred: cloudfsd `pin.list`. A real engine error surfaces.
            do { raw = try await engine.pinList(filespace: id) }
            catch {
                guard selectedFilespaceID == id else { return }
                pinned.items = []
                pinned.state = .failed(error.localizedDescription)
                return
            }
        } else if mode == .mock {
            // Offline/demo: no daemon to ask and no route to fake it, so serve the
            // fixture — this is the ONLY path that ever shows fixture data.
            raw = PinnedItem.fixtures().map(\.asPinState)
        } else {
            // HTTP mode with no reachable engine: never silently swap in fixture
            // data for a real account. Say so plainly; the pane's Retry re-checks
            // the engine once the daemon comes up.
            pinned.items = []
            pinned.state = .failed("Pinned files need the local engine. Start cloudfsd, then try again.")
            return
        }
        guard selectedFilespaceID == id else { return }
        let items = raw.map(PinnedItem.init(from:)).sortedForDisplay()
        pinned.items = items
        pinned.state = .loaded(items)
    }

    /// Per-row Unpin → existing `setPinned(false,…)`, then reload so the row
    /// drops out and the summary recomputes. Marks the row busy meanwhile. Unpin
    /// is the single per-row action on the Pinned screen: it removes the
    /// keep-local pin, so the item leaves the list (an unpinned path has no pin
    /// record).
    func unpinItem(_ item: PinnedItem) async {
        guard selectedFilespaceID != nil else { return }
        pinned.busyPaths.insert(item.path)
        _ = await setPinned(false, path: item.path, fileID: item.path)
        await loadPinnedItems()
        pinned.busyPaths.remove(item.path)
    }

    /// Reveal a pinned item in Finder at its real path under the mounted volume.
    func showPinnedInFinder(_ item: PinnedItem) {
        guard let fs = selectedFilespace, isSignedIn, !isSigningOut else { return }
        let base = (fs.mountPath as NSString).expandingTildeInPath
        guard !base.isEmpty, MountProbe.isCloudFSMounted(mountRoot: base) else {
            operationError = "This filespace isn’t connected. Connect it to show the item in Finder."
            return
        }
        let relative = item.path.hasPrefix("/") ? String(item.path.dropFirst()) : item.path
        let target = URL(fileURLWithPath: base).appendingPathComponent(relative)
        NSWorkspace.shared.activateFileViewerSelecting([target])
    }

    func openOfflinePin(_ item: PinnedItem) async {
        guard let id = selectedFilespaceID, isEngineConnected, isSignedIn, !isSigningOut else { return }
        pinned.busyPaths.insert(item.path)
        defer { pinned.busyPaths.remove(item.path) }
        do {
            if try await engine.filespaceList().contains(where: { $0.id == id && $0.mountPath != nil }) {
                operationError = "Eject this filespace before opening its read-only offline copy."
                return
            }
            let mounted = try await engine.mountOffline(filespace: id, pinPath: item.path, name: item.displayName + " — Offline copy")
            if let path = mounted.mountPath { NSWorkspace.shared.open(URL(fileURLWithPath: path)) }
        } catch { operationError = "Couldn’t open offline copy. " + error.localizedDescription }
    }

    /// Re-issue the pin for a failed item (same recursion as the original), then reload.
    func retryPin(_ item: PinnedItem) async {
        guard let id = selectedFilespaceID, isEngineConnected else { return }
        pinned.busyPaths.insert(item.path)
        do { _ = try await engine.pin(filespace: id, path: item.path, recursive: item.recursive) }
        catch { operationError = "Couldn’t retry pinning \(item.displayName). \(error.localizedDescription)" }
        await loadPinnedItems()
        pinned.busyPaths.remove(item.path)
    }

    /// "Unpin all" (header action, behind a confirmation dialog): drops every
    /// given item's pin SEQUENTIALLY — same underlying mutation as `unpinItem`
    /// — then reloads exactly ONCE at the end, so unpinning a large pinned set
    /// doesn't refetch the list after every single item.
    func unpinAll(_ items: [PinnedItem]) async {
        guard !items.isEmpty, selectedFilespaceID != nil else { return }
        let paths = items.map(\.path)
        pinned.busyPaths.formUnion(paths)
        for item in items {
            _ = await setPinned(false, path: item.path, fileID: item.path)
        }
        await loadPinnedItems()
        pinned.busyPaths.subtract(paths)
    }
}

// MARK: - PinnedItem → PinState (fixture round-trip)
//
// The fallback fixture is authored as display-ready `[PinnedItem]`; the fetch
// seam returns `[PinState]` (the wire shape) so the same `PinnedItem(from:)`
// projection runs in both the engine and fallback paths. This re-lifts a fixture
// row back to its wire form so there is a single mapping path through the loader.

private extension PinnedItem {
    var asPinState: PinState {
        // Every fixture row is a live pin (pinned or pinning); an unpinned/evicted
        // path has no pin record and never appears in the list.
        PinState(path: path, pinned: true, recursive: recursive,
                 blocks: 0, cachedBytes: cachedBytes, totalBytes: totalBytes,
                 cacheState: state, failureReason: failureReason)
    }
}
