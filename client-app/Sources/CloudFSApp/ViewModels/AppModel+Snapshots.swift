// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import AppKit
import Observation
import CloudFSKit

// MARK: - SnapshotsFeatureModel  (WS4 — owned by the snapshot agent)
//
// State for the snapshot enhancements: deep lazy folder-tree browse, multi-select
// restore, and real manual-snapshot create. Factored into its OWN @Observable
// model + file so the WS4 agent never touches AppModel.swift (FROZEN) or the
// other feature files. `AppModel.snaps` holds the single instance.
//
// The restore engine + browse endpoints are UNCHANGED and survive WS1
// (CONTRACTS §2): `GatewayClient.listSnapshotFiles(snapshotID:in:parentID:)` for
// deep browse, `AppModel.restore(path:recursive:fromSnapshot:)` for restore, and
// the new `GatewayClient.createSnapshot(...)` for manual create.
//
// Time-Machine-style intent: restores bring items back as NEW current versions —
// nothing is overwritten wholesale, items newer than the snapshot are left
// untouched, and exclusively-locked items are skipped (never clobbered). That
// non-destructive, selective semantic is FROZEN (CONTRACTS §2, §6.2); the client
// only fans a multi-selection across the existing per-path restore and merges.

@MainActor
@Observable
final class SnapshotsFeatureModel {
    /// Root sentinel key for `children` / `expanded` (the snapshot namespace root).
    /// `listSnapshotFiles(parentID:)` takes a `String?`; we normalize root → "".
    static let rootKey = ""

    /// Lazily-loaded children of a snapshot folder, keyed by folder inode id
    /// ("" == root). Populated on first expand via the deep-browse seam.
    var children: [String: [FileNode]] = [:]
    /// Folder ids whose children are currently loading (drives per-row spinners).
    var loadingFolders: Set<String> = []
    /// Inode ids the user expanded in the tree (drives lazy load + chevrons).
    var expanded: Set<String> = []

    /// Multi-select restore: the snapshot file nodes the user picked. Keyed by id
    /// so a node can be toggled from anywhere in the (lazy) tree. We keep whole
    /// `FileNode`s so we know each item's name + directory-ness (→ recursive).
    var selected: [String: FileNode] = [:]

    /// The snapshot the loaded tree belongs to (reset clears stale children).
    var browsingSnapshotID: String?

    /// Set while a manual-snapshot create / multi-restore is in flight.
    var isWorking = false
    /// Outcome of the most recent multi-select restore (aggregated across paths).
    var lastRestoreResult: RestoreResult?
    /// Human-readable error from the most recent restore / create, if any.
    var lastError: String?
    /// Set briefly after a successful manual create so the view can confirm.
    var lastCreatedSnapshotName: String?
    var mounts: [SnapshotMount] = []
    var mountInProgress: String?

    init() {}

    // MARK: Derived helpers (pure — keep the view declarative)

    /// Children already loaded for `folderID` (nil == root).
    func loadedChildren(of folderID: String?) -> [FileNode]? {
        children[folderID ?? Self.rootKey]
    }

    var hasSelection: Bool { !selected.isEmpty }
    var selectionCount: Int { selected.count }

    /// Reset all browse + selection state when the selected snapshot changes.
    func resetBrowse(for snapshotID: String?) {
        children = [:]
        loadingFolders = []
        expanded = []
        selected = [:]
        browsingSnapshotID = snapshotID
        lastRestoreResult = nil
        lastError = nil
        lastCreatedSnapshotName = nil
    }

    func isSelected(_ node: FileNode) -> Bool { selected[node.id] != nil }

    func toggleSelection(_ node: FileNode) {
        if selected[node.id] != nil { selected[node.id] = nil }
        else { selected[node.id] = node }
    }
}

extension AppModel {
    func refreshSnapshotMounts() async {
        // Demo data must never be sent to a real daemon discovered on this Mac.
        guard isHttpMode, engine.isAvailable, !isSigningOut,
              let filespace = selectedFilespaceID else { snaps.mounts = []; return }
        do {
            let mounts = try await engine.snapshotMounts(filespace: filespace)
            guard isHttpMode, !isSigningOut, selectedFilespaceID == filespace else { return }
            snaps.mounts = mounts
        } catch {
            if isHttpMode, !isSigningOut, selectedFilespaceID == filespace {
                snaps.lastError = error.localizedDescription
            }
        }
    }

    func openSnapshotInFinder(_ snapshot: Snapshot) async {
        guard isHttpMode, engine.isAvailable, let filespace = selectedFilespaceID,
              snaps.mountInProgress == nil, !isSigningOut else { return }
        snaps.mountInProgress = snapshot.id; snaps.lastError = nil
        defer { snaps.mountInProgress = nil }
        do {
            let record = try await mountOperations.perform(generation: mountOperations.generation) {
                try await engine.mountSnapshot(filespace: filespace, snapshotID: snapshot.id, at: nil,
                                               name: snapshot.name + " (Snapshot)")
            }
            guard isHttpMode, !isSigningOut, selectedFilespaceID == filespace,
                  let path = record.mountPath, record.isMounted else { return }
            if !NSWorkspace.shared.open(URL(fileURLWithPath: path)) {
                snaps.lastError = "Finder could not open the snapshot. Try Open in Finder again."
            }
            await refreshSnapshotMounts()
        } catch {
            if isHttpMode, !isSigningOut, selectedFilespaceID == filespace {
                snaps.lastError = error.localizedDescription
            }
        }
    }

    func ejectSnapshot(_ snapshot: Snapshot) async {
        guard isHttpMode, engine.isAvailable, !isSigningOut,
              let filespace = selectedFilespaceID,
              let mounted = snaps.mounts.first(where: { $0.snapshotId == snapshot.id && $0.isMounted }),
              snaps.mountInProgress == nil else { return }
        snaps.mountInProgress = snapshot.id; snaps.lastError = nil
        defer { snaps.mountInProgress = nil }
        do {
            _ = try await engine.unmountSnapshot(mountID: mounted.mountId, force: false)
            await refreshSnapshotMounts()
        } catch {
            if isHttpMode, !isSigningOut, selectedFilespaceID == filespace {
                snaps.lastError = "Close any documents open from this snapshot and try ejecting again. " + error.localizedDescription
            }
        }
    }

    // MARK: Deep lazy folder-tree browse (CONTRACTS §6.1)

    /// Lazily load the children of a folder AS-OF a snapshot (deep browse). Drives
    /// per-directory expansion: each expanded folder fetches only its own level
    /// through the EXISTING `listSnapshotFiles(parentID:)` endpoint — no backend
    /// change, no whole-tree load. Results are cached in `snaps.children` keyed by
    /// the folder inode id ("" == root) so re-expanding is instant.
    func loadSnapshotChildren(snapshotID: String, folderID: String?) async {
        guard let fsID = selectedFilespaceID else { return }
        let key = folderID ?? SnapshotsFeatureModel.rootKey

        // Already cached → nothing to do (collapse/expand stays instant).
        if snaps.children[key] != nil { return }

        snaps.loadingFolders.insert(key)
        defer {
            if selectedFilespaceID == fsID, snaps.browsingSnapshotID == snapshotID {
                snaps.loadingFolders.remove(key)
            }
        }
        do {
            let nodes = try await gateway.listSnapshotFiles(
                snapshotID: snapshotID, in: fsID, parentID: folderID ?? snapshots.first(where: { $0.id == snapshotID })?.scope)
            guard selectedFilespaceID == fsID, snaps.browsingSnapshotID == snapshotID else { return }
            snaps.children[key] = nodes
        } catch {
            guard selectedFilespaceID == fsID, snaps.browsingSnapshotID == snapshotID else { return }
            // A failed request is not an empty folder. Leave it uncached so
            // collapsing/reopening the folder retries the request.
            snaps.lastError = restoreFailureText(error)
        }
    }

    /// Expand (and lazily load) or collapse a folder in the snapshot tree.
    func toggleSnapshotFolder(snapshotID: String, folder: FileNode) async {
        if snaps.expanded.contains(folder.id) {
            snaps.expanded.remove(folder.id)
        } else {
            snaps.expanded.insert(folder.id)
            await loadSnapshotChildren(snapshotID: snapshotID, folderID: folder.id)
        }
    }

    /// Prepare browse state for a freshly-selected snapshot, then load its root.
    func beginSnapshotBrowse(_ snapshotID: String) async {
        if snaps.browsingSnapshotID != snapshotID {
            snaps.resetBrowse(for: snapshotID)
        }
        await loadSnapshotChildren(snapshotID: snapshotID, folderID: nil)
    }

    // MARK: Multi-select restore (CONTRACTS §6.2 — non-destructive, selective)

    /// Restore the user's multi-selection from a snapshot. Loops the EXISTING
    /// single-path `restore(path:recursive:fromSnapshot:)` (the client-only batch
    /// fallback per CONTRACTS §6.2 — no backend change needed to ship multi-select)
    /// and merges every per-path `RestoreResult` into one aggregate the view shows.
    ///
    /// Semantics are FROZEN and Time-Machine-style: each restored item returns as a
    /// NEW current version, nothing is overwritten wholesale, items newer than the
    /// snapshot are left untouched, and exclusively-locked items are skipped.
    func restoreSelected(fromSnapshot snapshotID: String) async {
        guard let fsID = selectedFilespaceID, !snaps.isWorking else { return }
        let nodes = Array(snaps.selected.values)
        guard !nodes.isEmpty else { return }

        snaps.isWorking = true
        snaps.lastError = nil
        snaps.lastRestoreResult = nil
        defer { snaps.isWorking = false }

        var merged = RestoreResult(snapshotId: snapshotID, restored: [],
                                   recreated: [], conflicts: [], newerThanSnapshot: [])
        var firstError: String?

        // Restore in a stable order (folders' recursive flag follows isDirectory).
        for node in nodes.sorted(by: { $0.name.localizedStandardCompare($1.name) == .orderedAscending }) {
            do {
                let r = try await gateway.restore(path: node.id, recursive: node.isDirectory,
                                                  fromSnapshot: snapshotID, in: fsID)
                merged.restored.append(contentsOf: r.restored)
                merged.recreated.append(contentsOf: r.recreated)
                merged.conflicts.append(contentsOf: r.conflicts)
                merged.newerThanSnapshot.append(contentsOf: r.newerThanSnapshot)
                if let forbidden = r.forbidden { merged.forbidden = (merged.forbidden ?? []) + forbidden }
                merged.skippedPermissions = (merged.skippedPermissions ?? 0) + (r.skippedPermissions ?? r.forbidden?.count ?? 0)
                if r.streamsCaptured == false { merged.streamsCaptured = false }
            } catch {
                if firstError == nil { firstError = restoreFailureText(error) }
            }
        }

        guard selectedFilespaceID == fsID, snaps.browsingSnapshotID == snapshotID else { return }
        snaps.lastRestoreResult = merged
        snaps.lastError = firstError
        await refreshForSelection()
        // Keep the selection so the user can see what they acted on; the result
        // banner reflects what actually applied vs. was skipped.
    }

    // MARK: Real manual snapshot create (CONTRACTS §6.3)

    /// Take a REAL manual snapshot through the existing gateway route, then refresh
    /// the snapshot list so the new point-in-time appears immediately (replaces the
    /// old activity-log-only stub). `label` is optional; the gateway/mock supplies a
    /// timestamped default.
    @discardableResult
    func takeManualSnapshot(label: String? = nil, scope: String? = nil) async -> Bool {
        guard let id = selectedFilespaceID else {
            snaps.lastError = "No filespace selected."
            return false
        }
        guard canManageFolderAccess, !snaps.isWorking else { return false }
        snaps.isWorking = true
        snaps.lastError = nil
        snaps.lastCreatedSnapshotName = nil
        defer { snaps.isWorking = false }
        do {
            let trimmed = label?.trimmingCharacters(in: .whitespacesAndNewlines)
            let snap = try await gateway.createSnapshot(
                label: (trimmed?.isEmpty == false) ? trimmed : nil,
                scope: scope, tier: nil, in: id)
            guard selectedFilespaceID == id else { return true }
            snaps.lastCreatedSnapshotName = snap.name
            await refreshForSelection()
            return true
        } catch {
            if selectedFilespaceID == id { snaps.lastError = restoreFailureText(error) }
            return false
        }
    }

    // MARK: Error text

    /// Map a thrown error to a clear, action-specific message (mirrors the view's
    /// gateway-error mapping so model-side failures read the same).
    private func restoreFailureText(_ error: Error) -> String {
        if let e = error as? HttpGatewayClient.GatewayError {
            switch e {
            case .http(let status, let code, let reason):
                switch status {
                case 409:
                    return "Locked by another editor right now — try again once the lease is released."
                case 404:
                    return "Snapshot or path no longer exists (\(reason ?? code))."
                case 403:
                    return "You don’t have edit access on this path (\(reason ?? code))."
                default:
                    return "Gateway returned \(status) \(code)\(reason.map { " — \($0)" } ?? "")."
                }
            case .unsupported(let m):
                return m
            default:
                return e.description
            }
        }
        return error.localizedDescription
    }
}
