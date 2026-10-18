// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import Observation
import CloudFSKit

@MainActor @Observable
final class RecoveryFeatureModel {
    var filespaceID: String?
    var state: LoadState<[RecoveryItem]> = .idle
    var busyIDs: Set<String> = []
    var actionErrors: [String: String] = [:]
    var savedCopies: [String: RecoveryExportResult] = [:]
    var retryingIDs: Set<String> = []
    var isRefreshing = false
    var items: [RecoveryItem] = []
    var completionNotice: String?

    func reset(for id: String?) {
        filespaceID = id; state = .idle; busyIDs = []; actionErrors = [:]
        savedCopies = [:]; retryingIDs = []; isRefreshing = false
        items = []; completionNotice = nil
    }
}

extension AppModel {
    func loadRecoveryItems() async {
        guard let id = selectedFilespaceID else { recovery.reset(for: nil); return }
        if recovery.filespaceID != id { recovery.reset(for: id) }
        guard !recovery.isRefreshing else { return }
        guard isHttpMode else {
            recovery.state = .loaded(ProcessInfo.processInfo.environment["CLOUDFS_DEMO_RECOVERY"] == "1" ? [
                RecoveryItem(id: "demo-conflict", path: "Editorial/Assembly.prproj", bytes: 7_864_320,
                             reason: "A teammate saved a newer version while this Mac had local changes.", kind: "conflict", canRetry: false),
                RecoveryItem(id: "demo-upload", path: "Exports/Review.mov", bytes: 125_829_120,
                             reason: "The upload could not finish after several attempts.", kind: "upload", canRetry: true)
            ] : [])
            recovery.items = recovery.state.value ?? []
            return
        }
        guard isEngineConnected else {
            recovery.state = .failed("Connect the background engine to check for local changes that need recovery.")
            return
        }
        if recovery.state.value == nil { recovery.state = .loading }
        recovery.isRefreshing = true
        defer { if recovery.filespaceID == id { recovery.isRefreshing = false } }
        do {
            let items = try await engine.recoveryItems(filespace: id)
            guard selectedFilespaceID == id, recovery.filespaceID == id else { return }
            recovery.state = .loaded(items)
            recovery.items = items
            recovery.retryingIDs.formIntersection(Set(items.map(\.id)))
        } catch {
            guard selectedFilespaceID == id, recovery.filespaceID == id else { return }
            recovery.state = .failed(error.localizedDescription)
        }
    }

    func retryRecovery(_ item: RecoveryItem) async {
        guard let fsID = selectedFilespaceID, isHttpMode, item.canRetry,
              !recovery.busyIDs.contains(item.id) else { return }
        recovery.busyIDs.insert(item.id)
        recovery.actionErrors[item.id] = nil
        defer { if recovery.filespaceID == fsID { recovery.busyIDs.remove(item.id) } }
        do {
            try await engine.retryRecovery(filespace: fsID, itemID: item.id)
            guard selectedFilespaceID == fsID else { return }
            recovery.retryingIDs.insert(item.id)
            await loadRecoveryItems()
            await loadDashboardSyncState()
        } catch {
            guard selectedFilespaceID == fsID else { return }
            recovery.actionErrors[item.id] = error.localizedDescription
        }
    }

    func saveRecoveryCopy(_ item: RecoveryItem) {
        guard let fsID = selectedFilespaceID, isHttpMode, item.canExport,
              !recovery.busyIDs.contains(item.id) else { return }
        let panel = NSSavePanel()
        panel.title = "Save local copy"
        panel.message = "Choose a new filename outside the filespace. Your pending changes remain preserved until they are safely resolved."
        panel.nameFieldStringValue = item.suggestedFileName
        panel.canCreateDirectories = true
        panel.isExtensionHidden = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        recovery.busyIDs.insert(item.id)
        recovery.actionErrors[item.id] = nil
        Task {
            defer { if recovery.filespaceID == fsID { recovery.busyIDs.remove(item.id) } }
            do {
                let saved = try await engine.exportRecovery(filespace: fsID, itemID: item.id, destination: url.path)
                guard recovery.filespaceID == fsID else { return }
                recovery.savedCopies[item.id] = saved
            } catch {
                guard recovery.filespaceID == fsID else { return }
                recovery.actionErrors[item.id] = "Could not save the copy. \(error.localizedDescription) Your local changes are still preserved."
            }
        }
    }

    func completeRecovery(_ item: RecoveryItem) async {
        guard let fsID = selectedFilespaceID, isHttpMode,
              let saved = recovery.savedCopies[item.id], !recovery.busyIDs.contains(item.id) else { return }
        recovery.busyIDs.insert(item.id)
        recovery.actionErrors[item.id] = nil
        defer { if recovery.filespaceID == fsID { recovery.busyIDs.remove(item.id) } }
        do {
            try await engine.completeRecovery(filespace: fsID, itemID: item.id, destination: saved.path)
            guard recovery.filespaceID == fsID else { return }
            recovery.savedCopies[item.id] = nil
            recovery.completionNotice = "Recovery finished for \(item.displayName). Your verified copy is saved at \(saved.path). Close and reopen the file in your editing app to use the team’s current version."
            await loadRecoveryItems()
            await loadDashboardSyncState()
        } catch {
            guard recovery.filespaceID == fsID else { return }
            recovery.actionErrors[item.id] = "Recovery could not finish. \(error.localizedDescription) The pending local write is still preserved."
        }
    }
}
