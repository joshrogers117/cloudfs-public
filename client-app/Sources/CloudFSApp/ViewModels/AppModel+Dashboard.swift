// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import Observation
import CloudFSKit

@MainActor @Observable
final class DashboardFeatureModel {
    var pendingUploadBytes: Int64?
    var inSync: Bool?
    var checkedAt: Date?
    var busyFilespaces: Set<String> = []
    /// Daemon `status` for the selected filespace (reachability, last failure, latency).
    var status: EngineStatus?
    /// A grant root appeared that the mounted volume doesn't show yet.
    var newAccessAvailable = false
    var lastAccessCheck: Date?
    var lastUsageCheck: Date?
}

extension AppModel {
    func loadDashboardSyncState() async {
        guard let id = selectedFilespaceID, isHttpMode, isEngineConnected else {
            dashboard.pendingUploadBytes = nil
            dashboard.inSync = nil
            dashboard.checkedAt = nil
            return
        }
        do {
            let state = try await engine.syncState(filespace: id, path: "")
            guard selectedFilespaceID == id else { return }
            dashboard.pendingUploadBytes = state.pendingBytes
            dashboard.inSync = state.inSync
            dashboard.checkedAt = Date()
        } catch {
            guard selectedFilespaceID == id else { return }
            noteEngineError(error)
            dashboard.pendingUploadBytes = nil
            dashboard.inSync = nil
            dashboard.checkedAt = nil
        }
    }

    /// One dashboard poll tick: mount state (no auto-mount), sync/recovery readings,
    /// daemon status and the throttled new-access check.
    func dashboardTick() async {
        guard let id = selectedFilespaceID else { return }
        let plan = DashboardRefreshPlan.make(operationInFlight: dashboard.busyFilespaces.contains(id) || isSigningOut,
                                             lastAccessCheck: dashboard.lastAccessCheck, now: Date(),
                                             lastUsageCheck: dashboard.lastUsageCheck)
        if plan.refreshUsage, isHttpMode, isSignedIn {
            dashboard.lastUsageCheck = Date()
            await reloadFilespaces(reportErrors: false)
        }
        if plan.refreshMountState { await applyEngineMountState(autoMount: false) }
        await loadDashboardSyncState()
        await loadRecoveryItems()
        await loadDashboardStatus()
        if plan.checkNewAccess { await checkForNewMountAccess() }
    }

    func loadDashboardStatus() async {
        guard let id = selectedFilespaceID, isHttpMode, isEngineConnected else {
            dashboard.status = nil
            return
        }
        let status = try? await engine.status(filespace: id)   // older daemon / transient: keep UI honest, show nothing extra
        guard selectedFilespaceID == id else { return }
        dashboard.status = status
    }

    /// Reachability for the selected filespace as the dashboard should show it.
    var dashboardReachability: EngineReachability? { dashboard.status?.reachability }

    func checkForNewMountAccess() async {
        guard let id = selectedFilespaceID, isHttpMode, isEngineConnected else {
            dashboard.newAccessAvailable = false
            return
        }
        dashboard.lastAccessCheck = Date()
        guard let mounted = dashboard.status?.mountedRootIds,
              let current = try? await gateway.mountRootIds(in: id) else {
            if dashboard.status?.mountedRootIds == nil { dashboard.newAccessAvailable = false }
            return
        }
        guard selectedFilespaceID == id else { return }
        dashboard.newAccessAvailable = MountAccessChange.hasNewAccess(mountedRootIds: mounted, currentRootIds: current)
    }

    /// "Reconnect" from the new-access hint: flush, unmount, then mount again so the
    /// projection is rebuilt from the current grants.
    func reconnectSelectedForNewAccess() async {
        guard let id = selectedFilespaceID else { return }
        await unmountSelected()
        guard operationError == nil, selectedFilespaceID == id else { return }
        await mountSelected()
        dashboard.newAccessAvailable = false
        dashboard.lastAccessCheck = nil
    }

    func unmountSelected() async {
        guard let fs = selectedFilespace, isSignedIn, !isSigningOut, isHttpMode, isEngineConnected,
              !dashboard.busyFilespaces.contains(fs.id) else { return }
        dashboard.busyFilespaces.insert(fs.id)
        operationError = nil
        defer { dashboard.busyFilespaces.remove(fs.id) }
        do {
            // Upload and commit before disconnecting. Never force a busy mount.
            _ = try await engine.flush(filespace: fs.id, path: "", wait: true, timeoutMs: 60_000)
            let rec = try await engine.unmount(filespace: fs.id, force: false)
            intentionallyDisconnected.insert(fs.id)
            pausedFilespaces.remove(fs.id)
            onboarding.mountRows[fs.id] = nil
            applyDashboardMountRecord(rec, to: fs.id)
            await loadDashboardSyncState()
        } catch {
            operationError = "Could not finish disconnecting \(fs.name). Pending changes are preserved on this Mac. \(error.localizedDescription)"
            noteEngineError(error)
            await applyEngineMountState(autoMount: false)
        }
    }

    func mountSelected() async {
        let mountGeneration = mountOperations.generation
        guard let fs = selectedFilespace, isSignedIn, !isSigningOut, isHttpMode, isEngineConnected,
              !dashboard.busyFilespaces.contains(fs.id) else { return }
        dashboard.busyFilespaces.insert(fs.id)
        operationError = nil
        defer { dashboard.busyFilespaces.remove(fs.id) }
        do {
            let rec = try await mountOperations.perform(generation: mountGeneration) {
                try await engine.mount(filespace: fs.id, at: nil, name: fs.name)
            }
            guard isSignedIn, !isSigningOut else { return }
            intentionallyDisconnected.remove(fs.id)
            pausedFilespaces.remove(fs.id)
            onboarding.mountRows[fs.id] = nil
            applyDashboardMountRecord(rec, to: fs.id)
            await refreshForSelection()
        } catch {
            guard isSignedIn, !isSigningOut else { return }
            operationError = "Could not connect \(fs.name). \(error.localizedDescription)"
            noteEngineError(error)
        }
    }

    private func applyDashboardMountRecord(_ rec: EngineFilespace, to id: String) {
        guard let idx = filespaces.firstIndex(where: { $0.id == id }) else { return }
        if rec.status == "connected", let mp = rec.mountPath, !mp.isEmpty {
            filespaces[idx].connection = .connected
            filespaces[idx].mountPath = mp
        } else {
            filespaces[idx].connection = .disconnected
            filespaces[idx].mountPath = ""
        }
    }
}
