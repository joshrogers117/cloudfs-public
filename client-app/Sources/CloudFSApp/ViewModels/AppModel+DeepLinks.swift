// SPDX-License-Identifier: AGPL-3.0-or-later
import AppKit
import CloudFSKit

extension AppModel {
    /// Links carry no credentials. Only the signed-in account's known filespaces
    /// may be selected; filesystem access still goes through the mounted ACLs.
    func handleNavigationLink(_ url: URL) -> Bool {
        guard url.scheme?.lowercased() == DeepLink.scheme else { return false }
        guard let link = DeepLink.parse(url.absoluteString) else {
            operationError = "This CloudFS link is not valid. Ask the sender to copy a new link."
            return true
        }
        navigationRequestID = UUID()
        pendingNavigationLink = link
        NSApp.activate(ignoringOtherApps: true)
        if isSignedIn { Task { await resumePendingNavigationLink() } }
        return true
    }

    func resumePendingNavigationLink() async {
        guard isSignedIn, !isSigningOut, let link = pendingNavigationLink else { return }
        let requestID = navigationRequestID
        let mountGeneration = mountOperations.generation
        pendingNavigationLink = nil
        operationError = nil
        guard let fs = filespaces.first(where: { $0.id == link.spaceId }) else {
            operationError = "This filespace is not available in your workspace. Check that you signed in to the right workspace and have access."
            return
        }
        select(fs.id)
        guard isHttpMode, isEngineConnected else {
            operationError = "Connect the CloudFS background service to open this link in Finder."
            return
        }
        guard !dashboard.busyFilespaces.contains(fs.id) else {
            operationError = "This filespace is connecting or disconnecting. Open the link again when it has finished."
            return
        }
        dashboard.busyFilespaces.insert(fs.id)
        defer { dashboard.busyFilespaces.remove(fs.id) }
        do {
            // The shared gate makes sign-out drain this operation before taking
            // its mount list; idempotent mount retains the daemon's projection.
            let record = try await mountOperations.perform(generation: mountGeneration) {
                try await engine.mount(filespace: fs.id, at: nil, name: fs.name)
            }
            guard isSignedIn, !isSigningOut, requestID == navigationRequestID else { return }
            guard let path = record.mountPath, !path.isEmpty else {
                throw EngineError.decoding("The filespace did not connect. Try connecting it from the dashboard.")
            }
            intentionallyDisconnected.remove(fs.id)
            let paused = record.paused ?? (record.status == "disconnected")
            if paused { pausedFilespaces.insert(fs.id) }
            else { pausedFilespaces.remove(fs.id) }
            onboarding.mountRows[fs.id] = nil
            if let index = filespaces.firstIndex(where: { $0.id == fs.id }) {
                filespaces[index].connection = paused ? .paused : .connected
                filespaces[index].mountPath = path
            }
            let resolvedLink: DeepLink.Parsed
            if let itemID = link.itemId {
                let resolved = try await engine.resolveItemLink(filespace: fs.id, itemID: itemID)
                resolvedLink = DeepLink.Parsed(spaceId: fs.id, path: resolved.path, select: link.select)
            } else {
                resolvedLink = link
            }
            guard isSignedIn, !isSigningOut, requestID == navigationRequestID else { return }
            let target = await Task.detached(priority: .userInitiated) {
                guard MountProbe.isCloudFSMounted(mountRoot: path),
                      let url = DeepLink.resolve(resolvedLink, mountPath: path),
                      FileManager.default.fileExists(atPath: url.path) else { return Optional<URL>.none }
                return url
            }.value
            guard isSignedIn, !isSigningOut, requestID == navigationRequestID else { return }
            guard let target else {
                operationError = "This item is unavailable. It may have moved, or you may not have access to its folder."
                return
            }
            if resolvedLink.path.isEmpty {
                NSWorkspace.shared.open(target)
            } else if link.select {
                NSWorkspace.shared.activateFileViewerSelecting([target])
            } else {
                NSWorkspace.shared.open(target.deletingLastPathComponent())
            }
        } catch {
            guard isSignedIn, !isSigningOut, requestID == navigationRequestID else { return }
            operationError = "Could not open this CloudFS link. \(error.localizedDescription)"
            noteEngineError(error)
        }
    }
}
