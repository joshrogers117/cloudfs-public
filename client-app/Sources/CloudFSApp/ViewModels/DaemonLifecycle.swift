// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import ServiceManagement
import CloudFSKit
import os

// MARK: - DaemonLifecycle — the embedded cloudfsd as a launch agent (M7)
//
// The daemon ships inside the app (Contents/MacOS/cloudfsd) with a static agent
// plist (Contents/Library/LaunchAgents/dev.cloudfs.daemon.plist). On sign-in the
// app: (1) writes the daemon's provisioning into the App Group container
// (DaemonProvisioning: gateway URL + bearer token + socket), then (2) registers
// the agent with SMAppService — launchd starts cloudfsd and keeps it alive across
// reboots. macOS may require a one-time user approval (Login Items); we surface
// that state and deep-link to the settings pane.

@MainActor
final class DaemonLifecycle {
    static let shared = DaemonLifecycle()
    static let agentPlistName = "dev.cloudfs.daemon.plist"
    private let log = Logger(subsystem: "dev.cloudfs.client", category: "daemon")

    /// Human-readable agent state for the UI / diagnostics.
    private(set) var statusDescription: String = "not registered"

    /// True only for builds that actually embed the agent (the quick SwiftPM dev
    /// bundle has neither the plist nor the binary — registration would fail).
    /// Exposed (not just `private`) so the onboarding checklist's "Background
    /// engine" row can tell "dev bundle, no agent to wait on" apart from
    /// "waiting" without duplicating the bundle-inspection logic.
    var canHostAgent: Bool {
        guard let bundle = Bundle.main.bundleURL as URL? else { return false }
        let plist = bundle.appendingPathComponent("Contents/Library/LaunchAgents/\(Self.agentPlistName)")
        let binary = bundle.appendingPathComponent("Contents/MacOS/cloudfsd")
        return FileManager.default.fileExists(atPath: plist.path)
            && FileManager.default.fileExists(atPath: binary.path)
    }

    /// Live-checked (not cached): true when `SMAppService` currently reports
    /// `.requiresApproval` — the user hasn't yet flipped the Login Items switch.
    /// The onboarding checklist polls this each tick so its row flips to a
    /// checkmark the moment the user approves, with no app relaunch needed.
    var requiresApproval: Bool {
        guard canHostAgent else { return false }
        return SMAppService.agent(plistName: Self.agentPlistName).status == .requiresApproval
    }

    /// Provision the daemon's config + token, then register (or re-kick) the agent.
    /// Safe to call on every sign-in: provisioning overwrites idempotently, and a
    /// re-register of an enabled agent is a no-op.
    @discardableResult
    func provisionAndStart(gatewayURL: String, token: String) -> Bool {
        guard let root = DaemonProvisioning.containerRoot() else {
            log.error("daemon provisioning: no App Group container available")
            return false
        }
        do {
            let socket = try DaemonProvisioning.provision(gatewayURL: gatewayURL, token: token, root: root)
            log.log("daemon provisioned; socket \(socket, privacy: .public)")
        } catch {
            log.error("daemon provisioning failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
        guard canHostAgent else {
            statusDescription = "agent not embedded (dev bundle) — start cloudfsd manually"
            log.log("agent not embedded; skipping SMAppService registration")
            return true
        }
        let service = SMAppService.agent(plistName: Self.agentPlistName)
        do {
            // SMAppService may retain its enabled registration after an updater
            // unloads the launchd job. Re-register that exact service only when
            // launchd confirms it is absent; never interrupt a running engine.
            if service.status == .enabled, launchAgentIsMissing() {
                try service.unregister()
            }
            try service.register()
        } catch {
            // Re-registering an already-enabled agent throws; that's fine.
            log.log("agent register: \(error.localizedDescription, privacy: .public)")
        }
        switch service.status {
        case .enabled:
            statusDescription = "running (launch agent)"
        case .requiresApproval:
            statusDescription = "waiting for Login Items approval"
            // One-time macOS gate: the user must flip the switch once.
            openLoginItemsSettings()
        case .notRegistered:
            statusDescription = "not registered"
        case .notFound:
            statusDescription = "agent plist not found in bundle"
        @unknown default:
            statusDescription = "unknown agent state"
        }
        log.log("agent status: \(self.statusDescription, privacy: .public)")
        return true
    }

    private func launchAgentIsMissing() -> Bool {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["print", "gui/\(getuid())/dev.cloudfs.daemon"]
        task.standardOutput = FileHandle.nullDevice
        task.standardError = FileHandle.nullDevice
        do { try task.run(); task.waitUntilExit() } catch { return false }
        // launchctl uses ESRCH (3) or its bootstrap-domain equivalent (113).
        // Other failures (including permissions) are not evidence to unregister.
        return task.terminationStatus == 3 || task.terminationStatus == 113
    }

    /// Deep-link to System Settings → Login Items (the one-time approval gate).
    /// Single call site reused by the auto-open on registration and by the
    /// onboarding checklist's "Open Login Items…" action row.
    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    /// Sign-out / uninstall: stop managing the agent. (The daemon also drains and
    /// unmounts gracefully on SIGTERM, which launchd sends on unregister.)
    func stop() {
        guard canHostAgent else { return }
        let service = SMAppService.agent(plistName: Self.agentPlistName)
        try? service.unregister()
        statusDescription = "not registered"
    }
}
