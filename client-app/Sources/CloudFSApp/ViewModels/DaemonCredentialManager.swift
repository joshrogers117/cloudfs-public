// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSKit
import os

// MARK: - DaemonCredentialManager — auto-renew the daemon's 30-day token (C6)
//
// The daemon authenticates to the gateway with a 30-day service token the app
// mints from its device session (POST /v1/auth/device/daemon-token) and writes
// to the rendezvous dir's 0600 token.txt (DaemonProvisioning). The daemon
// re-reads that file per request, so renewal is just a rewrite — no restart,
// no unmount.
//
// Renewal rules (pure math in CloudFSKit.DaemonCredential):
//   • re-mint when < 7 days remain (or expiry unknown);
//   • checked right after sign-in, at every app launch (start()), then on a
//     6-hour timer while the app runs, and on demand when the daemon reports
//     an auth failure;
//   • mint failures are logged and retried next tick — transient gateway
//     problems never break the running daemon (its current token keeps working
//     until its real expiry).

@MainActor
final class DaemonCredentialManager {

    private let log = Logger(subsystem: "dev.cloudfs.client", category: "daemon-credential")
    private var session: AuthSessionManager?
    private var gatewayURL = ""
    private var timerTask: Task<Void, Never>?
    private var generation = UUID()
    private var renewalTask: Task<Bool, Never>?
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// Begin the renewal cycle for a device session: check/renew immediately,
    /// then keep checking on a timer. Safe to call again (re-arms the timer).
    func start(session: AuthSessionManager, gatewayURL: String, newSession: Bool) async throws {
        stop()
        self.session = session
        self.gatewayURL = gatewayURL
        let currentGeneration = generation
        try await prepare(session: session, gatewayURL: gatewayURL,
                          generation: currentGeneration, force: newSession)
        guard generation == currentGeneration else { throw CancellationError() }
        timerTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(DaemonCredential.checkInterval))
                guard !Task.isCancelled else { break }
                await self?.ensureFresh()
            }
        }
    }

    /// Stop renewing (sign-out / session expiry). Leaves token.txt alone — the
    /// caller decides whether the daemon should keep serving cached reads.
    func stop() {
        timerTask?.cancel()
        timerTask = nil
        renewalTask?.cancel()
        renewalTask = nil
        generation = UUID()
        session = nil
    }

    /// Mint + provision when the stored token is inside the renewal window.
    /// `force` skips the window check (used for daemon-reported auth failures).
    @discardableResult
    func ensureFresh(force: Bool = false) async -> Bool {
        guard let session, !gatewayURL.isEmpty else { return false }
        if let renewalTask { return await renewalTask.value }
        let expiry = DaemonCredential.storedExpiry(defaults: defaults)
        guard force || DaemonCredential.shouldRenew(expiresAt: expiry)
                || DaemonCredential.needsCapabilityUpgrade(defaults: defaults) else { return true }
        let currentGeneration = generation
        let currentGateway = gatewayURL
        let task = Task { [self] in
            do {
                try await prepare(session: session, gatewayURL: currentGateway,
                                  generation: currentGeneration, force: force)
                return true
            } catch {
                log.error("daemon credential renewal failed: \(error.localizedDescription, privacy: .public)")
                return false
            }
        }
        renewalTask = task
        let result = await task.value
        if generation == currentGeneration { renewalTask = nil }
        return result
    }

    private func prepare(session: AuthSessionManager, gatewayURL: String,
                         generation expected: UUID, force: Bool) async throws {
        try await DaemonCredentialHandoff.prepare(
            forceMint: force, defaults: defaults,
            existingToken: {
                guard let root = DaemonProvisioning.containerRoot() else { return nil }
                return DaemonProvisioning.existingToken(gatewayURL: gatewayURL, root: root)
            },
            mint: { try await session.mintDaemonToken() },
            provision: { token in
                guard DaemonLifecycle.shared.provisionAndStart(gatewayURL: gatewayURL, token: token) else {
                    throw DaemonCredentialHandoff.Failure.provisioning
                }
            },
            isCurrent: { self.generation == expected })
    }

    /// The daemon (or an engine call on its behalf) hit an auth failure against
    /// the gateway — re-mint immediately rather than waiting for the timer.
    @discardableResult
    func daemonReportedAuthFailure() async -> Bool {
        await ensureFresh(force: true)
    }
}
