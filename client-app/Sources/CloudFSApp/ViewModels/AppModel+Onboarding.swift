// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import Observation
import CloudFSKit

// MARK: - OnboardingFeatureModel (ONBOARDING.md build step 4)
//
// The first-run checklist sheet's state, factored into its OWN @Observable
// model + file per the app's established per-feature convention (see
// AppModel+Pinned.swift / AppModel+Members.swift). `AppModel.onboarding` holds
// the single instance; `OnboardingChecklistView` renders it.
//
// Three rows, per ONBOARDING.md:
//   1. Background engine — `EngineRowState`, polled live from `DaemonLifecycle`.
//   2. Cache — informational only; no state machine needed.
//   3. Filespaces — one `MountRowState` per filespace, ending in a REAL verified
//      probe (`MountProbe`) through the kernel SMB mount, never a trusted-blind
//      "mounted ⇒ done".
//
// Demo/mock mode has no real daemon to probe: every mount row becomes `.demo`
// (a calm, clearly-labeled stand-in for success) and the engine row is
// `.unavailable` — the sheet still shows, once, so demo users see the same
// choreography, but nothing here pretends to have verified real I/O.

@MainActor
@Observable
final class OnboardingFeatureModel {
    var isPresented = false
    var engineState: EngineRowState = .starting
    /// One row per signed-in filespace, keyed by filespace id.
    var mountRows: [String: MountRowState] = [:]

    /// ONBOARDING.md "Defaults (decided)" — shown verbatim, not computed from
    /// engine state, so it reads correctly even before the daemon has reported in.
    let cacheDefaultSummary = "25 GB in Application Support"

    var allHealthy: Bool {
        OnboardingChecklist.isHealthy(engine: engineState, mounts: Array(mountRows.values))
    }

    /// True while any row is still moving (drives the sheet's busy affordances;
    /// the "Open in Finder" CTA only appears once this goes false AND healthy).
    var isRunning: Bool {
        !engineState.isHealthy || mountRows.values.contains { !$0.isTerminal }
    }

    init() {}
}

extension AppModel {

    /// After a successful sign-in: decide whether to show the first-run
    /// checklist sheet. Shown the first time on this device, or any time the
    /// cheap post-sign-in signal (a filespace that didn't come up connected)
    /// looks unhealthy — the sheet's own verified-probe pass then does the deep
    /// check. Http mode only; Demo/mock still gets one first-run pass so the
    /// choreography is consistent, just without a real daemon underneath.
    func presentOnboardingChecklistIfNeeded() {
        let completed = settings.onboardingCompletedOnDevice
        let cheapHealthy = filespaces.allSatisfy { $0.connection == .connected || intentionallyDisconnected.contains($0.id) }
        guard OnboardingChecklist.shouldPresent(alreadyCompletedOnDevice: completed,
                                                isHealthy: cheapHealthy) else { return }
        onboarding.mountRows = [:]
        onboarding.engineState = .starting
        onboarding.isPresented = true
        Task { await runOnboardingChecklist() }
    }

    /// Drive every row to a terminal state. Demo/mock: no daemon exists, so
    /// every row becomes a clearly-labeled `.demo` stand-in — never a probe we
    /// didn't actually run. Http mode: waits for the background engine (polling
    /// live, so a Login Items approval mid-flow is picked up with no relaunch),
    /// then mounts + verifies each filespace in turn.
    func runOnboardingChecklist() async {
        guard !filespaces.isEmpty else {
            // No filespace to mount yet (a brand-new org) — nothing to verify.
            // Still reflect the real engine state when there's a real daemon to
            // ask, and treat the (vacuously healthy) checklist as complete so it
            // doesn't re-show every sign-in before the admin creates one.
            onboarding.mountRows = [:]
            if case .http = mode { refreshOnboardingEngineState() } else { onboarding.engineState = .unavailable }
            settings.onboardingCompletedOnDevice = true
            return
        }
        guard case .http = mode else {
            onboarding.engineState = .unavailable
            onboarding.mountRows = Dictionary(uniqueKeysWithValues: filespaces.map { ($0.id, .demo) })
            settings.onboardingCompletedOnDevice = true   // demo still completes the choreography once
            return
        }

        refreshOnboardingEngineState()
        for fs in filespaces where onboarding.mountRows[fs.id] == nil {
            onboarding.mountRows[fs.id] = .waiting
        }

        // Background engine not reachable yet: name it plainly rather than
        // leaving every mount row spinning forever, then keep polling — the
        // moment the socket appears, re-run automatically (spec: "flips to a
        // checkmark automatically ... the app already polls for the daemon
        // socket").
        guard engine.isAvailable else {
            for fs in filespaces { onboarding.mountRows[fs.id] = .failed(.daemonNotRunning) }
            await pollUntilEngineReadyThenRerun()
            return
        }

        for fs in filespaces {
            onboarding.mountRows[fs.id] = intentionallyDisconnected.contains(fs.id) ? .disconnected : .mounting
        }
        await applyEngineMountState()   // the shared reconcile path (mount + overlay)

        for fs in filespaces {
            // Deliberately disconnected: neutral, never "Mount failed".
            if intentionallyDisconnected.contains(fs.id) { onboarding.mountRows[fs.id] = .disconnected; continue }
            guard let mounted = filespaces.first(where: { $0.id == fs.id }),
                  mounted.connection == .connected, !mounted.mountPath.isEmpty
            else {
                onboarding.mountRows[fs.id] = .failed(.mountFailed("The filespace didn't mount."))
                continue
            }
            onboarding.mountRows[fs.id] = .verifying
            let mountPath = (mounted.mountPath as NSString).expandingTildeInPath
            let generation = mountOperations.generation
            do {
                let result = try await mountOperations.perform(generation: generation) {
                    try await MountProbe.verifyWhenReady(mountRoot: mountPath)
                }
                guard isSignedIn, !isSigningOut else { return }
                switch result {
                case .listed: onboarding.mountRows[fs.id] = .done
                case .failed(let failure): onboarding.mountRows[fs.id] = .failed(failure)
                }
            } catch { return }
        }

        if onboarding.allHealthy {
            settings.onboardingCompletedOnDevice = true
        }
    }

    /// Poll the live `DaemonLifecycle`/socket signals (bounded ticks via the
    /// existing `refreshEngineWhenSocketAppears`) until the engine is reachable
    /// or the sheet is no longer open, then re-run the checklist once. Never
    /// blocks the sheet's own dismiss affordance — this just stops polling when
    /// `onboarding.isPresented` goes false.
    private func pollUntilEngineReadyThenRerun() async {
        while onboarding.isPresented, !engine.isAvailable {
            await refreshEngineWhenSocketAppears(timeout: 3.0)
            refreshOnboardingEngineState()
        }
        guard onboarding.isPresented, engine.isAvailable else { return }
        await runOnboardingChecklist()
    }

    /// Force a fresh run of the first-run checklist — the Dashboard hero's
    /// "Run checks again" after a failed verified-mount probe. Bypasses
    /// `shouldPresent`'s already-completed-on-device gate, since the user just
    /// explicitly asked to re-verify right now.
    func rerunOnboardingChecklist() {
        onboarding.mountRows = [:]
        onboarding.engineState = .starting
        onboarding.isPresented = true
        Task { await runOnboardingChecklist() }
    }

    /// Row 1 — live snapshot of `DaemonLifecycle` + the resolved engine socket.
    func refreshOnboardingEngineState() {
        onboarding.engineState = OnboardingChecklist.engineRowState(
            canHostAgent: DaemonLifecycle.shared.canHostAgent,
            requiresApproval: DaemonLifecycle.shared.requiresApproval,
            socketReachable: engine.isAvailable)
    }
}
