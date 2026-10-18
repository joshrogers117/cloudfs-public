// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - Onboarding checklist — pure state machine (ONBOARDING.md build step 4)
//
// The first-run checklist sheet shown after the first successful sign-in on a
// device (CloudFSApp/Views/OnboardingChecklistView.swift). These types carry the
// row-state derivation and the verified-mount probe's failure taxonomy so they
// are unit-testable in isolation, with no SwiftUI/AppKit dependency; the view
// layer only renders whichever case is active. `AppModel+Onboarding.swift`
// drives the state from the live `DaemonLifecycle`/`EngineClient` signals.

// MARK: Row 1 — background engine (the embedded cloudfsd launch agent)

public enum EngineRowState: Equatable, Sendable {
    /// Registered (or registering); the control socket isn't reachable yet.
    case starting
    /// `SMAppService` reports `.requiresApproval` — the user must flip the
    /// Login Items switch once. The row shows a deep-link action.
    case waitingForApproval
    /// The daemon's control socket answered — the row shows a checkmark.
    case ready
    /// This build doesn't embed the agent (quick SwiftPM dev bundle). Treated
    /// as a non-blocking, informational state — never fails the checklist.
    case unavailable

    /// Whether this row counts as "done" for the checklist's overall health
    /// (spec: `.unavailable` — no agent to wait on — is not a failure).
    public var isHealthy: Bool {
        switch self {
        case .ready, .unavailable: return true
        case .starting, .waitingForApproval: return false
        }
    }
}

// MARK: Row 3 (one per filespace) — the verified end-to-end mount probe

public enum MountRowState: Equatable, Sendable {
    case waiting     // not yet attempted
    case mounting    // engine mount in flight
    case verifying   // read-only listing probe in flight
    case done        // mounted + root listing verified
    case browseOnly  // root listing verified; writing at this level is restricted
    /// The user deliberately disconnected this filespace — neutral, not a failure.
    case disconnected
    case failed(MountProbeFailure)
    /// Mock/offline (Demo) mode: no real daemon to probe. Shown as a calm,
    /// clearly-labeled equivalent of success rather than a real verified state.
    case demo

    /// True once the row has stopped moving (whether it succeeded or not).
    public var isTerminal: Bool {
        switch self {
        case .done, .browseOnly, .demo, .disconnected, .failed: return true
        case .waiting, .mounting, .verifying: return false
        }
    }

    /// True when the row is a healthy terminal state (drives the sheet's
    /// overall "You're all set" + the persisted "completed on this device" flag).
    public var isHealthy: Bool {
        switch self {
        case .done, .browseOnly, .demo, .disconnected: return true
        case .waiting, .mounting, .verifying, .failed: return false
        }
    }
}

/// Named, actionable failure reasons for the verified probe (spec: "distinguish
/// at minimum: daemon not running / mount failed / probe write failed / probe
/// read mismatch — never a dead volume presented as success").
public enum MountProbeFailure: Equatable, Sendable {
    case daemonNotRunning
    case mountFailed(String)
    case probeWriteFailed(String)
    case probeReadMismatch

    public var title: String {
        switch self {
        case .daemonNotRunning:  return "Background engine isn't running"
        case .mountFailed:       return "Mount failed"
        case .probeWriteFailed:  return "Couldn't write to the mount"
        case .probeReadMismatch: return "Mount looks broken"
        }
    }

    public var detail: String {
        switch self {
        case .daemonNotRunning:
            return "CloudFS's background engine isn't reachable yet — approve it above, then this retries automatically."
        case .mountFailed(let msg):
            return msg.isEmpty ? "The filespace didn't mount." : msg
        case .probeWriteFailed(let msg):
            return msg.isEmpty ? "Couldn't write a test file to the mount." : msg
        case .probeReadMismatch:
            return "The file read back didn't match what was written — the mount may be missing its encryption key."
        }
    }
}

// MARK: - Pure derivations

public enum OnboardingChecklist {

    /// Whether the first-run sheet should be shown after a successful sign-in:
    /// the first time on this device, or any time the cheap post-sign-in signal
    /// looks unhealthy (spec: "subsequent sign-ins skip it unless something on
    /// it is unhealthy").
    public static func shouldPresent(alreadyCompletedOnDevice: Bool, isHealthy: Bool) -> Bool {
        !alreadyCompletedOnDevice || !isHealthy
    }

    /// Row 1 derivation from the raw signals `DaemonLifecycle`/`EngineClient`
    /// already expose. Order matters: a reachable socket always wins (macOS can
    /// report stale `.requiresApproval` for a moment after the user approves).
    public static func engineRowState(canHostAgent: Bool, requiresApproval: Bool,
                                       socketReachable: Bool) -> EngineRowState {
        guard canHostAgent else { return .unavailable }
        if socketReachable { return .ready }
        if requiresApproval { return .waitingForApproval }
        return .starting
    }

    /// True once every row is in a terminal, healthy state — drives the sheet's
    /// "You're all set" state and whether the "completed on this device" flag
    /// gets persisted.
    public static func isHealthy(engine: EngineRowState, mounts: [MountRowState]) -> Bool {
        engine.isHealthy && mounts.allSatisfy(\.isHealthy)
    }

    /// Coarse "N of M" progress for the sidebar's "Get Started" pill: M is the
    /// engine row plus one row per filespace, N is however many of those are
    /// currently healthy. Callers should pass one `MountRowState` per signed-in
    /// filespace (padding with `.waiting` for any filespace whose row hasn't been
    /// initialized in the checklist's dictionary yet) so `total` tracks the real
    /// filespace count even before a run starts.
    public static func progress(engine: EngineRowState, mounts: [MountRowState]) -> (done: Int, total: Int) {
        let total = 1 + mounts.count
        let done = (engine.isHealthy ? 1 : 0) + mounts.filter(\.isHealthy).count
        return (done, total)
    }
}
