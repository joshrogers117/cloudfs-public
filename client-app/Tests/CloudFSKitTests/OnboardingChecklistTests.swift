// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// ONBOARDING.md build step 4 — the first-run checklist's pure state machine:
// row-state derivation, overall health, and the "show it or not" decision.

@Suite struct OnboardingChecklistTests {

    // MARK: EngineRowState.isHealthy

    @Test func engineHealthyStatesAreReadyAndUnavailable() {
        #expect(EngineRowState.ready.isHealthy)
        #expect(EngineRowState.unavailable.isHealthy)
        #expect(!EngineRowState.starting.isHealthy)
        #expect(!EngineRowState.waitingForApproval.isHealthy)
    }

    // MARK: MountRowState

    @Test func mountRowTerminalStates() {
        #expect(!MountRowState.waiting.isTerminal)
        #expect(!MountRowState.mounting.isTerminal)
        #expect(!MountRowState.verifying.isTerminal)
        #expect(MountRowState.done.isTerminal)
        #expect(MountRowState.demo.isTerminal)
        #expect(MountRowState.failed(.probeReadMismatch).isTerminal)
    }

    @Test func mountRowHealthyStates() {
        #expect(MountRowState.done.isHealthy)
        #expect(MountRowState.demo.isHealthy)
        #expect(!MountRowState.waiting.isHealthy)
        #expect(!MountRowState.mounting.isHealthy)
        #expect(!MountRowState.verifying.isHealthy)
        #expect(!MountRowState.failed(.daemonNotRunning).isHealthy)
    }

    // MARK: engineRowState derivation

    @Test func engineRowStateNotHostable() {
        #expect(OnboardingChecklist.engineRowState(
            canHostAgent: false, requiresApproval: true, socketReachable: true) == .unavailable)
        #expect(OnboardingChecklist.engineRowState(
            canHostAgent: false, requiresApproval: false, socketReachable: false) == .unavailable)
    }

    @Test func engineRowStateReachableSocketWinsOverApproval() {
        // A reachable socket always wins — macOS can report a stale
        // .requiresApproval for a moment right after the user approves.
        #expect(OnboardingChecklist.engineRowState(
            canHostAgent: true, requiresApproval: true, socketReachable: true) == .ready)
    }

    @Test func engineRowStateWaitingForApproval() {
        #expect(OnboardingChecklist.engineRowState(
            canHostAgent: true, requiresApproval: true, socketReachable: false) == .waitingForApproval)
    }

    @Test func engineRowStateStarting() {
        #expect(OnboardingChecklist.engineRowState(
            canHostAgent: true, requiresApproval: false, socketReachable: false) == .starting)
    }

    // MARK: isHealthy rollup

    @Test func isHealthyRequiresEngineAndEveryMount() {
        #expect(OnboardingChecklist.isHealthy(engine: .ready, mounts: [.done, .demo]))
        #expect(OnboardingChecklist.isHealthy(engine: .unavailable, mounts: []))
        #expect(!OnboardingChecklist.isHealthy(engine: .starting, mounts: [.done]))
        #expect(!OnboardingChecklist.isHealthy(engine: .ready, mounts: [.done, .failed(.probeReadMismatch)]))
        #expect(!OnboardingChecklist.isHealthy(engine: .ready, mounts: [.verifying]))
    }

    // MARK: shouldPresent

    @Test func shouldPresentFirstTimeOnDevice() {
        #expect(OnboardingChecklist.shouldPresent(alreadyCompletedOnDevice: false, isHealthy: true))
        #expect(OnboardingChecklist.shouldPresent(alreadyCompletedOnDevice: false, isHealthy: false))
    }

    @Test func shouldPresentSkipsWhenCompletedAndHealthy() {
        #expect(!OnboardingChecklist.shouldPresent(alreadyCompletedOnDevice: true, isHealthy: true))
    }

    @Test func shouldPresentReshowsWhenUnhealthyEvenIfCompletedBefore() {
        #expect(OnboardingChecklist.shouldPresent(alreadyCompletedOnDevice: true, isHealthy: false))
    }

    // MARK: MountProbeFailure copy — named + actionable (never blank)

    @Test func failureTitlesAreDistinctAndNonEmpty() {
        let all: [MountProbeFailure] = [
            .daemonNotRunning, .mountFailed("x"), .probeWriteFailed("x"), .probeReadMismatch,
        ]
        let titles = Set(all.map(\.title))
        #expect(titles.count == all.count)
        for f in all {
            #expect(!f.title.isEmpty)
            #expect(!f.detail.isEmpty)
        }
    }

    @Test func failureDetailFallsBackWhenUnderlyingMessageIsEmpty() {
        #expect(!MountProbeFailure.mountFailed("").detail.isEmpty)
        #expect(!MountProbeFailure.probeWriteFailed("").detail.isEmpty)
    }

    // MARK: progress — sidebar "Get Started · N of M" pill

    @Test func progressTotalIsEngineRowPlusOnePerFilespace() {
        #expect(OnboardingChecklist.progress(engine: .starting, mounts: []).total == 1)
        #expect(OnboardingChecklist.progress(engine: .starting, mounts: [.waiting, .waiting]).total == 3)
    }

    @Test func progressDoneCountsHealthyRowsOnly() {
        let p = OnboardingChecklist.progress(engine: .ready, mounts: [.done, .demo, .failed(.daemonNotRunning)])
        #expect(p.done == 3)   // engine + 2 healthy mounts
        #expect(p.total == 4)  // engine + 3 mounts
    }

    @Test func progressNothingHealthyYet() {
        let p = OnboardingChecklist.progress(engine: .starting, mounts: [.waiting, .mounting])
        #expect(p.done == 0)
        #expect(p.total == 3)
    }

    @Test func progressAllHealthyMatchesTotal() {
        let p = OnboardingChecklist.progress(engine: .unavailable, mounts: [.demo, .demo])
        #expect(p.done == p.total)
        #expect(p.total == 3)
    }
}

// MARK: - Per-device "completed onboarding" persistence

@Suite struct OnboardingCompletedOnDevicePersistenceTests {

    private func isolatedStore() throws -> (GatewaySettingsStore, UserDefaults, String) {
        let suite = "test.onboarding." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        return (GatewaySettingsStore(defaults: defaults), defaults, suite)
    }

    @Test func defaultsToFalseAndRoundTrips() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        #expect(!store.onboardingCompletedOnDevice)
        store.onboardingCompletedOnDevice = true
        #expect(store.onboardingCompletedOnDevice)
    }

    @Test func survivesClearCredentialsKeepingServer() throws {
        // Per-device, not per-credential: sign-out on the same Mac must not
        // re-trigger the first-run sheet on the next sign-in.
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.onboardingCompletedOnDevice = true
        store.clearCredentialsKeepingServer()
        #expect(store.onboardingCompletedOnDevice)
    }

    @Test func survivesFullClear() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.onboardingCompletedOnDevice = true
        store.clear()
        #expect(store.onboardingCompletedOnDevice)
    }
}

// MARK: - Cache default alignment (ONBOARDING.md "Defaults")

@Suite struct CacheDefaultAlignmentTests {

    @Test func sliderFloorMatchesTheDaemonsDecimalDefault() {
        // cloudfsd's fresh-provision default is 25_000_000_000 (Daemon.swift). The
        // GUI slider's floor must be at or below that so a freshly-mounted
        // filespace's ceiling never lands below the slider's own minimum.
        #expect(CacheSettings.minBytes == 25_000_000_000)
    }

    // MARK: Deliberately disconnected filespaces are neutral and persisted

    @Test func disconnectedRowIsTerminalAndHealthy() {
        #expect(MountRowState.disconnected.isTerminal)
        #expect(MountRowState.disconnected.isHealthy)
        #expect(OnboardingChecklist.isHealthy(engine: .ready, mounts: [.done, .disconnected]))
    }

    @Test func disconnectedSetPersistsAndSurvivesSessionExpiryCredentialClear() throws {
        let suite = "test.disconnected." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = GatewaySettingsStore(defaults: defaults, credentialNamespace: suite)
        #expect(store.disconnectedFilespaces.isEmpty)
        store.disconnectedFilespaces = ["a", "b"]
        // A fresh store over the same defaults (a relaunch) sees it.
        #expect(GatewaySettingsStore(defaults: defaults, credentialNamespace: suite).disconnectedFilespaces == ["a", "b"])
        store.clearCredentialsKeepingServer()   // session expiry path: set is kept
        #expect(store.disconnectedFilespaces == ["a", "b"])
        store.disconnectedFilespaces = []        // explicit sign-out assigns the empty set
        #expect(store.disconnectedFilespaces.isEmpty)
    }

    @Test func productNameFallsBackToCloudFS() throws {
        let suite = "test.product." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = GatewaySettingsStore(defaults: defaults, credentialNamespace: suite)
        #expect(store.displayProductName == "CloudFS")
        store.productName = "  Acme Drive "
        #expect(store.displayProductName == "Acme Drive")
        store.productName = ""
        #expect(store.displayProductName == "CloudFS")
    }
}
