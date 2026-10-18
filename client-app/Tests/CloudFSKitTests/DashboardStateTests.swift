// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Dashboard's pure state derivation: hero-state selection from
// (connection, mountPath, probe), the copy that goes with each state, and the
// "Remaining upload" honest-fallback rule. No SwiftUI — `DashboardView` only
// renders whichever case these compute.

@Suite(.timeLimit(.minutes(1)))
struct DashboardHeroStateTests {

    // MARK: derive — probe failure always wins

    @Test func failedProbeWinsRegardlessOfConnection() {
        for connection in ConnectionState.allCases {
            let state = DashboardHeroState.derive(connection: connection, mountPath: "/mnt/x",
                                                  probe: .failed(.probeReadMismatch))
            #expect(state == .probeFailed(.probeReadMismatch))
        }
    }

    @Test func demoProbeWinsOverPlainConnection() {
        let state = DashboardHeroState.derive(connection: .disconnected, mountPath: "/mnt/x", probe: .demo)
        #expect(state == .demo(mountPath: "/mnt/x"))
    }

    // MARK: derive — connection-based branches (no probe signal)

    @Test func connectedWithMountPathIsConnected() {
        let state = DashboardHeroState.derive(connection: .connected, mountPath: "/mnt/x", probe: nil)
        #expect(state == .connected(mountPath: "/mnt/x"))
    }

    @Test func connectedWithNoMountPathIsNotMounted() {
        // Never fabricate a mount that isn't actually there yet.
        let state = DashboardHeroState.derive(connection: .connected, mountPath: "", probe: nil)
        #expect(state == .notMounted)
    }

    @Test func connectingIsConnecting() {
        #expect(DashboardHeroState.derive(connection: .connecting, mountPath: "", probe: nil) == .connecting)
    }

    @Test func pausedIsPaused() {
        #expect(DashboardHeroState.derive(connection: .paused, mountPath: "/mnt/x", probe: nil) == .paused)
    }

    @Test func disconnectedAndErrorAreNotMounted() {
        #expect(DashboardHeroState.derive(connection: .disconnected, mountPath: "", probe: nil) == .notMounted)
        #expect(DashboardHeroState.derive(connection: .error, mountPath: "", probe: nil) == .notMounted)
    }

    @Test func nonTerminalProbeDoesNotOverrideConnection() {
        // A probe still in flight (.waiting/.mounting/.verifying) or .done isn't
        // a failure or a demo stand-in — the connection state still drives it.
        for probe: MountRowState in [.waiting, .mounting, .verifying, .done] {
            let state = DashboardHeroState.derive(connection: .connected, mountPath: "/mnt/x", probe: probe)
            #expect(state == .connected(mountPath: "/mnt/x"))
        }
    }

    // MARK: headline / subCopy — honest, non-empty, distinguishable

    @Test func headlinesAreDistinctPerState() {
        let states: [DashboardHeroState] = [
            .connected(mountPath: "/mnt/x"), .connecting, .paused, .notMounted,
            .demo(mountPath: "/mnt/x"), .probeFailed(.daemonNotRunning),
        ]
        let headlines = states.map { $0.headline(filespaceName: "Edit-1") }
        // .connected and .demo intentionally share the same honest headline
        // ("is connected") — everything else must be distinct.
        let distinctHeadlines = Set(headlines)
        #expect(distinctHeadlines.count == 5)
        for h in headlines { #expect(!h.isEmpty) }
    }

    @Test func connectedAndDemoShareTheSameHonestHeadline() {
        let connected = DashboardHeroState.connected(mountPath: "/mnt/x").headline(filespaceName: "Edit-1")
        let demo = DashboardHeroState.demo(mountPath: "/mnt/x").headline(filespaceName: "Edit-1")
        #expect(connected == demo)
        #expect(connected == "Edit-1 is connected")
    }

    @Test func probeFailedHeadlineUsesTheFailureTitleVerbatim() {
        let state = DashboardHeroState.probeFailed(.mountFailed("disk full"))
        #expect(state.headline(filespaceName: "Edit-1") == MountProbeFailure.mountFailed("disk full").title)
    }

    @Test func everyStateHasNonEmptySubCopy() {
        let states: [DashboardHeroState] = [
            .connected(mountPath: "/mnt/x"), .connecting, .paused, .notMounted,
            .demo(mountPath: "/mnt/x"), .probeFailed(.probeReadMismatch),
        ]
        for s in states { #expect(!s.subCopy.isEmpty) }
    }

    // MARK: canOpenInFinder / isProbeFailure

    @Test func onlyConnectedAndDemoCanOpenInFinder() {
        #expect(DashboardHeroState.connected(mountPath: "/x").canOpenInFinder)
        #expect(DashboardHeroState.demo(mountPath: "/x").canOpenInFinder)
        #expect(!DashboardHeroState.connecting.canOpenInFinder)
        #expect(!DashboardHeroState.paused.canOpenInFinder)
        #expect(!DashboardHeroState.notMounted.canOpenInFinder)
        #expect(!DashboardHeroState.probeFailed(.daemonNotRunning).canOpenInFinder)
    }

    @Test func onlyProbeFailedReportsIsProbeFailure() {
        #expect(DashboardHeroState.probeFailed(.daemonNotRunning).isProbeFailure)
        #expect(!DashboardHeroState.connected(mountPath: "/x").isProbeFailure)
        #expect(!DashboardHeroState.notMounted.isProbeFailure)
    }
}

// MARK: - "Remaining upload" honest-fallback rule

@Suite(.timeLimit(.minutes(1)))
struct DashboardUploadDisplayTests {

    @Test func engineFigurePreferredWhenPresent() {
        let result = DashboardDerivations.remainingUpload(
            engineSyncPendingBytes: 4_096, transfersLoaded: true, transferSumBytes: 999)
        #expect(result == .bytes(4_096))
    }

    @Test func engineFigureOfZeroIsStillPreferred() {
        // 0 pending uploads from the engine is a real, honest answer — must not
        // be treated as "absent" and fall through to the client-side sum.
        let result = DashboardDerivations.remainingUpload(
            engineSyncPendingBytes: 0, transfersLoaded: true, transferSumBytes: 999)
        #expect(result == .bytes(0))
    }

    @Test func fallsBackToTransferSumWhenNoEngineFigure() {
        let result = DashboardDerivations.remainingUpload(
            engineSyncPendingBytes: nil, transfersLoaded: true, transferSumBytes: 2_048)
        #expect(result == .bytes(2_048))
    }

    @Test func unavailableWhenNeitherSourceHasData() {
        let result = DashboardDerivations.remainingUpload(
            engineSyncPendingBytes: nil, transfersLoaded: false, transferSumBytes: 0)
        #expect(result == .unavailable)
    }

    // MARK: Transfer.pendingUploadBytes

    private func transfer(kind: TransferKind, state: TransferState,
                          done: Int64, total: Int64) -> Transfer {
        Transfer(id: UUID().uuidString, fileName: "f", kind: kind, state: state,
                bytesDone: done, bytesTotal: total, throughputBytesPerSec: 0, startedAt: Date())
    }

    @Test func pendingUploadBytesSumsOnlyActiveAndQueuedUploads() {
        let transfers = [
            transfer(kind: .upload, state: .active, done: 100, total: 500),     // +400
            transfer(kind: .upload, state: .queued, done: 0, total: 200),       // +200
            transfer(kind: .upload, state: .completed, done: 500, total: 500),  // excluded (done)
            transfer(kind: .upload, state: .failed, done: 100, total: 500),     // excluded (failed)
            transfer(kind: .download, state: .active, done: 0, total: 1_000),   // excluded (download)
        ]
        #expect(transfers.pendingUploadBytes == 600)
    }

    @Test func pendingUploadBytesIsZeroForEmptyOrNonMatchingTransfers() {
        #expect([Transfer]().pendingUploadBytes == 0)
    }
}

// MARK: - Truthful connection state (reachability), upload-retry copy, new-access hint, poll plan

@Suite(.timeLimit(.minutes(1)))
struct DashboardReachabilityTests {

    @Test func offlineNeverRendersAsConnected() {
        let state = DashboardHeroState.derive(connection: .connected, mountPath: "/mnt/x", probe: nil, reachability: .offline)
        #expect(state == .offline(mountPath: "/mnt/x"))
        #expect(!state.headline(filespaceName: "Edit-1").contains("connected"))
        #expect(state.headline(filespaceName: "Edit-1") == "Edit-1 is offline")
        #expect(state.canOpenInFinder)   // the mounted volume still serves cached files
    }

    @Test func degradedAndOnlineAndUnknownMapping() {
        #expect(DashboardHeroState.derive(connection: .connected, mountPath: "/m", probe: nil, reachability: .degraded) == .degraded(mountPath: "/m"))
        #expect(DashboardHeroState.derive(connection: .connected, mountPath: "/m", probe: nil, reachability: .online) == .connected(mountPath: "/m"))
        #expect(DashboardHeroState.derive(connection: .connected, mountPath: "/m", probe: nil, reachability: nil) == .connected(mountPath: "/m"))
        // Reachability can't make an unmounted filespace look mounted.
        #expect(DashboardHeroState.derive(connection: .disconnected, mountPath: "", probe: nil, reachability: .online) == .notMounted)
        #expect(DashboardHeroState.derive(connection: .connected, mountPath: "", probe: nil, reachability: .offline) == .notMounted)
    }

    @Test func connectionCardLabels() {
        #expect(ConnectionHealthDisplay(.online).label == "Online")
        #expect(ConnectionHealthDisplay(.degraded).label == "Degraded")
        #expect(ConnectionHealthDisplay(.offline).label == "Offline")
        #expect(ConnectionHealthDisplay(nil).label == nil)
    }

    @Test func statusDecodesNewFieldsAndToleratesOldDaemons() throws {
        let new = try JSONDecoder().decode(EngineStatus.self, from: Data(#"{"filespace":"fs","connection":"connected","latencyMsToBucket":41.6,"pendingUploads":2,"pendingBytes":10,"lastSuccessAt":1000,"lastFailureAt":2000,"lastFailureReason":"network: offline","reachability":"offline","mountedRootIds":["a","b"],"cache":{"x":1}}"#.utf8))
        #expect(new.reachability == .offline)
        #expect(new.lastFailureReason == "network: offline")
        #expect(new.mountedRootIds == ["a", "b"])
        let old = try JSONDecoder().decode(EngineStatus.self, from: Data(#"{"filespace":"fs","connection":"connected","latencyMsToBucket":null,"pendingUploads":0,"pendingBytes":0,"health":"green"}"#.utf8))
        #expect(old.reachability == nil); #expect(old.mountedRootIds == nil)
        let unknown = try JSONDecoder().decode(EngineStatus.self, from: Data(#"{"filespace":"fs","reachability":"sideways"}"#.utf8))
        #expect(unknown.reachability == nil)
    }

    @Test func daemonClientFetchesStatus() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("status") { p in
            #expect(p["filespace"]?.stringValue == "team")
            return #"{"filespace":"team","reachability":"degraded","lastFailureReason":"gateway: HTTP 503"}"#
        }
        try daemon.start(); defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        let status = try await client.status(filespace: "team")
        #expect(status.reachability == .degraded)
        await client.disconnect()
    }

    // MARK: durability line

    private func label(inSync: Bool?, error: String? = nil, health: ConnectionHealthDisplay = .online,
                       recovery: Bool = false, paused: Bool = false, noMount: Bool = false, http: Bool = true) -> String {
        DashboardDerivations.durabilityLabel(isHttpMode: http, recoveryNeedsAttention: recovery, paused: paused,
                                             mountPathEmpty: noMount, inSync: inSync, uploadError: error, health: health)
    }

    @Test func stagedUploadErrorReplacesSavingChangesCopy() {
        #expect(label(inSync: false) == "Saving changes to cloud")
        #expect(label(inSync: false, error: "network: timed out") == "Uploads retrying — last error: network: timed out")
        #expect(label(inSync: nil, error: "x") == "Uploads retrying — last error: x")
        #expect(label(inSync: true, error: "stale") == "All changes saved to cloud")
    }

    @Test func durabilityPrecedenceKeepsEarlierGatesFirst() {
        #expect(label(inSync: false, error: "e", recovery: true) == "Local changes need attention")
        #expect(label(inSync: false, error: "e", paused: true) == "Transfers paused")
        #expect(label(inSync: false, error: "e", noMount: true) == "Not connected on this Mac")
        #expect(label(inSync: false, http: false) == "Sample connection")
        #expect(label(inSync: nil) == "Connected · checking uploads")
        #expect(label(inSync: false, health: .offline) == "Offline — changes wait on this Mac")
    }

    @Test func firstUploadErrorOnlyFromUnfinishedUploads() {
        func t(_ kind: TransferKind, _ state: TransferState, _ error: String?) -> Transfer {
            Transfer(id: UUID().uuidString, fileName: "f", kind: kind, state: state, bytesDone: 0, bytesTotal: 1,
                     throughputBytesPerSec: 0, startedAt: Date(), error: error)
        }
        #expect(DashboardDerivations.firstUploadError([t(.upload, .active, nil)]) == nil)
        #expect(DashboardDerivations.firstUploadError([t(.download, .failed, "dl")]) == nil)
        #expect(DashboardDerivations.firstUploadError([t(.upload, .completed, "old")]) == nil)
        #expect(DashboardDerivations.firstUploadError([t(.upload, .queued, nil), t(.upload, .failed, "boom")]) == "boom")
    }

    @Test func connectionDetailShowsLatencyOnlineAndReasonWhenNot() {
        #expect(DashboardDerivations.connectionDetail(health: .online, latencyMs: 41.6, lastFailureReason: "old") == "Metadata · 42 ms/request")
        #expect(DashboardDerivations.connectionDetail(health: .online, latencyMs: nil, lastFailureReason: nil) == nil)
        #expect(DashboardDerivations.connectionDetail(health: .offline, latencyMs: 5, lastFailureReason: "network: down") == "Last error: network: down")
        #expect(DashboardDerivations.connectionDetail(health: .unknown, latencyMs: 5, lastFailureReason: "x") == nil)
    }

    // MARK: item 9 + item 4

    @Test func newAccessOnlyWhenCurrentRootsExceedMountedProjection() {
        #expect(MountAccessChange.hasNewAccess(mountedRootIds: ["a"], currentRootIds: ["a", "b"]))
        #expect(!MountAccessChange.hasNewAccess(mountedRootIds: ["a", "b"], currentRootIds: ["a", "b"]))
        #expect(!MountAccessChange.hasNewAccess(mountedRootIds: ["a", "b"], currentRootIds: ["a"]))   // revocation keeps aliases until remount
        #expect(!MountAccessChange.hasNewAccess(mountedRootIds: nil, currentRootIds: ["a", "b"]))     // whole-filespace / explicit folder
        #expect(MountAccessChange.hasNewAccess(mountedRootIds: ["a"], currentRootIds: ["root"]))
    }

    @Test func pollPlanAlwaysRefreshesMountStateWithoutAutoMountDecisionAndThrottlesAccessCheck() {
        let now = Date(timeIntervalSince1970: 10_000)
        let first = DashboardRefreshPlan.make(operationInFlight: false, lastAccessCheck: nil, now: now)
        #expect(first.refreshMountState && first.checkNewAccess)
        let soon = DashboardRefreshPlan.make(operationInFlight: false, lastAccessCheck: now.addingTimeInterval(-5), now: now)
        #expect(soon.refreshMountState && !soon.checkNewAccess)
        let later = DashboardRefreshPlan.make(operationInFlight: false, lastAccessCheck: now.addingTimeInterval(-31), now: now)
        #expect(later.checkNewAccess)
        let busy = DashboardRefreshPlan.make(operationInFlight: true, lastAccessCheck: nil, now: now)
        #expect(!busy.refreshMountState && !busy.checkNewAccess)
    }

    @Test func cloudUsageRefreshHasAnIndependentBoundedSchedule() {
        let now = Date(timeIntervalSince1970: 10_000)
        #expect(DashboardRefreshPlan.make(operationInFlight: false, lastAccessCheck: now, now: now).refreshUsage)
        #expect(!DashboardRefreshPlan.make(operationInFlight: false, lastAccessCheck: nil, now: now,
                                          lastUsageCheck: now.addingTimeInterval(-29)).refreshUsage)
        #expect(DashboardRefreshPlan.make(operationInFlight: false, lastAccessCheck: now, now: now,
                                         lastUsageCheck: now.addingTimeInterval(-30)).refreshUsage)
        #expect(!DashboardRefreshPlan.make(operationInFlight: true, lastAccessCheck: nil, now: now).refreshUsage)
    }
}

@Suite struct StorageStatusDisplayTests {
    @Test func separatesStorageMeasurementsAndUnknownState() throws {
        let old = try JSONDecoder().decode(EngineStatus.self, from: Data(#"{"filespace":"fs","latencyMsToBucket":25}"#.utf8))
        #expect(old.gatewayLatencyMs == nil); #expect(old.storage == nil)
        #expect(DashboardDerivations.storageDetail(nil) == "Storage · no recent requests")
        var storage = StorageTelemetry(); storage.reachability = "online"; storage.requestDurationMs = 140
        storage.downloadBytesPerSecond = 1024; storage.retries = 2
        let detail = DashboardDerivations.storageDetail(storage)
        #expect(detail.contains("140 ms/request")); #expect(detail.contains("2 retries"))
        storage.reachability = "degraded"; storage.lastFailureReason = "HTTP 503"
        #expect(DashboardDerivations.storageDetail(storage) == "Storage · HTTP 503")
    }
}
