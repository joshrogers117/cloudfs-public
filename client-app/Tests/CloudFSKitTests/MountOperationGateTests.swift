// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Testing
@testable import CloudFSKit

@MainActor
@Suite(.timeLimit(.minutes(1)))
struct MountOperationGateTests {
    @MainActor private final class DeferredMount {
        var continuation: CheckedContinuation<Void, Never>?
        var started = false
        var volumes: [String] = []
        var credentialsPresent = true
        var listedVolumes: [String]?
        func mount() async {
            started = true
            await withCheckedContinuation { continuation = $0 }
            volumes.append("old-account-volume")
        }
        func finish() { continuation?.resume(); continuation = nil }
    }

    @Test func signOutDrainsSuspendedMountBeforeListingAndClearingCredentials() async throws {
        let gate = MountOperationGate(), daemon = DeferredMount()
        let oldGeneration = gate.generation
        let mounting = Task { try await gate.perform(generation: oldGeneration) { await daemon.mount() } }
        while !daemon.started { await Task.yield() }
        let signingOut = Task {
            await gate.closeAndDrain()
            // This models the real ordering: take a FRESH list after drain,
            // flush/unmount everything in it, then clear account credentials.
            daemon.listedVolumes = daemon.volumes
            daemon.volumes.removeAll()
            daemon.credentialsPresent = false
        }
        while gate.acceptsMounts { await Task.yield() }
        #expect(daemon.listedVolumes == nil)
        #expect(daemon.credentialsPresent)
        await #expect(throws: MountOperationGate.GateError.self) {
            try await gate.perform(generation: gate.generation) { daemon.volumes.append("late-volume") }
        }
        // Always release the blocked operation, even if an expectation failed.
        daemon.finish()
        try await mounting.value
        await signingOut.value
        #expect(daemon.listedVolumes == ["old-account-volume"])
        #expect(daemon.volumes.isEmpty)
        #expect(!daemon.credentialsPresent)
        gate.reopen()
        // An earlier automatic-mount loop can resume after sign-out has ended.
        // Its captured session generation must remain refused after reopen.
        await #expect(throws: MountOperationGate.GateError.self) {
            try await gate.perform(generation: oldGeneration) { daemon.volumes.append("resurrected-volume") }
        }
        #expect(daemon.volumes.isEmpty)
    }

    @Test func failedMountDrainsAndFailedSignOutCanReopenForNewRequests() async throws {
        enum Failure: Error { case cannotMount }
        let gate = MountOperationGate()
        await #expect(throws: Failure.self) {
            try await gate.perform(generation: gate.generation) { throw Failure.cannotMount }
        }
        await gate.closeAndDrain()
        #expect(!gate.acceptsMounts)
        gate.reopen() // a flush/unmount failure retains credentials and permits retry
        let value = try await gate.perform(generation: gate.generation) { "connected" }
        #expect(value == "connected")
    }
}
