// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// DaemonCredential (auth-spec C6/§4.3): the daemon's 30-day token is re-minted
// by the app when < 7 days remain. Pure threshold math + the UserDefaults
// expiry persistence the renewal cycle reads.

@Suite struct DaemonCredentialTests {

    private let now = Date(timeIntervalSince1970: 1_780_000_000)

    @Test func unknownExpiryAlwaysRenews() {
        #expect(DaemonCredential.shouldRenew(expiresAt: nil, now: now))
    }

    @Test func freshTokenDoesNotRenew() {
        let in30d = now.addingTimeInterval(30 * 86_400)
        #expect(!DaemonCredential.shouldRenew(expiresAt: in30d, now: now))
        let in8d = now.addingTimeInterval(8 * 86_400)
        #expect(!DaemonCredential.shouldRenew(expiresAt: in8d, now: now))
    }

    @Test func insideSevenDayWindowRenews() {
        let in6d = now.addingTimeInterval(6 * 86_400)
        #expect(DaemonCredential.shouldRenew(expiresAt: in6d, now: now))
        let inOneHour = now.addingTimeInterval(3600)
        #expect(DaemonCredential.shouldRenew(expiresAt: inOneHour, now: now))
    }

    @Test func expiredTokenRenews() {
        let past = now.addingTimeInterval(-60)
        #expect(DaemonCredential.shouldRenew(expiresAt: past, now: now))
    }

    @Test func boundaryIsExclusive() {
        // Exactly 7 days remaining: not yet inside the window (strict <)…
        let exactly7d = now.addingTimeInterval(DaemonCredential.renewThreshold)
        #expect(!DaemonCredential.shouldRenew(expiresAt: exactly7d, now: now))
        // …one second less is.
        let justInside = exactly7d.addingTimeInterval(-1)
        #expect(DaemonCredential.shouldRenew(expiresAt: justInside, now: now))
    }

    @Test func checkIntervalIsWellInsideTheRenewWindow() {
        // The periodic check must fire many times within the 7-day window so a
        // long-running app can never sail past expiry between ticks.
        #expect(DaemonCredential.checkInterval * 4 < DaemonCredential.renewThreshold)
    }

    @Test func expiryPersistenceRoundTrips() throws {
        let suite = "test.daemoncred." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }

        #expect(DaemonCredential.storedExpiry(defaults: defaults) == nil)
        let expiry = Date(timeIntervalSince1970: 1_782_600_000)
        DaemonCredential.storeExpiry(expiry, defaults: defaults)
        #expect(DaemonCredential.storedExpiry(defaults: defaults) == expiry)
        DaemonCredential.storeExpiry(nil, defaults: defaults)
        #expect(DaemonCredential.storedExpiry(defaults: defaults) == nil)
    }

    @Test func preSnapshotCredentialsRenewOnceEvenWithFreshExpiry() throws {
        let suite = "test.daemoncred.upgrade." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defer { defaults.removePersistentDomain(forName: suite) }
        let expiry = now.addingTimeInterval(30 * 86_400)
        defaults.set(expiry.timeIntervalSince1970, forKey: DaemonCredential.expiresAtKey)
        #expect(!DaemonCredential.shouldRenew(expiresAt: expiry, now: now))
        #expect(DaemonCredential.needsCapabilityUpgrade(defaults: defaults))
        DaemonCredential.storeExpiry(expiry, defaults: defaults)
        #expect(!DaemonCredential.needsCapabilityUpgrade(defaults: defaults))
        DaemonCredential.storeExpiry(nil, defaults: defaults)
        #expect(DaemonCredential.needsCapabilityUpgrade(defaults: defaults))
    }
}

@MainActor
@Suite struct DaemonCredentialHandoffTests {
    private func fixture(_ body: @MainActor (UserDefaults, URL) async throws -> Void) async throws {
        let suite = "test.daemon-handoff." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(suite)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: root)
        }
        try DaemonProvisioning.provision(gatewayURL: "https://fixture.invalid", token: "revoked-old-account",
                                         root: root, finderSocketPath: nil)
        DaemonCredential.storeExpiry(Date().addingTimeInterval(30 * 86_400), defaults: defaults)
        try await body(defaults, root)
    }

    private func minted() -> DaemonTokenResponse {
        .init(id: "fixture-service-token", token: "new-normal-user",
              expiresAt: Date().addingTimeInterval(30 * 86_400).timeIntervalSince1970 * 1000)
    }

    @Test func browserSignInReplacesFreshButRevokedPreviousAccountToken() async throws {
        try await fixture { defaults, root in
            var mintCalls = 0
            try await DaemonCredentialHandoff.prepare(forceMint: true, defaults: defaults,
                existingToken: { DaemonProvisioning.existingToken(gatewayURL: "https://fixture.invalid", root: root) },
                mint: { mintCalls += 1; return minted() },
                provision: { token in
                    try DaemonProvisioning.provision(gatewayURL: "https://fixture.invalid", token: token,
                                                     root: root, finderSocketPath: nil)
                })
            #expect(mintCalls == 1)
            #expect(DaemonProvisioning.existingToken(gatewayURL: "https://fixture.invalid", root: root) == "new-normal-user")
            #expect(DaemonCredential.storedExpiry(defaults: defaults) != nil)
        }
    }

    @Test func failedFreshMintCannotReusePreviousAccountOnNextLaunch() async throws {
        try await fixture { defaults, root in
            var provisionCalls = 0
            await #expect(throws: AuthSessionError.self) {
                try await DaemonCredentialHandoff.prepare(forceMint: true, defaults: defaults,
                    existingToken: { "revoked-old-account" },
                    mint: { throw AuthSessionError.transient("fixture offline") },
                    provision: { _ in provisionCalls += 1 })
            }
            #expect(provisionCalls == 0)
            #expect(DaemonCredential.storedExpiry(defaults: defaults) == nil)
            var resumedMintCalls = 0
            try await DaemonCredentialHandoff.prepare(forceMint: false, defaults: defaults,
                existingToken: { DaemonProvisioning.existingToken(gatewayURL: "https://fixture.invalid", root: root) },
                mint: { resumedMintCalls += 1; return minted() },
                provision: { token in
                    #expect(token == "new-normal-user")
                    provisionCalls += 1
                })
            #expect(resumedMintCalls == 1)
            #expect(provisionCalls == 1)
        }
    }

    @Test func updateResumingSameSessionRestartsEngineWithoutNeedlessRotation() async throws {
        try await fixture { defaults, _ in
            var mintCalls = 0
            var provisioned: [String] = []
            try await DaemonCredentialHandoff.prepare(forceMint: false, defaults: defaults,
                existingToken: { "same-session-token" },
                mint: { mintCalls += 1; return minted() },
                provision: { provisioned.append($0) })
            #expect(mintCalls == 0)
            #expect(provisioned == ["same-session-token"])
        }
    }

    @Test func provisioningFailureDoesNotRecordSuccessOrKeepOldExpiry() async throws {
        try await fixture { defaults, _ in
            await #expect(throws: DaemonCredentialHandoff.Failure.self) {
                try await DaemonCredentialHandoff.prepare(forceMint: true, defaults: defaults,
                    existingToken: { "revoked-old-account" }, mint: { minted() },
                    provision: { _ in throw DaemonCredentialHandoff.Failure.provisioning })
            }
            #expect(DaemonCredential.storedExpiry(defaults: defaults) == nil)
        }
    }

    @Test func supersededSessionCannotOverwriteNewAccountAfterAwait() async throws {
        try await fixture { defaults, _ in
            var current = true
            var provisionCalls = 0
            let newestExpiry = Date(timeIntervalSince1970: floor(Date().timeIntervalSince1970) + 10 * 86_400)
            await #expect(throws: CancellationError.self) {
                try await DaemonCredentialHandoff.prepare(forceMint: true, defaults: defaults,
                    existingToken: { nil }, mint: {
                        current = false
                        DaemonCredential.storeExpiry(newestExpiry, defaults: defaults)
                        return minted()
                    }, provision: { _ in provisionCalls += 1 }, isCurrent: { current })
            }
            #expect(provisionCalls == 0)
            #expect(DaemonCredential.storedExpiry(defaults: defaults) == newestExpiry)
        }
    }
}
