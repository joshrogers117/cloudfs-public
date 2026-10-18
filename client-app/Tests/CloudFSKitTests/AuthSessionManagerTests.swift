// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// AuthSessionManager (auth-spec C2/§2.4/§1.5): exchange, rotate-on-use refresh,
// persist-before-discard, Keychain-failure retry, transport-vs-auth error
// classification, session-expired terminal state, daemon-token mint, and the
// proactive-refresh schedule math. Mock transport + in-memory token store —
// no network, no Keychain.

// MARK: Test doubles

/// In-memory RefreshTokenStore with controllable save failures.
private final class TokenBox: @unchecked Sendable {
    private let lock = NSLock()
    private var _value: String?
    private var _failSaves = false
    private var _saveAttempts = 0

    var value: String? {
        lock.lock(); defer { lock.unlock() }
        return _value
    }
    var saveAttempts: Int {
        lock.lock(); defer { lock.unlock() }
        return _saveAttempts
    }
    func setFailSaves(_ fail: Bool) {
        lock.lock(); defer { lock.unlock() }
        _failSaves = fail
    }
    func preload(_ v: String?) {
        lock.lock(); defer { lock.unlock() }
        _value = v
    }

    struct SaveFailed: Error {}

    var store: RefreshTokenStore {
        RefreshTokenStore(
            load: { [self] in
                lock.lock(); defer { lock.unlock() }
                return _value
            },
            save: { [self] new in
                lock.lock(); defer { lock.unlock() }
                _saveAttempts += 1
                if _failSaves { throw SaveFailed() }
                _value = new
            },
            clear: { [self] in
                lock.lock(); defer { lock.unlock() }
                _value = nil
            })
    }
}

/// Controllable mock of the device-auth endpoints. Counts calls and records the
/// refresh tokens presented.
private final class MockAPI: DeviceAuthAPIProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var _refreshCalls = 0
    private var _presentedRefreshTokens: [String] = []
    private var _mintedWithAccess: [String] = []

    /// Behaviors (settable from tests; guarded).
    var exchangeResult: @Sendable (String, String) throws -> DeviceTokenResponse = { code, _ in
        DeviceTokenResponse(refreshToken: "refresh-1", accessToken: "access-1",
                            accessTtlSeconds: 900, orgId: "acme", orgName: "Acme Post",
                            account: .init(email: "josh@acme.example"),
                            device: .init(id: "dev-1", name: "Mac"))
    }
    var refreshResult: @Sendable (Int, String) throws -> DeviceRefreshResponse = { n, _ in
        DeviceRefreshResponse(refreshToken: "refresh-\(n + 1)",
                              accessToken: "access-\(n + 1)", accessTtlSeconds: 900)
    }
    var daemonResult: @Sendable (String) throws -> DaemonTokenResponse = { _ in
        DaemonTokenResponse(id: "svc-1", token: "daemon-jws",
                            expiresAt: Date().addingTimeInterval(30 * 86_400).timeIntervalSince1970 * 1000,
                            scopes: ["fs:read", "fs:write", "fs:lock"])
    }

    var refreshCalls: Int {
        lock.lock(); defer { lock.unlock() }
        return _refreshCalls
    }
    var presentedRefreshTokens: [String] {
        lock.lock(); defer { lock.unlock() }
        return _presentedRefreshTokens
    }
    var mintedWithAccess: [String] {
        lock.lock(); defer { lock.unlock() }
        return _mintedWithAccess
    }

    // NSLock is unavailable inside async functions; do the bookkeeping in
    // synchronous helpers instead.
    private func recordRefresh(_ token: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        _refreshCalls += 1
        _presentedRefreshTokens.append(token)
        return _refreshCalls
    }
    private func recordMint(_ access: String) {
        lock.lock(); defer { lock.unlock() }
        _mintedWithAccess.append(access)
    }

    func publicConfig() async throws -> PublicAuthConfig {
        PublicAuthConfig(mode: "builtin", webBaseUrl: "https://gw.test")
    }
    func exchange(code: String, codeVerifier: String) async throws -> DeviceTokenResponse {
        try exchangeResult(code, codeVerifier)
    }
    func refresh(refreshToken: String) async throws -> DeviceRefreshResponse {
        let n = recordRefresh(refreshToken)
        return try refreshResult(n, refreshToken)
    }
    func mintDaemonToken(accessToken: String) async throws -> DaemonTokenResponse {
        recordMint(accessToken)
        return try daemonResult(accessToken)
    }
}

/// Adjustable clock so expiry checks are deterministic.
private final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var _now = Date(timeIntervalSince1970: 1_780_000_000)
    var now: Date {
        lock.lock(); defer { lock.unlock() }
        return _now
    }
    func advance(_ seconds: TimeInterval) {
        lock.lock(); defer { lock.unlock() }
        _now = _now.addingTimeInterval(seconds)
    }
    var closure: @Sendable () -> Date { { self.now } }
}

/// Deliberately ignores task cancellation until released, like an HTTP response
/// already queued for delivery when the user switches accounts.
private actor DeferredDeviceAPI: DeviceAuthAPIProtocol {
    enum Operation: CaseIterable { case exchange, refresh, mint }
    let operation: Operation
    let fails: Bool
    private var pending: CheckedContinuation<Void, Never>?
    private var entered = false
    init(_ operation: Operation, fails: Bool) { self.operation = operation; self.fails = fails }
    func waitUntilRequested() async {
        while !entered { await Task.yield() }
    }
    func release() { pending?.resume(); pending = nil }
    private func hold(_ requested: Operation) async throws {
        guard requested == operation else { return }
        await withCheckedContinuation { pending = $0; entered = true }
        if fails {
            throw HttpGatewayClient.GatewayError.http(status: 401, code: "device_revoked", reason: nil)
        }
    }
    func publicConfig() async throws -> PublicAuthConfig { .init(mode: "builtin", webBaseUrl: "https://fixture.invalid") }
    func exchange(code: String, codeVerifier: String) async throws -> DeviceTokenResponse {
        try await hold(.exchange)
        return .init(refreshToken: "old-refresh", accessToken: "old-access", accessTtlSeconds: 900, orgId: "old-org")
    }
    func refresh(refreshToken: String) async throws -> DeviceRefreshResponse {
        try await hold(.refresh)
        return .init(refreshToken: "late-old-refresh", accessToken: "late-old-access", accessTtlSeconds: 900)
    }
    func mintDaemonToken(accessToken: String) async throws -> DaemonTokenResponse {
        try await hold(.mint)
        return .init(id: "old-service", token: "late-old-daemon", expiresAt: 2_000_000_000_000)
    }
}

@Suite struct AuthSessionManagerTests {

    @Test func retiredSessionCannotOverwriteOrClearReplacementCredentials() async throws {
        for operation in DeferredDeviceAPI.Operation.allCases {
            for fails in [false, true] {
                let box = TokenBox(), notices = TokenBox()
                let oldAPI = DeferredDeviceAPI(operation, fails: fails)
                let old = AuthSessionManager(api: oldAPI, store: box.store, autoRefresh: false)
                await old.setOnSessionExpired { notices.preload($0) }
                if operation != .exchange { _ = try await old.exchange(code: "old", codeVerifier: "fixture") }
                let late = Task {
                    switch operation {
                    case .exchange: _ = try await old.exchange(code: "old", codeVerifier: "fixture")
                    case .refresh: try await old.refreshIfNeeded(force: true)
                    case .mint: _ = try await old.mintDaemonToken()
                    }
                }
                await oldAPI.waitUntilRequested()
                let beforeRetirement = box.value
                await old.retire()
                #expect(box.value == beforeRetirement, "Retirement itself must not clear the shared store")
                let replacement = AuthSessionManager(api: MockAPI(), store: box.store, autoRefresh: false)
                _ = try await replacement.exchange(code: "new", codeVerifier: "fixture")
                #expect(box.value == "refresh-1")
                await oldAPI.release()
                await #expect(throws: AuthSessionError.notSignedIn) { try await late.value }
                #expect(box.value == "refresh-1", "Late old success/failure must not replace or erase the new account")
                #expect(notices.value == nil, "Old account must not expire the replacement UI/daemon session")
                #expect(await old.validAccessToken() == nil)
                #expect(await old.loadPersistedSession() == false)
                await old.signOutLocal()
                #expect(box.value == "refresh-1", "Retired sign-out cannot clear replacement credentials")
                #expect(await replacement.validAccessToken() == "access-1")
            }
        }
    }

    private func makeManager(api: MockAPI = MockAPI(), box: TokenBox = TokenBox(),
                             clock: TestClock = TestClock())
        -> (AuthSessionManager, MockAPI, TokenBox, TestClock) {
        // autoRefresh off: tests drive refreshes explicitly (the schedule math is
        // tested separately as a pure function).
        let m = AuthSessionManager(api: api, store: box.store,
                                   autoRefresh: false, now: clock.closure)
        return (m, api, box, clock)
    }

    // MARK: exchange

    @Test func exchangePersistsRefreshAndKeepsAccessInMemory() async throws {
        let (m, api, box, _) = makeManager()
        let session = try await m.exchange(code: "acme.dac-1.s", codeVerifier: "v")
        #expect(session.orgId == "acme")
        #expect(box.value == "refresh-1")                       // refresh → store
        let access = await m.validAccessToken()
        #expect(access == "access-1")                           // access → memory
        #expect(api.refreshCalls == 0)                          // fresh: no refresh yet
    }

    @Test func exchangeFailureNeverExpiresOrPersistsAnything() async throws {
        let (m, api, box, _) = makeManager()
        api.exchangeResult = { _, _ in
            throw HttpGatewayClient.GatewayError.http(status: 400, code: "invalid_code", reason: nil)
        }
        await #expect(throws: AuthSessionError.self) {
            _ = try await m.exchange(code: "burned", codeVerifier: "v")
        }
        let expired = await m.isExpired
        #expect(!expired)               // no session existed — nothing to expire
        #expect(box.value == nil)
    }

    // Exchange classification (contract-review N-2): the backend consumes the
    // one-time code even on failure, so 400 invalid_code / pkce_mismatch are
    // TERMINAL for the attempt — the UI must say "start again", not imply that
    // retrying the same code might work.

    @Test func burnedCodeExchangeThrowsCodeRejectedWithStartAgainCopy() async {
        let (m, api, _, _) = makeManager()
        api.exchangeResult = { _, _ in
            throw HttpGatewayClient.GatewayError.http(status: 400, code: "invalid_code", reason: nil)
        }
        do {
            _ = try await m.exchange(code: "burned", codeVerifier: "v")
            Issue.record("expected codeRejected")
        } catch let e as AuthSessionError {
            #expect(e == .codeRejected(code: "invalid_code"))
            #expect(e.localizedDescription ==
                    "That code was already used or expired — start the sign-in again from the browser.")
            #expect(!e.localizedDescription.contains("Temporary"))
        } catch {
            Issue.record("unexpected error type: \(error)")
        }
    }

    @Test func classifyExchangeMapsTerminalCodesAndKeepsEverythingElseTransient() {
        func http(_ status: Int, _ code: String) -> Error {
            HttpGatewayClient.GatewayError.http(status: status, code: code, reason: nil)
        }
        // Both spec §2.3 terminal codes (auth-device.ts consumes the code first).
        #expect(AuthSessionManager.classifyExchange(http(400, "invalid_code"))
                == .codeRejected(code: "invalid_code"))
        #expect(AuthSessionManager.classifyExchange(http(400, "pkce_mismatch"))
                == .codeRejected(code: "pkce_mismatch"))
        // Everything else stays transient: other 400s, 429, 5xx, transport —
        // and a terminal-looking code on a NON-400 status is not trusted.
        for err in [http(400, "bad_request"), http(429, "rate_limited"),
                    http(500, "internal"), http(401, "account_inactive"),
                    http(503, "invalid_code"),
                    HttpGatewayClient.GatewayError.transport("offline")] {
            guard case .transient = AuthSessionManager.classifyExchange(err) else {
                Issue.record("\(err) must classify transient")
                continue
            }
        }
    }

    // MARK: refresh rotation

    @Test func refreshRotatesAndPersistsBeforeUse() async throws {
        let (m, api, box, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        try await m.refreshIfNeeded(force: true)
        #expect(box.value == "refresh-2")                       // rotated + persisted
        try await m.refreshIfNeeded(force: true)
        #expect(api.presentedRefreshTokens == ["refresh-1", "refresh-2"])
        #expect(box.value == "refresh-3")
    }

    @Test func staleAccessTokenTriggersRefreshOnDemand() async throws {
        let (m, api, _, clock) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        clock.advance(1000)                                     // past the 900s TTL
        let access = await m.validAccessToken()
        #expect(access == "access-2")
        #expect(api.refreshCalls == 1)
    }

    @Test func keychainFailureKeepsOldStoredValueAndRetriesNextTick() async throws {
        let (m, _, box, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        #expect(box.value == "refresh-1")

        box.setFailSaves(true)
        try await m.refreshIfNeeded(force: true)                // rotation succeeds server-side
        #expect(box.value == "refresh-1")                       // old stored value kept
        let access = await m.validAccessToken()
        #expect(access == "access-2")                           // memory advanced anyway

        box.setFailSaves(false)
        try await m.refreshIfNeeded(force: true)
        // The unpersisted refresh-2 is re-saved BEFORE rotating again, then the
        // rotation result lands too — store converges on the newest secret.
        #expect(box.value == "refresh-3")
    }

    @Test func memoryUsesNewestSecretAfterFailedPersist() async throws {
        let (m, api, box, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        box.setFailSaves(true)
        try await m.refreshIfNeeded(force: true)
        try await m.refreshIfNeeded(force: true)
        // Server rotated twice; the manager must keep presenting the newest.
        #expect(api.presentedRefreshTokens == ["refresh-1", "refresh-2"])
        #expect(box.value == "refresh-1")
    }

    // MARK: error classification (spec §1.5 — transport never destroys credentials)

    @Test func transportErrorKeepsCredentials() async throws {
        let (m, api, box, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        api.refreshResult = { _, _ in
            throw HttpGatewayClient.GatewayError.transport("offline")
        }
        do {
            try await m.refreshIfNeeded(force: true)
            Issue.record("expected transient error")
        } catch let e as AuthSessionError {
            guard case .transient = e else {
                Issue.record("transport must classify transient, got \(e)")
                return
            }
        }
        let expired = await m.isExpired
        #expect(!expired)
        #expect(box.value == "refresh-1")                       // credentials intact
        // Recovery: network back → refresh works again.
        api.refreshResult = { n, _ in
            DeviceRefreshResponse(refreshToken: "refresh-\(n + 1)",
                                  accessToken: "access-\(n + 1)", accessTtlSeconds: 900)
        }
        try await m.refreshIfNeeded(force: true)
        #expect(box.value == "refresh-3")                       // call #2 → refresh-3
    }

    @Test func serverErrorsAreTransientToo() async throws {
        let (m, api, box, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        for (status, code) in [(429, "rate_limited"), (500, "internal"), (503, "unavailable")] {
            api.refreshResult = { _, _ in
                throw HttpGatewayClient.GatewayError.http(status: status, code: code, reason: nil)
            }
            do { try await m.refreshIfNeeded(force: true) }
            catch let e as AuthSessionError {
                guard case .transient = e else {
                    Issue.record("HTTP \(status) must be transient, got \(e)")
                    return
                }
            }
        }
        let expired = await m.isExpired
        #expect(!expired)
        #expect(box.value == "refresh-1")
    }

    @Test func terminal401ExpiresSessionAndClearsCredentials() async throws {
        let (m, api, box, _) = makeManager()
        let observed = TokenBox()                               // reuse as a string box
        await m.setOnSessionExpired { code in observed.preload(code) }
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        api.refreshResult = { _, _ in
            throw HttpGatewayClient.GatewayError.http(status: 401, code: "device_revoked", reason: nil)
        }
        do {
            try await m.refreshIfNeeded(force: true)
            Issue.record("expected sessionExpired")
        } catch let e as AuthSessionError {
            #expect(e == .sessionExpired(code: "device_revoked"))
        }
        let expired = await m.isExpired
        #expect(expired)
        #expect(box.value == nil)                               // stored refresh cleared
        #expect(observed.value == "device_revoked")             // app notified once
        let access = await m.validAccessToken()
        #expect(access == nil)                                  // no more tokens handed out
    }

    @Test func everyTerminalCodeExpires() async throws {
        for code in ["invalid_refresh", "refresh_reused", "device_revoked",
                     "device_expired", "account_inactive"] {
            let (m, api, _, _) = makeManager()
            _ = try await m.exchange(code: "c", codeVerifier: "v")
            api.refreshResult = { _, _ in
                throw HttpGatewayClient.GatewayError.http(status: 401, code: code, reason: nil)
            }
            await #expect(throws: AuthSessionError.sessionExpired(code: code)) {
                try await m.refreshIfNeeded(force: true)
            }
        }
    }

    // MARK: 401-retry-once recovery hook

    @Test func recoverFromUnauthorizedForcesOneRefresh() async throws {
        let (m, api, _, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        let fresh = await m.recoverFromUnauthorized()
        #expect(fresh == "access-2")
        #expect(api.refreshCalls == 1)
    }

    @Test func recoverReturnsNilOnceExpired() async throws {
        let (m, api, _, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        api.refreshResult = { _, _ in
            throw HttpGatewayClient.GatewayError.http(status: 401, code: "invalid_refresh", reason: nil)
        }
        let first = await m.recoverFromUnauthorized()
        #expect(first == nil)
        let second = await m.recoverFromUnauthorized()          // already expired: no call
        #expect(second == nil)
        #expect(api.refreshCalls == 1)
    }

    // MARK: relaunch resume

    @Test func loadPersistedSessionResumesFromStore() async throws {
        let box = TokenBox()
        box.preload("refresh-7")
        let (m, api, _, _) = makeManager(box: box)
        let found = await m.loadPersistedSession()
        #expect(found)
        try await m.refreshIfNeeded(force: true)
        #expect(api.presentedRefreshTokens == ["refresh-7"])
    }

    @Test func loadPersistedSessionFalseWhenStoreEmpty() async throws {
        let (m, _, _, _) = makeManager()
        let found = await m.loadPersistedSession()
        #expect(!found)
        await #expect(throws: AuthSessionError.notSignedIn) {
            try await m.refreshIfNeeded(force: true)
        }
    }

    // MARK: daemon-token mint (C6)

    @Test func mintDaemonTokenUsesLiveAccessToken() async throws {
        let (m, api, _, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        let minted = try await m.mintDaemonToken()
        #expect(minted.token == "daemon-jws")
        #expect(api.mintedWithAccess == ["access-1"])
        // expiryDate converts the epoch-ms wire field.
        #expect(abs(minted.expiryDate.timeIntervalSinceNow - 30 * 86_400) < 60)
    }

    @Test func mintDaemonTokenTerminalFailureExpiresSession() async throws {
        let (m, api, _, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        api.daemonResult = { _ in
            throw HttpGatewayClient.GatewayError.http(status: 401, code: "device_revoked", reason: nil)
        }
        await #expect(throws: AuthSessionError.sessionExpired(code: "device_revoked")) {
            _ = try await m.mintDaemonToken()
        }
        let expired = await m.isExpired
        #expect(expired)
    }

    // MARK: schedule math (C2: proactive refresh at 0.8×TTL)

    @Test func refreshDelayIsEightyPercentOfTTL() {
        #expect(AuthSessionManager.refreshDelay(ttlSeconds: 900) == 720)
        #expect(AuthSessionManager.refreshDelay(ttlSeconds: 60) == 48)
        #expect(AuthSessionManager.refreshDelay(ttlSeconds: 0) == 1)   // floor: never spin
    }

    @Test func signOutLocalClearsEverything() async throws {
        let (m, _, box, _) = makeManager()
        _ = try await m.exchange(code: "c", codeVerifier: "v")
        await m.signOutLocal()
        #expect(box.value == nil)
        let access = await m.validAccessToken()
        #expect(access == nil)
        let found = await m.loadPersistedSession()
        #expect(!found)
    }
}
