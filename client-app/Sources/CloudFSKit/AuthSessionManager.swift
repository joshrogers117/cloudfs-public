// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import os

// MARK: - AuthSessionManager — the long-lived device session (auth-spec §6.3 C2)
//
// Owns the device credential pair:
//   • refresh token — opaque, ~400-day sliding, ROTATES on every use. Persisted
//     in the Keychain (account "device-refresh-token"), never in UserDefaults.
//   • access token  — short-lived JWS (15 min), kept in MEMORY only.
//
// Rules implemented here (normative, spec §2.4 + §1.5):
//   • proactive refresh at 0.8×TTL (self-scheduling task), plus refresh-on-demand
//     when a caller needs a token and the current one is stale;
//   • rotate-on-use persistence: the NEW refresh token is written to the Keychain
//     BEFORE the old one is dropped; if the Keychain write fails the old stored
//     value is kept and the persist retries on the next tick (the 60s server-side
//     rotation grace covers the race);
//   • error classification: transport/server hiccups NEVER destroy credentials;
//     only the terminal 401 codes (invalid_refresh / refresh_reused /
//     device_revoked / device_expired / account_inactive) flip the session to
//     EXPIRED — which clears local credentials and notifies the app so it can
//     show "Session expired — sign in again" (never a raw gateway error).

// MARK: Pluggable refresh-token persistence (Keychain in prod, memory in tests)

public struct RefreshTokenStore: Sendable {
    public var load: @Sendable () -> String?
    public var save: @Sendable (String) throws -> Void
    public var clear: @Sendable () -> Void

    public init(load: @escaping @Sendable () -> String?,
                save: @escaping @Sendable (String) throws -> Void,
                clear: @escaping @Sendable () -> Void) {
        self.load = load; self.save = save; self.clear = clear
    }

    /// The production store: macOS Keychain under the app's service, with the
    /// existing DP-keychain → legacy-file-keychain fallback chain (Keychain.swift).
    public static let keychain = RefreshTokenStore(
        load: { Keychain.get(account: Keychain.deviceRefreshTokenAccount) },
        save: { try Keychain.set($0, account: Keychain.deviceRefreshTokenAccount) },
        clear: { Keychain.delete(account: Keychain.deviceRefreshTokenAccount) })
}

// MARK: Errors as the APP classifies them (spec §1.5 failure classes)

public enum AuthSessionError: Error, Sendable, Equatable, CustomStringConvertible, LocalizedError {
    /// No device session exists locally (fresh install / after sign-out).
    case notSignedIn
    /// Network / transient server problem — credentials are intact; retry later.
    case transient(String)
    /// The device session is dead server-side (revoked/expired/reused/account
    /// inactive). Local credentials are cleared; the user must sign in again.
    case sessionExpired(code: String)
    /// The one-time sign-in code was rejected TERMINALLY (`invalid_code` /
    /// `pkce_mismatch` — the backend consumes the code even on failure), so
    /// retrying the same code can never succeed. No session exists yet and no
    /// credentials are touched; the user must start the sign-in over.
    case codeRejected(code: String)

    public var description: String {
        switch self {
        case .notSignedIn: return "Not signed in."
        case .transient(let m): return "Temporary connection problem: \(m)"
        case .sessionExpired: return "Session expired — sign in again."
        case .codeRejected:
            return "That code was already used or expired — start the sign-in again from the browser."
        }
    }
    public var errorDescription: String? { description }
}

// MARK: The manager

public actor AuthSessionManager {

    /// 401 codes that mean the device session itself is dead (spec §2.4).
    /// Anything else — 429, 5xx, transport — is transient and keeps credentials.
    public static let terminalCodes: Set<String> = [
        "invalid_refresh", "refresh_reused", "device_revoked",
        "device_expired", "account_inactive",
    ]

    /// Proactive refresh point as a fraction of the access TTL (spec C2: 0.8×TTL).
    public static let refreshFraction = 0.8
    /// Don't hand out an access token with less than this many seconds left;
    /// refresh instead (covers clock skew + request flight time).
    public static let expiryMarginSeconds: TimeInterval = 30

    /// Schedule math, kept pure for tests: when to proactively refresh.
    public static func refreshDelay(ttlSeconds: Double) -> TimeInterval {
        max(1, ttlSeconds * refreshFraction)
    }

    private let api: any DeviceAuthAPIProtocol
    private let store: RefreshTokenStore
    private let now: @Sendable () -> Date
    private let autoRefresh: Bool
    private let log = Logger(subsystem: "dev.cloudfs.client", category: "auth-session")

    // Credential state
    private var refreshToken: String?
    private var unpersistedRefresh: String?   // newest rotation the Keychain hasn't accepted yet
    private var accessToken: String?
    private var accessExpiry: Date = .distantPast
    private var lastTtlSeconds: Double = 900
    private(set) public var isExpired = false
    private var retired = false

    // Coordination
    private var inFlightRefresh: Task<Void, Error>?
    private var scheduledRefresh: Task<Void, Never>?
    private var onSessionExpired: (@Sendable (String) -> Void)?

    public init(api: any DeviceAuthAPIProtocol,
                store: RefreshTokenStore = .keychain,
                autoRefresh: Bool = true,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.store = store
        self.autoRefresh = autoRefresh
        self.now = now
    }

    deinit {
        scheduledRefresh?.cancel()
        inFlightRefresh?.cancel()
    }

    /// Called once on terminal refresh failure with the gateway's error code.
    public func setOnSessionExpired(_ handler: @escaping @Sendable (String) -> Void) {
        onSessionExpired = handler
    }

    // MARK: Session lifecycle

    /// Load a persisted refresh token (app relaunch). Returns true when a device
    /// session exists locally — the caller should then `refreshIfNeeded()`.
    @discardableResult
    public func loadPersistedSession() -> Bool {
        guard !retired else { return false }
        guard refreshToken == nil else { return true }
        refreshToken = store.load()
        return refreshToken != nil
    }

    /// Exchange a one-time device code + PKCE verifier for the device session
    /// (POST /v1/auth/device/token). Persists the refresh token, keeps the access
    /// token in memory, and starts the proactive-refresh schedule.
    public func exchange(code: String, codeVerifier: String) async throws -> DeviceTokenResponse {
        try requireActive()
        let response: DeviceTokenResponse
        do {
            response = try await api.exchange(code: code, codeVerifier: codeVerifier)
        } catch {
            try requireActive()
            throw Self.classifyExchange(error)
        }
        try requireActive()
        isExpired = false
        adopt(refresh: response.refreshToken,
              access: response.accessToken,
              ttlSeconds: response.accessTtlSeconds)
        return response
    }

    /// A valid access token for an Authorization header, refreshing first when
    /// the in-memory one is missing/stale. nil when the session is gone (expired
    /// or signed out) OR the refresh failed transiently (callers treat nil as
    /// "send nothing"; the request will 401 and retry via `recoverFromUnauthorized`).
    public func validAccessToken() async -> String? {
        if isExpired || retired { return nil }
        if let token = accessToken,
           now().addingTimeInterval(Self.expiryMarginSeconds) < accessExpiry {
            return token
        }
        try? await refreshIfNeeded(force: false)
        return isExpired || retired ? nil : accessToken
    }

    /// One forced refresh for a 401-retry (spec C2: refresh-on-401, retry once).
    /// Returns the fresh access token, or nil when the session is dead/unreachable.
    public func recoverFromUnauthorized() async -> String? {
        guard !isExpired, !retired else { return nil }
        do {
            try await refreshIfNeeded(force: true)
            return retired ? nil : accessToken
        } catch {
            return nil
        }
    }

    /// Refresh the device session now (rotate-on-use). Single-flight: concurrent
    /// callers await the same network round-trip.
    public func refreshIfNeeded(force: Bool = true) async throws {
        try requireActive()
        if isExpired { throw AuthSessionError.sessionExpired(code: "expired") }
        if !force, let _ = accessToken,
           now().addingTimeInterval(Self.expiryMarginSeconds) < accessExpiry {
            return
        }
        if let inFlight = inFlightRefresh {
            try await inFlight.value
            return
        }
        let task = Task { try await self.performRefresh() }
        inFlightRefresh = task
        defer { inFlightRefresh = nil }
        try await task.value
    }

    private func performRefresh() async throws {
        try requireActive()
        // Retry any rotation the Keychain didn't accept last time, BEFORE rotating
        // again (keeps the persisted token at most one rotation behind).
        retryUnpersisted()
        guard let current = refreshToken ?? store.load() else {
            throw AuthSessionError.notSignedIn
        }
        refreshToken = current
        let response: DeviceRefreshResponse
        do {
            response = try await api.refresh(refreshToken: current)
        } catch {
            try requireActive()
            let classified = Self.classifyRefresh(error)
            if case .sessionExpired(let code) = classified {
                expireLocally(code: code)
            } else {
                log.notice("device refresh transient failure: \(String(describing: error), privacy: .public)")
            }
            throw classified
        }
        try requireActive()
        adopt(refresh: response.refreshToken,
              access: response.accessToken,
              ttlSeconds: response.accessTtlSeconds)
    }

    /// Mint the daemon's 30-day service token from this device session
    /// (POST /v1/auth/device/daemon-token, Bearer = device access JWS).
    public func mintDaemonToken() async throws -> DaemonTokenResponse {
        try requireActive()
        guard let access = await validAccessToken() else {
            try requireActive()
            throw isExpired
                ? AuthSessionError.sessionExpired(code: "expired")
                : AuthSessionError.transient("no access token available")
        }
        try requireActive()
        do {
            let minted = try await api.mintDaemonToken(accessToken: access)
            try requireActive()
            return minted
        } catch {
            try requireActive()
            let classified = Self.classifyRefresh(error)
            if case .sessionExpired(let code) = classified { expireLocally(code: code) }
            throw classified
        }
    }

    /// Local sign-out: clear both tokens (Keychain + memory) and stop the
    /// schedule. (Server-side device revocation is out of scope tonight —
    /// the device stays revocable from the web console's Devices list.)
    public func signOutLocal() {
        guard !retired else { return }
        retire()
        store.clear()
    }

    /// Permanently relinquish the shared credential store before another account
    /// takes ownership. Even an API that ignores cancellation cannot publish a
    /// late refresh or clear the replacement account's saved credentials.
    public func retire() {
        retired = true
        scheduledRefresh?.cancel(); scheduledRefresh = nil
        inFlightRefresh?.cancel(); inFlightRefresh = nil
        onSessionExpired = nil
        refreshToken = nil
        unpersistedRefresh = nil
        accessToken = nil
        accessExpiry = .distantPast
        isExpired = false
    }

    private func requireActive() throws {
        guard !retired else { throw AuthSessionError.notSignedIn }
    }

    // MARK: internals

    /// Rotation persistence rule (spec C2): write the NEW refresh token to the
    /// store BEFORE dropping the old from memory; on store failure keep the old
    /// stored value and retry on the next tick. Memory always advances to the
    /// newest secret (the server has already rotated — the old one only survives
    /// inside the 60s grace window).
    private func adopt(refresh newRefresh: String, access: String, ttlSeconds: Double) {
        do {
            try store.save(newRefresh)
            unpersistedRefresh = nil
        } catch {
            log.error("refresh-token Keychain write failed; will retry: \(error.localizedDescription, privacy: .public)")
            unpersistedRefresh = newRefresh
        }
        refreshToken = newRefresh
        accessToken = access
        lastTtlSeconds = ttlSeconds
        accessExpiry = now().addingTimeInterval(ttlSeconds)
        scheduleProactiveRefresh(ttlSeconds: ttlSeconds)
    }

    private func retryUnpersisted() {
        guard let pending = unpersistedRefresh else { return }
        if (try? store.save(pending)) != nil {
            unpersistedRefresh = nil
        }
    }

    private func scheduleProactiveRefresh(ttlSeconds: Double) {
        guard autoRefresh, !retired else { return }
        scheduledRefresh?.cancel()
        let delay = Self.refreshDelay(ttlSeconds: ttlSeconds)
        scheduledRefresh = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard !Task.isCancelled else { return }
            // Transient failures self-reschedule (short backoff) so a network
            // blip never silently stops the refresh loop.
            do { try await self?.refreshIfNeeded(force: true) }
            catch let e as AuthSessionError {
                if case .transient = e { await self?.scheduleRetryAfterTransient() }
            } catch {}
        }
    }

    private func scheduleRetryAfterTransient() {
        guard autoRefresh, !isExpired, !retired else { return }
        scheduledRefresh?.cancel()
        scheduledRefresh = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 60 * 1_000_000_000)
            guard !Task.isCancelled else { return }
            do { try await self?.refreshIfNeeded(force: true) }
            catch let e as AuthSessionError {
                if case .transient = e { await self?.scheduleRetryAfterTransient() }
            } catch {}
        }
    }

    private func expireLocally(code: String) {
        guard !isExpired, !retired else { return }
        isExpired = true
        scheduledRefresh?.cancel(); scheduledRefresh = nil
        store.clear()
        refreshToken = nil
        unpersistedRefresh = nil
        accessToken = nil
        accessExpiry = .distantPast
        log.error("device session expired (\(code, privacy: .public))")
        onSessionExpired?(code)
    }

    // MARK: error classification (pure, testable)

    /// Refresh/daemon-mint failures: 401 with a terminal code kills the session;
    /// everything else is transient (credentials intact).
    static func classifyRefresh(_ error: Error) -> AuthSessionError {
        if let gw = error as? HttpGatewayClient.GatewayError {
            switch gw {
            case .http(let status, let code, _):
                if status == 401, terminalCodes.contains(code) {
                    return .sessionExpired(code: code)
                }
                return .transient(gw.description)
            default:
                return .transient(gw.description)
            }
        }
        return .transient(error.localizedDescription)
    }

    /// 400 codes from POST /v1/auth/device/token that are TERMINAL for the
    /// attempt (auth-spec §2.3): the backend consumes the one-time code even on
    /// failure — `invalid_code` covers absent/expired/already-used, and
    /// `pkce_mismatch` burns the code before failing the verify — so retrying
    /// the SAME code can never succeed.
    public static let terminalExchangeCodes: Set<String> = [
        "invalid_code", "pkce_mismatch",
    ]

    /// Exchange failures are never "session expired" (there is no session yet).
    /// A terminal code rejection (`terminalExchangeCodes`) maps to
    /// `.codeRejected` so the UI can say "start again" instead of implying a
    /// retry might work; everything else stays transient with the gateway's
    /// message.
    static func classifyExchange(_ error: Error) -> AuthSessionError {
        if let gw = error as? HttpGatewayClient.GatewayError {
            if case .http(let status, let code, _) = gw,
               status == 400, terminalExchangeCodes.contains(code) {
                return .codeRejected(code: code)
            }
            return .transient(gw.description)
        }
        return .transient(error.localizedDescription)
    }
}

// MARK: - Keychain account for the device refresh token

extension Keychain {
    /// Account label for the device session's opaque refresh token (auth-spec C2).
    public static let deviceRefreshTokenAccount = "device-refresh-token"
}
