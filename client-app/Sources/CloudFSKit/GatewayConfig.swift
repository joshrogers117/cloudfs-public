// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - GatewayConfig & the Http-vs-Mock switch
//
// One place that decides whether the app talks to the real gateway or the mock,
// and carries the connection settings (base URL + org + token). The token comes
// from the Keychain; the non-secret URL/org persist in UserDefaults.
//
// Selection precedence (first that resolves wins):
//   1. Env var  CLOUDFS_GATEWAY_URL  (+ CLOUDFS_GATEWAY_TOKEN / CLOUDFS_ORG) → Http
//   2. Persisted setting  "useHttpGateway == true" with a stored URL+token   → Http
//   3. otherwise                                                              → Mock
//
// This keeps MockGatewayClient the DEFAULT so the app still builds/runs offline.

public struct GatewayConfig: Sendable, Hashable, Codable {
    public var baseURL: String   // e.g. https://gw.cloudfs.example or http://127.0.0.1:8787
    public var org: String       // tenant id used for /v1/orgs/:org/* routes
    public var token: String     // service-account JWS bearer token

    public init(baseURL: String, org: String, token: String) {
        self.baseURL = baseURL; self.org = org; self.token = token
    }

    public var isUsable: Bool {
        !baseURL.trimmingCharacters(in: .whitespaces).isEmpty
            && !token.trimmingCharacters(in: .whitespaces).isEmpty
            && URL(string: baseURL) != nil
    }
}

// MARK: - Persistence

/// Persists the non-secret gateway settings (URL, org, the "use http?" flag) in
/// UserDefaults, and the token in the Keychain. Pure logic — no UI.
public struct GatewaySettingsStore {
    private let defaults: UserDefaults
    private let tokenAccount: String
    private let refreshAccount: String
    /// A separate credential namespace keeps isolated test stores from changing
    /// another store's Keychain items. Production uses the stable default names.
    public init(defaults: UserDefaults = .standard, credentialNamespace: String? = nil) {
        self.defaults = defaults
        tokenAccount = credentialNamespace.map { "\($0).service-account-token" } ?? Keychain.tokenAccount
        refreshAccount = credentialNamespace.map { "\($0).device-refresh-token" } ?? Keychain.deviceRefreshTokenAccount
    }

    private enum K {
        static let useHttp = "cloudfs.useHttpGateway"
        static let baseURL = "cloudfs.gatewayBaseURL"
        static let org     = "cloudfs.gatewayOrg"
        static let authMethod = "cloudfs.authMethod"
        static let onboardingCompleted = "cloudfs.onboarding.completedOnDevice"
        static let orgDisplayName = "cloudfs.orgDisplayName"
        static let webBaseUrl = "cloudfs.webBaseUrl"
        static let productName = "cloudfs.productName"
        static let disconnectedFilespaces = "cloudfs.disconnectedFilespaces"
    }

    /// ONBOARDING.md step 4: the first-run checklist sheet is shown after the
    /// first successful sign-in on a device, then skipped on later sign-ins
    /// (unless something on it is unhealthy). Deliberately per-DEVICE, not
    /// per-credential — sign-out/sign-in on the same Mac shouldn't re-show it,
    /// so this flag is untouched by `clear()`/`clearCredentialsKeepingServer()`.
    public var onboardingCompletedOnDevice: Bool {
        get { defaults.bool(forKey: K.onboardingCompleted) }
        nonmutating set { defaults.set(newValue, forKey: K.onboardingCompleted) }
    }

    /// The deployment's configured product name (public auth config), used for
    /// window-title fallbacks. Server-scoped: survives sign-out, cleared by `clear()`.
    public var productName: String? {
        get { defaults.string(forKey: K.productName) }
        nonmutating set {
            if let v = newValue?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty { defaults.set(v, forKey: K.productName) }
            else { defaults.removeObject(forKey: K.productName) }
        }
    }

    /// Window-title fallback: the configured product name, else "CloudFS".
    public var displayProductName: String { productName ?? "CloudFS" }

    /// Filespaces the user deliberately disconnected on this Mac. Persisted so a
    /// relaunch does not silently remount them. NOT touched by `clear()` /
    /// `clearCredentialsKeepingServer()` so a session that merely expires keeps it; only an
    /// explicit sign-out empties it (`AppModel.signOut` assigns `intentionallyDisconnected = []`).
    /// Pruned when the user connects the space successfully; a failed Connect may leave the id
    /// in the set (it simply stays "deliberately disconnected" until a Connect succeeds).
    public var disconnectedFilespaces: Set<String> {
        get { Set(defaults.stringArray(forKey: K.disconnectedFilespaces) ?? []) }
        nonmutating set {
            if newValue.isEmpty { defaults.removeObject(forKey: K.disconnectedFilespaces) }
            else { defaults.set(newValue.sorted(), forKey: K.disconnectedFilespaces) }
        }
    }

    /// How the stored session authenticates (auth-spec decision E): the default
    /// browser-handoff DEVICE session vs the Advanced LEGACY service-token paste.
    public enum AuthMethod: String, Sendable {
        case device    // refresh token in Keychain; access JWS minted per refresh
        case legacy    // fixed service-account token in Keychain
    }

    public var useHttp: Bool {
        get { defaults.bool(forKey: K.useHttp) }
        nonmutating set { defaults.set(newValue, forKey: K.useHttp) }
    }
    public var baseURL: String {
        get { defaults.string(forKey: K.baseURL) ?? "" }
        nonmutating set { defaults.set(newValue, forKey: K.baseURL) }
    }
    public var org: String {
        get { defaults.string(forKey: K.org) ?? "" }
        nonmutating set { defaults.set(newValue, forKey: K.org) }
    }
    public var authMethod: AuthMethod? {
        get { defaults.string(forKey: K.authMethod).flatMap(AuthMethod.init(rawValue:)) }
        nonmutating set {
            if let newValue { defaults.set(newValue.rawValue, forKey: K.authMethod) }
            else { defaults.removeObject(forKey: K.authMethod) }
        }
    }

    /// The org's human display name (distinct from `org`, the raw org id used in
    /// routes) — learned from the device-token exchange's `orgName` and rendered
    /// nowhere unless persisted here. Sidebar-workspace-header plumbing: set on a
    /// fresh exchange, read back on `resumeDeviceSession()` (which has no fresh
    /// exchange to read it from), cleared on sign-out.
    public var orgDisplayName: String? {
        get { defaults.string(forKey: K.orgDisplayName) }
        nonmutating set {
            if let newValue, !newValue.isEmpty { defaults.set(newValue, forKey: K.orgDisplayName) }
            else { defaults.removeObject(forKey: K.orgDisplayName) }
        }
    }

    /// The web console's base URL — learned from `GET /v1/auth/config/public`
    /// (`PublicAuthConfig.webBaseUrl`) during sign-in and otherwise dropped.
    /// Persisted so the sidebar's workspace-overflow menu can deep-link into the
    /// web console (create filespace / manage members / devices) after a relaunch,
    /// not just mid-sign-in. Callers fall back to the gateway server base URL
    /// when this is absent (same-origin deployments never set it).
    public var webBaseUrl: String? {
        get { defaults.string(forKey: K.webBaseUrl) }
        nonmutating set {
            if let newValue, !newValue.isEmpty { defaults.set(newValue, forKey: K.webBaseUrl) }
            else { defaults.removeObject(forKey: K.webBaseUrl) }
        }
    }

    /// Save URL+org to UserDefaults and the token to the Keychain, and flip the
    /// "use http" flag on. Throws only if the Keychain write fails. This is the
    /// LEGACY (Advanced service-account token) path.
    public func save(_ config: GatewayConfig) throws {
        baseURL = config.baseURL
        org = config.org
        try Keychain.set(config.token, account: tokenAccount)
        useHttp = true
        authMethod = .legacy
    }

    /// Persist a DEVICE session's non-secret half (URL + org learned from the
    /// token exchange). The refresh token is stored separately by
    /// AuthSessionManager (Keychain account "device-refresh-token").
    public func saveDeviceSession(baseURL url: String, org orgId: String) {
        baseURL = url
        org = orgId
        useHttp = true
        authMethod = .device
    }

    /// Clear the persisted settings + every stored credential (legacy token,
    /// device refresh token, daemon-token expiry) and revert to the mock.
    public func clear() {
        Keychain.delete(account: tokenAccount)
        Keychain.delete(account: refreshAccount)
        useHttp = false
        defaults.removeObject(forKey: K.baseURL)
        defaults.removeObject(forKey: K.org)
        defaults.removeObject(forKey: K.authMethod)
        defaults.removeObject(forKey: K.orgDisplayName)
        defaults.removeObject(forKey: K.webBaseUrl)
        defaults.removeObject(forKey: K.productName)
        DaemonCredential.storeExpiry(nil, defaults: defaults)
    }

    /// Sign-out / session-expiry variant: drop every credential but KEEP the
    /// server address (and org) so the next sign-in screen comes prefilled
    /// (auth-spec §1.5 — "returns to sign-in with the server URL preserved").
    public func clearCredentialsKeepingServer() {
        Keychain.delete(account: tokenAccount)
        Keychain.delete(account: refreshAccount)
        useHttp = false
        defaults.removeObject(forKey: K.authMethod)
        // The org DISPLAY name is account-derived (unlike `baseURL`/`org`/
        // `webBaseUrl`, which are server-scoped and deliberately kept so the next
        // sign-in screen comes prefilled) — drop it so a stale name never lingers
        // on a signed-out sidebar/login screen. It's re-learned on the next
        // device-token exchange.
        defaults.removeObject(forKey: K.orgDisplayName)
        DaemonCredential.storeExpiry(nil, defaults: defaults)
    }

    /// Reconstruct the persisted LEGACY config. The token comes from the
    /// Keychain, falling back to the token.txt that DaemonProvisioning writes for
    /// the launch agent — the daemon already holds the token there, so the
    /// fallback adds no new exposure and keeps sign-in restore working even when
    /// keychain reads misbehave. DEVICE sessions return nil here: they are
    /// resumed by AuthSessionManager (and token.txt then holds the daemon's own
    /// scoped token, which must NOT become the app's credential).
    public func loadConfig() -> GatewayConfig? {
        guard useHttp, !baseURL.isEmpty else { return nil }
        guard authMethod != .device else { return nil }
        guard let token = Keychain.get(account: tokenAccount) ?? (tokenAccount == Keychain.tokenAccount ? provisionedFileToken() : nil), !token.isEmpty
        else { return nil }
        return GatewayConfig(baseURL: baseURL, org: org, token: token)
    }

    private func provisionedFileToken() -> String? {
        guard let root = DaemonProvisioning.containerRoot() else { return nil }
        let url = root.appendingPathComponent("token.txt")
        guard let raw = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return token.isEmpty ? nil : token
    }
}

// MARK: - The selector

public enum GatewayFactory {

    /// Read env-var overrides (used by CI / `swift run` smoke tests).
    public static func envConfig(_ env: [String: String] = ProcessInfo.processInfo.environment) -> GatewayConfig? {
        guard let url = env["CLOUDFS_GATEWAY_URL"], !url.isEmpty else { return nil }
        let token = env["CLOUDFS_GATEWAY_TOKEN"] ?? ""
        let org = env["CLOUDFS_ORG"] ?? ""
        let cfg = GatewayConfig(baseURL: url, org: org, token: token)
        return cfg.isUsable ? cfg : nil
    }

    /// THE ONE SWITCH. Returns the live Http client when an env override or a
    /// persisted+usable config exists; otherwise the offline Mock. Also reports
    /// which one was chosen so the UI can show a "connected to <url>" banner.
    public static func makeClient(
        store: GatewaySettingsStore = GatewaySettingsStore(),
        env: [String: String] = ProcessInfo.processInfo.environment
    ) -> (client: GatewayClient, mode: GatewayMode) {
        if let cfg = envConfig(env) {
            return (HttpGatewayClient(config: cfg), .http(cfg.baseURL))
        }
        if let cfg = store.loadConfig(), cfg.isUsable {
            return (HttpGatewayClient(config: cfg), .http(cfg.baseURL))
        }
        return (MockGatewayClient(), .mock)
    }
}

public enum GatewayMode: Sendable, Equatable {
    case mock
    case http(String)   // base URL

    public var isHttp: Bool { if case .http = self { return true }; return false }
    public var label: String {
        switch self {
        case .mock:           return "Offline (mock data)"
        case .http(let url):  return "Connected — \(url)"
        }
    }
}

// MARK: - Engine (cloudfsd) selection
//
// The local FS engine is chosen INDEPENDENTLY of the gateway: the gateway is the
// cloud metadata authority, cloudfsd is the local cache/streaming daemon. The
// daemon client is selected when a socket is configured (env override, or the
// default socket file exists on disk); otherwise the offline `NullEngineClient`
// is used so every engine op throws `.unavailable` and the GUI falls back to the
// mock/gateway. This keeps Mock the default with no daemon present.

public enum EngineFactory {

    /// macOS default control-socket path (CONTROL-API §1).
    public static var defaultSocketPath: String {
        let base = NSSearchPathForDirectoriesInDomains(.applicationSupportDirectory, .userDomainMask, true).first
            ?? (NSHomeDirectory() + "/Library/Application Support")
        return base + "/cloudfs/cloudfsd.sock"
    }

    /// The product's App Group id (shared host ↔ File Provider appex ↔ daemon).
    // Signed distributions use the macOS TeamID-prefixed group convention,
    // which permits Finder/daemon sharing without a provisioning profile.
    // Older Xcode development bundles retain their existing group container.
    public static var appGroupIdentifier: String {
        (Bundle.main.object(forInfoDictionaryKey: "CloudFSAppGroupIdentifier") as? String)
            ?? "group.dev.cloudfs.client"
    }

    /// The control socket the app provisions for the launch agent (M7): `d.sock`
    /// inside the rendezvous dir (the short name keeps the path well under the
    /// AF_UNIX `sun_path` limit).
    public static var provisionedSocketPath: String? {
        DaemonProvisioning.containerRoot()?.appendingPathComponent("d.sock").path
    }

    /// Resolve the socket path: `CLOUDFS_SOCKET` env override, else the default.
    public static func socketPath(_ env: [String: String] = ProcessInfo.processInfo.environment) -> String {
        if let p = env["CLOUDFS_SOCKET"], !p.isEmpty { return p }
        return defaultSocketPath
    }

    /// Pick the engine client. Returns the daemon client when a socket path is
    /// explicitly configured (env) or the default socket file exists on disk;
    /// otherwise `NullEngineClient`. Reports the resolved path for the UI.
    public static func makeEngine(
        env: [String: String] = ProcessInfo.processInfo.environment,
        fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    ) -> (engine: EngineClient, socketPath: String?) {
        // An explicit env override always selects the daemon client (it connects
        // lazily; an absent socket surfaces as `.unavailable` at first call).
        if let p = env["CLOUDFS_SOCKET"], !p.isEmpty {
            return (DaemonEngineClient(socketPath: p), p)
        }
        // M7 — the launch-agent daemon binds the provisioned socket (the canonical
        // app↔daemon rendezvous daemon.env points at). Prefer it whenever it is
        // live. (The former App Group socket — and the sandboxed-build branch that
        // selected it — is gone: macOS 15+ consent-gates the group container, and
        // the unsandboxed app + daemon now meet in the support dir instead.)
        if let ps = provisionedSocketPath, fileExists(ps) {
            return (DaemonEngineClient(socketPath: ps), ps)
        }
        let def = defaultSocketPath
        if fileExists(def) {
            return (DaemonEngineClient(socketPath: def), def)
        }
        return (NullEngineClient(), nil)
    }
}
