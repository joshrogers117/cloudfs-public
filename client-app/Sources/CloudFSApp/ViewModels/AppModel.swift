// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import Observation
import os
import CloudFSKit

// MARK: - AppModel
//
// The single observable app state, shared by the menu-bar extra and the main
// window. It owns the GatewayClient (the seam) and translates async calls into
// @Observable state the SwiftUI views render. Injected with MockGatewayClient
// today; swap to the real composite client and the views are unchanged.

@MainActor
@Observable
final class AppModel {

    // The seam. `var` so the user can switch between Http and Mock at runtime
    // (e.g. paste a service token in the connection-settings surface).
    private(set) var gateway: GatewayClient

    // The LOCAL engine seam (cloudfsd over UDS). NullEngineClient when no daemon
    // socket is present, so engine ops fall back to the gateway/mock.
    private(set) var engine: EngineClient
    private(set) var engineSocketPath: String?

    /// True when a cloudfsd socket was selected (env override or default socket
    /// file present). Drives the UI banner + whether engine ops are attempted.
    var isEngineConnected: Bool { isHttpMode && engine.isAvailable }

    // Which backend we're talking to (mock vs http://…), for the UI banner.
    private(set) var mode: GatewayMode

    // Persisted, non-secret gateway settings (token lives in the Keychain).
    let settings = GatewaySettingsStore()

    // Session
    var isSignedIn = false
    // Keep the scene opener outside command observation so menu actions can
    // restore a closed dashboard without changing the main menu's dependencies.
    @ObservationIgnored var showMainWindow: (() -> Void)?
    var operationError: String?
    var isSigningOut = false
    var isQuitting = false
    let mountOperations = MountOperationGate()
    /// Persisted (GatewaySettingsStore) so a relaunch honours a deliberate disconnect.
    var intentionallyDisconnected: Set<String> = GatewaySettingsStore().disconnectedFilespaces {
        didSet { if intentionallyDisconnected != oldValue { settings.disconnectedFilespaces = intentionallyDisconnected } }
    }
    var pausedFilespaces: Set<String> = []
    var pendingNavigationLink: DeepLink.Parsed?
    var navigationRequestID = UUID()
    var signInError: String?
    var isConnecting = false

    // MARK: `cloudfs://connect` deep link (ONBOARDING.md build step 3)
    //
    // Parsing + the signed-in/out decision live in CloudFSKit's `ConnectLink`
    // (pure, unit-tested); this is just the UI hook LoginView/RootView observe.

    /// Set while signed OUT: the login form prefills + focuses its server field
    /// from this, then clears it (see `LoginView.onChange(of: model.connectServerPrefill)`).
    var connectServerPrefill: String?
    /// Set when a connect link named a DIFFERENT server than the one we're
    /// signed into. RootView presents this as an `.alert(item:)` — never a
    /// silent switch/sign-out (destructive-adjacent; the user decides).
    var connectDifferentServerNotice: ConnectDifferentServerNotice?

    struct ConnectDifferentServerNotice: Equatable, Identifiable {
        let id = UUID()
        let currentHost: String
        let requestedHost: String
    }

    // MARK: Browser-handoff device auth state (auth-spec §1.2 / C5)

    /// The login card's sub-state machine for the default (browser) path.
    enum AuthFlow: Equatable {
        case idle               // server-address form
        case probing            // GET /v1/auth/config/public in flight
        case waitingForBrowser  // browser open; awaiting callback or pasted code
        case exchanging         // POST /v1/auth/device/token in flight
    }
    var authFlow: AuthFlow = .idle
    /// 10-minute client-side wait timeout flipped (spec §1.2 step 3 guard).
    var browserWaitTimedOut = false
    /// Non-nil ⇒ the device session died (revoked/expired). Drives the
    /// "Session expired — sign in again" banner; never a raw gateway error.
    var sessionExpiredNotice: String?
    /// Open the login form's Advanced disclosure on next show (legacy-token
    /// expiry path, spec §1.5 row 5).
    var advancedPreExpanded = false
    /// Signed-in identity learned from the device-token exchange (display only).
    private(set) var accountEmail: String?
    private(set) var orgName: String?

    private(set) var pendingDeviceAuth: DeviceAuth.PendingRequest?
    private(set) var authSession: AuthSessionManager?
    private var browserWaitTimer: Task<Void, Never>?
    private var deviceResumeRetry: Task<Void, Never>?
    /// Mints + renews the daemon's 30-day token from the device session (C6).
    let daemonCredentials = DaemonCredentialManager()

    /// Client-side wait bound before offering "Try again" (spec: 10 minutes).
    static let browserWaitTimeout: TimeInterval = 600

    // Filespaces
    var isCreatingFilespace = false
    var filespaces: [Filespace] = []
    var selectedFilespaceID: String?

    var selectedFilespace: Filespace? {
        filespaces.first { $0.id == selectedFilespaceID }
    }

    // Navigation in the main window. Default landing section is Dashboard — the
    // per-filespace overview (hero status + info cards); Filespaces remains the
    // multi-filespace manager, reachable from the nav/sidebar switcher.
    var section: NavSection = .dashboard

    // Command "intent" signal observed by section views. Bumping the token triggers
    // a reload on the next render — this lets scene-level menu Commands drive
    // view-local refreshes cleanly.
    private(set) var refreshToken = 0

    // Per-filespace caches of loaded data (kept simple for the stub)
    var recentActivity: [ActivityEvent] = []
    var transfers: [Transfer] = []
    var snapshots: [Snapshot] = []
    var shareLinks: [CloudShareLink] = []
    var cache: CacheSettings?

    // Per-feature state holders (WS2/WS3/WS4). Each is a nested @Observable model
    // defined in its OWN extension file so the three feature agents never edit the
    // same Swift file:
    //   • pinned   → AppModel+Pinned.swift     (WS2 — Pinned Items)
    //   • liveLog  → AppModel+Activity.swift    (WS3 — Live feed + Audit log split)
    //   • snaps    → AppModel+Snapshots.swift   (WS4 — deep browse / multi-restore / create)
    // AppModel itself is FROZEN after WS1 scaffolding; feature agents add state +
    // methods inside their nested model class, not here.
    let pinned = PinnedFeatureModel()
    let liveLog = ActivityFeatureModel()
    let snaps = SnapshotsFeatureModel()
    //   • members  → AppModel+Members.swift    (Members & Access — org users + ACL)
    let members = MembersFeatureModel()
    //   • onboarding → AppModel+Onboarding.swift (ONBOARDING.md step 4 — first-run checklist)
    let onboarding = OnboardingFeatureModel()
    //   • dashboard → AppModel+Dashboard.swift (per-filespace overview landing section)
    let dashboard = DashboardFeatureModel()
    let recovery = RecoveryFeatureModel()
    let sharing = SharingFeatureModel()

    // Async-content state machines (drive EMPTY / LOADING / ERROR presentation).
    // The arrays above stay populated for derived summaries; these add the state.
    var activityState: LoadState<[ActivityEvent]> = .idle
    var transfersState: LoadState<[Transfer]> = .idle
    var snapshotsState: LoadState<[Snapshot]> = .idle
    var shareLinksState: LoadState<[CloudShareLink]> = .idle
    var cacheState: LoadState<CacheSettings> = .idle

    private var liveTransferTask: Task<Void, Never>?

    /// Default init: the factory picks Http (env override or persisted+usable
    /// config) or falls back to Mock; the engine factory picks the cloudfsd daemon
    /// client when a socket is configured/present, else the Null engine.
    init() {
        if ProcessInfo.processInfo.environment["CLOUDFS_DEMO"] == "1" {
            self.gateway = MockGatewayClient(role: OrgRole(rawValue: ProcessInfo.processInfo.environment["CLOUDFS_DEMO_ROLE"] ?? "admin") ?? .standard)
            self.mode = .mock
            self.engine = NullEngineClient()
            self.engineSocketPath = nil
            return
        }
        let (client, mode) = GatewayFactory.makeClient()
        self.gateway = client
        self.mode = mode
        let (engine, socket) = EngineFactory.makeEngine()
        self.engine = engine
        self.engineSocketPath = socket
    }

    init(gateway: GatewayClient, mode: GatewayMode = .mock, engine: EngineClient = NullEngineClient()) {
        self.gateway = gateway
        self.mode = mode
        self.engine = engine
        self.engineSocketPath = (engine is NullEngineClient) ? nil : "(injected)"
    }

    var isHttpMode: Bool { mode.isHttp }

    /// The workspace's display name for the sidebar header: the org's human
    /// name when known, else the raw org id (`settings.org`) so something
    /// sensible still shows before the display name has ever been learned.
    var workspaceDisplayName: String {
        if let orgName, !orgName.isEmpty { return orgName }
        if !isHttpMode { return "Studio workspace" }
        return settings.org.isEmpty ? "CloudFS" : settings.org
    }

    /// Typed web-console deep links (create filespace / members / devices),
    /// resolved from the persisted `webBaseUrl` with a same-origin fallback to
    /// the gateway server itself. See `ConsoleLinks`.
    var consoleLinks: ConsoleLinks {
        ConsoleLinks(webBaseUrl: settings.webBaseUrl, serverBaseURL: settings.baseURL)
    }

    // MARK: Session

    func signIn(_ credentials: Credentials) async {
        navigationRequestID = UUID() // invalidate navigation from an earlier account session
        isConnecting = true
        signInError = nil
        defer { isConnecting = false }
        do {
            let spaces = try await gateway.connect(credentials)
            filespaces = spaces
            await applyEngineMountState()     // reflect what the local daemon ACTUALLY has mounted
            selectedFilespaceID = spaces.first?.id
            isSignedIn = true
            presentOnboardingChecklistIfNeeded()   // ONBOARDING.md §4 — first-run only, unless unhealthy
            await loadCurrentUserRole()      // resolve org role for the Members gate
            await refreshForSelection()
            await resumePendingNavigationLink()
        } catch {
            signInError = error.localizedDescription
        }
    }

    /// Persist a real gateway config (URL + token → Keychain), switch the live
    /// client to Http, and connect. Falls back to leaving the error visible.
    func connectToGateway(baseURL: String, org: String, token: String) async {
        let config = GatewayConfig(baseURL: baseURL.trimmingCharacters(in: .whitespacesAndNewlines),
                                   org: org.trimmingCharacters(in: .whitespacesAndNewlines),
                                   token: token.trimmingCharacters(in: .whitespacesAndNewlines))
        guard config.isUsable else {
            signInError = "Enter a valid gateway URL and token."
            return
        }
        do {
            try settings.save(config)        // token → Keychain, URL/org → UserDefaults
        } catch {
            signInError = "Could not save token to Keychain: \(error.localizedDescription)"
            return
        }
        gateway = HttpGatewayClient(config: config)
        mode = .http(config.baseURL)
        // M7: provision + start the embedded daemon (launch agent) BEFORE sign-in,
        // then re-resolve the engine client once its socket appears.
        DaemonLifecycle.shared.provisionAndStart(gatewayURL: config.baseURL, token: token)
        await refreshEngineWhenSocketAppears()
        await signIn(.serviceToken(token: token))
        if !isSignedIn {
            // Connect failed (bad URL/token/server) — revert to mock so the app
            // stays usable offline, but keep the error visible.
            settings.clear()
            let (client, m) = GatewayFactory.makeClient()
            gateway = client
            mode = m
        }
    }

    /// Drop back to the offline mock (and forget any stored gateway/token).
    /// Synchronously resets session state so a caller can immediately sign in.
    func useMockGateway() {
        liveTransferTask?.cancel()
        gateway = MockGatewayClient()
        mode = .mock
        isSignedIn = false
        filespaces = []; selectedFilespaceID = nil
        recentActivity = []; transfers = []; snapshots = []; shareLinks = []; cache = nil
        resetLoadStates()
        signInError = nil
    }

    func signOut() async {
        navigationRequestID = UUID()
        pendingNavigationLink = nil
        // Leaving a demo must not erase a remembered real account or stop its engine.
        if !isHttpMode {
            try? await gateway.signOut()
            liveTransferTask?.cancel()
            isSignedIn = false
            filespaces = []; selectedFilespaceID = nil
            recentActivity = []; transfers = []; snapshots = []; shareLinks = []; cache = nil
            members.currentRole = .standard
            resetLoadStates()
            return
        }
        guard !isSigningOut else { return }
        isSigningOut = true
        defer { mountOperations.reopen(); isSigningOut = false }
        operationError = nil
        // A mount publishes its volume only on completion. Drain all admissions
        // before listing, so credentials cannot disappear under a late mount.
        await mountOperations.closeAndDrain()
        // Keep credentials until every local write is durable and every mount
        // has closed. A failed flush must never become a successful sign-out.
        if isHttpMode, engine.isAvailable {
            do {
                try await FilespaceShutdown.drain(engine)
            } catch {
                operationError = "Could not sign out safely. Your account is still signed in so pending changes can finish uploading. \(error.localizedDescription)"
                noteEngineError(error)
                await applyEngineMountState(autoMount: false)
                return
            }
        }
        do { try await gateway.signOut() }
        catch { operationError = error.localizedDescription; return }
        liveTransferTask?.cancel()
        intentionallyDisconnected = []
        pausedFilespaces = []
        await FileProviderDomains.shared.removeAll()   // clear FP-era domains from the Finder sidebar
        // C8: sign-out clears every stored credential — the device refresh token
        // (Keychain), the legacy token (Keychain), and the daemon's token.txt —
        // but KEEPS the server URL so the next sign-in comes prefilled.
        // (App-initiated server-side revocation is deliberately out of scope
        // tonight; the device stays revocable from the web console.)
        daemonCredentials.stop()
        if let session = authSession { await session.signOutLocal() }
        authSession = nil
        settings.clearCredentialsKeepingServer()
        if let root = DaemonProvisioning.containerRoot() {
            try? FileManager.default.removeItem(at: root.appendingPathComponent("token.txt"))
        }
        sessionExpiredNotice = nil
        advancedPreExpanded = false
        accountEmail = nil; orgName = nil
        authFlow = .idle
        isSignedIn = false
        filespaces = []
        selectedFilespaceID = nil
        recentActivity = []; transfers = []; snapshots = []; shareLinks = []; cache = nil
        members.currentRole = .standard   // close the Members gate until next sign-in
        resetLoadStates()
        // Revert the live client to the factory default (mock now that no
        // credentials remain) so the login screen's Demo path stays usable.
        let (client, m) = GatewayFactory.makeClient()
        gateway = client
        mode = m
    }

    private func resetLoadStates() {
        activityState = .idle; transfersState = .idle
        snapshotsState = .idle; cacheState = .idle
        shareLinksState = .idle
        recovery.reset(for: nil)
        sharing.error = nil; sharing.copiedRoot = false
    }

    /// Quit disconnects Finder volumes safely but keeps the remembered account.
    /// Closing only the window continues to run the app and its mounted volumes.
    func prepareToQuit() async -> Bool {
        guard !isSigningOut else { return false }
        guard isHttpMode, engine.isAvailable else { return true }
        isSigningOut = true
        isQuitting = true
        operationError = nil
        await mountOperations.closeAndDrain()
        do {
            try await FilespaceShutdown.drain(engine)
            daemonCredentials.stop()
            return true
        } catch {
            mountOperations.reopen()
            isSigningOut = false
            isQuitting = false
            operationError = "Could not quit safely. CloudFS is still running so your pending changes remain available. \(error.localizedDescription)"
            noteEngineError(error)
            await applyEngineMountState(autoMount: false)
            showMainWindow?()
            NSApp.activate(ignoringOtherApps: true)
            return false
        }
    }

    /// Reconcile + overlay the daemon's REAL mount state (M3 — the NFS-loopback era):
    /// 1. MOUNT every signed-in filespace the daemon doesn't already serve — the
    ///    daemon spins up its in-process NFS server and the volume appears in
    ///    Finder's sidebar under the FILESPACE NAME (the v3-parity behavior).
    /// 2. Overlay the daemon's authoritative state onto the gateway registry so a
    ///    card shows Connected + its real mount path only when actually mounted.
    /// Http mode only — the offline mock keeps its fixture connection states.
    func applyEngineMountState(autoMount: Bool = true) async {
        guard case .http = mode else { return }
        let mountGeneration = mountOperations.generation
        var mounted = (try? await engine.filespaceList()) ?? []   // Null engine / no daemon ⇒ []
        for record in mounted {
            if let paused = record.paused {
                if paused { pausedFilespaces.insert(record.id) }
                else { pausedFilespaces.remove(record.id) }
            }
        }
        if engine.isAvailable, autoMount, !isSigningOut {
            let alreadyMounted = Set(mounted.filter { !($0.mountPath ?? "").isEmpty }
                                            .map(\.id))
            var didMount = false
            for fs in filespaces where !alreadyMounted.contains(fs.id) && !intentionallyDisconnected.contains(fs.id) && !pausedFilespaces.contains(fs.id) {
                // Default mount point (daemon: ~/cloudfs/<id>); the sidebar entry
                // comes from the NAME, so the path stays an implementation detail.
                guard !isSigningOut, mountOperations.acceptsMounts,
                      mountOperations.generation == mountGeneration else { break }
                do {
                    _ = try await mountOperations.perform(generation: mountGeneration) {
                        do {
                            return try await engine.mount(filespace: fs.id, at: nil, name: fs.name)
                        } catch let error as EngineError where error.needsCredentialRefresh {
                            // A daemon token can be revoked independently of the
                            // browser session. Renew and retry once, before the
                            // UI settles into an apparently connected account.
                            guard await daemonCredentials.daemonReportedAuthFailure() else { throw error }
                            return try await engine.mount(filespace: fs.id, at: nil, name: fs.name)
                        }
                    }
                    didMount = true
                } catch {
                    if !isSigningOut {
                        operationError = "Could not connect \(fs.name). \(error.localizedDescription)"
                    }
                }
            }
            if didMount { mounted = (try? await engine.filespaceList()) ?? mounted }
        }
        let byId = Dictionary(mounted.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        filespaces = filespaces.map { fs in
            var f = fs
            if let rec = byId[fs.id], let mp = rec.mountPath, !mp.isEmpty {
                f.connection = pausedFilespaces.contains(fs.id) ? .paused : .connected
                f.mountPath = mp
            } else {
                f.connection = .disconnected
                f.mountPath = ""        // not mounted on this machine
            }
            return f
        }
        // FP-shelved (mount-architecture decision): domains register only behind the
        // research flag; default builds RETIRE any domains an FP-era build left so
        // the CloudStorage namespace disappears for upgraded users.
        await FileProviderDomains.shared.sync(filespaces: filespaces)
    }

    /// First-launch bootstrap. A persisted DEVICE session resumes silently
    /// (refresh-token rotation, then connect). In Mock mode we auto-populate so
    /// the app runs offline with no login. In Http (legacy-token) mode we
    /// attempt a real connect (the token is already in the Keychain); on
    /// failure we fall through to the login UI.
    func bootstrap() async {
        if ProcessInfo.processInfo.environment["CLOUDFS_DEMO"] != "1", settings.authMethod == .device, settings.useHttp, !settings.baseURL.isEmpty {
            await resumeDeviceSession()
            return
        }
        switch mode {
        case .mock:
            // Fresh installs start at sign-in. Demo requires an explicit choice.
            guard ProcessInfo.processInfo.environment["CLOUDFS_DEMO"] == "1" else { return }
            do {
                filespaces = try await gateway.filespaces()
                selectedFilespaceID = filespaces.first?.id
                isSignedIn = true
                await loadCurrentUserRole()      // resolve org role for the Members gate
                await refreshForSelection()
            } catch { /* mock never throws */ }
        case .http:
            // M7: a relaunch with persisted credentials must ALSO bring the daemon
            // up (provision + agent) — not just the fresh connect path.
            if let config = settings.loadConfig(), config.isUsable {
                DaemonLifecycle.shared.provisionAndStart(gatewayURL: config.baseURL, token: config.token)
                await refreshEngineWhenSocketAppears()
            }
            await signIn(.serviceToken(token: settings.loadConfig()?.token ?? ""))
        }
    }

    // MARK: Selection + refresh

    func select(_ filespaceID: String) {
        section = .dashboard
        guard filespaceID != selectedFilespaceID else { return }
        liveTransferTask?.cancel()
        dashboard.pendingUploadBytes = nil
        dashboard.inSync = nil
        recovery.reset(for: filespaceID)
        sharing.error = nil; sharing.copiedRoot = false
        snaps.resetBrowse(for: nil)
        selectedFilespaceID = filespaceID
        Task { await refreshForSelection() }
    }

    func refreshForSelection() async {
        guard let id = selectedFilespaceID else { return }
        // Mark sub-feeds loading (so panes show a spinner, not stale content).
        activityState = .loading
        snapshotsState = .loading
        transfersState = .loading
        cacheState = .loading
        shareLinksState = .loading

        let mayReadActivity = canReadWorkspaceActivity
        let mayManageLinks = canManageGuestLinks
        async let activity = loadResult { mayReadActivity ? try await self.gateway.recentActivity(in: id, limit: 25) : [] }
        async let snaps = loadResult { try await self.gateway.snapshots(in: id) }
        async let lks = loadResult { mayManageLinks ? try await self.gateway.shareLinks(in: id) : [] }

        let activityRes = await activity
        let snapsRes = await snaps
        let loadedLinks = await lks
        guard selectedFilespaceID == id, isSignedIn else { return }
        recentActivity = canReadWorkspaceActivity ? (activityRes.value ?? []) : []
        activityState = canReadWorkspaceActivity ? activityRes : .loaded([])
        snapshots = snapsRes.value ?? []
        snapshotsState = snapsRes
        shareLinks = canManageGuestLinks ? (loadedLinks.value ?? []) : []
        shareLinksState = canManageGuestLinks ? loadedLinks : .loaded([])

        // Cache + transfers come from the engine when a daemon is present, else
        // the gateway/mock.
        let cacheVal = await loadCache(id)
        guard selectedFilespaceID == id, isSignedIn else { return }
        cache = cacheVal
        cacheState = cacheVal.map { .loaded($0) } ?? .failed("Cache unavailable.")

        let xfers = await loadTransfers(id)
        guard selectedFilespaceID == id, isSignedIn else { return }
        transfers = xfers.value ?? []
        transfersState = xfers
        startLiveTransfers(for: id)
        await loadRecoveryItems()
    }

    /// Run an async fetch and fold the result into a `LoadState` (loaded/failed).
    private func loadResult<T: Sendable>(_ op: () async throws -> T) async -> LoadState<T> {
        do { return .loaded(try await op()) }
        catch { return .failed(error.localizedDescription) }
    }

    /// Cache from cloudfsd `cache.info` when available, mapped to the GUI
    /// `CacheSettings`; otherwise the gateway/mock.
    private func loadCache(_ id: String) async -> CacheSettings? {
        if isEngineConnected, let info = try? await engine.cacheInfo(filespace: id) {
            return info.toSettings()
        }
        return try? await gateway.cacheSettings(for: id)
    }

    private func loadTransfers(_ id: String) async -> LoadState<[Transfer]> {
        await loadResult {
            if self.isEngineConnected { return try await self.engine.currentTransfers(filespace: id) }
            return try await self.gateway.currentTransfers(in: id)
        }
    }

    // MARK: Live transfer feed

    private func startLiveTransfers(for id: String) {
        liveTransferTask?.cancel()
        // Prefer the engine's event-stream-fed updates; fall back to the gateway.
        if isEngineConnected {
            liveTransferTask = Task { [engine] in
                for await snapshot in engine.transferUpdates(filespace: id) {
                    if Task.isCancelled { break }
                    await MainActor.run {
                        guard self.selectedFilespaceID == id, self.isSignedIn, !Task.isCancelled else { return }
                        self.transfers = snapshot; self.transfersState = .loaded(snapshot)
                    }
                }
            }
        } else {
            liveTransferTask = Task { [gateway] in
                for await snapshot in gateway.transferUpdates(in: id) {
                    if Task.isCancelled { break }
                    await MainActor.run {
                        guard self.selectedFilespaceID == id, self.isSignedIn, !Task.isCancelled else { return }
                        self.transfers = snapshot; self.transfersState = .loaded(snapshot)
                    }
                }
            }
        }
    }

    // MARK: Sync control

    func togglePauseSync() async {
        guard let fs = selectedFilespace else { return }
        let pausing = fs.connection != .paused
        operationError = nil
        do {
            if isHttpMode {
                guard isEngineConnected, !fs.mountPath.isEmpty else {
                    operationError = "Connect this filespace before pausing transfers."
                    return
                }
                try await engine.setConnectionState(!pausing, filespace: fs.id)
                if pausing { try await engine.pauseTransfers(filespace: fs.id) }
                else { try await engine.resumeTransfers(filespace: fs.id) }
            } else {
                try await gateway.setConnectionState(pausing ? .paused : .connected, for: fs.id)
            }
            if pausing { pausedFilespaces.insert(fs.id) }
            else { pausedFilespaces.remove(fs.id) }
            await reloadFilespaces()
        } catch {
            operationError = "Could not \(pausing ? "pause" : "resume") transfers. \(error.localizedDescription)"
            noteEngineError(error)
        }
    }

    func reloadFilespaces(reportErrors: Bool = true) async {
        let session = navigationRequestID
        guard isSignedIn, !isSigningOut else { return }
        do {
            let available = try await gateway.filespaces()
            guard isSignedIn, !isSigningOut, navigationRequestID == session else { return }
            filespaces = available
            await applyEngineMountState(autoMount: false)
        } catch {
            guard isSignedIn, !isSigningOut, navigationRequestID == session else { return }
            if reportErrors { operationError = error.localizedDescription }
        }
    }

    /// M7 — after the launch agent is (re)started, wait briefly for its control
    /// socket and re-resolve the engine client so this session talks to it without
    /// an app relaunch. Bounded: a missing daemon (dev bundle, approval pending)
    /// degrades to the Null engine exactly as before.
    func refreshEngineWhenSocketAppears(timeout: TimeInterval = 5.0) async {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let (resolved, path) = EngineFactory.makeEngine()
            // A leftover socket file can belong to an exited engine. Confirm a
            // control RPC before selecting it while launchd starts its replacement.
            if !(resolved is NullEngineClient), (try? await resolved.filespaceList()) != nil {
                engine = resolved
                engineSocketPath = path
                return
            }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
    }

    // MARK: Derived menu-bar summaries

    var activeUploadCount: Int {
        transfers.filter { $0.kind == .upload && ($0.state == .active || $0.state == .queued) }.count
    }
    var activeDownloadCount: Int {
        transfers.filter { $0.kind == .download && ($0.state == .active || $0.state == .queued) }.count
    }
    var aggregateThroughput: Int64 {
        transfers.filter { $0.state == .active }.reduce(0) { $0 + $1.throughputBytesPerSec }
    }

    // MARK: Cache mutations

    /// Apply a new cache config. When a daemon is present, route size + location
    /// changes through cloudfsd (`cache.setSize`/`cache.setLocation`) and reflect
    /// the authoritative `CacheInfo` it returns; else fall back to the gateway.
    func updateCache(_ newValue: CacheSettings) async {
        guard let id = selectedFilespaceID else { return }
        operationError = nil
        guard !isHttpMode || isEngineConnected else {
            operationError = "Connect the background service before changing this Mac’s cache."
            return
        }
        let previous = cache
        cache = newValue                       // optimistic
        cacheState = .loaded(newValue)
        guard isEngineConnected else {
            do { try await gateway.updateCacheSettings(newValue, for: id) }
            catch {
                guard selectedFilespaceID == id else { return }
                cache = previous
                if let previous { cacheState = .loaded(previous) }
                operationError = "Could not change the cache settings. \(error.localizedDescription)"
            }
            return
        }
        do {
            var info: CacheInfo?
            if previous?.maxBytes != newValue.maxBytes {
                info = try await engine.cacheSetSize(filespace: id, bytes: newValue.maxBytes)
            }
            if previous?.location != newValue.location {
                info = try await engine.cacheSetLocation(filespace: id, path: newValue.location)
            }
            if let info {
                guard selectedFilespaceID == id else { return }
                let settings = info.toSettings(prefetchEnabled: newValue.prefetchEnabled,
                                               prefetchDepth: newValue.prefetchDepth)
                cache = settings
                cacheState = .loaded(settings)
            }
        } catch {
            guard selectedFilespaceID == id else { return }
            cache = previous                   // revert on engine error
            if let previous { cacheState = .loaded(previous) }
            operationError = "Could not change the cache settings. \(error.localizedDescription)"
        }
    }

    /// Filespace-wide "Clear cache" (Cache settings' Usage card + the Pinned view
    /// header — both share this one action path). Routes through cloudfsd's
    /// `cache.clear`: the daemon evicts every evictable block while protecting
    /// pinned content and any not-yet-durable local write itself (the write-back
    /// journal lives in storage the clear never touches — see
    /// `DiskBlockCache.clear` / `WriteBackJournal` in cloudfsd), so it's safe to
    /// fire while transfers are active. Cache is engine-owned (§5.4) with no
    /// gateway/mock equivalent, so this is a no-op without a connected daemon —
    /// both call sites hide/disable the action on `!isEngineConnected` rather than
    /// fake a clear (matching the Pinned view's existing engine-less honesty:
    /// no daemon ⇒ say so, never fabricate). Returns the bytes freed, or nil if
    /// there was nothing to do or the call failed.
    @discardableResult
    func clearCache() async -> Int64? {
        guard isEngineConnected, let id = selectedFilespaceID else { return nil }
        operationError = nil
        do {
            let result = try await engine.cacheClear(filespace: id)
            guard selectedFilespaceID == id else { return nil }
            let settings = result.info.toSettings(prefetchEnabled: cache?.prefetchEnabled ?? true,
                                                   prefetchDepth: cache?.prefetchDepth ?? 8)
            cache = settings
            cacheState = .loaded(settings)
            return result.freedBytes
        } catch {
            if selectedFilespaceID == id {
                operationError = "Could not clear the downloaded cache. \(error.localizedDescription)"
            }
            return nil
        }
    }

    // MARK: Pin / prefetch / evict (engine-owned)

    /// Pin/unpin a file via cloudfsd; returns true on success. Callers (Pinned
    /// view, Finder extension round-trips) reload to pick up the new
    /// materialization state. Falls back to the gateway/mock when no daemon is
    /// present.
    ///
    /// `recursive: false` on UNPIN is deliberate, not an oversight: the daemon
    /// keys pins by exact path and stores a recursive folder pin as ONE
    /// `PinRecord` whose block set was expanded at pin time —
    /// `DiskBlockCache.unpin` removes that whole record (descendant blocks
    /// included) and ignores the flag behaviorally (cloudfsd
    /// Sources/CloudFSCache/DiskBlockCache.swift, unpin). There are no separate
    /// descendant pin records to leave behind. `recursive: false` on PIN is the
    /// single-file semantics this call site wants; callers that pin folders
    /// recursively pass their own flag to the daemon's pin RPC, which honors
    /// whatever the caller sends (Engine.swift `pin(_:)`, `p.recursive ?? false`).
    @discardableResult
    func setPinned(_ pinned: Bool, path: String, fileID: String) async -> Bool {
        guard let id = selectedFilespaceID else { return false }
        if isEngineConnected {
            do {
                if pinned { _ = try await engine.pin(filespace: id, path: path, recursive: false) }
                else { _ = try await engine.unpin(filespace: id, path: path, recursive: false) }
                return true
            } catch { return false }
        }
        try? await gateway.setPinned(pinned, fileID: fileID, in: id)
        return true
    }

    @discardableResult
    func prefetch(path: String, fileID: String) async -> Bool {
        guard let id = selectedFilespaceID else { return false }
        if isEngineConnected {
            return (try? await engine.prefetch(filespace: id, path: path)) != nil
        }
        try? await gateway.prefetch(fileID: fileID, in: id)
        return true
    }

    @discardableResult
    func evict(path: String, fileID: String) async -> Bool {
        guard let id = selectedFilespaceID else { return false }
        if isEngineConnected {
            return (try? await engine.evict(filespace: id, path: path)) != nil
        }
        try? await gateway.evict(fileID: fileID, in: id)
        return true
    }

    // MARK: File-row actions (copy-link / reveal / get-info)

    /// Mint an internal `cloudfs://` deep link for the file and copy it to the
    /// pasteboard. Returns the URL string (nil on failure).
    @discardableResult
    func copyDeepLink(fileID: String) async -> String? {
        guard let id = selectedFilespaceID,
              let link = try? await gateway.createShareLink(for: fileID, kind: .internalDeepLink, in: id),
              !link.url.isEmpty
        else { return nil }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(link.url, forType: .string)
        return link.url
    }

    /// Resolve the immutable item ID through the same permission-checked path
    /// used by team links, including renamed items and folder-only mounts.
    func revealInFinder(node: FileNode) {
        guard let fs = selectedFilespace,
              let url = URL(string: DeepLink.buildItem(spaceId: fs.id, itemId: node.id)) else { return }
        _ = handleNavigationLink(url)
    }

    /// Open the actual volume. Finder may have ejected it since the last status
    /// refresh; an empty local mount directory is never a successful connection.
    func revealFilespaceInFinder(_ fs: Filespace) {
        guard isSignedIn, !isSigningOut else { return }
        guard isHttpMode else {
            operationError = "Demo filespaces do not mount a volume. Sign in to your workspace to open your files."
            return
        }
        let base = (fs.mountPath as NSString).expandingTildeInPath
        guard MountProbe.isCloudFSMounted(mountRoot: base) else {
            operationError = "This filespace is no longer connected. Connect it again to open your files in Finder."
            Task { await applyEngineMountState(autoMount: false) }
            return
        }
        if !NSWorkspace.shared.open(URL(fileURLWithPath: base)) {
            operationError = "Finder could not open this filespace. Check the connection and try again."
        }
    }

    // MARK: Durability barrier

    /// Durability barrier — `flush(wait:)` against cloudfsd. Surfaces the typed
    /// error so the UI can show sync-timeout/failed.
    func flush(path: String, wait: Bool) async throws -> SyncState {
        guard let id = selectedFilespaceID else {
            throw EngineError.notFound("no filespace selected")
        }
        return try await engine.flush(filespace: id, path: path, wait: wait, timeoutMs: 30_000)
    }

    // MARK: Snapshot restore

    /// Restore `path` (optionally recursive) from `snapshotID`. Returns the
    /// `RestoreResult` on success, or throws (the view maps 409 → "locked by
    /// another editor" etc.). Refreshes the activity feed afterward.
    func restore(path: String, recursive: Bool, fromSnapshot snapshotID: String) async throws -> RestoreResult {
        guard let id = selectedFilespaceID else {
            throw HttpGatewayClient.GatewayError.unsupported("no filespace selected")
        }
        let result = try await gateway.restore(path: path, recursive: recursive,
                                               fromSnapshot: snapshotID, in: id)
        await refreshForSelection()
        return result
    }

    // MARK: Browser-handoff sign-in (auth-spec §1.2 / §3)

    /// Step 1→3 of the default sign-in: probe the server's public auth config
    /// (reachability + learn `webBaseUrl`), generate state + PKCE, open the
    /// system browser at `/device/authorize`, and enter the waiting state. The
    /// browser-open is delegated so the view layer owns `NSWorkspace`.
    func beginBrowserSignIn(serverURL raw: String, openURL: (URL) -> Void) async {
        let url = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard LoginValidation.canSignInWithBrowser(url: url) else {
            signInError = "Enter a full http(s):// server address."
            return
        }
        signInError = nil
        sessionExpiredNotice = nil
        authFlow = .probing
        isConnecting = true
        defer { isConnecting = false }

        let config: PublicAuthConfig
        do {
            config = try await DeviceAuthAPI(baseURL: url).publicConfig()
        } catch let error as HttpGatewayClient.GatewayError {
            authFlow = .idle
            switch error {
            case .transport, .badURL:
                signInError = "Couldn’t reach that server. Check the address and your connection."
            default:
                // Reachable but not speaking the cloud-fs public-config shape.
                signInError = "That address doesn’t look like a cloud-fs server."
            }
            return
        } catch {
            authFlow = .idle
            signInError = "Couldn’t reach that server. Check the address and your connection."
            return
        }

        let webBase = (config.webBaseUrl?.isEmpty == false) ? config.webBaseUrl! : url
        guard let pending = DeviceAuth.beginRequest(serverURL: url, webBaseURL: webBase,
                                                    device: .current()) else {
            authFlow = .idle
            signInError = "That address doesn’t look like a cloud-fs server."
            return
        }
        pendingDeviceAuth = pending
        settings.baseURL = url          // remember the server address (spec: remembered field)
        // Persist the web console's base URL now — it's only ever learned here
        // (GET /v1/auth/config/public) and would otherwise be dropped the moment
        // this function returns. The sidebar's workspace-overflow menu reads it
        // back via `AppModel.consoleLinks`, including after a relaunch.
        settings.webBaseUrl = webBase
        settings.productName = config.productName
        browserWaitTimedOut = false
        authFlow = .waitingForBrowser
        startBrowserWaitTimeout()
        openURL(pending.authorizeURL)
    }

    /// "Open browser again" / "Try again" from the waiting card.
    func reopenBrowser(openURL: (URL) -> Void) {
        guard let pending = pendingDeviceAuth else { return }
        browserWaitTimedOut = false
        startBrowserWaitTimeout()
        openURL(pending.authorizeURL)
    }

    /// Cancel the pending browser sign-in and return to the form. Invalidates
    /// the pending state so a late callback for it is refused.
    func cancelBrowserSignIn() {
        pendingDeviceAuth = nil
        browserWaitTimer?.cancel()
        browserWaitTimedOut = false
        authFlow = .idle
        isConnecting = false
    }

    private func startBrowserWaitTimeout() {
        browserWaitTimer?.cancel()
        browserWaitTimer = Task { [weak self] in
            try? await Task.sleep(for: .seconds(Self.browserWaitTimeout))
            guard !Task.isCancelled, let self else { return }
            if self.authFlow == .waitingForBrowser { self.browserWaitTimedOut = true }
        }
    }

    /// Paste-code fallback (spec §3): a pasted code is accepted ONLY against the
    /// active pending request — that explicit user action replaces `state`.
    func submitPastedCode(_ raw: String) async {
        switch DeviceAuth.resolvePastedCode(raw, pending: pendingDeviceAuth) {
        case .reject(let message):
            signInError = message
        case .exchange(let code, let verifier):
            await completeDeviceExchange(code: code, verifier: verifier)
        }
    }

    /// Exchange code + PKCE verifier for the device session, then bring the
    /// whole stack up: settings, gateway client (access-JWS provider), daemon
    /// token mint + provisioning, and the normal connect.
    private func completeDeviceExchange(code: String, verifier: String) async {
        guard let pending = pendingDeviceAuth, authFlow != .exchanging else { return }
        authFlow = .exchanging
        isConnecting = true
        signInError = nil
        let manager = AuthSessionManager(api: DeviceAuthAPI(baseURL: pending.serverURL))
        deviceResumeRetry?.cancel()
        let previous = authSession
        authSession = manager
        daemonCredentials.stop()
        await previous?.retire()
        guard authSession === manager else { return }
        // Invalidate before the new refresh token is persisted. If the app exits
        // between exchange and daemon provisioning, resume must mint for the new
        // account instead of reusing the old account's still-valid daemon token.
        DaemonCredential.storeExpiry(nil)
        do {
            let session = try await manager.exchange(code: code, codeVerifier: verifier)
            guard authSession === manager, pendingDeviceAuth?.state == pending.state else {
                await manager.retire()
                return
            }
            pendingDeviceAuth = nil
            browserWaitTimer?.cancel()
            browserWaitTimedOut = false
            try await adoptDeviceSession(manager, serverURL: pending.serverURL, exchange: session)
            authFlow = .idle
        } catch {
            guard authSession === manager else { return }
            if case AuthSessionError.codeRejected = error {
                // Terminal for this attempt (invalid_code / pkce_mismatch — the
                // backend burns the one-time code even on failure, and the PKCE
                // pair died with it). Drop the dead pending request and return
                // to the form so "Sign in with browser" is the obvious restart.
                pendingDeviceAuth = nil
                browserWaitTimer?.cancel()
                browserWaitTimedOut = false
                authFlow = .idle
            } else {
                // Transient (network/server hiccup). Stay in the waiting card
                // so the user can paste again, reopen the browser, or cancel.
                // Once the one-time code was exchanged, retry the saved session
                // (including daemon provisioning), never the consumed code.
                if pendingDeviceAuth == nil {
                    authFlow = .idle
                    scheduleDeviceResumeRetry()
                } else {
                    authFlow = .waitingForBrowser
                }
            }
            signInError = error.localizedDescription
        }
        if authSession === manager { isConnecting = false }
    }

    /// Wire a live device session into the app: persist the non-secret half,
    /// install the access-token provider on the gateway client, start the daemon
    /// credential cycle, and connect.
    private func adoptDeviceSession(_ manager: AuthSessionManager, serverURL: String,
                                    exchange: DeviceTokenResponse?) async throws {
        guard authSession === manager else { throw CancellationError() }
        await manager.setOnSessionExpired { [weak self, weak manager] code in
            Task { @MainActor [weak self, weak manager] in
                guard let self, let manager, self.authSession === manager else { return }
                self.deviceSessionDidExpire(code: code)
            }
        }
        guard authSession === manager else { throw CancellationError() }
        if let exchange {
            settings.saveDeviceSession(baseURL: serverURL, org: exchange.orgId)
            accountEmail = exchange.account?.email
            orgName = exchange.orgName
            // Persist the org DISPLAY name (distinct from the raw org id above) —
            // a fresh exchange is the only place it's ever learned; without this
            // it's lost the moment the app relaunches (`resumeDeviceSession` has
            // no exchange to read it from — see the `else` branch below).
            settings.orgDisplayName = exchange.orgName
        } else {
            settings.saveDeviceSession(baseURL: serverURL, org: settings.org)
            // Relaunch path: no fresh exchange, so restore the display name this
            // app instance would otherwise never see again.
            orgName = settings.orgDisplayName
        }
        sessionExpiredNotice = nil
        advancedPreExpanded = false

        let config = GatewayConfig(baseURL: serverURL, org: settings.org, token: "")
        gateway = HttpGatewayClient(
            config: config,
            tokenProvider: { await manager.validAccessToken() ?? "" },
            unauthorizedRecovery: { await manager.recoverFromUnauthorized() })
        mode = .http(serverURL)

        // Daemon credential cycle (C6): mint/renew the 30-day token, write
        // daemon.env + 0600 token.txt, register the launch agent, keep renewing.
        try await daemonCredentials.start(session: manager, gatewayURL: serverURL,
                                          newSession: exchange != nil)
        guard authSession === manager else { throw CancellationError() }
        await refreshEngineWhenSocketAppears()
        guard authSession === manager else { throw CancellationError() }
        await signIn(.serviceToken(token: ""))
        // On connect failure the error stays visible; the device session remains
        // valid (and revocable from the web console) — never destroy credentials
        // for what may be a transient gateway problem.
    }

    /// App relaunch with a persisted device session: load the refresh token from
    /// the Keychain, rotate it, and bring the stack up — no UI.
    func resumeDeviceSession() async {
        deviceResumeRetry?.cancel()
        let serverURL = settings.baseURL
        let manager = AuthSessionManager(api: DeviceAuthAPI(baseURL: serverURL))
        let previous = authSession
        authSession = manager
        daemonCredentials.stop()
        await previous?.retire()
        guard authSession === manager else { return }
        // A legacy Keychain read can wait for a protected macOS approval.
        // Keep the sign-in form busy during that wait so a second browser flow
        // cannot compete with the session being restored.
        isConnecting = true
        defer { if authSession === manager { isConnecting = false } }
        guard await manager.loadPersistedSession() else {
            guard authSession === manager else { return }
            // Keychain has no refresh token (cleared / restore lost it).
            presentSessionExpired(host: Self.host(of: serverURL))
            return
        }
        do {
            try await manager.refreshIfNeeded(force: true)
            try await adoptDeviceSession(manager, serverURL: serverURL, exchange: nil)
        } catch let error as AuthSessionError {
            guard authSession === manager else { return }
            switch error {
            case .sessionExpired, .notSignedIn:
                presentSessionExpired(host: Self.host(of: serverURL))
            case .transient, .codeRejected:
                // Network down ≠ session expired (spec §1.5): keep credentials,
                // surface a reachability message, and retry quietly.
                // (.codeRejected is exchange-only and unreachable from a
                // refresh; grouped here purely for exhaustiveness.)
                signInError = "Can’t reach \(Self.host(of: serverURL)) — retrying…"
                scheduleDeviceResumeRetry()
            }
        } catch {
            guard authSession === manager else { return }
            signInError = error.localizedDescription
            scheduleDeviceResumeRetry()
        }
    }

    private func scheduleDeviceResumeRetry() {
        deviceResumeRetry?.cancel()
        deviceResumeRetry = Task { [weak self] in
            try? await Task.sleep(for: .seconds(30))
            guard !Task.isCancelled, let self else { return }
            // Only while still signed out, on the device path, with no flow open.
            guard !self.isSignedIn, self.settings.authMethod == .device,
                  self.authFlow == .idle else { return }
            await self.resumeDeviceSession()
        }
    }

    /// Terminal refresh failure (revoked / expired / reuse-detected / account
    /// inactive): show the session-expired UX. Local data stays visible
    /// read-only; the daemon keeps serving cached reads until its token dies.
    private func deviceSessionDidExpire(code: String) {
        presentSessionExpired(host: Self.host(of: settings.baseURL))
        daemonCredentials.stop()
    }

    private func presentSessionExpired(host: String) {
        sessionExpiredNotice =
            "Your sign-in for \(host) is no longer valid on this Mac."
        advancedPreExpanded = (settings.authMethod == .legacy)
    }

    /// The "Sign in again" CTA: clear the dead credentials (keeping the server
    /// URL prefilled) and return to the sign-in screen.
    func signInAgainAfterSessionExpiry() async {
        if let session = authSession { await session.signOutLocal() }
        authSession = nil
        daemonCredentials.stop()
        settings.clearCredentialsKeepingServer()
        // NOTE: token.txt is left in place — the daemon keeps serving cached
        // reads until its own token expires (spec §1.5).
        liveTransferTask?.cancel()
        isSignedIn = false
        authFlow = .idle
        accountEmail = nil; orgName = nil
        filespaces = []; selectedFilespaceID = nil
        recentActivity = []; transfers = []; snapshots = []; shareLinks = []; cache = nil
        members.currentRole = .standard
        resetLoadStates()
        let (client, m) = GatewayFactory.makeClient()
        gateway = client
        mode = m
        // Keep sessionExpiredNotice set: the login screen shows it inline until
        // the next sign-in attempt clears it.
    }

    static func host(of url: String) -> String {
        URL(string: url)?.host ?? url
    }

    /// Refresh triggers (C2): system wake + app foreground nudge the session
    /// refresh and the daemon-token check (both are cheap no-ops when fresh).
    func refreshCredentialsAfterWake() async {
        guard let session = authSession else { return }
        try? await session.refreshIfNeeded(force: false)
        await daemonCredentials.ensureFresh()
        await loadCurrentUserRole()
    }

    /// On-demand daemon-token renewal (C6): when an engine call surfaces the
    /// daemon's own gateway 401 (its service token died early — revoked or
    /// expired while the app was closed), re-mint immediately instead of
    /// waiting for the periodic check.
    func noteEngineError(_ error: Error) {
        if let error = error as? EngineError, error.needsCredentialRefresh {
            Task { await daemonCredentials.daemonReportedAuthFailure() }
        }
    }

    // MARK: SSO (OIDC) login — legacy delivery, kept for compatibility

    /// Begin an OIDC SSO login against the configured gateway. Persists URL+org,
    /// opens the gateway's `/v1/auth/oidc/start` in the browser, and awaits the
    /// minted session token coming back via the `cloudfs://` URL scheme (handled
    /// by `completeSSOLogin(token:)`). The actual browser-open is delegated so the
    /// view layer owns `NSWorkspace`.
    func beginSSOLogin(baseURL: String, org: String, openURL: (URL) -> Void) {
        let url = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let orgT = org.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !url.isEmpty, let startURL = SSO.startURL(gatewayBaseURL: url) else {
            signInError = "Enter a valid gateway URL for SSO."
            return
        }
        // Stash URL+org now so completeSSOLogin can build the HttpGatewayClient.
        settings.baseURL = url
        settings.org = orgT
        signInError = nil
        isConnecting = true
        openURL(startURL)
    }

    /// Complete SSO: a `cloudfs://auth/callback?token=…` deep link arrived (or a
    /// loopback delivered the token). Store it in the Keychain and connect exactly
    /// like the service-account path.
    func completeSSOLogin(token rawToken: String) async {
        let token = rawToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else {
            isConnecting = false
            signInError = "SSO login returned no token."
            return
        }
        let config = GatewayConfig(baseURL: settings.baseURL, org: settings.org, token: token)
        guard config.isUsable else {
            isConnecting = false
            signInError = "SSO succeeded but the gateway URL is missing — set it first."
            return
        }
        do { try settings.save(config) }
        catch {
            isConnecting = false
            signInError = "Could not store SSO token: \(error.localizedDescription)"
            return
        }
        gateway = HttpGatewayClient(config: config)
        mode = .http(config.baseURL)
        // M7: same daemon bring-up on the SSO path.
        DaemonLifecycle.shared.provisionAndStart(gatewayURL: config.baseURL, token: token)
        await refreshEngineWhenSocketAppears()
        await signIn(.serviceToken(token: token))
        if !isSignedIn {
            settings.clear()
            let (client, m) = GatewayFactory.makeClient()
            gateway = client
            mode = m
        }
    }

    /// Handle an incoming `cloudfs://` URL. Returns true if it was consumed
    /// here (auth callback, connect link, or filespace/file navigation).
    ///
    /// `connect` (ONBOARDING.md step 3): reserved host, checked FIRST —
    /// `ConnectLink.parseServerURL` validates `?server=` the same way the login
    /// form's own field does; garbage is logged and dropped, never crashed on.
    ///
    /// Device handoff (`?code&state`): the callback is bound to the single
    /// pending request via `state` (spec §5.2) — a mismatch or a callback with
    /// no pending request is refused WITHOUT cancelling any legit pending flow.
    /// Legacy `?token=` delivery still routes to `completeSSOLogin`.
    @discardableResult
    func handleIncomingURL(_ url: URL) -> Bool {
        if url.scheme == DeepLink.scheme, url.host == ConnectLink.host {
            guard let server = ConnectLink.parseServerURL(url) else {
                Self.connectLinkLog.notice("Ignoring malformed cloudfs://connect link (no valid ?server=)")
                return true   // it WAS a connect link — don't fall through to nav-reveal parsing
            }
            handleConnectLink(server: server)
            return true
        }
        guard let callback = DeviceAuth.parseCallback(url) else { return handleNavigationLink(url) }
        switch callback {
        case .device(let code, let state):
            switch DeviceAuth.resolve(callbackCode: code, state: state,
                                      pending: pendingDeviceAuth) {
            case .reject(let message):
                signInError = message
            case .exchange(let code, let verifier):
                Task { await completeDeviceExchange(code: code, verifier: verifier) }
            }
            return true
        case .legacyToken(let token):
            Task { await completeSSOLogin(token: token) }
            return true
        }
    }

    private static let connectLinkLog = Logger(subsystem: "dev.cloudfs.client", category: "connect-link")

    /// Route a validated connect-link server URL through `ConnectLink.decide`
    /// (auth-spec-style: pure decision, thin UI wiring).
    private func handleConnectLink(server: String) {
        switch ConnectLink.decide(server: server, isSignedIn: isSignedIn,
                                  currentServerURL: settings.baseURL) {
        case .prefill(let url):
            connectServerPrefill = url
        case .alreadyConnected:
            // Gentle confirmation: bring the already-signed-in window forward,
            // no state change.
            NSApp.activate(ignoringOtherApps: true)
        case .differentServer(let current, let requested):
            connectDifferentServerNotice = ConnectDifferentServerNotice(
                currentHost: current, requestedHost: requested)
        }
    }

    // MARK: Menu-bar commands

    /// The current state slice the menu Commands read for enablement (pure logic
    /// lives in `AppCommand.isEnabled(in:)`).
    var commandContext: CommandContext {
        CommandContext(isSignedIn: isSignedIn,
                       section: section.rawValue)
    }

    func isEnabled(_ command: AppCommand) -> Bool {
        (command != .newShare || canManageGuestLinks) && command.isEnabled(in: commandContext)
    }

    /// Dispatch a menu-bar command to the matching action/state change. Section
    /// views observe `refreshToken` to perform view-local reloads.
    func run(_ command: AppCommand) {
        guard isEnabled(command) else { return }
        switch command {
        case .newShare:
            section = .sharing
        case .refresh:
            refreshToken += 1
            Task {
                await loadCurrentUserRole()
                await reloadFilespaces()
                await refreshForSelection()
            }
        }
    }

    /// Jump to a section (Go menu).
    func go(to section: NavSection) { if canAccess(section) { self.section = section } }

    // MARK: Per-pane toolbar actions

    /// Whether the current member role permits writes (create folder/link/snapshot).
    /// All current roles can edit; a future read-only viewer role would flip this.
    var canEdit: Bool { selectedFilespace != nil }

    private var hasCompletedTransfers: Bool {
        transfers.contains { $0.state == .completed }
    }
    private var hasActiveTransfers: Bool {
        transfers.contains { $0.state == .active || $0.state == .queued }
    }
    /// True when the selected filespace's sync is paused (drives Pause/Resume All).
    var transfersPaused: Bool { selectedFilespace?.connection == .paused }

    /// The state slice the per-pane toolbar reads for enablement (pure logic in
    /// `PaneAction.isEnabled(in:)`).
    var paneActionContext: PaneAction.Context {
        PaneAction.Context(isSignedIn: isSignedIn,
                           canEdit: canEdit,
                           hasCompletedTransfers: hasCompletedTransfers,
                           hasActiveTransfers: hasActiveTransfers,
                           transfersPaused: transfersPaused)
    }

    func isEnabled(_ action: PaneAction) -> Bool {
        isVisible(action) && action.isEnabled(in: paneActionContext)
    }

    /// Dispatch a per-pane toolbar action to its live feature operation.
    func isVisible(_ action: PaneAction) -> Bool {
        switch action {
        case .newSnapshot: return canManageFolderAccess
        case .newLink: return canManageGuestLinks
        default: return true
        }
    }

    func run(_ action: PaneAction) {
        guard isEnabled(action) else { return }
        switch action {
        case .newLink:
            section = .sharing
            Task { await copyFilespaceLink() }
        case .newSnapshot:
            Task { await takeManualSnapshot() }
        case .clearCompleted:
            Task { await clearCompletedTransfers() }
        case .togglePauseAll:
            Task { await togglePauseSync() }
        }
    }

    /// Only successful transfers may be dismissed; failures remain actionable.
    func clearCompletedTransfers() async {
        guard let filespace = selectedFilespaceID else { return }
        if isEngineConnected {
            do { try await engine.clearCompletedTransfers(filespace: filespace) }
            catch {
                operationError = "Could not clear completed transfers. \(error.localizedDescription)"
                return
            }
        }
        guard selectedFilespaceID == filespace else { return }
        transfers.removeAll { $0.state == .completed }
        transfersState = .loaded(transfers)
    }
}

// MARK: - CacheInfo → CacheSettings mapping

extension CacheInfo {
    /// Map the engine's `CacheInfo` onto the GUI `CacheSettings`. Prefetch flags
    /// aren't part of `CacheInfo`, so carry them through (defaults shown).
    func toSettings(prefetchEnabled: Bool = true, prefetchDepth: Int = 8) -> CacheSettings {
        CacheSettings(
            maxBytes: maxBytes,
            usedBytes: usedBytes,
            pinnedBytes: pinnedBytes,
            location: location,
            prefetchEnabled: prefetchEnabled,
            prefetchDepth: prefetchDepth)
    }
}

// MARK: - Navigation sections (sidebar)

enum NavSection: String, CaseIterable, Identifiable {
    case dashboard   = "Dashboard"    // DEFAULT landing section — per-filespace overview
    case filespaces  = "Filespaces"   // the multi-filespace manager
    case pinned      = "Pinned files"       // NEW (WS2)
    case activity    = "Activity"     // KEPT — now the LIVE feed (WS3)
    case audit       = "Audit"        // NEW (WS3) — historical audit log
    case snapshots   = "Snapshots"
    case sharing     = "Sharing"
    case members     = "Members & Access"   // NEW — org users + per-folder ACL (admin-gated)
    case cache       = "Filespace settings"
    case preferences = "Preferences"

    var id: String { rawValue }

    var symbol: String {
        switch self {
        case .dashboard:   return IconSet.dashboard
        case .filespaces:  return IconSet.filespaces
        case .pinned:      return IconSet.pin          // exists (IconSet.swift)
        case .activity:    return IconSet.activity
        case .audit:       return IconSet.audit        // dedicated audit glyph
        case .snapshots:   return IconSet.snapshots
        case .sharing:     return IconSet.sharing
        case .members:     return IconSet.membersNav
        case .cache:       return IconSet.cache
        case .preferences: return IconSet.preferences
        }
    }

    /// Whether this section is gated to org admins (owner/admin/space_admin).
    /// Members & Access is the only admin-only section; the rest are visible to all.
    var requiresAdmin: Bool { self == .members }
}
