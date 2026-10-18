// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - LoginView
//
// Browser-handoff sign-in (auth-spec §1.2): ONE remembered server-address field
// + a primary "Sign in with browser" button. Auth itself happens on the portal
// (password/TOTP/passkey/SSO — the app inherits every method); the approval
// bounces back via cloudfs://auth/callback, with a paste-code fallback. The
// legacy service-account token paste survives only inside the "Advanced"
// disclosure (machines/recovery — decision E). Demo stays the second segment.

struct LoginView: View {
    @Environment(AppModel.self) private var model

    private enum Mode: String, CaseIterable {
        case signIn = "Sign in"  // browser handoff (+ Advanced token paste)
        case demo   = "Demo"     // mock — explore offline with sample data
    }
    @State private var mode: Mode = .signIn

    // Connection settings (prefilled from the persisted store).
    @State private var baseURL = ""
    @State private var org = ""
    @State private var token = ""
    @State private var advancedExpanded = false

    // Waiting-state paste fallback.
    @State private var showCodeEntry = false
    @State private var pastedCode = ""

    /// A non-empty server URL that doesn't parse as http(s) — drives the inline
    /// validation hint + disables Sign in. Empty input shows no error (calm).
    /// Delegates to the pure, tested `LoginValidation`.
    private var gatewayURLInvalid: Bool { LoginValidation.gatewayURLInvalid(baseURL) }

    private var canSignIn: Bool { LoginValidation.canSignInWithBrowser(url: baseURL) }

    private var canConnectGateway: Bool {
        LoginValidation.canConnectGateway(url: baseURL, token: token)
    }

    var body: some View {
        // A ScrollView that vertically CENTERS the content when the window is tall
        // enough, and gracefully SCROLLS (never clips the footnote) when it isn't.
        GeometryReader { geo in
            ScrollView(.vertical, showsIndicators: false) {
                VStack(spacing: Theme.Space.xl) {
                    header
                    if model.pendingNavigationLink != nil {
                        Text("Sign in to your workspace to open the shared item.")
                            .font(Theme.Font.caption)
                            .foregroundStyle(Theme.textSecondary)
                            .multilineTextAlignment(.center)
                    }
                    card
                    footnote
                }
                .frame(maxWidth: 440)
                .padding(.horizontal, Theme.Space.xxxl)
                .padding(.vertical, Theme.Space.xl)
                // Center vertically when there's room; expand to scroll otherwise.
                .frame(maxWidth: .infinity, minHeight: geo.size.height, alignment: .center)
            }
        }
        .background(Theme.canvas.ignoresSafeArea())
        .preferredColorScheme(.dark)
        .onAppear {
            let cfg = model.settings
            baseURL = cfg.baseURL.isEmpty ? "" : cfg.baseURL
            org = cfg.org
            // Legacy-token expiry reopens the form with Advanced pre-expanded
            // (spec §1.5 row 5).
            advancedExpanded = model.advancedPreExpanded
            // Default keyboard focus to the first field for fast entry.
            DispatchQueue.main.async { focusFirstField = true }
        }
        .onChange(of: model.authFlow) { _, flow in
            // Whenever the flow falls back to the form (cancel, or a burned
            // one-time code), reset the paste fallback so a stale — already
            // consumed — code can't be resubmitted on the next attempt.
            if flow == .idle {
                showCodeEntry = false
                pastedCode = ""
            }
        }
        .onChange(of: mode) { _, _ in
            model.signInError = nil
        }
        // `cloudfs://connect?server=…` arrived while signed out (ONBOARDING.md
        // step 3): prefill + focus the server field so the user only has to
        // click "Sign in with browser". AppModel already ran the pure
        // ConnectLink.decide (same-server/different-server never reach here).
        .onChange(of: model.connectServerPrefill) { _, newValue in
            guard let newValue else { return }
            if model.authFlow != .idle { model.cancelBrowserSignIn() }
            mode = .signIn
            baseURL = newValue
            DispatchQueue.main.async { focusFirstField = true }
            model.connectServerPrefill = nil   // consumed
        }
    }

    private var footnote: some View {
        Text(mode == .signIn
             ? "Signing in opens your browser. Your session is stored in the macOS Keychain on this Mac only."
             : "Sample data only. Demo mode does not connect to storage or mount a volume.")
            .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
            .multilineTextAlignment(.center).frame(maxWidth: 380)
    }

    private var modeBanner: some View {
        HStack(spacing: Theme.Space.sm) {
            StatusDot(color: model.isHttpMode ? Theme.Status.ok : Theme.Status.paused, size: 7)
            Text(model.mode.label).font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
        }
        .accessibilityElement(children: .combine)
    }

    @FocusState private var focusFirstField: Bool

    private var header: some View {
        VStack(spacing: Theme.Space.sm) {
            BrandMark(chrome: true, size: 72)
                .clipShape(RoundedRectangle(cornerRadius: 16))
                .accessibilityHidden(true)
                .padding(.bottom, Theme.Space.xs)
            Text("CloudFS").font(Theme.Font.hero)
                .foregroundStyle(Theme.textPrimary)
            Text("Your team’s files, right in Finder.")
                .font(Theme.Font.body)
                .foregroundStyle(Theme.textSecondary)
                .multilineTextAlignment(.center)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("CloudFS. Your team’s files, right in Finder.")
    }

    private var card: some View {
        VStack(spacing: Theme.Space.xl) {
            // The mode picker hides while a browser handoff is in flight — the
            // waiting card owns the whole surface (Cancel returns here).
            if model.authFlow == .idle || model.authFlow == .probing {
                Picker("", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }

            if mode == .signIn { signInPane } else { demoPanel }

            if let notice = model.sessionExpiredNotice, mode == .signIn {
                Banner(kind: .warning, title: "Session expired", detail: notice)
                    .transition(.opacity)
            }
            if let err = model.signInError, mode == .signIn {
                Banner(kind: .error, title: "Sign-in failed", detail: err)
                    .transition(.opacity)
            }
        }
        .padding(Theme.Space.xxl)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.Radius.lg))
        .overlay(RoundedRectangle(cornerRadius: Theme.Radius.lg).strokeBorder(Theme.border))
        .motionAnimation(Theme.Motion.section, value: mode)
        .motionAnimation(Theme.Motion.section, value: model.authFlow)
    }

    // MARK: Sign-in tab — the §1.2 state machine

    @ViewBuilder private var signInPane: some View {
        switch model.authFlow {
        case .idle, .probing:
            serverForm
        case .waitingForBrowser:
            waitingCard
        case .exchanging:
            exchangingCard
        }
    }

    // Step 1: one remembered server-address field + the primary CTA.
    @ViewBuilder private var serverForm: some View {
        VStack(alignment: .leading, spacing: Theme.Space.lg) {
            LabeledField(title: "Server address", systemImage: IconSet.network, text: $baseURL,
                         prompt: "https://cloudfs.example.com", focused: $focusFirstField)
            if gatewayURLInvalid {
                inlineHint("Enter a full http(s):// server address.")
            }
        }

        Button(action: startBrowserSignIn) {
            HStack {
                if model.isConnecting { ProgressView().controlSize(.small) }
                Text(model.authFlow == .probing ? "Contacting server…" : model.isConnecting ? "Connecting…" : "Sign in with browser")
                    .frame(maxWidth: .infinity)
            }
        }
        .cfButton(.primary, size: .large)
        .keyboardShortcut(.defaultAction)   // Enter submits
        .disabled(model.isConnecting || !canSignIn)

        if model.isConnecting && model.authFlow == .idle {
            Text("If macOS asks, approve CloudFS access to your saved sign-in.")
                .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }

        // Decision E: the legacy service-account token paste lives ONLY here.
        DisclosureGroup(isExpanded: $advancedExpanded) {
            VStack(alignment: .leading, spacing: Theme.Space.lg) {
                Text("For service accounts and recovery access.")
                    .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                    .fixedSize(horizontal: false, vertical: true)
                LabeledField(title: "Org", systemImage: IconSet.building, text: $org,
                             prompt: "acme")
                LabeledField(title: "Service-account token", systemImage: IconSet.key,
                             text: $token, prompt: "eyJ… (JWS bearer token)", isSecure: true)
                Button(action: connectGateway) {
                    HStack {
                        if model.isConnecting { ProgressView().controlSize(.small) }
                        Text(model.isConnecting ? "Connecting…" : "Connect with token")
                            .frame(maxWidth: .infinity)
                    }
                }
                .cfButton(.secondary, size: .large)
                .disabled(model.isConnecting || !canConnectGateway)
            }
            .padding(.top, Theme.Space.md)
        } label: {
            Text("Advanced: service-account token")
                .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
        }
        .tint(Theme.textSecondary)
    }

    // Step 3: waiting for the browser handoff (spinner + fallbacks).
    @ViewBuilder private var waitingCard: some View {
        VStack(spacing: Theme.Space.lg) {
            ProgressView().controlSize(.regular)
            Text(model.browserWaitTimedOut ? "Still waiting?" : "Waiting for your browser…")
                .font(Theme.Font.headline).foregroundStyle(Theme.textPrimary)
            Group {
                if model.browserWaitTimedOut {
                    Text("The browser sign-in may have been closed.")
                } else {
                    Text("Finish signing in to **\(serverHost)** in the browser window we just opened. This screen will continue automatically.")
                }
            }
            .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Theme.Space.sm)

        if showCodeEntry {
            VStack(alignment: .leading, spacing: Theme.Space.md) {
                LabeledField(title: "One-time code", systemImage: IconSet.key,
                             text: $pastedCode, prompt: "acme.dac-…")
                Text("If the browser didn’t hand back automatically, paste the code shown there.")
                    .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                    .fixedSize(horizontal: false, vertical: true)
                Button(action: submitCode) {
                    Text("Continue").frame(maxWidth: .infinity)
                }
                .cfButton(.primary, size: .large)
                .keyboardShortcut(.defaultAction)
                .disabled(pastedCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }

        HStack(spacing: Theme.Space.md) {
            Button(model.browserWaitTimedOut ? "Try again" : "Open browser again") {
                model.reopenBrowser { NSWorkspace.shared.open($0) }
            }
            .cfButton(.secondary, size: .small)
            if !showCodeEntry {
                Button("Enter code instead") { showCodeEntry = true }
                    .cfButton(.secondary, size: .small)
            }
            Button("Cancel") {
                showCodeEntry = false
                pastedCode = ""
                model.cancelBrowserSignIn()
            }
            .cfButton(.subtle, size: .small)
        }
        .frame(maxWidth: .infinity)
    }

    // Code → device-session exchange in flight.
    @ViewBuilder private var exchangingCard: some View {
        VStack(spacing: Theme.Space.lg) {
            ProgressView().controlSize(.regular)
            Text("Signing you in…")
                .font(Theme.Font.headline).foregroundStyle(Theme.textPrimary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Theme.Space.xl)
    }

    private var serverHost: String {
        AppModel.host(of: model.settings.baseURL.isEmpty ? baseURL : model.settings.baseURL)
    }

    // MARK: Demo tab — a calm single call-to-action (no dev form)

    @ViewBuilder private var demoPanel: some View {
        VStack(spacing: Theme.Space.lg) {
            Image(systemName: IconSet.filespaces)
                .font(Theme.IconRole.hero.font)
                .foregroundStyle(Theme.accent)
                .accessibilityHidden(true)
            Text("Explore with demo data")
                .font(Theme.Font.headline).foregroundStyle(Theme.textPrimary)
            Text("Explore a sample workspace, filespaces, activity, and cache settings. No connection required.")
                .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, Theme.Space.sm)

        Button(action: exploreDemo) {
            HStack {
                if model.isConnecting { ProgressView().controlSize(.small) }
                Text(model.isConnecting ? "Loading…" : "Explore with demo data")
                    .frame(maxWidth: .infinity)
            }
        }
        .cfButton(.primary, size: .large)
        .keyboardShortcut(.defaultAction)   // Enter submits
        .disabled(model.isConnecting)
    }

    private func inlineHint(_ text: String) -> some View {
        Label(text, systemImage: IconSet.errorOutline)
            .font(Theme.Font.micro)
            .foregroundStyle(Theme.Status.warn)
            .transition(.opacity)
            .accessibilityLabel(text)
    }

    /// Default path: probe the server, then open the system browser at the
    /// portal's /device/authorize (state + PKCE S256 + device name/model). The
    /// approval returns via `cloudfs://auth/callback?code&state`, captured by
    /// `AppModel.handleIncomingURL`; a one-time code can be pasted instead.
    private func startBrowserSignIn() {
        showCodeEntry = false
        pastedCode = ""
        Task {
            await model.beginBrowserSignIn(serverURL: baseURL) { url in
                NSWorkspace.shared.open(url)
            }
        }
    }

    private func submitCode() {
        let code = pastedCode
        Task { await model.submitPastedCode(code) }
    }

    /// Advanced path (decision E): the legacy service-account token connect.
    private func connectGateway() {
        Task { await model.connectToGateway(baseURL: baseURL, org: org, token: token) }
    }

    private func exploreDemo() {
        // Demo mode: ensure we're on the mock, then sign in with sample identity.
        if model.isHttpMode { model.useMockGateway() }
        Task { await model.signIn(.interactive(email: "demo@studio.example",
                                               filespace: "Studio A — Editorial")) }
    }
}

// MARK: - LabeledField

struct LabeledField: View {
    let title: String
    let systemImage: String
    @Binding var text: String
    var prompt: String? = nil
    var isSecure = false
    /// Optional external focus driver (used to set the form's initial focus).
    var focused: FocusState<Bool>.Binding? = nil

    @FocusState private var localFocus: Bool

    private var isFocused: Bool { focused?.wrappedValue ?? localFocus }

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.sm) {
            Label(title, systemImage: systemImage)
                .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            field
                .textFieldStyle(.plain)
                .padding(Theme.Space.md)
                .background(Theme.surfaceInset, in: RoundedRectangle(cornerRadius: Theme.Radius.sm))
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.Radius.sm)
                        .strokeBorder(isFocused ? Theme.accent : Theme.border,
                                      lineWidth: isFocused ? 1.5 : 1)
                )
                .animation(.easeOut(duration: 0.12), value: isFocused)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(title)
    }

    @ViewBuilder private var field: some View {
        let inner = Group {
            if isSecure { SecureField(prompt ?? title, text: $text) }
            else { TextField(prompt ?? title, text: $text) }
        }
        if let focused {
            inner.focused(focused)
        } else {
            inner.focused($localFocus)
        }
    }
}
