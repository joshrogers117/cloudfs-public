// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import ServiceManagement
import CloudFSKit

// MARK: - PreferencesView
//
// A real macOS settings surface: grouped cards, label + control rows, help text,
// status indicators. Preferences are persisted; launch at login uses macOS
// Service Management and reports approval or registration failures.

struct PreferencesView: View {
    @Environment(AppModel.self) private var model

    @State private var launchAtLogin = false
    @State private var loginItemError: String?
    @State private var loginItemApproval = false
    @State private var showFinderBadges = true
    @AppStorage("cloudfs.showMenuBar") private var showMenuBar = true

    var body: some View {
        VStack(spacing: 0) {
            PaneHeader(title: "Preferences")
            ScrollView {
                VStack(alignment: .leading, spacing: Theme.Space.xl) {
                    generalCard
                    connectionCard
                    engineCard
                    accountCard
                    footnote
                }
                .frame(maxWidth: 780, alignment: .leading)
                .padding(Theme.Space.xxl)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .background(Theme.bg)
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            refreshLoginItemState()
        }
    }

    // MARK: General

    private var generalCard: some View {
        Card("General") {
            SettingToggle("Launch at login",
                          help: "Start CloudFS automatically when you log in.",
                          isOn: Binding(get: { launchAtLogin }, set: setLaunchAtLogin))
                .onAppear { refreshLoginItemState() }
            if let loginItemError { Text(loginItemError).font(Theme.Font.micro).foregroundStyle(Theme.Status.error) }
            if loginItemApproval {
                Button("Allow in Login Items…") { SMAppService.openSystemSettingsLoginItems() }
                    .cfButton(.secondary, size: .small)
            }
            Divider().overlay(Theme.divider)
            SettingToggle("Show cloud badges in Finder",
                          help: "Overlay pin state on file icons (Finder extension).",
                          isOn: $showFinderBadges)
                .onAppear {
                    showFinderBadges = UserDefaults(suiteName: EngineFactory.appGroupIdentifier)?
                        .object(forKey: "cloudfs.finderBadges") as? Bool ?? true
                }
                .onChange(of: showFinderBadges) { _, on in
                    // M8 — shared flag the sandboxed Finder Sync appex reads per badge query.
                    UserDefaults(suiteName: EngineFactory.appGroupIdentifier)?
                        .set(on, forKey: "cloudfs.finderBadges")
                }
            Divider().overlay(Theme.divider)
            SettingToggle("Show menu-bar status item",
                          help: "Keep CloudFS status in the menu bar.",
                          isOn: $showMenuBar)
        }
    }

    private func refreshLoginItemState() {
        launchAtLogin = SMAppService.mainApp.status == .enabled
        loginItemApproval = SMAppService.mainApp.status == .requiresApproval
    }

    private func setLaunchAtLogin(_ enabled: Bool) {
        loginItemError = nil
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch { loginItemError = "Couldn't change launch at login. \(error.localizedDescription)" }
        refreshLoginItemState()
    }

    // MARK: Connection

    private var connectionCard: some View {
        Card("Connection") {
            statusLine(ok: model.isHttpMode, text: model.mode.label,
                       a11y: model.isHttpMode ? "Connected to gateway" : "Offline demo mode")
            if model.isHttpMode {
                KeyValueRow(key: "Workspace", value: model.settings.org.isEmpty ? "—" : model.settings.org)
                KeyValueRow(key: "Sign-in",
                            value: model.settings.authMethod == .device
                                ? "This Mac is securely signed in"
                                : "Service account")
                helpText("Your account connects securely to this server. File data streams directly from your workspace storage.")
            } else {
                // Honest copy: there's no separate in-app "connect a gateway"
                // flow that keeps this session alive — switching to a real
                // server means signing out to the login screen first, so say
                // that plainly instead of a euphemistic label that silently
                // signed you out.
                helpText("You are exploring a demonstration workspace. Sign out to connect to your team’s server.")
                Button("Sign out to switch server…") { Task { await model.signOut() } }
                    .cfButton(.secondary, size: .small)
            }
        }
    }

    // MARK: Local engine

    private var engineCard: some View {
        Card("Background service") {
            statusLine(ok: model.isEngineConnected,
                       text: model.isEngineConnected ? "Service configured" : "Service unavailable",
                       a11y: model.isEngineConnected ? "Background service configured" : "Background service unavailable")
            if model.isEngineConnected {
                helpText("CloudFS manages your mounted filespaces, local cache and file transfers in the background. Check the filespace dashboard for connection and upload status.")
            } else {
                helpText(model.isHttpMode
                    ? "The background service is not available. Reopen CloudFS to start it, then connect your filespace."
                    : "The demonstration workspace does not mount files or run transfers. Sign in to your team’s server to connect a filespace.")
            }
        }
    }

    // MARK: Account

    private var accountCard: some View {
        Card("Account") {
            if let fs = model.selectedFilespace {
                KeyValueRow(key: "Filespace", value: fs.name)
                KeyValueRow(key: "Role", value: fs.displayRole(orgRole: model.isHttpMode ? model.members.currentRole : nil).rawValue)
                KeyValueRow(key: "Storage backend", value: fs.storageBackend)
                KeyValueRow(key: "Region", value: fs.region)
            }
            Button("Sign Out", role: .destructive) { Task { await model.signOut() } }
                .cfButton(.destructive, size: .small).padding(.top, Theme.Space.xs)
        }
    }

    private var footnote: some View {
        Text("Your preferences stay on this Mac. Account credentials are stored securely in Keychain.")
            .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
    }

    // MARK: Helpers

    private func statusLine(ok: Bool, text: String, a11y: String) -> some View {
        HStack(spacing: Theme.Space.md) {
            StatusDot(color: ok ? Theme.Status.ok : Theme.Status.paused)
            Text(text).font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
            Spacer()
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(a11y)
    }

    private func helpText(_ s: String) -> some View {
        Text(s).font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

// MARK: - SettingToggle — label + help text on the left, switch on the right

private struct SettingToggle: View {
    let title: String
    let help: String
    @Binding var isOn: Bool
    init(_ title: String, help: String, isOn: Binding<Bool>) {
        self.title = title; self.help = help; self._isOn = isOn
    }
    var body: some View {
        Toggle(isOn: $isOn) {
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(title).font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                Text(help).font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .toggleStyle(.switch).tint(Theme.accent)
        .accessibilityHint(help)
    }
}
