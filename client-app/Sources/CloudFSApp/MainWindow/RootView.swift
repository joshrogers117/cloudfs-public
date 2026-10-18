// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - RootView
//
// Switches between the login/connect flow (when signed out) and the main
// sidebar window (when connected). Hosts the session-expired banner (auth-spec
// §1.5): when the device session dies, cached data stays visible read-only
// under a non-dismissable "Session expired — sign in again" strip — never a raw
// gateway error.

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            if model.isSignedIn {
                MainWindowView()
                    .safeAreaInset(edge: .top, spacing: 0) {
                        if let error = model.operationError {
                            HStack(alignment: .top, spacing: 12) {
                                Image(systemName: "exclamationmark.triangle").foregroundStyle(Theme.Status.warn)
                                Text(error).font(Theme.Font.caption).foregroundStyle(Theme.textPrimary)
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer(minLength: 0)
                                IconButton("xmark", label: "Dismiss message", role: .badge) { model.operationError = nil }
                            }.padding(16).background(Theme.surface)
                        }
                        if model.isSigningOut {
                            HStack { ProgressView().controlSize(.small); Text(model.isQuitting ? "Finishing uploads before quitting…" : "Finishing uploads before signing out…").font(Theme.Font.caption); Spacer() }
                                .padding(12).background(Theme.surface)
                        }
                        if let notice = model.sessionExpiredNotice {
                            SessionExpiredBar(notice: notice)
                        }
                    }
            } else {
                LoginView()
            }
        }
        .background(Theme.bg)
        .onAppear { model.showMainWindow = { openWindow(id: "main") } }
        .motionAnimation(Theme.Motion.signIn, value: model.isSignedIn)
        // Credential freshness triggers (auth-spec C2): system wake and app
        // re-activation nudge the device-session refresh + daemon-token check.
        .onReceive(NSWorkspace.shared.notificationCenter
            .publisher(for: NSWorkspace.didWakeNotification)) { _ in
            Task { await model.refreshCredentialsAfterWake() }
        }
        .onReceive(NotificationCenter.default
            .publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await model.refreshCredentialsAfterWake() }
        }
        // `cloudfs://connect?server=…` named a DIFFERENT server than the one
        // we're signed into (ONBOARDING.md step 3). Destructive-adjacent
        // (would mean switching servers/signing out), so this is surfaced as
        // an alert, never a silent switch — the user decides.
        .alert("Signed in to a different server",
               isPresented: Binding(
                   get: { model.connectDifferentServerNotice != nil },
                   set: { if !$0 { model.connectDifferentServerNotice = nil } }),
               presenting: model.connectDifferentServerNotice) { _ in
            Button("OK") { model.connectDifferentServerNotice = nil }
        } message: { notice in
            Text("This Mac is signed in to “\(notice.currentHost)”. The link you opened points to “\(notice.requestedHost)”. Sign out first if you want to connect to that server instead.")
        }
    }
}

// MARK: - SessionExpiredBar (auth-spec §1.5)
//
// Non-dismissable banner over the main window. The only affordance is
// [Sign in again], which returns to the login screen with the server URL
// preserved (the dead credentials are cleared on the way).

private struct SessionExpiredBar: View {
    @Environment(AppModel.self) private var model
    let notice: String

    var body: some View {
        HStack(alignment: .center, spacing: Theme.Space.md) {
            Image(systemName: IconSet.errorOutline)
                .foregroundStyle(Theme.Status.warn)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text("Session expired")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textPrimary)
                Text(notice)
                    .font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
            }
            Spacer(minLength: Theme.Space.md)
            Button("Sign in again") {
                Task { await model.signInAgainAfterSessionExpiry() }
            }
            .cfButton(.primary, size: .small)
        }
        .padding(.horizontal, Theme.Space.xl)
        .padding(.vertical, Theme.Space.md)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Theme.surface)
        .overlay(alignment: .bottom) {
            Rectangle().fill(Theme.Status.warn.opacity(0.6))
                .frame(height: Theme.Metric.hairlineWidth)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Session expired. \(notice) Sign in again.")
    }
}

// MARK: - MainWindowView (sidebar + detail)

struct MainWindowView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("cloudfs.sidebarVisible") private var sidebarVisible = true

    var body: some View {
        VStack(spacing: 0) {
            WorkspaceHeader(sidebarVisible: $sidebarVisible)
            Rectangle().fill(Theme.divider).frame(height: 1)
            HStack(spacing: 0) {
                WorkspaceRail()
                Rectangle().fill(Theme.divider).frame(width: 1)
                if sidebarVisible {
                    SidebarView().frame(width: Theme.sidebarWidth)
                }
                DetailView(section: model.canAccess(model.section) ? model.section : .dashboard)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .background(Theme.bg)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
                    .overlay(RoundedRectangle(cornerRadius: 16).strokeBorder(Theme.border))
                    .padding(.vertical, 8)
                    .padding(.trailing, 8)
                    .padding(.leading, sidebarVisible ? 0 : 8)
                    .id(model.section)
            }
        }
        .background(Theme.canvas)
        .navigationTitle(model.settings.displayProductName)
        .sheet(isPresented: Binding(get: { model.isCreatingFilespace && model.canCreateFilespaces }, set: { model.isCreatingFilespace = $0 })) {
            CreateFilespaceView()
        }
        .sheet(isPresented: Binding(
            get: { model.onboarding.isPresented },
            set: { model.onboarding.isPresented = $0 })) {
            OnboardingChecklistView()
        }
    }
}

/// The narrow workspace strip stays visible when the navigation is collapsed.
private struct WorkspaceRail: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 16) {
            Button { model.section = .filespaces } label: {
                Text(String(model.workspaceDisplayName.prefix(2)).uppercased())
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.onAccent)
                    .frame(width: 34, height: 34)
                    .background(Theme.accent, in: RoundedRectangle(cornerRadius: 9))
                    .padding(3)
                    .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.textSecondary, lineWidth: 1.5))
            }
            .buttonStyle(.plain)
            .help("\(model.workspaceDisplayName) workspace")
            .accessibilityLabel("\(model.workspaceDisplayName) workspace dashboard")
            Spacer()
            BrandMark(size: 25).padding(.bottom, 20)
        }
        .padding(.top, 18)
        .frame(width: Theme.Metric.workspaceRailWidth)
    }
}

/// A full-width navigation header matches the workspace and filespace hierarchy.
private struct WorkspaceHeader: View {
    @Environment(AppModel.self) private var model
    @Binding var sidebarVisible: Bool

    private var title: String {
        switch model.section {
        case .dashboard: return model.selectedFilespace == nil ? "Workspace dashboard" : "Filespace dashboard"
        case .filespaces: return "Workspace dashboard"
        case .members: return model.members.tab == .access ? "Access and permissions" : model.members.tab.rawValue
        case .audit: return "History"
        case .sharing: return "Guest links"
        default: return model.section.rawValue
        }
    }

    var body: some View {
        HStack(spacing: 14) {
            IconButton("sidebar.left", label: sidebarVisible ? "Hide sidebar" : "Show sidebar") {
                sidebarVisible.toggle()
            }
            Text(title).font(.system(size: 16, weight: .semibold))
                .foregroundStyle(Theme.textPrimary).lineLimit(1)
            Spacer(minLength: 12)
            ForEach(PaneAction.actions(for: model.section.rawValue).filter { model.isVisible($0) && $0 != .newLink && $0 != .newSnapshot }) { action in
                IconButton(action.glyph, label: action.title(in: model.paneActionContext)) {
                    model.run(action)
                }.disabled(!model.isEnabled(action))
            }
            IconButton(IconSet.refresh, label: "Refresh") { model.run(.refresh) }
                .disabled(!model.isSignedIn)
            if let fs = model.selectedFilespace, !fs.mountPath.isEmpty, model.isHttpMode {
                IconButton(fs.connection == .paused ? IconSet.play : IconSet.pause,
                           label: fs.connection == .paused ? "Resume sync" : "Pause sync") {
                    Task { await model.togglePauseSync() }
                }
                .keyboardShortcut("p", modifiers: [.command, .shift])
            }
            if model.isHttpMode, let url = model.consoleLinks.url(.root) {
                Button { NSWorkspace.shared.open(url) } label: {
                    Label("Web console", systemImage: "arrow.up.right.square")
                        .font(.system(size: 13, weight: .medium))
                }
                .buttonStyle(.plain).foregroundStyle(Theme.textSecondary)
                .padding(.horizontal, 8)
            }
            Menu {
                Text(model.accountEmail ?? (model.isHttpMode ? "Signed in" : "Demo workspace"))
                Text(model.isHttpMode ? model.members.currentRole.displayName : "Sample data only")
                Divider()
                Button("Preferences…", systemImage: IconSet.preferences) { model.section = .preferences }
                if model.isHttpMode, let url = model.consoleLinks.url(.devices) {
                    Button("My devices…", systemImage: IconSet.devices) { NSWorkspace.shared.open(url) }
                }
                Divider()
                Button(model.isHttpMode ? "Sign out" : "Exit demo", systemImage: IconSet.signOut) {
                    Task { await model.signOut() }
                }.disabled(model.isSigningOut)
            } label: {
                Image(systemName: "person.crop.circle.fill")
                    .font(.system(size: 28))
                    .foregroundStyle(Theme.accent)
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 32)
            .accessibilityLabel("Account menu, \(model.accountEmail ?? "CloudFS")")
        }
        .padding(.horizontal, 20)
        .frame(height: Theme.Metric.appHeaderHeight)
    }
}

// MARK: - Detail router

struct DetailView: View {
    let section: NavSection

    var body: some View {
        switch section {
        case .dashboard:   DashboardView()
        case .filespaces:  FilespacesView()
        case .pinned:      PinnedItemsView()   // NEW (WS2)
        case .activity:    LiveActivityView()  // LIVE feed (WS3)
        case .audit:       AuditLogView()      // NEW (WS3) — historical audit log
        case .snapshots:   SnapshotsView()
        case .sharing:     SharingView()
        case .members:     MembersView()       // NEW — org users + per-folder ACL (admin-gated)
        case .cache:       CacheSettingsView()
        case .preferences: PreferencesView()
        }
    }
}
