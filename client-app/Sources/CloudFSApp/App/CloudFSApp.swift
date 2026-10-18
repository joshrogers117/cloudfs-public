// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - App entry
//
// Two scenes mirror the real client topology (docs §1.1 component (c)):
//   • Window           — the main admin/browser window (sidebar nav).
//   • MenuBarExtra      — the always-on NSStatusItem agent surfacing aggregate
//                         status, cache gauge, pause/resume, recent activity.
//
// The native distribution embeds the SMB streaming engine and Finder extension.
// CLOUDFS_DEMO=1 is an explicit offline UI demonstration, separate from sign-in.
//
// APPEARANCE DECISION: cloud-fs is **locked to dark** (`.preferredColorScheme
// (.dark)` on every scene). The brand IS the dark aesthetic, and the
// semantic color tokens are tuned for dark layers; a light variant would need a
// parallel token set for no product benefit. Documented in UI-POLISH.md.

// MARK: - App delegate
//
// Guarantees the app is a **regular**, foregrounded app with a Dock icon and a
// front window, even when launched as a raw `swift run` executable (which has no
// bundle and otherwise defaults to a background/accessory activation policy and
// can exit before a window appears). When launched as `CloudFSApp.app`, this is
// belt-and-suspenders alongside the Info.plist.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    var prepareToQuit: (() async -> Bool)?
    private var terminationPending = false

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        guard let prepareToQuit else { return .terminateNow }
        guard !terminationPending else { return .terminateLater }
        terminationPending = true
        Task {
            let ready = await prepareToQuit()
            terminationPending = false
            sender.reply(toApplicationShouldTerminate: ready)
        }
        return .terminateLater
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    // The background agent and credential renewal outlive the dashboard window.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Closing the dashboard must keep mount status and credential refresh alive.
        false
    }
}

@main
struct CloudFSApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()
    // AppStorage used directly as MenuBarExtra's insertion binding produces a
    // menu invalidation loop on macOS 27. Keep scene identity in State and accept
    // only actual preference changes from the settings view.
    @State private var showMenuBar = UserDefaults.standard.object(forKey: "cloudfs.showMenuBar") as? Bool ?? true

    var body: some Scene {
        Window("CloudFS", id: "main") {
            RootView()
                .environment(model)
                .frame(minWidth: Theme.Metric.windowMinWidth,
                       minHeight: Theme.Metric.windowMinHeight)
                .preferredColorScheme(.dark)   // locked dark — on-brand
                // Window-level brand tint: native controls (segmented pickers,
                // toggles, progress, links) inherit purple instead of the
                // system-blue default. CFButton roles keep their own explicit
                // accent/onAccent pins; local `.tint(...)` overrides still win.
                .tint(Theme.accent)
                .task {
                    // Mock mode auto-bootstraps so the app runs offline; Http mode
                    // attempts a real connect with the Keychain token, else shows
                    // the login/connection-settings screen.
                    if !model.isSignedIn { await model.bootstrap() }
                }
                .onAppear {
                    appDelegate.prepareToQuit = { await model.prepareToQuit() }
                    // Ensure the window is front-most on launch (covers `open` and
                    // re-activation from the Dock / menu bar).
                    NSApp.setActivationPolicy(.regular)
                    NSApp.activate(ignoringOtherApps: true)
                }
                .onReceive(NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification)
                    .receive(on: RunLoop.main)) { _ in
                    let visible = UserDefaults.standard.object(forKey: "cloudfs.showMenuBar") as? Bool ?? true
                    if showMenuBar != visible { showMenuBar = visible }
                }
                // cloudfs:// URLs handle authentication and filespace/file links.
                .onOpenURL { url in _ = model.handleIncomingURL(url) }
        }
        .defaultSize(width: 1160, height: 780)
        .windowResizability(.contentMinSize)
        .windowStyle(.titleBar)
        .commands { AppCommands(model: model) }

        MenuBarExtra(isInserted: $showMenuBar) {
            MenuBarView()
                .environment(model)
                .frame(width: Theme.Metric.menuWidth)
                .preferredColorScheme(.dark)   // locked dark — on-brand
                .tint(Theme.accent)            // brand tint (separate scene root)
        } label: {
            // The drive mark as a TEMPLATE image (status bars tint these
            // for highlight/dark-mode; arbitrary views don't render reliably here).
            Image(nsImage: BrandMark.statusItemImage())
        }
        .menuBarExtraStyle(.window)
    }
}
