// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - AppCommands — menu-bar commands + keyboard shortcuts
//
// Four custom menus wired to AppModel, with state-driven enablement:
//   • Account — Preferences + a discoverable Sign Out (⇧⌘Q).
//   • Go      — jump to each sidebar section (⌘1…⌘N, in sidebar order) + Prefs.
//   • Actions — New Share.
//   • View    — Refresh (⌘R).
//
// The vocabulary, shortcut mapping, and enablement are the pure, tested
// `AppCommand`/`GoMenu` in CloudFSKit; this just renders them. We deliberately do
// NOT add a custom "Toggle Sidebar" shortcut — SwiftUI already provides the
// system item (⌃⌘S) for NavigationSplitView; our menu item drives the same state.

struct AppCommands: Commands {
    @Bindable var model: AppModel

    var body: some Commands {
        // Account — a discoverable Sign Out (the user couldn't find it in-window),
        // returning cleanly to the Login screen. ⇧⌘Q so it doesn't clash with the
        // system ⌘Q Quit.
        CommandMenu("Account") {
            Button("Preferences…") { navigate(to: .preferences) }
                .keyboardShortcut(",", modifiers: .command)
                .disabled(!model.isSignedIn)
            Divider()
            Button("Sign Out") { Task { await model.signOut() } }
                .keyboardShortcut("q", modifiers: [.command, .shift])
                .disabled(!model.isSignedIn)
        }

        // Go — section navigation, mirrors the sidebar order (⌘1…⌘N).
        CommandMenu("Go") {
            ForEach(Array(NavSection.allCases.enumerated()).filter { model.canAccess($0.element) }, id: \.element) { index, section in
                Button {
                    navigate(to: section)
                } label: {
                    Label(section.rawValue, systemImage: section.symbol)
                }
                .modifier(ShortcutModifier(GoMenu.shortcut(forIndex: index)))
                .disabled(!model.isSignedIn)
            }
        }

        // Actions — operate on the current filespace.
        CommandMenu("Actions") {
            if model.canManageGuestLinks { commandButton(.newShare) }
        }

        // View — refresh, added after SwiftUI's system "Toggle Sidebar" item
        // (which NavigationSplitView already provides with ⌃⌘S, so we don't
        // re-add a Toggle Sidebar entry and clash with it).
        CommandGroup(after: .sidebar) {
            Divider()
            commandButton(.refresh)
        }
    }

    private func navigate(to section: NavSection) {
        model.showMainWindow?()
        model.go(to: section)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Render one AppCommand as a Button: title (flips for Pin/Unpin), glyph,
    /// shortcut, and state-driven enablement — all from the pure model.
    @ViewBuilder
    private func commandButton(_ command: AppCommand) -> some View {
        Button {
            model.showMainWindow?()
            model.run(command)
        } label: {
            Label(command.title(in: model.commandContext), systemImage: command.glyph)
        }
        .modifier(ShortcutModifier(command.shortcut))
        .disabled(!model.isEnabled(command))
    }
}

// MARK: - ShortcutModifier — apply a CommandShortcut (or nothing) to a view

/// Maps the pure `CommandShortcut` data onto SwiftUI's `keyboardShortcut`; a `nil`
/// shortcut leaves the item menu-only.
private struct ShortcutModifier: ViewModifier {
    let shortcut: CommandShortcut?
    init(_ shortcut: CommandShortcut?) { self.shortcut = shortcut }

    func body(content: Content) -> some View {
        if let s = shortcut {
            content.keyboardShortcut(KeyEquivalent(s.key), modifiers: s.modifiers.eventModifiers)
        } else {
            content
        }
    }
}

private extension Set<CommandShortcut.Modifier> {
    /// Map the data modifiers onto SwiftUI's `EventModifiers`.
    var eventModifiers: EventModifiers {
        var m: EventModifiers = []
        if contains(.command) { m.insert(.command) }
        if contains(.shift)   { m.insert(.shift) }
        if contains(.option)  { m.insert(.option) }
        if contains(.control) { m.insert(.control) }
        return m
    }
}
