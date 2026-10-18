// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - AppCommand — the menu-bar command vocabulary (pure, testable)
//
// The SwiftUI app exposes a small set of menu-bar commands + keyboard shortcuts
// (Go to a section, act on the selected file, View controls). The *vocabulary*,
// the **keyboard-shortcut mapping**, and the **state-driven enablement** live
// here as pure logic — no SwiftUI — so they can be unit-tested. The scene's
// `.commands { }` renders each case, binds its `shortcut`, and gates it with
// `isEnabled(in:)`; it never re-derives these rules.

// MARK: Shortcut as data

/// A keyboard shortcut expressed as plain data (so it's testable without
/// SwiftUI's `KeyEquivalent`/`EventModifiers`). The view maps `key`/`modifiers`
/// onto the SwiftUI types 1:1.
public struct CommandShortcut: Equatable, Sendable {
    public enum Modifier: String, Sendable, CaseIterable { case command, shift, option, control }
    /// The base key character (e.g. "1", "c", "f", "r"). Empty for non-character
    /// keys that the view supplies directly (none today).
    public let key: Character
    public let modifiers: Set<Modifier>

    public init(_ key: Character, _ modifiers: Set<Modifier> = [.command]) {
        self.key = key
        self.modifiers = modifiers
    }
}

// MARK: Command context (the slice of app state enablement depends on)

/// The minimal app state the command enablement reads. Kept tiny + value-typed so
/// enablement is a pure function of it.
public struct CommandContext: Sendable {
    public let isSignedIn: Bool
    public let section: String          // NavSection.rawValue ("Filespaces", "Cache", …)

    public init(isSignedIn: Bool, section: String) {
        self.isSignedIn = isSignedIn
        self.section = section
    }
}

// MARK: The commands

public enum AppCommand: String, CaseIterable, Identifiable, Sendable {
    // Actions on the current filespace
    case newShare        // open Sharing to mint a link

    // View controls. (Toggle Sidebar is provided by SwiftUI's system View-menu
    // item for NavigationSplitView, so it isn't part of this custom vocabulary.)
    case refresh         // reload the current section

    public var id: String { rawValue }

    /// User-facing menu title.
    public func title(in ctx: CommandContext? = nil) -> String {
        switch self {
        case .newShare:       return "New Share…"
        case .refresh:        return "Refresh"
        }
    }

    /// The SF Symbol glyph (from the canonical IconSet) — the view renders Labels.
    public var glyph: String {
        switch self {
        case .newShare:       return IconSet.sharing
        case .refresh:        return IconSet.activity
        }
    }

    /// The keyboard shortcut, or `nil` for commands that live only in the menu.
    public var shortcut: CommandShortcut? {
        switch self {
        case .refresh:        return CommandShortcut("r", [.command])
        case .newShare:       return nil
        }
    }

    /// Whether the command is enabled given the current app state. View controls
    /// only require being signed in.
    public func isEnabled(in ctx: CommandContext) -> Bool {
        guard ctx.isSignedIn else { return false }
        switch self {
        case .refresh, .newShare:
            return true
        }
    }
}

// MARK: - Login form validation (pure, testable)
//
// The login screen's gateway tab gates Connect on a valid URL + a non-empty
// token; the SSO button needs only a valid URL. The view renders the inline hint
// + enablement straight from these.

public enum LoginValidation {

    /// A non-empty gateway URL that does NOT parse as an http(s) URL with a host.
    /// Empty input is NOT "invalid" (the form stays calm until the user types).
    public static func gatewayURLInvalid(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              scheme == "http" || scheme == "https",
              let host = url.host, !host.isEmpty
        else { return true }
        return false
    }

    /// Whether the gateway "Connect" CTA should be enabled: a usable URL + token.
    public static func canConnectGateway(url: String, token: String) -> Bool {
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        let t = token.trimmingCharacters(in: .whitespacesAndNewlines)
        return !u.isEmpty && !t.isEmpty && !gatewayURLInvalid(u)
    }

    /// Whether the SSO button should be enabled: a usable URL (token comes back
    /// from the browser, so no token is required here).
    public static func canStartSSO(url: String) -> Bool {
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        return !u.isEmpty && !gatewayURLInvalid(u)
    }

    /// The default path (auth-spec §1.2): "Sign in with browser" needs ONLY a
    /// valid server URL — everything else happens on the portal. Same URL-only
    /// rule as SSO; named separately so the two CTAs can diverge later.
    public static func canSignInWithBrowser(url: String) -> Bool {
        canStartSSO(url: url)
    }
}

// MARK: - Go menu (section navigation) — mirrors the sidebar order

/// The Go-menu entries: jump to a section by ⌘1…⌘N in sidebar order. The list of
/// sections is supplied by the app (NavSection) so this stays UI-free; the index
/// drives the digit shortcut.
public enum GoMenu {
    /// The 1-based ⌘-digit shortcut for the Nth section (⌘1 = first). Returns nil
    /// past ⌘9 (macOS digit shortcuts stop at 9).
    public static func shortcut(forIndex index: Int) -> CommandShortcut? {
        guard index >= 0, index < 9 else { return nil }
        let digit = Character("\(index + 1)")
        return CommandShortcut(digit, [.command])
    }
}

// MARK: - PaneAction — contextual window-toolbar actions per section (pure)
//
// The window toolbar's trailing area carries 0–N tasteful, contextual actions for
// the current pane (New Folder in Files, New Link in Sharing, New Snapshot in
// Snapshots, Clear-completed / Pause-all in Activity). The *vocabulary*, the
// per-section set, and the state-driven enablement live here as pure logic so
// they're unit-tested; the toolbar just renders them (title + IconSet glyph) and
// dispatches back to AppModel. The "global Refresh" is rendered separately by the
// toolbar (it maps to the existing AppCommand.refresh).

public enum PaneAction: String, Sendable, CaseIterable, Identifiable {
    case newLink          // Sharing: mint a new share link
    case newSnapshot      // Snapshots: take a manual snapshot
    case clearCompleted   // Activity: drop finished transfers from the list
    case togglePauseAll   // Activity: pause/resume all transfers

    public var id: String { rawValue }

    /// The slice of pane state the toolbar enablement reads. Tiny + value-typed so
    /// `isEnabled(in:)` is a pure function of it.
    public struct Context: Sendable {
        public let isSignedIn: Bool
        public let canEdit: Bool            // member role permits writes
        public let hasCompletedTransfers: Bool
        public let hasActiveTransfers: Bool
        public let transfersPaused: Bool

        public init(isSignedIn: Bool, canEdit: Bool,
                    hasCompletedTransfers: Bool, hasActiveTransfers: Bool,
                    transfersPaused: Bool) {
            self.isSignedIn = isSignedIn
            self.canEdit = canEdit
            self.hasCompletedTransfers = hasCompletedTransfers
            self.hasActiveTransfers = hasActiveTransfers
            self.transfersPaused = transfersPaused
        }
    }

    /// The contextual actions for a section, in toolbar order (leading→trailing).
    /// Sections without a contextual action return `[]` (the toolbar still shows
    /// the global Refresh + the sync pause control).
    public static func actions(for section: String) -> [PaneAction] {
        switch section {
        case "Sharing":   return [.newLink]
        case "Snapshots": return [.newSnapshot]
        case "Activity":  return [.togglePauseAll, .clearCompleted]
        default:          return []
        }
    }

    /// User-facing title. `togglePauseAll` flips by state.
    public func title(in ctx: Context? = nil) -> String {
        switch self {
        case .newLink:        return "New Link"
        case .newSnapshot:    return "New Snapshot"
        case .clearCompleted: return "Clear Completed"
        case .togglePauseAll: return (ctx?.transfersPaused ?? false) ? "Resume All" : "Pause All"
        }
    }

    /// The SF Symbol glyph (from the canonical IconSet).
    public var glyph: String {
        switch self {
        case .newLink:        return IconSet.newLink
        case .newSnapshot:    return IconSet.newSnapshot
        case .clearCompleted: return IconSet.clearCompleted
        case .togglePauseAll: return IconSet.pause
        }
    }

    /// State-driven enablement. Writes require edit permission; the Activity
    /// actions require something to act on.
    public func isEnabled(in ctx: Context) -> Bool {
        guard ctx.isSignedIn else { return false }
        switch self {
        case .newLink, .newSnapshot:
            return ctx.canEdit
        case .clearCompleted:
            return ctx.hasCompletedTransfers
        case .togglePauseAll:
            // Enable when there's an active transfer to pause, or when already
            // paused (so the user can resume).
            return ctx.hasActiveTransfers || ctx.transfersPaused
        }
    }
}
