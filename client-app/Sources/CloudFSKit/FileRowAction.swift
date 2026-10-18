// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - FileRowAction — the file-row context-menu vocabulary (pure, testable)
//
// The right-click / "…" actions for a Files-browser row. This is
// pure logic (no SwiftUI) so the action set + per-state enablement is unit
// tested; the view layer renders each case with its IconSet glyph and wires it to
// the matching AppModel call.

public enum FileRowAction: String, Sendable, CaseIterable, Identifiable {
    case pin           // Pin to cache (keep local)
    case unpin         // Remove pin
    case prefetch      // Download now (stays evictable)
    case rename        // Inline rename
    case copyLink      // Copy cloudfs:// link
    case revealInFinder// Reveal at the mounted path
    case evict         // Free cache space
    case getInfo       // Show details

    public var id: String { rawValue }

    /// User-facing menu title.
    public var title: String {
        switch self {
        case .pin:            return "Pin to Cache"
        case .unpin:          return "Remove Pin"
        case .prefetch:       return "Prefetch"
        case .rename:         return "Rename"
        case .copyLink:       return "Copy Link"
        case .revealInFinder: return "Reveal in Finder"
        case .evict:          return "Evict from Cache"
        case .getInfo:        return "Get Info"
        }
    }

    /// The SF Symbol glyph for this action (from the canonical IconSet).
    public var glyph: String {
        switch self {
        case .pin:            return IconSet.pin
        case .unpin:          return IconSet.unpin
        case .prefetch:       return IconSet.prefetch
        case .rename:         return IconSet.rename
        case .copyLink:       return IconSet.copyLink
        case .revealInFinder: return IconSet.revealInFinder
        case .evict:          return IconSet.evict
        case .getInfo:        return IconSet.getInfo
        }
    }

    /// True when this action makes sense as a *destructive* role (UI styling).
    public var isDestructive: Bool { self == .evict }

    /// Whether a divider should precede this action in the rendered menu (so the
    /// view doesn't hardcode menu structure).
    public var startsNewGroup: Bool {
        switch self {
        case .rename:   return true   // group 2: item management
        case .copyLink: return true   // group 3: sharing / navigation
        case .evict:    return true   // group 4: cache / info
        default:        return false
        }
    }
}

// MARK: - Menu construction + enablement (state-driven)

public enum FileRowMenu {

    /// The ordered actions to show for a node, with each marked enabled/disabled
    /// by the node's current materialization state. Pin↔Unpin are mutually
    /// exclusive (only the relevant one appears).
    public static func actions(for node: FileNode) -> [(action: FileRowAction, enabled: Bool)] {
        let isPinned = node.state == .pinned
        let isLocal  = node.state == .downloaded || node.state == .pinned
        let isUploading = node.state == .uploading

        // Pin vs Unpin: show exactly one based on state.
        let pinPair: FileRowAction = isPinned ? .unpin : .pin

        return [
            // Cache residency group
            (pinPair, true),
            // Prefetch: only useful when the item isn't already fully local.
            (.prefetch, !isLocal),
            // Item management — rename is blocked while another editor holds the
            // write-lease (can't rename a locked item).
            (.rename, node.lockedBy == nil),
            // Sharing / navigation group (always available)
            (.copyLink, true),
            (.revealInFinder, true),
            // Cache / info group
            // Evict: only when there's something cached to drop, and not mid-upload
            // (dirty/not-yet-uploaded items are non-evictable — client doc §2.8).
            (.evict, isLocal && !isUploading),
            (.getInfo, true),
        ]
    }

    /// Whether a given action is enabled for the node (convenience for tests/UI).
    public static func isEnabled(_ action: FileRowAction, for node: FileNode) -> Bool {
        actions(for: node).first { $0.action == action }?.enabled ?? false
    }

    /// Whether a given action is *present* in the menu for the node (Pin/Unpin
    /// are mutually exclusive, so only one is present).
    public static func isPresent(_ action: FileRowAction, for node: FileNode) -> Bool {
        actions(for: node).contains { $0.action == action }
    }
}
