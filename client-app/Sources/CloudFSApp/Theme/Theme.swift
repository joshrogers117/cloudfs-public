// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - Theme — the single source of truth
//
// Visual language: dark, compact, monochrome SF Symbols, small
// colored status dots, "files look local." Everything visual flows from the
// tokens below so the whole app tunes in one place.
//
//   Theme.Space   — 4-pt spacing scale (xxs…xxl)
//   Theme.Font    — semantic type roles (title/headline/body/callout/caption/mono)
//   Theme.Radius  — corner radii (sm/md/lg/pill)
//   Theme.Metric  — control / row / sidebar metrics
//   color tokens  — background layers, surfaces, text, accent, borders, status
//
// Legacy flat names (windowBackground, primaryText, cornerRadius, …) are kept as
// aliases so existing call sites keep compiling while views migrate to tokens.

enum Theme {

    // MARK: Spacing scale (4-pt rhythm)

    enum Space {
        static let xxs: CGFloat = 2
        static let xs:  CGFloat = 4
        static let sm:  CGFloat = 6
        static let md:  CGFloat = 8
        static let lg:  CGFloat = 12
        static let xl:  CGFloat = 16
        static let xxl: CGFloat = 20
        static let xxxl: CGFloat = 24
    }

    // MARK: Corner radii

    enum Radius {
        static let xs: CGFloat = 2   // tiny chips / legend swatches
        static let sm: CGFloat = 8
        static let md: CGFloat = 12
        static let lg: CGFloat = 12
        static let pill: CGFloat = 999
    }

    // MARK: Control / layout metrics

    enum Metric {
        static let sidebarWidth: CGFloat = 264
        static let workspaceRailWidth: CGFloat = 64
        static let appHeaderHeight: CGFloat = 54
        static let rowHeight: CGFloat = 38
        static let menuWidth: CGFloat = 320
        static let windowMinWidth: CGFloat = 960
        // Content panes and sign-in scroll. Keep the window itself within small
        // displays so bottom actions remain reachable at 1024 × 640 points.
        static let windowMinHeight: CGFloat = 560
        /// Fixed Files-row columns (kept consistent so rows don't shift).
        static let disclosureWidth: CGFloat = 12
        static let leadingIconWidth: CGFloat = 18
        static let trailingBadgeWidth: CGFloat = 22
        static let sizeColumnWidth: CGFloat = 56
        /// Secondary metadata column (size · modified / item count) — wide enough
        /// for "4.2 GB · 2d ago" so it reads as a real file-list column.
        static let metadataColumnWidth: CGFloat = 130
        static let indentPerLevel: CGFloat = 16
        static let hairlineWidth: CGFloat = 1
        /// Gauges / progress.
        static let gaugeHeight: CGFloat = 16
        static let gaugeHeightSmall: CGFloat = 8
        static let progressBarHeight: CGFloat = 5
        static let markerWidth: CGFloat = 1.5
        static let legendSwatch: CGFloat = 10
        /// Avatars / leading affordances.
        static let avatar: CGFloat = 26
        static let filespaceIconColumn: CGFloat = 34
        /// Active-section indicator bar in the sidebar.
        static let activeBarWidth: CGFloat = 3
        /// Snapshot-list min/ideal column.
        static let snapshotListMin: CGFloat = 260
        static let snapshotListIdeal: CGFloat = 300
        /// Brand mark in the login hero / status item.
        static let heroMark: CGFloat = 44
    }

    // MARK: Iconography (consistent SF Symbol size + weight per role)
    //
    // Glyph NAMES live in `CloudFSKit.IconSet` (testable). `Theme.Icon` pairs a
    // name with a role so weight/scale stay consistent. Use the `Icon(_:role:)`
    // view (below) instead of bare `Image(systemName:)` at call sites.

    enum IconRole {
        case nav        // sidebar / section glyphs
        case badge      // small trailing status glyph
        case rowLeading // file/folder leading glyph
        case action     // toolbar / inline action button
        case hero       // large empty-state / brand glyph

        var font: SwiftUI.Font {
            switch self {
            case .nav:        return .body
            case .badge:      return .caption
            case .rowLeading: return .body
            case .action:     return .title3
            case .hero:       return .system(size: 38, weight: .light)
            }
        }
    }

    // MARK: Typography (semantic roles)

    enum Font {
        /// Brand wordmark / hero (login). `.system(size:)` scales with Dynamic Type.
        static let hero = SwiftUI.Font.system(size: 30, weight: .semibold)
        /// Pane titles.
        static let title = SwiftUI.Font.title2.weight(.semibold)
        /// Card / row emphasis, toolbar.
        static let headline = SwiftUI.Font.headline
        /// Primary row text.
        static let body = SwiftUI.Font.callout
        /// Secondary / labels.
        static let caption = SwiftUI.Font.caption
        /// Micro labels, section captions, hints.
        static let micro = SwiftUI.Font.caption2
        /// All-caps section labels (cards / menu sections).
        static let sectionLabel = SwiftUI.Font.caption2.weight(.semibold)
        /// Large centered glyph for empty/error panes.
        static let emptyGlyph = SwiftUI.Font.system(size: 40, weight: .light)
        /// Monospaced numerics (sizes, rates, percentages) — no layout jitter.
        static let mono = SwiftUI.Font.caption.monospacedDigit()
        static let monoMicro = SwiftUI.Font.caption2.monospacedDigit()
        /// Prominent monospaced readout (e.g. the cache-size value).
        static let monoTitle = SwiftUI.Font.title3.monospacedDigit().weight(.semibold)
        /// Monospaced path / code-like text.
        static let monoPath = SwiftUI.Font.caption.monospaced()
    }

    // MARK: Color — background layers (dark, low-chroma)

    // Restrained, violet-tinted neutrals. Shared with the web console.
    static let canvas = Color(red: 0.094, green: 0.090, blue: 0.114)
    static let bg = Color(red: 0.133, green: 0.129, blue: 0.141)
    static let bgSidebar = canvas
    static let surface = Color(red: 0.165, green: 0.161, blue: 0.176)
    static let surfaceInset = Color(red: 0.149, green: 0.145, blue: 0.165)
    static let textPrimary = Color(red: 0.949, green: 0.945, blue: 0.957)
    static let textSecondary = Color(red: 0.729, green: 0.718, blue: 0.773)
    static let textTertiary = Color(red: 0.651, green: 0.639, blue: 0.698)
    static let accent = Color(red: 0.631, green: 0.565, blue: 1.0)
    static let primaryAction = Color(red: 0.949, green: 0.945, blue: 0.957)
    // Post-onboarding action color, approximately web oklch(0.90 0.20 125).
    static let operationalAction = Color(red: 0.753, green: 0.957, blue: 0.281)
    static let onAccent = Color(red: 0.098, green: 0.086, blue: 0.133)
    static let info = Color(red: 0.427, green: 0.710, blue: 0.949)
    static let divider = Color(red: 0.247, green: 0.239, blue: 0.298)
    static let border = Color(red: 0.267, green: 0.255, blue: 0.322)
    static let hover = textPrimary.opacity(0.055)
    static let selection = Color(red: 0.247, green: 0.231, blue: 0.325)
    static let markerLine = textPrimary.opacity(0.6)

    enum Status {
        static let ok = Color(red: 0.525, green: 0.875, blue: 0.576)
        static let busy = Theme.info
        static let paused = Color(red: 0.651, green: 0.663, blue: 0.761)
        static let warn = Color(red: 0.988, green: 0.710, blue: 0.361)
        static let error = Color(red: 1.0, green: 0.541, blue: 0.576)
        static let idle = Theme.textTertiary
    }

    // MARK: Motion — restrained, consistent transitions (easeInOut, short)
    //
    // One place for durations + named curves so motion stays subtle and uniform.
    // Pair with `.motionAnimation(_:value:)` below, which collapses to an instant
    // change when Reduce Motion is on.

    enum Motion {
        /// Hover / press feedback — barely there.
        static let quick    = 0.12
        /// The default for most UI transitions (section, list, selection).
        static let standard = 0.20
        /// Slightly longer for larger swaps (sign-in/out, value fills).
        static let emphasis = 0.30

        static let hover: Animation   = .easeOut(duration: quick)
        static let section: Animation = .easeOut(duration: standard)
        static let list: Animation    = .easeOut(duration: standard)
        static let signIn: Animation  = .easeOut(duration: emphasis)
        static let value: Animation   = .easeOut(duration: emphasis)
        /// Drop-target highlight appear/disappear — snappy but smooth.
        static let drop: Animation    = .easeOut(duration: quick)
    }

    // MARK: - Legacy aliases (keep existing call sites compiling)

    static let windowBackground  = bg
    static let sidebarBackground = bgSidebar
    static let panelBackground   = surface
    static let rowHover          = hover
    static let rowSelected       = selection
    static let hairline          = divider
    static let primaryText       = textPrimary
    static let secondaryText     = textSecondary
    static let tertiaryText      = textTertiary
    static let sidebarWidth: CGFloat = Metric.sidebarWidth
    static let cornerRadius: CGFloat = Radius.md
    static let rowHeight: CGFloat = Metric.rowHeight
}

// MARK: - Reusable view styling

extension View {
    /// Quiet inset surface for a related group of controls or readings.
    func themedCard(padding: CGFloat = Theme.Space.xl,
                    radius: CGFloat = Theme.Radius.md) -> some View {
        self
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: radius))
    }
}

// MARK: - Button styles (one consistent vocabulary)
//
// Five roles cover the whole app:
//   .cfPrimary     — the single prominent action per surface (Connect, etc.)
//   .operational   — the prominent action in the signed-in workspace
//   .cfSecondary   — bordered alternative actions (Relocate…, Restore, Copy)
//   .cfSubtle      — borderless low-emphasis actions inside cards
//   .cfDestructive — bordered destructive (Sign Out, Revoke)
// Each is a thin wrapper over the system styles so it inherits native focus
// rings / press states, but pins tint + control size so call sites stop
// re-specifying them.

enum CFButton {
    case primary, operational, secondary, subtle, destructive
}

/// Explicit fills stay legible when the window is inactive, including on macOS 27.
struct CapsuleActionStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.isFocused) private var isFocused
    var size: ControlSize = .regular
    var fill: Color = Theme.primaryAction
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: size == .small || size == .mini ? 11 : 13, weight: .semibold))
            .foregroundStyle(Theme.onAccent)
            .padding(.horizontal, size == .small || size == .mini ? 12 : 18)
            .frame(minHeight: size == .large || size == .extraLarge ? 40 : size == .small || size == .mini ? 28 : 34)
            .background(fill, in: Capsule())
            .overlay(Capsule().strokeBorder(isFocused ? Theme.accent : .clear, lineWidth: 2))
            .opacity(isEnabled ? (configuration.isPressed ? 0.78 : 1) : 0.45)
    }
}

private struct CFButtonModifier: ViewModifier {
    @Environment(\.isEnabled) private var isEnabled
    let kind: CFButton
    var size: ControlSize = .regular
    func body(content: Content) -> some View {
        switch kind {
        case .primary:
            content.buttonStyle(CapsuleActionStyle(size: size))
        case .operational:
            content.buttonStyle(CapsuleActionStyle(size: size, fill: Theme.operationalAction))
        case .secondary:
            content.buttonStyle(.bordered).buttonBorderShape(.capsule).controlSize(size)
        case .subtle:
            content.buttonStyle(.borderless).controlSize(size)
                .foregroundStyle(isEnabled ? Theme.accent : Theme.textTertiary.opacity(0.65))
        case .destructive:
            content.buttonStyle(.bordered).buttonBorderShape(.capsule).controlSize(size).tint(Theme.Status.error)
        }
    }
}

extension View {
    /// Apply a cloud-fs button role (consistent tint + control size).
    func cfButton(_ kind: CFButton, size: ControlSize = .regular) -> some View {
        modifier(CFButtonModifier(kind: kind, size: size))
    }
}

/// An all-caps section label used in cards and the menu bar.
struct SectionLabel: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased())
            .font(Theme.Font.sectionLabel)
            .tracking(0.6)
            .foregroundStyle(Theme.textTertiary)
    }
}

/// A key/value row (label left, value right) used across detail cards.
struct KeyValueRow: View {
    let key: String
    let value: String
    var monoValue: Bool = false
    var body: some View {
        HStack {
            Text(key).font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
            Spacer(minLength: Theme.Space.md)
            Text(value)
                .font(monoValue ? Theme.Font.mono : Theme.Font.caption)
                .foregroundStyle(Theme.textPrimary)
        }
    }
}

/// A `KeyValueRow` variant for path-like/identifier values (monospaced,
/// truncated in the middle) with a trailing copy-to-clipboard affordance.
/// Used by the Dashboard's Details card (mount path, filespace id).
struct CopyableKeyValueRow: View {
    let key: String
    let value: String
    /// False for a placeholder value (e.g. "Not mounted") — there's nothing
    /// real to copy, so the affordance is hidden rather than copying a string
    /// that would read as fabricated data.
    var copyable: Bool = true
    @State private var copied = false

    var body: some View {
        HStack {
            Text(key).font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
            Spacer(minLength: Theme.Space.md)
            Text(value)
                .font(Theme.Font.monoPath)
                .foregroundStyle(Theme.textPrimary)
                .lineLimit(1).truncationMode(.middle)
                .help(value)
            if copyable {
                IconButton(copied ? IconSet.copied : IconSet.copy,
                           label: copied ? "Copied" : "Copy \(key)",
                           role: .badge, tint: copied ? Theme.Status.ok : Theme.textTertiary) {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                    withAnimation(.easeOut(duration: 0.15)) { copied = true }
                    Task {
                        try? await Task.sleep(for: .seconds(2))
                        withAnimation(.easeOut(duration: 0.15)) { copied = false }
                    }
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(key): \(value)")
    }
}

// MARK: - Status colors

extension ConnectionState {
    var dotColor: Color {
        switch self {
        case .connected:    return Theme.Status.ok
        case .connecting:   return Theme.Status.busy
        case .paused:       return Theme.Status.paused
        case .disconnected: return Theme.Status.idle
        case .error:        return Theme.Status.error
        }
    }
}

// MARK: Dashboard hero → status color (decorative glow + StatusDot tint)

extension DashboardHeroState {
    var statusColor: Color {
        switch self {
        case .connected, .demo: return Theme.Status.ok
        case .connecting:       return Theme.Status.busy
        case .paused:           return Theme.Status.paused
        case .notMounted:       return Theme.Status.idle
        case .probeFailed:      return Theme.Status.warn
        case .degraded:         return Theme.Status.warn
        case .offline:          return Theme.Status.error
        }
    }
}

// MARK: Materialization -> SF Symbol + tint (the cloud-badge vocabulary)

extension MaterializationState {
    /// Monochrome SF Symbol mirroring File Provider native status glyphs.
    var symbol: String {
        switch self {
        case .dataless:    return "cloud"
        case .streaming:   return "dot.radiowaves.up.forward"
        case .downloaded:  return "checkmark.circle"
        case .pinned:      return "pin.fill"
        case .uploading:   return "arrow.up.circle"
        }
    }

    var tint: Color {
        switch self {
        case .dataless:    return Theme.textTertiary
        case .streaming:   return Theme.accent
        case .downloaded:  return Theme.Status.ok
        case .pinned:      return Theme.Status.ok
        case .uploading:   return Theme.Status.warn
        }
    }

    var label: String {
        switch self {
        case .dataless:    return "In cloud"
        case .streaming:   return "Streaming"
        case .downloaded:  return "Local"
        case .pinned:      return "Pinned"
        case .uploading:   return "Uploading"
        }
    }
}

// MARK: A small reusable status dot

struct StatusDot: View {
    let color: Color
    var size: CGFloat = 8
    /// Optional VoiceOver label (e.g. the connection state). Defaults to none so
    /// callers that supply their own text aren't double-announced.
    var accessibility: String? = nil
    var body: some View {
        Circle()
            .fill(color)
            .frame(width: size, height: size)
            .overlay(Circle().stroke(Color.black.opacity(0.25), lineWidth: 0.5))
            .accessibilityHidden(accessibility == nil)
            .accessibilityLabel(accessibility ?? "")
    }
}

// MARK: - Icon — a named SF Symbol rendered at a consistent role size/weight

struct Icon: View {
    let name: String
    var role: Theme.IconRole = .badge
    init(_ name: String, role: Theme.IconRole = .badge) {
        self.name = name; self.role = role
    }
    var body: some View {
        Image(systemName: name)
            .font(role.font)
    }
}

// MARK: - IconButton — accessible icon-only button (VoiceOver label required)

struct IconButton: View {
    let icon: String
    let label: String                 // VoiceOver + tooltip (never icon-only silently)
    var role: Theme.IconRole = .action
    var tint: Color = Theme.textSecondary
    var buttonRole: ButtonRole? = nil
    let action: () -> Void

    init(_ icon: String, label: String, role: Theme.IconRole = .action,
         tint: Color = Theme.textSecondary, buttonRole: ButtonRole? = nil,
         action: @escaping () -> Void) {
        self.icon = icon; self.label = label; self.role = role
        self.tint = tint; self.buttonRole = buttonRole; self.action = action
    }

    var body: some View {
        Button(role: buttonRole, action: action) {
            Icon(icon, role: role).foregroundStyle(tint)
        }
        .buttonStyle(.plain)
        .help(label)
        .accessibilityLabel(label)
    }
}

// MARK: - Reduce-Motion-aware animation
//
// `Motion.resolve(_:reduceMotion:)` is the single gate: when the system's Reduce
// Motion setting is on, every animated transition collapses to `nil` (an instant
// change). Pure + testable; the view modifier below reads the environment and
// forwards to it.

extension Theme.Motion {
    /// Returns the animation, or `nil` when Reduce Motion is requested — so the
    /// change happens instantly instead of animating. Delegates the decision to
    /// the pure `MotionGate` (unit-tested in CloudFSKit).
    static func resolve(_ animation: Animation?, reduceMotion: Bool) -> Animation? {
        MotionGate.shouldAnimate(reduceMotion: reduceMotion) ? animation : nil
    }
}

extension View {
    /// Animate on `value` with `animation`, honoring Reduce Motion (instant when
    /// the user has it on). Use instead of bare `.animation(_:value:)`.
    func motionAnimation<V: Equatable>(_ animation: Animation, value: V) -> some View {
        modifier(MotionAnimationModifier(animation: animation, value: value))
    }
}

private struct MotionAnimationModifier<V: Equatable>: ViewModifier {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let animation: Animation
    let value: V
    func body(content: Content) -> some View {
        content.animation(Theme.Motion.resolve(animation, reduceMotion: reduceMotion), value: value)
    }
}

// MARK: Relative-time formatting

enum RelativeTime {
    static func string(_ date: Date) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .abbreviated
        return f.localizedString(for: date, relativeTo: Date())
    }
}
