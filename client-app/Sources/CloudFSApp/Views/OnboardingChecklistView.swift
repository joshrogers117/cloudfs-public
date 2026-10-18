// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

// MARK: - OnboardingChecklistView (ONBOARDING.md build step 4)
//
// The ONE first-run checklist sheet shown after the first successful sign-in on
// a device, replacing the old scattered Login Items / cache-default / silent-
// mount experience. Three rows (state lives in `AppModel.onboarding` —
// `OnboardingFeatureModel`, driven by `AppModel+Onboarding.swift`):
//   1. Background engine — live `DaemonLifecycle` state + a Login Items deep link.
//   2. Cache — informational default + a "Change…" jump to the real Cache pane.
//   3. Filespaces — one progress row per filespace, ending in a REAL verified
//      probe through the kernel mount (never a trusted-blind "mounted ⇒ done").
// Terminal state: "You're all set" + "Open in Finder". Not blocking — a subtle
// dismiss lets the user continue while the background engine/mount keep trying
// (the sheet reopens on the next sign-in if anything is still unhealthy).

struct OnboardingChecklistView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: Theme.Space.xl) {
            header
            VStack(alignment: .leading, spacing: Theme.Space.lg) {
                engineRow
                Divider().overlay(Theme.divider)
                cacheRow
                Divider().overlay(Theme.divider)
                if model.filespaces.isEmpty {
                    firstFilespaceRow
                } else {
                    mountsSection
                }
            }
            .padding(Theme.Space.xl)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.Radius.lg))
            .overlay(RoundedRectangle(cornerRadius: Theme.Radius.lg).strokeBorder(Theme.border))
            footer
        }
        .padding(Theme.Space.xxl)
        .frame(width: 480)
        .background(Theme.bg)
        .motionAnimation(Theme.Motion.section, value: model.onboarding.allHealthy)
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .top, spacing: Theme.Space.md) {
            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(model.filespaces.isEmpty ? "Welcome to CloudFS" : !model.isHttpMode ? "Explore CloudFS" : model.onboarding.allHealthy ? "You’re all set" : "Setting up CloudFS")
                    .font(Theme.Font.headline).foregroundStyle(Theme.textPrimary)
                Text(!model.isHttpMode
                     ? "Sample workspace only. No filespace is mounted or connected to storage."
                     : model.filespaces.isEmpty
                     ? "Your workspace is ready. Connect a filespace to start working with your team."
                     : model.onboarding.allHealthy
                         ? "Your filespaces are ready to open in Finder."
                         : "A few one-time steps to get your filespaces streaming.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            }
            Spacer(minLength: Theme.Space.md)
            if !model.onboarding.allHealthy {
                Button {
                    model.onboarding.isPresented = false
                } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.plain)
                .foregroundStyle(Theme.textTertiary)
                .help("Continue in the background — this reopens if anything still needs attention.")
                .accessibilityLabel("Dismiss")
            }
        }
    }

    // MARK: Row 1 — Background engine

    private var engineRow: some View {
        ChecklistRow(symbol: engineSymbol, tint: engineTint, spinning: engineSpinning,
                     title: "Background engine", detail: engineDetail) {
            if model.onboarding.engineState == .waitingForApproval {
                Button("Open Login Items…") {
                    DaemonLifecycle.shared.openLoginItemsSettings()
                }
                .cfButton(.secondary, size: .small)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Background engine: \(engineDetail)")
    }

    private var engineSymbol: String {
        switch model.onboarding.engineState {
        case .starting:          return "circle.dotted"
        case .waitingForApproval: return IconSet.warning
        case .ready, .unavailable: return IconSet.success
        }
    }
    private var engineTint: Color {
        switch model.onboarding.engineState {
        case .starting, .unavailable: return Theme.textTertiary
        case .waitingForApproval:     return Theme.Status.warn
        case .ready:                  return Theme.Status.ok
        }
    }
    private var engineSpinning: Bool { model.onboarding.engineState == .starting }
    private var engineDetail: String {
        switch model.onboarding.engineState {
        case .starting:           return "Starting…"
        case .waitingForApproval: return "Needs a one-time approval in Login Items."
        case .ready:               return "Running."
        case .unavailable:         return "Not needed for this build."
        }
    }

    // MARK: Row 2 — Cache (informational, never blocking)

    private var cacheRow: some View {
        ChecklistRow(symbol: IconSet.cache, tint: Theme.textSecondary,
                     title: "Cache", detail: model.onboarding.cacheDefaultSummary) {
            Button("Change…") {
                model.go(to: .cache)
                model.onboarding.isPresented = false
            }
            .cfButton(.subtle, size: .small)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Cache: \(model.onboarding.cacheDefaultSummary)")
    }

    // MARK: Row 3 — Filespaces (verified mount, one row per filespace)

    private var firstFilespaceRow: some View {
        ChecklistRow(symbol: "folder.badge.plus", tint: Theme.textSecondary,
                     title: "Your first filespace",
                     detail: model.canCreateFilespaces
                        ? "Create it in the workspace console, then return here to connect."
                        : "Ask your workspace administrator to give you access to a filespace.") {
            if model.canCreateFilespaces, let url = model.consoleLinks.url(.createFilespace) {
                Link("Create filespace", destination: url)
                    .cfButton(.primary, size: .small)
            }
        }
    }

    private var mountsSection: some View {
        VStack(alignment: .leading, spacing: Theme.Space.md) {
            SectionLabel("Filespaces")
            VStack(alignment: .leading, spacing: Theme.Space.lg) {
                ForEach(model.filespaces) { fs in
                    mountRow(fs)
                }
            }
        }
    }

    private func mountRow(_ fs: Filespace) -> some View {
        let state = model.onboarding.mountRows[fs.id] ?? .waiting
        return ChecklistRow(symbol: mountSymbol(state), tint: mountTint(state),
                            spinning: mountSpinning(state), title: fs.name,
                            detail: mountDetail(state)) { EmptyView() }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(fs.name): \(mountDetail(state) ?? "")")
    }

    private func mountSymbol(_ s: MountRowState) -> String {
        switch s {
        case .waiting, .mounting, .verifying: return "circle.dotted"
        case .done, .browseOnly, .demo:                    return IconSet.success
        case .disconnected:                    return "circle"
        case .failed:                          return IconSet.error
        }
    }
    private func mountTint(_ s: MountRowState) -> Color {
        switch s {
        case .waiting, .mounting, .verifying, .demo, .disconnected: return Theme.textTertiary
        case .done, .browseOnly:                      return Theme.Status.ok
        case .failed:                                  return Theme.Status.error
        }
    }
    private func mountSpinning(_ s: MountRowState) -> Bool {
        switch s { case .mounting, .verifying: return true; default: return false }
    }
    private func mountDetail(_ s: MountRowState) -> String? {
        switch s {
        case .waiting:   return "Waiting…"
        case .mounting:  return "Mounting…"
        case .verifying: return "Verifying…"
        case .done:      return "Connected — browsing verified."
        case .browseOnly: return "Connected — browsing verified. Writing is restricted at this level."
        case .disconnected: return "Disconnected by you. Connect it from the dashboard when needed."
        case .demo:      return "Demo mode — nothing to verify."
        case .failed(let f): return "\(f.title) — \(f.detail)"
        }
    }

    // MARK: Footer

    @ViewBuilder private var footer: some View {
        if model.filespaces.isEmpty || !model.isHttpMode {
            HStack {
                Spacer()
                Button(model.isHttpMode ? "Done" : "Explore workspace") { model.onboarding.isPresented = false }
                    .cfButton(.primary, size: .large)
                    .keyboardShortcut(.defaultAction)
            }
        } else if model.onboarding.allHealthy {
            HStack {
                Spacer()
                Button("Open in Finder") {
                    model.revealInFinder(node: OnboardingChecklistView.finderRevealPlaceholder)
                    model.onboarding.isPresented = false
                }
                .cfButton(.primary, size: .large)
                .keyboardShortcut(.defaultAction)
            }
        } else if !model.onboarding.isRunning {
            HStack {
                Text("The connection check couldn’t finish. Try again when you’re ready.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                Spacer()
                Button("Try again") { model.rerunOnboardingChecklist() }
                    .cfButton(.secondary, size: .small)
            }
        } else {
            Text("This finishes automatically — feel free to keep working.")
                .font(Theme.Font.micro).foregroundStyle(Theme.textTertiary)
        }
    }

    /// `AppModel.revealInFinder(node:)` reveals the SELECTED filespace's mount
    /// root and ignores the node's own fields — a placeholder is all it needs.
    private static let finderRevealPlaceholder = FileNode(
        id: "root", name: "", isDirectory: true, sizeBytes: 0,
        modified: Date(), state: .downloaded)
}

// MARK: - ChecklistRow (shared row layout: leading status glyph + title/detail + trailing action)

private struct ChecklistRow<Trailing: View>: View {
    let symbol: String
    let tint: Color
    var spinning: Bool = false
    let title: String
    var detail: String? = nil
    @ViewBuilder var trailing: () -> Trailing

    var body: some View {
        HStack(alignment: .top, spacing: Theme.Space.lg) {
            Group {
                if spinning {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: symbol).foregroundStyle(tint)
                }
            }
            .frame(width: 18)
            .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Theme.Space.xxs) {
                Text(title).font(Theme.Font.body).foregroundStyle(Theme.textPrimary)
                if let detail {
                    Text(detail).font(Theme.Font.micro).foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: Theme.Space.md)
            trailing()
        }
    }
}
