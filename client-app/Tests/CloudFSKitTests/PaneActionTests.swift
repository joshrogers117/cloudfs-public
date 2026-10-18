// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// The per-pane window-toolbar action vocabulary: which actions a section shows,
// their titles/glyphs, and the state-driven enablement. Pure logic (no SwiftUI),
// so the toolbar just renders `PaneAction.actions(for:)` + gates with
// `isEnabled(in:)`.

@Suite(.timeLimit(.minutes(1)))
struct PaneActionTests {

    private func ctx(signedIn: Bool = true, canEdit: Bool = true,
                     completed: Bool = false, active: Bool = false,
                     paused: Bool = false) -> PaneAction.Context {
        PaneAction.Context(isSignedIn: signedIn, canEdit: canEdit,
                           hasCompletedTransfers: completed,
                           hasActiveTransfers: active, transfersPaused: paused)
    }

    // MARK: Per-section action sets (mirror the sidebar panes)

    @Test func sectionsExposeTheirContextualActions() {
        #expect(PaneAction.actions(for: "Sharing") == [.newLink])
        #expect(PaneAction.actions(for: "Snapshots") == [.newSnapshot])
        #expect(PaneAction.actions(for: "Activity") == [.togglePauseAll, .clearCompleted])
    }

    @Test func panesWithoutContextualActionsReturnEmpty() {
        // "Files" was removed in WS1; "Pinned"/"Audit" are the new WS2/WS3 panes
        // (no contextual toolbar action yet).
        for section in ["Filespaces", "Pinned", "Audit", "Cache", "Preferences", "Unknown"] {
            #expect(PaneAction.actions(for: section).isEmpty)
        }
    }

    // MARK: Enablement — signed out disables everything

    @Test func everythingDisabledWhenSignedOut() {
        let c = ctx(signedIn: false, canEdit: true, completed: true, active: true, paused: true)
        for action in PaneAction.allCases {
            #expect(!action.isEnabled(in: c), "\(action) should be disabled signed-out")
        }
    }

    // MARK: Write actions need edit permission

    @Test func writeActionsNeedEditPermission() {
        let noEdit = ctx(canEdit: false)
        let edit = ctx(canEdit: true)
        for action in [PaneAction.newLink, .newSnapshot] {
            #expect(!action.isEnabled(in: noEdit), "\(action) needs edit")
            #expect(action.isEnabled(in: edit), "\(action) should enable with edit")
        }
    }

    // MARK: Clear-completed needs something completed

    @Test func clearCompletedNeedsCompletedTransfers() {
        #expect(!PaneAction.clearCompleted.isEnabled(in: ctx(completed: false)))
        #expect(PaneAction.clearCompleted.isEnabled(in: ctx(completed: true)))
    }

    // MARK: Pause-all — active OR already paused, and the title flips

    @Test func pauseAllEnabledWhenActiveOrPaused() {
        #expect(PaneAction.togglePauseAll.isEnabled(in: ctx(active: true, paused: false)))
        #expect(PaneAction.togglePauseAll.isEnabled(in: ctx(active: false, paused: true)))
        #expect(!PaneAction.togglePauseAll.isEnabled(in: ctx(active: false, paused: false)))
    }

    @Test func pauseAllTitleFlipsWithState() {
        #expect(PaneAction.togglePauseAll.title(in: ctx(paused: false)) == "Pause All")
        #expect(PaneAction.togglePauseAll.title(in: ctx(paused: true)) == "Resume All")
    }

    // MARK: Every action has a registered glyph + a title

    @Test func everyActionHasGlyphAndTitle() {
        for action in PaneAction.allCases {
            #expect(!action.glyph.isEmpty)
            #expect(IconSet.all.contains(action.glyph), "glyph not in IconSet: \(action.glyph)")
            #expect(!action.title().isEmpty)
        }
    }

    // MARK: New IconSet glyphs are registered

    @Test func newToolbarGlyphsRegistered() {
        for g in [IconSet.newFolder, IconSet.newLink, IconSet.newSnapshot,
                  IconSet.clearCompleted, IconSet.refresh, IconSet.account] {
            #expect(IconSet.all.contains(g), "glyph not registered: \(g)")
        }
    }
}

// MARK: - Sign-out resets the data layer (so the app can return to Login)

@Suite(.timeLimit(.minutes(1)))
struct SignOutResetTests {

    @Test func signOutDisconnectsFilespaces() async throws {
        let mock = MockGatewayClient()
        let spaces = try await mock.connect(.interactive(email: "a@b.c", filespace: "X"))
        #expect(spaces.allSatisfy { $0.connection == .connected })
        // Sign out should quiesce every filespace so a stale "connected" badge
        // can't linger after returning to the Login screen.
        try await mock.signOut()
        let after = try await mock.filespaces()
        #expect(after.allSatisfy { $0.connection == .disconnected })
    }
}
