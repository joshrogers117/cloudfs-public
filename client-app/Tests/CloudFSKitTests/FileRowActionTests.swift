// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// The file-row context-menu vocabulary + per-state enablement (pure logic; the
// view renders whatever `FileRowMenu.actions` returns). These guard the
// interaction wiring without touching SwiftUI.

@Suite(.timeLimit(.minutes(1)))
struct FileRowActionTests {

    private func node(_ state: MaterializationState,
                      dir: Bool = false,
                      locked: String? = nil) -> FileNode {
        FileNode(id: "p/x", name: "x", isDirectory: dir, sizeBytes: 10,
                 modified: Date(), state: state, lockedBy: locked,
                 isShared: false, childCount: dir ? 3 : 0)
    }

    // MARK: Pin / Unpin are mutually exclusive by state

    @Test func pinnedShowsUnpinNotPin() {
        let n = node(.pinned)
        #expect(FileRowMenu.isPresent(.unpin, for: n))
        #expect(!FileRowMenu.isPresent(.pin, for: n))
    }

    @Test func unpinnedShowsPinNotUnpin() {
        let n = node(.dataless)
        #expect(FileRowMenu.isPresent(.pin, for: n))
        #expect(!FileRowMenu.isPresent(.unpin, for: n))
    }

    // MARK: Prefetch — only when not already local

    @Test func prefetchEnabledForCloudOnly() {
        #expect(FileRowMenu.isEnabled(.prefetch, for: node(.dataless)))
        #expect(FileRowMenu.isEnabled(.prefetch, for: node(.streaming)))
    }

    @Test func prefetchDisabledWhenLocalOrPinned() {
        #expect(!FileRowMenu.isEnabled(.prefetch, for: node(.downloaded)))
        #expect(!FileRowMenu.isEnabled(.prefetch, for: node(.pinned)))
    }

    // MARK: Evict — only when something is cached, and not mid-upload

    @Test func evictEnabledWhenLocal() {
        #expect(FileRowMenu.isEnabled(.evict, for: node(.downloaded)))
        #expect(FileRowMenu.isEnabled(.evict, for: node(.pinned)))
    }

    @Test func evictDisabledForCloudOnly() {
        #expect(!FileRowMenu.isEnabled(.evict, for: node(.dataless)))
    }

    @Test func evictDisabledWhileUploading() {
        // Dirty/not-yet-uploaded items are non-evictable (client doc §2.8).
        #expect(!FileRowMenu.isEnabled(.evict, for: node(.uploading)))
    }

    // MARK: Always-available actions

    @Test func copyLinkRevealAndInfoAlwaysPresentAndEnabled() {
        for state in [MaterializationState.dataless, .streaming, .downloaded, .pinned, .uploading] {
            let n = node(state)
            for a in [FileRowAction.copyLink, .revealInFinder, .getInfo] {
                #expect(FileRowMenu.isPresent(a, for: n))
                #expect(FileRowMenu.isEnabled(a, for: n))
            }
        }
    }

    // MARK: Structure — grouping + glyphs + destructive role

    @Test func menuStartsNewGroupsForSharingAndCache() {
        #expect(FileRowAction.copyLink.startsNewGroup)
        #expect(FileRowAction.evict.startsNewGroup)
        #expect(!FileRowAction.pin.startsNewGroup)
    }

    @Test func evictIsTheOnlyDestructiveAction() {
        let destructive = FileRowAction.allCases.filter(\.isDestructive)
        #expect(destructive == [.evict])
    }

    @Test func everyActionHasARegisteredGlyph() {
        for a in FileRowAction.allCases {
            #expect(!a.glyph.isEmpty)
            #expect(IconSet.all.contains(a.glyph), "glyph not in IconSet.all: \(a.glyph)")
        }
    }

    @Test func everyActionHasATitle() {
        for a in FileRowAction.allCases {
            #expect(!a.title.isEmpty)
        }
    }

    // MARK: Folders get the full action set too

    @Test func folderActionsResolve() {
        let dir = node(.downloaded, dir: true)
        // A downloaded folder can be evicted + pinned-removed; copy/reveal/info on.
        #expect(FileRowMenu.isEnabled(.evict, for: dir))
        #expect(FileRowMenu.isPresent(.copyLink, for: dir))
        // pin/unpin · prefetch · rename · copyLink · reveal · evict · getInfo
        #expect(FileRowMenu.actions(for: dir).count == 7)
    }

    // MARK: Rename — present always, disabled while locked by another editor

    @Test func renameEnabledUnlessLocked() {
        #expect(FileRowMenu.isEnabled(.rename, for: node(.downloaded)))
        #expect(!FileRowMenu.isEnabled(.rename, for: node(.downloaded, locked: "Mara P.")))
    }
}
