// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// The icon registry is the single source of truth for SF Symbol names, so a
// typo'd or duplicated glyph is a real (silent) UI bug. These tests guard the
// mapping. Pure data — no SwiftUI needed.

@Suite(.timeLimit(.minutes(1)))
struct IconSetTests {

    @Test func allGlyphNamesAreNonEmpty() {
        for name in IconSet.all {
            #expect(!name.isEmpty)
            // SF Symbol names are dot-separated lowercase tokens; reject stray
            // whitespace which would silently render nothing.
            #expect(!name.contains(" "))
        }
    }

    @Test func duplicatesAreOnlyIntentionalAliases() {
        // Some semantic roles deliberately share an SF Symbol (e.g. `sharing` and
        // `copyLink` both use "link"). Catch ACCIDENTAL dupes by allowing only the
        // documented alias glyphs to repeat.
        var counts: [String: Int] = [:]
        for n in IconSet.all { counts[n, default: 0] += 1 }
        let repeated = Set(counts.filter { $0.value > 1 }.keys)
        let allowedAliases: Set<String> = [
            "link",                 // sharing + copyLink
            "arrow.down.circle",    // download + downloadOutline
            "externaldrive.fill",   // storage + externalDrive
            "checkmark.circle.fill",// filespaceCheck + success
            "person.2",             // members + activityIdle (empty-state)
            "person.crop.circle.badge.checkmark", // changeRole + reactivate
        ]
        #expect(repeated.isSubset(of: allowedAliases),
                "unexpected duplicate glyph(s): \(repeated.subtracting(allowedAliases))")
    }

    @Test func coreNavigationGlyphsAreRegistered() {
        // The section nav must have a glyph for every pane.
        for g in [IconSet.filespaces, IconSet.files, IconSet.activity,
                  IconSet.snapshots, IconSet.sharing, IconSet.cache, IconSet.preferences] {
            #expect(IconSet.all.contains(g))
        }
    }

    @Test func pauseAndPlayAreDistinctVariants() {
        // Outline + filled variants must not collapse to the same glyph.
        #expect(IconSet.pause != IconSet.play)
        #expect(IconSet.pauseFill != IconSet.playFill)
        #expect(IconSet.pause != IconSet.pauseFill)
    }

    @Test func transferDirectionGlyphsDiffer() {
        #expect(IconSet.upload != IconSet.downloadFill)
        #expect(IconSet.uploadOutline != IconSet.downloadOutline)
    }

    // The banner status glyphs are duplicated between BannerKind (CloudFSKit) and
    // IconSet — this test pins them in sync so they can't silently drift apart.
    @Test func bannerKindSymbolsMatchIconSet() {
        #expect(BannerKind.info.symbolName    == IconSet.info)
        #expect(BannerKind.success.symbolName == IconSet.success)
        #expect(BannerKind.warning.symbolName == IconSet.warning)
        #expect(BannerKind.error.symbolName   == IconSet.error)
    }

    // Glyphs wired into views (Pass 4 tokenization). If an IconSet constant is
    // renamed/removed, this fails before the silent blank glyph ships.
    @Test func viewReferencedGlyphsAreRegistered() {
        for g in [IconSet.errorOutline, IconSet.recreated, IconSet.clock,
                  IconSet.locked, IconSet.document, IconSet.connectMore,
                  IconSet.ssoProvider, IconSet.signOut, IconSet.menuChevron,
                  IconSet.pauseFill, IconSet.playFill, IconSet.trash, IconSet.copy] {
            #expect(IconSet.all.contains(g), "glyph not registered in IconSet.all: \(g)")
        }
    }
}
