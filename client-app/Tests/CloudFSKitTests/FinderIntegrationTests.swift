// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// M8 — pure logic behind the Finder Sync appex: path→filespace resolution,
// share links, and badge identity from pin records.
@Suite struct FinderIntegrationTests {

    private let mounts = ["edit1": "/Users/test-user/cloudfs/edit1",
                          "mac1": "/Users/test-user/cloudfs/mac1/"]   // trailing slash tolerated

    @Test func resolveMapsPathsToFilespaceAndRelative() {
        let r = FinderIntegration.resolve(path: "/Users/test-user/cloudfs/edit1/proj/a.mov", mounts: mounts)
        #expect(r?.filespace == "edit1")
        #expect(r?.relativePath == "proj/a.mov")

        // Mount root itself → "".
        let root = FinderIntegration.resolve(path: "/Users/test-user/cloudfs/mac1", mounts: mounts)
        #expect(root?.filespace == "mac1")
        #expect(root?.relativePath == "")

        // Outside any mount → nil; sibling-prefix dirs don't false-match.
        #expect(FinderIntegration.resolve(path: "/Users/test-user/other/x", mounts: mounts) == nil)
        #expect(FinderIntegration.resolve(path: "/Users/test-user/cloudfs/edit1extra/x", mounts: mounts) == nil)
    }

    @Test func shareLinkEncodesSegments() {
        let url = FinderIntegration.shareLink(filespace: "edit1", relativePath: "proj A/clip 01.mov")
        #expect(url?.scheme == "cloudfs")
        #expect(url?.host == "edit1")
        #expect(url?.absoluteString == "cloudfs://edit1/proj%20A/clip%2001.mov")

        // Root link (no path) is just the filespace.
        #expect(FinderIntegration.shareLink(filespace: "mac1", relativePath: "")?.absoluteString
                == "cloudfs://mac1")
    }

    @Test func badgeReflectsPinRecords() {
        typealias P = FinderIntegration.PinRecord
        let pins = [P(path: "a/b.mov", recursive: false, cacheState: "pinned"),
                    P(path: "dir", recursive: true, cacheState: "pinning")]

        #expect(FinderIntegration.badge(relativePath: "a/b.mov", pins: pins) == "pinned")
        // Recursive pin covers the subtree (and the directory itself)…
        #expect(FinderIntegration.badge(relativePath: "dir/sub/c.mov", pins: pins) == "pinning")
        #expect(FinderIntegration.badge(relativePath: "dir", pins: pins) == "pinning")
        // …but not siblings or unpinned paths.
        #expect(FinderIntegration.badge(relativePath: "dir2/c.mov", pins: pins) == "")
        #expect(FinderIntegration.badge(relativePath: "a/other.mov", pins: pins) == "")
        // A fully-pinned record beats a covering "pinning" record.
        let both = pins + [P(path: "dir/sub/c.mov", recursive: false, cacheState: "pinned")]
        #expect(FinderIntegration.badge(relativePath: "dir/sub/c.mov", pins: both) == "pinned")
    }

    @Test func menuActionsAreStateful() {
        typealias P = FinderIntegration.PinRecord
        let pins = ["mac1": [P(path: "a.mov", recursive: false, cacheState: "pinned"),
                             P(path: "b.mov", recursive: false, cacheState: "pinning")]]

        // Entirely unpinned selection → Pin only.
        let unpinned = FinderIntegration.menuActions(items: [("mac1", "c.mov")], pins: pins)
        #expect(unpinned == (showPin: true, showUnpin: false))

        // Entirely pinned (or still pinning) selection → Unpin only.
        let pinned = FinderIntegration.menuActions(items: [("mac1", "a.mov"), ("mac1", "b.mov")],
                                                   pins: pins)
        #expect(pinned == (showPin: false, showUnpin: true))

        // Mixed selection → both options (each acts on its half).
        let mixed = FinderIntegration.menuActions(items: [("mac1", "a.mov"), ("mac1", "c.mov")],
                                                  pins: pins)
        #expect(mixed == (showPin: true, showUnpin: true))
    }

    @Test func failedPinsRemainVisibleAndInheritedPinsHaveNoMisleadingUnpinAction() {
        let failed = FinderIntegration.PinRecord(path: "project", recursive: true, cacheState: "pinned", failureReason: "Cache is full")
        #expect(FinderIntegration.badge(relativePath: "project/clip.mov", pins: [failed]) == "attention")
        let child = FinderIntegration.menuActions(items: [("fs", "project/clip.mov")], pins: ["fs": [failed]])
        #expect(child == (showPin: false, showUnpin: false))
        let parent = FinderIntegration.menuActions(items: [("fs", "project")], pins: ["fs": [failed]])
        #expect(parent == (showPin: false, showUnpin: true))
    }
}
