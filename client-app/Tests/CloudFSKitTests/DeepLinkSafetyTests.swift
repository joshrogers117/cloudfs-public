// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Testing
@testable import CloudFSKit

@Suite struct DeepLinkSafetyTests {
    @Test func rootsAndLegacyFinderLinks() {
        #expect(DeepLink.parse("cloudfs://space")?.path == "")
        #expect(DeepLink.parse("cloudfs://space/")?.path == "")
        #expect(DeepLink.parse("cloudfs://file/space/Folder/a.mov") ==
                DeepLink.Parsed(spaceId: "space", path: "Folder/a.mov", select: true))
        #expect(DeepLink.parse("cloudfs://file/space")?.path == "")
        let finder = FinderIntegration.shareLink(filespace: "space", relativePath: "Folder/one.mov")!
        #expect(DeepLink.parse(finder.absoluteString)?.path == "Folder/one.mov")
    }

    @Test func stableItemIdentityRequiresDaemonResolution() throws {
        let url = DeepLink.buildItem(spaceId: "SPACE-123", itemId: "ino-ABC", select: false)
        #expect(url == "cloudfs://item/SPACE-123/ino-ABC?select=0")
        let parsed = try #require(DeepLink.parse(url))
        #expect(parsed.spaceId == "SPACE-123")
        #expect(parsed.itemId == "ino-ABC")
        #expect(parsed.select == false)
        #expect(DeepLink.resolve(parsed, mountPath: "/Volumes/Space") == nil)
        let finder = try #require(FinderIntegration.shareItemLink(filespace: "SPACE-123", itemId: "ino-ABC"))
        #expect(DeepLink.parse(finder.absoluteString)?.itemId == "ino-ABC")
        for invalid in ["cloudfs://item/fs", "cloudfs://item/fs/id/extra", "cloudfs://item/fs/%00",
                        "cloudfs://item/fs/%2e%2e", "cloudfs://item/fs/a%2Fb", "cloudfs://item/%2F/id"] {
            #expect(DeepLink.parse(invalid) == nil)
        }
    }

    @Test func roundTripLiteralPercentUnicodeAndReservedCharacters() {
        let path = "雪 100%/literal%2F ?#&.mov"
        let url = DeepLink.build(spaceId: "SPACE-123", path: path)
        #expect(DeepLink.parse(url)?.spaceId == "SPACE-123")
        #expect(DeepLink.parse(url)?.path == path)
        // Double-encoded slash stays a literal filename; it is never decoded again.
        #expect(DeepLink.parse("cloudfs://space/%252F")?.path == "%2F")
    }

    @Test func rejectTraversalSeparatorsAndAmbiguousAuthority() {
        let paths = ["../secret", ".", "%2e%2e/secret", "a/%2E%2e/b", "a%2Fb", "a%5cb",
                     "a/%00", "a/%0a", "a//b", "a/", "%2Fetc/passwd"]
        for path in paths { #expect(DeepLink.parse("cloudfs://space/" + path) == nil) }
        for url in ["cloudfs://user@space/a", "cloudfs://space:123/a", "cloudfs://space/a#fragment",
                    "cloudfs://space/a?token=secret", "cloudfs://space/a?select=0&select=1",
                    "cloudfs://auth/callback", "cloudfs://connect?server=https://example.com"] {
            #expect(DeepLink.parse(url) == nil)
        }
    }

    @Test func resolverContainsSymlinksAndValidatesConstructedParsedValues() throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let root = base.appendingPathComponent("volume")
        let outside = base.appendingPathComponent("volume-other")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("escape"), withDestinationURL: outside)
        try FileManager.default.createSymbolicLink(at: root.appendingPathComponent("inside"), withDestinationURL: root)
        let link: (String) -> DeepLink.Parsed = { .init(spaceId: "space", path: $0, select: true) }
        let canonicalRoot = root.resolvingSymlinksInPath().path
        #expect(DeepLink.resolve(link(""), mountPath: root.path)?.path == canonicalRoot)
        #expect(DeepLink.resolve(link("inside/a.mov"), mountPath: root.path)?.path == canonicalRoot + "/a.mov")
        #expect(DeepLink.resolve(link("escape/a.mov"), mountPath: root.path) == nil)
        #expect(DeepLink.resolve(link("../volume-other"), mountPath: root.path) == nil)
        #expect(DeepLink.resolve(link("/etc/passwd"), mountPath: root.path) == nil)
        #expect(DeepLink.resolve(link("a\0b"), mountPath: root.path) == nil)
        #expect(DeepLink.resolve(link("a"), mountPath: "relative/root") == nil)
        #expect(DeepLink.resolve(link("a"), mountPath: "/") == nil)
    }
}
