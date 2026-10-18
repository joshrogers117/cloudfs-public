// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
import AppKit

// The app icon is generated programmatically (scripts/make-icon.swift). This test
// runs the generator into a temp dir and verifies it produces a valid, loadable
// AppIcon.icns at the expected sizes — so a broken generator fails CI, not the
// Dock at launch.

@Suite(.serialized, .timeLimit(.minutes(2)))
struct AppIconTests {

    /// Locate the package root from this test file's path (…/Tests/CloudFSKitTests/…).
    private func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)          // …/Tests/CloudFSKitTests/AppIconTests.swift
            .deletingLastPathComponent()         // …/Tests/CloudFSKitTests
            .deletingLastPathComponent()         // …/Tests
            .deletingLastPathComponent()         // package root
    }

    @Test func iconGeneratorProducesValidIcns() throws {
        let root = packageRoot()
        let script = root.appendingPathComponent("scripts/make-icon.swift")
        try #require(FileManager.default.fileExists(atPath: script.path),
                     "make-icon.swift missing at \(script.path)")

        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("cfs-icon-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: tmp) }

        // Run: swift make-icon.swift <tmp>
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = ["swift", script.path, tmp.path]
        proc.standardOutput = nil
        proc.standardError = nil
        try proc.run()
        proc.waitUntilExit()
        #expect(proc.terminationStatus == 0, "generator exited \(proc.terminationStatus)")

        // .icns exists and is non-trivial.
        let icns = tmp.appendingPathComponent("AppIcon.icns")
        #expect(FileManager.default.fileExists(atPath: icns.path), "AppIcon.icns not produced")
        let attrs = try FileManager.default.attributesOfItem(atPath: icns.path)
        let bytes = (attrs[.size] as? Int) ?? 0
        #expect(bytes > 10_000, "icns suspiciously small: \(bytes) bytes")

        // Loads as an image with real pixels.
        let image = try #require(NSImage(contentsOf: icns), "icns did not load as NSImage")
        #expect(image.size.width > 0 && image.size.height > 0)

        // The iconset has all 10 required PNG variants.
        let iconset = tmp.appendingPathComponent("AppIcon.iconset")
        let pngs = (try? FileManager.default.contentsOfDirectory(atPath: iconset.path)) ?? []
        let expected = ["icon_16x16.png", "icon_16x16@2x.png", "icon_32x32.png",
                        "icon_32x32@2x.png", "icon_128x128.png", "icon_128x128@2x.png",
                        "icon_256x256.png", "icon_256x256@2x.png", "icon_512x512.png",
                        "icon_512x512@2x.png"]
        for name in expected {
            #expect(pngs.contains(name), "missing iconset variant: \(name)")
        }
    }

    @Test func packagedBundleIconWiredWhenPresent() {
        // If the bundle has been built (CloudFSApp.app), confirm the icon is in
        // place + the Info.plist references it. Skipped (not failed) when the
        // bundle hasn't been assembled — make-app.sh produces it on demand.
        let root = packageRoot()
        let bundle = root.appendingPathComponent("CloudFSApp.app")
        guard FileManager.default.fileExists(atPath: bundle.path) else { return }

        let icns = bundle.appendingPathComponent("Contents/Resources/AppIcon.icns")
        #expect(FileManager.default.fileExists(atPath: icns.path),
                "built bundle is missing Resources/AppIcon.icns")

        let plist = bundle.appendingPathComponent("Contents/Info.plist")
        if let data = try? Data(contentsOf: plist),
           let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
            #expect(dict["CFBundleIconFile"] as? String == "AppIcon")
        }
    }
}
