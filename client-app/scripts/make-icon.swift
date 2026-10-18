#!/usr/bin/env swift
// SPDX-License-Identifier: AGPL-3.0-or-later
import AppKit
import CoreGraphics

// Every packaged icon is rendered from the canonical purple-drive vector.
// Passing --web-assets also refreshes the checked-in browser/site assets.
let packageURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let sourceURL = packageURL.appendingPathComponent("Resources/cloudfs-logo.svg")
let sourceData = try Data(contentsOf: sourceURL)
guard let source = String(data: sourceData, encoding: .utf8),
      source.contains("#a08cff"), !source.lowercased().contains("#f5c21a"),
      let vector = NSImage(contentsOf: sourceURL) else {
    fatalError("Expected the canonical CloudFS purple drive; see docs/BRANDING.md")
}

func drawIcon(size: Int) -> CGImage? {
    let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
    guard let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8,
                              bytesPerRow: 0, space: colorSpace,
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: false)
    vector.draw(in: CGRect(x: 0, y: 0, width: size, height: size))
    NSGraphicsContext.restoreGraphicsState()
    return ctx.makeImage()
}

// MARK: - Write iconset + build .icns

let args = CommandLine.arguments
let outDir = args.dropFirst().first(where: { !$0.hasPrefix("--") })
    ?? packageURL.appendingPathComponent("scripts/.icon-build").path
let iconsetDir = outDir + "/AppIcon.iconset"

let fm = FileManager.default
try? fm.removeItem(atPath: iconsetDir)
try! fm.createDirectory(atPath: iconsetDir, withIntermediateDirectories: true)

// (pointSize, scale) → filename per Apple's iconset naming convention.
let variants: [(point: Int, scale: Int)] = [
    (16,1),(16,2),(32,1),(32,2),(128,1),(128,2),(256,1),(256,2),(512,1),(512,2),
]

func pngData(_ image: CGImage) -> Data {
    let rep = NSBitmapImageRep(cgImage: image)
    return rep.representation(using: .png, properties: [:])!
}

func writePNG(_ image: CGImage, to path: String) {
    try! pngData(image).write(to: URL(fileURLWithPath: path))
}

for v in variants {
    let px = v.point * v.scale
    guard let img = drawIcon(size: px) else { continue }
    let name = v.scale == 1 ? "icon_\(v.point)x\(v.point).png"
                            : "icon_\(v.point)x\(v.point)@2x.png"
    writePNG(img, to: iconsetDir + "/" + name)
}

// Build AppIcon.icns via iconutil.
let icns = outDir + "/AppIcon.icns"
let p = Process()
p.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
p.arguments = ["-c", "icns", iconsetDir, "-o", icns]
try? p.run()
p.waitUntilExit()

if p.terminationStatus == 0, fm.fileExists(atPath: icns) {
    FileHandle.standardError.write("==> Wrote \(icns)\n".data(using: .utf8)!)
} else {
    FileHandle.standardError.write("error: iconutil failed (status \(p.terminationStatus))\n".data(using: .utf8)!)
    exit(1)
}

if args.contains("--web-assets") {
    let root = packageURL.deletingLastPathComponent()
    let destinations = [root.appendingPathComponent("web/public"), root.appendingPathComponent("site/assets")]
    let png32 = pngData(drawIcon(size: 32)!)
    let png180 = pngData(drawIcon(size: 180)!)
    // ICO files can contain lossless PNG images. Include the three browser sizes.
    var ico = Data()
    func appendLE<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
        var little = value.littleEndian
        withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
    }
    appendLE(UInt16(0), to: &ico)
    appendLE(UInt16(1), to: &ico)
    appendLE(UInt16(3), to: &ico)
    let sizes = [16, 32, 48]
    let images = sizes.map { pngData(drawIcon(size: $0)!) }
    var offset = UInt32(6 + sizes.count * 16)
    for (size, data) in zip(sizes, images) {
        ico.append(contentsOf: [UInt8(size), UInt8(size), 0, 0])
        appendLE(UInt16(1), to: &ico)
        appendLE(UInt16(32), to: &ico)
        appendLE(UInt32(data.count), to: &ico)
        appendLE(offset, to: &ico)
        offset += UInt32(data.count)
    }
    for data in images { ico.append(data) }
    for directory in destinations {
        try sourceData.write(to: directory.appendingPathComponent("brand.svg"))
        try sourceData.write(to: directory.appendingPathComponent("cloudfs-drive-v2.svg"))
        try png32.write(to: directory.appendingPathComponent("cloudfs-drive-v2-32.png"))
        try png180.write(to: directory.appendingPathComponent("cloudfs-drive-v2-180.png"))
        try ico.write(to: directory.appendingPathComponent("cloudfs-drive-v2.ico"))
        // Preserve the conventional fallback URL for browsers that request it directly.
        try ico.write(to: directory.appendingPathComponent("favicon.ico"))
    }
    try Data(contentsOf: URL(fileURLWithPath: icns)).write(to: packageURL.appendingPathComponent("Resources/AppIcon.icns"))
    FileHandle.standardError.write("==> Refreshed purple-drive web, site, and native assets\n".data(using: .utf8)!)
}
