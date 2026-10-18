// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI

/// A native volume symbol shared by the login, sidebar, and menu bar.
struct BrandMark: View {
    var tint: Color = Theme.accent
    var chrome = false
    var size: CGFloat = 18

    var body: some View {
        Image(systemName: "externaldrive.fill")
            .font(.system(size: size * (chrome ? 0.50 : 0.82), weight: .medium))
            .foregroundStyle(chrome ? Theme.accent : tint)
            .frame(width: size, height: size)
            .background(chrome ? Theme.selection : .clear,
                        in: RoundedRectangle(cornerRadius: size * 0.24))
            .accessibilityHidden(true)
    }

    static func statusItemImage(size: CGFloat = 17) -> NSImage {
        let image = NSImage(systemSymbolName: "externaldrive", accessibilityDescription: "CloudFS")!
        image.size = NSSize(width: size, height: size)
        image.isTemplate = true
        return image
    }
}

/// A volume illustration, separate from the app icon, for connection states and tiles.
struct FilespaceDriveIllustration: View {
    var size: CGFloat = 112
    var body: some View {
        Canvas { context, bounds in
            let scale = bounds.width / 120
            context.scaleBy(x: scale, y: scale)
            var top = Path()
            top.move(to: CGPoint(x: 29, y: 23))
            top.addQuadCurve(to: CGPoint(x: 39, y: 17), control: CGPoint(x: 31, y: 17))
            top.addLine(to: CGPoint(x: 81, y: 17))
            top.addQuadCurve(to: CGPoint(x: 91, y: 23), control: CGPoint(x: 89, y: 17))
            top.addLine(to: CGPoint(x: 108, y: 76))
            top.addLine(to: CGPoint(x: 12, y: 76))
            top.closeSubpath()
            context.fill(top, with: .linearGradient(Gradient(colors: [Color(red: 0.88, green: 0.84, blue: 1), Theme.accent]), startPoint: CGPoint(x: 40, y: 17), endPoint: CGPoint(x: 80, y: 85)))
            let face = Path(roundedRect: CGRect(x: 12, y: 70, width: 96, height: 24), cornerRadius: 9)
            context.fill(face, with: .color(Color(red: 0.43, green: 0.33, blue: 0.74)))
            context.fill(Path(ellipseIn: CGRect(x: 90, y: 79, width: 5, height: 5)), with: .color(.white.opacity(0.9)))
            context.fill(Path(roundedRect: CGRect(x: 26, y: 80, width: 25, height: 3), cornerRadius: 1.5), with: .color(.white.opacity(0.35)))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
