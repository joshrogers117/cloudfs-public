# CloudFS brand assets

CloudFS uses a **purple drive** on charcoal. The former yellow ring and dot are permanently retired.

The canonical vector is [`client-app/Resources/cloudfs-logo.svg`](../client-app/Resources/cloudfs-logo.svg): purple `#a08cff`, charcoal `#303038`. The drive silhouette matches the native `externaldrive.fill` symbol. The native menu-bar mark remains a monochrome template so macOS can provide the appropriate contrast.

The web `BrandMark` uses the same drive geometry with application theme colors. Primary-action colors can differ from the lighter icon accent to keep text legible. Semantic warning amber and third-party provider colors retain their meanings.

To regenerate all assets on macOS, run from the repository root:

```sh
swift client-app/scripts/make-icon.swift client-app/scripts/.icon-build --web-assets
node scripts/check-brand-assets.mjs
```

The generator reads the SVG directly and writes the native iconset/ICNS, `Resources/AppIcon.icns`, and the browser/site asset copies. `brand.svg` remains a compatible URL, now containing the purple drive. Browser entry points use the new `cloudfs-drive-v2` filenames to avoid cached copies of the old favicon. The SVG favicon has PNG and ICO fallbacks and a 180-pixel Apple touch icon. Conventional `favicon.ico` requests also receive the drive.

Native release builds regenerate their icon. The File Provider build also refreshes `Resources/AppIcon.icns` before Xcode packaging. The web build runs the branding check so stale vectors or obsolete source colors fail before deployment.

Product screenshots published by the landing page must show the current purple-drive interface. Do not reuse screenshots from older releases as current marketing assets.
