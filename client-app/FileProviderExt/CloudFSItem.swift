// SPDX-License-Identifier: AGPL-3.0-or-later
import FileProvider
import UniformTypeIdentifiers

/// An `NSFileProviderItem` backed by the daemon's `ItemMetadata` (wire: `WireItem`).
///
/// Read/enumerate only for now (the daemon's out-of-process write path is a later stage);
/// `capabilities` advertises exactly what the appex currently honours so Finder doesn't
/// offer actions that would fail. `itemVersion` is taken verbatim from the daemon's
/// content/metadata versions — both are derived from the block-manifest hash on the daemon
/// side, so they're stable across re-fetches (a stable contentVersion is required or the
/// system invalidates cached partial materializations and ranged reads fail with EINVAL).
final class CloudFSItem: NSObject, NSFileProviderItem {
    let identifierString: String
    let parentString: String
    let name: String
    let isFolder: Bool
    let byteSize: Int64
    let contentVersionData: Data
    let metadataVersionData: Data

    init(_ w: WireItem) {
        self.identifierString = w.id
        // A nil/"root" parent maps to the synthetic root container.
        let p = w.parent ?? "root"
        self.parentString = (p == "root") ? NSFileProviderItemIdentifier.rootContainer.rawValue : p
        self.name = w.name
        self.isFolder = w.isDir
        self.byteSize = Int64(w.size)
        // Each itemVersion component must be ≤ 128 bytes (hard, documented limit).
        self.contentVersionData = Data(w.contentVersion.utf8.prefix(128))
        self.metadataVersionData = Data(w.metadataVersion.utf8.prefix(128))
    }

    /// The synthetic root container, named for the filespace so Finder's sidebar shows the
    /// filespace name (NOT "fuse-t" or a generic label).
    static func root(displayName: String) -> CloudFSItem {
        let w = WireItem(id: NSFileProviderItemIdentifier.rootContainer.rawValue, parent: nil,
                         name: displayName, isDir: true, size: 0,
                         contentVersion: "root", metadataVersion: "root")
        return CloudFSItem(w)
    }

    // MARK: NSFileProviderItem

    var itemIdentifier: NSFileProviderItemIdentifier { NSFileProviderItemIdentifier(identifierString) }
    var parentItemIdentifier: NSFileProviderItemIdentifier { NSFileProviderItemIdentifier(parentString) }
    var filename: String { name }

    var contentType: UTType {
        if isFolder { return .folder }
        let ext = (name as NSString).pathExtension
        return UTType(filenameExtension: ext) ?? .data
    }

    var capabilities: NSFileProviderItemCapabilities {
        isFolder ? [.allowsReading, .allowsContentEnumerating] : [.allowsReading]
    }

    var documentSize: NSNumber? { isFolder ? nil : NSNumber(value: byteSize) }

    var itemVersion: NSFileProviderItemVersion {
        NSFileProviderItemVersion(contentVersion: contentVersionData, metadataVersion: metadataVersionData)
    }
}
