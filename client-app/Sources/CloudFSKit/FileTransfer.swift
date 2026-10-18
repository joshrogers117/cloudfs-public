// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - Drag-and-drop logic (pure, testable)
//
// The DECISION logic behind Files-browser drag/drop lives here (no SwiftUI), so
// the export-representation choice and the drop-accept rules are unit-tested. The
// view layer wires the actual `NSItemProvider` / `.dropDestination` to these.

public enum DragExport {

    /// What a dragged file row should hand to the drop target (Finder, etc.).
    public enum Representation: Sendable, Equatable {
        /// A real on-disk file URL — used when the item is materialized locally
        /// (downloaded or pinned), so dragging to Finder copies the actual file.
        case fileURL(path: String)
        /// The internal `cloudfs://` deep link — used when the item is NOT local
        /// yet (cloud-only / streaming / uploading): dragging exports a link the
        /// recipient's client resolves, without forcing a download.
        case deepLink(url: String)
    }

    /// Pick the export representation for `node` in `spaceId`, given the mount
    /// path (nil/absent when the File Provider mount isn't present — e.g. the
    /// stub), in which case we always fall back to the deep link.
    public static func representation(for node: FileNode,
                                      spaceId: String,
                                      mountPath: String?) -> Representation {
        let isLocal = node.state == .downloaded || node.state == .pinned
        if isLocal, let mount = mountPath, !mount.isEmpty {
            let base = (mount as NSString).expandingTildeInPath
            return .fileURL(path: base + "/" + node.name)
        }
        return .deepLink(url: DeepLink.build(spaceId: spaceId, path: node.name))
    }
}

// MARK: - Drop-accept rules

public enum DropTarget {

    /// Whether a row can be a *drop destination* for files. Only directories
    /// accept drops (you drop INTO a folder); a file row is not a container.
    /// A folder locked by another editor refuses drops.
    public static func acceptsDrop(into node: FileNode) -> Bool {
        node.isDirectory && node.lockedBy == nil
    }

    /// Whether the Files pane *root* accepts a drop (drop onto empty space /
    /// the list background). Always true when a filespace is selected.
    public static func rootAcceptsDrop(filespaceSelected: Bool) -> Bool {
        filespaceSelected
    }

    /// Whether dragging a row onto the **Cache** nav target should PIN it
    /// (drag-to-pin). Only meaningful for not-already-pinned items.
    public static func dragToPinIsMeaningful(for node: FileNode) -> Bool {
        node.state != .pinned
    }
}
