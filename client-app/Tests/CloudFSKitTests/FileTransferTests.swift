// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Drag-and-drop decision logic (pure): the export representation a dragged row
// hands a target, and the drop-accept rules. The view layer wires the actual
// NSItemProvider / .dropDestination to these decisions.

@Suite(.timeLimit(.minutes(1)))
struct FileTransferTests {

    private func node(_ state: MaterializationState,
                      dir: Bool = false,
                      name: String = "Clip.mov",
                      locked: String? = nil) -> FileNode {
        FileNode(id: "ShowA/\(name)", name: name, isDirectory: dir, sizeBytes: 10,
                 modified: Date(), state: state, lockedBy: locked,
                 isShared: false, childCount: dir ? 3 : 0)
    }

    // MARK: DragExport — file URL when local, deep link otherwise

    @Test func localFileDragsAsFileURL() {
        let rep = DragExport.representation(for: node(.downloaded),
                                            spaceId: "active-edit",
                                            mountPath: "/Volumes/cloudfs")
        #expect(rep == .fileURL(path: "/Volumes/cloudfs/Clip.mov"))
    }

    @Test func pinnedFileAlsoDragsAsFileURL() {
        let rep = DragExport.representation(for: node(.pinned),
                                            spaceId: "active-edit",
                                            mountPath: "/Volumes/cloudfs")
        #expect(rep == .fileURL(path: "/Volumes/cloudfs/Clip.mov"))
    }

    @Test func cloudOnlyFileDragsAsDeepLink() {
        let rep = DragExport.representation(for: node(.dataless),
                                            spaceId: "active-edit",
                                            mountPath: "/Volumes/cloudfs")
        // Not local → cloudfs:// link, never forces a download.
        #expect(rep == .deepLink(url: "cloudfs://active-edit/Clip.mov"))
    }

    @Test func streamingAndUploadingDragAsDeepLink() {
        for s in [MaterializationState.streaming, .uploading] {
            let rep = DragExport.representation(for: node(s),
                                                spaceId: "active-edit",
                                                mountPath: "/Volumes/cloudfs")
            #expect(rep == .deepLink(url: "cloudfs://active-edit/Clip.mov"))
        }
    }

    @Test func absentMountFallsBackToDeepLinkEvenWhenLocal() {
        // No File Provider mount present (stub) → link, since there's no file URL.
        for mount in [String?.none, ""] {
            let rep = DragExport.representation(for: node(.downloaded),
                                                spaceId: "active-edit",
                                                mountPath: mount)
            #expect(rep == .deepLink(url: "cloudfs://active-edit/Clip.mov"))
        }
    }

    // MARK: DropTarget — only folders accept drops

    @Test func folderAcceptsDrop() {
        #expect(DropTarget.acceptsDrop(into: node(.downloaded, dir: true)))
    }

    @Test func fileDoesNotAcceptDrop() {
        #expect(!DropTarget.acceptsDrop(into: node(.downloaded, dir: false)))
    }

    @Test func lockedFolderRefusesDrop() {
        #expect(!DropTarget.acceptsDrop(into: node(.downloaded, dir: true, locked: "Mara")))
    }

    @Test func rootAcceptsDropOnlyWithSelection() {
        #expect(DropTarget.rootAcceptsDrop(filespaceSelected: true))
        #expect(!DropTarget.rootAcceptsDrop(filespaceSelected: false))
    }

    // MARK: Drag-to-pin meaningfulness

    @Test func dragToPinMeaningfulUnlessAlreadyPinned() {
        #expect(DropTarget.dragToPinIsMeaningful(for: node(.dataless)))
        #expect(DropTarget.dragToPinIsMeaningful(for: node(.downloaded)))
        #expect(!DropTarget.dragToPinIsMeaningful(for: node(.pinned)))
    }
}

// MARK: - Reduce-Motion gating

@Suite(.timeLimit(.minutes(1)))
struct MotionGateTests {

    @Test func animatesWhenReduceMotionOff() {
        #expect(MotionGate.shouldAnimate(reduceMotion: false))
    }

    @Test func doesNotAnimateWhenReduceMotionOn() {
        #expect(!MotionGate.shouldAnimate(reduceMotion: true))
    }
}
