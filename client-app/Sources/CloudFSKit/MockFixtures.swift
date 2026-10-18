// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - MockFixtures
//
// Plausible post-house fake data: two filespaces, a media/project folder tree
// with mixed materialization states, in-flight transfers, GFS snapshots, share
// links, and cache stats. Centralized here so MockGatewayClient stays logic-only
// and SwiftUI previews can reuse the same fixtures.

public struct MockFixtures: Sendable {
    public var spaces: [Filespace]
    public var trees: [String: [String?: [FileNode]]]
    public var activity: [String: [ActivityEvent]]
    public var transfers: [String: [Transfer]]
    public var snapshots: [String: [Snapshot]]
    public var snapshotTrees: [String: [String?: [FileNode]]]
    public var links: [String: [CloudShareLink]]
    public var caches: [String: CacheSettings]

    private static let GiB: Int64 = 1024 * 1024 * 1024
    private static let MiB: Int64 = 1024 * 1024

    public static func defaultCache() -> CacheSettings {
        CacheSettings(
            maxBytes: 250 * GiB, usedBytes: 96 * GiB, pinnedBytes: 38 * GiB,
            location: "/Users/editor/Library/Caches/cloud-fs",
            prefetchEnabled: true, prefetchDepth: 8)
    }

    public static func build() -> MockFixtures {
        let now = Date()
        func ago(_ s: TimeInterval) -> Date { now.addingTimeInterval(-s) }

        // --- Filespaces -----------------------------------------------------
        let studioA = Filespace(
            id: "fs-studio-a", name: "Studio A — Editorial", region: "ENAM (us-east)",
            storageBackend: "Cloudflare R2", connection: .connected, role: .filespaceAdmin,
            usedBytes: 14 * 1024 * GiB, memberCount: 22,
            mountPath: "~/Library/CloudStorage/cloud-fs-Studio A — Editorial")
        let archive = Filespace(
            id: "fs-archive", name: "Archive 2025", region: "WNAM (us-west)",
            storageBackend: "Backblaze B2 + CDN", connection: .paused, role: .standard,
            usedBytes: 312 * 1024 * GiB, memberCount: 30,
            mountPath: "~/Library/CloudStorage/cloud-fs-Archive 2025")
        let spaces = [studioA, archive]

        // --- File tree for Studio A ----------------------------------------
        let rootA: [FileNode] = [
            FileNode(id: "a-projects", name: "Projects", isDirectory: true, sizeBytes: 0,
                     modified: ago(3600), state: .downloaded, childCount: 4),
            FileNode(id: "a-footage", name: "Footage", isDirectory: true, sizeBytes: 0,
                     modified: ago(7200), state: .dataless, childCount: 6),
            FileNode(id: "a-proxies", name: "Proxies", isDirectory: true, sizeBytes: 0,
                     modified: ago(1800), state: .pinned, childCount: 3),
            FileNode(id: "a-exports", name: "Exports", isDirectory: true, sizeBytes: 0,
                     modified: ago(600), state: .downloaded, childCount: 2)
        ]
        let projectsA: [FileNode] = [
            FileNode(id: "a-proj-hero", name: "Hero Spot v7.prproj", isDirectory: false,
                     sizeBytes: 84 * MiB, modified: ago(420), state: .uploading,
                     lockedBy: nil, isShared: true),
            FileNode(id: "a-proj-cut", name: "Director Cut.fcpbundle", isDirectory: false,
                     sizeBytes: 1240 * MiB, modified: ago(900), state: .pinned,
                     lockedBy: "Mara P."),
            FileNode(id: "a-proj-resolve", name: "Color Pass.drp", isDirectory: false,
                     sizeBytes: 56 * MiB, modified: ago(5400), state: .downloaded),
            FileNode(id: "a-proj-notes", name: "Notes.md", isDirectory: false,
                     sizeBytes: 12 * 1024, modified: ago(120), state: .downloaded)
        ]
        let footageA: [FileNode] = [
            FileNode(id: "a-foot-a001", name: "A001_C002.R3D", isDirectory: false,
                     sizeBytes: 4 * GiB, modified: ago(86_400), state: .dataless),
            FileNode(id: "a-foot-a002", name: "A001_C003.R3D", isDirectory: false,
                     sizeBytes: 4 * GiB, modified: ago(86_400), state: .streaming),
            FileNode(id: "a-foot-b001", name: "B001_0007.mov", isDirectory: false,
                     sizeBytes: 9 * GiB, modified: ago(172_800), state: .dataless,
                     lockedBy: "Devin K."),
            FileNode(id: "a-foot-aud", name: "Scene12_BoomMix.wav", isDirectory: false,
                     sizeBytes: 220 * MiB, modified: ago(90_000), state: .downloaded),
            FileNode(id: "a-foot-prx", name: "ProRes Proxy", isDirectory: true, sizeBytes: 0,
                     modified: ago(80_000), state: .pinned, childCount: 12),
            FileNode(id: "a-foot-stills", name: "Stills", isDirectory: true, sizeBytes: 0,
                     modified: ago(95_000), state: .dataless, childCount: 48)
        ]
        let proxiesA: [FileNode] = [
            FileNode(id: "a-prx-1", name: "Reel1_proxy.mov", isDirectory: false,
                     sizeBytes: 1800 * MiB, modified: ago(4000), state: .pinned),
            FileNode(id: "a-prx-2", name: "Reel2_proxy.mov", isDirectory: false,
                     sizeBytes: 1700 * MiB, modified: ago(4200), state: .pinned),
            FileNode(id: "a-prx-3", name: "Reel3_proxy.mov", isDirectory: false,
                     sizeBytes: 1900 * MiB, modified: ago(4400), state: .downloaded)
        ]
        let exportsA: [FileNode] = [
            FileNode(id: "a-exp-1", name: "HeroSpot_H264_master.mp4", isDirectory: false,
                     sizeBytes: 640 * MiB, modified: ago(300), state: .uploading, isShared: true),
            FileNode(id: "a-exp-2", name: "HeroSpot_ProRes422HQ.mov", isDirectory: false,
                     sizeBytes: 7 * GiB, modified: ago(900), state: .downloaded)
        ]

        // Stills (image-heavy) — gives the Gallery view varied poster tiles.
        let stillsA: [FileNode] = [
            FileNode(id: "a-still-1", name: "Frame_grab_01.tiff", isDirectory: false,
                     sizeBytes: 28 * MiB, modified: ago(95_500), state: .downloaded),
            FileNode(id: "a-still-2", name: "Frame_grab_02.tiff", isDirectory: false,
                     sizeBytes: 27 * MiB, modified: ago(95_400), state: .dataless),
            FileNode(id: "a-still-3", name: "Keyart_concept.psd", isDirectory: false,
                     sizeBytes: 410 * MiB, modified: ago(96_000), state: .pinned, isShared: true),
            FileNode(id: "a-still-4", name: "Lookdev_A.png", isDirectory: false,
                     sizeBytes: 6 * MiB, modified: ago(94_800), state: .streaming),
            FileNode(id: "a-still-5", name: "Reference_grade.jpg", isDirectory: false,
                     sizeBytes: 3 * MiB, modified: ago(94_200), state: .downloaded),
            FileNode(id: "a-still-6", name: "Mood_board.pdf", isDirectory: false,
                     sizeBytes: 18 * MiB, modified: ago(93_000), state: .downloaded)
        ]

        var treeA: [String?: [FileNode]] = [:]
        treeA[nil] = rootA
        treeA["a-projects"] = projectsA
        treeA["a-footage"] = footageA
        treeA["a-proxies"] = proxiesA
        treeA["a-exports"] = exportsA
        treeA["a-foot-stills"] = stillsA

        // --- Minimal tree for the Archive ----------------------------------
        let rootArchive: [FileNode] = [
            FileNode(id: "ar-2025q1", name: "2025-Q1", isDirectory: true, sizeBytes: 0,
                     modified: ago(2_600_000), state: .dataless, childCount: 120),
            FileNode(id: "ar-2025q2", name: "2025-Q2", isDirectory: true, sizeBytes: 0,
                     modified: ago(1_900_000), state: .dataless, childCount: 98),
            FileNode(id: "ar-masters", name: "Delivered Masters", isDirectory: true, sizeBytes: 0,
                     modified: ago(900_000), state: .dataless, childCount: 240)
        ]
        let treeArchive: [String?: [FileNode]] = [nil: rootArchive]

        let trees: [String: [String?: [FileNode]]] = [
            "fs-studio-a": treeA,
            "fs-archive": treeArchive
        ]

        // --- Activity feed --------------------------------------------------
        let activityA: [ActivityEvent] = [
            ActivityEvent(id: "ev1", actor: "Mara P.", verb: "locked", path: "Projects/Director Cut.fcpbundle", at: ago(180)),
            ActivityEvent(id: "ev2", actor: "Devin K.", verb: "is streaming", path: "Footage/B001_0007.mov", at: ago(420)),
            ActivityEvent(id: "ev3", actor: "You", verb: "uploaded", path: "Exports/HeroSpot_H264_master.mp4", at: ago(900)),
            ActivityEvent(id: "ev4", actor: "Sasha R.", verb: "pinned", path: "Proxies/Reel1_proxy.mov", at: ago(3600)),
            ActivityEvent(id: "ev5", actor: "Jules T.", verb: "restored", path: "Projects/Color Pass.drp", at: ago(7200))
        ]

        // --- Transfers ------------------------------------------------------
        let transfersA: [Transfer] = [
            Transfer(id: "t1", fileName: "HeroSpot_H264_master.mp4", kind: .upload, state: .active,
                     bytesDone: 220 * MiB, bytesTotal: 640 * MiB,
                     throughputBytesPerSec: 38 * MiB, startedAt: ago(20)),
            Transfer(id: "t2", fileName: "A001_C003.R3D", kind: .download, state: .active,
                     bytesDone: 1200 * MiB, bytesTotal: 4 * GiB,
                     throughputBytesPerSec: 52 * MiB, startedAt: ago(40)),
            Transfer(id: "t3", fileName: "Reel3_proxy.mov", kind: .download, state: .completed,
                     bytesDone: 1900 * MiB, bytesTotal: 1900 * MiB,
                     throughputBytesPerSec: 0, startedAt: ago(600)),
            Transfer(id: "t4", fileName: "Scene12_BoomMix.wav", kind: .upload, state: .queued,
                     bytesDone: 0, bytesTotal: 220 * MiB,
                     throughputBytesPerSec: 0, startedAt: ago(5))
        ]

        // --- Snapshots (GFS) ------------------------------------------------
        let snapsA: [Snapshot] = [
            Snapshot(id: "snap-h1", name: "Hourly 14:00", takenAt: ago(1800),
                     sizeBytes: 14 * 1024 * GiB, isScheduled: true, retentionTier: "Hourly"),
            Snapshot(id: "snap-h2", name: "Hourly 13:00", takenAt: ago(5400),
                     sizeBytes: 14 * 1024 * GiB, isScheduled: true, retentionTier: "Hourly"),
            Snapshot(id: "snap-d1", name: "Daily 2026-06-03", takenAt: ago(90_000),
                     sizeBytes: 13 * 1024 * GiB, isScheduled: true, retentionTier: "Daily"),
            Snapshot(id: "snap-w1", name: "Weekly 2026-W22", takenAt: ago(520_000),
                     sizeBytes: 12 * 1024 * GiB, isScheduled: true, retentionTier: "Weekly"),
            Snapshot(id: "snap-m1", name: "Manual: pre-conform", takenAt: ago(260_000),
                     sizeBytes: 13 * 1024 * GiB, isScheduled: false, retentionTier: "Manual")
        ]

        // --- Share links ----------------------------------------------------
        let linksA: [CloudShareLink] = [
            CloudShareLink(id: "lk1", path: "/Exports/HeroSpot_H264_master.mp4",
                      kind: .guestLink, url: "https://share.cloud-fs.example/g/9fA2bQ7xK0",
                      expiresAt: ago(-5 * 86_400), canDownload: true, canEdit: false),
            CloudShareLink(id: "lk2", path: "/Projects/Hero Spot v7.prproj",
                      kind: .internalDeepLink, url: "cloudfs://fs-studio-a/Projects/Hero Spot v7.prproj",
                      expiresAt: nil, canDownload: true, canEdit: true)
        ]

        // --- Caches ---------------------------------------------------------
        let caches: [String: CacheSettings] = [
            "fs-studio-a": defaultCache(),
            "fs-archive": CacheSettings(
                maxBytes: 100 * GiB, usedBytes: 12 * GiB, pinnedBytes: 0,
                location: "/Volumes/ScratchNVMe/cloud-fs-archive",
                prefetchEnabled: false, prefetchDepth: 4)
        ]

        return MockFixtures(
            spaces: spaces, trees: trees,
            activity: ["fs-studio-a": activityA, "fs-archive": []],
            transfers: ["fs-studio-a": transfersA, "fs-archive": []],
            snapshots: ["fs-studio-a": snapsA, "fs-archive": []],
            snapshotTrees: [:],
            links: ["fs-studio-a": linksA, "fs-archive": []],
            caches: caches)
    }
}
