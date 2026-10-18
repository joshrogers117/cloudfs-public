// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - IconSet — the canonical SF Symbol registry
//
// A single, named source of truth for every SF Symbol the app draws, so glyph
// choices stay consistent and semantic (no scattered string literals). Lives in
// CloudFSKit (pure `String` names, no SwiftUI) so the mapping is unit-testable;
// the SwiftUI layer renders these via `Theme.Icon` + an `IconRole` size/weight.
//
// Add new glyphs here, never inline at a call site.

public enum IconSet {

    // Brand / app
    public static let brand          = "cloud.fill"

    // Navigation sections (mirror NavSection)
    public static let dashboard      = "rectangle.3.group"      // per-filespace overview (Dashboard section)
    public static let filespaces     = "square.stack.3d.up"
    public static let files          = "folder"             // retained: used by SnapshotsView row glyph
    public static let activity       = "arrow.up.arrow.down.circle"
    public static let audit          = "list.bullet.rectangle"   // historical audit log (WS3)
    public static let snapshots      = "clock.arrow.circlepath"
    public static let sharing        = "link"
    public static let cache          = "internaldrive"
    public static let preferences    = "gearshape"
    public static let membersNav     = "person.2.badge.gearshape"   // Members & Access section

    // Filespace / connection
    public static let filespace      = "square.stack.3d.up.fill"
    public static let filespaceCheck = "checkmark.circle.fill"
    public static let manage         = "slider.horizontal.3"
    public static let region         = "globe"
    public static let members        = "person.2"
    public static let storage        = "externaldrive.fill"
    public static let connectMore    = "plus.circle"
    public static let signOut        = "rectangle.portrait.and.arrow.right"
    public static let menuChevron    = "chevron.up.chevron.down"

    // Sync control
    public static let pause          = "pause.circle"
    public static let play           = "play.circle"
    public static let pauseFill      = "pause.circle.fill"
    public static let playFill       = "play.circle.fill"

    // Files / disclosure
    public static let folder         = "folder.fill"
    public static let document       = "doc"
    public static let chevronRight   = "chevron.right"
    public static let chevronDown    = "chevron.down"
    public static let locked         = "lock.fill"
    public static let shared         = "person.2.fill"

    // Navigation / search / sort (Files browser)
    public static let back           = "chevron.backward"
    public static let up             = "chevron.up"
    public static let crumbSeparator = "chevron.compact.right"
    public static let search         = "magnifyingglass"
    public static let clearSearch    = "xmark.circle.fill"
    public static let sort           = "arrow.up.arrow.down"
    public static let sortAscending  = "arrow.up"
    public static let sortDescending = "arrow.down"
    public static let foldersFirst   = "folder.badge.gearshape"

    // View-mode toggle (List ⇄ Gallery)
    public static let viewList       = "list.bullet"
    public static let viewGallery    = "square.grid.2x2"

    // Media kinds (gallery poster glyphs)
    public static let kindVideo      = "film"
    public static let kindImage      = "photo"
    public static let kindAudio      = "waveform"
    public static let kindProject    = "rectangle.stack"
    public static let kindDocument   = "doc.text"

    // Right-click actions
    public static let pin            = "pin"
    public static let unpin          = "pin.slash"
    public static let download       = "arrow.down.circle"
    public static let prefetch       = "arrow.down.to.line"
    public static let evict          = "xmark.bin"
    public static let copyLink       = "link"
    public static let guestLink      = "person.badge.shield.checkmark"
    public static let revealInFinder = "macwindow.and.cursorarrow"
    public static let getInfo        = "info.circle"
    public static let rename         = "pencil"
    public static let rowActions     = "ellipsis.circle"

    // Drag-and-drop
    public static let dropImport     = "square.and.arrow.down.on.square"
    public static let dropHere       = "tray.and.arrow.down.fill"

    // Per-pane toolbar actions (contextual, trailing)
    public static let newFolder      = "folder.badge.plus"
    public static let newLink        = "link.badge.plus"
    public static let newSnapshot    = "camera.badge.clock"
    public static let clearCompleted = "checklist.unchecked"
    public static let refresh        = "arrow.clockwise"
    public static let account        = "person.crop.circle"

    // Transfers (outline = menu-bar stat; fill = transfer row)
    public static let upload         = "arrow.up.circle.fill"
    public static let downloadFill   = "arrow.down.circle.fill"
    public static let uploadOutline  = "arrow.up.circle"
    // `downloadOutline` deliberately aliases `download` ("arrow.down.circle") —
    // the same glyph serves both the "Download Now" action and the menu-bar stat.
    public static let downloadOutline = download

    // Snapshots
    public static let scheduled      = "calendar.badge.clock"
    public static let manual         = "camera"
    public static let recreated      = "arrow.uturn.backward"
    public static let clock          = "clock"

    // Sharing
    public static let internalLink   = "link.circle.fill"
    public static let copy           = "doc.on.doc"
    public static let copied         = "checkmark"
    public static let trash          = "trash"

    // Cache / preferences
    public static let externalDrive  = "externaldrive.fill"
    public static let network        = "network"
    public static let key            = "key"
    public static let building       = "building.2"
    public static let envelope       = "envelope"
    public static let ssoProvider    = "person.badge.key"
    public static let window         = "macwindow"
    public static let quit           = "power"

    // Sidebar redesign — workspace header overflow menu + "Get Started" pill
    public static let devices        = "laptopcomputer"      // "My devices…"
    public static let externalLink   = "arrow.up.forward.square"  // "Open web console"
    public static let checklist      = "checklist"           // Get-Started pill

    // Members & Access
    public static let inviteUser     = "person.badge.plus"
    public static let changeRole     = "person.crop.circle.badge.checkmark"
    public static let suspend        = "person.crop.circle.badge.moon"
    public static let reactivate     = "person.crop.circle.badge.checkmark"
    public static let deprovision    = "person.crop.circle.badge.xmark"
    public static let group          = "person.3"
    public static let serviceAccount = "terminal"
    public static let addGrant       = "lock.badge.plus"
    public static let removeGrant    = "lock.slash"
    public static let folderGrant    = "folder.badge.person.crop"
    public static let mountRoot      = "arrow.down.right.and.arrow.up.left"
    public static let expires        = "hourglass"
    public static let roleOwner      = "crown"
    public static let roleAdmin      = "shield.lefthalf.filled"
    public static let roleStandard   = "person"

    // Status / banners
    public static let info           = "info.circle.fill"
    public static let success        = "checkmark.circle.fill"
    public static let warning        = "exclamationmark.triangle.fill"
    public static let error          = "xmark.octagon.fill"
    public static let errorOutline   = "exclamationmark.triangle"

    // Empty-state glyphs (outline variants for the friendly "nothing here" panes)
    public static let transfersIdle  = "checkmark.circle"     // no active transfers
    public static let activityIdle   = "person.2"             // no recent team activity

    /// Every referenced glyph (may include intentional aliases — see `distinct`).
    public static let all: [String] = [
        brand, dashboard, filespaces, files, activity, audit, snapshots, sharing, cache, preferences,
        membersNav,
        inviteUser, changeRole, suspend, reactivate, deprovision, group, serviceAccount,
        addGrant, removeGrant, folderGrant, mountRoot, expires,
        roleOwner, roleAdmin, roleStandard,
        filespace, filespaceCheck, manage, region, members, storage, connectMore,
        signOut, menuChevron, pause, play, pauseFill, playFill, folder, document,
        chevronRight, chevronDown, locked, shared,
        back, up, crumbSeparator, search, clearSearch, sort, sortAscending,
        sortDescending, foldersFirst,
        viewList, viewGallery,
        kindVideo, kindImage, kindAudio, kindProject, kindDocument,
        pin, unpin, download, prefetch,
        evict, copyLink, guestLink, revealInFinder, getInfo, rename, rowActions,
        dropImport, dropHere,
        newFolder, newLink, newSnapshot, clearCompleted, refresh, account,
        upload, downloadFill, uploadOutline, downloadOutline,
        scheduled, manual, recreated,
        clock, internalLink, copy, copied, trash, externalDrive, network, key,
        building, envelope, ssoProvider, window, quit, info, success, warning,
        error, errorOutline, transfersIdle, activityIdle,
        devices, externalLink, checklist,
    ]

    /// The set of distinct SF Symbol names referenced (intentional aliases — e.g.
    /// `sharing`/`copyLink` both `link` — collapse here). Used for audits/tests.
    public static var distinct: Set<String> { Set(all) }
}
