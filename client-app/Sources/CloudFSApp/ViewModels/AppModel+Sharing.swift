// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import Observation
import CloudFSKit

@MainActor @Observable
final class SharingFeatureModel {
    var error: String?
    var copiedRoot = false
    var creating = false
    var busyIDs: Set<String> = []
}

extension AppModel {
    func copyFilespaceLink() async {
        guard let id = selectedFilespaceID, !sharing.creating else { return }
        sharing.creating = true
        sharing.error = nil
        defer { sharing.creating = false }
        do {
            let link = try await gateway.createShareLink(for: "", kind: .internalDeepLink, in: id)
            guard !link.url.isEmpty else { throw EngineError.decoding("The filespace link was empty.") }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(link.url, forType: .string)
            if selectedFilespaceID == id { sharing.copiedRoot = true }
        } catch {
            if selectedFilespaceID == id { sharing.error = error.localizedDescription }
        }
    }

    func revokeShare(_ link: CloudShareLink) async {
        guard canManageGuestLinks, let id = selectedFilespaceID, !sharing.busyIDs.contains(link.id) else { return }
        sharing.busyIDs.insert(link.id)
        sharing.error = nil
        defer { sharing.busyIDs.remove(link.id) }
        do {
            try await gateway.revokeShareLink(link.id, in: id)
            guard selectedFilespaceID == id else { return }
            shareLinks.removeAll { $0.id == link.id }
            shareLinksState = .loaded(shareLinks)
        } catch {
            if selectedFilespaceID == id { sharing.error = "Could not revoke this link. \(error.localizedDescription)" }
        }
    }
}
