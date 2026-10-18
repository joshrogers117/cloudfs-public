// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

struct FilespaceDetailsSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let filespace: Filespace
    private var fs: Filespace { model.filespaces.first { $0.id == filespace.id } ?? filespace }
    private var mounted: Bool { !fs.mountPath.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            HStack {
                Text("FILESPACE DETAILS").font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                Spacer()
                Button { dismiss() } label: { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("Close filespace details")
            }
            HStack(spacing: 18) {
                FilespaceDriveIllustration(size: 76)
                VStack(alignment: .leading, spacing: 8) {
                    Text(fs.name).font(.system(size: 24, weight: .semibold))
                    HStack { StatusDot(color: fs.connection.dotColor); Text(fs.connection.label).font(Theme.Font.body) }
                }
            }
            HStack(spacing: 12) {
                if mounted {
                    Button("Open filespace") { model.revealFilespaceInFinder(fs) }.cfButton(.primary)
                    Button("Disconnect") { Task { await model.unmountSelected() } }.cfButton(.secondary)
                        .disabled(model.dashboard.busyFilespaces.contains(fs.id) || model.selectedFilespaceID != fs.id)
                } else {
                    Button("Connect") { Task { await model.mountSelected() } }.cfButton(.primary)
                        .disabled(model.dashboard.busyFilespaces.contains(fs.id) || model.selectedFilespaceID != fs.id)
                }
            }
            VStack(spacing: 0) {
                detail("Cloud provider", fs.storageBackend, shaded: true)
                detail("Region", fs.region)
                detail("Used storage", fs.storageDisplay, shaded: true)
                detail("Location on this Mac", mounted ? fs.mountPath : "Not connected")
                detail("Remaining upload", remainingUpload, shaded: true)
                detail("Your role", fs.displayRole(orgRole: model.members.currentRole).rawValue)
            }
            CopyableKeyValueRow(key: "Filespace ID", value: fs.id)
        }.padding(28).frame(width: 540).background(Theme.bg)
    }

    private var remainingUpload: String {
        guard model.selectedFilespaceID == fs.id, let bytes = model.dashboard.pendingUploadBytes else { return "Unavailable" }
        return ByteFormat.string(bytes)
    }
    private func detail(_ title: String, _ value: String, shaded: Bool = false) -> some View {
        HStack(spacing: 24) {
            Text(title).foregroundStyle(Theme.textSecondary)
            Spacer(minLength: 12)
            Text(value).multilineTextAlignment(.trailing).textSelection(.enabled)
        }.font(Theme.Font.body).padding(14).background(shaded ? Theme.surface : .clear, in: RoundedRectangle(cornerRadius: 6))
    }
}
