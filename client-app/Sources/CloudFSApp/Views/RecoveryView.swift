// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

struct RecoverySection: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if let notice = model.recovery.completionNotice {
            Banner(kind: .success, title: "Recovery finished", detail: notice)
        }
        if let message = model.recovery.state.errorMessage {
            Banner(kind: .warning, title: "Couldn’t check local recovery", detail: message,
                   actionTitle: "Try again") { Task { await model.loadRecoveryItems() } }
        } else if model.recovery.state.isInitial && model.recovery.items.isEmpty {
            InlineLoading(text: "Checking local changes…")
        }
        let items = model.recovery.items
            if !items.isEmpty {
                VStack(alignment: .leading, spacing: 18) {
                    HStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.Status.warn)
                        Text("Needs attention (\(items.count))").font(.system(size: 18, weight: .semibold))
                        Spacer()
                    }
                    Text("These changes are kept on this Mac, but have not been saved to the cloud. Keep the cache until recovery is complete.")
                        .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if !model.isHttpMode {
                        Text("Demo recovery examples. No real files are affected.")
                            .font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
                    }
                    ForEach(items) { item in
                        RecoveryRow(item: item)
                        if item.id != items.last?.id { Divider().overlay(Theme.border) }
                    }
                }
                .padding(22)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: Theme.Radius.md))
                .overlay(RoundedRectangle(cornerRadius: Theme.Radius.md).strokeBorder(Theme.Status.warn.opacity(0.35)))
            }
    }
}

private struct RecoveryRow: View {
    @Environment(AppModel.self) private var model
    let item: RecoveryItem
    @State private var confirmCompletion = false
    private var busy: Bool { model.recovery.busyIDs.contains(item.id) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(item.displayName).font(Theme.Font.body.weight(.semibold))
                    .lineLimit(2).truncationMode(.middle).help(item.path ?? item.id)
                Spacer(minLength: 8)
                Text(ByteFormat.string(item.bytes)).font(Theme.Font.monoMicro)
                    .foregroundStyle(Theme.textTertiary)
            }
            Text(item.statusTitle).font(Theme.Font.caption.weight(.medium)).foregroundStyle(Theme.Status.warn)
            Text(item.reason).font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            if !item.canRetry {
                Text("Save a separate copy to review alongside the team’s version. Retrying will not replace someone else’s changes.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
            }
            if !item.canExport {
                Text("A complete copy cannot be reconstructed safely yet. Your preserved local data remains in the cache.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.Status.warn)
            }
            HStack(spacing: 14) {
                Button { model.saveRecoveryCopy(item) } label: {
                    Label("Save local copy…", systemImage: "square.and.arrow.down")
                }.cfButton(.secondary, size: .small)
                    .disabled(busy || !item.canExport || !model.isHttpMode)
                if item.canRetry {
                    Button("Retry upload") { Task { await model.retryRecovery(item) } }
                        .cfButton(.subtle, size: .small).disabled(busy || !model.isHttpMode)
                }
                if busy { ProgressView().controlSize(.small) }
                Spacer(minLength: 0)
            }
            if let error = model.recovery.actionErrors[item.id] {
                Banner(kind: .error, title: "Recovery needs attention", detail: error)
            }
            if let saved = model.recovery.savedCopies[item.id] {
                HStack(spacing: 12) {
                    Label("Local copy saved · \(ByteFormat.string(saved.bytes))", systemImage: "checkmark.circle.fill")
                        .font(Theme.Font.caption).foregroundStyle(Theme.Status.ok)
                    Spacer()
                    Button("Show in Finder") {
                        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: saved.path)])
                    }.cfButton(.subtle, size: .small)
                }
                Text("The pending write is still preserved. Finish recovery to use the team’s current version in the filespace, keeping this separate copy.")
                    .font(Theme.Font.caption).foregroundStyle(Theme.textTertiary)
                Button("Finish recovery…") { confirmCompletion = true }
                    .cfButton(.subtle, size: .small).disabled(busy)
            }
        }
        .padding(.vertical, 4)
        .confirmationDialog("Finish recovery for \(item.displayName)?", isPresented: $confirmCompletion,
                            titleVisibility: .visible) {
            Button("Finish recovery") { Task { await model.completeRecovery(item) } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("CloudFS will verify the saved copy, then remove this pending local edit from the upload queue. The team’s cloud version stays unchanged. Keep your copy to review or upload under a new name.")
        }
    }
}
