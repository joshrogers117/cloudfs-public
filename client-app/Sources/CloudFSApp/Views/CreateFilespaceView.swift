// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

struct CreateFilespaceView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var step = 0
    @State private var name = ""
    @State private var storage: WorkspaceStorage?
    @State private var error: String?
    @State private var loading = true
    @State private var creating = false
    @FocusState private var nameFocused: Bool
    private let steps = ["Name", "Storage type", "Storage region", "Summary"]
    private let titles = ["Name your filespace", "Select storage type", "Storage region", "Review your filespace"]
    private var validName: Bool { !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && name.count <= 100 }

    var body: some View {
        VStack(spacing: 24) {
            HStack {
                Text("Create filespace").font(Theme.Font.body.weight(.semibold))
                Spacer()
                Button { dismiss() } label: { Image(systemName: "xmark") }.buttonStyle(.plain).disabled(creating).accessibilityLabel("Cancel filespace creation")
            }
            HStack(spacing: 20) {
                ForEach(steps.indices, id: \.self) { index in
                    HStack(spacing: 7) {
                        Text(index < step ? "✓" : String(index + 1)).font(Theme.Font.caption)
                            .frame(width: 24, height: 24)
                            .background(index < step ? Theme.accent : index == step ? Theme.primaryAction : Theme.surface, in: Circle())
                            .foregroundStyle(index <= step ? Theme.onAccent : Theme.textSecondary)
                        Text(steps[index]).font(Theme.Font.caption).foregroundStyle(index == step ? Theme.textPrimary : Theme.textSecondary)
                    }.accessibilityLabel("Step \(index + 1), \(steps[index])\(index == step ? ", current" : "")")
                }
            }.padding(.top, 10)
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    Text(titles[step]).font(.system(size: 26, weight: .semibold)).frame(maxWidth: .infinity).padding(.top, 20)
                    if let error { Banner(kind: .error, title: "Something needs attention", detail: error) }
                    if step == 0 {
                        Text("Give your filespace a name. You can always change it later.")
                            .font(Theme.Font.body).foregroundStyle(Theme.textSecondary).frame(maxWidth: .infinity)
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Filespace name").font(Theme.Font.caption)
                            TextField("Production", text: $name).textFieldStyle(.plain).padding(13)
                                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 7))
                                .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Theme.border))
                                .focused($nameFocused).onSubmit { if validName { step = 1 } }
                            if name.count > 100 { Text("Use 100 characters or fewer.").font(Theme.Font.caption).foregroundStyle(Theme.Status.error) }
                        }.padding(.top, 14)
                    } else if loading {
                        ProgressView("Checking workspace storage…").frame(maxWidth: .infinity).padding(30)
                    } else if let storage, storage.configured {
                        if step == 1 {
                            HStack(alignment: .top, spacing: 18) {
                                Image(systemName: "largecircle.fill.circle").foregroundStyle(Theme.accent)
                                VStack(alignment: .leading, spacing: 10) {
                                    Text("Workspace storage").font(.system(size: 18, weight: .semibold))
                                    Text("Use the \(storage.providerLabel) bucket already connected to your workspace.")
                                        .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                                }
                            }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
                                .background(Theme.selection, in: RoundedRectangle(cornerRadius: 12))
                                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.accent))
                            customStorageLink
                        } else if step == 2 {
                            VStack(alignment: .leading, spacing: 16) {
                                Label(storage.regionLabel, systemImage: "globe").font(Theme.Font.headline)
                                Text(storage.bucket).font(Theme.Font.body)
                                Text("Files use the connected bucket’s region. To choose a different region, connect a bucket in that region in the web console.")
                                    .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                            }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
                                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 12))
                        } else {
                            Card {
                                KeyValueRow(key: "Name", value: name.trimmingCharacters(in: .whitespacesAndNewlines))
                                KeyValueRow(key: "Storage", value: storage.providerLabel)
                                KeyValueRow(key: "Bucket", value: storage.bucket)
                                KeyValueRow(key: "Region", value: storage.regionLabel)
                            }
                        }
                    } else {
                        Text("Connect storage to your workspace before creating a filespace.").foregroundStyle(Theme.textSecondary)
                        customStorageLink
                        Button("Try again") { Task { await loadStorage() } }.cfButton(.secondary)
                    }
                }.frame(maxWidth: .infinity).padding(.horizontal, 1)
            }
            VStack(spacing: 14) {
                Button {
                    if step < 3 { step += 1; nameFocused = false }
                    else { Task { await create() } }
                } label: {
                    Text(creating ? "Creating filespace…" : step == 3 ? "Create filespace" : "Continue").frame(maxWidth: .infinity)
                }.cfButton(.primary, size: .large)
                    .disabled(!validName || creating || (step > 0 && (loading || storage?.configured != true)))
                HStack(spacing: 24) {
                    if step > 0 { Button("Back") { step -= 1 }.cfButton(.subtle).disabled(creating) }
                    Button("Cancel") { dismiss() }.cfButton(.subtle).disabled(creating)
                }
            }
        }.padding(32).frame(width: 640, height: 590).background(Theme.bg)
            .interactiveDismissDisabled(creating)
            .task { nameFocused = true; await loadStorage() }
    }

    @ViewBuilder private var customStorageLink: some View {
        if let url = model.consoleLinks.url(.createFilespace) {
            Link(destination: url) {
                HStack {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Connect a different storage bucket").font(Theme.Font.headline)
                        Text("Choose a provider and saved credentials in the web console.").font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                    }
                    Spacer()
                    Image(systemName: "arrow.up.right")
                }.padding(22).background(Theme.surface, in: RoundedRectangle(cornerRadius: 12))
                    .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Theme.border))
            }.buttonStyle(.plain)
        }
    }
    private func loadStorage() async {
        loading = true; error = nil
        defer { loading = false }
        do { storage = try await model.gateway.workspaceStorage() }
        catch { self.error = error.localizedDescription }
    }
    private func create() async {
        guard let storage, validName, model.canCreateFilespaces else { return }
        creating = true; error = nil
        defer { creating = false }
        do {
            let id = try await model.gateway.createWorkspaceFilespace(name: name, storage: storage)
            await model.reloadFilespaces()
            if model.isSignedIn { model.select(id) }
            dismiss()
        } catch { self.error = error.localizedDescription }
    }
}
