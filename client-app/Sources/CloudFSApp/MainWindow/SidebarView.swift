// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

/// Workspace identity stays separate from the selected volume's controls.
struct SidebarView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            workspaceHeader
            Divider().overlay(Theme.divider).padding(.horizontal, 14)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        Text("Filespaces (\(model.filespaces.count))")
                            .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                        Spacer()
                        if model.canCreateFilespaces, model.isHttpMode {
                            IconButton("plus.circle", label: "Create filespace") {
                                model.isCreatingFilespace = true
                            }
                        }
                    }
                    .padding(.horizontal, 8).padding(.top, 20).padding(.bottom, 10)

                    ForEach(model.filespaces) { fs in
                        FilespaceNavGroup(filespace: fs, isSelected: fs.id == model.selectedFilespaceID)
                    }
                    if model.filespaces.isEmpty {
                        Text(model.canCreateFilespaces ? "Create a filespace in the web console, then refresh here." : "Ask your administrator for filespace access, then refresh here.")
                            .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true).padding(12)
                    }
                }
                .padding(.horizontal, 8)
            }
            Spacer(minLength: 12)
            if model.isHttpMode, !(model.settings.onboardingCompletedOnDevice && model.onboarding.allHealthy) {
                Button { model.rerunOnboardingChecklist() } label: {
                    Label("Setup checklist", systemImage: "checklist")
                        .frame(maxWidth: .infinity)
                }
                .cfButton(.secondary, size: .small)
                .padding(.horizontal, 32).padding(.bottom, 20)
            }
        }
        .background(Theme.bgSidebar)
        .task(id: "\(model.selectedFilespaceID ?? ""):\(model.navigationRequestID)") { await model.loadGrants() }
    }

    private var workspaceHeader: some View {
        HStack(spacing: 10) {
            Button { model.section = .filespaces } label: {
                HStack(spacing: 10) {
                    Image(systemName: "house").font(.system(size: 21, weight: .regular))
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Workspace").font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                        Text(model.workspaceDisplayName).font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(Theme.textPrimary).lineLimit(1)
                    }
                }
                .contentShape(Rectangle())
            }.buttonStyle(.plain).accessibilityLabel("Workspace dashboard, \(model.workspaceDisplayName)")
            Spacer(minLength: 0)
            Menu {
                if model.canCreateFilespaces, model.isHttpMode {
                    Button("Create filespace…", systemImage: "plus.circle") { model.isCreatingFilespace = true }
                }
                Button("All filespaces", systemImage: IconSet.filespaces) { model.section = .filespaces }
                Divider()
                if model.members.currentRole.canManageMembers {
                    Button("Members", systemImage: IconSet.members) {
                        model.members.tab = .members; model.section = .members
                    }
                    Button("Groups", systemImage: IconSet.group) {
                        model.members.tab = .groups; model.section = .members
                    }
                }
                if model.canManageFolderAccess {
                    Button("Access and permissions", systemImage: IconSet.folderGrant) {
                        model.members.tab = .access; model.section = .members
                    }
                }
                Button("Preferences…", systemImage: IconSet.preferences) { model.section = .preferences }
                if model.isHttpMode {
                    Divider()
                    Button("Open web console", systemImage: IconSet.externalLink) { openConsole(.root) }
                    Button("My devices…", systemImage: IconSet.devices) { openConsole(.devices) }
                }
            } label: { Image(systemName: "ellipsis").rotationEffect(.degrees(90)) }
                .menuStyle(.borderlessButton).fixedSize()
                .accessibilityLabel("Workspace menu")
        }
        .padding(.horizontal, 16).padding(.vertical, 20)
    }

    private func openConsole(_ path: ConsoleLinks.Path) {
        guard let url = model.consoleLinks.url(path) else { return }
        NSWorkspace.shared.open(url)
    }
}

private struct FilespaceNavGroup: View {
    @Environment(AppModel.self) private var model
    @State private var showDetails = false
    let filespace: Filespace
    let isSelected: Bool
    private var isMounted: Bool { !filespace.mountPath.isEmpty && (filespace.connection == .connected || filespace.connection == .paused) }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 9) {
                Button { model.select(filespace.id) } label: {
                    HStack(spacing: 9) {
                        Image(systemName: "externaldrive").font(.system(size: 17))
                        Text(filespace.name).font(Theme.Font.body.weight(.semibold)).lineLimit(1)
                        Spacer(minLength: 0)
                    }.contentShape(Rectangle())
                }.buttonStyle(.plain)
                if isMounted, model.isHttpMode {
                    Button("Open") { model.revealFilespaceInFinder(filespace) }
                        .cfButton(.secondary, size: .mini)
                        .help("Open \(filespace.name) in Finder")
                } else if isSelected, model.isHttpMode {
                    Button("Connect") { Task { await model.mountSelected() } }
                        .cfButton(.primary, size: .mini)
                        .disabled(model.dashboard.busyFilespaces.contains(filespace.id) || filespace.connection == .connecting)
                } else {
                    StatusDot(color: filespace.connection.dotColor, size: 7)
                }
                Image(systemName: isSelected ? "chevron.up" : "chevron.down")
                    .font(.system(size: 9, weight: .semibold)).foregroundStyle(Theme.textSecondary)
            }
            .foregroundStyle(Theme.textPrimary)
            .padding(.horizontal, 12).frame(height: 44)
            .background(isSelected ? Theme.selection : .clear, in: RoundedRectangle(cornerRadius: 10))
            .accessibilityElement(children: .contain)
            .accessibilityLabel("\(filespace.name), \(filespace.connection.label)")

            if isSelected {
                VStack(spacing: 3) {
                    row("Snapshots", symbol: IconSet.snapshots, section: .snapshots)
                    if model.canManageFolderAccess {
                        navButton("Access and permissions", symbol: IconSet.folderGrant,
                                  selected: model.section == .members && model.members.tab == .access) {
                            model.members.tab = .access; model.section = .members
                        }
                    }
                    if model.canManageGuestLinks { row("Guest links", symbol: IconSet.sharing, section: .sharing) }
                    row("Pinned files", symbol: IconSet.pin, section: .pinned)
                    row("Filespace settings", symbol: IconSet.preferences, section: .cache)
                    navButton("Filespace details", symbol: "info.circle", selected: false) { showDetails = true }
                    row("Activity", symbol: IconSet.activity, section: .activity)
                    if model.canReadWorkspaceActivity {
                        row("History", symbol: IconSet.audit, section: .audit)
                    }
                    if model.isHttpMode, isMounted {
                        Divider().overlay(Theme.divider).padding(.horizontal, 8).padding(.vertical, 5)
                        Button {
                            Task { await model.unmountSelected() }
                        } label: {
                            Label(model.dashboard.busyFilespaces.contains(filespace.id) ? "Finishing changes…" : "Disconnect",
                                  systemImage: "externaldrive.badge.xmark")
                                .font(Theme.Font.body).foregroundStyle(Theme.Status.error)
                                .frame(maxWidth: .infinity, alignment: .leading).padding(10)
                        }.buttonStyle(.plain)
                            .disabled(model.dashboard.busyFilespaces.contains(filespace.id))
                    }
                }
                .padding(6)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 14))

            }
        }
        .sheet(isPresented: $showDetails) { FilespaceDetailsSheet(filespace: filespace) }
    }

    private func row(_ title: String, symbol: String, section: NavSection) -> some View {
        navButton(title, symbol: symbol, selected: model.section == section) { model.section = section }
    }

    private func navButton(_ title: String, symbol: String, selected: Bool,
                           action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: symbol).font(.system(size: 15)).frame(width: 20)
                Text(title).font(Theme.Font.body).lineLimit(1)
                Spacer(minLength: 0)
            }
            .foregroundStyle(selected ? Theme.textPrimary : Theme.textSecondary)
            .padding(.horizontal, 10).frame(height: 35)
            .background(selected ? Theme.selection : .clear, in: RoundedRectangle(cornerRadius: 7))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? [.isSelected] : [])
    }
}
