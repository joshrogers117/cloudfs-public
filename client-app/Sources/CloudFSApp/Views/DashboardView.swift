// SPDX-License-Identifier: AGPL-3.0-or-later
import SwiftUI
import CloudFSKit

struct DashboardView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(spacing: 0) {
            if let fs = model.selectedFilespace {
                if model.isHttpMode && (fs.mountPath.isEmpty || fs.connection == .connecting) {
                    FilespaceHero(fs: fs, centered: true).frame(maxWidth: .infinity, maxHeight: .infinity).padding(40)
                } else {
                ScrollView {
                    VStack(alignment: .leading, spacing: 18) {
                        if !model.isHttpMode {
                            Label("Demo workspace · Sample data, no volume mounted", systemImage: "info.circle")
                                .font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
                        }
                        FilespaceHero(fs: fs)
                            .padding(.vertical, 12)
                        if model.dashboard.newAccessAvailable, fs.connection == .connected, !fs.mountPath.isEmpty {
                            Banner(kind: .info, title: "New access available",
                                   detail: "You’ve been given access to more folders. Reconnect to see them in Finder.",
                                   actionTitle: "Reconnect") { Task { await model.reconnectSelectedForNewAccess() } }
                        }
                        if !model.recovery.items.isEmpty {
                            Banner(kind: .warning, title: "\(model.recovery.items.count) local \(model.recovery.items.count == 1 ? "change needs" : "changes need") attention",
                                   detail: "These files are preserved on this Mac and need recovery before they can be saved to the cloud.",
                                   actionTitle: "Review files") { model.section = .activity }
                        }
                        HStack(alignment: .top, spacing: 12) {
                            storage(fs).frame(width: 245).frame(maxHeight: .infinity, alignment: .topLeading)
                            connection(fs).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        }
                        .fixedSize(horizontal: false, vertical: true)
                        pinnedCache
                        if model.isHttpMode, !fs.mountPath.isEmpty {
                            Button {
                                Task { await model.unmountSelected() }
                            } label: {
                                Label("Disconnect filespace", systemImage: "externaldrive.badge.xmark")
                            }
                            .buttonStyle(.plain).foregroundStyle(Theme.Status.error)
                            .disabled(model.dashboard.busyFilespaces.contains(fs.id))
                        }
                    }
                    .padding(24)
                }
                }
            } else {
                WorkspaceEmptyState()
            }
        }
        .background(Theme.bg)
        .task(id: model.selectedFilespaceID) {
            // Visible dashboard readings stay current without polling hidden panes.
            while !Task.isCancelled {
                await model.dashboardTick()
                do { try await Task.sleep(for: .seconds(3)) } catch { break }
            }
        }
        .task(id: model.refreshToken) { await model.loadDashboardSyncState() }
    }

    private func storage(_ fs: Filespace) -> some View {
        VStack(alignment: .leading, spacing: 24) {
            panelTitle("Filespace details", symbol: "externaldrive")
            metric("Cloud provider", fs.storageBackend)
            metric("Region", fs.region)
            metric("Used storage", fs.storageDisplay)
        }
        .padding(22).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 12))
    }

    private func status(for fs: Filespace) -> EngineStatus? {
        guard model.isHttpMode, let status = model.dashboard.status, status.filespace == fs.id else { return nil }
        return status
    }

    private func health(_ fs: Filespace) -> ConnectionHealthDisplay {
        // Reachability only qualifies a filespace that is actually mounted here.
        guard fs.connection == .connected, !fs.mountPath.isEmpty else { return .unknown }
        return ConnectionHealthDisplay(status(for: fs)?.reachability)
    }

    private func connection(_ fs: Filespace) -> some View {
        let health = health(fs)
        let status = status(for: fs)
        let uploadError = DashboardDerivations.firstUploadError(model.transfers)
        let dot: Color = {
            if health == .offline { return Theme.Status.error }
            if health == .degraded || !model.recovery.items.isEmpty { return Theme.Status.warn }
            if uploadError != nil && model.dashboard.inSync != true { return Theme.Status.warn }
            if model.dashboard.inSync == false { return Theme.Status.busy }
            return fs.connection.dotColor
        }()
        return VStack(alignment: .leading, spacing: 14) {
            HStack {
                panelTitle("Activity", symbol: "waveform.path")
                Spacer()
                if let label = health.label {
                    Text(label).font(Theme.Font.caption).padding(.horizontal, 9).padding(.vertical, 5)
                        .background(Theme.bg, in: Capsule())
                }
            }
            Divider().overlay(Theme.divider)
            VStack(spacing: 10) {
                Image(systemName: model.dashboard.inSync == true && health != .offline && model.recovery.items.isEmpty ? "checkmark" : "arrow.up.arrow.down")
                    .font(.system(size: 22, weight: .medium)).foregroundStyle(dot)
                    .frame(width: 46, height: 46).background(Theme.bg, in: RoundedRectangle(cornerRadius: 16))
                Text(durabilityLabel(fs, health: health, uploadError: uploadError))
                    .font(.system(size: 18, weight: .semibold)).multilineTextAlignment(.center)
                if let detail = DashboardDerivations.connectionDetail(
                    health: health, latencyMs: status?.gatewayLatencyMs, lastFailureReason: status?.lastFailureReason) {
                    Text(detail).font(Theme.Font.caption).foregroundStyle(Theme.textSecondary).multilineTextAlignment(.center)
                }
            }.frame(maxWidth: .infinity).padding(.vertical, 8)
            if model.dashboard.inSync != true {
            HStack(alignment: .firstTextBaseline) {
                metric("Remaining upload", remainingUploadText)
                Spacer(minLength: 0)
                Button("View activity") { model.section = .activity }
                    .cfButton(.subtle, size: .small)
            }
            }
        }
        .padding(22).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 12))
    }

    private func durabilityLabel(_ fs: Filespace, health: ConnectionHealthDisplay, uploadError: String?) -> String {
        DashboardDerivations.durabilityLabel(
            isHttpMode: model.isHttpMode, recoveryNeedsAttention: !model.recovery.items.isEmpty,
            paused: fs.connection == .paused, mountPathEmpty: fs.mountPath.isEmpty,
            inSync: model.dashboard.inSync, uploadError: uploadError, health: health)
    }

    private var remainingUploadText: String {
        if !model.isHttpMode { return ByteFormat.string(model.transfers.pendingUploadBytes) }
        guard let bytes = model.dashboard.pendingUploadBytes else { return "Unavailable" }
        return ByteFormat.string(bytes)
    }

    private var pinnedCache: some View {
        VStack(alignment: .leading, spacing: 24) {
            panelTitle("Pinned files", symbol: "pin")
            switch model.cacheState {
            case .idle, .loading:
                InlineLoading(text: "Reading local cache…")
            case .failed:
                Text("Connect the background engine to see local cache usage.")
                    .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
            case .loaded(let cache):
                HStack(alignment: .top) {
                    metric("Pinned files", ByteFormat.string(cache.pinnedBytes))
                    Spacer()
                    metric("Pinning limit", ByteFormat.string(cache.pinningCeilingBytes))
                    Spacer()
                    metric("Cache size", ByteFormat.string(cache.maxBytes))
                }
                CacheGauge(usedFraction: cache.usedFraction, pinnedFraction: cache.pinnedFraction)
                    .frame(height: Theme.Metric.gaugeHeightSmall)
                    .accessibilityLabel("Cache \(Int(cache.usedFraction * 100)) percent used; \(Int(cache.pinnedFraction * 100)) percent pinned")
                HStack(spacing: 28) {
                    Button { model.section = .pinned } label: {
                        Label("Manage pinned files", systemImage: "pin")
                    }.cfButton(.subtle)
                    Button { model.section = .cache } label: {
                        Label("Manage cache size", systemImage: "slider.horizontal.3")
                    }.cfButton(.subtle)
                    Spacer(minLength: 0)
                }
            }
        }.themedCard(padding: 22)
    }

    private func details(_ fs: Filespace) -> some View {
        DisclosureGroup {
            VStack(spacing: 14) {
                CopyableKeyValueRow(key: "Location on this Mac", value: fs.mountPath.isEmpty ? "Not connected" : fs.mountPath,
                                    copyable: !fs.mountPath.isEmpty && model.isHttpMode)
                KeyValueRow(key: "Your role", value: fs.displayRole(orgRole: model.isHttpMode ? model.members.currentRole : nil).rawValue)
                CopyableKeyValueRow(key: "Filespace ID", value: fs.id)
            }.padding(.top, 18)
        } label: {
            Label("Filespace details", systemImage: "info.circle")
                .font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
        }
        .tint(Theme.textSecondary)
        .padding(.horizontal, 4)
    }

    private func panelTitle(_ title: String, symbol: String) -> some View {
        HStack(spacing: 9) {
            Image(systemName: symbol).font(.system(size: 13, weight: .medium))
                .foregroundStyle(title == "Pinned files" ? Theme.onAccent : Theme.textPrimary)
                .frame(width: 25, height: 25)
                .background(title == "Pinned files" ? Theme.accent : Theme.selection,
                            in: RoundedRectangle(cornerRadius: 7))
            Text(title).font(.system(size: 18, weight: .semibold))
        }.foregroundStyle(Theme.textPrimary)
    }

    private func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title).font(Theme.Font.caption).foregroundStyle(Theme.textSecondary)
            Text(value).font(Theme.Font.body.weight(.semibold)).foregroundStyle(Theme.textPrimary)
                .monospacedDigit().fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct FilespaceHero: View {
    @Environment(AppModel.self) private var model
    let fs: Filespace
    var centered = false
    private var busy: Bool { model.dashboard.busyFilespaces.contains(fs.id) }
    private var hero: DashboardHeroState {
        DashboardHeroState.derive(connection: fs.connection, mountPath: fs.mountPath,
                                  probe: model.onboarding.mountRows[fs.id],
                                  reachability: model.dashboard.status?.filespace == fs.id && model.isHttpMode
                                      ? model.dashboard.status?.reachability : nil)
    }

    var body: some View {
        if centered {
            VStack(spacing: 20) {
                FilespaceDriveIllustration(size: 140)
                Text(hero.headline(filespaceName: fs.name))
                    .font(.system(size: 25, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                Text(hero.subCopy).font(Theme.Font.body).foregroundStyle(Theme.textSecondary)
                    .multilineTextAlignment(.center).frame(maxWidth: 370)
                action.padding(.top, 12)
            }
        } else {
            HStack(spacing: 16) {
                FilespaceDriveIllustration(size: 64)
                Text(fs.name).font(.system(size: 25, weight: .semibold)).foregroundStyle(Theme.textPrimary)
                Spacer(minLength: 4)
                action
            }
        }
    }

    @ViewBuilder private var action: some View {
        if !model.isHttpMode {
            Text("Demo").font(Theme.Font.caption).foregroundStyle(Theme.accent)
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(Theme.selection, in: Capsule())
        } else if busy {
            ProgressView().controlSize(.small).help("Finishing changes safely")
        } else if hero.isProbeFailure || !model.isEngineConnected {
            Button("Check connection") { model.rerunOnboardingChecklist() }
                .cfButton(.primary, size: .large)
        } else if fs.connection == .paused {
            Button("Resume transfers") { Task { await model.togglePauseSync() } }
                .cfButton(.operational, size: .large)
        } else if hero.canOpenInFinder {
            Button { model.revealFilespaceInFinder(fs) } label: {
                Label("Browse files", systemImage: "arrow.up.right.square")
            }.cfButton(.operational, size: .large)
        } else {
            Button("Connect") { Task { await model.mountSelected() } }
                .cfButton(.operational, size: .large)
                .disabled(fs.connection == .connecting)
        }
    }
}
