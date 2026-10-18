// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import FileProvider
import CloudFSKit
import os

// MARK: - FileProviderDomains
//
// Registers one `NSFileProviderDomain` per CONNECTED filespace, named after the filespace
// so Finder's sidebar shows the filespace name (NOT "fuse-t" or a generic label) — the
// filespaces in the app and in Finder match exactly. Registering the domain IS the mount in
// the File Provider hybrid: the embedded `CloudFSFileProvider.appex` then streams content on
// demand from the cloudfsd daemon. There is no separate FUSE mount step.
//
// The domain identifier is the stable filespace id; the appex recovers which filespace it
// serves from `domain.identifier.rawValue`, and the daemon multiplexes by that id.

@MainActor
final class FileProviderDomains {
    static let shared = FileProviderDomains()
    private let log = Logger(subsystem: "dev.cloudfs.client", category: "domains")

    /// True only for the signed build that actually embeds the File Provider extension.
    /// The quick offline SwiftPM dev bundle (make-app.sh) has no appex, so registration is
    /// skipped there — `NSFileProviderManager.add` would fail with "no matching extension".
    private lazy var canHostDomains: Bool = {
        guard let plugins = Bundle.main.builtInPlugInsURL else { return false }
        return FileManager.default.fileExists(
            atPath: plugins.appendingPathComponent("CloudFSFileProvider.appex").path)
    }()

    /// FP SHELVED (mount-architecture decision, 2026-06-10): the user-facing mount is
    /// the daemon's NFS-loopback volume; File Provider no longer ships a browsable
    /// CloudStorage namespace. The appex + this registration path stay in-repo as the
    /// FSKit-era research track, enabled only by CLOUDFS_FP_DOMAINS=1.
    private var fpResearchEnabled: Bool {
        ProcessInfo.processInfo.environment["CLOUDFS_FP_DOMAINS"] == "1"
    }

    /// Reconcile registered domains with the connected filespaces: add a domain for each
    /// connected filespace (named after it), drop domains for ones disconnected or gone, and
    /// re-create a domain whose display name changed (there is no rename API).
    /// Default builds (research flag off) RETIRE every registered domain instead, so an
    /// upgrade from an FP-era build cleans the stale CloudStorage namespace away.
    func sync(filespaces: [Filespace]) async {
        guard canHostDomains else { return }
        guard fpResearchEnabled else {
            await removeAll()
            return
        }
        let wanted = filespaces.filter { $0.connection == .connected }
        let wantedByID = Dictionary(wanted.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })

        let existing = (try? await NSFileProviderManager.domains()) ?? []
        let existingByID = Dictionary(existing.map { ($0.identifier.rawValue, $0) }, uniquingKeysWith: { a, _ in a })

        // Add new / re-create renamed.
        for fs in wanted {
            if let cur = existingByID[fs.id] {
                if cur.displayName != fs.name {
                    await remove(cur)
                    await add(fs)
                }
            } else {
                await add(fs)
            }
        }
        // Remove domains for filespaces no longer connected.
        for dom in existing where wantedByID[dom.identifier.rawValue] == nil {
            await remove(dom)
        }
    }

    /// Ask Finder to re-enumerate a filespace's root (e.g. after remote activity), so newly
    /// added/removed items appear without the user navigating away and back.
    func signalChange(filespace id: String) {
        guard canHostDomains else { return }
        let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(id), displayName: id)
        NSFileProviderManager(for: domain)?.signalEnumerator(for: .rootContainer) { _ in }
        NSFileProviderManager(for: domain)?.signalEnumerator(for: .workingSet) { _ in }
    }

    /// Remove every registered domain (sign-out / reset) so no stale filespaces linger in the
    /// Finder sidebar.
    func removeAll() async {
        guard canHostDomains else { return }
        do { try await NSFileProviderManager.removeAllDomains() }
        catch { log.error("removeAllDomains failed: \(error.localizedDescription, privacy: .public)") }
    }

    // MARK: Internals

    private func add(_ fs: Filespace) async {
        let domain = NSFileProviderDomain(identifier: NSFileProviderDomainIdentifier(fs.id),
                                          displayName: fs.name)
        do {
            try await NSFileProviderManager.add(domain)
            log.log("added domain \(fs.id, privacy: .public) name=\(fs.name, privacy: .public)")
        } catch {
            log.error("add domain \(fs.id, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func remove(_ domain: NSFileProviderDomain) async {
        do {
            try await NSFileProviderManager.remove(domain)
            log.log("removed domain \(domain.identifier.rawValue, privacy: .public)")
        } catch {
            log.error("remove domain \(domain.identifier.rawValue, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
    }
}
