// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// Identifiers + paths shared by the host app and the File Provider extension.
///
/// The appex is **sandboxed**; the only filesystem it can reach outside its own
/// container is the App Group container (`~/Library/Group Containers/<group>/`).
/// So the daemon↔appex seam lives there:
///   • `daemonSocketPath` — the cloudfsd control UDS the appex makes data-path RPCs to.
///   • the daemon also materializes decrypted byte-range files under this container so
///     the sandboxed appex can read them (CONTROL-API §7, `DataReadRangeResult.path`).
///
/// The daemon is NOT sandboxed (it runs as the user), so it can bind/write here freely;
/// it just has to be pointed at this path (env `CLOUDFS_SOCKET` / `CLOUDFS_GROUP_CONTAINER`).
enum CloudFSAppGroup {
    /// Must match `com.apple.security.application-groups` in the appex entitlements.
    static let identifier = "group.dev.cloudfs.client"

    /// App Group container root (shared host ↔ appex ↔ daemon). Falls back to a temp
    /// dir only if the entitlement is missing (e.g. an unsigned dev build), so code that
    /// reads it never crashes — it just won't see the daemon.
    static var containerURL: URL {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
            ?? FileManager.default.temporaryDirectory.appendingPathComponent(identifier, isDirectory: true)
    }

    /// The cloudfsd control socket, inside the group container so the sandboxed appex
    /// can connect. Kept short (AF_UNIX `sun_path` ≤ 103 bytes).
    static var daemonSocketPath: String {
        containerURL.appendingPathComponent("d.sock").path
    }

    /// One File Provider domain per filespace. The domain identifier IS the filespace id,
    /// so the appex recovers which filespace it serves from `domain.identifier.rawValue`.
    static func domainIdentifier(filespace: String) -> String { filespace }
}
