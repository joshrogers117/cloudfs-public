// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - DaemonProvisioning — the app→daemon config hand-off (M7)
//
// The daemon ships INSIDE the app and runs as a launch agent. The agent's plist
// is static in the bundle, so everything dynamic — gateway URL, where the bearer
// token lives, which socket to bind — is written by the app into the rendezvous
// dir as `daemon.env` (KEY=VALUE; the daemon reads it as lowest-priority
// defaults) plus a 0600 `token.txt`. Pure functions + explicit root injection so
// the whole hand-off is unit-testable without a real directory.

public struct DaemonProvisioning: Sendable {

    /// The app↔daemon rendezvous directory (created if needed): the daemon's own
    /// support dir. M7 originally used the App Group container (a sandboxed-app-era
    /// requirement), but macOS 15+ consent-gates group-container access — open(2)
    /// blocks indefinitely on the TCC check — which wedged daemon startup and
    /// data-path reads. The app is unsandboxed (M7) and the daemon never was;
    /// nothing needs the gated container.
    public static func containerRoot(fileManager: FileManager = .default) -> URL? {
        let base = NSSearchPathForDirectoriesInDomains(.applicationSupportDirectory, .userDomainMask, true).first
            ?? (NSHomeDirectory() + "/Library/Application Support")
        let url = URL(fileURLWithPath: base + "/cloudfs", isDirectory: true)
        try? fileManager.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    /// Reuse only credentials already provisioned for this exact server. Starting
    /// the engine is independent of whether its token needs renewal.
    public static func existingToken(gatewayURL: String, root: URL) -> String? {
        guard let environment = try? String(contentsOf: root.appendingPathComponent("daemon.env"), encoding: .utf8),
              environment.split(separator: "\n").contains(Substring("CLOUDFS_GATEWAY=\(gatewayURL)")),
              let token = try? String(contentsOf: root.appendingPathComponent("token.txt"), encoding: .utf8),
              !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        return token.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Render the daemon.env contents for a deployment. Ends with a newline so
    /// operator appends can't glue onto the last key (that mangled CLOUDFS_SPILL_DIR
    /// once). CLOUDFS_KEY_FILE points at an OPTIONAL local filespace master key
    /// override — the app does NOT create key.hex. The optional
    /// `CLOUDFS_KEY_FILE_FILESPACE`, `CLOUDFS_KEY_FILE_GATEWAY` and
    /// `CLOUDFS_KEY_FILE_ORG` bind that override to one deployment; provisioning
    /// preserves it only for the same gateway and authenticated organization.
    /// `finderSocketPath` (M8) is the appex-reachable second control socket in the
    /// App Group container — nil omits the line (daemon skips the listener).
    public static func envFileContents(gatewayURL: String, root: URL,
                                       finderSocketPath: String? = nil,
                                       keyFileFilespace: String? = nil,
                                       keyFileGateway: String? = nil,
                                       keyFileOrganization: String? = nil) -> String {
        var lines = """
        # Written by CloudFSApp at sign-in — consumed by the cloudfsd launch agent.
        # Precedence: daemon flags > process env > this file.
        CLOUDFS_GATEWAY=\(gatewayURL)
        CLOUDFS_SOCKET=\(root.appendingPathComponent("d.sock").path)
        CLOUDFS_TOKEN_FILE=\(root.appendingPathComponent("token.txt").path)
        CLOUDFS_SPILL_DIR=\(root.path)
        CLOUDFS_KEY_FILE=\(root.appendingPathComponent("key.hex").path)
        CLOUDFS_KEY_FILE_OPTIONAL=1
        """
        if let keyFileFilespace, !keyFileFilespace.isEmpty,
           let keyFileGateway = normalizedGateway(keyFileGateway ?? gatewayURL),
           let keyFileOrganization, !keyFileOrganization.isEmpty {
            lines += "\nCLOUDFS_KEY_FILE_FILESPACE=\(keyFileFilespace)"
            lines += "\nCLOUDFS_KEY_FILE_GATEWAY=\(keyFileGateway)"
            lines += "\nCLOUDFS_KEY_FILE_ORG=\(keyFileOrganization)"
        }
        if let finderSocketPath {
            lines += "\nCLOUDFS_FINDER_SOCKET=\(finderSocketPath)"
        }
        return lines + "\n"
    }

    /// Write the full provisioning: daemon.env + the bearer token (0600). Returns
    /// the socket path the daemon will bind, for the engine client to connect to.
    /// The finder socket (M8) defaults to the App Group container so the sandboxed
    /// Finder Sync appex can reach it; tests inject their own.
    @discardableResult
    public static func provision(gatewayURL: String, token: String, root: URL,
                                 finderSocketPath: String? = FinderIntegration.finderSocketPath,
                                 keyFileFilespace: String? = nil) throws -> String {
        let envURL = root.appendingPathComponent("daemon.env")
        let organization = keyOrganization(from: token)
        let binding: (filespace: String, gateway: String, organization: String)?
        if let keyFileFilespace, !keyFileFilespace.isEmpty,
           let gateway = normalizedGateway(gatewayURL),
           let organization {
            binding = (keyFileFilespace, gateway, organization)
        } else if let previous = existingKeyFileBinding(at: envURL),
                  previous.gateway == normalizedGateway(gatewayURL),
                  previous.organization == organization {
            binding = previous
        } else {
            binding = nil
        }
        let env = envFileContents(gatewayURL: gatewayURL, root: root,
                                  finderSocketPath: finderSocketPath,
                                  keyFileFilespace: binding?.filespace,
                                  keyFileGateway: binding?.gateway,
                                  keyFileOrganization: binding?.organization)
        try env.write(to: envURL, atomically: true, encoding: .utf8)
        let tokenURL = root.appendingPathComponent("token.txt")
        try token.write(to: tokenURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tokenURL.path)
        return root.appendingPathComponent("d.sock").path
    }

    private static func existingKeyFileBinding(at envURL: URL) -> (filespace: String, gateway: String, organization: String)? {
        guard let text = try? String(contentsOf: envURL, encoding: .utf8) else { return nil }
        var filespace: String?
        var gateway: String?
        var organization: String?
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard let separator = trimmed.firstIndex(of: "=") else { continue }
            let name = String(trimmed[..<separator])
            let value = String(trimmed[trimmed.index(after: separator)...])
            if name == "CLOUDFS_KEY_FILE_FILESPACE", !value.isEmpty { filespace = value }
            if name == "CLOUDFS_KEY_FILE_GATEWAY", !value.isEmpty { gateway = value }
            if name == "CLOUDFS_KEY_FILE_ORG", !value.isEmpty { organization = value }
        }
        guard let filespace, let rawGateway = gateway,
              let normalized = normalizedGateway(rawGateway),
              let organization else { return nil }
        return (filespace, normalized, organization)
    }

    private static func keyOrganization(from token: String) -> String? {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return nil }
        var payload = String(parts[1]).replacingOccurrences(of: "-", with: "+")
                                      .replacingOccurrences(of: "_", with: "/")
        while payload.count % 4 != 0 { payload += "=" }
        guard let data = Data(base64Encoded: payload),
              let claims = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let organization = claims["org"] as? String,
              !organization.isEmpty else { return nil }
        return organization
    }

    private static func normalizedGateway(_ raw: String?) -> String? {
        guard let raw, var parts = URLComponents(string: raw),
              let scheme = parts.scheme?.lowercased(),
              let host = parts.host?.lowercased(),
              parts.user == nil, parts.password == nil,
              parts.query == nil, parts.fragment == nil else { return nil }
        parts.scheme = scheme
        parts.host = host
        if (scheme == "http" && parts.port == 80) || (scheme == "https" && parts.port == 443) {
            parts.port = nil
        }
        var path = parts.percentEncodedPath
        while path.count > 1 && path.hasSuffix("/") { path.removeLast() }
        if path == "/" { path = "" }
        parts.percentEncodedPath = path
        return parts.string
    }
}
