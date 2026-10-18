// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - ConsoleLinks — typed deep links into the web admin console
//
// The sidebar's workspace-overflow menu (and the "+" create-filespace
// affordance) sends the user to the web console for anything that isn't a
// first-class Mac-app surface (creating a filespace, the org member directory,
// device sessions). Building those URLs by string concatenation at each call
// site would be untestable and a magnet for path typos, so it happens here
// instead — pure, unit-tested, no SwiftUI/AppKit dependency.
//
// Destinations mirror the routes in web/src/app/router.tsx.

public struct ConsoleLinks: Sendable, Equatable {
    /// The resolved console base URL (no trailing slash), or `nil` when neither
    /// a web base URL nor a server base URL is available (e.g. signed out).
    public let base: String?

    /// Resolve the effective console base: the persisted `webBaseUrl` (learned
    /// from `GET /v1/auth/config/public` at sign-in) when present and non-empty,
    /// else the gateway server's own base URL — same-origin deployments never
    /// set a distinct `webBaseUrl`, so the API host doubles as the console host.
    public init(webBaseUrl: String?, serverBaseURL: String) {
        let trimmedWeb = (webBaseUrl ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedServer = serverBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let resolved = trimmedWeb.isEmpty ? trimmedServer : trimmedWeb
        self.base = resolved.isEmpty ? nil : resolved
    }

    /// A destination in the web console.
    public enum Path: Sendable, CaseIterable {
        /// `/filespaces/new` — `CreateFilespace.tsx`.
        case createFilespace
        /// `/members` — workspace member directory.
        case members
        /// `/devices` — app download and device sessions.
        case devices
        /// The console root — "Open web console".
        case root

        var routePath: String {
            switch self {
            case .createFilespace: return "/filespaces/new"
            case .members: return "/members"
            case .devices: return "/devices"
            case .root: return ""
            }
        }
    }

    /// Build the full URL for `path`, or `nil` when there's no usable base or
    /// the resolved string isn't a valid URL.
    public func url(_ path: Path) -> URL? {
        guard var trimmed = base else { return nil }
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        guard !trimmed.isEmpty else { return nil }
        return URL(string: trimmed + path.routePath)
    }
    public func filespaceSettings(id: String, section: String? = nil) -> URL? {
        guard let baseURL = url(.root), var parts = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else { return nil }
        let segment = id.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
        parts.percentEncodedPath = baseURL.path.trimmingCharacters(in: CharacterSet(charactersIn: "/")).isEmpty
            ? "/filespaces/\(segment)/settings" : parts.percentEncodedPath + "/filespaces/\(segment)/settings"
        parts.fragment = section
        return parts.url
    }

}
