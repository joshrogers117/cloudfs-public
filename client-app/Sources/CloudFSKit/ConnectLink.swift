// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - cloudfs://connect deep link (ONBOARDING.md build step 3)
//
//   cloudfs://connect?server=<gateway-url>
//
// Fired by the post-join "Get the app" page (web/src/pages/join/GetTheAppCard.tsx)
// and the equivalent settings-page card, so an editor who just finished the web
// `/join` flow never has to type a server URL into the Mac app.
//
// Like `auth` (SSO.callbackHost), `connect` is a RESERVED host on the `cloudfs://`
// scheme — it is not a filespace id, and is handled before the navigation
// deep-link (reveal-in-Finder) path ever sees it.
//
// Parsing + the signed-in/out decision are pure and unit-tested here; AppModel
// wires the `Outcome` into UI state (LoginView prefill, window-forward, or the
// "signed in elsewhere" alert) — see AppModel.handleIncomingURL /
// AppModel.handleConnectLink.

public enum ConnectLink {

    /// The reserved `cloudfs://connect` host.
    public static let host = "connect"

    /// Parse `cloudfs://connect?server=<url>`. Returns the trimmed server URL
    /// only when the link is well-formed AND `server` is a full http(s) URL with
    /// a host — the same rule the login form's own field uses
    /// (`LoginValidation.gatewayURLInvalid`). Hostile/garbage input (wrong host,
    /// missing/empty `server`, a non-URL value, javascript: etc.) returns nil so
    /// the caller can log-and-ignore rather than crash or half-apply it.
    public static func parseServerURL(_ url: URL) -> String? {
        guard url.scheme == DeepLink.scheme, url.host == host else { return nil }
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let raw = comps.queryItems?.first(where: { $0.name == "server" })?.value
        else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !LoginValidation.gatewayURLInvalid(trimmed) else { return nil }
        return trimmed
    }

    /// What an incoming connect link should do, given current session state.
    public enum Outcome: Sendable, Equatable {
        /// Signed OUT: prefill the login form's server field and focus the
        /// sign-in pane so the user only has to click "Sign in with browser".
        case prefill(server: String)
        /// Signed IN to the SAME server: no-op — just bring the window forward
        /// as a gentle confirmation. Never re-runs sign-in.
        case alreadyConnected
        /// Signed IN to a DIFFERENT server: destructive-adjacent (would mean
        /// switching servers/signing out), so this NEVER happens silently.
        /// Surfaces an alert naming both hosts; the user decides.
        case differentServer(current: String, requested: String)
    }

    /// Decide the outcome for a parsed `server` URL. `currentServerURL` is
    /// whatever the app's persisted gateway base URL is (only meaningful when
    /// `isSignedIn`).
    public static func decide(server: String, isSignedIn: Bool,
                              currentServerURL: String) -> Outcome {
        guard isSignedIn else { return .prefill(server: server) }
        if sameServer(server, currentServerURL) { return .alreadyConnected }
        return .differentServer(current: displayHost(currentServerURL),
                                requested: displayHost(server))
    }

    /// Same-origin comparison (scheme + host + port, with the scheme's default
    /// port implied when omitted) — not a raw string compare, so
    /// `https://gw.example.com` and `https://gw.example.com/` (or an explicit
    /// `:443`) still count as the same server.
    static func sameServer(_ a: String, _ b: String) -> Bool {
        guard let ua = URL(string: a), let ub = URL(string: b),
              let ha = ua.host?.lowercased(), let hb = ub.host?.lowercased(),
              let sa = ua.scheme?.lowercased(), let sb = ub.scheme?.lowercased()
        else { return a == b }
        return sa == sb && ha == hb
            && (ua.port ?? defaultPort(for: sa)) == (ub.port ?? defaultPort(for: sb))
    }

    private static func defaultPort(for scheme: String) -> Int? {
        switch scheme {
        case "https": return 443
        case "http":  return 80
        default:      return nil
        }
    }

    /// Best-effort host for display in the "signed in elsewhere" alert; falls
    /// back to the raw string if it doesn't parse as a URL.
    static func displayHost(_ url: String) -> String {
        URL(string: url)?.host ?? url
    }
}
