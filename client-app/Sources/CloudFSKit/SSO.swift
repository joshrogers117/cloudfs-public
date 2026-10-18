// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - SSO (OIDC) — start-URL builder + callback token capture
//
// The gateway owns the OIDC dance (oidc-INTEGRATION.md): the client opens
// `GET /v1/auth/oidc/start` in the system browser; the IdP redirects to the
// gateway's `/callback`, which mints a normal cloud-fs SESSION token (same HS256
// format the bearer path uses) and hands it back to the app.
//
// The token comes back to the desktop app one of two ways; this helper parses
// BOTH so the wiring works regardless of how the gateway is configured to deliver
// it:
//   1. cloudfs:// URL scheme  — gateway 302 → `cloudfs://auth/callback?token=…`
//      (the app registers the scheme; LaunchServices delivers it as an open-URL).
//   2. loopback redirect      — gateway 302 → `http://127.0.0.1:<port>/callback?token=…`
//      (a transient local listener; same `?token=` extraction).
//
// LIVE PREREQUISITE: a real OIDC IdP must be configured on the gateway
// (OIDC_ISSUER / CLIENT_ID / CLIENT_SECRET / REDIRECT_URI / ORG_ID — see
// oidc-INTEGRATION.md §2). Without it `/start` returns a provider error. The
// client side (start-URL build + token capture + Keychain store + connect) is
// fully testable offline via deep-link parsing.

public enum SSO {

    /// The `cloudfs://` host the gateway redirects to with the minted token.
    public static let callbackHost = "auth"
    public static let callbackPath = "/callback"

    /// The redirect URI the client asks the gateway to send the token back to.
    /// (The gateway's own registered IdP REDIRECT_URI is separate — this is the
    /// final hop from gateway → app.)
    public static let appRedirect = "\(DeepLink.scheme)://\(callbackHost)\(callbackPath)"

    /// Build the gateway SSO-start URL: `<base>/v1/auth/oidc/start?redirect_uri=…`.
    /// Returns nil if the base URL is malformed.
    public static func startURL(gatewayBaseURL: String) -> URL? {
        let trimmed = gatewayBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        // Require a real absolute URL (scheme + host) — reject "" / bare paths.
        guard var comps = URLComponents(string: trimmed),
              comps.scheme != nil, let host = comps.host, !host.isEmpty
        else { return nil }
        let basePath = comps.path.hasSuffix("/") ? String(comps.path.dropLast()) : comps.path
        comps.path = basePath + "/v1/auth/oidc/start"
        // Pass our app redirect so the gateway knows where to deliver the token.
        comps.queryItems = (comps.queryItems ?? []) + [
            URLQueryItem(name: "redirect_uri", value: appRedirect)
        ]
        return comps.url
    }

    /// Extract the session token from a callback URL — both the `cloudfs://auth/
    /// callback?token=…` deep link and a loopback `http://127.0.0.1:…?token=…`.
    /// Also accepts the token in the URL fragment (`#token=…`), per the
    /// oidc-INTEGRATION note that a redirect may deliver it via fragment.
    public static func tokenFromCallback(_ url: URL) -> String? {
        // cloudfs:// scheme: must be the auth/callback host+path.
        if url.scheme == DeepLink.scheme {
            guard url.host == callbackHost else { return nil }
            // path may be "/callback" or empty; accept either.
            if !url.path.isEmpty && url.path != callbackPath { return nil }
        }
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return nil }
        if let t = comps.queryItems?.first(where: { $0.name == "token" })?.value,
           !t.isEmpty { return t }
        // Fragment form: #token=…&foo=…
        if let frag = comps.fragment {
            for pair in frag.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1)
                if kv.count == 2, kv[0] == "token" {
                    let raw = String(kv[1])
                    return raw.removingPercentEncoding ?? raw
                }
            }
        }
        return nil
    }
}
