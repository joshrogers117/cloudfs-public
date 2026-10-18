// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CryptoKit

// MARK: - DeviceAuth — browser-handoff sign-in (auth-spec §1.2/§2.1/§3)
//
// The app's side of the device-authorization handoff:
//
//   1. generate `state` (32B b64url) + a PKCE S256 pair (verifier 64B b64url,
//      challenge = b64url(SHA-256(verifier)));
//   2. open `<webBaseUrl>/device/authorize?state&code_challenge&…` in the system
//      browser (plus device name/model so the approval screen can show them);
//   3. receive `cloudfs://auth/callback?code&state` (or a manually pasted code),
//      bind it to the single pending request, and exchange code+verifier at
//      `POST /v1/auth/device/token`.
//
// Everything here is pure + synchronous (CryptoKit only) so the whole handoff
// protocol is unit-testable offline. The HTTP half lives in DeviceAuthAPI; the
// state machine driving the UI lives in AppModel and calls `resolve*`.
//
// SECURITY (auth-spec §5.1/§5.2): the custom URL scheme is first-claimant on
// macOS, so the code alone must be useless — PKCE binds it to the verifier that
// never leaves this process. `state` binds a URL callback to OUR pending
// request; the paste path replaces `state` with the explicit user action, bound
// to the active pending request (a paste with no pending request is refused).

public enum DeviceAuth {

    // MARK: PKCE + state generation

    /// 64 random bytes, base64url — an RFC 7636-valid verifier (86 chars, within
    /// the 43–128 bound).
    public static func makeVerifier() -> String {
        randomBase64URL(byteCount: 64)
    }

    /// 32 random bytes, base64url — the `state` echoed verbatim on the callback.
    public static func makeState() -> String {
        randomBase64URL(byteCount: 32)
    }

    /// PKCE S256: challenge = base64url(SHA-256(ASCII(verifier))).
    public static func challenge(forVerifier verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).base64URLEncodedString()
    }

    static func randomBase64URL(byteCount: Int) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        // SecRandomCopyBytes-equivalent without importing Security here.
        for i in bytes.indices { bytes[i] = UInt8.random(in: .min ... .max) }
        return Data(bytes).base64URLEncodedString()
    }

    // MARK: Device identity (shown on the portal approval screen)

    public struct DeviceInfo: Sendable, Equatable {
        public let name: String      // e.g. "Josh's MacBook Pro" (≤64 UTF-16 units)
        public let model: String?    // e.g. "MacBookPro18,3" (≤32 UTF-16 units)
        public let appVersion: String?  // display only (≤16 UTF-16 units)

        public init(name: String, model: String? = nil, appVersion: String? = nil) {
            self.name = Self.clamp(name, max: 64)
            self.model = model.map { Self.clamp($0, max: 32) }
            self.appVersion = appVersion.map { Self.clamp($0, max: 16) }
        }

        /// Trim + strip control characters + cap length (spec §2.2 validation —
        /// do it client-side too so the request never bounces on a long name).
        ///
        /// LENGTH UNITS: both validators on the other side of the wire — the
        /// portal and the backend — check JS `String.length`, i.e. UTF-16 code
        /// units, so the cap here counts UTF-16 units too. (A Swift
        /// `prefix(max)` counts grapheme clusters: an emoji-heavy name could
        /// pass at ≤64 graphemes yet exceed 64 UTF-16 units on the wire, and
        /// the portal would reject the whole authorize link as malformed.)
        /// The cut never splits a surrogate pair or a grapheme cluster — it
        /// trims back to the last whole Character that fits.
        ///
        /// The control-character strip targets Unicode Cc ONLY (NUL, newlines,
        /// escapes). Foundation's `.controlCharacters` also covers Cf (format)
        /// — which would strip ZWJ/ZWNJ and silently shred multi-person emoji
        /// ("👨‍👩‍👧‍👦" → "👨👩👧👦") and Persian/Arabic names that depend on ZWNJ;
        /// the wire validators only check length, so Cf passes through intact.
        static func clamp(_ raw: String, max: Int) -> String {
            var kept = String.UnicodeScalarView()
            for scalar in raw.unicodeScalars
            where scalar.properties.generalCategory != .control {
                kept.append(scalar)
            }
            let cleaned = String(kept)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard cleaned.utf16.count > max else { return cleaned }
            var unitCount = 0
            var clamped = ""
            for character in cleaned {
                unitCount += character.utf16.count
                if unitCount > max { break }
                clamped.append(character)
            }
            return clamped
        }

        /// The current Mac: localized host name + `hw.model` sysctl.
        public static func current(processInfo: ProcessInfo = .processInfo) -> DeviceInfo {
            let name = Host.current().localizedName ?? processInfo.hostName
            return DeviceInfo(name: name, model: hardwareModel(),
                              appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String)
        }

        static func hardwareModel() -> String? {
            var size = 0
            guard sysctlbyname("hw.model", nil, &size, nil, 0) == 0, size > 0 else { return nil }
            var bytes = [UInt8](repeating: 0, count: size)
            guard sysctlbyname("hw.model", &bytes, &size, nil, 0) == 0 else { return nil }
            let model = String(decoding: bytes.prefix(while: { $0 != 0 }), as: UTF8.self)
            return model.isEmpty ? nil : model
        }
    }

    // MARK: Pending request (the app enforces a SINGLE pending request)

    public struct PendingRequest: Sendable, Equatable {
        public let serverURL: String     // the gateway base the user typed
        public let state: String
        public let verifier: String
        public let authorizeURL: URL     // for "Open browser again"
        public let startedAt: Date

        public init(serverURL: String, state: String, verifier: String,
                    authorizeURL: URL, startedAt: Date = Date()) {
            self.serverURL = serverURL
            self.state = state
            self.verifier = verifier
            self.authorizeURL = authorizeURL
            self.startedAt = startedAt
        }
    }

    /// Build the full pending request: fresh state + PKCE pair + authorize URL.
    /// `webBaseURL` comes from `GET /v1/auth/config/public` (falls back to the
    /// server URL itself on same-origin deployments). Returns nil only when the
    /// web base URL is malformed.
    public static func beginRequest(serverURL: String, webBaseURL: String,
                                    device: DeviceInfo) -> PendingRequest? {
        let state = makeState()
        let verifier = makeVerifier()
        guard let url = authorizeURL(webBaseURL: webBaseURL, state: state,
                                     challenge: challenge(forVerifier: verifier),
                                     device: device) else { return nil }
        return PendingRequest(serverURL: serverURL, state: state,
                              verifier: verifier, authorizeURL: url)
    }

    /// `<webBaseUrl>/device/authorize?state&code_challenge&code_challenge_method=S256
    ///  &device_name&device_model&app_version` (spec §2.1).
    ///
    /// QUERY ENCODING: values are percent-encoded down to RFC 3986 *unreserved*
    /// characters (the `encodeURIComponent` ballpark), NOT URLComponents'
    /// default `urlQueryAllowed`. The default leaves `+` literal — valid per
    /// RFC 3986, but the portal parses the query with `URLSearchParams`
    /// (application/x-www-form-urlencoded rules), which decodes a literal `+`
    /// as a SPACE. Encoding to unreserved makes every value byte-exact through
    /// that decoder: `+` → %2B, space → %20, `&`/`=` and all non-ASCII
    /// percent-escaped.
    public static func authorizeURL(webBaseURL: String, state: String,
                                    challenge: String, device: DeviceInfo) -> URL? {
        let trimmed = webBaseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard var comps = URLComponents(string: trimmed),
              comps.scheme != nil, let host = comps.host, !host.isEmpty
        else { return nil }
        let basePath = comps.path.hasSuffix("/") ? String(comps.path.dropLast()) : comps.path
        comps.path = basePath + "/device/authorize"
        var items: [URLQueryItem] = [
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "device_name", value: device.name),
        ]
        if let model = device.model { items.append(URLQueryItem(name: "device_model", value: model)) }
        if let v = device.appVersion { items.append(URLQueryItem(name: "app_version", value: v)) }
        // Names are fixed ASCII identifiers (nothing to encode); values get the
        // strict form-urlencoded-safe escaping described above.
        comps.percentEncodedQueryItems = items.map {
            URLQueryItem(name: $0.name,
                         value: $0.value?.addingPercentEncoding(
                            withAllowedCharacters: queryValueAllowed))
        }
        return comps.url
    }

    /// RFC 3986 "unreserved" — the only characters that survive UN-encoded in
    /// a query value (see `authorizeURL` doc: keeps `URLSearchParams` from
    /// reading a literal `+` as a space).
    static let queryValueAllowed = CharacterSet(
        charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")

    // MARK: Callback parsing (extends — does not replace — the legacy ?token=)

    public enum Callback: Sendable, Equatable {
        /// New device handoff: `cloudfs://auth/callback?code=…&state=…`.
        case device(code: String, state: String)
        /// Legacy SSO delivery: `cloudfs://auth/callback?token=…` (kept parsing).
        case legacyToken(String)
    }

    /// Parse an incoming auth-callback URL. Returns nil for anything that is not
    /// an auth callback (e.g. a navigation deep link).
    public static func parseCallback(_ url: URL) -> Callback? {
        // Must be our scheme + the auth host (mirror SSO.tokenFromCallback rules).
        if url.scheme == DeepLink.scheme {
            guard url.host == SSO.callbackHost else { return nil }
            if !url.path.isEmpty && url.path != SSO.callbackPath { return nil }
        }
        if let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let items = comps.queryItems {
            let code = items.first { $0.name == "code" }?.value
            let state = items.first { $0.name == "state" }?.value
            if let code, let state, !code.isEmpty, !state.isEmpty {
                return .device(code: code, state: state)
            }
        }
        // Fall through to the legacy token form (query or fragment).
        if let token = SSO.tokenFromCallback(url) { return .legacyToken(token) }
        return nil
    }

    // MARK: Binding a callback / pasted code to the pending request

    public enum Resolution: Sendable, Equatable {
        /// Proceed: exchange `code` + `verifier` at POST /v1/auth/device/token.
        case exchange(code: String, verifier: String)
        /// Hard-fail with this user-facing message (spec §5.2 — never exchange).
        case reject(String)
    }

    /// URL-path binding: the callback's `state` must equal the single pending
    /// request's `state` (stale/duplicate/injected callbacks are refused).
    public static func resolve(callbackCode code: String, state: String,
                               pending: PendingRequest?) -> Resolution {
        guard let pending else {
            return .reject("No sign-in is in progress. Click “Sign in with browser” first.")
        }
        guard state == pending.state else {
            return .reject("That sign-in response didn’t match this app’s request. Start again from the cloud-fs app.")
        }
        return .exchange(code: code, verifier: pending.verifier)
    }

    /// Paste-path binding: the explicit user action stands in for `state`, but
    /// ONLY against the active pending request (spec §3).
    public static func resolvePastedCode(_ raw: String,
                                         pending: PendingRequest?) -> Resolution {
        guard let pending else {
            return .reject("Start sign-in first, then paste the code.")
        }
        let code = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !code.isEmpty else {
            return .reject("Paste the one-time code shown in your browser.")
        }
        return .exchange(code: code, verifier: pending.verifier)
    }
}

// MARK: - base64url (RFC 4648 §5, no padding)

extension Data {
    /// Standard base64 with the URL-safe alphabet and no `=` padding — the
    /// encoding every handle/challenge in the auth spec uses.
    public func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
