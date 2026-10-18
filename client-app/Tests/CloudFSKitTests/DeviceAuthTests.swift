// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Browser-handoff device auth (auth-spec §2.1/§3/§5): PKCE S256 generation,
// state generation, authorize-URL building, callback parsing (new code+state,
// legacy token, junk), and the pending-request binding rules — state mismatch
// and pasted-code-without-pending are refused. All offline.

@Suite struct DeviceAuthTests {

    // MARK: PKCE

    @Test func pkceChallengeMatchesRFC7636AppendixB() {
        // RFC 7636 Appendix B reference vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        #expect(DeviceAuth.challenge(forVerifier: verifier)
                == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    @Test func verifierIsWithinRFCBoundsAndURLSafe() {
        let allowed = CharacterSet(charactersIn:
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        for _ in 0..<8 {
            let v = DeviceAuth.makeVerifier()
            #expect((43...128).contains(v.count))          // RFC 7636 §4.1
            #expect(v.count == 86)                          // 64 bytes b64url
            #expect(v.unicodeScalars.allSatisfy { allowed.contains($0) })
        }
        #expect(DeviceAuth.makeVerifier() != DeviceAuth.makeVerifier())
    }

    @Test func stateIs32BytesBase64URLAndUnique() {
        let s = DeviceAuth.makeState()
        #expect(s.count == 43)                              // 32 bytes b64url, no padding
        #expect(!s.contains("=") && !s.contains("+") && !s.contains("/"))
        #expect(DeviceAuth.makeState() != DeviceAuth.makeState())
    }

    @Test func base64URLEncodingDropsPaddingAndSwapsAlphabet() {
        // 0xFB 0xEF 0xBE encodes to "++++"-class chars in plain base64.
        let data = Data([0xFB, 0xEF, 0xBE, 0xFF])
        let encoded = data.base64URLEncodedString()
        #expect(!encoded.contains("+") && !encoded.contains("/") && !encoded.contains("="))
        #expect(encoded == "----_w")
    }

    // MARK: Device info clamping (spec §2.2 validation, client-side)

    @Test func deviceInfoClampsNameAndModel() {
        let long = String(repeating: "n", count: 100)
        let info = DeviceAuth.DeviceInfo(name: long, model: String(repeating: "m", count: 40),
                                         appVersion: String(repeating: "v", count: 20))
        #expect(info.name.count == 64)
        #expect(info.model?.count == 32)
        #expect(info.appVersion?.count == 16)
    }

    @Test func deviceInfoStripsControlCharactersAndTrims() {
        let info = DeviceAuth.DeviceInfo(name: "  Josh’s\u{0000} MacBook\n Pro  ")
        #expect(info.name == "Josh’s MacBook Pro")
    }

    @Test func formatCharactersLikeZWJSurviveTheControlStrip() {
        // Cf (format) is NOT Cc (control): stripping ZWJ would shred
        // multi-person emoji into their parts and break ZWNJ-dependent
        // scripts. The wire validators only check length — keep Cf.
        let info = DeviceAuth.DeviceInfo(name: "Mac 👨‍👩‍👧‍👦")
        #expect(info.name == "Mac 👨‍👩‍👧‍👦")
        #expect(info.name.unicodeScalars.contains { $0.value == 0x200D })
    }

    // The clamp counts UTF-16 code units — JS `String.length`, the unit BOTH
    // wire validators (portal + backend) use — never Swift graphemes
    // (contract-review M-2: a grapheme clamp let emoji-heavy names through at
    // ≤64 graphemes but >64 units, and the portal rejected the link).

    @Test func deviceInfoClampsByUTF16UnitsNotGraphemes() {
        // 40×😀 = 40 graphemes (old clamp: untouched) but 80 UTF-16 units.
        let info = DeviceAuth.DeviceInfo(name: String(repeating: "😀", count: 40))
        #expect(info.name.utf16.count <= 64)
        #expect(info.name == String(repeating: "😀", count: 32))   // exactly 64 units
    }

    @Test func clampNeverSplitsASurrogatePair() {
        // 63 ASCII + one emoji (2 units) = 65 units; cutting at unit 64 would
        // land mid-surrogate — must trim back to the last whole Character.
        let info = DeviceAuth.DeviceInfo(name: String(repeating: "a", count: 63) + "😀")
        #expect(info.name == String(repeating: "a", count: 63))
        #expect(info.name.utf16.count == 63)
    }

    @Test func clampNeverSplitsAGraphemeCluster() {
        // Family emoji: 4 people + 3 ZWJs = 7 scalars = 11 UTF-16 units, ONE
        // grapheme. 6×11 = 66 > 64 → only 5 whole families (55 units) fit.
        let family = "👨‍👩‍👧‍👦"
        #expect(family.utf16.count == 11)
        let info = DeviceAuth.DeviceInfo(name: String(repeating: family, count: 6))
        #expect(info.name == String(repeating: family, count: 5))
        #expect(info.name.utf16.count == 55)
    }

    @Test func emojiNameWithinTheUTF16BudgetPassesUntouched() {
        let name = "Josh's Edit Bay 🚀🎬 Mac"   // 22 graphemes, 24 UTF-16 units
        let info = DeviceAuth.DeviceInfo(name: name)
        #expect(info.name == name)
        #expect(info.name.utf16.count <= 64)
    }

    // MARK: Authorize URL (spec §2.1)

    private func params(of url: URL) -> [String: String] {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        return Dictionary(uniqueKeysWithValues: items.map { ($0.name, $0.value ?? "") })
    }

    @Test func authorizeURLCarriesAllParams() throws {
        let device = DeviceAuth.DeviceInfo(name: "Josh's MacBook Pro",
                                           model: "MacBookPro18,3", appVersion: "1.2.3")
        let url = try #require(DeviceAuth.authorizeURL(
            webBaseURL: "https://gw.acme.example", state: "st-1",
            challenge: "ch-1", device: device))
        #expect(url.host == "gw.acme.example")
        #expect(url.path == "/device/authorize")
        let q = params(of: url)
        #expect(q["state"] == "st-1")
        #expect(q["code_challenge"] == "ch-1")
        #expect(q["code_challenge_method"] == "S256")
        #expect(q["device_name"] == "Josh's MacBook Pro")
        #expect(q["device_model"] == "MacBookPro18,3")
        #expect(q["app_version"] == "1.2.3")
    }

    @Test func authorizeURLToleratesTrailingSlashAndPort() throws {
        let url = try #require(DeviceAuth.authorizeURL(
            webBaseURL: "http://127.0.0.1:5173/", state: "s", challenge: "c",
            device: .init(name: "Mac")))
        #expect(url.path == "/device/authorize")
        #expect(url.port == 5173)
        let q = params(of: url)
        #expect(q["device_model"] == nil)   // optional param omitted when absent
        #expect(q["app_version"] == nil)
    }

    @Test func authorizeURLRejectsGarbage() {
        #expect(DeviceAuth.authorizeURL(webBaseURL: "", state: "s", challenge: "c",
                                        device: .init(name: "Mac")) == nil)
        #expect(DeviceAuth.authorizeURL(webBaseURL: "not a url", state: "s", challenge: "c",
                                        device: .init(name: "Mac")) == nil)
    }

    // Query-value encoding (contract-review N-1): the portal parses the query
    // with URLSearchParams (form-urlencoded rules), where a literal '+'
    // decodes as a SPACE. Values must arrive byte-exact through THAT decoder.

    /// Decode a raw query value exactly the way the portal does:
    /// URLSearchParams semantics — '+' → space, then percent-decode.
    private func formURLDecoded(_ raw: String) -> String? {
        raw.replacingOccurrences(of: "+", with: " ").removingPercentEncoding
    }

    /// The value as it appears ON THE WIRE (still percent-encoded).
    private func rawQueryValue(of url: URL, name: String) -> String? {
        URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .percentEncodedQueryItems?.first { $0.name == name }?.value
    }

    @Test func plusInDeviceNameSurvivesThePortalDecoder() throws {
        let device = DeviceAuth.DeviceInfo(name: "Josh's MacBook + Studio")
        let url = try #require(DeviceAuth.authorizeURL(
            webBaseURL: "https://gw.test", state: "s", challenge: "c", device: device))
        let raw = try #require(rawQueryValue(of: url, name: "device_name"))
        #expect(!raw.contains("+"))            // never a literal '+' (reads as space)
        #expect(raw.contains("%2B"))           // the '+' itself, percent-encoded
        #expect(formURLDecoded(raw) == "Josh's MacBook + Studio")
    }

    @Test func trickyDeviceNamesRoundTripThroughFormURLDecoding() throws {
        // Space, '+', '&', '=', '%', non-ASCII, emoji — each must round-trip
        // byte-exact through URLSearchParams AND plain RFC 3986 decoding.
        let names = [
            "Josh's MacBook + Studio",
            "Cut & Color = Done",
            "a+b=c&d e?f#g",
            "Müller-Lüdenscheidt Büro",
            "Edit Bay 🎬 + Suite 2",
            "100% render + 50%",
        ]
        for name in names {
            let device = DeviceAuth.DeviceInfo(name: name)
            let url = try #require(DeviceAuth.authorizeURL(
                webBaseURL: "https://gw.test", state: "st", challenge: "ch", device: device))
            let raw = try #require(rawQueryValue(of: url, name: "device_name"))
            #expect(!raw.contains("+"), "literal '+' leaked for \(name)")
            #expect(formURLDecoded(raw) == name, "URLSearchParams round-trip failed for \(name)")
            #expect(params(of: url)["device_name"] == name,
                    "RFC 3986 round-trip failed for \(name)")
        }
    }

    @Test func beginRequestBindsItsOwnStateAndChallenge() throws {
        let pending = try #require(DeviceAuth.beginRequest(
            serverURL: "https://gw.test", webBaseURL: "https://gw.test",
            device: .init(name: "Mac")))
        let q = params(of: pending.authorizeURL)
        #expect(q["state"] == pending.state)
        #expect(q["code_challenge"] == DeviceAuth.challenge(forVerifier: pending.verifier))
        #expect(q["code_challenge_method"] == "S256")
        #expect(pending.serverURL == "https://gw.test")
    }

    // MARK: Callback parsing (extends — does not replace — the legacy ?token=)

    @Test func parsesDeviceCallback() throws {
        let url = try #require(URL(string:
            "cloudfs://auth/callback?code=acme.dac-1.secret&state=st-9"))
        #expect(DeviceAuth.parseCallback(url) ==
                .device(code: "acme.dac-1.secret", state: "st-9"))
    }

    @Test func parsesLegacyTokenCallback() throws {
        let url = try #require(URL(string: "cloudfs://auth/callback?token=eyJABC.def.ghi"))
        #expect(DeviceAuth.parseCallback(url) == .legacyToken("eyJABC.def.ghi"))
    }

    @Test func codeWithoutStateIsNotADeviceCallback() throws {
        // A code with no state can't be bound to the pending request via URL —
        // it must come through the paste path instead.
        let url = try #require(URL(string: "cloudfs://auth/callback?code=acme.dac-1.s"))
        #expect(DeviceAuth.parseCallback(url) == nil)
    }

    @Test func rejectsNavDeepLinkAndJunk() throws {
        let nav = try #require(URL(string: "cloudfs://reveal/ShowA/clip.mov?select=0"))
        #expect(DeviceAuth.parseCallback(nav) == nil)
        let noParams = try #require(URL(string: "cloudfs://auth/callback"))
        #expect(DeviceAuth.parseCallback(noParams) == nil)
        let error = try #require(URL(string: "cloudfs://auth/callback?error=access_denied"))
        #expect(DeviceAuth.parseCallback(error) == nil)
    }

    // MARK: Pending-request binding (spec §5.2 + §3)

    private var pending: DeviceAuth.PendingRequest {
        DeviceAuth.PendingRequest(serverURL: "https://gw.test", state: "st-good",
                                  verifier: "verifier-1",
                                  authorizeURL: URL(string: "https://gw.test/device/authorize")!)
    }

    @Test func matchingStateExchangesWithPendingVerifier() {
        let res = DeviceAuth.resolve(callbackCode: "code-1", state: "st-good", pending: pending)
        #expect(res == .exchange(code: "code-1", verifier: "verifier-1"))
    }

    @Test func stateMismatchIsRejected() {
        let res = DeviceAuth.resolve(callbackCode: "code-1", state: "st-evil", pending: pending)
        guard case .reject = res else {
            Issue.record("state mismatch must hard-fail, got \(res)")
            return
        }
    }

    @Test func callbackWithoutPendingRequestIsRejected() {
        let res = DeviceAuth.resolve(callbackCode: "code-1", state: "st-good", pending: nil)
        guard case .reject = res else {
            Issue.record("callback with no pending request must be refused")
            return
        }
    }

    @Test func pastedCodeBindsToActivePendingRequest() {
        let res = DeviceAuth.resolvePastedCode("  acme.dac-2.s  ", pending: pending)
        #expect(res == .exchange(code: "acme.dac-2.s", verifier: "verifier-1"))
    }

    @Test func pastedCodeWithoutPendingIsRejectedWithSpecCopy() {
        let res = DeviceAuth.resolvePastedCode("acme.dac-2.s", pending: nil)
        #expect(res == .reject("Start sign-in first, then paste the code."))
    }

    @Test func emptyPasteIsRejected() {
        guard case .reject = DeviceAuth.resolvePastedCode("   ", pending: pending) else {
            Issue.record("empty paste must be refused")
            return
        }
    }
}
