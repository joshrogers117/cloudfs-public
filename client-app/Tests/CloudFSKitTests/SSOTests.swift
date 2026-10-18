// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// SSO (OIDC) client-side wiring: start-URL build + callback token capture
// (cloudfs:// scheme AND loopback) + the settings/Keychain store round-trip.
// All offline — no IdP, no network. (A live run needs a real OIDC IdP configured
// on the gateway; see oidc-INTEGRATION.md §2.)

@Suite struct SSOTests {

    // MARK: start URL

    @Test func startURLAppendsOidcStartAndRedirect() throws {
        let url = try #require(SSO.startURL(gatewayBaseURL: "https://gw.test"))
        let comps = try #require(URLComponents(url: url, resolvingAgainstBaseURL: false))
        #expect(comps.path == "/v1/auth/oidc/start")
        let redirect = comps.queryItems?.first { $0.name == "redirect_uri" }?.value
        #expect(redirect == "cloudfs://auth/callback")
    }

    @Test func startURLToleratesTrailingSlash() throws {
        let url = try #require(SSO.startURL(gatewayBaseURL: "http://127.0.0.1:8787/"))
        #expect(url.path == "/v1/auth/oidc/start")
        #expect(url.host == "127.0.0.1")
        #expect(url.port == 8787)
    }

    @Test func startURLRejectsGarbage() {
        #expect(SSO.startURL(gatewayBaseURL: "") == nil)
    }

    // MARK: token capture — cloudfs:// scheme

    @Test func capturesTokenFromCloudfsCallback() throws {
        let url = try #require(URL(string: "cloudfs://auth/callback?token=eyJABC.def.ghi"))
        #expect(SSO.tokenFromCallback(url) == "eyJABC.def.ghi")
    }

    @Test func capturesTokenFromCloudfsCallbackNoPath() throws {
        // host-only form: cloudfs://auth?token=…
        let url = try #require(URL(string: "cloudfs://auth?token=tok123"))
        #expect(SSO.tokenFromCallback(url) == "tok123")
    }

    @Test func capturesTokenFromFragment() throws {
        let url = try #require(URL(string: "cloudfs://auth/callback#token=fragTok&state=x"))
        #expect(SSO.tokenFromCallback(url) == "fragTok")
    }

    @Test func rejectsWrongHost() throws {
        let url = try #require(URL(string: "cloudfs://reveal/ShowA/clip.mov?select=0"))
        #expect(SSO.tokenFromCallback(url) == nil)   // a nav deep link, not SSO
    }

    @Test func rejectsCallbackWithoutToken() throws {
        let url = try #require(URL(string: "cloudfs://auth/callback?error=access_denied"))
        #expect(SSO.tokenFromCallback(url) == nil)
    }

    // MARK: token capture — loopback redirect

    @Test func capturesTokenFromLoopback() throws {
        let url = try #require(URL(string: "http://127.0.0.1:53117/callback?token=loopTok&state=s"))
        #expect(SSO.tokenFromCallback(url) == "loopTok")
    }

    // MARK: settings/Keychain store round-trip
    //
    // The token belongs in the Keychain; URL+org in UserDefaults. We exercise the
    // store with an isolated UserDefaults suite, tolerating environments where the
    // login Keychain is unavailable (CI sandboxes) — there the save throws and we
    // simply skip the read-back assertion rather than fail.

    @Test func ssoConfigPersistsTokenToKeychainAndUrlToDefaults() throws {
        let suite = "test.sso." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        let store = GatewaySettingsStore(defaults: defaults, credentialNamespace: suite)

        let config = GatewayConfig(baseURL: "https://gw.test", org: "acme",
                                   token: "sso.session.token")
        do {
            try store.save(config)
        } catch {
            // Keychain not writable here (sandboxed CI). The non-secret part still
            // persisted; assert that and stop.
            #expect(store.baseURL == "https://gw.test")
            #expect(store.org == "acme")
            return
        }
        // URL+org in UserDefaults; token reconstructed from Keychain.
        #expect(store.useHttp == true)
        #expect(store.baseURL == "https://gw.test")
        #expect(store.org == "acme")
        let reloaded = store.loadConfig()
        #expect(reloaded?.token == "sso.session.token")
        // Cleanup.
        store.clear()
        defaults.removePersistentDomain(forName: suite)
    }
}

// MARK: - Device-session settings persistence (auth-spec C5/C8)

@Suite struct DeviceSessionSettingsTests {

    private func isolatedStore() throws -> (GatewaySettingsStore, UserDefaults, String) {
        let suite = "test.device." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        defaults.removePersistentDomain(forName: suite)
        return (GatewaySettingsStore(defaults: defaults, credentialNamespace: suite), defaults, suite)
    }

    @Test func saveDeviceSessionPersistsNonSecretHalf() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.saveDeviceSession(baseURL: "https://gw.acme.example", org: "acme")
        #expect(store.useHttp)
        #expect(store.baseURL == "https://gw.acme.example")
        #expect(store.org == "acme")
        #expect(store.authMethod == .device)
    }

    @Test func loadConfigReturnsNilForDeviceSessions() throws {
        // Device sessions are resumed by AuthSessionManager — loadConfig must
        // NOT fall back to token.txt (that file now holds the daemon's own
        // scoped token, which must never become the app's credential).
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.saveDeviceSession(baseURL: "https://gw.acme.example", org: "acme")
        #expect(store.loadConfig() == nil)
    }

    @Test func legacySaveMarksLegacyMethod() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite); store.clear() }

        do {
            try store.save(GatewayConfig(baseURL: "https://gw.test", org: "acme", token: "tok"))
        } catch {
            return   // Keychain unavailable in this environment — skip
        }
        #expect(store.authMethod == .legacy)
    }

    @Test func clearCredentialsKeepsServerURLPrefilled() throws {
        // Spec §1.5: session expiry returns to sign-in WITH the URL preserved.
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.saveDeviceSession(baseURL: "https://gw.acme.example", org: "acme")
        DaemonCredential.storeExpiry(Date(), defaults: defaults)

        store.clearCredentialsKeepingServer()
        #expect(!store.useHttp)
        #expect(store.authMethod == nil)
        #expect(store.baseURL == "https://gw.acme.example")    // preserved
        #expect(store.org == "acme")                            // preserved
        #expect(DaemonCredential.storedExpiry(defaults: defaults) == nil)
    }

    @Test func fullClearRemovesEverythingIncludingDaemonExpiry() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.saveDeviceSession(baseURL: "https://gw.acme.example", org: "acme")
        DaemonCredential.storeExpiry(Date(), defaults: defaults)

        store.clear()
        #expect(!store.useHttp)
        #expect(store.baseURL.isEmpty)
        #expect(store.org.isEmpty)
        #expect(store.authMethod == nil)
        #expect(DaemonCredential.storedExpiry(defaults: defaults) == nil)
    }
}
