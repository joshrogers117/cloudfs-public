// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Sidebar workspace-header plumbing (client-app redesign lane 2): the org
// DISPLAY name and the web console's base URL are learned mid-sign-in and
// otherwise dropped — these round-trip them through `GatewaySettingsStore` so
// the sidebar can render them after a relaunch. Pure UserDefaults logic, no UI.

@Suite struct GatewaySettingsStoreOrgAndWebBaseTests {

    private func isolatedStore() throws -> (GatewaySettingsStore, UserDefaults, String) {
        let suite = "test.settingsstore." + UUID().uuidString
        let defaults = try #require(UserDefaults(suiteName: suite))
        return (GatewaySettingsStore(defaults: defaults, credentialNamespace: suite), defaults, suite)
    }

    // MARK: orgDisplayName

    @Test func orgDisplayNameDefaultsToNilAndRoundTrips() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        #expect(store.orgDisplayName == nil)
        store.orgDisplayName = "Acme Studios"
        #expect(store.orgDisplayName == "Acme Studios")
    }

    @Test func orgDisplayNameSettingEmptyStringClearsIt() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.orgDisplayName = "Acme Studios"
        store.orgDisplayName = ""
        #expect(store.orgDisplayName == nil)
    }

    @Test func orgDisplayNameSettingNilClearsIt() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.orgDisplayName = "Acme Studios"
        store.orgDisplayName = nil
        #expect(store.orgDisplayName == nil)
    }

    @Test func orgDisplayNameIsClearedBySignOut() throws {
        // clearCredentialsKeepingServer() is what AppModel.signOut() calls — the
        // org display name is account-derived, unlike baseURL/org/webBaseUrl, so
        // it must NOT survive a sign-out the way the server address does.
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.orgDisplayName = "Acme Studios"
        store.clearCredentialsKeepingServer()
        #expect(store.orgDisplayName == nil)
    }

    @Test func orgDisplayNameIsClearedByFullClear() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.orgDisplayName = "Acme Studios"
        store.clear()
        #expect(store.orgDisplayName == nil)
    }

    // MARK: webBaseUrl

    @Test func webBaseUrlDefaultsToNilAndRoundTrips() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        #expect(store.webBaseUrl == nil)
        store.webBaseUrl = "https://app.example.com"
        #expect(store.webBaseUrl == "https://app.example.com")
    }

    @Test func webBaseUrlSurvivesSignOut() throws {
        // Server-scoped, like baseURL/org — kept so the next sign-in (same
        // server) doesn't need to re-probe before the console links work again.
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.webBaseUrl = "https://app.example.com"
        store.clearCredentialsKeepingServer()
        #expect(store.webBaseUrl == "https://app.example.com")
    }

    @Test func webBaseUrlIsClearedByFullClear() throws {
        let (store, defaults, suite) = try isolatedStore()
        defer { defaults.removePersistentDomain(forName: suite) }

        store.webBaseUrl = "https://app.example.com"
        store.clear()
        #expect(store.webBaseUrl == nil)
    }
}
