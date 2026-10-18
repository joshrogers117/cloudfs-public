// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// `cloudfs://connect?server=<url>` (ONBOARDING.md build step 3): parsing +
// the signed-in/out decision. All pure/offline — no network, no app state.

@Suite struct ConnectLinkTests {

    // MARK: parseServerURL

    @Test func parsesWellFormedServerURL() throws {
        let url = try #require(URL(string: "cloudfs://connect?server=https://gw.example.com"))
        #expect(ConnectLink.parseServerURL(url) == "https://gw.example.com")
    }

    @Test func trimsWhitespaceInServerValue() throws {
        // %20 is a percent-encoded trailing space in the query value.
        let url = try #require(URL(string: "cloudfs://connect?server=https://gw.example.com%20"))
        #expect(ConnectLink.parseServerURL(url) == "https://gw.example.com")
    }

    @Test func rejectsWrongHost() throws {
        // Not the reserved `connect` host — e.g. a nav deep link or the auth callback.
        let url = try #require(URL(string: "cloudfs://auth/callback?server=https://gw.example.com"))
        #expect(ConnectLink.parseServerURL(url) == nil)
    }

    @Test func rejectsWrongScheme() throws {
        let url = try #require(URL(string: "https://connect?server=https://gw.example.com"))
        #expect(ConnectLink.parseServerURL(url) == nil)
    }

    @Test func rejectsMissingServerParam() throws {
        let url = try #require(URL(string: "cloudfs://connect"))
        #expect(ConnectLink.parseServerURL(url) == nil)
    }

    @Test func rejectsEmptyServerParam() throws {
        let url = try #require(URL(string: "cloudfs://connect?server="))
        #expect(ConnectLink.parseServerURL(url) == nil)
    }

    @Test func rejectsNonURLServerValue() throws {
        let url = try #require(URL(string: "cloudfs://connect?server=not-a-url"))
        #expect(ConnectLink.parseServerURL(url) == nil)
    }

    @Test func rejectsSchemelessHostOnlyServerValue() throws {
        // A bare host with no scheme is exactly the mistake the login field's
        // own inline validation catches — the deep link must reject it too.
        let url = try #require(URL(string: "cloudfs://connect?server=gw.example.com"))
        #expect(ConnectLink.parseServerURL(url) == nil)
    }

    @Test func rejectsHostileSchemeInServerValue() throws {
        let raw = "javascript:alert(1)".addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!
        let url = try #require(URL(string: "cloudfs://connect?server=\(raw)"))
        #expect(ConnectLink.parseServerURL(url) == nil)
    }

    @Test func acceptsHttpForLocalDevServers() throws {
        let url = try #require(URL(string: "cloudfs://connect?server=http://127.0.0.1:8787"))
        #expect(ConnectLink.parseServerURL(url) == "http://127.0.0.1:8787")
    }

    // MARK: decide — signed out

    @Test func signedOutAlwaysPrefills() {
        let outcome = ConnectLink.decide(server: "https://gw.example.com",
                                         isSignedIn: false, currentServerURL: "")
        #expect(outcome == .prefill(server: "https://gw.example.com"))
    }

    // MARK: decide — signed in, same server

    @Test func signedInSameServerIsNoOp() {
        let outcome = ConnectLink.decide(server: "https://gw.example.com",
                                         isSignedIn: true,
                                         currentServerURL: "https://gw.example.com")
        #expect(outcome == .alreadyConnected)
    }

    @Test func signedInSameServerIgnoresTrailingSlash() {
        let outcome = ConnectLink.decide(server: "https://gw.example.com/",
                                         isSignedIn: true,
                                         currentServerURL: "https://gw.example.com")
        #expect(outcome == .alreadyConnected)
    }

    @Test func signedInSameServerIgnoresExplicitDefaultPort() {
        let outcome = ConnectLink.decide(server: "https://gw.example.com:443",
                                         isSignedIn: true,
                                         currentServerURL: "https://gw.example.com")
        #expect(outcome == .alreadyConnected)
    }

    @Test func signedInSameServerIsCaseInsensitiveOnHost() {
        let outcome = ConnectLink.decide(server: "https://GW.Example.com",
                                         isSignedIn: true,
                                         currentServerURL: "https://gw.example.com")
        #expect(outcome == .alreadyConnected)
    }

    // MARK: decide — signed in, different server

    @Test func signedInDifferentHostSurfacesAlert() {
        let outcome = ConnectLink.decide(server: "https://other.example.com",
                                         isSignedIn: true,
                                         currentServerURL: "https://gw.example.com")
        #expect(outcome == .differentServer(current: "gw.example.com",
                                            requested: "other.example.com"))
    }

    @Test func signedInDifferentPortSurfacesAlert() {
        // Same host, different port — still a different server; never coalesced.
        let outcome = ConnectLink.decide(server: "https://gw.example.com:9443",
                                         isSignedIn: true,
                                         currentServerURL: "https://gw.example.com")
        #expect(outcome == .differentServer(current: "gw.example.com",
                                            requested: "gw.example.com"))
    }

    @Test func signedInDifferentSchemeSurfacesAlert() {
        let outcome = ConnectLink.decide(server: "http://gw.example.com",
                                         isSignedIn: true,
                                         currentServerURL: "https://gw.example.com")
        #expect(outcome == .differentServer(current: "gw.example.com",
                                            requested: "gw.example.com"))
    }
}
