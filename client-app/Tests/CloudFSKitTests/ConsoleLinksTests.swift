// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// The sidebar's workspace-overflow menu builds every web-console link through
// `ConsoleLinks` instead of ad hoc string concatenation. Pure/offline.

@Suite struct ConsoleLinksTests {

    @Test func prefersWebBaseUrlOverServerBaseURL() {
        let links = ConsoleLinks(webBaseUrl: "https://app.example.com", serverBaseURL: "https://gw.example.com")
        #expect(links.url(.createFilespace)?.absoluteString == "https://app.example.com/filespaces/new")
    }

    @Test func fallsBackToServerBaseURLWhenWebBaseUrlAbsent() {
        let links = ConsoleLinks(webBaseUrl: nil, serverBaseURL: "https://gw.example.com")
        #expect(links.url(.createFilespace)?.absoluteString == "https://gw.example.com/filespaces/new")
    }

    @Test func fallsBackToServerBaseURLWhenWebBaseUrlIsEmpty() {
        let links = ConsoleLinks(webBaseUrl: "  ", serverBaseURL: "https://gw.example.com")
        #expect(links.url(.createFilespace)?.absoluteString == "https://gw.example.com/filespaces/new")
    }

    @Test func stripsTrailingSlashesBeforeAppendingThePath() {
        let links = ConsoleLinks(webBaseUrl: "https://app.example.com/", serverBaseURL: "")
        #expect(links.url(.members)?.absoluteString == "https://app.example.com/members")
    }

    @Test func membersAndDevicesResolveToTheirOwnPages() {
        let links = ConsoleLinks(webBaseUrl: "https://app.example.com", serverBaseURL: "")
        #expect(links.url(.members)?.path == "/members")
        #expect(links.url(.devices)?.path == "/devices")
    }

    @Test func rootPathIsTheBareConsoleBase() {
        let links = ConsoleLinks(webBaseUrl: "https://app.example.com", serverBaseURL: "")
        #expect(links.url(.root)?.absoluteString == "https://app.example.com")
    }

    @Test func nilWhenNeitherBaseIsAvailable() {
        let links = ConsoleLinks(webBaseUrl: nil, serverBaseURL: "")
        #expect(links.url(.createFilespace) == nil)
        #expect(links.base == nil)
    }

    @Test func nilWhenBothBasesAreBlank() {
        let links = ConsoleLinks(webBaseUrl: "   ", serverBaseURL: "  ")
        #expect(links.base == nil)
    }
    @Test func snapshotSettingsEscapesFilespaceIDsAndPreservesConsolePrefix() {
        let links = ConsoleLinks(webBaseUrl: "https://app.example.com/console/", serverBaseURL: "")
        #expect(links.filespaceSettings(id: "edit/one", section: "snapshots")?.absoluteString == "https://app.example.com/console/filespaces/edit%2Fone/settings#snapshots")
    }

}
