// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// The menu-bar command vocabulary: keyboard-shortcut mapping, state-driven
// enablement, the Go-menu digit shortcuts, and the login-form validation. All
// pure logic (no SwiftUI), so the scene's `.commands { }` just renders these.

@Suite(.timeLimit(.minutes(1)))
struct AppCommandTests {

    private func ctx(signedIn: Bool = true, section: String = "Filespaces") -> CommandContext {
        CommandContext(isSignedIn: signedIn, section: section)
    }

    // MARK: Shortcut → action mapping (the documented accelerators)
    //
    // After WS1 removed the Finder-like browser, the selection-bound commands
    // (Copy Link / Pin Selected / Reveal / Search) are gone. The surviving menu
    // vocabulary is New Share (menu-only) + Refresh (⌘R).

    @Test func shortcutsMatchSpec() {
        #expect(AppCommand.refresh.shortcut == CommandShortcut("r", [.command]))
    }

    @Test func menuOnlyCommandsHaveNoShortcut() {
        // New Share is menu-only. (Toggle Sidebar is the system View-menu item, so
        // it isn't part of this vocabulary.)
        #expect(AppCommand.newShare.shortcut == nil)
    }

    // MARK: Enablement — signed out disables everything

    @Test func everythingDisabledWhenSignedOut() {
        let c = ctx(signedIn: false)
        for command in AppCommand.allCases {
            #expect(!command.isEnabled(in: c), "\(command) should be disabled signed-out")
        }
    }

    // MARK: Enablement — view controls only require being signed in

    @Test func viewControlsEnabledWhenSignedIn() {
        let c = ctx()
        for command in AppCommand.allCases {
            #expect(command.isEnabled(in: c), "\(command) should be enabled when signed in")
        }
    }

    // MARK: Every command has a registered glyph + a title

    @Test func everyCommandHasGlyphAndTitle() {
        for command in AppCommand.allCases {
            #expect(!command.glyph.isEmpty)
            #expect(IconSet.all.contains(command.glyph), "glyph not in IconSet: \(command.glyph)")
            #expect(!command.title().isEmpty)
        }
    }

    // MARK: Go-menu — ⌘1…⌘9 by sidebar index, nothing past 9

    @Test func goMenuDigitShortcuts() {
        #expect(GoMenu.shortcut(forIndex: 0) == CommandShortcut("1", [.command]))   // Filespaces ⌘1
        #expect(GoMenu.shortcut(forIndex: 7) == CommandShortcut("8", [.command]))   // Preferences ⌘8 (8 sections)
        #expect(GoMenu.shortcut(forIndex: 8) == CommandShortcut("9", [.command]))
        #expect(GoMenu.shortcut(forIndex: 9) == nil)                                 // ⌘10 doesn't exist
        #expect(GoMenu.shortcut(forIndex: -1) == nil)
    }
}

// MARK: - Login form validation

@Suite(.timeLimit(.minutes(1)))
struct LoginValidationTests {

    @Test func emptyURLIsNotFlaggedInvalid() {
        // Calm: an empty field shows no error until the user types.
        #expect(!LoginValidation.gatewayURLInvalid(""))
        #expect(!LoginValidation.gatewayURLInvalid("   "))
    }

    @Test func httpAndHttpsURLsAreValid() {
        #expect(!LoginValidation.gatewayURLInvalid("https://gw.cloudfs.example"))
        #expect(!LoginValidation.gatewayURLInvalid("http://127.0.0.1:8787"))
    }

    @Test func nonHttpOrHostlessURLsAreInvalid() {
        #expect(LoginValidation.gatewayURLInvalid("gw.cloudfs.example"))   // no scheme
        #expect(LoginValidation.gatewayURLInvalid("ftp://host"))           // wrong scheme
        #expect(LoginValidation.gatewayURLInvalid("https://"))            // no host
        #expect(LoginValidation.gatewayURLInvalid("not a url"))
    }

    @Test func connectNeedsURLAndToken() {
        #expect(!LoginValidation.canConnectGateway(url: "", token: "eyJ"))
        #expect(!LoginValidation.canConnectGateway(url: "https://gw.example", token: ""))
        #expect(!LoginValidation.canConnectGateway(url: "bad", token: "eyJ"))
        #expect(LoginValidation.canConnectGateway(url: "https://gw.example", token: "eyJ"))
        // Whitespace-only token is not enough.
        #expect(!LoginValidation.canConnectGateway(url: "https://gw.example", token: "   "))
    }

    @Test func ssoNeedsOnlyAValidURL() {
        #expect(!LoginValidation.canStartSSO(url: ""))
        #expect(!LoginValidation.canStartSSO(url: "bad"))
        #expect(LoginValidation.canStartSSO(url: "https://gw.example"))   // no token required
    }

    @Test func browserSignInNeedsOnlyAValidURL() {
        // The default path (auth-spec §1.2): URL-only rules — no org, no token.
        #expect(!LoginValidation.canSignInWithBrowser(url: ""))
        #expect(!LoginValidation.canSignInWithBrowser(url: "   "))
        #expect(!LoginValidation.canSignInWithBrowser(url: "gw.example"))      // no scheme
        #expect(!LoginValidation.canSignInWithBrowser(url: "ftp://gw.example"))
        #expect(LoginValidation.canSignInWithBrowser(url: "https://gw.example"))
        #expect(LoginValidation.canSignInWithBrowser(url: "http://127.0.0.1:8787"))
    }
}
