// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Byte / rate formatting used across the UI (transfers, cache, menu bar).
@Suite(.timeLimit(.minutes(1)))
struct ByteFormatTests {

    @Test func zeroRendersAsCleanZeroNotZeroKB() {
        // ByteCountFormatter renders 0 as "Zero KB"; we want a clean "0 KB".
        #expect(ByteFormat.string(0) == "0 KB")
    }

    @Test func negativeIsTreatedAsZero() {
        #expect(ByteFormat.string(-1) == "0 KB")
    }

    @Test func nonZeroStillFormats() {
        // Don't assert exact spacing/locale — just that it's not the zero string
        // and mentions the right unit.
        let mb = ByteFormat.string(220 * 1024 * 1024)
        #expect(mb != "0 KB")
        #expect(mb.contains("MB"))
    }

    @Test func rateZeroRendersDash() {
        #expect(ByteFormat.rate(0) == "—")
    }

    @Test func rateNonZeroHasPerSecondSuffix() {
        #expect(ByteFormat.rate(5 * 1024 * 1024).hasSuffix("/s"))
    }
}
