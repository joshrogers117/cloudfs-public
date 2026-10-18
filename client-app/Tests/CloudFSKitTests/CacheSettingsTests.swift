// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// The pinning-ceiling derivations (`pinningCeilingBytes` / `remainingPinningBytes`)
// underpin BOTH `CacheGauge`'s 80% marker line (CacheSettingsView, Dashboard's
// Pinned & cache card) and the Pinned view's "Remaining pinning" side stat — one
// formula, unit-tested here, so the two surfaces can never silently disagree.

@Suite(.timeLimit(.minutes(1)))
struct CacheSettingsTests {

    private func settings(maxBytes: Int64, usedBytes: Int64 = 0, pinnedBytes: Int64 = 0) -> CacheSettings {
        CacheSettings(maxBytes: maxBytes, usedBytes: usedBytes, pinnedBytes: pinnedBytes,
                     location: "/tmp/cache", prefetchEnabled: true, prefetchDepth: 8)
    }

    @Test func pinningCeilingIs80PercentOfMax() {
        let c = settings(maxBytes: 100_000_000_000)
        #expect(c.pinningCeilingBytes == 80_000_000_000)
        #expect(abs(Double(c.pinningCeilingBytes) / Double(c.maxBytes) - CacheSettings.pinningCeilingFraction) < 0.0001)
    }

    @Test func pinningCeilingGuardsZeroMax() {
        let c = settings(maxBytes: 0)
        #expect(c.pinningCeilingBytes == 0)
        #expect(c.remainingPinningBytes == 0)
    }

    @Test func remainingPinningSubtractsPinnedFromCeiling() {
        let c = settings(maxBytes: 100_000_000_000, pinnedBytes: 30_000_000_000)
        #expect(c.remainingPinningBytes == 50_000_000_000)   // 80 - 30
    }

    @Test func remainingPinningNeverGoesNegative() {
        // Cache shrunk below what's already pinned (e.g. user lowered maxBytes).
        let c = settings(maxBytes: 100_000_000_000, pinnedBytes: 95_000_000_000)
        #expect(c.remainingPinningBytes == 0)
    }

    @Test func remainingPinningIsFullCeilingWhenNothingPinned() {
        let c = settings(maxBytes: 100_000_000_000, pinnedBytes: 0)
        #expect(c.remainingPinningBytes == c.pinningCeilingBytes)
    }
}
