// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// Pure state-selection logic that drives the UI's EMPTY / LOADING / ERROR /
// LOADED presentation. No SwiftUI — just the decision logic the views render.

@Suite(.timeLimit(.minutes(1)))
struct ViewStateTests {

    // MARK: LoadState basic selectors

    @Test func idleAndLoadingAreInitialWithNoValue() {
        let idle = LoadState<[Int]>.idle
        let loading = LoadState<[Int]>.loading
        #expect(idle.isInitial)
        #expect(loading.isInitial)
        #expect(loading.isLoading)
        #expect(!idle.isLoading)
        #expect(idle.value == nil)
        #expect(loading.value == nil)
        #expect(idle.errorMessage == nil)
    }

    @Test func loadedExposesValueAndIsNotInitial() {
        let s = LoadState.loaded([1, 2, 3])
        #expect(s.value == [1, 2, 3])
        #expect(!s.isInitial)
        #expect(!s.isLoading)
        #expect(s.errorMessage == nil)
    }

    @Test func failedExposesMessage() {
        let s = LoadState<[Int]>.failed("boom")
        #expect(s.errorMessage == "boom")
        #expect(s.value == nil)
        #expect(!s.isInitial)
        #expect(!s.isLoading)
    }

    // MARK: Collection helpers — the empty-vs-content decision a pane makes

    @Test func loadedEmptyDistinctFromLoadedContent() {
        let empty = LoadState.loaded([Int]())
        let full = LoadState.loaded([1])
        #expect(empty.isLoadedEmpty)
        #expect(!empty.hasContent)
        #expect(full.hasContent)
        #expect(!full.isLoadedEmpty)
    }

    @Test func loadingIsNeitherEmptyNorContent() {
        // While loading we show a spinner, not the empty state — guard against a
        // regression where a pane flashes "empty" mid-load.
        let loading = LoadState<[Int]>.loading
        #expect(!loading.isLoadedEmpty)
        #expect(!loading.hasContent)
    }

    @Test func failedIsNeitherEmptyNorContent() {
        let failed = LoadState<[Int]>.failed("x")
        #expect(!failed.isLoadedEmpty)
        #expect(!failed.hasContent)
    }

    // MARK: BannerKind semantics (symbol + a11y prefix mapping)

    @Test func bannerKindSymbolsAreDistinct() {
        let symbols = BannerKind.allCases.map(\.symbolName)
        #expect(Set(symbols).count == BannerKind.allCases.count) // all unique
        #expect(BannerKind.error.symbolName == "xmark.octagon.fill")
        #expect(BannerKind.success.symbolName == "checkmark.circle.fill")
    }

    @Test func bannerKindAccessibilityPrefixes() {
        #expect(BannerKind.info.accessibilityPrefix == "Info")
        #expect(BannerKind.warning.accessibilityPrefix == "Warning")
        #expect(BannerKind.error.accessibilityPrefix == "Error")
        #expect(BannerKind.success.accessibilityPrefix == "Success")
    }
}
