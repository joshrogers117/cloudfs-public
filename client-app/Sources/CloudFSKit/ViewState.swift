// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - LoadState — a pure, testable async-content state machine
//
// Views drive their EMPTY / LOADING / ERROR / LOADED presentation from this one
// enum instead of ad-hoc `isEmpty` checks. It lives in CloudFSKit (no SwiftUI) so
// the state-selection logic is unit-testable in isolation; the SwiftUI layer just
// renders whichever case is active.

public enum LoadState<Value: Sendable>: Sendable {
    case idle                  // not yet requested
    case loading               // request in flight (show LoadingPane / skeleton)
    case loaded(Value)         // success — render `Value` (which may itself be empty)
    case failed(String)        // error — show a Banner with this message + retry

    // MARK: Convenience selectors (what the view asks)

    public var value: Value? {
        if case .loaded(let v) = self { return v }
        return nil
    }

    public var isLoading: Bool {
        if case .loading = self { return true }
        return false
    }

    public var errorMessage: String? {
        if case .failed(let m) = self { return m }
        return nil
    }

    /// True when there is nothing yet to show *and* we are actively loading or
    /// have never loaded — i.e. the view should present a loading/idle placeholder
    /// rather than content or an error.
    public var isInitial: Bool {
        switch self {
        case .idle, .loading: return true
        case .loaded, .failed: return false
        }
    }
}

extension LoadState where Value: Collection {
    /// True when loaded successfully but the collection is empty → show the
    /// inviting empty state (not a spinner, not an error).
    public var isLoadedEmpty: Bool {
        if case .loaded(let v) = self { return v.isEmpty }
        return false
    }

    /// True when loaded with at least one element → show content.
    public var hasContent: Bool {
        if case .loaded(let v) = self { return !v.isEmpty }
        return false
    }
}

// MARK: - BannerKind — semantic styling key for inline banners
//
// The visual mapping (symbol + color) lives in the view layer (Theme); this enum
// is the pure semantic key so banner-kind selection is testable and consistent.

public enum BannerKind: String, Sendable, CaseIterable {
    case info
    case success
    case warning
    case error

    /// The SF Symbol name for this kind (monochrome, matches the dark theme).
    public var symbolName: String {
        switch self {
        case .info:    return "info.circle.fill"
        case .success: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error:   return "xmark.octagon.fill"
        }
    }

    /// A default screen-reader prefix so the banner announces its severity.
    public var accessibilityPrefix: String {
        switch self {
        case .info:    return "Info"
        case .success: return "Success"
        case .warning: return "Warning"
        case .error:   return "Error"
        }
    }
}
