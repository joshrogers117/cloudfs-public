// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - DaemonCredential — renewal rules for the daemon's 30-day token (C6)
//
// The app auto-provisions and auto-renews the daemon's service token from its
// device session (POST /v1/auth/device/daemon-token). The daemon re-reads
// token.txt per request, so renewal = rewrite the file; no daemon restart.
//
// Rules (auth-spec §4.1/§4.3): token TTL 30 days; the app re-mints when less
// than 7 days remain — checked at launch, after every sign-in, on a periodic
// timer while the app runs, and on-demand when the daemon reports auth failure.
// Pure math here; the app-side manager (DaemonCredentialManager) does the I/O.

public enum DaemonCredential {

    /// Re-mint when less than this much lifetime remains (spec: 7 days).
    public static let renewThreshold: TimeInterval = 7 * 24 * 3600
    /// How often the running app re-checks the threshold (6h keeps the check
    /// cheap while bounding staleness to far less than the 7-day window).
    public static let checkInterval: TimeInterval = 6 * 3600

    /// Whether the daemon token needs re-minting. Unknown expiry (nil — e.g.
    /// pre-upgrade provisioning or a cleared preference) ⇒ renew, so the daemon
    /// always converges onto a tracked token.
    public static func shouldRenew(expiresAt: Date?, now: Date = Date(),
                                   threshold: TimeInterval = renewThreshold) -> Bool {
        guard let expiresAt else { return true }
        return expiresAt.timeIntervalSince(now) < threshold
    }

    // MARK: persisted expiry (UserDefaults — the token itself is in token.txt)

    static let expiresAtKey = "cloudfs.daemonTokenExpiresAt"
    static let capabilityRevisionKey = "cloudfs.daemonTokenCapabilityRevision"
    // Revision 1 adds historical reads needed by Finder-mounted snapshots.
    static let capabilityRevision = 1

    public static func needsCapabilityUpgrade(defaults: UserDefaults = .standard) -> Bool {
        defaults.integer(forKey: capabilityRevisionKey) < capabilityRevision
    }

    public static func storedExpiry(defaults: UserDefaults = .standard) -> Date? {
        let t = defaults.double(forKey: expiresAtKey)
        return t > 0 ? Date(timeIntervalSince1970: t) : nil
    }

    public static func storeExpiry(_ date: Date?, defaults: UserDefaults = .standard) {
        if let date {
            defaults.set(date.timeIntervalSince1970, forKey: expiresAtKey)
            defaults.set(capabilityRevision, forKey: capabilityRevisionKey)
        } else {
            defaults.removeObject(forKey: expiresAtKey)
            defaults.removeObject(forKey: capabilityRevisionKey)
        }
    }
}

/// The browser session and background engine must change credentials together.
/// In particular, an unexpired daemon token may belong to a different (revoked)
/// device session on the same server. Never reuse it after a fresh exchange.
@MainActor
public enum DaemonCredentialHandoff {
    public enum Failure: LocalizedError {
        case provisioning
        public var errorDescription: String? {
            "Signed in, but the background service credential could not be saved. Please try connecting again."
        }
    }

    public static func prepare(
        forceMint: Bool, defaults: UserDefaults = .standard,
        existingToken: () -> String?,
        mint: () async throws -> DaemonTokenResponse,
        provision: (String) throws -> Void,
        isCurrent: () -> Bool = { true }
    ) async throws {
        guard isCurrent() else { throw CancellationError() }
        // If minting fails, a later app launch must still retry the new session,
        // rather than mistake the previous account's expiry for this one's.
        if forceMint { DaemonCredential.storeExpiry(nil, defaults: defaults) }
        if !forceMint,
           !DaemonCredential.shouldRenew(expiresAt: DaemonCredential.storedExpiry(defaults: defaults)),
           !DaemonCredential.needsCapabilityUpgrade(defaults: defaults),
           let existing = existingToken() {
            try provision(existing)
            return
        }
        let minted = try await mint()
        // A sign-out or another browser callback may have happened during HTTP.
        // An obsolete response must never overwrite the active account's token.
        guard isCurrent(), !Task.isCancelled else { throw CancellationError() }
        try provision(minted.token)
        DaemonCredential.storeExpiry(minted.expiryDate, defaults: defaults)
    }
}
