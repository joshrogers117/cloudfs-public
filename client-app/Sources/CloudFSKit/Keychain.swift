// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Security
import os

// MARK: - Keychain
//
// Minimal generic-password wrapper for the service-account token. The token is
// the bearer credential (API.md §1) and must NOT live in UserDefaults; it goes
// in the login Keychain. The gateway URL + org are non-secret and persist in
// UserDefaults via GatewaySettingsStore.
//
// In a sandboxed/App-Group build this would carry a Keychain access group
// (kSecAttrAccessGroup) so the appex/engine can read the same token; for the
// unsandboxed control-app stub the default keychain is correct.

public enum Keychain {

    /// Account label under which the token is stored.
    public static let tokenAccount = "service-account-token"
    /// Service label namespacing all cloud-fs keychain items.
    public static let service = "dev.cloudfs.client"

    private static let log = Logger(subsystem: "dev.cloudfs.client", category: "keychain")

    public enum KeychainError: Error, Sendable, CustomStringConvertible, LocalizedError {
        case unexpectedStatus(OSStatus)
        /// Both the data-protection write AND the legacy-file-keychain fallback failed.
        case bothKeychainsFailed(dataProtection: OSStatus, legacy: OSStatus)
        public var description: String {
            switch self {
            case .unexpectedStatus(let s):
                return "Keychain error \(s): \(Self.message(s))"
            case .bothKeychainsFailed(let dp, let legacy):
                return "Keychain error — data-protection: \(dp) (\(Self.message(dp))); legacy: \(legacy) (\(Self.message(legacy)))"
            }
        }
        // LocalizedError, so UI alerts show the real OSStatus instead of "error 0".
        public var errorDescription: String? { description }
        private static func message(_ s: OSStatus) -> String {
            SecCopyErrorMessageString(s, nil) as String? ?? "OSStatus \(s)"
        }
    }

    /// Items PREFER the DATA-PROTECTION keychain (kSecUseDataProtectionKeychain):
    /// its access rule is the app's keychain access group (team + bundle id),
    /// which is STABLE across rebuilds — the legacy file keychain ACLs are
    /// per-binary and silently broke token restore after a repackage (M5 live
    /// test: token written at sign-in, gone on relaunch).
    ///
    /// The DP keychain needs a signed keychain access group (the app entitlements
    /// list $(AppIdentifierPrefix)dev.cloudfs.client). Where that isn't available
    /// — unsigned test runners, CI — writes FALL BACK to the legacy file keychain
    /// rather than failing sign-in, and reads check both.
    private static func query(account: String, dataProtection: Bool) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if dataProtection { q[kSecUseDataProtectionKeychain as String] = true }
        return q
    }

    /// Update-else-add against ONE keychain domain. Returns the failing OSStatus
    /// instead of throwing so set() can chain domains.
    private static func upsert(_ data: Data, account: String, dataProtection: Bool) -> OSStatus {
        let query = query(account: account, dataProtection: dataProtection)
        let attrs: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if updateStatus == errSecSuccess { return errSecSuccess }
        guard updateStatus == errSecItemNotFound else { return updateStatus }
        var add = query
        add[kSecValueData as String] = data
        if dataProtection {
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        return SecItemAdd(add as CFDictionary, nil)
    }

    /// Store (or overwrite) a string value for `account`.
    public static func set(_ value: String, account: String) throws {
        let data = Data(value.utf8)
        let dpStatus = upsert(data, account: account, dataProtection: true)
        if dpStatus == errSecSuccess {
            // Don't leave a stale copy behind in the legacy keychain.
            SecItemDelete(query(account: account, dataProtection: false) as CFDictionary)
            return
        }
        log.error("data-protection keychain write failed (\(dpStatus)); falling back to file keychain")
        let legacyStatus = upsert(data, account: account, dataProtection: false)
        guard legacyStatus == errSecSuccess else {
            throw KeychainError.bothKeychainsFailed(dataProtection: dpStatus, legacy: legacyStatus)
        }
    }

    /// Read a string value for `account`, or nil if absent. Checks the
    /// data-protection keychain first, then the legacy file keychain.
    public static func get(account: String) -> String? {
        var statuses: [OSStatus] = []
        for dataProtection in [true, false] {
            var query = query(account: account, dataProtection: dataProtection)
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            var item: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &item)
            if status == errSecSuccess, let data = item as? Data {
                return String(data: data, encoding: .utf8)
            }
            statuses.append(status)
        }
        log.notice("keychain read miss for \(account, privacy: .public): dp=\(statuses[0]) legacy=\(statuses[1])")
        return nil
    }

    /// Remove the value for `account` from both keychains (no-op if absent).
    public static func delete(account: String) {
        SecItemDelete(query(account: account, dataProtection: true) as CFDictionary)
        SecItemDelete(query(account: account, dataProtection: false) as CFDictionary)
    }

    // Convenience for the token specifically.
    public static func setToken(_ token: String) throws { try set(token, account: tokenAccount) }
    public static func token() -> String? { get(account: tokenAccount) }
    public static func clearToken() { delete(account: tokenAccount) }
}
