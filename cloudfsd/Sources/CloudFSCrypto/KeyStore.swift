// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCrypto — key material + HKDF derivation. (DESIGN.md §5 "Key handling")
//
// Key hierarchy (security.md §5):
//   - Per-filespace AES-256 *master key*, generated/stored by the gateway and
//     delivered over authenticated TLS, then cached in the macOS Keychain.
//     Operator-provisioned 0600 key files remain supported for headless nodes.
//     This is server-managed encryption, not a zero-knowledge key model.
//   - Per-file / per-block *data keys* derived from the master via HKDF-SHA256, so
//     a single block-key compromise does not expose the master (security.md §5,
//     DESIGN.md §5). Derivation is deterministic (no stored wrapped keys needed
//     for the content-addressed block store): the same (master, itemID, block)
//     always yields the same key, which is required for content-address stability.
//
// Spike-compat (CTR) intentionally does NOT derive: obj-encrypt.mjs uses the raw
// 32-byte master key directly with a per-block CTR counter, so the CTR backend
// takes the master key verbatim to stay wire-compatible with uploaded objects.

import Foundation
import CryptoKit
import CloudFSCore
#if canImport(Security)
import Security
#endif

/// The per-filespace master key plus the HKDF derivation used by the GCM backend.
/// `Sendable` because `SymmetricKey` is an immutable value type.
public struct FilespaceKey: Sendable {
    /// The raw 32-byte master key. Used verbatim by the CTR (spike-compat) path;
    /// used as HKDF input-keying-material by the GCM path.
    let master: SymmetricKey

    public init(masterKeyBytes: Data) throws {
        guard masterKeyBytes.count == 32 else {
            throw EngineErrorBridge.invalid("filespace master key must be 32 bytes, got \(masterKeyBytes.count)")
        }
        self.master = SymmetricKey(data: masterKeyBytes)
    }

    /// Load a master key from a hex-encoded key file (the spike's
    /// `/tmp/cloudfs-fuse-key` format: 64 hex chars, optional trailing newline).
    /// This is the headless / test path; on macOS the production loader reads the
    /// Keychain (`keychainKey(account:)`). Audit B15: the loader also CHECKS the file
    /// mode — a group/other-readable master key file is rejected (the key must be 0600),
    /// since a leaked master key defeats the whole encrypted-at-rest design.
    public init(hexKeyFile path: String) throws {
        // Reject a key file readable by group/other (anything below 0600 exclusivity).
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let perms = (attrs[.posixPermissions] as? NSNumber)?.uint16Value,
           (perms & 0o077) != 0 {
            throw EngineErrorBridge.invalid(
                "key file \(path) is group/other-readable (mode \(String(perms, radix: 8))); chmod 600 it — a leaked master key defeats encryption")
        }
        guard let raw = try? String(contentsOfFile: path, encoding: .utf8) else {
            throw EngineErrorBridge.invalid("cannot read key file at \(path)")
        }
        let hex = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let bytes = Data(hexString: hex) else {
            throw EngineErrorBridge.invalid("key file is not valid hex")
        }
        try self.init(masterKeyBytes: bytes)
    }

    #if canImport(Security)
    /// Audit B15 — load a per-deployment master key from the macOS Keychain
    /// (`kSecClassGenericPassword`, service `com.cloudfs.masterkey`, account supplied by caller).
    /// Returns nil when no item exists (the caller resolves another source), throws on a malformed
    /// item. The stored value is the raw 32 master-key bytes (NOT hex), provisioned out-of-band
    /// (MDM / `security add-generic-password`) so the key never lives in a plaintext file.
    public static func fromKeychain(account: String, service: String = "com.cloudfs.masterkey") -> FilespaceKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = withUnsafeMutablePointer(to: &out) { SecItemCopyMatching(query as CFDictionary, $0) }
        query.removeAll()
        guard status == errSecSuccess, let data = out as? Data, data.count == 32 else { return nil }
        return try? FilespaceKey(masterKeyBytes: data)
    }

    /// ONBOARDING.md "Key model" — cache a key FETCHED from the gateway into the SAME Keychain
    /// item `fromKeychain` reads (service `com.cloudfs.masterkey`, caller-supplied account), so a
    /// device that just fetched its key over the network only pays that round-trip ONCE: every
    /// later connect finds it locally via the existing `fromKeychain` precedence. Update-else-add
    /// (idempotent — a repeated fetch/store just overwrites the same item; safe if a stale/wrong
    /// item is already there, e.g. an operator-provisioned key being superseded).
    ///
    /// Returns `false` — NEVER throws — on any Keychain failure. This repo has known
    /// data-protection-keychain flakiness in dev/headless contexts (macOS 15+ TCC quirks); the
    /// caller's contract is "log a warning and keep using the fetched key in-memory for this
    /// session", not "crash the mount" over a Keychain write.
    @discardableResult
    public func storeInKeychain(account: String, service: String = "com.cloudfs.masterkey") -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let data = masterRawBytes
        let updateStatus = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updateStatus == errSecSuccess { return true }
        guard updateStatus == errSecItemNotFound else { return false }
        var add = query
        add[kSecValueData as String] = data
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }
    #endif

    /// Raw master bytes — only the CTR spike-compat path needs them (it uses the
    /// master key directly, matching obj-encrypt.mjs).
    var masterRawBytes: Data {
        master.withUnsafeBytes { Data($0) }
    }

    /// Derive a per-(file, block, content) AES-256 data key via HKDF-SHA256. The
    /// `info` binds the key to the itemID, the block index, AND the block's
    /// plaintext content digest (SHA-256), so:
    ///   - distinct blocks get distinct keys (an attacker who recovers one block
    ///     key learns nothing about others or the master — security.md §5), and
    ///   - distinct *content* in the SAME (itemID, blockIndex) slot gets a DISTINCT
    ///     key. That is the critical property: the GCM nonce is deterministically
    ///     derived from (itemID, blockIndex) too, so without binding the key to the
    ///     content an in-place edit (RealTransferEngine re-seals block N from a new
    ///     plaintext under the SAME slot) would reuse the SAME (key, nonce) pair on
    ///     DIFFERENT plaintext — catastrophic GCM nonce reuse. A fresh key per
    ///     distinct content makes the fixed deterministic nonce safe.
    ///
    /// Determinism + content-addressed dedup are preserved: identical plaintext
    /// yields an identical `contentDigest`, hence the identical key → nonce →
    /// ciphertext → hash → the same stored object.
    func deriveBlockKey(itemID: InodeID, blockIndex: Int, contentDigest: Data) -> SymmetricKey {
        let info = Data("cloudfs/block/v2/\(itemID.rawValue)/\(blockIndex)/".utf8) + contentDigest
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            salt: Data("cloudfs-filespace-block-key".utf8),
            info: info,
            outputByteCount: 32
        )
    }

    /// Lazily-derived content-digest sub-key (HKDF(master, 'content-digest')). The
    /// content digest that travels in the GCM wire header is `HMAC-SHA256` under
    /// this sub-key, NOT a bare `SHA-256(plaintext)`: a bare hash let anyone with
    /// bucket read access run confirmation/dictionary attacks on known content
    /// (cloudfsd audit — "block header stores raw SHA-256 of the plaintext").
    /// The MAC keeps every property the digest needs — deterministic (same content
    /// ⇒ same digest ⇒ same key/nonce/ciphertext ⇒ dedup), and content-binding for
    /// the per-block key so the fixed nonce is never reused on different plaintext —
    /// while revealing nothing to a holder who lacks the master key.
    private var contentDigestKey: SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: master,
            salt: Data("cloudfs-filespace-content-digest".utf8),
            info: Data("cloudfs/content-digest/v1".utf8),
            outputByteCount: 32
        )
    }

    /// The KEYED content digest stored in the CFB3 wire header and fed to
    /// `deriveBlockKey`. `HMAC-SHA256(HKDF(master,'content-digest'), plaintext)`.
    func contentDigest(_ plaintext: Data) -> Data {
        var mac = HMAC<SHA256>(key: contentDigestKey)
        mac.update(data: plaintext)
        return Data(mac.finalize())
    }
}

// MARK: - Bearer-token loading (Audit B15)

/// Loader for the daemon's service-account BEARER TOKEN, mirroring the master-key precedence: the
/// macOS Keychain FIRST (the token never lives in a plaintext file), then a mode-checked file
/// fallback (headless render nodes / CI). The bearer token authenticates EVERY gateway call, so a
/// leaked token is as dangerous as a leaked master key — hence the same 0600 file-mode requirement
/// and the Keychain-preferred path.
public enum BearerTokenStore {
    /// Result of a token load, with the source for an operator-visible log line.
    public struct Loaded: Sendable, Equatable {
        public let token: String
        public let source: String
        public init(token: String, source: String) { self.token = token; self.source = source }
    }

    #if canImport(Security)
    /// Read the bearer token from the Keychain (`kSecClassGenericPassword`, service
    /// `com.cloudfs.bearer`, account = the filespace id). The stored value is the UTF-8 token
    /// string. Returns nil when no item exists.
    public static func fromKeychain(account: String, service: String = "com.cloudfs.bearer") -> String? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = withUnsafeMutablePointer(to: &out) { SecItemCopyMatching(query as CFDictionary, $0) }
        query.removeAll()
        guard status == errSecSuccess, let data = out as? Data,
              let s = String(data: data, encoding: .utf8) else { return nil }
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
    #endif

    /// Read the token from a file, REJECTING a group/other-readable file (mode must be 0600, like the
    /// master key) so a world-readable token file can't silently leak the credential. Throws on a bad
    /// mode; returns nil when the file is absent/empty/unreadable.
    public static func fromFile(_ path: String) throws -> String? {
        let fm = FileManager.default
        guard fm.fileExists(atPath: path) else { return nil }
        if let attrs = try? fm.attributesOfItem(atPath: path),
           let perms = (attrs[.posixPermissions] as? NSNumber)?.uint16Value,
           (perms & 0o077) != 0 {
            throw EngineErrorBridge.invalid(
                "token file \(path) is group/other-readable (mode \(String(perms, radix: 8))); chmod 600 it — a leaked bearer token authenticates every gateway call")
        }
        guard let raw = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Load with the production precedence: Keychain → mode-checked file → empty (anonymous/dev).
    /// `filespace` keys the Keychain account; `filePath` is the optional `--token-file`. Pure logic
    /// (no logging) so it's unit-testable; the daemon logs the chosen `source`.
    public static func load(filespace: String?, filePath: String?) throws -> Loaded {
        #if canImport(Security)
        if let filespace, let tok = fromKeychain(account: filespace) {
            return Loaded(token: tok, source: "keychain")
        }
        #endif
        if let filePath, let tok = try fromFile(filePath) {
            return Loaded(token: tok, source: "file")
        }
        return Loaded(token: "", source: "none")
    }
}

// MARK: - Hex helpers

extension Data {
    /// Parse an even-length hex string into bytes. Returns nil on bad input.
    init?(hexString: String) {
        let chars = Array(hexString.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        func nibble(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: return c - 0x30           // 0-9
            case 0x61...0x66: return c - 0x61 + 10      // a-f
            case 0x41...0x46: return c - 0x41 + 10      // A-F
            default: return nil
            }
        }
        var i = 0
        while i < chars.count {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            out.append((hi << 4) | lo)
            i += 2
        }
        self = out
    }

    /// Lowercase hex encoding.
    var hexEncodedString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
