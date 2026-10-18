// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCrypto — production block pipeline: LZ4 -> AES-256-GCM -> SHA-256(serialized block).
// (DESIGN.md §5 "Production", SPEC §4.6, security.md §5)
//
// PIPELINE (encrypt-on-write):
//   plaintext
//     -> LZ4 compress (best-effort; store-raw if incompressible)
//     -> AES-256-GCM seal (per-block key via HKDF, 12-byte deterministic nonce,
//        block index authenticated as AAD)
//     -> serialize: HEADER || GCM(nonce||ciphertext||tag)
//     -> SHA-256(serialized) = content address (BlockHash)
//
// DECRYPT-on-read reverses it and VERIFIES the GCM tag before returning a byte
// (tamper-evidence — the property CTR lacks). A tag failure throws `.corrupt`,
// which the read path treats as "re-fetch from R2" (DESIGN.md §3.5 self-healing).
//
// ── WIRE FORMAT (the serialized block that is hashed + PUT to R2) ──
//   off  size  field
//   0    4     magic "CFB3"  (Cloud-Fs-Block v3 — KEYED content digest;
//              "CFB2" is read-compat: same layout, bare SHA-256 digest)
//   4    1     flags         bit0 = LZ4-compressed payload
//   5    4     plaintextLen  big-endian UInt32 (pre-compression length)
//   9    32    contentDigest KEYED MAC of the plaintext — HMAC-SHA256(HKDF(master,
//              'content-digest'), plaintext). Binds the per-block KEY to the content
//              (see "content-bound key" below) and travels with the block so decrypt
//              can re-derive the key from ciphertext alone. v3 replaces v2's bare
//              SHA-256(plaintext): a bare hash is a per-block plaintext fingerprint
//              in the clear that lets a bucket-credential holder confirmation-attack
//              known content; the keyed MAC reveals nothing without the master key
//              while keeping determinism + dedup + the content↔key binding intact.
//   41   ...   AES.GCM.combined = nonce(12) || ciphertext || tag(16)
// The header (magic|flags|plaintextLen|contentDigest) is also fed to GCM as
// Associated Data alongside the 8-byte big-endian block index, so neither the
// header (including the digest) nor the block's position can be altered without
// failing the tag.
//
// ── DETERMINISTIC NONCE + CONTENT-BOUND KEY — why, and why it is safe ──
// Blocks are content-addressed by SHA-256(serialized block), so encryption MUST be
// deterministic: the same (master key, itemID, blockIndex, plaintext) has to
// produce the same bytes (and thus the same hash) every time, or dedup and the
// cache's content-address check break. A *random* nonce would make every encrypt
// of identical content a different object. So the nonce is derived (HKDF) from
// (itemID, blockIndex) — NOT from the plaintext.
//
// GCM's safety rule is "never reuse a (key, nonce) pair for different plaintexts."
// The nonce is fixed per slot, so the KEY must change whenever the plaintext does.
// We therefore derive the per-block KEY via HKDF from (itemID, blockIndex,
// SHA-256(plaintext)). The slot is NOT immutable in practice: an in-place edit
// re-seals block N of the SAME (itemID, blockIndex) with DIFFERENT plaintext
// (RealTransferEngine.runUpload re-encrypts the whole dense image from block 0 on
// every staged write). Without binding the key to the content, that would reuse
// the SAME (key, nonce) on DIFFERENT plaintext — a catastrophic GCM nonce reuse
// (keystream-XOR leakage + GHASH-H recovery → tag forgery), defeating the
// tamper-evidence guarantee. Binding the key to SHA-256(plaintext) gives every
// distinct content its own key, so the fixed nonce is only ever paired with one
// plaintext per key — safe. Identical plaintext still yields the identical digest
// → identical key → identical ciphertext → identical hash → dedup is preserved.
// (The earlier rationale claimed storage immutability prevented reuse; that was
// wrong — the upload path overwrites a slot in place — so the key is now bound to
// the content, not merely the slot. This is the construction Cryptomator uses for
// its content-addressed chunks.)

import Foundation
import CryptoKit
import CloudFSCore

public struct AESGCMBlockCrypto: BlockCrypto {
    public let mode: CipherMode = .aes256gcm

    private let keys: FilespaceKey

    public init(key: FilespaceKey) { self.keys = key }

    // Convenience: build straight from raw master-key bytes.
    public init(masterKeyBytes: Data) throws {
        self.keys = try FilespaceKey(masterKeyBytes: masterKeyBytes)
    }

    // MARK: Wire-format constants
    static let magic: [UInt8] = Array("CFB3".utf8)    // 4 bytes (v3 = KEYED content digest)
    static let magicV2: [UInt8] = Array("CFB2".utf8)  // read-compat (bare SHA-256 digest)
    static let digestLen = 32                         // keyed MAC (v3) / SHA-256 (v2 read-compat)
    static let headerLen = 9 + digestLen              // magic(4) + flags(1) + plaintextLen(4) + digest(32)
    static let flagLZ4: UInt8 = 0x01

    // MARK: BlockCrypto

    public func encryptBlock(_ plaintext: Data, itemID: InodeID, blockIndex: Int) async throws -> (ciphertext: Data, hash: BlockHash) {
        guard blockIndex >= 0 else { throw EngineErrorBridge.invalid("negative block index") }
        guard plaintext.count <= UInt32.max else { throw EngineErrorBridge.invalid("block too large") }

        // 1. LZ4 (best-effort). Empty / incompressible -> store raw.
        var flags: UInt8 = 0
        let payload: Data
        if let comp = LZ4.compress(plaintext) {
            payload = comp
            flags |= Self.flagLZ4
        } else {
            payload = plaintext
        }

        // 2. Content digest — KEYED MAC of the plaintext (v3). Binds the per-block
        //    KEY to the content (distinct content in the same slot ⇒ distinct key ⇒
        //    no (key,nonce) reuse) and travels in the header so decrypt can re-derive
        //    the key from ciphertext alone. Authenticated via the AAD below. Unlike
        //    v2's bare SHA-256, the MAC is opaque to a bucket-only adversary.
        let contentDigest = keys.contentDigest(plaintext)

        // 3. Header (magic|flags|plaintextLen|contentDigest) — also bound into the GCM AAD.
        var header = Data(Self.magic)
        header.append(flags)
        header.append(bigEndian: UInt32(plaintext.count))
        header.append(contentDigest)

        // 4. AES-256-GCM seal with the content-bound key + deterministic nonce + AAD.
        let key = keys.deriveBlockKey(itemID: itemID, blockIndex: blockIndex, contentDigest: contentDigest)
        let nonce = deterministicNonce(itemID: itemID, blockIndex: blockIndex)
        let aad = header + blockIndexAAD(blockIndex)
        let sealed: AES.GCM.SealedBox
        do {
            sealed = try AES.GCM.seal(payload, using: key, nonce: nonce, authenticating: aad)
        } catch {
            throw EngineErrorBridge.corrupt("GCM seal failed: \(error)")
        }
        guard let combined = sealed.combined else {
            throw EngineErrorBridge.corrupt("GCM produced no combined box")
        }

        // 5. Serialize + content-address.
        let wire = header + combined
        let hash = BlockHash(hex: Data(SHA256.hash(data: wire)).hexEncodedString)
        return (wire, hash)
    }

    public func decryptBlock(_ ciphertext: Data, itemID: InodeID, blockIndex: Int) async throws -> Data {
        guard blockIndex >= 0 else { throw EngineErrorBridge.invalid("negative block index") }
        guard ciphertext.count >= Self.headerLen + 12 + 16 else {
            throw EngineErrorBridge.corrupt("block shorter than header+nonce+tag")
        }

        // 1. Parse + validate header. Accept v3 (keyed MAC digest) and v2 (legacy
        //    bare-SHA-256 digest) — both share the layout; only the digest's
        //    construction (and the defense-in-depth recompute below) differs.
        let header = ciphertext.prefix(Self.headerLen)
        let hb = Array(header)
        let magic = Array(hb.prefix(4))
        let isV3: Bool
        if magic == Self.magic { isV3 = true }
        else if magic == Self.magicV2 { isV3 = false }
        else { throw EngineErrorBridge.corrupt("bad block magic") }
        let flags = hb[4]
        let plaintextLen = Int(UInt32(bigEndian4: Array(hb[5..<9])))
        // The plaintext content digest carried in the header; the per-block KEY is
        // derived from it, so we re-derive the same key from the stored block.
        let contentDigest = Data(hb[9..<(9 + Self.digestLen)])

        // 2. Re-derive the content-bound key + nonce + AAD, then open (verifies the
        //    tag — including that the header's digest is authentic, since the whole
        //    header is AAD; a forged digest changes the key AND fails the tag).
        let key = keys.deriveBlockKey(itemID: itemID, blockIndex: blockIndex, contentDigest: contentDigest)
        let aad = Data(header) + blockIndexAAD(blockIndex)
        let combined = ciphertext.suffix(from: ciphertext.startIndex + Self.headerLen)
        let payload: Data
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            payload = try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            // CryptoKitError.authenticationFailure (tamper) lands here.
            throw EngineErrorBridge.corrupt("GCM authentication failed (tampered or wrong key)")
        }

        // 3. De-LZ4 if flagged, then check the recovered length.
        let plain: Data
        if flags & Self.flagLZ4 != 0 {
            plain = try LZ4.decompress(payload, plaintextLength: plaintextLen)
        } else {
            plain = payload
        }
        guard plain.count == plaintextLen else {
            throw EngineErrorBridge.corrupt("recovered length \(plain.count) != header \(plaintextLen)")
        }
        // 4. Defense-in-depth: the recovered plaintext must match the digest the
        //    key was derived from (closes the loop on the content↔key binding). v3
        //    recomputes the KEYED MAC; v2 (read-compat) recomputes the bare SHA-256.
        let recomputed = isV3 ? keys.contentDigest(plain) : Data(SHA256.hash(data: plain))
        guard recomputed == contentDigest else {
            throw EngineErrorBridge.corrupt("recovered plaintext digest != header content digest")
        }
        return plain
    }

    // MARK: Helpers

    /// 12-byte GCM nonce derived from (itemID, blockIndex) via HKDF-SHA256 — see
    /// the "deterministic nonce" note above for why this is safe and required.
    private func deterministicNonce(itemID: InodeID, blockIndex: Int) -> AES.GCM.Nonce {
        let info = Data("cloudfs/block-nonce/v1/\(itemID.rawValue)/\(blockIndex)".utf8)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: keys.master,
            salt: Data("cloudfs-filespace-block-nonce".utf8),
            info: info,
            outputByteCount: 12
        )
        let bytes = derived.withUnsafeBytes { Data($0) }
        // 12 bytes is always a valid GCM nonce length.
        return try! AES.GCM.Nonce(data: bytes)
    }

    /// The block index authenticated as part of the AAD (8-byte big-endian).
    private func blockIndexAAD(_ blockIndex: Int) -> Data {
        var d = Data()
        d.append(bigEndian: UInt64(blockIndex))
        return d
    }
}

// MARK: - Big-endian Data helpers

extension Data {
    mutating func append(bigEndian value: UInt32) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }
    mutating func append(bigEndian value: UInt64) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }
}

extension UInt32 {
    init(bigEndian4 bytes: [UInt8]) {
        precondition(bytes.count == 4)
        self = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
    }
}
