// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCrypto — spike-compat AES-256-CTR backend. (DESIGN.md §5 "Today")
//
// Wire/format-compatible with fuse-spike/obj-encrypt.mjs + obj-uploader.mjs so
// cloudfsd v1 interoperates with already-uploaded spike objects:
//   - AES-256-CTR, 32-byte master key used VERBATIM (no HKDF — matches the spike).
//   - The whole file is one CTR keystream from an all-zero 16-byte IV (counter 0).
//     Block `i` therefore starts at CTR counter `i * (blockSize/16)` — for the
//     default 1 MiB block that is exactly `i * 65536`, the value the spike bakes
//     in ("block i's CTR counter = i * 65536"). We compute it from blockSize so
//     256/512 KiB filespaces stay correct.
//   - Ciphertext is the SAME SIZE as plaintext (no header, no tag, no LZ4) — this
//     is what gives the spike clean random access. CTR encrypt == decrypt.
//
// CommonCrypto (in-libSystem, no third-party dep) provides CTR; CryptoKit has no
// CTR mode (DESIGN.md §0a Swift delta). `kCCModeOptionCTR_BE` makes CommonCrypto
// increment the full 128-bit counter big-endian, matching OpenSSL/Node's
// `aes-256-ctr` (verified against a Node reference vector in the tests).
//
// NOTE: CTR provides confidentiality but NOT authentication — there is no tag to
// verify, so `decryptBlock` cannot detect tampering. That is the spike's known
// limitation; production filespaces use `.aes256gcm`. This backend exists only for
// interop with pre-existing spike-era objects.
//
// READ-ONLY (cloudfsd audit): the CTR IV derives from `blockIndex` alone and the
// master key is used verbatim, so block `i` of EVERY file shares one (key, counter)
// keystream — XOR of any two files at the same index recovers plaintext. That made
// `--cipher ctr` effectively-unencrypted for NEW writes. `encryptBlock` therefore
// now REFUSES (throws), so this backend can only DECRYPT pre-existing spike objects;
// nothing new is ever written under the reused keystream.

import Foundation
import CommonCrypto
import CloudFSCore

public struct AESCTRBlockCrypto: BlockCrypto {
    public let mode: CipherMode = .aes256ctr

    private let masterKey: Data   // 32 bytes, used verbatim
    private let blockSize: Int

    public init(key: FilespaceKey, blockSize: Int = kDefaultBlockSize) throws {
        try self.init(masterKeyBytes: key.masterRawBytes, blockSize: blockSize)
    }

    public init(masterKeyBytes: Data, blockSize: Int = kDefaultBlockSize) throws {
        guard masterKeyBytes.count == 32 else {
            throw EngineErrorBridge.invalid("AES-256 key must be 32 bytes, got \(masterKeyBytes.count)")
        }
        guard blockSize > 0, blockSize % 16 == 0 else {
            throw EngineErrorBridge.invalid("block size must be a positive multiple of 16")
        }
        self.masterKey = masterKeyBytes
        self.blockSize = blockSize
    }

    public func encryptBlock(_ plaintext: Data, itemID: InodeID, blockIndex: Int) async throws -> (ciphertext: Data, hash: BlockHash) {
        // READ-ONLY backend: the CTR keystream is reused across every file (the IV
        // ignores itemID), so encrypting NEW content here would ship effectively
        // unencrypted data. Refuse — production writes must use `.aes256gcm`. The
        // engine surfaces this as a write error rather than silently corrupting the
        // filespace's confidentiality.
        throw EngineErrorBridge.invalid(
            "AES-256-CTR is read-only (spike-interop decrypt only): its keystream is reused across files; encrypt with --cipher gcm")
    }

    public func decryptBlock(_ ciphertext: Data, itemID: InodeID, blockIndex: Int) async throws -> Data {
        guard blockIndex >= 0 else { throw EngineErrorBridge.invalid("negative block index") }
        // CTR is symmetric: the same keystream XOR recovers the plaintext.
        return try crypt(ciphertext, blockIndex: blockIndex)
    }

    // MARK: CTR core

    /// Apply the AES-256-CTR keystream for `blockIndex`, starting the 128-bit
    /// big-endian counter at `blockIndex * (blockSize/16)` to match the spike's
    /// whole-file CTR stream sliced at block boundaries.
    private func crypt(_ input: Data, blockIndex: Int) throws -> Data {
        let iv = counterIV(forBlock: blockIndex)
        var cryptor: CCCryptorRef?
        let createStatus: CCCryptorStatus = masterKey.withUnsafeBytes { kp in
            iv.withUnsafeBytes { ip in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt), CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES), CCPadding(ccNoPadding),
                    ip.baseAddress, kp.baseAddress, masterKey.count,
                    nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
            }
        }
        guard createStatus == kCCSuccess, let cryptor else {
            throw EngineErrorBridge.corrupt("CCCryptorCreateWithMode failed (\(createStatus))")
        }
        defer { CCCryptorRelease(cryptor) }

        if input.isEmpty { return Data() }
        var out = Data(count: input.count + kCCBlockSizeAES128)
        var moved = 0
        let status: CCCryptorStatus = out.withUnsafeMutableBytes { op in
            input.withUnsafeBytes { inp in
                CCCryptorUpdate(cryptor, inp.baseAddress, input.count,
                                op.baseAddress, op.count, &moved)
            }
        }
        guard status == kCCSuccess else {
            throw EngineErrorBridge.corrupt("CCCryptorUpdate failed (\(status))")
        }
        out.removeSubrange(moved..<out.count)
        return out
    }

    /// 16-byte big-endian counter IV for `blockIndex`: counter = blockIndex *
    /// (blockSize / 16). For 1 MiB blocks this is `blockIndex * 65536`.
    private func counterIV(forBlock blockIndex: Int) -> Data {
        let counter = UInt64(blockIndex) * UInt64(blockSize / 16)
        var iv = Data(repeating: 0, count: 16)
        // Place the 64-bit counter big-endian in the low 8 bytes (bytes 8..15);
        // the high 8 bytes stay zero, matching an IV of 0 advanced by `counter`.
        withUnsafeBytes(of: counter.bigEndian) { src in
            for i in 0..<8 { iv[8 + i] = src[i] }
        }
        return iv
    }
}
