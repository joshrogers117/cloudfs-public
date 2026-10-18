// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCrypto — the per-block encrypt/decrypt seam. (DESIGN.md §5)
//
// Owner (next round): CRYPTO. Implements the zero-knowledge block pipeline,
// aligned to fuse-spike/obj-encrypt.mjs (AES-256-CTR, per-block counter, client
// key never uploaded) and hardened to production AES-256-GCM + LZ4 + per-block
// nonce + SHA-256(ciphertext) content addressing. Key handling: HKDF from the
// filespace master key loaded out-of-band (Keychain / keyfile).
//
// THIS FILE DEFINES THE PROTOCOL + A STUB. The real pipeline is the next round.

import Foundation
import CloudFSCore

/// Cipher mode for a filespace's blocks.
public enum CipherMode: String, Sendable, Codable {
    /// Spike-compat: AES-256-CTR, counter = blockIndex * (blockSize/16). Same
    /// size in/out; interoperates with already-uploaded spike objects.
    case aes256ctr
    /// Production: LZ4 -> AES-256-GCM (12-byte nonce + tag) -> SHA-256(ciphertext).
    case aes256gcm
}

/// One block's crypto seam. Encrypt-on-write / decrypt-on-read; the content
/// address is SHA-256 of the ciphertext.
public protocol BlockCrypto: Sendable {
    var mode: CipherMode { get }
    /// Encrypt one plaintext block; returns ciphertext + its content hash.
    func encryptBlock(_ plaintext: Data, itemID: InodeID, blockIndex: Int) async throws -> (ciphertext: Data, hash: BlockHash)
    /// Decrypt one ciphertext block (verifying the GCM tag in production mode).
    func decryptBlock(_ ciphertext: Data, itemID: InodeID, blockIndex: Int) async throws -> Data
}

/// Foundation stub: compiles green, throws `.unimplemented`.
/// Retained so callers that have not yet wired a key still link; the real
/// backends are `AESGCMBlockCrypto` (production) and `AESCTRBlockCrypto` (spike).
public struct StubBlockCrypto: BlockCrypto {
    public let mode: CipherMode
    public init(mode: CipherMode = .aes256gcm) { self.mode = mode }
    public func encryptBlock(_ plaintext: Data, itemID: InodeID, blockIndex: Int) async throws -> (ciphertext: Data, hash: BlockHash) {
        throw EngineError.unimplemented()
    }
    public func decryptBlock(_ ciphertext: Data, itemID: InodeID, blockIndex: Int) async throws -> Data {
        throw EngineError.unimplemented()
    }
}

// MARK: - Factory

/// Build the real `BlockCrypto` backend for a filespace's cipher `mode` from its
/// master key. `.aes256gcm` is the production pipeline (LZ4 + GCM + SHA-256);
/// `.aes256ctr` is spike-compat for interop with already-uploaded objects.
public func makeBlockCrypto(mode: CipherMode, key: FilespaceKey,
                            blockSize: Int = kDefaultBlockSize) throws -> BlockCrypto {
    switch mode {
    case .aes256gcm: return AESGCMBlockCrypto(key: key)
    case .aes256ctr: return try AESCTRBlockCrypto(key: key, blockSize: blockSize)
    }
}
