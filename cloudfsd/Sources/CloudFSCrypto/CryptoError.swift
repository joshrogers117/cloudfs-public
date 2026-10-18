// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCrypto — error bridging into the frozen CloudFSCore taxonomy.
//
// The crypto module surfaces two failure classes through `EngineError` (the only
// error type the engine propagates):
//   - `.invalidParams` — caller-supplied bad input (wrong key length, malformed
//     block header) — maps to JSON-RPC -32602 / CLI exit 2.
//   - `.internal`      — integrity / authentication failure (GCM tag mismatch,
//     truncated ciphertext, LZ4 corruption). These are NOT a wire-param error;
//     they mean a cached/fetched block is corrupt or tampered, which the read
//     path treats as "re-fetch from R2" (DESIGN.md §3.5 self-healing).
//
// We keep a dedicated `CryptoFailure` reason in `EngineError.data` so callers can
// distinguish a tamper/auth failure from other internal errors when deciding to
// re-fetch.

import Foundation
import CloudFSCore

enum EngineErrorBridge {
    /// Bad caller input (key/header). JSON-RPC -32602 / exit 2.
    static func invalid(_ message: String) -> EngineError {
        EngineError(.invalidParams, "crypto: \(message)")
    }

    /// Integrity / authentication failure — a corrupt or tampered block. Tagged so
    /// the read path can recognize it and re-fetch (self-healing). -32603 / exit 1.
    static func corrupt(_ message: String) -> EngineError {
        EngineError(.internal, "crypto: \(message)", data: ["cryptoFailure": .string("integrity")])
    }
}
