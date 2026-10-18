// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCrypto — LZ4 raw-block compression. (DESIGN.md §5)
//
// The production pipeline's first stage: LZ4 compress -> AES-256-GCM -> SHA-256.
// We use Apple's `Compression` framework (`COMPRESSION_LZ4`) raw-buffer codec —
// no third-party dependency (the Swift delta to DESIGN.md §0a).
//
// `COMPRESSION_LZ4` is Apple's *frame* format (a sequence of LZ4 blocks with a
// trailing 0x00000000 end marker), self-terminating on decode. We pair it with an
// explicit plaintext-length header in the GCM block so decompression has a tight
// output bound (and so a zero-length / incompressible block round-trips exactly).
//
// LZ4 is best-effort: if a block does not shrink (already-compressed media — the
// common case for ProRes/H.264), `compress` returns `nil` and the caller stores
// the block uncompressed, flagged in the GCM header. This keeps incompressible
// media from paying a copy + expansion tax.

import Foundation
import Compression

enum LZ4 {
    /// Compress `src` as an LZ4 frame. Returns `nil` if the input is empty or the
    /// result would not be smaller than the input (store-uncompressed signal).
    static func compress(_ src: Data) -> Data? {
        guard !src.isEmpty else { return nil }
        // Worst case LZ4 expands slightly; size the scratch generously.
        let cap = src.count + (src.count / 255) + 64
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: cap)
        defer { dst.deallocate() }
        let n = src.withUnsafeBytes { sp -> Int in
            guard let base = sp.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return compression_encode_buffer(dst, cap, base, src.count, nil, COMPRESSION_LZ4)
        }
        // n == 0 → the frame did not fit in `cap` (incompressible). Treat as "do
        // not compress" so the caller stores raw.
        guard n > 0, n < src.count else { return nil }
        return Data(bytes: dst, count: n)
    }

    /// Decompress an LZ4 frame produced by `compress`, given the exact plaintext
    /// length recorded in the block header. Throws on a short/garbled frame.
    static func decompress(_ src: Data, plaintextLength: Int) throws -> Data {
        guard plaintextLength > 0 else { return Data() }
        let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: plaintextLength)
        defer { dst.deallocate() }
        let n = src.withUnsafeBytes { sp -> Int in
            guard let base = sp.bindMemory(to: UInt8.self).baseAddress else { return 0 }
            return compression_decode_buffer(dst, plaintextLength, base, src.count, nil, COMPRESSION_LZ4)
        }
        guard n == plaintextLength else {
            throw EngineErrorBridge.corrupt("LZ4 decompress produced \(n) bytes, expected \(plaintextLength)")
        }
        return Data(bytes: dst, count: n)
    }
}
