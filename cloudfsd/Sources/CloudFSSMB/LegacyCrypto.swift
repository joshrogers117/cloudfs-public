// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — the legacy primitives NTLM needs that the system crypto libraries
// don't ship: MD4 (RFC 1320) and RC4 (RFC "Arcfour"). Both are cryptographically
// broken and are used ONLY where the NTLMv2 handshake mandates them; nothing else
// in cloudfs touches them. Content confidentiality rests on AES-256-GCM elsewhere.
//
// Kept dependency-free and self-contained so they can be unit-tested against the
// published RFC test vectors.

import Foundation

// MARK: - MD4 (RFC 1320)

public enum MD4 {
    /// 16-byte MD4 digest of `message`.
    public static func hash(_ message: Data) -> Data {
        var a: UInt32 = 0x6745_2301
        var b: UInt32 = 0xEFCD_AB89
        var c: UInt32 = 0x98BA_DCFE
        var d: UInt32 = 0x1032_5476

        // Padding: 0x80, then zeros to 56 mod 64, then 64-bit LE bit length.
        var msg = [UInt8](message)
        let bitLen = UInt64(msg.count) &* 8
        msg.append(0x80)
        while msg.count % 64 != 56 { msg.append(0) }
        for i in 0..<8 { msg.append(UInt8((bitLen >> (8 * UInt64(i))) & 0xFF)) }

        func rotl(_ x: UInt32, _ s: UInt32) -> UInt32 { (x << s) | (x >> (32 - s)) }
        let F: (UInt32, UInt32, UInt32) -> UInt32 = { x, y, z in (x & y) | (~x & z) }
        let G: (UInt32, UInt32, UInt32) -> UInt32 = { x, y, z in (x & y) | (x & z) | (y & z) }
        let H: (UInt32, UInt32, UInt32) -> UInt32 = { x, y, z in x ^ y ^ z }

        var block = [UInt32](repeating: 0, count: 16)
        var chunk = 0
        while chunk < msg.count {
            for j in 0..<16 {
                let o = chunk + j * 4
                block[j] = UInt32(msg[o]) | (UInt32(msg[o+1]) << 8)
                       | (UInt32(msg[o+2]) << 16) | (UInt32(msg[o+3]) << 24)
            }
            var (aa, bb, cc, dd) = (a, b, c, d)

            // Round 1: [abcd k s], s in 3,7,11,19
            let r1s: [UInt32] = [3, 7, 11, 19]
            for i in 0..<16 {
                let k = i
                let s = r1s[i % 4]
                switch i % 4 {
                case 0: aa = rotl(aa &+ F(bb, cc, dd) &+ block[k], s)
                case 1: dd = rotl(dd &+ F(aa, bb, cc) &+ block[k], s)
                case 2: cc = rotl(cc &+ F(dd, aa, bb) &+ block[k], s)
                default: bb = rotl(bb &+ F(cc, dd, aa) &+ block[k], s)
                }
            }
            // Round 2: k = (i%4)*4 + i/4, add 0x5A827999, s in 3,5,9,13
            let r2s: [UInt32] = [3, 5, 9, 13]
            let r2k = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
            for i in 0..<16 {
                let k = r2k[i]
                let s = r2s[i % 4]
                switch i % 4 {
                case 0: aa = rotl(aa &+ G(bb, cc, dd) &+ block[k] &+ 0x5A82_7999, s)
                case 1: dd = rotl(dd &+ G(aa, bb, cc) &+ block[k] &+ 0x5A82_7999, s)
                case 2: cc = rotl(cc &+ G(dd, aa, bb) &+ block[k] &+ 0x5A82_7999, s)
                default: bb = rotl(bb &+ G(cc, dd, aa) &+ block[k] &+ 0x5A82_7999, s)
                }
            }
            // Round 3: k bit-reversed order, add 0x6ED9EBA1, s in 3,9,11,15
            let r3s: [UInt32] = [3, 9, 11, 15]
            let r3k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for i in 0..<16 {
                let k = r3k[i]
                let s = r3s[i % 4]
                switch i % 4 {
                case 0: aa = rotl(aa &+ H(bb, cc, dd) &+ block[k] &+ 0x6ED9_EBA1, s)
                case 1: dd = rotl(dd &+ H(aa, bb, cc) &+ block[k] &+ 0x6ED9_EBA1, s)
                case 2: cc = rotl(cc &+ H(dd, aa, bb) &+ block[k] &+ 0x6ED9_EBA1, s)
                default: bb = rotl(bb &+ H(cc, dd, aa) &+ block[k] &+ 0x6ED9_EBA1, s)
                }
            }

            a = a &+ aa; b = b &+ bb; c = c &+ cc; d = d &+ dd
            chunk += 64
        }

        var out = Data(capacity: 16)
        for v in [a, b, c, d] {
            out.append(UInt8(v & 0xFF)); out.append(UInt8((v >> 8) & 0xFF))
            out.append(UInt8((v >> 16) & 0xFF)); out.append(UInt8((v >> 24) & 0xFF))
        }
        return out
    }
}

// MARK: - RC4 (Arcfour)

/// RC4 stream cipher. Used only for the NTLMv2 KEY_EXCH step (RC4-decrypt the
/// EncryptedRandomSessionKey with the session base key). Symmetric: the same call
/// encrypts and decrypts.
public struct RC4 {
    private var s: [UInt8]
    private var i = 0
    private var j = 0

    public init(key: Data) {
        s = Array(0...255)
        var jj = 0
        let k = [UInt8](key)
        guard !k.isEmpty else { return }
        for ii in 0..<256 {
            jj = (jj + Int(s[ii]) + Int(k[ii % k.count])) & 0xFF
            s.swapAt(ii, jj)
        }
    }

    public mutating func process(_ input: Data) -> Data {
        var out = Data(capacity: input.count)
        for byte in input {
            i = (i + 1) & 0xFF
            j = (j + Int(s[i])) & 0xFF
            s.swapAt(i, j)
            let k = s[(Int(s[i]) + Int(s[j])) & 0xFF]
            out.append(byte ^ k)
        }
        return out
    }

    /// One-shot convenience.
    public static func apply(key: Data, data: Data) -> Data {
        var c = RC4(key: key)
        return c.process(data)
    }
}
