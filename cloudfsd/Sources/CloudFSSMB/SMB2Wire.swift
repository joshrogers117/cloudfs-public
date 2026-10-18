// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — SMB2 wire primitives: Direct-TCP framing, the 64-byte packet
// header, and little-endian scalar/byte cursors.
//
// SMB2 is LITTLE-ENDIAN (unlike NFS/XDR, which is big-endian) and structures are
// NOT self-padding: fields sit at fixed byte offsets defined by [MS-SMB2], so the
// reader/writer here are plain offset cursors with no alignment magic. Everything
// the server needs to frame, route, and reply lives in this file; per-command
// request/response bodies are decoded/encoded by the handlers.

import Foundation

// MARK: - Direct TCP transport framing ([MS-SMB2] §2.1)

/// SMB2 over Direct TCP (port-445 style, which is what the loopback mount uses):
/// each message is prefixed with a 4-byte length header. The top byte is always
/// zero (reserved); the low 24 bits are the SMB2 message length in bytes.
public enum DirectTCP {
    public static let maxMessage = 16 << 20  // generous cap; a hostile length must not OOM us

    /// Encode the 4-byte length prefix for a message of `length` bytes.
    public static func frame(length: Int) -> Data {
        precondition(length >= 0 && length <= 0xFF_FFFF, "SMB2 message too large to frame")
        var out = Data(count: 4)
        out[1] = UInt8((length >> 16) & 0xFF)
        out[2] = UInt8((length >> 8) & 0xFF)
        out[3] = UInt8(length & 0xFF)
        return out
    }

    /// Decode a 4-byte length prefix. Returns nil if the reserved top byte is set
    /// or the length exceeds the sanity cap.
    public static func length(prefix: Data) -> Int? {
        guard prefix.count >= 4 else { return nil }
        let b = [UInt8](prefix.prefix(4))
        guard b[0] == 0 else { return nil }
        let len = (Int(b[1]) << 16) | (Int(b[2]) << 8) | Int(b[3])
        return len <= maxMessage ? len : nil
    }
}

// MARK: - Little-endian byte writer

/// Append-only little-endian byte buffer. SMB structures are written by absolute
/// layout, so this also supports back-patching a previously reserved slot (used
/// for the header's NextCommand offset and for buffer-offset/length pairs).
public struct ByteWriter: Sendable {
    public private(set) var data: Data
    public init(_ data: Data = Data()) { self.data = data }

    public var count: Int { data.count }

    public mutating func u8(_ v: UInt8) { data.append(v) }
    public mutating func u16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
    public mutating func u32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }
    public mutating func u64(_ v: UInt64) { withUnsafeBytes(of: v.littleEndian) { data.append(contentsOf: $0) } }

    public mutating func bytes(_ b: Data) { data.append(b) }
    public mutating func bytes(_ b: [UInt8]) { data.append(contentsOf: b) }

    /// n zero bytes (reserved fields / alignment padding).
    public mutating func zeros(_ n: Int) { if n > 0 { data.append(contentsOf: [UInt8](repeating: 0, count: n)) } }

    /// UTF-16LE encoding of `s` (no BOM, no terminator) — SMB's string form.
    public mutating func utf16(_ s: String) { data.append(SMBString.utf16le(s)) }

    /// Reserve a 2/4-byte little-endian slot and return its absolute offset so a
    /// later value (e.g. a computed offset) can be patched in via `patch*`.
    public mutating func reserveU16() -> Int { let at = data.count; u16(0); return at }
    public mutating func reserveU32() -> Int { let at = data.count; u32(0); return at }

    public mutating func patchU16(at offset: Int, _ v: UInt16) {
        let le = v.littleEndian
        withUnsafeBytes(of: le) { raw in
            for i in 0..<2 { data[data.startIndex + offset + i] = raw[i] }
        }
    }
    public mutating func patchU32(at offset: Int, _ v: UInt32) {
        let le = v.littleEndian
        withUnsafeBytes(of: le) { raw in
            for i in 0..<4 { data[data.startIndex + offset + i] = raw[i] }
        }
    }
}

// MARK: - Little-endian byte reader

public enum WireError: Error, Equatable {
    case underflow
    case malformed(String)
}

/// Forward-only little-endian reader with random-access helpers (SMB bodies point
/// at buffers by absolute offset from the packet header, so handlers need to seek).
public struct ByteReader: Sendable {
    public let data: Data
    public private(set) var offset: Int   // absolute index into `data`
    private let base: Int                 // data.startIndex (Data may be a slice)

    public init(_ data: Data) {
        self.data = data
        self.base = data.startIndex
        self.offset = data.startIndex
    }

    public var remaining: Int { data.endIndex - offset }
    public var consumed: Int { offset - base }

    /// Seek to an absolute position measured from the start of `data` (i.e. the
    /// SMB2 header, which is what [MS-SMB2] offsets are relative to).
    public mutating func seek(to absolute: Int) throws {
        let target = base + absolute
        guard target >= base, target <= data.endIndex else { throw WireError.underflow }
        offset = target
    }

    public mutating func u8() throws -> UInt8 {
        guard remaining >= 1 else { throw WireError.underflow }
        defer { offset += 1 }
        return data[offset]
    }
    public mutating func u16() throws -> UInt16 {
        guard remaining >= 2 else { throw WireError.underflow }
        let v = data[offset..<offset+2].withUnsafeBytes { $0.loadUnaligned(as: UInt16.self) }
        offset += 2
        return UInt16(littleEndian: v)
    }
    public mutating func u32() throws -> UInt32 {
        guard remaining >= 4 else { throw WireError.underflow }
        let v = data[offset..<offset+4].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        offset += 4
        return UInt32(littleEndian: v)
    }
    public mutating func u64() throws -> UInt64 {
        guard remaining >= 8 else { throw WireError.underflow }
        let v = data[offset..<offset+8].withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }
        offset += 8
        return UInt64(littleEndian: v)
    }

    public mutating func take(_ n: Int) throws -> Data {
        guard n >= 0, remaining >= n else { throw WireError.underflow }
        let out = data.subdata(in: offset..<(offset + n))
        offset += n
        return out
    }

    /// Read `n` bytes at absolute `offset` without moving the cursor.
    public func peek(at absolute: Int, _ n: Int) throws -> Data {
        let start = base + absolute
        guard n >= 0, start >= base, start + n <= data.endIndex else { throw WireError.underflow }
        return data.subdata(in: start..<(start + n))
    }
}

// MARK: - SMB string helpers

public enum SMBString {
    /// UTF-16LE bytes for `s` (SMB's on-wire string form), NFC-normalized so names
    /// match the backend's canonical form regardless of how macOS composed them.
    public static func utf16le(_ s: String) -> Data {
        var out = Data()
        for u in s.precomposedStringWithCanonicalMapping.utf16 {
            withUnsafeBytes(of: u.littleEndian) { out.append(contentsOf: $0) }
        }
        return out
    }

    /// Decode UTF-16LE `bytes` to a String, NFC-normalized. Odd-length input drops
    /// the trailing byte rather than throwing (defensive against malformed clients).
    public static func decodeUTF16le(_ bytes: Data) -> String {
        var units: [UInt16] = []
        units.reserveCapacity(bytes.count / 2)
        var it = bytes.makeIterator()
        while let lo = it.next(), let hi = it.next() {
            units.append(UInt16(lo) | (UInt16(hi) << 8))
        }
        return String(decoding: units, as: UTF16.self).precomposedStringWithCanonicalMapping
    }
}
