// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSControlPlane — newline-delimited JSON-RPC framing (CONTROL-API.md §1).
//
// One JSON object per line, `\n`-terminated, UTF-8. The decoder buffers bytes
// across reads so it tolerates BOTH partial frames (one frame split across many
// `recv`s) AND coalesced frames (many frames in one `recv`). The encoder appends
// the trailing newline. Pure value types — no I/O — so they unit-test directly.

import Foundation
import CloudFSCore

/// Incremental newline framer. Feed it arbitrary byte chunks; it yields whole
/// `\n`-delimited frames (the newline stripped) as they complete. Not Sendable on
/// purpose: each connection owns its own decoder on one read loop.
struct FrameDecoder {
    private var buffer = [UInt8]()
    /// Guard against an unbounded line from a hostile/buggy peer (4 MiB).
    static let maxFrameBytes = 4 << 20

    /// Append a chunk and return every complete frame it unlocked, in order.
    /// Each returned `Data` is one JSON object (without the terminating newline).
    /// Throws if a single un-terminated line exceeds `maxFrameBytes`.
    mutating func push(_ chunk: [UInt8]) throws -> [Data] {
        buffer.append(contentsOf: chunk)
        var frames = [Data]()
        var start = 0
        var i = 0
        while i < buffer.count {
            if buffer[i] == 0x0A {  // '\n'
                let slice = buffer[start..<i]
                // Tolerate a trailing '\r' (CRLF) and drop empty keep-alive lines.
                var end = slice.endIndex
                if end > slice.startIndex, buffer[end - 1] == 0x0D { end -= 1 }
                if end > slice.startIndex {
                    frames.append(Data(buffer[slice.startIndex..<end]))
                }
                start = i + 1
            }
            i += 1
        }
        if start > 0 {
            buffer.removeFirst(start)
        }
        if buffer.count > FrameDecoder.maxFrameBytes {
            throw EngineError(.invalidParams, "control frame exceeds \(FrameDecoder.maxFrameBytes) bytes")
        }
        return frames
    }
}

/// Encode one JSON-RPC value to a newline-terminated wire frame.
enum FrameEncoder {
    static let encoder: JSONEncoder = {
        let e = JSONEncoder()
        // Deterministic key order keeps the conformance harness diffs stable.
        e.outputFormatting = [.sortedKeys]
        return e
    }()

    static func encode<T: Encodable>(_ value: T) throws -> Data {
        var data = try encoder.encode(value)
        data.append(0x0A)  // '\n'
        return data
    }
}
