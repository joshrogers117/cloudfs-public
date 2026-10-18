// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// Only ordinary standalone disk WRITEs can share one durability barrier.
/// Identity, flags, extent and payload bounds are validated for every member.
struct SMBWriteRequest {
    let header: SMB2Header
    let fileId: SMBFileId
    let offset: Int
    let flags: UInt32
    let payload: Data
    init?(_ message: Data) {
        var r = ByteReader(message)
        guard let header = try? SMB2Header.decode(&r), header.command == .write,
              header.nextCommand == 0, header.flags.isEmpty,
              (try? r.u16()) == 49, let start = try? r.u16(), let length = try? r.u32(),
              length > 0, length <= SMBLimits.maximumWriteBytes,
              let offset = try? r.u64(), offset <= UInt64(Int.max - Int(length)),
              let persistent = try? r.u64(), let volatile = try? r.u64(),
              (try? r.u32()) == 0 else { return nil }
        _ = try? r.u32()
        guard (try? r.u16()) == 0, (try? r.u16()) == 0,
              let flags = try? r.u32(), flags & ~UInt32(1) == 0,
              Int(start) >= SMB2Header.size + 48, Int(start) <= message.count - Int(length) else { return nil }
        let fileId = SMBFileId(persistent: persistent, volatile: volatile)
        guard !fileId.isRelated else { return nil }
        self.header = header; self.fileId = fileId; self.offset = Int(offset); self.flags = flags
        payload = message.subdata(in: Int(start)..<(Int(start) + Int(length)))
    }
    func follows(_ first: SMBWriteRequest, bytes: Int) -> Bool {
        header.sessionId == first.header.sessionId && header.treeId == first.header.treeId &&
        fileId == first.fileId && flags == first.flags && offset == first.offset + bytes &&
        payload.count <= SMBLimits.maximumWriteBytes - bytes
    }
    func body(with combined: Data) -> Data {
        var w = ByteWriter()
        w.u16(49); w.u16(UInt16(SMB2Header.size + 48)); w.u32(UInt32(combined.count)); w.u64(UInt64(offset))
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        w.u32(0); w.u32(0); w.u16(0); w.u16(0); w.u32(flags); w.bytes(combined)
        return w.data
    }
}

/// Single-thread-owned, bounded partial frame. No wait for a new request; an
/// already-started frame gets at most 2 ms before the prior batch is processed.
/// Partial bytes survive that timeout and resume in the ordinary blocking read.
final class SMBFrameReader {
    private let fd: Int32
    private var buffer = Data()
    private var length: Int?
    private var closed = false
    init(fd: Int32) { self.fd = fd }
    func next(blocking: Bool) -> Data? {
        guard !closed else { return nil }
        let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000
        while true {
            if length == nil, buffer.count == 4 {
                guard let size = DirectTCP.length(prefix: buffer), size >= SMB2Header.size,
                      size <= SMBLimits.maximumFrameBytes else { closed = true; return nil }
                length = size
            }
            let needed = (length.map { $0 + 4 } ?? 4) - buffer.count
            if needed == 0 {
                let message = buffer.subdata(in: 4..<buffer.count)
                buffer = Data(); length = nil; return message
            }
            var bytes = [UInt8](repeating: 0, count: min(needed, 64 << 10))
            let count = recv(fd, &bytes, bytes.count, blocking ? 0 : MSG_DONTWAIT)
            if count > 0 { buffer.append(contentsOf: bytes.prefix(count)); continue }
            if count == 0 { closed = true; return nil }
            if errno == EINTR { continue }
            if !blocking && (errno == EAGAIN || errno == EWOULDBLOCK) {
                guard !buffer.isEmpty, DispatchTime.now().uptimeNanoseconds < deadline else { return nil }
                var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
                if poll(&descriptor, 1, 1) < 0 && errno != EINTR { closed = true; return nil }
                continue
            }
            closed = true; return nil
        }
    }
}
