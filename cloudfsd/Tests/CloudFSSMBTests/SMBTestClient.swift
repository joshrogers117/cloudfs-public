// SPDX-License-Identifier: AGPL-3.0-or-later
// A raw SMB2 test client: speaks Direct-TCP framed SMB2 over a blocking loopback
// socket, exactly what the kernel smbfs client does minus the kernel. Doubles as
// executable protocol documentation. Grows per phase; P1a covers the handshake.

import Foundation
import Darwin
@testable import CloudFSSMB

final class SMBTestClient {
    private var fd: Int32 = -1
    private(set) var sessionId: UInt64 = 0
    private(set) var treeId: UInt32 = 0
    private var messageId: UInt64 = 0

    func connect(port: UInt16) throws {
        fd = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else { throw TestError.connectFailed }
    }

    func close() { if fd >= 0 { Darwin.close(fd); fd = -1 } }

    enum TestError: Error { case connectFailed, shortRead, badResponse, status(UInt32) }

    // MARK: framed request/response

    struct Response { var header: SMB2Header; var body: Data }

    /// Send one SMB2 request (header + body) and read one response.
    @discardableResult
    func request(_ command: SMB2Command, body: Data, creditRequest: UInt16 = 64) throws -> Response {
        let mid = messageId; messageId += 1
        let hdr = SMB2Header(command: command, messageId: mid, creditCharge: 1,
                             creditReqGrant: creditRequest, treeId: treeId, sessionId: sessionId)
        var w = ByteWriter()
        hdr.encode(into: &w)
        w.bytes(body)
        var framed = DirectTCP.frame(length: w.count)
        framed.append(w.data)
        try writeAll(framed)

        guard let prefix = readN(4), let len = DirectTCP.length(prefix: prefix),
              let payload = readN(len) else { throw TestError.shortRead }
        var r = ByteReader(payload)
        let respHdr = try SMB2Header.decode(&r)
        let respBody = payload.subdata(in: SMB2Header.size..<payload.count)
        return Response(header: respHdr, body: respBody)
    }

    func compound(_ commands: [(SMB2Command, Data)],
                  mutateHeader: ((Int, inout SMB2Header) -> Void)? = nil) throws -> [Response] {
        var payload = Data()
        for (index, command) in commands.enumerated() {
            let last = index == commands.count - 1
            let size = SMB2Header.size + command.1.count
            let padded = last ? size : (size + 7) & ~7
            var header = SMB2Header(command: command.0, messageId: messageId,
                                   creditCharge: 1, creditReqGrant: 32,
                                   flags: index == 0 ? [] : [.relatedOps],
                                   nextCommand: last ? 0 : UInt32(padded),
                                   treeId: treeId, sessionId: sessionId)
            mutateHeader?(index, &header)
            messageId += 1
            var part = ByteWriter()
            header.encode(into: &part); part.bytes(command.1)
            part.zeros(padded - size)
            payload.append(part.data)
        }
        var frame = DirectTCP.frame(length: payload.count); frame.append(payload)
        try writeAll(frame)
        guard let prefix = readN(4), let size = DirectTCP.length(prefix: prefix), let response = readN(size) else {
            throw TestError.shortRead
        }
        var results: [Response] = []
        var cursor = 0
        while cursor + SMB2Header.size <= response.count {
            var reader = ByteReader(response.subdata(in: cursor..<response.count))
            let header = try SMB2Header.decode(&reader)
            let end = header.nextCommand == 0 ? response.count : cursor + Int(header.nextCommand)
            results.append(Response(header: header, body: response.subdata(in: cursor + SMB2Header.size..<end)))
            if header.nextCommand == 0 { break }
            cursor = end
        }
        return results
    }

    /// Send a request without reading its response (for interleaving with async
    /// CHANGE_NOTIFY completions). Returns the MessageId used.
    @discardableResult
    func sendOnly(_ command: SMB2Command, body: Data, creditRequest: UInt16 = 64) throws -> UInt64 {
        let mid = messageId; messageId += 1
        let hdr = SMB2Header(command: command, messageId: mid, creditCharge: 1,
                             creditReqGrant: creditRequest, treeId: treeId, sessionId: sessionId)
        var w = ByteWriter(); hdr.encode(into: &w); w.bytes(body)
        var framed = DirectTCP.frame(length: w.count); framed.append(w.data)
        try writeAll(framed)
        return mid
    }

    /// Queue complete independent requests in one socket write. Their responses
    /// retain separate framing and MessageIds even when the server coalesces data.
    func sendPipeline(_ commands: [(SMB2Command, Data)]) throws -> [UInt64] {
        var frames = Data(), ids: [UInt64] = []
        for (command, body) in commands {
            let id = messageId; messageId += 1; ids.append(id)
            let header = SMB2Header(command: command, messageId: id, creditCharge: 1,
                creditReqGrant: 64, treeId: treeId, sessionId: sessionId)
            var packet = ByteWriter(); header.encode(into: &packet); packet.bytes(body)
            frames.append(DirectTCP.frame(length: packet.count)); frames.append(packet.data)
        }
        try writeAll(frames); return ids
    }

    func writeBody(fileId: SMBFileId, offset: UInt64, data: Data, flags: UInt32 = 0) -> Data {
        var body = ByteWriter()
        body.u16(49); body.u16(UInt16(SMB2Header.size + 48)); body.u32(UInt32(data.count)); body.u64(offset)
        body.u64(fileId.persistent); body.u64(fileId.volatile)
        body.u32(0); body.u32(0); body.u16(0); body.u16(0); body.u32(flags); body.bytes(data)
        return body.data
    }

    /// A minimal CREATE body for `sendOnly` (open-existing).
    func createBody(path: String) -> Data {
        let nameBytes = SMBString.utf16le(path)
        var w = ByteWriter()
        w.u16(57); w.u8(0); w.u8(0); w.u32(2); w.u64(0); w.u64(0)
        w.u32(SMBAccess.all); w.u32(0); w.u32(0x07); w.u32(2 /* CREATE */); w.u32(0)
        w.u16(UInt16(nameBytes.isEmpty ? 0 : SMB2Header.size + 56)); w.u16(UInt16(nameBytes.count))
        w.u32(0); w.u32(0); w.bytes(nameBytes)
        return w.data
    }

    // MARK: handshake helpers

    func negotiate() throws -> Response {
        // Minimal NEGOTIATE request ([MS-SMB2] §2.2.3): offer 2.0.2 + 2.1.
        var w = ByteWriter()
        w.u16(36)                 // StructureSize
        w.u16(2)                  // DialectCount
        w.u16(0x0001)             // SecurityMode = SIGNING_ENABLED
        w.u16(0)                  // Reserved
        w.u32(0)                  // Capabilities
        for i in 0..<16 { w.u8(UInt8(i)) }   // ClientGuid
        w.u64(0); w.u16(0); w.u16(0)         // (Client)StartTime / NegotiateContext fields
        w.u16(SMB2Dialect.smb202.rawValue)
        w.u16(SMB2Dialect.smb21.rawValue)
        return try request(.negotiate, body: w.data)
    }

    /// Full two-leg NTLMv2 session setup with the synthetic credential.
    func sessionSetup(user: String, password: String) throws {
        // Leg 1: NTLM NEGOTIATE wrapped in a bare SPNEGO-ish token. The server
        // extracts the raw NTLMSSP blob, so a raw NEGOTIATE is accepted directly.
        let negotiate = ntlmNegotiate()
        let leg1 = try request(.sessionSetup, body: sessionSetupBody(security: negotiate))
        sessionId = leg1.header.sessionId
        guard leg1.header.status == NTStatus.moreProcessingRequired.rawValue else {
            throw TestError.status(leg1.header.status)
        }

        // Extract the server challenge from the CHALLENGE message inside the SPNEGO.
        let challengeSecurity = extractSecurityBuffer(leg1.body)
        guard let ntlmChallenge = SPNEGO.extractNTLM(challengeSecurity) else {
            throw TestError.badResponse
        }
        let serverChallenge = ntlmChallenge.subdata(in: (ntlmChallenge.startIndex + 24)..<(ntlmChallenge.startIndex + 32))

        // Leg 2: AUTHENTICATE.
        let auth = ReferenceNTLMClient.authenticate(
            username: user, password: password, domain: "",
            serverChallenge: serverChallenge,
            clientChallenge: Data([1,2,3,4,5,6,7,8]), timestamp: nowFiletime())
        let leg2 = try request(.sessionSetup, body: sessionSetupBody(security: auth))
        guard leg2.header.status == NTStatus.success.rawValue else {
            throw TestError.status(leg2.header.status)
        }
    }

    func treeConnect(server: String = "127.0.0.1", share: String) throws -> Response {
        let path = "\\\\\(server)\\\(share)"
        let pathBytes = SMBString.utf16le(path)
        var w = ByteWriter()
        w.u16(9)                                        // StructureSize
        w.u16(0)                                        // Flags/Reserved
        w.u16(UInt16(SMB2Header.size + 8))              // PathOffset
        w.u16(UInt16(pathBytes.count))                  // PathLength
        w.bytes(pathBytes)
        let resp = try request(.treeConnect, body: w.data)
        treeId = resp.header.treeId
        return resp
    }

    // MARK: data-path requests (P1b)

    /// CREATE (open existing). Returns (status, FileId, endOfFile).
    func create(path: String, wantMxAc: Bool = true, wantAAPL: Bool = false,
                desiredAccess: UInt32 = SMBAccess.all, shareAccess: UInt32 = 0x07)
        throws -> (status: UInt32, fileId: SMBFileId, size: UInt64) {
        let nameBytes = SMBString.utf16le(path)
        var contexts = Data()
        if wantMxAc { contexts.append(clientContext(name: "MxAc", data: Data())) }
        if wantAAPL {
            var d = ByteWriter()
            d.u32(1); d.u32(0); d.u64(0x03); d.u64(0)   // ServerQuery request
            let aapl = clientContext(name: "AAPL", data: d.data)
            if contexts.isEmpty { contexts = aapl } else {
                // chain: patch previous Next
                patchU32(&contexts, at: 0, UInt32((contexts.count + 7) & ~7))
                while contexts.count % 8 != 0 { contexts.append(0) }
                contexts.append(aapl)
            }
        }
        var w = ByteWriter()
        w.u16(57)                                       // StructureSize
        w.u8(0); w.u8(0)                                // SecurityFlags, OplockLevel
        w.u32(2)                                        // ImpersonationLevel = Impersonation
        w.u64(0); w.u64(0)                              // SmbCreateFlags, Reserved
        w.u32(desiredAccess)                           // Explicit handle access
        w.u32(0)                                        // FileAttributes
        w.u32(shareAccess)                              // ShareAccess
        w.u32(1)                                        // CreateDisposition = OPEN
        w.u32(0)                                        // CreateOptions
        let nameOffset = SMB2Header.size + 56
        w.u16(UInt16(nameBytes.isEmpty ? 0 : nameOffset))
        w.u16(UInt16(nameBytes.count))
        // Contexts follow the (8-aligned) name.
        let namePadded = (nameBytes.count + 7) & ~7
        let ctxOffset = nameBytes.isEmpty ? nameOffset : nameOffset + namePadded
        w.u32(contexts.isEmpty ? 0 : UInt32(ctxOffset))
        w.u32(UInt32(contexts.count))
        if !nameBytes.isEmpty {
            w.bytes(nameBytes)
            if !contexts.isEmpty, namePadded > nameBytes.count { w.zeros(namePadded - nameBytes.count) }
        }
        w.bytes(contexts)
        let resp = try request(.create, body: w.data)
        guard resp.header.status == NTStatus.success.rawValue else {
            return (resp.header.status, SMBFileId(persistent: 0, volatile: 0), 0)
        }
        var r = ByteReader(resp.body)
        _ = try r.u16(); _ = try r.u8(); _ = try r.u8(); _ = try r.u32()   // struct/oplock/flags/action
        _ = try r.u64(); _ = try r.u64(); _ = try r.u64(); _ = try r.u64() // times
        _ = try r.u64()                                                    // alloc
        let eof = try r.u64()
        _ = try r.u32(); _ = try r.u32()                                   // attrs, reserved
        let p = try r.u64(); let v = try r.u64()
        return (resp.header.status, SMBFileId(persistent: p, volatile: v), eof)
    }

    func read(fileId: SMBFileId, offset: UInt64, length: UInt32) throws -> (status: UInt32, data: Data) {
        let resp = try request(.read, body: readBody(fileId: fileId, offset: offset, length: length))
        guard resp.header.status == NTStatus.success.rawValue else { return (resp.header.status, Data()) }
        var r = ByteReader(resp.body)
        _ = try r.u16()                                 // StructureSize
        let dataOffset = Int(try r.u8()); _ = try r.u8()
        let dataLen = Int(try r.u32())
        let rel = dataOffset - SMB2Header.size
        let payload = resp.body.subdata(in: rel..<(rel + dataLen))
        return (resp.header.status, payload)
    }

    func readBody(fileId: SMBFileId, offset: UInt64, length: UInt32) -> Data {
        var w = ByteWriter()
        w.u16(49)                                       // StructureSize
        w.u8(0); w.u8(0)                                // Padding, Flags
        w.u32(length)                                   // Length
        w.u64(offset)                                   // Offset
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        w.u32(0)                                        // MinimumCount
        w.u32(0)                                        // Channel
        w.u32(0)                                        // RemainingBytes
        w.u16(0); w.u16(0)                              // ReadChannelInfo offset/len
        w.u8(0)                                         // Buffer
        return w.data
    }

    struct DirItem { var name: String; var isDir: Bool; var size: UInt64; var fileId: UInt64 }

    /// QUERY_DIRECTORY one page; returns (status, entries).
    func queryDirectory(fileId: SMBFileId, restart: Bool, outMax: UInt32 = 64 << 10,
                       pattern: String = "*")
        throws -> (status: UInt32, items: [DirItem]) {
        let patternBytes = SMBString.utf16le(pattern)
        var w = ByteWriter()
        w.u16(33)                                       // StructureSize
        w.u8(0x25)                                      // FileInfoClass = IdBothDirectoryInfo
        w.u8(restart ? 0x01 : 0x00)                     // Flags
        w.u32(0)                                        // FileIndex
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        let nameOffset = SMB2Header.size + 32
        w.u16(UInt16(nameOffset)); w.u16(UInt16(patternBytes.count))
        w.u32(outMax)
        w.bytes(patternBytes)
        let resp = try request(.queryDirectory, body: w.data)
        guard resp.header.status == NTStatus.success.rawValue else { return (resp.header.status, []) }
        var r = ByteReader(resp.body)
        _ = try r.u16()                                 // StructureSize
        let bufOffset = Int(try r.u16()); let bufLen = Int(try r.u32())
        let rel = bufOffset - SMB2Header.size
        let buf = resp.body.subdata(in: rel..<(rel + bufLen))
        return (resp.header.status, parseIdBothDirInfo(buf))
    }

    /// Raw QUERY_DIRECTORY buffer (the FileIdBothDirectoryInformation bytes) for
    /// byte-level layout inspection.
    func rawQueryDirectory(fileId: SMBFileId, outMax: UInt32 = 64 << 10) throws -> Data {
        let pattern = SMBString.utf16le("*")
        var w = ByteWriter()
        w.u16(33); w.u8(0x25); w.u8(0x01); w.u32(0)
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        w.u16(UInt16(SMB2Header.size + 32)); w.u16(UInt16(pattern.count))
        w.u32(outMax); w.bytes(pattern)
        let resp = try request(.queryDirectory, body: w.data)
        var r = ByteReader(resp.body)
        _ = try r.u16(); let bufOffset = Int(try r.u16()); let bufLen = Int(try r.u32())
        let rel = bufOffset - SMB2Header.size
        return resp.body.subdata(in: rel..<(rel + bufLen))
    }

    /// CREATE with an explicit disposition/options (for create/overwrite/mkdir).
    func createEx(path: String, disposition: UInt32, options: UInt32 = 0,
                  desiredAccess: UInt32 = SMBAccess.all, shareAccess: UInt32 = 0x07)
        throws -> (status: UInt32, fileId: SMBFileId) {
        let nameBytes = SMBString.utf16le(path)
        var w = ByteWriter()
        w.u16(57); w.u8(0); w.u8(0); w.u32(2); w.u64(0); w.u64(0)
        w.u32(desiredAccess); w.u32(0); w.u32(shareAccess)
        w.u32(disposition); w.u32(options)
        let nameOffset = SMB2Header.size + 56
        w.u16(UInt16(nameBytes.isEmpty ? 0 : nameOffset)); w.u16(UInt16(nameBytes.count))
        w.u32(0); w.u32(0)
        w.bytes(nameBytes)
        let resp = try request(.create, body: w.data)
        guard resp.header.status == NTStatus.success.rawValue else {
            return (resp.header.status, SMBFileId(persistent: 0, volatile: 0))
        }
        var r = ByteReader(resp.body)
        _ = try r.u16(); _ = try r.u8(); _ = try r.u8(); _ = try r.u32()
        for _ in 0..<4 { _ = try r.u64() }; _ = try r.u64(); _ = try r.u64(); _ = try r.u32(); _ = try r.u32()
        let p = try r.u64(); let v = try r.u64()
        return (resp.header.status, SMBFileId(persistent: p, volatile: v))
    }

    func write(fileId: SMBFileId, offset: UInt64, data: Data) throws -> (status: UInt32, count: UInt32) {
        var w = ByteWriter()
        w.u16(49)
        let dataOffset = SMB2Header.size + 48       // fixed WRITE request body is 48 bytes
        w.u16(UInt16(dataOffset)); w.u32(UInt32(data.count)); w.u64(offset)
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        w.u32(0); w.u32(0); w.u16(0); w.u16(0)      // Channel, RemainingBytes, WriteChannelInfo off/len
        w.u32(0)                                     // Flags
        w.bytes(data)
        let resp = try request(.write, body: w.data)
        guard resp.header.status == NTStatus.success.rawValue else { return (resp.header.status, 0) }
        var r = ByteReader(resp.body)
        _ = try r.u16(); _ = try r.u16()
        return (resp.header.status, try r.u32())
    }

    /// SET_INFO FileEndOfFileInformation (truncate).
    func setEndOfFile(fileId: SMBFileId, size: UInt64) throws -> UInt32 {
        var payload = ByteWriter(); payload.u64(size)
        return try setInfo(fileId: fileId, infoType: 0x01, infoClass: 20, data: payload.data)
    }

    /// SET_INFO FileDispositionInformation (delete-on-close).
    func setDisposition(fileId: SMBFileId, delete: Bool) throws -> UInt32 {
        try setInfo(fileId: fileId, infoType: 0x01, infoClass: 13, data: Data([delete ? 1 : 0]))
    }

    /// SET_INFO FileRenameInformation.
    func rename(fileId: SMBFileId, to newPath: String, replace: Bool) throws -> UInt32 {
        let nameBytes = SMBString.utf16le(newPath)
        var p = ByteWriter()
        p.u8(replace ? 1 : 0); p.zeros(7); p.u64(0); p.u32(UInt32(nameBytes.count)); p.bytes(nameBytes)
        return try setInfo(fileId: fileId, infoType: 0x01, infoClass: 10, data: p.data)
    }

    func setInfo(fileId: SMBFileId, infoType: UInt8, infoClass: UInt8, data: Data) throws -> UInt32 {
        var w = ByteWriter()
        w.u16(33); w.u8(infoType); w.u8(infoClass); w.u32(UInt32(data.count))
        w.u16(UInt16(SMB2Header.size + 32)); w.u16(0); w.u32(0)
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        w.bytes(data)
        return try request(.setInfo, body: w.data).header.status
    }

    /// SMB2 LOCK with a single range. flags: SHARED=1, EXCLUSIVE=2, UNLOCK=4.
    func lock(fileId: SMBFileId, offset: UInt64, length: UInt64, flags: UInt32) throws -> UInt32 {
        var w = ByteWriter()
        w.u16(48); w.u16(1); w.u32(0)
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        w.u64(offset); w.u64(length); w.u32(flags | 0x10 /* FAIL_IMMEDIATELY */); w.u32(0)
        return try request(.lock, body: w.data).header.status
    }

    /// Send CHANGE_NOTIFY (async); returns the interim response (STATUS_PENDING).
    func changeNotifyRequest(fileId: SMBFileId, messageId: UInt64? = nil) throws -> Response {
        var w = ByteWriter()
        w.u16(32); w.u16(0); w.u32(64 << 10)
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        w.u32(0x0000_0007); w.u32(0)                // CompletionFilter (name|dirname|attrs), Reserved
        return try request(.changeNotify, body: w.data)
    }

    /// Read one raw framed SMB2 message (for the async CHANGE_NOTIFY completion
    /// that arrives out of band). Returns nil on timeout.
    func readAsyncResponse(timeoutMs: Int) -> Response? {
        var tv = timeval(tv_sec: timeoutMs / 1000, tv_usec: Int32((timeoutMs % 1000) * 1000))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        defer { var z = timeval(); setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &z, socklen_t(MemoryLayout<timeval>.size)) }
        guard let prefix = readN(4), let len = DirectTCP.length(prefix: prefix), let payload = readN(len) else { return nil }
        var r = ByteReader(payload)
        guard let hdr = try? SMB2Header.decode(&r) else { return nil }
        return Response(header: hdr, body: payload.subdata(in: SMB2Header.size..<payload.count))
    }

    func flush(fileId: SMBFileId) throws -> UInt32 {
        var w = ByteWriter(); w.u16(24); w.u16(0); w.u32(0)
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        return try request(.flush, body: w.data).header.status
    }

    func close(fileId: SMBFileId) throws {
        var w = ByteWriter()
        w.u16(24); w.u16(0); w.u32(0)
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        _ = try request(.close, body: w.data)
    }

    func queryInfo(fileId: SMBFileId, infoType: UInt8, infoClass: UInt8, outMax: UInt32 = 4096)
        throws -> (status: UInt32, buffer: Data) {
        var w = ByteWriter()
        w.u16(41)                                       // StructureSize
        w.u8(infoType); w.u8(infoClass)
        w.u32(outMax)                                   // OutputBufferLength
        w.u16(0); w.u16(0); w.u32(0)                    // Input offset/reserved/len
        w.u32(0); w.u32(0)                              // AdditionalInformation, Flags
        w.u64(fileId.persistent); w.u64(fileId.volatile)
        let resp = try request(.queryInfo, body: w.data)
        guard resp.header.status == NTStatus.success.rawValue else { return (resp.header.status, Data()) }
        var r = ByteReader(resp.body)
        _ = try r.u16()
        let off = Int(try r.u16()); let len = Int(try r.u32())
        let rel = off - SMB2Header.size
        return (resp.header.status, resp.body.subdata(in: rel..<(rel + len)))
    }

    private func parseIdBothDirInfo(_ buf: Data) -> [DirItem] {
        var out: [DirItem] = []
        var cursor = 0
        while cursor + 104 <= buf.count {
            let slice = buf.subdata(in: cursor..<buf.count)
            var r = ByteReader(slice)
            guard let next = try? r.u32() else { break }
            _ = try? r.u32()                            // FileIndex
            for _ in 0..<4 { _ = try? r.u64() }         // times
            let eof = (try? r.u64()) ?? 0               // EndOfFile
            _ = try? r.u64()                            // AllocationSize
            let attrs = (try? r.u32()) ?? 0
            let nameLen = Int((try? r.u32()) ?? 0)
            _ = try? r.u32()                            // EaSize
            _ = try? r.u8(); _ = try? r.u8()            // ShortNameLength, Reserved
            _ = try? r.take(24)                         // ShortName
            _ = try? r.u16()                            // Reserved2
            let fileId = (try? r.u64()) ?? 0             // FileId
            let name = (try? r.take(nameLen)).map { SMBString.decodeUTF16le($0) } ?? ""
            out.append(DirItem(name: name, isDir: attrs & 0x10 != 0, size: eof, fileId: fileId))
            if next == 0 { break }
            cursor += Int(next)
        }
        return out
    }

    private func clientContext(name: String, data: Data) -> Data {
        let nameBytes = Data(name.utf8)
        var w = ByteWriter()
        w.u32(0)                                        // Next
        w.u16(16)                                       // NameOffset
        w.u16(UInt16(nameBytes.count))
        w.u16(0)                                        // Reserved
        let namePadded = (nameBytes.count + 7) & ~7
        w.u16(UInt16(16 + namePadded))                  // DataOffset
        w.u32(UInt32(data.count))
        w.bytes(nameBytes)
        if namePadded > nameBytes.count { w.zeros(namePadded - nameBytes.count) }
        w.bytes(data)
        // pad whole context to 8
        var d = w.data
        while d.count % 8 != 0 { d.append(0) }
        return d
    }

    // MARK: NTLM/SPNEGO framing for the client side

    private func ntlmNegotiate() -> Data {
        var w = ByteWriter()
        w.bytes(Array("NTLMSSP\u{0}".utf8))
        w.u32(1)                                        // NEGOTIATE
        w.u32(NTLMFlag.unicode | NTLMFlag.ntlm | NTLMFlag.requestTarget
              | NTLMFlag.extendedSessionSecurity | NTLMFlag.keyExchange)
        w.u16(0); w.u16(0); w.u32(0)                    // DomainName fields
        w.u16(0); w.u16(0); w.u32(0)                    // Workstation fields
        return w.data
    }

    /// SESSION_SETUP request body ([MS-SMB2] §2.2.5) with the security buffer.
    private func sessionSetupBody(security: Data) -> Data {
        var w = ByteWriter()
        w.u16(25)                                       // StructureSize
        w.u8(0)                                         // Flags
        w.u8(0)                                         // SecurityMode
        w.u32(0)                                        // Capabilities
        w.u32(0)                                        // Channel
        w.u16(UInt16(SMB2Header.size + 24))             // SecurityBufferOffset
        w.u16(UInt16(security.count))                   // SecurityBufferLength
        w.u64(0)                                        // PreviousSessionId
        w.bytes(security)
        return w.data
    }

    /// Pull the security buffer out of a SESSION_SETUP response body.
    private func extractSecurityBuffer(_ body: Data) -> Data {
        var r = ByteReader(body)
        _ = try? r.u16()                                // StructureSize
        _ = try? r.u16()                                // SessionFlags
        guard let secOffset = try? r.u16(), let secLen = try? r.u16() else { return Data() }
        let rel = Int(secOffset) - SMB2Header.size
        guard rel >= 0, rel + Int(secLen) <= body.count else { return Data() }
        return body.subdata(in: rel..<(rel + Int(secLen)))
    }

    // MARK: socket io

    private func writeAll(_ data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var off = 0
            while off < raw.count {
                let n = Darwin.write(fd, base.advanced(by: off), raw.count - off)
                if n > 0 { off += n; continue }
                if n < 0 && errno == EINTR { continue }
                throw TestError.shortRead
            }
        }
    }

    private func readN(_ count: Int) -> Data? {
        var out = Data(capacity: count)
        var buf = [UInt8](repeating: 0, count: min(max(count, 1), 64 << 10))
        while out.count < count {
            let want = min(buf.count, count - out.count)
            let n = Darwin.read(fd, &buf, want)
            if n <= 0 { return nil }
            out.append(contentsOf: buf[0..<n])
        }
        return out
    }
}
