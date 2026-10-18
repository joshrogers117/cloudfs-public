// SPDX-License-Identifier: AGPL-3.0-or-later
// Wire regressions for independently-scoped SMB2 tree connections.

import XCTest
import Darwin
import CloudFSCore
@testable import CloudFSSMB

final class TreeLifecycleTests: XCTestCase {
    func testSecondaryTreeDisconnectClosesOnlyItsOpens() throws {
        let engine = MemoryEngine()
        let file = engine.seed("tree-child.txt", data: Data("child".utf8))
        let password = "tree-life-\(UUID().uuidString)"
        let server = SMBServer(engine: engine, shareName: "cloudfs",
                               credential: (user: "cfs", password: password))
        let port = try server.start()
        defer { server.stop() }

        let client = TreeWireClient()
        try client.connect(port: port)
        defer { client.close() }
        try client.authenticate(user: "cfs", password: password)

        let primary = try client.treeConnect(share: "cloudfs")
        XCTAssertNotEqual(primary, 0)
        let primaryRoot = try client.create(path: "", tree: primary).fileId
        XCTAssertEqual(engine.openReferenceCount(.root), 1)
        XCTAssertEqual(try client.relatedOpenClose(tree: primary),
                       [NTStatus.success.rawValue, NTStatus.success.rawValue])
        XCTAssertEqual(engine.openReferenceCount(.root), 1,
                       "RELATED TreeId inheritance must use this compound's preceding tree")

        let secondary = try client.treeConnect(share: "cloudfs")
        XCTAssertNotEqual(secondary, 0)
        XCTAssertNotEqual(secondary, primary)
        let secondaryFile = try client.create(path: "tree-child.txt", tree: secondary).fileId
        XCTAssertEqual(engine.openReferenceCount(file), 1)
        XCTAssertEqual(try client.close(fileId: secondaryFile, tree: primary), NTStatus.fileClosed.rawValue)
        XCTAssertEqual(engine.openReferenceCount(file), 1,
                       "a wrong-tree CLOSE must not release another tree's open")

        // An unsupported share must not disturb either already-connected tree.
        XCTAssertEqual(try client.treeConnect(share: "other-share"), 0)
        let primaryCheck = try client.create(path: "", tree: primary)
        XCTAssertEqual(primaryCheck.status, NTStatus.success.rawValue)
        XCTAssertEqual(try client.close(fileId: primaryCheck.fileId, tree: primary), NTStatus.success.rawValue)

        XCTAssertEqual(try client.disconnect(tree: secondary), NTStatus.success.rawValue)
        XCTAssertEqual(engine.openReferenceCount(file), 0, "disconnect must release the secondary FID")
        XCTAssertEqual(engine.openReferenceCount(.root), 1, "the primary tree's root FID must remain open")

        let primaryAfterDisconnect = try client.create(path: "", tree: primary)
        XCTAssertEqual(primaryAfterDisconnect.status, NTStatus.success.rawValue,
                       "disconnecting the diagnostic tree must leave the mounted tree usable")
        XCTAssertEqual(try client.close(fileId: primaryAfterDisconnect.fileId, tree: primary), NTStatus.success.rawValue)
        XCTAssertEqual(try client.read(fileId: secondaryFile, tree: primary).status, NTStatus.fileClosed.rawValue,
                       "a FID created on another tree cannot be used through the primary tree")
        XCTAssertEqual(try client.create(path: "", tree: secondary).status, NTStatus.networkNameDeleted.rawValue)

        let relatedStatuses = try client.invalidTreeRelatedClose(validTree: primary, staleTree: secondary)
        XCTAssertEqual(relatedStatuses, [NTStatus.success.rawValue, NTStatus.networkNameDeleted.rawValue,
                                         NTStatus.networkNameDeleted.rawValue])
        XCTAssertEqual(engine.openReferenceCount(.root), 2,
                       "invalid tree must clear RELATED inheritance so CLOSE cannot consume a prior FID")

        XCTAssertEqual(try client.logoff(), NTStatus.success.rawValue)
        XCTAssertEqual(engine.openReferenceCount(.root), 0)
        XCTAssertEqual(try client.create(path: "", tree: primary).status, NTStatus.userSessionDeleted.rawValue,
                       "LOGOFF must invalidate tree I/O even when the old TreeId was active")
        _ = primaryRoot
    }
}

/// A tiny raw client so the test can choose the TreeId on each request while
/// retaining one TCP connection. SMBTestClient intentionally models one tree.
private final class TreeWireClient {
    private var fd: Int32 = -1
    private var sessionId: UInt64 = 0
    private var nextMessageId: UInt64 = 0

    func connect(port: UInt16) throws {
        fd = socket(AF_INET, SOCK_STREAM, 0)
        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else { throw SMBTestClient.TestError.connectFailed }
        var negotiate = ByteWriter()
        negotiate.u16(36); negotiate.u16(2); negotiate.u16(1); negotiate.u16(0); negotiate.u32(0)
        negotiate.bytes(Data(0..<16)); negotiate.u64(0); negotiate.u16(0); negotiate.u16(0)
        negotiate.u16(SMB2Dialect.smb202.rawValue); negotiate.u16(SMB2Dialect.smb21.rawValue)
        let response = try request(.negotiate, body: negotiate.data)
        guard response.header.status == NTStatus.success.rawValue else { throw SMBTestClient.TestError.badResponse }
    }

    func close() { if fd >= 0 { Darwin.close(fd); fd = -1 } }

    func authenticate(user: String, password: String) throws {
        let first = try request(.sessionSetup, body: setupBody(security: ntlmNegotiate()))
        sessionId = first.header.sessionId
        guard first.header.status == NTStatus.moreProcessingRequired.rawValue else {
            throw SMBTestClient.TestError.status(first.header.status)
        }
        var response = ByteReader(first.body)
        _ = try response.u16(); _ = try response.u16()
        let offset = Int(try response.u16()) - SMB2Header.size
        let length = Int(try response.u16())
        let security = first.body.subdata(in: offset..<(offset + length))
        guard let challengeMessage = SPNEGO.extractNTLM(security) else { throw SMBTestClient.TestError.badResponse }
        let challenge = challengeMessage.subdata(in: (challengeMessage.startIndex + 24)..<(challengeMessage.startIndex + 32))
        let auth = ReferenceNTLMClient.authenticate(username: user, password: password, domain: "",
            serverChallenge: challenge, clientChallenge: Data([1,2,3,4,5,6,7,8]), timestamp: nowFiletime())
        let second = try request(.sessionSetup, body: setupBody(security: auth))
        guard second.header.status == NTStatus.success.rawValue else {
            throw SMBTestClient.TestError.status(second.header.status)
        }
    }

    func treeConnect(share: String) throws -> UInt32 {
        let path = SMBString.utf16le("\\\\127.0.0.1\\\(share)")
        var body = ByteWriter()
        body.u16(9); body.u16(0); body.u16(UInt16(SMB2Header.size + 8)); body.u16(UInt16(path.count)); body.bytes(path)
        let response = try request(.treeConnect, body: body.data)
        return response.header.status == NTStatus.success.rawValue ? response.header.treeId : 0
    }

    func create(path: String, tree: UInt32) throws -> (status: UInt32, fileId: SMBFileId) {
        let response = try request(.create, body: createBody(path: path), tree: tree)
        guard response.header.status == NTStatus.success.rawValue else {
            return (response.header.status, SMBFileId(persistent: 0, volatile: 0))
        }
        var r = ByteReader(response.body)
        _ = try r.u16(); _ = try r.u8(); _ = try r.u8(); _ = try r.u32()
        for _ in 0..<6 { _ = try r.u64() }
        _ = try r.u32(); _ = try r.u32()
        return (response.header.status, SMBFileId(persistent: try r.u64(), volatile: try r.u64()))
    }

    func read(fileId: SMBFileId, tree: UInt32) throws -> (status: UInt32, data: Data) {
        var body = ByteWriter()
        body.u16(49); body.u8(0); body.u8(0); body.u32(32); body.u64(0)
        body.u64(fileId.persistent); body.u64(fileId.volatile)
        body.u32(0); body.u32(0); body.u32(0); body.u16(0); body.u16(0); body.u8(0)
        let response = try request(.read, body: body.data, tree: tree)
        if response.header.status != NTStatus.success.rawValue { return (response.header.status, Data()) }
        var r = ByteReader(response.body)
        _ = try r.u16(); let offset = Int(try r.u8()); _ = try r.u8(); let count = Int(try r.u32())
        let rel = offset - SMB2Header.size
        return (response.header.status, response.body.subdata(in: rel..<(rel + count)))
    }

    func disconnect(tree: UInt32) throws -> UInt32 {
        var body = ByteWriter(); body.u16(4); body.u16(0)
        return try request(.treeDisconnect, body: body.data, tree: tree).header.status
    }

    func logoff() throws -> UInt32 {
        var body = ByteWriter(); body.u16(4); body.u16(0)
        return try request(.logoff, body: body.data).header.status
    }

    func close(fileId: SMBFileId, tree: UInt32) throws -> UInt32 {
        var body = ByteWriter(); body.u16(24); body.u16(0); body.u32(0)
        body.u64(fileId.persistent); body.u64(fileId.volatile)
        return try request(.close, body: body.data, tree: tree).header.status
    }

    func relatedOpenClose(tree: UInt32) throws -> [UInt32] {
        var createHeader = SMB2Header(command: .create, messageId: nextMessageId, creditCharge: 1,
                                      creditReqGrant: 64, treeId: tree, sessionId: sessionId)
        nextMessageId += 1
        let createBody = createBody(path: "")
        let createSize = SMB2Header.size + createBody.count
        let paddedSize = (createSize + 7) & ~7
        createHeader.nextCommand = UInt32(paddedSize)
        var first = ByteWriter(); createHeader.encode(into: &first); first.bytes(createBody)
        first.zeros(paddedSize - createSize)

        let closeHeader = SMB2Header(command: .close, messageId: nextMessageId, creditCharge: 1,
                                     creditReqGrant: 64, flags: [.relatedOps], treeId: UInt32.max,
                                     sessionId: sessionId)
        nextMessageId += 1
        var closeBody = ByteWriter(); closeBody.u16(24); closeBody.u16(0); closeBody.u32(0)
        closeBody.u64(UInt64.max); closeBody.u64(UInt64.max)
        var second = ByteWriter(); closeHeader.encode(into: &second); second.bytes(closeBody.data)
        var packet = first.data; packet.append(second.data)
        var framed = DirectTCP.frame(length: packet.count); framed.append(packet)
        try writeAll(framed)
        guard let prefix = readN(4), let length = DirectTCP.length(prefix: prefix), let payload = readN(length) else {
            throw SMBTestClient.TestError.shortRead
        }
        var statuses: [UInt32] = []
        var cursor = 0
        while cursor + SMB2Header.size <= payload.count {
            var r = ByteReader(payload.subdata(in: cursor..<payload.count))
            let header = try SMB2Header.decode(&r)
            statuses.append(header.status)
            if header.nextCommand == 0 { break }
            cursor += Int(header.nextCommand)
        }
        return statuses
    }

    func invalidTreeRelatedClose(validTree: UInt32, staleTree: UInt32) throws -> [UInt32] {
        let specs: [(SMB2Command, Data, UInt32, SMB2HeaderFlags)] = [
            (.create, createBody(path: ""), validTree, []),
            (.create, createBody(path: ""), staleTree, []),
            (.close, relatedCloseBody(), UInt32.max, [.relatedOps])
        ]
        var packet = Data()
        for (index, spec) in specs.enumerated() {
            var header = SMB2Header(command: spec.0, messageId: nextMessageId, creditCharge: 1,
                                    creditReqGrant: 64, flags: spec.3, treeId: spec.2, sessionId: sessionId)
            nextMessageId += 1
            let bodySize = SMB2Header.size + spec.1.count
            let paddedSize = index == specs.count - 1 ? bodySize : (bodySize + 7) & ~7
            header.nextCommand = index == specs.count - 1 ? 0 : UInt32(paddedSize)
            var part = ByteWriter(); header.encode(into: &part); part.bytes(spec.1)
            part.zeros(paddedSize - bodySize)
            packet.append(part.data)
        }
        var framed = DirectTCP.frame(length: packet.count); framed.append(packet)
        try writeAll(framed)
        guard let prefix = readN(4), let length = DirectTCP.length(prefix: prefix), let payload = readN(length) else {
            throw SMBTestClient.TestError.shortRead
        }
        var statuses: [UInt32] = []
        var cursor = 0
        while cursor + SMB2Header.size <= payload.count {
            var r = ByteReader(payload.subdata(in: cursor..<payload.count))
            let header = try SMB2Header.decode(&r)
            statuses.append(header.status)
            if header.nextCommand == 0 { break }
            cursor += Int(header.nextCommand)
        }
        return statuses
    }

    private func createBody(path: String) -> Data {
        let name = SMBString.utf16le(path)
        var body = ByteWriter()
        body.u16(57); body.u8(0); body.u8(0); body.u32(2); body.u64(0); body.u64(0)
        body.u32(SMBAccess.all); body.u32(0); body.u32(7); body.u32(1); body.u32(0)
        body.u16(UInt16(name.isEmpty ? 0 : SMB2Header.size + 56)); body.u16(UInt16(name.count)); body.u32(0); body.u32(0)
        body.bytes(name)
        return body.data
    }

    private func relatedCloseBody() -> Data {
        var body = ByteWriter(); body.u16(24); body.u16(0); body.u32(0)
        body.u64(UInt64.max); body.u64(UInt64.max)
        return body.data
    }

    private func request(_ command: SMB2Command, body: Data, tree: UInt32 = 0) throws -> SMBTestClient.Response {
        let header = SMB2Header(command: command, messageId: nextMessageId, creditCharge: 1,
                                creditReqGrant: 64, treeId: tree, sessionId: sessionId)
        nextMessageId += 1
        var packet = ByteWriter(); header.encode(into: &packet); packet.bytes(body)
        var framed = DirectTCP.frame(length: packet.count); framed.append(packet.data)
        try writeAll(framed)
        guard let prefix = readN(4), let length = DirectTCP.length(prefix: prefix), let payload = readN(length) else {
            throw SMBTestClient.TestError.shortRead
        }
        var r = ByteReader(payload)
        let responseHeader = try SMB2Header.decode(&r)
        return SMBTestClient.Response(header: responseHeader, body: payload.subdata(in: SMB2Header.size..<payload.count))
    }

    private func writeAll(_ data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(fd, base.advanced(by: offset), raw.count - offset)
                if count > 0 { offset += count; continue }
                if count < 0 && errno == EINTR { continue }
                throw SMBTestClient.TestError.shortRead
            }
        }
    }

    private func readN(_ count: Int) -> Data? {
        var output = Data(count: count)
        let success = output.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return count == 0 }
            var offset = 0
            while offset < count {
                let received = Darwin.read(fd, base.advanced(by: offset), count - offset)
                if received > 0 { offset += received; continue }
                if received < 0 && errno == EINTR { continue }
                return false
            }
            return true
        }
        return success ? output : nil
    }

    private func ntlmNegotiate() -> Data {
        var w = ByteWriter(); w.bytes(Array("NTLMSSP\u{0}".utf8)); w.u32(1)
        w.u32(NTLMFlag.unicode | NTLMFlag.ntlm | NTLMFlag.requestTarget | NTLMFlag.extendedSessionSecurity | NTLMFlag.keyExchange)
        w.u16(0); w.u16(0); w.u32(0); w.u16(0); w.u16(0); w.u32(0)
        return w.data
    }

    private func setupBody(security: Data) -> Data {
        var w = ByteWriter(); w.u16(25); w.u8(0); w.u8(0); w.u32(0); w.u32(0)
        w.u16(UInt16(SMB2Header.size + 24)); w.u16(UInt16(security.count)); w.u64(0); w.bytes(security)
        return w.data
    }
}
