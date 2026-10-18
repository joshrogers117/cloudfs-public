// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — the connection-establishment handlers: NEGOTIATE, SESSION_SETUP
// (two NTLM legs), TREE_CONNECT. These decide the dialect (2.1), drive the
// synthetic-credential NTLMv2 handshake through SPNEGO, and attach the single
// share. Everything is little-endian per [MS-SMB2].

import Foundation

extension SMBServer {

    // MARK: NEGOTIATE ([MS-SMB2] §2.2.3 request / §2.2.4 response)

    /// Answer with dialect 2.1 + CAP_LARGE_MTU and an SPNEGO hint advertising
    /// NTLMSSP. We ignore the client's dialect list beyond confirming it offered
    /// something ≥ 2.1 territory; a pure-2.0.2 client still works (it just won't
    /// use multi-credit large I/O). No leasing/encryption caps → no break machinery.
    func handleNegotiate(_ body: Data) -> Data {
        let security = SPNEGO.negotiateHint()
        var w = ByteWriter()
        w.u16(65)                                   // StructureSize
        w.u16(0x0001)                               // SecurityMode = SIGNING_ENABLED (not required)
        w.u16(SMB2Dialect.smb21.rawValue)           // DialectRevision = 2.1
        w.u16(0)                                    // NegotiateContextCount (2.1: none)
        w.bytes(serverGuid)                         // ServerGuid (16)
        w.u32(SMB2Capabilities.largeMTU)            // Capabilities (NO leasing)
        w.u32(1 << 20)                              // MaxTransactSize = 1 MiB
        w.u32(1 << 20)                              // MaxReadSize = 1 MiB (enables 1 MiB reads)
        w.u32(UInt32(SMBLimits.maximumWriteBytes))   // MaxWriteSize = 8 MiB (durable bounded transaction)
        w.u64(nowFiletime())                        // SystemTime
        w.u64(0)                                    // ServerStartTime
        // SecurityBufferOffset is measured from the SMB2 header start: 64 (header)
        // + 64 (this fixed part through Reserved2) = 128.
        let secOffset = SMB2Header.size + 64
        w.u16(UInt16(secOffset))                    // SecurityBufferOffset
        w.u16(UInt16(security.count))               // SecurityBufferLength
        w.u32(0)                                    // Reserved2
        w.bytes(security)
        return w.data
    }

    // MARK: SESSION_SETUP ([MS-SMB2] §2.2.5 request / §2.2.6 response)

    func handleSessionSetup(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        guard let incoming = parseSessionSetupSecurityBuffer(hdr: hdr, body: body),
              let ntlm = SPNEGO.extractNTLM(incoming) else {
            return (.invalidParameter, errorBody(), DispatchExtra())
        }

        // NTLM message type is the u32 right after the 8-byte signature.
        let msgType: UInt32 = ntlm.count >= 12
            ? ntlm.subdata(in: (ntlm.startIndex + 8)..<(ntlm.startIndex + 12))
                  .withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self)) }
            : 0

        switch msgType {
        case 1:   // NEGOTIATE → mint + return a CHALLENGE, ask for more processing.
            let negFlags = parseNegotiateFlags(ntlm)
            state.negotiateFlags = negFlags
            var challenge = Data(count: 8)
            for i in 0..<8 { challenge[i] = UInt8.random(in: .min ... .max) }
            state.pendingServerChallenge = challenge
            let ntlmChallenge = ntlm2challenge(negFlags: negFlags, serverChallenge: challenge)
            let spnego = SPNEGO.challengeResponse(ntlmChallenge: ntlmChallenge)
            // Assign a session id now; it rides both legs.
            if state.sessionId == 0 { state.sessionId = UInt64.random(in: 1 ... .max) }
            let respBody = sessionSetupResponse(flags: 0, security: spnego)
            return (.moreProcessingRequired, respBody,
                    DispatchExtra(sessionId: state.sessionId, treeId: nil))

        case 3:   // AUTHENTICATE → verify NTProofStr against our challenge.
            guard let challenge = state.pendingServerChallenge,
                  ntlm.verifyAgainst(server: ntlm2server(), serverChallenge: challenge) else {
                return (.logonFailure, errorBody(), DispatchExtra())
            }
            state.authenticated = true
            state.pendingServerChallenge = nil
            let spnego = SPNEGO.acceptCompleted()
            let respBody = sessionSetupResponse(flags: 0, security: spnego)
            return (.success, respBody, DispatchExtra(sessionId: state.sessionId, treeId: nil))

        default:
            return (.invalidParameter, errorBody(), DispatchExtra())
        }
    }

    /// SESSION_SETUP response body ([MS-SMB2] §2.2.6).
    private func sessionSetupResponse(flags: UInt16, security: Data) -> Data {
        var w = ByteWriter()
        w.u16(9)                                    // StructureSize
        w.u16(flags)                                // SessionFlags (0 = not guest/anon)
        let secOffset = SMB2Header.size + 8         // header + fixed body (8 bytes)
        w.u16(UInt16(secOffset))                    // SecurityBufferOffset
        w.u16(UInt16(security.count))               // SecurityBufferLength
        w.bytes(security)
        return w.data
    }

    /// Pull the SESSION_SETUP request's security buffer using its offset/length
    /// (both measured from the SMB2 header start).
    private func parseSessionSetupSecurityBuffer(hdr: SMB2Header, body: Data) -> Data? {
        var r = ByteReader(body)
        guard (try? r.u16()) == 25 else { return nil }   // StructureSize
        _ = try? r.u8()                                  // Flags
        _ = try? r.u8()                                  // SecurityMode
        _ = try? r.u32()                                 // Capabilities
        _ = try? r.u32()                                 // Channel
        guard let secOffset = try? r.u16(),
              let secLen = try? r.u16(),
              let _ = try? r.u64() else { return nil }    // PreviousSessionId
        // Offset is from the header; body starts at header+64.
        let rel = Int(secOffset) - SMB2Header.size
        guard rel >= 0, rel + Int(secLen) <= body.count else { return nil }
        return body.subdata(in: rel..<(rel + Int(secLen)))
    }

    // MARK: TREE_CONNECT ([MS-SMB2] §2.2.9 request / §2.2.10 response)

    func handleTreeConnect(_ hdr: SMB2Header, body: Data, state: SMBConnectionState)
        -> (NTStatus, Data, DispatchExtra) {
        guard state.authenticated else { return (.accessDenied, errorBody(), DispatchExtra()) }
        // We host exactly one disk share. Reject unknown shares before changing
        // connection state; diagnostics may connect to the same share repeatedly.
        let path = parseTreeConnectPath(body) ?? ""
        let leaf = path.split(whereSeparator: { $0 == "\\" || $0 == "/" }).last.map(String.init) ?? ""
        guard leaf.caseInsensitiveCompare(shareName) == .orderedSame else {
            return (.badNetworkName, errorBody(), DispatchExtra())
        }
        let treeId = state.connectTree()

        var w = ByteWriter()
        w.u16(16)                                   // StructureSize
        w.u8(0x01)                                  // ShareType = DISK
        w.u8(0)                                     // Reserved
        w.u32(0)                                    // ShareFlags
        w.u32(0)                                    // Capabilities
        w.u32(0x001F_01FF)                          // MaximalAccess = FILE_ALL_ACCESS
        return (.success, w.data, DispatchExtra(sessionId: nil, treeId: treeId))
    }

    private func parseTreeConnectPath(_ body: Data) -> String? {
        var r = ByteReader(body)
        guard (try? r.u16()) == 9 else { return nil }    // StructureSize
        _ = try? r.u16()                                 // Flags/Reserved
        guard let pathOffset = try? r.u16(),
              let pathLen = try? r.u16() else { return nil }
        let rel = Int(pathOffset) - SMB2Header.size
        guard rel >= 0, rel + Int(pathLen) <= body.count else { return nil }
        return SMBString.decodeUTF16le(body.subdata(in: rel..<(rel + Int(pathLen))))
    }

    // MARK: NTLM glue

    private func ntlm2server() -> NTLMServer { ntlm }

    private func ntlm2challenge(negFlags: UInt32, serverChallenge: Data) -> Data {
        ntlm.challengeMessage(negotiateFlags: negFlags, serverChallenge: serverChallenge,
                              timestamp: nowFiletime())
    }

    /// NTLMSSP NEGOTIATE NegotiateFlags sit at a fixed offset (signature 8 + type 4
    /// + domain fields 8 + workstation fields 8 = 28... flags are at offset 12).
    private func parseNegotiateFlags(_ ntlm: Data) -> UInt32 {
        let at = ntlm.startIndex + 12
        guard ntlm.count >= 16 else { return 0 }
        return ntlm.subdata(in: at..<(at + 4)).withUnsafeBytes {
            UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self))
        }
    }
}

// MARK: - NTLM verify adapter

private extension Data {
    /// Verify this AUTHENTICATE blob against `server` + `serverChallenge`.
    func verifyAgainst(server: NTLMServer, serverChallenge: Data) -> Bool {
        server.verifyAuthenticate(self, serverChallenge: serverChallenge) != nil
    }
}
