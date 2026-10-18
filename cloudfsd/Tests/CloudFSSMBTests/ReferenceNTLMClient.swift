// SPDX-License-Identifier: AGPL-3.0-or-later
// A minimal client-side NTLMv2 AUTHENTICATE builder used by the P0 round-trip
// tests (and, later, by the live SMB test client). Mirrors [MS-NLMP] §3.3.2 so it
// exercises the server verifier's exact field layout and math.

import Foundation
import CryptoKit
@testable import CloudFSSMB

enum ReferenceNTLMClient {
    static func hmacMD5(_ key: Data, _ msg: Data) -> Data {
        Data(HMAC<Insecure.MD5>.authenticationCode(for: msg, using: SymmetricKey(data: key)))
    }

    /// Build a Type-3 AUTHENTICATE message with an NTLMv2 response.
    static func authenticate(username: String, password: String, domain: String,
                             serverChallenge: Data, clientChallenge: Data,
                             timestamp: UInt64) -> Data {
        // NTOWFv2 = HMAC-MD5(MD4(UTF16LE(password)), UTF16LE(UPPER(user)+domain))
        let ntlmHash = MD4.hash(SMBString.utf16le(password))
        let ntowfv2 = hmacMD5(ntlmHash, SMBString.utf16le(username.uppercased() + domain))

        // temp = 0x01 0x01 00000000 timestamp(8) clientChallenge(8) 00000000 [targetInfo] 00000000
        var temp = Data([0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        withUnsafeBytes(of: timestamp.littleEndian) { temp.append(contentsOf: $0) }
        temp.append(clientChallenge)
        temp.append(Data([0x00, 0x00, 0x00, 0x00]))
        // (targetInfo omitted for the loopback closed-loop test — the server does
        // not require it to verify NTProofStr; real clients echo the AV pairs.)
        temp.append(Data([0x00, 0x00, 0x00, 0x00]))

        var proofInput = serverChallenge
        proofInput.append(temp)
        let ntProof = hmacMD5(ntowfv2, proofInput)
        let ntResponse = ntProof + temp

        let sessionBaseKey = hmacMD5(ntowfv2, ntProof)
        // KEY_EXCH: send RC4(sessionBaseKey, exportedSessionKey). Use a fixed key.
        let exportedKey = Data(repeating: 0x5A, count: 16)
        let encryptedSessionKey = RC4.apply(key: sessionBaseKey, data: exportedKey)

        let flags = NTLMFlag.unicode | NTLMFlag.ntlm | NTLMFlag.extendedSessionSecurity | NTLMFlag.keyExchange

        // Assemble Type-3. Payload after the fixed 64-byte header:
        // [LM][NT][Domain][User][Workstation][SessionKey]
        let lm = Data(count: 24)
        let domainB = SMBString.utf16le(domain)
        let userB = SMBString.utf16le(username)
        let wsB = SMBString.utf16le("CLIENT")

        var payload = Data()
        let headerLen = 64
        func appendField(_ b: Data, into fields: inout Data, offsetAcc: inout Int) {
            fields.append(le16(UInt16(b.count)))
            fields.append(le16(UInt16(b.count)))
            fields.append(le32(UInt32(headerLen + offsetAcc)))
            payload.append(b)
            offsetAcc += b.count
        }

        var fields = Data()
        var acc = 0
        // Order of fields in the header is LM, NT, Domain, User, WS, SessionKey.
        appendField(lm, into: &fields, offsetAcc: &acc)
        appendField(ntResponse, into: &fields, offsetAcc: &acc)
        appendField(domainB, into: &fields, offsetAcc: &acc)
        appendField(userB, into: &fields, offsetAcc: &acc)
        appendField(wsB, into: &fields, offsetAcc: &acc)
        appendField(encryptedSessionKey, into: &fields, offsetAcc: &acc)

        var msg = Data("NTLMSSP\u{0}".utf8)
        msg.append(le32(3))            // MessageType = AUTHENTICATE
        msg.append(fields)             // 6 × 8-byte field descriptors = 48 bytes
        msg.append(le32(flags))        // NegotiateFlags
        // Pad header to 64 bytes (8 sig + 4 type + 48 fields + 4 flags = 64). No pad needed.
        assert(msg.count == headerLen, "NTLM Type-3 header must be 64 bytes, got \(msg.count)")
        msg.append(payload)
        return msg
    }

    static func le16(_ v: UInt16) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
    static func le32(_ v: UInt32) -> Data { withUnsafeBytes(of: v.littleEndian) { Data($0) } }
}
