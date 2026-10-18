// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — minimal server-side NTLMSSP for a single synthetic credential.
//
// The loopback mount authenticates with a random per-mount username+password that
// the daemon generates and stashes in the login keychain for `mount_smbfs -N` to
// read. We are therefore both the only client and the only server, so this
// implements exactly the NTLMv2 message flow the mac smbfs client drives:
//
//   NEGOTIATE  (client → server)   — we note requested flags
//   CHALLENGE  (server → client)   — we mint an 8-byte challenge + TargetInfo
//   AUTHENTICATE (client → server) — we recompute NTProofStr and compare
//
// Guest is deliberately NOT used: a guest-flagged session makes the mac client
// disable signing and fail authenticated mounts with EAUTH. See MS-NLMP.

import Foundation
import CryptoKit

// MARK: - HMAC-MD5 / MD5 helpers (CryptoKit ships MD5 as Insecure.MD5)

enum NTLMCrypto {
    static func md5(_ d: Data) -> Data { Data(Insecure.MD5.hash(data: d)) }

    static func hmacMD5(key: Data, _ message: Data) -> Data {
        let mac = HMAC<Insecure.MD5>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(mac)
    }
}

// MARK: - NTLMSSP constants

public enum NTLMFlag {
    public static let unicode:               UInt32 = 0x0000_0001
    public static let requestTarget:          UInt32 = 0x0000_0004
    public static let sign:                   UInt32 = 0x0000_0010
    public static let seal:                   UInt32 = 0x0000_0020
    public static let ntlm:                   UInt32 = 0x0000_0200
    public static let alwaysSign:             UInt32 = 0x0000_8000
    public static let targetTypeServer:       UInt32 = 0x0002_0000
    public static let extendedSessionSecurity:UInt32 = 0x0008_0000
    public static let targetInfo:             UInt32 = 0x0080_0000
    public static let version:                UInt32 = 0x0200_0000
    public static let keyExchange:            UInt32 = 0x4000_0000
    public static let negotiate56:            UInt32 = 0x8000_0000
    public static let negotiate128:           UInt32 = 0x2000_0000
}

/// AV_PAIR ids for the CHALLENGE TargetInfo block ([MS-NLMP] §2.2.2.1).
enum AVId: UInt16 {
    case eol            = 0x0000
    case nbComputerName = 0x0001
    case nbDomainName   = 0x0002
    case dnsComputerName = 0x0003
    case dnsDomainName  = 0x0004
    case timestamp      = 0x0007
}

let ntlmSignature: [UInt8] = Array("NTLMSSP\0".utf8)  // 8 bytes incl. NUL

// MARK: - Server

public struct NTLMServer: Sendable {
    /// Case-insensitive per MS-NLMP (username is upper-cased in NTOWFv2).
    public let username: String
    public let password: String
    public let targetName: String   // NetBIOS computer/domain label shown in TargetInfo

    public init(username: String, password: String, targetName: String) {
        self.username = username
        self.password = password
        self.targetName = targetName
    }

    /// Build the CHALLENGE message (Type 2) given the client's negotiate flags and
    /// a caller-supplied 8-byte server challenge (injectable for deterministic
    /// tests). `timestamp` is Windows FILETIME (100 ns ticks since 1601).
    public func challengeMessage(negotiateFlags: UInt32,
                                 serverChallenge: Data,
                                 timestamp: UInt64) -> Data {
        precondition(serverChallenge.count == 8)
        let targetInfo = buildTargetInfo(timestamp: timestamp)
        let targetNameBytes = SMBString.utf16le(targetName)

        // Flags we assert back. Always Unicode + NTLM + TargetInfo + ExtSecurity;
        // honor KeyExchange/128/56 if the client asked.
        var flags = NTLMFlag.unicode | NTLMFlag.ntlm | NTLMFlag.targetInfo
                  | NTLMFlag.extendedSessionSecurity | NTLMFlag.requestTarget
                  | NTLMFlag.targetTypeServer
        for f in [NTLMFlag.keyExchange, NTLMFlag.negotiate128, NTLMFlag.negotiate56,
                  NTLMFlag.sign, NTLMFlag.alwaysSign] where (negotiateFlags & f) != 0 {
            flags |= f
        }

        var w = ByteWriter()
        w.bytes(ntlmSignature)
        w.u32(2)                                  // MessageType = CHALLENGE
        // TargetName fields (len, maxlen, offset). Payload laid out after the
        // fixed 56-byte header: [TargetName][TargetInfo].
        let headerLen = 56
        let tnOffset = headerLen
        let tiOffset = tnOffset + targetNameBytes.count
        w.u16(UInt16(targetNameBytes.count)); w.u16(UInt16(targetNameBytes.count)); w.u32(UInt32(tnOffset))
        w.u32(flags)
        w.bytes(serverChallenge)                  // 8 bytes
        w.u64(0)                                  // Reserved
        // TargetInfo fields
        w.u16(UInt16(targetInfo.count)); w.u16(UInt16(targetInfo.count)); w.u32(UInt32(tiOffset))
        w.u64(0)                                  // Version (8 bytes, ignored)
        w.bytes(targetNameBytes)
        w.bytes(targetInfo)
        return w.data
    }

    /// Verify an AUTHENTICATE message (Type 3) against `serverChallenge` (the one
    /// we sent in the matching CHALLENGE). Returns the session base key on success,
    /// or nil if the NTProofStr doesn't match (bad password / tampered token).
    public func verifyAuthenticate(_ message: Data, serverChallenge: Data) -> Data? {
        guard let a = try? parseAuthenticate(message) else { return nil }

        // NTOWFv2 = HMAC-MD5( MD4(UTF16LE(password)), UTF16LE(UPPER(user)+domain) )
        let ntlmHash = MD4.hash(SMBString.utf16le(password))
        let identity = SMBString.utf16le(username.uppercased() + a.domain)
        let ntowfv2 = NTLMCrypto.hmacMD5(key: ntlmHash, identity)

        // NtChallengeResponse = NTProofStr(16) || temp. temp starts after proof.
        guard a.ntResponse.count >= 16 else { return nil }
        let proof = a.ntResponse.prefix(16)
        let temp = a.ntResponse.suffix(from: a.ntResponse.startIndex + 16)

        // NTProofStr = HMAC-MD5( NTOWFv2, serverChallenge || temp )
        var proofInput = Data()
        proofInput.append(serverChallenge)
        proofInput.append(contentsOf: temp)
        let expected = NTLMCrypto.hmacMD5(key: ntowfv2, proofInput)
        guard constantTimeEquals(Data(proof), expected) else { return nil }

        // SessionBaseKey = HMAC-MD5( NTOWFv2, NTProofStr )
        let sessionBaseKey = NTLMCrypto.hmacMD5(key: ntowfv2, Data(proof))

        // If KEY_EXCH, the exported session key is RC4(sessionBaseKey)^-1 of the
        // client's EncryptedRandomSessionKey; otherwise it's the base key itself.
        if (a.flags & NTLMFlag.keyExchange) != 0, !a.encryptedSessionKey.isEmpty {
            return RC4.apply(key: sessionBaseKey, data: a.encryptedSessionKey)
        }
        return sessionBaseKey
    }

    // MARK: TargetInfo

    private func buildTargetInfo(timestamp: UInt64) -> Data {
        let name = SMBString.utf16le(targetName)
        var w = ByteWriter()
        func pair(_ id: AVId, _ value: Data) {
            w.u16(id.rawValue); w.u16(UInt16(value.count)); w.bytes(value)
        }
        pair(.nbDomainName, name)
        pair(.nbComputerName, name)
        var ts = Data(); withUnsafeBytes(of: timestamp.littleEndian) { ts.append(contentsOf: $0) }
        pair(.timestamp, ts)
        w.u16(AVId.eol.rawValue); w.u16(0)   // MsvAvEOL
        return w.data
    }
}

// MARK: - AUTHENTICATE parsing

struct NTLMAuthenticate {
    var flags: UInt32
    var domain: String
    var user: String
    var workstation: String
    var lmResponse: Data
    var ntResponse: Data
    var encryptedSessionKey: Data
}

/// Parse a Type-3 AUTHENTICATE. Each `(len, maxlen, offset)` field points at a
/// payload slice measured from the start of the NTLM message.
func parseAuthenticate(_ msg: Data) throws -> NTLMAuthenticate {
    var r = ByteReader(msg)
    let sig = try r.take(8)
    guard [UInt8](sig) == ntlmSignature else { throw WireError.malformed("not NTLMSSP") }
    guard try r.u32() == 3 else { throw WireError.malformed("not AUTHENTICATE") }

    func field() throws -> Data {
        let len = Int(try r.u16())
        _ = try r.u16()                 // MaxLen
        let off = Int(try r.u32())
        guard len >= 0 else { throw WireError.malformed("negative field len") }
        return len == 0 ? Data() : try r.peek(at: off, len)
    }

    let lm = try field()
    let nt = try field()
    let domainRaw = try field()
    let userRaw = try field()
    let wsRaw = try field()
    let sessionKey = try field()
    let flags = try r.u32()

    return NTLMAuthenticate(
        flags: flags,
        domain: SMBString.decodeUTF16le(domainRaw),
        user: SMBString.decodeUTF16le(userRaw),
        workstation: SMBString.decodeUTF16le(wsRaw),
        lmResponse: lm,
        ntResponse: nt,
        encryptedSessionKey: sessionKey
    )
}

// MARK: - Utilities

func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for (x, y) in zip(a, b) { diff |= x ^ y }
    return diff == 0
}
