// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB — just enough SPNEGO (RFC 4178) DER to carry NTLMSSP tokens through
// SMB2 SESSION_SETUP. We support exactly one mechanism (NTLMSSP), so the DER we
// emit is minimal and the DER we parse only needs to surface the wrapped NTLMSSP
// blob and (on the final leg) the negotiation result.
//
// Structure recap:
//   NegotiationToken ::= CHOICE {
//     negTokenInit [0] NegTokenInit,     -- first client token, and our NEGOTIATE hint
//     negTokenResp [1] NegTokenResp }    -- every subsequent token
//   NegTokenInit ::= SEQUENCE { mechTypes [0] MechTypeList, ... mechToken [2] OCTET STRING }
//   NegTokenResp ::= SEQUENCE { negState [0] ENUM, supportedMech [1] OID,
//                               responseToken [2] OCTET STRING, mechListMIC [3] OCTET STRING }

import Foundation

// MARK: - Minimal DER

enum DER {
    // Tag bytes we use.
    static let sequence: UInt8   = 0x30
    static let octetString: UInt8 = 0x04
    static let oid: UInt8         = 0x06
    static let enumerated: UInt8  = 0x0A
    static func contextConstructed(_ n: UInt8) -> UInt8 { 0xA0 | n }  // [n] constructed
    static let appConstructed0: UInt8 = 0x60                          // [APPLICATION 0] (GSSAPI wrapper)

    /// Encode a length in DER definite form.
    static func length(_ n: Int) -> Data {
        if n < 0x80 { return Data([UInt8(n)]) }
        var bytes: [UInt8] = []
        var v = n
        while v > 0 { bytes.insert(UInt8(v & 0xFF), at: 0); v >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    /// tag + length + value.
    static func tlv(_ tag: UInt8, _ value: Data) -> Data {
        var out = Data([tag]); out.append(length(value.count)); out.append(value); return out
    }

    /// A TLV parser cursor.
    struct Parser {
        let data: Data
        var offset: Int
        init(_ d: Data) { data = d; offset = d.startIndex }
        var remaining: Int { data.endIndex - offset }

        mutating func read() throws -> (tag: UInt8, value: Data) {
            guard remaining >= 2 else { throw WireError.underflow }
            let tag = data[offset]; offset += 1
            var len = Int(data[offset]); offset += 1
            if len & 0x80 != 0 {
                let n = len & 0x7F
                guard n > 0, n <= 4, remaining >= n else { throw WireError.malformed("bad DER length") }
                len = 0
                for _ in 0..<n { len = (len << 8) | Int(data[offset]); offset += 1 }
            }
            guard remaining >= len else { throw WireError.underflow }
            let value = data.subdata(in: offset..<(offset + len))
            offset += len
            return (tag, value)
        }
    }
}

// MARK: - OIDs

enum SPNEGOOID {
    /// SPNEGO mechanism  1.3.6.1.5.5.2
    static let spnego = Data([0x2B, 0x06, 0x01, 0x05, 0x05, 0x02])
    /// NTLMSSP           1.3.6.1.4.1.311.2.2.10
    static let ntlmssp = Data([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A])
}

// MARK: - SPNEGO

public enum SPNEGO {
    /// The SPNEGO `negTokenInit` we put in the NEGOTIATE response security buffer:
    /// advertises NTLMSSP as the only supported mechanism (the client then sends
    /// its NTLMSSP NEGOTIATE inside a matching negTokenInit).
    public static func negotiateHint() -> Data {
        let mechType = DER.tlv(DER.oid, SPNEGOOID.ntlmssp)
        let mechTypeList = DER.tlv(DER.sequence, mechType)
        let mechTypes = DER.tlv(DER.contextConstructed(0), mechTypeList)
        let negTokenInit = DER.tlv(DER.sequence, mechTypes)
        let choice = DER.tlv(DER.contextConstructed(0), negTokenInit)   // [0] negTokenInit
        // GSSAPI wrapper: [APPLICATION 0] { SPNEGO-OID, NegotiationToken }
        var inner = DER.tlv(DER.oid, SPNEGOOID.spnego)
        inner.append(choice)
        return DER.tlv(DER.appConstructed0, inner)
    }

    /// Extract the wrapped NTLMSSP token from a SESSION_SETUP security buffer,
    /// whether it arrives as a GSSAPI-wrapped negTokenInit (first leg) or a bare
    /// negTokenResp (later legs). Falls back to a raw NTLMSSP blob (some clients
    /// send raw NTLMSSP after the first exchange).
    public static func extractNTLM(_ blob: Data) -> Data? {
        if isRawNTLM(blob) { return blob }
        // Unwrap optional [APPLICATION 0] GSSAPI header.
        var top = blob
        if let first = blob.first, first == DER.appConstructed0 {
            var p = DER.Parser(blob)
            guard let (_, appVal) = try? p.read() else { return nil }
            // appVal = OID(spnego) + NegotiationToken. Skip the OID TLV.
            var q = DER.Parser(appVal)
            guard let (oidTag, _) = try? q.read(), oidTag == DER.oid else { return nil }
            top = appVal.subdata(in: q.offset..<appVal.endIndex)
        }
        return findNTLMToken(in: top)
    }

    /// Wrap our NTLMSSP CHALLENGE in a negTokenResp with negState =
    /// accept-incomplete (1), so the client proceeds to send AUTHENTICATE.
    public static func challengeResponse(ntlmChallenge: Data) -> Data {
        let negState = DER.tlv(DER.contextConstructed(0), DER.tlv(DER.enumerated, Data([0x01])))
        let supportedMech = DER.tlv(DER.contextConstructed(1), DER.tlv(DER.oid, SPNEGOOID.ntlmssp))
        let responseToken = DER.tlv(DER.contextConstructed(2), DER.tlv(DER.octetString, ntlmChallenge))
        var seqBody = negState; seqBody.append(supportedMech); seqBody.append(responseToken)
        let negTokenResp = DER.tlv(DER.sequence, seqBody)
        return DER.tlv(DER.contextConstructed(1), negTokenResp)   // [1] negTokenResp
    }

    /// The final negTokenResp announcing accept-completed (0) after AUTHENTICATE
    /// verifies. Sent in the success SESSION_SETUP response security buffer.
    public static func acceptCompleted() -> Data {
        let negState = DER.tlv(DER.contextConstructed(0), DER.tlv(DER.enumerated, Data([0x00])))
        let negTokenResp = DER.tlv(DER.sequence, negState)
        return DER.tlv(DER.contextConstructed(1), negTokenResp)
    }

    // MARK: helpers

    static func isRawNTLM(_ d: Data) -> Bool {
        d.count >= 8 && [UInt8](d.prefix(8)) == ntlmSignature
    }

    /// Walk the SPNEGO DER tree and return the first OCTET STRING whose contents
    /// begin with the NTLMSSP signature. Robust to negTokenInit vs negTokenResp
    /// layout differences without fully modeling either.
    static func findNTLMToken(in data: Data) -> Data? {
        var p = DER.Parser(data)
        while p.remaining > 0 {
            guard let (tag, value) = try? p.read() else { return nil }
            if tag == DER.octetString, isRawNTLM(value) { return value }
            // Recurse into constructed tags (SEQUENCE / [n] context).
            let constructed = (tag & 0x20) != 0
            if constructed, let found = findNTLMToken(in: value) { return found }
        }
        return nil
    }
}
