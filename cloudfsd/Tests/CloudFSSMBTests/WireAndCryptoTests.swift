// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB P0 tests: wire codec round-trips + the legacy/NTLM crypto vectors.

import XCTest
import Foundation
@testable import CloudFSSMB

final class WireCodecTests: XCTestCase {
    func testDirectTCPFrameRoundTrip() {
        for len in [0, 1, 64, 1024, 0xFF_FFFF] {
            let prefix = DirectTCP.frame(length: len)
            XCTAssertEqual(prefix.count, 4)
            XCTAssertEqual(DirectTCP.length(prefix: prefix), len)
        }
        // Reserved top byte set → rejected.
        XCTAssertNil(DirectTCP.length(prefix: Data([0x01, 0, 0, 0])))
    }

    func testByteWriterReaderScalars() throws {
        var w = ByteWriter()
        w.u8(0xAB); w.u16(0x1234); w.u32(0xDEAD_BEEF); w.u64(0x0102_0304_0506_0708)
        var r = ByteReader(w.data)
        XCTAssertEqual(try r.u8(), 0xAB)
        XCTAssertEqual(try r.u16(), 0x1234)
        XCTAssertEqual(try r.u32(), 0xDEAD_BEEF)
        XCTAssertEqual(try r.u64(), 0x0102_0304_0506_0708)
        XCTAssertEqual(r.remaining, 0)
        XCTAssertThrowsError(try r.u8())
    }

    func testPatchU32BackfillsReservedSlot() throws {
        var w = ByteWriter()
        w.u32(0xAAAA_AAAA)
        let slot = w.reserveU32()
        w.u32(0xBBBB_BBBB)
        w.patchU32(at: slot, 0x1122_3344)
        var r = ByteReader(w.data)
        XCTAssertEqual(try r.u32(), 0xAAAA_AAAA)
        XCTAssertEqual(try r.u32(), 0x1122_3344)
        XCTAssertEqual(try r.u32(), 0xBBBB_BBBB)
    }

    func testUTF16NFCRoundTrip() {
        // "é" as NFD (e + combining acute) must normalize to NFC single codepoint.
        let nfd = "e\u{0301}"
        let bytes = SMBString.utf16le(nfd)
        XCTAssertEqual(bytes.count, 2, "é should be one UTF-16 unit after NFC")
        XCTAssertEqual(SMBString.decodeUTF16le(bytes), "é")
    }

    func testHeaderEncodeDecodeSync() throws {
        let h = SMB2Header(command: .create, messageId: 42, creditCharge: 2,
                           creditReqGrant: 16, status: 0, flags: [.serverToRedir],
                           nextCommand: 0, treeId: 7, sessionId: 0xABCD)
        var w = ByteWriter()
        h.encode(into: &w)
        XCTAssertEqual(w.count, SMB2Header.size)
        var r = ByteReader(w.data)
        let d = try SMB2Header.decode(&r)
        XCTAssertEqual(d.command, .create)
        XCTAssertEqual(d.messageId, 42)
        XCTAssertEqual(d.creditCharge, 2)
        XCTAssertEqual(d.treeId, 7)
        XCTAssertEqual(d.sessionId, 0xABCD)
    }

    func testHeaderRejectsBadProtocolId() {
        var w = ByteWriter()
        w.bytes([0xFF, 0x53, 0x4D, 0x42]); w.u16(64); w.zeros(56)
        var r = ByteReader(w.data)
        XCTAssertThrowsError(try SMB2Header.decode(&r))
    }
}

final class LegacyCryptoTests: XCTestCase {
    // RFC 1320 appendix A.5 test suite.
    func testMD4RFC1320Vectors() {
        func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
        XCTAssertEqual(hex(MD4.hash(Data("".utf8))), "31d6cfe0d16ae931b73c59d7e0c089c0")
        XCTAssertEqual(hex(MD4.hash(Data("a".utf8))), "bde52cb31de33e46245e05fbdbd6fb24")
        XCTAssertEqual(hex(MD4.hash(Data("abc".utf8))), "a448017aaf21d8525fc10ae87aa6729d")
        XCTAssertEqual(hex(MD4.hash(Data("message digest".utf8))), "d9130a8164549fe818874806e1c7014b")
        XCTAssertEqual(hex(MD4.hash(Data("abcdefghijklmnopqrstuvwxyz".utf8))),
                       "d79e1c308aa5bbcdeea8ed63df412da9")
        XCTAssertEqual(hex(MD4.hash(Data("12345678901234567890123456789012345678901234567890123456789012345678901234567890".utf8))),
                       "e33b4ddc9c38f2199c3e7b164fcc0536")
    }

    // RFC 6229 RC4 test vector: key "Key", first bytes of keystream on zeros.
    func testRC4KnownAnswer() {
        // Wikipedia/known vector: key="Key", plaintext="Plaintext" → BBF316E8D940AF0AD3
        let ct = RC4.apply(key: Data("Key".utf8), data: Data("Plaintext".utf8))
        XCTAssertEqual(ct.map { String(format: "%02X", $0) }.joined(), "BBF316E8D940AF0AD3")
        // Symmetric: decrypting the ciphertext returns the plaintext.
        let pt = RC4.apply(key: Data("Key".utf8), data: ct)
        XCTAssertEqual(String(decoding: pt, as: UTF8.self), "Plaintext")
    }
}

final class NTLMTests: XCTestCase {
    /// End-to-end: build a CHALLENGE, have a reference client compute the NTLMv2
    /// AUTHENTICATE with the right password, and confirm the server accepts it and
    /// rejects a wrong password. Uses the same primitives so this is a closed-loop
    /// correctness check of the verifier's field layout and math.
    func testNTLMv2RoundTripAcceptsAndRejects() throws {
        let server = NTLMServer(username: "cfs-user", password: "s3cr3t-pass", targetName: "CLOUDFS")
        let serverChallenge = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let clientChallenge = Data([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11])
        let timestamp: UInt64 = 132_000_000_000_000_000

        let challenge = server.challengeMessage(negotiateFlags: NTLMFlag.unicode | NTLMFlag.ntlm | NTLMFlag.keyExchange,
                                                 serverChallenge: serverChallenge,
                                                 timestamp: timestamp)
        XCTAssertEqual([UInt8](challenge.prefix(8)), Array("NTLMSSP\0".utf8))

        // Reference client AUTHENTICATE with correct password.
        let good = ReferenceNTLMClient.authenticate(username: "cfs-user", password: "s3cr3t-pass",
                                                     domain: "", serverChallenge: serverChallenge,
                                                     clientChallenge: clientChallenge, timestamp: timestamp)
        XCTAssertNotNil(server.verifyAuthenticate(good, serverChallenge: serverChallenge),
                        "correct password must verify")

        // Wrong password must fail.
        let bad = ReferenceNTLMClient.authenticate(username: "cfs-user", password: "WRONG",
                                                   domain: "", serverChallenge: serverChallenge,
                                                   clientChallenge: clientChallenge, timestamp: timestamp)
        XCTAssertNil(server.verifyAuthenticate(bad, serverChallenge: serverChallenge),
                     "wrong password must be rejected")
    }
}

final class SPNEGOTests: XCTestCase {
    func testNegotiateHintContainsNTLMSSPOID() {
        let hint = SPNEGO.negotiateHint()
        // The NTLMSSP OID bytes must appear somewhere in the DER.
        XCTAssertNotNil(hint.range(of: SPNEGOOID.ntlmssp))
    }

    func testExtractNTLMFromRawAndWrapped() {
        let ntlm = Data("NTLMSSP\u{0}".utf8) + Data([0x01, 0, 0, 0])  // fake NEGOTIATE
        // Raw passes through.
        XCTAssertEqual(SPNEGO.extractNTLM(ntlm), ntlm)
        // Wrapped in a negTokenResp responseToken → extracted.
        let wrapped = SPNEGO.challengeResponse(ntlmChallenge: ntlm)
        XCTAssertEqual(SPNEGO.extractNTLM(wrapped), ntlm)
    }

    func testAcceptCompletedParses() throws {
        let tok = SPNEGO.acceptCompleted()
        var p = DER.Parser(tok)
        let (tag, _) = try p.read()
        XCTAssertEqual(tag, DER.contextConstructed(1))  // [1] negTokenResp
    }
}
