// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CryptoKit
import CloudFSCore
@testable import CloudFSCrypto

final class CloudFSCryptoTests: XCTestCase {

    // 32-byte demo master key (== the spike's /tmp/cloudfs-fuse-key value).
    static let demoKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    var demoKey: FilespaceKey { try! FilespaceKey(masterKeyBytes: Data(hexString: Self.demoKeyHex)!) }

    func data(_ hex: String) -> Data { Data(hexString: hex)! }

    // MARK: - Stub (foundation contract) still intact

    func testStubThrowsUnimplemented() async {
        let c = StubBlockCrypto(mode: .aes256gcm)
        XCTAssertEqual(c.mode, .aes256gcm)
        do {
            _ = try await c.encryptBlock(Data([1, 2, 3]), itemID: "a", blockIndex: 0)
            XCTFail("expected unimplemented")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .unimplemented)
        } catch { XCTFail("wrong error: \(error)") }
    }

    // MARK: - GCM round-trip (plaintext -> encrypt -> decrypt == plaintext)

    func testGCMRoundTripVariousSizes() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let sizes = [0, 1, 15, 16, 17, 1024, 65_536, 1 << 20]   // incl. empty + full 1 MiB
        for size in sizes {
            let plain = Data((0..<size).map { UInt8(($0 &* 31 &+ 7) & 0xff) })
            let (ct, hash) = try await crypto.encryptBlock(plain, itemID: "projectA/clip.mov", blockIndex: 3)
            let back = try await crypto.decryptBlock(ct, itemID: "projectA/clip.mov", blockIndex: 3)
            XCTAssertEqual(back, plain, "round-trip failed at size \(size)")
            XCTAssertEqual(hash.hex.count, 64, "SHA-256 hex must be 64 chars")
        }
    }

    func testGCMCompressibleBlockShrinks() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data(repeating: 0x41, count: 1 << 20)        // highly compressible
        let (ct, _) = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 0)
        // Header(9) + nonce(12) + tag(16) = 37 bytes of overhead; LZ4 of 1 MiB of
        // one byte is tiny, so the stored block must be far smaller than plaintext.
        XCTAssertLessThan(ct.count, plain.count / 10, "LZ4 block did not shrink")
        let back = try await crypto.decryptBlock(ct, itemID: "a", blockIndex: 0)
        XCTAssertEqual(back, plain)
    }

    func testGCMIncompressibleBlockRoundTrips() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        // Random (incompressible) — LZ4 bails, stored raw; must still round-trip.
        var plain = Data(count: 1 << 20)
        plain.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        let (ct, _) = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 0)
        let back = try await crypto.decryptBlock(ct, itemID: "a", blockIndex: 0)
        XCTAssertEqual(back, plain)
    }

    // MARK: - Tamper detection (GCM auth failure)

    func testGCMTamperDetectedInCiphertext() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data((0..<4096).map { UInt8($0 & 0xff) })
        var (ct, _) = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 1)
        // Flip a bit deep in the GCM ciphertext body (past the header+nonce).
        ct[ct.count - 20] ^= 0x01
        do {
            _ = try await crypto.decryptBlock(ct, itemID: "a", blockIndex: 1)
            XCTFail("expected GCM authentication failure")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .internal)
            XCTAssertEqual(e.data?["cryptoFailure"], .string("integrity"))
        }
    }

    func testGCMTamperDetectedInHeaderAAD() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data((0..<4096).map { UInt8($0 & 0xff) })
        var (ct, _) = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 1)
        ct[4] ^= 0x01   // flip the flags byte (header is authenticated as AAD)
        do {
            _ = try await crypto.decryptBlock(ct, itemID: "a", blockIndex: 1)
            XCTFail("expected AAD authentication failure")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .internal)
        }
    }

    func testGCMWrongBlockIndexFailsAuth() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data((0..<4096).map { UInt8($0 & 0xff) })
        let (ct, _) = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 1)
        // Block index is part of the key, nonce, AND the AAD — decrypting as a
        // different index must fail (defends against block-reordering attacks).
        do {
            _ = try await crypto.decryptBlock(ct, itemID: "a", blockIndex: 2)
            XCTFail("expected failure decrypting under wrong block index")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .internal)
        }
    }

    func testGCMWrongKeyFailsAuth() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data((0..<4096).map { UInt8($0 & 0xff) })
        let (ct, _) = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 0)
        let otherKey = try FilespaceKey(masterKeyBytes: Data(repeating: 0xAB, count: 32))
        let other = AESGCMBlockCrypto(key: otherKey)
        do {
            _ = try await other.decryptBlock(ct, itemID: "a", blockIndex: 0)
            XCTFail("expected failure decrypting under a different master key")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .internal)
        }
    }

    // MARK: - Content-address stability (determinism + dedup)

    func testGCMContentAddressIsStable() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data((0..<8192).map { UInt8($0 & 0xff) })
        let (ct1, h1) = try await crypto.encryptBlock(plain, itemID: "x/y.mov", blockIndex: 5)
        let (ct2, h2) = try await crypto.encryptBlock(plain, itemID: "x/y.mov", blockIndex: 5)
        XCTAssertEqual(ct1, ct2, "encryption must be deterministic for dedup")
        XCTAssertEqual(h1, h2, "content address must be stable")
        // And the hash is exactly SHA-256(ciphertext) — the content-address rule.
        XCTAssertEqual(h1.hex, Data(SHA256.hash(data: ct1)).hexEncodedString)
        // Sharded object key uses the hash prefix (Types.swift contract).
        XCTAssertEqual(h1.objectKey, "chunks/\(String(h1.hex.prefix(2)))/\(h1.hex)")
    }

    func testGCMDifferentSlotsDifferentAddress() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data((0..<8192).map { UInt8($0 & 0xff) })
        let (_, hBlock0) = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 0)
        let (_, hBlock1) = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 1)
        let (_, hItemB)  = try await crypto.encryptBlock(plain, itemID: "b", blockIndex: 0)
        // Same plaintext but different (item, index) => different key/nonce =>
        // different ciphertext => different content address.
        XCTAssertNotEqual(hBlock0, hBlock1)
        XCTAssertNotEqual(hBlock0, hItemB)
    }

    // MARK: - CTR is DECRYPT-ONLY (read-compat for spike objects)

    /// B6 (cloudfsd audit): the CTR keystream is reused across files (the IV ignores
    /// itemID), so encrypting NEW content under it ships effectively-unencrypted data.
    /// `encryptBlock` must REFUSE; `decryptBlock` still recovers pre-existing objects.
    func testCTREncryptIsRefused() async {
        let crypto = try! AESCTRBlockCrypto(key: demoKey)
        let plain = Data((0..<5000).map { UInt8(($0 &* 13 &+ 1) & 0xff) })
        do {
            _ = try await crypto.encryptBlock(plain, itemID: "a", blockIndex: 2)
            XCTFail("CTR encryptBlock must throw (read-only backend)")
        } catch let e as EngineError {
            XCTAssertEqual(e.kind, .invalidParams)
        } catch { XCTFail("wrong error: \(error)") }
    }

    // MARK: - CROSS-COMPAT decrypt vectors vs fuse-spike/obj-encrypt.mjs (Node aes-256-ctr)
    // Reference ciphertext generated by Node's createCipheriv("aes-256-ctr", KEY, IV0)
    // with the spike's demo key. We can no longer ENCRYPT (read-only), so interop is
    // proven by DECRYPTING the Node-produced ciphertext back to its plaintext.

    func testCTRDecryptsNodeVectorBlock0() async throws {
        let crypto = try AESCTRBlockCrypto(key: demoKey)
        let pt0 = data("636c6f75646673207370696b652043545220626c6f636b203020766563746f7220e2809420696e7465726f7020636865636b2039383736353433323130")
        let expectedCT0 = data("d2e971683bd388cc6060879ffb1b33adf3148fb4c814b10a6b5b118695737f3eeb10b23af8748d75f424e64e3c9b9bcc7158ccfcbf7d12ec0490759aa2")
        // Decrypt of the Node-produced ciphertext recovers the plaintext (interop).
        let back = try await crypto.decryptBlock(expectedCT0, itemID: "spike", blockIndex: 0)
        XCTAssertEqual(back, pt0)
    }

    func testCTRDecryptsNodeVectorBlock1() async throws {
        // Block index 1 starts at CTR counter = blockSize/16 = 65536 — the spike's
        // "block i's CTR counter = i * 65536". The reference slice was cut from a
        // whole-file Node CTR stream at byte offset 1 MiB.
        let crypto = try AESCTRBlockCrypto(key: demoKey)
        let pt1 = data("030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bc")
        let expectedCT1 = data("c8d510009436cd237f36853c6aea54a8747891407110b8cd6ba9a4d4271e07a6c07ebeb3e3c27eb4227b562ca3567580c6c47bcd9f3aa502b9bf8064b95cf2d3")
        let back = try await crypto.decryptBlock(expectedCT1, itemID: "spike", blockIndex: 1)
        XCTAssertEqual(back, pt1)
    }

    // MARK: - Key handling

    func testKeyFileLoaderMatchesRawBytes() throws {
        // The spike key-file format: 64 hex chars + trailing newline. Audit B15: the loader now
        // REJECTS a group/other-readable key file, so write it 0600 (the correct posture).
        let tmp = NSTemporaryDirectory() + "cloudfs-test-key-\(UUID().uuidString)"
        try (Self.demoKeyHex + "\n").write(toFile: tmp, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let fromFile = try FilespaceKey(hexKeyFile: tmp)
        XCTAssertEqual(fromFile.masterRawBytes, Data(hexString: Self.demoKeyHex))
    }

    /// Audit B15: a master key file readable by group/other is REJECTED (a leaked master key
    /// defeats the whole encrypted-at-rest design).
    func testKeyFileRejectsWorldReadableMode() throws {
        let tmp = NSTemporaryDirectory() + "cloudfs-test-key-\(UUID().uuidString)"
        try (Self.demoKeyHex + "\n").write(toFile: tmp, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: tmp)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        XCTAssertThrowsError(try FilespaceKey(hexKeyFile: tmp)) { err in
            XCTAssertEqual((err as? EngineError)?.kind, .invalidParams)
        }
    }

    func testRejectsWrongLengthKey() {
        XCTAssertThrowsError(try FilespaceKey(masterKeyBytes: Data(repeating: 0, count: 16))) { err in
            XCTAssertEqual((err as? EngineError)?.kind, .invalidParams)
        }
    }

    // MARK: - Audit B15: bearer-token loader (Keychain-preferred, mode-checked file fallback)

    /// A 0600 token file loads (trimmed of whitespace).
    func testBearerTokenFromFile0600Loads() throws {
        let tmp = NSTemporaryDirectory() + "cloudfs-test-tok-\(UUID().uuidString)"
        try ("svc.tok.abc\n").write(toFile: tmp, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        XCTAssertEqual(try BearerTokenStore.fromFile(tmp), "svc.tok.abc")
        // `load` with no Keychain item falls through to the file and reports source=file.
        let loaded = try BearerTokenStore.load(filespace: "no-such-fs-\(UUID().uuidString)", filePath: tmp)
        XCTAssertEqual(loaded.token, "svc.tok.abc")
        XCTAssertEqual(loaded.source, "file")
    }

    /// A group/other-readable token file is REJECTED (a leaked bearer token authenticates every call).
    func testBearerTokenRejectsWorldReadableMode() throws {
        let tmp = NSTemporaryDirectory() + "cloudfs-test-tok-\(UUID().uuidString)"
        try ("svc.tok.leaky\n").write(toFile: tmp, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: tmp)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        XCTAssertThrowsError(try BearerTokenStore.fromFile(tmp)) { err in
            XCTAssertEqual((err as? EngineError)?.kind, .invalidParams)
        }
    }

    /// No source configured ⇒ empty token (anonymous; the gateway then rejects it — never a silent
    /// world-readable secret).
    func testBearerTokenNoSourceYieldsEmpty() throws {
        let loaded = try BearerTokenStore.load(filespace: nil, filePath: nil)
        XCTAssertEqual(loaded.token, "")
        XCTAssertEqual(loaded.source, "none")
    }

    /// An absent file path is nil (not an error) so the loader cleanly falls through to "none".
    func testBearerTokenAbsentFileIsNil() throws {
        XCTAssertNil(try BearerTokenStore.fromFile(NSTemporaryDirectory() + "cloudfs-absent-\(UUID().uuidString)"))
    }

    func testHKDFBlockKeysAreDistinctAndDeterministic() {
        let k = demoKey
        let d1 = Data(SHA256.hash(data: Data("content-one".utf8)))
        let d2 = Data(SHA256.hash(data: Data("content-two".utf8)))
        func key(_ id: InodeID, _ i: Int, _ d: Data) -> Data {
            k.deriveBlockKey(itemID: id, blockIndex: i, contentDigest: d).withUnsafeBytes { Data($0) }
        }
        let a0 = key("a", 0, d1)
        let a0b = key("a", 0, d1)
        let a1 = key("a", 1, d1)
        let b0 = key("b", 0, d1)
        XCTAssertEqual(a0, a0b, "HKDF derivation must be deterministic")
        XCTAssertNotEqual(a0, a1, "distinct block index ⇒ distinct key")
        XCTAssertNotEqual(a0, b0, "distinct itemID ⇒ distinct key")
        XCTAssertNotEqual(a0, k.masterRawBytes, "derived key must not equal the master")
        // FINDING 2: distinct CONTENT in the SAME (itemID, blockIndex) slot ⇒
        // distinct key (so the deterministic per-slot nonce is never reused with
        // two different plaintexts).
        XCTAssertNotEqual(a0, key("a", 0, d2), "distinct content ⇒ distinct key (no nonce reuse)")
    }

    // MARK: - FINDING 2: content-bound key prevents GCM (key,nonce) reuse on in-place edits

    /// Two DISTINCT plaintexts written to the SAME (itemID, blockIndex) slot must
    /// produce ciphertexts encrypted under DISTINCT keys+nonces — i.e. the keystream
    /// must NOT be reused. We assert this directly via the derived key (distinct)
    /// and indirectly via the produced ciphertext bodies (no shared keystream).
    func testGCMInPlaceEditDoesNotReuseKeyOrNonce() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let item: InodeID = "projectA/edit.mov"
        let idx = 7
        // Two distinct INCOMPRESSIBLE plaintexts (so LZ4 bails → stored raw → the
        // GCM body is the plaintext XOR keystream, exposing any keystream reuse).
        var p1 = Data(count: 4096); p1.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        var p2 = Data(count: 4096); p2.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }

        let (ct1, h1) = try await crypto.encryptBlock(p1, itemID: item, blockIndex: idx)
        let (ct2, h2) = try await crypto.encryptBlock(p2, itemID: item, blockIndex: idx)

        // Different content ⇒ different content address (the new object an in-place
        // edit produces — the old slot ciphertext is NOT reproduced).
        XCTAssertNotEqual(h1, h2)

        // The derived KEYS for the two contents differ (the core of the fix).
        let k1 = demoKey.deriveBlockKey(itemID: item, blockIndex: idx,
            contentDigest: Data(SHA256.hash(data: p1))).withUnsafeBytes { Data($0) }
        let k2 = demoKey.deriveBlockKey(itemID: item, blockIndex: idx,
            contentDigest: Data(SHA256.hash(data: p2))).withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(k1, k2, "same slot, different content ⇒ different key")

        // Keystream-reuse check: with a REUSED (key,nonce), ct1 ⊕ ct2 == p1 ⊕ p2
        // over the raw-stored GCM body. Extract each body (skip the header + 12-byte
        // nonce, drop the 16-byte tag) and confirm that relation does NOT hold.
        let header = AESGCMBlockCrypto.headerLen
        func body(_ ct: Data) -> [UInt8] {
            Array(ct[(ct.startIndex + header + 12)..<(ct.endIndex - 16)])
        }
        let b1 = body(ct1), b2 = body(ct2)
        XCTAssertEqual(b1.count, p1.count); XCTAssertEqual(b2.count, p2.count)
        let ctXor = zip(b1, b2).map { $0 ^ $1 }
        let ptXor = zip(Array(p1), Array(p2)).map { $0 ^ $1 }
        XCTAssertNotEqual(ctXor, ptXor, "ct1⊕ct2 must NOT equal p1⊕p2 — that would prove keystream (key,nonce) reuse")

        // Both still round-trip correctly.
        let back1 = try await crypto.decryptBlock(ct1, itemID: item, blockIndex: idx)
        let back2 = try await crypto.decryptBlock(ct2, itemID: item, blockIndex: idx)
        XCTAssertEqual(back1, p1)
        XCTAssertEqual(back2, p2)
    }

    /// Determinism + content-addressed dedup preserved: IDENTICAL plaintext in the
    /// same slot still yields one identical object (same key→nonce→ciphertext→hash).
    func testGCMIdenticalContentStillDedupsAfterContentBinding() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data((0..<8192).map { UInt8(($0 &* 37 &+ 11) & 0xff) })
        let (ct1, h1) = try await crypto.encryptBlock(plain, itemID: "p/a.mov", blockIndex: 2)
        let (ct2, h2) = try await crypto.encryptBlock(plain, itemID: "p/a.mov", blockIndex: 2)
        XCTAssertEqual(ct1, ct2, "identical content must still be deterministic (dedup)")
        XCTAssertEqual(h1, h2, "identical content must dedup to one content address")
    }

    // MARK: - B6: keyed content digest (zero-knowledge header) + v2 read-compat

    /// The header's content digest must NOT be a bare SHA-256(plaintext): that was a
    /// per-block plaintext fingerprint in the clear that let a bucket-credential
    /// holder confirmation-attack known content. After B6 the digest is a KEYED MAC,
    /// so a holder who lacks the master key cannot reproduce or recognize it.
    func testGCMHeaderDigestIsKeyedNotBareSHA256() async throws {
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let plain = Data((0..<4096).map { UInt8(($0 &* 17 &+ 3) & 0xff) })
        let (ct, _) = try await crypto.encryptBlock(plain, itemID: "p/clip.mov", blockIndex: 4)
        // Magic is v3.
        XCTAssertEqual(Array(ct.prefix(4)), Array("CFB3".utf8))
        // Extract the 32-byte digest the bucket would see (header offset 9..41).
        let storedDigest = ct.subdata(in: (ct.startIndex + 9)..<(ct.startIndex + 9 + 32))
        let bareSHA = Data(SHA256.hash(data: plain))
        XCTAssertNotEqual(storedDigest, bareSHA,
            "header digest must NOT be a bare SHA-256(plaintext) — that breaks zero-knowledge")
        // The stored digest IS the keyed MAC (which the holder of the master key can
        // recompute, but a bucket-only adversary cannot).
        XCTAssertEqual(storedDigest, demoKey.contentDigest(plain))
    }

    /// Different master keys produce different header digests for the SAME plaintext —
    /// so the stored digest reveals nothing about the content to anyone without the key.
    func testGCMHeaderDigestVariesByMasterKey() async throws {
        let other = try FilespaceKey(masterKeyBytes: Data((0..<32).map { UInt8(($0 &+ 99) & 0xff) }))
        let plain = Data((0..<2048).map { UInt8($0 & 0xff) })
        let d1 = demoKey.contentDigest(plain)
        let d2 = other.contentDigest(plain)
        XCTAssertNotEqual(d1, d2, "keyed digest must differ across filespace master keys")
    }

    /// Read-compat: a v2 (CFB2, bare-SHA-256-digest) block produced by the OLD wire
    /// format must still decrypt under the v3-capable backend, so an in-place rollout
    /// doesn't strand already-uploaded blocks.
    func testGCMDecryptsLegacyCFB2Block() async throws {
        // Hand-build a v2 block exactly as the pre-B6 encoder did: magic "CFB2",
        // digest = bare SHA-256(plaintext), key derived from that digest.
        let crypto = AESGCMBlockCrypto(key: demoKey)
        let item: InodeID = "legacy/old.mov"
        let idx = 5
        let plain = Data((0..<3000).map { UInt8(($0 &* 7 &+ 1) & 0xff) })
        let legacy = try Self.makeLegacyV2Block(plain, key: demoKey, itemID: item, blockIndex: idx)
        XCTAssertEqual(Array(legacy.prefix(4)), Array("CFB2".utf8))
        let back = try await crypto.decryptBlock(legacy, itemID: item, blockIndex: idx)
        XCTAssertEqual(back, plain, "v2 (legacy bare-SHA-256) block must still decrypt")
    }

    /// Build a CFB2 block the way the pre-B6 encoder did (bare SHA-256 digest), so the
    /// read-compat test has a real legacy object to decrypt.
    private static func makeLegacyV2Block(_ plaintext: Data, key: FilespaceKey,
                                          itemID: InodeID, blockIndex: Int) throws -> Data {
        var flags: UInt8 = 0
        let payload: Data
        if let comp = LZ4.compress(plaintext) { payload = comp; flags |= AESGCMBlockCrypto.flagLZ4 }
        else { payload = plaintext }
        let digest = Data(SHA256.hash(data: plaintext))   // v2: bare SHA-256
        var header = Data(Array("CFB2".utf8))
        header.append(flags)
        var len = UInt32(plaintext.count).bigEndian
        withUnsafeBytes(of: &len) { header.append(contentsOf: $0) }
        header.append(digest)
        let symKey = key.deriveBlockKey(itemID: itemID, blockIndex: blockIndex, contentDigest: digest)
        // Nonce derivation is unchanged across v2/v3 — recompute it the same way.
        let info = Data("cloudfs/block-nonce/v1/\(itemID.rawValue)/\(blockIndex)".utf8)
        let nonceBytes = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key.master,
            salt: Data("cloudfs-filespace-block-nonce".utf8),
            info: info, outputByteCount: 12).withUnsafeBytes { Data($0) }
        let nonce = try AES.GCM.Nonce(data: nonceBytes)
        var aad = header
        var bi = UInt64(blockIndex).bigEndian
        withUnsafeBytes(of: &bi) { aad.append(contentsOf: $0) }
        let sealed = try AES.GCM.seal(payload, using: symKey, nonce: nonce, authenticating: aad)
        return header + sealed.combined!
    }

    // MARK: - Factory

    func testFactoryBuildsBackends() throws {
        let gcm = try makeBlockCrypto(mode: .aes256gcm, key: demoKey)
        let ctr = try makeBlockCrypto(mode: .aes256ctr, key: demoKey)
        XCTAssertEqual(gcm.mode, .aes256gcm)
        XCTAssertEqual(ctr.mode, .aes256ctr)
    }
}
