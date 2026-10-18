// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB P3: real timestamps — the SMBAttrs real/synth selection, and the
// backward-compat guarantee that ItemMetadata still decodes JSON that predates
// the createdAt/modifiedAt keys (the appex JSON-RPC compat requirement).

import XCTest
import Foundation
import CloudFSCore
@testable import CloudFSSMB

final class TimestampTests: XCTestCase {
    func testRealTimePreferredOverSynth() {
        let modified = Date(timeIntervalSince1970: 1_700_000_000)   // 2023-11-14
        let real = SMBAttrs.time(modified, contentVersion: "cv-x")
        let synth = SMBAttrs.time(nil, contentVersion: "cv-x")
        XCTAssertNotEqual(real, synth)
        // Real FILETIME must decode back to the same wall-clock second.
        let epochDelta = 11_644_473_600.0
        let secs = Double(real) / 10_000_000.0 - epochDelta
        XCTAssertEqual(secs, 1_700_000_000, accuracy: 1.0)
    }

    func testSynthFallbackIsStablePerContentVersion() {
        XCTAssertEqual(SMBAttrs.time(nil, contentVersion: "cv-a"),
                       SMBAttrs.time(nil, contentVersion: "cv-a"))
        XCTAssertNotEqual(SMBAttrs.time(nil, contentVersion: "cv-a"),
                          SMBAttrs.time(nil, contentVersion: "cv-b"))
    }

    func testTimesUsesModifiedForWriteChangeAndCreatedForCreation() {
        let created = Date(timeIntervalSince1970: 1_600_000_000)
        let modified = Date(timeIntervalSince1970: 1_700_000_000)
        let ts = SMBAttrs.times(created: created, modified: modified, contentVersion: "cv")
        XCTAssertEqual(ts.write, ts.change)
        XCTAssertEqual(ts.write, SMBAttrs.time(modified, contentVersion: "cv"))
        XCTAssertEqual(ts.creation, SMBAttrs.time(created, contentVersion: "cv"))
        XCTAssertNotEqual(ts.creation, ts.write)
    }

    /// The load-bearing backward-compat test: an ItemMetadata JSON payload written
    /// by a pre-v13 encoder (no createdAt/modifiedAt keys) must still decode, with
    /// the timestamps coming through as nil.
    func testItemMetadataDecodesLegacyJSONWithoutTimestamps() throws {
        let legacy = """
        {"id":"root/file.txt","parent":"root","name":"file.txt","isDir":false,
         "size":42,"contentVersion":"cv-1","metadataVersion":"3"}
        """.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(ItemMetadata.self, from: legacy)
        XCTAssertEqual(decoded.name, "file.txt")
        XCTAssertNil(decoded.createdAt)
        XCTAssertNil(decoded.modifiedAt)
    }

    func testItemMetadataRoundTripsTimestamps() throws {
        let m = ItemMetadata(id: "root/a", parent: "root", name: "a", isDir: false, size: 1,
                             contentVersion: "cv", metadataVersion: "1",
                             createdAt: Date(timeIntervalSince1970: 1000),
                             modifiedAt: Date(timeIntervalSince1970: 2000))
        let round = try JSONDecoder().decode(ItemMetadata.self,
                                             from: try JSONEncoder().encode(m))
        XCTAssertEqual(round.createdAt, m.createdAt)
        XCTAssertEqual(round.modifiedAt, m.modifiedAt)
    }
}
