// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
@testable import CloudFSCore

final class CloudFSCoreTests: XCTestCase {

    func testErrorCodeMappingMatchesCLIExitCodes() {
        // The frozen 1:1 map (CONTROL-API.md §2 / cli/src/exit-codes.ts).
        XCTAssertEqual(EngineError(.notConnected).exitCode, 23)
        XCTAssertEqual(EngineError(.notFound).exitCode, 20)
        XCTAssertEqual(EngineError(.conflict).exitCode, 21)
        XCTAssertEqual(EngineError(.locked).exitCode, 22)
        XCTAssertEqual(EngineError(.permissionDenied).exitCode, 30)
        XCTAssertEqual(EngineError(.gatewayError).exitCode, 40)
        XCTAssertEqual(EngineError(.networkError).exitCode, 41)
        XCTAssertEqual(EngineError(.syncTimeout).exitCode, 50)
        XCTAssertEqual(EngineError(.syncFailed).exitCode, 51)
        XCTAssertEqual(EngineError(.invalidParams).exitCode, 2)
        XCTAssertEqual(EngineError(.internal).exitCode, 1)
    }

    func testJSONRPCCodesAreStable() {
        XCTAssertEqual(EngineError(.conflict).jsonrpcCode, -32021)
        XCTAssertEqual(EngineError(.syncTimeout).jsonrpcCode, -32050)
        XCTAssertEqual(EngineError(.invalidParams).jsonrpcCode, -32602)
    }

    func testBlockHashObjectKeyIsSharded() {
        let h = BlockHash(hex: "abcdef0123456789")
        XCTAssertEqual(h.objectKey, "chunks/ab/abcdef0123456789")
    }

    func testControlMethodsRoundTripRawValues() {
        // The closed method set must encode to the wire names in CONTROL-API.md.
        XCTAssertEqual(ControlMethod.cacheSetSize.rawValue, "cache.setSize")
        XCTAssertEqual(ControlMethod.pinList.rawValue, "pin.list")
        XCTAssertEqual(ControlMethod.syncState.rawValue, "sync.state")
        XCTAssertEqual(ControlMethod.eventsSubscribe.rawValue, "events.subscribe")
    }

    func testRPCRequestCodableRoundTrip() throws {
        let req = RPCRequest(id: .number(7), method: "cache.setSize",
                             params: .object(["filespace": .string("fs1"), "bytes": .int(1024)]))
        let data = try JSONEncoder().encode(req)
        let back = try JSONDecoder().decode(RPCRequest.self, from: data)
        XCTAssertEqual(back.jsonrpc, "2.0")
        XCTAssertEqual(back.method, "cache.setSize")
        XCTAssertEqual(back.id, .number(7))
    }

    func testCacheInfoCodableMatchesShape() throws {
        let info = CacheInfo(filespace: "fs1", location: "/cache", sizeBytes: 1, usedBytes: 1,
                             pinnedBytes: 0, maxBytes: 10, freeOnVolumeBytes: 100, hitRate: 0.5)
        let back = try JSONDecoder().decode(CacheInfo.self, from: JSONEncoder().encode(info))
        XCTAssertEqual(info, back)
    }

    func testEventNotificationMethodNames() {
        let t = EventNotification.transfer(filespace: "f",
            transfer: Transfer(id: "1", filespace: "f", path: "/a", direction: .download,
                               bytesDone: 0, bytesTotal: 1, state: .active))
        XCTAssertEqual(t.method, "transfer")
        XCTAssertEqual(EventNotification.cache(filespace: "f",
            cache: CacheInfo(filespace: "f", location: "/", sizeBytes: 0, usedBytes: 0,
                             pinnedBytes: 0, maxBytes: 0, freeOnVolumeBytes: 0, hitRate: 0)).method, "cache")
    }
}
