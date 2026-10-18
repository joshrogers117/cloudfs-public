// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSCrypto
import CloudFSGateway
@testable import cloudfsd

final class ReadAheadDataPathTests: XCTestCase {
    /// Exercise the actual adapter, authenticated transfer and cache. The old
    /// unconditional 16-block warm downloaded neighbors even on a first/random
    /// read; these requests should fetch exactly their five requested blocks.
    func testFirstAndRandomMountedReadsFetchOnlyRequestedAuthenticatedBlocks() async throws {
        GWStub.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("read-ahead-demand-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let key = Data(repeating: 11, count: 32)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: key)
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session())
        let blockSize = 32 << 10
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: root.path, cacheSizeBytes: 8 << 20,
            controlSocketPath: root.appendingPathComponent("socket").path, gatewayBaseURL: "https://gw.test", blockSize: blockSize),
            gateway: gateway, blobSession: GWStub.session(), key: try FilespaceKey(masterKeyBytes: key))
        var rows: [String] = []
        var lastBlockKey = ""
        for index in 0..<32 {
            let (bytes, hash) = try await crypto.encryptBlock(Data(repeating: UInt8(index), count: blockSize), itemID: "file", blockIndex: index)
            var url = URLComponents(string: "https://blob.test/blob")!
            url.queryItems = [URLQueryItem(name: "key", value: hash.objectKey)]
            var request = URLRequest(url: url.url!)
            request.httpMethod = "PUT"; request.httpBody = bytes
            _ = try await GWStub.session().data(for: request)
            lastBlockKey = hash.objectKey
            rows.append("{\"chunkIdx\":\(index),\"blockIdx\":\(index),\"blockHash\":\"\(hash.hex)\",\"objectKey\":\"\(hash.objectKey)\",\"offset\":\(index * blockSize),\"length\":\(blockSize)}")
        }
        GWStub.on("GET /v1/filespaces/fs/blocks/file", json: "[" + rows.joined(separator: ",") + "]")
        GWStub.on("GET /v1/filespaces/fs/items/file", json: "{\"id\":\"file\",\"parent\":\"root\",\"name\":\"file\",\"isDir\":false,\"size\":\(32 * blockSize),\"contentVersion\":\"v1\",\"version\":1}")
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let adapter = await engine.dataPath(for: "fs")
        for (count, index) in [0, 8, 2, 14, 4].enumerated() {
            let bytes = try await adapter.readBytes("file", version: "v1", offset: index * blockSize, length: blockSize)
            XCTAssertEqual(bytes, Data(repeating: UInt8(index), count: blockSize))
            XCTAssertEqual(GWStub.totalBlobGets(), count + 1, "first/seek read must not fetch unrequested neighbors")
            XCTAssertEqual(engine.readAhead.snapshot().activeTasks, 0)
        }
        // A failing authenticated read must also retire its observation from the
        // predictor; otherwise a later seek is mistaken for concurrent demand.
        var corruptURL = URLComponents(string: "https://blob.test/blob")!
        corruptURL.queryItems = [URLQueryItem(name: "key", value: lastBlockKey)]
        var corrupt = URLRequest(url: corruptURL.url!)
        corrupt.httpMethod = "PUT"; corrupt.httpBody = Data(repeating: 0xff, count: blockSize)
        _ = try await GWStub.session().data(for: corrupt)
        do {
            _ = try await adapter.readBytes("file", version: "v1", offset: 31 * blockSize, length: blockSize)
            XCTFail("tampered ciphertext must never become readable")
        } catch { /* Authentication/checksum failure remains a hard read error. */ }
        XCTAssertEqual(engine.readAhead.snapshot().activeDemands, 0)
        XCTAssertEqual(engine.readAhead.snapshot().trackedStreams, 0)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: true))
        XCTAssertEqual(engine.readAhead.snapshot().trackedStreams, 0)
    }
}
