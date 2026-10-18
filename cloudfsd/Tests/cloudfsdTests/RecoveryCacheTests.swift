// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
import CloudFSGateway
@testable import cloudfsd

final class RecoveryCacheTests: XCTestCase {
    func testCompletedRecoveryDropsStaleManifestBeforeReadingTeamVersion() async throws {
        GWStub.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("recovery-cache-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let key = Data(repeating: 7, count: 32)
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: key)
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session())
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: root.path, cacheSizeBytes: 1 << 20,
            controlSocketPath: root.appendingPathComponent("socket").path, gatewayBaseURL: "https://gw.test"),
            gateway: gateway, blobSession: GWStub.session(), key: try FilespaceKey(masterKeyBytes: key))
        func publish(_ value: String, version: Int) async throws {
            let (bytes, hash) = try await crypto.encryptBlock(Data(value.utf8), itemID: "file", blockIndex: 0)
            var url = URLComponents(string: "https://blob.test/blob")!; url.queryItems = [URLQueryItem(name: "key", value: hash.objectKey)]
            var request = URLRequest(url: url.url!); request.httpMethod = "PUT"; request.httpBody = bytes
            _ = try await GWStub.session().data(for: request)
            GWStub.on("GET /v1/filespaces/fs/items/file", json: "{\"id\":\"file\",\"parent\":\"root\",\"name\":\"file\",\"isDir\":false,\"size\":\(value.utf8.count),\"contentVersion\":\"v\(version)\",\"version\":\(version)}")
            GWStub.on("GET /v1/filespaces/fs/blocks/file", json: "[{\"chunkIdx\":0,\"blockIdx\":0,\"blockHash\":\"\(hash.hex)\",\"objectKey\":\"\(hash.objectKey)\",\"offset\":0,\"length\":\(value.utf8.count)}]")
        }
        try await publish("remote-old", version: 1)
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let adapter = await engine.dataPath(for: "fs")
        let first = try await adapter.readRange("file", version: "v1", offset: 0, length: 10, alignment: 1 << 20)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: first.ref.path!)), Data("remote-old".utf8))
        _ = try await engine.transfersPause(FilespaceOnlyParams(filespace: "fs"))
        _ = try await adapter.writeRange("file", offset: 0, data: Data("local-save".utf8), baseVersion: "1")
        let output = root.appendingPathComponent("recovered.bin").path
        _ = try await engine.recoveryExport(RecoveryExportParams(filespace: "fs", itemId: "file", destination: output))
        try await publish("remote-new", version: 2)
        try await engine.recoveryComplete(RecoveryExportParams(filespace: "fs", itemId: "file", destination: output))
        _ = try await engine.transfersResume(FilespaceOnlyParams(filespace: "fs"))
        // Simulate the still-open SMB handle retaining v1. Its old cached
        // manifest must be invalidated, even though the caller's version is old.
        let refreshed = try await adapter.readRange("file", version: "v1", offset: 0, length: 10, alignment: 1 << 20)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: refreshed.ref.path!)), Data("remote-new".utf8))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: output)), Data("local-save".utf8))
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: true))
    }
}
