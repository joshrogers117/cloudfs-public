// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSCrypto
import CloudFSGateway
import CloudFSSMB
@testable import cloudfsd

final class DemandManifestTests: XCTestCase {
    func testLiveSMBReadSurvivesChangeNotificationDuringManifestFetch() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        GWStub.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("manifest-smb-race-\(UUID())")
        let mount = root.appendingPathComponent("volume").path
        let key = Data(repeating: 43, count: 32)
        let plain = Data((0..<(1 << 20)).map { UInt8(truncatingIfNeeded: $0) })
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: key)
        let (cipher, hash) = try await crypto.encryptBlock(plain, itemID: "file", blockIndex: 0)
        var url = URLComponents(string: "https://blob.test/blob")!
        url.queryItems = [URLQueryItem(name: "key", value: hash.objectKey)]
        var put = URLRequest(url: url.url!); put.httpMethod = "PUT"; put.httpBody = cipher
        _ = try await GWStub.session().data(for: put)
        let item = #"{"id":"file","parent":"root","name":"read.bin","isDir":false,"size":\#(plain.count),"contentVersion":"v1","version":1}"#
        GWStub.on("GET /v1/filespaces/fs/items", json: #"{"items":[\#(item)],"cursor":null}"#)
        GWStub.on("GET /v1/filespaces/fs/items/file", json: item)
        // The production SMB adapter now admits even cached READs through the
        // range authority. This fixture owns the file and has no competing lock.
        GWStub.on("POST /v1/filespaces/fs/range-locks") { request in
            let body=(try? JSONSerialization.jsonObject(with:GWStub.bodyData(request) ?? Data())) as? [String:Any]
            switch body?["action"] as? String {
            case "check": return (200,#"{"allowed":true,"permitTtlMs":1000,"permitFence":1}"#)
            case "release-read": return (200,#"{"released":true}"#)
            default: return (400,#"{"error":"unexpected range operation"}"#)
            }
        }
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: true)
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: root.appendingPathComponent("cache").path,
            cacheSizeBytes: 8 << 20, controlSocketPath: root.appendingPathComponent("socket").path,
            gatewayBaseURL: "https://gw.test"), gateway: gateway, blobSession: GWStub.session(), key: try FilespaceKey(masterKeyBytes: key))
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { _ in
            if GWStub.count("GET /v1/filespaces/fs/blocks/file/range") == 1 {
                engine.manifestRanges.invalidate(filespace: "fs", itemID: "file")
            }
            return (200, #"{"format":2,"item":\#(item),"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":0,"length":\#(plain.count)}],"nextOffset":null}"#)
        }
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let backend = SMBLoopbackMountBackend()
        addTeardownBlock {
            try? await backend.unmount(filespace: "fs", force: true)
            _ = try? await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
            try? FileManager.default.removeItem(at: root)
        }
        try await backend.mount(filespace: "fs", displayName: "Manifest race regression", at: mount,
            engine: await engine.dataPath(for: "fs"))
        let reader = Process(), output = root.appendingPathComponent("readback.bin")
        reader.executableURL = URL(fileURLWithPath: "/bin/dd")
        reader.arguments = ["if=\(mount)/read.bin", "of=\(output.path)", "bs=64k"]
        let errors = Pipe(); reader.standardError = errors
        try reader.run()
        let deadline = Date().addingTimeInterval(20)
        while reader.isRunning && Date() < deadline { try await Task.sleep(for: .milliseconds(20)) }
        if reader.isRunning { reader.terminate(); XCTFail("Kernel read timed out") }
        reader.waitUntilExit()
        let message = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertEqual(reader.terminationStatus, 0, message)
        XCTAssertEqual(try Data(contentsOf: output), plain)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), 2)
        XCTAssertGreaterThan(GWStub.count("POST /v1/filespaces/fs/range-locks"),0)
    }

    func testDirectorySequenceWarmsOnlyNextTwoAuthenticatedFiles() async throws {
        GWStub.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("directory-demand-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let key = Data(repeating: 19, count: 32), size = 64 << 10
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: key)
        var items: [String] = []
        for index in 1...6 {
            let id = InodeID("frame\(index)")
            let (cipher, hash) = try await crypto.encryptBlock(Data(repeating: UInt8(index), count: size), itemID: id, blockIndex: 0)
            var url = URLComponents(string: "https://blob.test/blob")!; url.queryItems = [URLQueryItem(name: "key", value: hash.objectKey)]
            var request = URLRequest(url: url.url!); request.httpMethod = "PUT"; request.httpBody = cipher
            _ = try await GWStub.session().data(for: request)
            let item = #"{"id":"frame\#(index)","parent":"root","name":"shot_000\#(index).exr","isDir":false,"size":\#(size),"contentVersion":"v1","version":1}"#
            items.append(item)
            GWStub.on("GET /v1/filespaces/fs/blocks/frame\(index)/range", json: #"{"format":2,"item":\#(item),"firstBlockIndex":0,"blocks":[{"chunkIdx":0,"blockIdx":0,"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":0,"length":\#(size)}],"nextOffset":null}"#)
        }
        GWStub.on("GET /v1/filespaces/fs/items", json: "{\"items\":[" + items.joined(separator: ",") + "],\"cursor\":null}")
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test", token: "owner"), session: GWStub.session(), streamingManifests: true)
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: root.path, cacheSizeBytes: 8 << 20, controlSocketPath: root.appendingPathComponent("socket").path, gatewayBaseURL: "https://gw.test", blockSize: size), gateway: gateway, blobSession: GWStub.session(), key: try FilespaceKey(masterKeyBytes: key))
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let path = await engine.dataPath(for: "fs"); _ = try await path.enumerate(container: .root, page: nil)
        let before = try await engine.status(StatusParams(filespace: "fs"))[0]
        XCTAssertNotNil(before.gatewayLatencyMs); XCTAssertNil(before.latencyMsToBucket); XCTAssertNil(before.storage?.reachability)
        for index in 1...3 {
            let bytes = try await path.readBytes(InodeID("frame\(index)"), version: "v1", offset: 0, length: size)
            XCTAssertEqual(bytes, Data(repeating: UInt8(index), count: size))
            if index < 3 { XCTAssertEqual(GWStub.totalBlobGets(), index) }
        }
        for _ in 0..<200 where GWStub.totalBlobGets() < 5 { try await Task.sleep(for: .milliseconds(10)) }
        XCTAssertEqual(GWStub.totalBlobGets(), 5)
        for _ in 0..<100 where engine.directoryPrefetch.snapshot().activeJobs > 0 { try await Task.sleep(for: .milliseconds(10)) }
        let fourth = try await path.readBytes("frame4", version: "v1", offset: 0, length: size)
        XCTAssertEqual(fourth, Data(repeating: 4, count: size))
        // Reading frame4 is new demand and may now legitimately predict frame6.
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/frame4/range"), 1)
        let status = try await engine.status(StatusParams(filespace: "fs"))[0]
        XCTAssertNotNil(status.gatewayLatencyMs); XCTAssertNotNil(status.storage?.requestDurationMs)
        XCTAssertGreaterThan(status.storage?.downloadBytesPerSecond ?? 0, 0)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs", drain: false))
    }

    func testHugeFileTailReadsOneManifestExtentAndAuthenticatesItsAbsoluteBlockIndex() async throws {
        GWStub.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("demand-manifest-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let key = Data(repeating: 63,count: 32), blockSize = 1 << 20, index = 16383
        let crypto = try AESGCMBlockCrypto(masterKeyBytes: key)
        let plain = Data(repeating: 79,count: blockSize)
        let (cipher,hash) = try await crypto.encryptBlock(plain,itemID: "file",blockIndex: index)
        var url = URLComponents(string: "https://blob.test/blob")!; url.queryItems = [URLQueryItem(name: "key",value: hash.objectKey)]
        var request = URLRequest(url: url.url!); request.httpMethod = "PUT"; request.httpBody = cipher
        _ = try await GWStub.session().data(for: request)
        let item = #"{"id":"file","parent":"root","name":"large.mov","isDir":false,"size":\#((index+1)*blockSize),"contentVersion":"v1","version":1}"#
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { request in
            let q = URLComponents(url: request.url!,resolvingAgainstBaseURL: false)!.queryItems!
            XCTAssertEqual(q.first { $0.name == "offset" }?.value,String(index*blockSize))
            XCTAssertFalse(q.contains { $0.name == "after" })
            return (200,#"{"format":2,"item":\#(item),"firstBlockIndex":\#(index),"blocks":[{"chunkIdx":\#(index),"blockIdx":0,"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":\#(index*blockSize),"length":\#(blockSize)}],"nextOffset":null}"#)
        }
        let gateway = HttpGatewayClient(config: GatewayClientConfig(baseURL: "https://gw.test",token: "owner"),session: GWStub.session(),streamingManifests: true)
        let engine = CloudFSEngine(config: EngineConfig(cacheDir: root.path,cacheSizeBytes: 8 << 20,controlSocketPath: root.appendingPathComponent("socket").path,gatewayBaseURL: "https://gw.test"),gateway: gateway,blobSession: GWStub.session(),key: try FilespaceKey(masterKeyBytes: key))
        _ = try await engine.connect(FilespaceConnectParams(filespace: "fs"))
        let path = await engine.dataPath(for: "fs")
        for _ in 0..<2 {
            let bytes = try await path.readBytes("file",version: "v1",offset: index*blockSize+17,length: 257)
            XCTAssertEqual(bytes,plain.prefix(257))
        }
        XCTAssertEqual(GWStub.totalBlobGets(),1)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"),1)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file"),0)
        engine.manifestRanges.invalidate(filespace: "fs")
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range",status: 409,json: #"{"error":"version_conflict"}"#)
        do { _ = try await path.readBytes("file",version: "v1",offset: index*blockSize,length: 1); XCTFail("stale extent must not survive invalidation") } catch {}
        // A handle opened before a publication keeps its old version hint. Only
        // the first extent may refresh; subsequent extents must remain coherent.
        let freshItem = item.replacingOccurrences(of: "v1", with: "v2")
        GWStub.on("GET /v1/filespaces/fs/items/file", json: freshItem)
        GWStub.on("GET /v1/filespaces/fs/blocks/file/range") { request in
            let version = URLComponents(url: request.url!, resolvingAgainstBaseURL: false)!.queryItems!.first { $0.name == "contentVersion" }!.value!
            if version == "v1" { return (409, #"{"error":"version_conflict"}"#) }
            return (200, #"{"format":2,"item":\#(freshItem),"firstBlockIndex":\#(index),"blocks":[{"chunkIdx":\#(index),"blockIdx":0,"blockHash":"\#(hash.hex)","objectKey":"\#(hash.objectKey)","offset":\#(index*blockSize),"length":\#(blockSize)}],"nextOffset":null}"#)
        }
        let refreshed = try await path.readBytes("file", version: "v1", offset: index*blockSize, length: 1)
        XCTAssertEqual(refreshed, plain.prefix(1))
        let count = GWStub.count("GET /v1/filespaces/fs/blocks/file/range")
        _ = try await path.readBytes("file", version: "v1", offset: index*blockSize, length: 1)
        XCTAssertEqual(GWStub.count("GET /v1/filespaces/fs/blocks/file/range"), count)
        _ = try await engine.disconnect(FilespaceDisconnectParams(filespace: "fs",drain: false))
    }
}
