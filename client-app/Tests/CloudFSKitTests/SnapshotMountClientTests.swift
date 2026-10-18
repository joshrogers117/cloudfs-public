// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

@Suite(.timeLimit(.minutes(1)))
struct SnapshotMountClientTests {
    @Test func readOnlyMountRoundTripsOpaqueIdentityAndScopedName() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("snapshot.mount") { params in
            #expect(params["filespace"]?.stringValue == "team")
            #expect(params["snapshotId"]?.stringValue == "saved-1")
            #expect(params["name"]?.stringValue == "Before review")
            return #"{"mountId":"snapshot-opaque","filespace":"team","snapshotId":"saved-1","name":"Before review","mountPath":"/Volumes/Before review","status":"mounted","readOnly":true}"#
        }
        daemon.onResult("snapshot.unmount") { params in
            #expect(params["mountId"]?.stringValue == "snapshot-opaque")
            return #"{"mountId":"snapshot-opaque","filespace":"team","snapshotId":"saved-1","name":"Before review","status":"unmounted","readOnly":true}"#
        }
        daemon.onResult("snapshot.mounts", json: #"[{"mountId":"snapshot-opaque","filespace":"team","snapshotId":"saved-1","name":"Before review","status":"unavailable","readOnly":true}]"#)
        try daemon.start(); defer { daemon.stop() }
        let client: any EngineClient = DaemonEngineClient(socketPath: daemon.path)
        let mounted = try await client.mountSnapshot(filespace: "team", snapshotID: "saved-1", at: nil, name: "Before review")
        #expect(mounted.isMounted); #expect(mounted.readOnly); #expect(mounted.filespace != mounted.mountId)
        let ejected = try await client.unmountSnapshot(mountID: mounted.mountId, force: false)
        #expect(!ejected.isMounted)
        let unavailable = try await client.snapshotMounts(filespace: "team")
        #expect(unavailable.first?.status == "unavailable"); #expect(unavailable.first?.isMounted == false)
        await (client as? DaemonEngineClient)?.disconnect()
    }
    @Test func snapshotsParticipateInNormalQuitDrain() async throws {
        let daemon = FakeDaemon()
        daemon.onResult("filespace.list", json: #"[{"id":"team","name":"Team","status":"connected","mountPath":"/team"},{"id":"snapshot-x","name":"Saved","status":"connected","mountPath":"/saved","sourceFilespace":"team","snapshotId":"point","readOnly":true,"paused":false}]"#)
        daemon.onResult("flush", json: #"{"path":"","inSync":true,"pendingUploads":0,"pendingBytes":0}"#)
        daemon.onResult("unmount") { p in #"{"id":"\#(p["filespace"]!.stringValue!)","name":"Unmounted","status":"disconnected"}"# }
        try daemon.start(); defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        try await FilespaceShutdown.drain(client)
        #expect(daemon.requestCount("unmount") == 2)
        #expect(daemon.requestCount("flush") == 4)
        await client.disconnect()
    }
    @Test func oldFilespaceRecordsRemainDecodableWithoutSnapshotFields() throws {
        let record = try JSONDecoder().decode(EngineFilespace.self, from: Data(#"{"id":"team","name":"Team","status":"connected"}"#.utf8))
        #expect(record.readOnly == nil); #expect(record.sourceFilespace == nil); #expect(record.snapshotId == nil)
    }
}
