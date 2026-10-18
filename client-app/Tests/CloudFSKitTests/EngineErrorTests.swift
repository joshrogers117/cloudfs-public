// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Testing
@testable import CloudFSKit

@Suite(.timeLimit(.minutes(1)))
struct EngineErrorTests {
    @Test func foundationErrorBridgeKeepsUsefulMessagesForEveryCase() {
        let cases: [EngineError] = [
            .unavailable("The background service is not running."),
            .invalidParams("Choose a filespace."),
            .notConnected("Connect this filespace first."),
            .notFound("This snapshot was deleted."),
            .conflict(expected: 2, actual: 3, reason: "Another editor saved changes."),
            .locked(heldBy: "A teammate", expiresAt: nil),
            .permissionDenied("Your access to this folder was removed."),
            .gatewayError(status: 503, reason: "The server is temporarily unavailable."),
            .networkError("The Internet connection appears to be offline."),
            .syncTimeout(pendingUploads: 1, pendingBytes: 1024),
            .syncFailed(path: "draft.mov", reason: "Local changes remain safely queued."),
            .internalError("The snapshot could not be opened."),
            .decoding("The server response was incomplete.")
        ]
        for typed in cases {
            let error: any Error = typed
            #expect(error.localizedDescription == typed.description)
            #expect((error as NSError).localizedDescription == typed.description)
            #expect(!error.localizedDescription.contains("CloudFSKit.EngineError"))
        }
    }

    @Test func snapshotWireFailureReachesBannerAsServerExplanation() async throws {
        let daemon = FakeDaemon()
        daemon.onError("snapshot.mounts", errorJSON: #"{"code":-32020,"message":"This snapshot was deleted."}"#)
        try daemon.start(); defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        do {
            _ = try await client.snapshotMounts(filespace: "team")
            Issue.record("Expected the daemon error")
        } catch {
            #expect(error.localizedDescription == "Not found: This snapshot was deleted.")
        }
        await client.disconnect()
    }

    @Test func revokedDaemonWireErrorRequestsRenewalButAclDenialDoesNot() async throws {
        let daemon = FakeDaemon()
        daemon.onError("mount", errorJSON: #"{"code":-32030,"message":"revoked","data":{"error":"revoked"}}"#)
        try daemon.start(); defer { daemon.stop() }
        let client = DaemonEngineClient(socketPath: daemon.path)
        do {
            _ = try await client.mount(filespace: "fixture", at: nil, name: "Fixture")
            Issue.record("Expected the revoked daemon credential to fail")
        } catch let error as EngineError {
            #expect(error.needsCredentialRefresh)
        }
        await client.disconnect()
        for reason in ["forbidden", "forbidden_scope", "wrong_space", "cross_tenant", "read_only"] {
            let denied = EngineError.from(.init(code: -32030, message: reason,
                data: .object(["error": .string(reason), "status": .int(403)])))
            #expect(!denied.needsCredentialRefresh)
            #expect(denied == .permissionDenied(reason))
        }
        let unknown401 = EngineError.from(.init(code: -32030, message: "Sign in again",
            data: .object(["status": .int(401)])))
        #expect(unknown401.needsCredentialRefresh)
    }
}
