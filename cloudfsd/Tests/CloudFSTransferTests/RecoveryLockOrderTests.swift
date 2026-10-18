// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSCache
import CloudFSCrypto
@testable import CloudFSTransfer

private actor SuspendedLease {
    var entered = false
    var completed = false
    private var waiter: CheckedContinuation<Void, Never>?
    func acquire() async -> Int? {
        entered = true
        await withCheckedContinuation { waiter = $0 }
        return 1
    }
    func release() { waiter?.resume(); waiter = nil }
    func markCompleted() { completed = true }
}

final class RecoveryLockOrderTests: XCTestCase {
    func testRecoveryCanTakeMutationGateWhileUploadWaitsForLease() async throws {
        BlobURLProtocol.reset()
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("lock-order-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [BlobURLProtocol.self]
        let session = URLSession(configuration: config); defer { session.invalidateAndCancel() }
        let gate = SuspendedLease()
        let transfer = RealTransferEngine(cache: try DiskBlockCache(filespace: "fs", directory: root, maxBytes: 1 << 20),
            crypto: try AESGCMBlockCrypto(masterKeyBytes: Data(repeating: 8, count: 32)), gateway: MockGateway(),
            blob: BlobTransport(session: session), blockSize: 4, journal: WriteBackJournal(cacheDir: root.path), maxUploadRetries: 0,
            leaseFence: { _, _ in await gate.acquire() })
        _ = try await transfer.pause(filespace: "fs")
        try await transfer.stageReplace(filespace: "fs", itemID: "file", data: Data("save".utf8), baseVersion: "1", fence: nil)
        let destination = root.appendingPathComponent("saved.bin").path
        _ = try await transfer.exportRecovery(filespace: "fs", itemID: "file", destination: destination)
        _ = try await transfer.resume(filespace: "fs")
        for _ in 0..<200 { if await gate.entered { break }; try await Task.sleep(for: .milliseconds(5)) }
        let entered = await gate.entered
        XCTAssertTrue(entered, "upload should be waiting for coordinator lease gate")
        let completion = Task {
            try await transfer.completeRecovery(filespace: "fs", itemID: "file", destination: destination)
            await gate.markCompleted()
        }
        for _ in 0..<200 { if await gate.completed { break }; try await Task.sleep(for: .milliseconds(5)) }
        let completedBeforeLease = await gate.completed
        // Release even on failure so the regression reports a failure, not a hung suite.
        await gate.release()
        try await completion.value
        XCTAssertTrue(completedBeforeLease, "recovery holding the lease gate must not wait on an upload that holds the mutation gate")
        let staged = await transfer.stagedState(filespace: "fs", itemID: "file")
        XCTAssertNil(staged)
    }
}
