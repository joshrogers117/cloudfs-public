// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Testing
@testable import CloudFSKit

@Suite struct RecoveryTests {
    @Test func suggestedCopyNamePreservesExtension() {
        let item = RecoveryItem(id: "a", path: "Edits/Friday.cut.prproj", bytes: 12,
                                reason: "Conflict", kind: "conflict", canRetry: false)
        #expect(item.displayName == "Friday.cut.prproj")
        #expect(item.suggestedFileName == "Friday.cut (recovered).prproj")
    }
    @Test func deletedFileStillHasAName() {
        let item = RecoveryItem(id: "abcdefgh-1234", bytes: 12,
                                reason: "Deleted", kind: "deleted", canRetry: false)
        #expect(item.displayName == "Local file abcdefgh")
        #expect(item.suggestedFileName == "Local file abcdefgh (recovered)")
        #expect(item.statusTitle == "File removed from the filespace")
    }
    @Test func offlineRecoveryFailsExplicitly() async {
        await #expect(throws: (any Error).self) {
            try await NullEngineClient().recoveryItems(filespace: "fs1")
        }
    }

    @Test func pinFailureRemainsDistinctFromActivePinning() throws {
        let data = Data(#"{"path":"Projects","pinned":true,"recursive":true,"blocks":5,"cachedBytes":4,"totalBytes":10,"cacheState":"pinning","failureReason":"The pinning limit has been reached."}"#.utf8)
        let wire = try JSONDecoder().decode(PinState.self, from: data)
        let item = PinnedItem(from: wire)
        #expect(item.needsAttention)
        #expect(item.statusLabel == "Needs attention")
        #expect(item.failureReason == "The pinning limit has been reached.")
        let summary = PinnedSummary(items: [item])
        #expect(summary.needsAttentionCount == 1)
        #expect(summary.pinningCount == 0 && summary.pinnedCount == 0)
        #expect(summary.totalCachedBytes == 4 && summary.totalBytes == 10)
    }
}
