// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// Small, session-local handoff from authenticated download to read assembly.
/// Never persists plaintext. The full crypto identity prevents reuse for another
/// inode/index, even when a caller supplies the same ciphertext hash.
actor VerifiedBlockWindow {
    struct Key: Hashable, Sendable {
        let filespace: FilespaceID
        let itemID: InodeID
        let index: Int
        let hash: BlockHash
    }
    private struct Entry { let bytes: Data; var touched: UInt64 }
    private let limit: Int
    private var entries: [Key: Entry] = [:]
    private var clock: UInt64 = 0
    private(set) var byteCount = 0
    init(limit: Int = 16 << 20) { self.limit = max(0, limit) }
    func get(_ key: Key, length: Int) -> Data? {
        guard var entry = entries[key], entry.bytes.count == length else { return nil }
        clock &+= 1; entry.touched = clock; entries[key] = entry
        return entry.bytes
    }
    func insert(_ bytes: Data, for key: Key) {
        guard bytes.count <= limit else { return }
        if let previous = entries.removeValue(forKey: key) { byteCount -= previous.bytes.count }
        while byteCount > limit - bytes.count, let oldest = entries.min(by: { $0.value.touched < $1.value.touched }) {
            entries.removeValue(forKey: oldest.key); byteCount -= oldest.value.bytes.count
        }
        clock &+= 1; entries[key] = Entry(bytes: bytes, touched: clock); byteCount += bytes.count
    }
}
