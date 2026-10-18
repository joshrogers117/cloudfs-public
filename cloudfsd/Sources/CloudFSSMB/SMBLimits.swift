// SPDX-License-Identifier: AGPL-3.0-or-later

/// Incoming writes remain ordered per handle and bounded. A larger negotiated write lets a
/// client amortize one durable journal transaction over several 1 MiB blocks;
/// it does not change acknowledgement durability, compound, FLUSH or CLOSE ordering.
enum SMBLimits {
    static let maximumWriteBytes = 8 << 20
    /// Concurrent standalone READs per connection (cold object reads are slow).
    static let readSlots = 8
    /// Concurrently EXECUTING per-handle write lanes per connection (scheduler cap).
    static let writeSlots = 4
    /// Safety valve on queued-but-unfinished write payload per connection.
    static let maximumQueuedWriteBytes = 128 << 20
    static let maximumFrameBytes = 16 << 20
}
