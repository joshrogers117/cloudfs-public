// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// Opt-in local timing without paths, keys or file contents. Nested phase totals
/// intentionally overlap: stage.total contains journal.total and its subphases.
final class WriteProfiler: @unchecked Sendable {
    static let shared = WriteProfiler()
    let enabled = ProcessInfo.processInfo.environment["CLOUDFS_PROFILE_WRITES"] == "1"
    private let lock = NSLock()
    private var seconds: [String: Double] = [:]
    private var counts: [String: Int] = [:]
    private var bytes = 0
    private var sizes: [Int: Int] = [:]
    private var byteTotals: [String: Int] = [:]

    func start() -> UInt64 { enabled ? DispatchTime.now().uptimeNanoseconds : 0 }

    func elapsed(_ name: String, since start: UInt64) {
        guard enabled else { return }
        let duration = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000_000
        lock.withLock { seconds[name, default: 0] += duration; counts[name, default: 0] += 1 }
    }

    func measure<T>(_ name: String, _ operation: () throws -> T) rethrows -> T {
        guard enabled else { return try operation() }
        let begin = start()
        defer { elapsed(name, since: begin) }
        return try operation()
    }

    func count(_ name: String) {
        guard enabled else { return }
        lock.withLock { counts[name, default: 0] += 1 }
    }

    /// Last-value gauge, reported alongside the counters.
    func setCount(_ name: String, _ value: Int) {
        guard enabled else { return }
        lock.withLock { counts[name] = value }
    }

    func recordDuration(_ name: String, seconds duration: Double) {
        guard enabled, duration.isFinite, duration >= 0 else { return }
        lock.withLock { seconds[name, default: 0] += duration; counts[name, default: 0] += 1 }
    }

    func addBytes(_ name: String, count: Int) {
        guard enabled else { return }
        lock.withLock { byteTotals[name, default: 0] += count }
    }

    func completedWrite(bytes count: Int) {
        guard enabled else { return }
        let shouldReport = lock.withLock {
            bytes += count; sizes[count, default: 0] += 1
            return sizes.values.reduce(0, +) % 128 == 0
        }
        if shouldReport { report() }
    }

    func report() {
        guard enabled else { return }
        let snapshot: [String: Any] = lock.withLock {
            ["bytes": bytes, "writeSizes": Dictionary(uniqueKeysWithValues: sizes.map { (String($0.key), $0.value) }),
             "seconds": seconds, "counts": counts, "byteTotals": byteTotals]
        }
        guard let json = try? JSONSerialization.data(withJSONObject: snapshot, options: [.sortedKeys]),
              let value = String(data: json, encoding: .utf8) else { return }
        FileHandle.standardError.write(Data(("CLOUDFS_WRITE_PROFILE " + value + "\n").utf8))
    }
}
