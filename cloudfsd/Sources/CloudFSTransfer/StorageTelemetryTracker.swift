// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// Bounded, per-filespace measurements from the real payload plane. Never stores
/// signed URLs or object keys. Successful ciphertext bytes are aggregated over a
/// rolling ten-second window; request durations include the whole response body.
public final class StorageTelemetryTracker: @unchecked Sendable {
    private struct Bucket { var second: Int64; var down = 0; var up = 0 }
    private struct State {
        var value = StorageTelemetry()
        var buckets: [Bucket] = []
        var touched: Int64 = 0
    }
    private let lock = NSLock()
    private var states: [FilespaceID: State] = [:]
    private let now: @Sendable () -> Date
    public init(now: @escaping @Sendable () -> Date = { Date() }) { self.now = now }

    private func update(_ fs: FilespaceID, _ body: (inout State, Int64) -> Void) {
        lock.lock(); defer { lock.unlock() }
        let ms = Int64(now().timeIntervalSince1970 * 1000)
        if states[fs] == nil, states.count >= 256 {
            guard let victim = states.filter({ $0.value.value.activeRequests == 0 }).min(by: { $0.value.touched < $1.value.touched })?.key else { return }
            states.removeValue(forKey: victim)
        }
        var s = states[fs] ?? State(); s.touched = ms
        body(&s, ms); states[fs] = s
    }
    public func begin(_ fs: FilespaceID) {
        update(fs) { s, _ in s.value.requests += 1; s.value.activeRequests += 1 }
    }
    public func retry(_ fs: FilespaceID) { update(fs) { s, _ in s.value.retries += 1 } }
    func finish(_ fs: FilespaceID, durationMs: Double?, failure: String?, cancelled: Bool = false,
                downloaded: Int = 0, uploaded: Int = 0) {
        update(fs) { s, ms in
            s.value.activeRequests = max(0, s.value.activeRequests - 1)
            guard !cancelled else { return }
            if let failure {
                s.value.failures += 1; s.value.lastFailureAt = ms; s.value.lastFailureReason = failure
                s.value.reachability = "degraded"
            } else {
                s.value.lastSuccessAt = ms; s.value.reachability = "online"
                if let durationMs {
                    s.value.requestDurationMs = s.value.requestDurationMs.map { $0 * 0.8 + durationMs * 0.2 } ?? durationMs
                }
            }
            s.buckets.removeAll { $0.second <= ms / 1000 - 10 }
            if downloaded > 0 || uploaded > 0 {
                if s.buckets.last?.second != ms / 1000 { s.buckets.append(Bucket(second: ms / 1000)) }
                s.buckets[s.buckets.count - 1].down += downloaded
                s.buckets[s.buckets.count - 1].up += uploaded
            }
        }
    }
    public func snapshot(_ fs: FilespaceID) -> StorageTelemetry {
        lock.lock(); defer { lock.unlock() }
        guard let state = states[fs] else { return StorageTelemetry() }
        let ms = Int64(now().timeIntervalSince1970 * 1000)
        var result = state.value
        let last = max(result.lastSuccessAt ?? 0, result.lastFailureAt ?? 0)
        if ms - last > 30_000 { result.reachability = nil; result.requestDurationMs = nil }
        let buckets = state.buckets.filter { $0.second > ms / 1000 - 10 }
        let seconds = Double(min(10, max(1, ms / 1000 - (buckets.first?.second ?? ms / 1000) + 1)))
        result.downloadBytesPerSecond = Double(buckets.reduce(0) { $0 + $1.down }) / seconds
        result.uploadBytesPerSecond = Double(buckets.reduce(0) { $0 + $1.up }) / seconds
        return result
    }
}
