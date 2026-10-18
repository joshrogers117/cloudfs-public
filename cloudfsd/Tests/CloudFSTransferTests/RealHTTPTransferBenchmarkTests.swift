// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CryptoKit
import CloudFSCore
@testable import CloudFSTransfer

/// Opt-in, real HTTP/1.1 sockets. Run scripts/benchmark-transfer-http.py.
/// This isolates connection admission; it is not an R2 or encrypted SMB result.
final class RealHTTPTransferBenchmarkTests: XCTestCase {
    func testRealHTTPConnectionCapacityAndDeadline() async throws {
        guard let origin = ProcessInfo.processInfo.environment["CLOUDFS_HTTP_BENCHMARK_URL"],
              let output = ProcessInfo.processInfo.environment["CLOUDFS_HTTP_BENCHMARK_OUTPUT"] else {
            throw XCTSkip("Run scripts/benchmark-transfer-http.py for the real-socket benchmark")
        }
        let expected = Data((0..<(1 << 20)).map { UInt8($0 % 251) })
        let checksum = SHA256.hash(data: expected)
        struct Sample: Codable { let seconds: Double; let mibPerSecond: Double; let p95Seconds: Double; let sha256Matched: Bool }
        var results: [String: Sample] = [:]
        for label in ["default-six-connections", "scheduler-capacity"] {
            let oldConfig = URLSessionConfiguration.ephemeral
            oldConfig.httpMaximumConnectionsPerHost = 6
            let transport = label == "scheduler-capacity" ? BlobTransport() : BlobTransport(session: URLSession(configuration: oldConfig))
            let start = ContinuousClock.now
            let timings = try await withThrowingTaskGroup(of: Double.self) { group in
                var next = 0, elapsed: [Double] = []
                func enqueue(_ index: Int) {
                    group.addTask {
                        let began = ContinuousClock.now
                        let bytes = try await transport.get(url: origin + "/data?object=\(label)-\(index)")
                        guard SHA256.hash(data: bytes) == checksum else { throw NSError(domain: "integrity", code: 1) }
                        let d = began.duration(to: .now).components
                        return Double(d.seconds) + Double(d.attoseconds) / 1e18
                    }
                }
                for _ in 0..<32 { enqueue(next); next += 1 }
                while let duration = try await group.next() {
                    elapsed.append(duration)
                    if next < 128 { enqueue(next); next += 1 }
                }
                return elapsed.sorted()
            }
            let duration = start.duration(to: .now).components
            let seconds = Double(duration.seconds) + Double(duration.attoseconds) / 1e18
            results[label] = Sample(seconds: seconds, mibPerSecond: 128 / seconds, p95Seconds: timings[Int(Double(timings.count - 1) * 0.95)], sha256Matched: true)
        }
        // A trickling body resets URLRequest's inactivity timeout. Our outer
        // deadline must still cancel the request promptly and return no bytes.
        let deadlineStart = ContinuousClock.now
        let limited = BlobTransport(policy: RetryPolicy(maxAttempts: 1, maxElapsedMs: 200))
        do { _ = try await limited.get(url: origin + "/trickle"); XCTFail("partial body must not escape deadline") }
        catch let error as EngineError {
            XCTAssertEqual(error.kind, .networkError)
            XCTAssertGreaterThanOrEqual(deadlineStart.duration(to: .now), .milliseconds(150))
            XCTAssertLessThan(deadlineStart.duration(to: .now), .seconds(2))
        }
        try JSONEncoder().encode(results).write(to: URL(fileURLWithPath: output), options: .atomic)
    }
}
