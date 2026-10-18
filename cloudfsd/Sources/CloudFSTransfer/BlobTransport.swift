// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSTransfer — the byte mover: presigned-URL range GETs / part PUTs.
// (DESIGN.md §4.1 step 3, §4.2 step 2, §4.3)
//
// Bytes go client<->bucket directly over a plain `URLSession` against a
// gateway-minted presigned URL — they NEVER transit the gateway (which only
// signs the URL). This file owns that HTTP plane: a ranged GET of one block's
// ciphertext and a whole-object PUT of one block's ciphertext, each wrapped in
// exponential-backoff-with-jitter retry on transient (5xx / 429 / network)
// failures. A presign that came back 401/expired is the caller's concern (it
// re-mints and re-enters); here we retry the transport-level transient class.

import Foundation
import CryptoKit

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

import CloudFSCore

/// Retry/backoff policy for block transfers (DESIGN.md §4.3).
public struct RetryPolicy: Sendable {
    public var maxAttempts: Int
    public var baseDelayMs: Int
    public var maxDelayMs: Int
    /// One object's network retry budget. This never discards journaled writes.
    public var maxElapsedMs: Int
    public var nowMilliseconds: @Sendable () -> UInt64
    /// Injectable sleep so tests run without real wall-clock waits.
    public var sleep: @Sendable (_ ms: Int) async -> Void

    public init(maxAttempts: Int = 4, baseDelayMs: Int = 50, maxDelayMs: Int = 2000,
                maxElapsedMs: Int = 60_000,
                sleep: (@Sendable (_ ms: Int) async -> Void)? = nil) {
        self.maxAttempts = max(1, maxAttempts)
        self.baseDelayMs = max(0, baseDelayMs)
        self.maxDelayMs = max(0, maxDelayMs)
        self.maxElapsedMs = max(1, maxElapsedMs)
        self.nowMilliseconds = { DispatchTime.now().uptimeNanoseconds / 1_000_000 }
        self.sleep = sleep ?? { ms in
            try? await Task.sleep(nanoseconds: UInt64(ms) * 1_000_000)
        }
    }

    /// Backoff for attempt `n` (0-based): min(max, base * 2^n) + up to 50% jitter.
    func delayMs(forAttempt n: Int) -> Int {
        let exp = Double(baseDelayMs) * pow(2.0, Double(n))
        let capped = min(Double(maxDelayMs), exp)
        let jitter = Double.random(in: 0...(capped * 0.5))
        return Int(capped + jitter)
    }
}

/// Network outcomes only. A successful response is not a checksum or durability acknowledgement.
/// `.congestion` is a bare signal (timeout, connection loss, or 408/429/503
/// without a retry hint). `.overloaded` means the server explicitly signaled
/// overload (429/503 WITH Retry-After), which is direct evidence of pressure.
public enum BlobTransferFeedback: Sendable, Equatable { case success, congestion, overloaded(retryAfter: Double) }

/// Whether an HTTP status is a transient condition worth retrying (DESIGN.md
/// §4.3: 5xx + 429). 408 (request timeout) is also transient.
func isTransientStatus(_ status: Int) -> Bool {
    status == 408 || status == 429 || (500...599).contains(status)
}

/// The presigned-URL byte plane. One `URLSession`; injectable for tests.
public final class BlobTransport: Sendable {
    private let session: URLSession
    private let policy: RetryPolicy
    private let ownsSession: Bool
    public let telemetry = StorageTelemetryTracker()

    public init(session: URLSession? = nil, policy: RetryPolicy = RetryPolicy()) {
        self.session = session ?? URLSession(configuration: Self.transferConfiguration())
        self.ownsSession = session == nil
        self.policy = policy
    }

    deinit { if ownsSession { session.invalidateAndCancel() } }

    static func transferConfiguration() -> URLSessionConfiguration {
        let config = URLSessionConfiguration.ephemeral
        // The engine admits at most 64 uploads and 64 downloads. An HTTP/1.1
        // library default of six must not silently override those bounded pools.
        // HTTP/2 multiplexing negotiates its own stream capacity.
        config.httpMaximumConnectionsPerHost = 2 * kMaxTransferConcurrency
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpShouldSetCookies = false
        config.httpCookieStorage = nil
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        return config
    }

    /// GET a byte range of a presigned object (the block ciphertext). The block
    /// is content-addressed and self-contained, so we request the whole object
    /// (`length == nil`) or a sub-range when the caller knows the block bounds.
    public func get(url: String, range: Range<Int>? = nil, filespace: FilespaceID? = nil,
                    feedback: (@Sendable (BlobTransferFeedback) async -> Void)? = nil) async throws -> Data {
        guard let u = URL(string: url) else {
            throw EngineError(.invalidParams, "bad presigned URL")
        }
        var req = URLRequest(url: u)
        req.httpMethod = "GET"
        if let range {
            req.setValue("bytes=\(range.lowerBound)-\(range.upperBound - 1)",
                         forHTTPHeaderField: "Range")
        }
        return try await perform(req, expecting: [200, 206], op: "block GET", filespace: filespace, feedback: feedback)
    }

    /// PUT one block's ciphertext to a presigned URL (DESIGN.md §4.2 step 2).
    public func put(url: String, body: Data, headers: [String: String] = [:], verificationUrl: String? = nil, filespace: FilespaceID? = nil,
                    feedback: (@Sendable (BlobTransferFeedback) async -> Void)? = nil) async throws {
        guard let u = URL(string: url) else {
            throw EngineError(.invalidParams, "bad presigned URL")
        }
        var req = URLRequest(url: u)
        req.httpMethod = "PUT"
        req.httpBody = body
        req.setValue("application/octet-stream", forHTTPHeaderField: "content-type")
        for (name, value) in headers { req.setValue(value, forHTTPHeaderField: name) }
        do {
            _ = try await perform(req, expecting: [200, 201, 204], op: "block PUT", filespace: filespace, feedback: feedback)
        } catch let error as EngineError {
            guard case .int(412)? = error.data?["status"],
                  headers["if-none-match"] == "*", let verificationUrl else { throw error }
            // A lost PUT reply or deterministic rewrite can encounter an existing
            // immutable key. 412 alone proves nothing about its bytes.
            let existing = try await get(url: verificationUrl, filespace: filespace, feedback: feedback)
            guard existing.count == body.count, SHA256.hash(data: existing) == SHA256.hash(data: body) else {
                throw EngineError(.syncFailed, "existing immutable object failed checksum verification")
            }
        }
    }

    // MARK: Retry loop

    private func perform(_ req: URLRequest, expecting ok: Set<Int>, op: String, filespace: FilespaceID?,
                         feedback: (@Sendable (BlobTransferFeedback) async -> Void)?) async throws -> Data {
        var lastError: EngineError = EngineError(.networkError, "\(op) failed")
        let began = policy.nowMilliseconds()
        var serverDelayMs = 0
        func remaining() -> Int {
            let current = policy.nowMilliseconds()
            let elapsed = current >= began ? current - began : 0
            return max(0, policy.maxElapsedMs - Int(min(UInt64(Int.max), elapsed)))
        }
        for attempt in 0..<policy.maxAttempts {
            // Finding 3: a superseded upload's Task is cancelled cooperatively. Do
            // NOT keep retrying through cancellation — surface `CancellationError`
            // so the engine can distinguish genuine supersession from a real
            // transient network failure (and not publish a phantom `.error`).
            try Task.checkCancellation()
            if attempt > 0 {
                let delay = max(serverDelayMs, policy.delayMs(forAttempt: attempt - 1))
                guard delay < remaining() else { throw lastError }
                WriteProfiler.shared.count("http.retry")
                await policy.sleep(delay)
                try Task.checkCancellation()
            }
            guard remaining() > 0 else { throw lastError }
            if attempt > 0, let filespace { telemetry.retry(filespace) }
            var request = req
            request.timeoutInterval = min(30, Double(remaining()) / 1000)
            do {
                let (data, response): (Data, URLResponse)
                do {
                    try Task.checkCancellation()
                    let metrics = WriteProfiler.shared.enabled ? BlobTaskMetrics.shared : nil
                    (data, response) = try await observedData(request, milliseconds: remaining(), metrics: metrics, filespace: filespace)
                } catch is CancellationError {
                    throw CancellationError()
                } catch let urlErr as URLError where urlErr.code == .cancelled {
                    // URLSession surfaces task cancellation as URLError(.cancelled);
                    // treat it as cooperative cancellation, never a retryable transient.
                    throw CancellationError()
                } catch {
                    if let error = error as? URLError,
                       [.timedOut, .networkConnectionLost].contains(error.code) {
                        await feedback?(.congestion)
                    }
                    lastError = EngineError(.networkError, "\(op): \(error.localizedDescription)")
                    serverDelayMs = 0
                    continue   // transient transport failure → retry
                }
                guard let http = response as? HTTPURLResponse else {
                    lastError = EngineError(.networkError, "\(op): non-HTTP response")
                    continue
                }
                if ok.contains(http.statusCode) {
                    await feedback?(.success)
                    return data
                }
                if isTransientStatus(http.statusCode) {
                    let retryAfter = Self.retryAfterSeconds(http.value(forHTTPHeaderField: "Retry-After"))
                    if [408, 429, 503].contains(http.statusCode) {
                        await feedback?([429, 503].contains(http.statusCode) ? (retryAfter.map { .overloaded(retryAfter: $0) } ?? .congestion) : .congestion)
                    }
                    serverDelayMs = retryAfter.map { Int(min(Double(Int.max / 2), ceil($0 * 1000))) } ?? 0
                    var details: [String: CodableValue] = ["status": .int(http.statusCode)]
                    if let retryAfter { details["retryAfter"] = .string(String(retryAfter)) }
                    lastError = EngineError(.gatewayError,
                        "\(op): transient HTTP \(http.statusCode)",
                        data: details)
                    continue
                }
                // Non-transient (403/404/etc.) — fail immediately, do not retry.
                throw EngineError(http.statusCode == 404 ? .notFound :
                                  http.statusCode == 403 ? .permissionDenied : .gatewayError,
                    "\(op): HTTP \(http.statusCode)",
                    data: ["status": .int(http.statusCode)])
            }
        }
        throw lastError
    }

    private func observedData(_ request: URLRequest, milliseconds: Int, metrics: BlobTaskMetrics?,
                              filespace: FilespaceID?) async throws -> (Data, URLResponse) {
        let began = ContinuousClock.now
        if let filespace { telemetry.begin(filespace) }
        do {
            let result = try await dataWithinBudget(request, milliseconds: milliseconds, metrics: metrics)
            if let filespace {
                let duration = began.duration(to: .now).components
                let ms = Double(duration.seconds) * 1000 + Double(duration.attoseconds) / 1e15
                let status = (result.1 as? HTTPURLResponse)?.statusCode
                // Conditional immutable PUT collisions are normal, but their bytes
                // are verified by a separate GET before the write can succeed.
                let ok = status.map { (200...299).contains($0) || ($0 == 412 && request.value(forHTTPHeaderField: "if-none-match") == "*") } ?? false
                telemetry.finish(filespace, durationMs: ms, failure: ok ? nil : status.map { "HTTP \($0)" } ?? "Non-HTTP response",
                    downloaded: ok && request.httpMethod == "GET" ? result.0.count : 0,
                    uploaded: ok && status != 412 && request.httpMethod == "PUT" ? request.httpBody?.count ?? 0 : 0)
            }
            return result
        } catch {
            if let filespace {
                let cancelled = error is CancellationError || (error as? URLError)?.code == .cancelled
                telemetry.finish(filespace, durationMs: nil,
                    failure: cancelled ? nil : (error as? URLError).map { "Network error \($0.code.rawValue)" } ?? "Transport failed",
                    cancelled: cancelled)
            }
            throw error
        }
    }

    /// URLRequest.timeoutInterval is an inactivity timeout. Race the request
    /// against the remaining total budget so a slow streaming response cannot
    /// occupy a permit indefinitely. Cancellation propagates to URLSession.
    private func dataWithinBudget(_ request: URLRequest, milliseconds: Int,
                                  metrics: BlobTaskMetrics?) async throws -> (Data, URLResponse) {
        let session = self.session
        return try await withThrowingTaskGroup(of: (Data, URLResponse).self) { group in
            group.addTask { try await session.data(for: request, delegate: metrics) }
            group.addTask {
                try await Task.sleep(for: .milliseconds(max(1, milliseconds)))
                throw URLError(.timedOut)
            }
            defer { group.cancelAll() }
            return try await group.next()!
        }
    }

    static func retryAfterSeconds(_ raw: String?, now: Date = Date()) -> Double? {
        guard let raw else { return nil }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let seconds = Double(value), seconds.isFinite, seconds >= 0 { return seconds }
        let format = DateFormatter()
        format.locale = Locale(identifier: "en_US_POSIX")
        format.timeZone = TimeZone(secondsFromGMT: 0)
        format.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return format.date(from: value).map { max(0, $0.timeIntervalSince(now)) }
    }
}
