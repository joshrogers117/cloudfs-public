// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Opt-in aggregate timings; never retain signed URLs, headers, object names or contents.
final class BlobTaskMetrics: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    static let shared = BlobTaskMetrics()
    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        let profile = WriteProfiler.shared
        profile.recordDuration("http.task", seconds: metrics.taskInterval.duration)
        for transaction in metrics.transactionMetrics {
            let protocolName: String
            switch transaction.networkProtocolName {
            case "http/1.1": protocolName = "http1"
            case "h2": protocolName = "h2"
            case "h3": protocolName = "h3"
            default: protocolName = "other"
            }
            profile.count("http.protocol." + protocolName)
            profile.count(transaction.isReusedConnection ? "http.connection.reused" : "http.connection.new")
            func measure(_ name: String, _ start: Date?, _ end: Date?) {
                guard let start, let end else { return }
                profile.recordDuration(name, seconds: max(0, end.timeIntervalSince(start)))
            }
            // This includes queueing plus connection setup; do not label it pure queue time.
            measure("http.taskToRequest", metrics.taskInterval.start, transaction.requestStartDate)
            measure("http.dns", transaction.domainLookupStartDate, transaction.domainLookupEndDate)
            measure("http.connect", transaction.connectStartDate, transaction.connectEndDate)
            measure("http.tls", transaction.secureConnectionStartDate, transaction.secureConnectionEndDate)
            measure("http.requestToFirstByte", transaction.requestStartDate, transaction.responseStartDate)
            measure("http.responseBody", transaction.responseStartDate, transaction.responseEndDate)
        }
    }
}
