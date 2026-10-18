// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// The authority's current state; page cursors and page contents do not affect
/// identity. Permission visibility is included even when the sequence is stable.
public struct GatewayChangeCheckpoint: Sendable, Decodable, Equatable {
    public let anchor: Int
    public let visibility: String?
    public init(anchor: Int, visibility: String?) { self.anchor = anchor; self.visibility = visibility }
    public var token: String {
        "seq:\(anchor);visibility:" + (visibility.map { "s\($0.utf8.count):\($0)" } ?? "null")
    }
}

public struct GatewayChangePage: Sendable {
    public let anchor: Int
    public let updated: [ItemMetadata]
    public let deleted: [InodeID]
    public let cursor: Int?
    public let visibility: String?
    public init(anchor: Int, updated: [ItemMetadata], deleted: [InodeID], cursor: Int?, visibility: String?) {
        self.anchor = anchor; self.updated = updated; self.deleted = deleted; self.cursor = cursor; self.visibility = visibility
    }
}
public struct GatewayChangeHint: Sendable {
    public let acknowledge: @Sendable () async throws -> Void
    public init(acknowledge: @escaping @Sendable () async throws -> Void) { self.acknowledge = acknowledge }
}

extension HttpGatewayClient {
    public func changeHints(filespace: FilespaceID) async throws -> AsyncThrowingStream<GatewayChangeHint, Error> {
        let url = try makeURL(path: "/v1/filespaces/\(pathEscape(filespace))/changes/subscribe", query: [])
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else { throw EngineError(.invalidParams) }
        parts.scheme = parts.scheme == "https" ? "wss" : "ws"
        guard let socketURL = parts.url else { throw EngineError(.invalidParams) }
        var request = URLRequest(url: socketURL)
        request.setValue("Bearer \(await config.tokenProvider())", forHTTPHeaderField: "Authorization")
        request.setValue(clientID, forHTTPHeaderField: "X-CloudFS-Client-ID")
        let socket = session.webSocketTask(with: request)
        socket.maximumMessageSize = 1024
        socket.resume()
        return AsyncThrowingStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            let reader = Task {
                let heartbeat = Task {
                    do {
                        while !Task.isCancelled {
                            try await Task.sleep(for: .seconds(10))
                            try await socket.send(.string("check"))
                        }
                    } catch { socket.cancel(with: .goingAway, reason: nil) }
                }
                defer { heartbeat.cancel(); socket.cancel(with: .goingAway, reason: nil) }
                do {
                    while !Task.isCancelled {
                        let message = try await socket.receive()
                        guard case .string(let text) = message,
                              let data = text.data(using: .utf8),
                              let object = try JSONSerialization.jsonObject(with: data) as? [String: String],
                              object["type"] == "invalidate" else { throw EngineError(.gatewayError, "Invalid change hint") }
                        continuation.yield(GatewayChangeHint { try await socket.send(.string("ack")) })
                    }
                    continuation.finish()
                } catch { continuation.finish(throwing: error) }
            }
            continuation.onTermination = { _ in reader.cancel(); socket.cancel(with: .goingAway, reason: nil) }
        }
    }
}
