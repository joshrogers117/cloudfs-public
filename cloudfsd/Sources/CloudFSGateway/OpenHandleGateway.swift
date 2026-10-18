// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// Retains an inode, without granting a write lock or overriding current ACLs.
public struct OpenHandleStreamRequest: Sendable, Codable, Equatable {
    public let name: String
    public let required: Bool
    public init(name: String, required: Bool) { self.name = name; self.required = required }
}

/// Stream metadata resolved as part of acquiring an open handle, when supported
/// by the gateway. A missing `stream` in the response means an older gateway.
public struct OpenHandleStreamInfo: Sendable, Codable, Equatable {
    public let exists: Bool
    public let size: Int
    public init(exists: Bool, size: Int) { self.exists = exists; self.size = size }
}

public struct OpenHandleLease: Sendable, Codable, Equatable {
    public let granted: Bool
    public let expiresAt: Double?
    public let reason: String?
    public let stream: OpenHandleStreamInfo?
    public init(granted: Bool, expiresAt: Double? = nil, reason: String? = nil,
                stream: OpenHandleStreamInfo? = nil) {
        self.granted = granted; self.expiresAt = expiresAt; self.reason = reason; self.stream = stream
    }
}

/// The per-handle result of a bounded renewal batch. A missing handle in a
/// batch response is treated as a denied renewal by the coordinator.
public struct OpenHandleRenewal: Sendable, Codable, Equatable {
    public let handleId: String
    public let granted: Bool
    public let expiresAt: Double?
    public let reason: String?
    public init(handleId: String, granted: Bool, expiresAt: Double? = nil, reason: String? = nil) {
        self.handleId = handleId; self.granted = granted; self.expiresAt = expiresAt; self.reason = reason
    }
}

public extension GatewayClient {
    var supportsOpenHandles: Bool { false }
    func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String, access: OpenFileAccess, sharing: OpenFileSharing, ttlMs: Int) async throws -> OpenHandleLease {
        throw EngineError(.unimplemented, "Open-file retention is unavailable")
    }
    /// Older gateways and conformers ignore the optional stream query and return
    /// a lease without stream metadata; callers then use the ordinary list path.
    func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String,
                           access: OpenFileAccess, sharing: OpenFileSharing, ttlMs: Int,
                           stream: OpenHandleStreamRequest?) async throws -> OpenHandleLease {
        try await acquireOpenHandle(filespace: filespace, id: id, handle: handle,
                                    access: access, sharing: sharing, ttlMs: ttlMs)
    }
    func renewOpenHandle(filespace: FilespaceID, handle: String, ttlMs: Int) async throws -> OpenHandleLease {
        throw EngineError(.unimplemented, "Open-file retention is unavailable")
    }
    func renewOpenHandles(filespace: FilespaceID, handles: [String], ttlMs: Int) async throws -> [OpenHandleRenewal] {
        var results: [OpenHandleRenewal] = []
        results.reserveCapacity(handles.count)
        for handle in handles {
            let result = try await renewOpenHandle(filespace: filespace, handle: handle, ttlMs: ttlMs)
            results.append(OpenHandleRenewal(handleId: handle, granted: result.granted, expiresAt: result.expiresAt, reason: result.reason))
        }
        return results
    }
    func closeOpenHandle(filespace: FilespaceID, handle: String) async throws {
        throw EngineError(.unimplemented, "Open-file retention is unavailable")
    }
}

extension HttpGatewayClient {
    public var supportsOpenHandles: Bool { true }
    public func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String, access: OpenFileAccess, sharing: OpenFileSharing, ttlMs: Int) async throws -> OpenHandleLease {
        try await acquireOpenHandle(filespace: filespace, id: id, handle: handle,
                                    access: access, sharing: sharing, ttlMs: ttlMs, stream: nil)
    }
    public func acquireOpenHandle(filespace: FilespaceID, id: InodeID, handle: String,
                                  access: OpenFileAccess, sharing: OpenFileSharing, ttlMs: Int,
                                  stream: OpenHandleStreamRequest?) async throws -> OpenHandleLease {
        struct Body: Encodable {
            let action = "acquire"
            let id: String; let handleId: String; let accessMask: UInt8; let shareMask: UInt8; let ttlMs: Int
            let stream: OpenHandleStreamRequest?
        }
        return try await sendJSON(OpenHandleLease.self,"POST",path:"/v1/filespaces/\(filespace)/open-handles",
            body: JSONEncoder().encode(Body(id:id.rawValue,handleId:handle,accessMask:UInt8(access.rawValue),shareMask:UInt8(sharing.rawValue),ttlMs:ttlMs,stream:stream)))
    }
    public func renewOpenHandle(filespace: FilespaceID, handle: String, ttlMs: Int) async throws -> OpenHandleLease {
        struct Body: Encodable { let action = "renew"; let handleId: String; let ttlMs: Int }
        return try await sendJSON(OpenHandleLease.self,"POST",path:"/v1/filespaces/\(filespace)/open-handles",
            body: JSONEncoder().encode(Body(handleId:handle,ttlMs:ttlMs)))
    }
    public func renewOpenHandles(filespace: FilespaceID, handles: [String], ttlMs: Int) async throws -> [OpenHandleRenewal] {
        struct Body: Encodable { let action = "renew-batch"; let handles: [String]; let ttlMs: Int }
        struct Response: Decodable { let handles: [OpenHandleRenewal] }
        let response = try await sendJSON(Response.self,"POST",path:"/v1/filespaces/\(filespace)/open-handles",
            body: JSONEncoder().encode(Body(handles:handles,ttlMs:ttlMs)))
        return response.handles
    }
    public func closeOpenHandle(filespace: FilespaceID, handle: String) async throws {
        struct Body: Encodable { let action = "close"; let handleId: String }
        struct Response: Decodable { let closed: Bool; let reason: String? }
        let data = try await send("POST",path:"/v1/filespaces/\(filespace)/open-handles",
            body: JSONEncoder().encode(Body(handleId:handle)))
        guard let response = try? JSONDecoder().decode(Response.self, from: data) else {
            throw EngineError(.gatewayError, "Invalid close response for open file handle")
        }
        // The gateway's not_found result means an earlier close already removed
        // this exact idempotent lease. Other denials must remain visible so the
        // caller can retain and retry its local reference.
        guard response.closed || response.reason == "not_found" else {
            throw EngineError(response.reason == "forbidden" ? .permissionDenied : .gatewayError,
                              "Gateway did not close the open file handle",
                              data:["reason":.string(response.reason ?? "unknown")])
        }
    }

}
