// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

public struct RangeAccess: Sendable, Codable {
    public let allowed: Bool
    public let reason: String?
    public let heldBy: String?
    public let permitTtlMs: Int?
    public let permitFence: Int?
}
public extension GatewayClient {
    var supportsRangeLocks: Bool { false }
    func acquireRanges(filespace: FilespaceID, id: InodeID, handle: String, ranges: [FileLockRange], fence: Int?, ttlMs: Int) async throws -> FileLease {
        throw EngineError(.unimplemented, "Distributed byte-range locks are unavailable")
    }
    func renewRanges(filespace: FilespaceID, id: InodeID, handle: String, fence: Int, ttlMs: Int) async throws -> FileLease {
        throw EngineError(.unimplemented, "Distributed byte-range locks are unavailable")
    }
    func releaseRanges(filespace: FilespaceID, id: InodeID, handle: String, fence: Int, ranges: [FileLockRange]?) async throws {
        throw EngineError(.unimplemented, "Distributed byte-range locks are unavailable")
    }
    func releaseReadPermit(filespace: FilespaceID, id: InodeID, handle: String, fence: Int) async throws {
        throw EngineError(.unimplemented, "Distributed read permits are unavailable")
    }
    func checkRangeAccess(filespace: FilespaceID, id: InodeID, handle: String, range: FileLockRange, fence: Int?) async throws -> RangeAccess {
        throw EngineError(.unimplemented, "Distributed byte-range locks are unavailable")
    }
}
extension HttpGatewayClient {
    public var supportsRangeLocks: Bool { true }
    public func acquireRanges(filespace: FilespaceID, id: InodeID, handle: String, ranges: [FileLockRange], fence: Int?, ttlMs: Int) async throws -> FileLease {
        struct Body: Encodable { let action = "acquire"; let path: String; let handle: String; let ranges: [FileLockRange]; let fence: Int?; let ttlMs: Int }
        return try await sendJSON(FileLease.self,"POST",path:"/v1/filespaces/\(filespace)/range-locks",
            body: JSONEncoder().encode(Body(path:id.rawValue,handle:handle,ranges:ranges,fence:fence,ttlMs:ttlMs)))
    }
    public func renewRanges(filespace: FilespaceID, id: InodeID, handle: String, fence: Int, ttlMs: Int) async throws -> FileLease {
        struct Body: Encodable { let action = "renew"; let path: String; let handle: String; let fence: Int; let ttlMs: Int }
        return try await sendJSON(FileLease.self,"POST",path:"/v1/filespaces/\(filespace)/range-locks",
            body: JSONEncoder().encode(Body(path:id.rawValue,handle:handle,fence:fence,ttlMs:ttlMs)))
    }
    public func releaseRanges(filespace: FilespaceID, id: InodeID, handle: String, fence: Int, ranges: [FileLockRange]?) async throws {
        struct Body: Encodable { let action = "release"; let path: String; let handle: String; let fence: Int; let ranges: [FileLockRange]? }
        struct Result: Decodable { let released: Bool; let reason: String? }
        let result = try await sendJSON(Result.self,"POST",path:"/v1/filespaces/\(filespace)/range-locks",
            body: JSONEncoder().encode(Body(path:id.rawValue,handle:handle,fence:fence,ranges:ranges)))
        guard result.released else { throw EngineError(.locked,result.reason ?? "Byte-range lock changed",data:["reason":.string(result.reason ?? "lease-lost")]) }
    }
    public func releaseReadPermit(filespace: FilespaceID, id: InodeID, handle: String, fence: Int) async throws {
        struct Body: Encodable { let action = "release-read"; let path: String; let handle: String; let fence: Int }
        _ = try await send("POST",path:"/v1/filespaces/\(filespace)/range-locks",
            body: JSONEncoder().encode(Body(path:id.rawValue,handle:handle,fence:fence)))
    }
    public func checkRangeAccess(filespace: FilespaceID, id: InodeID, handle: String, range: FileLockRange, fence: Int?) async throws -> RangeAccess {
        struct Body: Encodable { let action = "check"; let path: String; let handle: String; let range: FileLockRange; let fence: Int? }
        return try await sendJSON(RangeAccess.self,"POST",path:"/v1/filespaces/\(filespace)/range-locks",
            body: JSONEncoder().encode(Body(path:id.rawValue,handle:handle,range:range,fence:fence)))
    }
}
