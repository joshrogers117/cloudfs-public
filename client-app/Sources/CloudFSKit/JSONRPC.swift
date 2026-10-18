// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

// MARK: - Newline-delimited JSON-RPC 2.0 (the cloudfsd control wire)
//
// One JSON object per line, `\n`-terminated, UTF-8 (CONTROL-API.md §1). This file
// holds the wire shapes + the typed error model; DaemonEngineClient layers the
// method calls on top, and UnixSocketConnection moves the bytes.

// MARK: Wire request / response / notification

/// A JSON-RPC request frame. `params` is encoded as an arbitrary JSON object.
struct RPCRequest: Encodable {
    let jsonrpc = "2.0"
    let id: Int
    let method: String
    let params: JSONValue

    enum CodingKeys: String, CodingKey { case jsonrpc, id, method, params }
}

/// A decoded JSON-RPC frame — either a response (has `id`) or a notification
/// (no `id`, carries `method` + `params`).
struct RPCFrame: Decodable {
    let id: Int?
    let method: String?
    let result: JSONValue?
    let error: RPCErrorBody?
    let params: JSONValue?
}

struct RPCErrorBody: Decodable, Sendable {
    let code: Int
    let message: String
    let data: JSONValue?
}

// MARK: - Typed engine errors (CONTROL-API.md §2)

/// The error surface the GUI sees. Transport failures (socket absent/unreachable)
/// are `.unavailable` — the GUI's analog of the CLI `ENGINE_UNAVAILABLE` / exit 42
/// (a transport condition, never a wire error). Wire errors map by `code`.
public enum EngineError: LocalizedError, Sendable, Equatable, CustomStringConvertible {
    case unavailable(String)                 // socket missing / connection dropped
    case invalidParams(String)               // -32602
    case notConnected(String)                // -32010
    case notFound(String)                    // -32020
    case conflict(expected: Int?, actual: Int?, reason: String?)  // -32021
    case locked(heldBy: String?, expiresAt: String?)              // -32022
    case permissionDenied(String)            // -32030
    case gatewayError(status: Int?, reason: String?)              // -32040
    case networkError(String)                // -32041
    case syncTimeout(pendingUploads: Int?, pendingBytes: Int?)    // -32050
    case syncFailed(path: String?, reason: String?)               // -32051
    case internalError(String)               // -32603 / unknown
    case decoding(String)                    // local: malformed frame

    /// SwiftUI banners receive errors through Foundation's localizedDescription.
    /// Preserve the useful daemon/transport explanation when bridged as Error.
    public var errorDescription: String? { description }

    /// Build from a wire error body, pulling structured `data` where the contract
    /// defines it.
    static func from(_ body: RPCErrorBody) -> EngineError {
        let data = body.data
        switch body.code {
        case -32602: return .invalidParams(body.message)
        case -32010: return .notConnected(body.message)
        case -32020: return .notFound(body.message)
        case -32021: return .conflict(expected: data?["expected"]?.intValue,
                                      actual: data?["actual"]?.intValue,
                                      reason: data?["reason"]?.stringValue)
        case -32022: return .locked(heldBy: data?["heldBy"]?.stringValue,
                                    expiresAt: data?["expiresAt"]?.stringValue)
        case -32030:
            // Older daemons collapsed HTTP 401 and 403 into this wire code.
            // Retain ACL denials, but let the app renew a dead engine token.
            let reason = data?["error"]?.stringValue
            let legacyCredentialErrors: Set<String> = ["revoked", "expired", "no_token", "unauthorized", "bad_signature", "malformed"]
            if data?["status"]?.intValue == 401 ||
                (data?["status"] == nil && reason.map(legacyCredentialErrors.contains) == true) {
                return .gatewayError(status: 401, reason: reason ?? body.message)
            }
            return .permissionDenied(body.message)
        case -32040: return .gatewayError(status: data?["status"]?.intValue,
                                          reason: data?["reason"]?.stringValue)
        case -32041: return .networkError(body.message)
        case -32050: return .syncTimeout(pendingUploads: data?["pendingUploads"]?.intValue,
                                         pendingBytes: data?["pendingBytes"]?.intValue)
        case -32051: return .syncFailed(path: data?["path"]?.stringValue,
                                        reason: data?["reason"]?.stringValue)
        case -32603: return .internalError(body.message)
        default:     return .internalError("\(body.code): \(body.message)")
        }
    }

    public var needsCredentialRefresh: Bool {
        if case .gatewayError(let status, _) = self { return status == 401 }
        return false
    }

    public var description: String {
        switch self {
        case .unavailable(let m):        return "Engine unavailable: \(m)"
        case .invalidParams(let m):      return "Invalid params: \(m)"
        case .notConnected(let m):       return "Not connected: \(m)"
        case .notFound(let m):           return "Not found: \(m)"
        case .conflict(let e, let a, let r):
            return "Conflict\(r.map { " (\($0))" } ?? "")\(e != nil ? " expected \(e!) actual \(a ?? -1)" : "")"
        case .locked(let by, _):         return "Locked\(by.map { " by \($0)" } ?? "")"
        case .permissionDenied(let m):   return "Permission denied: \(m)"
        case .gatewayError(let s, let r): return "Gateway error \(s.map(String.init) ?? "")\(r.map { ": \($0)" } ?? "")"
        case .networkError(let m):       return "Network error: \(m)"
        case .syncTimeout:               return "Sync timed out"
        case .syncFailed(let p, let r):  return "Sync failed\(p.map { " for \($0)" } ?? "")\(r.map { ": \($0)" } ?? "")"
        case .internalError(let m):      return "Engine error: \(m)"
        case .decoding(let m):           return "Malformed engine response: \(m)"
        }
    }
}

// MARK: - JSONValue
//
// A small, Sendable, dynamic JSON value so we can build params and read results
// without a hand-written Codable type per method. (Method results are decoded
// into typed structs via JSONValue.decode(_:).)

public enum JSONValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    // Subscripts / accessors for ergonomic reads.
    public subscript(_ key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }
    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var intValue: Int? {
        switch self {
        case .int(let i): return i
        case .double(let d): return Int(d)
        case .string(let s): return Int(s)
        default: return nil
        }
    }
    public var doubleValue: Double? {
        switch self {
        case .double(let d): return d
        case .int(let i): return Double(i)
        default: return nil
        }
    }
    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
}

extension JSONValue: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        if let b = try? c.decode(Bool.self) { self = .bool(b); return }
        if let i = try? c.decode(Int.self) { self = .int(i); return }
        if let d = try? c.decode(Double.self) { self = .double(d); return }
        if let s = try? c.decode(String.self) { self = .string(s); return }
        if let a = try? c.decode([JSONValue].self) { self = .array(a); return }
        if let o = try? c.decode([String: JSONValue].self) { self = .object(o); return }
        throw DecodingError.dataCorruptedError(in: c, debugDescription: "Unsupported JSON")
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null:          try c.encodeNil()
        case .bool(let b):   try c.encode(b)
        case .int(let i):    try c.encode(i)
        case .double(let d): try c.encode(d)
        case .string(let s): try c.encode(s)
        case .array(let a):  try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}

extension JSONValue {
    /// Build an `.object` from a `[String: JSONValue?]`, dropping nil entries.
    static func params(_ dict: [String: JSONValue?]) -> JSONValue {
        var o: [String: JSONValue] = [:]
        for (k, v) in dict { if let v { o[k] = v } }
        return .object(o)
    }

    /// Re-decode this value into a typed Decodable (method result mapping).
    func decode<T: Decodable>(_ type: T.Type) throws -> T {
        let data = try JSONEncoder().encode(self)
        return try JSONDecoder().decode(T.self, from: data)
    }
}
