// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCore — error model. FROZEN (CONTROL-API.md §2).
//
// One error taxonomy, mapping 1:1 onto BOTH:
//   - JSON-RPC error `code` on the control-plane wire, and
//   - the CLI's stable exit codes (cli/src/exit-codes.ts), so the CLI surfaces
//     the right exit code with no extra translation table.
//
// `.unimplemented` is the stub sentinel every module's StubXxx throws so the
// package compiles GREEN before any module is built (round D2a foundation).

import Foundation

/// The canonical engine error. Carries the JSON-RPC code, the CLI exit code, a
/// message, and optional structured `data` (e.g. version-conflict expected/actual).
public struct EngineError: Error, Sendable, Codable, Equatable {
    public let kind: Kind
    public let message: String
    public let data: [String: CodableValue]?

    public init(_ kind: Kind, _ message: String? = nil, data: [String: CodableValue]? = nil) {
        self.kind = kind
        self.message = message ?? kind.defaultMessage
        self.data = data
    }

    /// JSON-RPC 2.0 `error.code`.
    public var jsonrpcCode: Int { kind.jsonrpcCode }
    /// CLI process exit code (cli/src/exit-codes.ts).
    public var exitCode: Int { kind.exitCode }

    // MARK: Error taxonomy

    public enum Kind: String, Sendable, Codable, CaseIterable {
        case invalidParams        // -32602 / exit 2  USAGE
        case notConnected         // -32010 / exit 23 NOT_CONNECTED
        case notFound             // -32020 / exit 20 NOT_FOUND
        case conflict             // -32021 / exit 21 CONFLICT
        case locked               // -32022 / exit 22 LOCKED
        case permissionDenied     // -32030 / exit 30 PERMISSION_DENIED
        case gatewayError         // -32040 / exit 40 GATEWAY_ERROR
        case networkError         // -32041 / exit 41 NETWORK_ERROR
        case syncTimeout          // -32050 / exit 50 SYNC_TIMEOUT
        case syncFailed           // -32051 / exit 51 SYNC_FAILED
        case `internal`           // -32603 / exit 1  GENERIC
        /// Stub sentinel: a not-yet-implemented module method (foundation round).
        case unimplemented        // -32603 / exit 1  GENERIC (surfaced as internal on the wire)

        public var jsonrpcCode: Int {
            switch self {
            case .invalidParams:    return -32602
            case .notConnected:     return -32010
            case .notFound:         return -32020
            case .conflict:         return -32021
            case .locked:           return -32022
            case .permissionDenied: return -32030
            case .gatewayError:     return -32040
            case .networkError:     return -32041
            case .syncTimeout:      return -32050
            case .syncFailed:       return -32051
            case .internal:         return -32603
            case .unimplemented:    return -32603
            }
        }

        public var exitCode: Int {
            switch self {
            case .invalidParams:    return 2
            case .notConnected:     return 23
            case .notFound:         return 20
            case .conflict:         return 21
            case .locked:           return 22
            case .permissionDenied: return 30
            case .gatewayError:     return 40
            case .networkError:     return 41
            case .syncTimeout:      return 50
            case .syncFailed:       return 51
            case .internal:         return 1
            case .unimplemented:    return 1
            }
        }

        public var defaultMessage: String {
            switch self {
            case .invalidParams:    return "invalid params"
            case .notConnected:     return "filespace not connected"
            case .notFound:         return "not found"
            case .conflict:         return "version conflict"
            case .locked:           return "locked by another holder"
            case .permissionDenied: return "permission denied"
            case .gatewayError:     return "gateway error"
            case .networkError:     return "network error"
            case .syncTimeout:      return "sync barrier timed out"
            case .syncFailed:       return "sync failed"
            case .internal:         return "internal engine error"
            case .unimplemented:    return "not implemented (cloudfsd foundation stub)"
            }
        }
    }

    /// Convenience for the module stubs.
    public static func unimplemented(_ what: String = #function) -> EngineError {
        EngineError(.unimplemented, "\(what) is not implemented (cloudfsd foundation stub)")
    }
}

/// A minimal JSON value so `EngineError.data` (and JSON-RPC params) stay Codable
/// without `Any`. Covers the shapes CONTROL-API.md needs (numbers, strings,
/// bools, null, nested objects/arrays for `{expected,actual}` etc.).
public enum CodableValue: Sendable, Codable, Equatable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case null
    case array([CodableValue])
    case object([String: CodableValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        if let b = try? c.decode(Bool.self) { self = .bool(b); return }
        if let i = try? c.decode(Int.self) { self = .int(i); return }
        if let d = try? c.decode(Double.self) { self = .double(d); return }
        if let s = try? c.decode(String.self) { self = .string(s); return }
        if let a = try? c.decode([CodableValue].self) { self = .array(a); return }
        if let o = try? c.decode([String: CodableValue].self) { self = .object(o); return }
        throw DecodingError.dataCorruptedError(in: c, debugDescription: "unsupported JSON value")
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .int(let i):    try c.encode(i)
        case .double(let d): try c.encode(d)
        case .bool(let b):   try c.encode(b)
        case .null:          try c.encodeNil()
        case .array(let a):  try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }
}
