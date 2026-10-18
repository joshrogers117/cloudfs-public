// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSCore — JSON-RPC 2.0 envelope. FROZEN (CONTROL-API.md §1.1).
//
// Newline-delimited JSON-RPC 2.0 over a Unix-domain socket. These are the wire
// frames; the typed request/response payloads are in Contract.swift.

import Foundation

/// A JSON-RPC id: number or string (the server echoes whatever the client sent).
public enum RPCID: Sendable, Codable, Equatable, Hashable {
    case number(Int)
    case string(String)

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let i = try? c.decode(Int.self) { self = .number(i); return }
        self = .string(try c.decode(String.self))
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .number(let i): try c.encode(i)
        case .string(let s): try c.encode(s)
        }
    }
}

/// A request frame: `{ jsonrpc, id, method, params }`. `params` stays as raw
/// `CodableValue` here; the typed decode happens per-method in Contract.swift.
public struct RPCRequest: Sendable, Codable {
    public let jsonrpc: String
    public let id: RPCID?            // nil => notification (no reply expected)
    public let method: String
    public let params: CodableValue?
    public init(id: RPCID?, method: String, params: CodableValue? = nil) {
        self.jsonrpc = "2.0"; self.id = id; self.method = method; self.params = params
    }
}

/// A response frame: exactly one of `result` / `error` is present.
public struct RPCResponse: Sendable, Codable {
    public let jsonrpc: String
    public let id: RPCID?
    public let result: CodableValue?
    public let error: RPCError?

    public init(id: RPCID?, result: CodableValue) {
        self.jsonrpc = "2.0"; self.id = id; self.result = result; self.error = nil
    }
    public init(id: RPCID?, error: RPCError) {
        self.jsonrpc = "2.0"; self.id = id; self.result = nil; self.error = error
    }
}

/// The JSON-RPC error object `{ code, message, data? }` (CONTROL-API.md §1.1/§2).
public struct RPCError: Sendable, Codable, Equatable {
    public let code: Int
    public let message: String
    public let data: CodableValue?
    public init(code: Int, message: String, data: CodableValue? = nil) {
        self.code = code; self.message = message; self.data = data
    }
    /// Build directly from an EngineError so the code/message stay 1:1.
    public init(_ e: EngineError) {
        self.code = e.jsonrpcCode
        self.message = e.message
        if let d = e.data { self.data = .object(d) } else { self.data = nil }
    }
}

/// A server→client notification (event stream): no `id`, no reply.
/// CONTROL-API.md §6: methods `transfer` | `activity` | `cache` | `mount`.
public struct RPCNotification: Sendable, Codable {
    public let jsonrpc: String
    public let method: String
    public let params: CodableValue
    public init(method: String, params: CodableValue) {
        self.jsonrpc = "2.0"; self.method = method; self.params = params
    }
}
