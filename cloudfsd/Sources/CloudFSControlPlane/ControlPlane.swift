// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSControlPlane — the UDS JSON-RPC server seam (THE control-plane). (DESIGN.md §6)
//
// Owner (next round): CONTROL. Listens on the Unix-domain socket, decodes
// newline-delimited JSON-RPC 2.0 frames (CloudFSCore.RPCRequest), dispatches each
// `ControlMethod` to a backing `Engine`, encodes `RPCResponse`/`RPCError`, and
// fans the `Engine.events(...)` stream out as `RPCNotification`s. The error model
// maps 1:1 to the CLI exit codes via `EngineError` (CONTROL-API.md §2).
//
// THIS FILE DEFINES THE PROTOCOL + A STUB. The real server is the next round.

import Foundation
import CloudFSCore

public protocol ControlPlane: Sendable {
    /// Start serving on `socketPath`, dispatching to `engine`. Returns when the
    /// listener is bound; serves until `stop()`.
    func serve(socketPath: String, engine: any Engine) async throws
    func stop() async
}

/// Foundation stub: compiles green, throws `.unimplemented`.
public struct StubControlPlane: ControlPlane {
    public init() {}
    public func serve(socketPath: String, engine: any Engine) async throws {
        throw EngineError.unimplemented("ControlPlane.serve")
    }
    public func stop() async {}
}

/// Pure helper (no I/O): turn any thrown error into the wire `RPCError`, mapping
/// `EngineError` 1:1 and defaulting unknown errors to `internal`. Lives here so
/// the real server and tests share one mapping. Frozen behavior.
public func rpcError(for error: any Error, id: RPCID?) -> RPCResponse {
    let e = (error as? EngineError) ?? EngineError(.internal, String(describing: error))
    return RPCResponse(id: id, error: RPCError(e))
}
