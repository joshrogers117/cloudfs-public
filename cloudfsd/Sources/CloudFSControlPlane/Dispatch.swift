// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSControlPlane — method dispatch (CONTROL-API.md §4–8).
//
// Decodes a typed params struct out of an `RPCRequest`, calls the matching
// `Engine` method, and encodes the result back into an `RPCResponse`. Errors are
// mapped 1:1 via `rpcError(...)`. `events.subscribe`/`events.unsubscribe` are
// handled by the connection (they touch transport state), so they are NOT routed
// here — the dispatcher returns `.subscribe`/`.unsubscribe` directives for them.
//
// Pure of socket I/O: it takes an `Engine` and an `RPCRequest`, returns an outcome.
// That makes the entire method surface unit-testable without a socket.

import Foundation
import CloudFSCore

/// What the connection should do after the dispatcher handles a request.
enum DispatchOutcome: Sendable {
    /// Send this response frame back to the caller.
    case reply(RPCResponse)
    /// The request was a notification (no `id`): send nothing.
    case silent
    /// `events.subscribe`: register this connection for the stream, then reply.
    case subscribe(EventsSubscribeParams, RPCResponse)
    /// `events.unsubscribe`: tear down this connection's stream, then reply.
    case unsubscribe(RPCResponse)
}

enum Dispatcher {
    private static let decoder = JSONDecoder()

    /// Decode a request's `params` into the typed struct `T`.
    /// A `nil` params is allowed only for the no-arg shapes (decoded as `{}`).
    private static func params<T: Decodable>(_ req: RPCRequest, as: T.Type) throws -> T {
        let raw = req.params ?? .object([:])
        do {
            let data = try FrameEncoder.encoder.encode(raw)
            return try decoder.decode(T.self, from: data)
        } catch {
            throw EngineError(.invalidParams, "invalid params for \(req.method): \(error)")
        }
    }

    /// Wrap any `Encodable` result into a `CodableValue` for the response frame.
    private static func result<T: Encodable>(_ value: T) throws -> CodableValue {
        let data = try FrameEncoder.encoder.encode(value)
        return try decoder.decode(CodableValue.self, from: data)
    }

    /// Route one request to the engine. Never throws — every failure becomes an
    /// `RPCError` reply (or `.silent` for a notification).
    static func dispatch(_ req: RPCRequest, engine: any Engine) async -> DispatchOutcome {
        // A frame with no id is a notification: we never reply, even on error.
        let isNotification = (req.id == nil)

        func ok(_ value: CodableValue) -> DispatchOutcome {
            isNotification ? .silent : .reply(RPCResponse(id: req.id, result: value))
        }
        func fail(_ error: any Error) -> DispatchOutcome {
            isNotification ? .silent : .reply(rpcError(for: error, id: req.id))
        }

        guard let method = ControlMethod(rawValue: req.method) else {
            return fail(EngineError(.invalidParams, "unknown method: \(req.method)"))
        }

        do {
            switch method {
            // §4 filespace / connection
            case .filespaceList:
                return ok(try result(try await engine.filespaceList()))
            case .filespaceConnect:
                return ok(try result(try await engine.connect(params(req, as: FilespaceConnectParams.self))))
            case .filespaceDisconnect:
                return ok(try result(try await engine.disconnect(params(req, as: FilespaceDisconnectParams.self))))
            case .filespaceSetConnection:
                return ok(try result(try await engine.setConnectionState(params(req, as: FilespaceSetConnectionParams.self))))

            // §5.1 mount
            case .mount:
                return ok(try result(try await engine.mount(params(req, as: MountParams.self))))
            case .unmount:
                return ok(try result(try await engine.unmount(params(req, as: UnmountParams.self))))

            case .snapshotMount:
                return ok(try result(try await engine.snapshotMount(params(req, as: SnapshotMountParams.self))))
            case .snapshotUnmount:
                return ok(try result(try await engine.snapshotUnmount(params(req, as: SnapshotUnmountParams.self))))
            case .snapshotMounts:
                return ok(try result(try await engine.snapshotMounts(params(req, as: SnapshotMountsParams.self))))

            // §5.2 status — array when `filespace` omitted, single object otherwise.
            case .status:
                let p = try params(req, as: StatusParams.self)
                let statuses = try await engine.status(p)
                if p.filespace == nil {
                    return ok(try result(statuses))
                } else {
                    guard let first = statuses.first else {
                        return fail(EngineError(.notFound, "no status for filespace \(p.filespace ?? "")"))
                    }
                    return ok(try result(first))
                }

            // §5.3 cache
            case .cacheInfo:
                return ok(try result(try await engine.cacheInfo(params(req, as: CacheInfoParams.self))))
            case .cacheSetSize:
                return ok(try result(try await engine.cacheSetSize(params(req, as: CacheSetSizeParams.self))))
            case .cacheSetLocation:
                return ok(try result(try await engine.cacheSetLocation(params(req, as: CacheSetLocationParams.self))))
            case .cacheClear:
                return ok(try result(try await engine.cacheClear(params(req, as: CacheClearParams.self))))

            // §5.4 pin / prefetch / evict
            case .pin:
                return ok(try result(try await engine.pin(params(req, as: PinParams.self))))
            case .unpin:
                return ok(try result(try await engine.unpin(params(req, as: PinParams.self))))
            case .pinList:
                return ok(try result(try await engine.pinList(params(req, as: FilespaceOnlyParams.self))))
            case .prefetch:
                return ok(try result(try await engine.prefetch(params(req, as: PathParams.self))))
            case .evict:
                return ok(try result(try await engine.evict(params(req, as: PathParams.self))))

            case .linkCreate:
                return ok(try result(try await engine.linkCreate(params(req, as: LinkCreateParams.self))))
            case .linkResolve:
                return ok(try result(try await engine.linkResolve(params(req, as: LinkResolveParams.self))))

            // §5.5 transfers
            case .transfersCurrent:
                return ok(try result(try await engine.transfersCurrent(params(req, as: FilespaceOnlyParams.self))))
            case .transfersPause:
                return ok(try result(try await engine.transfersPause(params(req, as: FilespaceOnlyParams.self))))
            case .transfersResume:
                return ok(try result(try await engine.transfersResume(params(req, as: FilespaceOnlyParams.self))))
            case .recoveryList:
                return ok(try result(try await engine.recoveryList(params(req, as: FilespaceOnlyParams.self))))
            case .recoveryRetry:
                try await engine.recoveryRetry(params(req, as: RecoveryItemParams.self))
                return ok(.object([:]))
            case .recoveryExport:
                return ok(try result(try await engine.recoveryExport(params(req, as: RecoveryExportParams.self))))
            case .recoveryComplete:
                try await engine.recoveryComplete(params(req, as: RecoveryExportParams.self))
                return ok(.object([:]))

            // §5.6 sync barriers
            case .syncState:
                return ok(try result(try await engine.syncState(params(req, as: SyncStateParams.self))))
            case .flush:
                return ok(try result(try await engine.flush(params(req, as: FlushParams.self))))

            // §7 data path (out-of-process: File Provider appex)
            case .dataReadRange:
                return ok(try result(try await engine.dataReadRange(params(req, as: DataReadRangeParams.self))))
            case .dataLookup:
                return ok(try result(try await engine.dataLookup(params(req, as: DataLookupParams.self))))
            case .dataEnumerate:
                return ok(try result(try await engine.dataEnumerate(params(req, as: DataEnumerateParams.self))))
            case .dataEnumerateChanges:
                return ok(try result(try await engine.dataEnumerateChanges(params(req, as: DataEnumerateChangesParams.self))))

            // §6 events — transport-level: handled by the connection.
            case .eventsSubscribe:
                let p = try params(req, as: EventsSubscribeParams.self)
                let reply = RPCResponse(id: req.id, result: try result(SubscribedResult(subscribed: true)))
                return .subscribe(p, reply)
            case .eventsUnsubscribe:
                _ = try params(req, as: EmptyParams.self)
                let reply = RPCResponse(id: req.id, result: try result(SubscribedResult(subscribed: false)))
                return .unsubscribe(reply)

            // §8 versioning
            case .systemVersion:
                return ok(try result(try await engine.systemVersion()))
            }
        } catch {
            return fail(error)
        }
    }
}

/// `{}` params for the no-arg methods (`events.unsubscribe`).
struct EmptyParams: Codable, Sendable { init() {} ; init(from decoder: Decoder) throws {} }

/// Encode an `EventNotification` to a wire `RPCNotification` (no id).
func notificationFrame(for n: EventNotification) throws -> RPCNotification {
    let payload: CodableValue
    switch n {
    case let .transfer(filespace, transfer):
        payload = try encodeObject(["filespace": .string(filespace)], merging: transfer, key: "transfer")
    case let .activity(filespace, event):
        payload = try encodeObject(["filespace": .string(filespace)], merging: event, key: "event")
    case let .cache(filespace, cache):
        payload = try encodeObject(["filespace": .string(filespace)], merging: cache, key: "cache")
    case let .mount(filespace, status):
        payload = try encodeObject(["filespace": .string(filespace)], merging: status, key: "status")
    }
    return RPCNotification(method: n.method, params: payload)
}

/// Build `{ ...base, key: <encoded value> }` as a `CodableValue` object.
private func encodeObject<T: Encodable>(_ base: [String: CodableValue],
                                        merging value: T, key: String) throws -> CodableValue {
    let data = try FrameEncoder.encoder.encode(value)
    let encoded = try JSONDecoder().decode(CodableValue.self, from: data)
    var obj = base
    obj[key] = encoded
    return .object(obj)
}
