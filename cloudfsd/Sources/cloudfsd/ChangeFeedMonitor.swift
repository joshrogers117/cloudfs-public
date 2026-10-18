// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore
import CloudFSGateway

/// The cursor is advanced only after the consumer applies the page. A dropped
/// hint, reconnect or process restart therefore resumes the durable HTTP feed.
actor ChangeFeedMonitor {
    private struct Checkpoint: Codable { var anchor: Int; var visibility: String? }
    private let gateway: any GatewayClient
    private let filespace: FilespaceID
    private let checkpointURL: URL
    private let accessLost: @Sendable () async -> Void
    private let apply: @Sendable (GatewayChangePage, Bool) async throws -> Void
    private var checkpoint: Checkpoint
    private var initial = true
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    init(gateway: any GatewayClient, filespace: FilespaceID, checkpointURL: URL,
         accessLost: @escaping @Sendable () async -> Void = {},
         apply: @escaping @Sendable (GatewayChangePage, Bool) async throws -> Void) {
        self.gateway = gateway; self.filespace = filespace; self.checkpointURL = checkpointURL; self.apply = apply; self.accessLost = accessLost
        checkpoint = (try? JSONDecoder().decode(Checkpoint.self, from: Data(contentsOf: checkpointURL))) ?? Checkpoint(anchor: 0, visibility: nil)
    }
    func replay() async throws {
        while busy { await withCheckedContinuation { waiters.append($0) } }
        busy = true
        defer { busy = false; let pending = waiters; waiters.removeAll(); for waiter in pending { waiter.resume() } }
        while true {
            try Task.checkCancellation()
            let page: GatewayChangePage
            do { page = try await gateway.changePage(filespace: filespace, since: checkpoint.anchor) }
            catch {
                if (error as? EngineError)?.kind == .permissionDenied { initial = true; await accessLost() }
                throw error
            }
            let reset = initial || page.visibility != checkpoint.visibility || page.anchor < checkpoint.anchor
            // A restored server can have an older sequence than our checkpoint.
            // Start over rather than accepting a permanently unreachable cursor.
            if page.anchor < checkpoint.anchor {
                checkpoint.anchor = 0; initial = true
                continue
            }
            let next = page.cursor ?? page.anchor
            guard next >= checkpoint.anchor, page.cursor == nil || next > checkpoint.anchor else {
                throw EngineError(.gatewayError, "Change feed did not advance")
            }
            do { try await apply(page, reset) }
            catch {
                if (error as? EngineError)?.kind == .permissionDenied { initial = true; await accessLost() }
                throw error
            }
            let updated = Checkpoint(anchor: next, visibility: page.visibility)
            try FileManager.default.createDirectory(at: checkpointURL.deletingLastPathComponent(), withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])
            try JSONEncoder().encode(updated).write(to: checkpointURL, options: .atomic)
            checkpoint = updated; initial = false
            if page.cursor == nil { return }
        }
    }
    nonisolated func run() async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { [self] in
                // Fallback also catches identity/group changes and grant expiry
                // that happen without a content mutation on this authority.
                while !Task.isCancelled {
                    try? await replay()
                    do { try await Task.sleep(for: .seconds(5)) } catch { return }
                }
            }
            group.addTask { [self] in
                var delay: Double = 1
                while !Task.isCancelled {
                    do {
                        let hints = try await gateway.changeHints(filespace: filespace)
                        for try await hint in hints {
                            try Task.checkCancellation()
                            try await replay()
                            try await hint.acknowledge()
                            delay = 1
                        }
                    } catch {}
                    do { try await Task.sleep(for: .seconds(delay)) } catch { return }
                    delay = min(30, delay * 2)
                }
            }
            await group.waitForAll()
        }
    }
}

/// A versioned wakeup avoids losing a notification between the SMB baseline
/// enumeration and installing its waiter. Polling remains a bounded fallback.
actor ChangeSignal {
    private var generation: UInt64 = 0
    private var waiters: [UUID: CheckedContinuation<UInt64, Never>] = [:]
    func current() -> UInt64 { generation }
    func signal() {
        generation &+= 1
        let pending = waiters; waiters.removeAll()
        for waiter in pending.values { waiter.resume(returning: generation) }
    }
    private func finish(_ id: UUID) { waiters.removeValue(forKey: id)?.resume(returning: generation) }
    func wait(after: UInt64) async -> UInt64 {
        if after != generation || Task.isCancelled { return generation }
        let id = UUID()
        let timer = Task { try? await Task.sleep(for: .milliseconds(2500)); if !Task.isCancelled { finish(id) } }
        defer { timer.cancel() }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled { continuation.resume(returning: generation) }
                else { waiters[id] = continuation }
            }
        } onCancel: { Task { await self.finish(id) } }
    }
}
