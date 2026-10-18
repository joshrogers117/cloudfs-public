// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// One admission gate for every UI-triggered mount. Sign-out closes admission
/// and drains existing operations before taking the daemon's final mount list.
/// Main-actor ownership makes admission atomic with the GUI's session checks.
@MainActor
public final class MountOperationGate {
    public enum GateError: Error, Equatable { case signingOut }
    public private(set) var acceptsMounts = true
    public private(set) var generation = UUID()
    private var active = 0
    private var drains: [CheckedContinuation<Void, Never>] = []

    public init() {}

    public func perform<T: Sendable>(generation expected: UUID, _ operation: @MainActor () async throws -> T) async throws -> T {
        guard expected == generation, acceptsMounts else { throw GateError.signingOut }
        active += 1
        defer {
            active -= 1
            if active == 0 {
                let waiting = drains
                drains.removeAll()
                for continuation in waiting { continuation.resume() }
            }
        }
        return try await operation()
    }

    /// Stays closed after draining, including while flush/unmount/auth cleanup
    /// suspend. The caller reopens only when sign-out has completed or failed.
    public func closeAndDrain() async {
        if acceptsMounts { generation = UUID() } // late continuations from the old session stay invalid after reopen
        acceptsMounts = false
        guard active > 0 else { return }
        await withCheckedContinuation { drains.append($0) }
    }

    public func reopen() {
        precondition(active == 0, "Cannot reopen before outstanding mounts have drained")
        acceptsMounts = true
    }
}
