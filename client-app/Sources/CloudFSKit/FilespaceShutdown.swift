// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation

/// Finish pending writes before removing any mounted volume. The caller closes
/// and drains its mount-admission gate first, so this list is authoritative.
public enum FilespaceShutdown {
    public static func drain(_ engine: any EngineClient) async throws {
        let records = try await engine.filespaceList()
        var resumed: [String] = []
        do {
            for record in records where record.paused == true {
                try await engine.resumeTransfers(filespace: record.id)
                resumed.append(record.id)
            }
            for record in records {
                _ = try await engine.flush(filespace: record.id, path: "", wait: true, timeoutMs: 60_000)
            }
            for record in records where !(record.mountPath ?? "").isEmpty {
                _ = try await engine.unmount(filespace: record.id, force: false)
            }
            // Editors can save between the first barrier and kernel detach.
            // Once every volume is closed, drain those final acknowledged
            // writes too. This also protects older daemons whose unmount only
            // guarantees local journal durability, before credentials go away.
            for record in records {
                _ = try await engine.flush(filespace: record.id, path: "", wait: true, timeoutMs: 60_000)
            }
        } catch {
            // An unsuccessful Quit/Sign Out returns to the user's prior pause
            // preference, with credentials and journal still available to retry.
            for filespace in resumed { try? await engine.pauseTransfers(filespace: filespace) }
            throw error
        }
    }
}
