// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Darwin

// MARK: - MountProbe — the verified mount check (ONBOARDING.md §4)
//
// READ-ONLY by design: every check used to write and delete a hidden file at
// the filespace root, which is a real remote commit visible to the whole
// team. The check now consults the kernel mount table and lists the root
// directory through the mount. It never creates, modifies or deletes anything.

public enum MountProbeResult: Equatable, Sendable {
    /// Mounted (kernel table) and the root directory listing succeeded.
    case listed
    case failed(MountProbeFailure)

    public var failure: MountProbeFailure? {
        if case .failed(let value) = self { return value }
        return nil
    }
}

public enum MountProbe {

    /// A newly mounted volume can briefly change while startup reconciles the
    /// kernel and daemon state. Retry the whole read-only check, never merely
    /// turn a failed result into success. Persistent failures stay actionable.
    public static func verifyWhenReady(
        mountRoot: String, maximumAttempts: Int = 3,
        retryDelay: Duration = .milliseconds(300),
        probe: @Sendable (String) async -> MountProbeResult = { path in
            await Task.detached { verify(mountRoot: path) }.value
        }
    ) async throws -> MountProbeResult {
        let attempts = max(1, maximumAttempts)
        for index in 0..<attempts {
            try Task.checkCancellation()
            let result = await probe(mountRoot)
            try Task.checkCancellation()
            guard case .failed(.mountFailed) = result, index + 1 < attempts else { return result }
            try await Task.sleep(for: retryDelay)
        }
        preconditionFailure("At least one probe attempt must return")
    }

    @discardableResult
    public static func run(mountRoot: String, fileManager: FileManager = .default,
                           mountIsPresent: ((String) -> Bool)? = nil) -> MountProbeFailure? {
        verify(mountRoot: mountRoot, fileManager: fileManager, mountIsPresent: mountIsPresent).failure
    }

    public static func verify(mountRoot: String, fileManager: FileManager = .default,
                              mountIsPresent: ((String) -> Bool)? = nil) -> MountProbeResult {
        guard !mountRoot.isEmpty else { return .failed(.mountFailed("The mount point isn't on disk yet.")) }
        let isPresent = mountIsPresent ?? KernelMountProbe.isMounted
        // Check the kernel table before any path operation that could block
        // against a disconnected network volume or mistake a local folder for it.
        guard isPresent(mountRoot) else {
            return .failed(.mountFailed("The CloudFS volume isn't connected. Connect it before running the check."))
        }
        var isDir: ObjCBool = false
        guard fileManager.fileExists(atPath: mountRoot, isDirectory: &isDir), isDir.boolValue else {
            return .failed(.mountFailed("The mount point isn't on disk yet."))
        }
        do {
            _ = try fileManager.contentsOfDirectory(atPath: mountRoot)
        } catch {
            return .failed(.mountFailed("Couldn't browse the connected filespace: " + error.localizedDescription))
        }
        guard isPresent(mountRoot) else {
            return .failed(.mountFailed("The CloudFS volume disconnected during the check."))
        }
        return .listed
    }

    /// A leftover local folder must never be shown as a connected filespace.
    public static func isCloudFSMounted(mountRoot: String) -> Bool {
        KernelMountProbe.isMounted(mountRoot)
    }
}
