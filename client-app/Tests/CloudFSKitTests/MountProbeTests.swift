// SPDX-License-Identifier: AGPL-3.0-or-later
import Testing
import Foundation
@testable import CloudFSKit

// ONBOARDING.md build step 4 — the read-only mount probe: kernel mount table
// plus a root listing; it never writes. Real FileManager I/O against a temp
// directory standing in for a mount point.

@Suite struct MountProbeTests {

    private actor ProbeSequence {
        var results: [MountProbeResult]
        var calls = 0
        init(_ results: [MountProbeResult]) { self.results = results }
        func next() -> MountProbeResult {
            calls += 1
            return results.count > 1 ? results.removeFirst() : results[0]
        }
    }

    @Test func startupProbeRechecksTransientMountFailure() async throws {
        let sequence = ProbeSequence([.failed(.mountFailed("Mount is changing")), .listed])
        let result = try await MountProbe.verifyWhenReady(mountRoot: "/unused", retryDelay: .zero) { _ in
            await sequence.next()
        }
        #expect(result == .listed)
        #expect(await sequence.calls == 2)
    }

    @Test func startupProbeNeverHidesPersistentFailure() async throws {
        let failure = MountProbeResult.failed(.mountFailed("Volume disconnected"))
        let sequence = ProbeSequence([failure])
        let result = try await MountProbe.verifyWhenReady(mountRoot: "/unused", retryDelay: .zero) { _ in
            await sequence.next()
        }
        #expect(result == failure)
        #expect(await sequence.calls == 3)
    }

    @Test func cancelledStartupProbeStopsBeforeTryingAgain() async {
        let sequence = ProbeSequence([.failed(.mountFailed("Volume disconnected"))])
        let task = Task {
            try await MountProbe.verifyWhenReady(mountRoot: "/unused", retryDelay: .seconds(60)) { _ in
                await sequence.next()
            }
        }
        while await sequence.calls == 0 { await Task.yield() }
        task.cancel()
        do { _ = try await task.value; Issue.record("Cancelled probe returned a result") }
        catch is CancellationError {} catch { Issue.record("Unexpected error: \(error)") }
        #expect(await sequence.calls == 1)
    }

    /// A fresh temp directory per test, auto-cleaned.
    private func tempDir() -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cloudfs-mountprobe-\(UUID().uuidString)", isDirectory: true)
        try! FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func listsRootAfterMountVerificationAndWritesNothing() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        try Data("x".utf8).write(to: dir.appendingPathComponent("existing.txt"))

        #expect(MountProbe.verify(mountRoot: dir.path, mountIsPresent: { _ in true }) == .listed)
        #expect(MountProbe.run(mountRoot: dir.path, mountIsPresent: { _ in true }) == nil)

        // Read-only: the directory is byte-for-byte what it was (no probe file).
        let entries = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        #expect(entries == ["existing.txt"])
    }

    @Test func probeWorksOnAReadOnlyRootWithoutAttemptingToWrite() throws {
        let dir = tempDir()
        try FileManager.default.setAttributes([.posixPermissions: 0o555], ofItemAtPath: dir.path)
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
            try? FileManager.default.removeItem(at: dir)
        }
        #expect(MountProbe.verify(mountRoot: dir.path, mountIsPresent: { _ in true }) == .listed)
    }

    @Test func ordinaryLocalDirectoryCannotPassAsCloudVolume() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let failure = MountProbe.run(mountRoot: dir.path)
        #expect(failure == .mountFailed("The CloudFS volume isn't connected. Connect it before running the check."))
        #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
    }

    @Test func presenceRequiresActualSMBTypeLoopbackIdentityAndExactRoot() {
        let root = "/Volumes/Project"
        #expect(KernelMountProbe.matches(path: root, filesystem: "smbfs", source: "//cfs-user@127.0.0.1:4000/Project", expectedPath: root))
        #expect(!KernelMountProbe.matches(path: root, filesystem: "apfs", source: "/dev/disk1", expectedPath: root))
        #expect(!KernelMountProbe.matches(path: root, filesystem: "smbfs", source: "//josh@nas.local/Project", expectedPath: root))
        #expect(!KernelMountProbe.matches(path: root, filesystem: "smbfs", source: "//other@127.0.0.1:4000/Project", expectedPath: root))
        #expect(!KernelMountProbe.matches(path: root + "-other", filesystem: "smbfs", source: "//cfs-user@127.0.0.1:4000/Project", expectedPath: root))
    }

    @Test func ejectDuringProbeCannotReportSuccess() {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        var calls = 0
        let failure = MountProbe.run(mountRoot: dir.path, mountIsPresent: { _ in calls += 1; return calls == 1 })
        #expect(failure == .mountFailed("The CloudFS volume disconnected during the check."))
    }

    @Test func unreadableRootFailsAsMountFailed() throws {
        let dir = tempDir()
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: dir.path)
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dir.path)
            try? FileManager.default.removeItem(at: dir)
        }
        if case .mountFailed = MountProbe.run(mountRoot: dir.path, mountIsPresent: { _ in true }) {} else {
            Issue.record("expected .mountFailed")
        }
    }

    @Test func mountNotOnDiskYetFailsAsMountFailed() {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("cloudfs-mountprobe-missing-\(UUID().uuidString)")
        let failure = MountProbe.run(mountRoot: missing.path, mountIsPresent: { _ in true })
        #expect(failure == .mountFailed("The mount point isn't on disk yet."))
    }

    @Test func emptyMountRootFailsAsMountFailed() {
        let failure = MountProbe.run(mountRoot: "")
        if case .mountFailed = failure {} else { Issue.record("expected .mountFailed, got \(String(describing: failure))") }
    }

    @Test func aFileAtTheMountRootPathIsNotTreatedAsAMountedDirectory() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let fileNotDir = dir.appendingPathComponent("not-a-directory")
        try Data("x".utf8).write(to: fileNotDir)

        let failure = MountProbe.run(mountRoot: fileNotDir.path, mountIsPresent: { _ in true })
        #expect(failure == .mountFailed("The mount point isn't on disk yet."))
    }
}
