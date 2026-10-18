// SPDX-License-Identifier: AGPL-3.0-or-later
// CloudFSSMB backend helpers (non-live) + a gated real-mount smoke test.

import XCTest
import Foundation
import CryptoKit
import CloudFSCore
import CloudFSMount
@testable import CloudFSSMB

extension Data {
    var sha256Hex: String { SHA256.hash(data: self).map { String(format: "%02x", $0) }.joined() }
}

final class WildcardTests: XCTestCase {
    func testSMBWildcardMatch() {
        XCTAssertTrue(SMBWildcard.match(name: "clip.bin", pattern: "*"))
        XCTAssertTrue(SMBWildcard.match(name: "clip.bin", pattern: "clip.bin"))
        XCTAssertTrue(SMBWildcard.match(name: "clip.bin", pattern: "*.bin"))
        XCTAssertTrue(SMBWildcard.match(name: "clip.bin", pattern: "clip.*"))
        XCTAssertTrue(SMBWildcard.match(name: "CLIP.BIN", pattern: "clip.bin"))   // case-insensitive
        XCTAssertTrue(SMBWildcard.match(name: "clip.bin", pattern: "clip.b?n"))
        XCTAssertFalse(SMBWildcard.match(name: "clip.bin", pattern: "._"))
        XCTAssertFalse(SMBWildcard.match(name: "readme.txt", pattern: "clip.bin"))
        XCTAssertFalse(SMBWildcard.match(name: "._foo", pattern: "_*"))
        XCTAssertTrue(SMBWildcard.match(name: "._foo", pattern: "._*"))
    }
}

final class BackendHelperTests: XCTestCase {
    func testShareNameSanitizeStripsIllegalChars() {
        XCTAssertEqual(SMBShareName.sanitize("Editorial"), "Editorial")
        XCTAssertEqual(SMBShareName.sanitize("a/b\\c:d|e"), "abcde")
        XCTAssertEqual(SMBShareName.sanitize(""), "cloudfs")
        XCTAssertEqual(SMBShareName.sanitize(String(repeating: "x", count: 200)).count, 80)
    }

    func testShareURLComponentEscapesDisplayNames() {
        XCTAssertEqual(SMBShareName.urlComponent("Production Media #1"), "Production%20Media%20%231")
        XCTAssertEqual(SMBShareName.urlComponent("100%"), "100%25")
    }

    func testSyntheticCredentialIsURLSafe() {
        for _ in 0..<50 {
            let c = SyntheticCredential.generate()
            let safe = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-"))
            XCTAssertTrue(c.user.unicodeScalars.allSatisfy { safe.contains($0) }, c.user)
            XCTAssertTrue(c.password.unicodeScalars.allSatisfy { safe.contains($0) }, c.password)
            XCTAssertFalse(c.password.isEmpty)
        }
    }
}

/// Real kernel mount via `mount_smbfs`. Gated on CLOUDFS_LIVE_MOUNT=1 because CI
/// hosts can't mount. Exercises the full stack: server + client tuning + mount +
/// browse + read through the real smbfs kernel client.
final class LiveMountSmokeTests: XCTestCase {
    func testLiveMountResourceForkTruncateCompatibility() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine()
        let main = Data("unchanged carrier".utf8)
        engine.seed("fork.bin", data: main)
        let backend = SMBLoopbackMountBackend()
        let filespace = "fork-truncate-\(UUID())"
        let point = NSTemporaryDirectory() + filespace
        addTeardownBlock {
            try? await backend.unmount(filespace: filespace, force: true)
            try? FileManager.default.removeItem(atPath: point)
        }
        try await backend.mount(filespace: filespace, displayName: "Fork truncation", at: point, engine: engine)
        let program = #"""
        import errno,os,sys
        path=sys.argv[1]
        for payload in [b"original fork", b"short", b"", b"replacement fork"]:
            try:
                fd=os.open(path+"/..namedfork/rsrc",os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
            except OSError as error:
                # Apple's SMB client can reject the combined create/truncate
                # of an existing named fork before issuing a server request.
                # Keep explicit descriptor truncation covered independently.
                if error.errno != errno.ENOTSUP: raise
                print("KERNEL_FORK_TRUNCATING_OPEN_UNSUPPORTED",flush=True)
                fd=os.open(path+"/..namedfork/rsrc",os.O_WRONLY)
                os.ftruncate(fd,0)
            try:
                assert os.write(fd,payload)==len(payload)
                os.fsync(fd)
            finally: os.close(fd)
            with open(path+"/..namedfork/rsrc","rb") as f: assert f.read()==payload
            with open(path,"rb") as f: assert f.read()==b"unchanged carrier"
        print("FORK_TRUNCATION_PASS")
        """#
        let (output, errors, timedOut) = Self.runWithTimeout("/usr/bin/python3", ["-c", program, point + "/fork.bin"], seconds: 30)
        XCTAssertFalse(timedOut, errors)
        XCTAssertTrue(output.contains("FORK_TRUNCATION_PASS"), "\(output) \(errors)")
    }

    // Each test owns a UUID mount path and only unmounts that path. Never sweep
    // other mounts: they may belong to a running app or another test process.

    /// A failed admission among pipelined kernel READs must not turn into
    /// silently accepted different bytes. A retry may recover, or the caller
    /// may receive an I/O error; a successful read must remain byte exact.
    func testLiveMountTransientReadAdmissionNeverReturnsDifferentBytes() async throws {
        try await assertReadAdmissionFailure(failingCheck: 1)
    }

    func testLiveMountLaterReadAdmissionNeverReturnsDifferentBytes() async throws {
        try await assertReadAdmissionFailure(failingCheck: 9)
    }

    private func assertReadAdmissionFailure(failingCheck: Int) async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine()
        let size = (12 << 20) + 33
        let bytes: [UInt8] = (0..<size).map { index in UInt8((index / 4096 + index * 17) % 251) }
        let payload = Data(bytes)
        engine.seed("read-fault.bin", data: payload)
        let fault = FirstReadAdmissionFault(failingCheck: failingCheck)
        engine.rangeAccessHook = { try await fault.check() }
        let backend = SMBLoopbackMountBackend()
        let point = NSTemporaryDirectory() + "cloudfs-read-fault-\(UUID())"
        addTeardownBlock {
            try? await backend.unmount(filespace: "read-fault", force: true)
            try? FileManager.default.removeItem(atPath: point)
        }
        try await backend.mount(filespace: "read-fault", displayName: "Read admission fault", at: point, engine: engine)
        let program = """
        import hashlib,json,pathlib,sys
        def read():
            try:
                data=pathlib.Path(sys.argv[1]).read_bytes()
                return {'result':'read','length':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            except OSError as error:
                return {'result':'error','errno':error.errno}
        print(json.dumps({'first':read(),'reopened':[read(),read(),read()]}))
        """
        let (output, errors, timedOut) = Self.runWithTimeout("/usr/bin/python3",
            ["-c", program, point + "/read-fault.bin"], seconds: 30)
        XCTAssertFalse(timedOut, errors)
        let report = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(output.utf8)) as? [String: Any])
        FileHandle.standardError.write(Data("READ_ADMISSION_FAULT \(output)".utf8))
        let first = try XCTUnwrap(report["first"] as? [String: Any])
        if first["result"] as? String == "read" {
            XCTAssertEqual(first["length"] as? Int, payload.count, output)
            XCTAssertEqual(first["sha256"] as? String, payload.sha256Hex, output)
        } else {
            XCTAssertEqual(first["result"] as? String, "error", output)
            XCTAssertNotNil(first["errno"] as? Int, output)
        }
        let reopened = try XCTUnwrap(report["reopened"] as? [[String: Any]])
        for attempt in reopened where attempt["result"] as? String == "read" {
            XCTAssertEqual(attempt["length"] as? Int, payload.count, output)
            XCTAssertEqual(attempt["sha256"] as? String, payload.sha256Hex, output)
        }
        // Apple can retain EIO in its vnode even after a successful new SMB
        // handle. Every successful reopen must be exact; remount must recover.
        for attempt in reopened { XCTAssertTrue(["read", "error"].contains(attempt["result"] as? String ?? ""), output) }
        let failed = await fault.failed
        XCTAssertTrue(failed, "The test must exercise the admission failure")
        try await backend.unmount(filespace: "read-fault", force: false)
        try await backend.mount(filespace: "read-fault", displayName: "Read admission recovery", at: point, engine: engine)
        let (recovered, recoveryError, recoveryTimeout) = Self.runWithTimeout("/usr/bin/shasum",
            ["-a", "256", point + "/read-fault.bin"], seconds: 15)
        XCTAssertFalse(recoveryTimeout, recoveryError)
        XCTAssertTrue(recovered.hasPrefix(payload.sha256Hex), "Remount recovery failed: \(recovered) \(recoveryError)")
    }

    /// Apple shares one SMB BRL handle between read-only opens from different
    /// processes. A second exclusive acquisition must conflict even when its
    /// wire FileId matches the first. POSIX fcntl is not supported by smbfs, so
    /// use Apple's ByteRangeLockPB2 through the same helper as the two-Mac test.
    func testLiveMountAppleByteRangeLocksAcrossProcesses() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("cloudfs-editor-validation-brl-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let helper = directory.appendingPathComponent("lock-helper")
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("scripts/validate-mac-locks.c")
        let (_, compileError, compileTimeout) = Self.runWithTimeout("/usr/bin/xcrun",
            ["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", source.path, "-o", helper.path], seconds: 30)
        XCTAssertFalse(compileTimeout, compileError)
        XCTAssertTrue(FileManager.default.isExecutableFile(atPath: helper.path), compileError)

        let engine = MemoryEngine()
        let payload = Data((0..<16384).map { UInt8($0 & 255) })
        engine.seed("ranges.bin", data: payload)
        let backend = SMBLoopbackMountBackend()
        let point = directory.appendingPathComponent("mount").path
        let filespace = "apple-brl"
        addTeardownBlock {
            try? await backend.unmount(filespace: filespace, force: true)
            try? FileManager.default.removeItem(at: directory)
        }
        try await backend.mount(filespace: filespace, displayName: "Apple BRL", at: point, engine: engine)
        let path = point + "/ranges.bin"
        let ready = directory.appendingPathComponent("holder.ready")
        let release = directory.appendingPathComponent("holder.release")
        let holder = Process()
        holder.executableURL = helper
        holder.arguments = ["hold", path, "exclusive", "0", "4096", "--api", "smbfs", "--open", "read",
                            "--seconds", "30", "--ready", ready.path, "--release", release.path]
        let holderOutput = Pipe(), holderError = Pipe()
        holder.standardOutput = holderOutput; holder.standardError = holderError
        try holder.run()
        defer { if holder.isRunning { holder.terminate() } }
        let deadline = ContinuousClock.now.advanced(by: .seconds(10))
        while !FileManager.default.fileExists(atPath: ready.path), holder.isRunning, ContinuousClock.now < deadline {
            try await Task.sleep(for: .milliseconds(25))
        }
        guard FileManager.default.fileExists(atPath: ready.path) else {
            XCTFail("Apple BRL holder failed to acquire before deadline")
            return
        }
        let readyInfo = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: ready)) as? [String: Any])
        XCTAssertEqual(readyInfo["phase"] as? String, "held")
        XCTAssertEqual(readyInfo["api"] as? String, "smbfs")

        func probe(_ offset: Int, expected: String, api: String = "smbfs", mode: String = "exclusive") throws {
            let (output, error, timedOut) = Self.runWithTimeout(helper.path,
                ["probe", path, mode, "\(offset)", "4096", "--api", api, "--open", "read", "--expect", expected], seconds: 10)
            XCTAssertFalse(timedOut, output + error)
            let line = try XCTUnwrap(output.split(separator: "\n").last)
            let value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
            XCTAssertEqual(value["api"] as? String, api)
            XCTAssertEqual(value["openMode"] as? String, "read")
            XCTAssertEqual(value["expectationMatched"] as? Bool, true, output + error)
            XCTAssertEqual(value["phase"] as? String, expected == "acquired" ? "probed" : expected, output + error)
        }
        try probe(0, expected: "blocked")
        // A partial overlap is also a conflict; a disjoint range can coexist.
        try probe(2048, expected: "blocked")
        try probe(8192, expected: "acquired")
        try probe(0, expected: "unsupported", api: "fcntl", mode: "shared")
        try Data("release\n".utf8).write(to: release)
        let releaseDeadline = ContinuousClock.now.advanced(by: .seconds(10))
        while holder.isRunning, ContinuousClock.now < releaseDeadline { try await Task.sleep(for: .milliseconds(25)) }
        guard !holder.isRunning else { XCTFail("Apple BRL holder failed to release"); return }
        XCTAssertEqual(holder.terminationStatus, 0)
        let released = String(decoding: holderOutput.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        XCTAssertTrue(released.contains("\"phase\":\"released\""), released)
        try probe(0, expected: "acquired")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), payload)
    }

    /// A normal stat caller does not necessarily hold a CHANGE_NOTIFY watch.
    /// macOS keeps absent names until fresh parent metadata advances its mtime.
    /// Mutate the engine directly to model another Mac, without local SMB
    /// invalidation, directory enumeration, or a Finder refresh hiding the bug.
    func testLiveMountRemoteCreateAndRenameClearNegativeLookups() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine()
        let nested = engine.seedDir("project")
        let old = Date().addingTimeInterval(-5)
        for parent in [InodeID.root, nested] {
            _ = try await engine.setBasicInfo(parent, info: BasicFileInfo(modifiedAt: old))
        }
        let backend = SMBLoopbackMountBackend()
        let point = NSTemporaryDirectory() + "cloudfs-negative-lookup-\(UUID())"
        let filespace = "negative-lookup"
        addTeardownBlock {
            try? await backend.unmount(filespace: filespace, force: true)
            try? FileManager.default.removeItem(atPath: point)
        }
        try await backend.mount(filespace: filespace, displayName: "Negative lookup", at: point, engine: engine)
        let parents: [(id: InodeID, path: String)] = [(.root, point), (nested, point + "/project")]

        func directStat(_ path: String) -> Bool {
            var attrs = stat()
            let result = lstat(path, &attrs)
            if result != 0 { XCTAssertEqual(errno, ENOENT, "Unexpected lookup error for \(path)") }
            return result == 0
        }
        func requireVisible(_ paths: [String], phase: String) async throws {
            let start = ContinuousClock.now
            let deadline = start.advanced(by: .seconds(35))
            var missing = Set(paths)
            while !missing.isEmpty, ContinuousClock.now < deadline {
                for path in missing where directStat(path) {
                    missing.remove(path)
                    let relative = String(path.dropFirst(point.count + 1))
                    FileHandle.standardError.write(Data("LIVE negative lookup \(phase) visible \(relative) after \(start.duration(to: .now))\n".utf8))
                }
                if !missing.isEmpty { try await Task.sleep(for: .milliseconds(200)) }
            }
            XCTAssertTrue(missing.isEmpty, "\(phase): direct stat still returned absent after 35s: \(missing.sorted())")
            for path in paths where !missing.contains(path) {
                XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), Data("peer edit".utf8))
            }
        }

        let createdPaths = parents.map { $0.path + "/peer-created.txt" }
        for path in createdPaths { XCTAssertFalse(directStat(path), "Prime an absent child in the kernel name cache") }
        var created: [InodeID] = []
        for parent in parents {
            created.append(engine.seed("peer-created.txt", parent: parent.id, data: Data("peer edit".utf8)))
            _ = try await engine.setBasicInfo(parent.id, info: BasicFileInfo(modifiedAt: Date()))
        }
        try await requireVisible(createdPaths, phase: "remote create")

        let renamedPaths = parents.map { $0.path + "/peer-renamed.txt" }
        for path in renamedPaths { XCTAssertFalse(directStat(path), "Prime the rename destination before the remote rename") }
        for (parent, id) in zip(parents, created) {
            _ = try await engine.rename(id, newParent: parent.id, newName: "peer-renamed.txt")
            _ = try await engine.setBasicInfo(parent.id, info: BasicFileInfo(modifiedAt: Date()))
        }
        try await requireVisible(renamedPaths, phase: "remote rename")
    }

    /// Repeatedly reopening an existing file must not starve the parent's
    /// negative-name refresh when a peer atomically replaces that file and
    /// creates a completion marker. No directory enumeration may rescue it.
    func testLiveMountRemoteAtomicReplaceAndMarkerDuringRepeatedReads() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine()
        let parent = engine.seedDir("project")
        let old = Data(repeating: 0x31, count: 81920)
        let new = Data(repeating: 0x72, count: 82117)
        let target = engine.seed("atomic.bin", parent: parent, data: old)
        let staged = engine.seed("atomic.stage", parent: parent, data: new)
        _ = try await engine.setBasicInfo(parent, info: BasicFileInfo(modifiedAt: Date().addingTimeInterval(-5)))
        let backend = SMBLoopbackMountBackend()
        let point = NSTemporaryDirectory() + "cloudfs-atomic-marker-\(UUID())"
        addTeardownBlock {
            try? await backend.unmount(filespace: "atomic-marker", force: true)
            try? FileManager.default.removeItem(atPath: point)
        }
        try await backend.mount(filespace: "atomic-marker", displayName: "Atomic marker", at: point, engine: engine)
        let path = URL(fileURLWithPath: point + "/project/atomic.bin")
        let marker = point + "/project/peer.done.json"
        XCTAssertEqual(try Data(contentsOf: path), old)
        var info = stat()
        XCTAssertEqual(lstat(marker, &info), -1)
        XCTAssertEqual(errno, ENOENT)

        _ = try await engine.rename(staged, newParent: parent, newName: "atomic.bin", replacing: engine.lookup(target))
        _ = engine.seed("peer.done.json", parent: parent, data: Data("done".utf8))
        _ = try await engine.setBasicInfo(parent, info: BasicFileInfo(modifiedAt: Date()))
        let began = ContinuousClock.now
        let deadline = began.advanced(by: .seconds(35))
        var oldReads = 0, newReads = 0
        var sawMarker = false
        while ContinuousClock.now < deadline {
            let data = try Data(contentsOf: path)
            if data == old { oldReads += 1 }
            else if data == new { newReads += 1 }
            else { XCTFail("Remote atomic replacement returned partial/unexpected contents"); break }
            if lstat(marker, &info) == 0 { sawMarker = true }
            else { XCTAssertEqual(errno, ENOENT) }
            if newReads > 0 && sawMarker { break }
            try await Task.sleep(for: .milliseconds(20))
        }
        FileHandle.standardError.write(Data("LIVE atomic marker oldReads=\(oldReads) newReads=\(newReads) marker=\(sawMarker) after \(began.duration(to: .now))\n".utf8))
        XCTAssertGreaterThan(newReads, 0, "Replacement contents must become visible within 35s")
        XCTAssertTrue(sawMarker, "Hot reads must not keep the peer marker absent for more than 35s")
    }

    /// Perf baseline (recorded, not a hard gate): serve an in-memory file through the
    /// real kernel SMB mount and time sequential reads. This is NOT a WAN benchmark.
    func testLiveMountThroughput() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1",
                          "set CLOUDFS_LIVE_MOUNT=1 to run the throughput benchmark")
        let engine = MemoryEngine()
        // Seed a 256 MiB file directly in the engine (bytes are in-memory).
        let sizeMiB = 256
        engine.seed("big.bin", data: Data(count: sizeMiB << 20))
        let backend = SMBLoopbackMountBackend()
        let mountPoint = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("cloudfs-smb-perf-\(UUID().uuidString)")
        try await backend.mount(filespace: "liveperf", displayName: "LivePerf", at: mountPoint, engine: engine)

        let file = (mountPoint as NSString).appendingPathComponent("big.bin")
        // dd read-back with 1 MiB blocks; capture dd's throughput line from stderr.
        let (_, ddErr, timedOut) = Self.runWithTimeout(
            "/bin/dd", ["if=\(file)", "of=/dev/null", "bs=1m"], seconds: 60)
        FileHandle.standardError.write(Data("LIVE throughput (\(sizeMiB) MiB): \(ddErr)\n".utf8))

        try? await backend.unmount(filespace: "liveperf", force: true)
        try? FileManager.default.removeItem(atPath: mountPoint)
        XCTAssertFalse(timedOut, "dd read timed out")
        XCTAssertTrue(ddErr.contains("\(sizeMiB << 20) bytes transferred"), "dd must read the ENTIRE file: \(ddErr)")
    }

    func testLiveMountBrowseAndRead() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1",
                          "set CLOUDFS_LIVE_MOUNT=1 to run the real-mount smoke test")

        let engine = MemoryEngine()
        let payload = Data((0..<(5 * 1024)).map { UInt8($0 & 0xFF) })
        engine.seed("readme.txt", data: Data("cloudfs smb live".utf8))
        engine.seed("clip.bin", data: payload)
        _ = engine.seedDir("projects")

        let backend = SMBLoopbackMountBackend()
        let mountPoint = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("cloudfs-smb-live-\(UUID().uuidString)")
        let filespace = "livetest"

        try await backend.mount(filespace: filespace, displayName: "LiveTest",
                                at: mountPoint, engine: engine)

        // Browse via a subprocess `ls` with a hard timeout so a kernel readdir
        // stall shows up as a fast diagnostic rather than hanging the test 500s.
        let (lsOut, lsErr, timedOut) = Self.runWithTimeout(
            "/bin/ls", ["-la1", mountPoint], seconds: 8)
        FileHandle.standardError.write(Data("LIVE ls timedOut=\(timedOut)\nSTDOUT:\n\(lsOut)\nSTDERR:\n\(lsErr)\n".utf8))

        // Read a file through the kernel client and verify byte-exactness.
        let clipPath = (mountPoint as NSString).appendingPathComponent("clip.bin")
        let (shaOut, _, readTimedOut) = Self.runWithTimeout("/usr/bin/shasum", ["-a", "256", clipPath], seconds: 8)
        let expectedSHA = payload.sha256Hex

        try? await backend.unmount(filespace: filespace, force: true)
        try? FileManager.default.removeItem(atPath: mountPoint)

        XCTAssertFalse(timedOut, "readdir hung (kernel rejecting listing)")
        XCTAssertTrue(lsOut.contains("readme.txt"), "listing missing readme.txt; got:\n\(lsOut)")
        XCTAssertTrue(lsOut.contains("clip.bin"), "listing missing clip.bin")
        XCTAssertTrue(lsOut.contains("projects"), "listing missing projects")
        XCTAssertFalse(readTimedOut, "read hung")
        XCTAssertTrue(shaOut.contains(expectedSHA), "clip.bin read mismatch; sha=\(shaOut) expected \(expectedSHA)")
    }

    /// Live write path: create a file through the kernel mount, read it back.
    func testLiveMountTouchAndHiddenAttributePersistAcrossRemount() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine(); let id = engine.seed("dated.txt", data: Data("metadata".utf8))
        let backend = SMBLoopbackMountBackend()
        let point = NSTemporaryDirectory() + "cloudfs-basic-live-\(UUID())"
        addTeardownBlock { try? await backend.unmount(filespace: "basic", force: true); try? FileManager.default.removeItem(atPath: point) }
        try await backend.mount(filespace: "basic", displayName: "Basic metadata", at: point, engine: engine)
        let path = point + "/dated.txt"
        let (_, touchError, touchTimeout) = Self.runWithTimeout("/usr/bin/touch", ["-t", "202001020304.05", path], seconds: 10)
        XCTAssertFalse(touchTimeout); XCTAssertEqual(touchError, "")
        let (_, flagError, flagTimeout) = Self.runWithTimeout("/usr/bin/chflags", ["hidden", path], seconds: 10)
        XCTAssertFalse(flagTimeout); XCTAssertEqual(flagError, "")
        let stored = try await engine.lookup(id)
        XCTAssertNotNil(stored.modifiedAt); XCTAssertEqual(stored.fileAttributes.map { $0 & 2 }, 2)
        try await backend.unmount(filespace: "basic", force: true)
        try await backend.mount(filespace: "basic", displayName: "Basic metadata", at: point, engine: engine)
        let (_, statError, statTimeout) = Self.runWithTimeout("/usr/bin/stat", ["-f", "%m %Sf", path], seconds: 10)
        XCTAssertFalse(statTimeout); XCTAssertEqual(statError, "")
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attrs[.modificationDate] as? Date)?.timeIntervalSince1970, stored.modifiedAt?.timeIntervalSince1970)
    }

    func testLiveMountReadOnlyProtectionAndAuthorizedClearAcrossRemount() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine(); let payload = Data("protected edit".utf8)
        let id = engine.seed("protected.txt", data: payload)
        let backend = SMBLoopbackMountBackend()
        let point = NSTemporaryDirectory() + "cloudfs-readonly-live-\(UUID())"
        addTeardownBlock { try? await backend.unmount(filespace: "readonly-compat", force: true); try? FileManager.default.removeItem(atPath: point) }
        try await backend.mount(filespace: "readonly-compat", displayName: "Read-only compatibility", at: point, engine: engine)
        let path = point + "/protected.txt"
        let (_, flagError, flagTimeout) = Self.runWithTimeout("/usr/bin/chflags", ["uchg", path], seconds: 15)
        XCTAssertFalse(flagTimeout); XCTAssertEqual(flagError, "")
        let stored = try await engine.lookup(id)
        XCTAssertEqual(stored.fileAttributes.map { $0 & 1 }, 1)
        try await backend.unmount(filespace: "readonly-compat", force: true)
        try await backend.mount(filespace: "readonly-compat", displayName: "Read-only compatibility", at: point, engine: engine)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), payload)
        XCTAssertThrowsError(try Data("clobber".utf8).write(to: URL(fileURLWithPath: path)))
        XCTAssertThrowsError(try FileManager.default.removeItem(atPath: path))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), payload)
        let (_, clearError, clearTimeout) = Self.runWithTimeout("/usr/bin/chflags", ["nouchg", path], seconds: 15)
        XCTAssertFalse(clearTimeout); XCTAssertEqual(clearError, "")
        let cleared = try await engine.lookup(id)
        XCTAssertEqual(cleared.fileAttributes.map { $0 & 1 }, 0)
        try await backend.unmount(filespace: "readonly-compat", force: true)
        try await backend.mount(filespace: "readonly-compat", displayName: "Read-only compatibility", at: point, engine: engine)
        try Data("new edit".utf8).write(to: URL(fileURLWithPath: path))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), Data("new edit".utf8))
    }

    func testLiveMountRmdirRejectsNonemptyDirectoryWithoutRemovingChildren() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine(); let directory = engine.seedDir("project")
        engine.seed("edit.bin", parent: directory, data: Data("keep".utf8))
        let backend = SMBLoopbackMountBackend()
        let point = NSTemporaryDirectory() + "cloudfs-rmdir-live-\(UUID())"
        addTeardownBlock { try? await backend.unmount(filespace: "rmdir-compat", force: true); try? FileManager.default.removeItem(atPath: point) }
        try await backend.mount(filespace: "rmdir-compat", displayName: "Directory compatibility", at: point, engine: engine)
        let (_, error, timeout) = Self.runWithTimeout("/bin/rmdir", [point + "/project"], seconds: 15)
        XCTAssertFalse(timeout); XCTAssertTrue(error.localizedCaseInsensitiveContains("not empty"), error)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: point + "/project/edit.bin")), Data("keep".utf8))
    }

    func testLiveMountWriteAndReadBack() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1",
                          "set CLOUDFS_LIVE_MOUNT=1 to run the real-mount smoke test")
        let engine = MemoryEngine()
        _ = engine.seedDir("existing")
        let backend = SMBLoopbackMountBackend()
        let mountPoint = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("cloudfs-smb-write-\(UUID().uuidString)")
        let filespace = "livewrite"
        try await backend.mount(filespace: filespace, displayName: "LiveWrite",
                                at: mountPoint, engine: engine)

        // Write a source file into the mount via `cp`, then read it back via `cat`.
        let srcPath = (NSTemporaryDirectory() as NSString).appendingPathComponent("cfs-src-\(UUID().uuidString).txt")
        let content = "written through the smb mount \(UUID().uuidString)"
        try content.write(toFile: srcPath, atomically: true, encoding: .utf8)
        let dstPath = (mountPoint as NSString).appendingPathComponent("uploaded.txt")
        let (_, cpErr, cpTimedOut) = Self.runWithTimeout("/bin/cp", [srcPath, dstPath], seconds: 8)
        let (catOut, _, catTimedOut) = Self.runWithTimeout("/bin/cat", [dstPath], seconds: 8)
        FileHandle.standardError.write(Data("LIVE write cpErr=\(cpErr) cat=\(catOut)\n".utf8))

        try? await backend.unmount(filespace: filespace, force: true)
        try? FileManager.default.removeItem(atPath: mountPoint)
        try? FileManager.default.removeItem(atPath: srcPath)

        XCTAssertFalse(cpTimedOut, "cp into mount hung")
        XCTAssertTrue(cpErr.isEmpty, "copy failed: \(cpErr)")
        XCTAssertFalse(catTimedOut, "cat from mount hung")
        XCTAssertEqual(catOut, content, "round-tripped content mismatch")
        // The engine should now hold the uploaded item.
        let items = engine.snapshotNames()
        XCTAssertTrue(items.contains("uploaded.txt"), "engine missing uploaded item; has \(items)")
    }

    /// Live xattr round-trip: write + read an extended attribute through the kernel
    /// mount and assert it lands as a native stream (no `._` AppleDouble sidecar).
    func testLiveMountXattrRoundTrip() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1",
                          "set CLOUDFS_LIVE_MOUNT=1 to run the real-mount smoke test")
        let engine = MemoryEngine()
        engine.seed("photo.jpg", data: Data("jpegbytes".utf8))
        let backend = SMBLoopbackMountBackend()
        let mountPoint = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("cloudfs-smb-xattr-\(UUID().uuidString)")
        let filespace = "livexattr"
        try await backend.mount(filespace: filespace, displayName: "LiveXattr", at: mountPoint, engine: engine)

        let file = (mountPoint as NSString).appendingPathComponent("photo.jpg")
        let value = "prov-\(UUID().uuidString)"
        let (_, wErr, wTO) = Self.runWithTimeout("/usr/bin/xattr", ["-w", "com.example.origin", value, file], seconds: 8)
        let (pOut, _, pTO) = Self.runWithTimeout("/usr/bin/xattr", ["-p", "com.example.origin", file], seconds: 8)
        FileHandle.standardError.write(Data("LIVE xattr wErr=\(wErr) read=\(pOut)\n".utf8))

        try? await backend.unmount(filespace: filespace, force: true)
        try? FileManager.default.removeItem(atPath: mountPoint)

        XCTAssertFalse(wTO || pTO, "xattr op hung")
        XCTAssertEqual(pOut.trimmingCharacters(in: .whitespacesAndNewlines), value, "xattr did not round-trip")
        // No AppleDouble `._` companion file leaked into the engine.
        let names = engine.snapshotNames()
        XCTAssertFalse(names.contains { $0.hasPrefix("._") }, "AppleDouble sidecar leaked: \(names)")
    }

    /// Run a subprocess with a wall-clock timeout. Returns (stdout, stderr, timedOut).
    static func runWithTimeout(_ path: String, _ args: [String], seconds: Int)
        -> (String, String, Bool) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let out = Pipe(); let err = Pipe()
        proc.standardOutput = out; proc.standardError = err
        do { try proc.run() } catch { return ("", "launch failed: \(error)", false) }
        let deadline = Date().addingTimeInterval(TimeInterval(seconds))
        while proc.isRunning && Date() < deadline { usleep(100_000) }
        var timedOut = false
        if proc.isRunning { timedOut = true; proc.terminate(); usleep(200_000); if proc.isRunning { kill(proc.processIdentifier, SIGKILL) } }
        let o = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let e = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return (o, e, timedOut)
    }
}

extension LiveMountSmokeTests {
    /// Keep a kernel descriptor open across unlink, then exercise fstat, read,
    /// and write through that descriptor after the name has disappeared.
    func testLiveMountHeldDescriptorSurvivesUnlink() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine()
        let original = Data("held-unlink-\(UUID().uuidString)".utf8)
        let id = engine.seed("held-unlink.bin", data: original)
        let backend = SMBLoopbackMountBackend()
        let filespace = "held-unlink-\(UUID().uuidString)"
        let point = NSTemporaryDirectory() + "cloudfs-held-unlink-\(UUID())"
        addTeardownBlock {
            try? await backend.unmount(filespace: filespace, force: true)
            try? FileManager.default.removeItem(atPath: point)
        }
        try await backend.mount(filespace: filespace, displayName: "Held unlink", at: point, engine: engine)

        let program = #"""
        import json,os,sys
        path=sys.argv[1]
        expected=bytes.fromhex(sys.argv[2])
        fd=os.open(path, os.O_RDWR)
        before=os.fstat(fd)
        assert os.pread(fd, len(expected), 0)==expected
        os.unlink(path)
        assert not os.path.exists(path)
        held=os.fstat(fd)
        assert held.st_ino==before.st_ino and held.st_size==len(expected)
        assert os.pread(fd, len(expected), 0)==expected
        patch=b"after-unlink"
        assert os.pwrite(fd, patch, 0)==len(patch)
        after=os.fstat(fd)
        assert after.st_ino==before.st_ino and after.st_size==len(expected)
        assert os.pread(fd, len(expected), 0)==patch+expected[len(patch):]
        os.close(fd)
        print(json.dumps({"inode":before.st_ino,"size":after.st_size,"pathAbsent":not os.path.exists(path)}))
        """#
        let (output, errors, timedOut) = Self.runWithTimeout("/usr/bin/python3",
            ["-c", program, point + "/held-unlink.bin", original.map { String(format: "%02x", $0) }.joined()], seconds: 20)
        XCTAssertFalse(timedOut, errors)
        XCTAssertEqual(errors, "", errors)
        XCTAssertTrue(output.contains("\"pathAbsent\": true") || output.contains("\"pathAbsent\":true"), output)
        XCTAssertEqual(engine.openReferenceCount(id), 0, "the descriptor close should eventually release its remote open lifetime")
    }

    /// Unlink the old name, move a new file into that name, and keep using the
    /// old kernel descriptor. This checks replacement lifetime and resource-fork
    /// access without asserting strict atomic rename visibility.
    func testLiveMountHeldDescriptorSurvivesReplacementAndResourceForkIO() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine()
        let oldBytes = Data("old-generation-\(UUID().uuidString)".utf8)
        let newBytes = Data("new-generation-\(UUID().uuidString)".utf8)
        let oldID = engine.seed("held-replace.bin", data: oldBytes)
        engine.seedStream(oldID, name: StreamName.afpResource, data: Data("old-fork".utf8))
        _ = engine.seed("held-replace.stage", data: newBytes)
        let backend = SMBLoopbackMountBackend()
        let filespace = "held-replace-\(UUID().uuidString)"
        let point = NSTemporaryDirectory() + "cloudfs-held-replace-\(UUID())"
        addTeardownBlock {
            try? await backend.unmount(filespace: filespace, force: true)
            try? FileManager.default.removeItem(atPath: point)
        }
        try await backend.mount(filespace: filespace, displayName: "Held replacement", at: point, engine: engine)

        let program = #"""
        import json,os,sys
        target,staged=sys.argv[1:3]
        old=bytes.fromhex(sys.argv[3]); new=bytes.fromhex(sys.argv[4])
        fd=os.open(target, os.O_RDWR)
        fork_fd=os.open(target+"/..namedfork/rsrc",os.O_RDWR)
        before=os.fstat(fd)
        assert os.pread(fd, len(old), 0)==old
        assert os.pread(fork_fd,8,0)==b"old-fork"
        os.unlink(target)
        os.rename(staged,target)
        with open(target,"rb") as current: assert current.read()==new
        held=os.fstat(fd)
        assert held.st_ino==before.st_ino and held.st_size==len(old)
        assert os.pread(fd,len(old),0)==old
        patch=b"edited-old"
        assert os.pwrite(fd,patch,0)==len(patch)
        assert os.pread(fd,len(old),0)==patch+old[len(patch):]
        replacement_fork=b"edited-old-fork"
        assert os.pwrite(fork_fd,replacement_fork,0)==len(replacement_fork)
        assert os.pread(fork_fd,len(replacement_fork),0)==replacement_fork
        after=os.fstat(fd)
        assert after.st_ino==before.st_ino and after.st_size==len(old)
        os.close(fork_fd)
        os.close(fd)
        print(json.dumps({"oldInode":before.st_ino,"oldSize":after.st_size,"newPath":True,"fork":"edited-old-fork"}))
        """#
        let args = ["-c", program, point + "/held-replace.bin", point + "/held-replace.stage",
                    oldBytes.map { String(format: "%02x", $0) }.joined(),
                    newBytes.map { String(format: "%02x", $0) }.joined()]
        let (output, errors, timedOut) = Self.runWithTimeout("/usr/bin/python3", args, seconds: 25)
        XCTAssertFalse(timedOut, errors)
        XCTAssertEqual(errors, "", errors)
        XCTAssertTrue(output.contains("\"newPath\": true") || output.contains("\"newPath\":true"), output)
        XCTAssertEqual(engine.openReferenceCount(oldID), 0, "the descriptor close should eventually release its remote open lifetime")
    }
}

private actor FirstReadAdmissionFault {
    private var count = 0
    private let failingCheck: Int
    private(set) var failed = false
    init(failingCheck: Int) { self.failingCheck = failingCheck }
    func check() async throws {
        count += 1
        if count == failingCheck {
            // Later requests finish first. Their successful prepared bytes must
            // remain unpublished until this earlier failure is known.
            try await Task.sleep(for: .milliseconds(950))
            failed = true
            throw EngineError(.locked, "Injected expired read permit", data: ["reason": .string("read-permit-expired")])
        }
    }
}

final class KernelMountOwnershipTests: XCTestCase {
    func testMountPathUsesKernelAliasesForExistingAndMissingLeaves() throws {
        let leaf = "cloudfs-canonical-\(UUID())"
        XCTAssertEqual(try KernelMountTable.canonicalMountPath("/tmp/" + leaf), "/private/tmp/" + leaf)
        let directory = "/private/tmp/" + leaf
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        XCTAssertEqual(try KernelMountTable.canonicalMountPath(directory), directory)
        XCTAssertEqual(try KernelMountTable.canonicalMountPath("/tmp/" + leaf), directory)
        XCTAssertEqual(try KernelMountTable.canonicalMountPath("/var/empty/" + leaf), "/private/var/empty/" + leaf)
        XCTAssertEqual(try KernelMountTable.canonicalMountPath(directory + "/missing/child"), directory + "/missing/child")
    }
    func testOwnershipRequiresExactKernelTypePathUserPortAndShare() throws {
        let path = "/private/tmp/cloudfs-volume"
        let owned = KernelMountRecord(path: path, filesystem: "smbfs", source: "//cfs-owner@127.0.0.1:34567/CloudFS%20Team")
        XCTAssertTrue(owned.matchesSMB(path: path, user: "cfs-owner", port: 34567, share: "CloudFS Team"))
        XCTAssertTrue(owned.isCloudFSLoopbackSMB)
        for other in [
            KernelMountRecord(path: path, filesystem: "apfs", source: "/dev/disk4s1"),
            KernelMountRecord(path: path, filesystem: "smbfs", source: "//cfs-other@127.0.0.1:34567/CloudFS%20Team"),
            KernelMountRecord(path: path, filesystem: "smbfs", source: "//cfs-owner@127.0.0.1:34568/CloudFS%20Team"),
            KernelMountRecord(path: path, filesystem: "smbfs", source: "//cfs-owner@192.168.1.2:34567/CloudFS%20Team"),
            KernelMountRecord(path: path + "-other", filesystem: "smbfs", source: owned.source),
            KernelMountRecord(path: path, filesystem: "smbfs", source: "//cfs-owner@127.0.0.1:34567/Another")
        ] {
            XCTAssertFalse(other.matchesSMB(path: path, user: "cfs-owner", port: 34567, share: "CloudFS Team"))
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        XCTAssertFalse(try KernelMountTable.snapshot().contains { $0.path == directory.path }, "an ordinary directory is not a mounted volume")
    }
}

extension LiveMountSmokeTests {
    func testExternalEjectReconcilesAndNeverUnmountsReplacementVolume() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let directory = URL(fileURLWithPath: try KernelMountTable.canonicalMountPath("/tmp/cloudfs-eject-\(UUID())"), isDirectory: true)
        let original = SMBLoopbackMountBackend(), replacement = SMBLoopbackMountBackend()
        addTeardownBlock {
            try? await original.unmount(filespace: "original", force: true)
            try? await replacement.unmount(filespace: "other", force: true)
            let actual = directory.path
            if (try? KernelMountTable.snapshot().contains { $0.path == actual }) == false {
                try? FileManager.default.removeItem(at: directory)
            }
        }
        let engine = MemoryEngine(); engine.seed("original.txt", data: Data("original".utf8))
        try await original.mount(filespace: "original", displayName: "Eject original", at: directory.path, engine: engine)
        let actual = directory.path
        let first = try await original.reconcile(filespace: "original", at: actual)
        XCTAssertEqual(first, true)
        let external = Process(); external.executableURL = URL(fileURLWithPath: "/sbin/umount"); external.arguments = [actual]
        try external.run(); external.waitUntilExit(); XCTAssertEqual(external.terminationStatus, 0)
        let ejected = try await original.reconcile(filespace: "original", at: actual)
        XCTAssertEqual(ejected, false)
        // A new connection must work with the same backend after external eject.
        try await original.mount(filespace: "original", displayName: "Eject original", at: actual, engine: engine)
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("original.txt")), Data("original".utf8))
        let externalAgain = Process(); externalAgain.executableURL = URL(fileURLWithPath: "/sbin/umount"); externalAgain.arguments = [actual]
        try externalAgain.run(); externalAgain.waitUntilExit(); XCTAssertEqual(externalAgain.terminationStatus, 0)
        let otherEngine = MemoryEngine(); otherEngine.seed("other.txt", data: Data("unrelated volume".utf8))
        try await replacement.mount(filespace: "other", displayName: "Eject unrelated", at: actual, engine: otherEngine)
        let stale = try await original.reconcile(filespace: "original", at: actual)
        XCTAssertEqual(stale, false)
        try await original.unmount(filespace: "original", force: true)
        // The old listener's cleanup cannot detach the replacement volume.
        let present = try await replacement.reconcile(filespace: "other", at: actual)
        XCTAssertEqual(present, true)
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("other.txt")), Data("unrelated volume".utf8))
        try await replacement.unmount(filespace: "other", force: false)
        try? FileManager.default.removeItem(at: directory)
    }
}
