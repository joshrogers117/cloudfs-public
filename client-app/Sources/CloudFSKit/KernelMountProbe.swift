// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Darwin

/// Read the kernel table without traversing a disconnected network filesystem.
enum KernelMountProbe {
    static func matches(path: String, filesystem: String, source: String, expectedPath: String) -> Bool {
        guard path == expectedPath, filesystem == "smbfs",
              let url = URLComponents(string: "smb:" + source) else { return false }
        return url.host == "127.0.0.1" && url.port != nil && url.user?.hasPrefix("cfs-") == true
    }
    static func isMounted(_ path: String) -> Bool {
        guard path.hasPrefix("/") else { return false }
        var expected = path
        while expected.count > 1 && expected.hasSuffix("/") { expected.removeLast() }
        let parent = (expected as NSString).deletingLastPathComponent
        guard let resolvedParent = realpath(parent, nil) else { return false }
        defer { free(resolvedParent) }
        let canonicalParent = String(cString: resolvedParent)
        let kernelPath = (canonicalParent == "/" ? "/" : canonicalParent + "/") + (expected as NSString).lastPathComponent
        var entries: UnsafeMutablePointer<statfs>?
        // Foundation can also inspect mounts on other threads. A lock around
        // our calls cannot protect getmntinfo's process-global buffer.
        let count = getmntinfo_r_np(&entries, MNT_NOWAIT)
        guard count > 0, let entries else { return false }
        defer { free(entries) }
        for index in 0..<Int(count) {
            var entry = entries[index]
            let mountPath = withUnsafePointer(to: &entry.f_mntonname) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            guard mountPath == kernelPath else { continue }
            let source = withUnsafePointer(to: &entry.f_mntfromname) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            let filesystem = withUnsafePointer(to: &entry.f_fstypename) {
                $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
            }
            return matches(path: mountPath, filesystem: filesystem, source: source, expectedPath: kernelPath)
        }
        return false
    }
}
