// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import Darwin

/// Kernel mount-table reads never traverse a possibly wedged network volume.
public struct KernelMountRecord: Sendable, Equatable {
    public let path: String
    public let filesystem: String
    public let source: String
    public init(path: String, filesystem: String, source: String) {
        self.path = path; self.filesystem = filesystem; self.source = source
    }
    public func matchesSMB(path: String, user: String, port: UInt16, share: String) -> Bool {
        guard self.path == path, filesystem == "smbfs",
              let url = URLComponents(string: "smb:" + source) else { return false }
        return url.host == "127.0.0.1" && url.port == Int(port) && url.user == user && url.path == "/" + share
    }
    public var isCloudFSLoopbackSMB: Bool {
        guard filesystem == "smbfs", let url = URLComponents(string: "smb:" + source) else { return false }
        return url.host == "127.0.0.1" && url.port != nil && url.user?.hasPrefix("cfs-") == true
    }
}

public enum KernelMountTable {
    /// Resolve local parent aliases (/tmp, /var, and user-selected parents)
    /// without touching the mount root itself. Foundation can shorten /private
    /// paths again, and statting a disconnected SMB root can block indefinitely.
    public static func canonicalMountPath(_ path: String) throws -> String {
        var candidate = (path as NSString).expandingTildeInPath
        if !candidate.hasPrefix("/") { candidate = FileManager.default.currentDirectoryPath + "/" + candidate }
        while candidate.count > 1 && candidate.hasSuffix("/") { candidate.removeLast() }
        guard candidate != "/" else { return candidate }
        var remaining: [String] = []
        repeat {
            guard let slash = candidate.lastIndex(of: "/") else { throw POSIXError(.EINVAL) }
            remaining.append(String(candidate[candidate.index(after: slash)...]))
            candidate = slash == candidate.startIndex ? "/" : String(candidate[..<slash])
            if let resolved = realpath(candidate, nil) {
                defer { free(resolved) }
                var pieces = String(cString: resolved).split(separator: "/").map(String.init)
                for piece in remaining.reversed() {
                    if piece == ".." { if !pieces.isEmpty { pieces.removeLast() } }
                    else if piece != "." && !piece.isEmpty { pieces.append(piece) }
                }
                return "/" + pieces.joined(separator: "/")
            }
            guard errno == ENOENT, candidate != "/" else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        } while true
    }
    public static func snapshot() throws -> [KernelMountRecord] {
        var entries: UnsafeMutablePointer<statfs>?
        // Own the snapshot; Foundation's mount queries do not share our locks.
        let count = getmntinfo_r_np(&entries, MNT_NOWAIT)
        guard count > 0, let entries else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        defer { free(entries) }
        return (0..<Int(count)).map { index in
            var entry = entries[index]
            let path = withUnsafePointer(to: &entry.f_mntonname) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            let source = withUnsafePointer(to: &entry.f_mntfromname) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
            }
            let filesystem = withUnsafePointer(to: &entry.f_fstypename) {
                $0.withMemoryRebound(to: CChar.self, capacity: 16) { String(cString: $0) }
            }
            return KernelMountRecord(path: path, filesystem: filesystem, source: source)
        }
    }
}
