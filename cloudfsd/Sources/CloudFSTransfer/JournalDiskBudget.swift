// SPDX-License-Identifier: AGPL-3.0-or-later
import Foundation
import CloudFSCore

/// One instance per daemon, shared by all journal actors. Counts conservative
/// allocated bytes, including unpublished generations and atomic replacement
/// overhead. Existing disconnected journals are included on first admission.
/// This is admission control, not a filesystem quota: other processes can still
/// consume disk space after the free-space probe; normal write/fsync failures
/// must continue to prevent acknowledgement.
public final class JournalDiskBudget: @unchecked Sendable {
    public static let defaultLimitBytes = 10 << 30
    public static let defaultReserveBytes = 1 << 30
    public struct Snapshot: Sendable, Equatable {
        public let usedBytes: Int
        public let reservedBytes: Int
        public let limitBytes: Int
        public let freeSpaceReserveBytes: Int
    }
    private let lock = NSLock()
    private let cacheRoot: URL
    private let limit: Int
    private let reserve: Int
    private let available: @Sendable (URL) throws -> Int
    private var initialized = false
    private var sizes: [String: Int] = [:]
    private var used = 0
    private var pending = 0

    public init(cacheRoot: URL, limitBytes: Int = defaultLimitBytes,
                freeSpaceReserveBytes: Int = defaultReserveBytes,
                availableBytes: @escaping @Sendable (URL) throws -> Int = JournalDiskBudget.diskAvailable) {
        self.cacheRoot = URL(fileURLWithPath: Self.canonicalPath(cacheRoot))
        limit = max(0, limitBytes); reserve = max(0, freeSpaceReserveBytes)
        available = availableBytes
    }

    /// Foundation directory enumeration may return /private/var while callers
    /// use /var. Resolve the nearest existing ancestor even for a new payload or
    /// a just-unlinked directory, so scan, reservation and retirement share keys.
    private static func canonicalPath(_ url: URL) -> String {
        var ancestor = url.standardizedFileURL
        var suffix: [String] = []
        while true {
            if let resolved = realpath(ancestor.path, nil) {
                defer { free(resolved) }
                return suffix.reversed().reduce(URL(fileURLWithPath: String(cString: resolved))) { $0.appendingPathComponent($1) }.path
            }
            if ancestor.path == "/" { return url.standardizedFileURL.path }
            suffix.append(ancestor.lastPathComponent); ancestor.deleteLastPathComponent()
        }
    }

    public static func diskAvailable(_ url: URL) throws -> Int {
        var existing = url
        while !FileManager.default.fileExists(atPath: existing.path), existing.path != "/" {
            existing.deleteLastPathComponent()
        }
        let attributes = try FileManager.default.attributesOfFileSystem(forPath: existing.path)
        guard let free = attributes[.systemFreeSize] as? NSNumber else { throw POSIXError(.EIO) }
        return max(0, free.intValue)
    }

    private static func allocation(_ bytes: Int) throws -> Int {
        guard bytes >= 0, bytes <= Int.max - 4095 else { throw POSIXError(.EFBIG) }
        return max(4096, ((bytes + 4095) / 4096) * 4096)
    }
    private func charge(_ url: URL) throws -> Int {
        var value = stat()
        guard lstat(url.path, &value) == 0 else {
            if errno == ENOENT { return 0 }
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        // Do not follow links outside the journal. Files and directories both
        // consume at least one accounting page, including zero-length log files.
        return max(try Self.allocation(Int(value.st_size)), Int(value.st_blocks) * 512)
    }
    private func setSize(_ path: String, _ size: Int) {
        used += size - sizes[path, default: 0]
        sizes[path] = size == 0 ? nil : size
    }
    private func scan(_ root: URL) throws {
        setSize(root.path, try charge(root))
        var failure: Error?
        if let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil,
            errorHandler: { _, error in failure = error; return false }) {
            for case let url as URL in walker { setSize(url.path, try charge(url)) }
        }
        if let failure { throw failure }
    }
    private func initialize() throws {
        guard !initialized else { return }
        // Clear a partially scanned inventory before retrying an I/O failure.
        sizes.removeAll(); used = 0
        if FileManager.default.fileExists(atPath: cacheRoot.path) {
            for child in try FileManager.default.contentsOfDirectory(at: cacheRoot,
                includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]) {
                let values = try child.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
                guard values.isDirectory == true, values.isSymbolicLink != true else { continue }
                let staging = child.appendingPathComponent("staging")
                if FileManager.default.fileExists(atPath: staging.path) { try scan(staging) }
            }
        }
        initialized = true
    }
    public func snapshot() throws -> Snapshot {
        try lock.withLock {
            try initialize()
            return Snapshot(usedBytes: used, reservedBytes: pending, limitBytes: limit, freeSpaceReserveBytes: reserve)
        }
    }
    private func denied(_ reason: String, requested: Int) -> EngineError {
        EngineError(.syncFailed,
            "Pending-write storage is full. Resume uploads or free disk space, then retry. Previously acknowledged writes remain in the journal.",
            data: ["reason": .string(reason), "diskFull": .bool(true), "requestedBytes": .int(requested),
                   "usedBytes": .int(used), "limitBytes": .int(limit), "freeSpaceReserveBytes": .int(reserve)])
    }

    /// Reserve before touching disk. For replacement, keep the old allocation
    /// charged until the atomic rename succeeds. Append reserves only growth.
    func write<T>(to url: URL, length: Int, replacing: Bool = false, _ body: () throws -> T) throws -> T {
        let url = URL(fileURLWithPath: Self.canonicalPath(url))
        let wanted = try Self.allocation(length)
        let amount: Int = try lock.withLock {
            try initialize()
            let old = sizes[url.path, default: 0]
            let growth = replacing ? wanted : max(0, wanted - old)
            guard growth <= Int.max - 4096 else { throw POSIXError(.EFBIG) }
            let amount = growth + 4096 // directory allocation growth / atomic temporary name
            guard used <= limit, pending <= limit - used, amount <= limit - used - pending else {
                throw denied("pending_write_limit", requested: amount)
            }
            let free = try available(url)
            guard free >= reserve, pending <= free - reserve, amount <= free - reserve - pending else {
                throw denied("free_space_reserve", requested: amount)
            }
            pending += amount
            return amount
        }
        defer {
            lock.withLock {
                // Failure may have left a short immutable file. Retain its charge
                // too; failed writes must not manufacture fresh budget capacity.
                if let size = try? charge(url) { setSize(url.path, size) }
                else { setSize(url.path, max(sizes[url.path, default: 0], wanted)) }
                let parent = url.deletingLastPathComponent()
                if sizes[parent.path] != nil, let size = try? charge(parent) { setSize(parent.path, size) }
                pending -= amount
            }
        }
        return try body()
    }

    func reconcile(_ url: URL) throws {
        let url = URL(fileURLWithPath: Self.canonicalPath(url))
        try lock.withLock { setSize(url.path, try charge(url)) }
    }

    /// Called only after successful unlink. A failed cleanup remains charged.
    func removed(_ url: URL) {
        let url = URL(fileURLWithPath: Self.canonicalPath(url))
        lock.withLock {
            let prefix = url.path + "/"
            for path in sizes.keys.filter({ $0 == url.path || $0.hasPrefix(prefix) }) { setSize(path, 0) }
        }
    }
}
