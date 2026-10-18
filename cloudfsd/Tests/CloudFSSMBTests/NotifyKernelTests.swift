// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Darwin
import CloudFSCore
import CloudFSMount
@testable import CloudFSSMB

final class NotifyKernelTests: XCTestCase {
    func testKernelDirectoryWatchReceivesRemoteChangeWithoutEnumeration() async throws {
        try XCTSkipUnless(ProcessInfo.processInfo.environment["CLOUDFS_LIVE_MOUNT"] == "1")
        let engine = MemoryEngine()
        let directory = engine.seedDir("watched")
        let signal = NotificationGeneration()
        let registered = expectation(description: "macOS CHANGE_NOTIFY reaches the engine")
        registered.assertForOverFulfill = false
        engine.changeGenerationHook = { await signal.value }
        engine.changeEnumerationHook = { container in
            if container == directory { registered.fulfill() }
        }
        let backend = SMBLoopbackMountBackend()
        let point = NSTemporaryDirectory() + "cloudfs-notify-\(UUID())"
        addTeardownBlock {
            try? await backend.unmount(filespace: "notify", force: true)
            try? FileManager.default.removeItem(atPath: point)
        }
        try await backend.mount(filespace: "notify", displayName: "Notification test", at: point, engine: engine)
        let fd = Darwin.open(point + "/watched", O_EVTONLY)
        XCTAssertGreaterThanOrEqual(fd, 0)
        guard fd >= 0 else { return }
        defer { Darwin.close(fd) }
        let queue = kqueue()
        XCTAssertGreaterThanOrEqual(queue, 0)
        guard queue >= 0 else { return }
        defer { Darwin.close(queue) }
        var registration = kevent(ident: UInt(fd), filter: Int16(EVFILT_VNODE),
            flags: UInt16(EV_ADD | EV_CLEAR), fflags: UInt32(NOTE_WRITE), data: 0, udata: nil)
        XCTAssertEqual(kevent(queue, &registration, 1, nil, 0, nil), 0)
        await fulfillment(of: [registered], timeout: 5)
        // Discard any initial vnode event from installing the watch. Only a
        // subsequent event can demonstrate the remote mutation was delivered.
        var initialEvent = kevent()
        var immediate = timespec(tv_sec: 0, tv_nsec: 0)
        while kevent(queue, nil, 0, &initialEvent, 1, &immediate) > 0 {}

        // This models a peer publication through the engine change feed. Neither
        // test nor kernel reader lists or stats the watched directory afterward.
        engine.seed("remote.txt", parent: directory, data: Data("peer".utf8))
        await signal.advance()
        var event = kevent()
        var timeout = timespec(tv_sec: 5, tv_nsec: 0)
        let count = kevent(queue, nil, 0, &event, 1, &timeout)
        XCTAssertEqual(count, 1, "Remote change did not reach the native directory watch; errno=\(errno)")
        if count == 1 {
            XCTAssertEqual(event.filter, Int16(EVFILT_VNODE))
            XCTAssertNotEqual(event.fflags & UInt32(NOTE_WRITE), 0)
            XCTAssertEqual(event.flags & UInt16(EV_ERROR), 0)
        }
    }
}

private actor NotificationGeneration {
    private(set) var value: UInt64 = 0
    func advance() { value += 1 }
}
