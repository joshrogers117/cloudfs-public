// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import cloudfsd

private actor ReadAheadWork {
    var windows: [ReadAheadController.Window] = []
    var waiters: [CheckedContinuation<Void, Never>] = []
    var canceledCompletions = 0
    func run(_ window: ReadAheadController.Window) async {
        windows.append(window)
        await withCheckedContinuation { waiters.append($0) }
        if Task.isCancelled { canceledCompletions += 1 }
    }
    func count() -> Int { windows.count }
    func release() { let pending = waiters; waiters.removeAll(); for waiter in pending { waiter.resume() } }
}

private actor SlidingReadAheadWork {
    var windows: [ReadAheadController.Window] = []
    var reports: [ReadAheadController.Progress] = []
    var waiters: [CheckedContinuation<Void, Never>] = []
    func run(_ window: ReadAheadController.Window, progress: ReadAheadController.Progress) async {
        windows.append(window); reports.append(progress)
        await withCheckedContinuation { waiters.append($0) }
    }
    func count() -> Int { windows.count }
    func report(_ index: Int, completed: Int) { reports[index](completed) }
    func release() { let pending = waiters; waiters.removeAll(); for waiter in pending { waiter.resume() } }
}

private actor CompletedReadAheadWork {
    var canceled = 0
    var count = 0
    func run(_ window: ReadAheadController.Window, progress: ReadAheadController.Progress) {
        count += 1
        if Task.isCancelled { canceled += 1 }
        progress(window.length)
    }
}

final class ReadAheadControllerTests: XCTestCase {
    private let key = ReadAheadController.Key(filespace: "fs", itemID: "movie", version: "v1")
    private let block = 1 << 20

    private func observe(_ controller: ReadAheadController, _ index: Int,
                         key: ReadAheadController.Key? = nil, now: UInt64 = 1) -> ReadAheadController.Ticket? {
        controller.observe(key: key ?? self.key, offset: index * block, length: block,
                           fileSize: 256 * block, blockSize: block, now: now)
    }
    private func waitUntil(_ predicate: @escaping () async -> Bool,
                           file: StaticString = #filePath, line: UInt = #line) async {
        let until = Date().addingTimeInterval(3)
        while !(await predicate()), Date() < until { try? await Task.sleep(for: .milliseconds(5)) }
        let passed = await predicate()
        XCTAssertTrue(passed, "Timed out waiting for bounded read-ahead work", file: file, line: line)
    }

    func testFirstAndRandomReadsDoNotSpeculate() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        for index in [0, 16, 4, 64, 12, 12, 12] {
            let ticket = observe(controller, index)
            controller.demandCompleted(ticket) { await worker.run($0) }
        }
        XCTAssertEqual(controller.snapshot().activeTasks, 0)
        let count = await worker.count()
        XCTAssertEqual(count, 0)
    }

    func testSequentialRampOnlyStartsAfterDemandCompletesAndDoesNotRepeatWarmedRanges() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0)) { await worker.run($0) }
        let second = observe(controller, 1)
        XCTAssertEqual(controller.snapshot().activeTasks, 0, "Observing demand must not issue speculative work")
        controller.demandCompleted(second) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        let firstWindows = await worker.windows
        XCTAssertEqual(firstWindows, [ReadAheadController.Window(offset: 2 * block, length: 2 * block)])
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        controller.demandCompleted(observe(controller, 2)) { await worker.run($0) }
        await waitUntil { await worker.count() == 2 }
        let windows = await worker.windows
        XCTAssertEqual(windows[1], .init(offset: 4 * block, length: 3 * block))
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        controller.demandCompleted(observe(controller, 2)) { await worker.run($0) }
        XCTAssertEqual(controller.snapshot().activeTasks, 0, "Repeated same read must not grow confidence")
    }

    func testSeekCancelsObsoleteWorkAndItsLateCompletionCannotClearReplacement() async {
        let controller = ReadAheadController()
        let oldWork = ReadAheadWork(), newWork = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0)) { _ in }
        controller.demandCompleted(observe(controller, 1)) { await oldWork.run($0) }
        await waitUntil { await oldWork.count() == 1 }
        let stale = observe(controller, 32)
        controller.demandCompleted(observe(controller, 33)) { await newWork.run($0) }
        await waitUntil { await newWork.count() == 1 }
        await oldWork.release()
        await waitUntil { controller.snapshot().activeTasks == 1 }
        XCTAssertEqual(controller.snapshot().trackedStreams, 1)
        XCTAssertEqual(controller.snapshot().reservedBytes, 2 * block)
        // Even a pre-seek ticket cannot create old work after the generation changed.
        _ = observe(controller, 64)
        controller.demandCompleted(stale) { await oldWork.run($0) }
        let oldCount = await oldWork.count()
        XCTAssertEqual(oldCount, 1)
        await newWork.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testSeekReallyCancelsOperation() async {
        let controller = ReadAheadController()
        let started = expectation(description: "speculation began")
        let canceled = expectation(description: "seek cancels speculation")
        controller.demandCompleted(observe(controller, 0)) { _ in }
        controller.demandCompleted(observe(controller, 1)) { _ in
            started.fulfill()
            do { try await Task.sleep(for: .seconds(30)); XCTFail("obsolete speculation was not canceled") }
            catch { canceled.fulfill(); throw error }
        }
        await fulfillment(of: [started], timeout: 3)
        _ = observe(controller, 32)
        await fulfillment(of: [canceled], timeout: 3)
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testCanceledTasksRetainGlobalBudgetUntilTheyUnwind() async {
        let controller = ReadAheadController(streamLimit: 3, taskLimit: 2, byteLimit: 4 << 20)
        let worker = ReadAheadWork()
        for index in 0..<20 {
            let stream = ReadAheadController.Key(filespace: "fs", itemID: InodeID("file-\(index)"), version: "v1")
            controller.demandCompleted(observe(controller, 0, key: stream, now: UInt64(index * 2))) { _ in }
            controller.demandCompleted(observe(controller, 1, key: stream, now: UInt64(index * 2 + 1))) { await worker.run($0) }
            if index < 2 { await waitUntil { await worker.count() == index + 1 } }
            let state = controller.snapshot()
            XCTAssertLessThanOrEqual(state.trackedStreams, 3)
            XCTAssertLessThanOrEqual(state.activeTasks, 2)
            XCTAssertLessThanOrEqual(state.reservedBytes, 4 << 20)
        }
        XCTAssertEqual(controller.snapshot().activeTasks, 2)
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testVersionAndFilespaceIdentityAndDisconnectCancellation() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0)) { _ in }
        controller.demandCompleted(observe(controller, 1)) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        let newVersion = ReadAheadController.Key(filespace: "fs", itemID: "movie", version: "v2")
        controller.demandCompleted(observe(controller, 2, key: newVersion)) { await worker.run($0) }
        XCTAssertEqual(controller.snapshot().trackedStreams, 1)
        let other = ReadAheadController.Key(filespace: "other", itemID: "movie", version: "v1")
        controller.demandCompleted(observe(controller, 2, key: other)) { await worker.run($0) }
        XCTAssertEqual(controller.snapshot().trackedStreams, 2)
        controller.cancel(filespace: "fs")
        XCTAssertEqual(controller.snapshot().trackedStreams, 1)
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        controller.cancel(filespace: "other")
        XCTAssertEqual(controller.snapshot().trackedStreams, 0)
    }

    func testStaleIdleAndInvalidExtentsNeverCreateWork() async {
        let controller = ReadAheadController(idleNanoseconds: 10)
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0, now: 0)) { _ in }
        controller.demandCompleted(observe(controller, 1, now: 20)) { await worker.run($0) }
        XCTAssertEqual(controller.snapshot().activeTasks, 0)
        for (offset, length, size) in [(Int.max - 1, 3, Int.max), (-1, 1, 10), (0, 0, 10), (10, 1, 10)] {
            XCTAssertNil(controller.observe(key: key, offset: offset, length: length, fileSize: size, blockSize: block))
        }
        XCTAssertEqual(controller.snapshot().trackedStreams, 0)
        // A legal but huge block size must not overflow optional cluster slack.
        let hugeBlock = Int.max / 4
        let huge = controller.observe(key: key, offset: 0, length: 1, fileSize: 100, blockSize: hugeBlock, now: 1)
        controller.demandCompleted(huge) { _ in }
        XCTAssertNotNil(controller.observe(key: key, offset: 1, length: 1, fileSize: 100, blockSize: hugeBlock, now: 1))
    }

    func testTinyReadsWarmOnlyWholeFutureCryptoBlocksAndStayWithinFile() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        controller.demandCompleted(controller.observe(key: key, offset: 0, length: 1, fileSize: block + 17, blockSize: block)) { _ in }
        let ticket = controller.observe(key: key, offset: 1, length: 1, fileSize: block + 17, blockSize: block)
        controller.demandCompleted(ticket) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        let windows = await worker.windows
        XCTAssertEqual(windows, [.init(offset: block, length: 17)])
        XCTAssertEqual(controller.snapshot().reservedBytes, 17)
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testFailedSpeculationCanBeRetriedAfterAnotherDemand() async {
        enum Rejected: Error { case capacity }
        let controller = ReadAheadController()
        controller.demandCompleted(observe(controller, 0)) { _ in }
        controller.demandCompleted(observe(controller, 1)) { _ in throw Rejected.capacity }
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 2)) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        let windows = await worker.windows
        XCTAssertEqual(windows[0].offset, 3 * block)
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }
    func testPauseSuppressesNewSpeculationUntilResume() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0)) { _ in }
        let ticket = observe(controller, 1)
        controller.setPaused(true, filespace: "fs")
        controller.demandCompleted(ticket) { await worker.run($0) }
        XCTAssertNil(observe(controller, 2))
        XCTAssertEqual(controller.snapshot().activeTasks, 0)
        controller.setPaused(false, filespace: "fs")
        controller.demandCompleted(observe(controller, 3)) { _ in }
        controller.demandCompleted(observe(controller, 4)) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testEvictionDrainWaitsForAlreadyAdmittedWorkToUnwind() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0)) { _ in }
        controller.demandCompleted(observe(controller, 1)) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        let drained = expectation(description: "optional cache admission has ended")
        let drain = Task {
            await controller.cancelAndWait(filespace: "fs", itemID: "movie")
            XCTAssertEqual(controller.snapshot().activeTasks, 0)
            drained.fulfill()
        }
        await waitUntil { controller.snapshot().trackedStreams == 0 }
        XCTAssertEqual(controller.snapshot().activeTasks, 1, "Cancellation alone is not a completed cache-admission barrier")
        await worker.release()
        await fulfillment(of: [drained], timeout: 3)
        await drain.value
    }

    func testFourOutOfOrderOverlappingDemandsMergeWithoutCancelingOrRefetchingWarm() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        // Establish actual sequential confidence first.
        controller.demandCompleted(observe(controller, 0)) { await worker.run($0) }
        controller.demandCompleted(observe(controller, 1)) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        // Four real simultaneous SMB requests arrive in 2,5,3,4 order. The gap
        // is a pipeline reorder: its missing requested coverage subsequently joins.
        let first = observe(controller, 2)
        let fourth = observe(controller, 5)
        let second = observe(controller, 3)
        let third = observe(controller, 4)
        XCTAssertEqual(controller.snapshot().activeDemands, 4)
        for ticket in [fourth, second, first, third] {
            controller.demandCompleted(ticket) { await worker.run($0) }
            controller.demandEnded(ticket) // adapter's unconditional defer is idempotent
        }
        XCTAssertEqual(controller.snapshot().activeDemands, 0)
        await waitUntil { await worker.count() == 2 }
        let windows = await worker.windows
        XCTAssertEqual(windows[0], .init(offset: 2 * block, length: 2 * block))
        XCTAssertEqual(windows[1].offset, 6 * block, "speculation skips every already-requested pipeline block")
        XCTAssertEqual(controller.snapshot().activeTasks, 2, "out-of-order demand must retain the old useful warm")
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let canceled = await worker.canceledCompletions
        XCTAssertEqual(canceled, 0, "pipeline backfills must not cancel useful speculative transfers")
    }

    func testUnresolvedGapResetsAfterItsLastOverlappingDemandRetires() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        let contiguous = observe(controller, 0)
        let seek = observe(controller, 4) // ambiguous while the first block is outstanding
        controller.demandCompleted(contiguous) { await worker.run($0) }
        controller.demandCompleted(seek) { await worker.run($0) }
        XCTAssertEqual(controller.snapshot().activeDemands, 0)
        XCTAssertEqual(controller.snapshot().activeTasks, 0, "an unfilled gap cannot start lookahead")
        // Now reading block5 confirms a NEW stream rooted at the seek target.
        controller.demandCompleted(observe(controller, 5)) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        let windows = await worker.windows
        XCTAssertEqual(windows[0], .init(offset: 6 * block, length: 2 * block))
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testMacOSReadClustersKeepEstablishedWarmAcrossZeroInflightBoundaries() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        // Replay actual mounted sequential-read ordering. Every read is retired
        // before the next arrives, including the 4→8 and 36→52 MiB cluster gaps.
        let clusters = [0..<4, 8..<12, 4..<8, 12..<36, 52..<56,
                        36..<44, 56..<60, 44..<52, 60..<64]
        var reads = 0
        for cluster in clusters {
            for halfBlock in (cluster.lowerBound * 2)..<(cluster.upperBound * 2) {
                let ticket = controller.observe(key: key, offset: halfBlock * (block / 2), length: block / 2,
                                                fileSize: 256 * block, blockSize: block, now: 1)
                XCTAssertNotNil(ticket)
                controller.demandCompleted(ticket) { await worker.run($0) }
                controller.demandEnded(ticket)
                XCTAssertEqual(controller.snapshot().activeDemands, 0)
                XCTAssertLessThanOrEqual(controller.snapshot().activeTasks, 2)
                reads += 1
                if reads == 2 { await waitUntil { await worker.count() == 1 } }
                if reads == 3 { await waitUntil { await worker.count() == 2 } }
            }
        }
        XCTAssertEqual(controller.snapshot().activeTasks, 2)
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let canceled = await worker.canceledCompletions
        XCTAssertEqual(canceled, 0, "bounded cluster gaps must not churn already-useful downloads")
        // Actual contiguous coverage has now joined all clusters: full horizon.
        controller.demandCompleted(observe(controller, 64)) { await worker.run($0) }
        await waitUntil { await worker.count() == 3 }
        let windows = await worker.windows
        XCTAssertEqual(windows[2], .init(offset: 65 * block, length: 16 * block))
        _ = observe(controller, 200) // outside the established reorder bound
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let canceledAfterSeek = await worker.canceledCompletions
        XCTAssertEqual(canceledAfterSeek, 1, "a genuine far seek still cancels obsolete prediction")
    }

    func testEstablishedGapDoesNotIncreaseConfidenceOrExtendItsHorizon() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0)) { await worker.run($0) }
        controller.demandCompleted(observe(controller, 1)) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        // Confidence two gives a two-block window. A request just inside that
        // window is retained with no growth, even after its demand retires.
        controller.demandCompleted(observe(controller, 4)) { await worker.run($0) }
        XCTAssertEqual(controller.snapshot().activeDemands, 0)
        await waitUntil { await worker.count() == 2 }
        let windows = await worker.windows
        XCTAssertEqual(windows[1], .init(offset: 5 * block, length: 2 * block), "a gap changes the cluster anchor, not confidence or window size")
        // Finish one bounded cluster. Its fixed slack ends at block8; repeated
        // pending-cluster extensions must not move that bound or gain confidence.
        for index in 5..<8 {
            controller.demandCompleted(observe(controller, index)) { await worker.run($0) }
        }
        controller.demandCompleted(observe(controller, 8)) { await worker.run($0) }
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let canceled = await worker.canceledCompletions
        XCTAssertEqual(canceled, 2)
        let count = await worker.count()
        XCTAssertEqual(count, 2, "gap-only requests cannot create sequential confidence")
    }

    func testConcurrentClockSamplesDoNotExpireOrMoveActivityBackward() async {
        let controller = ReadAheadController(idleNanoseconds: 100)
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0, now: 1000)) { _ in }
        let newer = observe(controller, 1, now: 1100)
        let older = observe(controller, 2, now: 1099)
        XCTAssertEqual(controller.snapshot().activeDemands, 2, "out-of-order pre-lock timestamps must keep one generation")
        controller.demandCompleted(newer) { await worker.run($0) }
        controller.demandCompleted(older) { await worker.run($0) }
        await waitUntil { await worker.count() >= 1 }
        // Exactly at the idle boundary measured from the newest sample. A
        // backward update to 1099 would incorrectly expire the retained warm.
        controller.demandCompleted(observe(controller, 3, now: 1200)) { await worker.run($0) }
        await waitUntil { await worker.count() == 2 }
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let canceled = await worker.canceledCompletions
        XCTAssertEqual(canceled, 0)
    }

    func testRecordedOneGiBMacOSColdAndWarmClusterTracesRetainUsefulPrediction() async {
        for trace in [MacOSClusterTrace.cold, MacOSClusterTrace.warm] {
            let controller = ReadAheadController()
            let worker = ReadAheadWork()
            var started = 0
            for (offset, length) in trace {
                let ticket = controller.observe(key: key, offset: offset, length: length,
                                                fileSize: 1024 * block, blockSize: block, now: 1)
                XCTAssertNotNil(ticket)
                controller.demandCompleted(ticket) { await worker.run($0) }
                controller.demandEnded(ticket)
                let state = controller.snapshot()
                XCTAssertEqual(state.activeDemands, 0)
                XCTAssertLessThanOrEqual(state.pendingRanges, 4)
                XCTAssertLessThanOrEqual(state.scheduledRanges, 8)
                XCTAssertLessThanOrEqual(state.activeTasks, 2)
                XCTAssertLessThanOrEqual(state.reservedBytes, 64 << 20)
                if state.activeTasks > started {
                    started = state.activeTasks
                    await waitUntil { await worker.count() == started }
                }
            }
            XCTAssertEqual(started, 2)
            await worker.release()
            await waitUntil { controller.snapshot().activeTasks == 0 }
            let canceled = await worker.canceledCompletions
            XCTAssertEqual(canceled, 0, "actual kernel cluster reorder must retain useful admitted work")
        }
    }

    func testRecordedOneGiBTracesRemainBoundedWithSlidingProgressEnabled() async {
        for trace in [MacOSClusterTrace.cold, MacOSClusterTrace.warm] {
            let controller = ReadAheadController(), worker = CompletedReadAheadWork()
            for (offset, length) in trace {
                let ticket = controller.observe(key: key, offset: offset, length: length,
                                                fileSize: 1024 * block, blockSize: block, now: 1)
                XCTAssertNotNil(ticket)
                controller.demandCompleted(ticket, elapsedNanoseconds: 25_000_000, progressOperation: { window, progress in
                    await worker.run(window, progress: progress)
                })
                controller.demandEnded(ticket)
                await Task.yield()
                let state = controller.snapshot()
                XCTAssertLessThanOrEqual(state.pendingRanges, 4)
                XCTAssertLessThanOrEqual(state.scheduledRanges, 8)
                XCTAssertLessThanOrEqual(state.activeTasks, 32)
                XCTAssertLessThanOrEqual(state.reservedBytes, 64 << 20)
                XCTAssertGreaterThanOrEqual(state.reservedBytes, 0)
            }
            await waitUntil { controller.snapshot().activeTasks == 0 }
            XCTAssertEqual(controller.snapshot().reservedBytes, 0)
            let canceled = await worker.canceled; XCTAssertEqual(canceled, 0)
            let count = await worker.count; XCTAssertGreaterThan(count, 2)
        }
    }

    func testEarlierClusterCanWarmWithoutSkippingBehindAheadClusterHistory() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        for index in 0..<5 {
            controller.demandCompleted(observe(controller, index)) { _ in }
            await waitUntil { controller.snapshot().activeTasks == 0 }
        }
        // Fully established direction accepts a distant kernel cluster. Its
        // prediction must not become a global high-water mark suppressing lower
        // uncovered bytes when the earlier cluster resumes.
        controller.demandCompleted(observe(controller, 36)) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        controller.demandCompleted(observe(controller, 5)) { await worker.run($0) }
        await waitUntil { await worker.count() == 2 }
        let windows = await worker.windows
        XCTAssertEqual(windows[0], .init(offset: 37 * block, length: 16 * block))
        XCTAssertEqual(windows[1], .init(offset: 21 * block, length: block))
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let canceled = await worker.canceledCompletions
        XCTAssertEqual(canceled, 0)
    }

    func testPendingHalfBlockBoundariesNeverReservePartialCryptoBlocks() async {
        let controller = ReadAheadController()
        let old = ReadAheadWork()
        for index in 0..<10 {
            controller.demandCompleted(observe(controller, index)) { await old.run($0) }
            if index == 1 { await waitUntil { await old.count() == 1 } }
            if index == 2 { await waitUntil { await old.count() == 2 } }
        }
        await old.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let pending = controller.observe(key: key, offset: 12 * block + block / 2, length: block,
                                         fileSize: 256 * block, blockSize: block, now: 1)
        let current = observe(controller, 10)
        let worker = ReadAheadWork()
        controller.demandCompleted(current) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        controller.demandCompleted(pending) { await worker.run($0) }
        await waitUntil { await worker.count() == 2 }
        let windows = await worker.windows
        XCTAssertEqual(windows, [.init(offset: 11 * block, length: block),
                                 .init(offset: 14 * block, length: 13 * block)])
        XCTAssertEqual(controller.snapshot().reservedBytes, 14 * block)
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testOnlySlowEstablishedReadsWidenAndWarmHitsPreserveThatEvidence() async {
        let controller = ReadAheadController()
        for index in 0..<8 {
            controller.demandCompleted(observe(controller, index), elapsedNanoseconds: 1_000_000) { _ in }
            await waitUntil { controller.snapshot().activeTasks == 0 }
        }
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 8), elapsedNanoseconds: 24_999_999) { await worker.run($0) }
        await waitUntil { await worker.count() == 1 }
        var windows = await worker.windows
        XCTAssertEqual(windows[0].end, 25 * block, "fast local demand retains the16 MiB horizon after read end9 MiB")
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        controller.demandCompleted(observe(controller, 9), elapsedNanoseconds: 25_000_000) { await worker.run($0) }
        await waitUntil { await worker.count() == 2 }
        windows = await worker.windows
        XCTAssertEqual(windows[1].end, 42 * block, "blocked proven sequential demand earns32 MiB beyond read end10 MiB")
        XCTAssertLessThanOrEqual(controller.snapshot().reservedBytes, 32 << 20) // 32 MiB tier, below the 64 MiB default budget
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        controller.demandCompleted(observe(controller, 10), elapsedNanoseconds: 0) { await worker.run($0) }
        await waitUntil { await worker.count() == 3 }
        windows = await worker.windows
        XCTAssertEqual(windows[2], .init(offset: 42 * block, length: block), "warm hits retain justified latency evidence")
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testHighLatencyWindowEvidenceResetsOnSeekIdleAndVersionChange() async {
        for reset in ["seek", "idle", "version"] {
            let controller = ReadAheadController(idleNanoseconds: 10)
            for index in 0..<6 {
                controller.demandCompleted(observe(controller, index)) { _ in }
                await waitUntil { controller.snapshot().activeTasks == 0 }
            }
            let worker = ReadAheadWork()
            controller.demandCompleted(observe(controller, 6), elapsedNanoseconds: 100_000_000) { await worker.run($0) }
            await waitUntil { await worker.count() == 1 }
            var windows = await worker.windows
            XCTAssertEqual(windows[0].end, 39 * block)
            await worker.release()
            await waitUntil { controller.snapshot().activeTasks == 0 }
            let resetKey = reset == "version" ? ReadAheadController.Key(filespace: "fs", itemID: "movie", version: "v2") : key
            let offset = reset == "seek" ? 200 : 7
            let now: UInt64 = reset == "idle" ? 12 : 1
            controller.demandCompleted(observe(controller, offset, key: resetKey, now: now), elapsedNanoseconds: 100_000_000) { await worker.run($0) }
            XCTAssertEqual(controller.snapshot().activeTasks, 0, "a first slow read after \(reset) must not speculate")
            controller.demandCompleted(observe(controller, offset + 1, key: resetKey, now: now + 1), elapsedNanoseconds: 100_000_000) { await worker.run($0) }
            await waitUntil { await worker.count() == 2 }
            windows = await worker.windows
            XCTAssertEqual(windows[1].length, 2 * block, "slow startup after \(reset) must rebuild confidence")
            await worker.release()
            await waitUntil { controller.snapshot().activeTasks == 0 }
        }
    }

    func testNearSeekWithNoOverlappingDemandStillResetsImmediately() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 0)) { await worker.run($0) }
        controller.demandCompleted(observe(controller, 2)) { await worker.run($0) }
        controller.demandCompleted(observe(controller, 4)) { await worker.run($0) }
        XCTAssertEqual(controller.snapshot().activeTasks, 0)
        XCTAssertEqual(controller.snapshot().activeDemands, 0)
    }

    func testAbandonedDemandRetiresOnErrorAndCancellationWithoutPhantomOverlap() async {
        let controller = ReadAheadController()
        let worker = ReadAheadWork()
        let failed = observe(controller, 0)
        XCTAssertEqual(controller.snapshot().activeDemands, 1)
        controller.demandEnded(failed)
        XCTAssertEqual(controller.snapshot().activeDemands, 0)
        XCTAssertEqual(controller.snapshot().trackedStreams, 0)
        controller.demandCompleted(failed) { await worker.run($0) }
        controller.demandCompleted(observe(controller, 1)) { await worker.run($0) }
        XCTAssertEqual(controller.snapshot().activeTasks, 0, "abandoned demand must not count as prior sequential coverage")
    }

    func testOutstandingDemandTrackingIsBoundedEvenWhenCallersNeverReturn() {
        let controller = ReadAheadController()
        var tickets: [ReadAheadController.Ticket?] = []
        for _ in 0..<100 { tickets.append(observe(controller, 0)) }
        XCTAssertEqual(controller.snapshot().activeDemands, ReadAheadController.maximumTrackedDemands)
        XCTAssertEqual(tickets.compactMap { $0 }.count, ReadAheadController.maximumTrackedDemands)
        for ticket in tickets { controller.demandEnded(ticket) }
        XCTAssertEqual(controller.snapshot().activeDemands, 0)
    }

    func testVerifiedProgressRefillsWhileOlderWindowTailsRemainStalled() async {
        let controller = ReadAheadController(taskLimit: 8, byteLimit: 4 * block)
        for index in 0..<6 {
            controller.demandCompleted(observe(controller, index)) { _ in }
            await waitUntil { controller.snapshot().activeTasks == 0 }
        }
        let worker = SlidingReadAheadWork()
        let operation: ReadAheadController.ProgressiveOperation = { window, progress in await worker.run(window, progress: progress) }
        controller.demandCompleted(observe(controller, 6), elapsedNanoseconds: 25_000_000, progressOperation: operation)
        await waitUntil { await worker.count() == 1 }
        // Intentional contract change: every tier is capped by the engine byte
        // budget (4 blocks here), so the window itself is budget-sized and
        // earlier warms already cover most of it. Windows now slide with the
        // demand horizon; progress frees budget but never extends the horizon.
        XCTAssertEqual(controller.snapshot().reservedBytes, block)
        controller.demandCompleted(observe(controller, 7), progressOperation: operation)
        await waitUntil { await worker.count() == 2 }
        XCTAssertEqual(controller.snapshot().reservedBytes, 2 * block)
        await worker.report(0, completed: block)
        XCTAssertEqual(controller.snapshot().reservedBytes, block, "a verified block frees its reservation despite the slow tail of other work")
        await worker.report(0, completed: block)
        await worker.report(0, completed: 0)
        XCTAssertEqual(controller.snapshot().reservedBytes, block, "duplicate or reordered cumulative progress cannot release budget twice")
        controller.demandCompleted(observe(controller, 8), progressOperation: operation)
        await waitUntil { await worker.count() == 3 }
        XCTAssertEqual(controller.snapshot().reservedBytes, 2 * block)
        XCTAssertEqual(controller.snapshot().activeTasks, 3, "a tail must not prevent replacing completed work")
        let windows = await worker.windows
        XCTAssertEqual(windows.map(\.length), [block, block, block])
        XCTAssertTrue(windows.allSatisfy { $0.end <= 13 * block }, "progress alone cannot move beyond actual demand plus the budget-capped window")
        controller.cancel(filespace: "fs")
        await worker.report(1, completed: block)
        XCTAssertEqual(controller.snapshot().reservedBytes, block, "canceled queued bytes remain reserved until verified or drained")
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        XCTAssertEqual(controller.snapshot().reservedBytes, 0)
        let finalCount = await worker.count(); XCTAssertEqual(finalCount, 3, "late progress cannot resurrect a canceled generation")
    }

    func testProgressWithoutNewDemandNeverRunsBeyondTheFixedPredictionHorizon() async {
        let controller = ReadAheadController(), worker = SlidingReadAheadWork()
        let operation: ReadAheadController.ProgressiveOperation = { window, progress in await worker.run(window, progress: progress) }
        controller.demandCompleted(observe(controller, 0), progressOperation: operation)
        controller.demandCompleted(observe(controller, 1), progressOperation: operation)
        await waitUntil { await worker.count() == 1 }
        await worker.report(0, completed: 2 * block)
        XCTAssertEqual(controller.snapshot().reservedBytes, 0)
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        let windows = await worker.windows; XCTAssertEqual(windows, [.init(offset: 2 * block, length: 2 * block)])
    }

    func testSlidingRefillRetainsAnExplicitTaskBoundEvenAfterMostBytesComplete() async {
        let controller = ReadAheadController(taskLimit: 3, byteLimit: 4 * block)
        for index in 0..<6 {
            controller.demandCompleted(observe(controller, index)) { _ in }
            await waitUntil { controller.snapshot().activeTasks == 0 }
        }
        let worker = SlidingReadAheadWork()
        let operation: ReadAheadController.ProgressiveOperation = { window, progress in await worker.run(window, progress: progress) }
        controller.demandCompleted(observe(controller, 6), elapsedNanoseconds: 25_000_000, progressOperation: operation)
        await waitUntil { await worker.count() == 1 }
        // Intentional contract change: every tier is capped by the engine byte
        // budget, so the 4-block window is fully reserved by the first task and
        // progress alone can no longer refill beyond it. Refill now follows new
        // demand advancing the horizon, still bounded by bytes and task limit.
        await worker.report(0, completed: 3 * block)
        controller.demandCompleted(observe(controller, 7), elapsedNanoseconds: 25_000_000, progressOperation: operation)
        await waitUntil { await worker.count() == 2 }
        XCTAssertLessThanOrEqual(controller.snapshot().reservedBytes, 4 * block)
        await worker.report(1, completed: block)
        controller.demandCompleted(observe(controller, 8), elapsedNanoseconds: 25_000_000, progressOperation: operation)
        await waitUntil { await worker.count() == 3 }
        controller.demandCompleted(observe(controller, 9), elapsedNanoseconds: 25_000_000, progressOperation: operation)
        try? await Task.sleep(for: .milliseconds(50))
        XCTAssertLessThanOrEqual(controller.snapshot().reservedBytes, 4 * block)
        XCTAssertLessThanOrEqual(controller.snapshot().activeTasks, 3)
        let count = await worker.count(); XCTAssertEqual(count, 3)
        controller.cancel(filespace: "fs"); await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        XCTAssertEqual(controller.snapshot().reservedBytes, 0)
    }


    // MARK: Wide (64 MiB) tier

    /// Completes read `index` with the given latency, returning the end of the
    /// window scheduled for it (nil when nothing was scheduled).
    private func completeRead(_ controller: ReadAheadController, _ index: Int, elapsed: UInt64,
                              expectedEnd: Int? = nil, file: StaticString = #filePath, line: UInt = #line) async {
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, index), elapsedNanoseconds: elapsed) { await worker.run($0) }
        // Always wait for the task to start: releasing first would strand it.
        await waitUntil({ await worker.count() == 1 }, file: file, line: line)
        if let expectedEnd {
            let windows = await worker.windows
            XCTAssertEqual(windows.last?.end, expectedEnd * block, file: file, line: line)
        }
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    private func establish(_ controller: ReadAheadController) async {
        for index in 0..<8 {
            controller.demandCompleted(observe(controller, index), elapsedNanoseconds: 1_000_000) { _ in }
            await waitUntil { controller.snapshot().activeTasks == 0 }
        }
    }

    func testWideTierPromotesOnlyThroughRepeatedBlockedDemandCompletions() async {
        let controller = ReadAheadController()
        await establish(controller)
        await completeRead(controller, 8, elapsed: 24_999_999, expectedEnd: 9 + 16)
        await completeRead(controller, 9, elapsed: 25_000_000, expectedEnd: 10 + 32)   // 16 -> 32
        await completeRead(controller, 10, elapsed: 0, expectedEnd: 11 + 32)           // warm: no promotion
        // Progress callbacks never promote either.
        let sliding = SlidingReadAheadWork()
        controller.demandCompleted(observe(controller, 11), elapsedNanoseconds: 0, progressOperation: { window, progress in
            await sliding.run(window, progress: progress)
        })
        await waitUntil { await sliding.count() >= 1 }
        for completed in stride(from: block, through: 8 * block, by: block) { await sliding.report(0, completed: completed) }
        await sliding.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        await completeRead(controller, 12, elapsed: 25_000_000, expectedEnd: 13 + 32)  // first blocked at 32: not yet wide
        await completeRead(controller, 13, elapsed: 1_000, expectedEnd: 14 + 32)       // fast: still not wide
        await completeRead(controller, 14, elapsed: 30_000_000, expectedEnd: 15 + 64)  // second blocked: 32 -> 64
        await completeRead(controller, 15, elapsed: 0, expectedEnd: 16 + 64)           // warm keeps the evidence
    }

    func testWideWindowNeverExceedsEngineByteBudget() async {
        let controller = ReadAheadController(byteLimit: 64 << 20)
        await establish(controller)
        await completeRead(controller, 8, elapsed: 25_000_000)
        await completeRead(controller, 9, elapsed: 25_000_000)
        let worker = ReadAheadWork()
        controller.demandCompleted(observe(controller, 10), elapsedNanoseconds: 25_000_000) { await worker.run($0) } // second blocked: wide
        await waitUntil { await worker.count() == 1 }
        let windows = await worker.windows
        // Earlier 16/32 MiB warms already cover up to block 42; the wide horizon is 11 + 64.
        XCTAssertEqual(windows[0], .init(offset: 42 * block, length: 33 * block))
        XCTAssertEqual(controller.snapshot().reservedBytes, 33 * block)
        // A second demand cannot reserve beyond the budget while the first is outstanding.
        controller.demandCompleted(observe(controller, 11), elapsedNanoseconds: 25_000_000) { await worker.run($0) }
        try? await Task.sleep(for: .milliseconds(30))
        XCTAssertLessThanOrEqual(controller.snapshot().reservedBytes, 64 << 20)
        await worker.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
    }

    func testByteLimitBelowTierCapsTheWindow() async {
        for limit in [20 << 20, 8 << 20] {
            let controller = ReadAheadController(byteLimit: limit)
            await establish(controller)
            await completeRead(controller, 8, elapsed: 25_000_000)
            await completeRead(controller, 9, elapsed: 25_000_000)
            await completeRead(controller, 10, elapsed: 25_000_000)
            await completeRead(controller, 11, elapsed: 25_000_000, expectedEnd: 12 + limit / block)
            XCTAssertEqual(controller.snapshot().reservedBytes, 0)
        }
    }

    func testTwoStreamsContendingForTheEngineBudgetRefillEachOthersFreedBytes() async {
        let budget = 20 * block
        let controller = ReadAheadController(byteLimit: budget)
        let keyA = ReadAheadController.Key(filespace: "fs", itemID: "a", version: "v1")
        let keyB = ReadAheadController.Key(filespace: "fs", itemID: "b", version: "v1")
        // Establish both streams. Failing warms leave no retained coverage, so
        // each stream's first real window spans its whole 16-block horizon.
        for index in 0..<6 {
            for k in [keyA, keyB] {
                controller.demandCompleted(observe(controller, index, key: k)) { _ in throw CancellationError() }
            }
            await waitUntil { controller.snapshot().activeTasks == 0 }
        }
        let workerA = SlidingReadAheadWork(), workerB = SlidingReadAheadWork()
        let opA: ReadAheadController.ProgressiveOperation = { w, p in await workerA.run(w, progress: p) }
        let opB: ReadAheadController.ProgressiveOperation = { w, p in await workerB.run(w, progress: p) }
        func reserved() -> Int { controller.snapshot().reservedBytes }

        controller.demandCompleted(observe(controller, 6, key: keyA), progressOperation: opA)
        await waitUntil { await workerA.count() == 1 }
        controller.demandCompleted(observe(controller, 6, key: keyB), progressOperation: opB)
        await waitUntil { await workerB.count() == 1 }
        var a = await workerA.windows, b = await workerB.windows
        XCTAssertEqual(a[0], .init(offset: 7 * block, length: 16 * block))
        XCTAssertEqual(b[0], .init(offset: 7 * block, length: 4 * block), "B gets only what the shared budget has left")
        XCTAssertEqual(reserved(), budget)

        // (b) Verified progress on A frees budget; B's refill (triggered by B's own
        // progress) uses it, but only inside B's existing horizon (block 23).
        await workerA.report(0, completed: 8 * block)
        XCTAssertLessThanOrEqual(reserved(), budget)
        await workerB.report(0, completed: 4 * block)
        await waitUntil { await workerB.count() == 2 }
        b = await workerB.windows
        XCTAssertEqual(b[1], .init(offset: 11 * block, length: 12 * block))
        XCTAssertLessThanOrEqual(b[1].end, 23 * block, "progress alone never advances the horizon")
        XCTAssertEqual(reserved(), budget)
        let countA = await workerA.count(); XCTAssertEqual(countA, 1, "A's horizon is fully covered; nothing new for it")

        // (c) Canceling A keeps its unfinished bytes reserved until it drains,
        // then B's advancing demand refills from the drained budget.
        controller.cancel(filespace: "fs", itemID: "a")
        XCTAssertEqual(reserved(), budget)
        await workerA.release()
        await waitUntil { reserved() == 12 * self.block }
        controller.demandCompleted(observe(controller, 7, key: keyB), progressOperation: opB)
        await waitUntil { await workerB.count() == 3 }
        b = await workerB.windows
        XCTAssertEqual(b[2], .init(offset: 23 * block, length: block))
        XCTAssertEqual(reserved(), 13 * block)
        XCTAssertLessThanOrEqual(reserved(), budget)
        a = await workerA.windows
        XCTAssertEqual(a.count, 1, "canceled stream does not restart")

        // (d) Everything completing returns the budget to zero.
        await workerB.report(1, completed: 12 * block)
        await workerB.report(2, completed: block)
        await workerB.release()
        await waitUntil { controller.snapshot().activeTasks == 0 }
        XCTAssertEqual(reserved(), 0)
    }
}
