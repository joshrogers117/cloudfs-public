// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
@testable import CloudFSTransfer

final class UploadPreparationBudgetTests: XCTestCase {
    private func until(_ condition: () -> Bool) async throws {
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !condition(), ContinuousClock.now < deadline { try await Task.sleep(for: .milliseconds(1)) }
        XCTAssertTrue(condition())
    }
    func testGlobalReservationsAreBoundedFairAndReleaseIsIdempotent() async throws {
        let budget = UploadPreparationBudget(limit: 2)
        let first = try XCTUnwrap(budget.tryAcquire()), second = try XCTUnwrap(budget.tryAcquire())
        XCTAssertNil(budget.tryAcquire())
        let queued = Task { try await budget.acquire() }
        try await until { budget.metrics().queued == 1 }
        first.release(); first.release()
        let third = try await queued.value
        XCTAssertEqual(budget.metrics().active, 2, "double release must not create another slot")
        XCTAssertNil(budget.tryAcquire(), "immediate early work cannot exceed the global reservation")
        second.release(); third.release()
        XCTAssertEqual(budget.metrics().active, 0); XCTAssertEqual(budget.metrics().peak, 2)
    }
    func testCancellationRemovesQueuedWorkAndLateCancellationDoesNotLeakCapacity() async throws {
        let budget = UploadPreparationBudget(limit: 1), held = try XCTUnwrap(budget.tryAcquire())
        let canceled = Task { try await budget.acquire() }
        try await until { budget.metrics().queued == 1 }
        canceled.cancel()
        do { _ = try await canceled.value; XCTFail("Canceled preparation was admitted") } catch is CancellationError {}
        XCTAssertEqual(budget.metrics().queued, 0); XCTAssertEqual(budget.metrics().active, 1)
        held.release()
        for iteration in 0..<100 {
            let reservation = try XCTUnwrap(budget.tryAcquire())
            let task = Task {
                let acquired = try await budget.acquire()
                defer { acquired.release() }
                try Task.checkCancellation()
            }
            try await until { budget.metrics().queued == 1 }
            // Exercise completion-vs-cancellation in both orders.
            if iteration.isMultiple(of: 2) { task.cancel(); reservation.release() }
            else { reservation.release(); task.cancel() }
            do { try await task.value } catch is CancellationError {}
            XCTAssertEqual(budget.metrics().active, 0); XCTAssertEqual(budget.metrics().queued, 0)
        }
    }
    func testReleasedReservationsHandOffToQueuedNormalWorkBeforeNewEarlyWork() async throws {
        let budget = UploadPreparationBudget(limit: 1), held = try XCTUnwrap(budget.tryAcquire())
        let normal = Task { try await budget.acquire() }
        try await until { budget.metrics().queued == 1 }
        held.release()
        XCTAssertNil(budget.tryAcquire())
        let next = try await normal.value; next.release()
        let early = try XCTUnwrap(budget.tryAcquire()); early.release()
        XCTAssertEqual(budget.metrics().peak, 1)
    }
}
