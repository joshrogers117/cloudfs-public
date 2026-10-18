// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
@testable import cloudfsd

private actor DirectoryRequests {
    var values: [String] = []
    func record(_ item: ItemMetadata) { values.append(item.id.rawValue) }
}
final class DirectoryPrefetchTests: XCTestCase {
    private func items(_ count: Int = 10) -> [ItemMetadata] {
        (1...count).map { ItemMetadata(id: InodeID("f\($0)"),parent: "frames",name: String(format:"frame%05d.exr",$0),isDir: false,size: 8 << 20,contentVersion:"v1",metadataVersion:"1") }
    }
    private func wait(_ recorder: DirectoryRequests, count: Int) async throws -> [String] {
        for _ in 0..<100 { let values = await recorder.values; if values.count >= count { return values }; try await Task.sleep(for:.milliseconds(5)) }
        return await recorder.values
    }
    func testRequiresThreeDemandedFramesAndBoundsWarmupWithoutRecursiveChaining() async throws {
        let predictor = DirectoryPrefetcher(), recorder = DirectoryRequests()
        predictor.listing(filespace:"fs",parent:"frames",items:items(),firstPage:true)
        let operation: DirectoryPrefetcher.Operation = { item,_ in await recorder.record(item); try await Task.sleep(for:.seconds(60)) }
        for i in 1...2 { predictor.readCompleted(filespace:"fs",itemID:InodeID("f\(i)"),version:"v1",blockSize:1<<20,operation:operation) }
        XCTAssertEqual(predictor.snapshot().activeJobs,0)
        predictor.readCompleted(filespace:"fs",itemID:"f3",version:"v1",blockSize:1<<20,operation:operation)
        let values = try await wait(recorder,count:2)
        XCTAssertEqual(Set(values),Set(["f4","f5"]))
        XCTAssertEqual(predictor.snapshot().activeJobs,2); XCTAssertEqual(predictor.snapshot().reservedBytes,4<<20)
        predictor.readCompleted(filespace:"fs",itemID:"f3",version:"v1",blockSize:1<<20,operation:operation)
        predictor.setPaused(true,filespace:"fs")
        await predictor.cancelAndWait(filespace:"fs")
        XCTAssertEqual(predictor.snapshot().activeJobs,0)
        predictor.listing(filespace:"fs",parent:"frames",items:items(),firstPage:true)
        XCTAssertEqual(predictor.snapshot().entries,0)
    }
    func testRandomAccessStaleVersionsAndInvalidationDoNotSpeculateAndMetadataIsBounded() async {
        let p = DirectoryPrefetcher()
        p.listing(filespace:"fs",parent:"frames",items:items(),firstPage:true)
        let noWork: DirectoryPrefetcher.Operation = { _,_ in XCTFail("unexpected speculation") }
        for id in ["f1","f8","f2","f2"] { p.readCompleted(filespace:"fs",itemID:InodeID(id),version:"v1",blockSize:1<<20,operation:noWork) }
        for id in ["f3","f4","f5"] { p.readCompleted(filespace:"fs",itemID:InodeID(id),version:"stale",blockSize:1<<20,operation:noWork) }
        p.invalidate(filespace:"fs",itemID:"f2")
        XCTAssertEqual(p.snapshot().directories,0); XCTAssertEqual(p.snapshot().activeJobs,0)
        p.listing(filespace:"fs",parent:"frames",items:items(5000),firstPage:true)
        XCTAssertEqual(p.snapshot().entries,2048)
        await p.cancelAndWait(filespace:"fs")
    }
    func testUnchangedDirectoryRefreshPreservesReadSequenceAndActiveWarmup() async throws {
        let predictor = DirectoryPrefetcher(), recorder = DirectoryRequests()
        let frames = items()
        let operation: DirectoryPrefetcher.Operation = { item, _ in
            await recorder.record(item)
            try await Task.sleep(for: .seconds(60))
        }
        // SMB may re-enumerate a directory between reads as its metadata cache expires.
        for i in 1...3 {
            predictor.listing(filespace: "fs", parent: "frames", items: frames, firstPage: true)
            predictor.readCompleted(filespace: "fs", itemID: InodeID("f\(i)"), version: "v1", blockSize: 1 << 20, operation: operation)
        }
        let requests = try await wait(recorder, count: 2)
        XCTAssertEqual(Set(requests), Set(["f4", "f5"]))
        predictor.listing(filespace: "fs", parent: "frames", items: frames.reversed(), firstPage: true)
        XCTAssertEqual(predictor.snapshot().activeJobs, 2)
        await predictor.cancelAndWait(filespace: "fs")
    }

    func testChangedListingDiscardsOldSequenceAndRemovedCandidates() async {
        let predictor = DirectoryPrefetcher()
        let frames = items()
        let noWork: DirectoryPrefetcher.Operation = { _, _ in XCTFail("stale directory sequence must not speculate") }
        predictor.listing(filespace: "fs", parent: "frames", items: frames, firstPage: true)
        for id: InodeID in ["f1", "f2"] {
            predictor.readCompleted(filespace: "fs", itemID: id, version: "v1", blockSize: 1 << 20, operation: noWork)
        }
        predictor.listing(filespace: "fs", parent: "frames", items: Array(frames.prefix(3)), firstPage: true)
        predictor.readCompleted(filespace: "fs", itemID: "f3", version: "v1", blockSize: 1 << 20, operation: noWork)
        XCTAssertEqual(predictor.snapshot().entries, 3)
        XCTAssertEqual(predictor.snapshot().activeJobs, 0)
        await predictor.cancelAndWait(filespace: "fs")
    }

}
