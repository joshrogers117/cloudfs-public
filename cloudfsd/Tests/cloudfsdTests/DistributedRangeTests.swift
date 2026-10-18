// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import cloudfsd

final class DistributedRangeTests: XCTestCase {
    private let route="POST /v1/filespaces/fs/range-locks"
    private func client() -> HttpGatewayClient {
        HttpGatewayClient(config:GatewayClientConfig(baseURL:"https://range.test",token:"same-user"),session:GWStub.session())
    }
    func testRangeWireUsesExactUInt64AndReleaseRetainsHandleFence() async throws {
        GWStub.reset()
        let fixture=RangeWireFixture()
        GWStub.on(route) { fixture.response($0) }
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        let high=FileLockRange(offset:UInt64.max-1,length:1,exclusive:false)
        try await c.acquire("file",handle:"handle",ranges:[high])
        try await c.acquire("file",handle:"handle",ranges:[.init(offset:10,length:5,exclusive:true)])
        try await c.check("file",handle:"handle",offset:10,length:1,write:true)
        try await c.release("file",handle:"handle",ranges:[high])
        await c.releaseAll("file",handle:"handle")
        let requests=fixture.requests
        XCTAssertEqual(requests.count,5)
        XCTAssertEqual((requests[0]["ranges"] as? [[String:Any]])?.first?["offset"] as? String,String(UInt64.max-1))
        XCTAssertNil(requests[0]["fence"])
        for request in requests.dropFirst() { XCTAssertEqual(request["fence"] as? Int,17) }
        XCTAssertNil(requests.last?["ranges"],"final close releases all remaining ranges")
        await c.shutdown()
    }
    func testLostRangeIsStickyAndDoesNotReacquireOrServeData() async throws {
        GWStub.reset(); let fixture=RangeWireFixture(); GWStub.on(route) { fixture.response($0) }
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        try await c.acquire("file",handle:"editor",ranges:[.init(offset:0,length:100,exclusive:true)])
        fixture.rejectRenewal=true
        await c.renewAll()
        let before=GWStub.count(route)
        for operation in 0..<2 {
            do {
                if operation == 0 { try await c.acquire("file",handle:"editor",ranges:[.init(offset:200,length:1,exclusive:true)]) }
                else { try await c.check("file",handle:"editor",offset:0,length:1,write:false,publicationDeadline:.now.advanced(by:.seconds(30))) }
                XCTFail("lost range must reject both acquisition and I/O, even with a publication lease")
            } catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        }
        XCTAssertEqual(GWStub.count(route),before)
        await c.releaseAll("file",handle:"editor")
        fixture.rejectRenewal=false
        try await c.acquire("file",handle:"reopened",ranges:[.init(offset:0,length:100,exclusive:true)])
        await c.shutdown()
    }
    func testUnprotectedReadsRecheckButPublicationProtectionAvoidsMetadataRTTs() async throws {
        GWStub.reset(); let fixture=RangeWireFixture(); fixture.delayMs=100; GWStub.on(route) { fixture.response($0) }
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        let start=ContinuousClock.now
        for _ in 0..<5 { try await c.check("file",handle:"reader",offset:0,length:1<<20,write:false) }
        let remoteElapsed=start.duration(to:.now)
        XCTAssertEqual(GWStub.count(route),5)
        XCTAssertGreaterThanOrEqual(remoteElapsed,.milliseconds(450))
        let localStart=ContinuousClock.now
        for _ in 0..<5 { try await c.check("file",handle:"reader",offset:0,length:1<<20,write:false,publicationDeadline:.now.advanced(by:.seconds(30))) }
        let protectedElapsed=localStart.duration(to:.now)
        XCTAssertEqual(GWStub.count(route),5,"live publication lease must remove all five redundant checks")
        XCTAssertLessThan(protectedElapsed,.milliseconds(100))
        print("RANGE_ADMISSION_BENCHMARK unprotected_5x100ms=\(remoteElapsed) publication_protected=\(protectedElapsed)")
        await c.shutdown()
    }
    func testPositiveReadPermitsAmortizeWarmReadsAndRecheckAfterExpiry() async throws {
        GWStub.reset(); let fixture=RangeWireFixture(); fixture.delayMs=100; fixture.grantPermit=true
        GWStub.on(route) { fixture.response($0) }
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        let start=ContinuousClock.now
        for _ in 0..<20 { try await c.check("file",handle:"reader",offset:0,length:1<<20,write:false) }
        let elapsed=start.duration(to:.now)
        XCTAssertEqual(GWStub.count(route),1,"20 warm read admissions require one positive permit, not 20 round trips")
        XCTAssertLessThan(elapsed,.milliseconds(500))
        print("READ_PERMIT_BENCHMARK 20x100ms=\(elapsed) metadata_requests=1")
        try await Task.sleep(for:.milliseconds(950))
        fixture.denyReads=true
        do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("expired permit must recheck conflicting remote lock") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        XCTAssertEqual(GWStub.count(route),2)
        await c.shutdown()
    }
    func testReadPermitNeverBypassesLostRangeAndCloseReleasesPermit() async throws {
        GWStub.reset(); let fixture=RangeWireFixture(); fixture.grantPermit=true; GWStub.on(route) { fixture.response($0) }
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        try await c.acquire("file",handle:"reader",ranges:[.init(offset:0,length:1,exclusive:false)])
        try await c.check("file",handle:"reader",offset:0,length:1,write:false)
        fixture.rejectRenewal=true; await c.renewAll()
        do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("a positive permit cannot resurrect a lost application lock") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        await c.releaseAll("file",handle:"reader")
        XCTAssertTrue(fixture.requests.contains { $0["action"] as? String == "release-read" && $0["fence"] as? Int == 23 })
        await c.shutdown()
    }
    func testPermitResponseArrivingAfterDeadlineCannotServeData() async throws {
        GWStub.reset(); let fixture=RangeWireFixture(); fixture.grantPermit=true; fixture.delayMs=950; GWStub.on(route) { fixture.response($0) }
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("delayed expired permit cannot authorize I/O") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        await c.shutdown()
    }
    func testExpiredPublicationProtectionDoesNotBypassRemoteConflict() async throws {
        GWStub.reset(); GWStub.on(route,json:"{\"allowed\":false,\"reason\":\"held-by-other\"}")
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        do {
            try await c.check("file",handle:"reader",offset:0,length:1,write:false,publicationDeadline:.now.advanced(by:.seconds(-1)))
            XCTFail("expired publication authority must not bypass remote locks")
        } catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        XCTAssertEqual(GWStub.count(route),1)
        await c.shutdown()
    }

    func testSharedMultiplicityDecrementRetainsRemoteFenceAndCannotHideLeaseLoss() async throws {
        GWStub.reset(); let fixture=RangeWireFixture(); GWStub.on(route) { fixture.response($0) }
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        let range=FileLockRange(offset:0,length:100,exclusive:false)
        try await c.acquire("file",handle:"reader",ranges:[range])
        try await c.release("file",handle:"reader",ranges:[])
        XCTAssertEqual(GWStub.count(route),1,"a local shared-lock decrement must not send an empty HTTP release")
        try await c.check("file",handle:"reader",offset:0,length:1,write:false)
        XCTAssertEqual(fixture.requests.last?["fence"] as? Int,17)
        fixture.rejectRenewal=true; await c.renewAll()
        let count=GWStub.count(route)
        do { try await c.release("file",handle:"reader",ranges:[]); XCTFail("lost authority must reject a local-only decrement") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        XCTAssertEqual(GWStub.count(route),count)
        await c.shutdown()
    }

    func testOwnerSharedLocksDenyWritesEvenWithPublicationFastPath() async throws {
        GWStub.reset(); let fixture=RangeWireFixture(); GWStub.on(route) { fixture.response($0) }
        let c=DistributedRangeCoordinator(gateway:client(),filespace:"fs")
        let shared=FileLockRange(offset:20,length:10,exclusive:false)
        try await c.acquire("file",handle:"writer",ranges:[.init(offset:0,length:100,exclusive:true),shared])
        let deadline=ContinuousClock.now.advanced(by:.seconds(30))
        try await c.check("file",handle:"writer",offset:0,length:10,write:true,publicationDeadline:deadline)
        try await c.check("file",handle:"writer",offset:20,length:10,write:false,publicationDeadline:deadline)
        do { try await c.check("file",handle:"writer",offset:29,length:1,write:true,publicationDeadline:deadline); XCTFail("own shared lock forbids writes") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        try await c.check("file",handle:"writer",offset:30,length:1,write:true,publicationDeadline:deadline)
        XCTAssertEqual(GWStub.count(route),1,"local held ranges suffice while publication authority is live")
        try await c.release("file",handle:"writer",ranges:[shared])
        try await c.check("file",handle:"writer",offset:29,length:1,write:true,publicationDeadline:deadline)
        await c.shutdown()
    }
}
private final class RangeWireFixture: @unchecked Sendable {
    private let mutex=NSLock()
    private var seen:[[String:Any]]=[]
    private var failRenew=false
    private var latency=0
    private var permits=false
    private var deny=false
    var grantPermit:Bool { get { mutex.withLock { permits } } set { mutex.withLock { permits=newValue } } }
    var denyReads:Bool { get { mutex.withLock { deny } } set { mutex.withLock { deny=newValue } } }
    var requests:[[String:Any]] { mutex.withLock { seen } }
    var rejectRenewal:Bool { get { mutex.withLock { failRenew } } set { mutex.withLock { failRenew=newValue } } }
    var delayMs:Int { get { mutex.withLock { latency } } set { mutex.withLock { latency=newValue } } }
    func response(_ request:URLRequest)->(Int,String) {
        let body=(try? JSONSerialization.jsonObject(with:GWStub.bodyData(request) ?? Data())) as? [String:Any] ?? [:]
        let state=mutex.withLock { seen.append(body); return (failRenew,latency,permits,deny) }
        if state.1 > 0 { Thread.sleep(forTimeInterval:Double(state.1)/1000) }
        switch body["action"] as? String {
        case "check":
            if state.3 { return (200,"{\"allowed\":false,\"reason\":\"held-by-other\"}") }
            return (200,state.2 ? "{\"allowed\":true,\"permitTtlMs\":1000,\"permitFence\":23}" : "{\"allowed\":true}")
        case "release", "release-read": return (200,"{\"released\":true}")
        case "renew" where state.0: return (200,"{\"granted\":false,\"path\":\"file\",\"reason\":\"fence-stale\"}")
        default: return (200,"{\"granted\":true,\"path\":\"file\",\"fence\":17}")
        }
    }
}
