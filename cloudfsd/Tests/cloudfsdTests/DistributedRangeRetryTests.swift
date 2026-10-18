// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import CloudFSCore
import CloudFSGateway
@testable import cloudfsd

final class DistributedRangeRetryTests: XCTestCase {
    private func coordinator(_ replies: [RangeRetryProtocol.Reply], ttlMs: Int = 60_000,
                             actions: Set<String> = ["check"]) -> DistributedRangeCoordinator {
        RangeRetryProtocol.reset(replies, actions: actions)
        let config=URLSessionConfiguration.ephemeral
        config.protocolClasses=[RangeRetryProtocol.self]
        let gateway=HttpGatewayClient(config:GatewayClientConfig(baseURL:"https://range-retry.test",token:"test"),
                                      session:URLSession(configuration:config))
        return DistributedRangeCoordinator(gateway:gateway,filespace:"fs",ttlMs:ttlMs)
    }
    private let permit=RangeRetryProtocol.Reply.http(200,"{\"allowed\":true,\"permitTtlMs\":1000,\"permitFence\":23}",0)

    func testTransientReadChecksRetryWithSameHandleAndFence() async throws {
        let failures: [RangeRetryProtocol.Reply] = [408,429,500,502,503,504].map { .http($0,"{\"error\":\"temporary\"}",0) }
            + [URLError.timedOut,.cannotFindHost,.cannotConnectToHost,.networkConnectionLost,.dnsLookupFailed,
               .notConnectedToInternet].map { .network($0) }
        for failure in failures {
            let c=coordinator([failure,permit])
            try await c.acquire("file",handle:"reader",ranges:[.init(offset:0,length:10,exclusive:false)])
            try await c.check("file",handle:"reader",offset:0,length:1,write:false)
            let requests=RangeRetryProtocol.requests("check")
            XCTAssertEqual(requests.count,2)
            XCTAssertTrue(requests.allSatisfy { $0["handle"] as? String == "reader" && $0["fence"] as? Int == 17 })
            XCTAssertEqual(RangeRetryProtocol.requests("acquire").count,1,"retry must not reacquire an application lock")
            await c.shutdown()
            XCTAssertEqual(RangeRetryProtocol.requests("release-read").count,1)
        }
    }

    func testRetrySuccessUsesItsOwnPermitDeadline() async throws {
        let c=coordinator([.http(503,"{}",400),.http(502,"{}",400),permit])
        let start=ContinuousClock.now
        try await c.check("file",handle:"reader",offset:0,length:1,write:false)
        XCTAssertGreaterThan(start.duration(to:.now),.milliseconds(1_000))
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,3)
        try await c.check("file",handle:"reader",offset:1,length:1,write:false)
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,3,"only the final successful attempt may cache a fresh permit")
        await c.shutdown()
    }

    func testPersistentTransientFailureStopsAfterThreeAttempts() async throws {
        let c=coordinator([.network(.networkConnectionLost)])
        let start=ContinuousClock.now
        do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("must stop") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.networkError) }
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,3)
        XCTAssertGreaterThanOrEqual(start.duration(to:.now),.milliseconds(300))
        XCTAssertLessThan(start.duration(to:.now),.seconds(3))
        await c.shutdown()
        XCTAssertTrue(RangeRetryProtocol.requests("release-read").isEmpty,"failed calls cannot leave local permit authority")
    }

    func testCredentialsSemanticDenialsAndMalformedResponsesNeverRetry() async throws {
        let failures: [RangeRetryProtocol.Reply] = [400,401,403,404,409,501].map { .http($0,"{\"error\":\"permanent\"}",0) }
            + [.http(200,"malformed",0)]
            + [URLError.cancelled,.serverCertificateUntrusted,.secureConnectionFailed,.badURL,.unsupportedURL,
               .userAuthenticationRequired,.unknown].map { .network($0) }
            + ["held-by-other","fence-stale","forbidden"].map { .http(200,"{\"allowed\":false,\"reason\":\"\($0)\"}",0) }
        for failure in failures {
            let c=coordinator([failure,permit])
            do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("must reject") }
            catch {}
            XCTAssertEqual(RangeRetryProtocol.requests("check").count,1)
            await c.shutdown()
        }
    }

    func testWriteAdmissionAndLockMutationNeverRetry() async throws {
        let c=coordinator([.http(503,"{}",0)],actions:["check","acquire"])
        do { try await c.check("file",handle:"writer",offset:0,length:1,write:true); XCTFail("must reject") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.gatewayError) }
        do { try await c.acquire("file",handle:"writer",ranges:[.init(offset:0,length:1,exclusive:true)]); XCTFail("must reject") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.gatewayError) }
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,1)
        XCTAssertEqual(RangeRetryProtocol.requests("acquire").count,1)
        await c.shutdown()
    }

    func testExpiredHeldRangeStopsBeforeRetryAndCannotReacquire() async throws {
        let c=coordinator([.http(503,"{}",100),permit],ttlMs:80)
        try await c.acquire("file",handle:"reader",ranges:[.init(offset:0,length:10,exclusive:false)])
        for operation in 0..<3 {
            do {
                if operation == 2 { try await c.acquire("file",handle:"reader",ranges:[.init(offset:20,length:1,exclusive:false)]) }
                else { try await c.check("file",handle:"reader",offset:0,length:1,write:false) }
                XCTFail("expired application authority is sticky")
            } catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        }
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,1)
        XCTAssertEqual(RangeRetryProtocol.requests("acquire").count,1)
        await c.shutdown()
    }

    func testLatePermitIsReleasedWhenHeldRangeExpiresDuringSuccessfulResponse() async throws {
        let c=coordinator([.http(200,"{\"allowed\":true,\"permitTtlMs\":1000,\"permitFence\":23}",100)],ttlMs:80)
        try await c.acquire("file",handle:"reader",ranges:[.init(offset:0,length:10,exclusive:false)])
        do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("must reject") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,1)
        XCTAssertEqual(RangeRetryProtocol.requests("release-read").count,1)
        await c.shutdown()
        XCTAssertEqual(RangeRetryProtocol.requests("release-read").count,1,"late permit was never cached")
    }

    func testCancellationDuringBackoffStopsWithoutAnotherAdmission() async throws {
        let c=coordinator([.http(503,"{}",0),permit])
        let read=Task { try await c.check("file",handle:"reader",offset:0,length:1,write:false) }
        let deadline=ContinuousClock.now.advanced(by:.seconds(2))
        while RangeRetryProtocol.requests("check").isEmpty && ContinuousClock.now<deadline { try await Task.sleep(for:.milliseconds(1)) }
        read.cancel()
        do { try await read.value; XCTFail("cancelled read must not resume") }
        catch is CancellationError {}
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,1)
        await c.shutdown()
    }

    func testExpiredPermitResponseRetriesBeforeAdmittingConcurrentWarmReads() async throws {
        let late=RangeRetryProtocol.Reply.http(200,"{\"allowed\":true,\"permitTtlMs\":1000,\"permitFence\":22}",950)
        let c=coordinator([late,permit])
        let admitted=await withTaskGroup(of:Bool.self) { group in
            for offset in 0..<8 {
                group.addTask {
                    do { try await c.check("file",handle:"reader",offset:UInt64(offset*524288),length:524288,write:false); return true }
                    catch { return false }
                }
            }
            var values:[Bool]=[]; for await value in group { values.append(value) }; return values
        }
        XCTAssertEqual(admitted.count,8)
        XCTAssertTrue(admitted.allSatisfy { $0 },"an unusably late permit must not become a spurious SMB lock denial")
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,2,"queued warm reads reuse only the fresh second permit")
        XCTAssertEqual(RangeRetryProtocol.requests("release-read").map { $0["fence"] as? Int },[22])
        XCTAssertTrue(RangeRetryProtocol.requests("acquire").isEmpty,"read retry must never acquire an application lock")
        await c.shutdown()
        XCTAssertEqual(RangeRetryProtocol.requests("release-read").map { $0["fence"] as? Int },[22,23])
    }

    func testRepeatedExpiredPermitResponsesStopWithinSharedRetryBudget() async throws {
        let late=RangeRetryProtocol.Reply.http(200,"{\"allowed\":true,\"permitTtlMs\":1000,\"permitFence\":23}",950)
        let c=coordinator([.http(503,"{}",0),late])
        let start=ContinuousClock.now
        do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("no late grant can authorize data") }
        catch let error as EngineError {
            XCTAssertEqual(error.kind,.locked); XCTAssertEqual(error.data?["reason"],.string("read-permit-expired"))
        }
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,3,"transport and expired-permit retries share one bounded budget")
        XCTAssertEqual(RangeRetryProtocol.requests("release-read").count,2)
        XCTAssertLessThan(start.duration(to:.now),.seconds(4))
        await c.shutdown()
        XCTAssertEqual(RangeRetryProtocol.requests("release-read").count,2,"no expired grant was cached")
    }

    func testExpiredPermitRetryCannotBypassConflictOrRevocation() async throws {
        let late=RangeRetryProtocol.Reply.http(200,"{\"allowed\":true,\"permitTtlMs\":1000,\"permitFence\":23}",950)
        for reason in ["held-by-other","forbidden","fence-stale"] {
            let c=coordinator([late,.http(200,"{\"allowed\":false,\"reason\":\"\(reason)\"}",0),permit])
            do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("must preserve true admission denial") }
            catch let error as EngineError { XCTAssertEqual(error.kind,reason == "forbidden" ? .permissionDenied : .locked) }
            XCTAssertEqual(RangeRetryProtocol.requests("check").count,2)
            XCTAssertEqual(RangeRetryProtocol.requests("release-read").count,1)
            await c.shutdown()
        }
    }

    func testHeldLeaseExpiryDuringExpiredPermitCleanupStopsBeforeRetry() async throws {
        let late=RangeRetryProtocol.Reply.http(200,"{\"allowed\":true,\"permitTtlMs\":1000,\"permitFence\":23}",950)
        let c=coordinator([late,.http(200,"{\"released\":true}",200),permit],ttlMs:1100,actions:["check","release-read"])
        try await c.acquire("file",handle:"reader",ranges:[.init(offset:0,length:10,exclusive:false)])
        do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("cleanup cannot extend held application authority") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,1)
        XCTAssertEqual(RangeRetryProtocol.requests("acquire").count,1)
        do { try await c.check("file",handle:"reader",offset:0,length:1,write:false); XCTFail("lost lease remains sticky") }
        catch let error as EngineError { XCTAssertEqual(error.kind,.locked) }
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,1)
        await c.shutdown()
    }

    func testCancellationAfterExpiredPermitCleanupStopsBeforeRetry() async throws {
        let late=RangeRetryProtocol.Reply.http(200,"{\"allowed\":true,\"permitTtlMs\":1000,\"permitFence\":23}",950)
        let c=coordinator([late,permit])
        let read=Task { try await c.check("file",handle:"reader",offset:0,length:1,write:false) }
        let deadline=ContinuousClock.now.advanced(by:.seconds(3))
        while RangeRetryProtocol.requests("release-read").isEmpty && ContinuousClock.now<deadline {
            try await Task.sleep(for:.milliseconds(1))
        }
        XCTAssertEqual(RangeRetryProtocol.requests("release-read").count,1)
        read.cancel()
        do { try await read.value; XCTFail("cancelled admission must not retry") }
        catch is CancellationError {}
        XCTAssertEqual(RangeRetryProtocol.requests("check").count,1)
        await c.shutdown()
    }
}

private final class RangeRetryProtocol: URLProtocol, @unchecked Sendable {
    enum Reply { case http(Int,String,Int); case network(URLError.Code) }
    private static let lock=NSLock()
    nonisolated(unsafe) private static var replies: [Reply]=[]
    nonisolated(unsafe) private static var actions: Set<String>=[]
    nonisolated(unsafe) private static var seen: [[String:Any]]=[]
    static func reset(_ values:[Reply],actions:Set<String>) {
        lock.withLock { replies=values; self.actions=actions; seen=[] }
    }
    static func requests(_ action:String)->[[String:Any]] { lock.withLock { seen.filter { $0["action"] as? String == action } } }
    override class func canInit(with request:URLRequest)->Bool { request.url?.host == "range-retry.test" }
    override class func canonicalRequest(for request:URLRequest)->URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        let body=(try? JSONSerialization.jsonObject(with:GWStub.bodyData(request) ?? Data())) as? [String:Any] ?? [:]
        let reply:Reply=Self.lock.withLock {
            Self.seen.append(body)
            let action=body["action"] as? String ?? ""
            if Self.actions.contains(action), let first=Self.replies.first {
                if Self.replies.count>1 { Self.replies.removeFirst() }
                return first
            }
            if action == "release" || action == "release-read" { return .http(200,"{\"released\":true}",0) }
            return .http(200,"{\"granted\":true,\"path\":\"file\",\"fence\":17}",0)
        }
        switch reply {
        case .network(let code): client?.urlProtocol(self,didFailWithError:URLError(code))
        case .http(let status,let body,let delay):
            if delay>0 { Thread.sleep(forTimeInterval:Double(delay)/1000) }
            let response=HTTPURLResponse(url:request.url!,statusCode:status,httpVersion:"HTTP/1.1",headerFields:["Content-Type":"application/json"])!
            client?.urlProtocol(self,didReceive:response,cacheStoragePolicy:.notAllowed)
            client?.urlProtocol(self,didLoad:Data(body.utf8))
            client?.urlProtocolDidFinishLoading(self)
        }
    }
}
