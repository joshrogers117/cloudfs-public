// SPDX-License-Identifier: AGPL-3.0-or-later
import XCTest
import Foundation
import CryptoKit
import CloudFSCore
@testable import CloudFSTransfer

private final class ImmutableUploadProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    nonisolated(unsafe) private static var existing = Data()
    nonisolated(unsafe) private static var requests: [URLRequest] = []
    static func configure(_ bytes: Data) { lock.withLock { existing = bytes; requests = [] } }
    static func captured() -> [URLRequest] { lock.withLock { requests } }
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "immutable.test" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}
    override func startLoading() {
        let body = Self.lock.withLock { Self.requests.append(request); return Self.existing }
        let code = request.httpMethod == "PUT" ? 412 : 200
        client?.urlProtocol(self,didReceive:HTTPURLResponse(url:request.url!,statusCode:code,httpVersion:nil,headerFields:nil)!,cacheStoragePolicy:.notAllowed)
        if request.httpMethod == "GET" { client?.urlProtocol(self,didLoad:body) }
        client?.urlProtocolDidFinishLoading(self)
    }
}
final class ImmutableUploadTransportTests: XCTestCase {
    private func transport() -> BlobTransport {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [ImmutableUploadProtocol.self]
        return BlobTransport(session:URLSession(configuration:config),policy:RetryPolicy(maxAttempts:1))
    }
    func testConditionalRetrySendsRequiredHeadersAndVerifiesExistingCiphertext() async throws {
        let bytes=Data([1,2,3,4]); ImmutableUploadProtocol.configure(bytes)
        let headers=["if-none-match":"*","x-amz-checksum-sha256":Data(SHA256.hash(data:bytes)).base64EncodedString()]
        try await transport().put(url:"https://immutable.test/put",body:bytes,headers:headers,verificationUrl:"https://immutable.test/verify")
        let requests=ImmutableUploadProtocol.captured();XCTAssertEqual(requests.map(\.httpMethod),["PUT","GET"])
        XCTAssertEqual(requests[0].value(forHTTPHeaderField:"if-none-match"),"*")
        XCTAssertEqual(requests[0].value(forHTTPHeaderField:"x-amz-checksum-sha256"),headers["x-amz-checksum-sha256"])
    }
    func testConditionalRetryNeverAcceptsWrongOrTruncatedCiphertext() async throws {
        for existing in [Data([1,2,3,5]),Data([1,2,3])] {
            ImmutableUploadProtocol.configure(existing)
            do { try await transport().put(url:"https://immutable.test/put",body:Data([1,2,3,4]),headers:["if-none-match":"*"],verificationUrl:"https://immutable.test/verify");XCTFail("corrupt existing object must not pass") }
            catch let error as EngineError { XCTAssertEqual(error.kind,.syncFailed) }
        }
    }
    func testBare412IsNotSuccessAndDoesNotInventReadAuthorization() async throws {
        ImmutableUploadProtocol.configure(Data([1,2,3,4]))
        do { try await transport().put(url:"https://immutable.test/put",body:Data([1,2,3,4]),headers:["if-none-match":"*"]);XCTFail("no proof") }
        catch let error as EngineError { XCTAssertEqual(error.data?["status"],.int(412)) }
        XCTAssertEqual(ImmutableUploadProtocol.captured().count,1)
    }
}
