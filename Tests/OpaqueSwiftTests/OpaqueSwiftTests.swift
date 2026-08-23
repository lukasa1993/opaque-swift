import XCTest
@testable import OpaqueSwift

final class OpaqueSwiftTests: XCTestCase {
    func testFFIVersion() {
        XCTAssertEqual(OpaqueClient.ffiVersion, 1)
    }

    func testRegistrationStartCreatesRequest() throws {
        let session = try OpaqueClient.startRegistration(password: "correct horse battery staple")
        XCTAssertFalse(session.request.isEmpty)
    }

    func testLoginStartCreatesRequest() throws {
        let session = try OpaqueClient.startLogin(password: "correct horse battery staple")
        XCTAssertFalse(session.request.isEmpty)
    }
}
