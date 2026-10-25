import XCTest
@testable import FortiCore

final class TokenResponseTests: XCTestCase {
    func testLeadingZeroAndTextWhitespace() throws {
        XCTAssertEqual(try TokenResponse.parse(Data("012345".utf8)), "012345")
        XCTAssertEqual(try TokenResponse.parse(Data(" \t012345\r\n".utf8)), "012345")
    }
    func testInvalidBodiesNeverBecomeTokens() {
        for body in ["", "12345", "1234567", "１２３４５６", "12 3456", "{\"key\":\"012345\"}", "<html>123456</html>", "123456\0", "\u{000B}123456"] {
            XCTAssertThrowsError(try TokenResponse.parse(Data(body.utf8)))
        }
    }
    func testOversizedBodyIsRejected() {
        XCTAssertThrowsError(try TokenResponse.parse(Data(repeating: 49, count: 65)))
    }
}
