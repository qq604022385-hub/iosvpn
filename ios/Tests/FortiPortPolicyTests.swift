import XCTest
@testable import FortiCore
final class FortiPortPolicyTests: XCTestCase {
    func testNoResponseTriesStandardNattOnlyOnce() {
        var policy = FortiPortPolicy()
        XCTAssertEqual(policy.port, 500)
        XCTAssertTrue(policy.nextAfterNoResponse())
        XCTAssertEqual(policy.port, 4500)
        XCTAssertFalse(policy.nextAfterNoResponse())
        XCTAssertEqual(policy.port, 500)
        XCTAssertFalse(policy.nextAfterNoResponse())
    }
}
