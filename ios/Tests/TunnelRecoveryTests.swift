import XCTest
@testable import FortiCore

final class TunnelRecoveryTests: XCTestCase {
    func testSystemRestartRestoresSavedProviderWithoutLaunchOptions() {
        XCTAssertEqual(TunnelRecoveryPolicy.provider(option: nil, saved: "hillstone"), "hillstone")
        XCTAssertEqual(TunnelRecoveryPolicy.provider(option: "forti", saved: "hillstone"), "forti")
        XCTAssertEqual(TunnelRecoveryPolicy.provider(option: nil, saved: nil), "forti")
    }
    func testNetworkFailuresRetryButTrustAndAuthenticationFailuresStop() {
        for error in ["data_heartbeat_expired", "control_keepalive_expired", "gateway_rekey_required",
                      "gateway_disconnected", "data_send_failed", "control_connect_failed"] {
            XCTAssertTrue(TunnelRecoveryPolicy.canRetry(error), error)
        }
        for error in ["certificate_pin_mismatch", "gateway_rejected_request", "invalid_profile"] {
            XCTAssertFalse(TunnelRecoveryPolicy.canRetry("Hillstone 连接失败：" + error), error)
        }
    }
    func testLongOutageKeepsBoundedBackoffWithoutAttemptLimit() {
        XCTAssertEqual((1...8).map(TunnelRecoveryPolicy.retryDelay), [1, 2, 4, 8, 15, 30, 60, 60])
        XCTAssertEqual(TunnelRecoveryPolicy.retryDelay(attempt: 100_000), 60)
    }
    func testFortiRetainsSessionUntilPathAndEncryptedDataBothRecover() {
        var state = FortiPathRecovery()
        XCTAssertEqual(state.observe(valid: true), .ready)
        for _ in 0..<100_000 { XCTAssertEqual(state.observe(valid: false), .waitForNetwork) }
        XCTAssertEqual(state.observe(valid: true), .validateTunnel)
        XCTAssertEqual(state.observe(valid: true), .validateTunnel)
        state.validated()
        XCTAssertEqual(state.observe(valid: true), .ready)
        state.wake()
        XCTAssertEqual(state.observe(valid: true), .validateTunnel)
        XCTAssertEqual(state.observe(valid: false), .waitForNetwork)
    }
}
