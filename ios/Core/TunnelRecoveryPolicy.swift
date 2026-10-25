// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation

/// Reconnect with saved SCVPN credentials or a freshly fetched Forti token.
/// A Forti token is never persisted or replayed.
public enum TunnelRecoveryPolicy {
    public static func provider(option: String?, saved: String?) -> String {
        option ?? saved ?? "forti"
    }
    public static func retryDelay(attempt: Int) -> Double {
        [1, 2, 4, 8, 15, 30, 60][min(max(attempt - 1, 0), 6)]
    }
    public static func canRetry(_ detail: String) -> Bool {
        // A fresh login cannot resolve rejected credentials or changed trust.
        !["certificate_pin_mismatch", "certificate_missing", "invalid_certificate_pin",
          "gateway_rejected_request", "invalid_profile", "gateway_requires_ipv4",
          "unsupported_key_exchange"].contains(where: detail.contains)
    }
}

/// Preserve an authenticated IKE session during transient path loss. Only the
/// native engine can declare that the SA is gone and a new OTP is required.
public struct FortiPathRecovery {
    public enum Action: Equatable { case ready, waitForNetwork, validateTunnel }
    private var needsValidation = false
    public init() {}
    public mutating func observe(valid: Bool) -> Action {
        if !valid { needsValidation = true; return .waitForNetwork }
        return needsValidation ? .validateTunnel : .ready
    }
    public mutating func wake() { needsValidation = true }
    public mutating func validated() { needsValidation = false }
}
