// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation

// Contains only redacted engine logs and fixed stage/error messages.
struct TunnelDiagnostics: Codable {
    let attemptID: String?
    let stage: String
    let failure: String?
    let logs: String
}
