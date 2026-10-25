// SPDX-License-Identifier: GPL-2.0-or-later
public struct FortiPortPolicy {
    public private(set) var port: UInt16 = 500
    private var triedNatt = false
    public init() {}
    public mutating func nextAfterNoResponse() -> Bool {
        if port == 500 && !triedNatt {
            port = 4500; triedNatt = true; return true
        }
        port = 500; return false
    }
}
