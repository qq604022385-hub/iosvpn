// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
public enum ProfileError: Error, LocalizedError {
    case invalid(String)
    public var errorDescription: String? { if case .invalid(let s) = self { return s }; return nil }
}
public struct SiteSettings: Codable, Equatable {
    public var gateway = "115.31.179.179"
    public var username = ""
    public var password = ""
    public var psk = ""
    public var localID = ""
    public var dns = "1.1.1.1"
    public var splitChina = true
    public var appendToken = true
    public init() {}
    public func validate(china: [IPv4CIDR]) throws {
        guard IPv4CIDR.address(gateway) != nil else { throw ProfileError.invalid("网关需要填写 IPv4 地址。") }
        guard let address = IPv4CIDR.address(dns), IPv4CIDR.isPublic(address) else {
            throw ProfileError.invalid("VPN DNS 需要填写公网 IPv4 地址。")
        }
        guard !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, username.count <= 200 else {
            throw ProfileError.invalid("请填写 XAuth 用户名（最多 200 字）。")
        }
        guard !password.isEmpty, password.count <= 512 else { throw ProfileError.invalid("请填写 XAuth 密码。") }
        guard !psk.isEmpty, psk.count <= 512 else { throw ProfileError.invalid("请填写明文 PSK。") }
        guard localID.count <= 200 else { throw ProfileError.invalid("本地标识过长。") }
        guard ![gateway, username, password, psk, localID, dns].contains(where: { $0.utf8.contains(0) }) else {
            throw ProfileError.invalid("设置不能包含空字符。")
        }
        if splitChina && china.contains(where: { $0.contains(address) }) {
            throw ProfileError.invalid("国内分流时，VPN DNS 不能位于国内直连网段。")
        }
    }
    public static func validateToken(_ token: String) throws {
        guard token.utf8.count == 6, token.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
            throw ProfileError.invalid("动态令牌必须是 6 位数字。")
        }
    }
}