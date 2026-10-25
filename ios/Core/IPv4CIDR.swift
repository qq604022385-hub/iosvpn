// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
public struct IPv4CIDR: Equatable {
    public let network: UInt32
    public let prefix: Int
    public var mask: UInt32 { prefix == 0 ? 0 : UInt32.max << (32 - prefix) }
    public var addressString: String { Self.string(network) }
    public var maskString: String { Self.string(mask) }
    public init(_ text: String) throws {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2, let ip = Self.address(String(parts[0])),
              let p = Int(parts[1]), (0...32).contains(p) else { throw ProfileError.invalid("非法 IPv4 网段。") }
        network = ip; prefix = p
        guard ip & mask == ip else { throw ProfileError.invalid("IPv4 网段未对齐。") }
    }
    public func contains(_ address: UInt32) -> Bool { address & mask == network }
    public static func address(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for part in parts {
            guard !part.isEmpty, part.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
                  let n = UInt32(part), n <= 255, String(n) == part else { return nil }
            result = (result << 8) | n
        }
        return result
    }
    public static func string(_ ip: UInt32) -> String {
        [24,16,8,0].map { String((ip >> $0) & 255) }.joined(separator: ".")
    }
    public static func isPublic(_ ip: UInt32) -> Bool {
        !nonPublic.contains(where: { $0.contains(ip) })
    }
    private static let nonPublic = ["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
        "169.254.0.0/16","172.16.0.0/12","192.168.0.0/16","198.18.0.0/15","224.0.0.0/4","240.0.0.0/4"].map { try! IPv4CIDR($0) }
}
public enum RoutePlan {
    public static let localRanges = ["0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
        "169.254.0.0/16","172.16.0.0/12","192.168.0.0/16","224.0.0.0/4","240.0.0.0/4"]
    public static func chinaRanges() throws -> [IPv4CIDR] {
        guard let url = Bundle.module.url(forResource: "cn-ipv4", withExtension: "txt") else {
            throw ProfileError.invalid("缺少国内分流规则。")
        }
        return try parseChina(String(contentsOf: url, encoding: .utf8))
    }
    public static func parseChina(_ text: String) throws -> [IPv4CIDR] {
        let lines = text.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") }
        guard !lines.isEmpty else { throw ProfileError.invalid("国内分流规则为空。") }
        return try lines.map { text in
            let cidr = try IPv4CIDR(text)
            guard cidr.prefix >= 4 else { throw ProfileError.invalid("国内分流规则范围过大。") }
            return cidr
        }
    }
    public static func excluded(settings: SiteSettings, china: [IPv4CIDR]) throws -> [IPv4CIDR] {
        try settings.validate(china: china)
        return try excluded(gateway: settings.gateway, dns: settings.dns, splitChina: settings.splitChina, china: china)
    }
    public static func excluded(gateway: String, dns: String, splitChina: Bool, china: [IPv4CIDR]) throws -> [IPv4CIDR] {
        guard let resolver = IPv4CIDR.address(dns), IPv4CIDR.address(gateway) != nil, dns != gateway else {
            throw ProfileError.invalid("VPN DNS 无效或与网关地址冲突。")
        }
        var result = try localRanges.map { try IPv4CIDR($0) }
        result.append(try IPv4CIDR(gateway + "/32"))
        if splitChina { result.append(contentsOf: china) }
        // A DNS /32 must never also be covered by an excluded route: excluded
        // routes take precedence on iOS, including private gateway resolvers.
        var filtered: [IPv4CIDR] = []
        for range in result {
            if !range.contains(resolver) { filtered.append(range); continue }
            var node = range
            while node.prefix < 32 {
                let prefix = node.prefix+1, step = UInt32(1) << (32-prefix)
                let left = try IPv4CIDR(IPv4CIDR.string(node.network) + "/" + String(prefix))
                let right = try IPv4CIDR(IPv4CIDR.string(node.network+step) + "/" + String(prefix))
                if left.contains(resolver) { filtered.append(right); node = left }
                else { filtered.append(left); node = right }
            }
        }
        return filtered
    }
}
public enum PacketPolicy {
    // Applied only to packets delivered by NEPacketTunnelFlow. Excluded routes bypass this filter.
    public static func allow(_ packet: Data, dns: String) -> Bool {
        let b = [UInt8](packet)
        guard b.count >= 20, b[0] >> 4 == 4 else { return false } // Drop IPv6.
        let ihl = Int(b[0] & 15) * 4
        let total = Int(b[2]) << 8 | Int(b[3])
        guard ihl >= 20, ihl <= b.count, total == b.count else { return false }
        guard b[9] == 6 || b[9] == 17 else { return true }
        // Drop fragmented TCP/UDP, so DNS ports cannot bypass validation in later fragments.
        guard (UInt16(b[6]) << 8 | UInt16(b[7])) & 0x3fff == 0,
              b.count >= ihl + (b[9] == 6 ? 20 : 8) else { return false }
        let port = UInt16(b[ihl+2]) << 8 | UInt16(b[ihl+3])
        if port != 53 { return true }
        let destination = UInt32(b[16]) << 24 | UInt32(b[17]) << 16 | UInt32(b[18]) << 8 | UInt32(b[19])
        return destination == IPv4CIDR.address(dns)
    }
}
