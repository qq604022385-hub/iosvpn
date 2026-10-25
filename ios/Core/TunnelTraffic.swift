// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation

public enum TunnelDefaults {
    // Leave extra headroom for ESP/NAT-T on paths with a smaller physical MTU.
    public static let mtu = 1280
}

// Counts only headers, never domain names, URLs or application payloads.
// "Forwarded" means accepted by the native input queue, not received by the peer.
public struct TunnelTraffic {
    public var capturedIPv4: UInt64 = 0
    public var gateHeld: UInt64 = 0
    public var queueFailures: UInt64 = 0
    public var ipv6Dropped: UInt64 = 0
    public var osWriteFailures: UInt64 = 0
    public private(set) var forwarded: UInt64 = 0
    public private(set) var forwardedBytes: UInt64 = 0
    public private(set) var decrypted: UInt64 = 0
    public private(set) var decryptedBytes: UInt64 = 0
    public private(set) var dnsRequests: UInt64 = 0
    public private(set) var dnsReplies: UInt64 = 0
    public private(set) var tcpSYN: UInt64 = 0
    public private(set) var tcpSYNACK: UInt64 = 0
    public private(set) var sourceMismatch: UInt64 = 0
    public init() {}
    public mutating func recordForwarded(_ packet: Data, dns: String, vip: String) {
        forwarded += 1; forwardedBytes += UInt64(packet.count)
        guard let header = Header(packet) else { return }
        if header.source != IPv4CIDR.address(vip) { sourceMismatch += 1 }
        if header.proto == 17, header.destination == IPv4CIDR.address(dns), header.destinationPort == 53 {
            dnsRequests += 1
        }
        if header.proto == 6, header.flags & 0x12 == 0x02 { tcpSYN += 1 }
    }
    public mutating func recordDecrypted(_ packet: Data, dns: String) {
        decrypted += 1; decryptedBytes += UInt64(packet.count)
        guard let header = Header(packet) else { return }
        if header.proto == 17, header.source == IPv4CIDR.address(dns), header.sourcePort == 53 {
            dnsReplies += 1
        }
        if header.proto == 6, header.flags & 0x12 == 0x12 { tcpSYNACK += 1 }
    }
    public var summary: String {
        "数据统计（累计，仅隧道内）：系统 IPv4 \(capturedIPv4)；引擎入队 \(forwarded)/\(forwardedBytes)B；解密回包 \(decrypted)/\(decryptedBytes)B；入队失败 \(queueFailures)；写回系统失败 \(osWriteFailures)；过滤/重组等待 \(gateHeld)；IPv6 丢弃 \(ipv6Dropped)。\n" +
        "UDP DNS 包：请求 \(dnsRequests)/响应 \(dnsReplies)；TCP 握手包：SYN \(tcpSYN)/SYN-ACK \(tcpSYNACK)；源地址不匹配 \(sourceMismatch)。"
    }
    private struct Header {
        let source: UInt32, destination: UInt32
        let proto: UInt8
        let sourcePort: UInt16, destinationPort: UInt16
        let flags: UInt8
        init?(_ packet: Data) {
            let b = [UInt8](packet)
            guard b.count >= 20, b[0] >> 4 == 4 else { return nil }
            let ihl = Int(b[0] & 15) * 4
            guard ihl >= 20, ihl <= b.count, (Int(b[2]) << 8 | Int(b[3])) == b.count else { return nil }
            source = UInt32(b[12]) << 24 | UInt32(b[13]) << 16 | UInt32(b[14]) << 8 | UInt32(b[15])
            destination = UInt32(b[16]) << 24 | UInt32(b[17]) << 16 | UInt32(b[18]) << 8 | UInt32(b[19])
            proto = b[9]
            // Non-initial fragment bytes are not a transport header.
            let nonInitial = (UInt16(b[6]) << 8 | UInt16(b[7])) & 0x1fff != 0
            if !nonInitial, proto == 17, b.count >= ihl + 8 {
                sourcePort = UInt16(b[ihl]) << 8 | UInt16(b[ihl + 1])
                destinationPort = UInt16(b[ihl + 2]) << 8 | UInt16(b[ihl + 3]); flags = 0
            } else if !nonInitial, proto == 6, b.count >= ihl + 20,
                      Int(b[ihl + 12] >> 4) * 4 >= 20, Int(b[ihl + 12] >> 4) * 4 <= b.count - ihl {
                sourcePort = UInt16(b[ihl]) << 8 | UInt16(b[ihl + 1])
                destinationPort = UInt16(b[ihl + 2]) << 8 | UInt16(b[ihl + 3]); flags = b[ihl + 13]
            } else { sourcePort = 0; destinationPort = 0; flags = 0 }
        }
    }
}
