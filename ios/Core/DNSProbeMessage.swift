// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation

public enum DNSProbeMessage {
    public static func packet(source: String, resolver: String, id: UInt16, port: UInt16) -> Data? {
        guard let src=IPv4CIDR.address(source),let dst=IPv4CIDR.address(resolver) else { return nil }
        let message=query(id:id);var b=[UInt8](repeating:0,count:28)
        b[0]=0x45;b[8]=64;b[9]=17
        for (offset,ip) in [(12,src),(16,dst)] {
            for i in 0..<4 { b[offset+i]=UInt8((ip >> (24-i*8)) & 255) }
        }
        b += message
        b[2]=UInt8(b.count >> 8);b[3]=UInt8(b.count & 255)
        b[20]=UInt8(port >> 8);b[21]=UInt8(port & 255);b[23]=53
        b[24]=UInt8((b.count-20) >> 8);b[25]=UInt8((b.count-20) & 255)
        var sum:UInt32=0
        for i in stride(from:0,to:20,by:2) { sum += UInt32(b[i]) << 8 | UInt32(b[i+1]) }
        while sum > 65535 { sum=(sum & 65535)+(sum >> 16) }
        let checksum=UInt16(truncatingIfNeeded:~sum);b[10]=UInt8(checksum >> 8);b[11]=UInt8(checksum & 255)
        return Data(b)
    }
    public static func matchesPacket(_ packet: Data, request: Data) -> Bool {
        let b=[UInt8](packet),q=[UInt8](request)
        guard b.count>=40,q.count>=40,b[0] >> 4 == 4,b[9]==17 else { return false }
        let ihl=Int(b[0] & 15)*4
        guard ihl>=20,ihl+20<=b.count,Int(b[2]) << 8 | Int(b[3]) == b.count,
              b[6] & 0x3f == 0,b[7]==0,
              b[12..<16].elementsEqual(q[16..<20]),b[16..<20].elementsEqual(q[12..<16]),
              b[ihl]==0,b[ihl+1]==53,b[ihl+2]==q[20],b[ihl+3]==q[21],
              Int(b[ihl+4]) << 8 | Int(b[ihl+5]) == b.count-ihl else { return false }
        let dns=Array(b[(ihl+8)...]),question=Array(q[28...])
        return dns.count>=question.count && dns[0]==question[0] && dns[1]==question[1]
            && dns[2] & 0xfa == 0x80 && dns[3] & 15 == 0 && dns[4]==0 && dns[5]==1
            && (dns[6] != 0 || dns[7] != 0) && dns[12..<question.count].elementsEqual(question[12...])
    }
    // Fixed diagnostic name, unrelated to the user's browsing activity.
    public static func query(id: UInt16) -> Data {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in ["example", "com"] {
            bytes.append(UInt8(label.utf8.count)); bytes.append(contentsOf: label.utf8)
        }
        bytes.append(contentsOf: [0, 0, 1, 0, 1])
        return Data(bytes)
    }
    public static func describeReply(_ data: Data, id: UInt16) -> String? {
        let b = [UInt8](data)
        guard b.count >= 12, (UInt16(b[0]) << 8 | UInt16(b[1])) == id,
              b[2] & 0x80 != 0, b[2] & 0x78 == 0 else { return nil }
        let code = b[3] & 15
        if b[2] & 2 != 0 { return "已收到 UDP 回复，但被截断，需使用 TCP DNS。" }
        let answers = Int(b[6]) << 8 | Int(b[7])
        if code != 0 { return "已收到 UDP 回复，但 DNS 返回错误码 \(code)。" }
        return answers > 0 ? "UDP DNS 已回复（返回码 0，答案计数 \(answers)）。" : "UDP DNS 已回复，但没有答案。"
    }
}
