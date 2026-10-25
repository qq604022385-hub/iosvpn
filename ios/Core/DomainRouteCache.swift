// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation

// Learn only A answers belonging to the requested name's CNAME chain. Unrelated
// additional records must never create bypass routes. No browsing names persist.
public enum DNSRouteAnswer {
    public struct Address: Equatable {
        public let ip: UInt32
        public let ttl: UInt32
    }
    public static func addresses(in packet: Data) -> [Address] {
        let p = [UInt8](packet)
        guard p.count >= 40, p[0] >> 4 == 4, p[9] == 17 else { return [] }
        let ihl = Int(p[0] & 15) * 4
        guard ihl >= 20, ihl + 20 <= p.count, Int(p[2]) << 8 | Int(p[3]) == p.count,
              p[6] & 0x3f == 0, p[7] == 0, p[ihl] == 0, p[ihl+1] == 53,
              Int(p[ihl+4]) << 8 | Int(p[ihl+5]) == p.count - ihl else { return [] }
        let b = Array(p[(ihl+8)...])
        func word(_ i: Int) -> Int { Int(b[i]) << 8 | Int(b[i+1]) }
        guard b[2] & 0xfa == 0x80, b[3] & 15 == 0, word(4) == 1,
              word(6) <= 128 else { return [] }
        func name(_ start: Int) -> (String, Int)? {
            var cursor = start, end: Int?, labels: [String] = [], visited = Set<Int>()
            var size = 0
            while cursor < b.count, visited.insert(cursor).inserted {
                let length = Int(b[cursor])
                if length == 0 { return (labels.joined(separator: "."), end ?? cursor+1) }
                if length & 0xc0 == 0xc0 {
                    guard cursor+1 < b.count else { return nil }
                    let target = (length & 63) << 8 | Int(b[cursor+1])
                    guard target >= 12, target < cursor else { return nil }
                    if end == nil { end = cursor+2 }; cursor = target; continue
                }
                guard length <= 63, cursor+1+length <= b.count else { return nil }
                let label = b[(cursor+1)..<(cursor+1+length)]
                guard label.allSatisfy({ (33...126).contains($0) }) else { return nil }
                size += length+1; guard size <= 254 else { return nil }
                labels.append(String(bytes: label, encoding: .ascii)!.lowercased())
                cursor += length+1
            }
            return nil
        }
        guard let (question, questionEnd) = name(12), questionEnd+4 <= b.count,
              word(questionEnd) == 1, word(questionEnd+2) == 1 else { return [] }
        var cursor = questionEnd+4
        var aliases: [String: (String, UInt32)] = [:]
        var answers: [(String, UInt32, UInt32)] = []
        for _ in 0..<word(6) {
            guard let (owner, end) = name(cursor), end+10 <= b.count else { return [] }
            let kind = word(end), klass = word(end+2), length = word(end+8), value = end+10
            guard value+length <= b.count else { return [] }
            let ttl = UInt32(b[end+4]) << 24 | UInt32(b[end+5]) << 16 | UInt32(b[end+6]) << 8 | UInt32(b[end+7])
            if klass == 1, kind == 5 {
                guard let (target, targetEnd) = name(value), targetEnd == value+length,
                      aliases[owner] == nil else { return [] }
                aliases[owner] = (target, ttl)
            } else if klass == 1, kind == 1, length == 4 {
                let ip = UInt32(b[value]) << 24 | UInt32(b[value+1]) << 16 | UInt32(b[value+2]) << 8 | UInt32(b[value+3])
                answers.append((owner, ip, ttl))
            }
            cursor = value+length
        }
        var chain = [question: UInt32.max], current = question, lifetime = UInt32.max
        for _ in 0..<16 {
            guard let (next, ttl) = aliases[current] else { break }
            guard chain[next] == nil else { return [] }
            lifetime = min(lifetime, ttl); chain[next] = lifetime; current = next
        }
        return answers.compactMap { owner, ip, ttl in
            guard let aliasTTL = chain[owner] else { return nil }
            return Address(ip: ip, ttl: min(ttl, aliasTTL))
        }
    }
}

public struct DomainRouteCache {
    public static let capacity = 512
    private var entries = Set<UInt32>()
    public init() {}
    public mutating func learn(_ answers: [DNSRouteAnswer.Address], excluding base: [IPv4CIDR],
                               protected: Set<UInt32>) {
        for answer in answers {
            guard IPv4CIDR.isPublic(answer.ip), !protected.contains(answer.ip),
                  !base.contains(where: { $0.contains(answer.ip) }),
                  entries.contains(answer.ip) || entries.count < Self.capacity else { continue }
            // Excluded flows are invisible to the extension. Keep a bounded set
            // until disconnect so TTL expiry cannot reroute an active TCP flow
            // with a physical source address into the IPsec selector for the VIP.
            entries.insert(answer.ip)
        }
    }
    public var addresses: [UInt32] { entries.sorted() }
}
