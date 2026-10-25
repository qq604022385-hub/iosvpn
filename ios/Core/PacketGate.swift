// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
// Buffer IPv4 fragments before applying DNS policy, then pass the original
// fragments to libipsec. This preserves large UDP traffic and avoids trusting
// the port bytes of a non-initial fragment.
public final class PacketGate {
    private struct Part { let offset: Int; let payload: Data; let original: Data }
    private struct Datagram {
        var parts: [Part] = []
        var firstHeader: Data?
        var end: Int?
        var updated: TimeInterval
    }
    private var pending: [Data: Datagram] = [:]
    public init() {}
    public func ingest(_ packet: Data, dns: String, now: TimeInterval = Date().timeIntervalSince1970) -> [Data] {
        pending = pending.filter { now - $0.value.updated <= 15 }
        let bytes = [UInt8](packet)
        guard bytes.count >= 20, bytes[0] >> 4 == 4 else { return [] }
        let headerLength = Int(bytes[0] & 15) * 4
        let length = Int(bytes[2]) << 8 | Int(bytes[3])
        guard headerLength >= 20, headerLength <= bytes.count, length == bytes.count else { return [] }
        let flags = Int(bytes[6]) << 8 | Int(bytes[7])
        if flags & 0x3fff == 0 { return PacketPolicy.allow(packet, dns: dns) ? [packet] : [] }
        let offset = (flags & 0x1fff) * 8
        let more = flags & 0x2000 != 0
        let payload = packet.subdata(in: headerLength..<packet.count)
        guard !payload.isEmpty, offset + payload.count <= 65515,
              (!more || payload.count % 8 == 0), flags & 0x4000 == 0 else { return [] }
        let key = Data([bytes[4], bytes[5], bytes[9]] + Array(bytes[12..<20]))
        if pending[key] == nil && pending.count >= 32 {
            if let oldest = pending.min(by: { $0.value.updated < $1.value.updated })?.key { pending.removeValue(forKey: oldest) }
        }
        var datagram = pending[key] ?? Datagram(updated: now)
        let end = offset + payload.count
        if let limit = datagram.end, end > limit { pending.removeValue(forKey: key); return [] }
        for part in datagram.parts {
            if offset < part.offset + part.payload.count && part.offset < end {
                if offset == part.offset && payload == part.payload { return [] } // Exact duplicate.
                pending.removeValue(forKey: key); return [] // Overlaps are rejected.
            }
        }
        guard datagram.parts.count < 256 else { pending.removeValue(forKey: key); return [] }
        if !more {
            if let limit = datagram.end, limit != end { pending.removeValue(forKey: key); return [] }
            if datagram.parts.contains(where: { $0.offset + $0.payload.count > end }) { pending.removeValue(forKey: key); return [] }
            datagram.end = end
        }
        if offset == 0 { datagram.firstHeader = packet.prefix(headerLength) }
        datagram.parts.append(Part(offset: offset, payload: payload, original: packet)); datagram.updated = now
        pending[key] = datagram
        guard let header = datagram.firstHeader, let expectedEnd = datagram.end,
              header.count + expectedEnd <= 65535 else { return [] }
        var cursor = 0; var assembled = header
        for part in datagram.parts.sorted(by: { $0.offset < $1.offset }) {
            guard part.offset == cursor else { return [] }
            assembled.append(part.payload); cursor += part.payload.count
        }
        guard cursor == expectedEnd else { return [] }
        pending.removeValue(forKey: key)
        assembled[2] = UInt8(assembled.count >> 8); assembled[3] = UInt8(assembled.count & 255)
        assembled[6] = 0; assembled[7] = 0
        return PacketPolicy.allow(assembled, dns: dns) ? datagram.parts.map(\.original) : []
    }
}