// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
// Validate the IP header rather than dropping packets on a family metadata mismatch.
public struct TunnelPacket {
 public let payload: Data
 public let version: Int
 public let hadFamilyPrefix: Bool
 public static func decode(_ input: Data) -> TunnelPacket? {
  return input.withUnsafeBytes { raw -> TunnelPacket? in
  let bytes = raw.bindMemory(to:UInt8.self)
  var offset = 0
  if bytes.count >= 5, bytes[0] == 0, bytes[1] == 0, bytes[2] == 0,
     (bytes[3] == 2 || bytes[3] == 30),
     bytes[4] >> 4 == (bytes[3] == 2 ? 4 : 6) { offset = 4 }
  guard bytes.count > offset else { return nil }
  let version = Int(bytes[offset] >> 4), count = bytes.count - offset
  let length: Int
  if version == 4 {
   guard count >= 20 else { return nil }
   let header = Int(bytes[offset] & 15) * 4
   length = Int(bytes[offset+2]) << 8 | Int(bytes[offset+3])
   guard header >= 20, length >= header else { return nil }
  } else if version == 6 {
   guard count >= 40 else { return nil }
   length = 40 + (Int(bytes[offset+4]) << 8 | Int(bytes[offset+5]))
  } else { return nil }
  guard length == count else { return nil }
  return TunnelPacket(payload: offset == 0 ? input : input.subdata(in: offset..<input.count), version: version, hadFamilyPrefix: offset != 0)
  }
 }
}
