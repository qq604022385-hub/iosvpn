// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
public struct PacketBatch {
 public static let maximumPackets=64,maximumBytes=256*1024
 private var packets:[Data]=[]
 public private(set) var byteCount=0
 public var count:Int {packets.count}
 public var isEmpty:Bool {packets.isEmpty}
 public init() {}
 public mutating func append(_ packet:Data)->Bool {
  guard !packet.isEmpty,packets.count < Self.maximumPackets,packet.count <= Self.maximumBytes-byteCount else{return false}
  packets.append(packet);byteCount += packet.count;return true
 }
 public mutating func takePackets()->[Data] {let result=packets;packets=[];byteCount=0;return result}
}
