// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
public struct BoundedDiagnostics {
 public static let maximumLines=120,maximumBytes=32*1024,maximumLineBytes=1024
 private var entries:[String]=[]
 public private(set) var byteCount=0
 public var count:Int {entries.count}
 public var snapshot:String {entries.joined(separator:"\n")}
 public init() {}
 public mutating func append(_ message:String) {
  let line=Self.limitLine(message)
  byteCount += line.utf8.count + (entries.isEmpty ? 0:1);entries.append(line)
  while entries.count > Self.maximumLines || byteCount > Self.maximumBytes {
   let removed=entries.removeFirst();byteCount -= removed.utf8.count + (entries.isEmpty ? 0:1)
  }
 }
 private static func limitLine(_ text:String)->String {
  let line=text.replacingOccurrences(of:"\r",with:" ").replacingOccurrences(of:"\n",with:" ")
  guard line.utf8.count > maximumLineBytes else{return line}
  var bytes=Array(line.utf8.prefix(maximumLineBytes-3))
  while let _=bytes.last {if let valid=String(bytes:bytes,encoding:.utf8){return valid+"…"};bytes.removeLast()}
  return "…"
 }
 public static func boundedSnapshot(_ text:String)->String {
  var buffer=BoundedDiagnostics()
  for line in text.split(separator:"\n",omittingEmptySubsequences:false).suffix(maximumLines){buffer.append(String(line))}
  return buffer.snapshot
 }
}
