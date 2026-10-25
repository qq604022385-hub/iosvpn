import XCTest
@testable import FortiCore
final class DiagnosticsTests:XCTestCase {
 func testLongSessionRetainsRecentRecordsWithinBothLimits() {
  var log=BoundedDiagnostics()
  for i in 0..<100_000 {log.append("record \(i) "+String(repeating:"x",count:400))}
  XCTAssertLessThanOrEqual(log.count,BoundedDiagnostics.maximumLines)
  XCTAssertLessThanOrEqual(log.byteCount,BoundedDiagnostics.maximumBytes)
  XCTAssertEqual(log.snapshot.utf8.count,log.byteCount)
  XCTAssertTrue(log.snapshot.contains("record 99999 "))
  XCTAssertFalse(log.snapshot.contains("record 0 "))
 }
 func testHugeUnicodeLineAndLegacySnapshotAreBounded() {
  var log=BoundedDiagnostics();log.append(String(repeating:"蜂窝网络🙂",count:10_000))
  XCTAssertLessThanOrEqual(log.snapshot.utf8.count,BoundedDiagnostics.maximumLineBytes)
  XCTAssertFalse(log.snapshot.contains("�"));XCTAssertTrue(log.snapshot.hasSuffix("…"))
  let legacy=(0..<2000).map{"line \($0)"}.joined(separator:"\n")
  let bounded=BoundedDiagnostics.boundedSnapshot(legacy)
  XCTAssertEqual(bounded.split(separator:"\n").count,120)
  XCTAssertTrue(bounded.hasSuffix("line 1999"))
  log.append("first\nsecond\rthird");XCTAssertTrue(log.snapshot.hasSuffix("first second third"))
 }
 func testPacketBatchCapsCountAndBytesWithoutLosingReturnedPackets() {
  var batch=PacketBatch();let packet=Data(repeating:7,count:1280)
  for _ in 0..<64 {XCTAssertTrue(batch.append(packet))}
  XCTAssertFalse(batch.append(packet));XCTAssertEqual(batch.byteCount,64*1280)
  let first=batch.takePackets();XCTAssertEqual(first.count,64);XCTAssertEqual(first.first,packet)
  XCTAssertEqual(batch.count,0);XCTAssertEqual(batch.byteCount,0)
  let big=Data(repeating:8,count:65535)
  for _ in 0..<4 {XCTAssertTrue(batch.append(big))}
  XCTAssertFalse(batch.append(big));XCTAssertLessThanOrEqual(batch.byteCount,PacketBatch.maximumBytes)
  XCTAssertEqual(batch.takePackets().count,4)
  XCTAssertFalse(batch.append(Data()));XCTAssertFalse(batch.append(Data(count:PacketBatch.maximumBytes+1)))
 }
}
