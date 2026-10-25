import XCTest
@testable import FortiCore
final class HillstoneTests:XCTestCase {
 func profile()->HillstoneSettings {var p=HillstoneSettings();p.gateway="203.0.113.40";p.username="synthetic-user";p.password="synthetic-password";return p}
 func testProfileCanSaveBeforeFirstTrust() throws {let p=profile();try p.validate();let data=try JSONEncoder().encode(p);XCTAssertEqual(try JSONDecoder().decode(HillstoneSettings.self,from:data),p)}
 func testMalformedStoredTrustRejected(){var p=profile();p.certificatePin=String(repeating:"g",count:64);XCTAssertThrowsError(try p.validate())}
 func testDNSSubtractedFromPrivateAndChinaBypass() throws {let p=profile();let dns=IPv4CIDR.address("10.2.3.4")!;let ranges=try p.exclusions(dns:"10.2.3.4",china:[IPv4CIDR("10.0.0.0/8")]);XCTAssertFalse(ranges.contains{$0.contains(dns)});XCTAssertTrue(ranges.contains{$0.contains(IPv4CIDR.address("10.2.3.5")!)})}
 func testGatewayCannotAlsoBeTunnelDNS(){let p=profile();XCTAssertThrowsError(try p.exclusions(dns:p.gateway,china:[]))}
 func testTunnelPacketUsesIPHeaderAndValidatesLength() {
  var v4=Data(repeating:0,count:20);v4[0]=0x45;v4[3]=20
  XCTAssertEqual(TunnelPacket.decode(v4)?.version,4)
  XCTAssertEqual(TunnelPacket.decode(v4)?.payload,v4)
  let wrapped=Data([0,0,0,2])+v4
  XCTAssertEqual(TunnelPacket.decode(wrapped)?.payload,v4)
  XCTAssertEqual(TunnelPacket.decode(wrapped)?.hadFamilyPrefix,true)
  v4[3]=21;XCTAssertNil(TunnelPacket.decode(v4))
  XCTAssertNil(TunnelPacket.decode(Data([0x45])))
  XCTAssertNil(TunnelPacket.decode(Data([0,0,0,30])+Data([0x45])+Data(repeating:0,count:19)))
  var v6=Data(repeating:0,count:48);v6[0]=0x60;v6[5]=8
  XCTAssertEqual(TunnelPacket.decode(v6)?.version,6)
  XCTAssertEqual(TunnelPacket.decode(Data([0,0,0,30])+v6)?.payload,v6)
  v6[5]=9;XCTAssertNil(TunnelPacket.decode(v6))
 }
}
