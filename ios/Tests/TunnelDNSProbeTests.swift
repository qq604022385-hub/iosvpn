import XCTest
@testable import FortiCore

final class TunnelDNSProbeTests: XCTestCase {
    func testProbeRequiresMatchingEncryptedReturnTraffic() throws {
        let request=try XCTUnwrap(DNSProbeMessage.packet(source:"10.0.0.2",resolver:"1.1.1.1",id:0x1234,port:54321))
        var reply=request
        reply.replaceSubrange(12..<16,with:request[16..<20])
        reply.replaceSubrange(16..<20,with:request[12..<16])
        reply[20]=0;reply[21]=53;reply[22]=request[20];reply[23]=request[21]
        reply[30]=0x81;reply[31]=0x80;reply[35]=1
        reply.append(contentsOf:[0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,93,184,216,34])
        reply[3]=UInt8(reply.count);reply[25]=UInt8(reply.count-20)
        XCTAssertTrue(DNSProbeMessage.matchesPacket(reply,request:request))
        reply[29] ^= 1;XCTAssertFalse(DNSProbeMessage.matchesPacket(reply,request:request));reply[29] ^= 1
        reply[12]=8;XCTAssertFalse(DNSProbeMessage.matchesPacket(reply,request:request));reply[12]=1
        reply[30] |= 2;XCTAssertFalse(DNSProbeMessage.matchesPacket(reply,request:request))
        XCTAssertFalse(DNSProbeMessage.matchesPacket(request,request:request))
    }
    func testProbeIPv4HeaderChecksumAndLengths() throws {
        let p=[UInt8](try XCTUnwrap(DNSProbeMessage.packet(source:"10.0.0.2",resolver:"1.1.1.1",id:1,port:54321)))
        var sum:UInt32=0
        for i in stride(from:0,to:20,by:2) { sum += UInt32(p[i]) << 8 | UInt32(p[i+1]) }
        while sum>65535 { sum=(sum & 65535)+(sum >> 16) }
        XCTAssertEqual(sum,65535);XCTAssertEqual(Int(p[3]),p.count);XCTAssertEqual(Int(p[25]),p.count-20)
        XCTAssertNil(DNSProbeMessage.packet(source:"bad",resolver:"1.1.1.1",id:1,port:54321))
    }
}
