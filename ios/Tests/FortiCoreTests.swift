import XCTest
@testable import FortiCore
final class FortiCoreTests: XCTestCase {
    func profile() -> SiteSettings { var s = SiteSettings(); s.username = "tester"; s.password = "test-password"; s.psk = "test-psk"; return s }
    func testStrictIPv4() {
        XCTAssertEqual(IPv4CIDR.address("115.31.179.179"), 0x731fb3b3)
        for invalid in ["01.2.3.4", "256.0.0.1", "1.2.3", "1.2.3.4 ", "::1", "1.2.3.-1", "1..3.4"] {
            XCTAssertNil(IPv4CIDR.address(invalid))
        }
    }
    func testCIDRBoundaries() throws {
        let c = try IPv4CIDR("1.2.3.0/24")
        XCTAssertTrue(c.contains(IPv4CIDR.address("1.2.3.255")!)); XCTAssertFalse(c.contains(IPv4CIDR.address("1.2.4.0")!))
        XCTAssertEqual(c.maskString, "255.255.255.0")
        XCTAssertThrowsError(try IPv4CIDR("1.2.3.1/24"))
        XCTAssertTrue(try IPv4CIDR("0.0.0.0/0").contains(UInt32.max))
        XCTAssertEqual(try IPv4CIDR("1.2.3.4/32").mask, UInt32.max)
    }
    func testNonPublicDNSRejected() {
        for dns in ["127.0.0.1", "192.168.1.1", "10.1.2.3", "100.64.0.1", "169.254.1.1", "224.1.1.1", "255.255.255.255"] {
            var s = profile(); s.dns = dns; XCTAssertThrowsError(try s.validate(china: []))
        }
    }
    func testChinaDNSRejectedOnlyInSplitMode() throws {
        let china = [try IPv4CIDR("1.2.3.0/24")]; var s = profile(); s.dns = "1.2.3.4"
        XCTAssertThrowsError(try s.validate(china: china)); s.splitChina = false
        XCTAssertNoThrow(try s.validate(china: china))
    }
    func testTokenASCIIOnly() {
        XCTAssertNoThrow(try SiteSettings.validateToken("012345"))
        for token in ["", "12345", "1234567", "１２３４５６", "12345a", "123456\n"] {
            XCTAssertThrowsError(try SiteSettings.validateToken(token))
        }
    }
    func testCredentialsAreRequired() {
        XCTAssertThrowsError(try SiteSettings().validate(china: []))
        var s = profile(); s.password = ""; XCTAssertThrowsError(try s.validate(china: []))
        s = profile(); s.psk = String(repeating: "x", count: 513); XCTAssertThrowsError(try s.validate(china: []))
        s = profile(); s.localID = "a\0b"; XCTAssertThrowsError(try s.validate(china: []))
    }
    func testSplitAndGlobalRoutes() throws {
        let china = [try IPv4CIDR("1.2.3.0/24")]; var s = profile()
        let split = try RoutePlan.excluded(settings: s, china: china)
        XCTAssertTrue(split.contains(china[0]))
        XCTAssertTrue(split.contains(try IPv4CIDR(s.gateway + "/32")))
        s.splitChina = false
        let global = try RoutePlan.excluded(settings: s, china: china)
        XCTAssertFalse(global.contains(china[0])); XCTAssertEqual(global.count, RoutePlan.localRanges.count + 1)
    }
    func testBundledChinaSnapshot() throws {
        let ranges = try RoutePlan.chinaRanges(); XCTAssertEqual(ranges.count, 5495)
        XCTAssertFalse(ranges.contains { $0.contains(IPv4CIDR.address("1.1.1.1")!) })
        XCTAssertThrowsError(try RoutePlan.parseChina("# comment\n"))
        XCTAssertThrowsError(try RoutePlan.parseChina("0.0.0.0/0"))
    }
    func udp(destination: String, port: UInt16) -> Data {
        let ip = IPv4CIDR.address(destination)!; var b = [UInt8](repeating: 0, count: 28)
        b[0] = 0x45; b[3] = 28; b[9] = 17
        b[16] = UInt8((ip >> 24) & 255); b[17] = UInt8((ip >> 16) & 255)
        b[18] = UInt8((ip >> 8) & 255); b[19] = UInt8(ip & 255)
        b[22] = UInt8(port >> 8); b[23] = UInt8(port & 255)
        return Data(b)
    }
    func testCapturedDNSOnlyUsesConfiguredServer() {
        XCTAssertTrue(PacketPolicy.allow(udp(destination: "1.1.1.1", port: 53), dns: "1.1.1.1"))
        XCTAssertFalse(PacketPolicy.allow(udp(destination: "8.8.8.8", port: 53), dns: "1.1.1.1"))
        XCTAssertTrue(PacketPolicy.allow(udp(destination: "8.8.8.8", port: 443), dns: "1.1.1.1"))
    }
    func testMalformedIPv6AndFragmentsDropped() {
        XCTAssertFalse(PacketPolicy.allow(Data([0x60] + [UInt8](repeating: 0, count: 39)), dns: "1.1.1.1"))
        XCTAssertFalse(PacketPolicy.allow(Data([0x45]), dns: "1.1.1.1"))
        var packet = udp(destination: "1.1.1.1", port: 53); packet[6] = 0x20
        XCTAssertFalse(PacketPolicy.allow(packet, dns: "1.1.1.1"))
        packet = udp(destination: "1.1.1.1", port: 53); packet[3] = 29
        XCTAssertFalse(PacketPolicy.allow(packet, dns: "1.1.1.1"))
    }
    func testFragmentGateReordersAndFiltersDNSBeforeForwarding() {
        func fragments(destination: String, port: UInt16) -> [Data] {
            var complete = udp(destination: destination, port: port)
            complete.append(Data(repeating: 0x61, count: 16)); complete[3] = 44
            var first = complete.prefix(20); first[3] = 36; first[6] = 0x20
            first.append(complete.subdata(in: 20..<36))
            var last = complete.prefix(20); last[3] = 28; last[7] = 2
            last.append(complete.subdata(in: 36..<44))
            return [first, last]
        }
        let dns = fragments(destination: "1.1.1.1", port: 53), gate = PacketGate()
        XCTAssertTrue(gate.ingest(dns[1], dns: "1.1.1.1", now: 1).isEmpty)
        XCTAssertEqual(gate.ingest(dns[0], dns: "1.1.1.1", now: 2).count, 2)
        let blocked = fragments(destination: "8.8.8.8", port: 53)
        XCTAssertTrue(gate.ingest(blocked[0], dns: "1.1.1.1", now: 3).isEmpty)
        XCTAssertTrue(gate.ingest(blocked[1], dns: "1.1.1.1", now: 4).isEmpty)
        let traffic = fragments(destination: "8.8.8.8", port: 443)
        XCTAssertTrue(gate.ingest(traffic[0], dns: "1.1.1.1", now: 5).isEmpty)
        let output = gate.ingest(traffic[1], dns: "1.1.1.1", now: 6)
        XCTAssertEqual(output, traffic)
        XCTAssertTrue(gate.ingest(traffic[0], dns: "1.1.1.1", now: 7).isEmpty)
        XCTAssertTrue(gate.ingest(traffic[1], dns: "1.1.1.1", now: 30).isEmpty) // Expired first part.
    }}
