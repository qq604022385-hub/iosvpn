import XCTest
@testable import FortiCore

final class DomainRouteTests: XCTestCase {
    func name(_ value: String) -> [UInt8] {
        value.split(separator: ".").flatMap { [UInt8($0.utf8.count)] + Array($0.utf8) } + [0]
    }
    func rr(_ owner: [UInt8], _ type: UInt8, _ ttl: UInt8, _ value: [UInt8]) -> [UInt8] {
        owner + [0,type,0,1,0,0,0,ttl,0,UInt8(value.count)] + value
    }
    func reply(_ records: [[UInt8]], question: String = "www.baidu.com") -> Data {
        let dns: [UInt8] = [1,2,0x81,0x80,0,1,0,UInt8(records.count),0,0,0,0]
            + name(question) + [0,1,0,1] + records.flatMap { $0 }
        var p = [UInt8](repeating:0,count:28); p[0]=0x45; p[9]=17; p[12]=1; p[15]=1; p[20]=0; p[21]=53
        p += dns; p[2]=UInt8(p.count >> 8); p[3]=UInt8(p.count & 255)
        p[24]=UInt8((p.count-20) >> 8); p[25]=UInt8((p.count-20) & 255)
        return Data(p)
    }
    func testOnlyRelatedAnswersLearnedWithCNAMEExpiry() {
        let p = reply([
            rr([0xc0,0x0c],5,20,name("cdn.example.net")),
            rr(name("unrelated.example"),1,60,[9,9,9,9]),
            rr(name("cdn.example.net"),1,60,[153,3,238,127])
        ])
        let answers=DNSRouteAnswer.addresses(in:p)
        XCTAssertEqual(answers.count,1); XCTAssertEqual(answers.first?.ip,IPv4CIDR.address("153.3.238.127"))
        XCTAssertEqual(answers.first?.ttl,20)
        var cache=DomainRouteCache();cache.learn(answers,excluding:[],protected:[])
        XCTAssertEqual(cache.addresses,[IPv4CIDR.address("153.3.238.127")!])
        cache=DomainRouteCache();XCTAssertTrue(cache.addresses.isEmpty)
    }
    func testMalformedAndCyclicAnswersDoNotCreateRoutes() {
        let cycle=reply([rr([0xc0,0x0c],5,60,[0xc0,0x0c])])
        XCTAssertTrue(DNSRouteAnswer.addresses(in:cycle).isEmpty)
        var p=reply([rr([0xc0,0x0c],1,60,[9,9,9,9])]);p.removeLast()
        XCTAssertTrue(DNSRouteAnswer.addresses(in:p).isEmpty)
        p=reply([rr([0xc0,0x0c],1,60,[9,9,9,9])]);p[30] |= 2
        XCTAssertTrue(DNSRouteAnswer.addresses(in:p).isEmpty)
        XCTAssertTrue(DNSRouteAnswer.addresses(in:reply([])).isEmpty)
    }
    func testProtectedPrivateAndExistingRoutesDoNotCreateBypasses() throws {
        let p=reply([[10,0,0,1],[1,1,1,1],[9,9,9,9],[153,3,238,127]].map { rr([0xc0,0x0c],1,60,$0) })
        var cache=DomainRouteCache()
        cache.learn(DNSRouteAnswer.addresses(in:p),excluding:[try IPv4CIDR("153.0.0.0/8")],
                    protected:[IPv4CIDR.address("1.1.1.1")!])
        XCTAssertEqual(cache.addresses,[IPv4CIDR.address("9.9.9.9")!])
    }
    func testCacheBoundAndRefreshPreserveLiveRoutes() {
        var cache=DomainRouteCache()
        for i in 0..<520 {
            let bytes:[UInt8]=[9,0,UInt8(i >> 8),UInt8(i & 255)]
            cache.learn(DNSRouteAnswer.addresses(in:reply([rr([0xc0,0x0c],1,60,bytes)])),excluding:[],protected:[])
        }
        XCTAssertEqual(cache.addresses.count,DomainRouteCache.capacity)
        let answers=DNSRouteAnswer.addresses(in:reply([rr([0xc0,0x0c],1,1,[9,0,0,0])]))
        cache.learn(answers,excluding:[],protected:[])
        XCTAssertEqual(cache.addresses.count,DomainRouteCache.capacity)
    }
    func testBothTransportsReserveDNSHostIncludingPrivateNetworks() throws {
        for dns in ["10.2.3.4","153.3.238.127"] {
            let ranges=try RoutePlan.excluded(gateway:"203.0.113.1",dns:dns,splitChina:true,china:[IPv4CIDR("153.0.0.0/8")])
            XCTAssertFalse(ranges.contains { $0.contains(IPv4CIDR.address(dns)!) })
            XCTAssertTrue(ranges.contains { $0.contains(IPv4CIDR.address("153.3.238.126")!) })
        }
    }
}
