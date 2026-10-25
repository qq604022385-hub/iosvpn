// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import Network
import FortiCore

enum NetworkProbe {
    static func run(dns: String) async -> [String] {
        async let udp = check(host: dns, port: 53, dns: true)
        async let tls = check(host: "1.1.1.1", port: 443, dns: false)
        async let domain = check(host: "example.com", port: 443, dns: false)
        let result = await (udp, tls, domain)
        return [result.0, result.1, result.2]
    }
    private static func check(host: String, port: UInt16, dns: Bool) async -> String {
        await withCheckedContinuation { continuation in
            Probe(host: host, port: port, dns: dns, continuation: continuation).start()
        }
    }
    private final class Probe {
        private let connection: NWConnection
        private let queue = DispatchQueue(label: "FortiOneTap.probe")
        private let label: String
        private let dns: Bool
        private let id = UInt16.random(in: 0...UInt16.max)
        private var continuation: CheckedContinuation<String, Never>?
        private var sent = false
        private var received = 0
        init(host: String, port: UInt16, dns: Bool, continuation: CheckedContinuation<String, Never>) {
            self.dns = dns; self.continuation = continuation
            if dns { label = "DNS \(host):53" }
            else if IPv4CIDR.address(host) != nil { label = "HTTPS \(host):443（跳过域名解析）" }
            else { label = "HTTPS \(host):443（含系统域名解析）" }
            connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
                                      using: dns ? .udp : .tls)
        }
        func start() {
            // This closure keeps the probe alive until its bounded deadline.
            queue.asyncAfter(deadline: .now() + 8) { self.finish("8 秒内没有完成响应/握手。") }
            connection.stateUpdateHandler = { [weak self] state in
                guard let self, self.continuation != nil else { return }
                switch state {
                case .ready:
                    if self.dns { self.sendDNS() }
                    else { self.finish("TLS 握手成功。") }
                case .failed(let error): self.finish("失败：" + error.localizedDescription)
                case .cancelled: self.finish("测试已取消。")
                default: break
                }
            }
            connection.start(queue: queue)
        }
        private func sendDNS() {
            guard !sent else { return }; sent = true
            connection.send(content: DNSProbeMessage.query(id: id), completion: .contentProcessed { [weak self] error in
                guard let self, self.continuation != nil else { return }
                if let error { self.finish("发送失败：" + error.localizedDescription) }
                else { self.receiveDNS() }
            })
        }
        private func receiveDNS() {
            connection.receiveMessage { [weak self] data, _, _, error in
                guard let self, self.continuation != nil else { return }
                if let error { self.finish("接收失败：" + error.localizedDescription); return }
                if let data, let description = DNSProbeMessage.describeReply(data, id: self.id) {
                    self.finish(description); return
                }
                self.received += 1
                if self.received >= 5 { self.finish("收到的回复与测试请求不匹配。") }
                else { self.receiveDNS() }
            }
        }
        private func finish(_ result: String) {
            guard let continuation else { return }
            self.continuation = nil
            connection.stateUpdateHandler = nil; connection.cancel()
            continuation.resume(returning: label + "：" + result)
        }
    }
}
