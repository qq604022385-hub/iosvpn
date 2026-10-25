// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import Darwin
import NetworkExtension
import Network
import FortiCore
private let onEngineEvent: fot_event_cb = { context, event, detail in
    guard let context, let event else { return }
    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(context).takeUnretainedValue()
    let name = String(cString: event), text = detail.map { String(cString: $0) } ?? ""
    provider.receive(event: name, detail: text)
}
private let onEnginePacket: fot_packet_cb = { context, bytes, count in
    guard let context, let bytes, count >= 20, count <= 65535 else { return }
    let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(context).takeUnretainedValue()
    provider.receive(packet: Data(bytes: bytes, count: count))
}
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let stateQueue = DispatchQueue(label: "FortiOneTap.state")
    private let engineQueue = DispatchQueue(label: "FortiOneTap.engine")
    private var running = false
    private var nativeReady = false
    private var networkReady = false
    private var networkVIP: String?
    private var networkFailures = 0
    private var startPhase = "读取配置"
    private var completion: ((Error?) -> Void)?
    private var profile = SiteSettings()
    private var hillstone=false
    private var hillProfile=HillstoneSettings()
    private var hillEngine:HillstoneTunnel?
    private var packetGate = PacketGate()
    private var logBuffer=BoundedDiagnostics()
    private var timer: DispatchSourceTimer?
    private var generation = UUID()
    private var reconnecting = false
    private var fortiStopping = false
    private var fortiAuthenticationRejected = false
    private var fortiPortPolicy = FortiPortPolicy()
    private var tokenTask: Task<Void, Never>?
    private var reconnectAttempt = 0
    private var retryWork: DispatchWorkItem?
    private var pathAvailable = true
    private var lastPathKey: String?
    private var packetReadInFlight = false
    private var sessionID = UUID()
    private var hasConnected = false
    private var pathMonitor: NWPathMonitor?
    private var dnsRelay: OpaquePointer?
    private var dnsPending = 0, dnsPollScheduled = false
    private var dnsDirect = 0, dnsFallback = 0
    private var installedSettings: NEPacketTunnelNetworkSettings?
    private var baseExclusions: [IPv4CIDR] = []
    private var domainRoutes = DomainRouteCache()
    private var installedDomainAddresses: [UInt32] = []
    private var routeUpdateInFlight = false, routeUpdateScheduled = false
    private var pendingDNSReplies: [Data] = []
    private var fortiProbe: Data?
    private var fortiDataValidated = false
    private var fortiResuming = false
    private var fortiPathRecovery = FortiPathRecovery()
    private var fortiInvalidPathSince: Date?
    private var fortiProbeID = UUID()
    private var flowV4=0,flowV6=0,flowInvalid=0,flowHeld=0,flowSent=0,flowLocal=0,flowWritten=0,flowWriteFailed=0,flowFamilyMismatch=0,flowBatches=0,flowBatchPeakBytes=0
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        stateQueue.async {
            guard !self.running else { completionHandler(ProfileError.invalid("VPN 已经运行。")); return }
            self.completion = completionHandler; self.running = true; self.nativeReady = false
            self.networkReady = false; self.networkVIP = nil; self.networkFailures = 0; self.startPhase = "读取配置"; self.logBuffer=BoundedDiagnostics();self.addLog("一键连接 1.4.3 build 12 · 正在连接")
            self.resetRouting()
            self.retryWork?.cancel(); self.retryWork = nil
            self.fortiStopping = false; self.fortiPortPolicy = FortiPortPolicy(); self.reconnecting = false; self.reconnectAttempt = 0; self.reasserting = false
            self.pathAvailable = true; self.lastPathKey = nil; self.hasConnected = false
            self.sessionID = UUID(); self.packetReadInFlight = false
            self.packetGate = PacketGate()
            self.flowV4=0;self.flowV6=0;self.flowInvalid=0;self.flowHeld=0;self.flowSent=0;self.flowLocal=0;self.flowWritten=0;self.flowWriteFailed=0;self.flowFamilyMismatch=0;self.flowBatches=0;self.flowBatchPeakBytes=0
            self.generation = UUID(); let generation = self.generation
            let monitor = NWPathMonitor(); self.pathMonitor = monitor
            monitor.pathUpdateHandler = { [weak self] path in
                guard let self, self.running else { return }
                let type = path.usesInterfaceType(.wifi) ? "Wi-Fi" : path.usesInterfaceType(.cellular) ? "蜂窝" : "其他"
                self.addLog("系统网络 \(type) status=\(path.status) ipv4=\(path.supportsIPv4) ipv6=\(path.supportsIPv6)")
                self.pathAvailable = path.status == .satisfied
                // Ignore our own utun interface so installing routes cannot trigger a reconnect loop.
                let key = path.availableInterfaces.filter {
                    [.wifi, .cellular, .wiredEthernet].contains($0.type) && path.usesInterfaceType($0.type)
                }.map { $0.name }.sorted().joined(separator: ",")
                let changed = self.lastPathKey.map { $0 != key } ?? false
                self.lastPathKey = key
                if !self.hillstone, self.hasConnected, self.pathAvailable, changed, !self.reconnecting {
                    self.recoverForti("外层网络切换，正在重新取令牌并重建 Forti 连接。")
                }
                if !self.hillstone, self.pathAvailable, self.reconnecting, !self.fortiStopping, self.tokenTask == nil, !self.nativeReady {
                    self.scheduleFortiRetry()
                }
                if self.hillstone, self.hasConnected, self.pathAvailable, changed, !self.reconnecting {
                    self.recoverHillstone("外层网络切换，正在重建加密连接。")
                } else if self.hillstone, self.reconnecting, self.pathAvailable, self.hillEngine == nil {
                    self.scheduleHillstoneRetry(delay: 0)
                }
            }
            monitor.start(queue: self.stateQueue)
            do {
                let saved = (self.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
                let selected = TunnelRecoveryPolicy.provider(option: options?["provider"] as? String, saved: saved?["provider"] as? String)
                if selected == "hillstone" {
                    self.hillstone = true
                    self.hillProfile = try HillstoneKeychain.load(); try self.hillProfile.validate()
                    guard !self.hillProfile.certificatePin.isEmpty else { throw ProfileError.invalid("请打开应用完成首次网关确认。") }
                    self.profile.gateway = self.hillProfile.gateway; self.profile.splitChina = self.hillProfile.splitChina
                    self.startHillstone()
                    return
                }
                self.hillstone=false;self.hillEngine=nil
                self.profile = try KeychainStore.load()
                try self.profile.validate(china: RoutePlan.chinaRanges())
                if let token = options?["token"] as? String,
                   let attempt = options?["attemptID"] as? String, UUID(uuidString: attempt) != nil {
                    try SiteSettings.validateToken(token)
                    guard UserDefaults.standard.string(forKey: "lastConsumedAttempt") != attempt else {
                        throw ProfileError.invalid("本次令牌已经使用，请重新连接。")
                    }
                    UserDefaults.standard.set(attempt, forKey: "lastConsumedAttempt")
                    self.startForti(token: token)
                } else {
                    self.fetchFortiToken()
                }
            } catch { self.fail(error.localizedDescription) }
        }
    }
    private func startForti(token: String) {
        guard running, !hillstone else { return }
        let generation = self.generation, settings = profile, remotePort = fortiPortPolicy.port
        fortiStopping = false; fortiAuthenticationRejected = false
        startPhase = "启动 IPsec 引擎"
        engineQueue.async {
            let result = fot_start_on_port(NSHomeDirectory() + "/tmp/fot", settings.gateway, settings.username,
                settings.password, settings.psk, settings.localID, token, settings.appendToken ? 1 : 0,
                Unmanaged.passUnretained(self).toOpaque(), onEngineEvent, onEnginePacket, remotePort)
            self.stateQueue.async {
                guard self.running, self.generation == generation else { return }
                if result == 1 { self.nativeReady = true; self.finishStart() }
                else { self.fail("Forti 认证或协商失败，请检查账号、PSK 和令牌。", retryable: !self.fortiAuthenticationRejected) }
            }
        }
        stateQueue.asyncAfter(deadline: .now() + 45) {
            guard self.running, self.generation == generation, !self.nativeReady || !self.networkReady else { return }
            self.fail("Forti 连接超时。")
        }
    }
    private func fetchFortiToken() {
        guard running, !hillstone, tokenTask == nil else { return }
        let generation = self.generation
        addLog("正在为本次后台连接读取新令牌…")
        tokenTask = Task { [weak self] in
            do {
                let token = try await TokenClient.fetch()
                guard !Task.isCancelled else { return }
                self?.stateQueue.async { [weak self] in
                    guard let self, self.running, self.generation == generation else { return }
                    self.tokenTask = nil; self.startForti(token: token)
                }
            } catch {
                self?.stateQueue.async { [weak self] in
                    guard let self, self.running, self.generation == generation else { return }
                    self.tokenTask = nil; self.reconnecting = true; self.reconnectAttempt = min(self.reconnectAttempt + 1, 7)
                    self.scheduleFortiRetry()
                }
            }
        }
    }
    private func scheduleFortiRetry() {
        guard running, !hillstone else { return }
        retryWork?.cancel(); retryWork = nil
        guard pathAvailable else { addLog("网络不可用，等待恢复后重新取令牌。"); return }
        let generation = self.generation
        let delay = TunnelRecoveryPolicy.retryDelay(attempt: reconnectAttempt)
        addLog("Forti 将在 \(Int(delay)) 秒后读取新令牌并重连。")
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.running, self.generation == generation, self.pathAvailable else { return }
            self.retryWork = nil; self.fetchFortiToken()
        }
        retryWork = work; stateQueue.asyncAfter(deadline: .now() + delay, execute: work)
    }
    private func recoverForti(_ message: String) {
        guard running, !hillstone, !fortiStopping else { return }
        addLog(message); reconnecting = true; fortiStopping = true
        if hasConnected { reasserting = true }
        generation = UUID(); let generation = self.generation
        nativeReady = false; networkReady = false; networkVIP = nil
        timer?.cancel(); timer = nil; retryWork?.cancel(); retryWork = nil
        tokenTask?.cancel(); tokenTask = nil
        resetRouting(cancelMonitor: false); packetGate = PacketGate()
        engineQueue.async {
            fot_stop()
            self.stateQueue.async {
                guard self.running, self.generation == generation else { return }
                self.fortiStopping = false
                self.reconnectAttempt = min(self.reconnectAttempt + 1, 7)
                self.scheduleFortiRetry()
            }
        }
    }
    private func startHillstone() {
        guard running, hillEngine == nil else { return }
        let generation = self.generation
        let engine = HillstoneTunnel(); hillEngine = engine
        addLog(reconnecting ? "正在后台重新认证 Hillstone…" : "正在启动独立 Hillstone 引擎…")
        engine.start(hillProfile, ready: { [weak self] vip, dns in
            guard let self else { return }
            self.stateQueue.async {
                guard self.running, self.generation == generation else { return }
                self.profile.dns = dns; self.nativeReady = false; self.installNetwork(vip: vip)
            }
        }, packets: { [weak self] data in self?.receiveHillstone(packets: data, generation: generation) }, verified: { [weak self] in
            guard let self else { return }
            self.stateQueue.async {
                guard self.running, self.generation == generation else { return }
                self.nativeReady = true
                self.addLog("安装路由后，VPN DNS 加密数据往返已验证。")
                self.finishStart()
            }
        }, error: { [weak self] text in
            guard let self else { return }
            self.stateQueue.async {
                guard self.running, self.generation == generation else { return }
                if TunnelRecoveryPolicy.canRetry(text) { self.recoverHillstone(text) }
                else { self.fail(text) }
            }
        })
        stateQueue.asyncAfter(deadline: .now() + 45) {
            guard self.running, self.generation == generation, !self.nativeReady || !self.networkReady else { return }
            self.recoverHillstone("Hillstone 连接超时。")
        }
    }
    private func recoverHillstone(_ message: String) {
        guard running, hillstone else { return }
        // Single flight: stop and join the old worker before creating a new native handle.
        guard let engine = hillEngine else { return }
        addLog(message); reconnecting = true
        if hasConnected { reasserting = true }
        generation = UUID(); let generation = self.generation
        nativeReady = false; networkReady = false; networkVIP = nil
        timer?.cancel(); timer = nil
        retryWork?.cancel(); retryWork = nil
        resetRouting(cancelMonitor: false)
        packetGate = PacketGate()
        engine.stop()
        engine.afterStopped(on: stateQueue) { [weak self] in
            guard let self, self.running, self.generation == generation else { return }
            self.hillEngine = nil
            self.reconnectAttempt = min(self.reconnectAttempt + 1, 7)
            self.scheduleHillstoneRetry(delay: TunnelRecoveryPolicy.retryDelay(attempt: self.reconnectAttempt))
        }
    }
    private func scheduleHillstoneRetry(delay: Double) {
        guard running, hillstone, reconnecting, hillEngine == nil else { return }
        retryWork?.cancel(); retryWork = nil
        guard pathAvailable else { addLog("网络不可用，保留连接意图，等待网络恢复。 "); return }
        let generation = self.generation
        addLog("后台重连将在 \(Int(delay)) 秒后执行。")
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.running, self.generation == generation else { return }
            self.retryWork = nil
            guard self.pathAvailable else { return }
            self.startHillstone()
        }
        retryWork = work; stateQueue.asyncAfter(deadline: .now() + delay, execute: work)
    }
    private func disableOnDemandAfterFailure() {
        // The extension can stop a permanent-failure loop even when the app is suspended.
        guard let identifier = Bundle.main.bundleIdentifier else { return }
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            guard error == nil, let manager = managers?.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == identifier
            }) else { return }
            manager.isOnDemandEnabled = false; manager.onDemandRules = nil
            manager.saveToPreferences { error in
                if let error { self.stateQueue.async { self.addLog("关闭自动连接失败：" + error.localizedDescription) } }
            }
        }
    }
    fileprivate func receive(event: String, detail: String) {
        stateQueue.async {
            guard self.running else { return }
            switch event {
            case "ready": self.installNetwork(vip: detail)
            case "down": if !self.fortiStopping { self.fail(detail) }
            case "error": if !self.fortiStopping { self.fail(detail, retryable: !self.fortiAuthenticationRejected && !detail.contains("服务端未提供")) }
            case "unreachable":
                if !self.fortiStopping {
                    if !self.fortiAuthenticationRejected, self.fortiPortPolicy.nextAfterNoResponse() {
                        self.recoverForti("UDP 500 协商无有效应答，读取新令牌后尝试 UDP 4500。")
                    } else { self.fail(detail, retryable: self.hasConnected) }
                }
            case "phase": self.startPhase = detail; self.addLog("Forti 阶段：" + detail)
            case "log":
                if detail.contains("AUTHENTICATION_FAILED") || detail.contains("XAuth authentication") && detail.contains("failed") || detail.contains("NO_PROPOSAL_CHOSEN") { self.fortiAuthenticationRejected = true }
                self.addLog(detail)
            default: break
            }
        }
    }
    fileprivate func receive(packet: Data) {
        stateQueue.async {
            guard self.running, self.networkReady, packet.first.map({ $0 >> 4 == 4 }) == true else { return }
            if let probe=self.fortiProbe,DNSProbeMessage.matchesPacket(packet,request:probe) {
                self.fortiProbe=nil;self.fortiDataValidated=true
                self.addLog("Forti：安装路由后，DNS 加密数据往返已验证。")
                self.finishStart();return
            }
            self.writePacket(packet, family: AF_INET)
        }
    }
    // The native worker waits for this bounded batch to be consumed: no per-packet async backlog.
    private func receiveHillstone(packets:[Data],generation:UUID) {
        stateQueue.sync {
            guard self.running,self.networkReady,self.generation==generation else{return}
            self.flowBatches += 1
            self.flowBatchPeakBytes=max(self.flowBatchPeakBytes,packets.reduce(0){$0+$1.count})
            if self.packetFlow.writePackets(packets,withProtocols:Array(repeating:NSNumber(value:AF_INET),count:packets.count)) {self.flowWritten += packets.count}else{self.flowWriteFailed += packets.count}
        }
    }
    private func installNetwork(vip: String) {
        guard IPv4CIDR.address(vip) != nil else { fail("服务端虚拟 IPv4 无效。"); return }
        if let existing = networkVIP {
            if existing != vip { fail("虚拟 IP 已变化，请使用新令牌重连。") }
            return
        }
        networkVIP = vip
        do {
            let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: profile.gateway)
            let ipv4 = NEIPv4Settings(addresses: [vip], subnetMasks: ["255.255.255.255"])
            // /1 routes take precedence over the cellular /0 route without enforceRoutes.
            ipv4.includedRoutes = [
                NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "128.0.0.0"),
                NEIPv4Route(destinationAddress: "128.0.0.0", subnetMask: "128.0.0.0"),
                NEIPv4Route(destinationAddress: profile.dns, subnetMask: "255.255.255.255")
            ]
            baseExclusions = try (hillstone ? hillProfile.exclusions(dns:profile.dns,china:RoutePlan.chinaRanges()) : RoutePlan.excluded(settings: profile, china: RoutePlan.chinaRanges()))
            ipv4.excludedRoutes = baseExclusions.map {
                NEIPv4Route(destinationAddress: $0.addressString, subnetMask: $0.maskString)
            }
            settings.ipv4Settings = ipv4
            // Capture IPv6; Hillstone replies no-route for TCP/UDP so apps promptly retry IPv4.
            let ipv6 = NEIPv6Settings(addresses: ["fd00:6040:2238::1"], networkPrefixLengths: [128])
            ipv6.includedRoutes = [NEIPv6Route.default()]
            ipv6.excludedRoutes = [NEIPv6Route(destinationAddress: "::1", networkPrefixLength: 128), NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10)]
            settings.ipv6Settings = ipv6
            let dns = NEDNSSettings(servers: [profile.dns]); dns.matchDomains = [""]; settings.dnsSettings = dns
            settings.mtu = 1280
            installedSettings = settings
            if profile.splitChina {
                dnsRelay = hs_dns_relay_create(profile.dns)
                guard dnsRelay != nil else { throw ProfileError.invalid("国内 DNS 分流初始化失败。") }
            }
            let generation = self.generation
            setTunnelNetworkSettings(settings) { error in
                self.stateQueue.async {
                    guard self.running, self.generation == generation else { return }
                    if let error { self.fail("安装 VPN 路由失败：" + error.localizedDescription); return }
                    self.networkReady = true
                    if self.hillstone {self.hillEngine?.requestNetworkValidation()}
                    self.addLog("虚拟 IPv4、DNS 与分流路由已安装；等待系统应用流量验证。")
                    self.addLog("路由配置 split_china=\(self.profile.splitChina) resolver=\(self.profile.dns) exclusions=\(ipv4.excludedRoutes?.count ?? 0)")
                    self.addLog("共享分流：国内域名 DNS 直连 + 答案 /32 路由，CN IP 直连，其余 VPN；MTU 1280，MSS 1160。")
                    if self.hillstone {self.addLog("Hillstone：MTU 1280，TCP MSS 上限 1160，AAAA 本地返回无记录，IPv6 快速回退到 IPv4。")}
                    self.finishStart()
                }
            }
        } catch { fail(error.localizedDescription) }
    }
    private func finishStart() {
        guard running, nativeReady, networkReady else { return }
        if !hillstone, fortiResuming {
            if fortiDataValidated {
                fortiResuming = false; reasserting = false
                fortiPathRecovery.validated()
                addLog("Forti 原会话已恢复，加密 DNS 往返已验证。")
            } else if fortiProbe == nil { beginFortiProbe() }
            return
        }
        guard completion != nil || reconnecting else { return }
        if !hillstone, !fortiDataValidated {
            if fortiProbe == nil { beginFortiProbe() }
            return
        }
        let complete = completion; completion = nil
        let recovered = reconnecting
        reconnecting = false; reconnectAttempt = 0; reasserting = false; hasConnected = true
        retryWork?.cancel(); retryWork = nil
        if !packetReadInFlight { readPackets(generation: generation) }
        addLog(recovered ? "后台重连完成，数据通道已验证。" : "系统 packetFlow 读取已启动。")
        complete?(nil)
        let timer = DispatchSource.makeTimerSource(queue: stateQueue)
        let interval=hillstone ? 5:2
        timer.schedule(deadline: .now() + .seconds(interval), repeating: .seconds(interval))
        timer.setEventHandler { [weak self] in
            guard let self, self.running else { return }
            self.addLog("分流 direct_dns=\(self.dnsDirect) fallback_dns=\(self.dnsFallback) domain_routes=\(self.installedDomainAddresses.count) forwarded=\(self.flowSent) held=\(self.flowHeld) written=\(self.flowWritten)")
            if self.hillstone {if let engine=self.hillEngine {self.addLog(engine.diagnostics()+" flow_v4=\(self.flowV4) flow_v6=\(self.flowV6) invalid=\(self.flowInvalid) held_or_filtered=\(self.flowHeld) forwarded=\(self.flowSent) local_reply=\(self.flowLocal) written=\(self.flowWritten) write_failed=\(self.flowWriteFailed) family_mismatch=\(self.flowFamilyMismatch) batches=\(self.flowBatches) batch_peak_bytes=\(self.flowBatchPeakBytes) log_bytes=\(self.logBuffer.byteCount) memory_bytes=\(self.memoryFootprint().map{String($0)} ?? "unknown")")};return}
            let generation = self.generation
            self.engineQueue.async {
                let valid = fot_network_valid()
                self.stateQueue.async {
                    guard self.running, self.generation == generation else { return }
                    self.networkFailures = valid == 0 ? min(self.networkFailures + 1, 3) : 0
                    switch self.fortiPathRecovery.observe(valid: valid != 0) {
                    case .waitForNetwork:
                        // A different physical source cannot carry this IKEv1 session.
                        // Keep brief outages, but bound waiting once a usable path returns.
                        if self.pathAvailable {
                            let since = self.fortiInvalidPathSince ?? Date()
                            self.fortiInvalidPathSince = since
                            if Date().timeIntervalSince(since) >= 15 {
                                self.recoverForti("网络已恢复但旧 IPsec 外层地址失效，正在重建连接。")
                                return
                            }
                        } else { self.fortiInvalidPathSince = nil }
                        self.reasserting = true
                        self.fortiResuming = false; self.fortiProbe = nil; self.fortiProbeID = UUID()
                        if self.networkFailures == 1 { self.addLog("外层网络暂不可用，保留 Forti 原会话等待恢复。") }
                    case .validateTunnel:
                        self.fortiInvalidPathSince = nil
                        self.reasserting = true; self.fortiResuming = true; self.fortiDataValidated = false
                        self.finishStart()
                    case .ready: self.fortiInvalidPathSince = nil
                    }
                }
            }
        }
        self.timer = timer; timer.resume()
    }
    private func beginFortiProbe() {
        guard let vip=networkVIP,let packet=DNSProbeMessage.packet(source:vip,resolver:profile.dns,
            id:UInt16.random(in:0...UInt16.max),port:UInt16.random(in:49152...65535)) else {
            fail("无法构造 Forti 数据通道检查。");return
        }
        fortiProbe=packet;startPhase="验证 Forti 加密 DNS 数据通道"
        fortiProbeID = UUID(); let probeID = fortiProbeID
        addLog("Forti：IKE/CHILD_SA 已建立，正在验证实际加密 DNS 往返。")
        let generation=self.generation
        for attempt in 0..<3 {
            stateQueue.asyncAfter(deadline:.now()+Double(attempt)) {
                guard self.running,self.generation==generation,self.fortiProbeID==probeID,self.fortiProbe != nil else { return }
                self.sendThroughVPN(packet)
            }
        }
        stateQueue.asyncAfter(deadline:.now()+5) {
            guard self.running,self.generation==generation,self.fortiProbeID==probeID,!self.fortiDataValidated else { return }
            self.fail("Forti 认证已通过，但加密 DNS 数据通道没有回复；请检查 UDP 4500 通路、服务器转发和配置的 VPN DNS。")
        }
    }
    private func readPackets(generation: UUID) {
        guard running, !packetReadInFlight else { return }
        packetReadInFlight = true
        let sessionID = self.sessionID
        packetFlow.readPackets { packets, protocols in
            self.stateQueue.async {
                guard self.sessionID == sessionID else { return }
                self.packetReadInFlight = false
                guard self.running else { return }
                guard self.generation == generation, self.networkReady, self.nativeReady else {
                    if self.networkReady, self.nativeReady { self.readPackets(generation: self.generation) }
                    return
                }
                for (index, raw) in packets.enumerated() {
                    guard self.running, self.generation == generation, self.networkReady else { break }
                    guard let decoded=TunnelPacket.decode(raw) else {self.flowInvalid += 1;continue}
                    let packet=decoded.payload
                    let family:Int32=decoded.version == 4 ? AF_INET : AF_INET6
                    if index >= protocols.count || protocols[index].int32Value != family {self.flowFamilyMismatch += 1}
                    if decoded.version == 6 {
                        self.flowV6 += 1
                        if let reply=self.localReply(packet) {self.flowLocal += 1;self.writePacket(reply,family:AF_INET6)}
                        continue
                    }
                    self.flowV4 += 1
                    let allowedPackets=self.packetGate.ingest(packet,dns:self.profile.dns)
                    if allowedPackets.isEmpty {self.flowHeld += 1}
                    for allowed in allowedPackets {
                        if let reply=self.localReply(allowed) {self.flowLocal += 1;self.writePacket(reply,family:AF_INET);continue}
                        if let relay=self.dnsRelay, self.dnsPending < 32,
                           allowed.withUnsafeBytes({ raw in hs_dns_relay_submit(relay,raw.bindMemory(to:UInt8.self).baseAddress,allowed.count) }) == 1 {
                            self.dnsPending += 1; self.dnsDirect += 1; self.scheduleDNSPoll(); continue
                        }
                        self.sendThroughVPN(allowed)
                    }
                }
                if self.running, self.networkReady, self.nativeReady {self.readPackets(generation: self.generation)}
            }
        }
    }
    private func localReply(_ packet: Data) -> Data? {
        var output = [UInt8](repeating: 0, count: 1280)
        let count = packet.withUnsafeBytes { raw in
            hs_local_reply(raw.bindMemory(to: UInt8.self).baseAddress, packet.count, &output, 1280)
        }
        return count > 0 ? Data(output.prefix(Int(count))) : nil
    }
    private func sendThroughVPN(_ packet: Data) {
        guard running, networkReady, nativeReady else { return }
        if hillstone {
            if hillEngine?.send(packet) == true { flowSent += 1 }
            else { recoverHillstone("Hillstone 数据发送失败。") }
        } else {
            var prepared = packet
            let count = prepared.count
            prepared.withUnsafeMutableBytes { raw in hs_prepare_ipv4(raw.bindMemory(to:UInt8.self).baseAddress, count) }
            let sent = prepared.withUnsafeBytes { raw in fot_input(raw.bindMemory(to:UInt8.self).baseAddress, count) }
            if sent == 1 { flowSent += 1 } else { flowHeld += 1 }
        }
    }
    private func scheduleDNSPoll() {
        guard !dnsPollScheduled else { return }
        dnsPollScheduled = true
        let generation = self.generation
        stateQueue.asyncAfter(deadline: .now()+0.02) {
            guard self.running, self.generation == generation else { return }
            self.dnsPollScheduled = false
            guard let relay = self.dnsRelay else { return }
            var buffer = [UInt8](repeating: 0, count: 2048)
            for _ in 0..<32 {
                var fallback: Int32 = 0
                let count = hs_dns_relay_poll(relay, &buffer, 2048, &fallback)
                if count <= 0 { break }
                self.dnsPending = max(0, self.dnsPending-1)
                let packet = Data(buffer.prefix(Int(count)))
                if fallback == 1 { self.dnsFallback += 1; self.sendThroughVPN(packet); continue }
                let protected = Set([self.profile.gateway,self.profile.dns].compactMap(IPv4CIDR.address))
                self.domainRoutes.learn(DNSRouteAnswer.addresses(in: packet), excluding: self.baseExclusions,
                                        protected: protected)
                if !self.routeUpdateInFlight, self.domainRoutes.addresses == self.installedDomainAddresses {
                    self.flowLocal += 1; self.writePacket(packet, family: AF_INET)
                } else if self.pendingDNSReplies.count < 64 {
                    self.pendingDNSReplies.append(packet); self.scheduleDomainRoutes()
                }
            }
            if self.dnsPending > 0 { self.scheduleDNSPoll() }
        }
    }
    private func scheduleDomainRoutes() {
        guard !routeUpdateScheduled, !routeUpdateInFlight else { return }
        routeUpdateScheduled = true
        let generation = self.generation
        stateQueue.asyncAfter(deadline: .now()+0.05) {
            guard self.running, self.generation == generation else { return }
            self.routeUpdateScheduled = false
            guard let settings = self.installedSettings, let ipv4 = settings.ipv4Settings else { return }
            let addresses = self.domainRoutes.addresses, replies = self.pendingDNSReplies
            self.pendingDNSReplies.removeAll()
            ipv4.excludedRoutes = self.baseExclusions.map { NEIPv4Route(destinationAddress:$0.addressString,subnetMask:$0.maskString) }
                + addresses.map { NEIPv4Route(destinationAddress:IPv4CIDR.string($0),subnetMask:"255.255.255.255") }
            self.routeUpdateInFlight = true
            self.setTunnelNetworkSettings(settings) { error in
                self.stateQueue.async {
                    guard self.running, self.generation == generation else { return }
                    self.routeUpdateInFlight = false
                    if let error { self.fail("更新域名分流路由失败："+error.localizedDescription); return }
                    self.installedDomainAddresses = addresses
                    // Release DNS only after the corresponding routes exist.
                    for reply in replies { self.flowLocal += 1; self.writePacket(reply,family:AF_INET) }
                    if !self.pendingDNSReplies.isEmpty || self.domainRoutes.addresses != addresses { self.scheduleDomainRoutes() }
                }
            }
        }
    }
    private func resetRouting(cancelMonitor: Bool = true) {
        if cancelMonitor { pathMonitor?.cancel(); pathMonitor = nil }
        if let relay = dnsRelay { hs_destroy(relay) }; dnsRelay = nil
        dnsPending = 0; dnsPollScheduled = false; dnsDirect = 0; dnsFallback = 0
        installedSettings = nil; baseExclusions = []; domainRoutes = DomainRouteCache()
        installedDomainAddresses = []; pendingDNSReplies = []; routeUpdateInFlight = false; routeUpdateScheduled = false
        fortiProbe = nil; fortiDataValidated = false
        fortiInvalidPathSince = nil; fortiResuming = false; fortiPathRecovery = FortiPathRecovery(); fortiProbeID = UUID()
    }
    private func memoryFootprint()->UInt64? {
        var info=task_vm_info_data_t()
        var count=mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size/MemoryLayout<integer_t>.size)
        let capacity=Int(count)
        let result=withUnsafeMutablePointer(to:&info){pointer in
            pointer.withMemoryRebound(to:integer_t.self,capacity:capacity){task_info(mach_task_self_,task_flavor_t(TASK_VM_INFO),$0,&count)}
        }
        return result == KERN_SUCCESS ? UInt64(info.phys_footprint):nil
    }
    private func writePacket(_ packet:Data,family:Int32) {
        if packetFlow.writePackets([packet],withProtocols:[NSNumber(value:family)]) {flowWritten += 1}else{flowWriteFailed += 1}
    }
    private func addLog(_ message: String) {
        logBuffer.append(message)
        DiagnosticsStore.save(logBuffer.snapshot)
    }
    private func fail(_ message: String, retryable: Bool = true) {
        guard running else { return }
        if !hillstone, retryable, hasConnected || reconnecting { recoverForti(message); return }
        addLog(message); running = false; generation = UUID(); reasserting = false
        retryWork?.cancel(); retryWork = nil
        tokenTask?.cancel(); tokenTask = nil
        timer?.cancel(); timer = nil;DiagnosticsStore.flush()
        disableOnDemandAfterFailure()
        resetRouting()
        let error = ProfileError.invalid(message)
        completion?(error); completion = nil
        if hillstone {
            if let engine=hillEngine {
                engine.stop();engine.afterStopped(on:engineQueue){self.setTunnelNetworkSettings(nil){_ in self.cancelTunnelWithError(error)}}
            } else { setTunnelNetworkSettings(nil) { _ in self.cancelTunnelWithError(error) } }
            return
        }
        engineQueue.async {
            fot_stop()
            self.setTunnelNetworkSettings(nil) { _ in self.cancelTunnelWithError(error) }
        }
    }
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stateQueue.async {
            self.addLog("系统停止 VPN reason=\(reason.rawValue)")
            self.running = false; self.generation = UUID(); self.reasserting = false
            self.retryWork?.cancel(); self.retryWork = nil
            self.tokenTask?.cancel(); self.tokenTask = nil
            self.timer?.cancel(); self.timer = nil
            self.resetRouting()
            self.completion?(ProfileError.invalid("连接已取消。")); self.completion = nil
            if self.hillstone,let engine=self.hillEngine {
                engine.stop();engine.afterStopped(on:self.engineQueue){
                    self.setTunnelNetworkSettings(nil){_ in self.stateQueue.async{self.networkReady=false;self.hillProfile=HillstoneSettings();self.hillEngine=nil;self.addLog("已断开，VPN 路由与 DNS 已移除。");DiagnosticsStore.flush();completionHandler()}}
                };return
            }
            self.engineQueue.async {
                fot_stop()
                self.setTunnelNetworkSettings(nil) { _ in
                    self.stateQueue.async {
                        self.networkReady = false; self.profile = SiteSettings(); self.packetGate = PacketGate()
                        self.addLog("已断开，VPN 路由与 DNS 已移除。");DiagnosticsStore.flush()
                        completionHandler()
                    }
                }
            }
        }
    }
    override func sleep(completionHandler: @escaping () -> Void) {
        stateQueue.async {
            if self.running { self.addLog("系统休眠；保持隧道，等待唤醒。") }
            completionHandler()
        }
    }
    override func wake() {
        stateQueue.async {
            guard self.running else { return }
            self.networkFailures = 0
            self.addLog("系统唤醒；恢复网络检查与心跳。")
            if self.hillstone {
                if self.reconnecting, self.hillEngine == nil { self.scheduleHillstoneRetry(delay: 0) }
                else { self.hillEngine?.requestNetworkValidation() }
            } else if self.hasConnected {
                self.fortiPathRecovery.wake(); self.reasserting = true
            }
        }
    }
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        stateQueue.async {
            guard messageData == Data("diagnostics".utf8) else { completionHandler?(nil); return }
            completionHandler?(Data(self.logBuffer.snapshot.utf8))
        }
    }
}
