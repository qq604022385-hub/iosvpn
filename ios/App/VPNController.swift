// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import Combine
import NetworkExtension
import UIKit
import FortiCore
@MainActor final class VPNController: ObservableObject {
    @Published var settings = SiteSettings()
    @Published var hillstoneSettings = HillstoneSettings()
    @Published var hillstone = UserDefaults.standard.bool(forKey:"lastProviderHillstone")
    @Published var certificatePrompt:HillstoneCertificate?
    private var certificateDecision:CheckedContinuation<Bool,Never>?
    @Published var status = "未连接"
    @Published var logs = DiagnosticsStore.load() ?? UserDefaults.standard.string(forKey:"lastDiagnostics").map{BoundedDiagnostics.boundedSnapshot($0)} ?? ""
    @Published var active = false
    @Published var busy = false
    @Published var error: String?
    @Published var needsManualToken = false
    @Published var tokenReadFailure = ""
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var poll: Timer?
    private var logRequestID:UUID?
    init() {
        do { settings = try KeychainStore.load(); hillstoneSettings = try HillstoneKeychain.load() } catch { self.error = error.localizedDescription }
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) {
            [weak self] _ in Task { @MainActor in await self?.restore() }
        }
        Task { await restore() }
        poll = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.readLogs() }
        }
    }
    private var extensionID: String { (Bundle.main.bundleIdentifier ?? "me.longxuan.fortionetap") + ".Tunnel" }
    private func restore() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == extensionID }
            if let saved = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["provider"] as? String {
                hillstone = saved == "hillstone"
            }
            refresh()
        } catch { self.error = "读取 VPN 配置失败：" + error.localizedDescription }
    }
    func save(_ profile: SiteSettings) throws {
        guard !active && !busy else { throw ProfileError.invalid("请先断开连接再修改设置。") }
        try KeychainStore.save(profile); settings = profile; status = "设置已保存，可以连接。"
    }
    func saveHillstone(_ profile:HillstoneSettings) throws {
        guard !active && !busy else {throw ProfileError.invalid("请先断开连接再修改设置。")}
        var value=profile;if value.gateway != hillstoneSettings.gateway || value.port != hillstoneSettings.port {value.certificatePin=""};try HillstoneKeychain.save(value);hillstoneSettings=value;status="设置已保存，可以连接。"
    }
    func answerCertificate(_ accepted:Bool){let decision=certificateDecision;certificateDecision=nil;certificatePrompt=nil;decision?.resume(returning:accepted)}
    private func verifyHillstoneCertificate() async throws {
        status="正在获取网关证书…";let profile=hillstoneSettings
        let certificate=try await Task.detached(priority:.userInitiated){try HillstoneCertificate.probe(profile)}.value
        if !profile.certificatePin.isEmpty {
            guard profile.certificatePin.lowercased()==certificate.pin else {throw ProfileError.invalid("网关证书已变化，已停止连接且未发送账号密码。请核实后在设置中重新信任证书。")};return
        }
        if !certificate.trusted {
            let accepted=await withCheckedContinuation{continuation in certificateDecision=continuation;certificatePrompt=certificate}
            guard accepted else {throw ProfileError.invalid("已取消，未发送账号密码。")}
        }
        hillstoneSettings.certificatePin=certificate.pin
    }
    func connect(token: String? = nil) async {
        guard !busy && !active else { return }
        busy = true; defer { busy = false }
        do {
            if hillstone {try hillstoneSettings.validate();try await verifyHillstoneCertificate();try HillstoneKeychain.save(hillstoneSettings)}else{if let token {try SiteSettings.validateToken(token)};try settings.validate(china: RoutePlan.chinaRanges());try KeychainStore.save(settings)}
            let m = manager ?? NETunnelProviderManager()
            let config = NETunnelProviderProtocol()
            config.providerBundleIdentifier = extensionID
            config.serverAddress = hillstone ? hillstoneSettings.gateway : settings.gateway
            config.providerConfiguration = ["profileVersion": 2, "provider": hillstone ? "hillstone" : "forti", "keepConnected": true] // Credentials and OTP are never persisted here.
            config.disconnectOnSleep = false
            config.enforceRoutes = false // Both engines use explicit /1 and DNS /32 routes.
            config.includeAllNetworks = false // Required for the configured domestic exclusions.
            m.protocolConfiguration = config; m.localizedDescription = "一键连接"
            m.isEnabled = true
            // System-owned restart survives suspension or termination of the containing app.
            let rule = NEOnDemandRuleConnect(); rule.interfaceTypeMatch = .any
            m.onDemandRules = [rule]
            m.isOnDemandEnabled = false
            manager = m
            try await m.saveToPreferences(); try await m.loadFromPreferences()
            manager = m
            guard let session = m.connection as? NETunnelProviderSession else {
                throw ProfileError.invalid("系统未创建 VPN 扩展会话。")
            }
            // Fetch after the system permission/save flow so the OTP stays fresh.
            var once = token ?? ""
            defer { once = "" }
            if !hillstone && token == nil {
                status = "正在自动读取动态令牌…"
                do { once = try await TokenClient.fetch() }
                catch is CancellationError { status = "连接已取消"; return }
                catch {
                    tokenReadFailure = error.localizedDescription
                    status = "自动读取失败，请输入动态令牌"
                    needsManualToken = true
                    return
                }
            }
            if !hillstone { try SiteSettings.validateToken(once) }
            logRequestID=nil
            UserDefaults.standard.set(hillstone,forKey:"lastProviderHillstone");logs = ""; status = "正在认证并建立 VPN…"
            if !hillstone || ![.connecting, .connected, .reasserting].contains(session.status) {
                try session.startTunnel(options: ["provider": (hillstone ? "hillstone" : "forti") as NSString, "token": once as NSString, "attemptID": UUID().uuidString as NSString])
            }
            m.isOnDemandEnabled = true
            try await m.saveToPreferences()
            refresh()
        } catch {
            self.error = error.localizedDescription; status = "连接未完成"
            // Do not leave an unexpected restart armed after a failed explicit start.
            if let manager, ![.connecting, .connected, .reasserting].contains(manager.connection.status) {
                manager.isOnDemandEnabled = false; manager.onDemandRules = nil
                do { try await manager.saveToPreferences() }
                catch { self.error = "保存自动连接状态失败：" + error.localizedDescription }
            }
        }
    }
    func disconnect() {
        guard !busy, let manager else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                // Persist cancellation BEFORE stopping; otherwise On Demand immediately restarts it.
                manager.isOnDemandEnabled = false; manager.onDemandRules = nil
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
                manager.connection.stopVPNTunnel()
                status = "正在断开并清理网络…"
                refresh()
            } catch {
                self.error = "关闭自动连接失败，尚未断开：" + error.localizedDescription
            }
        }
    }
    private func refresh() {
        let state = manager?.connection.status ?? .disconnected
        active = [.connecting, .connected, .reasserting, .disconnecting].contains(state) || manager?.isOnDemandEnabled == true
        if [.disconnected, .invalid].contains(state) {logRequestID=nil}
        switch state {
        case .connected: status = (hillstone ? hillstoneSettings.splitChina : settings.splitChina) ? "已连接 · 国内直连 / 国外走 VPN" : "已连接 · IPv4 全部走 VPN"
        case .connecting: status = "正在认证并建立 VPN…"
        case .disconnecting: status = "正在断开并清理网络…"
        case .reasserting: status = "网络中断 · 正在后台自动重连…"
        case .disconnected where manager?.isOnDemandEnabled == true: status = "保持连接已开启 · 等待系统恢复 VPN…"
        default: if !busy { status = hillstone ? "未连接" : "未连接 · 连接时自动读取新令牌" }
        }
        readLogs()
    }
    private func readLogs() {
        guard UIApplication.shared.applicationState == .active else{return}
        guard let session = manager?.connection as? NETunnelProviderSession,
              [.connecting, .connected, .reasserting].contains(session.status) else {if let saved=DiagnosticsStore.load(){logs=saved};return}
        guard logRequestID == nil else{return};let requestID=UUID();logRequestID=requestID
        do {try session.sendProviderMessage(Data("diagnostics".utf8)) { [weak self] data in
            Task { @MainActor in
                guard let self,self.logRequestID==requestID else{return};self.logRequestID=nil
                guard let data,let text=String(data:data,encoding:.utf8) else{return}
                let bounded=BoundedDiagnostics.boundedSnapshot(text);if self.logs != bounded {self.logs=bounded}
            }
        }}catch{logRequestID=nil;logs = BoundedDiagnostics.boundedSnapshot(logs+"\n日志读取失败："+error.localizedDescription)}
    }
}
