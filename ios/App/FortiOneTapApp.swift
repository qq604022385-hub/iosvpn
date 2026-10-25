// SPDX-License-Identifier: GPL-2.0-or-later
import SwiftUI
import FortiCore
@main @MainActor struct FortiOneTapApp: App {
    @StateObject private var vpn = VPNController()
    var body: some Scene { WindowGroup { MainView(vpn: vpn) } }
}
@MainActor struct MainView: View {
    @ObservedObject var vpn: VPNController
    @State private var showSettings = false
    @State private var token = ""
    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Picker("连接方式",selection:$vpn.hillstone){Text("Forti / IPsec").tag(false);Text("Hillstone / SCVPN").tag(true)}.pickerStyle(.segmented).disabled(vpn.active || vpn.busy)
                Text((vpn.hillstone ? vpn.hillstoneSettings.gateway : vpn.settings.gateway) + " · 独立 iOS VPN").foregroundStyle(.secondary)
                Text(vpn.status).font(.headline).frame(maxWidth: .infinity, minHeight: 72)
                    .background(.background, in: RoundedRectangle(cornerRadius: 16))
                Button(vpn.active ? "断开连接 / 取消连接" : "一键连接") {
                    if vpn.active { vpn.disconnect() }
                    else {
                        do { if vpn.hillstone {try vpn.hillstoneSettings.validate()} else {try vpn.settings.validate(china: RoutePlan.chinaRanges())};Task{await vpn.connect()} }
                        catch { showSettings = true }
                    }
                }.buttonStyle(.borderedProminent).controlSize(.large).frame(maxWidth: .infinity).disabled(vpn.busy)
                Toggle("国内直连，国外走 VPN", isOn: Binding(get:{vpn.hillstone ? vpn.hillstoneSettings.splitChina : vpn.settings.splitChina},set:{if vpn.hillstone {vpn.hillstoneSettings.splitChina=$0}else{vpn.settings.splitChina=$0}})).disabled(vpn.active || vpn.busy)
                Button("账号与连接设置") { showSettings = true }.disabled(vpn.active || vpn.busy)
                VStack(alignment: .leading) {
                    HStack {Text("连接日志").font(.subheadline).foregroundStyle(.secondary);Spacer();ShareLink(item:vpn.logs){Text("导出日志")}.disabled(vpn.logs.isEmpty)}
                    Text("仅保留最近 120 条，最多 32 KB；旧记录自动删除。").font(.caption).foregroundStyle(.secondary)
                    ScrollView {
                        Text(vpn.logs.isEmpty ? "连接后显示协商日志。" : vpn.logs)
                            .font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(12)
                    }.background(.background, in: RoundedRectangle(cornerRadius: 12))
                }
                Text(vpn.hillstone ? "后台保持连接 · 网络恢复自动重连 · 手动断开后停止" : "连接时自动读取新令牌 · 读取失败可手动输入 · 令牌不保存").font(.caption).foregroundStyle(.secondary)
            }.padding(24).background(Color(.systemGroupedBackground)).navigationTitle("一键连接 1.4.2")
            .sheet(isPresented: $showSettings) { if vpn.hillstone {HillstoneSettingsView(vpn:vpn)}else{SettingsView(vpn: vpn)} }
            .sheet(item:$vpn.certificatePrompt,onDismiss:{vpn.answerCertificate(false)}){certificate in
                NavigationStack{Form{
                    Text("此网关的证书未通过系统自动校验。确认是你要连接的网关后，信任一次即可。")
                    LabeledContent("网关",value:certificate.endpoint)
                    Text(certificate.subject)
                    Text("自动获取的指纹："+certificate.pin).font(.caption).textSelection(.enabled)
                    Button("信任并连接"){vpn.answerCertificate(true)}
                }.navigationTitle("首次连接：确认网关").toolbar{Button("取消"){vpn.answerCertificate(false)}}}
            }
            .sheet(isPresented: $vpn.needsManualToken, onDismiss: { token = ""; vpn.tokenReadFailure = "" }) {
                NavigationStack {
                    Form {
                        Section("输入当前 6 位动态令牌") {
                            Text(vpn.tokenReadFailure).font(.footnote).foregroundStyle(.secondary)
                            SecureField("6 位数字", text: $token).keyboardType(.numberPad).textContentType(.oneTimeCode)
                            Text("只用于本次连接，不会保存。下次连接将重新自动读取。").font(.footnote)
                        }
                        Button("连接") {
                            do {
                                try SiteSettings.validateToken(token)
                                let once = token; token = ""; vpn.needsManualToken = false
                                Task { await vpn.connect(token: once) }
                            } catch { vpn.error = error.localizedDescription }
                        }
                    }.navigationTitle("动态令牌").toolbar { Button("取消") { token = ""; vpn.needsManualToken = false } }
                }.presentationDetents([.medium])
            }
            .alert("连接提示", isPresented: Binding(get: { vpn.error != nil }, set: { if !$0 { vpn.error = nil } })) {
                Button("确定", role: .cancel) { vpn.error = nil }
            } message: { Text(vpn.error ?? "") }
        }
    }
}
@MainActor struct SettingsView: View {
    @ObservedObject var vpn: VPNController
    @Environment(\.dismiss) private var dismiss
    @State private var draft = SiteSettings()
    @State private var message: String?
    var body: some View {
        NavigationStack {
            Form {
                Section("账号与连接设置") {
                    TextField("VPN 网关", text: $draft.gateway).keyboardType(.decimalPad)
                    TextField("XAuth 用户名", text: $draft.username)
                    SecureField("XAuth 密码", text: $draft.password)
                    SecureField("明文 PSK", text: $draft.psk)
                    TextField("本地标识（可选）", text: $draft.localID)
                    TextField("VPN DNS", text: $draft.dns).keyboardType(.decimalPad)
                }.textInputAutocapitalization(.never).autocorrectionDisabled()
                Section {
                    Toggle("使用服务端多轮令牌挑战", isOn: Binding(get: { !draft.appendToken }, set: { draft.appendToken = !$0 }))
                    Text("默认发送密码 + 令牌。多轮模式依次应答密码、令牌、密码加令牌。账号与 PSK 保存在本机钥匙串。").font(.footnote)
                }
                if let message { Text(message).foregroundStyle(.red) }
            }.navigationTitle("连接设置").toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("取消") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) { Button("保存") {
                    do { try vpn.save(draft); dismiss() } catch { message = error.localizedDescription }
                } }
            }.onAppear { draft = vpn.settings }
        }
    }
}
@MainActor struct HillstoneSettingsView:View {
 @ObservedObject var vpn:VPNController
 @Environment(\.dismiss) private var dismiss
 @State private var draft=HillstoneSettings()
 @State private var message:String?
 var body:some View {NavigationStack{Form{
  Section("Hillstone 连接设置"){
   TextField("网关 IPv4",text:$draft.gateway).keyboardType(.decimalPad)
   TextField("端口",value:$draft.port,format:.number).keyboardType(.numberPad)
   TextField("用户名",text:$draft.username)
   SecureField("密码",text:$draft.password)
   Button("重新信任证书"){draft.certificatePin=""}.disabled(draft.certificatePin.isEmpty)
   Toggle("允许此网关使用旧版 TLS",isOn:$draft.legacyTLS)
  }.textInputAutocapitalization(.never).autocorrectionDisabled()
  Text("证书由程序自动获取，无需填写。首次连接可能需要确认一次。账号保存在本机钥匙串。")
  if let message {Text(message).foregroundStyle(.red)}
 }.navigationTitle("Hillstone 设置").toolbar{
  ToolbarItem(placement:.cancellationAction){Button("取消"){dismiss()}}
  ToolbarItem(placement:.confirmationAction){Button("保存"){do{try vpn.saveHillstone(draft);dismiss()}catch{message=error.localizedDescription}}}
 }.onAppear{draft=vpn.hillstoneSettings}}}
}
