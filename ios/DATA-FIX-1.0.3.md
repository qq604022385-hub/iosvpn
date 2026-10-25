# 已连接但网页 / 表情包不可用（1.0.3 / build 4）

## 当前证据

用户反馈：开启国内分流后 VPN 能连接，微信文字和部分图片正常，但浏览器打不开网页、表情包一直加载。尚未收到手机的连接日志，也尚未确认关闭分流后的网页情况。

国内分流下，微信部分流量可能通过直连路径或现有连接发送；这不能证明经过 VPN 的 DNS 和数据流量正常。当前所选 DNS `1.1.1.1` 在国内排除规则之外，会经 VPN 默认路由访问。现象可能涉及 DNS 没有响应、数据通道无回包、远端转发或路径 MTU；**本次没有把其中任何一项当作已经证实的根因**。

检查发现两处确定的诊断缺口：Swift 之前忽略 `fot_input()` 的失败返回值和 `packetFlow.writePackets()` 的结果；现有日志只报告认证与路由安装，缺少数据收发证据。

## 本次修改

| 文件 | 修改内容 |
| --- | --- |
| `ios/Core/TunnelTraffic.swift`（新增） | 增加累计头部统计：系统 IPv4、引擎入队、解密回包、队列 / 系统写回失败、过滤或重组等待、IPv6 丢弃、所选 UDP DNS 请求 / 响应、TCP SYN / SYN-ACK 和虚拟源地址不匹配。非首片不被当作传输层头部。共享默认 MTU 为 1280。 |
| `ios/Core/DNSProbeMessage.swift`（新增） | 构造固定 `example.com` 的 A 查询，并检查回复的事务 ID、QR、Opcode、RCODE、截断位和答案计数。这里只诊断 UDP 响应，不替代系统 DNS 解析器。 |
| `ios/App/NetworkProbe.swift`（新增） | 用户点“测试网络”时并行测试：所选 DNS 的 UDP 53；`1.1.1.1:443` 的 TLS 握手（IP 目标）；`example.com:443` 的 TLS 握手（含系统域名解析）。每项最多 8 秒。采用默认 TLS 证书校验，完成后关闭测试连接。 |
| `ios/Tunnel/PacketTunnelProvider.swift` | MTU 从 1400 改为 1280；实际检查入队及写回结果；记录收发统计，返回实时诊断并每 10 秒保存统计检查点。统计只覆盖系统交给 VPN 的流量，国内直连包不在其中。 |
| `ios/Native/tun_device_ios.c` | 默认及可设置 MTU 上限统一为 1280；队列发送遇到 EINTR 时重试。没有改为无限等待或无限缓存。 |
| `ios/Native/FortiBridge.c` | 开启 ESP 的策略 / SA / SPI 不匹配错误信息；过滤正常逐包日志，并把这些二级错误限制为每秒最多一条。原有凭据遮蔽与载荷日志限制继续保留。 |
| `ios/App/VPNController.swift` | 执行网络测试并把结果保留在当前日志中，忽略旧连接的测试结果。 |
| `ios/App/FortiOneTapApp.swift` | 日志区域新增“测试网络”“复制”按钮，底部显示构建版本，便于确认实际安装的新版本。 |
| `ios/Tests/FortiCoreTests.swift` | 新增 DNS 收发方向与源地址、TCP 握手及非首片、固定 DNS 请求 / 回复相关性测试，共 16 个 XCTest 方法。 |
| `ios/scripts/verify_source.py` | 增加 Swift / 原生 MTU 一致性、数据通道返回值检查及网络测试入口的集成检查。 |
| `ios/project.yml` | 主应用增加 Network.framework；主应用及扩展版本升级为 1.0.3 / build 4。 |
| `ios/VERIFICATION.md`、本文件 | 记录证据、改动、验证范围和下一次手机测试方法。 |

调低 MTU 是针对加密 / UDP 封装后路径大包问题的兼容性调整，可能降低峰值效率；它不能修复无响应的 DNS 服务器或网关缺少转发。没有改动 DNS 服务器、国内网段、分流模式、IPsec 参数或 IPv6 丢弃策略。

统计的“引擎入队”只证明队列接受了明文包，并不证明 ESP 已成功发出或远端已收到；“解密回包”表示原生 IPsec 引擎交回了明文包。UDP DNS 包计数包含重试与其他查询，不能当作完整 DNS 事务成功率。“过滤/重组等待”也不全是永久丢包。

## 设备复测与结果判断

1. 将 `ios/artifacts/FortiOneTap-iOS-source-1.0.3.zip` 解压内容合并上传到仓库根目录，保留 `.github`，通过 Actions 构建并签名安装。
2. 确认 App 底部显示 **v1.0.3**，保持目前分流 / DNS 设置并使用新令牌连接。
3. 点击“测试网络”，再尝试打开网页，等待约 10 秒；点击“复制”，把完整日志发回。
4. 如方便，用新令牌关闭分流重新连接，重复测试，作为对照。

| 观察结果 | 后续检查方向（不是定论） |
| --- | --- |
| UDP DNS 超时，但 IP 目标 TLS 成功 | UDP 53 / 所选 DNS 的可达性；可以在设置中换 DNS 后比较。 |
| IP TLS、UDP DNS 都失败，入队不断增加、解密回包为 0 | 策略 / 源地址 / ESP 传输或网关转发；检查原生错误和网关日志。 |
| 入队失败或系统写回失败增加 | Packet Flow 与原生队列通道。 |
| IP TLS 成功，含域名 TLS 失败 | 系统解析路径、IPv6 回退或该测试目标的访问；不据此判断所有域名都不可达。 |
| 连接测试正常，但大内容仍卡住 | 路径 MTU、TCP、具体站点 / 协议和网关策略。 |

测试仅访问固定诊断目标。日志不记录 DNS 查询内容、URL 或浏览历史，但原生错误可能包含用于排查策略不匹配的 IP 地址。单个测试目标失败也可能是该目标或路径问题，需要和统计及其他测试一起判断。

## 验证范围

- 源码集成检查、Python 编译检查通过；国内 5495 条快照保持原 SHA256。
- 主机工具回归 9 项通过，1 项 Bash 日志测试因本机缺少 Bash 跳过。
- 本机 HTTPS 测试目标返回了响应，用于检查目标有效性；这不是手机经 VPN 访问的证据。
- Windows 本机没有 Swift 编译器 / iOS SDK。新增 XCTest、Network API 的 iOS 类型检查、原生编译链接和设备 IPA 构建需由 GitHub macOS 工作流执行。没有运行手机上的探测，也没有确认本次已恢复网页 / 表情包。

参考：[Apple DNS 匹配规则](https://developer.apple.com/documentation/networkextension/nednssettings/matchdomains)、[Apple NWConnection](https://developer.apple.com/documentation/network/nwconnection)、[strongSwan 转发与 MTU](https://docs.strongswan.org/docs/latest/howtos/forwarding.html)。这些资料说明排查方法，不是该设备根因的证明。
