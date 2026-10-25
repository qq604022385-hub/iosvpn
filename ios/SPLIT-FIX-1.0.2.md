# 国内分流连接失败调整（1.0.2 / build 3）

## 设备反馈与判断范围

用户真机反馈：关闭“国内直连，国外走 VPN”可以连接，开启后失败；VPN DNS 为 `1.1.1.1`。截图只显示 `FortiCore.ProfileError error 0`，未包含原始失败原因。

源码检查确认：两种模式使用相同的 IKE / PSK / XAuth / OTP 协商，主要差异是国内排除路由。分流模式安装 5495 条国内网段，加上 4 条本地网段和网关 /32，共 5500 条；全局模式为 5 条。`1.1.1.1` 不在这批排除规则内，所以不会触发国内 DNS 冲突检查。5495 条国内网段已经合并，不能通过简单聚合进一步减少而保持原有范围。

**截图不足以确定底层错误，更没有证明 iOS 存在某个固定路由数量上限。** 本次提供分流兼容性调整和诊断修复；是否解决这台设备的问题需要安装新版本复测。

## 本次修改文件

| 文件 | 修改内容 |
| --- | --- |
| `ios/App/VPNController.swift` | 国内分流时设置 `enforceRoutes = false`，使用普通系统路由；全局模式保留原有强制路由。读取共享钥匙串中的诊断，即使扩展已停止也能显示原始失败。按 attemptID 过滤旧连接的日志。 |
| `ios/Core/SiteSettings.swift` | `ProfileError` 增加 `CustomNSError`，明确写入 `NSLocalizedDescriptionKey`；新增实际构造 `NSError` 的接口，避免系统跨进程传递时只剩 `error 0`。 |
| `ios/Shared/KeychainStore.swift` | 使用已有共享钥匙串权限，新增独立诊断记录。只保存随机 attemptID、阶段、错误和原生日志已遮蔽的最近 80 行，覆盖为下一次连接的诊断；不保存令牌值，也不把配置中的账号密码或 PSK 复制到诊断记录。 |
| `ios/Tunnel/PacketTunnelProvider.swift` | 认证前准备排除路由并复用，避免认证后重复读取规则；记录路由数量、DNS、安装耗时、系统错误域与错误码；在阶段变化及失败时保存诊断；向系统返回明确构造的 NSError。保留路由安装阶段，避免并发的原生令牌清除日志覆盖它。 |
| `ios/Tests/FortiCoreTests.swift` | 新增错误描述经 NSError 属性序列化后的恢复测试，以及完整国内快照下默认 DNS / 两种路由模式的测试。 |
| `ios/scripts/verify_source.py` | 新增路由模式、持久诊断、显式 NSError 描述的集成检查。 |
| `ios/project.yml` | 主应用和扩展更新为 1.0.2 / build 3。 |
| `ios/VERIFICATION.md`、本文件 | 记录判断依据、修改、验证范围及设备复测方法。 |

所有 5495 条国内网段均保留。没有更改密码、令牌模式、IPsec 加密参数、DNS 服务器或 IPv6 默认路由配置。此前 1.0.1 的工作线程、取消和超时修复也保留。

## 路由方式变化的实际边界

分流现在使用系统普通路由，而不是强制把每条排除规则作用于网络连接。国内目标按排除规则直连，其他 IPv4 目标使用 VPN 默认路由。系统中更具体的本地路由，以及 App 明确绑定的网络接口，可能优先于 VPN 路由。因此不能把这一兼容性调整当作所有 App、DNS 和 IPv6 都已通过防绕行验证；这些行为需要设备复测。

依据：[Apple 路由说明](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)、[enforceRoutes 属性](https://developer.apple.com/documentation/networkextension/nevpnprotocol/enforceroutes)。错误描述处理依据：[Apple CustomNSError](https://developer.apple.com/documentation/Foundation/CustomNSError)。这些文档说明 API 行为，不是该设备失败原因的证据。

## 验证与交付

- 源码集成检查通过，原始国内快照 SHA256 和 5495 条规则保持一致。
- Python 脚本编译检查通过。
- 主机工具回归测试 9 项通过；完整 Bash 构建日志测试 1 项因本机没有 Bash 跳过。
- 新增 Swift XCTest、iOS SDK 类型检查、C 等待循环测试、原生链接及 IPA 构建由现有 GitHub macOS 工作流执行。本机没有 Swift / iOS SDK，不能声称已经执行了这些测试或确认真机分流成功。

上传 `ios/artifacts/FortiOneTap-iOS-source.zip` 的解压内容，合并到 GitHub 仓库根目录，保留 `.github`。重新运行 Actions 打包，签名主应用和扩展，安装版本 1.0.2 / build 3。

保持 DNS `1.1.1.1`，使用新令牌开启国内分流测试。如果仍失败，复制 App 中完整的连接日志；应能看到“开始安装 … 5500 条排除路由”、安装结果或超时阶段。若有系统安装错误，会同时包含系统错误域和错误码。然后检查国内 / 国外访问、DNS、IPv6 和断开后的网络恢复。
