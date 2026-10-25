# iOS 1.4.8 / build 13

本次增加 H 的 UDP 源地址绑定与源端口恢复，以及 F 协商无应答时的新令牌 NAT-T 重试。交付 artifacts/FortiOneTap-iOS-1.4.8-source.zip，需重新编译签名安装；Apple SDK、IPA 和真实 Wi-Fi 尚未验收。

# 1.4.3 / build 12 自动重连（2026-10-21）

Forti / Hillstone 均支持后台自动重连和系统 On Demand。Forti 短暂断网保留原会话；会话失效后先清理旧引擎，再从真实接口获取新令牌重新认证。取码代码在 Shared/TokenClient.swift，主应用及 VPN 扩展共用；不保存或重放令牌。手动断开先关闭 On Demand；认证失败和证书变化停止重试。接口已实测 HTTP 200。

本次按用户要求只交付 `ios/artifacts/FortiOneTap-iOS-1.4.3-source.zip`。源码集成、16 项主机工具及 C 原生检查通过；Apple SDK 编译、Swift XCTest 和 iPhone 断线恢复留待用户后续打包验收。详情见根目录 RECONNECT-1.4.3.md。以下保留历史记录。

# 一键连接 iOS 完整源码：Forti / Hillstone

## 1.4.2 / build 11

Forti 一键连接在系统 VPN 授权完成后，自动从 `http://47.103.139.56:9000/api/key` 获取纯六位数字令牌；失败时显示手动输入窗口。保留前导零，每次连接重新读取，不缓存、不落盘、不写入日志或 VPN 配置。主应用的 HTTP 例外限定为该 IP，兼容 iOS 17 及更新系统的 ATS 限制。新增三项令牌解析 XCTest，待 Apple 环境执行；本机仅完成源码和主机工具检查。接口目前返回 502，真实自动取令牌和 VPN 认证待服务恢复后验收。

源码包：`ios/artifacts/FortiOneTap-iOS-1.4.2-source.zip`。本次没有生成 IPA。

## 1.4.1 / build 10

Hillstone 新增系统自动连接和扩展内后台重连：心跳失效、网络切换与会话到期后自动重新认证，重新安装路由并验证加密 DNS。手动断开先保存关闭自动连接，再停止隧道；证书变化或账号被拒绝会停止重试。Forti 同时移除短暂网络异常约 6 秒就主动断开的行为，保留原会话等待网络恢复并验证加密通道；一次性动态令牌仍不能用于完整会话失效后的自动重新登录。

源码包：`ios/artifacts/FortiOneTap-iOS-1.4.1-source.zip`。修复详情见根目录 `NETWORK-IOS-1.4.1.md`。本版尚待 Apple SDK 编译、签名安装与 iPhone 锁屏长时间验收；不承诺系统终止或无网时零中断。

## 1.4.0 / build 9

两种引擎改用共享 DNS 和路由策略：国内域名直连解析、相关 A/CNAME 答案增加临时 /32 直连路由、CN IP 直连、其他 IPv4 走 VPN。保留现有离线域名和 CN 网段规则。Forti 同步使用 /1 路由、MTU 1280、MSS 1160 和 IPv6 快速回退，并在连接成功前验证加密 DNS 往返。Hillstone 心跳超时会明确提示认证已通过但 UDP 通道无回包，并记录实际 UDP 端口。

详见 `NETWORK-IOS-1.4.0.md`。这是源码更新，Apple 编译、安装及真机速度验收待完成；Wi-Fi 上官方客户端也心跳超时的问题不能由分流规则保证解决。

## 1.3.5 历史记录

当前交付 `FortiOneTap-iOS-1.3.5-source.zip`，主应用/扩展 1.3.5/build 8。修复 Forti 的 8 线程饥饿，加入 VICI 控制自检；Hillstone 在加密隧道内比较 Google DNS 与 1.1.1.1，选择先有效回应的一方，保留私有及自定义 DNS，增加 TCP 握手耗时和 SYN 重试统计。26 项 C 检查、真实 strongSwan 调度回归、16 项主机回归通过。新 Apple 构建、IPA 和真机效果尚未验收。详见根目录 NETWORK-IOS-1.3.5.md。

## 1.3.4 历史记录

当前交付 `FortiOneTap-iOS-1.3.4-source.zip`，主应用/扩展 1.3.4/build 7。修复休眠主动断开，增加暂停后的心跳恢复；国内 DNS 支持 HTTPS/SVCB 与合法无记录响应；增加 DNS 耗时、系统停止原因和 Forti 协商阶段。22 项实际 C 检查与 16 项主机回归通过。新 Apple 编译、IPA 和真机结果尚未验收；Forti 本次超时根因仍待其失败日志。详见根目录 NETWORK-IOS-1.3.4.md。

## 1.3.3 历史记录

当前交付 `FortiOneTap-iOS-1.3.3-source.zip`，主应用/扩展 1.3.3/build 6。修复国内 DNS 被 ESP 单套接字等待拖延，批量写回并限制入站批次；日志限 120 条/32 KiB，异步合并持久化，增加真实进程内存指标。新 IPA、iPhone 速度及长时间内存尚未验收，需要重新构建签名安装。详情在根目录 NETWORK-MEMORY-1.3.3.md。

## 1.3.2 及以前的记录
当前交付 `FortiOneTap-iOS-1.3.2-source.zip`，主应用及扩展 1.3.2/build 5。调整蜂窝路由优先级、读取启动顺序、IP 头校验，并记录真实应用数据的读入/转发/本地回复/写回计数。不是已验收的 IPA；本轮未完成 Apple 编译和 iPhone 蜂窝联网验证，需重新构建签名安装。详见源码包根目录 NETWORK-THROUGHPUT-1.3.2.md。

## 历史版本记录
当前交付 `FortiOneTap-iOS-1.3.1-source.zip`，主应用及扩展 1.3.1/build 4。同步 111724 条成熟域名规则及独立 C 引擎，安装路由后验证实际 DNS 往返，并保留、导出连接日志。新 Apple 构建/IPA 和 iPhone 蜂窝联网尚未验收；需要重新编译签名安装。日志中可看到明确版本、DNS 失败和 tx/rx 计数，连接失败后仍保留。

2026-10-11 网络修复版为 1.3.0（主应用及扩展 build 3）。针对蜂窝网络加入 Hillstone MTU 1280、TCP MSS 上限 1160、UDP AAAA 本地无记录响应及 IPv6 ICMP 无路由快速回退。开启国内分流后，`.cn` 和常见国内站点 A 查询直接使用 223.5.5.5，1.5 秒未取得有效结果回退网关 DNS；其他域名继续使用网关 DNS。完整策略列表在 `Native/split_dns.h`。

本轮实际 C/OpenSSL 网络测试、源码及主机工具检查通过。修复后的 Swift/iOS SDK/Xcode 编译、IPA 和 iPhone 蜂窝网络效果仍待确认；当前 GitHub 连接对原 vpn 仓库返回 404，无法自动启动 Apple 构建。请用本次完整源码包重新构建和安装，旧 IPA 不包含这些修复。

一个应用内选择 Forti / IPsec 或 Hillstone / SCVPN，分别保存账号，提供国内直连、国外走 VPN。SwiftUI 主应用与 NEPacketTunnelProvider 扩展使用内置 strongSwan 6.1.0 和独立 C SCVPN 引擎，不调用官方 Hillstone 客户端、服务或私有 SDK。

本次按要求交付完整源码包，包含两种引擎源码、锁定哈希的 OpenSSL 3.6.5 源码归档、5495 条 CN IPv4 规则、测试、XcodeGen 工程定义及构建脚本。

当前交付是待 Xcode 云端编译和真机验收的源码；本机源码校验通过不代表 IPA 已成功生成，也不代表真实网关已连通。

## 上传到你的仓库

目标仓库：https://github.com/qq604022385-hub/vpn

`ios/artifacts/FortiOneTap-iOS-source.zip` 是独立源码上传包。先解压，再把解压后的内容上传到仓库根目录，保持以下结构；只上传 ZIP 文件本身不会启动打包。

```text
.github/workflows/ios-ipa.yml
COPYING
AUTHORS
README.md
SOURCE-MANIFEST.json
vendor/strongswan-source.tar.gz
vendor/strongswan-source.sha256
ios/project.yml
ios/Package.swift
ios/App/...
ios/Tunnel/...
ios/Native/...
ios/Core/...
ios/scripts/...
```

此包包含本次移植所需内核源码快照；不包含 Windows EXE、DPAPI 配置、真实账号、密码、PSK、证书、缓存或本机测试日志。根目录 `COPYING` 保留 strongSwan 许可。已有其他源码时只合并新增 iOS 文件，不删除已有 Windows/Android 文件。

GitHub 网页上传时必须保留 `.github` 隐藏目录。也可以使用 GitHub Desktop 将解压后的目录作为本地仓库上传。仓库已有内容时先拉取并合并这些文件，不强制覆盖分支。

## 生成未签名 IPA

1. 上传源码后，打开仓库的 **Actions**。
2. 如 GitHub 提示工作流尚未启用，启用仓库的 Actions。
3. 选择 **iOS Unsigned IPA**，点击 **Run workflow**，选择源码所在分支并运行。
4. 成功后，在该次运行页面的 **Artifacts** 下载 **FortiOneTap-unsigned-ipa**。
5. 解压下载的 artifact ZIP，得到 `FortiOneTap-unsigned.ipa`、SHA256 校验文件及 IPA 结构验证报告。
6. 失败时下载 **ios-build-diagnostics**，先看 `xcodebuild.log`、`strongswan.log` 或 `openssl.log` 对应的错误。

工作流会先运行 Swift 共享逻辑测试，再交叉编译 OpenSSL 和 strongSwan，生成 Xcode 双目标工程，编译 iPhone/iPad 的 arm64 应用并打包。它会检查应用、嵌入 VPN 扩展、Mach-O 架构/设备平台以及内置 CN 路由资源；缺少真实编译产物时直接失败。工作流无需签名 Secrets。

默认 Bundle ID 是 `me.longxuan.fortionetap`，扩展是 `me.longxuan.fortionetap.Tunnel`。可在 `ios/project.yml` 修改 `BUNDLE_ID`；扩展 ID 由主应用 ID 自动加 `.Tunnel` 得到。

## 安装与签名

此 IPA 未签名，不能直接安装运行。之后签名时，需要同时签名主应用及其 `PlugIns/FortiTunnel.appex`，给两者保留 `com.apple.developer.networking.networkextension = [packet-tunnel-provider]`，并让两者共享主应用的 `keychain-access-groups`。

实际签名证书及 provisioning profile 必须允许这些权限。只给主应用签名、删除扩展或丢失共享钥匙串权限，会导致 VPN 不启动或无法读取账号。未签名构建不需要提供 Apple 账号；实际可用性由后续签名权限和真机测试确认。

先选择连接方式。Forti 填写 XAuth 用户名、密码和明文 PSK。Hillstone 填写公网 IPv4、端口（默认 4433）、用户名和密码；证书自动获取，无需手填指纹。系统验证通过则自动保存信任，否则首次连接确认一次；已保存证书变化会在发送账号密码前停止，核实后可在设置中“重新信任证书”。旧网关需显式开启“允许此网关使用旧版 TLS”。Forti 以后点“一键连接”只输入当前 6 位动态令牌，并同意 iOS 的 VPN 配置权限。不要将账号密码或 PSK 写入源码、GitHub 或构建日志。

## 功能对应与平台差异

| Windows 功能 | iOS 实现/边界 |
| --- | --- |
| 网关、用户名、密码、PSK、本地标识、DNS 设置 | 对应 SwiftUI 设置页面，默认网关与 DNS 相同 |
| DPAPI 加密保存 | 改为设备钥匙串，主应用与 VPN 扩展共享访问 |
| 每次输入 6 位动态令牌 | 只经本次启动参数传递，内核内存使用；认证完成卸载 PIN 凭据，不写入 VPN 配置或日志 |
| 密码 + 令牌 / 多轮挑战 | 复用 Windows 的 XAuth 实现，多轮依次密码、令牌、密码加令牌 |
| IKEv1 Aggressive、PSK/XAuth、Mode Config、强制 NAT-T | 复用 strongSwan 实现及相同协商参数 |
| AES128/SHA1 或 AES256/SHA256，DH5 | Phase 1 参数相同 |
| AES128/SHA1 或 AES256/SHA1，PFS DH5 | Phase 2 参数相同，期限 43200 秒 |
| 国内直连、国外 VPN | 复用 5495 条 APNIC CN IPv4 网段，通过 iOS 排除路由覆盖普通 App 流量 |
| 全局 IPv4 VPN，私有网直连 | 全局 IPv4 包进入 IPsec，私有网及网关排除 |
| 隧道 DNS | 系统 DNS 使用所选服务器，捕获到的其他标准 DNS 流量丢弃；IPv4 分片先完整校验，再将原分片交给 IPsec |
| Windows WFP 阻止直连路径上的其他 DNS | 普通 iOS Packet Tunnel 无法过滤已被系统排除路由直连的包；这项不能承诺完全相同 |
| IPv6 防绕行 | 配置 IPv6 默认路由捕获并丢弃 IPv6 包；iOS 系统保留流量与实际网络场景需真机确认 |
| 本机网络变化需新令牌 | 每 2 秒检查网关的物理源地址/接口，变化时结束隧道，不自动重连 |
| 取消、断开、断线清理 | 结束内核并移除本次 VPN 网络设置，OS 管理路由与 DNS 生命周期 |
| 关闭 Windows 窗口断开 | iOS 应用转入后台时 VPN 必须继续服务其他 App，系统独立管理扩展；在应用内点断开或系统 VPN 设置断开 |
| Wintun / 管理员权限 | 改为公开 NetworkExtension Packet Flow 与用户授权 |

“所有功能不变”无法字面成立：WFP 防火墙、系统保留流量和桌面窗口退出行为由 iOS 权限及生命周期决定。这里保留可移植功能，并明确上述边界，不能把路由配置视为已经证明零泄漏。

## 本地开发（Mac）

依赖：Xcode、Python 3.12+、autoconf、automake、libtool、pkg-config、XcodeGen。执行：

```bash
brew install autoconf automake libtool pkg-config xcodegen openssl@3
bash ios/scripts/build_unsigned.sh
```

脚本使用隔离的 `ios/build` 目录，不修改原 `src` 或 `windows`。重建前请使用干净 checkout 或清空 `ios/build` 中上一次构建的原生源码/依赖目录。优先使用仓库根目录的 `src`；独立上传包没有该目录时使用 `vendor` 中经过哈希验证的完整源码快照。

Shell 脚本必须使用 UTF-8 无 BOM、LF 换行；根目录 `.gitattributes` 固定 iOS 构建脚本的 Git 换行。CI 在执行构建脚本前检查 CRLF/BOM，并将结果保留到 `shell-script-check.log`。独立源码包必须同时上传 `.gitattributes`。

换行检查：`python3 ios/scripts/check_shell_scripts.py`。源码检查：`python3 ios/scripts/verify_source.py`。共享逻辑行为测试：`swift test --package-path ios`。

C 回归检查：`python3 ios/scripts/test_native.py`。它实际编译 SCVPN 实现并验证加密固定结果、解密、非完整块拒绝和会话生命周期，在 Mac 上也包含系统 libc 头文件检查；只使用主机 OpenSSL，不访问网关，不替代 iOS 编译。完整构建会先运行此检查，再执行 Swift 测试、真实 iOS 原生编译、完整静态符号链接检查和 Xcode 双目标构建。

主机 C 检查显式选择 macOS SDK，并通过 `-isysroot` 与子进程 `SDKROOT` 传给 Clang；不会沿用 iPhone SDK 或 iOS 部署目标。日志会打印所选 SDK，缺少 `stdlib.h` 时在编译前明确报错。

## 验收状态

详见 `ios/VERIFICATION.md`。需要云端 Xcode 编译、正确签名、iPhone 首次授权、实际网关认证及分流/DNS/IPv6/断线恢复测试。禁止用本机静态检查或模拟 fixture 冒充真实 IPA 或真机连通证据。

## 参考

- Apple Packet Tunnel：https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
- Apple 路由说明：https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic
- Apple enforceRoutes：https://developer.apple.com/documentation/networkextension/nevpnprotocol/enforceroutes
- strongSwan 用户态 IPsec：https://docs.strongswan.org/docs/latest/plugins/kernel-libipsec.html
- GitHub macOS runner：https://docs.github.com/en/actions/reference/runners/github-hosted-runners
## Hillstone 协议与验证范围

当前独立引擎实现已验证网关的 TLS 认证、虚拟地址和 DNS 下发、3DES/SHA1 ESP UDP 数据通道、心跳、证书固定及取消清理。它按协议解析并检查加密套件，不支持的压缩或重协商会停止连接，不承诺任意 Hillstone 网关兼容。iOS DNS 主机从国内/私有排除路由中扣除，确保系统指定 DNS 进入 VPN；捕获的 IPv6 丢弃。国内直连路径上的自定义 DNS 仍受前述平台边界限制。

Windows 同一独立协议引擎已经真实网关与系统 HTTPS 验证；这不等于 iPhone 验收。此包尚未完成新增 Hillstone Swift/C 桥接的 Xcode 编译与 iPhone 连接验证。历史 Forti 云端诊断记录保留在 VERIFICATION.md。
