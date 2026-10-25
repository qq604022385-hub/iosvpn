# 1.4.3 / build 12 自动重连（2026-10-21）

Forti / Hillstone 均支持后台自动重连和系统 On Demand。Forti 短暂断网保留原会话；会话失效后先清理旧引擎，再从真实接口获取新令牌重新认证。取码代码在 Shared/TokenClient.swift，主应用及 VPN 扩展共用；不保存或重放令牌。手动断开先关闭 On Demand；认证失败和证书变化停止重试。接口已实测 HTTP 200。

本次按用户要求只交付 `ios/artifacts/FortiOneTap-iOS-1.4.3-source.zip`。源码集成、16 项主机工具及 C 原生检查通过；Apple SDK 编译、Swift XCTest 和 iPhone 断线恢复留待用户后续打包验收。详情见根目录 RECONNECT-1.4.3.md。以下保留历史记录。

# 1.4.2 / build 11 自动读取令牌（2026-10-20）

源码集成、16 项主机工具及 shell 换行检查通过。新增 3 项 Swift 令牌解析 XCTest 待 Apple 环境执行；未生成 IPA。接口返回 502，真实取码及 iPhone 登录待验收。详见根目录 AUTO-TOKEN-1.4.2.md。以下保留历史记录。

# 本次交付验证（2026-10-11）

1.3.3 build 6：16 项 C/OpenSSL、6 项真实 loopback 数据通路/等待测试、16 项主机工具及源码检查通过。国内 DNS 旧等待 218 ms 未交付，新实现 31 ms 交付；不是 iPhone 时间。Swift 长期日志/批次用例已加入，本轮未在 Apple 环境运行，新 IPA 和真机内存/速度仍待验收。详见 NETWORK-MEMORY-1.3.3.md。

## 1.3.2 及以前的记录
1.3.2 build 5：修改蜂窝路由优先级和 packetFlow 读取/识别/写回并增加分层计数。16 项同源 C/OpenSSL、16 项主机工具、源码校验通过。新增 Swift 用例尚未在 Apple 环境运行，新 IPA 和 iPhone 联网仍未验收；不能以原生 DNS 自检替代应用流量证明。详见 NETWORK-THROUGHPUT-1.3.2.md。

## 1.3.1 网络校验与诊断

同步 Loyalsoldier 111724 条精确/后缀规则和 C DNS 校验，接入 NE 路由安装后的 DNS 预检；失败清理路由，主应用可在断开后读取共享钥匙串中的操作日志并导出。15 项 C/OpenSSL 检查、16 项主机工具检查、源码检查通过。Windows 同源引擎经过真实网关三次重连和 9 次 HTTPS，但不是 iPhone 证据。新 Swift/iOS SDK 编译、IPA、正确签名与蜂窝真机效果未完成；GitHub 原仓库仍返回 404。

## 1.3.0 蜂窝网络修复

加入国内域名 A 查询直接解析与超时网关回退、UDP AAAA NODATA、IPv6 ICMP 快速回退，以及 Hillstone MTU 1280、TCP MSS 1160。15 项实际 C/OpenSSL 检查、16 项主机工具检查及源码检查通过。C 检查使用本机 Windows 编译器/实际 OpenSSL，包含真实 loopback UDP 转发和超时后加密回退；不是 Apple SDK 或 iPhone 证据。主应用及扩展版本为 1.3.0/build 3，完整源码已打包。本轮 GitHub 对原 vpn 仓库返回 404，无法代运行 Apple 构建；修复后 Swift/iOS SDK 编译、IPA、签名安装和 iPhone 蜂窝/Wi-Fi/网络切换验收仍未确认。下列为历史构建诊断。

## 主机 C 测试的 macOS SDK 修复（2026-10-11）

- 本次用户提供的 `ios-build-diagnostics.zip` 仅包含换行、主机和 C 测试日志。14 项主机测试通过，随后新增的主机 C 测试因 `stdlib.h` 缺失失败，尚未进入 Swift/iOS 原生构建。
- 根因是脚本通过 `xcrun --find clang` 取得可执行路径后直接调用，却没有把主机 SDK 传给该进程。现显式查询 `xcrun --sdk macosx --show-sdk-path`，确认该 SDK 的 `usr/include/stdlib.h` 存在，并同时设置 Clang `-isysroot` 和子进程 `SDKROOT`。
- 主机测试先清除继承的 SDKROOT、IPHONEOS_DEPLOYMENT_TARGET 和 MACOSX_DEPLOYMENT_TARGET，避免混用 iPhone SDK/部署目标；保留 DEVELOPER_DIR，让编译器和 SDK 来自同一 Xcode 选择。
- 本机 16 项主机测试与 4 项实际 C 测试通过，源码及 Python 编译检查通过。新增两个用例只验证 Mac 编译命令/环境选择和缺失 SDK 标准头的提前拒绝，不冒充实际 Apple SDK 编译。
- 独立源码包再次解压并执行主机/实际 C/源码检查，核对 ZIP CRC、SHA256、清单及依赖哈希。云端修复后的主机 C 测试、完整 iOS 构建和 IPA 尚需 macOS CI 运行结果确认。

## SCVPN 平台编译冲突与构建检查补齐（2026-10-11）

- 最新 `ios-build-diagnostics (1).zip` 证明换行检查、14 项主机测试、15 项 Swift XCTest 以及三个 iOS SDK 类型检查均通过；OpenSSL 和 strongSwan 三个静态库已编译。桥接日志唯一编译错误为 `scvpn.c` 的私有 `crypt` 函数与 iOS `unistd.h` 声明冲突；其余三份桥接 C 文件编译完成，libvici 仅有指针符号警告。
- 已将私有函数及加解密两个调用改为 `hs_esp_cipher`，不改变算法、协议、密钥或调用参数。
- 新增实际 C 源码回归测试：Windows 使用匹配的 MinGW/OpenSSL，Mac 使用 Xcode 主机 Clang/OpenSSL。Windows 测试显式加入同签名 libc 声明，在 Mac 上使用真实系统头文件；检查 3DES-CBC 固定密文、解密、非完整块拒绝和无网络会话生命周期。本机完整 C 编译、链接及 4 项测试通过。
- CI 安装主机 `openssl@3` 并在完整构建入口执行上述 C 测试。SCVPN 的真实 iOS C 编译提前到 OpenSSL 之后、strongSwan 之前，复用该对象，不再到桥接阶段才发现独立源码问题。
- 保留桥接多源错误汇总、全部静态符号的 iOS 动态库链接检查、Xcode 主应用/扩展 Release 编译和真实 IPA 校验；未关闭任何失败检查或用模拟产物替代真实编译。
- 本机 14 项主机测试、4 项 C 测试、源码检查、Python 编译检查、两个 Bash 语法检查、工作流/工程 YAML 解析及工程输入路径检查通过。生成的独立源码包重新解压验证并重跑源码/主机/C 检查；源文件、清单、CRC、依赖哈希和 ZIP SHA256 已核对。
- 当前 GitHub 连接对 `qq604022385-hub/vpn` 返回 404，GitHub App installations 为空。本次尚未推送或启动云端 CI；原生完整静态链接、最终 Xcode 构建、IPA 和真机验收不能声明通过。要继续自动修复至真实 IPA，需要仓库访问与构建权限。

## 构建脚本 CRLF 修复（2026-10-11）

- 用户提供的 `ios-build-diagnostics.zip` 显示 10 项主机测试、15 项 Swift XCTest 及 Core/App/Tunnel 的 iOS SDK 类型检查通过；随后在 `build_native.sh` 第 2 行因 `pipefail\r` 退出。本次运行尚未进入原生编译和 IPA 打包。
- 已将两个 iOS 构建 Shell 脚本转为 UTF-8 无 BOM、LF；新增根目录 `.gitattributes` 固定这些脚本的 Git 换行。
- 新增 `check_shell_scripts.py`，在 CI checkout 后、完整构建入口及源码打包前检查 CR/CRLF 和 BOM；CI 将检查结果保存到 `shell-script-check.log`。
- 本机 14 项主机工具测试通过，包含 LF 接受、CRLF 拒绝及路径/行号诊断、BOM 拒绝和缺失脚本拒绝；源码检查、Python 编译检查、两个 Bash 语法检查及 Git 换行属性检查通过。
- 源码打包器仅收录 App/Core/Native/scripts/Shared/Tests/Tunnel 及根目录文件，避免再次打入旧上传包的解压副本；包内包含 `.gitattributes` 和新增检查脚本。
- 本次为本机修复及验证，尚未推送 GitHub 或重新运行 macOS/Xcode CI；完整原生编译、IPA 与真机验收仍待验证。下列记录保留此前交付状态。

- 用户已选择先交付 iOS 完整源码包；此次没有交付 IPA。
- 新增独立 Hillstone SCVPN C 引擎、SwiftUI 连接方式选择、独立钥匙串配置、首次自动证书获取/系统校验/显式确认、证书变化拒绝和重新信任。
- VPN 扩展配置系统 IPv4 路由、5495 条 CN 规则、指定 DNS 主机强制入隧道、IPv6 捕获后丢弃，以及断开清理。
- 本机 `verify_source.py` 两组检查通过；`test_host.py` 10 项打包工具测试通过。
- 新增 Hillstone 共享逻辑 4 项 XCTest 已随源码交付，尚未在 Swift/Xcode 环境执行。
- 同源独立原生引擎的 Windows 真实网关认证、DNS、系统 HTTPS 和 70 秒心跳测试通过，已结束并清理网络；这些结果不能替代 iPhone 验证。
- 此次新增 Hillstone App/扩展的 Swift 与 iOS C 编译、签名、安装及真机网络测试均待 Apple 环境执行。后附历史记录仅用于保留已有 Forti 构建诊断。

# 验证记录（2026-10-09，Asia/Shanghai）

## 本机完成

- 按 `windows/Core.cs`、`Engine.cs`、`UI.cs` 和 Windows 原生 XAuth 代码核对并编写 iOS 移植，原 Windows 源码未修改。
- `python ios/scripts/verify_source.py` 通过：协商参数的源码一致性、令牌生命周期相关调用、两目标 VPN 权限声明、嵌入扩展及路由资源。
- CN IPv4 快照原样复用，5495 条，SHA256：`58790ccf97a41759d9ce05dca1118b756079956808f4241a29f58358d129e39b`。
- `python ios/scripts/test_host.py`：7 项通过，覆盖内核源码准备、XAuth/PIN 补丁、设备平台/架构识别、Payload/扩展结构、损坏规则拒绝、签名材料拒绝、构建目录边界。
- 主机测试使用明确的合成 Mach-O 结构 fixture；仅测试打包/验证器，fixture 存放在临时目录并清理，没有将其作为可安装 IPA 交付。
- `python -m compileall -q ios/scripts` 通过。
- Git Bash `bash -n` 对两个构建脚本检查通过。
- `project.yml` 与 `ios-ipa.yml` 通过 YAML 解析及双目标/工作流入口检查。
- 本机实际执行内核源码隔离准备及补丁；保留 OpenSSL plugin 原始源码，未使用 Windows 二进制替代 iOS 内核。
- 独立源码包包含 `.github` 工作流、iOS 文件和原内核源码快照；不包含 Windows DPAPI 配置/EXE 或签名私钥。

以上是源码和打包工具验证，不是 iOS 原生编译、VPN 协商或网络泄漏的运行证据。

## 首次云端运行（用户提供的 Actions 日志）

- 主机工具 7 项测试通过。
- FortiCore 已在 macOS arm64 上成功编译，11 项 XCTest 全部通过。
- 根据脚本顺序，日志已越过 OpenSSL 构建及依赖安装，并完成内核源码准备；没有获取到 OpenSSL 单独日志。
- 后续 strongSwan 阶段返回 exit 1；最初的外层日志未包含具体原因。随后读取诊断 ZIP，已确认是 configure 中的 C23/gperf 不兼容，详见下节。
- iOS 主应用/扩展的 Xcode 构建和真实 IPA 仍未完成。
- 已修复构建脚本隐藏报错的问题：失败时在 Actions 输出当前阶段日志尾部，保留原失败退出码，并保留完整诊断 artifact。

## 首次云端失败根因及修复（诊断 ZIP 已读取）

- `strongswan.log` 确认失败在 configure 的 `gperf len type` 探测；autoreconf 成功，尚未开始 make。
- `config.log` 中的实际编译器为 Xcode 16.4 Apple Clang，命令使用 `-std=gnu23`。macOS gperf 3.0.3 生成 K&R 函数，Apple Clang 报 `unknown type name 'str'/'len'`，两种长度参数探测都失败。
- `build_native.sh` 已给引擎 CFLAGS 及桥接编译参数显式加 `-std=gnu11`，保留完整探测，不跳过 gperf 检查。
- 同一日志显示 nm 未被正常识别并退回 `link -dump`；构建脚本现在通过 Xcode `xcrun` 明确选择 NM。
- 已将日志里真实的 unsigned-length 探测源码交给项目 GCC 16.2 编译：GNU C11 无错误/警告；模拟前置 GNU C23、后置 GNU C11 的参数顺序也通过。这是 Windows 编译器的正向兼容验证，不是 Apple Clang/iOS 编译证据；GCC 的 GNU C23 仍接受此旧式语法作为扩展。
- Bash 语法检查及失败日志输出/退出码保留测试通过。需要更新 GitHub 的 `ios/scripts/build_native.sh` 后重跑 Actions，完整原生编译和 IPA 仍待验证。

## 第二次云端失败及修复（ios-build-diagnostics (1).zip）

- `gperf len type... unsigned` 已通过，编译器使用 C11；nm 已明确识别为 Xcode 的工具。上一处修复在云端生效。
- 配置继续推进，失败于 `scripts/git-version: /bin/sh^M: bad interpreter`。版本前缀报错是脚本没有执行成功后产生的连带错误。
- 原 `normalize_tree` 只按扩展名转换 CRLF，遗漏了没有扩展名的 `git-version`。已增加 shebang 检测，对这类文本脚本转换为 LF；二进制和普通文件保持原样，执行权限保留。
- 9 项主机工具测试通过，包含两个新增回归用例：无扩展名脚本换行/权限保留，以及二进制/普通文件保护。
- 已实际执行隔离准备后的 `scripts/git-version`，通过 shebang 正常启动并返回 configure 支持的 `UNKNOWN` 源码归档回退值。
- 此次 GitHub 更新只需替换 `ios/scripts/prepare_source.py`。本机测试及语法检查通过；云端后续 configure/make/Xcode/IPA 尚需新提交重新验证。

## 第三次诊断和整合修复

- 最新诊断 ZIP 的 strongSwan 日志显示 libstrongswan、libipsec、libcharon 三个静态库均已编译完成；其后的桥接阶段没有独立日志，尚不能从该 ZIP 确认最终 stderr。
- 源码检查发现桥接单独编译 libvici.c 时漏掉原 Makefile 提供的 IPSEC_PIDDIR 和 SWANCTLDIR。已补齐这两个定义；实际 libvici POSIX URI 分支在主机编译对照中缺少 IPSEC_PIDDIR 时失败、补齐时通过。主机兼容检查不等于 Apple SDK 编译证据。
- 桥接阶段现在保存 bridge-link.log，三个源文件分别编译并收集全部错误；静态库合并后用真实 iOS SDK 做完整符号链接检查。
- 新增 typecheck_ios.py，在编译原生引擎前分别检查 FortiCore、主应用及 VPN 扩展，使用真实 iPhone SDK 和 SwiftPM 生成的资源访问器；此检查尚待云端执行。
- 外层构建脚本捕获所有 stdout/stderr 到 full-build.log 并保留失败退出码，新增回归用例已验证退出码 7 和 stderr 不会丢失。
- 当前 10 项主机工具测试、源码检查、Python 编译检查及两个 Bash 语法检查全部通过。
- GitHub 插件已安装且登录账号确认为 qq604022385-hub；连接返回的 GitHub App installations 和可访问仓库列表均为空，README 和工作流读取返回 404。仍需用户完成 vpn 私有仓库授权；尚未通过连接推送或启动新构建。

## 尚未完成

- Swift 共享逻辑的 11 个 XCTest 已在用户提供的 macOS Actions 日志中确认通过；Windows 本机未执行这些测试。
- strongSwan iOS 构建尚未通过；Xcode 主应用/扩展编译及最终静态链接尚未完成。
- 尚未生成真实 `.app` 或 `.ipa`，`artifacts` 当前只交付源码上传包。
- GitHub 未登录 API 对 `qq604022385-hub/vpn` 返回 404；本机 Git 没有可用的该仓库认证，未推送源码、未启动 Actions。原 `origin` 仍是 strongSwan 上游，未被修改。
- 正确重签名与 iPhone 安装、首次 VPN 授权及共享钥匙串访问未验证。
- 真实网关 `115.31.179.179` 的 PSK/XAuth/OTP/Mode Config、双向 ESP、分流/DNS/IPv6、App 流量、取消、断开、网络切换、休眠、扩展内存和后台行为未验证。
- iOS 排除路由上的任意第三方 DNS 无法由普通 Packet Tunnel 过滤；不能承诺与 Windows WFP 完全等同。

## 云端流程

`iOS Unsigned IPA` 工作流依次执行源码检查、主机工具测试、Swift XCTest、OpenSSL 与 strongSwan iOS 编译、Xcode 双目标编译、IPA 打包及结构/路由资源校验。只有所有步骤成功，才上传 `FortiOneTap-unsigned-ipa`。

云端成功后需把该次 Actions 链接、日志与 IPA 校验报告作为新的编译证据；随后使用有 Packet Tunnel 权限的签名进行真实设备验收。


## 2026-10-18：1.4.1/build 10 后台恢复源码

详见根目录 NETWORK-IOS-1.4.1.md 与 verification/ios-1.4.1-checks.json。本轮实际执行主机 C、主机工具、源码、换行检查；新增 Swift 恢复策略 XCTest 已纳入 swift test，本机未执行。本版未生成 IPA、未远程构建、未进行 iPhone 8/24 小时锁屏验收，历史“尚未完成”记录不是当前安装版本的实测结论。
