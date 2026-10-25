# Forti 三端自动读取令牌（1.4.2，2026-10-20）

Windows、Android、iOS 的 Forti / IPsec 每次由用户点击连接后，向 `http://47.103.139.56:9000/api/key` 发起新的 GET 请求。接口格式按用户确认的纯六位数字处理，保留前导零，允许首尾 ASCII 空格、制表符、CR/LF。拒绝 HTML、JSON、空响应、非 ASCII 数字、其他长度和超过 64 字节的响应；仅接受 HTTP 200，不跟随重定向。

令牌只交给现有 XAuth 流程，不写入设置、磁盘、日志或持久化 VPN 配置，不缓存和复用。请求不携带 VPN 账号、密码、PSK。读取失败后提供手动输入窗口；取消不会使用迟到的请求结果。Android 在系统 VPN 授权后读取，支持现有 XAuth 令牌补充入口；iOS 在系统 VPN 配置保存/授权完成后读取，以减少授权等待导致令牌过期。

Windows 和 Android 请求的连接/读取超时为 8 秒；iOS 单次请求超时 8 秒、资源总超时 10 秒。Android 明文例外只配置 `47.103.139.56`；iOS 主应用对同一 IP 配置 ATS 例外。iOS 17 及更新系统支持数字 IP 例外，iOS 16 默认允许 IP 连接，未全局关闭 ATS。依据 [Apple NSAllowsLocalNetworking](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking) 与 [Android 网络安全配置](https://developer.android.com/privacy-and-security/security-config)。

Hillstone 使用原有密码、证书和重连流程。Forti 的本次改动覆盖用户发起的连接，不额外启用隧道失效后的无人值守重新登录。

## 实际检查

- Windows：发布 EXE 编译通过；69 项检查通过，其中 19 项令牌检查覆盖前导零、异常正文、实际 loopback HTTP、每次取新值、错误状态、拒绝重定向、大小限制和请求前/请求中的取消。其余检查包括 DPAPI、现有配置、原生引擎启动和桌面窗口渲染。
- Android：assembleRelease、testDebugUnitTest、lintDebug 通过；118 项 JVM 测试（含 9 项新令牌测试），0 失败、0 错误；lint 0 错误、135 项原有/上游警告。发布 APK 的三个 ABI、APK v2 签名、原有发布证书、27 个原生库、16 KB ZIP/64 位 ELF 对齐和资源一致性经过包检查。
- iOS：16 项主机工具测试、源码集成检查、shell 换行检查通过。新增 3 项 Swift 令牌解析 XCTest 已加入源码，待 macOS/Apple SDK 执行。未在本机完成 Swift/iOS SDK 编译，未生成 IPA。
- 实际接口：连接用户指定地址返回 HTTP 502（nginx），没有获得有效令牌。因此本次没有完成真实自动取令牌、真实 Forti 网关登录以及 Android/iPhone 真机验收。loopback 测试使用的六位数都是合成数据。

## 交付

- `windows/dist/FortiOneTap-1.4.2.exe`
- `android-port/dist/FortiOneTap-Android-1.4.2.apk`
- `ios/artifacts/FortiOneTap-iOS-1.4.2-source.zip`

校验值记录在各平台的构建信息和项目 `release-token-1.4.2.json`。历史网络验收数据不能当作本版的真实登录证明。
