# iOS 1.3.4 build 7：休眠连接、DNS 与 Forti 诊断（2026-10-13）

## 当前证据

用户提供 1.3.3 build 6 的 Hillstone 真机日志：10 次状态采样，最后 heartbeat_age_ms=1501、direct_dns=1、fallback_dns=0、written=2607、write_failed=0、invalid=0。约 50 秒内进程内存约 3.77 MB 到 7.05 MB；这段数据不证明长时间内存泄漏，也不证明每个国内网页的路由或速度正常。末尾是正常清理日志，没有引擎故障；旧版没有系统停止原因，所以不能判定此次断开是谁触发的。DNS 直连次数少也可能受缓存影响，不能直接判定大多数域名解析异常。百度显示国内 IP 只反映那次访问的出口。

## 本次改动

- VPN 的 disconnectOnSleep 从 true 改为 false。休眠、唤醒与系统 stop reason 数值写入有界日志。重新连接时更新系统配置。
- Hillstone 工作线程暂停至少 8 秒后，给予 12 秒心跳恢复窗口。真实心跳时间不被伪造，正常运行时的 12 秒失联上限保留；服务器会话失效或网络切换导致旧会话无效，仍须重新连接。
- 国内规则匹配从 A 扩展到 HTTPS(65)/SVCB(64)。保留 AAAA 的 IPv4 回退策略，国外规则继续使用网关 DNS。
- 国内 DNS 的 NOERROR/NODATA 与 NXDOMAIN 不再因无 A 答案而转发到网关；SERVFAIL、截断或超时仍回退。没有增加全域名直连 DNS。
- 如果网关 DNS 恰好为 223.5.5.5，国内 DNS relay 改选 119.29.29.29，避免与为 VPN DNS 保留的 /32 相同。
- 增加 direct_reply/direct_avg_ms/direct_max_ms 与 vpn_dns/vpn_reply/vpn_avg_ms/vpn_max_ms/vpn_https 指标。网关耗时只观察 UDP DNS；表固定 64 项，不保留域名。丢失或超出容量的响应不计入平均值，DNS 的 TCP/DoH 流量不在该 RTT 指标范围内。
- Forti 增加配置校验、本地引擎、控制通道、IKE/XAuth、令牌销毁等失败阶段；外层网络连续三次（每两秒一次）复查失败才中断，避免单次瞬时检查失败即断线。不重用动态令牌。

## 验证

实际 C/OpenSSL 编译和 22 项原生检查通过：包含实际 UDP A/HTTPS/SVCB 返回、NODATA/NXDOMAIN、DNS 超时加密回退、固定大小耗时表、暂停恢复后的实际加密 UDP 心跳及无回应最终失效。新增暂停测试人为设置旧时间戳，并实际进行 UDP 加密收发，不是 iPhone 系统休眠测试。

16 项主机打包工具回归通过；源码集成、5495 条路由资源与 shell 换行检查通过。Forti 引擎及 Swift 的 Apple SDK 编译仍须原 macOS CI 完成，Windows C 测试不覆盖它们。

## 交付与未完成项

完整源码包：ios/artifacts/FortiOneTap-iOS-1.3.4-source.zip；构建方法沿用 ios/README.md 和 .github/workflows/ios-ipa.yml。本次不覆盖已安装的 Android/Windows 客户端，不修改原有提取副本，也不提供未经编译的 IPA。

本机尚未进行新 Apple SDK/Xcode 编译、生成 IPA、签名安装或新版本 iPhone 网关验证。因此未承诺所有网页秒开或后台永久不断。用户这次 Forti 超时尚无对应日志，根因未确认；新版本提供分阶段日志进一步定位。

重新构建安装后，确认主应用和扩展均为 1.3.4/build 7；在同一网络测试国内首开、锁屏后台 30 分钟、唤醒及断开后的网络恢复。若仍慢，导出 direct/vpn DNS 耗时和完整 stop reason；若 Forti 超时，提供从启动到失败的协商日志。通过 macOS 构建不替代这些真机验收。

依据：[Apple disconnectOnSleep](https://developer.apple.com/documentation/networkextension/nevpnprotocol/disconnectonsleep)、[Apple wake](https://developer.apple.com/documentation/networkextension/neprovider/wake())。
