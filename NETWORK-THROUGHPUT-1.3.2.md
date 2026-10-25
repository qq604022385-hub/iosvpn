# 1.3.2 数据通路与蜂窝诊断（2026-10-11）

Windows 实测有改善；iOS 已修改路由和 packetFlow，但还没有新版 Apple 构建及真机通过证据。不能把“原生 DNS 自检成功”当作 Safari 已恢复的验收。

## Windows 吞吐改动

1. Wintun/UDP 事件共同唤醒空闲工作线程，ESP 入站每轮最多处理 128 包，避免每收一包都返回 C#。
2. 网卡枚举由每 100 轮改为每 2 秒，统计由每 500 轮改为每 5 秒。高下载流量不再增加枚举频率。
3. 请求 8 MB UDP 接收缓冲及 1 MB 发送缓冲；本机实际接收值是 8,388,608 字节。iOS 会按系统允许值逐级回退，实际值可在日志看到。
4. 每个会话分别复用 TX/RX EVP 3DES 上下文，每包仍使用独立随机 IV，保持 3DES/HMAC-SHA1 协议与包序号验证。
5. 初始心跳窗口 12 秒，每秒重发；仍必须取得认证心跳才安装网络。DNS 自检 5 秒内最多发送 3 次同一查询，不自动重新提交账号认证。
6. 保留一次初始化、版本目录、断开重连和托盘后台行为。

## 真实带宽对照

同一 Windows 10 x64 主机、同一已保存网关、开启国内分流；curl 显式关闭代理。每轮最多下载 10 MB、45 秒截止。终点是 Cloudflare 公共下载端点。两版本各两次成功 HTTP 200，共 40 MB；这不是官方客户端或 YouTube 播放对照。

| 轮次 | 1.3.1 | 最终 1.3.2 |
| --- | --- | --- |
| 1 | 32.81 秒 / 0.30 MB/s | 17.88 秒 / 0.56 MB/s |
| 2 | 28.65 秒 / 0.35 MB/s | 11.11 秒 / 0.90 MB/s |

相同总下载量 / 总耗时计算，本次约 2.12 倍。此前开发构建曾测得 0.93–1.05 MB/s，网络速度有波动；不能保证任意线路或 YouTube 4K 达到相同倍率。

证据：`windows/throughput-baseline-1.3.1.log`、`windows/throughput-updated-1.3.2.log`、`windows/throughput-comparison-1.3.2.json`。

## 回归结果

- 最终构建同一进程分流→全局→分流连续三次真实连接，9 个默认双栈 HTTPS 请求均 200，国内两次走 WLAN、全局走隧道；国外三次走 OneTap-Hillstone。三次均清理完成。
- 首次回归第三次曾遇到 `data_heartbeat_timeout`，失败记录保留在 `gateway-acceptance-1.3.2-initial.log`；加入有限重发后重新验收，最终记录为 `gateway-acceptance-1.3.2.log`。不将首次失败算作通过。
- 真实 loopback 加密 UDP 的 512 包突发全部收到，单步确实交付 128 包；TUN/UDP 事件唤醒、DNS 首包故意丢弃后的加密重发与取消清理通过（5 项）。只有 Wintun 收写接口使用测试替身，网络和 C 数据通路为真实实现；不是 iPhone 证据。
- 16 项实际 C/OpenSSL 回归通过，包含 256 个独立 IV 下复用上下文与参考算法逐包一致；桌面 50 项通过，包含关闭窗口留在托盘、加载 DLL 后重复释放与证书变化拦截。

## iOS 1.3.2 build 5

用户提供 1.3.1 build 4 日志只有低频 tx/rx 和原生 DNS 成功。旧计数没有包含 packetFlow 读取、IPv6 本地响应或过滤情况，无法区分具体故障阶段。

本次用两个 /1 IPv4 路由和 DNS /32 明确覆盖蜂窝默认路由，Hillstone 关闭 enforceRoutes；保留更具体的国内/本地排除，选定 DNS 继续强制进隧道。IPv6 公网继续捕获并快速回退，仅排除本机 ::1 和链路本地 fe80::/10，给蜂窝本地链路保留路径。已按 [Apple enforceRoutes 文档](https://developer.apple.com/documentation/networkextension/nevpnprotocol/enforceroutes) 与 [排除路由说明](https://developer.apple.com/documentation/networkextension/neipv4settings/excludedroutes) 核对属性语义；这些调整是否解决本机蜂窝故障仍须真机证明。

网络设置完成并验证原生通道后，先启动读取，再完成 startTunnel。按 IP 头校验和识别数据，不再由 zip/单一 family 元数据静默丢弃整个批次中的包；合法 utun 家族前缀可规范化，长度错误仍拒绝。写回函数检查系统是否接受包。

新日志增加 flow_v4、flow_v6、invalid、held_or_filtered、forwarded、local_reply、written、write_failed、family_mismatch；native tx_bytes/rx_bytes/rcvbuf 可核对是否有真实业务数据及缓冲值。日志不记录账号、密码、密钥或应用负载。

16 项 C 回归、16 项主机工具和源码校验通过。新增 Swift XCTest 已写入，当前没有运行 Apple SDK/Xcode、生成新 IPA 或验证 iPhone；GitHub 连接本轮读取 qq604022385-hub/vpn 仍返回 404。完整源码包带现有 macOS CI 构建、SDK 类型检查、实际 IPA 校验，需重新构建签名安装。旧 IPA 不会取得这些改动。

真机验收仍需：分流开/关下 Safari 国内与国外 HTTPS、蜂窝与 Wi-Fi、IPv6 回退、后台、断开清理和连续重连。若仍失败，连接后打开 Safari 20 秒，导出新版本日志；各层计数能区分路由未捕获、过滤、发送与写回阶段。
