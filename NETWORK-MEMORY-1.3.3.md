# iOS 1.3.3 build 6：响应速度、日志与内存（2026-10-11）

## 根据这次真机日志能确认什么

用户确认：1.3.2/build 5 开启分流后，国内网页可以打开但普遍慢，国外网页也慢。日志最后一条：rx_bytes=131081613，累计隧道接收约 131.1 MB；flow_v4=12073，written=105495。全部 44 条记录里 invalid、write_failed、family_mismatch 均为 0，heartbeat_age_ms 维持在正常心跳周期附近。它证明该次使用有真实业务收发，不能证明每个国内网页的出口正确，也没有测量进程内存。

rx_bytes/tx_bytes 是累计网络流量计数，每个计数只占固定大小，数值上涨不表示把所有收过的流量留在内存。

## 日志会不会一直涨到崩溃

1.3.2 已有最多 180 条日志，超出删除最旧条目；钥匙串用同一 service/account 的记录覆盖更新。旧日志不按连接时间无限增长。但旧版没有总字节限制，每两秒在 packetFlow 状态队列同步更新钥匙串，且为每个入站包创建一个异步待处理任务。这些会增加开销，高流量时队列有积压风险；本次日志没有进程内存数据，不能据此声称发生或没有发生泄漏。

1.3.3 加强为：

- 最近 120 条且 UTF-8 总量最多 32 KiB，单条最多 1 KiB。超出自动删除旧条目；主应用读取、旧快照及读取失败消息也限制长度。
- Hillstone 状态每 5 秒采样，钥匙串在独立 utility 队列合并写入，通常最多每 15 秒一次；只保留一份待写最新快照。正常收包不再等周期性钥匙串 I/O；断开或失败保存最后记录。Forti 的网络状态检查仍保持 2 秒。
- 主应用仅在前台每 5 秒读取日志，最多一次在途请求；内容相同不触发 SwiftUI 更新，不再重复写同一日志到 UserDefaults。
- Hillstone 入站最多每批 64 包、256 KiB，原生工作线程等待本批写回完成，再继续收下一批；替代每包异步积压。当前读入单包和接收缓冲另有固定上限，不能将单批上限当作整个进程的内存上限。
- 新诊断包含 memory_bytes（Mach task_vm_info 的 phys_footprint，失败时 unknown）、log_bytes、batches、batch_peak_bytes，可核对实际进程内存是否随长时间使用继续涨。不是用累计流量充当内存。

[Apple 的批量 writePackets API](https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets%28_%3Awithprotocols%3A%29) 要求包与协议数组数量相同；本次每批生成相同数量的 AF_INET 协议项。Apple DTS [说明](https://developer.apple.com/forums/thread/73148)指出扩展内存限额存在设备与系统差异，长时间真机检查仍是必要证据。上述容量限制不等于承诺任何情况下都不会被系统终止。

## 慢响应的具体修复与复现

旧 hs_receive 先查国内 DNS，然后只在 ESP socket 等最多 200 ms。国内 DNS 在等待期间返回，不会唤醒这个等待。现在同时等待 ESP 与国内 DNS，响应到达立即处理。

实际 loopback 测试在约 20 ms 后返回 www.baidu.com 的 DNS 结果：旧实现本轮耗时 218 ms，返回 0（响应尚未交给调用方）；新实现 31 ms，取到 75 字节合法回包。随后 512 包加密 UDP 突发、128 包单步、TUN/UDP 唤醒、DNS 首包丢弃后重发和清理全部通过。完整前后记录附在 ios/verification。

这证明消除了这项等待；不是对 iPhone 上所有网站提速的保证。网页仍可能受实际分流出口、DNS/CDN 选择或链路影响，不能以这一项就宣称所有慢响应根因已解决。

## 验证与交付边界

- 16 项实际 C/OpenSSL 回归、6 项实际 Windows loopback 数据通路检查、16 项主机工具及源码集成检查通过；DNS 复现直接调用共享 C 实现，不是 Python 模拟。
- 新增 Swift XCTest 覆盖 100000 条长期日志、超长 Unicode 行、旧快照、批次包数/字节数与取出后重置；这些 Swift 用例本轮未在 Apple 环境运行。
- 新 Swift/iOS SDK 编译、Mach 内存指标、最终 IPA、签名安装、iPhone 响应速度和长时间内存曲线尚未验收。需用这份完整源码重新运行原有 macOS CI 并签名安装。旧 build 5 不包含改动。
- Windows 保留用户当前正在运行的 1.3.2，未中断连接或替换已加载引擎。本轮通过现有连接、禁用代理进行一次 3 MB 下载，HTTP 200，7.09 秒，约 0.42 MB/s；没有官方客户端同条件对照，国外速度差距尚未定位，未宣称与官方相当。

建议真机验收：同一网络与分流设置下比较国内/国外网页首开，持续下载及后台 30–60 分钟，检查 memory_bytes、batch_peak_bytes、write_failed、心跳以及断开后的网络恢复。源码/主机检查不替代该验收。
