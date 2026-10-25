# iOS 1.3.5 build 8：Forti 线程饥饿与 Hillstone DNS 延迟（2026-10-13）

## 这次真机日志确认的事实

Hillstone：split_china=true，VPN DNS 为 8.8.8.8，国内直连 DNS 6 次回应、平均 102 ms、最慢 240 ms；VPN DNS 11 次回应、平均 885 ms、最慢 2563 ms。有可量化的解析延迟，但样本小且包含启动验证查询，不等于 TCP RTT。后续状态中的平均值没有继续变化，不能把重复采样当作新解析样本。invalid/write_failed/family_mismatch 均为 0；held_or_filtered=22 同时包括等待分片与策略过滤，不能将它直接解释为丢包率。累计接收约 7.67 MB，最终内存约 13.42 MB；此段数据不证明内存泄漏。系统最终记录 reason=1，属于 userInitiated；不是一次由引擎错误报告的断开。

Forti：启动到了“连接本地控制通道并加载认证资料”，没有出现 IKE/XAuth 协商阶段，45 秒后超时。此日志不能用来归因于令牌或远端网关不可达。

## Forti 的具体原因及修复

旧 iOS 配置覆盖 charon.threads=8。已启用组件会排队运行 8 个长期任务：scheduler、watcher、sender、receiver、ipsec inbound、ipsec outbound、ipsec event relay、kernel-libipsec router。这些任务占用全部工作线程后，VICI accept/read/command 等处理没有空闲线程。本地同步 vici_submit 会一直等待应答，与真机阶段超时吻合。

改为 strongSwan 标准默认 16 个工作线程。在加载 PSK 前提交无账号内容的 VICI version 自检，收到合法 daemon 应答才继续；PSK、XAuth 密码和 PIN 各有单独阶段。没有修改网关协议或复用动态令牌。

实际链接本机 strongSwan 静态库，使用其 processor/semaphore/callback_job 实现复现：8 个长期阻塞任务时控制回调 250 ms 内无法执行；扩到 16 个线程后，同一个排队回调在 2 秒检查窗口内完成。此测试验证真实调度器，测试回调模拟控制工作；不是在 iPhone 上跑完整 VICI/网关认证。新增 test_processor.py 加入 macOS CI，主机编译显式使用 macOS SDK。

## Hillstone 的改动

如果网关提供 8.8.8.8 或 8.8.4.4，在建立会话后同时通过原 ESP 加密隧道探测原解析器与 1.1.1.1，选择先返回合法 example.com A 答案的一方，作为本次 VPN DNS。最多观察 1.2 秒、每个候选最多 3 次探测；均无有效答案时保留原 DNS，随后仍进行安装路由后的正常验证。源地址、端口、随机事务 ID、问题内容、UDP 长度及校验和均校验。私有和其他自定义 DNS 不参与替换。国内域名直连 DNS 策略继续沿用，国外查询仍在 VPN 中传输。

这是一轮连接时的响应选择，不保证每个域名在该解析器都更快，也不替代运营商或 VPN 链路测量。probe 用普通测试域名，不发送账号或访问历史。

新增有界 TCP SYN 元数据表（128 项），记录 tcp_syn、syn_retry、syn_reply、syn_avg_ms、syn_max_ms。时间从首个 SYN 到有效对应 SYN-ACK，包含重试等待与本机处理时间；不是纯传播延迟。只观察进入 VPN 的 IPv4 TCP，国内直连流量和 QUIC/HTTP3 不在该指标内。日志原有大小限制保留。

## 验证与交付

- 26 项实际 C/OpenSSL 检查通过，包括实际加密 UDP 候选解析器选择、错误事务 ID 忽略、私有/自定义 DNS 保留、公共解析器均无回答时回退；另有 TCP 元数据检查及原 DNS/心跳回归。
- 真实 strongSwan 8/16 线程调度回归通过；16 项主机打包工具回归通过。
- 源码集成、5495 条路由资源、Python/Bash 语法与 shell LF 检查通过。
- 完整源码：ios/artifacts/FortiOneTap-iOS-1.3.5-source.zip。按 ios/README.md 解压上传原 GitHub 仓库，再编译、签名安装；主应用及扩展必须均为 1.3.5/build 8。

本机尚未运行新 Apple SDK/Xcode 构建、完整 iOS VICI/网关连接、生成 IPA 或真机安装；新增 macOS 主机调度器构建分支也尚未在 Apple 主机运行。已附测试证据，不把 Windows 主机结果称作 iPhone 连接成功。新版本网页是否提速仍须真机验证。

安装后日志应显示 Forti“本地控制通道自检通过”并进入 IKE/XAuth 阶段；Hillstone 查看 resolver、selected_dns_ms、vpn_avg_ms 与 SYN 握手指标。DNS 降低但 SYN 耗时高/重试多时，再检查链路、出口、MTU、QUIC，避免继续将所有卡顿归因于 DNS。

参考：[strongSwan 默认线程配置](https://docs.strongswan.org/docs/5.9/config/strongswanConf.html)、[Apple 停止原因](https://developer.apple.com/documentation/networkextension/neproviderstopreason/userinitiated)。
