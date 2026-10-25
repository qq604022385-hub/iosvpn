# iOS 连接卡住修复说明（2026-10-10）

本次修改版本为 **1.0.1 / build 2**。以下结论来自当前 iOS 源码和随包 strongSwan 源码检查，尚未通过真实 iPhone / 网关连接验证。当前目录没有 Windows 客户端源码，也没有 Git 元数据，因此本次没有逐行比较 Windows 实现或推送 GitHub。

## 找到的问题

1. **工作线程不足，导致引擎控制和认证任务饥饿。** `FortiBridge.c` 原来把 `charon.threads` 设为 8。strongSwan 的调度器、socket watcher、UDP 收发各占一个常驻任务，libipsec 收发和事件处理占三个，Packet Flow 适配的 TUN reader 再占一个，共 8 个。这些任务通过同一个 `lib->processor` 运行，等待时不会把线程还给任务池。VICI 请求处理及 IKE 报文处理需要另外的空闲线程，因而会出现无法继续加载凭据或认证的情况。它是源码中能解释一直连接的明确缺陷，设备实际是否还存在签名、网络或网关认证问题需重新测试。
2. **VICI 客户端等待没有上限，取消也可能被阻塞。** 原来的 `initiate.timeout = 30000` 只约束服务端认证命令，不能约束 `libvici.c` 中等待响应的条件变量。扩展的 45 秒超时虽然在另一条队列执行，但 `fot_stop()` 排在被阻塞的 `fot_start()` 后面。
3. **App 没有显示异步失败。** `startTunnel()` 返回只表示启动请求已提交。App 只捕获调用当下的错误，没有读取系统最后一次断线错误；扩展停止后又不再读取日志，导致失败原因丢失。

## 文件改动

| 文件 | 修改 |
| --- | --- |
| `ios/Native/FortiBridge.c` | 工作线程从 8 增至 16；为 high 优先级保留 2 个线程；新增原子取消控制；输出初始化、插件加载、控制通道、凭据加载、认证、令牌清除等阶段；将 VICI 错误经已有敏感信息遮蔽处理后写入日志。 |
| `ios/Native/FortiBridge.h` | 声明准备连接、取消连接和查询取消标志的接口。 |
| `ios/scripts/prepare_source.py` | 构建时给私有 libvici 客户端加入 35 秒响应等待期限，每 250 毫秒检查取消。超时连接立即弃用，随后由原生层清理。原 vendor 压缩包无需手工修改。 |
| `ios/Tunnel/PacketTunnelProvider.swift` | 新连接前准备取消状态；超时或手动取消时先通知原生等待退出，再执行清理；启动失败在清理后完成系统回调；日志返回连接阶段、失败原因和 attemptID。 |
| `ios/App/VPNController.swift` | 每 2 秒更新系统状态；显示连接阶段；读取异步断线错误并弹窗；增加 App 端 60 秒保护；过滤旧连接的诊断回调；保留主动取消与异常失败的区别。 |
| `ios/Shared/TunnelDiagnostics.swift`（新增） | App 与扩展共用的诊断消息格式。 |
| `ios/project.yml` | 主应用和扩展版本均升为 1.0.1 / build 2。 |
| `ios/scripts/test_host.py` | 检查常驻任务与线程余量、实际生成的 VICI 补丁；有 C 编译器时执行补丁等待循环的超时、取消、正常响应和提前取消测试。 |
| `ios/scripts/verify_source.py` | 增加线程、取消控制、系统断线错误和超时保护的集成检查。 |
| `ios/VERIFICATION.md`、本文件 | 记录本次原因、改动、验证范围和上传方法。 |

本次保留 IKEv1 Aggressive / PSK / XAuth、密码与令牌模式、加密提案、DH/PFS、国内分流、DNS 和 IPv6 处理规则。共享诊断不包含配置中的账号密码或 PSK；原生日志沿用已有的凭据遮蔽逻辑。

## 已执行的验证

- `verify_source.py`：通过，包括 5495 条国内路由资源校验及原有协议配置检查。
- `test_host.py`：10 项中 9 项通过，1 项因本机没有 Bash 跳过（完整构建日志的 stderr / 退出码测试）。
- Python 脚本编译检查：通过。
- Windows 本机没有 C / Swift 编译器和 iOS SDK。C 等待循环行为测试、Swift 类型检查、原生链接和设备构建将在现有 GitHub macOS 工作流运行；本机通过的是源码与打包工具检查。

## 上传和重新验证

推荐把 `ios/artifacts/FortiOneTap-iOS-source.zip` 解压后，将内容合并到 GitHub 仓库根目录，保留 `.github` 隐藏目录。不要只上传 ZIP 文件，不要上传 `ios/build` 或 Python 缓存。新增的 `Shared/TunnelDiagnostics.swift` 必须一起上传。

在 Actions 运行 **iOS Unsigned IPA**，取得新构建后按原要求同时签名主应用和 Tunnel 扩展，安装到 iPhone，使用新的动态令牌连接。若仍失败，复制 App 页面里的连接日志和弹窗文字；新日志应能区分插件 / 控制通道启动、凭据加载、网关认证及路由安装阶段。

系统断线错误接口依据 [Apple NEVPNConnection 文档](https://developer.apple.com/documentation/networkextension/nevpnconnection/fetchlastdisconnecterror(completionhandler:))。
