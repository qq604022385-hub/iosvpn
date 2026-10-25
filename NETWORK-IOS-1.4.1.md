# iOS 1.4.1 / build 10：后台连接恢复

日期：2026-10-18。交付为源码修复包，尚未生成或安装本版 IPA。

## 已修复的缺口

- Hillstone 连接时保存系统 Connect On Demand 规则（所有网络），保持 `disconnectOnSleep = false`。系统可以在主应用不运行时启动扩展。
- 将连接方式写入非敏感 `providerConfiguration`。系统无 `startTunnel(options:)` 参数地重启扩展时恢复 Hillstone，不再误进入 Forti 动态令牌流程。账号、密码、证书信任仍通过原有共享钥匙串读取，支持设备首次解锁后的锁屏读取。
- Hillstone 心跳失效、服务端要求换钥匙/重建、网络变化、发送失败后，扩展保留系统隧道和连接意图，停止并等待旧原生线程退出，再重新认证。重试间隔为 1、2、4、8、15、30、60 秒，此后保持 60 秒；无可用网络时等待路径恢复。
- 每次重连重新安装虚拟 IP、DNS、国内域名/地址分流，验证加密 DNS 往返后才恢复已连接状态。重连时使用系统 `reasserting` 状态，绝不将未验证通道显示为已连接。
- 每轮连接隔离旧回调与延迟任务，维持单个 packetFlow 读取，断开时取消重试；忽略 VPN 自身 utun 接口变化，避免路由安装触发重连循环。
- 用户断开时先将 On Demand 关闭并保存，再停止隧道；若保存失败明确提示，避免断开后立即被系统自动拉起。
- 证书变化、凭据被拒绝等不可自动修复的错误停止重试，并尝试关闭系统自动连接，保留错误日志。
- Forti 不再因外层网络连续约 6 秒异常就主动结束会话；保留已认证的 IKE/CHILD_SA 等待路径恢复，系统显示正在恢复。路径回来或系统唤醒后验证原会话的加密 DNS 往返，验证完成才恢复已连接；旧路径上的探测超时回调不能误杀新路径。实际 IKE 会话失效仍由原生引擎报告。
- 原生 C 在心跳超时判断前读取已排队的加密心跳；不会因调度延迟丢掉有效回包，也不会伪造心跳或无限延长死连接。

## Forti 与系统边界

Forti 保留原有 IKE/CHILD_SA 换钥匙和会话心跳。该配置使用一次性动态令牌，完整会话失效或扩展进程被回收后，不能保存、重放旧令牌来完成新的认证。需要无人值守重新登录时，服务端必须提供允许自动认证的方式；本版没有伪造或绕过动态令牌。

普通 iOS 应用可以保持隧道并在故障后恢复，不能承诺无网络、服务端拒绝、系统终止扩展时仍有零中断连接。Apple 的强制 Always On VPN 属于受监管设备/MDM 配置，区别于本项目的 On Demand。状态栏图标由系统显示，本版不伪造或强制固定图标。

Apple 文档：
- [Connect On Demand](https://developer.apple.com/documentation/networkextension/nevpnmanager/isondemandenabled)
- [重连状态](https://developer.apple.com/documentation/networkextension/netunnelprovider/reasserting)
- [Always On 与路由范围](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)

## 代码来源与验收

以已有 `ios/artifacts/ios` 的 1.4.0/build 9 分流版本为基础修复，并同步至正常构建入口 `ios/`；旧主目录的差异保存在 `ios/build/pre-background-1.4.1.zip`，同步清单在 `ios/verification/ios-1.4.1-source-sync.json`。未修改 Windows、Android 代码与签名。

本机验证：原生 C 编译与实际加密 UDP 回归、16 项主机打包测试、源码集成校验和 Shell 换行检查。Swift 新增连接方式恢复、重试分类、长时间退避及 Forti 连续路径丢失/恢复/唤醒 XCTest，由现有 macOS 构建流程的 `swift test` 执行；本机 Windows 未运行 Swift/Xcode/iPhone SDK 检查。

真机待验收：安装本版签名 IPA 后重新连接一次，锁屏 8/24 小时，关闭主应用，切换 Wi-Fi/蜂窝，断网后恢复，跨服务端会话过期，手动断开后锁屏并切网确认不再重连，检查真实流量和连接日志。不能用主机回归替代这些结果。
