// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import FortiCore
final class HillstoneTunnel {
 private let lock=NSLock()
 private var handle:OpaquePointer?
 private var cancelled=false
 private var validationRequested=false
 private let group=DispatchGroup()
 func start(_ input:HillstoneSettings,ready:@escaping(String,String)->Void,packets:@escaping([Data])->Void,verified:@escaping()->Void,error:@escaping(String)->Void){
  group.enter()
  DispatchQueue.global(qos:.userInitiated).async {
   defer{self.group.leave()}
   self.lock.lock();if self.cancelled {self.lock.unlock();return}
   let pointer=hs_create();self.handle=pointer;self.lock.unlock()
   guard let pointer else {error("无法创建独立 Hillstone 引擎。");return}
   defer{self.lock.lock();hs_destroy(pointer);self.handle=nil;self.lock.unlock()}
   let result=hs_connect(pointer,input.gateway,UInt32(input.port),input.username,input.password,input.certificatePin,input.legacyTLS ? 1:0,nil,nil)
   self.lock.lock();let stopping=self.cancelled;self.lock.unlock();if stopping{return}
   guard result==1 else {
    let detail=String(cString:hs_error(pointer))
    if detail.hasPrefix("data_heartbeat_timeout") {
     error("Hillstone 账号认证已通过，客户端尝试了 3 个 UDP 源端口，仍未收到有效加密心跳。请导出本次日志，以便继续定位网络兼容问题。详情："+detail)
    }else{error("Hillstone 连接失败："+detail)}
    return
   }
   func address(_ field:UInt32)->String? {var bytes=[CChar](repeating:0,count:16);let capacity=bytes.count;guard hs_ipv4(pointer,field,&bytes,capacity)==1 else{return nil};return String(cString:bytes)}
   guard hs_select_public_dns(pointer)==1 else {error("公网 DNS 路径检查失败："+String(cString:hs_error(pointer)));return}
   guard let vip=address(0),let dns=address(2),dns != "0.0.0.0" else {error("服务端虚拟 IP 或 DNS 无效。");return}
   // The provider owns one shared DNS/routing policy for both transports.
   ready(vip,dns)
   var buffer=[UInt8](repeating:0,count:65536)
   let capacity=buffer.count
   while true {
    self.lock.lock();let stop=self.cancelled;let validate=self.validationRequested;self.validationRequested=false;self.lock.unlock();if stop{break}
    if validate {if hs_check_dns(pointer)==1 {verified()}else{error("安装路由后 DNS 往返失败："+String(cString:hs_error(pointer)));break}}
    var batch=PacketBatch()
    var readFailed=false
    while batch.count < PacketBatch.maximumPackets {
     let length=hs_receive(pointer,&buffer,capacity,batch.isEmpty ? 200:0)
     if length<0 {readFailed=true;break}
     if length==0 {break}
     let data=Data(buffer.prefix(Int(length)))
     if !batch.append(data) {packets(batch.takePackets());guard batch.append(data) else{error("Hillstone 单包超过批次上限。");return}}
    }
    if !batch.isEmpty {packets(batch.takePackets())}
    if readFailed {self.lock.lock();let stopped=self.cancelled;self.lock.unlock();if !stopped {error("Hillstone 隧道已断开："+String(cString:hs_error(pointer)))};break}
   }
  }
 }
 func send(_ packet:Data)->Bool {
  lock.lock();defer{lock.unlock()};guard !cancelled,let handle else{return false}
  return packet.withUnsafeBytes{raw in guard let bytes=raw.bindMemory(to:UInt8.self).baseAddress else{return false};return hs_send(handle,bytes,packet.count)==1}
 }
 func requestNetworkValidation(){lock.lock();validationRequested=true;lock.unlock()}
 func diagnostics()->String {lock.lock();defer{lock.unlock()};guard !cancelled,let handle else{return "Hillstone 引擎已停止。"};var bytes=[CChar](repeating:0,count:768);let capacity=bytes.count;guard hs_stats(handle,&bytes,capacity)==1 else{return "流量统计暂不可用。"};return String(cString:bytes)}
 func stop(){lock.lock();cancelled=true;if let handle {hs_cancel(handle)};lock.unlock()}
 func afterStopped(on queue:DispatchQueue,perform:@escaping()->Void){group.notify(queue:queue,execute:perform)}
}
