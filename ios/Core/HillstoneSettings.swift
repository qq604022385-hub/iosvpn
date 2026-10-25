// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
public struct HillstoneSettings: Codable, Equatable {
 public var gateway="",username="",password="",certificatePin=""
 public var port=4433
 public var legacyTLS=false,splitChina=true
 public init() {}
 public func validate() throws {
  guard let ip=IPv4CIDR.address(gateway),IPv4CIDR.isPublic(ip),port>0,port<65536 else {throw ProfileError.invalid("请填写 Hillstone 公网 IPv4 和端口。")}
  guard !username.trimmingCharacters(in:.whitespacesAndNewlines).isEmpty,username.utf8.count<=200,!password.isEmpty,password.utf8.count<=512 else {throw ProfileError.invalid("请填写 Hillstone 用户名和密码。")}
  guard certificatePin.isEmpty || (certificatePin.utf8.count==64 && certificatePin.utf8.allSatisfy({(48...57).contains($0)||(65...70).contains($0)||(97...102).contains($0)})) else {throw ProfileError.invalid("已保存的网关证书信息无效，请在设置中重新信任证书。")}
  guard ![gateway,username,password,certificatePin].contains(where:{$0.utf8.contains(0)}) else {throw ProfileError.invalid("设置不能包含空字符。")}
 }
 public func exclusions(dns:String,china:[IPv4CIDR]) throws -> [IPv4CIDR] {
  try validate()
  return try RoutePlan.excluded(gateway:gateway,dns:dns,splitChina:splitChina,china:china)
 }
}
