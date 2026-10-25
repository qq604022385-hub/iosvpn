// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import Security
import FortiCore
// Shared existing keychain group; stores operational diagnostics, never account secrets.
enum DiagnosticsStore {
 private static let query:[String:Any]=[kSecClass as String:kSecClassGenericPassword,kSecAttrService as String:"me.longxuan.fortionetap.diagnostics",kSecAttrAccount as String:"last-tunnel-log"]
 // At most one latest snapshot and one delayed write. Packet processing never waits for periodic keychain I/O.
 private static let lock=NSLock()
 private static let writer=DispatchQueue(label:"FortiOneTap.diagnostics",qos:.utility)
 private static var pending:String?
 private static var scheduled=false
 static func save(_ text:String){
  let bounded=BoundedDiagnostics.boundedSnapshot(text)
  lock.lock();pending=bounded;let enqueue = !scheduled;scheduled=true;lock.unlock()
  if enqueue {writer.asyncAfter(deadline:.now()+15){persistLatest(resetSchedule:true)}}
 }
 private static func persistLatest(resetSchedule:Bool){
  lock.lock();let text=pending;pending=nil;if resetSchedule {scheduled=false};lock.unlock()
  guard let text else{return}
  let value=[kSecValueData as String:Data(text.utf8)]
  if SecItemUpdate(query as CFDictionary,value as CFDictionary)==errSecItemNotFound {var item=query;item.merge(value){_,new in new};item[kSecAttrAccessible as String]=kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;_ = SecItemAdd(item as CFDictionary,nil)}
 }
 // Called after failure/disconnect, when data processing has stopped, to keep the final record.
 static func flush(){writer.sync{persistLatest(resetSchedule:false)}}
 static func load()->String? {
  var item=query;item[kSecReturnData as String]=true;item[kSecMatchLimit as String]=kSecMatchLimitOne;var result:CFTypeRef?
  guard SecItemCopyMatching(item as CFDictionary,&result)==errSecSuccess,let bytes=result as? Data else{return nil}
  return String(data:bytes,encoding:.utf8).map{BoundedDiagnostics.boundedSnapshot($0)}
 }
}