// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import Security
import CryptoKit
import FortiCore
struct HillstoneCertificate:Identifiable {
 let id=UUID()
 let endpoint:String
 let pin:String
 let subject:String
 let trusted:Bool
 static func probe(_ profile:HillstoneSettings) throws -> HillstoneCertificate {
  guard let session=hs_create() else {throw ProfileError.invalid("无法创建证书检查会话。")}
  defer{hs_destroy(session)}
  var bytes=[UInt8](repeating:0,count:16384)
  let capacity=bytes.count
  let count=hs_probe_certificate(session,profile.gateway,UInt32(profile.port),profile.legacyTLS ? 1:0,&bytes,capacity)
  guard count>0 else {throw ProfileError.invalid("获取网关证书失败："+String(cString:hs_error(session)))}
  let der=Data(bytes.prefix(Int(count)))
  guard let certificate=SecCertificateCreateWithData(nil,der as CFData) else {throw ProfileError.invalid("网关证书格式无效。")}
  var trust:SecTrust?
  let policy=SecPolicyCreateSSL(true,profile.gateway as CFString)
  let created=SecTrustCreateWithCertificates(certificate,policy,&trust)==errSecSuccess
  let verified=created && trust.map{SecTrustEvaluateWithError($0,nil)}==true
  // CryptoKit hashes DER locally; discovery sends no account credentials.
  let fingerprint=SHA256.hash(data:der).map{String(format:"%02x",$0)}.joined()
  return HillstoneCertificate(endpoint:profile.gateway+":"+String(profile.port),pin:fingerprint,subject:(SecCertificateCopySubjectSummary(certificate) as String?) ?? "网关证书",trusted:verified)
 }
}
