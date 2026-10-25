// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import Security
import FortiCore
enum HillstoneKeychain {
    private static var query: [String: Any] { [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "OneTap.HillstoneSettings", kSecAttrAccount as String: "profile-v1"] }
    static func load() throws -> HillstoneSettings {
        var q = query; q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?; let code = SecItemCopyMatching(q as CFDictionary, &item)
        if code == errSecItemNotFound { return HillstoneSettings() }
        guard code == errSecSuccess, let data = item as? Data else {
            throw ProfileError.invalid("读取钥匙串失败（\(code)）。请检查应用与 VPN 扩展的共享签名权限。")
        }
        return try JSONDecoder().decode(HillstoneSettings.self, from: data)
    }
    static func save(_ settings: HillstoneSettings) throws {
        try settings.validate()
        var data = try JSONEncoder().encode(settings)
        defer { data.resetBytes(in: 0..<data.count) }
        let attributes: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var code = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if code == errSecItemNotFound {
            code = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil)
        }
        guard code == errSecSuccess else { throw ProfileError.invalid("保存钥匙串失败（\(code)）。") }
    }
}