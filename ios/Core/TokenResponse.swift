// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation

public enum TokenResponse {
    public static func parse(_ data: Data) throws -> String {
        guard data.count <= 64, let text = String(data: data, encoding: .ascii) else {
            throw ProfileError.invalid("令牌接口返回格式无效，请手动输入。")
        }
        let token = text.trimmingCharacters(in: CharacterSet(charactersIn: " \t\r\n"))
        do { try SiteSettings.validateToken(token) }
        catch { throw ProfileError.invalid("令牌接口未返回六位数字，请手动输入。") }
        return token
    }
}
