// SPDX-License-Identifier: GPL-2.0-or-later
import Foundation
import FortiCore

enum TokenClient {
    static let endpoint = URL(string: "http://47.103.139.56:9000/api/key")!
    private final class NoRedirect: NSObject, URLSessionTaskDelegate {
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest,
                        completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(nil)
        }
    }
    static func fetch() async throws -> String {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil; config.httpCookieStorage = nil; config.urlCredentialStorage = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 8; config.timeoutIntervalForResource = 10
        let session = URLSession(configuration: config, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: endpoint)
        request.setValue("no-cache, no-store", forHTTPHeaderField: "Cache-Control")
        request.setValue("text/plain", forHTTPHeaderField: "Accept")
        do {
            try Task.checkCancellation()
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                throw ProfileError.invalid("令牌接口暂时不可用，请手动输入。")
            }
            guard response.expectedContentLength <= 64 else {
                throw ProfileError.invalid("令牌接口返回格式无效，请手动输入。")
            }
            var data = Data()
            for try await byte in bytes {
                try Task.checkCancellation()
                guard data.count < 64 else { throw ProfileError.invalid("令牌接口返回格式无效，请手动输入。") }
                data.append(byte)
            }
            return try TokenResponse.parse(data)
        } catch is CancellationError { throw CancellationError() }
        catch let error as ProfileError { throw error }
        catch { throw ProfileError.invalid("自动读取令牌失败或超时，请手动输入。") }
    }
}
