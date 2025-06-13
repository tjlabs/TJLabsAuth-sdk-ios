
import Foundation
import Security

public class TJLabsAuthManager {
    public static let shared = TJLabsAuthManager()

    private(set) var accessToken: String = ""
    private(set) var refreshToken: String = ""

    private var accessTokenExpDate: Date = .distantPast
    private var refreshTokenExpDate: Date = .distantPast

    private var storedUsername: String = ""
    private var storedPassword: String = ""

    private let tokenRefreshQueue = DispatchQueue(label: "com.tjlabs.auth.tokenrefresh")
    private var isRefreshing = false

    private init() {
        if let storedAccess = KeychainHelper.shared.load(key: "TJLabs.accessToken") {
            self.accessToken = storedAccess
        }
        if let storedRefresh = KeychainHelper.shared.load(key: "TJLabs.refreshToken") {
            self.refreshToken = storedRefresh
        }
        if let username = KeychainHelper.shared.load(key: "TJLabs.username") {
            self.storedUsername = username
        }
        if let password = KeychainHelper.shared.load(key: "TJLabs.password") {
            self.storedPassword = password
        }
    }

    func setTokenInfo(authOutput: AuthOutput) {
        self.accessToken = authOutput.access
        self.refreshToken = authOutput.refresh

        KeychainHelper.shared.save(key: "TJLabs.accessToken", value: accessToken)
        KeychainHelper.shared.save(key: "TJLabs.refreshToken", value: refreshToken)

        if let accessExp = extractExpirationDate(from: authOutput.access) {
            self.accessTokenExpDate = accessExp
        }
        if let refreshExp = extractExpirationDate(from: authOutput.refresh) {
            self.refreshTokenExpDate = refreshExp
        }
    }

    public func getAccessToken(update: Bool = true, completion: @escaping (TokenResult) -> Void) {
        if !update {
            completion(.success(accessToken))
        } else {
            if isTokenNearExpiry(token: refreshToken, threshold: 60) {
                reauthenticateIfPossible(completion: completion)
                return
            }

            if isTokenNearExpiry(token: accessToken, threshold: 60) {
                refresh { status, success in
                    if success {
                        completion(.success(self.accessToken))
                    } else {
                        completion(.failure(.refreshFailed, statusCode: status, message: "Failed to refresh token"))
                    }
                }
            } else {
                completion(.success(accessToken))
            }
        }
    }
    
    public func extractTenantID(from jwt: String) -> String? {
        let segments = jwt.components(separatedBy: ".")
        guard segments.count == 3 else { return nil }

        let payloadSegment = segments[1]
        
        var base64 = payloadSegment
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        // Padding 추가
        while base64.count % 4 != 0 {
            base64 += "="
        }

        guard let payloadData = Data(base64Encoded: base64),
              let jsonObject = try? JSONSerialization.jsonObject(with: payloadData, options: []),
              let payloadDict = jsonObject as? [String: Any],
              let tenantID = payloadDict["tenant_id"] as? String else {
            return nil
        }

        return tenantID
    }

    public func getRefreshToken() -> String {
        return refreshToken
    }

    public func auth(name: String, password: String, completion: @escaping (Int, Bool) -> Void) {
        self.storedUsername = name
        self.storedPassword = password

        KeychainHelper.shared.save(key: "TJLabs.username", value: name)
        KeychainHelper.shared.save(key: "TJLabs.password", value: password)

        let url = TJLabsAuthConstants.getUserTokenURL()
        let authInput = AuthInput(name: name, password: password)
        postAuthToken(url: url, input: authInput) { status, resultString, _ in
            let (success, output) = self.decodeAuthOutput(jsonString: resultString)
            if success {
                self.setTokenInfo(authOutput: output)
            }
            completion(status, success)
        }
    }

    private func reauthenticateIfPossible(completion: @escaping (TokenResult) -> Void) {
        guard !storedUsername.isEmpty && !storedPassword.isEmpty else {
            completion(.failure(.credentialsMissing, statusCode: nil, message: "Username/password not stored"))
            return
        }

        auth(name: storedUsername, password: storedPassword) { status, success in
            completion(success ? .success(self.accessToken) : .failure(.authFailed, statusCode: status, message: "Failed to reauthenticate"))
        }
    }

    public func refresh(completion: @escaping (Int, Bool) -> Void) {
        tokenRefreshQueue.async {
            guard !self.isRefreshing else {
                DispatchQueue.main.async { completion(409, false) }
                return
            }

            self.isRefreshing = true
            let url = TJLabsAuthConstants.getUserTokenURL()
            let input = RefreshTokenInput(refresh: self.refreshToken)

            self.postRefreshToken(url: url, input: input) { status, resultString, _ in
                self.isRefreshing = false
                let (success, output) = self.decodeRefreshTokenOutput(jsonString: resultString)
                if success {
                    self.accessToken = output.access
                    KeychainHelper.shared.save(key: "TJLabs.accessToken", value: self.accessToken)
                    if let expDate = self.extractExpirationDate(from: output.access) {
                        self.accessTokenExpDate = expDate
                    }
                }
                completion(status, success)
            }
        }
    }

    public func isTokenNearExpiry(token: String, threshold: TimeInterval = 60) -> Bool {
        guard let exp = extractExpirationDate(from: token) else { return true }
        return Date().addingTimeInterval(threshold) >= exp
    }

    private func extractExpirationDate(from token: String) -> Date? {
        let segments = token.components(separatedBy: ".")
        guard segments.count >= 2 else { return nil }
        var base64 = segments[1].replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 = base64.padding(toLength: ((base64.count+3)/4)*4, withPad: "=", startingAt: 0)

        guard let data = Data(base64Encoded: base64),
              let json = try? JSONSerialization.jsonObject(with: data),
              let payload = json as? [String: Any],
              let exp = payload["exp"] as? TimeInterval else {
            return nil
        }
        return Date(timeIntervalSince1970: exp)
    }

    func postAuthToken(url: String, input: AuthInput, completion: @escaping (Int, String, AuthInput) -> Void) {
        guard let body = encodeJson(input),
              let request = makeRequest(url: url, body: body) else {
            DispatchQueue.main.async { completion(406, "Invalid URL or failed to encode JSON", input) }
            return
        }

        let session = URLSession(configuration: .default)
        performRequest(request: request, session: session, input: input, completion: completion)
    }

    func postRefreshToken(url: String, input: RefreshTokenInput, completion: @escaping (Int, String, RefreshTokenInput) -> Void) {
        guard let body = encodeJson(input),
              let request = makeRequest(url: url, body: body) else {
            DispatchQueue.main.async { completion(406, "Invalid URL or failed to encode JSON", input) }
            return
        }

        let session = URLSession(configuration: .default)
        performRequest(request: request, session: session, input: input, completion: completion)
    }

    private func encodeJson<T: Encodable>(_ param: T) -> Data? {
        try? JSONEncoder().encode(param)
    }

    private func makeRequest(url: String, method: String = "POST", body: Data?) -> URLRequest? {
        guard let url = URL(string: url) else { return nil }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body = body {
            request.setValue("\(body.count)", forHTTPHeaderField: "Content-Length")
        }
        return request
    }

    private func performRequest<T>(
        request: URLRequest,
        session: URLSession,
        input: T,
        completion: @escaping (Int, String, T) -> Void
    ) {
        session.dataTask(with: request) { data, response, error in
            let code = (response as? HTTPURLResponse)?.statusCode ?? 500
            if let error = error {
                let message = (error as? URLError)?.code == .timedOut ? "Timed out" : error.localizedDescription
                DispatchQueue.main.async {
                    completion(code, message, input)
                }
                return
            }

            guard let statusCode = (response as? HTTPURLResponse)?.statusCode, (200..<300).contains(statusCode),
                  let data = data else {
                let message = HTTPURLResponse.localizedString(forStatusCode: code)
                DispatchQueue.main.async {
                    completion(code, message, input)
                }
                return
            }

            let resultData = String(data: data, encoding: .utf8) ?? ""
            DispatchQueue.main.async {
                completion(statusCode, resultData, input)
            }
        }.resume()
    }

    func decodeAuthOutput(jsonString: String) -> (Bool, AuthOutput) {
        guard let jsonData = jsonString.data(using: .utf8) else {
            return (false, AuthOutput(refresh: "", access: ""))
        }
        do {
            let decoded = try JSONDecoder().decode(AuthOutput.self, from: jsonData)
            return (true, decoded)
        } catch {
            print("Error decoding AuthOutput: \(error)")
            return (false, AuthOutput(refresh: "", access: ""))
        }
    }

    func decodeRefreshTokenOutput(jsonString: String) -> (Bool, RefreshTokenOutput) {
        guard let jsonData = jsonString.data(using: .utf8) else {
            return (false, RefreshTokenOutput(access: ""))
        }
        do {
            let decoded = try JSONDecoder().decode(RefreshTokenOutput.self, from: jsonData)
            return (true, decoded)
        } catch {
            print("Error decoding RefreshTokenOutput: \(error)")
            return (false, RefreshTokenOutput(access: ""))
        }
    }
}
