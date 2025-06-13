
import Foundation

public enum AuthRegion: String {
    case KOREA = "KOREA"
    case US_EAST = "US_EAST"
    case CANADA = "CANADA"
}

struct AuthInput: Codable {
    var name: String
    var password: String
    
    init(name: String, password: String) {
        self.name = name
        self.password = password
    }
}

struct AuthOutput: Codable {
    var refresh: String
    var access: String
    
    init(refresh: String, access: String) {
        self.refresh = refresh
        self.access = access
    }
}

struct RefreshTokenInput: Codable {
    var refresh: String
    
    init(refresh: String) {
        self.refresh = refresh
    }
}

struct RefreshTokenOutput: Codable {
    var access: String
    
    init(access: String) {
        self.access = access
    }
}

struct VerifyTokenInput: Codable {
    var token: String
    
    init(token: String) {
        self.token = token
    }
}

public enum TokenResult {
    case success(String)
    case failure(FailureReason, statusCode: Int?, message: String?)

    public enum FailureReason {
        case refreshFailed
        case authFailed
        case credentialsMissing
    }
}
