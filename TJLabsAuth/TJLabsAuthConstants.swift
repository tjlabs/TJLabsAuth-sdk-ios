
import Foundation

class TJLabsAuthConstants {
    static let TIMEOUT_VALUE_PUT: TimeInterval = 5.0
    static let TIMEOUT_VALUE_POST: TimeInterval = 5.0
    
    static let USER_TOKEN_SERVER_VERSION = "2025-03-25"
    
    private static let HTTP_PREFIX = "https://"
    private static let SUFFIX = ".tjlabs.dev"
    private static let JUPITER = ".jupiter"
    
    private(set) static var REGION_PREFIX = "ap-northeast-2."
    private(set) static var REGION_NAME = "Korea"
    
    private(set) static var USER_URL = HTTP_PREFIX + REGION_PREFIX + "user"
    
    public static func setServerURL(region: String, serverType: String) {
        switch region {
        case AuthRegion.KOREA.rawValue:
            REGION_PREFIX = "ap-northeast-2."
            REGION_NAME = "Korea"
        case AuthRegion.KOREA.rawValue:
            REGION_PREFIX = "ca-central-1."
            REGION_NAME = "Canada"
        case AuthRegion.KOREA.rawValue:
            REGION_PREFIX = "us-east-1."
            REGION_NAME = "US"
        default:
            REGION_PREFIX = "ap-northeast-2."
            REGION_NAME = "Korea"
        }
        
        USER_URL = HTTP_PREFIX + REGION_PREFIX + "user" + serverType + SUFFIX
    }
    
    public static func getUserBaseURL() -> String {
        return USER_URL
    }
    
    public static func getUserTokenVersion() -> String {
        return USER_TOKEN_SERVER_VERSION
    }
    
    public static func getUserTokenURL() -> String {
        return USER_URL + "/" + USER_TOKEN_SERVER_VERSION + "/user"
    }
}
