import Foundation
import SQLite3
import CryptoKit

// 1. SQL Injection vulnerability
func sqlInjection(userId: String) {
    var db: OpaquePointer?
    sqlite3_open("database.db", &db)

    // Direct string interpolation - vulnerable to SQL injection
    let query = "SELECT * FROM users WHERE id = '\(userId)'"
    var statement: OpaquePointer?
    sqlite3_prepare_v2(db, query, -1, &statement, nil)
    sqlite3_step(statement)
    sqlite3_finalize(statement)
    sqlite3_close(db)
}

// 2. Command Injection
func commandInjection(filename: String) {
    // User input directly passed to shell command
    let process = Process()
    process.launchPath = "/bin/sh"
    process.arguments = ["-c", "cat \(filename)"]
    process.launch()
    process.waitUntilExit()
}

// 3. Path Traversal
func pathTraversal(filename: String) {
    // No validation of filename - allows directory traversal
    let path = "/uploads/\(filename)"
    do {
        let content = try String(contentsOfFile: path)
        print(content)
    } catch {
        print("Error reading file: \(error)")
    }
}

// 4. Unsafe pointer operations
func unsafePointerOps() {
    let ptr = UnsafeMutablePointer<Int>.allocate(capacity: 10)
    ptr.deallocate()
    // Use after free
    ptr.pointee = 42
}

// 5. Buffer overflow simulation
func bufferOverflow(input: String) {
    // Fixed-size buffer with potential overflow
    var buffer = Array<CChar>(repeating: 0, count: 10)
    let cString = input.cString(using: .utf8)!

    // No bounds checking - potential overflow
    for i in 0..<cString.count {
        if i < buffer.count {
            buffer[i] = cString[i]
        }
    }
}

// 6. Weak cryptography
func weakCrypto(password: String) -> String {
    // Using MD5 (deprecated)
    let data = password.data(using: .utf8)!
    let digest = Insecure.MD5.hash(data: data)
    return digest.map { String(format: "%02hhx", $0) }.joined()
}

// 7. Hardcoded credentials
let DATABASE_PASSWORD = "admin123"
let API_KEY = "sk-1234567890abcdef"
let JWT_SECRET = "super_secret_key"

// 8. Insecure random number generation
func insecureRandom() -> Int {
    // Using arc4random without proper seeding
    return Int(arc4random_uniform(10000))
}

// 9. Information disclosure
func informationDisclosure(input: String) {
    guard let value = Int(input) else {
        // Exposing sensitive information in error messages
        print("Parse error with input: \(input)")
        print("Database path: /var/lib/app/production.db")
        print("API endpoint: https://internal-api.company.com/secret")
        return
    }
    print("Valid number: \(value)")
}

// 10. Race condition
var counter = 0

func raceCondition() {
    let queue = DispatchQueue.global(qos: .default)

    for _ in 0..<1000 {
        queue.async {
            counter += 1  // Not thread-safe
        }
    }
}

// 11. Memory leak
func memoryLeak() {
    for _ in 0..<1000 {
        let ptr = UnsafeMutablePointer<Int>.allocate(capacity: 1024)
        // Not deallocating - memory leak
        ptr.pointee = 42
    }
}

// 12. Unsafe type casting
func unsafeTypeCasting(data: Data) -> String? {
    // Unsafe casting without validation
    return data.withUnsafeBytes { rawBufferPointer in
        let stringPointer = rawBufferPointer.bindMemory(to: CChar.self)
        return String(cString: stringPointer.baseAddress!)
    }
}

// 13. File inclusion vulnerability
func fileInclusion(templateName: String) {
    // Dynamic file inclusion without validation
    let path = "/templates/\(templateName).swift"
    // In a real scenario, this would dynamically load and execute code
    print("Loading template from: \(path)")
}

// 14. URL scheme vulnerability
func urlSchemeVuln(urlString: String) {
    // No validation of URL scheme
    guard let url = URL(string: urlString) else { return }

    if #available(iOS 10.0, *) {
        UIApplication.shared.open(url, options: [:], completionHandler: nil)
    }
}

// 15. Keychain insecure storage
func insecureKeychainStorage(password: String) {
    // Storing sensitive data without proper protection
    let data = password.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "user_password",
        kSecValueData as String: data,
        kSecAttrAccessible as String: kSecAttrAccessibleAlways  // Too permissive
    ]
    SecItemAdd(query as CFDictionary, nil)
}

// 16. Improper SSL/TLS validation
func improperSSLValidation() {
    let config = URLSessionConfiguration.default
    // Disabling SSL validation
    config.urlCredentialStorage = nil
    config.tlsMinimumSupportedProtocol = .tlsProtocol10  // Weak protocol

    let session = URLSession(configuration: config)
    // This session would accept invalid certificates
}

// 17. Insecure data transmission
func insecureDataTransmission(sensitiveData: String) {
    // Sending sensitive data over HTTP instead of HTTPS
    let url = URL(string: "http://api.example.com/data")!
    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.httpBody = sensitiveData.data(using: .utf8)

    URLSession.shared.dataTask(with: request).resume()
}

// 18. Format string vulnerability (conceptual)
func formatStringVuln(userInput: String) {
    // Direct use of user input in string formatting
    print(String(format: userInput, "sensitive_data"))
}

// 19. Integer overflow
func integerOverflow(size: Int) {
    // Potential integer overflow
    let totalSize = size * 1000000
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: totalSize)
    buffer.deallocate()
}

// 20. Unsafe Core Data operations
func unsafeCoreDataOps(userInput: String) {
    // Using user input directly in Core Data predicate
    let predicate = NSPredicate(format: "name = '\(userInput)'")
    // This could lead to predicate injection
    print("Predicate: \(predicate)")
}

// Main function
func main() {
    print("Vulnerable Swift examples compiled successfully")

    // Example usage (commented to prevent actual execution)
    // commandInjection("file.txt; rm -rf /")
    // pathTraversal("../../../etc/passwd")
    // sqlInjection("'; DROP TABLE users; --")
}

// Note: Some vulnerabilities require specific iOS/macOS frameworks
// and may not compile in all environments
