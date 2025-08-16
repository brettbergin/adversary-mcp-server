package main

import (
    "crypto/md5"
    "database/sql"
    "fmt"
    "io/ioutil"
    "math/rand"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "time"
)

// 1. SQL Injection vulnerability
func sqlInjection(db *sql.DB, userID string) {
    // Direct string concatenation - vulnerable to SQL injection
    query := "SELECT * FROM users WHERE id = '" + userID + "'"
    rows, _ := db.Query(query)
    defer rows.Close()
}

// 2. Command injection
func commandInjection(filename string) {
    // User input directly passed to command execution
    cmd := exec.Command("cat", filename)
    output, _ := cmd.Output()
    fmt.Println(string(output))
}

// 3. Path traversal
func pathTraversal(filename string) {
    // No validation of filename - allows directory traversal
    fullPath := filepath.Join("/uploads", filename)
    content, _ := ioutil.ReadFile(fullPath)
    fmt.Println(string(content))
}

// 4. Weak cryptography - MD5
func weakCrypto(password string) string {
    // MD5 is cryptographically broken
    hasher := md5.New()
    hasher.Write([]byte(password))
    return fmt.Sprintf("%x", hasher.Sum(nil))
}

// 5. Insecure random number generation
func insecureRandom() string {
    // Using math/rand instead of crypto/rand for security-sensitive operations
    rand.Seed(time.Now().UnixNano())
    return strconv.Itoa(rand.Int())
}

// 6. Hardcoded credentials
const (
    DatabasePassword = "admin123"
    APIKey          = "sk-1234567890abcdef"
    JWTSecret       = "super_secret_key"
)

// 7. Information disclosure through error messages
func informationDisclosure(userID string) {
    if userID == "admin" {
        fmt.Println("Admin user detected - full database path: /var/db/users.db")
    }
}

// 8. Unvalidated redirect
func openRedirect(w http.ResponseWriter, r *http.Request) {
    // Redirect to user-provided URL without validation
    redirectURL := r.URL.Query().Get("url")
    http.Redirect(w, r, redirectURL, http.StatusFound)
}

// 9. File inclusion vulnerability
func fileInclusion(templateName string) {
    // Dynamic file inclusion without validation
    content, _ := ioutil.ReadFile("templates/" + templateName + ".html")
    fmt.Println(string(content))
}

// 10. Insecure file permissions
func insecureFilePermissions(filename string, content []byte) {
    // Writing file with overly permissive permissions
    ioutil.WriteFile(filename, content, 0777)
}

// 11. Race condition
var counter int

func raceCondition() {
    // Concurrent access without proper synchronization
    for i := 0; i < 1000; i++ {
        go func() {
            counter++ // Not thread-safe
        }()
    }
}

// 12. Memory exhaustion (potential DoS)
func memoryExhaustion(size string) {
    // No validation of size parameter
    sizeInt, _ := strconv.Atoi(size)
    data := make([]byte, sizeInt) // Could allocate huge amounts of memory
    fmt.Printf("Allocated %d bytes\n", len(data))
}

// 13. Command injection via shell execution
func shellInjection(userInput string) {
    // Using sh -c with user input
    cmd := exec.Command("sh", "-c", "echo "+userInput)
    output, _ := cmd.Output()
    fmt.Println(string(output))
}

// 14. Directory traversal in file operations
func directoryTraversal(basePath, userPath string) {
    // No validation against directory traversal
    fullPath := basePath + "/" + userPath
    file, _ := os.Open(fullPath)
    defer file.Close()
}

// 15. Unsafe reflection usage
func unsafeReflection(className string) {
    // Dynamic class loading based on user input
    fmt.Printf("Loading class: %s\n", className)
    // In a real scenario, this would use reflection to instantiate
}

func main() {
    fmt.Println("Vulnerable Go examples compiled successfully")
    // Example usage (commented to prevent actual execution)
    // commandInjection("file.txt; rm -rf /")
    // pathTraversal("../../../etc/passwd")
}
