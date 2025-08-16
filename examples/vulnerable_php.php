<?php
// 1. SQL Injection vulnerability
function sqlInjection($userId) {
    $connection = new mysqli("localhost", "user", "password", "database");
    // Direct string concatenation - vulnerable to SQL injection
    $query = "SELECT * FROM users WHERE id = '" . $userId . "'";
    $result = $connection->query($query);
    return $result;
}

// 2. Command Injection
function commandInjection($filename) {
    // User input directly passed to shell command
    $output = shell_exec("cat " . $filename);
    echo $output;
}

// 3. Path Traversal
function pathTraversal($filename) {
    // No validation of filename - allows directory traversal
    $content = file_get_contents("/uploads/" . $filename);
    echo $content;
}

// 4. Code Injection via eval()
function codeInjection($userCode) {
    // Direct execution of user-provided code
    eval($userCode);
}

// 5. File Inclusion vulnerability
function fileInclusion($page) {
    // Dynamic file inclusion without validation
    include("/pages/" . $page . ".php");
}

// 6. Cross-Site Scripting (XSS)
function xssVulnerability($userInput) {
    // Direct output of user input without escaping
    echo "<div>Hello " . $userInput . "</div>";
}

// 7. LDAP Injection
function ldapInjection($username) {
    // User input directly concatenated into LDAP filter
    $filter = "(uid=" . $username . ")";
    // LDAP search with vulnerable filter
    echo "LDAP Filter: " . $filter;
}

// 8. Weak cryptography - MD5
function weakCrypto($password) {
    // MD5 is cryptographically broken
    return md5($password);
}

// 9. Hardcoded credentials
define('DATABASE_PASSWORD', 'admin123');
define('API_KEY', 'sk-1234567890abcdef');
define('JWT_SECRET', 'super_secret_key');

// 10. Open Redirect
function openRedirect() {
    // Redirect to user-provided URL without validation
    $redirectUrl = $_GET['url'];
    header("Location: " . $redirectUrl);
    exit();
}

// 11. Insecure random number generation
function insecureRandom() {
    // Using rand() instead of cryptographically secure random
    return rand(1000, 9999);
}

// 12. XML External Entity (XXE) vulnerability
function xxeVulnerability($xmlInput) {
    // XML parser with external entities enabled
    $doc = new DOMDocument();
    $doc->loadXML($xmlInput); // Vulnerable to XXE attacks
    return $doc;
}

// 13. Unsafe deserialization
function unsafeDeserialization($data) {
    // Deserializing untrusted data
    return unserialize($data);
}

// 14. Information disclosure
function informationDisclosure($input) {
    try {
        $value = intval($input);
        if ($value === 0) {
            throw new Exception("Invalid input");
        }
    } catch (Exception $e) {
        // Exposing sensitive information in error messages
        echo "Error: " . $e->getMessage();
        echo "Database: mysqli://root:password@localhost/production";
        echo "File path: " . __FILE__;
    }
}

// 15. Session fixation
function sessionFixation() {
    // Not regenerating session ID after login
    $_SESSION['user_id'] = $_POST['user_id'];
    $_SESSION['logged_in'] = true;
}

// 16. Insecure file upload
function insecureFileUpload() {
    // No validation of file type or content
    $uploadDir = "/uploads/";
    $uploadFile = $uploadDir . $_FILES['file']['name'];
    move_uploaded_file($_FILES['file']['tmp_name'], $uploadFile);
}

// 17. Server-Side Request Forgery (SSRF)
function ssrfVulnerability($url) {
    // Making HTTP request to user-provided URL
    $content = file_get_contents($url);
    return $content;
}

// 18. Race condition
$counter = 0;
function raceCondition() {
    global $counter;
    // Not thread-safe (in multi-threaded PHP environments)
    $counter++;
}

// 19. Time-based blind SQL injection
function timeBlindsqlInjection($userId) {
    $connection = new mysqli("localhost", "user", "password", "database");
    // Vulnerable to time-based blind SQL injection
    $query = "SELECT * FROM users WHERE id = '" . $userId . "' AND SLEEP(5)";
    $result = $connection->query($query);
    return $result;
}

// 20. NoSQL Injection (MongoDB example)
function nosqlInjection($username) {
    // Assuming MongoDB PHP driver usage
    $filter = ['username' => $username]; // Could be manipulated if $username is an array
    // In real scenario: $collection->findOne($filter);
    return $filter;
}

// Example usage (commented to prevent actual execution)
// commandInjection("file.txt; rm -rf /");
// pathTraversal("../../../etc/passwd");
// codeInjection("phpinfo();");

echo "Vulnerable PHP examples loaded successfully\n";
?>
