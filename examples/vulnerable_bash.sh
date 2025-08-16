#!/bin/bash

# 1. Command Injection vulnerability
function command_injection() {
    local user_input="$1"
    # Direct execution of user input - vulnerable to command injection
    eval "echo $user_input"
    # Also vulnerable:
    bash -c "ls $user_input"
}

# 2. Path Traversal
function path_traversal() {
    local filename="$1"
    # No validation of filename - allows directory traversal
    cat "/uploads/$filename"
}

# 3. Hardcoded credentials
DATABASE_PASSWORD="admin123"
API_KEY="sk-1234567890abcdef"
JWT_SECRET="super_secret_key"

# 4. Insecure file permissions
function insecure_file_permissions() {
    local filename="$1"
    local content="$2"
    # Writing file with overly permissive permissions
    echo "$content" > "$filename"
    chmod 777 "$filename"
}

# 5. Information disclosure
function information_disclosure() {
    local user_input="$1"
    if [[ ! "$user_input" =~ ^[0-9]+$ ]]; then
        echo "Error: Invalid input '$user_input'"
        echo "Database connection: mysql://root:$DATABASE_PASSWORD@localhost/production"
        echo "Script location: $0"
        echo "Current user: $(whoami)"
        echo "Environment: $HOME"
    fi
}

# 6. Race condition
COUNTER=0
function race_condition() {
    for i in {1..1000}; do
        # Multiple processes could access this simultaneously
        COUNTER=$((COUNTER + 1))
    done
}

# 7. Unsafe use of temporary files
function unsafe_temp_files() {
    local data="$1"
    # Predictable temp file name - vulnerable to symlink attacks
    local temp_file="/tmp/data_$$"
    echo "$data" > "$temp_file"
    # File left with default permissions
}

# 8. Shell injection via variable substitution
function shell_injection() {
    local user_cmd="$1"
    # Unsafe variable substitution
    result=$(eval "$user_cmd")
    echo "$result"
}

# 9. Insecure random number generation
function insecure_random() {
    # Using RANDOM which is not cryptographically secure
    echo $RANDOM
}

# 10. Weak cryptography
function weak_crypto() {
    local password="$1"
    # Using MD5 (deprecated)
    echo -n "$password" | md5sum | cut -d' ' -f1
}

# 11. File inclusion vulnerability
function file_inclusion() {
    local script_name="$1"
    # Dynamic script inclusion without validation
    source "/scripts/$script_name.sh"
}

# 12. Unsafe curl usage
function unsafe_curl() {
    local url="$1"
    # No validation of URL, allows SSRF
    curl -s "$url"
    # Also unsafe - following redirects blindly
    curl -L "$url"
}

# 13. Improper input validation
function improper_validation() {
    local email="$1"
    # Weak email validation
    if [[ "$email" == *"@"* ]]; then
        echo "Valid email: $email"
        # Process email without proper sanitization
        mail -s "Subject" "$email" < /dev/null
    fi
}

# 14. Unsafe file operations
function unsafe_file_ops() {
    local source="$1"
    local dest="$2"
    # No validation of paths - allows overwriting system files
    cp "$source" "$dest"
}

# 15. SQL injection (via mysql command)
function sql_injection() {
    local user_id="$1"
    # Direct string interpolation in SQL query
    mysql -u root -p"$DATABASE_PASSWORD" -e "SELECT * FROM users WHERE id = '$user_id'"
}

# 16. XML External Entity (XXE) vulnerability
function xxe_vulnerability() {
    local xml_file="$1"
    # Processing XML without disabling external entities
    xmllint --format "$xml_file"
}

# 17. Unsafe archive extraction
function unsafe_extraction() {
    local archive="$1"
    # No path validation during extraction - zip slip vulnerability
    tar -xf "$archive"
    unzip "$archive"
}

# 18. Time-of-check to time-of-use (TOCTOU)
function toctou_vulnerability() {
    local filename="$1"

    # Check if file exists
    if [ -f "$filename" ]; then
        # Time gap - file could be changed/replaced
        sleep 1
        # Use file (could be different file now)
        cat "$filename"
    fi
}

# 19. Improper secret handling
function improper_secrets() {
    local secret="$1"
    # Secret appears in process list
    echo "Processing secret: $secret"
    # Secret written to log
    logger "API key used: $secret"
    # Secret in history
    echo "$secret" >> ~/.bash_history
}

# 20. Unsafe network operations
function unsafe_network() {
    local host="$1"
    local port="$2"
    # No validation of host/port - allows connection to arbitrary endpoints
    nc "$host" "$port"
}

# 21. Buffer overflow simulation (in bash context)
function buffer_overflow_sim() {
    local input="$1"
    # Creating extremely long environment variable
    export OVERFLOW_VAR="$input$(printf 'A%.0s' {1..10000})"
}

# 22. Privilege escalation attempt
function privilege_escalation() {
    # Attempting to modify system files
    echo "malicious content" > /etc/passwd 2>/dev/null
    # Attempting to create setuid binaries
    cp /bin/bash /tmp/rootshell 2>/dev/null
    chmod +s /tmp/rootshell 2>/dev/null
}

# Example usage (commented to prevent actual execution)
# command_injection "file.txt; cat /etc/passwd/"
# path_traversal "../../../etc/passwd"
# sql_injection "'; DROP TABLE users; --"

echo "Vulnerable Bash examples loaded successfully"

# Note: Many of these examples could cause system damage if executed
# They are for educational/testing purposes only
