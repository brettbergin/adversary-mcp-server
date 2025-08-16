require 'digest'
require 'open3'
require 'sqlite3'
require 'net/http'
require 'uri'

# 1. SQL Injection vulnerability
def sql_injection(user_id)
  # Direct string interpolation - vulnerable to SQL injection
  db = SQLite3::Database.new("test.db")
  query = "SELECT * FROM users WHERE id = '#{user_id}'"
  db.execute(query)
end

# 2. Command Injection
def command_injection(filename)
  # User input directly passed to system command
  output = `cat #{filename}`
  puts output
end

# 3. Path Traversal
def path_traversal(filename)
  # No validation of filename - allows directory traversal
  content = File.read("/uploads/#{filename}")
  puts content
end

# 4. Code Injection via eval
def code_injection(user_code)
  # Direct execution of user-provided code
  eval(user_code)
end

# 5. Weak cryptography - MD5
def weak_crypto(password)
  # MD5 is cryptographically broken
  Digest::MD5.hexdigest(password)
end

# 6. Hardcoded credentials
DATABASE_PASSWORD = 'admin123'
API_KEY = 'sk-1234567890abcdef'
JWT_SECRET = 'super_secret_key'

# 7. Open Redirect
def open_redirect(url)
  # Redirect to user-provided URL without validation
  # In Rails: redirect_to url
  puts "Redirecting to: #{url}"
end

# 8. Insecure random number generation
def insecure_random
  # Using rand instead of SecureRandom for security-sensitive operations
  rand(1000..9999).to_s
end

# 9. YAML deserialization vulnerability
def yaml_deserialization(user_input)
  # Unsafe YAML loading
  YAML.load(user_input)
end

# 10. Regular expression DoS (ReDoS)
def redos_vulnerability(user_input)
  # Vulnerable regex pattern
  regex = /^(a+)+$/
  user_input =~ regex
end

# 11. File inclusion vulnerability
def file_inclusion(template_name)
  # Dynamic file inclusion without validation
  require "/templates/#{template_name}"
end

# 12. Information disclosure
def information_disclosure(input)
  begin
    value = Integer(input)
  rescue ArgumentError => e
    # Exposing sensitive information in error messages
    puts "Error: #{e.message}"
    puts "Database connection: sqlite3://#{Dir.pwd}/production.db"
    puts "Current file: #{__FILE__}"
  end
end

# 13. Unsafe deserialization with Marshal
def unsafe_marshal(data)
  # Deserializing untrusted data with Marshal
  Marshal.load(data)
end

# 14. Server-Side Request Forgery (SSRF)
def ssrf_vulnerability(url)
  # Making HTTP request to user-provided URL
  uri = URI.parse(url)
  response = Net::HTTP.get_response(uri)
  response.body
end

# 15. Race condition
$counter = 0

def race_condition
  # Concurrent access without proper synchronization
  1000.times do
    Thread.new do
      $counter += 1  # Not thread-safe
    end
  end
end

# 16. Unsafe file operations
def unsafe_file_operations(filename, content)
  # Writing file with overly permissive permissions
  File.open(filename, 'w', 0777) do |f|
    f.write(content)
  end
end

# 17. Template injection
def template_injection(user_input)
  # User input directly embedded in template
  template = "Hello #{user_input}!"
  eval("\"#{template}\"")
end

# 18. Mass assignment vulnerability
class User
  attr_accessor :name, :email, :admin, :password

  def initialize(params)
    # No protection against mass assignment
    params.each do |key, value|
      send("#{key}=", value)
    end
  end
end

# 19. Timing attack vulnerability
def timing_attack(user_token, expected_token)
  # Vulnerable to timing attacks due to early return
  return false if user_token.length != expected_token.length

  user_token.each_char.with_index do |char, index|
    return false if char != expected_token[index]
  end

  true
end

# 20. Unsafe reflection
def unsafe_reflection(class_name, method_name)
  # Dynamic class instantiation and method calling
  klass = Object.const_get(class_name)
  instance = klass.new
  instance.send(method_name)
end

# Example usage (commented to prevent actual execution)
# command_injection("file.txt; rm -rf /")
# path_traversal("../../../etc/passwd")
# code_injection("puts 'Hello World'")

puts "Vulnerable Ruby examples loaded successfully"
