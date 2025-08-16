import java.io.*;
import java.net.*;
import java.sql.*;
import java.security.MessageDigest;
import java.util.*;
import javax.servlet.http.*;
import java.lang.reflect.*;

public class VulnerableJava {

    // 1. SQL Injection vulnerability
    public void sqlInjection(String userId) throws SQLException {
        // Direct string concatenation - vulnerable to SQL injection
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }

    // 2. Command Injection
    public void commandInjection(String filename) throws IOException {
        // User input directly passed to Runtime.exec
        Runtime runtime = Runtime.getRuntime();
        Process process = runtime.exec("cat " + filename);
    }

    // 3. Path Traversal
    public String pathTraversal(String filename) throws IOException {
        // No validation of filename - allows directory traversal
        File file = new File("/uploads/" + filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        return reader.readLine();
    }

    // 4. Deserialization vulnerability
    public Object unsafeDeserialization(byte[] data) throws Exception {
        // Deserializing untrusted data
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject(); // Vulnerable to deserialization attacks
    }

    // 5. Weak cryptography - MD5
    public String weakCrypto(String password) throws Exception {
        // MD5 is cryptographically broken
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(digest);
    }

    // 6. Hardcoded credentials
    private static final String DATABASE_PASSWORD = "admin123";
    private static final String API_KEY = "sk-1234567890abcdef";
    private static final String JWT_SECRET = "super_secret_key";

    // 7. LDAP Injection
    public void ldapInjection(String username) throws Exception {
        // User input directly concatenated into LDAP query
        String filter = "(uid=" + username + ")";
        // LDAP search with vulnerable filter
        System.out.println("LDAP Filter: " + filter);
    }

    // 8. XPath Injection
    public void xpathInjection(String userId) throws Exception {
        // User input directly concatenated into XPath expression
        String expression = "/users/user[@id='" + userId + "']";
        // XPath query with vulnerable expression
        System.out.println("XPath: " + expression);
    }

    // 9. Open Redirect
    public void openRedirect(HttpServletResponse response, String url) throws IOException {
        // Redirect to user-provided URL without validation
        response.sendRedirect(url);
    }

    // 10. Insecure Random Number Generation
    public String insecureRandom() {
        // Using Random instead of SecureRandom for security-sensitive operations
        Random random = new Random();
        return String.valueOf(random.nextLong());
    }

    // 11. XML External Entity (XXE) vulnerability
    public void xxeVulnerability(String xmlInput) throws Exception {
        // XML parser without disabling external entities
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new ByteArrayInputStream(xmlInput.getBytes()));
    }

    // 12. Reflection-based code execution
    public void unsafeReflection(String className, String methodName) throws Exception {
        // Dynamic class loading and method invocation based on user input
        Class<?> clazz = Class.forName(className);
        Method method = clazz.getMethod(methodName);
        method.invoke(clazz.newInstance());
    }

    // 13. File upload without validation
    public void unsafeFileUpload(String filename, byte[] content) throws IOException {
        // No validation of file type or content
        FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
        fos.write(content);
        fos.close();
    }

    // 14. Information disclosure through stack traces
    public void informationDisclosure(String input) {
        try {
            int value = Integer.parseInt(input);
        } catch (NumberFormatException e) {
            // Exposing full stack trace to user
            e.printStackTrace();
            System.out.println("Error occurred with input: " + input);
            System.out.println("Database connection string: jdbc:mysql://internal-db:3306/prod");
        }
    }

    // 15. Unsafe URL connection
    public void unsafeUrlConnection(String userUrl) throws Exception {
        // Opening connection to user-provided URL without validation
        URL url = new URL(userUrl);
        URLConnection connection = url.openConnection();
        InputStream inputStream = connection.getInputStream();
    }

    // 16. Race condition
    private int counter = 0;

    public void raceCondition() {
        // Concurrent access without proper synchronization
        for (int i = 0; i < 1000; i++) {
            new Thread(() -> {
                counter++; // Not thread-safe
            }).start();
        }
    }

    // 17. Server-Side Request Forgery (SSRF)
    public String ssrfVulnerability(String url) throws IOException {
        // Making HTTP request to user-provided URL
        URL targetUrl = new URL(url);
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(targetUrl.openStream())
        );
        return reader.readLine();
    }

    public static void main(String[] args) {
        System.out.println("Vulnerable Java examples compiled successfully");
        // Example usage (commented to prevent actual execution)
        // VulnerableJava vj = new VulnerableJava();
        // vj.commandInjection("file.txt; rm -rf /");
    }
}
