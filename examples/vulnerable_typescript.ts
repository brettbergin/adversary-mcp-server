import yaml from 'js-yaml';
import { exec } from 'child_process';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

// 1. YAML Deserialization vulnerability
export function vulnerableYamlLoad(userInput: string) {
    // This should be detected as unsafe yaml deserialization
    const parsed = yaml.load(userInput);
    return parsed;
}

// 2. Command Injection
export function commandInjection(userInput: string) {
    // Direct command execution with user input
    exec(`ls ${userInput}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// 3. Path Traversal
export function pathTraversal(filename: string) {
    // No sanitization of filename
    const filePath = path.join('/uploads/', filename);
    return fs.readFileSync(filePath);
}

// 4. SQL Injection (simulated)
export function sqlInjection(userId: string) {
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    // This would be vulnerable if executed
    return query;
}

// 5. Hardcoded credentials
export const DATABASE_PASSWORD = 'admin123';
export const API_KEY = 'sk-1234567890abcdef';
export const SECRET_TOKEN = 'super_secret_token_123';

// 6. Weak cryptography
export function weakCrypto(data: string) {
    // Using deprecated MD5
    return crypto.createHash('md5').update(data).digest('hex');
}

// 7. Insecure random number generation
export function insecureRandom() {
    // Math.random() is not cryptographically secure
    return Math.random().toString(36);
}

// 8. XSS via innerHTML (if this were browser code)
export function xssVulnerable(userInput: string) {
    // This would be XSS if executed in browser
    const element = `<div innerHTML="${userInput}"></div>`;
    return element;
}

// 9. Open redirect
export function openRedirect(url: string) {
    // No validation of redirect URL
    window.location.href = url;
}

// 10. Insecure file permissions
export function writeFile(filename: string, content: string) {
    // Writing file with overly permissive permissions
    fs.writeFileSync(filename, content, { mode: 0o777 });
}

// 11. Prototype pollution
export function prototypePollution(obj: any, key: string, value: any) {
    // No protection against __proto__ or constructor pollution
    obj[key] = value;
    return obj;
}

// 12. Unsafe eval
export function unsafeEval(userCode: string) {
    // Direct execution of user-provided code
    return eval(userCode);
}
