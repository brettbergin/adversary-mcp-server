/**
 * Example vulnerable JavaScript code for demonstration purposes.
 *
 * This file contains intentional security vulnerabilities for educational purposes.
 * DO NOT use these patterns in production code.
 */

// VULNERABILITY: DOM-based XSS
function updateUserProfile(username) {
    document.getElementById('profile').innerHTML = '<h1>Welcome ' + username + '</h1>';
}

// VULNERABILITY: Code injection via eval
function processUserExpression(expression) {
    try {
        var result = eval('(' + expression + ')');
        console.log('Result:', result);
        return result;
    } catch (e) {
        console.error('Error:', e);
    }
}

// VULNERABILITY: Function constructor injection
function dynamicFunction(userCode) {
    var func = new Function('return ' + userCode);
    return func();
}

// VULNERABILITY: setTimeout/setInterval injection
function scheduleUserAction(action, delay) {
    setTimeout('console.log("' + action + '")', delay);
}

// VULNERABILITY: innerHTML with user content
function displayMessage(message) {
    document.body.innerHTML += '<div class="message">' + message + '</div>';
}

// VULNERABILITY: Document.write with user input
function legacyContentInjection(content) {
    document.write('<p>' + content + '</p>');
}

// VULNERABILITY: Location manipulation
function redirectUser(url) {
    // No validation on URL
    window.location = url;
}

// VULNERABILITY: Postmessage without origin validation
function handleMessage(event) {
    // No origin validation
    document.getElementById('content').innerHTML = event.data;
}
window.addEventListener('message', handleMessage);

// VULNERABILITY: JSONP callback injection
function loadUserData(callback) {
    var script = document.createElement('script');
    script.src = 'https://api.example.com/user?callback=' + callback;
    document.head.appendChild(script);
}

// VULNERABILITY: SQL-like injection in NoSQL queries
function searchProducts(query) {
    // Simulating NoSQL injection
    var searchQuery = {
        $where: 'this.name.match(/' + query + '/i)'
    };
    console.log('Searching with:', searchQuery);
}

// VULNERABILITY: Prototype pollution
function mergeObjects(target, source) {
    for (var key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            mergeObjects(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// VULNERABILITY: Hardcoded API keys
const API_CONFIG = {
    apiKey: 'sk-1234567890abcdef1234567890abcdef',
    secretKey: 'secret-key-12345',
    databaseUrl: 'mongodb://admin:password@localhost:27017/myapp'
};

// VULNERABILITY: Weak random number generation for security
function generateSessionToken() {
    return Math.random().toString(36).substr(2, 9);
}

// VULNERABILITY: Insecure data transmission
function sendSensitiveData(data) {
    // Sending over HTTP instead of HTTPS
    fetch('http://api.example.com/sensitive', {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {
            'Content-Type': 'application/json'
        }
    });
}

// VULNERABILITY: Local storage of sensitive data
function storeSensitiveInfo(username, password) {
    localStorage.setItem('username', username);
    localStorage.setItem('password', password); // Never store passwords in localStorage!
}

// VULNERABILITY: CSRF-prone state changes
function deleteAccount(userId) {
    // No CSRF protection
    fetch('/api/users/' + userId, {
        method: 'DELETE'
    });
}

// VULNERABILITY: Regex DoS (ReDoS)
function validateEmail(email) {
    var regex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;
    // This regex can cause catastrophic backtracking
    return regex.test(email);
}

// VULNERABILITY: Information disclosure in error messages
function processUserData(userData) {
    try {
        // Process data
        return JSON.parse(userData);
    } catch (error) {
        // Exposing internal error details
        console.error('Full error details:', error.stack);
        throw new Error('Failed to process data: ' + error.message + ' at ' + error.stack);
    }
}

// VULNERABILITY: Path traversal in file operations (Node.js context)
function serveFile(filename) {
    if (typeof require !== 'undefined') {
        const fs = require('fs');
        const path = require('path');

        // No path validation - allows ../../../etc/passwd
        const filepath = path.join('./uploads', filename);
        return fs.readFileSync(filepath, 'utf8');
    }
}

// Example usage (for demonstration only)
if (typeof window !== 'undefined') {
    console.log('Vulnerable JavaScript loaded - for educational purposes only');

    // DOM-based vulnerabilities
    document.addEventListener('DOMContentLoaded', function() {
        // Simulate user input that could be malicious
        updateUserProfile('<script>alert("XSS")</script>');

        // Code injection
        processUserExpression('alert("Code injection")');

        // Generate weak session token
        console.log('Weak token:', generateSessionToken());
    });
}
