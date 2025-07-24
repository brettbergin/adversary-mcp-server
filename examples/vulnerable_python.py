"""Example vulnerable Python code for demonstration purposes.

This file contains intentional security vulnerabilities for educational purposes.
DO NOT use these patterns in production code.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)


def vulnerable_sql_query(username, password):
    """SQL Injection vulnerability - string concatenation."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # VULNERABILITY: SQL Injection via string concatenation
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    cursor.execute(query)

    return cursor.fetchone()


def vulnerable_command_execution(user_input):
    """Command injection vulnerability - os.system with user input."""
    # VULNERABILITY: Command injection
    os.system("echo " + user_input)  # noqa: S605

    # Another command injection variant
    subprocess.call("ls " + user_input, shell=True)  # noqa: S602


def vulnerable_deserialization(serialized_data):
    """Unsafe deserialization vulnerability."""
    # VULNERABILITY: Unsafe pickle deserialization
    return pickle.loads(serialized_data)  # noqa: S301


def vulnerable_file_access(filename):
    """Path traversal vulnerability."""
    # VULNERABILITY: Path traversal - no input validation
    with open("/var/www/uploads/" + filename) as f:
        return f.read()


@app.route("/search")
def vulnerable_web_endpoint():
    """Web vulnerability example."""
    query = request.args.get("q", "")

    # VULNERABILITY: SQL injection in web context
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")

    results = cursor.fetchall()
    return str(results)


def hardcoded_secrets():
    """Information disclosure - hardcoded secrets."""
    # VULNERABILITY: Hardcoded API key
    api_key = "sk-1234567890abcdef1234567890abcdef"

    # VULNERABILITY: Hardcoded password
    admin_password = "admin123"

    # VULNERABILITY: Hardcoded database credentials
    db_connection = "postgresql://admin:password123@localhost:5432/mydb"

    return api_key, admin_password, db_connection


def weak_crypto():
    """Weak cryptographic practices."""
    # VULNERABILITY: Weak hashing algorithm
    password = "user_password"
    weak_hash = hashlib.md5(password.encode()).hexdigest()  # noqa: S324

    # VULNERABILITY: Predictable random numbers for security
    session_token = str(random.randint(1000, 9999))  # noqa: S311

    return weak_hash, session_token


def eval_vulnerability(user_code):
    """Code injection via eval."""
    # VULNERABILITY: Code injection
    result = eval(user_code)  # noqa: S307
    return result


def exec_vulnerability(user_script):
    """Code injection via exec."""
    # VULNERABILITY: Code injection
    exec(user_script)  # noqa: S102


if __name__ == "__main__":
    # Example usage (DO NOT RUN IN PRODUCTION)
    print("Example vulnerable code - for educational purposes only")

    # Test SQL injection
    vulnerable_sql_query("admin", "password")

    # Test command injection
    vulnerable_command_execution("test")

    # Test hardcoded secrets
    secrets = hardcoded_secrets()
    print(f"Found secrets: {secrets}")

    app.run(debug=True)  # noqa: S201
