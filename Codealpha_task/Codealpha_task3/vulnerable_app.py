"""
vulnerable_app.py
A simple Login + File Manager CLI application.
NOTE: This file is intentionally written with security vulnerabilities
for educational/audit purposes as part of a Secure Coding Review.
"""

import sqlite3
import hashlib
import os

# -----------------------------------------------------------------------
# VULNERABILITY 1: Hardcoded Credentials
# Admin credentials are hardcoded directly in source code.
# Anyone with access to this file gains immediate admin access.
# -----------------------------------------------------------------------
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"  # Hardcoded plaintext password

DB_PATH = "users.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """)
    # VULNERABILITY 2: Weak Hashing (MD5)
    # MD5 is cryptographically broken. It is fast to brute-force and
    # does not use salting, making it trivial to reverse via rainbow tables.
    md5_pass = hashlib.md5(ADMIN_PASSWORD.encode()).hexdigest()
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', ?)", (md5_pass,))
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (2, 'alice', ?)",
                   (hashlib.md5(b"password123").hexdigest(),))
    conn.commit()
    conn.close()


def login(username, password):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULNERABILITY 3: SQL Injection
    # User input is directly concatenated into the SQL query without
    # sanitization or parameterization. An attacker can input:
    # username = ' OR '1'='1
    # to bypass authentication entirely.
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"

    try:
        cursor.execute(query)
        user = cursor.fetchone()
    except Exception as e:
        # VULNERABILITY 4: Insecure Error Handling (Information Leakage)
        # The raw exception and full SQL query are printed to the user.
        # This exposes internal structure, table names, and query logic
        # to an attacker performing reconnaissance.
        print(f"[ERROR] Database query failed: {e}")
        print(f"[DEBUG] Query was: {query}")
        return None
    finally:
        conn.close()

    return user


def read_file(base_dir, filename):
    # VULNERABILITY 5: Path Traversal
    # The filename is joined with base_dir without any validation.
    # An attacker can supply: filename = "../../etc/passwd"
    # to read arbitrary files outside the intended directory.
    filepath = os.path.join(base_dir, filename)

    try:
        with open(filepath, "r") as f:
            return f.read()
    except Exception as e:
        # VULNERABILITY 4 (repeated): Raw error exposed to user
        print(f"[ERROR] Could not read file: {e}")
        print(f"[DEBUG] Attempted path: {filepath}")
        return None


def main():
    init_db()
    print("=== Secure File Manager ===")
    username = input("Username: ")
    password_input = input("Password: ")

    # Hash input with MD5 before comparing (weak hash)
    hashed_input = hashlib.md5(password_input.encode()).hexdigest()
    user = login(username, hashed_input)

    if user:
        print(f"\n[+] Login successful. Welcome, {user[1]}!")
        base_dir = "/tmp/user_files"
        os.makedirs(base_dir, exist_ok=True)

        filename = input("\nEnter filename to read: ")
        content = read_file(base_dir, filename)
        if content:
            print(f"\n--- File Contents ---\n{content}")
    else:
        print("[-] Login failed.")


if __name__ == "__main__":
    main()
