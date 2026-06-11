"""
secure_app.py
Remediated version of vulnerable_app.py.
All five vulnerabilities have been fixed following secure coding best practices.
"""

import sqlite3
import hashlib
import os
import secrets
import getpass

# -----------------------------------------------------------------------
# FIX 1: No Hardcoded Credentials
# Credentials are loaded from environment variables.
# If not set, the app refuses to start rather than falling back to defaults.
# -----------------------------------------------------------------------
ADMIN_USERNAME = os.environ.get("APP_ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("APP_ADMIN_PASS")

if not ADMIN_USERNAME or not ADMIN_PASSWORD:
    raise EnvironmentError(
        "APP_ADMIN_USER and APP_ADMIN_PASS must be set as environment variables."
    )

DB_PATH = "users_secure.db"


def hash_password(password: str, salt: str = None):
    """
    FIX 2: Strong Hashing with Salt (SHA-256 + random salt)
    Each password gets a unique random salt. SHA-256 replaces MD5.
    This defeats rainbow table and brute-force attacks.
    For production, use bcrypt or argon2 instead.
    """
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return hashed, salt


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            salt TEXT
        )
    """)
    # Store admin with hashed + salted password
    pw_hash, salt = hash_password(ADMIN_PASSWORD)
    cursor.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, salt) VALUES (1, ?, ?, ?)",
        (ADMIN_USERNAME, pw_hash, salt)
    )
    conn.commit()
    conn.close()


def login(username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # FIX 3: Parameterized Query (Prevents SQL Injection)
    # User input is passed as a parameter, never concatenated into the query.
    # The database driver handles escaping safely.
    cursor.execute(
        "SELECT id, username, password_hash, salt FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()

    if user is None:
        return None

    user_id, uname, stored_hash, salt = user
    input_hash, _ = hash_password(password, salt)

    # FIX 4: Safe Error Handling — no internal details exposed
    # Comparison uses secrets.compare_digest to prevent timing attacks
    if secrets.compare_digest(input_hash, stored_hash):
        return (user_id, uname)

    return None


def read_file(base_dir: str, filename: str):
    # FIX 5: Path Traversal Prevention
    # os.path.realpath resolves all ".." and symlinks.
    # We then verify the resolved path still starts with base_dir.
    base_dir = os.path.realpath(base_dir)
    requested_path = os.path.realpath(os.path.join(base_dir, filename))

    if not requested_path.startswith(base_dir + os.sep):
        # FIX 4 (applied here too): Generic error message, no path details leaked
        print("[ERROR] Access denied: invalid file path.")
        return None

    # Only allow .txt files as an extra safety measure
    if not requested_path.endswith(".txt"):
        print("[ERROR] Only .txt files are permitted.")
        return None

    try:
        with open(requested_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        print("[ERROR] File not found.")
        return None
    except Exception:
        # FIX 4: Generic error — no internal details exposed
        print("[ERROR] Could not read the file.")
        return None


def main():
    init_db()
    print("=== Secure File Manager ===")
    username = input("Username: ")

    # Use getpass so the password is not echoed to the terminal
    password = getpass.getpass("Password: ")

    user = login(username, password)

    if user:
        print(f"\n[+] Login successful. Welcome, {user[1]}!")
        base_dir = "/tmp/secure_user_files"
        os.makedirs(base_dir, exist_ok=True)

        filename = input("\nEnter filename to read (must be a .txt file): ")
        content = read_file(base_dir, filename)
        if content:
            print(f"\n--- File Contents ---\n{content}")
    else:
        # FIX 4: Generic failure message — no hint about which field was wrong
        print("[-] Invalid credentials.")


if __name__ == "__main__":
    main()
