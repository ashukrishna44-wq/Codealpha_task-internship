# Task 3 — Secure Coding Review

## Overview
A complete security audit performed on a vulnerable Python-based Login and File Manager CLI application. The review identifies security vulnerabilities, demonstrates proof-of-concept attacks, and provides a fully remediated secure version of the application.

## Files
| File | Description |
|---|---|
| `vulnerable_app.py` | Original app with intentional security vulnerabilities |
| `secure_app.py` | Fully fixed and remediated version |
| `Secure_Coding_Review_CodeAlpha.pdf` | Detailed audit report with findings and fixes |

## Vulnerabilities Found

| ID | Vulnerability | Severity |
|---|---|---|
| VUL-001 | SQL Injection — Authentication Bypass | 🔴 Critical |
| VUL-002 | Hardcoded Credentials | 🟠 High |
| VUL-003 | Path Traversal — Arbitrary File Read | 🟠 High |
| VUL-004 | Weak Hashing (MD5, No Salt) | 🟡 Medium |
| VUL-005 | Information Leakage via Error Messages | 🟡 Medium |

## How to Test

**Run vulnerable app:**
```bash
python vulnerable_app.py
```

**Test SQL Injection:**
Username: ' OR '1'='1' --
Password: anything

**Test Path Traversal:**
Enter filename: ../../etc/passwd

**Run secure app (set env variables first):**
```bash
# Windows
set APP_ADMIN_USER=admin
set APP_ADMIN_PASS=admin123
python secure_app.py

# Linux/Mac
export APP_ADMIN_USER=admin
export APP_ADMIN_PASS=admin123
python secure_app.py
```

## Methodology
- Static Code Analysis
- Manual Code Inspection
- OWASP Top 10 (2021) Reference

## Tools Used
- **Python 3.x**
- **SQLite** — database
- **ReportLab** — PDF report generation
