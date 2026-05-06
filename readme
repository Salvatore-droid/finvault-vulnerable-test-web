# FinVault — Vulnerable Demo Target
## For Deception Platform Testing Only

---

## Quick Start

```bash
cd vuln-target
pip install flask
python app.py
# → http://localhost:5000
```

---

## Architecture

```
Flask (Python) → SQLite (finvault.db)
```

| File | Purpose |
|------|---------|
| `app.py` | Main app + routes + DB seed |
| `templates/` | Jinja2 HTML pages |
| `db/finvault.db` | Auto-created SQLite database |

---

## Seed Data

### Users (plaintext passwords — intentional)
| Username   | Password       | Role    |
|------------|----------------|---------|
| admin      | admin123       | admin   |
| jdoe       | password1      | user    |
| mwanjiku   | Nairobi@2024   | user    |
| tkoech     | Timu#567       | user    |
| aogola     | Ariel2023!     | manager |

### Accounts
| Account No      | Type    | Balance (USD) | Owner    |
|-----------------|---------|---------------|----------|
| FV-0000-ADMIN   | current | 500,000.00    | admin    |
| FV-1001-JDOE    | savings |  12,450.75    | jdoe     |
| FV-1002-JDOE    | current |   3,200.00    | jdoe     |
| FV-2001-MWA     | savings |  87,340.50    | mwanjiku |
| FV-3001-TKO     | savings |   9,100.25    | tkoech   |
| FV-4001-AOG     | current |  45,600.00    | aogola   |

---

## Vulnerabilities (Intentional)

### 1. SQL Injection — Login (/login POST)
**Vulnerable query:**
```python
f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
```

**Bypass payloads:**
```
# Classic comment bypass (no password needed)
username: admin'--
password: anything

# OR-always-true
username: ' OR '1'='1'--
password: x

# Union-based data extraction
username: ' UNION SELECT 1,username,password,email,role,full_name,created_at FROM users--
password: x

# Blind boolean test
username: admin' AND '1'='1
password: admin123
```

### 2. SQL Injection — Register (/register POST)
**Vulnerable query:**
```python
f"INSERT INTO users (username,password,email,full_name) VALUES ('{username}','{password}','{email}','{full_name}')"
```

**Stacked query (SQLite supports this via executescript):**
```
username: x', 'x', 'x', 'x'); DROP TABLE transactions;--
```

---

## Routes

| Route              | Auth | Description                          |
|--------------------|------|--------------------------------------|
| GET  /             | No   | Redirects to /login                  |
| GET  /login        | No   | Login form                           |
| POST /login        | No   | **VULNERABLE** — SQL injection       |
| GET  /register     | No   | Registration form                    |
| POST /register     | No   | **VULNERABLE** — SQL injection       |
| GET  /dashboard    | Yes  | Account overview + recent txns       |
| GET  /transactions | Yes  | Full transaction history             |
| GET  /profile      | Yes  | User profile + session info          |
| GET  /admin/audit  | Admin| Audit log (admin only)               |
| GET  /api/whoami   | Yes  | JSON: current session info           |
| GET  /logout       | Yes  | Clears session                       |

---

## Audit Log
All login attempts, successes, failures, and SQL errors are written to the
`audit_log` table. Admin users can view this at `/admin/audit`.

Your deception platform can:
- Hook into POST /login and POST /register
- Monitor the `audit_log` table directly
- Watch for SQL_ERROR events (dead giveaway of injection attempts)
- Flag sessions that use payloads containing `'`, `--`, `UNION`, `OR 1=1`

---

## Deception Platform Integration Points

```
Intercept layer:  Proxy between attacker and /login, /register
Detection signals:
  - SQL metacharacters in username/password field: ' " ; -- /* */
  - UNION keyword in any parameter
  - Multiple login failures from same session/IP
  - Login success without valid credential pair (SQLi bypass)
  - Requests to /admin/audit from non-admin session
  - Unusual User-Agent strings (sqlmap, curl, etc.)

Honeypot actions:
  - Return fake "success" response to bypass attempt
  - Log attacker session ID
  - Serve deceptive data (fake account numbers, fake admin data)
  - Rate-limit or tarpit the attacker session
```