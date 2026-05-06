"""
FinVault - Demo Banking Portal
Intentionally vulnerable target application for deception platform testing.

VULNERABILITY: SQL Injection on /login and /register (string interpolation, no parameterization)
PURPOSE: Used as a honeypot/deception platform test target — NOT for production use.
"""

import sqlite3
import os
import json
import datetime
from functools import wraps
from flask import (
    Flask, request, session, redirect, url_for,
    render_template, jsonify, g, abort
)

app = Flask(__name__)
app.secret_key = "finvault_demo_secret_2024"  # Weak static secret — intentional
DB_PATH = os.path.join(os.path.dirname(__file__), "db", "finvault.db")

# ─── DB helpers ──────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cur = db.cursor()

    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            email       TEXT,
            role        TEXT DEFAULT 'user',
            full_name   TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            account_no  TEXT UNIQUE NOT NULL,
            type        TEXT DEFAULT 'savings',
            balance     REAL DEFAULT 0.0,
            currency    TEXT DEFAULT 'USD',
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  INTEGER,
            type        TEXT,
            amount      REAL,
            description TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (account_id) REFERENCES accounts(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event       TEXT,
            username    TEXT,
            ip          TEXT,
            user_agent  TEXT,
            payload     TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        );
    """)

    # Seed realistic users (passwords stored plaintext — intentional)
    users = [
        ("admin",   "admin123",      "admin@finvault.io",   "admin",   "System Administrator"),
        ("jdoe",    "password1",     "john.doe@gmail.com",  "user",    "John Doe"),
        ("mwanjiku","Nairobi@2024",  "m.wanjiku@kra.go.ke", "user",    "Mary Wanjiku"),
        ("tkoech",  "Timu#567",      "t.koech@equity.co.ke","user",    "Timothy Koech"),
        ("aogola",  "Ariel2023!",    "a.ogola@safaricom.ke","manager", "Achieng Ogola"),
    ]
    for u in users:
        try:
            cur.execute(
                "INSERT INTO users (username,password,email,role,full_name) VALUES (?,?,?,?,?)", u
            )
        except sqlite3.IntegrityError:
            pass

    db.commit()

    # Seed accounts
    seeds = [
        (1, "FV-0000-ADMIN", "current",  500000.00),
        (2, "FV-1001-JDOE",  "savings",   12450.75),
        (2, "FV-1002-JDOE",  "current",    3200.00),
        (3, "FV-2001-MWA",   "savings",   87340.50),
        (4, "FV-3001-TKO",   "savings",    9100.25),
        (5, "FV-4001-AOG",   "current",   45600.00),
    ]
    for s in seeds:
        try:
            cur.execute(
                "INSERT INTO accounts (user_id,account_no,type,balance) VALUES (?,?,?,?)", s
            )
        except sqlite3.IntegrityError:
            pass

    db.commit()

    # Seed transactions
    txns = [
        (2, "credit", 5000.00, "Salary deposit - April 2024"),
        (2, "debit",  1200.50, "Utility bill - Kenya Power"),
        (2, "debit",   350.00, "M-PESA withdrawal"),
        (3, "credit", 50000.0, "Property rental income"),
        (3, "debit",  8000.00, "NHIF & NSSF contribution"),
        (4, "credit",  2500.0, "Freelance payment"),
        (5, "credit", 15000.0, "Quarterly bonus"),
        (5, "debit",  3200.00, "Staff salary disbursement"),
    ]
    for t in txns:
        try:
            cur.execute(
                "INSERT INTO transactions (account_id,type,amount,description) VALUES (?,?,?,?)", t
            )
        except sqlite3.IntegrityError:
            pass

    db.commit()
    db.close()

# ─── Audit logging ───────────────────────────────────────────────────────────

def log_event(event, username="anonymous", payload=""):
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (event,username,ip,user_agent,payload) VALUES (?,?,?,?,?)",
            (event, username, request.remote_addr,
             request.headers.get("User-Agent",""), str(payload))
        )
        db.commit()
        db.close()
    except Exception:
        pass

# ─── Auth decorator ───────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# ══════════════════════════════════════════════════════════════════
#  VULNERABLE LOGIN — raw string interpolation, no parameterization
# ══════════════════════════════════════════════════════════════════
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        log_event("LOGIN_ATTEMPT", username, {"username": username})

        db = get_db()
        # ⚠️  INTENTIONAL SQL INJECTION VULNERABILITY ⚠️
        # Classic bypass: username = admin'-- or ' OR '1'='1
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            row = db.execute(query).fetchone()
        except Exception as e:
            log_event("SQL_ERROR", username, str(e))
            error = "Database error."
            db.close()
            return render_template("login.html", error=error)

        db.close()

        if row:
            session["user_id"]  = row["id"]
            session["username"] = row["username"]
            session["role"]     = row["role"]
            session["full_name"]= row["full_name"]
            log_event("LOGIN_SUCCESS", row["username"])
            return redirect(url_for("dashboard"))
        else:
            log_event("LOGIN_FAILED", username, {"username": username})
            error = "Invalid credentials. Please try again."

    return render_template("login.html", error=error)

# ══════════════════════════════════════════════════════════════════
#  VULNERABLE REGISTER — raw string interpolation
# ══════════════════════════════════════════════════════════════════
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        username  = request.form.get("username", "")
        password  = request.form.get("password", "")
        email     = request.form.get("email", "")
        full_name = request.form.get("full_name", "")

        log_event("REGISTER_ATTEMPT", username, {"username": username, "email": email})

        db = get_db()
        # ⚠️  INTENTIONAL SQL INJECTION VULNERABILITY ⚠️
        check_query = f"SELECT id FROM users WHERE username='{username}'"
        try:
            exists = db.execute(check_query).fetchone()
            if exists:
                error = "Username already taken."
            else:
                insert_query = (
                    f"INSERT INTO users (username,password,email,full_name) "
                    f"VALUES ('{username}','{password}','{email}','{full_name}')"
                )
                db.execute(insert_query)
                db.commit()
                log_event("REGISTER_SUCCESS", username)
                success = "Account created! You may now log in."
        except Exception as e:
            log_event("SQL_ERROR", username, str(e))
            error = f"Registration error: {str(e)}"
        db.close()

    return render_template("register.html", error=error, success=success)

@app.route("/logout")
def logout():
    log_event("LOGOUT", session.get("username","?"))
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    accounts = db.execute(
        "SELECT * FROM accounts WHERE user_id=?", (session["user_id"],)
    ).fetchall()
    recent_txns = []
    for acc in accounts:
        txns = db.execute(
            "SELECT * FROM transactions WHERE account_id=? ORDER BY created_at DESC LIMIT 5",
            (acc["id"],)
        ).fetchall()
        recent_txns.extend(txns)
    db.close()
    return render_template("dashboard.html",
                           accounts=accounts,
                           transactions=recent_txns)

@app.route("/profile")
@login_required
def profile():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    db.close()
    return render_template("profile.html", user=user)

@app.route("/transactions")
@login_required
def transactions():
    db = get_db()
    accounts = db.execute(
        "SELECT * FROM accounts WHERE user_id=?", (session["user_id"],)
    ).fetchall()
    all_txns = []
    for acc in accounts:
        txns = db.execute(
            "SELECT t.*, a.account_no FROM transactions t "
            "JOIN accounts a ON t.account_id=a.id "
            "WHERE t.account_id=? ORDER BY t.created_at DESC",
            (acc["id"],)
        ).fetchall()
        all_txns.extend(txns)
    db.close()
    return render_template("transactions.html", transactions=all_txns)

# Admin-only audit log — useful for your deception platform to cross-check
@app.route("/admin/audit")
@login_required
def audit_log():
    if session.get("role") != "admin":
        abort(403)
    db = get_db()
    logs = db.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    db.close()
    return render_template("audit.html", logs=logs)

# JSON endpoint — exposes session info (intentionally weak, for testing)
@app.route("/api/whoami")
@login_required
def whoami():
    return jsonify({
        "user_id":   session["user_id"],
        "username":  session["username"],
        "role":      session["role"],
        "full_name": session["full_name"],
    })

# ─── Bootstrap & run ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs("db", exist_ok=True)
    init_db()
    print("\n  FinVault Demo Target")
    print("  ────────────────────────────────────────")
    print("  URL:          http://localhost:5000")
    print("  Test users:   admin/admin123  jdoe/password1")
    print("  SQLi bypass:  username: admin'--  password: anything")
    print("  ────────────────────────────────────────\n")
    app.run(debug=True, host="0.0.0.0", port=5000)