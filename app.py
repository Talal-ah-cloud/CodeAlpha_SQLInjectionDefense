"""
CodeAlpha — Cloud Computing, Task 2: Detecting Data Leaks Using SQL Injection.

What it does (exactly what the task PDF asks for):
  1. A cloud-ready login system that secures user data against
     SQL injection attacks.
  2. AES-256 encryption (AES-GCM, 256-bit key) for stored
     credentials and sensitive info — nothing sensitive sits in
     the database as plaintext.
  3. Double-layer security:
       Layer 1 — parameterized queries (prepared statements):
                 user input is DATA, never part of the SQL.
       Layer 2 — AES-256 encryption at rest: even if a row leaks,
                 it is ciphertext, not a password.
     Plus input validation on top (a username must match a strict
     pattern before it ever reaches the database).
  4. Lightweight and internet-ready: Flask + SQLite, runs on a
     Free Tier EC2 t2.micro — no heavy system requirements.

Two login endpoints, side by side, so the difference is visible:
  - /login/vulnerable — INTENTIONALLY INSECURE demo. Builds SQL
    by string concatenation and trusts whatever the query returns.
    Typing  ' OR '1'='1  as the username turns the query into
    WHERE username = '' OR '1'='1' — every row matches, so the
    app logs you in as the first user and leaks their secret
    note. That is the data leak this task is about. NEVER use
    this pattern in real code — it exists here only to
    demonstrate the attack.
  - /login/secure — the fixed version. Parameterized query +
    validation + AES-256 encrypted credentials. The same
    injection string is treated as a literal username, matches
    nobody, and login fails.

"Capability code mechanism" (PDF wording, garbled): interpreted
here as parameterized queries / prepared statements — the
standard, correct defence. The database compiles the SQL
structure first, then binds the user input as data, so input
can never change what the query DOES.

Honest notes (demo vs production):
  - Passwords in production are HASHED (bcrypt/argon2), not
    encrypted. This task's PDF explicitly asks for AES-256
    encryption of stored credentials, so that is what is
    demonstrated here.
  - The encryption key comes from the CODEALPHA_AES_KEY
    environment variable (64 hex chars or base64, 32 bytes).
    Without it, a DEMO-ONLY key is used — clearly marked, never
    for real data. Rotate it before any cloud run.
  - No rate limiting or account lockout here — a production
    login needs those too. This is a learning demo.

Run it locally (no AWS needed):
    pip install -r requirements.txt
    python app.py
    open http://127.0.0.1:5000

Cloud run: the same app on a Free Tier EC2 t2.micro in
ap-southeast-2 — see README.md Step 3. Cost: $0 (Free Tier,
instance terminated after the demo).
No credentials in this repo — the only secret is the encryption
key, which lives in an environment variable, never in code.
"""

import base64
import hashlib
import hmac
import html
import os
import re
import sqlite3

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "users.db")
REGION = "ap-southeast-2"  # named for the EC2 deploy (see README)

# ------------------------------------------------------------------
# Encryption key — AES-256 = 32 bytes.
#
# REAL key: set the CODEALPHA_AES_KEY environment variable to a
# 256-bit key, as 64 hex chars or base64. Generate one with:
#     python -c "import os; print(os.urandom(32).hex())"
#
# DEMO key below: used ONLY when the env var is not set. It is
# published in this file, so it protects NOTHING — it only lets
# the demo run without setup. NEVER use it for real data, and
# rotate to a real key (env var) before any cloud run.
# ------------------------------------------------------------------
DEMO_KEY_HEX = (
    "9f2c4a7e1b8d5036a1e7c9f2058b3d6a"
    "4c1e8f027a5b9d3c6e1f0a4827c5b913"
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

# Demo users (fake data, same names as Task 1 for continuity).
# Passwords + secret notes are stored AES-256 encrypted, never plaintext.
DEMO_USERS = [
    {"username": "ahmed", "password": "Ahmed@123",
     "secret": "Ahmed's secret note (DEMO data): salary slip and bank "
               "details live here — if you can read this without a "
               "password, the data has leaked."},
    {"username": "bilal", "password": "Bilal@456",
     "secret": "Bilal's secret note (DEMO data): flight booking and "
               "passport details live here — if you can read this "
               "without a password, the data has leaked."},
]


def load_key():
    """Returns (key_bytes, using_demo_key). Key must be 32 bytes."""
    raw = os.environ.get("CODEALPHA_AES_KEY", "").strip()
    if raw:
        key = None
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            key = None
        if key is None:
            try:
                key = base64.b64decode(raw, validate=True)
            except Exception:
                key = None
        if key is None or len(key) != 32:
            raise SystemExit(
                "CODEALPHA_AES_KEY must be a 256-bit key: 64 hex chars "
                "or base64 (32 bytes). Generate one with: "
                "python -c \"import os; print(os.urandom(32).hex())\"")
        return key, False
    return bytes.fromhex(DEMO_KEY_HEX), True


KEY, USING_DEMO_KEY = load_key()
AES = AESGCM(KEY)  # AES-256-GCM: 32-byte key, NOT Fernet (AES-128).


def encrypt(plaintext):
    """AES-256-GCM. Returns base64(nonce + ciphertext). A fresh random
    nonce per value means the same password encrypts differently
    every time — no pattern leaks."""
    nonce = os.urandom(12)
    ciphertext = AES.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt(blob):
    """Inverse of encrypt(). Raises if the key is wrong or the data
    was tampered with (GCM authentication)."""
    raw = base64.b64decode(blob.encode("ascii"))
    return AES.decrypt(raw[:12], raw[12:], None).decode("utf-8")


# ------------------------------------------------------------------
# Database — SQLite, one users table. Passwords + secrets stored
# encrypted (AES-256). Nothing sensitive is ever plaintext here.
# ------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT UNIQUE NOT NULL,"
        "  password_enc TEXT NOT NULL,"
        "  secret_enc TEXT NOT NULL"
        ")")
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        for user in DEMO_USERS:
            conn.execute(
                "INSERT INTO users (username, password_enc, secret_enc)"
                " VALUES (?, ?, ?)",
                (user["username"], encrypt(user["password"]),
                 encrypt(user["secret"])))
    conn.commit()
    conn.close()


def validate_login_input(username, password):
    """Input validation — the first gate. Returns a reason string,
    or None when the input is well-formed. An injection string like
    ' OR '1'='1 fails the username pattern right here, before it
    ever reaches the database."""
    if not USERNAME_RE.match(username or ""):
        return ("username can only contain letters, digits, _ . - "
                "(3-32 characters)")
    if not password or len(password) > 128:
        return "password is empty or too long"
    return None


# ------------------------------------------------------------------
# Web app — one file, no external templates or assets.
# ------------------------------------------------------------------

app = Flask(__name__)

CSS = """
body { font-family: Arial, sans-serif; max-width: 900px; margin: 30px auto;
       padding: 0 20px; color: #222; }
h1 { font-size: 24px; } h2 { font-size: 18px; margin-top: 28px; }
.card { border: 1px solid #ccc; border-radius: 8px; padding: 16px;
        margin: 14px 0; }
.vuln { border-color: #c00; } .vuln h2 { color: #c00; }
.secure { border-color: #080; } .secure h2 { color: #080; }
.warn { background: #fff3cd; border: 1px solid #d4a017; border-radius: 6px;
        padding: 10px; margin: 12px 0; }
.ok { background: #e6f4ea; border: 1px solid #080; border-radius: 6px;
      padding: 10px; margin: 12px 0; }
.bad { background: #fdecea; border: 1px solid #c00; border-radius: 6px;
       padding: 10px; margin: 12px 0; }
code { background: #f0f0f0; padding: 2px 5px; border-radius: 4px;
       word-break: break-all; }
pre { background: #f0f0f0; padding: 10px; border-radius: 6px;
      overflow-x: auto; }
input[type=text], input[type=password] { padding: 8px; margin: 4px 0;
      width: 260px; }
button { padding: 8px 16px; margin-top: 6px; cursor: pointer; }
table { border-collapse: collapse; margin: 10px 0; }
td, th { border: 1px solid #ccc; padding: 6px 10px; text-align: left; }
a { color: #0645ad; }
"""


def page(title, body):
    """Wraps a page body in the base HTML shell."""
    banner = ""
    if USING_DEMO_KEY:
        banner = ("<div class='warn'><b>DEMO KEY ACTIVE</b> — the encryption key did not come from "
                  "CODEALPHA_AES_KEY, this is a demo key. Never use it for real "
                  "data — set a real key via the env var before any cloud run "
                  "(README Step 3).</div>")
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>" + html.escape(title) + "</title>"
            "<style>" + CSS + "</style></head><body>"
            "<h1>CodeAlpha Task 2 — SQL Injection: Data Leak Demo</h1>"
            + banner + body +
            "<p><a href='/'>← Home</a> &nbsp;|&nbsp; "
            "<a href='/db'>What is stored in the database? (raw view)</a></p>"
            "</body></html>")


HOME_BODY = """
<p>There are two login forms — one <b>deliberately weak (vulnerable)</b>,
one <b>secure</b>. Try both with the same injection string and see the
difference.</p>

<h2>Double-layer security (the secure one)</h2>
<ul>
<li><b>Layer 1 — Parameterized queries:</b> user input never becomes part of the SQL,
only data. The database compiles the SQL first, then binds the input —
input can never change the query.</li>
<li><b>Layer 2 — AES-256 encryption at rest:</b> passwords and secret
notes are encrypted in the database. Even if a row leaks,
it is ciphertext, not a password.</li>
<li><b>Extra — Input validation:</b> the username pattern is fixed in advance
(letters/digits/_ . -). An injection string is stopped at this gate.</li>
</ul>

<div class='card vuln'>
<h2>⚠️ VULNERABLE login (demo — never use this pattern in real code)</h2>
<p>This code glues the username straight into the SQL (string
concatenation) and treats whatever row the query returns as a login.</p>
<form method='POST' action='/login/vulnerable'>
Username: <input type='text' name='username'><br>
Password: <input type='password' name='password'>
(this demo does not check the password)<br>
<button type='submit'>Login (vulnerable)</button>
</form>
<p>Try it — type this in the username, anything in the password:<br>
<code>' OR '1'='1</code></p>
</div>

<div class='card secure'>
<h2>✅ SECURE login (parameterized query + AES-256)</h2>
<p>This code first validates the input, then runs a parameterized query,
then decrypts the stored password and compares it.</p>
<form method='POST' action='/login/secure'>
Username: <input type='text' name='username'><br>
Password: <input type='password' name='password'><br>
<button type='submit'>Login (secure)</button>
</form>
<p>Try it — type the same string here:<br>
<code>' OR '1'='1</code><br>
Then try a correct login too: <code>ahmed</code> /
<code>Ahmed@123</code></p>
</div>

<h2>Demo users (fake data)</h2>
<table><tr><th>Username</th><th>Password</th></tr>
<tr><td>ahmed</td><td>Ahmed@123</td></tr>
<tr><td>bilal</td><td>Bilal@456</td></tr></table>
<p>Passwords are <b>not stored in plaintext</b> in the database — they are AES-256
encrypted. See for yourself in the <a href='/db'>raw view</a>.</p>
"""


@app.route("/")
def home():
    return page("SQL Injection Demo", HOME_BODY)


@app.route("/login/vulnerable", methods=["POST"])
def login_vulnerable():
    """INTENTIONALLY INSECURE — demo only.

    Flaws on purpose: (1) the username is glued straight into the
    SQL string; (2) the password is not even checked — the app logs
    in whoever the query returns. With  ' OR '1'='1  the query
    becomes WHERE username = '' OR '1'='1', which matches EVERY
    row, so the first user (Ahmed) is returned and their secret
    note leaks. That is the data leak this task demonstrates.
    """
    username = request.form.get("username", "")
    query = ("SELECT id, username, password_enc, secret_enc FROM users "
             "WHERE username = '%s'" % username)
    conn = get_db()
    try:
        row = conn.execute(query).fetchone()
    except sqlite3.Error as exc:
        conn.close()
        return page("Vulnerable login — error",
                    "<div class='bad'>Database error (bad SQL): "
                    + html.escape(str(exc)) + "</div>"
                    "<p>Query that ran:</p><pre>"
                    + html.escape(query) + "</pre>")
    conn.close()
    if row is None:
        return page("Vulnerable login — failed",
                    "<div class='bad'><b>Login failed</b> — no user "
                    "found.</div>"
                    "<p>Query that ran:</p><pre>"
                    + html.escape(query) + "</pre>")
    secret = decrypt(row["secret_enc"])
    return page("Vulnerable login — LEAKED",
                "<div class='bad'><b>⚠️ DATA LEAK — logged in as "
                + html.escape(row["username"]) + " (without a password!)"
                + "</b><br>The injection opened the whole table — the query "
                "condition became always TRUE.</div>"
                "<p><b>Leaked secret note:</b></p><pre>"
                + html.escape(secret) + "</pre>"
                "<p>Query that ran:</p><pre>"
                + html.escape(query) + "</pre>")


@app.route("/login/secure", methods=["POST"])
def login_secure():
    """The fixed version — three gates, in order:
    1. Input validation (username pattern).
    2. Parameterized query — input is data, never SQL.
    3. Decrypt the stored password and compare in Python.
    Failure message is generic on purpose: it never says whether
    the username or the password was wrong."""
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    problem = validate_login_input(username, password)
    if problem:
        return page("Secure login — failed",
                    "<div class='bad'><b>Login failed</b> — "
                    + html.escape(problem) + "</div>"
                    "<p>Gate 1 (validation) stopped the request — this "
                    "input never reached the database.</p>")

    conn = get_db()
    # Parameterized query: the ? placeholder keeps user input as DATA.
    # ' OR '1'='1 here is just a weird username that matches nobody.
    row = conn.execute(
        "SELECT id, username, password_enc, secret_enc FROM users "
        "WHERE username = ?", (username,)).fetchone()
    conn.close()

    if row is None:
        return page("Secure login — failed",
                    "<div class='bad'><b>Invalid username or "
                    "password.</b></div>"
                    "<p>Gate 2 (parameterized query): the injection string was treated as a "
                    "literal username — no match.</p>")

    try:
        real_password = decrypt(row["password_enc"])
    except Exception:
        return page("Secure login — failed",
                    "<div class='bad'><b>Invalid username or "
                    "password.</b></div>"
                    "<p>The stored credential could not be decrypted (the key probably "
                    "changed) — login blocked.</p>")

    if not hmac.compare_digest(real_password, password):
        return page("Secure login — failed",
                    "<div class='bad'><b>Invalid username or "
                    "password.</b></div>"
                    "<p>Gate 3 (password match): wrong password.</p>")

    secret = decrypt(row["secret_enc"])
    return page("Secure login — success",
                "<div class='ok'><b>✅ Login successful — welcome, "
                + html.escape(row["username"]) + "!</b></div>"
                "<p><b>Your secret note:</b></p><pre>"
                + html.escape(secret) + "</pre>"
                "<p>All three gates passed: validation ✓, parameterized query "
                "✓, AES-256 encrypted password match ✓.</p>")


@app.route("/db")
def show_db():
    """Raw view of what is actually stored — proves the credentials
    are encrypted at rest. Also checks the raw database FILE bytes
    for any plaintext demo password."""
    conn = get_db()
    rows = conn.execute(
        "SELECT username, password_enc, secret_enc FROM users").fetchall()
    conn.close()
    with open(DB_PATH, "rb") as f:
        raw_bytes = f.read()
    leaks = [u["password"] for u in DEMO_USERS
             if u["password"].encode("utf-8") in raw_bytes]
    lines = []
    for row in rows:
        lines.append(
            "user: " + row["username"] + "\n"
            "  password_enc: " + row["password_enc"][:60] + "...\n"
            "  secret_enc:   " + row["secret_enc"][:60] + "...")
    if leaks:
        check = ("<div class='bad'><b>⚠️ PLAINTEXT FOUND:</b> "
                 + html.escape(", ".join(leaks))
                 + " is in the database file in plaintext!</div>")
    else:
        check = ("<div class='ok'><b>✅ No plaintext password is in the database "
                 "file.</b> The values below are AES-256-GCM "
                 "ciphertext (base64) — without the key, no password can be "
                 "recovered from them.</div>")
    return page("Database — raw stored values",
                check + "<pre>" + html.escape("\n\n".join(lines)) + "</pre>"
                "<p>Every value is <code>base64(nonce + ciphertext)</code>. "
                "The nonce is freshly random each time, so encrypting the same "
                "password again gives a different ciphertext.</p>")


if __name__ == "__main__":
    init_db()
    host = os.environ.get("CODEALPHA_HOST", "127.0.0.1")
    port = int(os.environ.get("CODEALPHA_PORT", "5000"))
    print("CodeAlpha Task 2 — SQL Injection demo")
    print("Open: http://%s:%d/  (demo key: %s)"
          % (host, port, "YES — demo only" if USING_DEMO_KEY else "no, env key"))
    app.run(host=host, port=port, debug=False)
