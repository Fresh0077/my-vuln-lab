import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from collections import defaultdict

from flask import Flask, render_template, request, redirect, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

PASSWORD_SALT = bytes.fromhex(
    "44b494f56b14b7c6875fcac46655720b"
)
USER_CREDENTIALS = {
    "admin": {
        "hash": bytes.fromhex(
            "c1a75dbea5cc74e9ced64b11f64f4c4a"
            "d289a9fe2de75bbf4feb5dbe04ee0570"
        ),
    },
    "alice": {
        "hash": bytes.fromhex(
            "79559639701b989f5ece2923a26c84e3"
            "d91109a08ce4cfcee86cca0b70b5ab6a"
        ),
    },
}

USERS = {
    "admin": {
        "username": "admin",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

LOGIN_ATTEMPTS = defaultdict(list)
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


def _clean_attempts(ip: str) -> None:
    now = time.time()
    LOGIN_ATTEMPTS[ip][:] = [
        t for t in LOGIN_ATTEMPTS[ip] if now - t < LOCKOUT_SECONDS
    ]


def verify_password(username: str, password: str) -> bool:
    cred = USER_CREDENTIALS.get(username)
    if cred is None:
        return False
    target = cred["hash"]
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), PASSWORD_SALT, 600000
    )
    return hmac.compare_digest(target, candidate)


def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  username TEXT UNIQUE NOT NULL,"
        "  password TEXT NOT NULL,"
        "  email TEXT,"
        "  phone TEXT"
        ")"
    )
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("admin", "admin123", "admin@example.com", "13800138000"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    search_results = None
    search_keyword = None

    if username and username in USERS:
        user_info = USERS[username]

    keyword = request.args.get("keyword")
    if keyword:
        search_keyword = keyword
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        pattern = f"%{keyword}%"
        print(f"[SQL] {sql}  params: ({pattern!r})")
        try:
            c.execute(sql, (pattern, pattern))
            rows = c.fetchall()
            search_results = [dict(r) for r in rows]
        except Exception as e:
            print(f"[SQL ERROR] {e}")
            search_results = []
        conn.close()

    return render_template(
        "index.html",
        user=user_info,
        search_results=search_results,
        search_keyword=search_keyword,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        ip = request.remote_addr

        _clean_attempts(ip)
        if len(LOGIN_ATTEMPTS[ip]) >= MAX_ATTEMPTS:
            return render_template(
                "login.html",
                error="用户名或密码错误",
            )

        if verify_password(username, password):
            LOGIN_ATTEMPTS.pop(ip, None)
            session["username"] = username
            user_info = USERS[username]
            return render_template("index.html", user=user_info)
        else:
            LOGIN_ATTEMPTS[ip].append(time.time())
            return render_template(
                "login.html",
                error="用户名或密码错误",
            )
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        phone = request.form.get("phone")

        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] {sql}  params: ({username!r}, {password!r}, {email!r}, {phone!r})")
        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            conn.close()
            return redirect(url_for("login", registered="1"))
        except Exception as e:
            print(f"[SQL ERROR] {e}")
            conn.close()
            return render_template("register.html", error="注册失败，用户名可能已存在。")

    return render_template("register.html")


@app.route("/search")
def search():
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
