import hashlib
import hmac
import os
import secrets
import time
from collections import defaultdict

from flask import Flask, render_template, request, redirect, session

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


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    return render_template("index.html", user=user_info)


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
                error="尝试次数过多，请 5 分钟后再试。",
            )

        if verify_password(username, password):
            LOGIN_ATTEMPTS.pop(ip, None)
            session["username"] = username
            user_info = USERS[username]
            return render_template("index.html", user=user_info)
        else:
            LOGIN_ATTEMPTS[ip].append(time.time())
            remaining = max(0, MAX_ATTEMPTS - len(LOGIN_ATTEMPTS[ip]))
            return render_template(
                "login.html",
                error=f"用户名或密码错误（剩余 {remaining} 次尝试）",
            )
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
