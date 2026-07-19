import hashlib
import hmac
import os
import secrets

from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)

SALT = secrets.token_bytes(16)
USER_CREDENTIALS = {
    "admin": {
        "hash": hashlib.pbkdf2_hmac("sha256", b"admin123", SALT, 600000),
    },
    "alice": {
        "hash": hashlib.pbkdf2_hmac("sha256", b"alice2025", SALT, 600000),
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


def verify_password(username: str, password: str) -> bool:
    cred = USER_CREDENTIALS.get(username)
    if cred is None:
        return False
    target = cred["hash"]
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 600000)
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
        if verify_password(username, password):
            session["username"] = username
            user_info = USERS[username]
            return render_template("index.html", user=user_info)
        else:
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
