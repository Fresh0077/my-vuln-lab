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
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

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
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp", "bmp"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
UPLOAD_CSRF_TOKEN = None


def allowed_file(filename):
    if not filename or filename.startswith("."):
        return False
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS
LOCKOUT_SECONDS = 300


def _clean_attempts(ip: str) -> None:
    now = time.time()
    LOGIN_ATTEMPTS[ip][:] = [
        t for t in LOGIN_ATTEMPTS[ip] if now - t < LOCKOUT_SECONDS
    ]


def verify_password(username: str, password: str) -> bool:
    # 先查内存字典
    cred = USER_CREDENTIALS.get(username)
    if cred:
        target = cred["hash"]
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), PASSWORD_SALT, 600000)
        return hmac.compare_digest(target, candidate)

    # 再查 SQLite（支持注册用户登录）
    try:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row is None:
            return False
        target = bytes.fromhex(row[0]) if isinstance(row[0], str) else row[0]
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), PASSWORD_SALT, 600000)
        return hmac.compare_digest(target, candidate)
    except Exception:
        return False


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
        "  phone TEXT,"
        "  balance INTEGER DEFAULT 0,"
        "  role TEXT DEFAULT 'user'"
        ")"
    )
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance, role) VALUES (?, ?, ?, ?, ?, ?)",
              ("admin", "c1a75dbea5cc74e9ced64b11f64f4c4ad289a9fe2de75bbf4feb5dbe04ee0570", "admin@example.com", "13800138000", 99999, "admin"))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance, role) VALUES (?, ?, ?, ?, ?, ?)",
              ("alice", "79559639701b989f5ece2923a26c84e3d91109a08ce4cfcee86cca0b70b5ab6a", "alice@example.com", "13900139001", 100, "user"))

    # 兼容旧数据库：补充缺失的列
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
    except sqlite3.OperationalError:
        pass

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
    else:
        # 从 SQLite 获取注册用户信息
        try:
            conn = sqlite3.connect("data/users.db")
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT id, username, email, phone, balance, role FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            conn.close()
            if row:
                user_info = dict(row)
        except Exception:
            pass

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
            # 从内存或 SQLite 获取用户信息
            if username in USERS:
                user_info = USERS[username]
            else:
                conn = sqlite3.connect("data/users.db")
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                c.execute("SELECT id, username, email, phone, balance, role FROM users WHERE username = ?", (username,))
                user_info = dict(c.fetchone())
                conn.close()
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
        password_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), PASSWORD_SALT, 600000).hex()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"[SQL] {sql}  params: ({username!r}, {password_hash!r}, {email!r}, {phone!r})")
        try:
            c.execute(sql, (username, password_hash, email, phone))
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


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    # 生成 CSRF Token
    if request.method == "GET":
        session["upload_csrf"] = secrets.token_hex(16)

    uploaded_url = None
    error = None

    if request.method == "POST":
        # 验证 CSRF Token
        if request.form.get("csrf_token") != session.get("upload_csrf"):
            error = "CSRF 验证失败"
            return render_template("upload.html", uploaded_url=uploaded_url, error=error)

        f = request.files.get("file")
        if not f or not f.filename or not f.filename.strip():
            error = "请选择一个文件"
            return render_template("upload.html", uploaded_url=uploaded_url, error=error)

        # ① 路径遍历防护
        safe_name = os.path.basename(f.filename.strip())

        # ② 白名单后缀 + 隐藏文件 + 无扩展名 + 双扩展名
        if not allowed_file(safe_name):
            error = "不支持的文件类型，仅允许图片（png, jpg, jpeg, gif, webp, bmp）"
            return render_template("upload.html", uploaded_url=uploaded_url, error=error)

        # ③ 文件大小检查
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(0)
        if size > MAX_FILE_SIZE:
            error = f"文件过大，允许最大 {MAX_FILE_SIZE // 1024 // 1024}MB"
            return render_template("upload.html", uploaded_url=uploaded_url, error=error)

        # ④ 唯一文件名防覆盖
        name, ext = safe_name.rsplit(".", 1)
        unique_name = f"{name}_{session['username']}_{int(time.time())}.{ext}"

        os.makedirs("static/uploads", exist_ok=True)
        save_path = os.path.join("static/uploads", unique_name)
        f.save(save_path)
        uploaded_url = url_for("static", filename=f"uploads/{unique_name}")

    return render_template("upload.html", uploaded_url=uploaded_url, error=error)


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    user = _get_user(username)

    if user is None:
        return "用户不存在", 404

    return render_template("profile.html", user=dict(user), error=None)


def _get_user(username):
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, balance, role FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user


@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session["username"]
    amount_str = request.form.get("amount", "0")

    # 校验金额格式
    try:
        amount = int(amount_str)
    except (ValueError, TypeError):
        error = "金额格式无效"
        return render_template("profile.html", user=_get_user(username), error=error), 400

    # 校验金额正负和上限
    if amount <= 0:
        error = "充值金额必须为正数"
        return render_template("profile.html", user=_get_user(username), error=error), 400
    if amount > 1000000:
        error = "单次充值超出上限"
        return render_template("profile.html", user=_get_user(username), error=error), 400

    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("SELECT balance FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if row is None:
        conn.close()
        return "用户不存在", 404

    old_balance = row[0]
    new_balance = old_balance + amount

    c.execute("UPDATE users SET balance = ? WHERE username = ?", (new_balance, username))
    conn.commit()
    conn.close()

    # 同步更新内存中的用户数据
    if username in USERS:
        USERS[username]["balance"] = new_balance

    return redirect(url_for("profile"))


ALLOWED_PAGES = {"help", "about", "contact", "terms"}


@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    page_content = None
    page_error = None

    if name:
        if name not in ALLOWED_PAGES:
            page_error = "页面不存在"
        else:
            path = os.path.join("pages", name + ".html")
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_error = "页面不存在"

    return render_template("index.html",
                           user=USERS.get(session.get("username")),
                           page_content=page_content,
                           page_error=page_error)


@app.route("/change-password", methods=["POST"])
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    target_username = request.form.get("username")
    new_password = request.form.get("new_password")

    if not target_username or not new_password:
        return redirect(url_for("profile"))

    password_hash = hashlib.pbkdf2_hmac("sha256", new_password.encode(), PASSWORD_SALT, 600000).hex()

    # 更新 SQLite
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (password_hash, target_username))
    conn.commit()
    conn.close()

    # 同步更新内存字典
    if target_username in USER_CREDENTIALS:
        USER_CREDENTIALS[target_username]["hash"] = bytes.fromhex(password_hash)

    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
