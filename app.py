from flask import Flask, render_template, request, redirect, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import time
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-2025-insecure-change-in-production")
app.permanent_session_lifetime = timedelta(hours=2)  # Session 2 小时过期

# ============================================================
# 用户数据库（密码使用 werkzeug 哈希存储）
# ============================================================
USERS = {
    "admin": {
        "password": generate_password_hash("Admin@2025#Secure"),  # 强密码
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "password": generate_password_hash("Alice@2025#Secure"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

# ============================================================
# 登录频率限制（内存实现，防止暴力破解）
# ============================================================
LOGIN_ATTEMPTS = {}  # {ip: [timestamp1, timestamp2, ...]}

def check_login_rate_limit(ip: str) -> bool:
    """检查登录频率，同一 IP 1 分钟内最多尝试 5 次。"""
    now = time.time()
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    # 清除 1 分钟前的记录
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now - t < 60]
    if len(LOGIN_ATTEMPTS[ip]) >= 5:
        return False  # 超出限制
    LOGIN_ATTEMPTS[ip].append(now)
    return True


# ============================================================
# 安全响应头中间件
# ============================================================
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ============================================================
# CSRF 保护
# ============================================================
import secrets

@app.before_request
def csrf_protect():
    if request.method == "POST":
        # 对 /login 以外的 POST 请求检查 CSRF token
        if request.endpoint != "login":
            token = request.form.get("csrf_token", "")
            if not token or token != session.get("csrf_token"):
                return "CSRF Token 无效", 400


# ============================================================
# 路由
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # --- 1. 检查登录频率 ---
        client_ip = request.remote_addr or "unknown"
        if not check_login_rate_limit(client_ip):
            return render_template("login.html", error="登录过于频繁，请 1 分钟后再试"), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # --- 2. 验证用户存在 ---
        user = USERS.get(username)
        if not user:
            return render_template("login.html", error="用户名或密码错误")

        # --- 3. 密码哈希比对（不再使用明文 ==）---
        if not check_password_hash(user["password"], password):
            return render_template("login.html", error="用户名或密码错误")

        # --- 4. 登录成功 ---
        session.permanent = True
        session["username"] = username
        session["csrf_token"] = secrets.token_hex(32)

        # 准备传递给模板的用户信息（⚠️ 不包含密码字段）
        user_info = {
            "username": username,
            "role": user["role"],
            "email": user["email"],
            "phone": user["phone"],
            "balance": user["balance"]
        }
        return render_template("index.html", username=username, user=user_info)

    # GET 请求：生成 CSRF token
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return render_template("login.html", csrf_token=session["csrf_token"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ============================================================
# 管理员重置密码接口（演示用，生产环境应加权限控制）
# ============================================================
@app.route("/change-password", methods=["POST"])
def change_password():
    username = session.get("username")
    if not username or username not in USERS:
        return jsonify({"error": "未登录"}), 401

    old_pw = request.form.get("old_password", "")
    new_pw = request.form.get("new_password", "")

    # 验证旧密码
    if not check_password_hash(USERS[username]["password"], old_pw):
        return jsonify({"error": "旧密码错误"}), 403

    # 密码强度检查
    if len(new_pw) < 8:
        return jsonify({"error": "新密码长度至少 8 位"}), 400
    if not any(c.isupper() for c in new_pw):
        return jsonify({"error": "新密码需要包含大写字母"}), 400
    if not any(c.islower() for c in new_pw):
        return jsonify({"error": "新密码需要包含小写字母"}), 400
    if not any(c.isdigit() for c in new_pw):
        return jsonify({"error": "新密码需要包含数字"}), 400

    # 更新密码（哈希存储）
    USERS[username]["password"] = generate_password_hash(new_pw)
    return jsonify({"message": "密码修改成功"})


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
