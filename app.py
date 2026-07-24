from flask import Flask, render_template, request, redirect, session, jsonify, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import re
import time
import sqlite3
import secrets
from datetime import timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-2025-insecure-change-in-production")
app.permanent_session_lifetime = timedelta(hours=2)

# Session Cookie 安全属性
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False,       # 生产环境应设为 True（HTTPS）
)

# 上传文件大小限制
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# ============================================================
# SQLite 数据库初始化
# ============================================================
def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户。"""
    os.makedirs('data', exist_ok=True)
    conn = sqlite3.connect('data/users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        role TEXT DEFAULT 'user',
        balance INTEGER DEFAULT 0
    )''')
    # 插入默认用户（密码哈希存储）
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, ?, ?)",
              ('admin', generate_password_hash("Admin@2025#Secure"), 'admin@example.com', '13800138000', 'admin', 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, role, balance) VALUES (?, ?, ?, ?, ?, ?)",
              ('alice', generate_password_hash("Alice@2025#Secure"), 'alice@example.com', '13900139001', 'user', 100))
    conn.commit()
    conn.close()
    print("[DB] 数据库初始化完成（密码已哈希存储）")


def get_db_user(username):
    """从 SQLite 查询用户信息。"""
    conn = sqlite3.connect('data/users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, password, email, phone, role, balance FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            'id': row[0], 'username': row[1], 'password': row[2],
            'email': row[3], 'phone': row[4], 'role': row[5], 'balance': row[6]
        }
    return None


def get_all_users():
    """获取所有用户（不含密码字段）。"""
    conn = sqlite3.connect('data/users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, role, balance FROM users")
    rows = c.fetchall()
    conn.close()
    return rows


def get_user_by_id(user_id):
    """根据 user_id 查询用户信息。"""
    conn = sqlite3.connect('data/users.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, phone, role, balance FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            'id': row[0], 'username': row[1], 'email': row[2],
            'phone': row[3], 'role': row[4], 'balance': row[5]
        }
    return None


# ============================================================
# 登录频率限制（内存实现，防止暴力破解）
# ============================================================
LOGIN_ATTEMPTS = {}  # {ip: [timestamp1, timestamp2, ...]}

def check_login_rate_limit(ip: str) -> tuple:
    """检查登录频率，同一 IP 1 分钟内最多尝试 5 次。
    第 5 次失败立即锁定，倒计时 60 秒从第 5 次失败开始算起。
    返回 (allowed: bool, retry_after: int)。"""
    now = time.time()
    if ip not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip] = []
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS[ip] if now - t < 60]
    if len(LOGIN_ATTEMPTS[ip]) >= 5:
        lock_time = LOGIN_ATTEMPTS[ip][-1]
        retry_after = int(60 - (now - lock_time))
        return (False, max(retry_after, 1))
    LOGIN_ATTEMPTS[ip].append(now)
    if len(LOGIN_ATTEMPTS[ip]) >= 5:
        return (False, 60)
    return (True, 0)


REGISTER_ATTEMPTS = {}

def check_register_rate_limit(ip: str) -> tuple:
    """注册频率限制，同一 IP 1 分钟内最多注册 3 次。"""
    now = time.time()
    if ip not in REGISTER_ATTEMPTS:
        REGISTER_ATTEMPTS[ip] = []
    REGISTER_ATTEMPTS[ip] = [t for t in REGISTER_ATTEMPTS[ip] if now - t < 60]
    if len(REGISTER_ATTEMPTS[ip]) >= 3:
        return (False, 30)
    REGISTER_ATTEMPTS[ip].append(now)
    return (True, 0)


UPLOAD_ATTEMPTS = {}

def check_upload_rate_limit(ip: str) -> tuple:
    """上传频率限制，同一 IP 1 分钟内最多上传 10 次。"""
    now = time.time()
    if ip not in UPLOAD_ATTEMPTS:
        UPLOAD_ATTEMPTS[ip] = []
    UPLOAD_ATTEMPTS[ip] = [t for t in UPLOAD_ATTEMPTS[ip] if now - t < 60]
    if len(UPLOAD_ATTEMPTS[ip]) >= 10:
        return (False, 10)
    UPLOAD_ATTEMPTS[ip].append(now)
    return (True, 0)


# 允许上传的图片后缀
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'}

def allowed_file(filename):
    """检查文件后缀是否在允许列表中。"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def safe_filename(filename, username):
    """清洗文件名：防止路径穿越、去除危险字符、添加用户名前缀防止覆盖。"""
    # 去除路径分隔符（防止 ../../etc/passwd）
    filename = filename.replace('\\', '/')
    filename = filename.split('/')[-1]
    # 只保留安全的文件名字符
    safe_name = re.sub(r'[^\w\.\-]', '_', filename)
    # 限制文件名长度
    safe_name = safe_name[:100]
    # 添加用户名前缀防止覆盖
    return f"{username}_{safe_name}"


# ============================================================
# 安全响应头中间件
# ============================================================
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # 防止搜索反射内容被当作脚本执行
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline'"
    return response


# ============================================================
# CSRF 保护（覆盖所有 POST 请求，包括 /login 和 /change-password）
# ============================================================
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token"):
            return "CSRF Token 无效", 400


# ============================================================
# 登录验证装饰器
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================
# 输入验证函数
# ============================================================
def validate_input(username, password, email, phone):
    """验证注册/修改输入，返回 (is_valid, error_msg)。"""
    if not username or len(username) < 2 or len(username) > 50:
        return False, "用户名长度需在 2-50 位之间"
    if not re.match(r'^[a-zA-Z0-9_一-龥]+$', username):
        return False, "用户名只能包含字母、数字、下划线和中文"
    if not password or len(password) < 6:
        return False, "密码长度至少 6 位"
    if email and email.strip():
        email = email.strip()
        if len(email) > 100:
            return False, "邮箱地址过长"
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            return False, "邮箱格式不正确"
    if phone and phone.strip():
        phone = phone.strip()
        if len(phone) > 20:
            return False, "手机号过长"
        if not re.match(r'^\+?[0-9\- ]{6,20}$', phone):
            return False, "手机号格式不正确"
    return True, ""


# ============================================================
# 路由
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username:
        user_info = get_db_user(username)
    # 从 URL 参数读取搜索结果（如果有）
    search_keyword = request.args.get("keyword", "")
    search_results = []
    if search_keyword:
        conn = sqlite3.connect('data/users.db')
        c = conn.cursor()
        sql = "SELECT id, username, email, phone, role, balance FROM users WHERE username LIKE ? OR email LIKE ?"
        param = f'%{search_keyword}%'
        try:
            c.execute(sql, (param, param))
            search_results = c.fetchall()
        except Exception:
            pass
        finally:
            conn.close()
    return render_template("index.html", username=username, user=user_info,
                           search_results=search_results, search_keyword=search_keyword)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # --- 1. CSRF 检查（由 before_request 统一处理）---
        # --- 2. 检查登录频率 ---
        client_ip = request.remote_addr or "unknown"
        allowed, retry_after = check_login_rate_limit(client_ip)
        if not allowed:
            return render_template("login.html", error=f"登录过于频繁，请 {retry_after} 秒后再试",
                                   rate_limited=True, retry_after=retry_after,
                                   csrf_token=session.get("csrf_token", "")), 429

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return render_template("login.html", error="用户名和密码不能为空",
                                   csrf_token=session.get("csrf_token", ""))

        # --- 3. 从 SQLite 查询用户 ---
        user = get_db_user(username)
        if not user:
            return render_template("login.html", error="用户名或密码错误",
                                   csrf_token=session.get("csrf_token", ""))

        # --- 4. 密码哈希比对 ---
        if not check_password_hash(user["password"], password):
            return render_template("login.html", error="用户名或密码错误",
                                   csrf_token=session.get("csrf_token", ""))

        # --- 5. 登录成功 ---
        session.permanent = True
        session["username"] = username
        session["user_id"] = user["id"]
        session["csrf_token"] = secrets.token_hex(32)

        user_info = {
            "username": username,
            "role": user["role"],
            "email": user["email"],
            "phone": user["phone"],
            "balance": user["balance"]
        }
        return render_template("index.html", username=username, user=user_info)

    # GET 请求
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    msg = request.args.get("msg", "")
    return render_template("login.html", csrf_token=session["csrf_token"], msg=msg)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ============================================================
# 用户注册
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        allowed, _ = check_register_rate_limit(client_ip)
        if not allowed:
            return render_template("register.html", error="注册过于频繁，请稍后再试",
                                   csrf_token=session.get("csrf_token", ""))

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 输入校验
        valid, err_msg = validate_input(username, password, email, phone)
        if not valid:
            return render_template("register.html", error=err_msg,
                                   csrf_token=session.get("csrf_token", ""))

        # 密码哈希后存储
        hashed_pw = generate_password_hash(password)
        conn = sqlite3.connect('data/users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                      (username, hashed_pw, email, phone))
            conn.commit()
            conn.close()
            session["csrf_token"] = secrets.token_hex(32)
            return redirect(url_for('login', msg='注册成功，请登录'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="用户名已存在",
                                   csrf_token=session.get("csrf_token", ""))
        except Exception:
            conn.close()
            return render_template("register.html", error="注册失败，请稍后重试",
                                   csrf_token=session.get("csrf_token", ""))

    # GET 请求
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return render_template("register.html", csrf_token=session["csrf_token"])


# ============================================================
# 用户搜索（需登录）
# ============================================================
@app.route("/search")
@login_required
def search():
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        if len(keyword) > 100:
            return redirect(url_for('index'))
        conn = sqlite3.connect('data/users.db')
        c = conn.cursor()
        sql = "SELECT id, username, email, phone, role, balance FROM users WHERE username LIKE ? OR email LIKE ?"
        param = f'%{keyword}%'
        try:
            c.execute(sql, (param, param))
            results = c.fetchall()
        except Exception:
            pass
        finally:
            conn.close()

    return redirect(url_for('index', keyword=keyword))


# ============================================================
# 修改密码（新接口：无需原密码、无需CSRF、可修改他人密码）
# ============================================================
@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")

    if not username or not new_password:
        return "用户名和密码不能为空", 400

    hashed_pw = generate_password_hash(new_password)
    conn = sqlite3.connect('data/users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_pw, username))
    conn.commit()
    conn.close()

    return redirect(url_for('profile', user_id=session.get('user_id')))


# ============================================================
# 用户头像上传
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        # --- 1. 上传频率限制 ---
        client_ip = request.remote_addr or "unknown"
        allowed, _ = check_upload_rate_limit(client_ip)
        if not allowed:
            return render_template("upload.html", error="上传过于频繁，请稍后再试",
                                   csrf_token=session.get("csrf_token", ""))

        # --- 2. 检查是否有文件上传 ---
        if 'file' not in request.files:
            return render_template("upload.html", error="未选择文件",
                                   csrf_token=session.get("csrf_token", ""))

        file = request.files['file']
        if file.filename == '':
            return render_template("upload.html", error="未选择文件",
                                   csrf_token=session.get("csrf_token", ""))

        # --- 3. 文件大小检查（单文件不超过 16MB）---
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        if file_size > 16 * 1024 * 1024:
            return render_template("upload.html", error="文件大小超过 16MB 限制",
                                   csrf_token=session.get("csrf_token", ""))

        # --- 4. 文件后缀白名单校验 ---
        if not allowed_file(file.filename):
            return render_template("upload.html", error="不支持的文件格式，仅允许图片文件（JPG/PNG/GIF/WEBP/BMP）",
                                   csrf_token=session.get("csrf_token", ""))

        # --- 5. 清洗文件名（防路径穿越 + 去特殊字符 + 加用户名前缀防覆盖）---
        username = session.get("username")
        safe_name = safe_filename(file.filename, username)

        # --- 6. 保存文件 ---
        upload_dir = os.path.join(app.root_path, 'static', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, safe_name)
        file.save(filepath)

        # --- 7. 生成访问 URL ---
        file_url = url_for('static', filename=f'uploads/{safe_name}')
        return render_template("upload.html", success=True,
                               file_url=file_url, filename=safe_name,
                               csrf_token=session.get("csrf_token", ""))

    # GET 请求
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return render_template("upload.html", csrf_token=session["csrf_token"])


# ============================================================
# 个人中心（仅查看自己的资料）
# ============================================================
@app.route("/profile")
@login_required
def profile():
    login_user_id = session.get("user_id")
    user = get_user_by_id(login_user_id)
    if not user:
        return "用户不存在", 404
    return render_template("profile.html", user=user)


# ============================================================
# 充值（仅给自己的账户充值）
# ============================================================
@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    login_user_id = session.get("user_id")
    amount = request.form.get("amount", type=float, default=0)

    if amount <= 0:
        return "充值金额必须大于 0", 400

    conn = sqlite3.connect('data/users.db')
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, login_user_id))
    conn.commit()
    conn.close()

    return redirect(url_for('profile'))


# ============================================================
# 动态页面加载
# ============================================================
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    if not name:
        return "页面不存在", 404

    # 安全校验：防止路径穿越
    # 只允许字母、数字、下划线、横线，拒绝 ../ 等路径符号
    if not re.match(r'^[a-zA-Z0-9_\-一-龥]+$', name):
        return "页面不存在", 404

    # 限制在 pages/ 目录内，使用绝对路径
    base_dir = os.path.join(app.root_path, 'pages')
    filepath = os.path.join(base_dir, name + '.html')

    if not os.path.isfile(filepath):
        return "页面不存在", 404

    # 额外校验：确保文件仍在 pages/ 目录下（防止符号链接攻击）
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(base_dir)
    if not real_path.startswith(real_base + os.sep) and real_path != real_base:
        return "页面不存在", 404

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    return render_template("index.html", username=session.get("username"),
                           page_content=content)


# ============================================================
# 启动入口
# ============================================================
if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
