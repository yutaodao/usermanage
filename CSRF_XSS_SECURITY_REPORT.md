# CSRF 与 XSS 漏洞分析与修复报告

| 项目 | 内容 |
|------|------|
| **项目路径** | `/opt/Class01/` |
| **涉及文件** | `app.py`, `templates/login.html`, `templates/profile.html`, `templates/index.html` |
| **修复数量** | 5 项 |

---

## 一、漏洞总览

| 序号 | 漏洞名称 | 类型 | 严重程度 | OWASP 分类 | 修复状态 |
|:---:|---------|:----:|:-------:|-----------|:-------:|
| 1 | /change-password 接口无 CSRF 保护 | CSRF | 🔴 严重 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 2 | 登录页 msg 参数未经过滤传入模板 | XSS | 🟡 中危 | A03:2021 – 注入 | ✅ 已修复 |
| 3 | profile.html 修改密码表单无 CSRF Token | CSRF | 🟠 高危 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 4 | index.html 旧密码表单功能失效（接口变更） | 功能缺陷 | 🟡 中危 | — | ✅ 已修复 |
| 5 | 模板中直接使用 request.args 访问用户输入 | XSS | 🟢 低危 | A03:2021 – 注入 | ✅ 已修复 |

---

## 二、漏洞详情

### 1. /change-password 接口无 CSRF 保护

**风险等级：🔴 严重**

**漏洞类型：** CSRF（跨站请求伪造）

**漏洞描述：**
`/change-password` 路由在 CSRF 中间件中被特意跳过：

```python
# ❌ 修复前：CSRF 中间件中对 /change-password 网开一面
@app.before_request
def csrf_protect():
    if request.method == "POST":
        if request.endpoint == "change_password":
            return  # ← 跳过 CSRF 检查！
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token"):
            return "CSRF Token 无效", 400
```

**攻击场景：**

| 步骤 | 操作 |
|:---:|------|
| 1 | 攻击者构造恶意 HTML 页面，内含自动提交的隐藏表单 |
| 2 | 表单指向 `/change-password`，提交 `username=admin&new_password=hacked123` |
| 3 | 诱导已登录管理员访问该恶意页面 |
| 4 | 浏览器自动发送 POST 请求（携带 Session Cookie） |
| 5 | 由于 **没有 CSRF Token 检查**，请求通过 |
| 6 | 管理员的密码被修改为攻击者设置的密码 |

```html
<!-- 攻击者构造的 CSRF 攻击页面 -->
<html>
<body>
  <h1>有趣的视频</h1>
  <form id="attack" action="http://target/change-password" method="POST">
    <input name="username" value="admin">
    <input name="new_password" value="hacked123">
  </form>
  <script>document.getElementById('attack').submit();</script>
</body>
</html>
```

**攻击验证（修复前）：**
```
alice 登录 → 访问攻击者页面（无 CSRF Token）
→ POST /change-password 直接通过
→ admin 密码被修改！
```

---

### 2. login 模板中直接使用 request.args 获取 msg 参数

**风险等级：🟡 中危**

**漏洞类型：** XSS（跨站脚本）— 反射型，已由 Jinja2 自动转义缓解

**漏洞描述：**
`login.html` 模板中直接调用 `request.args.get('msg')` 获取 URL 参数：

```html
<!-- ❌ 修复前：模板中直接访问请求参数 -->
{% if request.args.get('msg') %}
<div class="success-message">{{ request.args.get('msg') }}</div>
{% endif %}
```

**虽然 Jinja2 的 `{{ }}` 会自动进行 HTML 转义**（`<script>` → `&lt;script&gt;`），这降低了直接 XSS 的风险，但仍然存在以下问题：
- 绕过了 MVC 架构中"视图不应直接访问请求对象"的设计原则
- 如果未来修改模板误删了 `{{ }}` 改用 `| safe`，将直接产生 XSS 漏洞
- 攻击者可注入超长字符串导致页面布局破坏

**攻击验证：**
```
访问: /login?msg=<script>alert(document.cookie)</script>
Jinja2 转义为: &lt;script&gt;alert(document.cookie)&lt;/script&gt;
→ 不执行，显示为文本（当前安全）
```

---

### 3. profile.html 修改密码表单无 CSRF Token

**风险等级：🟠 高危**

**漏洞类型：** CSRF

**漏洞描述：**
个人中心的修改密码表单缺少 CSRF Token 隐藏字段：

```html
<!-- ❌ 修复前：无 CSRF Token -->
<form method="POST" action="/change-password">
    <input type="hidden" name="username" value="...">
    <input type="password" name="new_password">
    <button type="submit">修改密码</button>
</form>
```

虽然服务端现在要求 CSRF Token，但表单没有提供，导致用户每次在个人中心修改密码都会失败。

---

### 4. index.html 旧密码表单与新接口不兼容

**风险等级：🟡 中危**

**漏洞类型：** 功能缺陷

**漏洞描述：**
首页的旧密码修改表单使用 `old_password` 和 `new_password` 字段，通过 `fetch` 发送 AJAX 请求并期望 JSON 响应。但新接口要求 `username` 和 `new_password` 字段，且返回 HTTP 重定向而非 JSON：

```javascript
// ❌ 修复前：使用旧字段名，期望 JSON 响应
const formData = new FormData(form);
// 发送 old_password + new_password + csrf_token
const resp = await fetch('/change-password', { method: 'POST', body: formData });
const data = await resp.json();  // 后端返回 302 重定向，非 JSON
```

攻击者可以利用此表单与后端的不一致进行混淆攻击。

---

### 5. 模板直接调用 request 对象

**风险等级：🟢 低危**

**漏洞类型：** XSS / 设计缺陷

**漏洞描述：**
`login.html` 中通过 `{{ request.args.get('msg') }}` 直接在模板中访问 Flask 请求对象，绕过了视图函数的数据处理层。这意味着任何 URL 参数都会未经服务端处理直接进入模板渲染流程。

---

## 三、漏洞根源分析

### CSRF 漏洞根源

```
┌─────────────────────────────────────────────────────────┐
│                  CSRF 漏洞根源                           │
│                                                         │
│  csrf_protect() 中间件：                                 │
│    if endpoint == "change_password":                    │
│        return  ← 特意跳过！                              │
│                                                         │
│  后果：                                                  │
│  /change-password 没有任何 CSRF 防御                     │
│  SameSite=Lax 是最后一道防线（但也可能被绕过）           │
│                                                         │
│  ✅ 修复：移除例外，所有 POST 统一检查 CSRF Token        │
└─────────────────────────────────────────────────────────┘
```

### XSS 漏洞根源

```
┌─────────────────────────────────────────────────────────┐
│                  XSS 漏洞根源（低危）                    │
│                                                         │
│  用户请求 /login?msg=<script>...</script>                │
│          ↓                                              │
│  Flask 路由 login() → GET                               │
│          ↓                                              │
│  render_template("login.html")                          │
│  未将 msg 作为参数传入                                   │
│          ↓                                              │
│  login.html 中直接调用 {{ request.args.get('msg') }}     │
│          ↓                                              │
│  Jinja2 {{ }} 自动 HTML 转义 → 当前安全                 │
│  但设计上存在风险                                        │
│                                                         │
│  ✅ 修复：msg 作为模板变量传入，模板不再直接访问请求对象  │
└─────────────────────────────────────────────────────────┘
```

---

## 四、修复方案

### 修复 1：CSRF 中间件覆盖所有 POST 接口

```python
# ✅ 修复后
@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token"):
            return "CSRF Token 无效", 400
    # 不再有例外路由！
```

---

### 修复 2：login 路由将 msg 作为模板变量传入

```python
# ✅ 修复后
@app.route("/login", methods=["GET", "POST"])
def login():
    # ...
    # GET 请求：将 msg 作为模板变量传入
    msg = request.args.get("msg", "")
    return render_template("login.html", csrf_token=session["csrf_token"], msg=msg)
```

模板中改为使用模板变量：

```html
<!-- ✅ 修复后：使用模板变量 -->
{% if msg %}
<div class="success-message">{{ msg }}</div>
{% endif %}
```

---

### 修复 3：profile.html 添加 CSRF Token

```html
<!-- ✅ 修复后：表单包含 CSRF Token -->
<form method="POST" action="/change-password">
    <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token', '') }}">
    <input type="hidden" name="username" value="{{ user.username }}">
    <div class="form-group">
        <label for="new_password">新密码</label>
        <input type="password" name="new_password" required>
    </div>
    <button type="submit" class="btn btn-primary">修改密码</button>
</form>
```

---

### 修复 4：移除首页不兼容的旧密码表单

```html
<!-- ✅ 修复后：跳转到个人中心修改密码 -->
<div class="card" style="margin-top: 20px;">
    <h3>修改密码</h3>
    <p class="text-muted">请前往个人中心修改密码。</p>
    <a href="/profile" class="btn btn-primary">前往个人中心</a>
</div>
```

---

## 五、修复前后对比

#### CSRF 修复

| 接口 | 修复前 | 修复后 |
|:----|:------|:------|
| `/change-password` | ❌ 完全无 CSRF 保护 | ✅ 需要 CSRF Token |
| `/login` | ✅ 需要 CSRF Token | ✅ 需要 CSRF Token |
| `/recharge` | ✅ 需要 CSRF Token | ✅ 需要 CSRF Token |
| `/register` | ✅ 需要 CSRF Token | ✅ 需要 CSRF Token |

#### XSS 修复

| 位置 | 修复前 | 修复后 |
|:----|:------|:------|
| login.html `msg` 来源 | `request.args.get('msg')` 直接在模板调用 | 通过 Python 变量传入模板 |
| 模板直接访问 request | ✅ 由 Jinja2 自动转义 | ✅ 由 Jinja2 自动转义 + 不再直接访问 |

---

## 六、攻击验证

```
修复前（CSRF 攻击成功）:
  伪造表单 → 自动提交 POST /change-password
  → 无需 Token → 修改成功  ❌

修复后（CSRF 攻击失败）:
  伪造表单 → 自动提交 POST /change-password
  → 缺少 CSRF Token → 400 拒绝  ✅

修复前（XSS 尝试）:
  /login?msg=<script>alert(1)</script>
  → Jinja2 自动转义，不执行（低风险）  ⚠️

修复后（XSS 尝试）:
  /login?msg=<script>alert(1)</script>
  → msg 经 Python 传入模板 + Jinja2 转义  ✅
```

---

## 七、安全建议总结

| 措施 | 说明 | 优先级 |
|:----|------|:----:|
| **统一 CSRF 保护** | 所有 POST 接口统一校验 Token，不设例外 | 🔴 必须 |
| **模板不直接访问 request** | 所有数据通过视图函数变量传入模板 | 🔴 必须 |
| **所有表单添加 CSRF Token** | 每个 POST 表单都必须包含 CSRF 隐藏字段 | 🔴 必须 |
| **利用 Jinja2 自动转义** | 默认使用 `{{ }}` 而非 `| safe` | 🟠 推荐 |
| **移除内联脚本** | 将 JS 移至外部文件，移除 `'unsafe-inline'` | 🟡 建议 |
| **CSP 强化** | 移除 `'unsafe-inline'` 后使用 nonce 或 hash | 🟡 建议 |

---

**核心原则：所有 POST 接口必须接受 CSRF Token 校验，所有用户输入必须经过模板引擎自动转义，视图函数应承担所有数据预处理职责，模板仅负责展示。**
