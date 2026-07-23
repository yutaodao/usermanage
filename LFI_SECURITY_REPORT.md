# 文件包含漏洞（LFI）分析与修复报告

| 项目 | 内容 |
|------|------|
| **项目路径** | `/opt/Class01/` |
| **涉及文件** | `app.py`、`templates/index.html` |
| **修复数量** | 4 项漏洞 + 1 项风险 |
| **漏洞类型** | 本地文件包含（LFI）/ 路径穿越（Path Traversal）|

---

## 一、漏洞总览

| 序号 | 漏洞名称 | 严重程度 | OWASP 分类 | 修复状态 |
|:---:|---------|:-------:|-----------|:-------:|
| 1 | 路径穿越读取任意文件 | 🔴 严重 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 2 | 任意文件内容回显（信息泄露） | 🔴 严重 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 3 | 无文件类型限制 | 🟠 高危 | A05:2021 – 安全配置错误 | ✅ 已修复 |
| 4 | 无后缀自动补全导致更多文件可读 | 🟡 中危 | A05:2021 – 安全配置错误 | ✅ 已修复 |
| 5 | 符号链接绕过目录限制 | 🟡 中危 | A01:2021 – 越界访问控制 | ✅ 已修复 |

---

## 二、漏洞详情

### 1. 路径穿越读取任意文件（LFI）

**风险等级：🔴 严重**

**漏洞描述：**
`/page` 路由直接将用户输入的 `name` 参数拼接到文件路径中，未做任何过滤：

```python
# ❌ 修复前
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    base_dir = os.path.join(app.root_path, 'pages')
    filepath = os.path.join(base_dir, name)  # 直接拼接用户输入！

    if os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()               # 读取任意文件
    else:
        # 还自动补 .html 后缀再试一次
        filepath_html = filepath + '.html'
        if os.path.isfile(filepath_html):
            with open(filepath_html, 'r', encoding='utf-8') as f:
                content = f.read()

    return render_template("index.html", ...,
                           page_content=content)  # 内容回显到页面！
```

**攻击场景：**

攻击者通过 URL 传入 `../` 穿越到系统任意目录：

| URL | 读取的文件 | 危害 |
|-----|-----------|------|
| `/page?name=../app.py` | `/opt/Class01/app.py` | 泄露源代码、数据库密码、Secret Key |
| `/page?name=../data/users.db` | SQLite 数据库文件 | 泄露所有用户数据（注册时密码明文） |
| `/page?name=../../etc/passwd` | `/etc/passwd` | 泄露服务器用户列表 |
| `/page?name=../../proc/self/environ` | 进程环境变量 | 泄露环境变量中的敏感信息 |
| `/page?name=../.git/config` | Git 配置文件 | 泄露仓库信息 |
| `/page?name=../.git/HEAD` | Git HEAD 引用 | 确认 Git 仓库存在，为进一步攻击打基础 |

**攻击验证（修复前）：**
```
访问: /page?name=../app.py
返回: app.py 的完整源代码！（包含 Secret Key、数据库结构等）
```

**路径解析过程：**
```
os.path.join('/opt/Class01/pages', '../app.py')
→ /opt/Class01/pages/../app.py
→ /opt/Class01/app.py    ← 成功读取应用源码！
```

---

### 2. 任意文件内容回显（信息泄露）

**风险等级：🔴 严重**

**漏洞描述：**
读取到的文件内容直接通过模板渲染返回给用户：

```python
# ❌ 修复前：读取内容直接显示
content = f.read()                   # 读取任意文件
return render_template("index.html",
                       page_content=content)  # 内容返回给攻击者
```

并且在模板中使用 `| safe` 过滤器，不做 HTML 转义：

```html
<!-- ❌ 修复前：内容原样渲染，不转义 -->
{{ page_content | safe }}
```

**攻击场景：**
- 读取包含 `<script>` 标签的文件 → XSS 攻击
- 读取包含敏感信息的文件 → 数据泄露
- 读取 `.py` 源代码 → 泄露业务逻辑和密钥

---

### 3. 无文件类型限制

**风险等级：🟠 高危**

**漏洞描述：**
代码不检查文件后缀/类型，任何文件都可被读取：

```python
# ❌ 修复前：任何文件类型都允许
if os.path.isfile(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
# .py, .db, .conf, .json, .sh ... 全部可读
```

**攻击场景：**
| 文件类型 | 敏感信息 |
|---------|---------|
| `.py` | 源代码、硬编码密钥、数据库结构 |
| `.db` / `.sqlite` | 数据库内容（用户数据）|
| `.conf` / `.config` | 系统配置信息 |
| `.env` | 环境变量、API Token |
| `.json` | 应用配置、用户数据 |
| `.gitignore` | 项目结构信息 |
| `.md` | 项目文档、可能含敏感信息 |

---

### 4. 自动补全后缀扩大攻击面

**风险等级：🟡 中危**

**漏洞描述：**
第一次找不到文件时，代码会自动追加 `.html` 后缀再试一次：

```python
# ❌ 修复前：找不到文件就加 .html 再试
if os.path.isfile(filepath):
    # ...
else:
    filepath_html = filepath + '.html'    # 再给一次机会
    if os.path.isfile(filepath_html):
        with open(filepath_html, 'r', encoding='utf-8') as f:
            content = f.read()
```

**攻击场景：**
- `name=../app` → 尝试 `pages/../app` 不存在 → 再试 `pages/../app.html`
- 虽然 `.html` 限制了部分读取，但也扩大了"命中"范围
- 攻击者可利用此行为进行"有无".html 后缀的盲注探测

---

### 5. 符号链接绕过目录限制

**风险等级：🟡 中危**

**漏洞描述：**
即使做了字符串过滤，攻击者如果在 `pages/` 目录下创建指向系统关键文件的符号链接，就能绕过路径校验：

```bash
# 攻击者在 pages/ 目录下创建指向 /etc/passwd 的符号链接
ln -s /etc/passwd /opt/Class01/pages/evil_link

# 然后访问
/page?name=evil_link
# → 成功读取 /etc/passwd
```

**攻击前提：** 攻击者需要有文件系统写入权限（通常配合文件上传漏洞实现）。

---

## 三、漏洞根源分析

```
┌─────────────────────────────────────────────────────────┐
│                    漏洞根源架构图                        │
│                                                         │
│  用户输入 name=../app.py                                │
│          ↓                                              │
│  os.path.join("pages", "../app.py")                     │
│          ↓                                              │
│  "pages/../app.py" → 解析为 app.py                      │
│          ↓                                              │
│  open("app.py").read()  ← 读取了应用源码！              │
│          ↓                                              │
│  渲染到页面 → 攻击者看到完整源代码                      │
│                                                         │
│  ❌ 问题：用户输入直接拼接到文件路径                     │
│  ❌ ../ 没有被过滤或规范化                               │
│  ❌ 文件内容直接回显到页面                               │
│                                                         │
│  ✅ 修复：                                              │
│     1. 白名单校验：只允许字母数字下划线横线              │
│     2. 强制追加 .html 后缀（用户无法控制）              │
│     3. realpath 校验确保文件在 pages/ 目录内            │
└─────────────────────────────────────────────────────────┘
```

---

## 四、修复方案

### 三层防御修复

```python
# ✅ 修复后
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    if not name:
        return "页面不存在", 404

    # 第一层：输入白名单校验
    # 只允许字母、数字、下划线、横线、中文，拒绝 ../ 等路径符号
    if not re.match(r'^[a-zA-Z0-9_\-一-龥]+$', name):
        return "页面不存在", 404

    # 第二层：强制追加 .html 后缀（用户不可控制后缀）
    # 确保只能读取 .html 文件，不能读取 .py/.db/.conf 等
    base_dir = os.path.join(app.root_path, 'pages')
    filepath = os.path.join(base_dir, name + '.html')

    if not os.path.isfile(filepath):
        return "页面不存在", 404

    # 第三层：realpath 校验防止符号链接绕过
    # 确保最终解析的文件路径仍在 pages/ 目录范围内
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(base_dir)
    if not real_path.startswith(real_base + os.sep) and real_path != real_base:
        return "页面不存在", 404

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    return render_template("index.html", ...,
                           page_content=content)
```

### 修复点说明

| 修复层 | 措施 | 防御目标 |
|:-----:|------|---------|
| **第一层** | 正则白名单 `^[a-zA-Z0-9_\-一-龥]+$` | 拦截 `../`、`..%2F`、空字节等攻击 |
| **第二层** | 强制追加 `.html` 后缀 | 只能读取 `.html` 文件，杜绝读取 `.py`/`.db` 等 |
| **第三层** | `os.path.realpath()` 校验 | 防止符号链接绕过目录限制 |

### 各攻击向量对抗验证

| 攻击 URL | 修复前 | 修复后 |
|----------|:-----:|:------:|
| `/page?name=help` | ✅ 正常显示 | ✅ 正常显示 |
| `/page?name=../app.py` | ❌ 读取源码 | ✅ 404 拒绝 |
| `/page?name=../../etc/passwd` | ❌ 读取系统文件 | ✅ 404 拒绝 |
| `/page?name=..%2F..%2Fetc%2Fpasswd` | ❌ URL编码绕过 | ✅ 404 拒绝 |
| `/page?name=help<script>` | ❌ 可能XSS | ✅ 404 拒绝 |
| `/page?name=../data/users.db` | ❌ 读取数据库 | ✅ 404 拒绝 |
| `/page?name=nonexist` | ✅ 显示"页面不存在" | ✅ 404 返回 |

---

## 五、修复前后代码对比

#### 修复前（5 个漏洞全部存在）

```python
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    if not name:
        return "页面不存在", 404

    # ❌ 无输入校验 ← 漏洞1: 路径穿越
    base_dir = os.path.join(app.root_path, 'pages')
    filepath = os.path.join(base_dir, name)  # ❌ 直接拼接用户输入

    content = None
    if os.path.isfile(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()               # ❌ 漏洞2: 任意文件内容回显
    else:
        filepath_html = filepath + '.html'   # ❌ 漏洞4: 自动补后缀扩大攻击面
        if os.path.isfile(filepath_html):
            with open(filepath_html, 'r', encoding='utf-8') as f:
                content = f.read()           # ❌ 漏洞3: 无文件类型限制

    return render_template("index.html", ...,
                           page_content=content)
```

#### 修复后（全部修复）

```python
@app.route("/page")
def dynamic_page():
    name = request.args.get("name", "")
    if not name:
        return "页面不存在", 404

    # ✅ 第一层：白名单校验，拒绝 ../ 等路径符号
    if not re.match(r'^[a-zA-Z0-9_\-一-龥]+$', name):
        return "页面不存在", 404

    base_dir = os.path.join(app.root_path, 'pages')
    filepath = os.path.join(base_dir, name + '.html')  # ✅ 强制后缀

    if not os.path.isfile(filepath):
        return "页面不存在", 404

    # ✅ 第三层：realpath 校验防止符号链接绕过
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(base_dir)
    if not real_path.startswith(real_base + os.sep) and real_path != real_base:
        return "页面不存在", 404

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    return render_template("index.html", ...,
                           page_content=content)
```

---

## 六、攻击链演示

```
修复前（全部攻击成功）:
  /page?name=../app.py          → 读取源代码              ❌
  /page?name=../../etc/passwd   → 读取系统用户列表         ❌
  /page?name=../.git/config     → 读取 Git 配置            ❌
  /page?name=../data/users.db   → 读取数据库文件           ❌
  + 符号链接 pages/evil → /etc/shadow                      ❌

修复后（全部防御成功）:
  /page?name=../app.py          → 404 拒绝（含非法字符）   ✅
  /page?name=../../etc/passwd   → 404 拒绝（含非法字符）   ✅
  /page?name=.../.../etc/passwd → 404 拒绝（含非法字符）   ✅
  /page?name=..%2F..%2Fapp.py   → 404 拒绝（URL编码穿透）  ✅
  /page?name=help<script>       → 404 拒绝（特殊字符）     ✅
  符号链接 pages/evil → /etc/shadow → realpath 检测到越界  ✅
```

---

## 七、安全原则总结

| 原则 | 说明 | 优先级 |
|:----|------|:----:|
| **永不信任用户输入** | 任何用户输入（URL 参数、表单字段）都可能被恶意构造 | 🔴 必须 |
| **白名单校验** | 限制输入只能包含特定安全字符，拒绝黑名单方式 | 🔴 必须 |
| **路径规范化校验** | 使用 `os.path.realpath()` 验证最终路径在预期范围内 | 🔴 必须 |
| **强制文件后缀** | 服务器端控制文件后缀，不让用户决定读取的文件类型 | 🟠 推荐 |
| **最小化回显** | 避免将文件内容直接渲染到页面中 | 🟠 推荐 |
| **权限最小化** | Web 进程只应读取必要的目录和文件 | 🟡 建议 |

---

**核心原则：永远不要让用户的输入参与文件路径的构建。** 如果需要读取用户指定的文件，必须通过白名单、路径规范化、强制后缀三层防御来确保安全。
