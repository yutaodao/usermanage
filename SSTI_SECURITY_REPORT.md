# SSTI（服务端模板注入）漏洞分析与修复报告

| 项目 | 内容 |
|------|------|
| **项目路径** | `/opt/Class01/` |
| **涉及文件** | `app.py` |
| **修复数量** | 2 处 SSTI 漏洞 |

---

## 一、漏洞总览

| 序号 | 漏洞名称 | 严重程度 | OWASP 分类 | 修复状态 |
|:---:|---------|:-------:|-----------|:-------:|
| 1 | /welcome SSTI — Jinja2 模板代码执行 | 🔴 严重 | A03:2021 – 注入 | ✅ 已修复 |
| 2 | /feedback SSTI — 姓名/留言字段模板注入 | 🔴 严重 | A03:2021 – 注入 | ✅ 已修复 |

---

## 二、漏洞详情

### 1. /welcome SSTI — Jinja2 模板代码执行

**风险等级：🔴 严重**

**漏洞描述：**
`/welcome` 路由使用 `render_template_string()` 处理用户输入的 `name` 参数，并通过 **f-string** 将用户输入直接拼接到模板字符串中：

```python
# ❌ 修复前：f-string 在 Python 层先拼接，然后 Jinja2 再解析
name = request.args.get("name", "")            # 用户输入 {{7*7}}
content = f"<h1>欢迎你，{name}！</h1>"          # Python 层：替换为 {{7*7}}
# content = "<h1>欢迎你，{{7*7}}！</h1>"        # 含 Jinja2 表达式！
html = f"...{{content}}..."                     # 嵌入到完整 HTML
return render_template_string(html)             # Jinja2 执行 {{7*7}} → 49
```

**攻击场景：**

| 攻击 Payload | URL | 结果（修复前） | 危害 |
|:-----------|:----|:-------------:|:----|
| `{{7*7}}` | `/welcome?name={{7*7}}` | 页面显示"欢迎你，49！" | 确认 SSTI 存在 |
| `{{config}}` | `/welcome?name={{config}}` | 泄露 Flask Secret Key | 密钥泄露 → Session 伪造 |
| `{{''.__class__.__mro__[2].__subclasses__()}}` | URL编码传入 | 列出所有子类 | 探测可利用类 |
| `{{''.__class__.__mro__[2].__subclasses__()[X]}}` | 探测子类索引 | 找到 `os`/`subprocess` 模块 | 为 RCE 做准备 |
| `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` | 远程命令执行 | 执行系统命令 | 服务器完全沦陷 |

**攻击链（从 SSTI 到 RCE）：**

```
{{7*7}} → 确认 SSTI 存在
   ↓
{{config}} → 获取应用配置
   ↓
{{''.__class__.__mro__[2].__subclasses__()}} → 寻找 os 模块
   ↓
{{''.__class__.__mro__[2].__subclasses__()[X].__init__.__globals__['os'].popen('id').read()}}
   ↓
远程命令执行！服务器沦陷
```

**攻击验证（修复前）：**
```
访问: /welcome?name={{7*7}}
返回: 欢迎你，49！                  ← {{7*7}} 被 Jinja2 执行！

访问: /welcome?name={{config}}
返回: ...SECRET_KEY...             ← Flask 配置泄露！
```

---

### 2. /feedback SSTI — 姓名/留言字段模板注入

**风险等级：🔴 严重**

**漏洞描述：**
`/feedback` POST 路由同样使用 f-string 将 `name` 和 `message` 拼接到模板字符串中：

```python
# ❌ 修复前
name = request.form.get("name", "")
message = request.form.get("message", "")
result = f"<h2>{name} 的反馈：</h2><p>{message}</p>"  # f-string 拼接含 Jinja2 表达式
html = f"...{result}..."
return render_template_string(html)  # Jinja2 执行
```

**攻击场景：**
```
POST /feedback  body: name={{7*7}}&message={{config}}
→ 页面显示 "49 的反馈：" + Flask Secret Key
```

**双字段注入危害更大：** `name` 和 `message` 两个独立入口均可触发 SSTI，攻击面扩大一倍。

---

## 三、漏洞根源分析

```
┌─────────────────────────────────────────────────────────┐
│                    SSTI 漏洞根源                         │
│                                                         │
│  用户输入: {{config}}                                    │
│          ↓                                              │
│  Python f-string: f"...{name}..."                       │
│          ↓                                              │
│  模板字符串: "...{{config}}..."  ← Jinja2 语法          │
│          ↓                                              │
│  render_template_string(html)                           │
│          ↓                                              │
│  Jinja2 解析 {{config}} → 执行 → 返回配置内容           │
│          ↓                                              │
│  攻击者看到 Secret Key  ❌                               │
│                                                         │
│  ✅ 修复：用户输入作为模板变量传递                         │
│  render_template_string(html, name=name)                │
│  Jinja2 中的 {{ name }} 从上下文取值                      │
│  {{7*7}} 作为字面字符串渲染，不再被解析为表达式           │
│                                                         │
│  Python 层         Jinja2 层                              │
│  f-string 拼接     render_template_string                 │
│  ❌ 旧: {name}  →  {{config}}  →  执行                  │
│  ✅ 新: name=xxx →  {{ name }}  →  取值（不执行）        │
└─────────────────────────────────────────────────────────┘
```

**关键区别：**

| 方式 | 代码 | 用户输入 `{{config}}` 的处理 |
|:----|:----|:---------------------------|
| ❌ f-string + render_template_string | `f"...{name}..."` → 传入 Jinja2 | {{config}} 被 Jinja2 解析为表达式 → 执行 |
| ✅ 模板变量 | `render_template_string("...", name=name)` | {{config}} 作为普通字符串取值 → 显示原文 |

---

## 四、修复方案

### 修复 1：/welcome 改用模板变量

```python
# ✅ 修复后
@app.route("/welcome")
def welcome():
    name = request.args.get("name", "")
    if not name:
        html = "...<h1>亲爱的用户，欢迎你！</h1>..."
        return render_template_string(html)
    else:
        html = "...<h1>欢迎你，{{ name }}！</h1>..."
        # name 作为模板变量传入，不会被解析为 Jinja2 表达式
        return render_template_string(html, name=name)
```

### 修复 2：/feedback 改用模板变量

```python
# ✅ 修复后
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        html = """...<h2>{{ name }} 的反馈：</h2><p>{{ message }}</p>..."""
        # name 和 message 都作为模板变量，SSTI 被阻断
        return render_template_string(html, name=name, message=message)
```

### 修复核心原则

| 原则 | 说明 |
|:----|------|
| **不要用 f-string 拼接模板** | 用户输入即使包含 `{{}}` 语法，f-string 会原样保留到模板字符串中 |
| **使用模板变量** | `render_template_string("{{ name }}", name=user_input)`，Jinja2 将输入视为值而非代码 |
| **利用自动转义** | Jinja2 自动对模板变量做 HTML 转义，进一步防止 XSS |
| **固定模板结构** | 模板字符串本身应该是固定的，不要用 Python 字符串操作动态构建 |

---

## 五、修复前后代码对比

#### 修复前（2 处 SSTI 漏洞）

```python
# /welcome — f-string 拼接用户输入到模板
name = request.args.get("name", "")
content = f"<h1>欢迎你，{name}！</h1>"           # ❌ 用户输入直接拼入模板
html = f"...{content}..."
return render_template_string(html)               # ❌ Jinja2 执行用户输入的表达式

# /feedback — f-string 拼接用户输入到模板
name = request.form.get("name", "")
message = request.form.get("message", "")
result = f"<h2>{name} 的反馈：</h2><p>{message}</p>"  # ❌ 双字段注入
html = f"...{result}..."
return render_template_string(html)               # ❌ Jinja2 执行用户输入的表达式
```

#### 修复后（SSTI 全部阻断）

```python
# /welcome — 使用模板变量
name = request.args.get("name", "")
html = "...<h1>欢迎你，{{ name }}！</h1>..."       # ✅ name 是模板变量
return render_template_string(html, name=name)     # ✅ 传入上下文，不拼接

# /feedback — 使用模板变量
name = request.form.get("name", "")
message = request.form.get("message", "")
html = "...<h2>{{ name }} 的反馈：</h2><p>{{ message }}</p>..."  # ✅ 模板变量
return render_template_string(html, name=name, message=message)   # ✅ 传入上下文
```

---

## 六、攻击验证

```
修复前（SSTI 全部成功）:
  /welcome?name={{7*7}}           →  49                           ❌
  /welcome?name={{config}}        →  Secret Key 泄露               ❌
  /welcome?name={{''.__class__}}  →  对象信息泄露                   ❌
  POST /feedback name={{config}}  →  Secret Key 泄露               ❌
  POST ...message={{7*7}}         →  49                           ❌

修复后（SSTI 全部阻断）:
  /welcome?name={{7*7}}           →  "欢迎你，{{7*7}}！"（字面值） ✅
  /welcome?name={{config}}        →  "欢迎你，{{config}}！"         ✅
  /welcome?name={{''.__class__}}  →  "欢迎你，{{''.__class__}}！"   ✅
  POST /feedback name={{config}}  →  "{{config}} 的反馈："          ✅
  POST ...message={{7*7}}         →  显示 {{7*7}} 原文             ✅
```

---

## 七、SSTI 防护最佳实践

| 措施 | 说明 | 优先级 |
|:----|------|:----:|
| **使用模板变量** | 永远通过 `render_template(template, **vars)` 传递用户数据 | 🔴 必须 |
| **禁止 f-string 拼模板** | 不要在模板字符串中使用 `f"...{user_input}..."` | 🔴 必须 |
| **最小化 render_template_string** | 优先使用文件模板 `render_template` | 🟠 推荐 |
| **沙箱环境** | Jinja2 sandbox 模式可限制危险函数访问 | 🟡 建议 |
| **白名单校验** | 对预期为简单文本的输入做格式校验 | 🟡 建议 |
| **输入长度限制** | 限制用户输入长度，防止超长 payload | 🟢 可选 |

---

## 八、Python + Jinja2 渲染方式安全对比

| 渲染方式 | 代码示例 | 用户输入 `{{config}}` | 安全性 |
|:--------|:--------|:--------------------:|:-----:|
| f-string + render_template_string | `render_template_string(f"{{{{ name }}}}{name}")` | 被执行 ❌ | 🔴 危险 |
| 模板变量 | `render_template_string("{{ name }}", name=data)` | 显示原文 ✅ | 🟢 安全 |
| render_template + .html文件 | `render_template("page.html", name=data)` | 显示原文 ✅ | 🟢 安全 |

---

**核心原则：永远不要用 f-string 将用户输入拼接到模板字符串中。用户数据必须通过模板变量（`render_template_string(..., key=value)`）传递给 Jinja2，这样输入中的 `{{}}` 语法不会被解析为模板代码。**
