# 越权漏洞分析与修复报告

| 项目 | 内容 |
|------|------|
| **项目路径** | `/opt/Class01/` |
| **涉及文件** | `app.py`、`templates/profile.html`、`templates/base.html`、`templates/index.html` |
| **修复数量** | 2 项越权漏洞 + 2 项业务风险 |

---

## 一、漏洞总览

| 序号 | 漏洞名称 | 严重程度 | OWASP 分类 | 修复状态 |
|:---:|---------|:-------:|-----------|:-------:|
| 1 | 个人中心水平越权访问 | 🔴 严重 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 2 | 充值接口水平越权操作 | 🔴 严重 | A01:2021 – 越界访问控制 | ✅ 已修复 |
| 3 | 充值负数金额（业务风险） | 🟠 高危 | A04:2021 – 不安全设计 | ✅ 已修复 |
| 4 | 前端泄露 user_id 参数 | 🟡 中危 | A05:2021 – 安全配置错误 | ✅ 已修复 |

---

## 二、漏洞详情

### 1. 个人中心水平越权访问

**风险等级：🔴 严重**

**漏洞描述：**
`/profile` 路由直接使用 URL 参数 `user_id` 查询用户资料，完全信任前端传入的参数：

```python
# ❌ 修复前
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id", type=int)  # 前端可控！
    user = get_user_by_id(user_id)                    # 直接查询
    return render_template("profile.html", user=user)
```

**攻击场景：**

| 步骤 | 操作 |
|:---:|------|
| 1 | 用户 A 登录自己账号（`user_id=1`） |
| 2 | 手动修改 URL 为 `/profile?user_id=2` |
| 3 | 直接查看用户 B 的邮箱、手机号、余额等隐私信息 |
| 4 | 遍历 `user_id=3,4,5...` 可批量获取全站用户隐私数据 |

**攻击验证（修复前）：**
```
登录 alice → GET /profile?user_id=1
→ 返回 admin 的邮箱、手机、余额（越权成功！）
```

**漏洞类型：**
水平越权（Horizontal Privilege Escalation）— 同等级用户之间越权访问他人数据，无需提升权限。

---

### 2. 充值接口水平越权操作

**风险等级：🔴 严重**

**漏洞描述：**
`/recharge` 路由接收表单提交的 `user_id` 直接更新余额，完全信任前端参数：

```python
# ❌ 修复前
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id", type=int)   # 前端可控！
    amount = request.form.get("amount", type=float)
    
    # 直接修改他人余额
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
```

**攻击场景：**

| 步骤 | 操作 |
|:---:|------|
| 1 | 用户 A 登录自己账号 |
| 2 | 抓包修改充值表单中隐藏的 `user_id` 字段 |
| 3 | 向其他用户账户充值或扣款 |
| 4 | 后续若扩展消费接口，同样逻辑可越权扣除他人余额 |

**攻击验证（修复前）：**
```
POST /recharge   body: user_id=2&amount=500
→ alice 的余额增加了 500（本应是 admin 给自己充值）
```

---

### 3. 充值负数金额（业务风险）

**风险等级：🟠 高危**

**漏洞描述：**
`amount` 参数未做正负校验，可传入负数实现"扣款"：

```python
# ❌ 修复前
amount = request.form.get("amount", type=float, default=0)
# 无任何正负检查
c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
```

**攻击场景：**
- 传入 `amount=-10000` → 余额减少 10000（扣款）
- 配合越权漏洞 `user_id=1` → 扣除 admin 余额
- 攻击者给自己充正数，给他人充负数，实现"余额转移"

**攻击验证（修复前）：**
```
POST /recharge   body: user_id=2&amount=-500
→ alice 的余额减少了 500（非法扣款成功）
```

---

### 4. 前端泄露 user_id 参数

**风险等级：🟡 中危**

**漏洞描述：**
导航栏和首页的"个人中心"链接直接拼接 `user_id` 参数，导致 HTML 源码中暴露用户 ID：

```html
<!-- ❌ 修复前 -->
<a href="/profile?user_id=1" class="nav-link">个人中心</a>
```

并且充值表单使用隐藏 `input` 传递 `user_id`：

```html
<!-- ❌ 修复前：可被攻击者修改 -->
<input type="hidden" name="user_id" value="1">
```

**攻击场景：**
- 查看页面源码即可获取当前用户的 ID 编号
- 修改隐藏字段值即可攻击其他用户账户

---

## 三、漏洞根源分析

```
┌─────────────────────────────────────────────────────────┐
│                    漏洞根源架构图                        │
│                                                         │
│  用户请求 ──→  user_id（前端传递）──→ 数据库             │
│                  ↑ 完全信任         ↑  直接操作          │
│                                                         │
│  ❌ 问题：系统没有以 session 中的登录 user_id            │
│     作为信任基准，所有操作都依赖前端传入的参数             │
│                                                         │
│  ✅ 修复：服务端 session 才是唯一可信来源                │
│     session.user_id → 查询/操作 → 数据库                │
│                   （忽略前端传入的 user_id）              │
└─────────────────────────────────────────────────────────┘
```

**核心原则：**
- 用户身份的**唯一可信来源** = 服务端 Session 中存储的登录 `user_id`
- URL 参数、POST 表单数据均属于**不可信外部输入**，攻击者可自由篡改
- 前端传入的 `user_id` 只能用来做**对比校验**，不能直接作为操作对象

---

## 四、修复方案

### 修复 1：/profile 改为从 session 获取 user_id

```python
# ✅ 修复后
@app.route("/profile")
@login_required  # 添加登录保护
def profile():
    login_user_id = session.get("user_id")  # 从 session 获取，忽略 URL 参数
    user = get_user_by_id(login_user_id)
    return render_template("profile.html", user=user)
```

| 变更点 | 说明 |
|-------|------|
| 添加 `@login_required` | 未登录跳转到登录页 |
| 删除 `request.args.get("user_id")` | 不再信任 URL 参数 |
| 改为 `session.get("user_id")` | 从服务端 session 获取当前用户 |

---

### 修复 2：/recharge 改为从 session 获取 user_id + amount 正负校验

```python
# ✅ 修复后
@app.route("/recharge", methods=["POST"])
@login_required  # 添加登录保护
def recharge():
    login_user_id = session.get("user_id")  # 从 session 获取，忽略表单 user_id
    amount = request.form.get("amount", type=float, default=0)
    
    if amount <= 0:                         # 新增金额正负校验
        return "充值金额必须大于 0", 400
    
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?",
              (amount, login_user_id))      # 只能操作自己的账户
```

| 变更点 | 说明 |
|-------|------|
| 添加 `@login_required` | 未登录无法充值 |
| 删除 `request.form.get("user_id")` | 不再信任表单提交的 user_id |
| 改为 `session.get("user_id")` | 从 session 获取真实登录用户 |
| 新增 `if amount <= 0` | 禁止负数/零元充值 |

---

### 修复 3：删除前端隐藏 user_id 字段

```html
<!-- ✅ 修复后：不再传递 user_id -->
<form method="POST" action="/recharge">
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <!-- user_id 已移除，后端从 session 获取 -->
    <div class="form-group">
        <label for="amount">充值金额</label>
        <input type="number" id="amount" name="amount" required>
    </div>
    <button type="submit" class="btn btn-primary">充值</button>
</form>
```

---

### 修复 4：导航链接不再拼接 user_id 参数

```html
<!-- ✅ 修复后 -->
<a href="/profile" class="nav-link">个人中心</a>
```

---

## 五、修复前后代码对比

#### 修复前（2 处越权 + 2 处风险）

```python
# /profile — 信任 URL 参数
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")    # ❌ 攻击者可修改
    user = get_user_by_id(user_id)            # ❌ 直接查他人资料
    return render_template("profile.html", user=user)

# /recharge — 信任表单参数
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")    # ❌ 攻击者可修改
    amount = request.form.get("amount")       # ❌ 无正负校验
    c.execute("UPDATE ... balance + ? WHERE id = ?", (amount, user_id))  # ❌ 越权修改
```

```html
<!-- ❌ URL 泄露 user_id -->
<a href="/profile?user_id=1">个人中心</a>

<!-- ❌ 隐藏字段可篡改 -->
<input type="hidden" name="user_id" value="1">
```

#### 修复后（全部从 session 获取）

```python
# /profile — 从 session 获取
@app.route("/profile")
@login_required
def profile():
    login_user_id = session.get("user_id")   # ✅ 服务端可信来源
    user = get_user_by_id(login_user_id)      # ✅ 只能查自己
    return render_template("profile.html", user=user)

# /recharge — 从 session 获取 + 金额校验
@app.route("/recharge", methods=["POST"])
@login_required
def recharge():
    login_user_id = session.get("user_id")   # ✅ 服务端可信来源
    amount = request.form.get("amount")
    if amount <= 0:                           # ✅ 禁止负数
        return "充值金额必须大于 0", 400
    c.execute("UPDATE ... balance + ? WHERE id = ?", (amount, login_user_id))  # ✅ 只能操作自己
```

```html
<!-- ✅ 不再拼接 user_id -->
<a href="/profile">个人中心</a>

<!-- ✅ 删除隐藏 user_id 字段 -->
<input type="hidden" name="csrf_token" value="...">
```

---

## 六、攻击链验证（修复后）

```
修复前（全部越权成功）:
  GET /profile?user_id=2      → 查看他人资料  ❌
  POST /recharge user_id=2    → 操作他人账户  ❌
  POST /recharge amount=-500  → 非法扣款      ❌
  
修复后（全部被拒绝）:
  GET /profile?user_id=2      → 仍显示自己的资料  ✅
  POST /recharge user_id=2    → 给自己充值操作   ✅
  POST /recharge amount=-500  → 被拒绝 400      ✅
  POST /recharge amount=0     → 被拒绝 400      ✅
```

---

## 七、安全建议总结

| 措施 | 说明 | 优先级 |
|-----|------|:----:|
| **信任服务端 Session** | 当前用户身份始终从 session 获取 | 🔴 必须 |
| **不信任前端参数** | URL 参数、表单字段均可被篡改 | 🔴 必须 |
| **添加登录保护** | 所有敏感操作接口加 `@login_required` | 🔴 必须 |
| **金额正负校验** | 涉及余额变动必须校验 `amount > 0` | 🟠 推荐 |
| **隐藏字段不传身份** | 用户标识不应出现在前端 HTML 中 | 🟡 建议 |
| **URL 不暴露 user_id** | 导航链接不应拼接身份参数 | 🟡 建议 |

---

**核心安全原则：永远不要信任客户端传入的用户身份标识。用户身份的唯一可靠来源是服务端 session。**
