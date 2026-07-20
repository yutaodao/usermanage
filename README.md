# 用户信息管理系统

一个使用 Python Flask 框架构建的简易用户信息管理平台，集成了完整的身份认证、用户管理功能和安全防护体系。

## 功能

- ✅ **用户注册** — 支持新用户自助注册（含服务端输入校验）
- ✅ **用户登录** — 密码哈希比对 + 频率限制 + 锁定倒计时
- ✅ **用户搜索** — 登录后可搜索用户名或邮箱（参数化查询防注入）
- ✅ **用户信息展示** — 展示当前登录用户的个人信息
- ✅ **密码修改** — 含旧密码验证 + 新密码强度校验
- ✅ **Session 管理** — 2 小时自动过期 + SameSite 防护

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端框架 | Python Flask |
| 数据库 | SQLite 3 |
| 密码哈希 | scrypt（`werkzeug.security`）|
| 前端 | Jinja2 模板 + CSS |

## 快速开始

```bash
# 安装依赖
pip install flask

# 启动服务
cd /opt/Class01
python3 app.py
```

访问 http://localhost:5000

## 默认账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | Admin@2025#Secure | admin |
| alice | Alice@2025#Secure | user |

## 项目结构

```
Class01/
├── app.py                 # Flask 主应用
├── data/
│   └── users.db          # SQLite 数据库（密码哈希存储）
├── templates/
│   ├── base.html         # 基础模板（导航栏）
│   ├── index.html        # 首页（用户信息 + 搜索 + 改密码）
│   ├── login.html        # 登录页（含限流锁定界面）
│   └── register.html     # 注册页
├── static/
│   └── css/
│       └── style.css     # 样式文件
├── SECURITY_REPORT.md    # 安全分析与修复报告（25 项漏洞）
└── README.md             # 本文件
```

## 安全特性

本系统经过完整的安全审计，共计修复 **25 项安全漏洞**，覆盖以下维度：

| 安全维度 | 措施 |
|---------|------|
| **认证架构** | 统一 SQLite 认证，注册用户可正常登录 |
| **密码存储** | 全站 scrypt 哈希（加盐），杜绝明文 |
| **密码比对** | `check_password_hash()` 安全比对 |
| **密码修改** | 持久化写入数据库，重启不丢失 |
| **SQL 注入** | 全部参数化查询，杜绝 f-string 拼接 |
| **CSRF 防护** | 所有 POST 接口绑定 Session Token |
| **访问控制** | 搜索功能仅登录用户可用 |
| **暴力破解** | 登录 5次/分钟 + 注册 3次/分钟 + 锁定倒计时 |
| **输入校验** | 服务端正则校验（用户名/邮箱/手机号/密码） |
| **Session 安全** | 2 小时自动过期 + SameSite=Lax + HttpOnly |
| **密钥管理** | Secret Key 从环境变量读取 |
| **信息泄露** | 异常信息收敛为通用提示 |
| **安全头** | X-Frame-Options / HSTS / CSP / XSS 保护 |

## 安全报告

详细的安全漏洞分析、攻击场景复现、修复前后代码对比，请参阅：
**[SECURITY_REPORT.md](./SECURITY_REPORT.md)**

## API 接口

| 路由 | 方法 | 说明 | 登录要求 |
|------|------|------|:-------:|
| `/` | GET | 首页（用户信息 + 搜索） | 部分功能需登录 |
| `/login` | GET/POST | 用户登录 | ❌ |
| `/register` | GET/POST | 用户注册 | ❌ |
| `/logout` | GET | 退出登录 | ❌ |
| `/search` | GET | 搜索用户（keyword 参数） | ✅ |
| `/change-password` | POST | 修改密码 | ✅ |

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|-------|
| `SECRET_KEY` | Flask 密钥（生产环境请设置强密钥） | `dev-key-2025-insecure-change-in-production` |
| `FLASK_DEBUG` | Debug 模式开关 | `0`（关闭） |
