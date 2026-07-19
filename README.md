# 用户信息管理系统

一个使用 Python Flask 框架构建的简易用户信息管理平台。

## 功能

- ✅ 用户登录（密码哈希存储 + 频率限制）
- ✅ 用户信息展示
- ✅ 密码修改（含强度校验）
- ✅ Session 过期管理
- ✅ CSRF 保护
- ✅ 安全响应头

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
├── templates/             # HTML 模板
│   ├── base.html          # 基础模板
│   ├── index.html         # 首页
│   └── login.html         # 登录页
├── static/
│   └── css/
│       └── style.css      # 样式文件
├── SECURITY_REPORT.md     # 安全修复报告
└── README.md              # 本文件
```

## 安全特性

- 密码使用 **scrypt** 哈希存储（不可逆）
- 登录频率限制（1 分钟 5 次）
- CSRF Token 保护
- Session 2 小时自动过期
- 安全响应头（X-Frame-Options, HSTS 等）
