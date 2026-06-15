# Vulnerable App Design Guide

## 1. 项目定位

`vulnerable_app` 是本项目中的本地被测网站，也就是扫描器的靶场目标。它不是生产网站，而是一个专门为计算机安全课程设计的授权实验环境。

它的目标有三个：

- 为动态扫描器提供稳定可复现的 Web 路由。
- 为静态扫描器提供明确的源码级风险样本。
- 在基础漏洞之外加入进阶漏洞模块，让课程展示更完整。

默认访问地址：

```text
http://127.0.0.1:5001
```

默认扫描命令：

```powershell
python run_scan.py --base-url http://127.0.0.1:5001 --project-path .\vulnerable_app
```

## 2. 建议上传的代码结构

只需要上传以下源码和说明文件：

```text
vulnerable_app/
├── app.py
├── README.md
├── VULNERABLE_APP_GUIDE.md
├── requirements.txt
└── files/
    ├── public.txt
    └── lab-notes.txt
```

根目录还需要保留 `.gitignore` 的相关更新，用来忽略运行产物：

```text
.gitignore
```

不要上传以下本地运行产物：

```text
.env
security_report.md
security_report.html
scanner/__pycache__/
vulnerable_app/__pycache__/
vulnerable_app/vulnerable.db
vulnerable_app/server.log
vulnerable_app/server.err.log
```

## 3. 文件说明

### `app.py`

Flask 靶场主程序，包含：

- 页面渲染
- SQLite 初始化
- 测试账号
- 基础漏洞接口
- 进阶漏洞接口
- 靶场控制接口

数据库文件 `vulnerable.db` 会在运行时自动生成，不需要上传。

### `requirements.txt`

靶场依赖，目前只需要 Flask：

```text
Flask>=3.0,<4.0
```

### `README.md`

面向快速启动的简短说明，适合队友直接运行项目。

### `VULNERABLE_APP_GUIDE.md`

面向课程报告和答辩的详细设计文档，也就是本文档。

### `files/`

用于路径穿越实验的示例文件目录：

- `public.txt`：正常下载文件。
- `lab-notes.txt`：靶场模块说明文件。

## 4. 启动方式

进入项目根目录：

```powershell
cd C:\Users\玖林\Documents\计安\Computer-security-main
```

安装依赖：

```powershell
pip install -r .\vulnerable_app\requirements.txt
```

启动靶场：

```powershell
python .\vulnerable_app\app.py
```

启动后访问：

```text
http://127.0.0.1:5001
```

健康检查：

```text
http://127.0.0.1:5001/health
```

## 5. 测试账号

```text
admin / admin123
user1 / 123456
user2 / 123456
lab_backdoor / letmein-lab
```

说明：

- `admin` 是管理员账号。
- `user1` 和 `user2` 是普通用户账号。
- `lab_backdoor` 是课程演示用旁路账号，只用于本地实验。

## 6. 基础漏洞模块

这些模块用于保证原扫描器可以稳定命中。

### 6.1 SQL Injection

路由：

```text
POST /login
```

设计点：

- 登录接口把用户名和密码哈希直接拼接进 SQL 查询。
- 扫描器使用错误密码和 SQL 注入 payload 做对比。
- 错误密码登录失败，注入 payload 登录成功时，报告 SQL 注入。

风险说明：

- 攻击者可能绕过登录。
- 攻击者可能读取或修改数据库。
- 生产环境应使用参数化查询或 ORM 绑定参数。

### 6.2 Stored XSS

路由：

```text
POST /comments
GET /comments
```

设计点：

- 评论内容写入数据库。
- 页面渲染评论时故意不做 HTML 转义。
- 扫描器提交 `<script>` payload 后，再访问评论页检测是否原样出现。

风险说明：

- 用户浏览页面时可能执行恶意脚本。
- 可能导致 cookie、会话或页面数据泄露。
- 生产环境应对输出进行 HTML 转义，并设置 CSP。

### 6.3 Broken Access Control

路由：

```text
GET /admin
GET /profile/2
```

设计点：

- `/admin` 只检查是否登录，不检查角色是否为管理员。
- `/profile/<id>` 只检查是否登录，不检查当前用户是否拥有该资源。

风险说明：

- 普通用户可以访问管理员页面。
- 普通用户可以查看其他用户资料。
- 生产环境应做服务端 RBAC 和对象级权限校验。

### 6.4 Hardcoded Secret

位置：

```text
vulnerable_app/app.py
```

设计点：

- 源码中保留演示用假密钥。
- 字段名包括 `SECRET_KEY`、`API_KEY`、`DB_PASSWORD`。
- 这些值都是课程演示用假值，不是真实凭据。

风险说明：

- 真实项目中硬编码密钥会导致凭据泄露。
- 生产环境应使用环境变量或密钥管理服务。

### 6.5 Weak Password Storage

位置：

```text
vulnerable_app/app.py
```

设计点：

- 使用 MD5 存储密码哈希。
- 同时保留 `plain_password` 字段用于静态扫描演示。

风险说明：

- MD5 不适合存储密码。
- 明文密码字段会带来严重数据泄露风险。
- 生产环境应使用 bcrypt、argon2 或 Werkzeug 安全哈希。

## 7. 进阶漏洞模块

这些模块用来体现靶场设计的完整性，让作业不止停留在基础漏洞。

### 7.1 CSRF

路由：

```text
GET /transfer
POST /transfer
```

设计点：

- 转账表单没有 CSRF token。
- 后端只依赖 cookie 会话判断用户身份。

演示方式：

1. 使用 `user1 / 123456` 登录。
2. 打开 `/transfer`。
3. 提交转账表单。

风险说明：

- 如果用户已登录，攻击页面可以诱导浏览器发起跨站请求。
- 生产环境应加入 CSRF token、SameSite cookie 和关键操作二次确认。

### 7.2 Path Traversal

路由：

```text
GET /download?file=public.txt
```

设计点：

- 接口把 `file` 参数直接拼接到 `files/` 路径后。
- 没有校验最终路径是否仍在允许目录中。

演示方式：

```text
http://127.0.0.1:5001/download?file=public.txt
```

风险说明：

- 攻击者可能尝试读取非预期文件。
- 生产环境应使用路径规范化、白名单文件 ID，不直接接收文件路径。

### 7.3 SSRF

路由：

```text
GET /fetch?url=http://127.0.0.1:5001/health
```

设计点：

- 服务端根据用户传入的 URL 发起请求。
- 没有限制内网地址、本机地址或敏感元数据地址。

演示方式：

```text
http://127.0.0.1:5001/fetch?url=http://127.0.0.1:5001/health
```

风险说明：

- 攻击者可能利用服务器访问内网服务。
- 生产环境应做目标域名白名单、IP 段过滤和协议限制。

### 7.4 Open Redirect

路由：

```text
GET /redirect?next=/login
```

设计点：

- 接口直接读取 `next` 参数并跳转。
- 没有判断目标是否为站内路径。

风险说明：

- 攻击者可以构造可信域名开头的钓鱼链接。
- 生产环境应只允许相对路径或白名单域名。

### 7.5 Mass Assignment

路由：

```text
GET /settings
POST /settings
```

设计点：

- 后端直接从表单读取允许更新的字段。
- 普通用户可以提交 `role=admin`。

演示方式：

1. 使用 `user1 / 123456` 登录。
2. 打开 `/settings`。
3. 将角色设置为 `admin` 并保存。
4. 访问 `/admin`，可以看到用户角色已经变化。

风险说明：

- 攻击者可能修改本不应该由用户控制的字段。
- 生产环境应使用 DTO 或字段白名单，并排除权限字段。

### 7.6 Information Disclosure

路由：

```text
GET /debug/config
```

设计点：

- 调试接口返回数据库路径、演示密钥、用户信息和审计日志。
- 没有身份认证和访问控制。

风险说明：

- 真实系统中调试接口可能泄露敏感配置。
- 生产环境应关闭 debug 接口，并对管理接口加鉴权和审计。

## 8. 靶场辅助模块

### 8.1 Health Check

路由：

```text
GET /health
```

用途：

- 给扫描器前端判断靶场是否在线。
- 返回服务名、用户数量、评论数量。

### 8.2 Lab Reset

路由：

```text
POST /lab/reset
```

用途：

- 重置 SQLite 数据库。
- 恢复默认用户、评论和余额数据。
- 方便多次演示后恢复初始状态。

### 8.3 Debug Session

路由：

```text
GET /lab/debug/session?token=lab-backdoor-token
```

用途：

- 仅本机可用。
- 创建演示用管理员会话。
- 方便扫描器前端和规则迭代。

## 9. 与扫描器的配合关系

扫描器默认配置：

```text
base_url: http://127.0.0.1:5001
project_path: ./vulnerable_app
```

动态扫描会访问：

```text
POST /login
POST /comments
GET /comments
GET /admin
GET /profile/2
```

静态扫描会扫描：

```text
.py
.js
.html
.env
.txt
.json
```

因此 `app.py` 中的假密钥、MD5、明文密码字段，以及 `files/` 下的实验说明文件都会作为源码样本参与扫描。

## 10. 答辩时可以强调的设计亮点

- 靶场不是单一路由 demo，而是覆盖认证、评论、管理后台、用户资料、转账、文件读取、服务端请求、跳转、配置泄露等多个业务场景。
- 基础漏洞可以被现有扫描器稳定识别，保证项目联调可运行。
- 进阶模块展示了扫描器未来可扩展方向，包括 CSRF、SSRF、路径穿越、开放重定向和 Mass Assignment。
- 提供 `/health` 和 `/lab/reset`，说明靶场考虑了前端联调、重复扫描和演示复现。
- 所有密钥都是假值，真实 API key 不写入源码。

## 11. 安全边界

本靶场只允许在本地授权环境使用：

```text
127.0.0.1
localhost
```

不要部署到公网，不要把真实密钥写入源码，不要用该项目扫描第三方网站。
