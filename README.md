# AI Web Vulnerability Scanner

面向课程项目的 Web 漏洞检测与 AI 修复建议平台。当前版本用于扫描本地授权的 vulnerable web app，不用于扫描真实第三方网站。

## 功能

- 动态漏洞检测 DAST
  - SQL Injection: 检测 `/login` 是否存在 SQL 注入登录绕过
  - Cross-Site Scripting: 检测 `/comments` 是否原样渲染脚本标签
  - Broken Access Control: 检测普通用户是否能访问 `/admin` 或其他用户资料
- 静态漏洞检测 SAST
  - Hardcoded Secret: 检测源码中的硬编码密钥、Token、密码等
  - Weak Password Storage: 检测 MD5、SHA1、明文密码存储等弱密码模式
- 风险评分
  - 根据漏洞最高分和数量加成计算整体风险
  - 输出 Low、Medium、High、Critical
- AI 修复建议
  - 优先调用 OpenAI、DeepSeek 或千问兼容接口
  - 没有 API Key 或调用失败时使用本地中文模板兜底
- 报告生成
  - Markdown 报告
  - HTML 报告

## 项目结构

```text
scanner/
├── __init__.py
├── full_scan.py
├── dynamic_scanner.py
├── static_scanner.py
├── risk_engine.py
├── ai_advisor.py
└── report_generator.py
run_scan.py
.env.example
```

## 环境要求

- Python 3.10+
- requests

安装依赖：

```powershell
pip install requests
```

## 配置 AI API Key

复制示例配置文件：

```powershell
copy .env.example .env
```

然后编辑 `.env`，填写一个可用的 API Key：

```env
QWEN_API_KEY=your_qwen_api_key_here
# OPENAI_API_KEY=your_openai_api_key_here
# DEEPSEEK_API_KEY=your_deepseek_api_key_here
```

注意：`.env` 保存的是本地私密配置，不应该提交到 GitHub。

如果没有配置 API Key，扫描器仍然可以运行，并会使用内置中文模板生成修复建议。

## 启动扫描

先启动本地靶场网站，例如：

```text
http://127.0.0.1:5001
```

然后在项目根目录运行：

```powershell
python run_scan.py
```

## 启动前后端联调控制台

当前分支已经提供本地 API + 静态前端服务：

```powershell
python serve_app.py
```

默认访问地址：

```text
http://127.0.0.1:8000/
```

该服务会直接托管 `frontend/` 页面，并提供这些接口：

```text
GET  /api/health
POST /api/auth/login
GET  /api/auth/me
POST /api/scan/start
GET  /api/scan/status/{task_id}
GET  /api/scan/result/{task_id}
POST /api/tasks/{task_id}/rerun
POST /api/tasks/{task_id}/cancel
GET  /api/assets
POST /api/assets
PATCH /api/assets/{asset_id}
DELETE /api/assets/{asset_id}
POST /api/assets/{asset_id}/scan
GET  /api/reports
GET  /api/report/{task_id}/html
GET  /api/report/{task_id}/markdown
PATCH /api/report/{task_id}
DELETE /api/report/{task_id}
POST /api/vulnerability/{vuln_id}/ai-advice
PATCH /api/vulnerability/{vuln_id}/status
```

前端点击“开始扫描”后，会调用 `/api/scan/start` 创建任务，轮询 `/api/scan/status/{task_id}`，完成后读取 `/api/scan/result/{task_id}` 并渲染真实扫描结果。

后端会把任务、扫描结果、报告内容、漏洞修复状态和系统设置持久化到：

```text
data/scanner_state.json
```

服务重启后会自动加载历史任务与最近报告。重启前仍在运行的任务会被标记为中断，避免前端一直显示运行中。

当前分支还包含这些平台迭代能力：

- DAST 会先做同源页面爬取，发现路由、表单和参数，再把发现结果用于登录、XSS、越权和敏感路由检测。
- 扫描结果会按漏洞类型、位置、检测方式和证据生成指纹，合并重复项，并输出 `confidence` 置信度。
- 资产库支持新增、编辑、删除，并可从资产发起扫描。
- 任务调度支持历史持久化、重跑和取消运行中任务。
- 报告中心支持重命名、删除、HTML 预览和 Markdown 打开。
- AI 修复建议支持生成后人工编辑确认，并保存建议版本。
- 后端写操作使用本地课程账号鉴权，默认账号为 `admin/admin123`。

默认参数：

```text
base_url: http://127.0.0.1:5001
project_path: ./vulnerable_app
markdown report: security_report.md
html report: security_report.html
```

自定义参数：

```powershell
python run_scan.py --base-url http://127.0.0.1:5001 --project-path ./vulnerable_app
```

指定报告输出路径：

```powershell
python run_scan.py --markdown reports/security_report.md --html reports/security_report.html
```

## 作为 Python 模块调用

```python
from scanner.full_scan import run_full_security_scan

result = run_full_security_scan(
    base_url="http://127.0.0.1:5001",
    project_path="./vulnerable_app",
)

print(result["risk"])
print(result["vulnerabilities"])
print(result["reports"]["markdown"])
```

返回数据结构：

```python
{
    "target": {
        "base_url": "http://127.0.0.1:5001",
        "project_path": "./vulnerable_app",
    },
    "risk": {
        "overall_score": 90,
        "overall_risk": "Critical",
        "total": 5,
    },
    "vulnerabilities": [],
    "reports": {
        "markdown": "...",
        "html": "...",
    },
    "errors": [],
}
```

## 当前检测规则

### SQL Injection

目标接口：

```text
POST /login
```

扫描器会先用错误密码登录，再使用 SQL 注入 payload 登录。如果错误密码失败但 payload 成功，则报告 SQL Injection。

### Cross-Site Scripting

目标接口：

```text
POST /comments
GET /comments
```

扫描器会提交测试脚本，再访问评论页面。如果页面原样包含脚本标签，则报告 XSS。

### Broken Access Control

目标接口：

```text
POST /login
GET /admin
GET /profile/2
```

扫描器会使用普通用户登录，然后检测是否能访问管理员页面或其他用户资料。

### Hardcoded Secret

扫描文件类型：

```text
.py .js .html .env .txt .json
```

检测关键词包括：

```text
SECRET_KEY
API_KEY
ACCESS_TOKEN
DB_PASSWORD
PRIVATE_KEY
CLIENT_SECRET
sk-
token =
password =
```

### Weak Password Storage

检测关键词包括：

```text
md5
sha1
hashlib.md5
hashlib.sha1
plain_password
save(password)
INSERT INTO users
```

## 安全边界

本项目只用于课程实验和本地授权靶场扫描。AI 模块只根据已经检测出的漏洞生成防御性修复建议，不负责攻击真实网站，也不提供扫描第三方站点的操作步骤。

