# AI 漏洞扫描器前端说明文档

## 1. 当前工作内容

本前端模块是 AI 漏洞扫描器的 Web 控制台原型，当前采用 **单页动态控制台 + 本地 API 联调** 实现。

当前目标不是只做一张静态 UI 图，而是把前端页面结构、交互流程、数据展示方式和后端扫描接口接起来。扫描管理、漏洞管理、资产管理、报告中心和任务调度页会优先读取本地后端 API。

当前分支已经加入本地 API 对接层。运行项目根目录的：

```powershell
python serve_app.py
```

然后打开：

```text
http://127.0.0.1:8000/
```

前端会优先调用后端 `/api` 接口启动扫描、轮询状态、加载结果和打开报告；如果后端未启动，则只有无法接入真实模型的展示模块保留本地兜底数据。

当前前端目录：

```text
frontend/
├── welcome.html
├── welcome.css
├── welcome.js
├── index.html
├── styles.css
├── app.js
└── README.md
```

打开方式：

```text
直接双击 frontend/welcome.html
```

或在浏览器打开：

```text
frontend/welcome.html
```

页面入口说明：

```text
welcome.html：初始化进入页
index.html：主控制台页面
```

## 2. 页面风格

整体风格参考安全运营控制台：

- 深色背景
- 蓝色扫描主视觉
- 大圆盘雷达扫描进度
- 玻璃拟态面板
- 红、橙、黄、蓝表示风险等级
- 左侧菜单 + 顶部导航 + 右侧详情抽屉

核心配色逻辑：

```text
主色：蓝色 / 青蓝色
背景：黑灰 / 深蓝
Critical：红色
High：橙色
Medium：黄色
Low：蓝色
Success：绿色
```

## 3. 已完成功能

### 3.0 初始化进入页

新增了一个独立初始化界面，用于在进入主控制台前展示项目启动效果。

文件：

```text
frontend/welcome.html
frontend/welcome.css
frontend/welcome.js
```

包含内容：

- 黑色背景
- 深绿色字符流动效果
- 中央启动面板
- 项目标题
- 简短终端初始化日志
- 1.5 秒固定读条动画
- “进入控制台”按钮

当前调整：

```text
减少了中间启动框中的文字数量
去掉了“跳过初始化”按钮
将浅荧光绿调整为更沉稳的深绿色
中间启动框尺寸保持克制，不占满页面
```

交互流程：

```text
打开 welcome.html
播放初始化动画
进度条约 1.5 秒到 100%
点击“进入控制台”
跳转到 index.html 主控制台
```

设计定位：

```text
初始化页负责黑客风启动氛围，主控制台负责实际扫描器功能展示。
```

### 3.1 扫描管理

扫描管理是首页，也是主展示页。

包含内容：

- 扫描目标
- 扫描类型
- 开始时间
- 预计耗时
- 已选择扫描模块
- 大圆盘扫描进度
- 扫描阶段流程
- 实时事件流
- 漏洞统计卡片
- 已发现漏洞列表
- 右侧漏洞详情抽屉

当前展示的扫描阶段：

```text
连接目标
SQL 注入测试
XSS 测试
越权访问测试
弱密码分析
AI 修复建议
```

当前展示的漏洞类型：

```text
SQL Injection
Cross-Site Scripting
Broken Access Control
Hardcoded Secret
Weak Password Storage
```

### 3.2 漏洞管理

漏洞管理页面用于集中查看和管理扫描结果。

包含内容：

- 总漏洞数
- 严重漏洞数量
- 高危漏洞数量
- 待修复漏洞数量
- 漏洞表格
- 风险等级标签
- 检测方式
- 修复状态

用途：

```text
给后续漏洞筛选、漏洞详情查看、漏洞状态跟踪、漏洞分派留接口位置。
```

### 3.3 资产管理

资产管理页面用于管理被扫描目标。

包含内容：

- 被扫描网站
- 源码路径
- 测试 API
- 资产类型
- 负责人
- 资产风险等级
- 最近扫描时间

用途：

```text
后续扫描任务可以从资产库中选择目标，而不是每次手动输入 URL 和源码路径。
```

### 3.4 报告中心

报告中心页面用于管理扫描报告。

包含内容：

- 报告名称
- 扫描目标
- 风险等级
- 报告格式
- 生成时间
- 预览按钮
- 下载 HTML 按钮
- 下载 Markdown 按钮

用途：

```text
对齐后端已经存在的 Markdown/HTML 报告生成能力。
```

### 3.5 AI 修复

AI 修复页面用于展示防御性修复建议。

包含内容：

- 漏洞选择列表
- AI 中文修复建议
- 修复优先级
- 修复前代码示例
- 修复后代码示例

用途：

```text
对齐后端 ai_advisor.py 生成的 ai_advice 字段。
```

### 3.6 任务调度

任务调度页面用于展示扫描任务计划。

包含内容：

- 运行中任务
- 等待中任务
- 失败任务
- 周期任务
- 任务名
- 扫描目标
- 扫描模式
- 计划时间
- 任务状态

用途：

```text
后续如果后端支持任务队列或定时扫描，可以直接接入。
```

### 3.7 系统设置

系统设置页面只保留扫描联调需要的参数。

包含内容：

- 后端 API 地址
- 默认目标 URL
- 默认源码路径
- 任务存储方式说明

用途：

```text
配置下一次扫描使用的默认目标，避免保留没有真实后端支撑的主题、插件、报告目录等设置。
```

## 4. 当前交互能力

当前不是纯静态页面，已经有部分前端交互：

- 左侧菜单可切换页面
- 顶部导航可同步切换部分页面
- 漏洞表格点击行可切换右侧详情
- DAST / SAST 筛选按钮可筛选漏洞
- 状态筛选可切换未修复 / 已修复
- 实时事件流可清空和刷新
- 查看详情会弹窗
- 生成修复建议会弹窗
- 导出报告会打开后端生成的 Markdown / HTML 报告
- 标记为已修复会更新前端状态
- 操作后会出现 toast 提示
- 支持 hash 直接打开模块

hash 示例：

```text
index.html#scan
index.html#vulnerabilities
index.html#assets
index.html#reports
index.html#ai-fix
index.html#schedule
index.html#settings
```

## 5. 当前数据来源

当前扫描主流程数据来自本地后端 API。

已经接入后端的数据包括：

- 扫描任务启动、状态和结果
- 漏洞列表和漏洞状态
- 后端生成的 Markdown / HTML 报告
- 后端任务列表
- 后端任务派生的资产列表

仍保留本地展示数据的部分主要是 AI 修复页中的代码对比示例、顶部通知数量和部分非核心说明文案。

## 6. 与后端现有代码的关系

当前后端已有核心扫描函数：

```python
from scanner.full_scan import run_full_security_scan

result = run_full_security_scan(
    base_url="http://127.0.0.1:5001",
    project_path="./vulnerable_app",
)
```

后端返回结构大致为：

```python
{
    "target": {
        "base_url": "...",
        "project_path": "..."
    },
    "risk": {
        "overall_score": 90,
        "overall_risk": "Critical",
        "total": 5,
        "critical": 1,
        "high": 3,
        "medium": 1,
        "low": 0
    },
    "vulnerabilities": [],
    "reports": {
        "markdown": "...",
        "html": "..."
    },
    "errors": []
}
```

前端页面基本就是围绕这个结构设计的。

## 7. 建议后端提供的 API

### 7.1 启动扫描

接口：

```http
POST /api/scan/start
```

请求体：

```json
{
  "base_url": "http://127.0.0.1:5001",
  "project_path": "./vulnerable_app",
  "scan_mode": "full",
  "modules": [
    "sql_injection",
    "xss",
    "broken_access_control",
    "hardcoded_secret",
    "weak_password_storage",
    "ai_advice"
  ]
}
```

建议响应：

```json
{
  "task_id": "SCAN-20240601-0001",
  "status": "running",
  "message": "Scan task started."
}
```

前端用途：

```text
点击“开始扫描”后调用该接口。
```

### 7.2 获取扫描状态

接口：

```http
GET /api/scan/status/{task_id}
```

建议响应：

```json
{
  "task_id": "SCAN-20240601-0001",
  "status": "running",
  "progress": 67,
  "current_step": "SQL 注入测试",
  "steps": [
    {
      "name": "连接目标",
      "status": "done",
      "duration": "00:00:08"
    },
    {
      "name": "SQL 注入测试",
      "status": "running",
      "duration": "00:02:15"
    }
  ],
  "events": [
    {
      "time": "14:32:37",
      "level": "RISK",
      "message": "检测到 SQL 注入漏洞"
    }
  ]
}
```

前端用途：

```text
更新大圆盘进度、扫描阶段、实时事件流。
```

### 7.3 获取扫描结果

接口：

```http
GET /api/scan/result/{task_id}
```

建议响应：

```json
{
  "task_id": "SCAN-20240601-0001",
  "target": {
    "base_url": "http://127.0.0.1:5001",
    "project_path": "./vulnerable_app"
  },
  "risk": {
    "overall_score": 92,
    "overall_risk": "Critical",
    "total": 5,
    "critical": 1,
    "high": 3,
    "medium": 1,
    "low": 0
  },
  "vulnerabilities": [
    {
      "id": "VULN-2024-0001",
      "type": "SQL Injection",
      "category": "Input Validation",
      "risk": "Critical",
      "score": 95,
      "location": "/login",
      "method": "DAST",
      "evidence": "SQL injection payload caused login bypass.",
      "suggestion": "Use parameterized queries instead of string concatenation.",
      "ai_advice": "建议将登录查询改为参数化查询...",
      "status": "未修复",
      "discovered_at": "2024-06-01 14:32:37"
    }
  ],
  "reports": {
    "markdown_url": "/api/report/SCAN-20240601-0001/markdown",
    "html_url": "/api/report/SCAN-20240601-0001/html"
  },
  "errors": []
}
```

前端用途：

```text
更新漏洞统计、漏洞表格、右侧详情、报告下载入口。
```

### 7.4 获取报告 HTML

接口：

```http
GET /api/report/{task_id}/html
```

返回：

```text
HTML 报告内容，或返回一个可打开的 html 文件。
```

前端用途：

```text
报告中心点击“预览”或“下载 HTML”。
```

### 7.5 获取报告 Markdown

接口：

```http
GET /api/report/{task_id}/markdown
```

返回：

```text
Markdown 报告内容，或返回一个 .md 文件。
```

前端用途：

```text
报告中心点击“下载 Markdown”。
```

### 7.6 生成 AI 修复建议

接口：

```http
POST /api/vulnerability/{vuln_id}/ai-advice
```

请求体：

```json
{
  "task_id": "SCAN-20240601-0001"
}
```

建议响应：

```json
{
  "vulnerability_id": "VULN-2024-0001",
  "ai_advice": "建议使用参数化查询或 ORM 绑定参数...",
  "priority": "立即修复"
}
```

前端用途：

```text
AI 修复页面和漏洞详情抽屉中的“生成修复建议”按钮。
```

### 7.7 更新漏洞状态

接口：

```http
PATCH /api/vulnerability/{vuln_id}/status
```

请求体：

```json
{
  "status": "已修复"
}
```

建议响应：

```json
{
  "vulnerability_id": "VULN-2024-0001",
  "status": "已修复"
}
```

前端用途：

```text
点击“标记为已修复”后更新漏洞状态。
```

### 7.8 获取资产列表

接口：

```http
GET /api/assets
```

建议响应：

```json
{
  "assets": [
    {
      "id": "ASSET-001",
      "name": "本地靶场",
      "url": "http://127.0.0.1:5001",
      "project_path": "./vulnerable_app",
      "type": "Web 应用",
      "owner": "SecOps Team",
      "risk": "Critical",
      "last_scan_at": "2024-06-01 14:32:37"
    }
  ]
}
```

前端用途：

```text
资产管理页面。
```

### 7.9 获取任务列表

接口：

```http
GET /api/tasks
```

建议响应：

```json
{
  "tasks": [
    {
      "id": "TASK-001",
      "name": "每日靶场扫描",
      "target": "http://127.0.0.1:5001",
      "scan_mode": "full",
      "schedule": "每天 20:00",
      "status": "running"
    }
  ]
}
```

前端用途：

```text
任务调度页面。
```

### 7.10 获取系统设置

接口：

```http
GET /api/settings
```

建议响应：

```json
{
  "api_base_url": "http://127.0.0.1:5000/api",
  "default_base_url": "http://127.0.0.1:5001",
  "default_project_path": "./vulnerable_app",
  "report_output_dir": "./reports",
  "ai_provider": "qwen",
  "ai_key_configured": false
}
```

前端用途：

```text
系统设置页面。
```

## 8. 前端需要后端统一的数据字段

漏洞对象建议统一字段：

```json
{
  "id": "VULN-2024-0001",
  "type": "SQL Injection",
  "category": "Input Validation",
  "risk": "Critical",
  "score": 95,
  "location": "/login",
  "method": "DAST",
  "evidence": "SQL injection payload caused login bypass.",
  "suggestion": "Use parameterized queries instead of string concatenation.",
  "ai_advice": "中文 AI 修复建议",
  "status": "未修复",
  "discovered_at": "2024-06-01 14:32:37",
  "component": "web-app"
}
```

风险等级建议固定为：

```text
Critical
High
Medium
Low
```

检测方式建议固定为：

```text
DAST
SAST
```

漏洞状态建议固定为：

```text
未修复
已修复
已忽略
复测中
```

事件等级建议固定为：

```text
INFO
WARN
RISK
ERROR
```

## 9. 后续接口完善点

当前扫描主流程、漏洞列表、资产列表、报告列表和任务列表已经接入本地 API。

后续需要补强的接口主要是：

```text
任务持久化
登录权限
平台级资产库
设置保存
更细粒度扫描进度
AI Key 状态检测
```

## 10. 当前完成度说明

当前已完成：

```text
初始化进入页完成
页面结构完成
视觉风格完成
七个侧边栏模块页面完成
核心页面本地 API 数据展示完成
基础交互完成
报告真实 API 打开完成
后端接口对齐文档完成
扫描管理、漏洞管理、资产管理、报告中心、任务调度已接本地 API
```

当前未完成：

```text
真实后端 API 已有本地标准库版本，后续可替换为正式测试平台服务
真实扫描任务已能通过本地 API 调用 run_full_security_scan
真实报告文件已能通过本地 API 返回 HTML / Markdown 内容
未接真实 AI API Key 状态
未做登录权限系统
```

## 11. 给组长/后端同学的说明

前端当前已经把主要页面和交互流程搭好。

后端同学接下来需要重点完成：

```text
1. 将当前标准库 API 服务替换或并入正式测试平台后端
2. 补充任务持久化，避免服务重启后丢失扫描历史
3. 提供更细粒度的扫描进度事件
4. 按团队统一协议继续稳定漏洞对象字段
5. 将当前资产、报告、任务调度列表接口持久化并扩展为正式平台接口
6. 接入真实 AI API Key 状态
7. 增加登录权限系统
```

前端核心扫描链路已经具备基础接口请求能力，后续主要是把登录权限、平台级资产库和持久化配置继续替换为正式接口数据。
