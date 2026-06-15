# Vulnerable Test Site

这是课程项目使用的本地授权靶场网站，默认运行在 `http://127.0.0.1:5001`。
它配合项目根目录的扫描器使用，提供稳定的 DAST 路由和 SAST 源码样本。

## 启动

```powershell
cd vulnerable_app
pip install -r requirements.txt
python app.py
```

启动后访问：

```text
http://127.0.0.1:5001
```

## 测试账号

```text
admin / admin123
user1 / 123456
user2 / 123456
lab_backdoor / letmein-lab
```

## 扫描器命令

在项目根目录运行：

```powershell
python run_scan.py --base-url http://127.0.0.1:5001 --project-path .\vulnerable_app
```

## 故意保留的漏洞

### 基础扫描器可命中的漏洞

- `/login` 使用字符串拼接 SQL，支持演示 SQL 注入登录绕过。
- `/comments` 原样渲染评论内容，支持演示存储型 XSS。
- `/admin` 只判断是否登录，不判断管理员角色。
- `/profile/<id>` 不校验资料归属，普通用户可访问其他用户资料。
- 源码中包含演示用硬编码假密钥、明文密码字段和 MD5 密码哈希，便于 SAST 规则命中。

### 进阶靶场模块

- `/transfer` 缺少 CSRF token，演示跨站请求伪造风险。
- `/download?file=public.txt` 未限制最终文件路径，演示路径穿越。
- `/fetch?url=http://127.0.0.1:5001/health` 服务端按用户输入抓取 URL，演示 SSRF。
- `/redirect?next=/login` 直接信任跳转参数，演示开放重定向。
- `/settings` 直接批量更新用户提交字段，演示 Mass Assignment 导致普通用户修改角色。
- `/debug/config` 返回调试配置、假密钥、用户和审计日志，演示敏感信息泄露。

### 靶场辅助入口

- `lab_backdoor / letmein-lab` 是课程演示用登录旁路。
- `/lab/debug/session?token=lab-backdoor-token` 是仅本机可用的调试会话入口，方便扫描器迭代。
- `/lab/reset` 可重置数据库，便于多次扫描后恢复初始状态。
- `/health` 返回 JSON 健康检查结果，方便扫描器前端判断靶场是否在线。

请只在本地实验环境使用，不要部署到公网。
