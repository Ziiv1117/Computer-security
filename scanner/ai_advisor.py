from __future__ import annotations

import json
import os
from pathlib import Path
import urllib.error
import urllib.request


PROMPT_TEMPLATE = """You are a defensive web security assistant.
Given the following vulnerability detected in a local authorized lab project, explain:
1. what the vulnerability means,
2. why it is dangerous,
3. how to fix it,
4. give a short secure coding suggestion.
Do not provide instructions for attacking real third-party websites.
Return the answer in Chinese for a course presentation and report.
Vulnerability:
{vulnerability}
"""


LOCAL_TEMPLATES = {
    "SQL Injection": "SQL 注入表示后端把用户输入直接拼进 SQL 语句，攻击者可能绕过登录或读取、修改数据库。修复时应使用参数化查询或 ORM 绑定参数，禁止字符串拼接 SQL，并对登录失败、异常信息做统一处理。",
    "Cross-Site Scripting": "跨站脚本漏洞表示用户输入被未转义地渲染到页面中，可能导致浏览器执行恶意脚本。修复时应在模板输出时进行 HTML 转义，对富文本使用白名单过滤，并设置合适的 Content-Security-Policy。",
    "Broken Access Control": "越权访问表示普通用户可以访问管理员页面或其他用户资源。修复时应在服务端为敏感路由增加身份和角色校验，并对对象资源检查所有权，不能只依赖前端隐藏入口。",
    "Hardcoded Secret": "硬编码密钥表示源码中直接保存了 SECRET、Token、密码等敏感信息，一旦代码泄露就会导致凭据泄露。修复时应把密钥迁移到环境变量或密钥管理服务，并清理版本历史中的泄露凭据。",
    "Weak Password Storage": "弱密码存储表示系统可能使用 MD5、SHA1 或明文保存密码，泄露后容易被破解。修复时应使用 bcrypt、argon2 或 werkzeug.security.generate_password_hash，并为每个密码使用独立 salt。",
}


def load_env_file(env_path: str | os.PathLike[str] = ".env") -> None:
    """Load simple KEY=VALUE pairs from a local .env file without extra dependencies."""
    path = Path(env_path)
    if not path.exists():
        return

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue

        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _fallback_advice(vulnerability: dict) -> str:
    vuln_type = str(vulnerability.get("type", ""))
    return LOCAL_TEMPLATES.get(
        vuln_type,
        "该问题需要从服务端验证、输入处理和安全配置三个方面修复。建议先定位对应代码路径，补充严格校验和权限检查，并增加回归测试，确保同类问题不会再次出现。",
    )


def _provider_config() -> tuple[str, str, str] | None:
    load_env_file()

    if os.getenv("OPENAI_API_KEY"):
        return ("https://api.openai.com/v1/chat/completions", os.environ["OPENAI_API_KEY"], "gpt-4o-mini")
    if os.getenv("DEEPSEEK_API_KEY"):
        return (
            "https://api.deepseek.com/v1/chat/completions",
            os.environ["DEEPSEEK_API_KEY"],
            "deepseek-chat",
        )
    if os.getenv("QWEN_API_KEY"):
        return (
            "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
            os.environ["QWEN_API_KEY"],
            "qwen-plus",
        )
    return None


def _call_ai_api(vulnerability: dict) -> str:
    config = _provider_config()
    if config is None:
        raise RuntimeError("No AI API key configured.")

    url, api_key, model = config
    prompt = PROMPT_TEMPLATE.format(vulnerability=json.dumps(vulnerability, ensure_ascii=False, indent=2))
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You only provide defensive security remediation advice."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        data = json.loads(response.read().decode("utf-8"))

    return data["choices"][0]["message"]["content"].strip()


def generate_ai_advice(vulnerability: dict) -> str:
    try:
        advice = _call_ai_api(vulnerability)
        return advice or _fallback_advice(vulnerability)
    except (KeyError, IndexError, RuntimeError, TimeoutError, urllib.error.URLError, OSError, json.JSONDecodeError):
        return _fallback_advice(vulnerability)
