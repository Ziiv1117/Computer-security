from __future__ import annotations

import ast
import os
import re
from pathlib import Path


SCAN_EXTENSIONS = {".py", ".js", ".html", ".env", ".txt", ".json"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "env",
    "dist",
    "build",
}

SECRET_PATTERNS = (
    re.compile(r"\bSECRET_KEY\b\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
    re.compile(r"\bAPI_KEY\b\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
    re.compile(r"\bACCESS_TOKEN\b\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
    re.compile(r"\bDB_PASSWORD\b\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
    re.compile(r"\bPRIVATE_KEY\b", re.IGNORECASE),
    re.compile(r"\bCLIENT_SECRET\b\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\btoken\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
    re.compile(r"\bpassword\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
)

WEAK_PASSWORD_PATTERNS = (
    re.compile(r"\bmd5\b", re.IGNORECASE),
    re.compile(r"\bsha1\b", re.IGNORECASE),
    re.compile(r"hashlib\.md5", re.IGNORECASE),
    re.compile(r"hashlib\.sha1", re.IGNORECASE),
    re.compile(r"\bplain_password\b", re.IGNORECASE),
    re.compile(r"save\s*\(\s*password\s*\)", re.IGNORECASE),
    re.compile(r"INSERT\s+INTO\s+users", re.IGNORECASE),
)

PYTHON_AST_EXTENSIONS = {".py"}


def _iter_source_lines(project_path: str):
    root = Path(project_path).resolve()
    if not root.exists():
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() not in SCAN_EXTENSIONS:
                continue
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as file:
                    for line_number, line in enumerate(file, start=1):
                        yield root, path, line_number, line.rstrip("\n")
            except OSError:
                continue


def _location(root: Path, path: Path, line_number: int) -> str:
    try:
        display_path = path.relative_to(root)
    except ValueError:
        display_path = path
    return f"{display_path.as_posix()}:{line_number}"


def _redact(value: str) -> str:
    if len(value) <= 16:
        return value
    return value[:8] + "...[redacted]"


def test_hardcoded_secret(project_path: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    seen_locations: set[str] = set()

    for root, path, line_number, line in _iter_source_lines(project_path) or []:
        if not any(pattern.search(line) for pattern in SECRET_PATTERNS):
            continue

        location = _location(root, path, line_number)
        if location in seen_locations:
            continue
        seen_locations.add(location)
        vulnerabilities.append(
            {
                "type": "Hardcoded Secret",
                "category": "Code and Data Security",
                "risk": "High",
                "score": 80,
                "location": location,
                "method": "SAST",
                "request_method": "SOURCE",
                "payload": "secret pattern",
                "scanner_rule": "sast.hardcoded_secret",
                "remediation_priority": "P1",
                "evidence": f"Potential hardcoded secret detected: {_redact(line.strip())}",
                "suggestion": "Move secrets to environment variables and do not commit them to source code.",
            }
        )

    return vulnerabilities


def test_weak_password_storage(project_path: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    seen_locations: set[str] = set()

    for root, path, line_number, line in _iter_source_lines(project_path) or []:
        if not any(pattern.search(line) for pattern in WEAK_PASSWORD_PATTERNS):
            continue

        location = _location(root, path, line_number)
        if location in seen_locations:
            continue
        seen_locations.add(location)
        vulnerabilities.append(
            {
                "type": "Weak Password Storage",
                "category": "Code and Data Security",
                "risk": "High",
                "score": 80,
                "location": location,
                "method": "SAST",
                "request_method": "SOURCE",
                "payload": "weak password storage pattern",
                "scanner_rule": "sast.weak_password_storage",
                "remediation_priority": "P1",
                "evidence": "Weak password storage pattern detected.",
                "suggestion": "Use bcrypt, argon2, or werkzeug.security.generate_password_hash.",
            }
        )

    return vulnerabilities


def _iter_python_files(project_path: str):
    root = Path(project_path).resolve()
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [dirname for dirname in dirnames if dirname not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() in PYTHON_AST_EXTENSIONS:
                yield root, path


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_call_name(node.value)}.{node.attr}"
    return ""


def _string_value(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "f-string"
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return f"{_string_value(node.left)} + {_string_value(node.right)}"
    return ""


def test_python_ast_security(project_path: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    for root, path in _iter_python_files(project_path) or []:
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (OSError, SyntaxError):
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = _call_name(node.func)
                if call_name.endswith(".execute") or call_name == "execute":
                    query = _string_value(node.args[0]) if node.args else ""
                    if "select" in query.lower() or "insert" in query.lower() or "update" in query.lower() or "f-string" in query:
                        if " + " in query or "f-string" in query:
                            vulnerabilities.append(
                                {
                                    "type": "SQL Injection",
                                    "category": "Code and Data Security",
                                    "risk": "High",
                                    "score": 78,
                                    "location": _location(root, path, getattr(node, "lineno", 1)),
                                    "method": "SAST",
                                    "request_method": "SOURCE",
                                    "payload": "dynamic SQL execute",
                                    "scanner_rule": "sast.ast.dynamic_sql_execute",
                                    "remediation_priority": "P1",
                                    "evidence": "AST detected dynamic SQL passed to execute().",
                                    "suggestion": "Use parameterized SQL placeholders or ORM-bound parameters.",
                                }
                            )
                if call_name.endswith("render_template_string"):
                    vulnerabilities.append(
                        {
                            "type": "Cross-Site Scripting",
                            "category": "Code and Data Security",
                            "risk": "High",
                            "score": 76,
                            "location": _location(root, path, getattr(node, "lineno", 1)),
                            "method": "SAST",
                            "request_method": "SOURCE",
                            "payload": "render_template_string",
                            "scanner_rule": "sast.ast.render_template_string",
                            "remediation_priority": "P1",
                            "evidence": "AST detected render_template_string(), which is risky with user-controlled input.",
                            "suggestion": "Render trusted templates with autoescaping and avoid string-built templates.",
                        }
                    )
                if call_name.endswith("Markup") or call_name == "Markup":
                    vulnerabilities.append(
                        {
                            "type": "Cross-Site Scripting",
                            "category": "Code and Data Security",
                            "risk": "Medium",
                            "score": 58,
                            "location": _location(root, path, getattr(node, "lineno", 1)),
                            "method": "SAST",
                            "request_method": "SOURCE",
                            "payload": "Markup",
                            "scanner_rule": "sast.ast.markup_unescaped_output",
                            "remediation_priority": "P2",
                            "evidence": "AST detected Markup(), which may bypass escaping.",
                            "suggestion": "Avoid marking user-controlled content safe unless it has been sanitized.",
                        }
                    )

            if isinstance(node, ast.FunctionDef):
                route_paths = []
                decorator_names = []
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call):
                        decorator_names.append(_call_name(decorator.func))
                        if decorator.args:
                            route_value = _string_value(decorator.args[0])
                            if route_value:
                                route_paths.append(route_value)
                    else:
                        decorator_names.append(_call_name(decorator))
                sensitive_route = any(any(keyword in route.lower() for keyword in ("admin", "debug", "config")) for route in route_paths)
                has_auth_decorator = any(keyword in name.lower() for name in decorator_names for keyword in ("login", "auth", "role", "permission"))
                if sensitive_route and not has_auth_decorator:
                    vulnerabilities.append(
                        {
                            "type": "Broken Access Control",
                            "category": "Authentication and Authorization",
                            "risk": "High",
                            "score": 74,
                            "location": _location(root, path, getattr(node, "lineno", 1)),
                            "method": "SAST",
                            "request_method": "SOURCE",
                            "payload": ", ".join(route_paths),
                            "scanner_rule": "sast.ast.sensitive_route_without_auth",
                            "remediation_priority": "P1",
                            "evidence": "AST detected sensitive Flask route without obvious auth/role decorator.",
                            "suggestion": "Require login and role checks on sensitive routes server-side.",
                        }
                    )
    return vulnerabilities


def run_static_scan(project_path: str, progress_callback=None) -> list[dict]:
    results: list[dict] = []
    for scanner in (test_hardcoded_secret, test_weak_password_storage, test_python_ast_security):
        try:
            if progress_callback:
                progress_callback("INFO", f"开始静态规则：{scanner.__name__}")
            found = scanner(project_path)
            results.extend(found)
            if progress_callback:
                level = "RISK" if found else "INFO"
                progress_callback(level, f"静态规则 {scanner.__name__} 完成，发现 {len(found)} 个问题")
        except Exception:
            if progress_callback:
                progress_callback("WARN", f"静态规则 {scanner.__name__} 执行失败，已跳过")
            continue
    return results

