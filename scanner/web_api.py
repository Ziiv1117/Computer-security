from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import secrets
import tempfile
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import RLock, Thread
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from scanner.ai_advisor import generate_ai_advice, load_env_file
from scanner.full_scan import run_full_security_scan
from scanner.report_generator import generate_html_report, generate_markdown_report


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_ROOT = PROJECT_ROOT / "frontend"
DATA_ROOT = PROJECT_ROOT / "data"
STATE_FILE = DATA_ROOT / "scanner_state.json"
DEFAULT_BASE_URL = "http://127.0.0.1:5001"
DEFAULT_PROJECT_PATH = "./vulnerable_app"

TASKS: dict[str, dict[str, Any]] = {}
TASK_LOCK = RLock()
TASK_COUNTER = 0
SETTINGS = {
    "default_base_url": DEFAULT_BASE_URL,
    "default_project_path": DEFAULT_PROJECT_PATH,
}
ASSETS: dict[str, dict[str, Any]] = {}
REPORT_META: dict[str, dict[str, Any]] = {}
SESSIONS: dict[str, dict[str, Any]] = {}
USERS = {
    "admin": {
        "password_hash": hashlib.sha256("admin123".encode("utf-8")).hexdigest(),
        "role": "admin",
        "display_name": "Admin",
    },
    "viewer": {
        "password_hash": hashlib.sha256("viewer123".encode("utf-8")).hexdigest(),
        "role": "viewer",
        "display_name": "Viewer",
    },
}

SCAN_STEPS = [
    "连接目标",
    "SQL 注入测试",
    "XSS 测试",
    "越权访问测试",
    "静态源码扫描",
    "AI 修复建议",
    "生成报告",
]

VULNERABILITY_DESCRIPTIONS = {
    "SQL Injection": "后端可能把用户输入直接拼接进 SQL 语句，导致登录绕过或数据被读取、修改。",
    "Cross-Site Scripting": "用户输入可能未经过 HTML 转义就渲染到页面中，导致脚本在浏览器内执行。",
    "Broken Access Control": "普通用户可以访问管理员页面或其他用户资源，说明服务端权限校验不足。",
    "Hardcoded Secret": "源码中疑似包含硬编码密钥、Token 或密码，代码泄露后会暴露凭据。",
    "Weak Password Storage": "系统疑似使用弱哈希或明文方式处理密码，泄露后容易被离线破解。",
}


def _now() -> datetime:
    return datetime.now()


def _timestamp() -> str:
    return _now().strftime("%Y-%m-%d %H:%M:%S")


def _clock() -> str:
    return _now().strftime("%H:%M:%S")


def _save_state_locked() -> None:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    state = {
        "version": 1,
        "task_counter": TASK_COUNTER,
        "settings": SETTINGS,
        "tasks": TASKS,
        "assets": ASSETS,
        "report_meta": REPORT_META,
        "sessions": SESSIONS,
        "saved_at": _timestamp(),
    }
    fd, temp_name = tempfile.mkstemp(prefix="scanner_state_", suffix=".json", dir=DATA_ROOT)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            json.dump(state, temp_file, ensure_ascii=False, indent=2)
        os.replace(temp_name, STATE_FILE)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _persist_state() -> None:
    with TASK_LOCK:
        _save_state_locked()


def _load_state() -> None:
    global TASK_COUNTER
    if not STATE_FILE.exists():
        return
    try:
        with STATE_FILE.open("r", encoding="utf-8") as state_file:
            state = json.load(state_file)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"State load failed, starting with empty runtime state: {exc}")
        return

    settings = state.get("settings") if isinstance(state, dict) else {}
    tasks = state.get("tasks") if isinstance(state, dict) else {}
    assets = state.get("assets") if isinstance(state, dict) else {}
    report_meta = state.get("report_meta") if isinstance(state, dict) else {}
    sessions = state.get("sessions") if isinstance(state, dict) else {}
    if isinstance(settings, dict):
        SETTINGS.update(
            {
                "default_base_url": str(settings.get("default_base_url") or DEFAULT_BASE_URL),
                "default_project_path": str(settings.get("default_project_path") or DEFAULT_PROJECT_PATH),
            }
        )
    if isinstance(tasks, dict):
        TASKS.clear()
        for task_id, task in tasks.items():
            if not isinstance(task, dict):
                continue
            if task.get("status") == "running":
                task["status"] = "failed"
                task["progress"] = 100
                task["current_step"] = "服务重启后任务已中断"
                task.setdefault("errors", []).append("Scanner service restarted before this task completed.")
                task.setdefault("events", []).append(_event("WARN", "服务重启，运行中的扫描任务已标记为中断"))
                task["completed_at"] = task.get("completed_at") or _timestamp()
                for step in task.get("steps", []):
                    if step.get("status") == "running":
                        step["status"] = "failed"
                        step["duration"] = "已中断"
            TASKS[str(task_id)] = task
    if isinstance(assets, dict):
        ASSETS.clear()
        ASSETS.update({str(asset_id): asset for asset_id, asset in assets.items() if isinstance(asset, dict)})
    if isinstance(report_meta, dict):
        REPORT_META.clear()
        REPORT_META.update({str(task_id): meta for task_id, meta in report_meta.items() if isinstance(meta, dict)})
    if isinstance(sessions, dict):
        SESSIONS.clear()
        SESSIONS.update({str(token): session for token, session in sessions.items() if isinstance(session, dict)})
    TASK_COUNTER = max(int(state.get("task_counter") or 0), len(TASKS))
    _persist_state()


def _next_task_id() -> str:
    global TASK_COUNTER
    with TASK_LOCK:
        TASK_COUNTER += 1
        _save_state_locked()
        return f"SCAN-{_now():%Y%m%d-%H%M%S}-{TASK_COUNTER:04d}"


def _initial_steps() -> list[dict[str, str]]:
    return [{"name": name, "status": "pending", "duration": "等待中"} for name in SCAN_STEPS]


def _event(level: str, message: str) -> dict[str, str]:
    return {"time": _clock(), "level": level, "message": message}


def _slug_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _password_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _create_session(username: str) -> dict[str, str]:
    user = USERS[username]
    token = secrets.token_urlsafe(24)
    session = {
        "token": token,
        "username": username,
        "role": user["role"],
        "display_name": user["display_name"],
        "created_at": _timestamp(),
    }
    with TASK_LOCK:
        SESSIONS[token] = session
        _save_state_locked()
    return session


def _upsert_asset(address: str, asset_type: str, *, name: str = "", task: dict[str, Any] | None = None) -> dict[str, Any]:
    asset_id = _slug_id("ASSET", f"{asset_type}:{address}")
    existing = ASSETS.get(asset_id, {})
    result = (task or {}).get("result") or {}
    risk = result.get("risk", {})
    asset = {
        "id": asset_id,
        "name": name or existing.get("name") or ("扫描目标" if asset_type == "Web 应用" else "源码目录"),
        "address": address,
        "type": asset_type,
        "risk": risk.get("overall_risk", existing.get("risk", "Low")),
        "last_scan_at": (task or {}).get("completed_at") or existing.get("last_scan_at"),
        "task_id": (task or {}).get("task_id") or existing.get("task_id"),
        "created_at": existing.get("created_at") or _timestamp(),
        "updated_at": _timestamp(),
    }
    ASSETS[asset_id] = asset
    return asset


def _sync_assets_for_task(task: dict[str, Any]) -> None:
    target = task.get("target") or {}
    base_url = target.get("base_url")
    project_path = target.get("project_path")
    if base_url:
        _upsert_asset(str(base_url), "Web 应用", task=task)
    if project_path:
        _upsert_asset(str(project_path), "Codebase", task=task)


def _set_task_state(
    task_id: str,
    *,
    status: str | None = None,
    progress: int | None = None,
    current_step: str | None = None,
    events: list[dict[str, str]] | None = None,
    step_index: int | None = None,
) -> None:
    with TASK_LOCK:
        task = TASKS[task_id]
        if status is not None:
            task["status"] = status
        if progress is not None:
            task["progress"] = progress
        if current_step is not None:
            task["current_step"] = current_step
        if events:
            task["events"].extend(events)
            task["events"] = task["events"][-50:]
        if step_index is not None:
            for index, step in enumerate(task["steps"]):
                if index < step_index:
                    step["status"] = "done"
                    if step["duration"] in {"等待中", "进行中"}:
                        step["duration"] = "已完成"
                elif index == step_index:
                    step["status"] = "running"
                    step["duration"] = "进行中"
                else:
                    step["status"] = "pending"
        _save_state_locked()


def _complete_steps(task_id: str) -> None:
    with TASK_LOCK:
        task = TASKS[task_id]
        for step in task["steps"]:
            step["status"] = "done"
            if step["duration"] in {"等待中", "进行中"}:
                step["duration"] = "已完成"
        _save_state_locked()


def _public_task(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task["task_id"],
        "status": task["status"],
        "progress": task["progress"],
        "current_step": task["current_step"],
        "steps": task["steps"],
        "events": task["events"],
        "target": task["target"],
        "created_at": task["created_at"],
        "completed_at": task.get("completed_at"),
        "errors": task.get("errors", []),
    }


def _task_reports() -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    for task in TASKS.values():
        result = task.get("result")
        if not result:
            continue
        meta = REPORT_META.get(task["task_id"], {})
        if meta.get("deleted"):
            continue
        reports.append(
            {
                "task_id": task["task_id"],
                "name": meta.get("name") or f"{task['task_id']} 安全扫描报告",
                "target": task["target"],
                "risk": result.get("risk", {}),
                "vulnerability_total": len(result.get("vulnerabilities", [])),
                "generated_at": task.get("completed_at") or task.get("created_at"),
                "updated_at": meta.get("updated_at"),
                "markdown_url": f"/api/report/{task['task_id']}/markdown",
                "html_url": f"/api/report/{task['task_id']}/html",
            }
        )
    return sorted(reports, key=lambda item: item.get("generated_at") or "", reverse=True)


def _task_assets() -> list[dict[str, Any]]:
    assets: dict[str, dict[str, Any]] = {asset_id: dict(asset) for asset_id, asset in ASSETS.items()}
    for task in TASKS.values():
        result = task.get("result") or {}
        risk = result.get("risk", {})
        base_url = task["target"].get("base_url", "")
        project_path = task["target"].get("project_path", "")
        if base_url:
            asset_id = _slug_id("ASSET", f"Web 应用:{base_url}")
            existing = assets.get(asset_id, {})
            assets[asset_id] = {
                "id": asset_id,
                "name": existing.get("name", "扫描目标"),
                "address": base_url,
                "type": "Web 应用",
                "risk": risk.get("overall_risk", "Low"),
                "last_scan_at": task.get("completed_at") or task.get("created_at"),
                "task_id": task["task_id"],
            }
        if project_path:
            asset_id = _slug_id("ASSET", f"Codebase:{project_path}")
            existing = assets.get(asset_id, {})
            assets[asset_id] = {
                "id": asset_id,
                "name": existing.get("name", "源码目录"),
                "address": project_path,
                "type": "Codebase",
                "risk": risk.get("overall_risk", "Low"),
                "last_scan_at": task.get("completed_at") or task.get("created_at"),
                "task_id": task["task_id"],
            }
    return sorted(assets.values(), key=lambda item: item.get("last_scan_at") or "", reverse=True)


def _component_from_location(location: str) -> str:
    if not location:
        return "unknown"
    first = location.split(":", 1)[0].strip("/")
    if "/" in first:
        return first.split("/", 1)[0] or "web-app"
    if "." in first:
        return first.rsplit(".", 1)[0] or "source-code"
    return first or "web-app"


def _normalize_vulnerability(raw: dict[str, Any], index: int, discovered_at: str, status: str) -> dict[str, Any]:
    vuln_type = str(raw.get("type") or "Unknown Vulnerability")
    evidence = str(raw.get("evidence") or "")
    location = str(raw.get("location") or "")
    ai_advice = str(raw.get("ai_advice") or raw.get("suggestion") or "")
    return {
        "id": str(raw.get("id") or f"VULN-{index:03d}"),
        "type": vuln_type,
        "category": str(raw.get("category") or "General"),
        "risk": str(raw.get("risk") or "Low"),
        "score": int(raw.get("score") or 0),
        "location": location,
        "method": str(raw.get("method") or "UNKNOWN"),
        "evidence": evidence,
        "evidence_count": int(raw.get("evidence_count") or (1 if evidence else 0)),
        "fingerprint": str(raw.get("fingerprint") or ""),
        "confidence": str(raw.get("confidence") or "Medium"),
        "suggestion": str(raw.get("suggestion") or ""),
        "ai_advice": ai_advice,
        "description": VULNERABILITY_DESCRIPTIONS.get(vuln_type, evidence or "扫描器发现了一个需要人工复核的安全风险。"),
        "component": _component_from_location(location),
        "status": status,
        "discovered_at": discovered_at,
    }


def _normalize_scan_result(task: dict[str, Any], scan_result: dict[str, Any]) -> dict[str, Any]:
    discovered_at = task["created_at"]
    statuses = task.setdefault("vulnerability_status", {})
    vulnerabilities = []
    for index, raw in enumerate(scan_result.get("vulnerabilities", []), start=1):
        vuln_id = str(raw.get("id") or f"VULN-{index:03d}")
        statuses.setdefault(vuln_id, "未修复")
        vulnerabilities.append(_normalize_vulnerability(raw, index, discovered_at, statuses[vuln_id]))

    normalized = {
        "task_id": task["task_id"],
        "target": scan_result.get("target", task["target"]),
        "risk": scan_result.get("risk", {}),
        "vulnerabilities": vulnerabilities,
        "discovery": scan_result.get("discovery", {"routes": [], "forms": [], "parameters": []}),
        "reports": {
            "markdown": "",
            "html": "",
            "markdown_url": f"/api/report/{task['task_id']}/markdown",
            "html_url": f"/api/report/{task['task_id']}/html",
        },
        "errors": scan_result.get("errors", []),
    }

    normalized["reports"]["markdown"] = generate_markdown_report(normalized)
    normalized["reports"]["html"] = generate_html_report(normalized)
    return normalized


def _run_task(task_id: str) -> None:
    try:
        with TASK_LOCK:
            task = TASKS[task_id]
            target = task["target"]

        _set_task_state(
            task_id,
            progress=10,
            current_step="连接目标",
            step_index=0,
            events=[_event("INFO", f"开始连接目标 {target['base_url']}")],
        )

        def report_progress(step_name: str, progress: int, step_index: int) -> None:
            _set_task_state(
                task_id,
                progress=progress,
                current_step=step_name,
                step_index=step_index,
                events=[_event("INFO", step_name)],
            )

        _set_task_state(task_id, progress=18, current_step="准备扫描模块", step_index=0)
        scan_result = run_full_security_scan(
            base_url=target["base_url"],
            project_path=target["project_path"],
            progress_callback=report_progress,
        )

        with TASK_LOCK:
            task = TASKS[task_id]
            if task.get("cancel_requested"):
                task["status"] = "cancelled"
                task["progress"] = 100
                task["current_step"] = "任务已取消"
                task["completed_at"] = _timestamp()
                task.setdefault("events", []).append(_event("WARN", "扫描任务已被用户取消，结果未写入报告中心"))
                _save_state_locked()
                return
            normalized = _normalize_scan_result(task, scan_result)
            task["result"] = normalized
            task["errors"] = normalized.get("errors", [])
            task["completed_at"] = _timestamp()
            _sync_assets_for_task(task)
            REPORT_META.setdefault(
                task_id,
                {
                    "name": f"{task_id} 安全扫描报告",
                    "created_at": task["completed_at"],
                    "updated_at": task["completed_at"],
                    "deleted": False,
                },
            )
            _save_state_locked()

        _complete_steps(task_id)
        total = len(normalized.get("vulnerabilities", []))
        level = "RISK" if total else "INFO"
        _set_task_state(
            task_id,
            status="completed",
            progress=100,
            current_step="扫描完成",
            events=[
                _event(level, f"扫描完成，发现 {total} 个漏洞"),
                _event("INFO", "Markdown / HTML 报告已生成"),
            ],
        )
    except Exception as exc:
        with TASK_LOCK:
            cancelled = TASKS.get(task_id, {}).get("cancel_requested")
        if cancelled:
            _set_task_state(
                task_id,
                status="cancelled",
                progress=100,
                current_step="任务已取消",
                events=[_event("WARN", "扫描任务已取消")],
            )
            return
        _set_task_state(
            task_id,
            status="failed",
            progress=100,
            current_step="扫描失败",
            events=[_event("ERROR", f"扫描失败：{exc}")],
        )
        with TASK_LOCK:
            task = TASKS[task_id]
            task["errors"] = [str(exc)]
            task["completed_at"] = _timestamp()
            _save_state_locked()


def start_scan(payload: dict[str, Any]) -> dict[str, Any]:
    load_env_file()
    task_id = _next_task_id()
    base_url = str(payload.get("base_url") or SETTINGS["default_base_url"])
    project_path = str(payload.get("project_path") or SETTINGS["default_project_path"])
    task = {
        "task_id": task_id,
        "status": "running",
        "progress": 3,
        "current_step": "排队启动",
        "steps": _initial_steps(),
        "events": [_event("INFO", "扫描任务已创建")],
        "target": {
            "base_url": base_url,
            "project_path": project_path,
        },
        "created_at": _timestamp(),
        "completed_at": None,
        "result": None,
        "errors": [],
        "vulnerability_status": {},
        "cancel_requested": False,
        "advice_versions": {},
    }
    with TASK_LOCK:
        TASKS[task_id] = task
        _save_state_locked()

    worker = Thread(target=_run_task, args=(task_id,), daemon=True)
    worker.start()
    return {
        "task_id": task_id,
        "status": "running",
        "message": "Scan task started.",
    }


def _find_vulnerability(task: dict[str, Any], vuln_id: str) -> dict[str, Any] | None:
    result = task.get("result") or {}
    for vulnerability in result.get("vulnerabilities", []):
        if vulnerability.get("id") == vuln_id:
            return vulnerability
    return None


class ScannerApiHandler(BaseHTTPRequestHandler):
    server_version = "ScannerApi/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{_timestamp()}] {self.address_string()} {format % args}")

    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path.startswith("/api/"):
            self._handle_api_get(path)
            return
        self._serve_static(path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/auth/login":
            self._handle_login()
            return
        if parsed.path == "/api/scan/start":
            if not self._require_role("admin"):
                return
            payload = self._read_json()
            self._send_json(start_scan(payload), HTTPStatus.ACCEPTED)
            return
        if parsed.path.startswith("/api/tasks/") and parsed.path.endswith("/rerun"):
            if not self._require_role("admin"):
                return
            self._handle_task_rerun(parsed.path)
            return
        if parsed.path.startswith("/api/tasks/") and parsed.path.endswith("/cancel"):
            if not self._require_role("admin"):
                return
            self._handle_task_cancel(parsed.path)
            return
        if parsed.path == "/api/assets":
            if not self._require_role("admin"):
                return
            self._handle_asset_create()
            return
        if parsed.path.startswith("/api/assets/") and parsed.path.endswith("/scan"):
            if not self._require_role("admin"):
                return
            self._handle_asset_scan(parsed.path)
            return
        if parsed.path.startswith("/api/vulnerability/") and parsed.path.endswith("/ai-advice"):
            if not self._require_role("admin"):
                return
            self._handle_ai_advice(parsed.path)
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_PATCH(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/settings":
            if not self._require_role("admin"):
                return
            self._handle_settings_update()
            return
        if parsed.path.startswith("/api/assets/"):
            if not self._require_role("admin"):
                return
            self._handle_asset_update(parsed.path)
            return
        if parsed.path.startswith("/api/report/"):
            if not self._require_role("admin"):
                return
            self._handle_report_update(parsed.path)
            return
        if parsed.path.startswith("/api/vulnerability/") and parsed.path.endswith("/status"):
            if not self._require_role("admin"):
                return
            self._handle_vulnerability_status(parsed.path)
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/api/assets/"):
            if not self._require_role("admin"):
                return
            self._handle_asset_delete(parsed.path)
            return
        if parsed.path.startswith("/api/report/"):
            if not self._require_role("admin"):
                return
            self._handle_report_delete(parsed.path)
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def _current_session(self) -> dict[str, Any] | None:
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            return None
        token = authorization.removeprefix("Bearer ").strip()
        return SESSIONS.get(token)

    def _require_role(self, role: str) -> bool:
        session = self._current_session()
        if not session:
            self._send_json({"error": "Authentication required"}, HTTPStatus.UNAUTHORIZED)
            return False
        if role == "admin" and session.get("role") != "admin":
            self._send_json({"error": "Admin role required"}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def _send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, text: str, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_login(self) -> None:
        payload = self._read_json()
        username = str(payload.get("username") or "")
        password = str(payload.get("password") or "")
        user = USERS.get(username)
        if not user or user.get("password_hash") != _password_hash(password):
            self._send_json({"error": "Invalid username or password"}, HTTPStatus.UNAUTHORIZED)
            return
        session = _create_session(username)
        self._send_json({"token": session["token"], "user": session})

    def _handle_api_get(self, path: str) -> None:
        if path == "/api/health":
            self._send_json({"status": "ok", "storage": str(STATE_FILE)})
            return
        if path == "/api/auth/me":
            session = self._current_session()
            if not session:
                self._send_json({"authenticated": False})
                return
            self._send_json({"authenticated": True, "user": session})
            return
        if path == "/api/settings":
            self._send_json(
                {
                    "api_base_url": "/api",
                    "default_base_url": SETTINGS["default_base_url"],
                    "default_project_path": SETTINGS["default_project_path"],
                    "storage": str(STATE_FILE),
                    "ai_key_configured": any(
                        os.getenv(name) for name in ("OPENAI_API_KEY", "DEEPSEEK_API_KEY", "QWEN_API_KEY")
                    ),
                }
            )
            return
        if path == "/api/tasks":
            with TASK_LOCK:
                tasks = [_public_task(task) for task in TASKS.values()]
            self._send_json({"tasks": tasks})
            return
        if path == "/api/reports":
            with TASK_LOCK:
                reports = _task_reports()
            query = parse_qs(urlparse(self.path).query)
            risk_filter = (query.get("risk") or [""])[0]
            if risk_filter:
                reports = [report for report in reports if report.get("risk", {}).get("overall_risk") == risk_filter]
            self._send_json({"reports": reports})
            return
        if path == "/api/assets":
            with TASK_LOCK:
                assets = _task_assets()
            self._send_json({"assets": assets})
            return
        if path.startswith("/api/scan/status/"):
            task_id = path.rsplit("/", 1)[-1]
            with TASK_LOCK:
                task = TASKS.get(task_id)
                data = _public_task(task) if task else None
            if data is None:
                self._send_json({"error": "Task not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(data)
            return
        if path.startswith("/api/scan/result/"):
            task_id = path.rsplit("/", 1)[-1]
            with TASK_LOCK:
                task = TASKS.get(task_id)
                result = task.get("result") if task else None
                status = task.get("status") if task else None
            if task is None:
                self._send_json({"error": "Task not found"}, HTTPStatus.NOT_FOUND)
                return
            if result is None:
                self._send_json({"task_id": task_id, "status": status, "message": "Scan is still running."}, HTTPStatus.ACCEPTED)
                return
            self._send_json(result)
            return
        if path.startswith("/api/report/"):
            self._handle_report(path)
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def _handle_report(self, path: str) -> None:
        parts = path.strip("/").split("/")
        if len(parts) != 4:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        _, _, task_id, report_type = parts
        with TASK_LOCK:
            task = TASKS.get(task_id)
            result = task.get("result") if task else None
            deleted = REPORT_META.get(task_id, {}).get("deleted")
        if task is None or result is None or deleted:
            self._send_json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)
            return
        if report_type == "html":
            self._send_text(result["reports"].get("html", ""), "text/html")
            return
        if report_type == "markdown":
            self._send_text(result["reports"].get("markdown", ""), "text/markdown")
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def _handle_settings_update(self) -> None:
        payload = self._read_json()
        base_url = str(payload.get("default_base_url") or "").strip()
        project_path = str(payload.get("default_project_path") or "").strip()
        if not base_url or not project_path:
            self._send_json({"error": "default_base_url and default_project_path are required"}, HTTPStatus.BAD_REQUEST)
            return
        SETTINGS["default_base_url"] = base_url
        SETTINGS["default_project_path"] = project_path
        _persist_state()
        self._send_json(
            {
                "api_base_url": "/api",
                "default_base_url": SETTINGS["default_base_url"],
                "default_project_path": SETTINGS["default_project_path"],
                "storage": str(STATE_FILE),
            }
        )

    def _handle_task_rerun(self, path: str) -> None:
        task_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            task = TASKS.get(task_id)
            target = dict(task.get("target") or {}) if task else None
        if not target:
            self._send_json({"error": "Task not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json(start_scan(target), HTTPStatus.ACCEPTED)

    def _handle_task_cancel(self, path: str) -> None:
        task_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            task = TASKS.get(task_id)
            if task and task.get("status") == "running":
                task["cancel_requested"] = True
                task["status"] = "cancelling"
                task["current_step"] = "正在取消"
                task.setdefault("events", []).append(_event("WARN", "用户请求取消扫描任务"))
                _save_state_locked()
        if not task:
            self._send_json({"error": "Task not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json(_public_task(task))

    def _handle_asset_create(self) -> None:
        payload = self._read_json()
        name = str(payload.get("name") or "").strip()
        address = str(payload.get("address") or "").strip()
        asset_type = str(payload.get("type") or "Web 应用").strip()
        if not address:
            self._send_json({"error": "address is required"}, HTTPStatus.BAD_REQUEST)
            return
        with TASK_LOCK:
            asset = _upsert_asset(address, asset_type, name=name)
            _save_state_locked()
        self._send_json({"asset": asset}, HTTPStatus.CREATED)

    def _handle_asset_update(self, path: str) -> None:
        asset_id = path.strip("/").split("/")[2]
        payload = self._read_json()
        with TASK_LOCK:
            asset = ASSETS.get(asset_id)
            if asset:
                for key in ("name", "address", "type", "risk"):
                    if key in payload and str(payload[key]).strip():
                        asset[key] = str(payload[key]).strip()
                asset["updated_at"] = _timestamp()
                _save_state_locked()
        if not asset:
            self._send_json({"error": "Asset not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"asset": asset})

    def _handle_asset_delete(self, path: str) -> None:
        asset_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            asset = ASSETS.pop(asset_id, None)
            if asset:
                _save_state_locked()
        if not asset:
            self._send_json({"error": "Asset not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"id": asset_id, "deleted": True})

    def _handle_asset_scan(self, path: str) -> None:
        asset_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            asset = ASSETS.get(asset_id)
        if not asset:
            self._send_json({"error": "Asset not found"}, HTTPStatus.NOT_FOUND)
            return
        payload = {
            "base_url": asset["address"] if asset.get("type") == "Web 应用" else SETTINGS["default_base_url"],
            "project_path": asset["address"] if asset.get("type") == "Codebase" else SETTINGS["default_project_path"],
        }
        self._send_json(start_scan(payload), HTTPStatus.ACCEPTED)

    def _handle_report_update(self, path: str) -> None:
        parts = path.strip("/").split("/")
        if len(parts) < 3:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        task_id = parts[2]
        payload = self._read_json()
        with TASK_LOCK:
            task = TASKS.get(task_id)
            if task:
                meta = REPORT_META.setdefault(task_id, {})
                if str(payload.get("name") or "").strip():
                    meta["name"] = str(payload["name"]).strip()
                meta["deleted"] = False
                meta["updated_at"] = _timestamp()
                _save_state_locked()
        if not task:
            self._send_json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"report": next((item for item in _task_reports() if item["task_id"] == task_id), None)})

    def _handle_report_delete(self, path: str) -> None:
        parts = path.strip("/").split("/")
        if len(parts) < 3:
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        task_id = parts[2]
        with TASK_LOCK:
            task = TASKS.get(task_id)
            if task:
                meta = REPORT_META.setdefault(task_id, {})
                meta["deleted"] = True
                meta["updated_at"] = _timestamp()
                _save_state_locked()
        if not task:
            self._send_json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"task_id": task_id, "deleted": True})

    def _handle_ai_advice(self, path: str) -> None:
        payload = self._read_json()
        task_id = str(payload.get("task_id") or "")
        vuln_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            task = TASKS.get(task_id)
            vulnerability = _find_vulnerability(task, vuln_id) if task else None
        if task is None or vulnerability is None:
            self._send_json({"error": "Vulnerability not found"}, HTTPStatus.NOT_FOUND)
            return
        manual_advice = str(payload.get("manual_advice") or "").strip()
        advice = manual_advice or generate_ai_advice(vulnerability)
        with TASK_LOCK:
            vulnerability["ai_advice"] = advice
            versions = task.setdefault("advice_versions", {}).setdefault(vuln_id, [])
            versions.append({"advice": advice, "created_at": _timestamp(), "source": "manual" if manual_advice else "ai"})
            _save_state_locked()
        self._send_json({"id": vuln_id, "ai_advice": advice})

    def _handle_vulnerability_status(self, path: str) -> None:
        payload = self._read_json()
        task_id = str(payload.get("task_id") or "")
        status = str(payload.get("status") or "未修复")
        vuln_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            task = TASKS.get(task_id)
            vulnerability = _find_vulnerability(task, vuln_id) if task else None
            if task and vulnerability:
                task.setdefault("vulnerability_status", {})[vuln_id] = status
                vulnerability["status"] = status
                _save_state_locked()
        if task is None or vulnerability is None:
            self._send_json({"error": "Vulnerability not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"id": vuln_id, "status": status})

    def _serve_static(self, request_path: str) -> None:
        relative = unquote(request_path.lstrip("/")) or "welcome.html"
        if relative == "frontend":
            relative = "welcome.html"
        path = (FRONTEND_ROOT / relative).resolve()
        try:
            path.relative_to(FRONTEND_ROOT.resolve())
        except ValueError:
            self._send_json({"error": "Forbidden"}, HTTPStatus.FORBIDDEN)
            return
        if path.is_dir():
            path = path / "index.html"
        if not path.exists():
            self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
            return
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    load_env_file()
    _load_state()
    server = ThreadingHTTPServer((host, port), ScannerApiHandler)
    print(f"Scanner console running at http://{host}:{port}/")
    print(f"API health check: http://{host}:{port}/api/health")
    print(f"State file: {STATE_FILE}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopping scanner console.")
    finally:
        server.server_close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the scanner API and frontend console.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind.")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_server(args.host, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
