from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import mimetypes
import os
import sqlite3
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import RLock, Thread
from typing import Any
from urllib.parse import unquote, urlparse

import requests

from scanner.ai_advisor import generate_ai_advice_result, load_env_file, test_ai_connection
from scanner.full_scan import run_full_security_scan
from scanner.report_generator import generate_html_report, generate_markdown_report


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_ROOT = PROJECT_ROOT / "frontend"
DATA_ROOT = PROJECT_ROOT / "data"
DB_PATH = DATA_ROOT / "scanner_platform.db"
DEFAULT_BASE_URL = "http://127.0.0.1:5001"
DEFAULT_PROJECT_PATH = "./vulnerable_app"

TASKS: dict[str, dict[str, Any]] = {}
TASK_LOCK = RLock()
TASK_COUNTER = 0
SETTINGS = {
    "default_base_url": DEFAULT_BASE_URL,
    "default_project_path": DEFAULT_PROJECT_PATH,
    "runtime_ai_provider": "",
    "runtime_ai_model": "qwen3.6-flash",
    "last_ai_test": "",
}
ASSETS: dict[str, dict[str, Any]] = {}

SCAN_STEPS = [
    "连接目标",
    "SQL 注入测试",
    "XSS 测试",
    "越权访问测试",
    "静态源码扫描",
    "生成 AI 建议",
    "生成报告",
]

VULNERABILITY_DESCRIPTIONS = {
    "SQL Injection": "后端可能把用户输入直接拼接进 SQL 语句，导致登录绕过或数据被读取、修改。",
    "Cross-Site Scripting": "用户输入可能未经过 HTML 转义就渲染到页面中，导致脚本在浏览器内执行。",
    "Broken Access Control": "普通用户可以访问管理员页面或其他用户资源，说明服务端权限校验不足。",
    "Hardcoded Secret": "源码中疑似包含硬编码密钥、Token 或密码，代码泄露后会暴露凭据。",
    "Weak Password Storage": "系统疑似使用弱哈希或明文方式处理密码，泄露后容易被离线破解。",
    "Cross-Site Request Forgery": "关键操作缺少 CSRF 防护，已登录用户可能被诱导提交非预期请求。",
    "Path Traversal": "文件读取接口未限制最终路径，可能读取允许目录之外的文件。",
    "Server-Side Request Forgery": "服务端会访问用户传入的 URL，可能被滥用访问本机或内网资源。",
    "Open Redirect": "跳转接口信任用户输入的外部地址，可能被用于钓鱼跳转。",
    "Mass Assignment": "后端批量接收用户提交字段，普通用户可能修改权限字段。",
    "Information Disclosure": "调试接口暴露配置、密钥或用户数据，可能导致敏感信息泄露。",
}


def _now() -> datetime:
    return datetime.now()


def _timestamp() -> str:
    return _now().strftime("%Y-%m-%d %H:%M:%S")


def _clock() -> str:
    return _now().strftime("%H:%M:%S")


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _db() -> sqlite3.Connection:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def _init_db() -> None:
    with _db() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scan_tasks (
                task_id TEXT PRIMARY KEY,
                base_url TEXT NOT NULL,
                project_path TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL,
                current_step TEXT NOT NULL,
                steps_json TEXT NOT NULL,
                events_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                errors_json TEXT NOT NULL,
                result_json TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                task_id TEXT NOT NULL,
                vuln_id TEXT NOT NULL,
                type TEXT,
                risk TEXT,
                score INTEGER,
                location TEXT,
                method TEXT,
                request_method TEXT,
                payload TEXT,
                scanner_rule TEXT,
                evidence TEXT,
                suggestion TEXT,
                ai_advice TEXT,
                ai_advice_source TEXT,
                status TEXT,
                remediation_priority TEXT,
                confidence TEXT,
                fingerprint TEXT,
                review_note TEXT,
                reviewer TEXT,
                updated_at TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (task_id, vuln_id)
            );
            CREATE TABLE IF NOT EXISTS reports (
                task_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                markdown TEXT NOT NULL,
                html TEXT NOT NULL,
                risk_json TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                address TEXT NOT NULL,
                type TEXT NOT NULL,
                project_path TEXT,
                owner TEXT,
                tags TEXT,
                notes TEXT,
                last_scan_at TEXT,
                risk TEXT NOT NULL DEFAULT 'Low',
                task_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ai_advice_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                vuln_id TEXT NOT NULL,
                advice TEXT NOT NULL,
                source TEXT NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS schedules (
                schedule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                project_path TEXT NOT NULL,
                interval_minutes INTEGER,
                daily_time TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_run_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )


def _save_setting(key: str, value: str) -> None:
    with _db() as connection:
        connection.execute(
            """
            INSERT INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
            """,
            (key, value, _timestamp()),
        )


def _load_settings() -> None:
    with _db() as connection:
        rows = connection.execute("SELECT key, value FROM settings").fetchall()
    for row in rows:
        if row["key"] in SETTINGS:
            SETTINGS[row["key"]] = row["value"]
    for key, value in SETTINGS.items():
        _save_setting(key, str(value))


def _slug_id(prefix: str, value: str) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _vulnerability_fingerprint(vulnerability: dict[str, Any]) -> str:
    basis = "|".join(
        str(vulnerability.get(key, "")).strip().lower()
        for key in ("type", "location", "request_method", "payload", "scanner_rule", "evidence")
    )
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def _same_private_or_local_target(base_url: str) -> tuple[bool, str]:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, "目标地址必须是 http/https URL"
    hostname = parsed.hostname.lower()
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return True, ""
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False, "默认只允许 localhost、127.0.0.1、私有网段或明确白名单目标"
    if address.is_loopback or address.is_private:
        return True, ""
    return False, "默认拒绝公网第三方目标，请改用本地授权靶场或私有网段目标"


def _preflight_scan(base_url: str, project_path: str) -> list[str]:
    errors: list[str] = []
    allowed, message = _same_private_or_local_target(base_url)
    if not allowed:
        errors.append(message)

    source_path = (PROJECT_ROOT / project_path).resolve() if not Path(project_path).is_absolute() else Path(project_path)
    if not source_path.exists() or not source_path.is_dir():
        errors.append(f"源码路径不存在或不可读：{project_path}")

    try:
        response = requests.get(f"{base_url.rstrip('/')}/health", timeout=3)
        if response.status_code >= 400:
            errors.append(f"靶场 /health 返回异常状态码：{response.status_code}")
    except requests.RequestException as exc:
        errors.append(f"靶场 /health 不可访问：{exc}")

    return errors


def _next_task_id() -> str:
    global TASK_COUNTER
    with TASK_LOCK:
        TASK_COUNTER += 1
        return f"SCAN-{_now():%Y%m%d-%H%M%S}-{TASK_COUNTER:04d}"


def _initial_steps() -> list[dict[str, str]]:
    return [{"name": name, "status": "pending", "duration": "等待中"} for name in SCAN_STEPS]


def _event(level: str, message: str) -> dict[str, str]:
    return {"time": _clock(), "level": level, "message": message}


def _save_task_locked(task: dict[str, Any]) -> None:
    with _db() as connection:
        connection.execute(
            """
            INSERT INTO scan_tasks (
                task_id, base_url, project_path, status, progress, current_step,
                steps_json, events_json, created_at, completed_at, errors_json,
                result_json, cancel_requested, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                base_url=excluded.base_url,
                project_path=excluded.project_path,
                status=excluded.status,
                progress=excluded.progress,
                current_step=excluded.current_step,
                steps_json=excluded.steps_json,
                events_json=excluded.events_json,
                completed_at=excluded.completed_at,
                errors_json=excluded.errors_json,
                result_json=excluded.result_json,
                cancel_requested=excluded.cancel_requested,
                updated_at=excluded.updated_at
            """,
            (
                task["task_id"],
                task["target"].get("base_url", ""),
                task["target"].get("project_path", ""),
                task.get("status", "pending"),
                int(task.get("progress") or 0),
                task.get("current_step", ""),
                _json_dump(task.get("steps", [])),
                _json_dump(task.get("events", [])),
                task.get("created_at") or _timestamp(),
                task.get("completed_at"),
                _json_dump(task.get("errors", [])),
                _json_dump(task.get("result")) if task.get("result") else None,
                1 if task.get("cancel_requested") else 0,
                _timestamp(),
            ),
        )


def _save_vulnerabilities_locked(task: dict[str, Any]) -> None:
    result = task.get("result") or {}
    for vulnerability in result.get("vulnerabilities", []):
        vulnerability.setdefault("fingerprint", _vulnerability_fingerprint(vulnerability))
        vulnerability.setdefault("confidence", "Medium")
        with _db() as connection:
            connection.execute(
                """
                INSERT INTO vulnerabilities (
                    task_id, vuln_id, type, risk, score, location, method,
                    request_method, payload, scanner_rule, evidence, suggestion,
                    ai_advice, ai_advice_source, status, remediation_priority,
                    confidence, fingerprint, review_note, reviewer, updated_at, raw_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id, vuln_id) DO UPDATE SET
                    type=excluded.type,
                    risk=excluded.risk,
                    score=excluded.score,
                    location=excluded.location,
                    method=excluded.method,
                    request_method=excluded.request_method,
                    payload=excluded.payload,
                    scanner_rule=excluded.scanner_rule,
                    evidence=excluded.evidence,
                    suggestion=excluded.suggestion,
                    ai_advice=excluded.ai_advice,
                    ai_advice_source=excluded.ai_advice_source,
                    status=excluded.status,
                    remediation_priority=excluded.remediation_priority,
                    confidence=excluded.confidence,
                    fingerprint=excluded.fingerprint,
                    review_note=COALESCE(vulnerabilities.review_note, excluded.review_note),
                    reviewer=COALESCE(vulnerabilities.reviewer, excluded.reviewer),
                    updated_at=excluded.updated_at,
                    raw_json=excluded.raw_json
                """,
                (
                    task["task_id"],
                    vulnerability.get("id"),
                    vulnerability.get("type"),
                    vulnerability.get("risk"),
                    int(vulnerability.get("score") or 0),
                    vulnerability.get("location"),
                    vulnerability.get("method"),
                    vulnerability.get("request_method"),
                    vulnerability.get("payload"),
                    vulnerability.get("scanner_rule"),
                    vulnerability.get("evidence"),
                    vulnerability.get("suggestion"),
                    vulnerability.get("ai_advice"),
                    vulnerability.get("ai_advice_source"),
                    vulnerability.get("status", "未修复"),
                    vulnerability.get("remediation_priority", "P3"),
                    vulnerability.get("confidence", "Medium"),
                    vulnerability.get("fingerprint"),
                    vulnerability.get("review_note", ""),
                    vulnerability.get("reviewer", ""),
                    _timestamp(),
                    _json_dump(vulnerability),
                ),
            )


def _save_report_locked(task: dict[str, Any]) -> None:
    result = task.get("result") or {}
    reports = result.get("reports") or {}
    if not reports:
        return
    generated_at = task.get("completed_at") or task.get("created_at") or _timestamp()
    with _db() as connection:
        connection.execute(
            """
            INSERT INTO reports (task_id, name, markdown, html, risk_json, generated_at, deleted, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(task_id) DO UPDATE SET
                markdown=excluded.markdown,
                html=excluded.html,
                risk_json=excluded.risk_json,
                generated_at=excluded.generated_at,
                deleted=0,
                updated_at=excluded.updated_at
            """,
            (
                task["task_id"],
                f"{task['task_id']} 安全扫描报告",
                reports.get("markdown", ""),
                reports.get("html", ""),
                _json_dump(result.get("risk", {})),
                generated_at,
                _timestamp(),
            ),
        )


def _upsert_asset_locked(
    *,
    name: str,
    address: str,
    asset_type: str = "Web 应用",
    project_path: str = "",
    owner: str = "",
    tags: str = "",
    notes: str = "",
    risk: str = "Low",
    task_id: str = "",
    last_scan_at: str | None = None,
) -> dict[str, Any]:
    asset_id = _slug_id("ASSET", f"{asset_type}:{address}:{project_path}")
    existing = ASSETS.get(asset_id, {})
    now = _timestamp()
    asset = {
        "id": asset_id,
        "name": name or existing.get("name") or ("扫描目标" if asset_type == "Web 应用" else "源码目录"),
        "address": address,
        "type": asset_type,
        "project_path": project_path or existing.get("project_path", ""),
        "owner": owner or existing.get("owner", ""),
        "tags": tags or existing.get("tags", ""),
        "notes": notes or existing.get("notes", ""),
        "risk": risk or existing.get("risk", "Low"),
        "task_id": task_id or existing.get("task_id", ""),
        "last_scan_at": last_scan_at or existing.get("last_scan_at"),
        "created_at": existing.get("created_at") or now,
        "updated_at": now,
    }
    ASSETS[asset_id] = asset
    with _db() as connection:
        connection.execute(
            """
            INSERT INTO assets (
                asset_id, name, address, type, project_path, owner, tags, notes,
                last_scan_at, risk, task_id, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(asset_id) DO UPDATE SET
                name=excluded.name,
                address=excluded.address,
                type=excluded.type,
                project_path=excluded.project_path,
                owner=excluded.owner,
                tags=excluded.tags,
                notes=excluded.notes,
                last_scan_at=excluded.last_scan_at,
                risk=excluded.risk,
                task_id=excluded.task_id,
                updated_at=excluded.updated_at
            """,
            (
                asset["id"],
                asset["name"],
                asset["address"],
                asset["type"],
                asset["project_path"],
                asset["owner"],
                asset["tags"],
                asset["notes"],
                asset["last_scan_at"],
                asset["risk"],
                asset["task_id"],
                asset["created_at"],
                asset["updated_at"],
            ),
        )
    return asset


def _sync_assets_for_task_locked(task: dict[str, Any]) -> None:
    target = task.get("target") or {}
    result = task.get("result") or {}
    risk = result.get("risk", {}).get("overall_risk", "Low")
    completed_at = task.get("completed_at") or task.get("created_at")
    base_url = str(target.get("base_url") or "")
    project_path = str(target.get("project_path") or "")
    if base_url:
        _upsert_asset_locked(
            name="扫描目标",
            address=base_url,
            asset_type="Web 应用",
            project_path=project_path,
            risk=risk,
            task_id=task["task_id"],
            last_scan_at=completed_at,
        )
    if project_path:
        _upsert_asset_locked(
            name="源码目录",
            address=project_path,
            asset_type="Codebase",
            project_path=project_path,
            risk=risk,
            task_id=task["task_id"],
            last_scan_at=completed_at,
        )


def _persist_task_bundle_locked(task: dict[str, Any]) -> None:
    _save_task_locked(task)
    if task.get("result"):
        _save_vulnerabilities_locked(task)
        _save_report_locked(task)
        _sync_assets_for_task_locked(task)


def _load_assets() -> None:
    ASSETS.clear()
    with _db() as connection:
        rows = connection.execute("SELECT * FROM assets ORDER BY updated_at DESC").fetchall()
    for row in rows:
        ASSETS[row["asset_id"]] = {
            "id": row["asset_id"],
            "name": row["name"],
            "address": row["address"],
            "type": row["type"],
            "project_path": row["project_path"] or "",
            "owner": row["owner"] or "",
            "tags": row["tags"] or "",
            "notes": row["notes"] or "",
            "last_scan_at": row["last_scan_at"],
            "risk": row["risk"] or "Low",
            "task_id": row["task_id"] or "",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }


def _merge_persisted_vulnerabilities(task: dict[str, Any]) -> None:
    result = task.get("result") or {}
    vulnerabilities = result.get("vulnerabilities") or []
    if not vulnerabilities:
        return
    with _db() as connection:
        rows = connection.execute(
            "SELECT vuln_id, status, ai_advice, ai_advice_source, confidence, fingerprint, review_note, reviewer FROM vulnerabilities WHERE task_id=?",
            (task["task_id"],),
        ).fetchall()
    persisted = {row["vuln_id"]: row for row in rows}
    statuses = task.setdefault("vulnerability_status", {})
    for vulnerability in vulnerabilities:
        row = persisted.get(vulnerability.get("id"))
        if not row:
            continue
        vulnerability["status"] = row["status"] or vulnerability.get("status", "未修复")
        vulnerability["ai_advice"] = row["ai_advice"] or vulnerability.get("ai_advice", "")
        vulnerability["ai_advice_source"] = row["ai_advice_source"] or vulnerability.get("ai_advice_source", "unknown")
        vulnerability["confidence"] = row["confidence"] or vulnerability.get("confidence", "Medium")
        vulnerability["fingerprint"] = row["fingerprint"] or vulnerability.get("fingerprint", "")
        vulnerability["review_note"] = row["review_note"] or ""
        vulnerability["reviewer"] = row["reviewer"] or ""
        statuses[vulnerability["id"]] = vulnerability["status"]


def _load_tasks() -> None:
    global TASK_COUNTER
    TASKS.clear()
    with _db() as connection:
        rows = connection.execute("SELECT * FROM scan_tasks ORDER BY created_at DESC").fetchall()
    max_counter = 0
    for row in rows:
        task_id = row["task_id"]
        try:
            max_counter = max(max_counter, int(task_id.rsplit("-", 1)[-1]))
        except ValueError:
            pass
        status = row["status"]
        events = _json_load(row["events_json"], [])
        errors = _json_load(row["errors_json"], [])
        completed_at = row["completed_at"]
        if status == "running":
            status = "failed"
            completed_at = completed_at or _timestamp()
            errors = [*errors, "Scanner service restarted before this task completed."]
            events = [*events, _event("WARN", "服务重启，运行中的扫描任务已标记为中断")]
        task = {
            "task_id": task_id,
            "status": status,
            "progress": 100 if status == "failed" and row["status"] == "running" else row["progress"],
            "current_step": "服务重启后任务已中断" if status == "failed" and row["status"] == "running" else row["current_step"],
            "steps": _json_load(row["steps_json"], _initial_steps()),
            "events": events[-50:],
            "target": {
                "base_url": row["base_url"],
                "project_path": row["project_path"],
            },
            "created_at": row["created_at"],
            "completed_at": completed_at,
            "result": _json_load(row["result_json"], None),
            "errors": errors,
            "ai_progress": {"total": 0, "completed": 0, "current": "", "active": False},
            "vulnerability_status": {},
            "cancel_requested": bool(row["cancel_requested"]),
        }
        _merge_persisted_vulnerabilities(task)
        TASKS[task_id] = task
        if status != row["status"]:
            _save_task_locked(task)
    TASK_COUNTER = max(TASK_COUNTER, max_counter, len(TASKS))


def _load_state_from_db() -> None:
    _init_db()
    _load_settings()
    _load_assets()
    _load_tasks()


def _set_task_state(
    task_id: str,
    *,
    status: str | None = None,
    progress: int | None = None,
    current_step: str | None = None,
    ai_progress: dict[str, Any] | None = None,
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
        if ai_progress is not None:
            task["ai_progress"] = {
                "total": max(0, int(ai_progress.get("total") or 0)),
                "completed": max(0, int(ai_progress.get("completed") or 0)),
                "current": str(ai_progress.get("current") or ""),
                "active": bool(ai_progress.get("active")),
            }
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
        _save_task_locked(task)


def _complete_steps(task_id: str) -> None:
    with TASK_LOCK:
        task = TASKS[task_id]
        for step in task["steps"]:
            step["status"] = "done"
            if step["duration"] in {"等待中", "进行中"}:
                step["duration"] = "已完成"
        _save_task_locked(task)


def _public_task(task: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task["task_id"],
        "status": task["status"],
        "progress": task["progress"],
        "current_step": task["current_step"],
        "steps": task["steps"],
        "events": task["events"],
        "ai_progress": task.get("ai_progress", {"total": 0, "completed": 0, "current": "", "active": False}),
        "target": task["target"],
        "created_at": task["created_at"],
        "completed_at": task.get("completed_at"),
        "errors": task.get("errors", []),
    }


def _task_reports() -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    with _db() as connection:
        rows = connection.execute("SELECT * FROM reports WHERE deleted=0 ORDER BY generated_at DESC").fetchall()
    for row in rows:
        task = TASKS.get(row["task_id"])
        target = task.get("target", {}) if task else {}
        reports.append(
            {
                "task_id": row["task_id"],
                "name": row["name"],
                "target": target,
                "risk": _json_load(row["risk_json"], {}),
                "vulnerability_total": len((task.get("result") or {}).get("vulnerabilities", [])) if task else 0,
                "generated_at": row["generated_at"],
                "markdown_url": f"/api/report/{row['task_id']}/markdown",
                "html_url": f"/api/report/{row['task_id']}/html",
            }
        )
    return reports


def _task_assets() -> list[dict[str, Any]]:
    assets: dict[str, dict[str, Any]] = {asset_id: dict(asset) for asset_id, asset in ASSETS.items()}
    for task in TASKS.values():
        result = task.get("result") or {}
        risk = result.get("risk", {})
        base_url = task["target"].get("base_url", "")
        project_path = task["target"].get("project_path", "")
        if base_url:
            asset_id = _slug_id("ASSET", f"Web 应用:{base_url}:{project_path}")
            assets.setdefault(asset_id, {
                "id": asset_id,
                "name": "扫描目标",
                "address": base_url,
                "type": "Web 应用",
                "project_path": project_path,
                "risk": risk.get("overall_risk", "Low"),
                "last_scan_at": task.get("completed_at") or task.get("created_at"),
                "task_id": task["task_id"],
            })
        if project_path:
            asset_id = _slug_id("ASSET", f"Codebase:{project_path}:{project_path}")
            assets.setdefault(asset_id, {
                "id": asset_id,
                "name": "源码目录",
                "address": project_path,
                "type": "Codebase",
                "project_path": project_path,
                "risk": risk.get("overall_risk", "Low"),
                "last_scan_at": task.get("completed_at") or task.get("created_at"),
                "task_id": task["task_id"],
            })
    return sorted(assets.values(), key=lambda item: item.get("last_scan_at") or "", reverse=True)


def _configured_ai_provider() -> str:
    selected_provider = os.getenv("AI_PROVIDER", "").strip().lower()
    selected_env_names = {
        "openai": "OPENAI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "qwen": "QWEN_API_KEY",
    }
    if selected_provider in selected_env_names and os.getenv(selected_env_names[selected_provider]):
        return selected_provider

    for provider, env_name in (
        ("openai", "OPENAI_API_KEY"),
        ("deepseek", "DEEPSEEK_API_KEY"),
        ("qwen", "QWEN_API_KEY"),
    ):
        if os.getenv(env_name):
            return provider
    return ""


def _priority_from_risk(risk: str) -> str:
    if risk == "Critical":
        return "P0"
    if risk == "High":
        return "P1"
    if risk == "Medium":
        return "P2"
    return "P3"


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
        "request_method": str(raw.get("request_method") or raw.get("method") or "UNKNOWN"),
        "payload": str(raw.get("payload") or ""),
        "scanner_rule": str(raw.get("scanner_rule") or ""),
        "remediation_priority": str(raw.get("remediation_priority") or _priority_from_risk(str(raw.get("risk") or "Low"))),
        "evidence": evidence,
        "evidence_count": int(raw.get("evidence_count") or (1 if evidence else 0)),
        "confidence": str(raw.get("confidence") or "Medium"),
        "fingerprint": str(raw.get("fingerprint") or _vulnerability_fingerprint(raw)),
        "suggestion": str(raw.get("suggestion") or ""),
        "ai_advice": ai_advice,
        "ai_advice_source": str(raw.get("ai_advice_source") or "unknown"),
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
        progress_cursor = {"value": 12}

        def progress_event(level: str, message: str, meta: dict[str, Any] | None = None) -> None:
            meta = meta or {}
            ai_state = None
            if meta.get("phase") == "ai_advice":
                step_index = 5
                current_step = "生成 AI 建议"
                progress = 100
                ai_state = {
                    "total": int(meta.get("ai_total") or 0),
                    "completed": int(meta.get("ai_completed") or 0),
                    "current": str(meta.get("ai_current") or ""),
                    "active": int(meta.get("ai_completed") or 0) < int(meta.get("ai_total") or 0),
                }
            elif "静态" in message:
                step_index = 4
                current_step = "静态源码扫描"
                progress_cursor["value"] = min(92, progress_cursor["value"] + 4)
                progress = progress_cursor["value"]
            elif "修复建议" in message:
                step_index = 5
                current_step = "生成 AI 建议"
                progress = 100
            elif "报告" in message:
                step_index = 6
                current_step = "生成报告"
                progress = 100
            elif "sql_injection" in message:
                step_index = 1
                current_step = "SQL 注入测试"
                progress_cursor["value"] = min(92, progress_cursor["value"] + 4)
                progress = progress_cursor["value"]
            elif "xss" in message:
                step_index = 2
                current_step = "XSS 测试"
                progress_cursor["value"] = min(92, progress_cursor["value"] + 4)
                progress = progress_cursor["value"]
            elif "broken_access_control" in message or "access_control" in message:
                step_index = 3
                current_step = "越权访问测试"
                progress_cursor["value"] = min(92, progress_cursor["value"] + 4)
                progress = progress_cursor["value"]
            else:
                step_index = 1
                current_step = "动态漏洞扫描"
                progress_cursor["value"] = min(92, progress_cursor["value"] + 4)
                progress = progress_cursor["value"]

            _set_task_state(
                task_id,
                progress=progress,
                current_step=current_step,
                ai_progress=ai_state,
                step_index=step_index,
                events=[_event(level, message)],
            )

        _set_task_state(task_id, progress=25, current_step="动态漏洞扫描", step_index=1)
        scan_result = run_full_security_scan(
            base_url=target["base_url"],
            project_path=target["project_path"],
            progress_callback=progress_event,
        )

        with TASK_LOCK:
            task = TASKS[task_id]
            if task.get("cancel_requested"):
                task["status"] = "cancelled"
                task["progress"] = 100
                task["current_step"] = "任务已取消"
                task["ai_progress"] = {**task.get("ai_progress", {}), "active": False}
                task["completed_at"] = _timestamp()
                task.setdefault("events", []).append(_event("WARN", "任务已取消，扫描结果未写入报告中心"))
                _save_task_locked(task)
                return
            normalized = _normalize_scan_result(task, scan_result)
            task["result"] = normalized
            task["errors"] = normalized.get("errors", [])
            task["completed_at"] = _timestamp()
            _persist_task_bundle_locked(task)

        _complete_steps(task_id)
        total = len(normalized.get("vulnerabilities", []))
        level = "RISK" if total else "INFO"
        _set_task_state(
            task_id,
            status="completed",
            progress=100,
            current_step="扫描完成",
            ai_progress={**task.get("ai_progress", {}), "active": False},
            events=[
                _event(level, f"扫描完成，发现 {total} 个漏洞"),
                _event("INFO", "Markdown / HTML 报告已生成"),
            ],
        )
    except Exception as exc:
        _set_task_state(
            task_id,
            status="failed",
            progress=100,
            current_step="扫描失败",
            ai_progress={"total": 0, "completed": 0, "current": "", "active": False},
            events=[_event("ERROR", f"扫描失败：{exc}")],
        )
        with TASK_LOCK:
            task = TASKS[task_id]
            task["errors"] = [str(exc)]
            task["completed_at"] = _timestamp()
            _save_task_locked(task)


def start_scan(payload: dict[str, Any]) -> dict[str, Any]:
    load_env_file()
    base_url = str(payload.get("base_url") or SETTINGS["default_base_url"])
    project_path = str(payload.get("project_path") or SETTINGS["default_project_path"])
    preflight_errors = _preflight_scan(base_url, project_path)
    if preflight_errors:
        return {
            "status": "rejected",
            "message": "Scan preflight failed.",
            "errors": preflight_errors,
        }

    task_id = _next_task_id()
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
        "ai_progress": {"total": 0, "completed": 0, "current": "", "active": False},
        "vulnerability_status": {},
        "cancel_requested": False,
    }
    with TASK_LOCK:
        TASKS[task_id] = task
        _save_task_locked(task)

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
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
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
        if parsed.path == "/api/scan/start":
            payload = self._read_json()
            result = start_scan(payload)
            status = HTTPStatus.BAD_REQUEST if result.get("status") == "rejected" else HTTPStatus.ACCEPTED
            self._send_json(result, status)
            return
        if parsed.path.startswith("/api/scan/") and parsed.path.endswith("/rerun"):
            self._handle_task_rerun(parsed.path)
            return
        if parsed.path.startswith("/api/scan/") and parsed.path.endswith("/cancel"):
            self._handle_task_cancel(parsed.path)
            return
        if parsed.path == "/api/assets":
            self._handle_asset_create()
            return
        if parsed.path.startswith("/api/assets/") and parsed.path.endswith("/scan"):
            self._handle_asset_scan(parsed.path)
            return
        if parsed.path.startswith("/api/report/") and parsed.path.endswith("/regenerate"):
            self._handle_report_regenerate(parsed.path)
            return
        if parsed.path.startswith("/api/vulnerability/") and parsed.path.endswith("/ai-advice"):
            self._handle_ai_advice(parsed.path)
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_PATCH(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/settings":
            self._handle_settings_update()
            return
        if parsed.path == "/api/settings/ai-key":
            self._handle_ai_key_update()
            return
        if parsed.path == "/api/settings/ai-test":
            self._handle_ai_key_test()
            return
        if parsed.path.startswith("/api/assets/"):
            self._handle_asset_update(parsed.path)
            return
        if parsed.path.startswith("/api/report/"):
            self._handle_report_update(parsed.path)
            return
        if parsed.path.startswith("/api/vulnerability/") and parsed.path.endswith("/status"):
            self._handle_vulnerability_status(parsed.path)
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/tasks":
            self._handle_tasks_clear()
            return
        if parsed.path.startswith("/api/scan/"):
            self._handle_task_delete(parsed.path)
            return
        if parsed.path.startswith("/api/assets/"):
            self._handle_asset_delete(parsed.path)
            return
        if parsed.path.startswith("/api/report/"):
            self._handle_report_delete(parsed.path)
            return
        self._send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

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

    def _handle_api_get(self, path: str) -> None:
        if path == "/api/health":
            self._send_json({"status": "ok", "storage": str(DB_PATH)})
            return
        if path == "/api/settings":
            self._send_json(
                {
                    "api_base_url": "/api",
                    "default_base_url": SETTINGS["default_base_url"],
                    "default_project_path": SETTINGS["default_project_path"],
                    "ai_key_configured": any(
                        os.getenv(name) for name in ("OPENAI_API_KEY", "DEEPSEEK_API_KEY", "QWEN_API_KEY")
                    ),
                    "ai_provider": _configured_ai_provider(),
                    "runtime_ai_provider": SETTINGS.get("runtime_ai_provider", ""),
                    "ai_model": os.getenv("AI_MODEL") or os.getenv("QWEN_MODEL") or SETTINGS.get("runtime_ai_model", "qwen3.6-flash"),
                    "storage": str(DB_PATH),
                    "last_ai_test": SETTINGS.get("last_ai_test", ""),
                }
            )
            return
        if path == "/api/tasks":
            with TASK_LOCK:
                tasks = sorted(
                    (_public_task(task) for task in TASKS.values()),
                    key=lambda item: item.get("created_at") or "",
                    reverse=True,
                )
            self._send_json({"tasks": tasks})
            return
        if path == "/api/reports":
            with TASK_LOCK:
                reports = _task_reports()
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
        with _db() as connection:
            report_row = connection.execute("SELECT markdown, html FROM reports WHERE task_id=? AND deleted=0", (task_id,)).fetchone()
        if (task is None or result is None) and report_row is None:
            self._send_json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)
            return
        if report_type == "html":
            self._send_text(report_row["html"] if report_row else result["reports"].get("html", ""), "text/html")
            return
        if report_type == "markdown":
            self._send_text(report_row["markdown"] if report_row else result["reports"].get("markdown", ""), "text/markdown")
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
        _save_setting("default_base_url", base_url)
        _save_setting("default_project_path", project_path)
        self._send_json(
            {
                "api_base_url": "/api",
                "default_base_url": SETTINGS["default_base_url"],
                "default_project_path": SETTINGS["default_project_path"],
                "ai_key_configured": any(
                    os.getenv(name) for name in ("OPENAI_API_KEY", "DEEPSEEK_API_KEY", "QWEN_API_KEY")
                ),
                "ai_provider": _configured_ai_provider(),
                "ai_model": os.getenv("AI_MODEL") or os.getenv("QWEN_MODEL") or SETTINGS.get("runtime_ai_model", "qwen3.6-flash"),
                "storage": str(DB_PATH),
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
        result = start_scan(target)
        status = HTTPStatus.BAD_REQUEST if result.get("status") == "rejected" else HTTPStatus.ACCEPTED
        self._send_json(result, status)

    def _handle_task_cancel(self, path: str) -> None:
        task_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            task = TASKS.get(task_id)
            if task and task.get("status") == "running":
                task["cancel_requested"] = True
                task["status"] = "cancelling"
                task["current_step"] = "正在取消"
                task.setdefault("events", []).append(_event("WARN", "用户请求取消扫描任务"))
                _save_task_locked(task)
        if not task:
            self._send_json({"error": "Task not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json(_public_task(task))

    def _handle_task_delete(self, path: str) -> None:
        task_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            task = TASKS.pop(task_id, None)
            with _db() as connection:
                connection.execute("DELETE FROM scan_tasks WHERE task_id=?", (task_id,))
                connection.execute("DELETE FROM vulnerabilities WHERE task_id=?", (task_id,))
                connection.execute("UPDATE reports SET deleted=1, updated_at=? WHERE task_id=?", (_timestamp(), task_id))
        if not task:
            self._send_json({"error": "Task not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"task_id": task_id, "deleted": True})

    def _handle_tasks_clear(self) -> None:
        with TASK_LOCK:
            TASKS.clear()
            with _db() as connection:
                connection.execute("DELETE FROM scan_tasks")
                connection.execute("DELETE FROM vulnerabilities")
                connection.execute("UPDATE reports SET deleted=1, updated_at=?", (_timestamp(),))
        self._send_json({"cleared": True})

    def _handle_asset_create(self) -> None:
        payload = self._read_json()
        address = str(payload.get("address") or "").strip()
        if not address:
            self._send_json({"error": "address is required"}, HTTPStatus.BAD_REQUEST)
            return
        with TASK_LOCK:
            asset = _upsert_asset_locked(
                name=str(payload.get("name") or "").strip(),
                address=address,
                asset_type=str(payload.get("type") or "Web 应用").strip(),
                project_path=str(payload.get("project_path") or "").strip(),
                owner=str(payload.get("owner") or "").strip(),
                tags=str(payload.get("tags") or "").strip(),
                notes=str(payload.get("notes") or "").strip(),
            )
        self._send_json({"asset": asset}, HTTPStatus.CREATED)

    def _handle_asset_update(self, path: str) -> None:
        asset_id = path.strip("/").split("/")[2]
        payload = self._read_json()
        with TASK_LOCK:
            existing = ASSETS.get(asset_id)
            if existing:
                asset = _upsert_asset_locked(
                    name=str(payload.get("name") or existing.get("name") or "").strip(),
                    address=str(payload.get("address") or existing.get("address") or "").strip(),
                    asset_type=str(payload.get("type") or existing.get("type") or "Web 应用").strip(),
                    project_path=str(payload.get("project_path") or existing.get("project_path") or "").strip(),
                    owner=str(payload.get("owner") or existing.get("owner") or "").strip(),
                    tags=str(payload.get("tags") or existing.get("tags") or "").strip(),
                    notes=str(payload.get("notes") or existing.get("notes") or "").strip(),
                    risk=str(payload.get("risk") or existing.get("risk") or "Low").strip(),
                    task_id=str(existing.get("task_id") or ""),
                    last_scan_at=existing.get("last_scan_at"),
                )
            else:
                asset = None
        if not asset:
            self._send_json({"error": "Asset not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"asset": asset})

    def _handle_asset_delete(self, path: str) -> None:
        asset_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            asset = ASSETS.pop(asset_id, None)
            with _db() as connection:
                connection.execute("DELETE FROM assets WHERE asset_id=?", (asset_id,))
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
            "project_path": asset.get("project_path") or (asset["address"] if asset.get("type") == "Codebase" else SETTINGS["default_project_path"]),
        }
        result = start_scan(payload)
        status = HTTPStatus.BAD_REQUEST if result.get("status") == "rejected" else HTTPStatus.ACCEPTED
        self._send_json(result, status)

    def _handle_report_update(self, path: str) -> None:
        task_id = path.strip("/").split("/")[2]
        payload = self._read_json()
        name = str(payload.get("name") or "").strip()
        if not name:
            self._send_json({"error": "name is required"}, HTTPStatus.BAD_REQUEST)
            return
        with _db() as connection:
            cursor = connection.execute(
                "UPDATE reports SET name=?, updated_at=? WHERE task_id=? AND deleted=0",
                (name, _timestamp(), task_id),
            )
        if cursor.rowcount == 0:
            self._send_json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"task_id": task_id, "name": name})

    def _handle_report_delete(self, path: str) -> None:
        task_id = path.strip("/").split("/")[2]
        with _db() as connection:
            cursor = connection.execute(
                "UPDATE reports SET deleted=1, updated_at=? WHERE task_id=?",
                (_timestamp(), task_id),
            )
        if cursor.rowcount == 0:
            self._send_json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"task_id": task_id, "deleted": True})

    def _handle_report_regenerate(self, path: str) -> None:
        task_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            task = TASKS.get(task_id)
            result = task.get("result") if task else None
            if task is None or result is None:
                self._send_json({"error": "Completed scan result not found"}, HTTPStatus.NOT_FOUND)
                return
            result["reports"] = {
                "markdown": generate_markdown_report(result),
                "html": generate_html_report(result),
                "markdown_url": f"/api/report/{task_id}/markdown",
                "html_url": f"/api/report/{task_id}/html",
            }
            _save_report_locked(task)
            report = {
                "task_id": task_id,
                "markdown_url": result["reports"]["markdown_url"],
                "html_url": result["reports"]["html_url"],
                "regenerated_at": _timestamp(),
            }
        self._send_json(report)

    def _handle_ai_key_update(self) -> None:
        payload = self._read_json()
        provider = str(payload.get("provider") or "qwen").strip().lower()
        api_key = str(payload.get("api_key") or "").strip()
        ai_model = str(payload.get("model") or payload.get("ai_model") or "").strip()
        key_names = {
            "qwen": "QWEN_API_KEY",
            "openai": "OPENAI_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
        }
        env_name = key_names.get(provider)
        if env_name is None:
            self._send_json({"error": "Unsupported AI provider"}, HTTPStatus.BAD_REQUEST)
            return
        if not api_key:
            self._send_json({"error": "API key is required"}, HTTPStatus.BAD_REQUEST)
            return

        os.environ[env_name] = api_key
        os.environ["AI_PROVIDER"] = provider
        if ai_model:
            os.environ["AI_MODEL"] = ai_model
            if provider == "qwen":
                os.environ["QWEN_MODEL"] = ai_model
            elif provider == "openai":
                os.environ["OPENAI_MODEL"] = ai_model
            elif provider == "deepseek":
                os.environ["DEEPSEEK_MODEL"] = ai_model
            SETTINGS["runtime_ai_model"] = ai_model
            _save_setting("runtime_ai_model", ai_model)
        SETTINGS["runtime_ai_provider"] = provider
        _save_setting("runtime_ai_provider", provider)
        self._send_json(
            {
                "ai_key_configured": True,
                "ai_provider": provider,
                "runtime_ai_provider": provider,
                "ai_model": ai_model or os.getenv("AI_MODEL") or os.getenv("QWEN_MODEL") or "",
            }
        )

    def _handle_ai_key_test(self) -> None:
        payload = self._read_json()
        provider = str(payload.get("provider") or _configured_ai_provider() or "qwen").strip().lower()
        ai_model = str(payload.get("model") or payload.get("ai_model") or "").strip()
        if provider not in {"qwen", "openai", "deepseek"}:
            self._send_json({"error": "Unsupported AI provider"}, HTTPStatus.BAD_REQUEST)
            return
        previous_model = os.environ.get("AI_MODEL")
        if ai_model:
            os.environ["AI_MODEL"] = ai_model

        try:
            result = test_ai_connection(provider)
            SETTINGS["last_ai_test"] = _json_dump({**result, "tested_at": _timestamp()})
            _save_setting("last_ai_test", SETTINGS["last_ai_test"])
            status = HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST
            self._send_json(result, status)
        finally:
            if ai_model:
                if previous_model is None:
                    os.environ.pop("AI_MODEL", None)
                else:
                    os.environ["AI_MODEL"] = previous_model

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
        advice_result = generate_ai_advice_result(vulnerability)
        vulnerability["ai_advice"] = advice_result["advice"]
        vulnerability["ai_advice_source"] = advice_result["source"]
        with TASK_LOCK:
            result = task.get("result") or {}
            if result:
                result["reports"] = {
                    "markdown": generate_markdown_report(result),
                    "html": generate_html_report(result),
                }
            _save_vulnerabilities_locked(task)
            if result:
                _save_report_locked(task)
            with _db() as connection:
                connection.execute(
                    """
                    INSERT INTO ai_advice_versions (task_id, vuln_id, advice, source, error, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        vuln_id,
                        advice_result["advice"],
                        advice_result["source"],
                        advice_result.get("error", ""),
                        _timestamp(),
                    ),
                )
        self._send_json(
            {
                "id": vuln_id,
                "ai_advice": advice_result["advice"],
                "ai_advice_source": advice_result["source"],
            }
        )

    def _handle_vulnerability_status(self, path: str) -> None:
        payload = self._read_json()
        task_id = str(payload.get("task_id") or "")
        status = str(payload.get("status") or "未修复")
        review_note = str(payload.get("review_note") or "")
        reviewer = str(payload.get("reviewer") or "")
        vuln_id = path.strip("/").split("/")[2]
        with TASK_LOCK:
            task = TASKS.get(task_id)
            vulnerability = _find_vulnerability(task, vuln_id) if task else None
            if task and vulnerability:
                task.setdefault("vulnerability_status", {})[vuln_id] = status
                vulnerability["status"] = status
                vulnerability["review_note"] = review_note or vulnerability.get("review_note", "")
                vulnerability["reviewer"] = reviewer or vulnerability.get("reviewer", "")
                _save_vulnerabilities_locked(task)
                _save_task_locked(task)
        if task is None or vulnerability is None:
            self._send_json({"error": "Vulnerability not found"}, HTTPStatus.NOT_FOUND)
            return
        self._send_json({"id": vuln_id, "status": status, "review_note": vulnerability.get("review_note", ""), "reviewer": vulnerability.get("reviewer", "")})

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
    _load_state_from_db()
    server = ThreadingHTTPServer((host, port), ScannerApiHandler)
    print(f"Scanner console running at http://{host}:{port}/")
    print(f"API health check: http://{host}:{port}/api/health")
    print(f"SQLite state: {DB_PATH}")
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
