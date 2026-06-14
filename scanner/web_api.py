from __future__ import annotations

import argparse
import json
import mimetypes
import os
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, Thread
from typing import Any
from urllib.parse import unquote, urlparse

from scanner.ai_advisor import generate_ai_advice, load_env_file
from scanner.full_scan import run_full_security_scan
from scanner.report_generator import generate_html_report, generate_markdown_report


PROJECT_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_ROOT = PROJECT_ROOT / "frontend"
DEFAULT_BASE_URL = "http://127.0.0.1:5001"
DEFAULT_PROJECT_PATH = "./vulnerable_app"

TASKS: dict[str, dict[str, Any]] = {}
TASK_LOCK = Lock()
TASK_COUNTER = 0
SETTINGS = {
    "default_base_url": DEFAULT_BASE_URL,
    "default_project_path": DEFAULT_PROJECT_PATH,
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


def _next_task_id() -> str:
    global TASK_COUNTER
    with TASK_LOCK:
        TASK_COUNTER += 1
        return f"SCAN-{_now():%Y%m%d-%H%M%S}-{TASK_COUNTER:04d}"


def _initial_steps() -> list[dict[str, str]]:
    return [{"name": name, "status": "pending", "duration": "等待中"} for name in SCAN_STEPS]


def _event(level: str, message: str) -> dict[str, str]:
    return {"time": _clock(), "level": level, "message": message}


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


def _complete_steps(task_id: str) -> None:
    with TASK_LOCK:
        task = TASKS[task_id]
        for step in task["steps"]:
            step["status"] = "done"
            if step["duration"] in {"等待中", "进行中"}:
                step["duration"] = "已完成"


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
        reports.append(
            {
                "task_id": task["task_id"],
                "name": f"{task['task_id']} 安全扫描报告",
                "target": task["target"],
                "risk": result.get("risk", {}),
                "vulnerability_total": len(result.get("vulnerabilities", [])),
                "generated_at": task.get("completed_at") or task.get("created_at"),
                "markdown_url": f"/api/report/{task['task_id']}/markdown",
                "html_url": f"/api/report/{task['task_id']}/html",
            }
        )
    return sorted(reports, key=lambda item: item.get("generated_at") or "", reverse=True)


def _task_assets() -> list[dict[str, Any]]:
    assets: dict[str, dict[str, Any]] = {}
    for task in TASKS.values():
        result = task.get("result") or {}
        risk = result.get("risk", {})
        base_url = task["target"].get("base_url", "")
        project_path = task["target"].get("project_path", "")
        if base_url:
            assets[base_url] = {
                "name": "扫描目标",
                "address": base_url,
                "type": "Web 应用",
                "risk": risk.get("overall_risk", "Low"),
                "last_scan_at": task.get("completed_at") or task.get("created_at"),
                "task_id": task["task_id"],
            }
        if project_path:
            assets[project_path] = {
                "name": "源码目录",
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
        "evidence_count": 1 if evidence else 0,
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
        _set_task_state(task_id, progress=25, current_step="动态漏洞扫描", step_index=1)
        scan_result = run_full_security_scan(
            base_url=target["base_url"],
            project_path=target["project_path"],
        )

        with TASK_LOCK:
            task = TASKS[task_id]
            normalized = _normalize_scan_result(task, scan_result)
            task["result"] = normalized
            task["errors"] = normalized.get("errors", [])
            task["completed_at"] = _timestamp()

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
    }
    with TASK_LOCK:
        TASKS[task_id] = task

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
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
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
            self._send_json(start_scan(payload), HTTPStatus.ACCEPTED)
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
        if parsed.path.startswith("/api/vulnerability/") and parsed.path.endswith("/status"):
            self._handle_vulnerability_status(parsed.path)
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
            self._send_json({"status": "ok"})
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
        if task is None or result is None:
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
        self._send_json(
            {
                "api_base_url": "/api",
                "default_base_url": SETTINGS["default_base_url"],
                "default_project_path": SETTINGS["default_project_path"],
                "storage": "memory",
            }
        )

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
        advice = generate_ai_advice(vulnerability)
        vulnerability["ai_advice"] = advice
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
    server = ThreadingHTTPServer((host, port), ScannerApiHandler)
    print(f"Scanner console running at http://{host}:{port}/")
    print(f"API health check: http://{host}:{port}/api/health")
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
