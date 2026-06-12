from __future__ import annotations

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
                "evidence": "Weak password storage pattern detected.",
                "suggestion": "Use bcrypt, argon2, or werkzeug.security.generate_password_hash.",
            }
        )

    return vulnerabilities


def run_static_scan(project_path: str) -> list[dict]:
    results: list[dict] = []
    for scanner in (test_hardcoded_secret, test_weak_password_storage):
        try:
            results.extend(scanner(project_path))
        except Exception:
            continue
    return results

