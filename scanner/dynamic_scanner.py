from __future__ import annotations

from urllib.parse import urljoin

import requests


REQUEST_TIMEOUT = 5


def _endpoint(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _looks_like_success(response: requests.Response, login_path: str = "/login") -> bool:
    text = response.text.lower()
    success_keywords = ("welcome", "dashboard", "logout", "success")
    if any(keyword in text for keyword in success_keywords):
        return True
    if response.status_code in (301, 302, 303, 307, 308):
        return True
    if response.url and login_path not in response.url.lower():
        return True
    return False


def test_sql_injection(base_url: str) -> list[dict]:
    """Detect login bypass through a basic SQL injection payload."""
    vulnerabilities: list[dict] = []
    login_url = _endpoint(base_url, "/login")

    try:
        with requests.Session() as session:
            wrong_response = session.post(
                login_url,
                data={"username": "admin", "password": "wrong_password"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            injection_response = session.post(
                login_url,
                data={"username": "admin' OR '1'='1' --", "password": "anything"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

        wrong_login_failed = not _looks_like_success(wrong_response)
        injection_login_succeeded = _looks_like_success(injection_response)

        if wrong_login_failed and injection_login_succeeded:
            vulnerabilities.append(
                {
                    "type": "SQL Injection",
                    "category": "Input Validation",
                    "risk": "Critical",
                    "score": 95,
                    "location": "/login",
                    "method": "DAST",
                    "evidence": "SQL injection payload caused login bypass.",
                    "suggestion": "Use parameterized queries instead of string concatenation.",
                }
            )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def test_xss(base_url: str) -> list[dict]:
    """Detect stored or reflected XSS in the comments page."""
    vulnerabilities: list[dict] = []
    comments_url = _endpoint(base_url, "/comments")
    payload = "<script>alert('xss-test')</script>"

    try:
        with requests.Session() as session:
            session.post(
                comments_url,
                data={"comment": payload, "content": payload, "message": payload},
                timeout=REQUEST_TIMEOUT,
            )
            response = session.get(comments_url, timeout=REQUEST_TIMEOUT)

        if payload in response.text:
            vulnerabilities.append(
                {
                    "type": "Cross-Site Scripting",
                    "category": "Input Validation",
                    "risk": "High",
                    "score": 75,
                    "location": "/comments",
                    "method": "DAST",
                    "evidence": "Script tag was reflected without escaping.",
                    "suggestion": "Escape user input before rendering it into HTML.",
                }
            )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def test_broken_access_control(base_url: str) -> list[dict]:
    """Detect whether a normal user can access privileged pages."""
    vulnerabilities: list[dict] = []
    login_url = _endpoint(base_url, "/login")
    admin_url = _endpoint(base_url, "/admin")

    try:
        with requests.Session() as session:
            session.post(
                login_url,
                data={"username": "user1", "password": "123456"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            admin_response = session.get(admin_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)

            admin_text = admin_response.text.lower()
            admin_keywords = ("admin", "dashboard", "manage")
            if admin_response.status_code == 200 and any(
                keyword in admin_text for keyword in admin_keywords
            ):
                vulnerabilities.append(
                    {
                        "type": "Broken Access Control",
                        "category": "Authentication and Authorization",
                        "risk": "Critical",
                        "score": 90,
                        "location": "/admin",
                        "method": "DAST",
                        "evidence": "Normal user can access admin page.",
                        "suggestion": "Add role-based access control and verify permissions on sensitive routes.",
                    }
                )

            profile_url = _endpoint(base_url, "/profile/2")
            profile_response = session.get(profile_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            profile_text = profile_response.text.lower()
            if profile_response.status_code == 200 and (
                "user2" in profile_text or "profile" in profile_text
            ):
                vulnerabilities.append(
                    {
                        "type": "Broken Access Control",
                        "category": "Authentication and Authorization",
                        "risk": "High",
                        "score": 80,
                        "location": "/profile/2",
                        "method": "DAST",
                        "evidence": "Normal user can access another user's profile page.",
                        "suggestion": "Check object ownership before returning user-specific resources.",
                    }
                )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def run_dynamic_scan(base_url: str) -> list[dict]:
    results: list[dict] = []
    for scanner in (test_sql_injection, test_xss, test_broken_access_control):
        try:
            results.extend(scanner(base_url))
        except Exception:
            continue
    return results

