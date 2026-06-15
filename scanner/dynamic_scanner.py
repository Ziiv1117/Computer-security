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
                    "request_method": "POST",
                    "payload": "admin' OR '1'='1' --",
                    "scanner_rule": "dast.sql_injection.login_bypass",
                    "remediation_priority": "P0",
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
                    "request_method": "POST/GET",
                    "payload": payload,
                    "scanner_rule": "dast.xss.stored_comment",
                    "remediation_priority": "P1",
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
                        "request_method": "GET",
                        "payload": "user1 / 123456",
                        "scanner_rule": "dast.access_control.admin_role",
                        "remediation_priority": "P0",
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
                        "request_method": "GET",
                        "payload": "user1 session -> /profile/2",
                        "scanner_rule": "dast.access_control.object_ownership",
                        "remediation_priority": "P1",
                        "evidence": "Normal user can access another user's profile page.",
                        "suggestion": "Check object ownership before returning user-specific resources.",
                    }
                )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def test_csrf(base_url: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    login_url = _endpoint(base_url, "/login")
    transfer_url = _endpoint(base_url, "/transfer")

    try:
        with requests.Session() as session:
            session.post(
                login_url,
                data={"username": "user1", "password": "123456"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            form_response = session.get(transfer_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            submit_response = session.post(
                transfer_url,
                data={"to_user": "user2", "amount": "1", "note": "scanner-csrf-check"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )

        form_text = form_response.text.lower()
        submit_text = submit_response.text.lower()
        missing_token = all(
            token_marker not in form_text
            for token_marker in (
                'name="csrf"',
                "name='csrf'",
                'name="csrf_token"',
                "name='csrf_token'",
                'name="_csrf"',
                "name='_csrf'",
            )
        )
        submitted = submit_response.status_code == 200 and (
            "transfer submitted" in submit_text or "scanner-csrf-check" in submit_text
        )
        if missing_token and submitted:
            vulnerabilities.append(
                {
                    "type": "Cross-Site Request Forgery",
                    "category": "Authentication and Authorization",
                    "risk": "High",
                    "score": 75,
                    "location": "/transfer",
                    "method": "DAST",
                    "request_method": "POST",
                    "payload": "to_user=user2&amount=1",
                    "scanner_rule": "dast.csrf.transfer_without_token",
                    "remediation_priority": "P1",
                    "evidence": "Authenticated transfer form accepted a state-changing POST without a CSRF token.",
                    "suggestion": "Add CSRF tokens, SameSite cookies, and server-side validation for state-changing requests.",
                }
            )
    except (requests.RequestException, ValueError):
        return vulnerabilities

    return vulnerabilities


def test_path_traversal(base_url: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    download_url = _endpoint(base_url, "/download")

    try:
        response = requests.get(
            download_url,
            params={"file": "../app.py"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        if response.status_code == 200 and ("SECRET_KEY" in response.text or "@app." in response.text):
            vulnerabilities.append(
                {
                    "type": "Path Traversal",
                    "category": "File and Path Security",
                    "risk": "High",
                    "score": 80,
                    "location": "/download?file=../app.py",
                    "method": "DAST",
                    "request_method": "GET",
                    "payload": "../app.py",
                    "scanner_rule": "dast.path_traversal.download_file",
                    "remediation_priority": "P1",
                    "evidence": "Download endpoint returned content from a parent-directory source file.",
                    "suggestion": "Normalize paths and enforce that requested files stay inside an allowlisted directory.",
                }
            )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def test_ssrf(base_url: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    fetch_url = _endpoint(base_url, "/fetch")
    health_url = _endpoint(base_url, "/health")

    try:
        response = requests.get(
            fetch_url,
            params={"url": health_url},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        text = response.text.lower()
        if response.status_code == 200 and ("vulnerable-app" in text or '"status"' in text):
            vulnerabilities.append(
                {
                    "type": "Server-Side Request Forgery",
                    "category": "Network Security",
                    "risk": "High",
                    "score": 85,
                    "location": "/fetch?url=http://127.0.0.1:5001/health",
                    "method": "DAST",
                    "request_method": "GET",
                    "payload": health_url,
                    "scanner_rule": "dast.ssrf.localhost_fetch",
                    "remediation_priority": "P0",
                    "evidence": "Server-side fetch endpoint retrieved a localhost URL supplied by the user.",
                    "suggestion": "Restrict outbound fetch targets with protocol, hostname, and IP range allowlists.",
                }
            )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def test_open_redirect(base_url: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    redirect_url = _endpoint(base_url, "/redirect")
    external_url = "https://example.com/security-lab"

    try:
        response = requests.get(
            redirect_url,
            params={"next": external_url},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        if response.status_code in (301, 302, 303, 307, 308) and response.headers.get("Location") == external_url:
            vulnerabilities.append(
                {
                    "type": "Open Redirect",
                    "category": "Input Validation",
                    "risk": "Medium",
                    "score": 60,
                    "location": "/redirect?next=https://example.com/security-lab",
                    "method": "DAST",
                    "request_method": "GET",
                    "payload": external_url,
                    "scanner_rule": "dast.open_redirect.external_location",
                    "remediation_priority": "P2",
                    "evidence": "Redirect endpoint accepted an absolute external URL from user input.",
                    "suggestion": "Only allow relative redirect paths or enforce a strict trusted-domain allowlist.",
                }
            )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def test_mass_assignment(base_url: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    login_url = _endpoint(base_url, "/login")
    settings_url = _endpoint(base_url, "/settings")
    admin_url = _endpoint(base_url, "/admin")

    try:
        with requests.Session() as session:
            session.post(
                login_url,
                data={"username": "user1", "password": "123456"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            response = session.post(
                settings_url,
                data={
                    "email": "user1@example.com",
                    "note": "scanner-mass-assignment-check",
                    "role": "admin",
                    "plain_password": "123456",
                },
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            admin_response = session.get(admin_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)

        if response.status_code == 200 and admin_response.status_code == 200 and "admin dashboard" in admin_response.text.lower():
            vulnerabilities.append(
                {
                    "type": "Mass Assignment",
                    "category": "Authentication and Authorization",
                    "risk": "High",
                    "score": 80,
                    "location": "/settings",
                    "method": "DAST",
                    "request_method": "POST",
                    "payload": "role=admin",
                    "scanner_rule": "dast.mass_assignment.role_update",
                    "remediation_priority": "P0",
                    "evidence": "Normal user submitted role=admin and gained access to the admin page.",
                    "suggestion": "Use explicit field allowlists and never accept privilege fields from user-controlled forms.",
                }
            )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def test_information_disclosure(base_url: str) -> list[dict]:
    vulnerabilities: list[dict] = []
    debug_url = _endpoint(base_url, "/debug/config")

    try:
        response = requests.get(debug_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        text = response.text.lower()
        if response.status_code == 200 and ("secret_key" in text or "db_password" in text or "plain_password" in text):
            vulnerabilities.append(
                {
                    "type": "Information Disclosure",
                    "category": "Configuration Security",
                    "risk": "High",
                    "score": 75,
                    "location": "/debug/config",
                    "method": "DAST",
                    "request_method": "GET",
                    "payload": "/debug/config",
                    "scanner_rule": "dast.information_disclosure.debug_config",
                    "remediation_priority": "P1",
                    "evidence": "Unauthenticated debug endpoint exposed configuration or user data fields.",
                    "suggestion": "Disable debug endpoints in production and require authorization for sensitive diagnostics.",
                }
            )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def run_dynamic_scan(base_url: str, progress_callback=None) -> list[dict]:
    results: list[dict] = []
    scanners = (
        test_sql_injection,
        test_xss,
        test_broken_access_control,
        test_csrf,
        test_path_traversal,
        test_ssrf,
        test_open_redirect,
        test_mass_assignment,
        test_information_disclosure,
    )
    for scanner in scanners:
        try:
            if progress_callback:
                progress_callback("INFO", f"开始动态规则：{scanner.__name__}")
            found = scanner(base_url)
            results.extend(found)
            if progress_callback:
                level = "RISK" if found else "INFO"
                progress_callback(level, f"动态规则 {scanner.__name__} 完成，发现 {len(found)} 个问题")
        except Exception:
            if progress_callback:
                progress_callback("WARN", f"动态规则 {scanner.__name__} 执行失败，已跳过")
            continue
    return results

