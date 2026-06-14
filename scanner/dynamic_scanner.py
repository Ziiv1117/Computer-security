from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse

import requests


REQUEST_TIMEOUT = 5
MAX_CRAWL_PAGES = 25


class DiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "a" and values.get("href"):
            self.links.add(values["href"])
            return
        if tag.lower() == "form":
            self._current_form = {
                "action": values.get("action", ""),
                "method": (values.get("method") or "GET").upper(),
                "inputs": [],
            }
            return
        if tag.lower() in {"input", "textarea", "select"} and self._current_form is not None:
            name = values.get("name") or values.get("id")
            if name:
                self._current_form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _endpoint(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    parsed = urlparse(candidate)
    return parsed.scheme in {"http", "https"} and parsed.netloc == base.netloc


def _path_with_query(url: str) -> str:
    parsed = urlparse(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def discover_site(base_url: str, max_pages: int = MAX_CRAWL_PAGES) -> dict:
    """Crawl same-origin pages and collect routes, forms, and query parameters."""
    discovered = {
        "routes": [],
        "forms": [],
        "parameters": [],
    }
    base = base_url.rstrip("/") + "/"
    queue = [base]
    seen: set[str] = set()
    routes: set[str] = set()
    parameters: set[tuple[str, str]] = set()
    forms: list[dict] = []

    with requests.Session() as session:
        while queue and len(seen) < max_pages:
            url = queue.pop(0)
            if url in seen or not _same_origin(base_url, url):
                continue
            seen.add(url)
            try:
                response = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            except requests.RequestException:
                continue
            if "text/html" not in response.headers.get("content-type", "") and "<html" not in response.text.lower():
                continue

            current_path = _path_with_query(response.url)
            routes.add(current_path or "/")
            for name, _value in parse_qsl(urlparse(response.url).query, keep_blank_values=True):
                parameters.add((urlparse(response.url).path or "/", name))

            parser = DiscoveryParser()
            parser.feed(response.text)
            for href in parser.links:
                absolute = urljoin(response.url, href)
                if _same_origin(base_url, absolute):
                    route = _path_with_query(absolute)
                    routes.add(route or "/")
                    for name, _value in parse_qsl(urlparse(absolute).query, keep_blank_values=True):
                        parameters.add((urlparse(absolute).path or "/", name))
                    if absolute not in seen and len(seen) + len(queue) < max_pages:
                        queue.append(absolute)

            for form in parser.forms:
                action_url = urljoin(response.url, form.get("action") or response.url)
                if not _same_origin(base_url, action_url):
                    continue
                form_record = {
                    "path": urlparse(action_url).path or "/",
                    "method": form.get("method") or "GET",
                    "inputs": sorted(set(form.get("inputs") or [])),
                    "source": current_path or "/",
                }
                forms.append(form_record)
                routes.add(form_record["path"])
                for name in form_record["inputs"]:
                    parameters.add((form_record["path"], name))

    discovered["routes"] = sorted(routes)
    discovered["forms"] = forms
    discovered["parameters"] = [
        {"path": path, "name": name} for path, name in sorted(parameters)
    ]
    return discovered


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


def test_sql_injection(base_url: str, discovery: dict | None = None) -> list[dict]:
    """Detect login bypass through a basic SQL injection payload."""
    vulnerabilities: list[dict] = []
    login_forms = [
        form
        for form in (discovery or {}).get("forms", [])
        if "login" in form.get("path", "").lower()
        or {"username", "password"}.issubset(set(form.get("inputs") or []))
    ] or [{"path": "/login", "inputs": ["username", "password"]}]

    with requests.Session() as session:
        for form in login_forms:
            login_path = form.get("path") or "/login"
            login_url = _endpoint(base_url, login_path)
            username_field = "username" if "username" in form.get("inputs", []) else (form.get("inputs") or ["username"])[0]
            password_field = "password" if "password" in form.get("inputs", []) else "password"
            try:
                wrong_response = session.post(
                    login_url,
                    data={username_field: "admin", password_field: "wrong_password"},
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )

                injection_response = session.post(
                    login_url,
                    data={username_field: "admin' OR '1'='1' --", password_field: "anything"},
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
            except requests.RequestException:
                continue

            wrong_login_failed = not _looks_like_success(wrong_response, login_path)
            injection_login_succeeded = _looks_like_success(injection_response, login_path)

            if wrong_login_failed and injection_login_succeeded:
                vulnerabilities.append(
                    {
                        "type": "SQL Injection",
                        "category": "Input Validation",
                        "risk": "Critical",
                        "score": 95,
                        "location": login_path,
                        "method": "DAST",
                        "evidence": "SQL injection payload caused login bypass.",
                        "suggestion": "Use parameterized queries instead of string concatenation.",
                        "confidence": "High",
                    }
                )
                break

    return vulnerabilities


def test_xss(base_url: str, discovery: dict | None = None) -> list[dict]:
    """Detect stored or reflected XSS in discovered forms and comment pages."""
    vulnerabilities: list[dict] = []
    payload = "<script>alert('xss-test')</script>"
    forms = [
        form
        for form in (discovery or {}).get("forms", [])
        if form.get("inputs")
        and any(keyword in " ".join([form.get("path", ""), *form.get("inputs", [])]).lower() for keyword in ("comment", "message", "content", "search", "q"))
    ] or [{"path": "/comments", "method": "POST", "inputs": ["comment", "content", "message"]}]

    with requests.Session() as session:
        for form in forms:
            path = form.get("path") or "/comments"
            url = _endpoint(base_url, path)
            inputs = form.get("inputs") or ["comment"]
            data = {name: payload for name in inputs}
            try:
                posted = False
                if (form.get("method") or "POST").upper() == "POST":
                    session.post(
                        url,
                        data=data,
                        timeout=REQUEST_TIMEOUT,
                    )
                    posted = True
                response = session.get(url, params=None if posted else data, timeout=REQUEST_TIMEOUT)
            except requests.RequestException:
                continue

            if payload in response.text:
                vulnerabilities.append(
                    {
                        "type": "Cross-Site Scripting",
                        "category": "Input Validation",
                        "risk": "High",
                        "score": 75,
                        "location": path,
                        "method": "DAST",
                        "evidence": "Script tag was reflected without escaping.",
                        "suggestion": "Escape user input before rendering it into HTML.",
                        "confidence": "High",
                    }
                )
    return vulnerabilities


def test_broken_access_control(base_url: str, discovery: dict | None = None) -> list[dict]:
    """Detect whether a normal user can access privileged pages."""
    vulnerabilities: list[dict] = []
    login_url = _endpoint(base_url, "/login")
    protected_paths = {
        "/admin",
        "/profile/2",
        *[
            route
            for route in (discovery or {}).get("routes", [])
            if any(keyword in route.lower() for keyword in ("admin", "manage", "profile", "user/"))
        ],
    }

    try:
        with requests.Session() as session:
            session.post(
                login_url,
                data={"username": "user1", "password": "123456"},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
            )
            for protected_path in sorted(protected_paths):
                response = session.get(_endpoint(base_url, protected_path), timeout=REQUEST_TIMEOUT, allow_redirects=True)
                text = response.text.lower()
                if response.status_code != 200:
                    continue
                if "admin" in protected_path.lower() and any(keyword in text for keyword in ("admin", "dashboard", "manage")):
                    vulnerabilities.append(
                        {
                            "type": "Broken Access Control",
                            "category": "Authentication and Authorization",
                            "risk": "Critical",
                            "score": 90,
                            "location": protected_path,
                            "method": "DAST",
                            "evidence": "Normal user can access privileged page.",
                            "suggestion": "Add role-based access control and verify permissions on sensitive routes.",
                            "confidence": "Medium",
                        }
                    )
                elif "profile" in protected_path.lower() and ("user2" in text or "profile" in text):
                    vulnerabilities.append(
                        {
                            "type": "Broken Access Control",
                            "category": "Authentication and Authorization",
                            "risk": "High",
                            "score": 80,
                            "location": protected_path,
                            "method": "DAST",
                            "evidence": "Normal user can access another user's profile page.",
                            "suggestion": "Check object ownership before returning user-specific resources.",
                            "confidence": "Medium",
                        }
                    )
    except requests.RequestException:
        return vulnerabilities

    return vulnerabilities


def test_route_discovery(base_url: str, discovery: dict | None = None) -> list[dict]:
    vulnerabilities: list[dict] = []
    for route in (discovery or {}).get("routes", []):
        if any(keyword in route.lower() for keyword in ("debug", "backup", ".env", "config")):
            vulnerabilities.append(
                {
                    "type": "Sensitive Route Exposure",
                    "category": "Configuration",
                    "risk": "Medium",
                    "score": 55,
                    "location": route,
                    "method": "DAST",
                    "evidence": "Crawler found a route name that may expose sensitive debug or configuration data.",
                    "suggestion": "Restrict debug/config routes and remove backup artifacts from web root.",
                    "confidence": "Low",
                }
            )
    return vulnerabilities


def run_dynamic_scan(base_url: str) -> dict:
    discovery = discover_site(base_url)
    results: list[dict] = []
    for scanner in (test_sql_injection, test_xss, test_broken_access_control, test_route_discovery):
        try:
            results.extend(scanner(base_url, discovery))
        except Exception:
            continue
    return {"vulnerabilities": results, "discovery": discovery}

