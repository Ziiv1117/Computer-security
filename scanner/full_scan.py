from __future__ import annotations

import hashlib

from scanner.ai_advisor import generate_ai_advice_result
from scanner.dynamic_scanner import run_dynamic_scan
from scanner.report_generator import generate_html_report, generate_markdown_report
from scanner.risk_engine import calculate_risk
from scanner.static_scanner import run_static_scan


def _fingerprint(vulnerability: dict) -> str:
    basis = "|".join(
        str(vulnerability.get(key, "")).strip().lower()
        for key in ("type", "location", "request_method", "payload", "scanner_rule", "evidence")
    )
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def _confidence(vulnerability: dict) -> str:
    if vulnerability.get("method") == "SAST":
        return "Medium"
    if vulnerability.get("risk") in {"Critical", "High"} and vulnerability.get("evidence"):
        return "High"
    return "Medium"


def _deduplicate(vulnerabilities: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    risk_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    for vulnerability in vulnerabilities:
        fingerprint = vulnerability.get("fingerprint") or _fingerprint(vulnerability)
        vulnerability["fingerprint"] = fingerprint
        vulnerability["confidence"] = vulnerability.get("confidence") or _confidence(vulnerability)
        if fingerprint not in merged:
            vulnerability["evidence_count"] = int(vulnerability.get("evidence_count") or 1)
            merged[fingerprint] = vulnerability
            continue
        current = merged[fingerprint]
        current["evidence_count"] = int(current.get("evidence_count") or 1) + 1
        if int(vulnerability.get("score") or 0) > int(current.get("score") or 0):
            current["score"] = vulnerability.get("score")
        if risk_rank.get(vulnerability.get("risk"), 0) > risk_rank.get(current.get("risk"), 0):
            current["risk"] = vulnerability.get("risk")
    return list(merged.values())


def run_full_security_scan(base_url: str, project_path: str, progress_callback=None) -> dict:
    errors: list[str] = []
    vulnerabilities: list[dict] = []

    try:
        if progress_callback:
            progress_callback("INFO", "动态漏洞扫描开始")
        vulnerabilities.extend(run_dynamic_scan(base_url, progress_callback=progress_callback))
    except Exception as exc:
        errors.append(f"Dynamic scan failed: {exc}")
        if progress_callback:
            progress_callback("ERROR", f"动态漏洞扫描失败：{exc}")

    try:
        if progress_callback:
            progress_callback("INFO", "静态源码扫描开始")
        vulnerabilities.extend(run_static_scan(project_path, progress_callback=progress_callback))
    except Exception as exc:
        errors.append(f"Static scan failed: {exc}")
        if progress_callback:
            progress_callback("ERROR", f"静态源码扫描失败：{exc}")

    vulnerabilities = _deduplicate(vulnerabilities)

    for index, vulnerability in enumerate(vulnerabilities, start=1):
        vulnerability["id"] = f"VULN-{index:03d}"
        try:
            if progress_callback:
                progress_callback("INFO", f"生成修复建议：{vulnerability['id']} {vulnerability.get('type', '')}")
            advice_result = generate_ai_advice_result(vulnerability)
            vulnerability["ai_advice"] = advice_result["advice"]
            vulnerability["ai_advice_source"] = advice_result["source"]
        except Exception as exc:
            errors.append(f"AI advice failed for {vulnerability['id']}: {exc}")
            vulnerability["ai_advice"] = vulnerability.get("suggestion", "")
            vulnerability["ai_advice_source"] = "fallback-error"
            if progress_callback:
                progress_callback("WARN", f"{vulnerability['id']} 修复建议生成失败，使用兜底建议")

    risk = calculate_risk(vulnerabilities)
    scan_result = {
        "target": {
            "base_url": base_url,
            "project_path": project_path,
        },
        "risk": risk,
        "vulnerabilities": vulnerabilities,
        "reports": {
            "markdown": "",
            "html": "",
        },
        "errors": errors,
    }

    try:
        if progress_callback:
            progress_callback("INFO", "生成 Markdown 报告")
        scan_result["reports"]["markdown"] = generate_markdown_report(scan_result)
    except Exception as exc:
        errors.append(f"Markdown report generation failed: {exc}")

    try:
        if progress_callback:
            progress_callback("INFO", "生成 HTML 报告")
        scan_result["reports"]["html"] = generate_html_report(scan_result)
    except Exception as exc:
        errors.append(f"HTML report generation failed: {exc}")

    return scan_result

