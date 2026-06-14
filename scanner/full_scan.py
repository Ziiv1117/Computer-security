from __future__ import annotations

import hashlib

from scanner.ai_advisor import generate_ai_advice
from scanner.dynamic_scanner import run_dynamic_scan
from scanner.report_generator import generate_html_report, generate_markdown_report
from scanner.risk_engine import calculate_risk
from scanner.static_scanner import run_static_scan


def _fingerprint(vulnerability: dict) -> str:
    basis = "|".join(
        str(vulnerability.get(key, "")).strip().lower()
        for key in ("type", "location", "method", "evidence")
    )
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def _deduplicate(vulnerabilities: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    risk_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    confidence_rank = {"low": 1, "medium": 2, "high": 3}

    for vulnerability in vulnerabilities:
        fingerprint = str(vulnerability.get("fingerprint") or _fingerprint(vulnerability))
        vulnerability["fingerprint"] = fingerprint
        vulnerability["confidence"] = str(vulnerability.get("confidence") or "Medium")
        if fingerprint not in merged:
            vulnerability["evidence_count"] = int(vulnerability.get("evidence_count") or 1)
            merged[fingerprint] = vulnerability
            continue

        current = merged[fingerprint]
        current["evidence_count"] = int(current.get("evidence_count") or 1) + 1
        if int(vulnerability.get("score") or 0) > int(current.get("score") or 0):
            current["score"] = vulnerability.get("score")
        if risk_rank.get(str(vulnerability.get("risk", "")).lower(), 0) > risk_rank.get(str(current.get("risk", "")).lower(), 0):
            current["risk"] = vulnerability.get("risk")
        if confidence_rank.get(str(vulnerability.get("confidence", "")).lower(), 0) > confidence_rank.get(str(current.get("confidence", "")).lower(), 0):
            current["confidence"] = vulnerability.get("confidence")

    return list(merged.values())


def run_full_security_scan(base_url: str, project_path: str, progress_callback=None) -> dict:
    errors: list[str] = []
    vulnerabilities: list[dict] = []
    discovery: dict = {"routes": [], "forms": [], "parameters": []}

    try:
        if progress_callback:
            progress_callback("站点爬取与动态扫描", 28, 1)
        dynamic_result = run_dynamic_scan(base_url)
        if isinstance(dynamic_result, dict):
            vulnerabilities.extend(dynamic_result.get("vulnerabilities", []))
            discovery = dynamic_result.get("discovery") or discovery
        else:
            vulnerabilities.extend(dynamic_result)
        if progress_callback:
            progress_callback("动态漏洞扫描完成", 46, 3)
    except Exception as exc:
        errors.append(f"Dynamic scan failed: {exc}")

    try:
        if progress_callback:
            progress_callback("静态源码扫描", 56, 4)
        vulnerabilities.extend(run_static_scan(project_path))
        if progress_callback:
            progress_callback("静态源码扫描完成", 66, 4)
    except Exception as exc:
        errors.append(f"Static scan failed: {exc}")

    vulnerabilities = _deduplicate(vulnerabilities)

    if progress_callback:
        progress_callback("AI 修复建议", 72, 5)
    for index, vulnerability in enumerate(vulnerabilities, start=1):
        vulnerability["id"] = f"VULN-{index:03d}"
        try:
            vulnerability["ai_advice"] = generate_ai_advice(vulnerability)
        except Exception as exc:
            errors.append(f"AI advice failed for {vulnerability['id']}: {exc}")
            vulnerability["ai_advice"] = vulnerability.get("suggestion", "")
        if progress_callback:
            ai_progress = 72 + int(12 * index / max(1, len(vulnerabilities)))
            progress_callback(f"AI 修复建议 {index}/{len(vulnerabilities)}", ai_progress, 5)

    if progress_callback:
        progress_callback("风险评分", 86, 5)
    risk = calculate_risk(vulnerabilities)
    scan_result = {
        "target": {
            "base_url": base_url,
            "project_path": project_path,
        },
        "risk": risk,
        "vulnerabilities": vulnerabilities,
        "discovery": discovery,
        "reports": {
            "markdown": "",
            "html": "",
        },
        "errors": errors,
    }

    try:
        if progress_callback:
            progress_callback("生成 Markdown 报告", 92, 6)
        scan_result["reports"]["markdown"] = generate_markdown_report(scan_result)
    except Exception as exc:
        errors.append(f"Markdown report generation failed: {exc}")

    try:
        if progress_callback:
            progress_callback("生成 HTML 报告", 96, 6)
        scan_result["reports"]["html"] = generate_html_report(scan_result)
    except Exception as exc:
        errors.append(f"HTML report generation failed: {exc}")

    return scan_result

