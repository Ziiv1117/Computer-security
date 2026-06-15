from __future__ import annotations

from scanner.ai_advisor import generate_ai_advice_result
from scanner.dynamic_scanner import run_dynamic_scan
from scanner.report_generator import generate_html_report, generate_markdown_report
from scanner.risk_engine import calculate_risk
from scanner.static_scanner import run_static_scan


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

