from __future__ import annotations

from scanner.ai_advisor import generate_ai_advice
from scanner.dynamic_scanner import run_dynamic_scan
from scanner.report_generator import generate_html_report, generate_markdown_report
from scanner.risk_engine import calculate_risk
from scanner.static_scanner import run_static_scan


def run_full_security_scan(base_url: str, project_path: str) -> dict:
    errors: list[str] = []
    vulnerabilities: list[dict] = []

    try:
        vulnerabilities.extend(run_dynamic_scan(base_url))
    except Exception as exc:
        errors.append(f"Dynamic scan failed: {exc}")

    try:
        vulnerabilities.extend(run_static_scan(project_path))
    except Exception as exc:
        errors.append(f"Static scan failed: {exc}")

    for index, vulnerability in enumerate(vulnerabilities, start=1):
        vulnerability["id"] = f"VULN-{index:03d}"
        try:
            vulnerability["ai_advice"] = generate_ai_advice(vulnerability)
        except Exception as exc:
            errors.append(f"AI advice failed for {vulnerability['id']}: {exc}")
            vulnerability["ai_advice"] = vulnerability.get("suggestion", "")

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
        scan_result["reports"]["markdown"] = generate_markdown_report(scan_result)
    except Exception as exc:
        errors.append(f"Markdown report generation failed: {exc}")

    try:
        scan_result["reports"]["html"] = generate_html_report(scan_result)
    except Exception as exc:
        errors.append(f"HTML report generation failed: {exc}")

    return scan_result

