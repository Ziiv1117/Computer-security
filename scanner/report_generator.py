from __future__ import annotations

from html import escape


def _priority_counts(vulnerabilities: list[dict]) -> dict[str, int]:
    counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for vulnerability in vulnerabilities:
        priority = str(vulnerability.get("remediation_priority") or "P3")
        counts[priority] = counts.get(priority, 0) + 1
    return counts


def _status_counts(vulnerabilities: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for vulnerability in vulnerabilities:
        status = str(vulnerability.get("status") or "未修复")
        counts[status] = counts.get(status, 0) + 1
    return counts


def generate_markdown_report(scan_result: dict) -> str:
    target = scan_result.get("target", {})
    risk = scan_result.get("risk", {})
    vulnerabilities = scan_result.get("vulnerabilities", [])

    lines = [
        "# Security Scan Report",
        "",
        "## Executive Summary",
        f"This local authorized scan found {risk.get('total', len(vulnerabilities))} vulnerabilities. "
        f"The overall risk is {risk.get('overall_risk', '')} with score {risk.get('overall_score', '')}.",
        "",
        "## 1. Target",
        f"- Base URL: {target.get('base_url', '')}",
        f"- Project Path: {target.get('project_path', '')}",
        "",
        "## 2. Overall Risk",
        f"- Risk: {risk.get('overall_risk', '')}",
        f"- Score: {risk.get('overall_score', '')}",
        f"- Total Vulnerabilities: {risk.get('total', len(vulnerabilities))}",
        f"- Critical: {risk.get('critical', 0)}",
        f"- High: {risk.get('high', 0)}",
        f"- Medium: {risk.get('medium', 0)}",
        f"- Low: {risk.get('low', 0)}",
        "",
    ]

    if not vulnerabilities:
        lines.append("")
        lines.append("No vulnerabilities were detected.")
        return "\n".join(lines)

    priority_counts = _priority_counts(vulnerabilities)
    status_counts = _status_counts(vulnerabilities)
    lines.extend(
        [
            "## 3. Remediation Plan",
            f"- P0 Immediate: {priority_counts.get('P0', 0)}",
            f"- P1 This iteration: {priority_counts.get('P1', 0)}",
            f"- P2 Backlog: {priority_counts.get('P2', 0)}",
            f"- P3 Monitor: {priority_counts.get('P3', 0)}",
            "",
            "## 4. Vulnerability Status",
            *[f"- {status}: {count}" for status, count in sorted(status_counts.items())],
            "",
            "## 5. Vulnerabilities",
        ]
    )

    for vulnerability in sorted(vulnerabilities, key=lambda item: str(item.get("remediation_priority", "P3"))):
        lines.extend(
            [
                "",
                f"### {vulnerability.get('id', '')} - {vulnerability.get('type', '')}",
                f"- Category: {vulnerability.get('category', '')}",
                f"- Risk: {vulnerability.get('risk', '')}",
                f"- Score: {vulnerability.get('score', '')}",
                f"- Confidence: {vulnerability.get('confidence', 'Medium')}",
                f"- Fingerprint: {vulnerability.get('fingerprint', '')}",
                f"- Priority: {vulnerability.get('remediation_priority', 'P3')}",
                f"- Status: {vulnerability.get('status', '未修复')}",
                f"- Method: {vulnerability.get('method', '')}",
                f"- Request Method: {vulnerability.get('request_method', '')}",
                f"- Location: {vulnerability.get('location', '')}",
                f"- Scanner Rule: {vulnerability.get('scanner_rule', '')}",
                f"- Payload: {vulnerability.get('payload', '')}",
                f"- Evidence: {vulnerability.get('evidence', '')}",
                f"- Suggestion: {vulnerability.get('suggestion', '')}",
                f"- Advice Source: {vulnerability.get('ai_advice_source', 'unknown')}",
                "- Remediation Advice:",
                "",
                str(vulnerability.get("ai_advice", "")),
            ]
        )

    return "\n".join(lines)


def generate_html_report(scan_result: dict) -> str:
    target = scan_result.get("target", {})
    risk = scan_result.get("risk", {})
    vulnerabilities = scan_result.get("vulnerabilities", [])
    priority_counts = _priority_counts(vulnerabilities)
    status_counts = _status_counts(vulnerabilities)

    vulnerability_sections = []
    if vulnerabilities:
        for vulnerability in vulnerabilities:
            vulnerability_sections.append(
                f"""
        <section class="vulnerability">
          <h3>{escape(str(vulnerability.get('id', '')))} - {escape(str(vulnerability.get('type', '')))}</h3>
          <ul>
            <li><strong>Category:</strong> {escape(str(vulnerability.get('category', '')))}</li>
            <li><strong>Risk:</strong> {escape(str(vulnerability.get('risk', '')))}</li>
            <li><strong>Score:</strong> {escape(str(vulnerability.get('score', '')))}</li>
            <li><strong>Confidence:</strong> {escape(str(vulnerability.get('confidence', 'Medium')))}</li>
            <li><strong>Fingerprint:</strong> {escape(str(vulnerability.get('fingerprint', '')))}</li>
            <li><strong>Priority:</strong> {escape(str(vulnerability.get('remediation_priority', 'P3')))}</li>
            <li><strong>Status:</strong> {escape(str(vulnerability.get('status', '未修复')))}</li>
            <li><strong>Method:</strong> {escape(str(vulnerability.get('method', '')))}</li>
            <li><strong>Request Method:</strong> {escape(str(vulnerability.get('request_method', '')))}</li>
            <li><strong>Location:</strong> {escape(str(vulnerability.get('location', '')))}</li>
            <li><strong>Scanner Rule:</strong> {escape(str(vulnerability.get('scanner_rule', '')))}</li>
            <li><strong>Payload:</strong> {escape(str(vulnerability.get('payload', '')))}</li>
            <li><strong>Evidence:</strong> {escape(str(vulnerability.get('evidence', '')))}</li>
            <li><strong>Suggestion:</strong> {escape(str(vulnerability.get('suggestion', '')))}</li>
            <li><strong>Advice Source:</strong> {escape(str(vulnerability.get('ai_advice_source', 'unknown')))}</li>
          </ul>
          <h4>Remediation Advice</h4>
          <p>{escape(str(vulnerability.get('ai_advice', ''))).replace(chr(10), '<br>')}</p>
        </section>
"""
            )
    else:
        vulnerability_sections.append("<p>No vulnerabilities were detected.</p>")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Scan Report</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      line-height: 1.6;
      margin: 32px;
      color: #222;
      background: #f7f7f7;
    }}
    main {{
      max-width: 960px;
      margin: 0 auto;
      background: #fff;
      padding: 24px;
      border: 1px solid #ddd;
      border-radius: 6px;
    }}
    .summary, .vulnerability {{
      border: 1px solid #ddd;
      border-radius: 6px;
      padding: 16px;
      margin: 16px 0;
      background: #fafafa;
    }}
    .risk {{
      font-weight: bold;
      color: #b00020;
    }}
    code {{
      background: #eee;
      padding: 2px 4px;
      border-radius: 3px;
    }}
  </style>
</head>
<body>
  <main>
    <h1>Security Scan Report</h1>
    <section>
      <h2>1. Target</h2>
      <ul>
        <li><strong>Base URL:</strong> <code>{escape(str(target.get('base_url', '')))}</code></li>
        <li><strong>Project Path:</strong> <code>{escape(str(target.get('project_path', '')))}</code></li>
      </ul>
    </section>
    <section class="summary">
      <h2>2. Overall Risk</h2>
      <p class="risk">{escape(str(risk.get('overall_risk', '')))} / {escape(str(risk.get('overall_score', '')))}</p>
      <p>Total Vulnerabilities: {escape(str(risk.get('total', len(vulnerabilities))))}</p>
      <p>Critical: {escape(str(risk.get('critical', 0)))}, High: {escape(str(risk.get('high', 0)))}, Medium: {escape(str(risk.get('medium', 0)))}, Low: {escape(str(risk.get('low', 0)))}</p>
      <p>Priorities: P0 {priority_counts.get('P0', 0)}, P1 {priority_counts.get('P1', 0)}, P2 {priority_counts.get('P2', 0)}, P3 {priority_counts.get('P3', 0)}</p>
      <p>Status: {escape(', '.join(f'{status}: {count}' for status, count in sorted(status_counts.items())) or 'No status')}</p>
    </section>
    <section>
      <h2>3. Vulnerabilities</h2>
      {''.join(vulnerability_sections)}
    </section>
  </main>
</body>
</html>"""

