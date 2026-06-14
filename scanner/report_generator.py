from __future__ import annotations

from html import escape


def generate_markdown_report(scan_result: dict) -> str:
    target = scan_result.get("target", {})
    risk = scan_result.get("risk", {})
    vulnerabilities = scan_result.get("vulnerabilities", [])

    lines = [
        "# Security Scan Report",
        "",
        "## 1. Target",
        f"- Base URL: {target.get('base_url', '')}",
        f"- Project Path: {target.get('project_path', '')}",
        "",
        "## 2. Overall Risk",
        f"- Risk: {risk.get('overall_risk', '')}",
        f"- Score: {risk.get('overall_score', '')}",
        f"- Total Vulnerabilities: {risk.get('total', len(vulnerabilities))}",
        "",
        "## 3. Vulnerabilities",
    ]

    if not vulnerabilities:
        lines.append("")
        lines.append("No vulnerabilities were detected.")
        return "\n".join(lines)

    for vulnerability in vulnerabilities:
        lines.extend(
            [
                "",
                f"### {vulnerability.get('id', '')} - {vulnerability.get('type', '')}",
                f"- Category: {vulnerability.get('category', '')}",
                f"- Risk: {vulnerability.get('risk', '')}",
                f"- Score: {vulnerability.get('score', '')}",
                f"- Method: {vulnerability.get('method', '')}",
                f"- Location: {vulnerability.get('location', '')}",
                f"- Evidence: {vulnerability.get('evidence', '')}",
                f"- Suggestion: {vulnerability.get('suggestion', '')}",
                "- AI Advice:",
                "",
                str(vulnerability.get("ai_advice", "")),
            ]
        )

    return "\n".join(lines)


def generate_html_report(scan_result: dict) -> str:
    target = scan_result.get("target", {})
    risk = scan_result.get("risk", {})
    vulnerabilities = scan_result.get("vulnerabilities", [])

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
            <li><strong>Method:</strong> {escape(str(vulnerability.get('method', '')))}</li>
            <li><strong>Location:</strong> {escape(str(vulnerability.get('location', '')))}</li>
            <li><strong>Evidence:</strong> {escape(str(vulnerability.get('evidence', '')))}</li>
            <li><strong>Suggestion:</strong> {escape(str(vulnerability.get('suggestion', '')))}</li>
          </ul>
          <h4>AI Advice</h4>
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
    </section>
    <section>
      <h2>3. Vulnerabilities</h2>
      {''.join(vulnerability_sections)}
    </section>
  </main>
</body>
</html>"""

