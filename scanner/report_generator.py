from __future__ import annotations

from html import escape
import re


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


def _advice_to_html(advice: str) -> str:
    html_lines: list[str] = []
    in_list = False
    for raw_line in str(advice or "").splitlines():
        line = raw_line.strip()
        if not line:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            continue

        heading = re.match(r"^###\s+(.+)$", line)
        if heading:
            if in_list:
                html_lines.append("</ul>")
                in_list = False
            html_lines.append(f"<h5>{escape(heading.group(1))}</h5>")
            continue

        ordered = re.match(r"^\d+\.\s+(.+)$", line)
        bullet = re.match(r"^-\s+(.+)$", line)
        if ordered or bullet:
            if not in_list:
                html_lines.append("<ul>")
                in_list = True
            html_lines.append(f"<li>{escape((ordered or bullet).group(1))}</li>")
            continue

        if in_list:
            html_lines.append("</ul>")
            in_list = False
        html_lines.append(f"<p>{escape(line)}</p>")

    if in_list:
        html_lines.append("</ul>")
    return "\n".join(html_lines) or "<p>暂无修复建议。</p>"


def _vulnerability_sort_key(vulnerability: dict) -> tuple[str, str]:
    return (str(vulnerability.get("remediation_priority", "P3")), str(vulnerability.get("id", "")))


def generate_markdown_report(scan_result: dict) -> str:
    target = scan_result.get("target", {})
    risk = scan_result.get("risk", {})
    vulnerabilities = scan_result.get("vulnerabilities", [])

    lines = [
        "# AI 安全扫描报告",
        "",
        "## 执行摘要",
        f"本次授权本地扫描共发现 {risk.get('total', len(vulnerabilities))} 个漏洞，"
        f"总体风险为 {risk.get('overall_risk', '')}，风险评分 {risk.get('overall_score', '')}。",
        "",
        "## 1. 扫描目标",
        f"- 目标地址：{target.get('base_url', '')}",
        f"- 源码路径：{target.get('project_path', '')}",
        "",
        "## 2. 风险概览",
        f"- 总体风险：{risk.get('overall_risk', '')}",
        f"- 风险评分：{risk.get('overall_score', '')}",
        f"- 漏洞总数：{risk.get('total', len(vulnerabilities))}",
        f"- Critical：{risk.get('critical', 0)}",
        f"- High：{risk.get('high', 0)}",
        f"- Medium：{risk.get('medium', 0)}",
        f"- Low：{risk.get('low', 0)}",
        "",
    ]

    if not vulnerabilities:
        lines.append("未检测到漏洞。")
        return "\n".join(lines)

    priority_counts = _priority_counts(vulnerabilities)
    status_counts = _status_counts(vulnerabilities)
    lines.extend(
        [
            "## 3. 修复优先级",
            f"- P0 立即修复：{priority_counts.get('P0', 0)}",
            f"- P1 本轮修复：{priority_counts.get('P1', 0)}",
            f"- P2 后续排期：{priority_counts.get('P2', 0)}",
            f"- P3 持续观察：{priority_counts.get('P3', 0)}",
            "",
            "## 4. 漏洞状态",
            *[f"- {status}: {count}" for status, count in sorted(status_counts.items())],
            "",
            "## 5. 漏洞详情",
        ]
    )

    for vulnerability in sorted(vulnerabilities, key=_vulnerability_sort_key):
        lines.extend(
            [
                "",
                f"### {vulnerability.get('id', '')} - {vulnerability.get('type', '')}",
                f"- 风险等级：{vulnerability.get('risk', '')}",
                f"- 风险评分：{vulnerability.get('score', '')}",
                f"- 置信度：{vulnerability.get('confidence', 'Medium')}",
                f"- 修复优先级：{vulnerability.get('remediation_priority', 'P3')}",
                f"- 当前状态：{vulnerability.get('status', '未修复')}",
                f"- 检测方式：{vulnerability.get('method', '')}",
                f"- 请求方法：{vulnerability.get('request_method', '')}",
                f"- 影响位置：{vulnerability.get('location', '')}",
                f"- 扫描规则：{vulnerability.get('scanner_rule', '')}",
                f"- 证据摘要：{vulnerability.get('evidence', '')}",
                f"- 基础建议：{vulnerability.get('suggestion', '')}",
                f"- AI 来源：{vulnerability.get('ai_advice_source', 'unknown')}",
                "",
                "#### AI 修复建议",
                "",
                str(vulnerability.get("ai_advice", "") or "暂无修复建议。"),
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
        for vulnerability in sorted(vulnerabilities, key=_vulnerability_sort_key):
            vulnerability_sections.append(
                f"""
        <section class="vulnerability">
          <h3>{escape(str(vulnerability.get('id', '')))} - {escape(str(vulnerability.get('type', '')))}</h3>
          <ul>
            <li><strong>风险等级：</strong> {escape(str(vulnerability.get('risk', '')))}</li>
            <li><strong>风险评分：</strong> {escape(str(vulnerability.get('score', '')))}</li>
            <li><strong>置信度：</strong> {escape(str(vulnerability.get('confidence', 'Medium')))}</li>
            <li><strong>修复优先级：</strong> {escape(str(vulnerability.get('remediation_priority', 'P3')))}</li>
            <li><strong>当前状态：</strong> {escape(str(vulnerability.get('status', '未修复')))}</li>
            <li><strong>检测方式：</strong> {escape(str(vulnerability.get('method', '')))}</li>
            <li><strong>请求方法：</strong> {escape(str(vulnerability.get('request_method', '')))}</li>
            <li><strong>影响位置：</strong> {escape(str(vulnerability.get('location', '')))}</li>
            <li><strong>扫描规则：</strong> {escape(str(vulnerability.get('scanner_rule', '')))}</li>
            <li><strong>证据摘要：</strong> {escape(str(vulnerability.get('evidence', '')))}</li>
            <li><strong>基础建议：</strong> {escape(str(vulnerability.get('suggestion', '')))}</li>
            <li><strong>AI 来源：</strong> {escape(str(vulnerability.get('ai_advice_source', 'unknown')))}</li>
          </ul>
          <h4>AI 修复建议</h4>
          <div class="advice">{_advice_to_html(str(vulnerability.get('ai_advice', '')))}</div>
        </section>
"""
            )
    else:
        vulnerability_sections.append("<p>未检测到漏洞。</p>")

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>AI 安全扫描报告</title>
  <style>
    body {{
      font-family: "Microsoft YaHei", Arial, sans-serif;
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
    h1, h2, h3, h4, h5 {{
      color: #111827;
    }}
    .advice {{
      background: #fff;
      border-left: 4px solid #2563eb;
      padding: 12px 16px;
      border-radius: 4px;
    }}
    .advice h5 {{
      margin: 12px 0 6px;
      font-size: 15px;
    }}
  </style>
</head>
<body>
  <main>
    <h1>AI 安全扫描报告</h1>
    <section>
      <h2>1. 扫描目标</h2>
      <ul>
        <li><strong>目标地址：</strong> <code>{escape(str(target.get('base_url', '')))}</code></li>
        <li><strong>源码路径：</strong> <code>{escape(str(target.get('project_path', '')))}</code></li>
      </ul>
    </section>
    <section class="summary">
      <h2>2. 风险概览</h2>
      <p class="risk">{escape(str(risk.get('overall_risk', '')))} / {escape(str(risk.get('overall_score', '')))}</p>
      <p>漏洞总数：{escape(str(risk.get('total', len(vulnerabilities))))}</p>
      <p>Critical: {escape(str(risk.get('critical', 0)))}, High: {escape(str(risk.get('high', 0)))}, Medium: {escape(str(risk.get('medium', 0)))}, Low: {escape(str(risk.get('low', 0)))}</p>
      <p>修复优先级：P0 {priority_counts.get('P0', 0)}, P1 {priority_counts.get('P1', 0)}, P2 {priority_counts.get('P2', 0)}, P3 {priority_counts.get('P3', 0)}</p>
      <p>漏洞状态：{escape(', '.join(f'{status}: {count}' for status, count in sorted(status_counts.items())) or '无状态')}</p>
    </section>
    <section>
      <h2>3. 漏洞详情</h2>
      {''.join(vulnerability_sections)}
    </section>
  </main>
</body>
</html>"""
