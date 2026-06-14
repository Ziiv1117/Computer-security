from __future__ import annotations

import argparse
from pathlib import Path

from scanner.ai_advisor import load_env_file
from scanner.full_scan import run_full_security_scan


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local web security scanner.")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:5001",
        help="Base URL of the local vulnerable web app.",
    )
    parser.add_argument(
        "--project-path",
        default="./vulnerable_app",
        help="Source directory of the vulnerable web app.",
    )
    parser.add_argument(
        "--markdown",
        default="security_report.md",
        help="Output path for the Markdown report.",
    )
    parser.add_argument(
        "--html",
        default="security_report.html",
        help="Output path for the HTML report.",
    )
    return parser.parse_args()


def main() -> int:
    load_env_file()
    args = parse_args()

    result = run_full_security_scan(
        base_url=args.base_url,
        project_path=args.project_path,
    )

    markdown_path = Path(args.markdown)
    html_path = Path(args.html)
    markdown_path.write_text(result["reports"]["markdown"], encoding="utf-8")
    html_path.write_text(result["reports"]["html"], encoding="utf-8")

    print("Security scan finished.")
    print(f"Target: {result['target']['base_url']}")
    print(f"Project: {result['target']['project_path']}")
    print(f"Risk: {result['risk']['overall_risk']} ({result['risk']['overall_score']})")
    print(f"Total vulnerabilities: {result['risk']['total']}")
    print(f"Markdown report: {markdown_path.resolve()}")
    print(f"HTML report: {html_path.resolve()}")

    if result["errors"]:
        print("Errors:")
        for error in result["errors"]:
            print(f"- {error}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

