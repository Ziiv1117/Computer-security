from __future__ import annotations


def _risk_level(score: int) -> str:
    if score <= 30:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def calculate_risk(vulnerabilities: list[dict]) -> dict:
    if not vulnerabilities:
        return {
            "overall_score": 0,
            "overall_risk": "Low",
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

    scores = [int(vulnerability.get("score", 0)) for vulnerability in vulnerabilities]
    max_score = max(scores)
    bonus = min(10, len(vulnerabilities) * 2)
    overall_score = min(100, max_score + bonus)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for vulnerability in vulnerabilities:
        risk = str(vulnerability.get("risk") or _risk_level(int(vulnerability.get("score", 0))))
        key = risk.lower()
        if key in counts:
            counts[key] += 1

    return {
        "overall_score": overall_score,
        "overall_risk": _risk_level(overall_score),
        "total": len(vulnerabilities),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
    }

