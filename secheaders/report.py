"""
Report rendering: console (colored), JSON, and a self-contained HTML report.
"""

import json
from datetime import datetime, timezone

from .scanner import ScanResult

# ANSI color codes (gracefully degrade — most terminals and CI logs handle these fine)
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
GRAY = "\033[90m"

GRADE_COLOR = {
    "A+": GREEN, "A": GREEN,
    "B": CYAN,
    "C": YELLOW,
    "D": YELLOW,
    "F": RED,
}


def print_console_report(result: ScanResult) -> None:
    if result.error:
        print(f"{RED}{BOLD}[ERROR]{RESET} Could not scan {result.url}: {result.error}")
        return

    grade_color = GRADE_COLOR.get(result.grade, RESET)

    print(f"\n{BOLD}SecHeaders-Auditor Report{RESET}")
    print(f"{GRAY}{'-' * 50}{RESET}")
    print(f"Target:      {result.url}")
    if result.final_url != result.url:
        print(f"Final URL:   {result.final_url}  {GRAY}(after redirects){RESET}")
    print(f"Status Code: {result.status_code}")
    print(f"Score:       {result.score} / {result.max_score}")
    print(f"Grade:       {grade_color}{BOLD}{result.grade}{RESET}")
    print(f"{GRAY}{'-' * 50}{RESET}\n")

    print(f"{BOLD}Header Findings{RESET}")
    for finding in result.findings:
        if finding.valid:
            tag = f"{GREEN}[PASS]{RESET}"
        elif finding.present:
            tag = f"{YELLOW}[WEAK]{RESET}"
        else:
            tag = f"{RED}[MISS]{RESET}"

        print(f"  {tag} {finding.rule.name}  {GRAY}(+{finding.points_awarded}/{finding.rule.points} pts, {finding.rule.severity}){RESET}")
        if not finding.valid:
            shown_value = finding.value if finding.present else "(not set)"
            print(f"         current: {shown_value}")
            print(f"         recommended: {finding.rule.recommended_value}")
            print(f"         why: {finding.rule.description}")

    if result.leaks:
        print(f"\n{BOLD}Information Disclosure{RESET}")
        for leak in result.leaks:
            print(f"  {YELLOW}[LEAK]{RESET} {leak.header}: {leak.value}")
            print(f"         why: {leak.reason}")

    print()


def to_dict(result: ScanResult) -> dict:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "url": result.url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "score": result.score,
        "max_score": result.max_score,
        "grade": result.grade,
        "error": result.error,
        "findings": [
            {
                "header": f.rule.name,
                "present": f.present,
                "valid": f.valid,
                "value": f.value,
                "severity": f.rule.severity,
                "points_awarded": f.points_awarded,
                "points_possible": f.rule.points,
                "recommended_value": f.rule.recommended_value,
                "description": f.rule.description,
            }
            for f in result.findings
        ],
        "leaks": [
            {"header": leak.header, "value": leak.value, "reason": leak.reason}
            for leak in result.leaks
        ],
    }


def write_json_report(result: ScanResult, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(to_dict(result), handle, indent=2)


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecHeaders Report — {url}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f1419; color: #e6edf3; max-width: 900px; margin: 40px auto; padding: 0 20px; }}
  h1 {{ color: #e94560; }}
  .meta {{ color: #8b949e; margin-bottom: 24px; }}
  .grade {{ display: inline-block; font-size: 2em; font-weight: bold; padding: 4px 18px; border-radius: 10px; background: #1a1a2e; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
  th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #30363d; }}
  th {{ color: #8b949e; font-weight: 600; }}
  .pass {{ color: #3fb950; }}
  .weak {{ color: #d29922; }}
  .miss {{ color: #f85149; }}
  .leak {{ color: #d29922; }}
  code {{ background: #1a1a2e; padding: 2px 6px; border-radius: 4px; }}
</style>
</head>
<body>
  <h1>🛡️ SecHeaders-Auditor Report</h1>
  <div class="meta">
    Target: <code>{url}</code> &nbsp;|&nbsp; Status: {status_code} &nbsp;|&nbsp; Generated: {generated_at}
  </div>
  <div class="grade">{grade} — {score}/{max_score}</div>
  <table>
    <tr><th>Header</th><th>Status</th><th>Points</th><th>Current Value</th><th>Recommended</th></tr>
    {rows}
  </table>
</body>
</html>
"""


def write_html_report(result: ScanResult, path: str) -> None:
    rows = []
    for f in result.findings:
        css = "pass" if f.valid else ("weak" if f.present else "miss")
        label = "PASS" if f.valid else ("WEAK" if f.present else "MISSING")
        value = f.value or "(not set)"
        rows.append(
            f"<tr><td>{f.rule.name}</td><td class='{css}'>{label}</td>"
            f"<td>{f.points_awarded}/{f.rule.points}</td><td><code>{value}</code></td>"
            f"<td><code>{f.rule.recommended_value}</code></td></tr>"
        )

    html = _HTML_TEMPLATE.format(
        url=result.url,
        status_code=result.status_code,
        generated_at=datetime.now(timezone.utc).isoformat(),
        grade=result.grade,
        score=result.score,
        max_score=result.max_score,
        rows="\n    ".join(rows),
    )
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(html)
