"""
Core scanning logic: fetches response headers from a target URL and
evaluates them against the rule set in rules.py.
"""

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

from .rules import RULES, LEAK_HEADERS, TOTAL_POSSIBLE_POINTS, HeaderRule

DEFAULT_TIMEOUT = 10
USER_AGENT = "SecHeaders-Auditor/1.0 (+https://github.com/Syed-Muhammad-Tayyab/SecHeaders-Auditor)"


@dataclass
class HeaderFinding:
    rule: HeaderRule
    present: bool
    value: Optional[str]
    valid: bool
    points_awarded: int


@dataclass
class LeakFinding:
    header: str
    value: str
    reason: str


@dataclass
class ScanResult:
    url: str
    final_url: str
    status_code: int
    findings: list[HeaderFinding] = field(default_factory=list)
    leaks: list[LeakFinding] = field(default_factory=list)
    score: int = 0
    max_score: int = TOTAL_POSSIBLE_POINTS
    grade: str = "F"
    error: Optional[str] = None


def _normalize_url(url: str) -> str:
    if not urlparse(url).scheme:
        url = f"https://{url}"
    return url


def _grade_for(percentage: float) -> str:
    if percentage >= 90:
        return "A+"
    if percentage >= 80:
        return "A"
    if percentage >= 70:
        return "B"
    if percentage >= 55:
        return "C"
    if percentage >= 40:
        return "D"
    return "F"


def scan_url(url: str, timeout: int = DEFAULT_TIMEOUT, verify_tls: bool = True) -> ScanResult:
    """
    Fetch headers for `url` and evaluate them against the security rule set.
    Follows redirects so the final, effective headers are what get scored.
    """
    target = _normalize_url(url)

    try:
        response = requests.get(
            target,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
        )
    except requests.exceptions.RequestException as exc:
        return ScanResult(url=url, final_url=target, status_code=0, error=str(exc))

    # requests' headers are case-insensitive already (CaseInsensitiveDict)
    headers = response.headers

    findings: list[HeaderFinding] = []
    total_points = 0

    for rule in RULES:
        raw_value = headers.get(rule.name)
        present = raw_value is not None
        valid = present and rule.is_valid(raw_value)
        awarded = rule.points if valid else 0
        total_points += awarded
        findings.append(
            HeaderFinding(
                rule=rule,
                present=present,
                value=raw_value,
                valid=valid,
                points_awarded=awarded,
            )
        )

    leaks: list[LeakFinding] = []
    for header_name, reason in LEAK_HEADERS.items():
        value = headers.get(header_name)
        if value:
            leaks.append(LeakFinding(header=header_name, value=value, reason=reason))

    percentage = (total_points / TOTAL_POSSIBLE_POINTS) * 100 if TOTAL_POSSIBLE_POINTS else 0

    return ScanResult(
        url=url,
        final_url=response.url,
        status_code=response.status_code,
        findings=findings,
        leaks=leaks,
        score=total_points,
        max_score=TOTAL_POSSIBLE_POINTS,
        grade=_grade_for(percentage),
    )
