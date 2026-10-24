"""
Security header rule definitions.

Each rule describes one HTTP response header that matters for web security,
why it matters, how many points it's worth, and a simple validator that
decides whether the header's *value* (not just its presence) is acceptable.
"""

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class HeaderRule:
    name: str                      # Canonical header name (case-insensitive match)
    points: int                    # Points awarded when present & valid
    severity: str                  # "critical" | "high" | "medium" | "low"
    description: str               # One-line explanation of what it protects against
    recommended_value: str         # Example of a good value, shown in reports
    validator: Optional[Callable[[str], bool]] = field(default=None)

    def is_valid(self, value: str) -> bool:
        if self.validator is None:
            return True  # presence alone is enough for this header
        try:
            return self.validator(value)
        except Exception:  # noqa: BLE001 - never let a bad validator crash a scan
            return False


def _valid_hsts(value: str) -> bool:
    value = value.lower()
    if "max-age=" not in value:
        return False
    try:
        age = int(value.split("max-age=")[1].split(";")[0].strip())
    except (IndexError, ValueError):
        return False
    return age >= 15552000  # 180 days, a commonly recommended floor


def _valid_frame_options(value: str) -> bool:
    return value.strip().upper() in {"DENY", "SAMEORIGIN"}


def _valid_content_type_options(value: str) -> bool:
    return value.strip().lower() == "nosniff"


def _valid_referrer_policy(value: str) -> bool:
    safe_values = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    return value.strip().lower() in safe_values


def _valid_permissions_policy(_value: str) -> bool:
    return True  # presence matters most; granular validation is site-specific


def _valid_csp(value: str) -> bool:
    value = value.lower()
    if "default-src" not in value and "script-src" not in value:
        return False
    # A CSP that still allows 'unsafe-inline' scripts defeats much of its purpose
    if "script-src" in value and "unsafe-inline" in value:
        return False
    return True


RULES: list[HeaderRule] = [
    HeaderRule(
        name="Content-Security-Policy",
        points=25,
        severity="critical",
        description="Restricts which sources scripts, styles, and other resources may load from — the primary defense against XSS.",
        recommended_value="default-src 'self'; script-src 'self'; object-src 'none'",
        validator=_valid_csp,
    ),
    HeaderRule(
        name="Strict-Transport-Security",
        points=20,
        severity="critical",
        description="Forces browsers to only connect over HTTPS, preventing downgrade and SSL-stripping attacks.",
        recommended_value="max-age=63072000; includeSubDomains; preload",
        validator=_valid_hsts,
    ),
    HeaderRule(
        name="X-Frame-Options",
        points=15,
        severity="high",
        description="Prevents the page from being embedded in an iframe, mitigating clickjacking.",
        recommended_value="DENY",
        validator=_valid_frame_options,
    ),
    HeaderRule(
        name="X-Content-Type-Options",
        points=10,
        severity="medium",
        description="Stops browsers from MIME-sniffing a response away from its declared Content-Type.",
        recommended_value="nosniff",
        validator=_valid_content_type_options,
    ),
    HeaderRule(
        name="Referrer-Policy",
        points=10,
        severity="medium",
        description="Controls how much referrer information is leaked to other origins on navigation.",
        recommended_value="strict-origin-when-cross-origin",
        validator=_valid_referrer_policy,
    ),
    HeaderRule(
        name="Permissions-Policy",
        points=10,
        severity="medium",
        description="Restricts access to powerful browser features (camera, geolocation, microphone, etc.) by origin.",
        recommended_value="geolocation=(), camera=(), microphone=()",
        validator=_valid_permissions_policy,
    ),
    HeaderRule(
        name="Cross-Origin-Opener-Policy",
        points=5,
        severity="low",
        description="Isolates the browsing context from cross-origin windows, mitigating some Spectre-class and tab-napping attacks.",
        recommended_value="same-origin",
        validator=None,
    ),
    HeaderRule(
        name="Cross-Origin-Resource-Policy",
        points=5,
        severity="low",
        description="Limits which origins may load this resource, reducing cross-origin information leaks.",
        recommended_value="same-origin",
        validator=None,
    ),
]

TOTAL_POSSIBLE_POINTS = sum(rule.points for rule in RULES)

# Headers that should generally NOT be present — they leak implementation details
LEAK_HEADERS = {
    "Server": "Reveals web server software/version — aids attacker fingerprinting.",
    "X-Powered-By": "Reveals backend framework/version — aids attacker fingerprinting.",
    "X-AspNet-Version": "Reveals ASP.NET version — aids attacker fingerprinting.",
}
