# Scoring Methodology — Extended Notes

This file explains the reasoning behind the point weights and validators in `secheaders/rules.py`, and gives background for anyone extending the rule set.

---

## Why these point values?

The weighting follows rough real-world impact, not alphabetical or spec order:

| Header | Points | Reasoning |
|---|---|---|
| `Content-Security-Policy` | 25 | The single strongest defense-in-depth control against XSS, which remains one of the most common and highest-impact web vulnerability classes (OWASP Top 10 fixture). A strong CSP can neutralize an XSS bug even if the underlying code flaw exists. |
| `Strict-Transport-Security` | 20 | Prevents SSL-stripping and protocol-downgrade attacks on every subsequent visit — a missing HSTS header leaves a permanent window for a man-in-the-middle to intercept a user's very first (or any) HTTP request before a redirect to HTTPS happens. |
| `X-Frame-Options` | 15 | Clickjacking is simple to execute and historically underprotected; this header (or the frame-ancestors CSP directive) is the direct fix. |
| `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` | 10 each | Solid, broadly-applicable hardening with lower exploit severity than the above three. |
| `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy` | 5 each | Newer, narrower-scope isolation headers (COOP/CORP/COEP family) — valuable, especially post-Spectre, but with a smaller blast radius than the headers above. |

Total possible: **100 points**, so the score reads naturally as a percentage.

---

## Why validate values, not just presence?

A header that exists with a weak or self-defeating value gives a false sense of security:

- A `Content-Security-Policy` that still allows `script-src 'unsafe-inline'` barely restricts anything — most stored/reflected XSS payloads are inline `<script>` tags.
- A `Strict-Transport-Security` with `max-age=60` expires almost immediately and provides negligible real-world protection.
- An `X-Frame-Options` set to a non-standard value (or left as an empty string) may be silently ignored by some browsers.

The validators in `rules.py` are intentionally **conservative but not exhaustive** — they catch the most common misconfigurations without trying to fully parse CSP grammar (which is a large undertaking on its own). Contributions that extend validation depth are welcome; see the Roadmap in the main README.

---

## Why these "leak" headers specifically?

`Server`, `X-Powered-By`, and `X-AspNet-Version` are the most commonly observed headers that **reveal implementation details without providing any security benefit**. They don't make an attack possible by themselves, but they reduce the attacker's reconnaissance cost — e.g. instantly narrowing which CVEs to try against a known server/framework version.

---

## Extending the rule set

To add a new header check, add an entry to the `RULES` list in `secheaders/rules.py`:

```python
HeaderRule(
    name="Your-Header-Name",
    points=10,
    severity="medium",
    description="What this header protects against, in one sentence.",
    recommended_value="example-good-value",
    validator=your_validator_function,  # or None if presence alone is enough
),
```

Keep `TOTAL_POSSIBLE_POINTS` in mind — if you want the scoring to stay out of 100, either rebalance existing weights or accept a different total and adjust the grade thresholds in `scanner.py` accordingly.
