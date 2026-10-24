"""
Command-line entrypoint for SecHeaders-Auditor.
"""

import argparse
import sys

from .scanner import scan_url
from .report import print_console_report, write_json_report, write_html_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secheaders",
        description="Scan a website's HTTP security headers and get a hardening report.",
    )
    parser.add_argument("url", help="Target URL or domain (e.g. example.com or https://example.com)")
    parser.add_argument("--json", metavar="PATH", help="Write a JSON report to PATH")
    parser.add_argument("--html", metavar="PATH", help="Write an HTML report to PATH")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    parser.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="SCORE",
        help="Exit with code 1 if the score is below this threshold (useful in CI)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    result = scan_url(args.url, timeout=args.timeout, verify_tls=not args.insecure)
    print_console_report(result)

    if result.error:
        sys.exit(2)

    if args.json:
        write_json_report(result, args.json)
        print(f"JSON report written to {args.json}")

    if args.html:
        write_html_report(result, args.html)
        print(f"HTML report written to {args.html}")

    if args.fail_under is not None and result.score < args.fail_under:
        print(f"\nScore {result.score} is below threshold {args.fail_under} — failing.")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
