#!/usr/bin/env python3
"""
jsminer.py

JS Secret Miner - CLI entrypoint.

Usage examples:
    python jsminer.py -u https://target.com/static/app.js
    python jsminer.py -l urls.txt -o report.txt --json report.json
    python jsminer.py -l urls.txt --threads 20 --min-severity high
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner import scan_location, ScanResult
import reporter


def parse_args():
    parser = argparse.ArgumentParser(
        prog="jsminer.py",
        description="Scan JavaScript files (by URL or local path) for exposed secrets, "
                    "API keys, tokens, and credentials.",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-u", "--url", help="Single JS file URL or local path to scan")
    target.add_argument("-l", "--list", help="Text file containing one URL/path per line")

    parser.add_argument("-o", "--output", help="Write a plain-text report to this file")
    parser.add_argument("--json", dest="json_output", help="Write a JSON report to this file")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent workers when using -l (default: 10)")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP request timeout in seconds (default: 15)")
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Only show findings at or above this severity in console output (default: info = show all)",
    )
    parser.add_argument("--context", action="store_true", help="Show surrounding code context for each finding")
    parser.add_argument("--no-noise-filter", action="store_true",
                         help="Disable filtering of common placeholder/dummy values")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--quiet", action="store_true", help="Only print the final summary, not per-target results")

    return parser.parse_args()


def load_targets_from_file(path: str):
    targets = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.append(line)
    except OSError as e:
        print(f"[!] Could not read target list '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    return targets


def run_single(location: str, timeout: int, filter_noise: bool) -> ScanResult:
    return scan_location(location, timeout=timeout, filter_noise=filter_noise)


def main():
    args = parse_args()

    if not args.no_banner:
        reporter.print_banner()

    if args.url:
        targets = [args.url.strip()]
    else:
        targets = load_targets_from_file(args.list)

    if not targets:
        print("[!] No targets to scan.", file=sys.stderr)
        sys.exit(1)

    filter_noise = not args.no_noise_filter
    results = []

    if len(targets) == 1:
        r = run_single(targets[0], args.timeout, filter_noise)
        results.append(r)
        if not args.quiet:
            reporter.print_result_console(r, show_context=args.context, min_severity=args.min_severity)
    else:
        print(f"[*] Scanning {len(targets)} targets with {args.threads} worker(s)...\n")
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            future_map = {
                pool.submit(run_single, t, args.timeout, filter_noise): t for t in targets
            }
            for future in as_completed(future_map):
                r = future.result()
                results.append(r)
                if not args.quiet:
                    reporter.print_result_console(r, show_context=args.context, min_severity=args.min_severity)

        # keep output order stable & matching input order for the report files
        order = {t: i for i, t in enumerate(targets)}
        results.sort(key=lambda r: order.get(r.source, 0))

    reporter.print_summary(results)

    if args.output:
        reporter.write_text_report(results, args.output)
        print(f"[+] Text report written to: {args.output}")

    if args.json_output:
        reporter.write_json_report(results, args.json_output)
        print(f"[+] JSON report written to: {args.json_output}")

    # non-zero exit code if any critical/high findings were made (handy for CI)
    has_serious = any(
        f.severity in ("critical", "high") for r in results for f in r.findings
    )
    sys.exit(2 if has_serious else 0)


if __name__ == "__main__":
    main()
