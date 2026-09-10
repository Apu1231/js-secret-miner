"""
reporter.py

Formats ScanResult / Finding objects for:
    - live colored terminal output
    - a plain-text report file
    - a JSON report file
"""

import json
from datetime import datetime, timezone
from typing import List

from scanner import ScanResult

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    _COLOR = True
except ImportError:  # colorama not installed, degrade gracefully
    _COLOR = False

    class _Dummy:
        def __getattr__(self, _):
            return ""

    Fore = _Dummy()
    Style = _Dummy()


SEVERITY_COLOR = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.RED,
    "medium": Fore.YELLOW,
    "low": Fore.CYAN,
    "info": Fore.WHITE,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _color(sev: str) -> str:
    return SEVERITY_COLOR.get(sev, "")


def print_banner():
    banner = r"""
     ██╗███████╗    ███╗   ███╗██╗███╗   ██╗███████╗██████╗
     ██║██╔════╝    ████╗ ████║██║████╗  ██║██╔════╝██╔══██╗
     ██║███████╗    ██╔████╔██║██║██╔██╗ ██║█████╗  ██████╔╝
██   ██║╚════██║    ██║╚██╔╝██║██║██║╚██╗██║██╔══╝  ██╔══██╗
╚█████╔╝███████║    ██║ ╚═╝ ██║██║██║ ╚████║███████╗██║  ██║
 ╚════╝ ╚══════╝    ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
        JS Secret Miner  -  find leaked keys & creds in JavaScript
"""
    print((Fore.GREEN if _COLOR else "") + banner)


def print_result_console(result: ScanResult, show_context: bool = False, min_severity: str = "info"):
    min_rank = SEVERITY_ORDER.get(min_severity, 4)

    if not result.ok:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {result.source} -> {result.error}")
        return

    visible = [f for f in result.findings if SEVERITY_ORDER.get(f.severity, 4) <= min_rank]

    if not visible:
        print(f"{Fore.GREEN}[CLEAN]{Style.RESET_ALL} {result.source}  "
              f"({result.bytes_scanned} bytes, {result.elapsed:.2f}s) - no secrets found")
        return

    print(f"{Fore.MAGENTA}{Style.BRIGHT}[TARGET]{Style.RESET_ALL} {result.source}  "
          f"({result.bytes_scanned} bytes, {result.elapsed:.2f}s) - "
          f"{len(visible)} finding(s)")

    for f in sorted(visible, key=lambda x: SEVERITY_ORDER.get(x.severity, 4)):
        c = _color(f.severity)
        print(f"  {c}[{f.severity.upper():^8}]{Style.RESET_ALL} {f.rule_name}: "
              f"{Fore.WHITE if _COLOR else ''}{f.value}")
        print(f"           └─ line {f.line_number} | {f.description}")
        if show_context:
            print(f"              context: ...{f.context}...")
    print("")


def print_summary(results: List[ScanResult]):
    total_targets = len(results)
    ok_targets = sum(1 for r in results if r.ok)
    failed_targets = total_targets - ok_targets
    total_findings = sum(len(r.findings) for r in results if r.ok)

    by_sev = {}
    for r in results:
        for f in r.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    print(Style.BRIGHT + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60 + Style.RESET_ALL)
    print(f"Targets scanned : {total_targets}  ({ok_targets} ok, {failed_targets} failed)")
    print(f"Total findings  : {total_findings}")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in by_sev:
            print(f"  {_color(sev)}{sev.upper():<8}{Style.RESET_ALL}: {by_sev[sev]}")
    print("")


def write_text_report(results: List[ScanResult], path: str):
    lines = []
    lines.append("JS SECRET MINER REPORT")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}Z")
    lines.append("=" * 70)
    lines.append("")

    for r in results:
        lines.append(f"TARGET: {r.source}")
        if not r.ok:
            lines.append(f"  STATUS: ERROR - {r.error}")
            lines.append("")
            continue

        lines.append(f"  STATUS: OK ({r.bytes_scanned} bytes, {r.elapsed:.2f}s)")
        lines.append(f"  FINDINGS: {len(r.findings)}")
        for f in sorted(r.findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 4)):
            lines.append(f"    - [{f.severity.upper()}] {f.rule_name} (line {f.line_number})")
            lines.append(f"        Value       : {f.value}")
            lines.append(f"        Description : {f.description}")
            lines.append(f"        Context     : ...{f.context}...")
        lines.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def write_json_report(results: List[ScanResult], path: str):
    payload = {
        "generated": datetime.now(timezone.utc).isoformat() + "Z",
        "targets": [],
    }

    for r in results:
        entry = {
            "source": r.source,
            "ok": r.ok,
            "error": r.error,
            "bytes_scanned": r.bytes_scanned,
            "elapsed_seconds": round(r.elapsed, 3),
            "findings": [
                {
                    "rule": f.rule_name,
                    "severity": f.severity,
                    "description": f.description,
                    "value": f.value,
                    "line": f.line_number,
                    "context": f.context,
                }
                for f in r.findings
            ],
        }
        payload["targets"].append(entry)

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
