"""
scanner.py

Core scanning engine for JS Secret Miner.

Responsibilities:
    - Fetch JS content from a URL (or read a local .js file)
    - Run all signatures from patterns.py against the content
    - De-duplicate and return structured findings
"""

import os
import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional

import requests

from patterns import get_signatures

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 JSSecretMiner"
    )
}

# Values that regularly false-positive as "secrets" — filtered out by default.
NOISE_VALUES = {
    "your_api_key", "your-api-key", "api_key_here", "xxxxxxxx", "changeme",
    "example", "null", "undefined", "true", "false", "0", "password",
    "type=password", "username", "email@example.com",
}


@dataclass
class Finding:
    rule_name: str
    severity: str
    description: str
    value: str
    source: str          # URL or file path the secret was found in
    line_number: int
    context: str = ""     # small snippet of surrounding code

    def fingerprint(self) -> str:
        """Unique key used for de-duplication."""
        raw = f"{self.rule_name}:{self.value}:{self.source}"
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


@dataclass
class ScanResult:
    source: str
    ok: bool
    error: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    bytes_scanned: int = 0
    elapsed: float = 0.0


def _looks_like_noise(value: str) -> bool:
    v = value.strip().strip("'\"").lower()
    if v in NOISE_VALUES:
        return True
    if len(set(v)) <= 1:  # e.g. "xxxxxxxxxxxx"
        return True
    return False


def _line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _context_snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    snippet = text[lo:hi].replace("\n", " ").strip()
    return snippet


def fetch_source(location: str, timeout: int = 15, retries: int = 2) -> ScanResult:
    """
    Load JS content either from a remote URL (http/https) or a local file path.
    Returns a ScanResult with ok=False and .error set on failure.
    """
    t0 = time.time()

    if location.startswith("http://") or location.startswith("https://"):
        last_err = None
        for attempt in range(retries + 1):
            try:
                resp = requests.get(location, headers=DEFAULT_HEADERS, timeout=timeout)
                if resp.status_code >= 400:
                    last_err = f"HTTP {resp.status_code}"
                    continue
                content = resp.text
                return ScanResult(source=location, ok=True, bytes_scanned=len(content.encode("utf-8", errors="ignore")),
                                   elapsed=time.time() - t0), content
            except requests.RequestException as e:
                last_err = str(e)
                time.sleep(0.5)
        return ScanResult(source=location, ok=False, error=last_err, elapsed=time.time() - t0), ""

    # local file
    if not os.path.isfile(location):
        return ScanResult(source=location, ok=False, error="file not found", elapsed=time.time() - t0), ""
    try:
        with open(location, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return ScanResult(source=location, ok=True, bytes_scanned=len(content.encode("utf-8", errors="ignore")),
                           elapsed=time.time() - t0), content
    except OSError as e:
        return ScanResult(source=location, ok=False, error=str(e), elapsed=time.time() - t0), ""


def scan_text(content: str, source: str, filter_noise: bool = True) -> List[Finding]:
    """Run all signatures against a blob of text and return Finding objects."""
    findings: List[Finding] = []
    seen = set()

    for sig in get_signatures():
        for match in sig["pattern"].finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            value = value.strip()

            if not value:
                continue
            if filter_noise and _looks_like_noise(value):
                continue

            line_no = _line_number_for_offset(content, match.start())
            snippet = _context_snippet(content, match.start(), match.end())

            finding = Finding(
                rule_name=sig["name"],
                severity=sig["severity"],
                description=sig["description"],
                value=value,
                source=source,
                line_number=line_no,
                context=snippet,
            )

            fp = finding.fingerprint()
            if fp in seen:
                continue
            seen.add(fp)
            findings.append(finding)

    return findings


def scan_location(location: str, timeout: int = 15, filter_noise: bool = True) -> ScanResult:
    """Fetch a single URL/file and scan it. Returns a fully populated ScanResult."""
    result, content = fetch_source(location, timeout=timeout)
    if not result.ok:
        return result
    result.findings = scan_text(content, source=location, filter_noise=filter_noise)
    return result
