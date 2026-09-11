"""
context_rules.py

Context-aware secret detection.

Instead of relying on fixed value formats (which only catch known
providers like AWS/Stripe/Google), this module looks at *assignments* in
the code — `identifier = "value"` or `identifier: "value"` — and flags
any assignment where the identifier itself looks sensitive (contains
"key", "secret", "token", "password", "email", "phone", "user_id", etc).

Findings from this module report the EXACT identifier name as it appears
in the source, plus its value verbatim — e.g. a variable named
`OPENAI_API_KEY` will be reported as `OPENAI_API_KEY`, not shoved into a
generic bucket. This is what catches custom / non-standard secret names
that no fixed-format regex could ever anticipate.
"""

import re

# Single tokens that, on their own, mark an identifier as sensitive.
# Mapped to the severity that assignment should be reported at.
SINGLE_KEYWORD_SEVERITY = {
    "key": "critical",
    "apikey": "critical",
    "secret": "critical",
    "token": "critical",
    "password": "critical",
    "passwd": "critical",
    "pwd": "critical",
    "credential": "critical",
    "credentials": "critical",
    "ssn": "critical",
    "auth": "high",
    "session": "high",
    "cookie": "high",
    "pin": "high",
    "otp": "high",
    "card": "high",
    "cvv": "high",
    "iban": "high",
    "email": "medium",
    "mail": "medium",
    "phone": "medium",
    "mobile": "medium",
    "contact": "medium",
    "address": "low",
}

# Two-token (snake/camel split) combinations that are only sensitive
# together — avoids flagging every identifier that merely contains "name"
# or "id" on its own (too noisy: fileName, gridId, etc).
MULTI_KEYWORD_SEVERITY = {
    ("user", "name"): "low",
    ("user", "id"): "low",
    ("account", "name"): "low",
    ("first", "name"): "low",
    ("last", "name"): "low",
    ("full", "name"): "low",
    ("display", "name"): "low",
    ("client", "id"): "low",
    ("account", "id"): "low",
}

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# identifier = "value"   |   identifier: "value"   |   identifier = value  (unquoted)
_ASSIGNMENT_RE = re.compile(
    r"""(?P<ident>[A-Za-z_$][A-Za-z0-9_$]{1,80})\s*[:=]\s*
        (?:
            (?P<q>['"])(?P<qval>[^'"\n]{1,500})(?P=q)   # quoted value
            |
            (?P<uval>[A-Za-z0-9_.\-]{2,500})            # bare/unquoted value
        )
    """,
    re.VERBOSE,
)

# Reserved words / common non-secret identifiers we never want to flag
# even if they happen to contain a keyword substring after tokenizing.
IDENTIFIER_DENYLIST = {
    "keydown", "keyup", "keypress", "keycode", "monkey", "turkey", "donkey",
}


def _tokenize(identifier: str):
    s = re.sub(r"[^A-Za-z0-9]+", "_", identifier)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return [t.lower() for t in s.split("_") if t]


def classify_identifier(identifier: str):
    """
    Return the severity string if `identifier` looks sensitive, else None.
    """
    low = identifier.lower()
    if low in IDENTIFIER_DENYLIST:
        return None

    tokens = _tokenize(identifier)
    if not tokens:
        return None

    best_rank = None

    for t in tokens:
        if t in SINGLE_KEYWORD_SEVERITY:
            sev = SINGLE_KEYWORD_SEVERITY[t]
            rank = SEVERITY_RANK[sev]
            if best_rank is None or rank < best_rank:
                best_rank = rank

    for i in range(len(tokens) - 1):
        pair = (tokens[i], tokens[i + 1])
        if pair in MULTI_KEYWORD_SEVERITY:
            sev = MULTI_KEYWORD_SEVERITY[pair]
            rank = SEVERITY_RANK[sev]
            if best_rank is None or rank < best_rank:
                best_rank = rank

    if best_rank is None:
        return None

    for sev, rank in SEVERITY_RANK.items():
        if rank == best_rank:
            return sev
    return None


def find_contextual_matches(content: str):
    """
    Scan `content` for identifier=value assignments where the identifier
    looks sensitive. Yields dicts with: identifier, value, severity,
    raw (exact matched text), start, end.
    """
    for m in _ASSIGNMENT_RE.finditer(content):
        identifier = m.group("ident")
        severity = classify_identifier(identifier)
        if not severity:
            continue

        value = m.group("qval") if m.group("qval") is not None else m.group("uval")
        if value is None:
            continue
        value = value.strip()
        if not value:
            continue

        yield {
            "identifier": identifier,
            "value": value,
            "severity": severity,
            "raw": m.group(0).strip(),
            "start": m.start(),
            "end": m.end(),
        }
