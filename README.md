# JS Secret Miner

A lightweight command-line tool for **bug bounty hunters and pentesters** that scans
JavaScript files — by URL or local path — for exposed secrets: API keys, access
tokens, hardcoded passwords, database connection strings, private keys, and more.

Feed it a single JS file link, or a text file containing dozens of links, and it
will report every secret it finds with the rule name, severity, exact value, and
the line number it was found on — ready to drop straight into a bug bounty report.

```
[CRITICAL] AWS_ACCESS_KEY: AKIA[REDACTED]
           └─ line 2 | AWS Access Key ID
[CRITICAL] STRIPE_LIVE_KEY: sk_live_[REDACTED]
           └─ line 4 | Stripe Live Secret Key
[  HIGH  ] HARDCODED_PASSWORD: [REDACTED]
           └─ line 9 | Hardcoded password assignment
```

## Features

- 🔗 **Single URL or bulk mode** — scan one JS file, or a whole list of URLs/paths from a text file
- ⚡ **Multi-threaded** — scans large URL lists concurrently
- 🧠 **30+ detection rules** — AWS, Google, Slack, Stripe, GitHub, Twilio, SendGrid, Mailgun,
  Heroku, PayPal/Braintree, Firebase, JWTs, private key blocks, DB connection strings
  (MongoDB/Postgres/MySQL/Redis), Basic-Auth URLs, hardcoded usernames/passwords, and more
- 🎯 **Noise filtering** — automatically ignores common placeholder values (`your_api_key`, `xxxxxx`, etc.)
- 📊 **Severity-ranked output** — critical / high / medium / low / info, color-coded in the terminal
- 📄 **Exportable reports** — plain-text and JSON report formats for write-ups or automation
- 🩹 **Local file support** — also works on `.js` files you've already downloaded/saved
- 🤖 **CI-friendly exit codes** — exits non-zero when critical/high findings are present

## Installation

```bash
git clone https://github.com/Apu1231/js-secret-miner.git
cd js-secret-miner
pip install -r requirements.txt
```

Requires Python 3.8+.

## Usage

### Scan a single JS file

```bash
python jsminer.py -u https://target.com/static/js/app.js
```

### Scan a list of JS files

Create a text file with one URL (or local path) per line — see [`urls_example.txt`](urls_example.txt):

```bash
python jsminer.py -l urls.txt
```

### Save a report

```bash
python jsminer.py -l urls.txt -o report.txt --json report.json
```

### Only show high-impact findings

```bash
python jsminer.py -l urls.txt --min-severity high
```

### Show surrounding code context for each finding

```bash
python jsminer.py -u https://target.com/app.js --context
```

### Full option list

```
usage: jsminer.py [-h] (-u URL | -l LIST) [-o OUTPUT] [--json JSON_OUTPUT]
                   [--threads THREADS] [--timeout TIMEOUT]
                   [--min-severity {critical,high,medium,low,info}]
                   [--context] [--no-noise-filter] [--no-banner] [--quiet]

  -u, --url             Single JS file URL or local path to scan
  -l, --list            Text file containing one URL/path per line
  -o, --output          Write a plain-text report to this file
  --json                Write a JSON report to this file
  --threads             Concurrent workers when using -l (default: 10)
  --timeout             HTTP request timeout in seconds (default: 15)
  --min-severity        Only show findings at or above this severity (default: info)
  --context             Show surrounding code context for each finding
  --no-noise-filter     Disable filtering of common placeholder/dummy values
  --no-banner           Suppress the ASCII banner
  --quiet               Only print the final summary, not per-target results
```

## What it detects

| Category            | Examples                                                              |
|----------------------|------------------------------------------------------------------------|
| Cloud providers       | AWS Access/Secret Keys, Google API Keys, Firebase URLs                |
| Payments              | Stripe live/test keys, PayPal/Braintree tokens                        |
| Communication         | Slack tokens & webhooks, Twilio keys/SIDs, SendGrid, Mailgun          |
| Source control        | GitHub PATs (classic + fine-grained)                                  |
| Databases              | MongoDB, PostgreSQL, MySQL, Redis connection strings                  |
| Auth                   | JWTs, Basic-Auth URLs, hardcoded usernames/passwords, generic tokens  |
| Crypto                 | RSA / EC / PGP / OpenSSH private key blocks                           |
| Misc                   | Internal IPs, email addresses                                         |

All rules live in [`patterns.py`](patterns.py) — add your own by appending to the
`SIGNATURES` list, no other code changes needed.

## Sample report output

**Text report** (`--output report.txt`):

```
JS SECRET MINER REPORT
Generated: 2026-09-10T05:01:34Z
======================================================================
TARGET: https://target.com/static/js/app.js
  STATUS: OK (48213 bytes, 0.62s)
  FINDINGS: 2
    - [CRITICAL] AWS_ACCESS_KEY (line 1042)
        Value       : AKIA[REDACTED]
        Description : AWS Access Key ID
        Context     : ...const s3Config = { accessKeyId: "AKIA[REDACTED]", ...
```

**JSON report** (`--json report.json`) — structured for feeding into other tools/CI pipelines.

## How it works

1. `scanner.py` fetches each target (HTTP GET for URLs, or reads local files) and
   runs every regex signature from `patterns.py` against the raw text.
2. Matches are de-duplicated, false-positive placeholder values are filtered out,
   and each finding is tagged with a severity and line number.
3. `reporter.py` renders results to the terminal (color-coded) and/or writes
   text/JSON report files.

## Extending detection rules

Add a new entry to `SIGNATURES` in `patterns.py`:

```python
{
    "name": "MY_CUSTOM_TOKEN",
    "pattern": re.compile(r"(my_token_[A-Za-z0-9]{32})"),
    "severity": "high",
    "description": "My Custom Service Token",
}
```

That's it — `jsminer.py` and `scanner.py` need no changes.

## Legal / Responsible use

This tool is intended for **authorized security testing only** — bug bounty
programs you're enrolled in, penetration tests you're contracted for, or your
own applications. Only scan targets you have explicit permission to test.
Scanning third-party assets without authorization may violate the law and/or a
program's terms of service. The authors take no responsibility for misuse.

## Contributing

Pull requests adding new detection signatures, fixing false positives, or
improving performance are welcome. Please open an issue first for larger changes.

## License

MIT — see [LICENSE](LICENSE).
