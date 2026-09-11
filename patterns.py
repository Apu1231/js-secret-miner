"""
patterns.py

Regex signature database used by JS Secret Miner.

Each entry is a dict:
    name        -> short identifier used in reports, e.g. "AWS_ACCESS_KEY"
    pattern     -> compiled regex. Should contain ONE capture group for the
                   actual secret value where possible (group(1)). If there is
                   no group, group(0) is used instead.
    severity    -> "critical" | "high" | "medium" | "low" | "info"
    description -> human readable description shown in the report

Feel free to add / tune patterns. Keeping them in one place makes the tool
easy to extend without touching the scanning logic.
"""

import re

SIGNATURES = [
    # ---------------------------------------------------------------- AWS
    {
        "name": "AWS_ACCESS_KEY",
        "pattern": re.compile(r"(?<![A-Za-z0-9])((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})(?![A-Za-z0-9])"),
        "severity": "critical",
        "description": "AWS Access Key ID",
    },
    {
        "name": "AWS_SECRET_KEY",
        "pattern": re.compile(
            r"(?i)aws(?:.{0,20})?(?:secret|access)?(?:_|-)?key(?:_|-)?(?:id)?[\"'\s:=]{1,4}([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        "severity": "critical",
        "description": "Possible AWS Secret Access Key",
    },
    {
        "name": "AWS_MWS_KEY",
        "pattern": re.compile(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
        "severity": "high",
        "description": "Amazon MWS Auth Token",
    },

    # ------------------------------------------------------------- Google
    {
        "name": "GOOGLE_API_KEY",
        "pattern": re.compile(r"(AIza[0-9A-Za-z\-_]{35})"),
        "severity": "high",
        "description": "Google API Key",
    },
    {
        "name": "GEMINI_API_KEY",
        "pattern": re.compile(r"(AQ\.[A-Za-z0-9_\-]{20,120})"),
        "severity": "critical",
        "description": "Google Gemini API Key",
    },
    {
        "name": "OPENAI_API_KEY",
        "pattern": re.compile(r"(sk-(?:proj-)?[A-Za-z0-9_\-]{20,161})"),
        "severity": "critical",
        "description": "OpenAI API Key",
    },
    {
        "name": "ANTHROPIC_API_KEY",
        "pattern": re.compile(r"(sk-ant-[A-Za-z0-9_\-]{20,161})"),
        "severity": "critical",
        "description": "Anthropic API Key",
    },
    {
        "name": "GROQ_API_KEY",
        "pattern": re.compile(r"(gsk_[A-Za-z0-9]{20,80})"),
        "severity": "critical",
        "description": "Groq API Key",
    },
    {
        "name": "GOOGLE_OAUTH_ID",
        "pattern": re.compile(r"([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)"),
        "severity": "medium",
        "description": "Google OAuth Client ID",
    },
    {
        "name": "FIREBASE_URL",
        "pattern": re.compile(r"([a-z0-9-]+\.firebaseio\.com)"),
        "severity": "low",
        "description": "Firebase Realtime Database URL",
    },

    # -------------------------------------------------------------- Slack
    {
        "name": "SLACK_TOKEN",
        "pattern": re.compile(r"(xox[baprs]-[0-9A-Za-z\-]{10,72})"),
        "severity": "critical",
        "description": "Slack Token",
    },
    {
        "name": "SLACK_WEBHOOK",
        "pattern": re.compile(r"(https://hooks\.slack\.com/services/T[0-9A-Za-z_]{8,10}/B[0-9A-Za-z_]{8,10}/[0-9A-Za-z_]{24})"),
        "severity": "high",
        "description": "Slack Incoming Webhook URL",
    },

    # ------------------------------------------------------------ Stripe
    {
        "name": "STRIPE_LIVE_KEY",
        "pattern": re.compile(r"((?:sk|rk)_live_[0-9A-Za-z]{24,247})"),
        "severity": "critical",
        "description": "Stripe Live Secret Key",
    },
    {
        "name": "STRIPE_TEST_KEY",
        "pattern": re.compile(r"((?:sk|rk)_test_[0-9A-Za-z]{24,247})"),
        "severity": "medium",
        "description": "Stripe Test Secret Key",
    },

    # ------------------------------------------------------------ GitHub
    {
        "name": "GITHUB_TOKEN",
        "pattern": re.compile(r"(gh[pousr]_[A-Za-z0-9]{36,255})"),
        "severity": "critical",
        "description": "GitHub Personal Access / OAuth Token",
    },
    {
        "name": "GITHUB_FINE_GRAINED_PAT",
        "pattern": re.compile(r"(github_pat_[A-Za-z0-9_]{22,255})"),
        "severity": "critical",
        "description": "GitHub Fine-Grained Personal Access Token",
    },

    # ----------------------------------------------------------- Twilio
    {
        "name": "TWILIO_API_KEY",
        "pattern": re.compile(r"(SK[a-f0-9]{32})"),
        "severity": "high",
        "description": "Twilio API Key",
    },
    {
        "name": "TWILIO_ACCOUNT_SID",
        "pattern": re.compile(r"(AC[a-f0-9]{32})"),
        "severity": "medium",
        "description": "Twilio Account SID",
    },

    # ---------------------------------------------------------- Mailgun
    {
        "name": "MAILGUN_API_KEY",
        "pattern": re.compile(r"(key-[0-9a-zA-Z]{32})"),
        "severity": "high",
        "description": "Mailgun API Key",
    },

    # ---------------------------------------------------------- SendGrid
    {
        "name": "SENDGRID_API_KEY",
        "pattern": re.compile(r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"),
        "severity": "critical",
        "description": "SendGrid API Key",
    },

    # ----------------------------------------------------------- Heroku
    {
        "name": "HEROKU_API_KEY",
        "pattern": re.compile(
            r"(?i)heroku(?:.{0,20})?[\"'\s:=]{1,4}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
        ),
        "severity": "high",
        "description": "Heroku API Key",
    },

    # ----------------------------------------------------------- PayPal
    {
        "name": "PAYPAL_BRAINTREE_TOKEN",
        "pattern": re.compile(r"(access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32})"),
        "severity": "critical",
        "description": "PayPal Braintree Access Token",
    },

    # ------------------------------------------------------------- Meta
    {
        "name": "FACEBOOK_ACCESS_TOKEN",
        "pattern": re.compile(r"(EAACEdEose0cBA[0-9A-Za-z]+)"),
        "severity": "high",
        "description": "Facebook Access Token",
    },

    # ----------------------------------------------------------- Twitter
    {
        "name": "TWITTER_BEARER_TOKEN",
        "pattern": re.compile(r"(A{2}AAAAAAAAAAAA[0-9A-Za-z%]{60,})"),
        "severity": "medium",
        "description": "Twitter Bearer Token",
    },

    # -------------------------------------------------------------- JWT
    {
        "name": "JWT_TOKEN",
        "pattern": re.compile(r"(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})"),
        "severity": "medium",
        "description": "JSON Web Token (JWT)",
    },

    # ---------------------------------------------------- Private Keys
    {
        "name": "RSA_PRIVATE_KEY",
        "pattern": re.compile(r"(-----BEGIN RSA PRIVATE KEY-----)"),
        "severity": "critical",
        "description": "RSA Private Key Block",
    },
    {
        "name": "PRIVATE_KEY",
        "pattern": re.compile(r"(-----BEGIN (?:EC|PGP|DSA|OPENSSH|)\s?PRIVATE KEY-----)"),
        "severity": "critical",
        "description": "Generic Private Key Block",
    },

    # -------------------------------------------------------- Databases
    {
        "name": "MONGODB_URI",
        "pattern": re.compile(r"(mongodb(?:\+srv)?://[^\s\"'<>]{6,120})"),
        "severity": "critical",
        "description": "MongoDB Connection String (may include credentials)",
    },
    {
        "name": "POSTGRES_URI",
        "pattern": re.compile(r"(postgres(?:ql)?://[^\s\"'<>]{6,120})"),
        "severity": "critical",
        "description": "PostgreSQL Connection String (may include credentials)",
    },
    {
        "name": "MYSQL_URI",
        "pattern": re.compile(r"(mysql://[^\s\"'<>]{6,120})"),
        "severity": "critical",
        "description": "MySQL Connection String (may include credentials)",
    },
    {
        "name": "REDIS_URI",
        "pattern": re.compile(r"(redis://[^\s\"'<>]{6,120})"),
        "severity": "high",
        "description": "Redis Connection String (may include credentials)",
    },

    # --------------------------------------------------------- Firebase
    {
        "name": "FCM_SERVER_KEY",
        "pattern": re.compile(r"(AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140})"),
        "severity": "high",
        "description": "Firebase Cloud Messaging Server Key",
    },

    # ------------------------------------------------ Generic patterns
    # NOTE: Free-form "identifier = value" secrets (api_key, user_email,
    # user_phone, password, custom var names, etc.) are NOT handled here
    # anymore — they're covered by the context-aware scanner in
    # scanner.py (scan_contextual), which reports the *actual* variable
    # name found in the code instead of a generic bucket name. Keep this
    # file focused on fixed, provider-specific value FORMATS that are
    # identifiable even with no variable name context at all (e.g. a key
    # sitting alone in a minified bundle or config blob).
    {
        "name": "BASIC_AUTH_URL",
        "pattern": re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s\"'/@]+:[^\s\"'/@]+@[^\s\"'/]+)"),
        "severity": "high",
        "description": "URL containing Basic Auth credentials",
    },
    {
        "name": "EMAIL_ADDRESS",
        "pattern": re.compile(r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"),
        "severity": "info",
        "description": "Email address found in source",
    },
    {
        "name": "IP_ADDRESS_INTERNAL",
        "pattern": re.compile(
            r"\b((?:10\.(?:\d{1,3}\.){2}\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3}))\b"
        ),
        "severity": "low",
        "description": "Internal / private IP address",
    },
]


def get_signatures():
    """Return the list of secret signatures."""
    return SIGNATURES
