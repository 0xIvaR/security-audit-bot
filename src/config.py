"""Configuration constants, rule catalogs, and security helpers.

Defines deterministic rule definitions, entropy thresholds, regex patterns,
and suppression rules as specified in PRD.md and ARCHITECTURE.md.
"""

import re
from re import Pattern
from typing import Any

from src.models import ScannerCategory, Severity

# ---------------------------------------------------------------------------
# Global SLA and GitHub Constants
# ---------------------------------------------------------------------------
IDEMPOTENCY_MARKER: str = "<!-- security-audit-bot-v1 -->"
OSV_QUERYBATCH_URL: str = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT_SECONDS: float = 3.0
MAX_SCAN_BUDGET_MS: float = 4800.0

# ---------------------------------------------------------------------------
# Secret Scanner Constants & Thresholds
# ---------------------------------------------------------------------------
SHANNON_ENTROPY_THRESHOLD: float = 4.5
MIN_SECRET_STRING_LEN: int = 20

# ---------------------------------------------------------------------------
# Secret Regex Patterns (Tier 1)
# ---------------------------------------------------------------------------
SECRET_REGEX_RULES: dict[str, dict[str, Any]] = {
    "SEC-001": {
        "title": "Exposed AWS Access Key ID",
        "severity": Severity.CRITICAL,
        "category": ScannerCategory.SECRET,
        "pattern": re.compile(
            r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
        ),
        "description": "Hardcoded AWS Access Key ID detected.",
        "remediation": "Immediately revoke this key in AWS IAM and inject credentials via GitHub Secrets/environment variables.",
    },
    "SEC-002": {
        "title": "Potential AWS Secret Access Key",
        "severity": Severity.CRITICAL,
        "category": ScannerCategory.SECRET,
        "pattern": re.compile(
            r"(?i)aws_?(?:secret)?_?(?:access)?_?key.*?['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        "description": "Potential AWS Secret Access Key assignment detected.",
        "remediation": "Revoke the exposed key and store sensitive credentials in a secrets manager or GitHub Actions Secrets.",
    },
    "SEC-003": {
        "title": "Exposed GitHub Personal Access Token",
        "severity": Severity.CRITICAL,
        "category": ScannerCategory.SECRET,
        "pattern": re.compile(
            r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82}"
        ),
        "description": "Exposed GitHub Personal Access Token (PAT) detected.",
        "remediation": "Revoke this token immediately in GitHub Developer Settings and use secrets injection.",
    },
    "SEC-004": {
        "title": "Private Cryptographic Key Header",
        "severity": Severity.CRITICAL,
        "category": ScannerCategory.SECRET,
        "pattern": re.compile(r"-----BEGIN (?:[A-Z0-9_-]+\s+)?(?:PRIVATE\s+)?KEY-----"),
        "description": "Plaintext private cryptographic key header detected.",
        "remediation": "Remove private keys from source code; store keys securely in a vault or secrets manager.",
    },
    "SEC-005": {
        "title": "Exposed JSON Web Token (JWT)",
        "severity": Severity.HIGH,
        "category": ScannerCategory.SECRET,
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "description": "Plaintext JSON Web Token (JWT) detected in source code.",
        "remediation": "Rotate compromised tokens and avoid committing runtime authorization tokens to repositories.",
    },
    "SEC-006": {
        "title": "Exposed Slack Token or Webhook",
        "severity": Severity.HIGH,
        "category": ScannerCategory.SECRET,
        "pattern": re.compile(
            r"xox[baprs]-[0-9a-zA-Z]{10,48}|https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
        ),
        "description": "Exposed Slack bot/user token or Incoming Webhook URL detected.",
        "remediation": "Revoke token or webhook in Slack App settings and supply via environment variables.",
    },
}

# Entropy rule metadata (Tier 2)
ENTROPY_RULE: dict[str, Any] = {
    "rule_id": "SEC-007",
    "title": "High-Entropy Secret Token",
    "severity": Severity.HIGH,
    "category": ScannerCategory.SECRET,
    "description": f"String literal with Shannon entropy exceeding {SHANNON_ENTROPY_THRESHOLD} bits/char detected.",
    "remediation": "Store high-entropy API tokens, salts, or passwords in environment variables or a secrets vault.",
}

# Suppression allowlist regex patterns (Tier 3)
ALLOWLIST_PATTERNS: list[Pattern[str]] = [
    re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    ),  # UUID
    re.compile(r"^https?://[^\s]+$"),  # URL
    re.compile(r"^/[a-zA-Z0-9_.\-/]+$"),  # Unix path
    re.compile(r"^[a-zA-Z]:\\[a-zA-Z0-9_.\-\\]+$"),  # Windows path
    re.compile(r"^#[0-9a-fA-F]{6}$"),  # Hex color
    re.compile(
        r"(?i)(EXAMPLE|DUMMY|TEST|PLACEHOLDER|YOUR_KEY_HERE|CHANGEME|REPLACE_ME|sample_secret)"
    ),  # Dummy placeholders
]

# ---------------------------------------------------------------------------
# AST Static Analyzer Rule Catalog
# ---------------------------------------------------------------------------
AST_RULES: dict[str, dict[str, Any]] = {
    "AST-001": {
        "title": "Dangerous Code Execution Sink",
        "severity": Severity.CRITICAL,
        "category": ScannerCategory.AST_OWASP,
        "description": "Dynamic execution call to eval(), exec(), or compile() allows arbitrary code execution.",
        "remediation": "Replace with ast.literal_eval() or deterministic domain-specific parsing.",
    },
    "AST-002": {
        "title": "Insecure Deserialization Sink",
        "severity": Severity.CRITICAL,
        "category": ScannerCategory.AST_OWASP,
        "description": "Untrusted deserialization via pickle.load/loads or unsafe yaml.load allows remote code execution.",
        "remediation": "Use yaml.safe_load() or JSON serialization instead of pickle.",
    },
    "AST-003": {
        "title": "Command Injection / Insecure Shell",
        "severity": Severity.HIGH,
        "category": ScannerCategory.AST_OWASP,
        "description": "Subprocess execution with shell=True or call to os.system()/os.popen() vulnerable to command injection.",
        "remediation": "Pass commands as argument lists without shell=True, or sanitize input arguments.",
    },
    "AST-004": {
        "title": "OWASP SQL Injection Sink",
        "severity": Severity.CRITICAL,
        "category": ScannerCategory.AST_OWASP,
        "description": "SQL statement constructed dynamically using f-string, concatenation, modulo, or .format().",
        "remediation": "Use parameterized queries passing arguments as tuple parameters, e.g. cursor.execute('SELECT ... %s', (val,)).",
    },
    "AST-005": {
        "title": "Hardcoded Sensitive Credential Assignment",
        "severity": Severity.HIGH,
        "category": ScannerCategory.AST_OWASP,
        "description": "Direct string literal assignment to variable representing password, token, or secret key.",
        "remediation": "Fetch sensitive values dynamically using os.getenv() or a secret management client.",
    },
    "AST-006": {
        "title": "Weak Cryptographic Hash Function",
        "severity": Severity.MEDIUM,
        "category": ScannerCategory.AST_OWASP,
        "description": "Use of deprecated or cryptographically broken hash function (MD5 or SHA1).",
        "remediation": "Use SHA-256 (hashlib.sha256()) or modern algorithms like BLAKE2 / Argon2.",
    },
}

# ---------------------------------------------------------------------------
# Dependency Manifest Rule Metadata
# ---------------------------------------------------------------------------
DEP_RULE: dict[str, Any] = {
    "rule_id": "DEP-OSV",
    "category": ScannerCategory.DEPENDENCY_CVE,
    "title": "Vulnerable Dependency (CVE/GHSA)",
    "description": "Dependency version contains known security vulnerabilities in OSV.dev database.",
    "remediation": "Upgrade package to a patched version specified in finding details.",
}


# ---------------------------------------------------------------------------
# Security Helpers
# ---------------------------------------------------------------------------
def redact_secret(raw_secret: str) -> str:
    """Mask a secret string preserving only the first 4 and last 4 characters.

    Examples:
        'AKIAIOSFODNN7EXAMPLE' -> 'AKIA************MPLE'
        'short' -> '********'
    """
    if len(raw_secret) <= 8:
        return "********"
    return f"{raw_secret[:4]}{'*' * 12}{raw_secret[-4:]}"
