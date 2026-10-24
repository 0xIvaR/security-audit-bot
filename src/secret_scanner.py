"""Hybrid Secret Scanner (Compiled Regex + Shannon Entropy).

Implements Tier 1 (compiled regular expressions), Tier 2 (Shannon Entropy > 4.5 bits/char),
Tier 3 (suppression allowlist), and mandatory secret masking using redact_secret().
"""

from __future__ import annotations

import math
import re
from collections import Counter

from src.config import (
    ALLOWLIST_PATTERNS,
    ENTROPY_RULE,
    MIN_SECRET_STRING_LEN,
    SECRET_REGEX_RULES,
    SHANNON_ENTROPY_THRESHOLD,
    redact_secret,
)
from src.models import DiffFile, Finding

# Regex to extract quoted string literals or candidate tokens without whitespace
QUOTED_STRING_RE: re.Pattern[str] = re.compile(r"""['"`]([^\s'"`]{20,})['"`]""")
ASSIGNMENT_TOKEN_RE: re.Pattern[str] = re.compile(
    r"""(?:[:=]\s*|token\s+|key\s+)([A-Za-z0-9+/=_\-]{20,})""", re.IGNORECASE
)
HEX_HASH_RE: re.Pattern[str] = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
SECRET_CONTEXT_RE: re.Pattern[str] = re.compile(
    r"(?i)(key|secret|token|password|passwd|auth|credential|api_key|access_key)"
)


def calculate_shannon_entropy(candidate: str) -> float:
    """Calculate the Shannon Entropy of a string in bits per character.

    Formula:
        H(X) = -sum(P(x_i) * log2(P(x_i)))
    """
    if not candidate:
        return 0.0

    length = len(candidate)
    counts = Counter(candidate)
    entropy = 0.0

    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


REGEX_SYNTAX_RE: re.Pattern[str] = re.compile(
    r"(\[\^?[a-zA-Z0-9_\-]+\]|\(\?:|re\.compile|\\[dswDSW]\{)"
)


def is_suppressed_candidate(candidate: str, raw_line: str = "") -> bool:
    """Check whether a high-entropy candidate string matches suppression allowlists.

    Suppresses standard UUIDs, URLs, file paths, CSS colors, test dummy placeholders,
    regular expression syntax, and standalone hex hashes lacking secret variable context.
    """
    # Suppress regular expression patterns and definitions
    if "re.compile" in raw_line or REGEX_SYNTAX_RE.search(candidate):
        return True

    # Check general allowlist patterns (UUID, URL, paths, colors, dummy strings)
    for pattern in ALLOWLIST_PATTERNS:
        if pattern.search(candidate):
            return True

    # Check for git commit SHAs / sha256 checksums without secret variable context
    if HEX_HASH_RE.match(candidate):
        if not SECRET_CONTEXT_RE.search(raw_line):
            return True

    return False


def extract_candidate_tokens(line: str) -> set[str]:
    """Extract candidate string tokens of length >= 20 characters from a code line."""
    candidates: set[str] = set()

    # Extract quoted literals
    for match in QUOTED_STRING_RE.finditer(line):
        token = match.group(1).strip()
        if len(token) >= MIN_SECRET_STRING_LEN:
            candidates.add(token)

    # Extract tokens from assignment / key-value lines
    for match in ASSIGNMENT_TOKEN_RE.finditer(line):
        token = match.group(1).strip()
        if len(token) >= MIN_SECRET_STRING_LEN:
            candidates.add(token)

    return candidates


def scan_line_for_secrets(file_path: str, line_number: int, raw_line: str) -> list[Finding]:
    """Scan a single added line for secrets using Regex (Tier 1) and Entropy (Tier 2).

    Returns a list of Finding objects with fully redacted snippets.
    """
    findings: list[Finding] = []
    matched_tokens: set[str] = set()

    # -----------------------------------------------------------------------
    # Tier 1: Compiled Regular Expression Engine
    # -----------------------------------------------------------------------
    for rule_id, rule_spec in SECRET_REGEX_RULES.items():
        pattern: re.Pattern[str] = rule_spec["pattern"]
        for match in pattern.finditer(raw_line):
            # Extract matched token (use first capturing group if present, else full match)
            if match.groups():
                raw_token = match.group(1)
            else:
                raw_token = match.group(0)

            # Skip dummy sample tokens
            if any(p.search(raw_token) for p in ALLOWLIST_PATTERNS if "EXAMPLE" in str(p)):
                continue

            matched_tokens.add(raw_token)
            masked_token = redact_secret(raw_token)
            redacted_snippet = raw_line.replace(raw_token, masked_token)

            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_number,
                    rule_id=rule_id,
                    category=rule_spec["category"],
                    severity=rule_spec["severity"],
                    title=rule_spec["title"],
                    description=f"{rule_spec['description']} Token: {masked_token}",
                    remediation=rule_spec["remediation"],
                    snippet=redacted_snippet,
                )
            )

    # -----------------------------------------------------------------------
    # Tier 2: Shannon Entropy Engine (SEC-007)
    # -----------------------------------------------------------------------
    candidate_tokens = extract_candidate_tokens(raw_line)

    for candidate in candidate_tokens:
        # Avoid redundant findings if candidate token already matched in Tier 1
        if any(candidate in token or token in candidate for token in matched_tokens):
            continue

        # Tier 3: Suppression Allowlist Filter
        if is_suppressed_candidate(candidate, raw_line):
            continue

        entropy = calculate_shannon_entropy(candidate)

        if entropy > SHANNON_ENTROPY_THRESHOLD:
            matched_tokens.add(candidate)
            masked_token = redact_secret(candidate)
            redacted_snippet = raw_line.replace(candidate, masked_token)

            findings.append(
                Finding(
                    file_path=file_path,
                    line_number=line_number,
                    rule_id=ENTROPY_RULE["rule_id"],
                    category=ENTROPY_RULE["category"],
                    severity=ENTROPY_RULE["severity"],
                    title=ENTROPY_RULE["title"],
                    description=(
                        f"{ENTROPY_RULE['description']} "
                        f"(Entropy: {entropy:.2f} bits/char, Token: {masked_token})"
                    ),
                    remediation=ENTROPY_RULE["remediation"],
                    snippet=redacted_snippet,
                )
            )

    return findings


def scan_diff_file_for_secrets(diff_file: DiffFile) -> list[Finding]:
    """Scan all newly added lines in a DiffFile for exposed secrets."""
    file_findings: list[Finding] = []

    for line_num, line_content in diff_file.added_lines.items():
        line_findings = scan_line_for_secrets(
            file_path=diff_file.file_path,
            line_number=line_num,
            raw_line=line_content,
        )
        file_findings.extend(line_findings)

    return file_findings


def scan_diff_for_secrets(diff_files: list[DiffFile]) -> list[Finding]:
    """Scan all modified DiffFile objects in the PR diff for secrets."""
    all_findings: list[Finding] = []

    for diff_file in diff_files:
        all_findings.extend(scan_diff_file_for_secrets(diff_file))

    return all_findings
