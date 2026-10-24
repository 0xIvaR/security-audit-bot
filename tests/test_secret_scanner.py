"""Unit tests for the Hybrid Secret Scanner (Milestone 3)."""

import time

from src.models import DiffFile, ScannerCategory, Severity
from src.secret_scanner import (
    calculate_shannon_entropy,
    is_suppressed_candidate,
    scan_diff_file_for_secrets,
    scan_diff_for_secrets,
    scan_line_for_secrets,
)


class TestShannonEntropyCalculator:
    """Tests for calculate_shannon_entropy."""

    def test_empty_string(self):
        assert calculate_shannon_entropy("") == 0.0

    def test_single_repeated_character(self):
        # Entropy of identical characters is exactly 0.0
        assert calculate_shannon_entropy("A" * 30) == 0.0

    def test_low_entropy_english_text(self):
        # Natural language / repetitive words have low entropy (< 4.5)
        text = "user_authentication_handler_service_configuration"
        entropy = calculate_shannon_entropy(text)
        assert entropy < 4.5

    def test_high_entropy_random_token(self):
        # High-randomness alphanumeric token with Shannon entropy > 4.5
        token = "x7K9mQ2vL5pB8wR1tY4jN3kH6aZ0cE2g"
        entropy = calculate_shannon_entropy(token)
        assert entropy > 4.5


class TestSuppressionAllowlist:
    """Tests for Tier 3 allowlist suppression."""

    def test_uuid_suppressed(self):
        uuid_str = "123e4567-e89b-12d3-a456-426614174000"
        assert is_suppressed_candidate(uuid_str) is True

    def test_url_suppressed(self):
        url = "https://api.github.com/repos/octocat/Hello-World/issues/comments"
        assert is_suppressed_candidate(url) is True

    def test_unix_path_suppressed(self):
        path = "/usr/local/var/log/application_service.log"
        assert is_suppressed_candidate(path) is True

    def test_windows_path_suppressed(self):
        path = r"C:\Windows\System32\drivers\etc\hosts.txt"
        assert is_suppressed_candidate(path) is True

    def test_hex_color_suppressed(self):
        color = "#A1B2C3"
        assert is_suppressed_candidate(color) is True

    def test_placeholder_suppressed(self):
        placeholder = "YOUR_API_KEY_HERE_REPLACE_ME_NOW"
        assert is_suppressed_candidate(placeholder) is True

    def test_sha_hash_without_secret_context_suppressed(self):
        commit_sha = "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
        line = f"git_commit = '{commit_sha}'"
        assert is_suppressed_candidate(commit_sha, raw_line=line) is True

    def test_sha_hash_with_secret_context_not_suppressed(self):
        # A 40-char hash assigned to an api_key or password should NOT be suppressed
        secret_hash = "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
        line = f"api_key = '{secret_hash}'"
        assert is_suppressed_candidate(secret_hash, raw_line=line) is False


class TestTier1RegexRules:
    """Tests for Tier 1 compiled regex secret rules."""

    def test_sec_001_aws_access_key(self):
        raw_key = "AKIA1234567890ABCDEF"
        line = f"AWS_ACCESS_KEY_ID = '{raw_key}'"
        findings = scan_line_for_secrets("config/aws.py", 10, line)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-001"
        assert f.severity == Severity.CRITICAL
        assert f.category == ScannerCategory.SECRET
        # Verify secret was redacted in snippet and description
        assert raw_key not in f.snippet
        assert "AKIA************CDEF" in f.snippet

    def test_sec_002_aws_secret_key(self):
        secret_val = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY1234567890"
        line = f"aws_secret_access_key = '{secret_val}'"
        findings = scan_line_for_secrets("config/aws.py", 12, line)

        assert any(f.rule_id == "SEC-002" for f in findings)
        f = next(f for f in findings if f.rule_id == "SEC-002")
        assert f.severity == Severity.CRITICAL
        assert secret_val not in f.snippet

    def test_sec_003_github_pat(self):
        pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"
        line = f"GITHUB_TOKEN = '{pat}'"
        findings = scan_line_for_secrets("deploy.py", 5, line)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-003"
        assert f.severity == Severity.CRITICAL
        assert pat not in f.snippet
        assert "ghp_************yzAB" in f.snippet

    def test_sec_004_private_key_header(self):
        header = "-----BEGIN RSA PRIVATE KEY-----"
        line = f"KEY_START = '{header}'"
        findings = scan_line_for_secrets("auth/keys.py", 20, line)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-004"
        assert f.severity == Severity.CRITICAL

    def test_sec_005_jwt_token(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        line = f"AUTH_HEADER = 'Bearer {jwt}'"
        findings = scan_line_for_secrets("api/client.py", 15, line)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-005"
        assert f.severity == Severity.HIGH
        assert jwt not in f.snippet

    def test_sec_006_slack_webhook(self):
        webhook = "https://hooks.slack.com/services/T12345678/B12345678/abcdef1234567890abcdef12"
        line = f"SLACK_URL = '{webhook}'"
        findings = scan_line_for_secrets("notifications.py", 8, line)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-006"
        assert f.severity == Severity.HIGH
        assert webhook not in f.snippet


class TestTier2ShannonEntropy:
    """Tests for Tier 2 Shannon Entropy rule (SEC-007)."""

    def test_high_entropy_secret_detected(self):
        high_entropy_token = "x7K9mQ2vL5pB8wR1tY4jN3kH6aZ0cE2g"
        line = f"API_SECRET = '{high_entropy_token}'"
        findings = scan_line_for_secrets("secrets.py", 3, line)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "SEC-007"
        assert f.severity == Severity.HIGH
        assert high_entropy_token not in f.snippet
        assert "x7K9************cE2g" in f.snippet

    def test_clean_lines_produce_no_findings(self):
        clean_lines = [
            "def calculate_total(price: float, tax_rate: float) -> float:",
            "    return price * (1.0 + tax_rate)",
            "DATABASE_URL = 'postgresql://localhost:5432/testdb'",
            "LOGGER_NAME = 'app.services.authentication'",
        ]
        for line in clean_lines:
            findings = scan_line_for_secrets("app/calc.py", 1, line)
            assert len(findings) == 0


class TestDiffScanning:
    """Tests for scan_diff_for_secrets on multiple DiffFile objects."""

    def test_scan_diff_file_and_diff_collection(self):
        diff1 = DiffFile(
            file_path="src/config.py",
            added_lines={
                10: "AWS_KEY = 'AKIA1234567890ABCDEF'",
                15: "print('safe code line')",
            },
        )
        diff2 = DiffFile(
            file_path="src/utils.py",
            added_lines={
                42: "SECRET = 'x7K9mQ2vL5pB8wR1tY4jN3kH6aZ0cE2g'",
            },
        )

        findings = scan_diff_for_secrets([diff1, diff2])
        assert len(findings) == 2
        assert findings[0].file_path == "src/config.py"
        assert findings[0].rule_id == "SEC-001"
        assert findings[1].file_path == "src/utils.py"
        assert findings[1].rule_id == "SEC-007"

    def test_scan_latency_benchmark(self):
        # 50 lines with mixed secrets and normal code
        added_lines = {}
        for i in range(50):
            if i % 10 == 0:
                added_lines[i + 1] = f"AWS_ID_{i} = 'AKIA{i:016d}'"
            else:
                added_lines[i + 1] = f"normal_var_{i} = 'normal_safe_string_value_{i}'"

        diff = DiffFile(file_path="test_perf.py", added_lines=added_lines)

        start = time.perf_counter()
        findings = scan_diff_file_for_secrets(diff)
        duration_ms = (time.perf_counter() - start) * 1000.0

        assert len(findings) == 5
        assert duration_ms < 350.0, f"Scanning took {duration_ms:.2f} ms (budget: < 350 ms)"
