"""Unit tests for domain models and security helper functions."""

import pytest
from pydantic import ValidationError

from src.config import redact_secret
from src.models import AuditReport, DiffFile, Finding, ScannerCategory, Severity


class TestSeverityAndCategory:
    """Tests for enum classifications."""

    def test_severity_values(self):
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"

    def test_category_values(self):
        assert ScannerCategory.SECRET.value == "SECRET"
        assert ScannerCategory.AST_OWASP.value == "AST_OWASP"
        assert ScannerCategory.DEPENDENCY_CVE.value == "DEPENDENCY_CVE"


class TestDiffFileModel:
    """Tests for DiffFile model validation and behavior."""

    def test_valid_diff_file(self):
        diff = DiffFile(
            file_path="src/main.py",
            added_lines={10: "print('hello')", 11: "x = 42"},
        )
        assert diff.file_path == "src/main.py"
        assert diff.added_lines[10] == "print('hello')"
        assert len(diff.added_lines) == 2

    def test_diff_file_immutable(self):
        diff = DiffFile(file_path="app.py", added_lines={1: "code"})
        with pytest.raises(ValidationError):
            diff.file_path = "other.py"  # Model is frozen


class TestFindingModel:
    """Tests for Finding model validation."""

    def test_valid_finding(self):
        finding = Finding(
            file_path="src/db.py",
            line_number=42,
            rule_id="AST-004",
            category=ScannerCategory.AST_OWASP,
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="Dynamic query formatting",
            remediation="Use parameterized query",
            snippet="cursor.execute(f'SELECT...')",
        )
        assert finding.file_path == "src/db.py"
        assert finding.line_number == 42
        assert finding.severity == Severity.CRITICAL
        assert finding.rule_id == "AST-004"

    def test_invalid_line_number(self):
        with pytest.raises(ValidationError):
            Finding(
                file_path="src/db.py",
                line_number=0,  # line_number must be >= 1
                rule_id="AST-004",
                category=ScannerCategory.AST_OWASP,
                severity=Severity.CRITICAL,
                title="SQL Injection",
                description="desc",
                remediation="fix",
            )


class TestAuditReportModel:
    """Tests for AuditReport aggregation and policy gate logic."""

    def _create_sample_finding(self, severity: Severity, rule_id: str) -> Finding:
        return Finding(
            file_path="src/app.py",
            line_number=10,
            rule_id=rule_id,
            category=ScannerCategory.SECRET,
            severity=severity,
            title=f"Sample {rule_id}",
            description="desc",
            remediation="fix",
        )

    def test_clean_audit_report(self):
        report = AuditReport(
            repository="owner/repo",
            pr_number=42,
            base_sha="a1b2c3d",
            head_sha="e5f6a7b",
            scan_duration_ms=120.5,
            files_scanned=5,
            findings=[],
        )
        assert report.critical_count == 0
        assert report.high_count == 0
        assert report.medium_count == 0
        assert report.total_findings == 0
        assert not report.should_block_merge

    def test_critical_finding_blocks_merge(self):
        finding = self._create_sample_finding(Severity.CRITICAL, "SEC-001")
        report = AuditReport(
            repository="owner/repo",
            base_sha="a1b2c3d",
            head_sha="e5f6a7b",
            scan_duration_ms=250.0,
            files_scanned=1,
            findings=[finding],
        )
        assert report.critical_count == 1
        assert report.high_count == 0
        assert report.should_block_merge

    def test_high_finding_blocks_merge(self):
        finding = self._create_sample_finding(Severity.HIGH, "AST-003")
        report = AuditReport(
            repository="owner/repo",
            base_sha="a1b2c3d",
            head_sha="e5f6a7b",
            scan_duration_ms=180.0,
            files_scanned=2,
            findings=[finding],
        )
        assert report.high_count == 1
        assert report.should_block_merge

    def test_medium_only_allows_merge(self):
        finding = self._create_sample_finding(Severity.MEDIUM, "AST-006")
        report = AuditReport(
            repository="owner/repo",
            base_sha="a1b2c3d",
            head_sha="e5f6a7b",
            scan_duration_ms=95.0,
            files_scanned=1,
            findings=[finding],
        )
        assert report.critical_count == 0
        assert report.high_count == 0
        assert report.medium_count == 1
        assert not report.should_block_merge


class TestSecretRedactionHelper:
    """Tests for secret redaction helper function."""

    def test_redact_aws_key(self):
        assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA************MPLE"

    def test_redact_short_secret(self):
        assert redact_secret("secret") == "********"
        assert redact_secret("12345678") == "********"

    def test_redact_medium_secret(self):
        result = redact_secret("123456789")
        assert result == "1234************6789"
        assert len(result) == 20
