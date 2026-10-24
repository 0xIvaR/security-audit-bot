"""Unit tests for the Aggregation Engine, Severity Classifier & Policy Gate (Milestone 7)."""

import sys
from unittest.mock import patch

from src.aggregator import (
    deduplicate_findings,
    evaluate_policy,
    run_audit,
    sort_findings,
)
from src.models import AuditReport, DiffFile, Finding, ScannerCategory, Severity


def create_sample_finding(
    rule_id: str = "SEC-001",
    severity: Severity = Severity.CRITICAL,
    file_path: str = "src/app.py",
    line_number: int = 10,
    category: ScannerCategory = ScannerCategory.SECRET,
) -> Finding:
    """Helper to generate sample Finding instances for testing."""
    return Finding(
        file_path=file_path,
        line_number=line_number,
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=f"Sample title for {rule_id}",
        description=f"Sample description for {rule_id}",
        remediation="Sample remediation action",
        snippet="sample code snippet",
    )


class TestDeduplicationAndSorting:
    """Tests for finding deduplication and severity-weighted sorting."""

    def test_deduplicate_identical_findings(self):
        f1 = create_sample_finding("SEC-001", Severity.HIGH, "src/a.py", 10)
        f2 = create_sample_finding("SEC-001", Severity.CRITICAL, "src/a.py", 10)
        f3 = create_sample_finding("AST-004", Severity.CRITICAL, "src/a.py", 20)

        deduped = deduplicate_findings([f1, f2, f3])
        assert len(deduped) == 2
        # Highest severity (CRITICAL) must be preserved for (src/a.py, 10, SEC-001)
        finding_at_10 = next(f for f in deduped if f.line_number == 10)
        assert finding_at_10.severity == Severity.CRITICAL

    def test_sort_findings_severity_hierarchy(self):
        f_med = create_sample_finding("AST-006", Severity.MEDIUM, "src/c.py", 5)
        f_crit1 = create_sample_finding("SEC-001", Severity.CRITICAL, "src/b.py", 15)
        f_high = create_sample_finding("AST-003", Severity.HIGH, "src/a.py", 25)
        f_crit2 = create_sample_finding("AST-001", Severity.CRITICAL, "src/a.py", 5)

        sorted_list = sort_findings([f_med, f_crit1, f_high, f_crit2])

        # CRITICAL findings first (sorted by file, line)
        assert sorted_list[0].severity == Severity.CRITICAL
        assert sorted_list[0].file_path == "src/a.py"
        assert sorted_list[1].severity == Severity.CRITICAL
        assert sorted_list[1].file_path == "src/b.py"

        # HIGH finding second
        assert sorted_list[2].severity == Severity.HIGH
        assert sorted_list[2].rule_id == "AST-003"

        # MEDIUM finding last
        assert sorted_list[3].severity == Severity.MEDIUM
        assert sorted_list[3].rule_id == "AST-006"


class TestAuditReportOrchestration:
    """Tests for run_audit pipeline orchestration and duration tracking."""

    @patch("src.aggregator.scan_diff_for_secrets")
    @patch("src.aggregator.scan_diff_for_ast_vulnerabilities")
    @patch("src.aggregator.scan_diff_for_dependencies")
    def test_run_audit_with_provided_diff_files(self, mock_deps, mock_ast, mock_secrets):
        mock_secrets.return_value = [
            create_sample_finding("SEC-001", Severity.CRITICAL, "src/app.py", 1)
        ]
        mock_ast.return_value = [create_sample_finding("AST-004", Severity.HIGH, "src/db.py", 10)]
        mock_deps.return_value = [
            create_sample_finding("DEP-OSV", Severity.MEDIUM, "requirements.txt", 5)
        ]

        diff_files = [
            DiffFile(file_path="src/app.py", added_lines={1: "key = '...' "}),
            DiffFile(file_path="src/db.py", added_lines={10: "query = '...' "}),
            DiffFile(file_path="requirements.txt", added_lines={5: "pkg == 1.0"}),
        ]

        report = run_audit(
            base_sha="base1234",
            head_sha="head5678",
            repo="octocat/Hello-World",
            pr_number=42,
            diff_files=diff_files,
        )

        assert isinstance(report, AuditReport)
        assert report.repository == "octocat/Hello-World"
        assert report.pr_number == 42
        assert report.base_sha == "base1234"
        assert report.head_sha == "head5678"
        assert report.files_scanned == 3
        assert report.total_findings == 3
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.medium_count == 1
        assert report.scan_duration_ms >= 0.0
        assert report.dep_scan_duration_ms >= 0.0
        assert report.should_block_merge is True

    @patch("src.aggregator.get_diff")
    @patch("src.aggregator.scan_diff_for_secrets")
    @patch("src.aggregator.scan_diff_for_ast_vulnerabilities")
    @patch("src.aggregator.scan_diff_for_dependencies")
    def test_run_audit_fetches_diff_when_not_provided(
        self, mock_deps, mock_ast, mock_secrets, mock_get_diff
    ):
        mock_get_diff.return_value = []
        mock_secrets.return_value = []
        mock_ast.return_value = []
        mock_deps.return_value = []

        report = run_audit(base_sha="a", head_sha="b")
        mock_get_diff.assert_called_once_with("a", "b")
        assert report.total_findings == 0
        assert report.should_block_merge is False


class TestPolicyGateExitCodes:
    """Tests for evaluate_policy CI gate enforcement."""

    def test_evaluate_policy_critical_blocks_merge(self):
        report = AuditReport(
            repository="owner/repo",
            base_sha="base",
            head_sha="head",
            scan_duration_ms=50.0,
            files_scanned=1,
            findings=[create_sample_finding(severity=Severity.CRITICAL)],
        )
        assert evaluate_policy(report) == 1

    def test_evaluate_policy_high_blocks_merge(self):
        report = AuditReport(
            repository="owner/repo",
            base_sha="base",
            head_sha="head",
            scan_duration_ms=50.0,
            files_scanned=1,
            findings=[create_sample_finding(severity=Severity.HIGH)],
        )
        assert evaluate_policy(report) == 1

    def test_evaluate_policy_medium_allows_merge(self):
        report = AuditReport(
            repository="owner/repo",
            base_sha="base",
            head_sha="head",
            scan_duration_ms=50.0,
            files_scanned=1,
            findings=[create_sample_finding(severity=Severity.MEDIUM)],
        )
        assert evaluate_policy(report) == 0

    def test_evaluate_policy_clean_report_allows_merge(self):
        report = AuditReport(
            repository="owner/repo",
            base_sha="base",
            head_sha="head",
            scan_duration_ms=50.0,
            files_scanned=1,
            findings=[],
        )
        assert evaluate_policy(report) == 0


class TestMemoryFootprintBenchmark:
    """Verifies that large finding sets consume < 50 MB memory."""

    def test_large_audit_report_memory_footprint(self):
        findings = [
            create_sample_finding(
                rule_id=f"RULE-{i % 10}",
                severity=Severity.HIGH if i % 2 == 0 else Severity.MEDIUM,
                file_path=f"src/module_{i % 50}.py",
                line_number=i + 1,
            )
            for i in range(500)
        ]
        report = AuditReport(
            repository="benchmark/large-pr",
            base_sha="a" * 40,
            head_sha="b" * 40,
            scan_duration_ms=120.0,
            files_scanned=50,
            findings=findings,
        )
        # Approximate size of findings list in memory
        estimated_bytes = sys.getsizeof(findings) + sum(sys.getsizeof(f) for f in findings)
        estimated_mb = estimated_bytes / (1024 * 1024)
        assert estimated_mb < 50.0, f"Memory footprint exceeded 50 MB: {estimated_mb:.2f} MB"
        assert report.total_findings == 500
