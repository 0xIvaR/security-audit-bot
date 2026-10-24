"""Unit tests for the Automated GitHub PR Review Commenter & Report Generator (Milestone 8)."""

from unittest.mock import MagicMock, patch

import requests

from src.config import IDEMPOTENCY_MARKER
from src.models import AuditReport, Finding, ScannerCategory, Severity
from src.pr_commenter import (
    build_html_report,
    build_markdown_report,
    escape_markdown_table_cell,
    post_or_update_pr_comment,
)


def create_sample_report(
    findings: list[Finding] | None = None,
    scan_duration_ms: float = 120.0,
    files_scanned: int = 5,
) -> AuditReport:
    """Helper to construct AuditReport fixtures."""
    return AuditReport(
        repository="octocat/Hello-World",
        pr_number=42,
        base_sha="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        head_sha="f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3b2a1f6e5",
        scan_duration_ms=scan_duration_ms,
        dep_scan_duration_ms=30.0,
        files_scanned=files_scanned,
        findings=findings or [],
    )


class TestMarkdownReportBuilder:
    """Tests for build_markdown_report formatting and idempotency marker."""

    def test_line_one_always_has_idempotency_marker(self):
        clean_report = create_sample_report([])
        clean_md = build_markdown_report(clean_report)
        assert clean_md.splitlines()[0] == IDEMPOTENCY_MARKER

        vuln_report = create_sample_report(
            [
                Finding(
                    file_path="src/app.py",
                    line_number=10,
                    rule_id="AST-001",
                    category=ScannerCategory.AST_OWASP,
                    severity=Severity.CRITICAL,
                    title="Code execution sink",
                    description="eval() detected",
                    remediation="Use ast.literal_eval()",
                    snippet="eval(x)",
                )
            ]
        )
        vuln_md = build_markdown_report(vuln_report)
        assert vuln_md.splitlines()[0] == IDEMPOTENCY_MARKER

    def test_clean_report_markdown_structure(self):
        report = create_sample_report([])
        md = build_markdown_report(report)

        assert "## 🛡️ CI Security Audit Report — Passed" in md
        assert "[!TIP]" in md
        assert "Audit Status" in md
        assert "`PASSED`" in md
        assert "Total PR Execution Time" in md
        assert "120 ms" in md
        assert "Files Modified & Scanned" in md
        assert "5 files" in md
        assert "f6e5d4c" in md

    def test_blocked_report_markdown_structure(self):
        findings = [
            Finding(
                file_path="src/query.py",
                line_number=25,
                rule_id="AST-004",
                category=ScannerCategory.AST_OWASP,
                severity=Severity.CRITICAL,
                title="SQL Injection",
                description="Dynamic query with f-string",
                remediation="Use parameterized tuple (query, (val,))",
                snippet='cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
            ),
            Finding(
                file_path="src/config.py",
                line_number=12,
                rule_id="SEC-001",
                category=ScannerCategory.SECRET,
                severity=Severity.HIGH,
                title="AWS Key",
                description="Hardcoded key",
                remediation="Use env var",
                snippet="AWS_KEY = 'AKIA************CDEF'",
            ),
        ]
        report = create_sample_report(findings, files_scanned=2)
        md = build_markdown_report(report)

        assert "## 🛡️ CI Security Audit Report — Action Required" in md
        assert "[!CAUTION]" in md
        assert "Merge Blocked" in md
        assert "detected **2** blocking issue(s)" in md
        assert "`FAILED (Merge Blocked)`" in md
        assert "| 🔴 **CRITICAL** | `AST-004` | `src/query.py:25` |" in md
        assert "| 🟠 **HIGH** | `SEC-001` | `src/config.py:12` |" in md
        assert "<details>" in md
        assert (
            "<summary>🔴 <b>[AST-004] SQL Injection in <code>src/query.py:25</code></b></summary>"
            in md
        )
        assert "```python" in md
        assert "cursor.execute" in md

    def test_report_with_medium_warnings_structure(self):
        findings = [
            Finding(
                file_path="src/hash.py",
                line_number=5,
                rule_id="AST-006",
                category=ScannerCategory.AST_OWASP,
                severity=Severity.MEDIUM,
                title="Weak MD5 Hash",
                description="MD5 is cryptographically broken",
                remediation="Use hashlib.sha256()",
                snippet="hashlib.md5(data)",
            )
        ]
        report = create_sample_report(findings)
        md = build_markdown_report(report)

        # Non-blocking: status is Passed
        assert "## 🛡️ CI Security Audit Report — Passed" in md
        assert "[!TIP]" in md
        assert "Medium Warnings" in md
        assert "Non-Blocking Advisories (1)" in md
        assert "| 🟡 **MEDIUM** | `AST-006` |" in md

    def test_escape_markdown_table_cell(self):
        raw = "Line with | pipe and \n newline"
        escaped = escape_markdown_table_cell(raw)
        assert "|" not in escaped or "\\|" in escaped
        assert "\n" not in escaped


class TestHTMLReportBuilder:
    """Tests for build_html_report static HTML rendering."""

    def test_html_report_rendering_clean(self):
        report = create_sample_report([])
        html_out = build_html_report(report)

        assert "<!DOCTYPE html>" in html_out
        assert "<title>Security Audit Report — octocat/Hello-World</title>" in html_out
        assert "--bg-primary: #0D1117;" in html_out
        assert "badge-passed" in html_out
        assert "PASSED" in html_out
        assert "No vulnerabilities detected." in html_out

    def test_html_report_rendering_with_findings(self):
        findings = [
            Finding(
                file_path="src/vulnerable.py",
                line_number=42,
                rule_id="AST-001",
                category=ScannerCategory.AST_OWASP,
                severity=Severity.CRITICAL,
                title="eval() code execution sink",
                description="eval() called on dynamic input",
                remediation="Replace with ast.literal_eval()",
                snippet="eval(payload)",
            )
        ]
        report = create_sample_report(findings)
        html_out = build_html_report(report)

        assert "badge-critical" in html_out
        assert "FAILED (Merge Blocked)" in html_out
        assert "AST-001" in html_out
        assert "src/vulnerable.py:42" in html_out
        assert "eval(payload)" in html_out
        assert "Replace with ast.literal_eval()" in html_out


class TestGitHubAPIClient:
    """Tests for post_or_update_pr_comment API client and idempotency."""

    def test_missing_github_token_returns_false(self, capsys):
        report = create_sample_report([])
        with patch.dict("os.environ", {}, clear=True):
            success = post_or_update_pr_comment(report, "owner/repo", 42, token=None)
            assert success is False
            captured = capsys.readouterr()
            assert "GITHUB_TOKEN not provided" in captured.err

    @patch("requests.Session.get")
    @patch("requests.Session.post")
    def test_post_new_comment_when_marker_absent(self, mock_post, mock_get, capsys):
        # Existing comments list without our idempotency tag
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = [
            {"id": 101, "body": "Great PR! Looks good to me."},
            {"id": 102, "body": "Please add more tests."},
        ]
        mock_get_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_get_resp

        mock_post_resp = MagicMock()
        mock_post_resp.json.return_value = {"id": 201}
        mock_post_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_post_resp

        report = create_sample_report([])
        success = post_or_update_pr_comment(report, "owner/repo", 42, token="ghp_fake_token")

        assert success is True
        mock_post.assert_called_once()
        post_call_kwargs = mock_post.call_args[1]
        assert "body" in post_call_kwargs["json"]
        assert IDEMPOTENCY_MARKER in post_call_kwargs["json"]["body"]
        captured = capsys.readouterr()
        assert "Posted new audit comment (id 201)" in captured.out

    @patch("requests.Session.get")
    @patch("requests.Session.patch")
    def test_update_existing_comment_when_marker_present(self, mock_patch, mock_get, capsys):
        # Existing comments list containing our idempotency tag
        mock_get_resp = MagicMock()
        mock_get_resp.json.return_value = [
            {"id": 101, "body": "Nice code."},
            {"id": 102, "body": f"{IDEMPOTENCY_MARKER}\nOld security audit report."},
        ]
        mock_get_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_get_resp

        mock_patch_resp = MagicMock()
        mock_patch_resp.raise_for_status = MagicMock()
        mock_patch.return_value = mock_patch_resp

        report = create_sample_report([])
        success = post_or_update_pr_comment(report, "owner/repo", 42, token="ghp_fake_token")

        assert success is True
        mock_patch.assert_called_once()
        patch_url = mock_patch.call_args[0][0]
        assert "/issues/comments/102" in patch_url
        captured = capsys.readouterr()
        assert "Updated existing audit comment (id 102)" in captured.out

    @patch("requests.Session.get")
    def test_api_network_error_handled_gracefully(self, mock_get, capsys):
        mock_get.side_effect = requests.RequestException("GitHub API connection error")

        report = create_sample_report([])
        success = post_or_update_pr_comment(report, "owner/repo", 42, token="ghp_fake_token")

        assert success is False
        captured = capsys.readouterr()
        assert "GitHub PR Comment Error" in captured.err
