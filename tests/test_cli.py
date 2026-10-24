"""Unit tests for the CLI harness and argument parser."""

from unittest.mock import patch

import pytest

from src.main import build_parser, main


class TestCLIParser:
    """Tests for build_parser argument parsing."""

    def test_default_parser_args(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.base_sha is None
        assert args.head_sha is None
        assert args.repo is None
        assert args.pr_number is None
        assert not args.dry_run
        assert args.html_report is None

    def test_full_pr_arguments(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "--base",
                "main",
                "--head",
                "feature-branch",
                "--repo",
                "octocat/Hello-World",
                "--pr-number",
                "42",
                "--dry-run",
                "--html-report",
                "report.html",
            ]
        )
        assert args.base_sha == "main"
        assert args.head_sha == "feature-branch"
        assert args.repo == "octocat/Hello-World"
        assert args.pr_number == 42
        assert args.dry_run is True
        assert args.html_report == "report.html"

    def test_version_flag(self, capsys):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "1.0.0" in (captured.out + captured.err)


class TestCLIMain:
    """Tests for main() entrypoint."""

    def test_main_without_args_returns_zero(self, capsys):
        exit_code = main([])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "GITHUB PR SECURITY AUDIT BOT" in captured.out
        assert "Notice: No base/head SHAs provided" in captured.out

    @patch("src.diff_parser.get_diff")
    def test_main_with_base_and_head(self, mock_get_diff, capsys):
        from src.models import DiffFile

        mock_get_diff.return_value = [
            DiffFile(file_path="src/app.py", added_lines={1: "print(1)", 2: "print(2)"})
        ]
        exit_code = main(["--base", "a1b2c3d4", "--head", "e5f6a7b8", "--repo", "owner/repo"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Target Repository : owner/repo" in captured.out
        assert "Diff Comparison   : base (a1b2c3d) ... head (e5f6a7b)" in captured.out
        assert "Git Diff Parsed" in captured.out
        assert "1 files modified" in captured.out
        assert "2 added lines" in captured.out

    @patch("src.diff_parser.get_diff")
    def test_main_with_diff_error(self, mock_get_diff, capsys):
        mock_get_diff.side_effect = RuntimeError("git command failed")
        exit_code = main(["--base", "bad", "--head", "worse"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Git Diff Error" in captured.err

    @patch("src.diff_parser.get_diff")
    def test_main_with_secret_findings(self, mock_get_diff, capsys):
        from src.models import DiffFile

        mock_get_diff.return_value = [
            DiffFile(
                file_path="src/config.py",
                added_lines={1: "AWS_KEY = 'AKIA1234567890ABCDEF'"},
            )
        ]
        exit_code = main(["--base", "a1b2c3d4", "--head", "e5f6a7b8"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Hybrid Secret Scanner" in captured.out
        assert "1 leaks detected" in captured.out
        assert "🚨 FINDINGS (1 issues detected):" in captured.out
        assert "SEC-001" in captured.out
        assert "AKIA************CDEF" in captured.out

    @patch("src.diff_parser.get_diff")
    @patch("src.ast_analyzer.scan_python_source")
    def test_main_with_ast_findings(self, mock_scan_source, mock_get_diff, capsys):
        from src.models import DiffFile, Finding, ScannerCategory, Severity

        mock_get_diff.return_value = [
            DiffFile(
                file_path="src/query.py",
                added_lines={1: 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'},
            )
        ]
        mock_scan_source.return_value = [
            Finding(
                rule_id="AST-004",
                category=ScannerCategory.AST_OWASP,
                severity=Severity.HIGH,
                title="Dynamic SQL query construction (SQL Injection vulnerability)",
                description="Potential SQL injection detected.",
                file_path="src/query.py",
                line_number=1,
                snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                remediation="Use parameterized queries.",
            )
        ]
        exit_code = main(["--base", "a1b2c3d4", "--head", "e5f6a7b8"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "AST Static Analyzer" in captured.out
        assert "1 vulnerabilities flagged" in captured.out
        assert "AST-004" in captured.out
        assert "Dynamic SQL query construction" in captured.out

    @patch("src.diff_parser.get_diff")
    @patch("src.dep_scanner.query_osv_batch")
    def test_main_with_dep_findings(self, mock_query_osv, mock_get_diff, capsys):
        from src.models import DiffFile, Finding, ScannerCategory, Severity

        mock_get_diff.return_value = [
            DiffFile(
                file_path="requirements.txt",
                added_lines={1: "requests==2.19.0"},
            )
        ]
        mock_query_osv.return_value = [
            Finding(
                rule_id="DEP-OSV",
                category=ScannerCategory.DEPENDENCY_CVE,
                severity=Severity.CRITICAL,
                title="Vulnerable dependency: requests==2.19.0 [CVE-2018-18074]",
                description="Credential leak on redirect.",
                file_path="requirements.txt",
                line_number=1,
                snippet="requests==2.19.0",
                remediation="Upgrade requests to >= 2.20.0.",
            )
        ]
        exit_code = main(["--base", "a1b2c3d4", "--head", "e5f6a7b8"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert "Dependency Auditor" in captured.out
        assert "1 CVEs found" in captured.out
        assert "DEP-OSV" in captured.out
        assert "requests==2.19.0" in captured.out

    @patch("src.diff_parser.get_diff")
    @patch("src.ast_analyzer.scan_python_source")
    def test_main_with_medium_only_allows_merge(self, mock_scan_source, mock_get_diff, capsys):
        from src.models import DiffFile, Finding, ScannerCategory, Severity

        mock_get_diff.return_value = [
            DiffFile(
                file_path="src/hashing.py",
                added_lines={1: "hashlib.md5(b'test')"},
            )
        ]
        mock_scan_source.return_value = [
            Finding(
                rule_id="AST-006",
                category=ScannerCategory.AST_OWASP,
                severity=Severity.MEDIUM,
                title="Weak Cryptographic Hash Function",
                description="MD5 is weak.",
                file_path="src/hashing.py",
                line_number=1,
                snippet="hashlib.md5(b'test')",
                remediation="Use SHA-256.",
            )
        ]
        exit_code = main(["--base", "a1b2c3d4", "--head", "e5f6a7b8"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "AST-006" in captured.out
