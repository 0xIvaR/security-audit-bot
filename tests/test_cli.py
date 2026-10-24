"""Unit tests for the CLI harness and argument parser."""

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

    def test_main_with_base_and_head(self, capsys):
        exit_code = main(["--base", "a1b2c3d4", "--head", "e5f6a7b8", "--repo", "owner/repo"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Target Repository : owner/repo" in captured.out
        assert "Diff Comparison   : base (a1b2c3d) ... head (e5f6a7b)" in captured.out
        assert "Milestone 1 Baseline Initialized" in captured.out
