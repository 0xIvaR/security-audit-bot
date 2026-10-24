"""CLI Entrypoint for the Automated GitHub PR Security Audit Bot.

Orchestrates diff parsing, security scanning engines, aggregation,
and PR comment generation within the < 4.8s SLA budget.
"""

import argparse
import sys

BANNER: str = r"""================================================================================
           🛡️  GITHUB PR SECURITY AUDIT BOT — STATIC SCANNER v1.0.0
================================================================================"""


def build_parser() -> argparse.ArgumentParser:
    """Build and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="security-audit-bot",
        description="Zero-configuration containerized static security analysis engine for GitHub PRs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Run diff scan between base and head commits in dry-run mode:
  python -m src.main --base main --head feature --dry-run

  # Run full CI PR audit with GitHub comment posting:
  python -m src.main --base "$BASE_SHA" --head "$HEAD_SHA" --repo "$REPO" --pr-number "$PR"
""",
    )

    parser.add_argument(
        "--base",
        dest="base_sha",
        type=str,
        default=None,
        help="Base commit SHA or branch name for comparison (e.g. main).",
    )
    parser.add_argument(
        "--head",
        dest="head_sha",
        type=str,
        default=None,
        help="Target commit SHA or branch containing changes to inspect.",
    )
    parser.add_argument(
        "--repo",
        dest="repo",
        type=str,
        default=None,
        help="Target GitHub repository in format 'owner/repo'.",
    )
    parser.add_argument(
        "--pr-number",
        dest="pr_number",
        type=int,
        default=None,
        help="GitHub Pull Request number for comment upsert.",
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Run offline diff scan and print report to stdout without calling GitHub API.",
    )
    parser.add_argument(
        "--html-report",
        dest="html_report",
        type=str,
        default=None,
        help="Optional destination path to export a standalone dark-mode HTML report.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0",
        help="Show program version and exit.",
    )

    return parser


def print_banner() -> None:
    """Print the formatted CLI banner."""
    print(BANNER)


def main(argv: list[str] | None = None) -> int:
    """Main execution entrypoint for CLI runner.

    Returns:
        Exit code (0 for clean PR or successful dry run, 1 for merge-blocking findings).
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    print_banner()

    # Informational output for Milestone 1 baseline execution
    if args.base_sha and args.head_sha:
        import time

        from src.diff_parser import get_diff

        print(f"Target Repository : {args.repo or 'Local / Unspecified'}")
        print(f"Diff Comparison   : base ({args.base_sha[:7]}) ... head ({args.head_sha[:7]})")
        print("Scan Mode         : Pull Request Scoped (Modified '+' Lines Only)")
        print("-" * 80)

        start_time = time.perf_counter()
        try:
            diff_files = get_diff(args.base_sha, args.head_sha)
            diff_duration_ms = (time.perf_counter() - start_time) * 1000.0
            total_added_lines = sum(len(df.added_lines) for df in diff_files)
            print(
                f"[✓] Git Diff Parsed         : {len(diff_files)} files modified "
                f"({total_added_lines} added lines) [{diff_duration_ms:.0f} ms]"
            )
        except RuntimeError as exc:
            print(f"[!] Git Diff Error          : {exc}", file=sys.stderr)
            return 1

        from src.aggregator import evaluate_policy, run_audit
        from src.models import ScannerCategory

        report = run_audit(
            base_sha=args.base_sha,
            head_sha=args.head_sha,
            repo=args.repo,
            pr_number=args.pr_number,
            diff_files=diff_files,
        )

        secret_count = sum(1 for f in report.findings if f.category == ScannerCategory.SECRET)
        ast_count = sum(1 for f in report.findings if f.category == ScannerCategory.AST_OWASP)
        dep_count = sum(1 for f in report.findings if f.category == ScannerCategory.DEPENDENCY_CVE)

        sec_status = "[✓]" if secret_count == 0 else "[!]"
        ast_status = "[✓]" if ast_count == 0 else "[!]"
        dep_status = "[✓]" if dep_count == 0 else "[!]"

        print(
            f"{sec_status} Hybrid Secret Scanner   : {secret_count} leaks detected "
            f"(Entropy > 4.5 bits/char)"
        )
        print(f"{ast_status} AST Static Analyzer     : {ast_count} vulnerabilities flagged")
        print(
            f"{dep_status} Dependency Auditor      : {dep_count} CVEs found "
            f"(OSV.dev batch) [{report.dep_scan_duration_ms:.0f} ms]"
        )

        if report.findings:
            print("-" * 80)
            print(f"🚨 FINDINGS ({len(report.findings)} issues detected):")
            for f in report.findings:
                print(f"\n  [{f.severity.value}] {f.rule_id}: {f.title}")
                print(f"  Location : {f.file_path}:{f.line_number}")
                if f.snippet:
                    print(f"  Snippet  : {f.snippet.strip()}")
                print(f"  Fix      : {f.remediation}")

        # Export HTML report if requested
        if args.html_report:
            from pathlib import Path

            from src.pr_commenter import build_html_report

            html_content = build_html_report(report)
            output_path = Path(args.html_report)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(html_content, encoding="utf-8")
            print(f"[✓] HTML Report Exported    : {output_path.resolve()}")

        # Post or update PR comment if running in CI mode (repo & pr-number provided, not dry-run)
        if args.repo and args.pr_number and not args.dry_run:
            from src.pr_commenter import post_or_update_pr_comment

            post_or_update_pr_comment(
                report=report,
                repo=args.repo,
                pr_number=args.pr_number,
            )

        print("-" * 80)
        return evaluate_policy(report)

    print("Notice: No base/head SHAs provided. Use --help to view usage instructions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
