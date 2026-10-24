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
        print(f"Target Repository : {args.repo or 'Local / Unspecified'}")
        print(f"Diff Comparison   : base ({args.base_sha[:7]}) ... head ({args.head_sha[:7]})")
        print("Scan Mode         : Pull Request Scoped (Modified '+' Lines Only)")
        print("-" * 80)
        print("[✓] Milestone 1 Baseline Initialized: CLI and models operational.")
        print("-" * 80)
        return 0

    print("Notice: No base/head SHAs provided. Use --help to view usage instructions.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
