"""PR Security Audit Simulation Script.

Simulates two production Pull Request scenarios:
1. Scenario A: Vulnerable PR containing CRITICAL AWS keys, dynamic SQL injection,
   and vulnerable dependencies (Merge Blocked -> Exit Code 1).
2. Scenario B: Clean PR containing safe parameterized SQL, modern hashing, and
   secure pinned dependencies (Passed Clean -> Exit Code 0).

Generates ANSI terminal tables, GitHub Markdown comments, and self-contained
interactive HTML reports under artifacts/reports/.
"""

from __future__ import annotations

from pathlib import Path

from src.aggregator import deduplicate_findings, evaluate_policy, sort_findings
from src.ast_analyzer import scan_python_source
from src.models import AuditReport, DiffFile, Finding, ScannerCategory, Severity
from src.pr_commenter import build_html_report, build_markdown_report
from src.secret_scanner import scan_diff_file_for_secrets


def run_scenario_blocked(output_dir: Path) -> AuditReport:
    """Simulate a PR containing high/critical security vulnerabilities."""
    print("\n" + "=" * 76)
    print("  SIMULATING SCENARIO A: Vulnerable Pull Request (Merge Blocked)")
    print("=" * 76 + "\n")

    # 1. Secret Scanner Finding
    vulnerable_secret_line = 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7ABCD123"'
    diff_file_secret = DiffFile(
        file_path="src/config/aws.py",
        added_lines={14: vulnerable_secret_line},
    )
    secret_findings = scan_diff_file_for_secrets(diff_file_secret)

    # 2. AST SQL Injection Finding
    vulnerable_sql_code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    ast_findings = scan_python_source(
        file_path="src/database/queries.py",
        source_code=vulnerable_sql_code,
        added_lines={1},
    )

    # 3. Simulated OSV Dependency Finding
    dep_findings = [
        Finding(
            file_path="requirements.txt",
            line_number=7,
            rule_id="DEP-OSV",
            category=ScannerCategory.DEPENDENCY_CVE,
            severity=Severity.HIGH,
            title="Vulnerable Dependency: requests@2.19.1",
            description="Vulnerable to CVE-2018-18074 (Session fixation / credential leak on cross-domain redirect).",
            remediation="Upgrade requests to >=2.31.0 in requirements.txt.",
            snippet="requests==2.19.1",
        )
    ]

    all_findings = secret_findings + ast_findings + dep_findings
    deduped = deduplicate_findings(all_findings)
    sorted_findings = sort_findings(deduped)

    report = AuditReport(
        repository="org/backend-service",
        pr_number=101,
        base_sha="main",
        head_sha="feat/add-auth",
        scan_duration_ms=42.5,
        dep_scan_duration_ms=15.0,
        files_scanned=3,
        findings=sorted_findings,
    )

    # Generate Markdown and HTML outputs
    markdown_content = build_markdown_report(report)
    html_content = build_html_report(report)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "pr_blocked_comment.md").write_text(markdown_content, encoding="utf-8")
    (output_dir / "pr_blocked_report.html").write_text(html_content, encoding="utf-8")

    status_str = "❌ Merge Blocked" if report.should_block_merge else "✅ Passed"
    print(f"[*] Findings Detected: {len(report.findings)}")
    print(f"[*] Blocking Vulnerabilities: {report.critical_count + report.high_count}")
    print(f"[*] Merge Status: {status_str}")
    print(f"[*] Policy Gate Exit Code: {evaluate_policy(report)}")
    print(f"[+] Saved Markdown Comment -> {output_dir / 'pr_blocked_comment.md'}")
    print(f"[+] Saved Dark-Mode HTML  -> {output_dir / 'pr_blocked_report.html'}")

    return report


def run_scenario_clean(output_dir: Path) -> AuditReport:
    """Simulate a PR containing clean code and safe parameterized queries."""
    print("\n" + "=" * 76)
    print("  SIMULATING SCENARIO B: Clean Pull Request (Security Audit Passed)")
    print("=" * 76 + "\n")

    # 1. Clean Secret Scanning
    safe_code_line = 'session_id = "c39e802d-0db5-4b19-8664-d9229e612985"'
    diff_file_clean = DiffFile(
        file_path="src/utils/session.py",
        added_lines={10: safe_code_line},
    )
    secret_findings = scan_diff_file_for_secrets(diff_file_clean)

    # 2. Clean Parameterized SQL & Safe Crypto
    safe_sql_code = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    ast_findings = scan_python_source(
        file_path="src/database/queries.py",
        source_code=safe_sql_code,
        added_lines={1},
    )

    all_findings = secret_findings + ast_findings
    deduped = deduplicate_findings(all_findings)
    sorted_findings = sort_findings(deduped)

    report = AuditReport(
        repository="org/fullstack-app",
        pr_number=204,
        base_sha="main",
        head_sha="feat/safe-queries",
        scan_duration_ms=18.2,
        dep_scan_duration_ms=10.0,
        files_scanned=2,
        findings=sorted_findings,
    )

    markdown_content = build_markdown_report(report)
    html_content = build_html_report(report)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "pr_clean_comment.md").write_text(markdown_content, encoding="utf-8")
    (output_dir / "pr_clean_report.html").write_text(html_content, encoding="utf-8")

    status_str = "❌ Merge Blocked" if report.should_block_merge else "✅ Passed"
    print(f"[*] Findings Detected: {len(report.findings)}")
    print(f"[*] Blocking Vulnerabilities: {report.critical_count + report.high_count}")
    print(f"[*] Merge Status: {status_str}")
    print(f"[*] Policy Gate Exit Code: {evaluate_policy(report)}")
    print(f"[+] Saved Markdown Comment -> {output_dir / 'pr_clean_comment.md'}")
    print(f"[+] Saved Dark-Mode HTML  -> {output_dir / 'pr_clean_report.html'}")

    return report


def main() -> None:
    output_dir = Path("artifacts/reports")
    blocked_report = run_scenario_blocked(output_dir)
    clean_report = run_scenario_clean(output_dir)

    print("\n" + "=" * 76)
    print("  AUDIT SIMULATION COMPLETED SUCCESSFULLY")
    print("=" * 76)
    print(f"  Scenario A Exit Code: {evaluate_policy(blocked_report)} (Blocked as expected)")
    print(f"  Scenario B Exit Code: {evaluate_policy(clean_report)} (Passed as expected)")
    print(f"  Artifacts stored in: {output_dir.resolve()}\n")


if __name__ == "__main__":
    main()
