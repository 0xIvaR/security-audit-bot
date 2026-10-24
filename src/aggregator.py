"""Aggregation Engine, Severity Classifier & Policy Gate (Milestone 7).

Orchestrates Diff Parser -> Secret Scanner -> AST Analyzer -> Dependency Auditor,
deduplicates findings by (file_path, line_number, rule_id), sorts by severity hierarchy
(CRITICAL -> HIGH -> MEDIUM), populates the final AuditReport Pydantic model, and enforces
the CI merge-blocking gate (sys.exit(1) on CRITICAL/HIGH; sys.exit(0) otherwise).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import requests

from src.ast_analyzer import scan_diff_for_ast_vulnerabilities
from src.dep_scanner import scan_diff_for_dependencies
from src.diff_parser import get_diff
from src.models import AuditReport, DiffFile, Finding, Severity
from src.secret_scanner import scan_diff_for_secrets

if TYPE_CHECKING:
    from collections.abc import Sequence

# Severity sort priority: lowest numeric value comes first
SEVERITY_WEIGHT: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
}


def deduplicate_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Deduplicate findings sharing the same (file_path, line_number, rule_id).

    Preserves the finding with the highest severity if duplicate rules trigger
    on the same physical line.
    """
    seen: dict[tuple[str, int, str], Finding] = {}

    for finding in findings:
        key = (finding.file_path, finding.line_number, finding.rule_id)
        if key not in seen:
            seen[key] = finding
        else:
            existing = seen[key]
            # Replace if current finding has higher severity (lower weight)
            if SEVERITY_WEIGHT.get(finding.severity, 99) < SEVERITY_WEIGHT.get(
                existing.severity, 99
            ):
                seen[key] = finding

    return list(seen.values())


def sort_findings(findings: Sequence[Finding]) -> list[Finding]:
    """Sort findings by severity hierarchy (CRITICAL -> HIGH -> MEDIUM), then file and line."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_WEIGHT.get(f.severity, 99),
            f.file_path,
            f.line_number,
            f.rule_id,
        ),
    )


def run_audit(
    base_sha: str,
    head_sha: str,
    repo: str | None = None,
    pr_number: int | None = None,
    diff_files: list[DiffFile] | None = None,
    session: requests.Session | None = None,
) -> AuditReport:
    """Execute complete security audit pipeline across diff files.

    Args:
        base_sha: Base commit SHA or branch.
        head_sha: Head commit SHA or branch.
        repo: Optional repository slug 'owner/repo'.
        pr_number: Optional Pull Request ID.
        diff_files: Pre-parsed DiffFile list (if provided, bypasses git subprocess).
        session: Optional requests.Session for dependency queries.

    Returns:
        Consolidated, deduplicated, and sorted AuditReport model.
    """
    overall_start = time.perf_counter()

    if diff_files is None:
        diff_files = get_diff(base_sha, head_sha)

    # 1. Hybrid Secret Scanner
    secret_findings = scan_diff_for_secrets(diff_files)

    # 2. Python AST Static Analyzer (OWASP Sinks & SQLi Taint)
    ast_findings = scan_diff_for_ast_vulnerabilities(diff_files)

    # 3. Batch Dependency Vulnerability Auditor (OSV.dev)
    dep_start = time.perf_counter()
    dep_findings = scan_diff_for_dependencies(diff_files, session=session)
    dep_duration_ms = (time.perf_counter() - dep_start) * 1000.0

    # 4. Consolidate, deduplicate, and sort
    raw_findings = secret_findings + ast_findings + dep_findings
    deduped = deduplicate_findings(raw_findings)
    sorted_findings = sort_findings(deduped)

    scan_duration_ms = (time.perf_counter() - overall_start) * 1000.0

    return AuditReport(
        repository=repo or "local/unspecified",
        pr_number=pr_number,
        base_sha=base_sha,
        head_sha=head_sha,
        scan_duration_ms=round(scan_duration_ms, 2),
        dep_scan_duration_ms=round(dep_duration_ms, 2),
        files_scanned=len(diff_files),
        findings=sorted_findings,
    )


def evaluate_policy(report: AuditReport) -> int:
    """Enforce CI exit code policy.

    Returns:
        1 if PR merge should be blocked (critical_count + high_count > 0).
        0 if PR is clean or contains only MEDIUM severity issues.
    """
    return 1 if report.should_block_merge else 0
