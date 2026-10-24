"""Batch Dependency Vulnerability Scanner (Milestone 6).

Parses dependency manifest additions from PR diffs (requirements.txt and package.json),
dispatches a single batched HTTP query to OSV.dev (POST /v1/querybatch) with a strict
3.0-second timeout, normalizes CVSS severities, extracts patched versions, and links
findings to physical manifest line numbers.
"""

from __future__ import annotations

import re
import sys
from typing import Any

import requests

from src.config import OSV_QUERYBATCH_URL, OSV_TIMEOUT_SECONDS
from src.models import DiffFile, Finding, ScannerCategory, Severity

# Regex for requirements.txt pinned versions (PyPI)
# Matches 'requests==2.19.0' or 'urllib3 == 1.24.1', ignoring comments and trailing markers
REQ_PIN_RE: re.Pattern[str] = re.compile(r"^\s*([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.]+)")

# Regex for package.json dependencies (npm)
# Matches '"lodash": "^4.17.15"' or '"express": "~4.16.0"', stripping ^ and ~ prefixes
PKG_JSON_PIN_RE: re.Pattern[str] = re.compile(
    r'^\s*"([@a-zA-Z0-9_\-\.\/]+)"\s*:\s*"[\^~]?([0-9a-zA-Z_\-\.]+)"'
)


class DependencyQuery:
    """Represents a candidate dependency extracted from a manifest line."""

    __slots__ = ("name", "version", "ecosystem", "file_path", "line_number", "raw_line")

    def __init__(
        self,
        name: str,
        version: str,
        ecosystem: str,
        file_path: str,
        line_number: int,
        raw_line: str,
    ) -> None:
        self.name = name
        self.version = version
        self.ecosystem = ecosystem
        self.file_path = file_path
        self.line_number = line_number
        self.raw_line = raw_line

    def to_osv_query(self) -> dict[str, Any]:
        """Format as OSV batch query object."""
        return {
            "package": {"name": self.name, "ecosystem": self.ecosystem},
            "version": self.version,
        }


def is_manifest_file(file_path: str) -> bool:
    """Determine if a file path is a supported dependency manifest."""
    normalized = file_path.replace("\\", "/").lower()
    base_name = normalized.split("/")[-1]
    return (
        base_name == "requirements.txt"
        or (base_name.startswith("requirements") and base_name.endswith(".txt"))
        or ("requirements" in normalized and base_name.endswith(".txt"))
        or base_name == "package.json"
    )


def extract_dependencies_from_diff(diff_file: DiffFile) -> list[DependencyQuery]:
    """Extract candidate dependency queries from added lines in a manifest DiffFile."""
    normalized_path = diff_file.file_path.replace("\\", "/").lower()
    base_name = normalized_path.split("/")[-1]
    queries: list[DependencyQuery] = []

    if base_name == "package.json":
        ecosystem = "npm"
        for lineno, line in diff_file.added_lines.items():
            clean_line = line.strip()
            if clean_line.startswith(("{", "}", "[", "]", '"name"', '"version"', '"scripts"')):
                continue
            match = PKG_JSON_PIN_RE.match(clean_line)
            if match:
                pkg_name, version = match.group(1), match.group(2)
                if pkg_name in ("name", "version", "description", "main", "author", "license"):
                    continue
                queries.append(
                    DependencyQuery(
                        name=pkg_name,
                        version=version,
                        ecosystem=ecosystem,
                        file_path=diff_file.file_path,
                        line_number=lineno,
                        raw_line=clean_line,
                    )
                )

    elif "requirements" in normalized_path and base_name.endswith(".txt"):
        ecosystem = "PyPI"
        for lineno, line in diff_file.added_lines.items():
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue
            if "#" in clean_line:
                clean_line = clean_line.split("#", 1)[0].strip()
            match = REQ_PIN_RE.match(clean_line)
            if match:
                pkg_name, version = match.group(1), match.group(2)
                queries.append(
                    DependencyQuery(
                        name=pkg_name,
                        version=version,
                        ecosystem=ecosystem,
                        file_path=diff_file.file_path,
                        line_number=lineno,
                        raw_line=line.strip(),
                    )
                )

    return queries


def parse_osv_severity(vuln: dict[str, Any]) -> Severity:
    """Normalize OSV vulnerability database_specific and CVSS scores into Severity."""
    db_spec = vuln.get("database_specific", {})
    if isinstance(db_spec, dict):
        db_sev = str(db_spec.get("severity", "")).upper()
        if "CRITICAL" in db_sev:
            return Severity.CRITICAL
        if "HIGH" in db_sev:
            return Severity.HIGH
        if "MODERATE" in db_sev or "MEDIUM" in db_sev or "LOW" in db_sev:
            return Severity.MEDIUM

    eco_spec = vuln.get("ecosystem_specific", {})
    if isinstance(eco_spec, dict):
        eco_sev = str(eco_spec.get("severity", "")).upper()
        if "CRITICAL" in eco_sev:
            return Severity.CRITICAL
        if "HIGH" in eco_sev:
            return Severity.HIGH
        if "MODERATE" in eco_sev or "MEDIUM" in eco_sev or "LOW" in eco_sev:
            return Severity.MEDIUM

    severities = vuln.get("severity", [])
    if isinstance(severities, list):
        for sev_entry in severities:
            if isinstance(sev_entry, dict):
                score_val = sev_entry.get("score")
                if score_val:
                    try:
                        numeric_score = float(score_val)
                        if numeric_score >= 9.0:
                            return Severity.CRITICAL
                        if numeric_score >= 7.0:
                            return Severity.HIGH
                        return Severity.MEDIUM
                    except ValueError:
                        pass

    return Severity.HIGH


def extract_minimum_fixed_version(vuln: dict[str, Any], target_pkg: str) -> str | None:
    """Extract minimum patched/fixed version string from affected ranges."""
    affected = vuln.get("affected", [])
    if not isinstance(affected, list):
        return None

    fixed_versions: list[str] = []
    for item in affected:
        if not isinstance(item, dict):
            continue
        pkg_info = item.get("package", {})
        if isinstance(pkg_info, dict):
            if pkg_info.get("name", "").lower() != target_pkg.lower():
                continue

        ranges = item.get("ranges", [])
        if isinstance(ranges, list):
            for r in ranges:
                if isinstance(r, dict):
                    events = r.get("events", [])
                    if isinstance(events, list):
                        for event in events:
                            if isinstance(event, dict) and "fixed" in event:
                                fixed_versions.append(str(event["fixed"]))

    if fixed_versions:
        return fixed_versions[0]
    return None


def query_osv_batch(
    dep_queries: list[DependencyQuery],
    session: requests.Session | None = None,
    timeout: float = OSV_TIMEOUT_SECONDS,
    endpoint_url: str = OSV_QUERYBATCH_URL,
) -> list[Finding]:
    """Execute a single batch query to OSV.dev and map results to Findings."""
    if not dep_queries:
        return []

    payload = {"queries": [q.to_osv_query() for q in dep_queries]}
    client = session or requests.Session()

    try:
        response = client.post(
            endpoint_url,
            json=payload,
            timeout=timeout,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as exc:
        print(
            f"[!] OSV.dev Batch Warning: Dependency query failed or timed out: {exc}",
            file=sys.stderr,
        )
        return []

    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    findings: list[Finding] = []

    for idx, dep in enumerate(dep_queries):
        if idx >= len(results):
            break
        item = results[idx]
        if not isinstance(item, dict):
            continue

        vulns = item.get("vulns", [])
        if not isinstance(vulns, list):
            continue

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue

            vuln_id = vuln.get("id", "UNKNOWN-CVE")
            aliases = vuln.get("aliases", [])
            cve_alias = next((a for a in aliases if a.startswith("CVE-")), None)
            display_id = (
                f"{vuln_id} ({cve_alias})" if cve_alias and cve_alias != vuln_id else vuln_id
            )

            summary = (
                vuln.get("summary")
                or vuln.get("details")
                or f"Known vulnerability in {dep.name}=={dep.version}."
            )
            first_line = summary.strip().split("\n")[0]
            if len(first_line) > 120:
                first_line = first_line[:117] + "..."

            severity = parse_osv_severity(vuln)
            fixed_version = extract_minimum_fixed_version(vuln, dep.name)

            if fixed_version:
                remediation = f"Upgrade {dep.name} to >= {fixed_version} to patch {vuln_id}."
            else:
                remediation = f"Upgrade {dep.name} to the latest available patched version."

            findings.append(
                Finding(
                    file_path=dep.file_path,
                    line_number=dep.line_number,
                    rule_id="DEP-OSV",
                    category=ScannerCategory.DEPENDENCY_CVE,
                    severity=severity,
                    title=f"Vulnerable dependency: {dep.name}=={dep.version} [{display_id}]",
                    description=first_line,
                    remediation=remediation,
                    snippet=dep.raw_line,
                )
            )

    return findings


def scan_diff_for_dependencies(
    diff_files: list[DiffFile],
    session: requests.Session | None = None,
    timeout: float = OSV_TIMEOUT_SECONDS,
    endpoint_url: str = OSV_QUERYBATCH_URL,
) -> list[Finding]:
    """Scan all modified dependency manifests across a PR diff using OSV.dev batch queries.

    Collects all added dependency pins across all manifests and issues exactly one
    HTTP request to POST /v1/querybatch within the < 650 ms budget.
    """
    all_queries: list[DependencyQuery] = []

    for diff_file in diff_files:
        if is_manifest_file(diff_file.file_path):
            all_queries.extend(extract_dependencies_from_diff(diff_file))

    if not all_queries:
        return []

    return query_osv_batch(
        all_queries,
        session=session,
        timeout=timeout,
        endpoint_url=endpoint_url,
    )
