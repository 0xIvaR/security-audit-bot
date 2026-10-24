"""Domain data models for the Automated GitHub PR Security Audit Bot.

Enforces strict type safety and validation across all module boundaries
using Pydantic v2 schemas per ARCHITECTURE.md Section 4.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    """Vulnerability severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


class ScannerCategory(str, Enum):
    """Categorization of security scanner engines."""

    SECRET = "SECRET"
    AST_OWASP = "AST_OWASP"
    DEPENDENCY_CVE = "DEPENDENCY_CVE"


class DiffFile(BaseModel):
    """Representation of a modified file in the PR diff and its newly added lines."""

    model_config = ConfigDict(frozen=True)

    file_path: str = Field(description="Relative path to modified file in repository")
    added_lines: dict[int, str] = Field(
        default_factory=dict,
        description="Map of physical 1-based line_number -> raw added line string for '+' lines",
    )


class Finding(BaseModel):
    """An individual security finding produced by one of the scanning engines."""

    model_config = ConfigDict(frozen=True)

    file_path: str = Field(description="Path to file containing violation")
    line_number: int = Field(ge=1, description="1-based physical line number of violation")
    rule_id: str = Field(
        description="Deterministic rule identifier, e.g. SEC-001, AST-004, DEP-OSV"
    )
    category: ScannerCategory = Field(description="Scanner engine category")
    severity: Severity = Field(description="Severity tier: CRITICAL, HIGH, or MEDIUM")
    title: str = Field(description="Short human-readable title of finding")
    description: str = Field(description="Detailed explanation of the vulnerability and risk")
    remediation: str = Field(description="Actionable, deterministic remediation recommendation")
    snippet: str | None = Field(
        default=None,
        description="Redacted snippet; raw secrets must be masked with redact_secret()",
    )


class AuditReport(BaseModel):
    """Aggregated security audit report across all scanned files and manifests."""

    repository: str = Field(description="Target repository in format owner/repo")
    pr_number: int | None = Field(default=None, description="GitHub Pull Request identifier")
    base_sha: str = Field(description="Base commit SHA")
    head_sha: str = Field(description="Head commit SHA")
    scan_duration_ms: float = Field(description="Total scan execution duration in milliseconds")
    dep_scan_duration_ms: float = Field(
        default=0.0,
        description="Portion of execution spent on dependency queries in milliseconds",
    )
    files_scanned: int = Field(ge=0, description="Total number of diff files evaluated")
    findings: list[Finding] = Field(default_factory=list, description="List of detected findings")

    @property
    def critical_count(self) -> int:
        """Count of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count of MEDIUM severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def total_findings(self) -> int:
        """Total count of all findings."""
        return len(self.findings)

    @property
    def should_block_merge(self) -> bool:
        """Policy gate: block PR merge if at least one CRITICAL or HIGH issue exists."""
        return (self.critical_count + self.high_count) > 0
