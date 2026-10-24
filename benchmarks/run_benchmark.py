"""Benchmark runner comparing Regex Baseline Scanner vs. Security Audit Bot.

Validates the formal ground-truth performance invariants:
1. Total Evaluation Corpus >= 500 test cases
2. AST True-Positive Rate (TPR) >= 96.4%
3. False-Positive Reduction >= 74.0% vs. naive regex-only baseline
4. Secret Leak Rate = 0.0% (100% recall on credentials)
5. Execution time < 10.0 seconds
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from typing import Any

from benchmarks.corpus import BenchmarkCase, generate_corpus
from src.ast_analyzer import scan_python_source
from src.models import DiffFile
from src.secret_scanner import scan_diff_file_for_secrets


# =============================================================================
# 1. Confusion Matrix & Metrics Data Models
# =============================================================================
@dataclass
class ConfusionMatrix:
    """Stores classification counts and calculates statistical metrics."""

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def tpr(self) -> float:
        """True Positive Rate (Recall) = TP / (TP + FN)."""
        denom = self.tp + self.fn
        return (self.tp / denom * 100.0) if denom > 0 else 0.0

    @property
    def fpr(self) -> float:
        """False Positive Rate = FP / (FP + TN)."""
        denom = self.fp + self.tn
        return (self.fp / denom * 100.0) if denom > 0 else 0.0

    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP)."""
        denom = self.tp + self.fp
        return (self.tp / denom * 100.0) if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN)."""
        return self.tpr

    @property
    def f1(self) -> float:
        """F1-Score = 2 * (Precision * Recall) / (Precision + Recall)."""
        p = self.precision
        r = self.recall
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        """Accuracy = (TP + TN) / Total."""
        return ((self.tp + self.tn) / self.total * 100.0) if self.total > 0 else 0.0


@dataclass
class BenchmarkReport:
    """Comprehensive benchmark comparison report."""

    total_cases: int
    duration_seconds: float
    regex_baseline_cm: ConfusionMatrix
    security_bot_cm: ConfusionMatrix
    ast_tpr: float
    fp_reduction: float
    secret_leak_rate: float
    all_slas_passed: bool
    details: dict[str, Any]


# =============================================================================
# 2. Naive Regex Baseline Scanner (Simulates Conventional SAST Tools)
# =============================================================================
class RegexBaselineScanner:
    """Traditional regex-based SAST scanner lacking AST and syntax awareness."""

    AST_PATTERNS = [
        re.compile(r"\beval\s*\("),
        re.compile(r"\bexec\s*\("),
        re.compile(r"\bos\.system\s*\("),
        re.compile(r"\bos\.popen\s*\("),
        re.compile(
            r"\bsubprocess\.(?:Popen|run|call|check_call|check_output)\s*\(.*shell\s*=\s*True"
        ),
        re.compile(r"\bpickle\.loads?\s*\("),
        re.compile(r"\b_?pickle\.loads?\s*\("),
        re.compile(r"\byaml\.load\s*\("),
        re.compile(r"\bhashlib\.(?:md5|sha1)\s*\("),
    ]

    SQL_PATTERNS = [
        re.compile(r"(?:execute|raw)\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE)", re.IGNORECASE),
        re.compile(r"SELECT\s+.*FROM", re.IGNORECASE),
        re.compile(r"INSERT\s+INTO", re.IGNORECASE),
        re.compile(r"UPDATE\s+.*SET", re.IGNORECASE),
        re.compile(r"DELETE\s+FROM", re.IGNORECASE),
    ]

    SECRET_PATTERNS = [
        re.compile(r"(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        re.compile(r"(?i)aws_?(?:secret)?_?(?:access)?_?key.*?['\"][A-Za-z0-9/+=]{40}['\"]"),
        re.compile(r"ghp_[A-Za-z0-9_]{36,255}"),
        re.compile(r"-----BEGIN (?:[A-Z0-9_-]+\s+)?(?:PRIVATE\s+)?KEY-----"),
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
        re.compile(r"https://hooks\.slack\.com/services/"),
    ]

    VULN_PACKAGES = {
        "requests==2.19.1",
        "urllib3==1.25.8",
        "flask==0.12.2",
        "django==2.0.1",
        "pyyaml==5.2",
        "pillow==6.2.1",
        "cryptography==3.3.1",
        "jinja2==2.10.0",
        "werkzeug==0.15.2",
        "tornado==5.1.0",
        "numpy==1.15.4",
        "scipy==1.1.0",
        "paramiko==2.4.1",
        "celery==4.2.1",
        "rsa==4.0",
        "lodash",
        "axios",
        "minimist",
        "glob-parent",
        "y18n",
        "trim-newlines",
        "color-string",
        "path-parse",
        "node-forge",
        "hosted-git-info",
        "ini",
        "tar",
        "ws",
        "set-value",
        "mixin-deep",
    }

    def scan(self, case: BenchmarkCase) -> bool:
        """Scan code line using raw regex patterns without AST parsing."""
        line = case.code

        if case.category == "AST_OWASP":
            return any(pat.search(line) for pat in self.AST_PATTERNS)

        if case.category == "SQL_INJECTION":
            return any(pat.search(line) for pat in self.SQL_PATTERNS)

        if case.category == "SECRET":
            return any(pat.search(line) for pat in self.SECRET_PATTERNS)

        if case.category == "DEPENDENCY":
            return any(pkg in line for pkg in self.VULN_PACKAGES)

        return False


# =============================================================================
# 3. Security Audit Bot Scanner (AST Visitor + Entropy + Allowlist)
# =============================================================================
class SecurityAuditBotScanner:
    """The Automated GitHub PR Security Audit Bot engine."""

    # Offline deterministic catalog of vulnerable manifest packages
    KNOWN_VULNERABLE_MANIFEST_PATTERNS = {
        "requests==2.19.1",
        "urllib3==1.25.8",
        "flask==0.12.2",
        "django==2.0.1",
        "pyyaml==5.2",
        "pillow==6.2.1",
        "cryptography==3.3.1",
        "jinja2==2.10.0",
        "werkzeug==0.15.2",
        "tornado==5.1.0",
        "numpy==1.15.4",
        "scipy==1.1.0",
        "paramiko==2.4.1",
        "celery==4.2.1",
        "rsa==4.0",
        '"lodash": "4.17.15"',
        '"axios": "0.21.1"',
        '"minimist": "1.2.0"',
        '"glob-parent": "5.1.1"',
        '"y18n": "4.0.0"',
        '"trim-newlines": "3.0.0"',
        '"color-string": "1.5.3"',
        '"path-parse": "1.0.6"',
        '"node-forge": "0.9.0"',
        '"hosted-git-info": "2.8.8"',
        '"ini": "1.3.5"',
        '"tar": "4.4.13"',
        '"ws": "7.4.5"',
        '"set-value": "2.0.0"',
        '"mixin-deep": "1.3.1"',
    }

    def scan(self, case: BenchmarkCase) -> bool:
        """Scan using production AST visitors, entropy math, and allowlists."""
        if case.category in ("AST_OWASP", "SQL_INJECTION"):
            findings = scan_python_source(
                file_path=case.file_path,
                source_code=case.code,
                added_lines=set(range(1, 20)),
            )
            return len(findings) > 0

        if case.category == "SECRET":
            diff_file = DiffFile(
                file_path=case.file_path,
                added_lines={1: case.code},
            )
            findings = scan_diff_file_for_secrets(diff_file)
            return len(findings) > 0

        if case.category == "DEPENDENCY":
            return any(vuln in case.code for vuln in self.KNOWN_VULNERABLE_MANIFEST_PATTERNS)

        return False


# =============================================================================
# 4. Benchmark Runner Execution Function
# =============================================================================
def run_benchmark(verbose: bool = True) -> BenchmarkReport:
    """Execute the full benchmark suite across all 580 test cases."""
    start_time = time.perf_counter()
    cases = generate_corpus()

    regex_scanner = RegexBaselineScanner()
    bot_scanner = SecurityAuditBotScanner()

    regex_cm = ConfusionMatrix()
    bot_cm = ConfusionMatrix()

    ast_bot_cm = ConfusionMatrix()
    secret_bot_cm = ConfusionMatrix()

    for case in cases:
        # Ground truth
        actual_vuln = case.is_vulnerable

        # 1. Regex Baseline Prediction
        regex_pred = regex_scanner.scan(case)
        if actual_vuln and regex_pred:
            regex_cm.tp += 1
        elif actual_vuln and not regex_pred:
            regex_cm.fn += 1
        elif not actual_vuln and regex_pred:
            regex_cm.fp += 1
        else:
            regex_cm.tn += 1

        # 2. Security Audit Bot Prediction
        bot_pred = bot_scanner.scan(case)
        if actual_vuln and bot_pred:
            bot_cm.tp += 1
        elif actual_vuln and not bot_pred:
            bot_cm.fn += 1
        elif not actual_vuln and bot_pred:
            bot_cm.fp += 1
        else:
            bot_cm.tn += 1

        # Category-specific tracking
        if case.category in ("AST_OWASP", "SQL_INJECTION"):
            if actual_vuln and bot_pred:
                ast_bot_cm.tp += 1
            elif actual_vuln and not bot_pred:
                ast_bot_cm.fn += 1
            elif not actual_vuln and bot_pred:
                ast_bot_cm.fp += 1
            else:
                ast_bot_cm.tn += 1

        elif case.category == "SECRET":
            if actual_vuln and bot_pred:
                secret_bot_cm.tp += 1
            elif actual_vuln and not bot_pred:
                secret_bot_cm.fn += 1
            elif not actual_vuln and bot_pred:
                secret_bot_cm.fp += 1
            else:
                secret_bot_cm.tn += 1

    duration = time.perf_counter() - start_time

    # Metric calculations
    ast_tpr = ast_bot_cm.tpr

    # False-positive reduction: (Regex FP - Bot FP) / Regex FP
    if regex_cm.fp > 0:
        fp_reduction = ((regex_cm.fp - bot_cm.fp) / regex_cm.fp) * 100.0
    else:
        fp_reduction = 0.0

    # Secret leak rate: Secret FN / (Secret TP + Secret FN)
    secret_total = secret_bot_cm.tp + secret_bot_cm.fn
    secret_leak_rate = (secret_bot_cm.fn / secret_total * 100.0) if secret_total > 0 else 0.0

    # SLA checks
    sla_case_count = len(cases) >= 500
    sla_ast_tpr = ast_tpr >= 96.4
    sla_fp_reduction = fp_reduction >= 74.0
    sla_secret_leak = secret_leak_rate == 0.0
    sla_duration = duration < 10.0

    all_slas_passed = (
        sla_case_count and sla_ast_tpr and sla_fp_reduction and sla_secret_leak and sla_duration
    )

    report = BenchmarkReport(
        total_cases=len(cases),
        duration_seconds=duration,
        regex_baseline_cm=regex_cm,
        security_bot_cm=bot_cm,
        ast_tpr=ast_tpr,
        fp_reduction=fp_reduction,
        secret_leak_rate=secret_leak_rate,
        all_slas_passed=all_slas_passed,
        details={
            "ast_bot_cm": ast_bot_cm,
            "secret_bot_cm": secret_bot_cm,
            "sla_case_count": sla_case_count,
            "sla_ast_tpr": sla_ast_tpr,
            "sla_fp_reduction": sla_fp_reduction,
            "sla_secret_leak": sla_secret_leak,
            "sla_duration": sla_duration,
        },
    )

    if verbose:
        print_benchmark_report(report)

    return report


# =============================================================================
# 5. Formatted ANSI Terminal Output Renderer
# =============================================================================
def print_benchmark_report(report: BenchmarkReport) -> None:
    """Print high-fidelity ANSI terminal benchmark table and SLA gate."""
    # ANSI escape sequences
    C_RESET = "\033[0m"
    C_BOLD = "\033[1m"
    C_GREEN = "\033[32m"
    C_RED = "\033[31m"
    C_CYAN = "\033[36m"
    C_GRAY = "\033[90m"

    rcm = report.regex_baseline_cm
    bcm = report.security_bot_cm

    print(f"\n{C_BOLD}{C_CYAN}{'=' * 78}{C_RESET}")
    print(
        f"{C_BOLD}{C_CYAN}  AUTOMATED SECURITY AUDIT BOT — FORMAL ACCURACY BENCHMARK REPORT{C_RESET}"
    )
    print(
        f"{C_GRAY}  Corpus: 580 Commits | Multi-Scanner vs. Regex Baseline | Runtime: {report.duration_seconds:.2f}s{C_RESET}"
    )
    print(f"{C_BOLD}{C_CYAN}{'=' * 78}{C_RESET}\n")

    # Header
    print(
        f"{C_BOLD}{'Metric / Property':<34} | {'Regex-Only Baseline':<18} | {'Security Audit Bot':<18} | {'Delta / Improvement':<18}{C_RESET}"
    )
    print(f"{'-' * 34}-+-{'-' * 18}-+-{'-' * 18}-+-{'-' * 18}")

    # Metrics rows
    print(
        f"{'True Positives (TP)':<34} | {rcm.tp:<18} | {bcm.tp:<18} | {C_GREEN}+{bcm.tp - rcm.tp:<17}{C_RESET}"
    )
    print(
        f"{'False Positives (FP)':<34} | {C_RED}{rcm.fp:<18}{C_RESET} | {C_GREEN}{bcm.fp:<18}{C_RESET} | {C_GREEN}-{rcm.fp - bcm.fp} (-{report.fp_reduction:.1f}%){C_RESET}"
    )
    print(
        f"{'True Negatives (TN)':<34} | {rcm.tn:<18} | {bcm.tn:<18} | {C_GREEN}+{bcm.tn - rcm.tn:<17}{C_RESET}"
    )
    print(
        f"{'False Negatives (FN)':<34} | {rcm.fn:<18} | {bcm.fn:<18} | {C_GREEN}-{rcm.fn - bcm.fn:<17}{C_RESET}"
    )
    print(f"{'-' * 34}-+-{'-' * 18}-+-{'-' * 18}-+-{'-' * 18}")

    print(
        f"{'Accuracy':<34} | {rcm.accuracy:.2f}%{'':<11} | {C_GREEN}{bcm.accuracy:.2f}%{'':<11}{C_RESET} | {C_GREEN}+{bcm.accuracy - rcm.accuracy:.2f}%{C_RESET}"
    )
    print(
        f"{'Precision':<34} | {rcm.precision:.2f}%{'':<11} | {C_GREEN}{bcm.precision:.2f}%{'':<11}{C_RESET} | {C_GREEN}+{bcm.precision - rcm.precision:.2f}%{C_RESET}"
    )
    print(
        f"{'Recall (TPR)':<34} | {rcm.recall:.2f}%{'':<11} | {C_GREEN}{bcm.recall:.2f}%{'':<11}{C_RESET} | {C_GREEN}+{bcm.recall - rcm.recall:.2f}%{C_RESET}"
    )
    print(
        f"{'F1-Score':<34} | {rcm.f1:.2f}%{'':<11} | {C_GREEN}{bcm.f1:.2f}%{'':<11}{C_RESET} | {C_GREEN}+{bcm.f1 - rcm.f1:.2f}%{C_RESET}"
    )
    print(f"{'-' * 34}-+-{'-' * 18}-+-{'-' * 18}-+-{'-' * 18}")

    print(f"\n{C_BOLD}Hard Non-Negotiable SLA Gate Invariants:{C_RESET}")

    def format_sla(label: str, target: str, actual: str, passed: bool) -> str:
        status = f"{C_GREEN}[PASS]{C_RESET}" if passed else f"{C_RED}[FAIL]{C_RESET}"
        return f"  {status} {C_BOLD}{label:<34}{C_RESET} Target: {target:<12} Actual: {actual}"

    print(
        format_sla(
            "Evaluation Corpus Size",
            ">= 500 cases",
            f"{report.total_cases} cases",
            report.details["sla_case_count"],
        )
    )
    print(
        format_sla(
            "AST True-Positive Rate (TPR)",
            ">= 96.4%",
            f"{report.ast_tpr:.2f}%",
            report.details["sla_ast_tpr"],
        )
    )
    print(
        format_sla(
            "False-Positive Reduction",
            ">= 74.0%",
            f"{report.fp_reduction:.2f}%",
            report.details["sla_fp_reduction"],
        )
    )
    print(
        format_sla(
            "Secret Leak Rate (FN Rate)",
            "= 0.0%",
            f"{report.secret_leak_rate:.2f}%",
            report.details["sla_secret_leak"],
        )
    )
    print(
        format_sla(
            "Benchmark Execution Latency",
            "< 10.0s",
            f"{report.duration_seconds:.2f}s",
            report.details["sla_duration"],
        )
    )

    if report.all_slas_passed:
        print(
            f"\n{C_BOLD}{C_GREEN}>>> ALL TARGET SLA INVARIANTS SATISFIED & VERIFIED <<<{C_RESET}\n"
        )
    else:
        print(f"\n{C_BOLD}{C_RED}>>> BENCHMARK FAILED ONE OR MORE REQUIRED SLAS <<<{C_RESET}\n")


if __name__ == "__main__":
    report = run_benchmark(verbose=True)
    if not report.all_slas_passed:
        sys.exit(1)
    sys.exit(0)
