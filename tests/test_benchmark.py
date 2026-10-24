"""Unit and integration tests for benchmark suite and SLA gate validation."""

from __future__ import annotations

import io
from unittest.mock import patch

from benchmarks.corpus import generate_corpus
from benchmarks.run_benchmark import (
    ConfusionMatrix,
    RegexBaselineScanner,
    SecurityAuditBotScanner,
    print_benchmark_report,
    run_benchmark,
)


class TestBenchmarkCorpus:
    """Validates structure and invariants of the 500+ test case evaluation corpus."""

    def test_corpus_count_exceeds_sla_target(self) -> None:
        cases = generate_corpus()
        assert len(cases) >= 500
        assert len(cases) == 580

    def test_corpus_balanced_distribution(self) -> None:
        cases = generate_corpus()
        vulnerable = [c for c in cases if c.is_vulnerable]
        benign = [c for c in cases if not c.is_vulnerable]

        assert len(vulnerable) == 290
        assert len(benign) == 290
        assert len(vulnerable) + len(benign) == len(cases)

    def test_corpus_unique_case_ids(self) -> None:
        cases = generate_corpus()
        case_ids = [c.case_id for c in cases]
        assert len(case_ids) == len(set(case_ids)), "Duplicate case_id found in corpus"

    def test_corpus_categories_covered(self) -> None:
        cases = generate_corpus()
        categories = {c.category for c in cases}
        expected = {"AST_OWASP", "SQL_INJECTION", "SECRET", "DEPENDENCY"}
        assert expected.issubset(categories)


class TestConfusionMatrixMath:
    """Verifies statistical metric math and division-by-zero protection."""

    def test_perfect_classification(self) -> None:
        cm = ConfusionMatrix(tp=100, fp=0, tn=100, fn=0)
        assert cm.total == 200
        assert cm.tpr == 100.0
        assert cm.fpr == 0.0
        assert cm.precision == 100.0
        assert cm.recall == 100.0
        assert cm.f1 == 100.0
        assert cm.accuracy == 100.0

    def test_zero_denominator_protection(self) -> None:
        cm = ConfusionMatrix(tp=0, fp=0, tn=0, fn=0)
        assert cm.total == 0
        assert cm.tpr == 0.0
        assert cm.fpr == 0.0
        assert cm.precision == 0.0
        assert cm.recall == 0.0
        assert cm.f1 == 0.0
        assert cm.accuracy == 0.0

    def test_standard_confusion_matrix(self) -> None:
        cm = ConfusionMatrix(tp=80, fp=20, tn=70, fn=30)
        assert cm.total == 200
        assert cm.tpr == 80 / 110 * 100.0
        assert cm.fpr == 20 / 90 * 100.0
        assert cm.precision == 80 / 100 * 100.0
        assert cm.accuracy == 150 / 200 * 100.0


class TestBenchmarkExecutionAndSLAGate:
    """Executes the benchmark runner and verifies all non-negotiable SLAs."""

    def test_full_benchmark_slas_satisfied(self) -> None:
        report = run_benchmark(verbose=False)

        assert report.all_slas_passed is True
        assert report.total_cases >= 500
        assert report.ast_tpr >= 96.4
        assert report.fp_reduction >= 74.0
        assert report.secret_leak_rate == 0.0
        assert report.duration_seconds < 10.0

    def test_security_audit_bot_beats_regex_baseline(self) -> None:
        report = run_benchmark(verbose=False)
        bot_cm = report.security_bot_cm
        regex_cm = report.regex_baseline_cm

        # Bot must have strictly fewer false positives than regex
        assert bot_cm.fp < regex_cm.fp
        # Bot must have higher or equal accuracy and precision
        assert bot_cm.accuracy >= regex_cm.accuracy
        assert bot_cm.precision >= regex_cm.precision

    def test_print_benchmark_report_output_rendering(self) -> None:
        report = run_benchmark(verbose=False)
        output_buffer = io.StringIO()

        with patch("sys.stdout", output_buffer):
            print_benchmark_report(report)

        output = output_buffer.getvalue()
        assert "FORMAL ACCURACY BENCHMARK REPORT" in output
        assert "AST True-Positive Rate (TPR)" in output
        assert "False-Positive Reduction" in output
        assert "Secret Leak Rate" in output
        assert "ALL TARGET SLA INVARIANTS SATISFIED & VERIFIED" in output

    def test_scanners_direct_dispatch(self) -> None:
        cases = generate_corpus()
        sample_case = cases[0]

        regex_scanner = RegexBaselineScanner()
        bot_scanner = SecurityAuditBotScanner()

        assert isinstance(regex_scanner.scan(sample_case), bool)
        assert isinstance(bot_scanner.scan(sample_case), bool)
