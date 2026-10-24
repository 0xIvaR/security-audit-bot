"""Unit test verifying PR audit simulation script execution."""

from __future__ import annotations

from pathlib import Path

from scripts.simulate_audit import run_scenario_blocked, run_scenario_clean
from src.aggregator import evaluate_policy


def test_simulation_scenarios(tmp_path: Path) -> None:
    blocked_report = run_scenario_blocked(tmp_path)
    assert blocked_report.should_block_merge is True
    assert evaluate_policy(blocked_report) == 1
    assert len(blocked_report.findings) >= 2
    assert (tmp_path / "pr_blocked_comment.md").exists()
    assert (tmp_path / "pr_blocked_report.html").exists()

    clean_report = run_scenario_clean(tmp_path)
    assert clean_report.should_block_merge is False
    assert evaluate_policy(clean_report) == 0
    assert len(clean_report.findings) == 0
    assert (tmp_path / "pr_clean_comment.md").exists()
    assert (tmp_path / "pr_clean_report.html").exists()
