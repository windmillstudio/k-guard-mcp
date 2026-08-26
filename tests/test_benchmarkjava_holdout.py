from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_benchmarkjava_holdout",
    ROOT / "scripts" / "run_benchmarkjava_holdout.py",
)
assert SPEC and SPEC.loader
holdout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(holdout)


def test_holdout_runner_supports_direct_cli_execution() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "run_benchmarkjava_holdout.py"), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )

    assert completed.returncode == 0
    assert "preregistered OWASP BenchmarkJava" in completed.stdout


def test_case_predictions_bind_only_high_sql_findings_to_official_case_ids() -> None:
    report = {
        "findings": [
            {
                "rule_id": "WEB_UNTRUSTED_INPUT_TO_SQL",
                "severity": "critical",
                "file": "<workspace>/src/BenchmarkTest00001.java",
                "line_start": 10,
                "evidence": "sink_hash=one",
            },
            {
                "rule_id": "WEB_UNTRUSTED_INPUT_TO_SQL",
                "severity": "medium",
                "file": "<workspace>/src/BenchmarkTest00002.java",
                "line_start": 11,
                "evidence": "sink_hash=two",
            },
            {
                "rule_id": "OTHER_RULE",
                "severity": "critical",
                "file": "<workspace>/src/BenchmarkTest00003.java",
                "line_start": 12,
                "evidence": "sink_hash=three",
            },
        ]
    }

    predictions, refs, unmatched = holdout._case_predictions(report, {"WEB_UNTRUSTED_INPUT_TO_SQL"})

    assert predictions == {"BenchmarkTest00001"}
    assert list(refs) == ["BenchmarkTest00001"]
    assert len(refs["BenchmarkTest00001"][0]) == 20
    assert unmatched == 0


def test_score_and_wilson_metrics_are_fail_closed_and_deterministic() -> None:
    truth = {
        "BenchmarkTest00001": True,
        "BenchmarkTest00002": True,
        "BenchmarkTest00003": False,
        "BenchmarkTest00004": False,
    }

    metrics, cases = holdout._score(truth, {"BenchmarkTest00001", "BenchmarkTest00003"}, {})

    assert metrics == {
        "total_cases": 4,
        "vulnerable_cases": 2,
        "clean_cases": 2,
        "true_positive": 1,
        "false_positive": 1,
        "false_negative": 1,
        "true_negative": 1,
        "precision": 0.5,
        "precision_wilson_95_lower": 0.094531,
        "recall": 0.5,
        "recall_wilson_95_lower": 0.094531,
        "specificity": 0.5,
        "specificity_wilson_95_lower": 0.094531,
    }
    assert [case["outcome"] for case in cases] == ["tp", "fn", "fp", "tn"]


def test_threshold_checks_require_every_preregistered_floor() -> None:
    metrics = {
        "total_cases": 504,
        "vulnerable_cases": 272,
        "clean_cases": 232,
        "precision": 0.81,
        "precision_wilson_95_lower": 0.76,
        "recall": 0.91,
        "recall_wilson_95_lower": 0.86,
        "specificity": 0.89,
        "specificity_wilson_95_lower": 0.86,
    }
    thresholds = {
        "minimum_total_cases": 100,
        "minimum_vulnerable_cases": 40,
        "minimum_clean_cases": 40,
        "minimum_precision": 0.8,
        "minimum_precision_wilson_95_lower": 0.75,
        "minimum_recall": 0.9,
        "minimum_recall_wilson_95_lower": 0.85,
        "minimum_specificity": 0.9,
        "minimum_specificity_wilson_95_lower": 0.85,
    }

    checks = holdout._threshold_checks(metrics, thresholds)

    assert checks["minimum_specificity"] is False
    assert sum(checks.values()) == len(checks) - 1
