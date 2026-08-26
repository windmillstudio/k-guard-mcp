from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "replay_juliet_java_remediation",
    ROOT / "scripts" / "replay_juliet_java_remediation.py",
)
assert SPEC and SPEC.loader
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


def _first_result() -> dict:
    return {
        "schema": replay.REPORT_SCHEMA,
        "scanner_revision": "a" * 40,
        "source": {"archive_sha256": replay.ARCHIVE_SHA256},
        "metrics": {"total_units": 4, "false_negative": 1},
        "cases": [{"flow_variant": "06", "outcome": "fn"}],
    }


def _worker(*, second_unit_tainted: bool = True) -> dict:
    return {
        "schema": replay.WORKER_SCHEMA,
        "errors": [],
        "units": [
            {"expected": "vulnerable", "predicted": "vulnerable", "flow_variant": "06"},
            {
                "expected": "clean",
                "predicted": "clean" if second_unit_tainted else "vulnerable",
                "flow_variant": "06",
            },
            {"expected": "vulnerable", "predicted": "vulnerable", "flow_variant": "07"},
            {"expected": "clean", "predicted": "clean", "flow_variant": "07"},
        ],
    }


def test_remediation_replay_is_explicitly_not_an_independent_holdout() -> None:
    worker = _worker()
    result = replay.build_result(
        _first_result(),
        [worker, worker],
        ["b" * 64, "b" * 64],
        execution_revision="c" * 40,
        first_result_sha256="d" * 64,
    )

    assert result["passed"] is True
    assert result["metrics"]["true_positive"] == 2
    assert result["metrics"]["false_negative"] == 0
    assert result["remediation"]["flow_variants"] == ["06"]
    assert result["claim_boundary"]["not_an_independent_holdout"] is True
    assert result["claim_boundary"]["first_result_remains_the_independent_public_result"] is True


def test_remediation_replay_holds_on_repeat_drift_or_false_positive() -> None:
    result = replay.build_result(
        _first_result(),
        [_worker(second_unit_tainted=False), _worker(second_unit_tainted=False)],
        ["b" * 64, "c" * 64],
        execution_revision="d" * 40,
        first_result_sha256="e" * 64,
    )

    assert result["passed"] is False
    assert result["verdict"] == "hold"
    assert result["metrics"]["false_positive"] == 1


def test_remediation_replay_requires_retained_first_failure() -> None:
    first = _first_result()
    first["metrics"]["false_negative"] = 0

    with pytest.raises(ValueError, match="false negatives"):
        replay.build_result(
            first,
            [_worker(), _worker()],
            ["b" * 64, "b" * 64],
            execution_revision="f" * 40,
            first_result_sha256="a" * 64,
        )
