from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest


RUNNER_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_wrongsecrets_challenge1.py"
COMPARATOR_PATH = Path(__file__).parents[1] / "scripts" / "compare_l2_wrongsecrets_challenge1_repeats.py"
TEST_HELPER_PATH = Path(__file__).with_name("test_replay_l2_wrongsecrets_challenge1.py")

RUNNER_SPEC = importlib.util.spec_from_file_location("k_guard_l2_wrongsecrets_runner_for_compare", RUNNER_PATH)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
runner = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = runner
RUNNER_SPEC.loader.exec_module(runner)

COMPARATOR_SPEC = importlib.util.spec_from_file_location("k_guard_l2_wrongsecrets_comparator", COMPARATOR_PATH)
assert COMPARATOR_SPEC is not None and COMPARATOR_SPEC.loader is not None
comparator = importlib.util.module_from_spec(COMPARATOR_SPEC)
sys.modules[COMPARATOR_SPEC.name] = comparator
COMPARATOR_SPEC.loader.exec_module(comparator)

HELPER_SPEC = importlib.util.spec_from_file_location("k_guard_l2_wrongsecrets_receipt_helper", TEST_HELPER_PATH)
assert HELPER_SPEC is not None and HELPER_SPEC.loader is not None
helper = importlib.util.module_from_spec(HELPER_SPEC)
sys.modules[HELPER_SPEC.name] = helper
HELPER_SPEC.loader.exec_module(helper)


def _write(path: Path, payload: dict[str, object]) -> None:
    path.write_bytes(runner.canonical_json_bytes(payload))


def _positive(dynamic: str) -> dict[str, object]:
    return helper._receipt("positive", dynamic)


def _negative(positive: dict[str, object], positive_path: Path, dynamic: str) -> dict[str, object]:
    receipt = helper._receipt("negative", dynamic)
    receipt["positive_receipt_sha256"] = runner.sha256_bytes(positive_path.read_bytes())
    receipt["positive_receipt_semantic_sha256"] = runner._canonical_sha256(
        runner.semantic_projection(positive, negative=False)
    )
    return receipt


def test_positive_comparator_ignores_dynamic_image_identity(tmp_path: Path) -> None:
    first = tmp_path / "positive-r1.json"
    second = tmp_path / "positive-r2.json"
    _write(first, _positive("4"))
    _write(second, _positive("5"))

    result = comparator.compare_receipts(first, second, negative=False)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["release_gate_passed"] is False
    assert result["authority"] == {
        "may_mark_field_fix": True,
        "may_affect_oracle_labels": False,
        "may_affect_performance_metrics": False,
        "may_affect_h100_or_release": False,
    }


def test_negative_comparator_requires_corresponding_positive_anchors(tmp_path: Path) -> None:
    first_positive = tmp_path / "positive-r1.json"
    second_positive = tmp_path / "positive-r2.json"
    positive_one = _positive("4")
    positive_two = _positive("5")
    _write(first_positive, positive_one)
    _write(second_positive, positive_two)
    first_negative = tmp_path / "negative-r1.json"
    second_negative = tmp_path / "negative-r2.json"
    _write(first_negative, _negative(positive_one, first_positive, "6"))
    _write(second_negative, _negative(positive_two, second_positive, "7"))

    result = comparator.compare_receipts(
        first_negative,
        second_negative,
        negative=True,
        first_positive=first_positive,
        second_positive=second_positive,
    )

    assert result["status"] == "FIX"
    assert result["positive_anchors"] is not None

    mismatched = copy.deepcopy(_negative(positive_one, first_positive, "8"))
    mismatched["positive_receipt_sha256"] = "f" * 64
    _write(second_negative, mismatched)
    with pytest.raises(ValueError, match="negative_positive_anchor_binding_invalid"):
        comparator.compare_receipts(
            first_negative,
            second_negative,
            negative=True,
            first_positive=first_positive,
            second_positive=second_positive,
        )


def test_comparator_rejects_same_path_and_noncanonical_receipt(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt.json"
    _write(receipt, _positive("4"))

    with pytest.raises(ValueError, match="execution_receipt_paths_not_distinct"):
        comparator.compare_receipts(receipt, receipt, negative=False)

    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps(_positive("5")), encoding="utf-8")
    with pytest.raises(ValueError, match="execution_receipt_not_canonical"):
        comparator.compare_receipts(receipt, invalid, negative=False)


def test_cli_rejects_partial_or_positive_mode_anchors(tmp_path: Path) -> None:
    first = tmp_path / "positive-r1.json"
    second = tmp_path / "positive-r2.json"
    _write(first, _positive("4"))
    _write(second, _positive("5"))

    with pytest.raises(SystemExit) as partial:
        comparator.main(
            [
                "--first",
                str(first),
                "--second",
                str(second),
                "--output",
                str(tmp_path / "partial.json"),
                "--negative",
                "--first-positive",
                str(first),
            ]
        )
    assert partial.value.code == 2

    with pytest.raises(SystemExit) as positive:
        comparator.main(
            [
                "--first",
                str(first),
                "--second",
                str(second),
                "--output",
                str(tmp_path / "positive.json"),
                "--first-positive",
                str(first),
            ]
        )
    assert positive.value.code == 2
