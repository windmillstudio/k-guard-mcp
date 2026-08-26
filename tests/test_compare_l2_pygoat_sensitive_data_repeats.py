from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
RUNNER_TEST_PATH = ROOT / "tests" / "test_replay_l2_pygoat_sensitive_data.py"
RUNNER_TEST_SPEC = importlib.util.spec_from_file_location("pygoat_replay_fixtures", RUNNER_TEST_PATH)
assert RUNNER_TEST_SPEC is not None and RUNNER_TEST_SPEC.loader is not None
fixtures = importlib.util.module_from_spec(RUNNER_TEST_SPEC)
sys.modules[RUNNER_TEST_SPEC.name] = fixtures
RUNNER_TEST_SPEC.loader.exec_module(fixtures)

MODULE_PATH = ROOT / "scripts" / "compare_l2_pygoat_sensitive_data_repeats.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_pygoat_sensitive_data_compare", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
compare = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compare
SPEC.loader.exec_module(compare)


def _write(path: Path, payload: dict) -> str:
    raw = compare.canonical_json_bytes(payload)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_positive_comparator_ignores_runtime_nonces_but_binds_contract(tmp_path: Path) -> None:
    first = tmp_path / "positive-1.json"
    second = tmp_path / "positive-2.json"
    one = fixtures._positive_receipt()
    two = copy.deepcopy(one)
    two["runs"][0]["run_nonce_sha256"] = "9" * 64
    _write(first, one)
    _write(second, two)

    comparison = compare.compare_positive_receipts(first, second)
    assert comparison["status"] == "FIX"
    assert comparison["repeat_exact"] is True

    altered = copy.deepcopy(two)
    altered["image"]["dockerfile_sha256"] = "a" * 64
    _write(second, altered)
    assert compare.compare_positive_receipts(first, second)["status"] == "HOLD"


def test_negative_comparator_requires_two_positive_receipt_anchors(tmp_path: Path) -> None:
    positive_one = tmp_path / "positive-1.json"
    positive_two = tmp_path / "positive-2.json"
    one = fixtures._positive_receipt()
    two = copy.deepcopy(one)
    two["runs"][0]["run_nonce_sha256"] = "9" * 64
    one_sha = _write(positive_one, one)
    two_sha = _write(positive_two, two)
    positive_comparison = tmp_path / "positive-comparison.json"
    _write(positive_comparison, compare.compare_positive_receipts(positive_one, positive_two))

    negative_one = tmp_path / "negative-1.json"
    negative_two = tmp_path / "negative-2.json"
    first = fixtures._negative_receipt()
    second = copy.deepcopy(first)
    first["positive_execution_contract"]["receipt_sha256"] = one_sha
    second["positive_execution_contract"]["receipt_sha256"] = two_sha
    second["runs"][0]["run_nonce_sha256"] = "9" * 64
    _write(negative_one, first)
    _write(negative_two, second)

    comparison = compare.compare_negative_receipts(
        negative_one, negative_two, positive_comparison
    )
    assert comparison["status"] == "FIX"
    assert comparison["positive_execution_pair"]["status"] == "FIX"

    broken = copy.deepcopy(second)
    broken["positive_execution_contract"]["receipt_sha256"] = "f" * 64
    _write(negative_two, broken)
    with pytest.raises(ValueError, match="positive_comparison_anchor_mismatch"):
        compare.compare_negative_receipts(negative_one, negative_two, positive_comparison)


def test_comparator_rejects_noncanonical_input_and_overwrite(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt.json"
    # A canonical empty object is exactly b"{}\n" on POSIX.  Use a missing
    # terminal newline so this fixture is non-canonical on every platform.
    receipt.write_bytes(b"{}")
    with pytest.raises(ValueError, match="execution_receipt_not_canonical"):
        compare.compare_positive_receipts(receipt, receipt)

    output = tmp_path / "comparison.json"
    output.write_text("already", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing_to_overwrite_execution_repeat_evidence"):
        compare.write_comparison(output, {"raw_returned": False})
