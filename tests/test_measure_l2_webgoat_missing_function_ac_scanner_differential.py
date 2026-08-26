from __future__ import annotations

import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "measure_l2_webgoat_missing_function_ac_scanner_differential.py"
SPEC = importlib.util.spec_from_file_location("measure_l2_webgoat_missing_function_ac_scanner_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
measure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure)


def _empty() -> dict:
    return {"relevant_finding_count": 0, "relevant_findings": [], "raw_returned": False}


def _positive(*, line: int = 83) -> dict:
    finding = {
        "rule_id": measure.EXPECTED_RULE_ID,
        "severity": measure.EXPECTED_SEVERITY,
        "confidence": measure.EXPECTED_CONFIDENCE,
        "detector_subtype": measure.EXPECTED_SUBTYPE,
        "artifact_scope": measure.EXPECTED_ARTIFACT_SCOPE,
        "path": measure.IMPLEMENTATION_PATH.as_posix(),
        "line": line,
        "line_hash": "a" * 16,
        "raw_returned": False,
    }
    return {"relevant_finding_count": 1, "relevant_findings": [finding], "raw_returned": False}


def _candidate_pair(*, negative_present: bool = False) -> dict:
    return {
        "positive_oracle": _positive(),
        "negative_oracle": _positive() if negative_present else _empty(),
        "raw_returned": False,
    }


def _receipt(*, status: str = measure.STATUS_PASS) -> dict:
    runs = [_candidate_pair(), _candidate_pair()] if status == measure.STATUS_PASS else []
    baseline_pair = {"positive_oracle": _empty(), "negative_oracle": _empty(), "raw_returned": False}
    source = {
        "app_id": "webgoat",
        "repository_id": "webgoat/webgoat",
        "commit": "a" * 40,
        "commit_tree": "b" * 40,
        "source_tree_sha256": "c" * 64,
        "source_receipt_sha256": "d" * 64,
        "source_receipt_semantic_sha256": "e" * 64,
        "lineage_id": "f" * 64,
        "implementation_path": measure.IMPLEMENTATION_PATH.as_posix(),
        "implementation_sha256": "1" * 64,
        "raw_returned": False,
    }
    mapping = {
        **source,
        "scenario_id": "webgoat:scenario",
        "persistence_line": 83,
    }
    return {
        "schema": measure.SCHEMA,
        "tool_provenance": {"raw_returned": False},
        "source": source,
        "evidence": {"raw_returned": False},
        "mapping": mapping,
        "execution_pair": {"raw_returned": False},
        "negative_control": {"raw_returned": False},
        "baseline": {
            "prechange_baseline": {"actual_prechange_zero_findings": True, "raw_returned": False},
            "counterfactual": {"variant": measure.BASELINE_VARIANT, "raw_returned": False},
            "pair": baseline_pair,
            "actual_prechange_zero_findings": True,
            "counterfactual_baseline_is_not_shipped_history": True,
            "raw_returned": False,
        },
        "candidate_runs": runs,
        "consensus": {
            "run_count": len(runs),
            "two_runs_byte_equivalent_after_normalization": len(runs) == 2,
            "projection_sha256": measure._canonical_sha256(runs) if runs else None,
            "raw_returned": False,
        },
        "score": {"generated_pair_count": 1, "tp": 1, "fp": 0, "fn": 0, "tn": 1}
        if status == measure.STATUS_PASS
        else None,
        "claim_boundary": measure._claim_boundary(),
        "differential_status": status,
        "release_gate_passed": False,
        "failure_code": None if status == measure.STATUS_PASS else "source_binding_changed_during_measurement",
        "raw_returned": False,
    }


def test_receipt_accepts_one_repeatable_generated_pair_without_product_promotion() -> None:
    receipt = _receipt()

    measure.validate_receipt(receipt)

    assert receipt["claim_boundary"]["actual_prechange_baseline_proven"] is True
    assert receipt["claim_boundary"]["product_accuracy_proven"] is False
    assert receipt["release_gate_passed"] is False


def test_receipt_rejects_a_negative_control_finding_and_nonrepeatable_candidate_runs() -> None:
    receipt = _receipt()
    receipt["candidate_runs"][0] = _candidate_pair(negative_present=True)

    with pytest.raises(measure.DifferentialError, match="candidate_pair_outcome_invalid"):
        measure.validate_receipt(receipt)

    receipt = _receipt()
    receipt["candidate_runs"][1]["positive_oracle"]["relevant_findings"][0]["line_hash"] = "b" * 16
    receipt["consensus"] = {
        "run_count": 2,
        "two_runs_byte_equivalent_after_normalization": False,
        "projection_sha256": measure._canonical_sha256(receipt["candidate_runs"]),
        "raw_returned": False,
    }

    with pytest.raises(measure.DifferentialError, match="candidate_runs_not_repeatable"):
        measure.validate_receipt(receipt)


def test_receipt_rejects_claim_promotion_and_missing_actual_prechange_baseline() -> None:
    receipt = _receipt()
    receipt["claim_boundary"]["product_tp_fp_fn_tn_proven"] = True

    with pytest.raises(measure.DifferentialError, match="claim_boundary_invalid"):
        measure.validate_receipt(receipt)

    receipt = _receipt()
    receipt["baseline"]["prechange_baseline"]["actual_prechange_zero_findings"] = False

    with pytest.raises(measure.DifferentialError, match="baseline_invalid"):
        measure.validate_receipt(receipt)


def test_hold_receipt_requires_a_failure_code() -> None:
    receipt = _receipt(status=measure.STATUS_HOLD)
    measure.validate_receipt(receipt)

    receipt["failure_code"] = None
    with pytest.raises(measure.DifferentialError, match="hold_without_failure"):
        measure.validate_receipt(receipt)
