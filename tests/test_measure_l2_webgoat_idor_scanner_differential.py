from __future__ import annotations

import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "measure_l2_webgoat_idor_scanner_differential.py"
SPEC = importlib.util.spec_from_file_location("measure_l2_webgoat_idor_scanner_differential_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
measure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure)


def _finding(*, present: bool) -> dict:
    findings = []
    if present:
        findings.append(
            {
                "rule_id": measure.EXPECTED_RULE_ID,
                "severity": measure.EXPECTED_SEVERITY,
                "confidence": measure.EXPECTED_CONFIDENCE,
                "detector_subtype": measure.EXPECTED_SUBTYPE,
                "artifact_scope": measure.EXPECTED_ARTIFACT_SCOPE,
                "path": "src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java",
                "line": 53,
                "line_hash": "0" * 16,
                "raw_returned": False,
            }
        )
    return {"relevant_finding_count": len(findings), "relevant_findings": findings, "raw_returned": False}


def _pair(*, negative_present: bool) -> dict:
    return {
        "positive_oracle": _finding(present=True),
        "negative_oracle": _finding(present=negative_present),
        "raw_returned": False,
    }


def _receipt(*, status: str = measure.STATUS_PASS) -> dict:
    candidate = _pair(negative_present=False)
    runs = [candidate, deepcopy(candidate)] if status == measure.STATUS_PASS else []
    return {
        "schema": measure.SCHEMA,
        "tool_provenance": {"raw_returned": False},
        "source_admission": {"raw_returned": False},
        "source": {
            "preregistered_source_receipt_sha256": "a" * 64,
            "observed_source_receipt_sha256": "b" * 64,
            "source_receipt_semantic_sha256": "c" * 64,
            "receipt_equivalence": "informational_porcelain_variance",
            "raw_returned": False,
        } if status == measure.STATUS_PASS else None,
        "execution_pair": {"source_receipt_sha256": "a" * 64, "raw_returned": False} if status == measure.STATUS_PASS else None,
        "mapping": {"raw_returned": False},
        "negative_control": {"raw_returned": False},
        "baseline": {
            "pair": _pair(negative_present=True),
            "historical_false_positive_reproduced": True,
            "raw_returned": False,
        } if status == measure.STATUS_PASS else None,
        "candidate_runs": runs,
        "consensus": {
            "run_count": len(runs),
            "two_runs_byte_equivalent_after_normalization": len(runs) == 2 and runs[0] == runs[1],
            "projection_sha256": measure._canonical_sha256(runs) if runs else None,
            "raw_returned": False,
        },
        "score": {"generated_pair_count": 1, "tp": 1, "fp": 0, "fn": 0, "tn": 1} if status == measure.STATUS_PASS else None,
        "claim_boundary": measure._claim_boundary(),
        "differential_status": status,
        "release_gate_passed": False,
        "failure_code": None if status == measure.STATUS_PASS else "source_admission_changed_during_measurement",
        "raw_returned": False,
    }


def test_receipt_accepts_a_repeatable_generated_pair_without_product_promotion() -> None:
    receipt = _receipt()

    measure.validate_receipt(receipt)

    assert receipt["claim_boundary"]["candidate_pair_tp_tn_proven"] is True
    assert receipt["claim_boundary"]["product_accuracy_proven"] is False
    assert receipt["release_gate_passed"] is False


def test_receipt_rejects_candidate_false_positive_and_nonrepeatable_runs() -> None:
    receipt = _receipt()
    receipt["candidate_runs"][0]["negative_oracle"] = _finding(present=True)

    with pytest.raises(measure.DifferentialError, match="candidate_pair_outcome_invalid"):
        measure.validate_receipt(receipt)

    receipt = _receipt()
    receipt["candidate_runs"][1]["positive_oracle"]["relevant_findings"][0]["line_hash"] = "1" * 16
    receipt["consensus"] = {
        "run_count": 2,
        "two_runs_byte_equivalent_after_normalization": False,
        "projection_sha256": measure._canonical_sha256(receipt["candidate_runs"]),
        "raw_returned": False,
    }

    with pytest.raises(measure.DifferentialError, match="candidate_runs_not_repeatable"):
        measure.validate_receipt(receipt)


def test_receipt_rejects_product_promotion_and_invalid_source_binding() -> None:
    receipt = _receipt()
    receipt["claim_boundary"]["product_accuracy_proven"] = True

    with pytest.raises(measure.DifferentialError, match="claim_boundary_invalid"):
        measure.validate_receipt(receipt)

    receipt = _receipt()
    receipt["execution_pair"]["source_receipt_sha256"] = "d" * 64

    with pytest.raises(measure.DifferentialError, match="execution_pair_source_binding_invalid"):
        measure.validate_receipt(receipt)


def test_hold_receipt_requires_a_failure_code() -> None:
    receipt = _receipt(status=measure.STATUS_HOLD)
    measure.validate_receipt(receipt)

    receipt["failure_code"] = None
    with pytest.raises(measure.DifferentialError, match="hold_without_failure"):
        measure.validate_receipt(receipt)
