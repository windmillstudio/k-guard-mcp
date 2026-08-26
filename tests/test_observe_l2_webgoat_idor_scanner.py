from __future__ import annotations

import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "observe_l2_webgoat_idor_scanner.py"
SPEC = importlib.util.spec_from_file_location("observe_l2_webgoat_idor_scanner_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
observer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(observer)


def _source() -> dict:
    return {
        "repository_id": observer.REPOSITORY_ID,
        "commit": observer.SOURCE_COMMIT,
        "commit_tree": observer.SOURCE_TREE,
        "source_tree_sha256": observer.SOURCE_TREE_SHA256,
        "source_receipt_sha256": observer.SOURCE_RECEIPT_SHA256,
        "file_count": 1211,
        "total_bytes": 21101002,
        "raw_returned": False,
    }


def _run() -> dict:
    return {
        "rule_id": observer.EXPECTED_RULE_ID,
        "severity": observer.EXPECTED_SEVERITY,
        "confidence": observer.EXPECTED_CONFIDENCE,
        "detector_subtype": observer.EXPECTED_SUBTYPE,
        "artifact_scope": observer.EXPECTED_ARTIFACT_SCOPE,
        "implementation_path": observer.IMPLEMENTATION_SOURCE_PATH.as_posix(),
        "line": observer.EXPECTED_FINDING_LINE,
        "line_hash": observer.EXPECTED_LINE_HASH,
        "raw_returned": False,
    }


def _receipt(*, status: str = observer.STATUS_PASS) -> dict:
    source = _source()
    runs = [_run(), _run()] if status == observer.STATUS_PASS else []
    receipt = {
        "schema": observer.SCHEMA,
        "tool_provenance": {
            "observer_sha256": "c" * 64,
            "runtime_contract_sha256": "d" * 64,
            "scanner_sha256": "e" * 64,
            "polyglot_detector_sha256": "f" * 64,
            "raw_returned": False,
        },
        "source": source if status == observer.STATUS_PASS else None,
        "execution_pair": {
            "positive_execution_receipt_sha256": observer.POSITIVE_EXECUTION_RECEIPT_SHA256,
            "negative_control_receipt_sha256": observer.NEGATIVE_CONTROL_RECEIPT_SHA256,
            "source_receipt_sha256": source["source_receipt_sha256"],
            "both_statuses_passed": True,
            "raw_returned": False,
        } if status == observer.STATUS_PASS else None,
        "mapping": {
            "oracle_source": {
                "path": observer.ORACLE_SOURCE_PATH.as_posix(),
                "content_sha256": "3" * 64,
                "line": observer.ORACLE_ROUTE_LINE,
            },
            "implementation_source": {
                "path": observer.IMPLEMENTATION_SOURCE_PATH.as_posix(),
                "content_sha256": "4" * 64,
                "line": observer.IMPLEMENTATION_ROUTE_LINE,
            },
            "mapping_kind": observer.ROUTE_MAPPING_KIND,
            "raw_returned": False,
        } if status == observer.STATUS_PASS else None,
        "runs": runs,
        "consensus": {
            "run_count": len(runs),
            "two_runs_byte_equivalent_after_normalization": len(runs) == 2 and runs[0] == runs[1],
            "projection_sha256": observer._canonical_sha256(runs) if runs else None,
            "raw_returned": False,
        },
        "claim_boundary": observer._claim_boundary(),
        "admission_blockers": list(observer.ADMISSION_BLOCKERS),
        "mapping_status": status,
        "release_gate_passed": False,
        "failure_code": None if status == observer.STATUS_PASS else "source_identity_mismatch",
        "raw_returned": False,
    }
    return receipt


def test_receipt_accepts_a_two_run_non_promoting_mapping_contract() -> None:
    receipt = _receipt()

    observer.validate_receipt(receipt)
    assert receipt["claim_boundary"]["source_bound_scanner_mapping_proven"] is True
    assert receipt["claim_boundary"]["tp_fp_fn_admitted"] is False
    assert receipt["release_gate_passed"] is False


def test_runtime_contract_loader_supports_dataclass_backed_contract_module() -> None:
    runtime = observer._load_runtime_contract()

    assert runtime.SCHEMA == "k_guard_l2_webgoat_idor_execution_contract.v1"
    assert runtime.NEGATIVE_CONTROL_SCHEMA == "k_guard_l2_webgoat_idor_negative_control.v1"


def test_receipt_rejects_scanner_accuracy_or_release_promotion() -> None:
    receipt = _receipt()
    receipt["claim_boundary"]["scanner_accuracy_proven"] = True

    with pytest.raises(observer.ObservationError, match="claim_boundary"):
        observer.validate_receipt(receipt)

    receipt = _receipt()
    receipt["release_gate_passed"] = True
    with pytest.raises(observer.ObservationError, match="claim_boundary"):
        observer.validate_receipt(receipt)


def test_receipt_rejects_nonrepeatable_or_wrong_observer_finding() -> None:
    receipt = _receipt()
    receipt["runs"][1]["line_hash"] = "9" * 16
    receipt["consensus"] = {
        "run_count": 2,
        "two_runs_byte_equivalent_after_normalization": False,
        "projection_sha256": observer._canonical_sha256(receipt["runs"]),
        "raw_returned": False,
    }

    with pytest.raises(observer.ObservationError, match="scanner_run_line_hash_invalid"):
        observer.validate_receipt(receipt)

    receipt = _receipt()
    receipt["runs"] = [_run()]
    receipt["consensus"] = {
        "run_count": 1,
        "two_runs_byte_equivalent_after_normalization": False,
        "projection_sha256": observer._canonical_sha256(receipt["runs"]),
        "raw_returned": False,
    }
    with pytest.raises(observer.ObservationError, match="pass_without_complete_evidence"):
        observer.validate_receipt(receipt)

    receipt = _receipt()
    receipt["runs"][0]["detector_subtype"] = "different"
    receipt["runs"][1]["detector_subtype"] = "different"
    receipt["consensus"]["projection_sha256"] = observer._canonical_sha256(receipt["runs"])
    with pytest.raises(observer.ObservationError, match="scanner_run_finding_invalid"):
        observer.validate_receipt(receipt)

    receipt = _receipt()
    receipt["execution_pair"]["positive_execution_receipt_sha256"] = "9" * 64
    with pytest.raises(observer.ObservationError, match="receipt_identity"):
        observer.validate_receipt(receipt)


def test_hold_receipt_requires_an_explicit_failure() -> None:
    receipt = _receipt(status=observer.STATUS_HOLD)
    observer.validate_receipt(receipt)

    receipt = deepcopy(receipt)
    receipt["failure_code"] = None
    with pytest.raises(observer.ObservationError, match="hold_without_failure"):
        observer.validate_receipt(receipt)
