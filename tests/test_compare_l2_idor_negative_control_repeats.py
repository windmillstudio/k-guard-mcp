from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_l2_idor_negative_control_repeats.py"
SPEC = importlib.util.spec_from_file_location("compare_l2_idor_negative_control_repeats_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = comparison
SPEC.loader.exec_module(comparison)


def _run(nonce: str = "a" * 64, image_id: str = "b" * 64) -> dict[str, object]:
    runner = comparison._load_runner()
    return {
        "run_nonce_sha256": nonce,
        "image_id": f"sha256:{image_id}",
        "maven_command_sha256": "c" * 64,
        "runtime_command_sha256": "d" * 64,
        "network_policy": "none",
        "expected_exit_code": runner.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE,
        "isolation": {"checks": {"network_none": True, "no_bind_mounts": True}, "passed": True, "raw_returned": False},
        "execution": {"returncode": runner.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE, "stdout_sha256": "e" * 64, "stderr_sha256": "f" * 64, "raw_returned": False},
        "normalized_result": {"schema": runner.NEGATIVE_CONTROL_RESULT_SCHEMA, "control_triggered": True, "suite": {"all_cases_passed": False}, "raw_returned": False},
        "observed_result": None,
        "report_hashes": {"summary_sha256": "1" * 64, "suite_sha256": "2" * 64},
        "cleanup": {"passed": True, "raw_returned": False},
        "failure_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _receipt(positive_receipt_sha256: str) -> dict[str, object]:
    runner = comparison._load_runner()
    first = _run()
    second = _run(nonce="9" * 64)
    projections = [runner._consensus_projection(first), runner._consensus_projection(second)]
    control = {
        "patch_id": runner.NEGATIVE_CONTROL_PATCH_ID,
        "source_path": runner.NEGATIVE_CONTROL_SOURCE_PATH.as_posix(),
        "original_file_sha256": "3" * 64,
        "patched_file_sha256": "4" * 64,
        "patch_sha256": "5" * 64,
        "variant_tree_sha256": "6" * 64,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }
    return {
        "schema": runner.NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": {"runner_sha256": "7" * 64, "source_verifier_sha256": "8" * 64, "base_image": runner.BASE_IMAGE, "raw_returned": False},
        "source": {"repository_id": runner.REPOSITORY_ID, "commit": runner.SOURCE_COMMIT, "commit_tree": runner.SOURCE_TREE, "source_tree_sha256": runner.SOURCE_TREE_SHA256, "source_receipt_sha256": "9" * 64, "file_count": 1211, "total_bytes": 21101002, "raw_returned": False},
        "positive_execution_contract": {"receipt_sha256": positive_receipt_sha256, "source_receipt_sha256": "9" * 64, "execution_contract_status": "EXECUTION_CONTRACT_PASS", "raw_returned": False},
        "negative_control": control,
        "image": {"base_image": runner.BASE_IMAGE, "build_command_sha256": "a" * 64, "build_contract_sha256": "b" * 64, "build_output_sha256": "c" * 64, "dockerfile_sha256": "d" * 64, "image_id": "sha256:" + "e" * 64, "image_id_sha256": "f" * 64, "online_build_non_evidence": True, "source_derived": True, "source_variant": control, "raw_returned": False},
        "runs": [first, second],
        "consensus": {"run_count": 2, "two_runs_byte_equivalent_after_normalization": True, "projection_sha256": runner._canonical_sha256(projections), "raw_returned": False},
        "image_cleanup": {"passed": True, "raw_returned": False},
        "claim_boundary": runner._negative_control_claim_boundary(),
        "admission_blockers": list(runner.NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": "NEGATIVE_CONTROL_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _write(path: Path, receipt: dict[str, object]) -> None:
    path.write_bytes(comparison.canonical_json_bytes(receipt))


def _positive_comparison(first_receipt_sha256: str, second_receipt_sha256: str) -> dict[str, object]:
    fingerprint = "c" * 64
    return {
        "schema": comparison.POSITIVE_COMPARISON_SCHEMA,
        "scenario": "webgoat-idor-upstream-integration-test",
        "first_receipt_sha256": first_receipt_sha256,
        "second_receipt_sha256": second_receipt_sha256,
        "first_semantic_fingerprint_sha256": fingerprint,
        "second_semantic_fingerprint_sha256": fingerprint,
        "repeat_exact": True,
        "status": "FIX",
        "authority": {
            "may_mark_field_fix": True,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "execution_repeatability_only": True,
            "scanner_accuracy_proven": False,
            "severity_or_cwe_admitted": False,
            "tp_fp_fn_admitted": False,
            "release_gate_admitted": False,
        },
        "raw_returned": False,
    }


def _write_positive_comparison(path: Path, first_receipt_sha256: str, second_receipt_sha256: str) -> None:
    path.write_bytes(comparison.canonical_json_bytes(_positive_comparison(first_receipt_sha256, second_receipt_sha256)))


def test_compares_fresh_negative_control_receipts_while_ignoring_volatile_values(tmp_path: Path) -> None:
    first_positive = "a" * 64
    second_positive = "b" * 64
    first = _receipt(first_positive)
    second = _receipt(second_positive)
    for index, run in enumerate(second["runs"]):
        run["run_nonce_sha256"] = str(index + 2) * 64
        run["image_id"] = "sha256:" + "0" * 64
        run["execution"]["stdout_sha256"] = str(index + 3) * 64
    second["image"]["image_id"] = "sha256:" + "0" * 64
    second["image"]["image_id_sha256"] = "1" * 64
    second["image"]["build_output_sha256"] = "2" * 64
    second["image"]["build_command_sha256"] = "3" * 64
    runner = comparison._load_runner()
    second["consensus"]["projection_sha256"] = runner._canonical_sha256(
        [runner._consensus_projection(run) for run in second["runs"]]
    )
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    positive_comparison_path = tmp_path / "positive-comparison.json"
    _write(first_path, first)
    _write(second_path, second)
    _write_positive_comparison(positive_comparison_path, first_positive, second_positive)

    result = comparison.compare_receipts(first_path, second_path, positive_comparison_path)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["authority"]["may_affect_h100_or_release"] is False


def test_rejects_positive_comparison_anchor_mismatch_and_holds_for_mutation_change(tmp_path: Path) -> None:
    first_positive = "a" * 64
    second_positive = "b" * 64
    first = _receipt(first_positive)
    second = _receipt("0" * 64)
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    positive_comparison_path = tmp_path / "positive-comparison.json"
    _write(first_path, first)
    _write(second_path, second)
    _write_positive_comparison(positive_comparison_path, first_positive, second_positive)

    with pytest.raises(ValueError, match="positive_comparison_anchor_mismatch"):
        comparison.compare_receipts(first_path, second_path, positive_comparison_path)

    second = _receipt(second_positive)
    second["negative_control"]["patch_sha256"] = "0" * 64
    second["image"]["source_variant"] = second["negative_control"]
    _write(second_path, second)
    result = comparison.compare_receipts(first_path, second_path, positive_comparison_path)

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False


def test_rejects_holding_or_noncanonical_negative_receipts(tmp_path: Path) -> None:
    first_positive = "a" * 64
    second_positive = "b" * 64
    holding = _receipt(first_positive)
    holding["negative_control_status"] = "HOLD"
    holding["failure_code"] = "simulated_failure"
    valid = _receipt(second_positive)
    holding_path = tmp_path / "holding.json"
    valid_path = tmp_path / "valid.json"
    positive_comparison_path = tmp_path / "positive-comparison.json"
    _write(holding_path, holding)
    _write(valid_path, valid)
    _write_positive_comparison(positive_comparison_path, first_positive, second_positive)

    with pytest.raises(ValueError, match="not_passed"):
        comparison.compare_receipts(holding_path, valid_path, positive_comparison_path)

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"not": "canonical"}', encoding="utf-8")
    with pytest.raises(ValueError, match="not_canonical"):
        comparison.compare_receipts(malformed, valid_path, positive_comparison_path)


def test_refuses_to_overwrite_negative_comparison_evidence(tmp_path: Path) -> None:
    output = tmp_path / "comparison.json"
    output.write_text("existing", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing_to_overwrite"):
        comparison.write_comparison(output, {"schema": comparison.SCHEMA})
