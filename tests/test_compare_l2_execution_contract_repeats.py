from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_l2_execution_contract_repeats.py"
SPEC = importlib.util.spec_from_file_location("compare_l2_execution_contract_repeats_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = comparison
SPEC.loader.exec_module(comparison)


def _run(nonce: str = "a" * 64, image_id: str = "b" * 64) -> dict[str, object]:
    return {
        "run_nonce_sha256": nonce,
        "image_id": f"sha256:{image_id}",
        "maven_command_sha256": "c" * 64,
        "runtime_command_sha256": "d" * 64,
        "network_policy": "none",
        "expected_exit_code": 0,
        "isolation": {"checks": {"network_none": True, "no_bind_mounts": True}, "passed": True, "raw_returned": False},
        "execution": {"returncode": 0, "stdout_sha256": "e" * 64, "stderr_sha256": "f" * 64, "raw_returned": False},
        "normalized_result": {"tests": 2, "failures": 0, "raw_returned": False},
        "observed_result": None,
        "report_hashes": {"summary_sha256": "1" * 64, "suite_sha256": "2" * 64},
        "cleanup": {"passed": True, "raw_returned": False},
        "failure_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _receipt() -> dict[str, object]:
    runner = comparison._load_runner()
    first = _run()
    second = _run(nonce="9" * 64)
    projections = [runner._consensus_projection(first), runner._consensus_projection(second)]
    return {
        "schema": runner.SCHEMA,
        "tool_provenance": {"runner_sha256": "3" * 64, "source_verifier_sha256": "4" * 64, "base_image": runner.BASE_IMAGE, "raw_returned": False},
        "source": {"repository_id": runner.REPOSITORY_ID, "commit": runner.SOURCE_COMMIT, "commit_tree": runner.SOURCE_TREE, "source_tree_sha256": runner.SOURCE_TREE_SHA256, "source_receipt_sha256": "5" * 64, "file_count": 1211, "total_bytes": 21101002, "raw_returned": False},
        "image": {"base_image": runner.BASE_IMAGE, "build_command_sha256": "6" * 64, "build_contract_sha256": "7" * 64, "build_output_sha256": "8" * 64, "dockerfile_sha256": "9" * 64, "image_id": "sha256:" + "b" * 64, "image_id_sha256": "a" * 64, "online_build_non_evidence": True, "source_derived": True, "raw_returned": False},
        "runs": [first, second],
        "consensus": {"run_count": 2, "two_runs_byte_equivalent_after_normalization": True, "projection_sha256": runner._canonical_sha256(projections), "raw_returned": False},
        "image_cleanup": {"passed": True, "raw_returned": False},
        "claim_boundary": runner._claim_boundary(),
        "admission_blockers": list(runner.ADMISSION_BLOCKERS),
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _write(path: Path, receipt: dict[str, object]) -> None:
    path.write_bytes(comparison.canonical_json_bytes(receipt))


def test_compares_fresh_receipts_while_ignoring_volatile_execution_values(tmp_path: Path) -> None:
    first = _receipt()
    second = copy.deepcopy(first)
    for index, run in enumerate(second["runs"]):
        run["run_nonce_sha256"] = str(index + 6) * 64
        run["image_id"] = "sha256:" + "a" * 64
        run["execution"]["stdout_sha256"] = str(index + 7) * 64
        run["report_hashes"]["summary_sha256"] = str(index + 8) * 64
    second["image"]["image_id"] = "sha256:" + "a" * 64
    second["image"]["image_id_sha256"] = "b" * 64
    second["image"]["build_output_sha256"] = "c" * 64
    second["image"]["build_command_sha256"] = "d" * 64
    runner = comparison._load_runner()
    second["consensus"]["projection_sha256"] = runner._canonical_sha256(
        [runner._consensus_projection(run) for run in second["runs"]]
    )
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    _write(first_path, first)
    _write(second_path, second)

    result = comparison.compare_receipts(first_path, second_path)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["first_receipt_sha256"] != result["second_receipt_sha256"]
    assert result["authority"]["may_affect_h100_or_release"] is False


def test_holds_when_source_contract_changes(tmp_path: Path) -> None:
    first = _receipt()
    second = copy.deepcopy(first)
    second["source"]["source_tree_sha256"] = "d" * 64
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    _write(first_path, first)
    _write(second_path, second)

    result = comparison.compare_receipts(first_path, second_path)

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False


def test_holds_when_stable_build_contract_changes(tmp_path: Path) -> None:
    first = _receipt()
    second = copy.deepcopy(first)
    second["image"]["build_contract_sha256"] = "d" * 64
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    _write(first_path, first)
    _write(second_path, second)

    result = comparison.compare_receipts(first_path, second_path)

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False


def test_rejects_holding_or_noncanonical_receipts(tmp_path: Path) -> None:
    holding = _receipt()
    holding["execution_contract_status"] = "HOLD"
    holding["failure_code"] = "simulated_failure"
    valid = _receipt()
    holding_path = tmp_path / "holding.json"
    valid_path = tmp_path / "valid.json"
    _write(holding_path, holding)
    _write(valid_path, valid)

    with pytest.raises(ValueError, match="not_passed"):
        comparison.compare_receipts(holding_path, valid_path)

    malformed = tmp_path / "malformed.json"
    malformed.write_text('{"not": "canonical"}', encoding="utf-8")
    with pytest.raises(ValueError, match="not_canonical"):
        comparison.compare_receipts(malformed, valid_path)


def test_refuses_to_overwrite_comparison_evidence(tmp_path: Path) -> None:
    output = tmp_path / "comparison.json"
    output.write_text("existing", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing_to_overwrite"):
        comparison.write_comparison(output, {"schema": comparison.SCHEMA})
