from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


RUNNER_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_crapi_vehicle_bola.py"
COMPARATOR_PATH = Path(__file__).parents[1] / "scripts" / "compare_l2_crapi_vehicle_bola_repeats.py"

RUNNER_SPEC = importlib.util.spec_from_file_location("k_guard_l2_crapi_vehicle_bola_runner_for_compare", RUNNER_PATH)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
runner = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = runner
RUNNER_SPEC.loader.exec_module(runner)

COMPARATOR_SPEC = importlib.util.spec_from_file_location("k_guard_l2_crapi_vehicle_bola_comparator", COMPARATOR_PATH)
assert COMPARATOR_SPEC is not None and COMPARATOR_SPEC.loader is not None
comparator = importlib.util.module_from_spec(COMPARATOR_SPEC)
sys.modules[COMPARATOR_SPEC.name] = comparator
COMPARATOR_SPEC.loader.exec_module(comparator)


def _sha(character: str) -> str:
    return character * 64


def _source() -> dict[str, object]:
    return {
        "repository_id": runner.REPOSITORY_ID,
        "commit": runner.SOURCE_COMMIT,
        "commit_tree": runner.SOURCE_TREE,
        "source_tree_sha256": runner.SOURCE_TREE_SHA256,
        "p23a_registry_sha256": _sha("1"),
        "p23a_app_receipt_sha256": runner.P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": runner.P23A_APP_SEMANTIC_SHA256,
        "current_source_receipt_sha256": _sha("2"),
        "current_source_receipt_semantic_sha256": _sha("3"),
        "file_count": 1,
        "total_bytes": 1,
        "source_file_sha256": dict(runner.SOURCE_FILES),
        "raw_returned": False,
    }


def _base_image() -> dict[str, object]:
    return {
        "source_image_ref": runner.SOURCE_IMAGE_REF,
        "source_image_id": runner.SOURCE_IMAGE_ID,
        "source_image_labels": dict(runner.EXPECTED_SOURCE_IMAGE_LABELS),
        "source_dockerfile_sha256": runner.SOURCE_DOCKERFILE_SHA256,
        "source_image_current_source_provenance_only": True,
        "fresh_dependency_rebuild_proven": False,
        "runtime_supply_chain_proven": False,
        "raw_returned": False,
    }


def _driver_image(dynamic: str) -> dict[str, object]:
    return {
        "driver_image_ref": f"kguard-driver:{dynamic}",
        "driver_image_id": "sha256:" + _sha(dynamic),
        "driver_sha256": runner.sha256_bytes(runner.DRIVER_SCRIPT.encode("utf-8")),
        "dockerfile_sha256": _sha("4"),
        "driver_base_image": {
            "reference": runner.PYTHON_DRIVER_IMAGE_REF,
            "image_id": "sha256:" + _sha("5"),
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _run(*, negative: bool, log_hash: str, app_contract: str) -> dict[str, object]:
    mode = "negative" if negative else "positive"
    expected_status = 403 if negative else 200
    normalized = {
        "mode": mode,
        "expected_status": expected_status,
        "observed_status": expected_status,
        "passed": True,
        "raw_returned": False,
    }
    return {
        "mode": mode,
        "expected_status": expected_status,
        "driver_sha256": runner.sha256_bytes(runner.DRIVER_SCRIPT.encode("utf-8")),
        "network_policy": runner.NETWORK_POLICY,
        "postgres_image": {
            "reference": runner.POSTGRES_IMAGE_REF,
            "image_id": "sha256:" + _sha("6"),
            "raw_returned": False,
        },
        "app_image_id": runner.SOURCE_IMAGE_ID if not negative else "sha256:" + _sha("7"),
        "app_image_contract_sha256": app_contract,
        "network": {"internal": True, "driver": True, "raw_returned": False},
        "isolation": {
            "postgres": {"passed": True},
            "application": {"passed": True},
            "driver": {"passed": True},
            "all_passed": True,
            "raw_returned": False,
        },
        "postgres_ready": {"ready": True, "raw_returned": False},
        "application_ready": {"ready": True, "raw_returned": False},
        "application_logs_sha256": log_hash,
        "normalized_result": normalized,
        "passed": True,
        "cleanup": {
            "driver": {"removed": True},
            "application": {"removed": True},
            "postgres": {"removed": True},
            "network": {"removed": True},
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _tool() -> dict[str, object]:
    return {
        "runner_sha256": _sha("8"),
        "source_verifier_provenance": _sha("9") + ":" + _sha("a"),
        "driver_sha256": runner.sha256_bytes(runner.DRIVER_SCRIPT.encode("utf-8")),
        "driver_image_id": "sha256:" + _sha("b"),
        "postgres_image_id": "sha256:" + _sha("c"),
        "raw_returned": False,
    }


def _image_contract(*, negative: bool) -> dict[str, object]:
    return {
        "app_image_ref": "kguard-app:dynamic",
        "app_image_id": runner.SOURCE_IMAGE_ID if not negative else "sha256:" + _sha("d"),
        "app_image_contract_sha256": _sha("e"),
        "contract_label": runner.NEGATIVE_CONTROL_LABEL if negative else runner.EXECUTION_CONTRACT_LABEL,
        "source_derived": True,
        "build_network": "default" if negative else "prior_source_build",
        "fresh_dependency_rebuild_proven": False,
        "raw_returned": False,
    }


def _positive_receipt(*, log_hash: str, dynamic: str) -> dict[str, object]:
    return {
        "schema": runner.SCHEMA,
        "source": _source(),
        "base_image": _base_image(),
        "driver_image": _driver_image(dynamic),
        "image_contract": _image_contract(negative=False),
        "runs": [
            _run(negative=False, log_hash=log_hash, app_contract=_sha("e")),
            _run(negative=False, log_hash=log_hash, app_contract=_sha("e")),
        ],
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "admission_blockers": list(runner.ADMISSION_BLOCKERS),
        "claim_boundary": runner._claim_boundary(negative=False),
        "tool_provenance": _tool(),
        "release_gate_passed": False,
        "raw_returned": False,
    }


def _negative_receipt(*, positive_sha256: str, log_hash: str, dynamic: str) -> dict[str, object]:
    control = {
        "patch_id": runner.NEGATIVE_CONTROL_PATCH_ID,
        "source_path": runner.CONTROLLER_PATH,
        "original_file_sha256": runner.SOURCE_FILES[runner.CONTROLLER_PATH],
        "patched_file_sha256": _sha("f"),
        "patch_sha256": _sha("0"),
        "marker_count": 1,
        "replacement_count": 1,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }
    return {
        "schema": runner.NEGATIVE_CONTROL_SCHEMA,
        "source": _source(),
        "base_image": _base_image(),
        "driver_image": _driver_image(dynamic),
        "image_contract": _image_contract(negative=True),
        "negative_control": control,
        "positive_execution_receipt_sha256": positive_sha256,
        "runs": [
            _run(negative=True, log_hash=log_hash, app_contract=_sha("e")),
            _run(negative=True, log_hash=log_hash, app_contract=_sha("e")),
        ],
        "negative_control_status": "NEGATIVE_CONTROL_PASS",
        "admission_blockers": list(runner.ADMISSION_BLOCKERS),
        "claim_boundary": runner._claim_boundary(negative=True),
        "tool_provenance": _tool(),
        "release_gate_passed": False,
        "raw_returned": False,
    }


def _write(path: Path, value: dict[str, object]) -> str:
    raw = comparator.canonical_json_bytes(value)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_positive_comparator_ignores_dynamic_log_and_image_identity(tmp_path: Path) -> None:
    first = _positive_receipt(log_hash=_sha("1"), dynamic="a")
    second = _positive_receipt(log_hash=_sha("2"), dynamic="b")
    runner.validate_receipt(first)
    runner.validate_receipt(second)

    first_path = tmp_path / "positive-a.json"
    second_path = tmp_path / "positive-b.json"
    _write(first_path, first)
    _write(second_path, second)
    comparison = comparator.compare_positive_receipts(first_path, second_path)

    assert comparison["status"] == "FIX"
    assert comparison["repeat_exact"] is True
    assert comparison["authority"]["may_affect_performance_metrics"] is False


def test_positive_comparator_holds_on_semantic_network_change(tmp_path: Path) -> None:
    first = _positive_receipt(log_hash=_sha("1"), dynamic="a")
    second = copy.deepcopy(_positive_receipt(log_hash=_sha("2"), dynamic="b"))
    second["runs"][0]["network"]["runtime_generation"] = "different"
    second["runs"][1]["network"]["runtime_generation"] = "different"

    first_path = tmp_path / "positive-a.json"
    second_path = tmp_path / "positive-b.json"
    _write(first_path, first)
    _write(second_path, second)
    comparison = comparator.compare_positive_receipts(first_path, second_path)

    assert comparison["status"] == "HOLD"
    assert comparison["repeat_exact"] is False


def test_negative_comparator_requires_the_positive_pair_anchor(tmp_path: Path) -> None:
    positive_a = _positive_receipt(log_hash=_sha("1"), dynamic="a")
    positive_b = _positive_receipt(log_hash=_sha("2"), dynamic="b")
    positive_a_path = tmp_path / "positive-a.json"
    positive_b_path = tmp_path / "positive-b.json"
    positive_a_sha = _write(positive_a_path, positive_a)
    positive_b_sha = _write(positive_b_path, positive_b)
    positive_comparison = comparator.compare_positive_receipts(positive_a_path, positive_b_path)
    positive_comparison_path = tmp_path / "positive-comparison.json"
    _write(positive_comparison_path, positive_comparison)

    negative_a = _negative_receipt(
        positive_sha256=positive_a_sha, log_hash=_sha("3"), dynamic="c"
    )
    negative_b = _negative_receipt(
        positive_sha256=positive_b_sha, log_hash=_sha("4"), dynamic="d"
    )
    runner.validate_negative_control_receipt(negative_a)
    runner.validate_negative_control_receipt(negative_b)
    negative_a_path = tmp_path / "negative-a.json"
    negative_b_path = tmp_path / "negative-b.json"
    _write(negative_a_path, negative_a)
    _write(negative_b_path, negative_b)

    comparison = comparator.compare_negative_receipts(
        negative_a_path, negative_b_path, positive_comparison_path
    )
    assert comparison["status"] == "FIX"
    assert comparison["positive_execution_pair"]["first_receipt_sha256"] == positive_a_sha

    negative_b["positive_execution_receipt_sha256"] = _sha("9")
    _write(negative_b_path, negative_b)
    try:
        comparator.compare_negative_receipts(negative_a_path, negative_b_path, positive_comparison_path)
    except ValueError as error:
        assert str(error) == "positive_comparison_anchor_mismatch"
    else:
        raise AssertionError("invalid positive anchor must be rejected")
