from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest


RUNNER_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_juice_shop_bola.py"
RUNNER_SPEC = importlib.util.spec_from_file_location("k_guard_l2_juice_shop_bola_compare_runner", RUNNER_PATH)
assert RUNNER_SPEC is not None and RUNNER_SPEC.loader is not None
runner = importlib.util.module_from_spec(RUNNER_SPEC)
sys.modules[RUNNER_SPEC.name] = runner
RUNNER_SPEC.loader.exec_module(runner)

MODULE_PATH = Path(__file__).parents[1] / "scripts" / "compare_l2_juice_shop_bola_repeats.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_juice_shop_bola_repeat_compare", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
compare = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = compare
SPEC.loader.exec_module(compare)


def _source() -> dict:
    return {
        "repository_id": runner.REPOSITORY_ID,
        "commit": runner.SOURCE_COMMIT,
        "commit_tree": runner.SOURCE_TREE,
        "source_tree_sha256": runner.SOURCE_TREE_SHA256,
        "p23a_registry_sha256": "1" * 64,
        "p23a_app_receipt_sha256": runner.P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": runner.P23A_APP_SEMANTIC_SHA256,
        "current_source_receipt_sha256": "2" * 64,
        "file_count": 1274,
        "total_bytes": 28394647,
        "raw_returned": False,
    }


def _tool() -> dict:
    return {
        "runner_sha256": "3" * 64,
        "source_verifier_sha256": "4" * 64,
        "driver_sha256": "5" * 64,
        "seed_sha256": "6" * 64,
        "source_image_id": runner.SOURCE_IMAGE_ID,
        "adapter_image_id": runner.ADAPTER_IMAGE_ID,
        "raw_returned": False,
    }


def _base_images() -> dict:
    return {
        "source_image_id": runner.SOURCE_IMAGE_ID,
        "adapter_image_id": runner.ADAPTER_IMAGE_ID,
        "adapter_image_ref": runner.ADAPTER_IMAGE_REF,
        "source_image_rootfs_layers_sha256": "7" * 64,
        "adapter_image_rootfs_layers_sha256": "8" * 64,
        "adapter_digest": f"kguard-l2/juice-shop-adapter@{runner.ADAPTER_IMAGE_ID}",
        "source_dockerfile_sha256": "9" * 64,
        "source_image_current_source_provenance_only": True,
        "fresh_dependency_rebuild_proven": False,
        "raw_returned": False,
    }


def _image(variant: str) -> dict:
    route = {
        "source_path": runner.ROUTE_PATH,
        "original_file_sha256": "a" * 64,
        "source_checkout_mutated": False,
        "extraction_container_network": "none",
        "raw_returned": False,
    }
    if variant == "negative":
        route.update(
            {
                "patch_id": runner.NEGATIVE_CONTROL_PATCH_ID,
                "patched_file_sha256": "b" * 64,
                "patch_sha256": "c" * 64,
                "marker_count": 1,
                "replacement_count": 1,
            }
        )
    return {
        "image_id": "sha256:" + "d" * 64,
        "image_id_sha256": "e" * 64,
        "base_adapter_image_id": runner.ADAPTER_IMAGE_ID,
        "contract_label": runner.EXECUTION_CONTRACT_LABEL if variant == "positive" else runner.NEGATIVE_CONTROL_LABEL,
        "dockerfile_sha256": "f" * 64,
        "driver_sha256": "5" * 64,
        "seed_sha256": "6" * 64,
        "build_contract_sha256": "0" * 64,
        "rootfs_lineage_sha256": "1" * 64,
        "route": route,
        "source_derived": True,
        "build_network": "none",
        "fresh_dependency_rebuild_proven": False,
        "raw_returned": False,
    }


def _run(variant: str, nonce: str) -> dict:
    status = 200 if variant == "positive" else 403
    return {
        "run_nonce_sha256": nonce * 64,
        "image_id": "sha256:" + "d" * 64,
        "driver_sha256": "5" * 64,
        "network_policy": "none",
        "expected_status": status,
        "mode": variant,
        "isolation": {"checks": {"network_none": True}, "passed": True, "raw_returned": False},
        "execution": {"returncode": 0, "raw_returned": False},
        "normalized_result": {"passed": True, "raw_returned": False},
        "cleanup": {"passed": True, "raw_returned": False},
        "failure_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _positive_receipt(nonce: str = "1") -> dict:
    return {
        "schema": runner.SCHEMA,
        "tool_provenance": _tool(),
        "source": _source(),
        "base_images": _base_images(),
        "image": _image("positive"),
        "runs": [_run("positive", nonce), _run("positive", "2" if nonce == "1" else "3")],
        "consensus": {"run_count": 2, "two_runs_byte_equivalent_after_normalization": True, "projection_sha256": "2" * 64, "raw_returned": False},
        "image_cleanup": {"passed": True, "raw_returned": False},
        "claim_boundary": runner._claim_boundary(negative=False),
        "admission_blockers": list(runner.ADMISSION_BLOCKERS),
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _negative_receipt(positive_sha256: str, nonce: str = "1") -> dict:
    control = _image("negative")["route"]
    return {
        "schema": runner.NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": _tool(),
        "source": _source(),
        "base_images": _base_images(),
        "image": _image("negative"),
        "runs": [_run("negative", nonce), _run("negative", "2" if nonce == "1" else "3")],
        "consensus": {"run_count": 2, "two_runs_byte_equivalent_after_normalization": True, "projection_sha256": "2" * 64, "raw_returned": False},
        "image_cleanup": {"passed": True, "raw_returned": False},
        "positive_execution_contract": {
            "receipt_sha256": positive_sha256,
            "source_receipt_sha256": "2" * 64,
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            "raw_returned": False,
        },
        "negative_control": {
            "patch_id": control["patch_id"],
            "source_path": control["source_path"],
            "original_file_sha256": control["original_file_sha256"],
            "patched_file_sha256": control["patched_file_sha256"],
            "patch_sha256": control["patch_sha256"],
            "marker_count": 1,
            "replacement_count": 1,
            "source_checkout_mutated": False,
            "raw_returned": False,
        },
        "claim_boundary": runner._claim_boundary(negative=True),
        "admission_blockers": list(runner.NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": "NEGATIVE_CONTROL_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _write(path: Path, payload: dict) -> str:
    raw = compare.canonical_json_bytes(payload)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_positive_comparator_ignores_nonce_but_binds_all_semantic_fields(tmp_path: Path) -> None:
    first = tmp_path / "positive-1.json"
    second = tmp_path / "positive-2.json"
    _write(first, _positive_receipt("1"))
    _write(second, _positive_receipt("9"))

    comparison = compare.compare_positive_receipts(first, second)

    assert comparison["status"] == "FIX"
    assert comparison["repeat_exact"] is True

    altered = _positive_receipt("9")
    altered["image"]["dockerfile_sha256"] = "a" * 64
    _write(second, altered)
    assert compare.compare_positive_receipts(first, second)["status"] == "HOLD"


def test_negative_comparator_binds_the_two_positive_receipt_anchors(tmp_path: Path) -> None:
    positive_one = tmp_path / "positive-1.json"
    positive_two = tmp_path / "positive-2.json"
    positive_one_sha = _write(positive_one, _positive_receipt("1"))
    positive_two_sha = _write(positive_two, _positive_receipt("9"))
    positive_comparison = compare.compare_positive_receipts(positive_one, positive_two)
    positive_comparison_path = tmp_path / "positive-comparison.json"
    _write(positive_comparison_path, positive_comparison)
    negative_one = tmp_path / "negative-1.json"
    negative_two = tmp_path / "negative-2.json"
    _write(negative_one, _negative_receipt(positive_one_sha, "1"))
    _write(negative_two, _negative_receipt(positive_two_sha, "9"))

    comparison = compare.compare_negative_receipts(negative_one, negative_two, positive_comparison_path)

    assert comparison["status"] == "FIX"
    assert comparison["positive_execution_pair"]["status"] == "FIX"

    broken = _negative_receipt("f" * 64, "9")
    _write(negative_two, broken)
    with pytest.raises(ValueError, match="positive_comparison_anchor_mismatch"):
        compare.compare_negative_receipts(negative_one, negative_two, positive_comparison_path)


def test_comparator_rejects_noncanonical_input_and_prevents_overwrite(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt.json"
    # A canonical empty object is exactly b"{}\n" on POSIX.  Use a missing
    # terminal newline so this fixture is non-canonical on every platform.
    receipt.write_bytes(b"{}")
    with pytest.raises(ValueError, match="execution_receipt_not_canonical"):
        compare.compare_positive_receipts(receipt, receipt)

    output = tmp_path / "comparison.json"
    output.write_text("already", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing_to_overwrite"):
        compare.write_comparison(output, {"raw_returned": False})
