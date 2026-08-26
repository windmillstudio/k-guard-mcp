from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_juice_shop_bola.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_juice_shop_bola", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
bola = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bola
SPEC.loader.exec_module(bola)


def _source() -> dict:
    return {
        "repository_id": bola.REPOSITORY_ID,
        "commit": bola.SOURCE_COMMIT,
        "commit_tree": bola.SOURCE_TREE,
        "source_tree_sha256": bola.SOURCE_TREE_SHA256,
        "p23a_registry_sha256": "1" * 64,
        "p23a_app_receipt_sha256": bola.P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": bola.P23A_APP_SEMANTIC_SHA256,
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
        "source_image_id": bola.SOURCE_IMAGE_ID,
        "adapter_image_id": bola.ADAPTER_IMAGE_ID,
        "raw_returned": False,
    }


def _run(variant: str) -> dict:
    expected_status = 200 if variant == "positive" else 403
    return {
        "run_nonce_sha256": "6" * 64,
        "image_id": "sha256:" + "7" * 64,
        "driver_sha256": "5" * 64,
        "network_policy": "none",
        "expected_status": expected_status,
        "mode": variant,
        "isolation": {"checks": {"network_none": True}, "passed": True, "raw_returned": False},
        "execution": {"returncode": 0, "raw_returned": False},
        "normalized_result": {
            "schema": bola.DRIVER_RESULT_SCHEMA,
            "mode": variant,
            "expected_status": expected_status,
            "observed_status": expected_status,
            "expected_basket_id_observed": expected_status == 200,
            "authorization_denied": expected_status == 403,
            "passed": True,
            "raw_returned": False,
        },
        "cleanup": {"passed": True, "raw_returned": False},
        "failure_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _positive_receipt(status: str = "EXECUTION_CONTRACT_PASS") -> dict:
    first = _run("positive")
    second = copy.deepcopy(first)
    second["run_nonce_sha256"] = "8" * 64
    return {
        "schema": bola.SCHEMA,
        "tool_provenance": _tool(),
        "source": _source(),
        "base_images": {"raw_returned": False},
        "image": {"raw_returned": False},
        "runs": [first, second],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": "9" * 64,
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True, "raw_returned": False},
        "claim_boundary": bola._claim_boundary(negative=False),
        "admission_blockers": list(bola.ADMISSION_BLOCKERS),
        "execution_contract_status": status,
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _negative_receipt(status: str = "NEGATIVE_CONTROL_PASS") -> dict:
    first = _run("negative")
    second = copy.deepcopy(first)
    second["run_nonce_sha256"] = "8" * 64
    return {
        "schema": bola.NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": _tool(),
        "source": _source(),
        "base_images": {"raw_returned": False},
        "image": {"raw_returned": False},
        "runs": [first, second],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": "9" * 64,
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True, "raw_returned": False},
        "positive_execution_contract": {
            "receipt_sha256": "a" * 64,
            "source_receipt_sha256": "2" * 64,
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            "raw_returned": False,
        },
        "negative_control": {
            "patch_id": bola.NEGATIVE_CONTROL_PATCH_ID,
            "source_path": bola.ROUTE_PATH,
            "original_file_sha256": "b" * 64,
            "patched_file_sha256": "c" * 64,
            "patch_sha256": "d" * 64,
            "marker_count": 1,
            "replacement_count": 1,
            "source_checkout_mutated": False,
            "raw_returned": False,
        },
        "claim_boundary": bola._claim_boundary(negative=True),
        "admission_blockers": list(bola.NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": status,
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _p23a_registry() -> dict:
    app = {
        "app_id": bola.APP_ID,
        "repository_id": bola.REPOSITORY_ID,
        "commit": bola.SOURCE_COMMIT,
        "commit_tree": bola.SOURCE_TREE,
        "source_tree_sha256": bola.SOURCE_TREE_SHA256,
        "receipt_sha256": bola.P23A_APP_RECEIPT_SHA256,
        "receipt_semantic_sha256": bola.P23A_APP_SEMANTIC_SHA256,
        "source_license_admission": "PASS",
        "scanner_output_observed": False,
        "oracle_gate_status": "HOLD",
        "oracle_missing": True,
    }
    return {
        "schema": "k_guard_l2_source_materialization.v3",
        "seed_sha256": "95f48fd53d3d411be9dbaa7b78a130a893d1fbf87bbc92f7ce40f1d6dbaf2fef",
        "expected_app_count": 6,
        "materialized_app_count": 6,
        "source_license_admission": "PASS",
        "apps": [app],
        "raw_returned": False,
    }


def test_negative_patch_is_single_anchor_and_does_not_mutate_input() -> None:
    route = (
        b"function retrieveBasket() {\n"
        b"            const basket = await basket_1.BasketModel.findOne({ where: { id } });\n"
        b"            /* jshint eqeqeq:false */\n"
        b"            res.json(basket);\n"
        b"}\n"
    )

    patched, control = bola._negative_route_patch(route)

    assert route != patched
    assert route.count(b"authenticatedUser") == 0
    assert patched.count(b"return res.status(403).json({ error: 'Forbidden' });") == 1
    assert control["marker_count"] == 1
    assert control["replacement_count"] == 1
    assert control["source_checkout_mutated"] is False


def test_runtime_seed_contract_restores_every_tmpfs_masked_static_directory() -> None:
    for relative in bola.RUNTIME_SEED_PATHS:
        assert f'"{relative}"' in bola.SEED_SCRIPT
        assert f'"{relative}"' in bola.DRIVER_SCRIPT
    assert "USER 0" in bola._dockerfile_template()
    assert 'RUN ["/nodejs/bin/node", "/opt/kguard/seed.js"]' in bola._dockerfile_template()


@pytest.mark.parametrize(
    "route",
    [b"no marker\n", b"/* jshint eqeqeq:false */\n/* jshint eqeqeq:false */\n"],
)
def test_negative_patch_rejects_missing_or_ambiguous_anchor(route: bytes) -> None:
    with pytest.raises(bola.RuntimeContractError, match="negative_control_patch_anchor_invalid"):
        bola._negative_route_patch(route)


def test_driver_parser_accepts_only_complete_expected_result() -> None:
    raw = (
        b"application startup noise\n"
        + bola.RESULT_MARKER.encode("ascii")
        + json.dumps(
            {
                "schema": bola.DRIVER_RESULT_SCHEMA,
                "mode": "positive",
                "expected_status": 200,
                "observed_status": 200,
                "expected_basket_id_observed": True,
                "authorization_denied": False,
                "driver_error_code": None,
                "passed": True,
                "raw_returned": False,
            }
        ).encode("utf-8")
        + b"\n"
    )

    assert bola._parse_driver_result(raw, expected_status=200, mode="positive") == {
        "schema": bola.DRIVER_RESULT_SCHEMA,
        "mode": "positive",
        "expected_status": 200,
        "observed_status": 200,
        "expected_basket_id_observed": True,
        "authorization_denied": False,
        "passed": True,
        "raw_returned": False,
    }


def test_driver_parser_rejects_extra_marker_or_invalid_outcome() -> None:
    one = bola.RESULT_MARKER + "{}\n"
    with pytest.raises(bola.RuntimeContractError, match="driver_result_marker_invalid"):
        bola._parse_driver_result((one + one).encode("utf-8"), expected_status=200, mode="positive")

    invalid = {
        "schema": bola.DRIVER_RESULT_SCHEMA,
        "mode": "negative",
        "expected_status": 403,
        "observed_status": 200,
        "expected_basket_id_observed": True,
        "authorization_denied": False,
        "driver_error_code": None,
        "passed": True,
        "raw_returned": False,
    }
    with pytest.raises(bola.RuntimeContractError, match="driver_result_outcome_invalid"):
        bola._parse_driver_result((bola.RESULT_MARKER + json.dumps(invalid)).encode("utf-8"), expected_status=403, mode="negative")


def test_p23a_registry_requires_the_frozen_juice_shop_binding(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_bytes(bola.canonical_json_bytes(_p23a_registry()))

    app, registry_sha256 = bola._load_p23a_registry(path)

    assert app["receipt_sha256"] == bola.P23A_APP_RECEIPT_SHA256
    assert len(registry_sha256) == 64

    invalid = _p23a_registry()
    invalid["apps"][0]["receipt_sha256"] = "f" * 64
    path.write_bytes(bola.canonical_json_bytes(invalid))
    with pytest.raises(bola.RuntimeContractError, match="p23a_registry_juice_shop_binding_invalid"):
        bola._load_p23a_registry(path)


def test_positive_and_negative_receipts_enforce_narrow_claim_boundaries() -> None:
    positive = _positive_receipt()
    bola.validate_receipt(positive)
    negative = _negative_receipt()
    bola.validate_negative_control_receipt(negative)

    promoted = copy.deepcopy(positive)
    promoted["claim_boundary"]["tp_fp_fn_admitted"] = True
    with pytest.raises(bola.RuntimeContractError, match="receipt_claim_boundary_invalid"):
        bola.validate_receipt(promoted)

    invalid_patch = copy.deepcopy(negative)
    invalid_patch["negative_control"]["patched_file_sha256"] = invalid_patch["negative_control"]["original_file_sha256"]
    with pytest.raises(bola.RuntimeContractError, match="negative_control_patch_unchanged"):
        bola.validate_negative_control_receipt(invalid_patch)


def test_receipt_rejects_missing_second_run_and_raw_boundary_promotion() -> None:
    receipt = _positive_receipt()
    receipt["runs"] = receipt["runs"][:1]
    with pytest.raises(bola.RuntimeContractError, match="receipt_pass_incomplete"):
        bola.validate_receipt(receipt)

    receipt = _negative_receipt()
    receipt["runs"][0]["execution"]["raw_returned"] = True
    with pytest.raises(bola.RuntimeContractError, match="raw_boundary_invalid"):
        bola.validate_negative_control_receipt(receipt)


def test_isolation_requires_all_hardened_runtime_constraints() -> None:
    host = {
        "NetworkMode": "none",
        "PortBindings": {},
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "CapAdd": None,
        "SecurityOpt": ["no-new-privileges=true"],
        "PidsLimit": bola.PIDS_LIMIT,
        "Memory": bola.MEMORY_BYTES,
        "NanoCpus": bola.NANO_CPUS,
        "Privileged": False,
        "Binds": None,
        "Tmpfs": {path: bola.TMPFS_OPTIONS for path in bola.TMPFS_PATHS},
    }
    container = {
        "Image": "sha256:" + "7" * 64,
        "HostConfig": host,
        "Config": {
            "User": bola.RUN_AS,
            "Labels": {"io.k-guard.execution-contract": bola.EXECUTION_CONTRACT_LABEL},
            "Env": ["KGUARD_EXPECTED_STATUS=200", "KGUARD_MODE=positive"],
        },
        "NetworkSettings": {"Ports": {}},
        "Mounts": [],
    }

    result = bola._container_isolation(
        container,
        image_id=container["Image"],
        contract_label=bola.EXECUTION_CONTRACT_LABEL,
        expected_status=200,
        mode="positive",
    )

    assert result["passed"] is True
    container["HostConfig"]["NetworkMode"] = "default"
    assert bola._container_isolation(
        container,
        image_id=container["Image"],
        contract_label=bola.EXECUTION_CONTRACT_LABEL,
        expected_status=200,
        mode="positive",
    )["passed"] is False
