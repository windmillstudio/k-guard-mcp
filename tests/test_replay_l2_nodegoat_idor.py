from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_nodegoat_idor.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_nodegoat_idor_replay", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
nodegoat = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = nodegoat
SPEC.loader.exec_module(nodegoat)


def _source() -> dict:
    return {
        "repository_id": nodegoat.REPOSITORY_ID,
        "commit": nodegoat.SOURCE_COMMIT,
        "commit_tree": nodegoat.SOURCE_TREE,
        "source_tree_sha256": nodegoat.SOURCE_TREE_SHA256,
        "p23a_registry_sha256": "1" * 64,
        "p23a_app_receipt_sha256": nodegoat.P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": nodegoat.P23A_APP_SEMANTIC_SHA256,
        "current_source_receipt_sha256": "2" * 64,
        "file_count": 111,
        "total_bytes": 2_976_004,
        "raw_returned": False,
    }


def _tool() -> dict:
    return {
        "runner_sha256": "3" * 64,
        "source_verifier_sha256": "4" * 64,
        "driver_sha256": "5" * 64,
        "seed_wrapper_sha256": "6" * 64,
        "source_image_id": nodegoat.SOURCE_IMAGE_ID,
        "mongo_image_id": nodegoat.MONGO_IMAGE_ID,
        "raw_returned": False,
    }


def _base() -> dict:
    return {
        "source_image_id": nodegoat.SOURCE_IMAGE_ID,
        "source_image_ref": nodegoat.SOURCE_IMAGE_REF,
        "source_image_rootfs_layers_sha256": "6" * 64,
        "source_image_commit_label": nodegoat.SOURCE_COMMIT,
        "mongo_image_id": nodegoat.MONGO_IMAGE_ID,
        "mongo_image_ref": nodegoat.MONGO_IMAGE_REF,
        "mongo_image_rootfs_layers_sha256": "7" * 64,
        "source_dockerfile_sha256": "8" * 64,
        "route_source_sha256": "9" * 64,
        "seed_source_sha256": "a" * 64,
        "source_image_current_source_provenance_only": True,
        "fresh_dependency_rebuild_proven": False,
        "mongo_runtime_supply_chain_proven": False,
        "raw_returned": False,
    }


def _image(variant: str) -> dict:
    route = {
        "source_path": nodegoat.ROUTE_PATH,
        "original_file_sha256": "b" * 64,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }
    if variant == "negative":
        route.update(
            {
                "patch_id": nodegoat.NEGATIVE_CONTROL_PATCH_ID,
                "patched_file_sha256": "c" * 64,
                "patch_sha256": "d" * 64,
                "marker_count": 1,
                "replacement_count": 1,
            }
        )
    return {
        "image_id": "sha256:" + "e" * 64,
        "image_id_sha256": "f" * 64,
        "base_source_image_id": nodegoat.SOURCE_IMAGE_ID,
        "contract_label": nodegoat.EXECUTION_CONTRACT_LABEL if variant == "positive" else nodegoat.NEGATIVE_CONTROL_LABEL,
        "dockerfile_sha256": "0" * 64,
        "driver_sha256": "5" * 64,
        "seed_wrapper_sha256": "6" * 64,
        "build_contract_sha256": "1" * 64,
        "rootfs_lineage_sha256": "2" * 64,
        "route": route,
        "source_derived": True,
        "build_network": "none",
        "fresh_dependency_rebuild_proven": False,
        "raw_returned": False,
    }


def _run(variant: str, nonce: str) -> dict:
    foreign = variant == "positive"
    own = variant == "negative"
    return {
        "run_nonce_sha256": nonce * 64,
        "image_id": "sha256:" + "e" * 64,
        "driver_sha256": "5" * 64,
        "network_policy": nodegoat.NETWORK_POLICY,
        "expected_status": 200,
        "mode": variant,
        "isolation": {"passed": True, "raw_returned": False},
        "seed_execution": {
            "normalized_result": {
                "schema": nodegoat.SEED_RESULT_SCHEMA,
                "attempts": 1,
                "max_attempts": 3,
                "passed": True,
                "raw_returned": False,
            },
            "passed": True,
            "raw_returned": False,
        },
        "application_start": {"returncode": 0, "raw_returned": False},
        "execution": {"returncode": 0, "raw_returned": False},
        "normalized_result": {
            "schema": nodegoat.DRIVER_RESULT_SCHEMA,
            "mode": variant,
            "expected_status": 200,
            "observed_status": 200,
            "foreign_allocation_observed": foreign,
            "own_allocation_observed": own,
            "passed": True,
            "raw_returned": False,
        },
        "cleanup": {"passed": True, "raw_returned": False},
        "failure_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _positive_receipt() -> dict:
    return {
        "schema": nodegoat.SCHEMA,
        "tool_provenance": _tool(),
        "source": _source(),
        "base_images": _base(),
        "image": _image("positive"),
        "runs": [_run("positive", "1"), _run("positive", "2")],
        "consensus": {"run_count": 2, "two_runs_byte_equivalent_after_normalization": True, "projection_sha256": "3" * 64, "raw_returned": False},
        "image_cleanup": {"passed": True, "raw_returned": False},
        "claim_boundary": nodegoat._claim_boundary(negative=False),
        "admission_blockers": list(nodegoat.ADMISSION_BLOCKERS),
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _negative_receipt() -> dict:
    positive = _positive_receipt()
    return {
        "schema": nodegoat.NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": _tool(),
        "source": _source(),
        "base_images": _base(),
        "image": _image("negative"),
        "runs": [_run("negative", "1"), _run("negative", "2")],
        "consensus": {"run_count": 2, "two_runs_byte_equivalent_after_normalization": True, "projection_sha256": "4" * 64, "raw_returned": False},
        "image_cleanup": {"passed": True, "raw_returned": False},
        "positive_execution_contract": {
            "receipt_sha256": "5" * 64,
            "source_receipt_sha256": positive["source"]["current_source_receipt_sha256"],
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            "raw_returned": False,
        },
        "negative_control": _image("negative")["route"],
        "claim_boundary": nodegoat._claim_boundary(negative=True),
        "admission_blockers": list(nodegoat.NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": "NEGATIVE_CONTROL_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _registry() -> dict:
    return {
        "schema": "k_guard_l2_source_materialization.v3",
        "seed_sha256": "95f48fd53d3d411be9dbaa7b78a130a893d1fbf87bbc92f7ce40f1d6dbaf2fef",
        "expected_app_count": 6,
        "materialized_app_count": 6,
        "source_license_admission": "PASS",
        "apps": [
            {
                "app_id": nodegoat.APP_ID,
                "repository_id": nodegoat.REPOSITORY_ID,
                "commit": nodegoat.SOURCE_COMMIT,
                "commit_tree": nodegoat.SOURCE_TREE,
                "source_tree_sha256": nodegoat.SOURCE_TREE_SHA256,
                "receipt_sha256": nodegoat.P23A_APP_RECEIPT_SHA256,
                "receipt_semantic_sha256": nodegoat.P23A_APP_SEMANTIC_SHA256,
                "source_license_admission": "PASS",
                "scanner_output_observed": False,
                "oracle_gate_status": "HOLD",
                "oracle_missing": True,
            }
        ],
        "raw_returned": False,
    }


def test_negative_patch_is_single_and_preserves_input() -> None:
    route = (
        b"        const {\n"
        b"            userId\n"
        b"        } = req.params;\n"
    )
    patched, control = nodegoat._negative_route_patch(route)

    assert route != patched
    assert b"req.params" in route
    assert b"req.session" in patched
    assert control["marker_count"] == 1
    assert control["replacement_count"] == 1
    assert control["source_checkout_mutated"] is False


@pytest.mark.parametrize(
    "route",
    [
        b"no user id marker\n",
        b"        const {\n            userId\n        } = req.params;\n" * 2,
        b"        const {\n            userId\n        } = req.session;\n",
    ],
)
def test_negative_patch_rejects_missing_or_ambiguous_marker(route: bytes) -> None:
    with pytest.raises(nodegoat.RuntimeContractError, match="negative_control_patch_anchor_invalid"):
        nodegoat._negative_route_patch(route)


def test_driver_parser_requires_the_mode_specific_outcome() -> None:
    result = {
        "schema": nodegoat.DRIVER_RESULT_SCHEMA,
        "mode": "positive",
        "expected_status": 200,
        "observed_status": 200,
        "foreign_allocation_observed": True,
        "own_allocation_observed": False,
        "driver_error_code": None,
        "passed": True,
        "raw_returned": False,
    }
    output = b"startup\n" + nodegoat.RESULT_MARKER.encode("ascii") + json.dumps(result).encode("utf-8") + b"\n"
    assert nodegoat._parse_driver_result(output, mode="positive")["passed"] is True

    result["foreign_allocation_observed"] = False
    output = nodegoat.RESULT_MARKER.encode("ascii") + json.dumps(result).encode("utf-8")
    with pytest.raises(nodegoat.RuntimeContractError, match="driver_result_outcome_invalid"):
        nodegoat._parse_driver_result(output, mode="positive")


def test_seed_parser_requires_bounded_success_marker() -> None:
    result = {
        "schema": nodegoat.SEED_RESULT_SCHEMA,
        "attempts": 2,
        "max_attempts": 3,
        "passed": True,
        "raw_returned": False,
    }
    output = nodegoat.SEED_RESULT_MARKER.encode("ascii") + json.dumps(result).encode("utf-8")
    assert nodegoat._parse_seed_result(output)["attempts"] == 2

    result["attempts"] = 4
    output = nodegoat.SEED_RESULT_MARKER.encode("ascii") + json.dumps(result).encode("utf-8")
    with pytest.raises(nodegoat.RuntimeContractError, match="seed_result_outcome_invalid"):
        nodegoat._parse_seed_result(output)


def test_seed_wrapper_stays_compatible_with_nodegoat_node_12_runtime() -> None:
    assert 'require("child_process")' in nodegoat.SEED_WRAPPER_SCRIPT
    assert 'require("node:child_process")' not in nodegoat.SEED_WRAPPER_SCRIPT


def test_p23a_registry_requires_frozen_nodegoat_binding(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_bytes(nodegoat.canonical_json_bytes(_registry()))
    app, receipt_sha256 = nodegoat._load_p23a_registry(path)
    assert app["app_id"] == nodegoat.APP_ID
    assert len(receipt_sha256) == 64

    invalid = _registry()
    invalid["apps"][0]["commit"] = "f" * 40
    path.write_bytes(nodegoat.canonical_json_bytes(invalid))
    with pytest.raises(nodegoat.RuntimeContractError, match="p23a_registry_nodegoat_binding_invalid"):
        nodegoat._load_p23a_registry(path)


def test_runtime_base_image_validator_is_not_shadowed_by_receipt_validator(tmp_path: Path) -> None:
    with pytest.raises(nodegoat.RuntimeContractError, match="source_file_missing"):
        nodegoat._validate_base_images(tmp_path, work_root=tmp_path)


def test_container_isolation_requires_internal_network_and_hardening() -> None:
    host = {
        "NetworkMode": "isolated-network",
        "PortBindings": {},
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "CapAdd": None,
        "SecurityOpt": ["no-new-privileges=true"],
        "PidsLimit": nodegoat.APP_PIDS_LIMIT,
        "Memory": nodegoat.APP_MEMORY_BYTES,
        "NanoCpus": nodegoat.NANO_CPUS,
        "Privileged": False,
        "Binds": None,
        "Tmpfs": dict(nodegoat.APP_TMPFS),
    }
    container = {
        "Image": nodegoat.SOURCE_IMAGE_ID,
        "HostConfig": host,
        "Config": {
            "User": nodegoat.APP_USER,
            "Labels": {
                "io.k-guard.app-id": nodegoat.APP_ID,
                "io.k-guard.execution-contract": nodegoat.EXECUTION_CONTRACT_LABEL,
                "io.k-guard.run-nonce": "nonce",
                "io.k-guard.role": "application",
            },
        },
        "NetworkSettings": {
            "Ports": {},
            "Networks": {"isolated-network": {"Aliases": ["nodegoat-app"]}},
        },
        "Mounts": [],
    }
    result = nodegoat._container_isolation(
        container,
        image_id=nodegoat.SOURCE_IMAGE_ID,
        network_name="isolated-network",
        alias="nodegoat-app",
        expected_user=nodegoat.APP_USER,
        expected_tmpfs=nodegoat.APP_TMPFS,
        memory_bytes=nodegoat.APP_MEMORY_BYTES,
        pids_limit=nodegoat.APP_PIDS_LIMIT,
        nonce="nonce",
        contract_label=nodegoat.EXECUTION_CONTRACT_LABEL,
        role="application",
    )
    assert result["passed"] is True

    container["HostConfig"]["NetworkMode"] = "default"
    assert nodegoat._container_isolation(
        container,
        image_id=nodegoat.SOURCE_IMAGE_ID,
        network_name="isolated-network",
        alias="nodegoat-app",
        expected_user=nodegoat.APP_USER,
        expected_tmpfs=nodegoat.APP_TMPFS,
        memory_bytes=nodegoat.APP_MEMORY_BYTES,
        pids_limit=nodegoat.APP_PIDS_LIMIT,
        nonce="nonce",
        contract_label=nodegoat.EXECUTION_CONTRACT_LABEL,
        role="application",
    )["passed"] is False


def test_consensus_projection_excludes_fresh_network_identity_only() -> None:
    base = {
        "driver_sha256": "a" * 64,
        "network_policy": nodegoat.NETWORK_POLICY,
        "expected_status": 200,
        "mode": "positive",
        "isolation": {
            "network": {"id_sha256": "1" * 64, "checks": {"internal": True}, "passed": True, "raw_returned": False},
            "database": {"checks": {"read_only_root": True}, "created_id_exact": True, "passed": True, "raw_returned": False},
            "seed": {"checks": {"read_only_root": True}, "created_id_exact": True, "passed": True, "raw_returned": False},
            "application": {"checks": {"read_only_root": True}, "created_id_exact": True, "passed": True, "raw_returned": False},
            "application_post_state": {"checks": {"running": True}, "passed": True, "raw_returned": False},
            "network_post_state": {"checks": {"only_database_and_application": True}, "passed": True, "raw_returned": False},
            "passed": True,
            "raw_returned": False,
        },
        "normalized_result": {"passed": True, "raw_returned": False},
        "passed": True,
    }
    other = copy.deepcopy(base)
    other["isolation"]["network"]["id_sha256"] = "2" * 64
    assert nodegoat._consensus_projection(base) == nodegoat._consensus_projection(other)

    other["isolation"]["network"]["checks"]["internal"] = False
    assert nodegoat._consensus_projection(base) != nodegoat._consensus_projection(other)


def test_pass_receipts_enforce_narrow_claim_boundaries() -> None:
    positive = _positive_receipt()
    nodegoat.validate_receipt(positive)
    negative = _negative_receipt()
    nodegoat.validate_negative_control_receipt(negative)

    promoted = copy.deepcopy(positive)
    promoted["claim_boundary"]["tp_fp_fn_admitted"] = True
    with pytest.raises(nodegoat.RuntimeContractError, match="receipt_claim_boundary_invalid"):
        nodegoat.validate_receipt(promoted)

    changed = copy.deepcopy(negative)
    changed["negative_control"]["patched_file_sha256"] = changed["negative_control"]["original_file_sha256"]
    with pytest.raises(nodegoat.RuntimeContractError, match="negative_control_patch_unchanged"):
        nodegoat.validate_negative_control_receipt(changed)


def test_hold_receipt_requires_failure_code() -> None:
    receipt = _positive_receipt()
    receipt["execution_contract_status"] = "HOLD"
    receipt["image"] = None
    receipt["runs"] = []
    receipt["consensus"] = {"run_count": 0, "two_runs_byte_equivalent_after_normalization": False, "projection_sha256": None, "raw_returned": False}
    receipt["image_cleanup"] = None
    receipt["failure_code"] = "runtime_failed"
    nodegoat.validate_receipt(receipt)

    receipt["failure_code"] = None
    with pytest.raises(nodegoat.RuntimeContractError, match="receipt_hold_without_failure"):
        nodegoat.validate_receipt(receipt)
