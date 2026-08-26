from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_pygoat_sensitive_data.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_pygoat_sensitive_data_replay", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
pygoat = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pygoat
SPEC.loader.exec_module(pygoat)


def _sha(character: str) -> str:
    return character * 64


def _source() -> dict:
    return {
        "repository_id": pygoat.REPOSITORY_ID,
        "commit": pygoat.SOURCE_COMMIT,
        "commit_tree": pygoat.SOURCE_TREE,
        "source_tree_sha256": pygoat.SOURCE_TREE_SHA256,
        "p23a_registry_sha256": _sha("1"),
        "p23a_app_receipt_sha256": pygoat.P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": pygoat.P23A_APP_SEMANTIC_SHA256,
        "current_source_receipt_sha256": _sha("2"),
        "file_count": 276,
        "total_bytes": 1_164_261,
        "raw_returned": False,
    }


def _tool() -> dict:
    return {
        "runner_sha256": _sha("3"),
        "source_verifier_sha256": _sha("4"),
        "driver_sha256": _sha("5"),
        "adapter_entrypoint_sha256": _sha("6"),
        "source_image_id": pygoat.SOURCE_IMAGE_ID,
        "raw_returned": False,
    }


def _base_image() -> dict:
    return {
        "source_image_id": pygoat.SOURCE_IMAGE_ID,
        "source_image_ref": pygoat.SOURCE_IMAGE_REF,
        "source_image_rootfs_layers_sha256": _sha("7"),
        "source_image_commit_label": pygoat.SOURCE_COMMIT,
        "source_dockerfile_sha256": pygoat.SOURCE_DOCKERFILE_SHA256,
        "source_subproject": pygoat.SOURCE_SUBPROJECT,
        "source_file_sha256": dict(pygoat.SOURCE_FILES),
        "image_file_sha256": {name: pygoat.SOURCE_FILES[name] for name in pygoat.IMAGE_FILE_PATHS},
        "source_image_current_source_provenance_only": True,
        "fresh_dependency_rebuild_proven": False,
        "runtime_supply_chain_proven": False,
        "raw_returned": False,
    }


def _view(variant: str) -> dict:
    view = {
        "source_path": pygoat.VIEW_PATH,
        "original_file_sha256": pygoat.SOURCE_FILES[pygoat.VIEW_PATH],
        "source_checkout_mutated": False,
        "raw_returned": False,
    }
    if variant == "negative":
        view.update(
            {
                "patch_id": pygoat.NEGATIVE_CONTROL_PATCH_ID,
                "patched_file_sha256": _sha("a"),
                "patch_sha256": _sha("b"),
                "marker_count": 1,
                "replacement_count": 1,
            }
        )
    return view


def _image(variant: str) -> dict:
    return {
        "image_id": "sha256:" + _sha("c"),
        "image_id_sha256": _sha("d"),
        "base_source_image_id": pygoat.SOURCE_IMAGE_ID,
        "contract_label": pygoat.EXECUTION_CONTRACT_LABEL
        if variant == "positive"
        else pygoat.NEGATIVE_CONTROL_LABEL,
        "dockerfile_sha256": _sha("e"),
        "driver_sha256": _sha("f"),
        "adapter_entrypoint_sha256": _sha("0"),
        "build_contract_sha256": _sha("1"),
        "rootfs_lineage_sha256": _sha("2"),
        "view": _view(variant),
        "source_derived": True,
        "build_network": "none",
        "fresh_dependency_rebuild_proven": False,
        "raw_returned": False,
    }


def _run(variant: str, nonce: str) -> dict:
    positive = variant == "positive"
    expected_status = 200 if positive else 302
    normalized = {
        "schema": pygoat.DRIVER_RESULT_SCHEMA,
        "mode": variant,
        "expected_status": expected_status,
        "observed_status": expected_status,
        "users_json_observed": positive,
        "users_nonempty": positive,
        "expected_field_shape_observed": positive,
        "login_redirect_observed": not positive,
        "driver_error_code": None,
        "passed": True,
        "raw_returned": False,
    }
    return {
        "run_nonce_sha256": _sha(nonce),
        "image_id": "sha256:" + _sha("c"),
        "driver_sha256": pygoat.sha256_bytes(pygoat.DRIVER_SCRIPT.encode("utf-8")),
        "network_policy": pygoat.NETWORK_POLICY,
        "expected_status": expected_status,
        "mode": variant,
        "isolation": {"checks": {"read_only_rootfs": True}, "passed": True, "raw_returned": False},
        "execution": {"returncode": 0, "raw_returned": False},
        "normalized_result": normalized,
        "cleanup": {"passed": True, "raw_returned": False},
        "failure_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _positive_receipt() -> dict:
    return {
        "schema": pygoat.SCHEMA,
        "tool_provenance": _tool(),
        "source": _source(),
        "base_image": _base_image(),
        "image": _image("positive"),
        "runs": [_run("positive", "1"), _run("positive", "2")],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": _sha("3"),
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True, "raw_returned": False},
        "claim_boundary": pygoat._claim_boundary(negative=False),
        "admission_blockers": list(pygoat.ADMISSION_BLOCKERS),
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _negative_receipt() -> dict:
    return {
        "schema": pygoat.NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": _tool(),
        "source": _source(),
        "base_image": _base_image(),
        "image": _image("negative"),
        "runs": [_run("negative", "1"), _run("negative", "2")],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": _sha("4"),
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True, "raw_returned": False},
        "positive_execution_contract": {
            "receipt_sha256": _sha("5"),
            "source_receipt_sha256": _sha("2"),
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            "raw_returned": False,
        },
        "negative_control": _view("negative"),
        "claim_boundary": pygoat._claim_boundary(negative=True),
        "admission_blockers": list(pygoat.NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
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
                "app_id": pygoat.APP_ID,
                "repository_id": pygoat.REPOSITORY_ID,
                "commit": pygoat.SOURCE_COMMIT,
                "commit_tree": pygoat.SOURCE_TREE,
                "source_tree_sha256": pygoat.SOURCE_TREE_SHA256,
                "receipt_sha256": pygoat.P23A_APP_RECEIPT_SHA256,
                "receipt_semantic_sha256": pygoat.P23A_APP_SEMANTIC_SHA256,
                "source_license_admission": "PASS",
                "scanner_output_observed": False,
                "oracle_gate_status": "HOLD",
                "oracle_missing": True,
            }
        ],
        "raw_returned": False,
    }


def test_negative_patch_is_single_and_preserves_source() -> None:
    source = (
        b"from django.contrib.auth.decorators import login_required\n"
        b"# Intentionally insecure - for teaching purposes!\n"
        b"def all_users_data_view(request):\n"
    )
    patched, control = pygoat._negative_view_patch(source)

    assert source != patched
    assert b"@login_required\ndef all_users_data_view" in patched
    assert control["marker_count"] == 1
    assert control["replacement_count"] == 1
    assert control["source_checkout_mutated"] is False


@pytest.mark.parametrize(
    "views",
    [
        b"from django.contrib.auth.decorators import login_required\n",
        b"from django.contrib.auth.decorators import login_required\n"
        b"def all_users_data_view(request):\n"
        b"def all_users_data_view(request):\n",
        b"from django.contrib.auth.decorators import login_required\n"
        b"@login_required\ndef all_users_data_view(request):\n",
    ],
)
def test_negative_patch_rejects_missing_or_ambiguous_anchor(views: bytes) -> None:
    with pytest.raises(pygoat.RuntimeContractError, match="negative_control_patch_anchor_invalid"):
        pygoat._negative_view_patch(views)


def test_driver_parser_requires_mode_specific_outcome() -> None:
    result = _run("positive", "1")["normalized_result"]
    output = b"start\n" + b"K_GUARD_PYGOAT_SENSITIVE_DATA_RESULT:" + json.dumps(result).encode("utf-8")
    assert pygoat._parse_driver_result(output, mode="positive", expected_status=200)["passed"] is True

    result["expected_field_shape_observed"] = False
    output = b"K_GUARD_PYGOAT_SENSITIVE_DATA_RESULT:" + json.dumps(result).encode("utf-8")
    with pytest.raises(pygoat.RuntimeContractError, match="driver_result_outcome_invalid"):
        pygoat._parse_driver_result(output, mode="positive", expected_status=200)


def test_p23a_registry_requires_frozen_pygoat_binding(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_bytes(pygoat.canonical_json_bytes(_registry()))
    app, receipt_sha256 = pygoat._load_p23a_registry(path)
    assert app["app_id"] == pygoat.APP_ID
    assert len(receipt_sha256) == 64

    invalid = _registry()
    invalid["apps"][0]["commit"] = "f" * 40
    path.write_bytes(pygoat.canonical_json_bytes(invalid))
    with pytest.raises(pygoat.RuntimeContractError, match="p23a_registry_pygoat_binding_invalid"):
        pygoat._load_p23a_registry(path)


def test_container_isolation_requires_internal_network_and_hardening() -> None:
    host = {
        "NetworkMode": "isolated-network",
        "PortBindings": {},
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "CapAdd": None,
        "SecurityOpt": ["no-new-privileges=true"],
        "PidsLimit": pygoat.APP_PIDS_LIMIT,
        "Memory": pygoat.APP_MEMORY_BYTES,
        "NanoCpus": pygoat.NANO_CPUS,
        "Privileged": False,
        "Binds": None,
        "Tmpfs": dict(pygoat.APP_TMPFS),
    }
    container = {
        "Image": pygoat.SOURCE_IMAGE_ID,
        "HostConfig": host,
        "Config": {
            "User": pygoat.APP_USER,
            "Labels": {
                "io.k-guard.app-id": pygoat.APP_ID,
                "io.k-guard.execution-contract": pygoat.EXECUTION_CONTRACT_LABEL,
                "io.k-guard.run-nonce": "nonce",
                "io.k-guard.role": "application",
            },
        },
        "NetworkSettings": {
            "Ports": {},
            "Networks": {"isolated-network": {"Aliases": ["pygoat-app"]}},
        },
        "Mounts": [],
    }
    result = pygoat._container_isolation(
        container,
        image_id=pygoat.SOURCE_IMAGE_ID,
        network_name="isolated-network",
        alias="pygoat-app",
        nonce="nonce",
        contract_label=pygoat.EXECUTION_CONTRACT_LABEL,
    )
    assert result["passed"] is True

    container["HostConfig"]["ReadonlyRootfs"] = False
    assert (
        pygoat._container_isolation(
            container,
            image_id=pygoat.SOURCE_IMAGE_ID,
            network_name="isolated-network",
            alias="pygoat-app",
            nonce="nonce",
            contract_label=pygoat.EXECUTION_CONTRACT_LABEL,
        )["passed"]
        is False
    )


def test_receipts_reject_release_claim_and_raw_evidence() -> None:
    positive = _positive_receipt()
    pygoat.validate_receipt(positive)

    invalid = copy.deepcopy(positive)
    invalid["release_gate_passed"] = True
    with pytest.raises(pygoat.RuntimeContractError, match="receipt_release_promotion_invalid"):
        pygoat.validate_receipt(invalid)

    negative = _negative_receipt()
    pygoat.validate_negative_control_receipt(negative)
    invalid_negative = copy.deepcopy(negative)
    invalid_negative["runs"][0]["normalized_result"]["raw_returned"] = True
    with pytest.raises(pygoat.RuntimeContractError, match="raw_boundary_invalid"):
        pygoat.validate_negative_control_receipt(invalid_negative)


def test_adapter_copies_immutable_source_to_non_root_tmpfs() -> None:
    dockerfile = pygoat._dockerfile_template()
    assert "cp -R /app/. /opt/pygoat-source/" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "FROM ${BASE_SOURCE}" in dockerfile
    assert 'test ! -w /opt/pygoat-source' in pygoat.ADAPTER_ENTRYPOINT
    assert "cp -R /opt/pygoat-source/. /app/" in pygoat.ADAPTER_ENTRYPOINT
    assert "chmod -R u+w /app" in pygoat.ADAPTER_ENTRYPOINT
