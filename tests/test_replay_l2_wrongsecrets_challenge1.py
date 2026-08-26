from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "replay_l2_wrongsecrets_challenge1.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_wrongsecrets_challenge1_replay", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
wrongsecrets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = wrongsecrets
SPEC.loader.exec_module(wrongsecrets)


def _sha(character: str) -> str:
    return character * 64


def _command() -> dict[str, object]:
    return {
        "returncode": 0,
        "timed_out": False,
        "output_truncated": False,
        "stdout_sha256": _sha("a"),
        "stderr_sha256": _sha("b"),
        "stdout_bytes": 1,
        "stderr_bytes": 1,
        "raw_returned": False,
    }


def _source() -> dict[str, object]:
    return {
        "repository_id": wrongsecrets.REPOSITORY_ID,
        "commit": wrongsecrets.SOURCE_COMMIT,
        "commit_tree": wrongsecrets.SOURCE_TREE,
        "source_tree_sha256": wrongsecrets.SOURCE_TREE_SHA256,
        "p23a_registry_sha256": _sha("1"),
        "p23a_observed_receipt_sha256": wrongsecrets.P23A_OBSERVED_RECEIPT_SHA256,
        "p23a_app_receipt_sha256": wrongsecrets.P23A_APP_RECEIPT_SHA256,
        "p23a_app_receipt_semantic_sha256": wrongsecrets.P23A_APP_SEMANTIC_SHA256,
        "current_source_receipt_sha256": _sha("2"),
        "file_count": 861,
        "total_bytes": 224_325_617,
        "raw_returned": False,
    }


def _base_image() -> dict[str, object]:
    return {
        "reference": wrongsecrets.BASE_IMAGE_REF,
        "image_id": wrongsecrets.BASE_IMAGE_ID,
        "java_version": wrongsecrets.EXPECTED_JAVA_VERSION,
        "raw_returned": False,
    }


def _staged(variant: str) -> dict[str, object]:
    hashes = dict(wrongsecrets.SOURCE_FILES)
    patch: dict[str, object] | None = None
    if variant == "negative":
        hashes["src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java"] = _sha("3")
        patch = {
            "patch_id": wrongsecrets.NEGATIVE_PATCH_ID,
            "anchor_count": 1,
            "source_sha256": wrongsecrets.SOURCE_FILES[
                "src/main/java/org/owasp/wrongsecrets/challenges/docker/Challenge1.java"
            ],
            "derived_sha256": _sha("3"),
            "raw_returned": False,
        }
    return {
        "variant": variant,
        "relevant_file_sha256": hashes,
        "negative_patch": patch,
        "harness_source_sha256": wrongsecrets._harness_source_hashes(),
        "raw_returned": False,
    }


def _image(variant: str, dynamic: str = "4") -> dict[str, object]:
    return {
        "image_id": "sha256:" + _sha(dynamic),
        "contract_label": wrongsecrets.EXECUTION_CONTRACT_LABEL,
        "variant": variant,
        "contract_sha256": _sha("5"),
        "dockerfile_sha256": _sha("6"),
        "source_derived": True,
        "build_network": "none",
        "fresh_source_compile_proven": True,
        "runtime_supply_chain_proven": False,
        "build_command": _command(),
        "staged_source": _staged(variant),
        "raw_returned": False,
    }


def _observation(variant: str) -> dict[str, object]:
    return {
        "schema": wrongsecrets.DRIVER_RESULT_SCHEMA,
        "answer_matches_source_constant": variant == "positive",
        "raw_returned": False,
    }


def _isolation() -> dict[str, object]:
    return {
        "passed": True,
        "read_only_root": True,
        "non_root_user": True,
        "cap_drop_all": True,
        "no_new_privileges": True,
        "network_none": True,
        "no_host_port": True,
        "no_bind_or_volume_mount": True,
        "tmpfs_contract": True,
        "resource_limits": True,
        "raw_returned": False,
    }


def _run(variant: str) -> dict[str, object]:
    return {
        "mode": variant,
        "driver_sha256": wrongsecrets.sha256_bytes(wrongsecrets._driver_command().encode("utf-8")),
        "observation": _observation(variant),
        "isolation": _isolation(),
        "driver_command": _command(),
        "cleanup": {"removed": True, "absent_after_cleanup": True, "raw_returned": False},
        "passed": True,
        "raw_returned": False,
    }


def _receipt(variant: str, dynamic: str = "4") -> dict[str, object]:
    common: dict[str, object] = {
        "source": _source(),
        "base_image": _base_image(),
        "image_contract": _image(variant, dynamic),
        "runs": [_run(variant), _run(variant)],
        "internal_repeat_exact": True,
        "tool_provenance": {
            "runner_sha256": wrongsecrets._runner_sha256(),
            "source_verifier_sha256": _sha("7"),
            "docker_cli": "docker",
            "raw_returned": False,
        },
        "image_cleanup": {"removed": True, "absent_after_cleanup": True, "raw_returned": False},
        "admission_blockers": list(wrongsecrets.ADMISSION_BLOCKERS),
        "release_gate_passed": False,
        "claim_boundary": wrongsecrets._claim_boundary(negative=variant == "negative"),
        "raw_returned": False,
    }
    if variant == "positive":
        return {
            "schema": wrongsecrets.SCHEMA,
            "scenario": "wrongsecrets-challenge1-javac-harness",
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            **common,
        }
    return {
        "schema": wrongsecrets.NEGATIVE_CONTROL_SCHEMA,
        "scenario": "wrongsecrets-challenge1-derived-empty-answer-javac-control",
        "negative_control_status": "NEGATIVE_CONTROL_PASS",
        "positive_receipt_sha256": _sha("8"),
        "positive_receipt_semantic_sha256": _sha("9"),
        **common,
    }


def test_negative_patch_is_exact_and_raw_free() -> None:
    raw = b"public String getAnswer() { return WrongSecretsConstants.password; }"
    patched, metadata = wrongsecrets._negative_challenge_patch(raw)

    assert wrongsecrets.PATCH_ANCHOR not in patched
    assert metadata["anchor_count"] == 1
    assert metadata["source_sha256"] == wrongsecrets.sha256_bytes(raw)
    assert metadata["raw_returned"] is False

    with pytest.raises(wrongsecrets.RuntimeContractError, match="negative_patch_anchor_ambiguous"):
        wrongsecrets._negative_challenge_patch(raw + raw)


def test_driver_parser_requires_only_normalized_single_marker() -> None:
    observation = _observation("positive")
    output = (wrongsecrets.DRIVER_MARKER + json.dumps(observation, sort_keys=True) + "\n").encode("utf-8")

    assert wrongsecrets._parse_driver_result(output) == observation
    with pytest.raises(wrongsecrets.RuntimeContractError, match="driver_marker_invalid"):
        wrongsecrets._parse_driver_result(output + b"unexpected\n")

    observation["raw_returned"] = True
    bad = (wrongsecrets.DRIVER_MARKER + json.dumps(observation, sort_keys=True)).encode("utf-8")
    with pytest.raises(wrongsecrets.RuntimeContractError, match="driver_result_binding_invalid"):
        wrongsecrets._parse_driver_result(bad)


def test_negative_requires_false_source_predicate_not_process_failure() -> None:
    observation = _observation("negative")
    assert wrongsecrets._expected_observation("negative", observation) is True

    observation["answer_matches_source_constant"] = True
    assert wrongsecrets._expected_observation("negative", observation) is False


def test_container_isolation_accepts_unpublished_port_metadata_but_rejects_host_binding() -> None:
    inspect = {
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "NetworkMode": "none",
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges=true"],
            "Memory": wrongsecrets.APP_MEMORY_BYTES,
            "NanoCpus": wrongsecrets.APP_NANO_CPUS,
            "PidsLimit": wrongsecrets.APP_PIDS_LIMIT,
            "Tmpfs": dict(wrongsecrets.APP_TMPFS),
            "PortBindings": {},
            "Binds": None,
        },
        "Config": {"User": wrongsecrets.APP_USER},
        "NetworkSettings": {"Ports": {"8080/tcp": None}},
        "Mounts": [],
    }
    assert wrongsecrets._container_isolation(inspect)["passed"] is True

    inspect["HostConfig"]["PortBindings"] = {"8080/tcp": [{"HostPort": "8080"}]}
    assert wrongsecrets._container_isolation(inspect)["passed"] is False


def test_run_attaches_verified_cleanup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    marker = (wrongsecrets.DRIVER_MARKER + json.dumps(_observation("positive")) + "\n").encode("utf-8")
    monkeypatch.setattr(wrongsecrets, "_create_container", lambda *args, **kwargs: ("a" * 12, _isolation()))
    monkeypatch.setattr(
        wrongsecrets,
        "_docker",
        lambda *args, **kwargs: wrongsecrets.CommandResult(0, marker, b"", False, False),
    )
    monkeypatch.setattr(wrongsecrets, "_inspect_container", lambda *args, **kwargs: {"State": {"ExitCode": 0}})
    monkeypatch.setattr(
        wrongsecrets,
        "_cleanup_container",
        lambda *args, **kwargs: {"removed": True, "absent_after_cleanup": True, "raw_returned": False},
    )

    result = wrongsecrets._run_one("sha256:" + _sha("a"), work_root=tmp_path, mode="positive", timeout=1)

    assert result["cleanup"] == {"removed": True, "absent_after_cleanup": True, "raw_returned": False}


def test_receipt_validation_rejects_raw_evidence_and_missing_cleanup() -> None:
    positive = _receipt("positive")
    wrongsecrets.validate_receipt(positive)

    raw = copy.deepcopy(positive)
    raw["runs"][0]["observation"]["raw_returned"] = True
    raw["runs"][1]["observation"]["raw_returned"] = True
    with pytest.raises(wrongsecrets.RuntimeContractError, match="receipt_raw_boundary_invalid"):
        wrongsecrets.validate_receipt(raw)

    missing_cleanup = copy.deepcopy(positive)
    del missing_cleanup["runs"][0]["cleanup"]
    with pytest.raises(wrongsecrets.RuntimeContractError, match="receipt_run_shape_invalid"):
        wrongsecrets.validate_receipt(missing_cleanup)


def test_driver_command_is_local_and_does_not_embed_challenge_answer() -> None:
    command = wrongsecrets._driver_command()

    assert command.startswith("exec java -cp ")
    assert "mvn" not in command
    assert "WrongSecretsConstants.password" not in command
