from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def _load(name: str, filename: str):
    path = ROOT / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


adapter = _load(
    "k_guard_l2_webgoat_idor_execution_evidence_test",
    "derive_l2_webgoat_idor_execution_evidence.py",
)
idor = _load("k_guard_l2_webgoat_idor_execution_evidence_replay_test", "replay_l2_webgoat_idor.py")


def _write(path: Path, payload: dict) -> bytes:
    raw = adapter.canonical_json_bytes(payload)
    path.write_bytes(raw)
    return raw


def _source_receipt() -> dict:
    return {
        "schema": "k_guard_git_source_materialization.v2",
        "passed": True,
        "raw_returned": False,
        "repository_id": idor.REPOSITORY_ID,
        "commit": idor.SOURCE_COMMIT,
        "commit_tree": idor.SOURCE_TREE,
        "source_tree_sha256": idor.SOURCE_TREE_SHA256,
        "source_worktree_clean": True,
        "origin_repository_match": True,
        "commit_match": True,
        "commit_object_hash_match": True,
        "commit_tree_match": True,
        "tree_object_reconstruction_match": True,
        "index_tree_match": True,
        "physical_bytes_match_git_blobs": True,
        "git_fsck_strict_passed": True,
        "files": [
            {
                "path": adapter.SOURCE_PATH,
                "sha256": adapter.SOURCE_CONTENT_SHA256,
                "byte_count": 3117,
            }
        ],
    }


def _positive_run(result_sha256: str) -> dict:
    return {
        "run_nonce_sha256": "a" * 64,
        "image_id": "sha256:" + "b" * 64,
        "maven_command_sha256": "c" * 64,
        "network_policy": "none",
        "isolation": {"passed": True, "raw_returned": False},
        "execution": {
            "returncode": 0,
            "timed_out": False,
            "output_truncated": False,
            "raw_returned": False,
        },
        "normalized_result": {
            "schema": idor.RESULT_SCHEMA,
            "test_class": idor.TEST_CLASS,
            "suite": {"all_cases_passed": True},
            "raw_returned": False,
        },
        "report_hashes": {"summary_sha256": result_sha256, "suite_sha256": "d" * 64},
        "cleanup": {"passed": True, "raw_returned": False},
        "passed": True,
        "raw_returned": False,
    }


def _positive_receipt(source_hash: str, result_sha256: str) -> dict:
    first = _positive_run(result_sha256)
    second = copy.deepcopy(first)
    second["run_nonce_sha256"] = "e" * 64
    projections = [idor._consensus_projection(first), idor._consensus_projection(second)]
    return {
        "schema": idor.SCHEMA,
        "tool_provenance": {"runner_sha256": "1" * 64, "raw_returned": False},
        "source": {
            "repository_id": idor.REPOSITORY_ID,
            "commit": idor.SOURCE_COMMIT,
            "commit_tree": idor.SOURCE_TREE,
            "source_tree_sha256": idor.SOURCE_TREE_SHA256,
            "source_receipt_sha256": source_hash,
        },
        "image": {"image_id": first["image_id"]},
        "runs": [first, second],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": idor._canonical_sha256(projections),
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True},
        "claim_boundary": idor._claim_boundary(),
        "admission_blockers": list(idor.ADMISSION_BLOCKERS),
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _negative_run(result_sha256: str) -> dict:
    return {
        "run_nonce_sha256": "a" * 64,
        "image_id": "sha256:" + "b" * 64,
        "maven_command_sha256": "c" * 64,
        "network_policy": "none",
        "isolation": {"passed": True, "raw_returned": False},
        "execution": {
            "returncode": idor.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE,
            "timed_out": False,
            "output_truncated": False,
            "raw_returned": False,
        },
        "expected_exit_code": idor.NEGATIVE_CONTROL_EXPECTED_EXIT_CODE,
        "normalized_result": {
            "schema": idor.NEGATIVE_CONTROL_RESULT_SCHEMA,
            "test_class": idor.TEST_CLASS,
            "suite": {"all_cases_passed": False},
            "control_triggered": True,
            "raw_returned": False,
        },
        "report_hashes": {"summary_sha256": result_sha256, "suite_sha256": "d" * 64},
        "cleanup": {"passed": True, "raw_returned": False},
        "passed": True,
        "raw_returned": False,
    }


def _negative_receipt(source_hash: str, positive_hash: str, result_sha256: str) -> dict:
    first = _negative_run(result_sha256)
    second = copy.deepcopy(first)
    second["run_nonce_sha256"] = "e" * 64
    control = {
        "patch_id": idor.NEGATIVE_CONTROL_PATCH_ID,
        "source_path": idor.NEGATIVE_CONTROL_SOURCE_PATH.as_posix(),
        "original_file_sha256": "1" * 64,
        "patched_file_sha256": "2" * 64,
        "patch_sha256": "3" * 64,
        "variant_tree_sha256": "4" * 64,
        "source_checkout_mutated": False,
        "raw_returned": False,
    }
    projections = [idor._consensus_projection(first), idor._consensus_projection(second)]
    return {
        "schema": idor.NEGATIVE_CONTROL_SCHEMA,
        "tool_provenance": {"runner_sha256": "5" * 64, "raw_returned": False},
        "source": {
            "repository_id": idor.REPOSITORY_ID,
            "commit": idor.SOURCE_COMMIT,
            "commit_tree": idor.SOURCE_TREE,
            "source_tree_sha256": idor.SOURCE_TREE_SHA256,
            "source_receipt_sha256": source_hash,
        },
        "positive_execution_contract": {
            "receipt_sha256": positive_hash,
            "source_receipt_sha256": source_hash,
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            "raw_returned": False,
        },
        "negative_control": control,
        "image": {"image_id": first["image_id"], "source_variant": control},
        "runs": [first, second],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "projection_sha256": idor._canonical_sha256(projections),
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True},
        "claim_boundary": idor._negative_control_claim_boundary(),
        "admission_blockers": list(idor.NEGATIVE_CONTROL_ADMISSION_BLOCKERS),
        "negative_control_status": "NEGATIVE_CONTROL_PASS",
        "release_gate_passed": False,
        "failure_code": None,
        "raw_returned": False,
    }


def _fixture_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    source_path = tmp_path / "source.json"
    source_raw = _write(source_path, _source_receipt())
    source_hash = adapter.sha256_bytes(source_raw)
    monkeypatch.setattr(adapter, "SOURCE_RECEIPT_SHA256", source_hash)

    positive_path = tmp_path / "positive.json"
    positive_raw = _write(positive_path, _positive_receipt(source_hash, "a" * 64))
    positive_hash = adapter.sha256_bytes(positive_raw)
    monkeypatch.setattr(adapter, "POSITIVE_EXECUTION_RECEIPT_SHA256", positive_hash)
    monkeypatch.setattr(idor, "POSITIVE_EXECUTION_RECEIPT_SHA256", positive_hash)

    negative_path = tmp_path / "negative.json"
    negative_raw = _write(negative_path, _negative_receipt(source_hash, positive_hash, "b" * 64))
    monkeypatch.setattr(adapter, "NEGATIVE_CONTROL_RECEIPT_SHA256", adapter.sha256_bytes(negative_raw))
    monkeypatch.setattr(adapter, "POSITIVE_RESULT_SHA256", "a" * 64)
    monkeypatch.setattr(adapter, "NEGATIVE_RESULT_SHA256", "b" * 64)
    return source_path, positive_path, negative_path


def test_derives_raw_free_process_evidence_and_validates_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)

    payload = adapter.derive_execution_evidence(source, positive, negative, replay_module=idor)

    adapter.validate_execution_evidence(payload)
    assert payload["adapter_status"] == "EXECUTION_EVIDENCE_PASS"
    assert payload["oracle"]["kind"] == "process"
    assert payload["oracle"]["expected_http_status"] is None
    assert payload["negative_control"]["expected_exit_code"] == 1
    assert payload["state_reset_evidence"]["registry_state_reset_admitted"] is False
    rendered = json.dumps(payload, sort_keys=True)
    assert "stdout" not in rendered
    assert "stderr" not in rendered
    assert payload["release_gate_passed"] is False


def test_rejects_source_receipt_without_bound_source_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    source_payload = json.loads(source.read_text(encoding="utf-8"))
    source_payload["files"][0]["sha256"] = "f" * 64
    raw = _write(source, source_payload)
    monkeypatch.setattr(adapter, "SOURCE_RECEIPT_SHA256", adapter.sha256_bytes(raw))

    with pytest.raises(adapter.ExecutionEvidenceError, match="source_receipt_selector_not_bound"):
        adapter.derive_execution_evidence(source, positive, negative, replay_module=idor)


def test_rejects_a_non_distinguishing_negative_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    negative_payload = json.loads(negative.read_text(encoding="utf-8"))
    for run in negative_payload["runs"]:
        run["report_hashes"]["summary_sha256"] = "a" * 64
    projections = [idor._consensus_projection(run) for run in negative_payload["runs"]]
    negative_payload["consensus"]["projection_sha256"] = idor._canonical_sha256(projections)
    raw = _write(negative, negative_payload)
    monkeypatch.setattr(adapter, "NEGATIVE_CONTROL_RECEIPT_SHA256", adapter.sha256_bytes(raw))
    monkeypatch.setattr(adapter, "NEGATIVE_RESULT_SHA256", "a" * 64)

    with pytest.raises(adapter.ExecutionEvidenceError, match="negative_control_not_distinguishing"):
        adapter.derive_execution_evidence(source, positive, negative, replay_module=idor)


def test_rejects_control_that_mutates_the_source_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    payload = json.loads(negative.read_text(encoding="utf-8"))
    payload["negative_control"]["source_checkout_mutated"] = True
    payload["image"]["source_variant"]["source_checkout_mutated"] = True
    raw = _write(negative, payload)
    monkeypatch.setattr(adapter, "NEGATIVE_CONTROL_RECEIPT_SHA256", adapter.sha256_bytes(raw))

    with pytest.raises(adapter.ExecutionEvidenceError, match="replay_contract_validation_failed"):
        adapter.derive_execution_evidence(source, positive, negative, replay_module=idor)


def test_rejects_a_changed_source_selector_preregistration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter, "SOURCE_LINE", 29)

    with pytest.raises(adapter.ExecutionEvidenceError, match="source_selector_preregistration_mismatch"):
        adapter.derive_execution_evidence(source, positive, negative, replay_module=idor)


def test_refuses_to_overwrite_execution_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    payload = adapter.derive_execution_evidence(source, positive, negative, replay_module=idor)
    output = tmp_path / "evidence.json"

    adapter.write_new_output(output, payload)

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        adapter.write_new_output(output, payload)
