from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).parents[1]
TEST_CLASS = "org.owasp.webgoat.integration.SqlInjectionAdvancedIntegrationTest"


def _load(name: str, filename: str):
    path = ROOT / "scripts" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


adapter = _load(
    "k_guard_l2_webgoat_sql_injection_advanced_execution_evidence_test",
    "derive_l2_webgoat_sql_injection_advanced_execution_evidence.py",
)


def _write(path: Path, payload: dict) -> bytes:
    raw = adapter.canonical_json_bytes(payload)
    path.write_bytes(raw)
    return raw


def _source_receipt() -> dict:
    return {
        "schema": "k_guard_git_source_materialization.v2",
        "passed": True,
        "raw_returned": False,
        "repository_id": adapter.REPOSITORY_ID,
        "commit": adapter.SOURCE_COMMIT,
        "commit_tree": adapter.SOURCE_TREE,
        "source_tree_sha256": adapter.SOURCE_TREE_SHA256,
        "source_worktree_clean": True,
        "origin_repository_match": True,
        "commit_match": True,
        "commit_object_hash_match": True,
        "commit_tree_match": True,
        "tree_object_reconstruction_match": True,
        "index_tree_match": True,
        "physical_bytes_match_git_blobs": True,
        "git_fsck_strict_passed": True,
        "git_porcelain_clean": True,
        "files": [
            {
                "path": adapter.SOURCE_PATH,
                "sha256": adapter.SOURCE_CONTENT_SHA256,
                "byte_count": 2440,
            }
        ],
    }


def _run(*, negative: bool, result_sha256: str, nonce: str) -> dict:
    expected_exit = 1 if negative else 0
    normalized = {
        "schema": "negative-schema" if negative else "positive-schema",
        "test_class": TEST_CLASS,
        "suite": {"all_cases_passed": not negative},
    }
    if negative:
        normalized["control_triggered"] = True
    return {
        "run_nonce_sha256": nonce * 64,
        "expected_exit_code": expected_exit,
        "execution": {
            "returncode": expected_exit,
            "timed_out": False,
            "output_truncated": False,
        },
        "normalized_result": normalized,
        "report_hashes": {"summary_sha256": result_sha256, "suite_sha256": "f" * 64},
        "cleanup": {"passed": True},
        "isolation": {"passed": True},
        "observed_result": None,
        "failure_code": None,
        "passed": True,
        "raw_returned": False,
    }


def _positive_receipt(source_hash: str, result_sha256: str) -> dict:
    return {
        "source": {
            "repository_id": adapter.REPOSITORY_ID,
            "commit": adapter.SOURCE_COMMIT,
            "commit_tree": adapter.SOURCE_TREE,
            "source_tree_sha256": adapter.SOURCE_TREE_SHA256,
            "source_receipt_sha256": source_hash,
        },
        "execution_contract_status": "EXECUTION_CONTRACT_PASS",
        "runs": [
            _run(negative=False, result_sha256=result_sha256, nonce="a"),
            _run(negative=False, result_sha256=result_sha256, nonce="b"),
        ],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True},
    }


def _negative_receipt(source_hash: str, positive_hash: str, result_sha256: str) -> dict:
    return {
        "source": {
            "repository_id": adapter.REPOSITORY_ID,
            "commit": adapter.SOURCE_COMMIT,
            "commit_tree": adapter.SOURCE_TREE,
            "source_tree_sha256": adapter.SOURCE_TREE_SHA256,
            "source_receipt_sha256": source_hash,
        },
        "positive_execution_contract": {
            "receipt_sha256": positive_hash,
            "source_receipt_sha256": source_hash,
            "execution_contract_status": "EXECUTION_CONTRACT_PASS",
            "raw_returned": False,
        },
        "negative_control_status": "NEGATIVE_CONTROL_PASS",
        "negative_control": {
            "patch_id": "escape-sql-literal-attack6a.v1",
            "source_checkout_mutated": False,
            "raw_returned": False,
        },
        "runs": [
            _run(negative=True, result_sha256=result_sha256, nonce="c"),
            _run(negative=True, result_sha256=result_sha256, nonce="d"),
        ],
        "consensus": {
            "run_count": 2,
            "two_runs_byte_equivalent_after_normalization": True,
            "raw_returned": False,
        },
        "image_cleanup": {"passed": True},
    }


def _replay() -> SimpleNamespace:
    return SimpleNamespace(
        RESULT_SCHEMA="positive-schema",
        NEGATIVE_CONTROL_RESULT_SCHEMA="negative-schema",
        NEGATIVE_CONTROL_EXPECTED_EXIT_CODE=1,
        NEGATIVE_CONTROL_PATCH_ID="escape-sql-literal-attack6a.v1",
        validate_receipt=lambda _receipt: None,
        validate_negative_control_receipt=lambda _receipt: None,
    )


def _fixture_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    monkeypatch.setattr(adapter, "_load_replay_contract", lambda: (_replay(), "0" * 64))
    source_path = tmp_path / "source.json"
    source_raw = _write(source_path, _source_receipt())
    source_hash = adapter.sha256_bytes(source_raw)
    monkeypatch.setattr(adapter, "SOURCE_RECEIPT_RAW_SHA256", source_hash)
    monkeypatch.setattr(adapter, "SOURCE_RECEIPT_SHA256", "e" * 64)

    positive_path = tmp_path / "positive.json"
    positive_raw = _write(positive_path, _positive_receipt(source_hash, "a" * 64))
    positive_hash = adapter.sha256_bytes(positive_raw)

    negative_path = tmp_path / "negative.json"
    negative_raw = _write(negative_path, _negative_receipt(source_hash, positive_hash, "b" * 64))
    return source_path, positive_path, negative_path


def test_derives_raw_free_execution_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)

    payload = adapter.derive_execution_evidence(source, positive, negative, replay_module=_replay())

    adapter.validate_execution_evidence(payload)
    assert payload["adapter_status"] == "EXECUTION_EVIDENCE_PASS"
    assert payload["oracle"]["kind"] == "process"
    assert payload["negative_control"]["expected_exit_code"] == 1
    assert payload["claim_boundary"]["release_gate_admitted"] is False
    assert "stdout" not in json.dumps(payload, sort_keys=True)


def test_rejects_unbound_source_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["files"][0]["sha256"] = "f" * 64
    raw = _write(source, payload)
    monkeypatch.setattr(adapter, "SOURCE_RECEIPT_RAW_SHA256", adapter.sha256_bytes(raw))

    with pytest.raises(adapter.ExecutionEvidenceError, match="source_receipt_selector_not_bound"):
        adapter.derive_execution_evidence(source, positive, negative, replay_module=_replay())


def test_rejects_non_distinguishing_control_result(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    payload = json.loads(negative.read_text(encoding="utf-8"))
    for run in payload["runs"]:
        run["report_hashes"]["summary_sha256"] = "a" * 64
    _write(negative, payload)

    with pytest.raises(adapter.ExecutionEvidenceError, match="negative_control_not_distinguishing"):
        adapter.derive_execution_evidence(source, positive, negative, replay_module=_replay())


def test_rejects_changed_preregistered_selector(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(adapter, "SOURCE_LINE", 16)

    with pytest.raises(adapter.ExecutionEvidenceError, match="source_selector_preregistration_mismatch"):
        adapter.derive_execution_evidence(source, positive, negative, replay_module=_replay())


def test_refuses_to_overwrite_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, positive, negative = _fixture_paths(tmp_path, monkeypatch)
    payload = adapter.derive_execution_evidence(source, positive, negative, replay_module=_replay())
    output = tmp_path / "evidence.json"

    adapter.write_new_output(output, payload)

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        adapter.write_new_output(output, payload)
