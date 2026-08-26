from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "derive_l2_webgoat_sql_injection_advanced_state_reset_evidence.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_sql_injection_advanced_state_reset_test", SCRIPT)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


def _write(path: Path, payload: dict) -> bytes:
    raw = adapter.canonical_json_bytes(payload)
    path.write_bytes(raw)
    return raw


def _run(nonce: str) -> dict:
    return {
        "run_nonce_sha256": nonce,
        "image_id": "sha256:" + "a" * 64,
        "cleanup": {
            "ownership_verified": True,
            "container_removed": True,
            "volume_count": 2,
            "volumes_removed": True,
            "passed": True,
            "raw_returned": False,
        },
        "passed": True,
        "raw_returned": False,
    }


def _receipt(first_nonce: str, second_nonce: str) -> dict:
    return {
        "runs": [_run(first_nonce), _run(second_nonce)],
        "image": {"image_id": "sha256:" + "a" * 64},
        "image_cleanup": {
            "ownership_verified": True,
            "removed": True,
            "absent_after": True,
            "passed": True,
            "raw_returned": False,
        },
    }


def _source() -> dict:
    return {
        "app_id": adapter.APP_ID,
        "repository_id": adapter.REPOSITORY_ID,
        "commit": adapter.SOURCE_COMMIT,
        "commit_tree": adapter.SOURCE_TREE,
        "source_tree_sha256": adapter.SOURCE_TREE_SHA256,
        "source_receipt_sha256": adapter.SOURCE_RECEIPT_RAW_SHA256,
        "source_receipt_semantic_sha256": adapter.SOURCE_RECEIPT_SEMANTIC_SHA256,
        "lineage_id": adapter.SOURCE_LINEAGE_ID,
        "selector": adapter._source_selector(),
        "raw_returned": False,
    }


def _fixture_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, SimpleNamespace]:
    positive_path = tmp_path / "positive.json"
    positive_raw = _write(positive_path, _receipt("1" * 64, "2" * 64))
    negative_path = tmp_path / "negative.json"
    negative_raw = _write(negative_path, _receipt("3" * 64, "4" * 64))
    pair = {"pair": "bound", "raw_returned": False}
    fake_execution_adapter = SimpleNamespace(
        validate_execution_evidence=lambda _value: None,
        _load_replay_contract=lambda: (SimpleNamespace(), "b" * 64),
        _validate_execution_pair=lambda *_args: copy.deepcopy(pair),
        _state_reset_evidence=lambda _pair: {
            "registry_state_reset_admitted": False,
            "raw_returned": False,
        },
    )
    execution_path = tmp_path / "execution.json"
    _write(
        execution_path,
        {
            "source": _source(),
            "execution_pair": pair,
            "state_reset_evidence": {
                "registry_state_reset_admitted": False,
                "raw_returned": False,
            },
            "claim_boundary": {"registry_state_reset_admitted": False},
        },
    )
    return execution_path, positive_path, negative_path, fake_execution_adapter


def test_derives_raw_free_state_reset_evidence_from_independent_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution, positive, negative, fake = _fixture_paths(tmp_path, monkeypatch)

    payload = adapter.derive_state_reset_evidence(
        execution, positive, negative, execution_adapter=fake
    )

    adapter.validate_state_reset_evidence(payload)
    assert payload["adapter_status"] == "STATE_RESET_EVIDENCE_PASS"
    assert payload["state_reset"] == adapter._expected_state_reset_command()
    assert payload["reset_proof"]["unique_run_nonce_count"] == 4
    assert payload["claim_boundary"]["registry_state_reset_admitted"] is False
    assert payload["release_gate_passed"] is False
    rendered = json.dumps(payload, sort_keys=True)
    assert "stdout" not in rendered
    assert "stderr" not in rendered


def test_rejects_cleanup_that_leaves_an_owned_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution, positive, negative, fake = _fixture_paths(tmp_path, monkeypatch)
    payload = json.loads(positive.read_text(encoding="utf-8"))
    payload["runs"][0]["cleanup"]["volumes_removed"] = False
    _write(positive, payload)

    with pytest.raises(adapter.StateResetEvidenceError, match="positive_run_cleanup_invalid"):
        adapter.derive_state_reset_evidence(execution, positive, negative, execution_adapter=fake)


def test_rejects_reused_run_nonce_across_positive_and_negative_receipts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution, positive, negative, fake = _fixture_paths(tmp_path, monkeypatch)
    payload = json.loads(negative.read_text(encoding="utf-8"))
    payload["runs"][0]["run_nonce_sha256"] = "1" * 64
    _write(negative, payload)

    with pytest.raises(adapter.StateResetEvidenceError, match="cleanup_nonce_collision"):
        adapter.derive_state_reset_evidence(execution, positive, negative, execution_adapter=fake)


def test_rejects_execution_evidence_that_self_admits_registry_reset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution, positive, negative, fake = _fixture_paths(tmp_path, monkeypatch)
    payload = json.loads(execution.read_text(encoding="utf-8"))
    payload["claim_boundary"]["registry_state_reset_admitted"] = True
    _write(execution, payload)

    with pytest.raises(adapter.StateResetEvidenceError, match="execution_evidence_cannot_self_admit_reset"):
        adapter.derive_state_reset_evidence(execution, positive, negative, execution_adapter=fake)


def test_rejects_execution_evidence_with_a_different_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    execution, positive, negative, fake = _fixture_paths(tmp_path, monkeypatch)
    payload = json.loads(execution.read_text(encoding="utf-8"))
    payload["execution_pair"] = {"pair": "forged", "raw_returned": False}
    _write(execution, payload)

    with pytest.raises(adapter.StateResetEvidenceError, match="execution_pair_does_not_match_receipts"):
        adapter.derive_state_reset_evidence(execution, positive, negative, execution_adapter=fake)


def test_refuses_to_overwrite_and_validation_cli_emits_fixed_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    execution, positive, negative, fake = _fixture_paths(tmp_path, monkeypatch)
    payload = adapter.derive_state_reset_evidence(
        execution, positive, negative, execution_adapter=fake
    )
    output = tmp_path / "evidence.json"
    adapter.write_new_output(output, payload)

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        adapter.write_new_output(output, payload)

    assert adapter.main(["validate", "--evidence", str(output)]) == 0
    assert capsys.readouterr().out.encode("utf-8") == adapter.canonical_json_bytes(
        adapter._validation_projection()
    )
