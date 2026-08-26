from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "derive_l2_webgoat_idor_cwe_evidence.py"
SPEC = importlib.util.spec_from_file_location("k_guard_l2_webgoat_idor_cwe_evidence_test", SCRIPT)
assert SPEC and SPEC.loader
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


TEST_SOURCE = b'''public class IDORIntegrationTest {
  void init() { startLesson("IDOR"); }
  void read() { .get(webGoatUrlConfig.url("IDOR/profile/2342388")); }
  void attributes() { params.put("attributes", "userId,role"); }
  void mutate() { String body = "{\\"role\\":\\"1\\""; }
}
'''
IMPLEMENTATION_SOURCE = b'''@GetMapping(
    path = "/IDOR/profile/{userId}")
public AttackResult completed(@PathVariable("userId") String userId) {
  if (!userId.equals(authUserId)) {
    // horizontal access control check
    return requestedProfile.profileToMap().toString();
  }
}
'''


def _write(path: Path, payload: dict) -> bytes:
    raw = adapter.canonical_json_bytes(payload)
    path.write_bytes(raw)
    return raw


def _patch_selector(monkeypatch: pytest.MonkeyPatch) -> None:
    material = "\0".join(
        (
            adapter.SOURCE_LINEAGE_ID,
            adapter.TEST_PATH,
            str(adapter.TEST_LINE),
            adapter.TEST_CONTENT_SHA256,
        )
    )
    identity = adapter.sha256_bytes(
        ("k_guard_l2_source_root_cause.v1\0" + material).encode("utf-8")
    )
    scenario_id = (
        "webgoat:upstream-test-org-owasp-webgoat-integration-idorintegrationtest-testidorlesson:"
        + identity[:16]
    )
    monkeypatch.setattr(adapter, "SOURCE_ROOT_CAUSE_IDENTITY", identity)
    monkeypatch.setattr(adapter, "SCENARIO_ID", scenario_id)


def _fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    test_source: bytes = TEST_SOURCE,
    implementation_source: bytes = IMPLEMENTATION_SOURCE,
) -> tuple[Path, Path]:
    monkeypatch.setattr(adapter, "TEST_CONTENT_SHA256", adapter.sha256_bytes(test_source))
    monkeypatch.setattr(adapter, "TEST_BYTE_COUNT", len(test_source))
    monkeypatch.setattr(
        adapter, "IMPLEMENTATION_CONTENT_SHA256", adapter.sha256_bytes(implementation_source)
    )
    monkeypatch.setattr(adapter, "IMPLEMENTATION_BYTE_COUNT", len(implementation_source))
    _patch_selector(monkeypatch)
    receipt = {
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
        "files": [
            {
                "path": adapter.TEST_PATH,
                "sha256": adapter.TEST_CONTENT_SHA256,
                "byte_count": adapter.TEST_BYTE_COUNT,
            },
            {
                "path": adapter.IMPLEMENTATION_PATH,
                "sha256": adapter.IMPLEMENTATION_CONTENT_SHA256,
                "byte_count": adapter.IMPLEMENTATION_BYTE_COUNT,
            },
        ],
    }
    receipt_path = tmp_path / "source-receipt.json"
    raw = _write(receipt_path, receipt)
    monkeypatch.setattr(adapter, "SOURCE_RECEIPT_SHA256", adapter.sha256_bytes(raw))
    blobs = {
        adapter.TEST_PATH: test_source,
        adapter.IMPLEMENTATION_PATH: implementation_source,
    }
    monkeypatch.setattr(adapter, "_verify_source_root", lambda source_root: source_root)
    monkeypatch.setattr(adapter, "_read_source_blob", lambda _root, path: blobs[path])
    return tmp_path, receipt_path


def test_derives_raw_free_source_bound_cwe_and_mechanism_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root, receipt = _fixture(tmp_path, monkeypatch)

    payload = adapter.derive_cwe_evidence(source_root, receipt)

    adapter.validate_cwe_evidence(payload)
    assert payload["adapter_status"] == "CWE_MECHANISM_EVIDENCE_PASS"
    assert payload["classification"]["cwe"]["id"] == "CWE-639"
    assert payload["classification"]["mechanism_truth"] == "present"
    assert payload["classification"]["cvss_v4"] is None
    assert payload["classification"]["expected_disposition"] is None
    assert payload["classification"]["severity_status"] == "DEFERRED_NO_SOURCE_BOUND_CVSS_PROFILE"
    assert payload["claim_boundary"]["customer_deployment_severity_admitted"] is False
    assert payload["release_gate_passed"] is False
    rendered = json.dumps(payload, sort_keys=True)
    assert "requestedProfile.profileToMap" not in rendered
    assert "stdout" not in rendered


def test_rejects_a_missing_implementation_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broken = IMPLEMENTATION_SOURCE.replace(b"horizontal access control check", b"other comment")
    source_root, receipt = _fixture(tmp_path, monkeypatch, implementation_source=broken)

    with pytest.raises(adapter.CweEvidenceError, match="implementation_source_anchor_missing"):
        adapter.derive_cwe_evidence(source_root, receipt)


def test_rejects_source_receipt_without_the_implementation_blob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root, receipt_path = _fixture(tmp_path, monkeypatch)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["files"] = receipt["files"][:1]
    raw = _write(receipt_path, receipt)
    monkeypatch.setattr(adapter, "SOURCE_RECEIPT_SHA256", adapter.sha256_bytes(raw))

    with pytest.raises(adapter.CweEvidenceError, match="source_receipt_selector_not_bound"):
        adapter.derive_cwe_evidence(source_root, receipt_path)


def test_validator_rejects_forged_cwe_or_claim_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root, receipt = _fixture(tmp_path, monkeypatch)
    payload = adapter.derive_cwe_evidence(source_root, receipt)
    payload["classification"]["cwe"]["id"] = "CWE-862"

    with pytest.raises(adapter.CweEvidenceError, match="cwe_evidence_classification_invalid"):
        adapter.validate_cwe_evidence(payload)

    payload = adapter.derive_cwe_evidence(source_root, receipt)
    payload["claim_boundary"]["customer_deployment_severity_admitted"] = True
    with pytest.raises(adapter.CweEvidenceError, match="cwe_evidence_claim_boundary_invalid"):
        adapter.validate_cwe_evidence(payload)


def test_output_is_canonical_and_never_overwrites(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source_root, receipt = _fixture(tmp_path, monkeypatch)
    payload = adapter.derive_cwe_evidence(source_root, receipt)
    output = tmp_path / "evidence.json"

    adapter.write_new_output(output, payload)
    assert output.read_bytes() == adapter.canonical_json_bytes(payload)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        adapter.write_new_output(output, payload)
