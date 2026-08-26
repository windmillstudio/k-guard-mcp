import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "derive_l2_webgoat_missing_function_ac_cvss_evidence.py"
SPEC = importlib.util.spec_from_file_location(
    "k_guard_l2_webgoat_missing_function_ac_cvss_evidence_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


def _sha(character: str) -> str:
    return character * 64


def _selector() -> dict:
    return {
        "root_cause": (
            "upstream-test:org.owasp.webgoat.integration."
            "AccessControlIntegrationTest#testLesson"
        ),
        "source_path": (
            "src/it/java/org/owasp/webgoat/integration/"
            "AccessControlIntegrationTest.java"
        ),
        "source_line": 15,
        "source_content_sha256": _sha("a"),
        "source_root_cause_identity": _sha("b"),
        "scenario_id": (
            "webgoat:upstream-test-org-owasp-webgoat-integration-"
            "accesscontrolintegrationtest-testlesson:deadbeefdeadbeef"
        ),
        "raw_returned": False,
    }


def _patch_dependencies(monkeypatch: pytest.MonkeyPatch, *, score: str = adapter.SCORE) -> None:
    selector = _selector()
    cwe = {
        "source": {"selector": selector},
        "classification": {
            "cwe": {"id": "CWE-266"},
            "mechanism_truth": "present",
            "cvss_v4": None,
            "expected_disposition": None,
        },
        "claim_boundary": {
            "source_bound_cwe_mapping_supported": True,
            "source_bound_mechanism_truth_supported": True,
            "source_bound_cvss_profile_proven": False,
            "customer_deployment_severity_admitted": False,
        },
    }
    execution = {
        "source": {"selector": copy.deepcopy(selector)},
        "claim_boundary": {
            "execution_result_pair_proven": True,
            "source_bound_execution_selector_proven": True,
            "severity_or_cwe_admitted": False,
            "registry_evidence_integrated": False,
            "release_gate_admitted": False,
        },
    }
    calculator = {
        "id": adapter.EXPECTED_CALCULATOR_ID,
        "binding_sha256": _sha("e"),
        "source_receipt_sha256": _sha("f"),
    }
    monkeypatch.setattr(adapter, "_load_cwe_evidence", lambda _path: (cwe, _sha("1"), _sha("2")))
    monkeypatch.setattr(
        adapter, "_load_execution_evidence", lambda _path: (execution, _sha("3"), _sha("4"))
    )
    monkeypatch.setattr(
        adapter, "_calculator_provenance", lambda _root, _receipt: (calculator, _sha("5"))
    )
    monkeypatch.setattr(adapter, "_calculate_score", lambda _root: score)


def test_derives_exact_raw_free_benchmark_cvss_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_dependencies(monkeypatch)

    payload = adapter.derive_cvss_evidence(
        tmp_path / "cwe.json", tmp_path / "execution.json", tmp_path, tmp_path / "calculator.json"
    )

    adapter.validate_cvss_evidence(payload)
    assert payload["adapter_status"] == "CVSS_PROFILE_EVIDENCE_PASS"
    assert payload["cvss_profile"]["vector"] == adapter.VECTOR
    assert payload["cvss_profile"]["score"] == "7.1"
    assert payload["cvss_profile"]["severity"] == "high"
    assert payload["cvss_profile"]["expected_disposition"] == "warn"
    assert payload["cvss_profile"]["metric_evidence"]["PR"] == (
        "authenticated_low_privilege_session_cookie"
    )
    assert payload["claim_boundary"]["customer_deployment_severity_admitted"] is False
    assert payload["release_gate_passed"] is False
    assert "stdout" not in json.dumps(payload, sort_keys=True)


def test_rejects_mismatched_source_selector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_dependencies(monkeypatch)
    cwe, cwe_hash, cwe_adapter_hash = adapter._load_cwe_evidence(tmp_path / "cwe.json")
    execution, execution_hash, execution_adapter_hash = adapter._load_execution_evidence(
        tmp_path / "execution.json"
    )
    execution["source"]["selector"]["scenario_id"] = "webgoat:forged:0"
    monkeypatch.setattr(
        adapter, "_load_cwe_evidence", lambda _path: (cwe, cwe_hash, cwe_adapter_hash)
    )
    monkeypatch.setattr(
        adapter,
        "_load_execution_evidence",
        lambda _path: (execution, execution_hash, execution_adapter_hash),
    )

    with pytest.raises(adapter.CvssEvidenceError, match="source_selector_mismatch"):
        adapter.derive_cvss_evidence(
            tmp_path / "cwe.json", tmp_path / "execution.json", tmp_path, tmp_path / "calculator.json"
        )


def test_rejects_wrong_calculated_score(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_dependencies(monkeypatch, score="8.6")

    with pytest.raises(adapter.CvssEvidenceError, match="calculator_score_mismatch"):
        adapter.derive_cvss_evidence(
            tmp_path / "cwe.json", tmp_path / "execution.json", tmp_path, tmp_path / "calculator.json"
        )


def test_validator_rejects_forged_selector_profile_and_claim_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_dependencies(monkeypatch)
    payload = adapter.derive_cvss_evidence(
        tmp_path / "cwe.json", tmp_path / "execution.json", tmp_path, tmp_path / "calculator.json"
    )

    forged = copy.deepcopy(payload)
    forged["source"]["selector"]["raw_returned"] = True
    with pytest.raises(adapter.CvssEvidenceError, match="cvss_evidence_source_invalid"):
        adapter.validate_cvss_evidence(forged)

    forged = copy.deepcopy(payload)
    forged["cvss_profile"]["calculator"]["id"] = "untrusted-calculator"
    with pytest.raises(adapter.CvssEvidenceError, match="cvss_evidence_calculator_invalid"):
        adapter.validate_cvss_evidence(forged)

    forged = copy.deepcopy(payload)
    forged["claim_boundary"]["customer_deployment_severity_admitted"] = True
    with pytest.raises(adapter.CvssEvidenceError, match="cvss_evidence_claim_boundary_invalid"):
        adapter.validate_cvss_evidence(forged)


def test_output_is_canonical_and_never_overwrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_dependencies(monkeypatch)
    payload = adapter.derive_cvss_evidence(
        tmp_path / "cwe.json", tmp_path / "execution.json", tmp_path, tmp_path / "calculator.json"
    )
    output = tmp_path / "evidence.json"

    adapter.write_new_output(output, payload)
    assert output.read_bytes() == adapter.canonical_json_bytes(payload)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        adapter.write_new_output(output, payload)
