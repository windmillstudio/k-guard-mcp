from __future__ import annotations

import json
import importlib.metadata
from pathlib import Path

import pytest

from k_guard_mcp import release_qualification as qualification
from k_guard_mcp.provenance import evidence_bundle, object_artifact, source_tree_snapshot
from k_guard_mcp.control_validation import run_control_validation
from k_guard_mcp.release_qualification import evaluate_release_qualification
from k_guard_mcp.language_validation import PINNED_SEMGREP_VERSION, REQUIRED_LANGUAGES, current_language_validation_contract
from k_guard_mcp.mcp_http_proxy import mcp_http_proxy_toolchain_contract
from k_guard_mcp.guardian import guardian_toolchain_contract


OPERATOR_KEY = "qualification-test-operator-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _seal(report: dict, label: str, role: str) -> dict:
    report["evidence_bundle"] = evidence_bundle(
        subject=label,
        producer="qualification-test",
        artifacts=[object_artifact(label, report, role=role)],
    )
    return report


def _deep(snapshot: dict) -> dict:
    hashes = current_language_validation_contract()["hashes"]
    return _seal(
        {
            "schema": "k_guard_analyzer_run.v1",
            "complete": True,
            "control_errors": [],
            "findings": [],
            "analyzer": "semgrep",
            "executable_version": PINNED_SEMGREP_VERSION,
            "analyzer_subtype": "semgrep-ce-intrafile",
            "profile_name": "semgrep-deep.yml",
            "adapter_sha256": hashes["adapter_sha256"],
            "profile_sha256": hashes["profile_sha256"],
            "rules_sha256": hashes["profile_rules_sha256"],
            "command_contract_sha256": hashes["adapter_command_contract_sha256"],
            "input_snapshot": snapshot,
            "raw_free": True,
        },
        "analyzer-run",
        "analysis",
    )


def _language() -> dict:
    requirements = {
        "all_expected_positives_found": True,
        "zero_clean_case_false_positives": True,
        "exact_repeat_fingerprint_multiset": True,
        "all_nine_languages": True,
        "minimum_five_vulnerable_and_five_clean_per_language": True,
        "all_five_categories_per_language_and_outcome": True,
        "all_findings_mapped": True,
        "bundled_profile_exact": True,
        "analyzer_complete": True,
    }
    return _seal(
        {
            "schema": "k_guard_language_validation_report.v1",
            "complete": True,
            "ready": True,
            "status": "development_validation_ready",
            "languages": list(REQUIRED_LANGUAGES),
            "metrics": {"overall": {"confusion_matrix": {"tp": 45, "fn": 0, "fp": 0, "tn": 45}}},
            "repeat": {"exact": True},
            "requirements": requirements,
            "hashes": current_language_validation_contract()["hashes"],
            "analyzer_runs": [
                {"input_snapshot_complete": True, "input_tree_sha256": "a" * 64},
                {"input_snapshot_complete": True, "input_tree_sha256": "a" * 64},
            ],
            "raw_free": True,
        },
        "language-validation-report",
        "validation",
    )


def _runtime() -> dict:
    toolchain = mcp_http_proxy_toolchain_contract()
    return _seal(
        {
            "schema": "k_guard_mcp_http_proxy_report.v1",
            "transport": "streamable_http",
            "complete": True,
            "passed": True,
            "control_errors": [],
            "control_status": "completed",
            "finding_count": 0,
            "execution": {"runtime_exercised": True, "toolchain_sha256": toolchain["sha256"], "toolchain_contract": toolchain},
            "enforcement_contract": {
                "client_to_server": "inspect_block_or_redact_before_forward",
                "server_to_client": "inspect_block_or_redact_before_forward",
                "fail_closed_on_control_gap": True,
            },
            "policy": {
                "settings": {"require_origin": True, "forward_authorization": False},
                "audit_persistence": {"configured": True, "healthy": True, "fail_closed_on_error": True},
            },
            "access_control": {
                "schema": "k_guard_access_controller_summary.v1",
                "complete": True,
                "default_action": "deny",
                "audit": {
                    "enabled": True,
                    "error_count": 0,
                    "entry_count": 12,
                    "last_entry_sha256": "b" * 64,
                },
            },
            "counts": {
                "access_decisions_allow": 5,
                "access_decisions_deny": 1,
                "access_tool_lists_filtered": 1,
                "requests_post": 3,
                "requests_get": 1,
                "requests_delete": 1,
                "json_responses_forwarded": 1,
                "sse_streams_forwarded": 1,
                "sse_events_forwarded": 2,
                "server_requests_correlated": 1,
                "sessions_deleted": 1,
            },
            "runtime_validation": {
                "schema": "k_guard_mcp_http_runtime_validation.v1",
                "profile": "synthetic_streamable_http_complete_mediation",
                "complete": True,
                "passed": True,
                "run_count": 2,
                "repeat_exact": True,
                "matrix_projection_sha256": "c" * 64,
                "checks": {"matrix_complete": True, "audit_chain_verified": True},
                "official_sdk_interoperability": {
                    "passed": True,
                    "sdk": "mcp-python-sdk",
                    "sdk_version": importlib.metadata.version("mcp"),
                    "checks": {"initialize": True, "tools_call": True},
                },
            },
            "raw_free": True,
        },
        "runtime-report",
        "runtime",
    )


def _field() -> dict:
    report = {
        "schema": "k_guard_field_validation.v1",
        "method": "ground_truth_field_validation",
        "toolchain_contract": guardian_toolchain_contract(),
        "profile": "field",
        "evidence_tier": "field",
        "raw_free": True,
        "sample": {"app_count": 12},
        "verdict_counts": {},
        "case_counts": {},
        "metric_contract": {},
        "rates": {},
        "rates_confidence_intervals": {},
        "holdout": {},
        "holdout_candidate_rates": {},
        "evaluation": {},
        "reproducibility": {},
        "repeat_guardian_source": {},
        "field_preregistration": {
            "roster_ready": True,
            "roster_signed": True,
            "roster_target_binding": True,
            "roster_row_count": 12,
        },
        "field_roster_source": {},
        "primary_guardian_evidence": {},
        "repeat_guardian_evidence": {},
        "thresholds": {},
        "gate_checks": [{"name": "all", "passed": True}],
        "claim_status": "field_validation_ready",
        "candidate_app_refs": [],
        "candidate_target_refs": [],
        "candidate_finding_refs": [],
        "evaluation_app_refs": [],
        "evaluation_target_refs": [],
    }
    report["validation_evidence_envelope"] = evidence_bundle(
        subject="field_validation_review",
        producer="qualification-test",
        artifacts=[object_artifact("field_validation_projection", report, role="gate")],
    )
    return report


def _sca(snapshot: dict) -> dict:
    return _seal(
        {
            "schema": "k_guard_sca_run.v1",
            "complete": True,
            "passed": True,
            "control_errors": [],
            "requested_ecosystems": [],
            "audited_ecosystems": [],
            "findings": [],
            "adapters": [],
            "input_snapshot": snapshot,
            "inventory": {
                "manifest_count": 0,
                "lock_count": 0,
                "uncovered_manifest_count": 0,
                "raw_returned": False,
            },
            "counts": {"finding_count": 0, "audited_ecosystem_count": 0},
            "raw_free": True,
        },
        "sca-run",
        "analysis",
    )


def _write(path: Path, report: dict) -> Path:
    path.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    return path


def test_all_release_qualification_gates_require_bound_operator_evidence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", OPERATOR_KEY)
    workspace = tmp_path / "app"
    workspace.mkdir()
    (workspace / "app.py").write_text("def health():\n    return 'ok'\n", encoding="utf-8")
    snapshot = source_tree_snapshot(workspace)

    report = evaluate_release_qualification(
        deep_analyzer_reports=[_deep(snapshot)],
        sca_reports=[_sca(snapshot)],
        language_validation_report_path=_write(tmp_path / "language.json", _language()),
        mcp_http_proxy_report_path=_write(tmp_path / "runtime.json", _runtime()),
        field_validation_report_path=_write(tmp_path / "field.json", _field()),
        control_validation_report_path=_write(tmp_path / "controls.json", run_control_validation()),
        workspace_snapshots={"app": snapshot},
        current_guardian_toolchain=guardian_toolchain_contract(),
    )

    assert report["passed"] is True
    assert all(gate["passed"] is True for gate in report["gates"].values())
    assert report["missing_inputs"] == []


def test_qualification_fails_closed_on_source_drift_public_signature_and_missing_field(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", OPERATOR_KEY)
    workspace = tmp_path / "app"
    workspace.mkdir()
    source = workspace / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    old_snapshot = source_tree_snapshot(workspace)
    runtime_path = _write(tmp_path / "runtime.json", _runtime())
    source.write_text("value = 2\n", encoding="utf-8")
    current_snapshot = source_tree_snapshot(workspace)

    monkeypatch.delenv("K_GUARD_EVIDENCE_HMAC_KEY")
    public_language = _write(tmp_path / "public-language.json", _language())
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", OPERATOR_KEY)
    report = evaluate_release_qualification(
        deep_analyzer_reports=[_deep(old_snapshot)],
        sca_reports=[_sca(current_snapshot)],
        language_validation_report_path=public_language,
        mcp_http_proxy_report_path=runtime_path,
        field_validation_report_path=None,
        control_validation_report_path=_write(tmp_path / "controls.json", run_control_validation()),
        workspace_snapshots={"app": current_snapshot},
        current_guardian_toolchain=guardian_toolchain_contract(),
    )

    assert report["passed"] is False
    assert report["gates"]["deep_multilang"]["passed"] is False
    assert "deep_source_snapshot_current" in report["gates"]["deep_multilang"]["failed_checks"]
    assert "language_operator_signature" in report["gates"]["deep_multilang"]["failed_checks"]
    assert report["gates"]["field_accuracy"]["passed"] is False
    assert report["missing_inputs"] == ["field_validation_report"]


def test_deep_qualification_rejects_wrong_semgrep_executable_version(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", OPERATOR_KEY)
    workspace = tmp_path / "app"
    workspace.mkdir()
    (workspace / "app.py").write_text("value = 1\n", encoding="utf-8")
    snapshot = source_tree_snapshot(workspace)
    deep = _deep(snapshot)
    deep["executable_version"] = "0.0.1"
    deep.pop("evidence_bundle", None)
    _seal(deep, "analyzer-run", "analysis")

    report = evaluate_release_qualification(
        deep_analyzer_reports=[deep],
        sca_reports=[_sca(snapshot)],
        language_validation_report_path=_write(tmp_path / "language.json", _language()),
        mcp_http_proxy_report_path=_write(tmp_path / "runtime.json", _runtime()),
        field_validation_report_path=_write(tmp_path / "field.json", _field()),
        control_validation_report_path=_write(tmp_path / "controls.json", run_control_validation()),
        workspace_snapshots={"app": snapshot},
        current_guardian_toolchain=guardian_toolchain_contract(),
    )

    assert report["gates"]["deep_multilang"]["passed"] is False
    assert "deep_current_toolchain" in report["gates"]["deep_multilang"]["failed_checks"]


@pytest.mark.parametrize(
    ("content", "expected_error"),
    [
        (b"", "size_invalid"),
        (b"[]", "schema_invalid"),
        (b"{", "invalid_json"),
        (b'{"same": 1, "same": 2}', "invalid_json"),
    ],
)
def test_release_report_loader_rejects_noncanonical_or_invalid_evidence(
    tmp_path: Path,
    content: bytes,
    expected_error: str,
) -> None:
    path = tmp_path / f"{expected_error}-{len(content)}.json"
    path.write_bytes(content)

    payload, error, artifact = qualification._load_report(path, "release-fixture")

    assert payload == {}
    assert error == expected_error
    assert artifact["role"] == "qualification_input"


def test_release_report_loader_rejects_missing_artifact(tmp_path: Path) -> None:
    payload, error, _artifact = qualification._load_report(
        tmp_path / "missing.json",
        "release-fixture",
    )

    assert payload == {}
    assert error == "missing_or_symlink"


def test_release_qualification_fails_closed_when_mcp_sdk_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_version(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(
        qualification.importlib.metadata,
        "version",
        missing_version,
    )
    monkeypatch.setattr(
        qualification,
        "mcp_http_proxy_toolchain_contract",
        lambda: {"complete": False},
    )

    checks = qualification._runtime_checks({}, "")

    sdk_check = next(
        check for check in checks if check["name"] == "runtime_official_sdk_interoperability"
    )
    assert sdk_check["passed"] is False


def test_release_qualification_redacts_opaque_observations_and_rejects_bad_bundles() -> None:
    class OpaqueObservation:
        pass

    check = qualification._check("opaque", False, OpaqueObservation())

    assert check["observed"] == "OpaqueObservation"
    assert qualification._bundle_has_artifact([], {}) is False
