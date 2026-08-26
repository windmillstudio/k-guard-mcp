from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "aggregate_l2_execution_oracles.py"
SPEC = importlib.util.spec_from_file_location("aggregate_l2_execution_oracles_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
aggregate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = aggregate
SPEC.loader.exec_module(aggregate)


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(aggregate.canonical_json_bytes(payload))


def _sha(label: str) -> str:
    return aggregate.hashlib.sha256(label.encode("utf-8")).hexdigest()


def _component_payload(spec: dict[str, object], role: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema": spec["schema"],
        "status": "FIX",
        "repeat_exact": True,
        "raw_returned": False,
        "authority": {
            "may_mark_field_fix": True,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "first_receipt_sha256": _sha(f"{role}-first"),
        "second_receipt_sha256": _sha(f"{role}-second"),
        "first_semantic_fingerprint_sha256": _sha(f"{role}-semantic"),
        "second_semantic_fingerprint_sha256": _sha(f"{role}-semantic"),
    }
    if role == "supervisor":
        payload["field_id"] = spec["field_id"]
        payload["run_count"] = 2
    return payload


def _build_evidence(tmp_path: Path) -> tuple[Path, Path]:
    evidence_root = tmp_path / "external-evidence"
    apps: list[dict[str, object]] = []
    for app_id in aggregate.EXPECTED_APP_IDS:
        spec = aggregate.APP_SPECS[app_id]
        apps.append(
            {
                "app_id": app_id,
                "source_tree_sha256": spec["source_tree_sha256"],
                "receipt_sha256": spec["source_receipt_sha256"],
                "receipt_semantic_sha256": _sha(f"{app_id}-source-semantic"),
                "source_license_admission": "PASS",
            }
        )
        components = spec["components"]
        for role in aggregate.EXPECTED_COMPONENT_ROLES:
            component_spec = components[role]
            _write(
                evidence_root / component_spec["path"],
                _component_payload(component_spec, role),
            )
    registry = evidence_root / "phase2-p23a" / "materialization-r2.json"
    _write(
        registry,
        {
            "schema": aggregate.SOURCE_REGISTRY_SCHEMA,
            "expected_app_count": len(aggregate.EXPECTED_APP_IDS),
            "materialized_app_count": len(aggregate.EXPECTED_APP_IDS),
            "source_license_admission": "PASS",
            "isolation_contract_declared": "PASS",
            "phase_2_status": "HOLD",
            "release_gate_passed": False,
            "raw_returned": False,
            "apps": apps,
        },
    )
    return evidence_root, registry


def test_builds_complete_six_app_measurement_without_release_claim(tmp_path: Path) -> None:
    evidence_root, registry = _build_evidence(tmp_path)

    result = aggregate.build_aggregate(evidence_root, registry)

    assert result["status"] == "MEASURED"
    assert result["aggregate_ready"] is True
    assert result["coverage"]["included_app_count"] == 6
    assert result["coverage"]["total_component_count"] == 18
    assert result["coverage"]["excluded_app_ids"] == []
    assert result["release_gate_passed"] is False
    assert result["claim_boundary"]["fresh_app_execution_proven"] is False
    aggregate.validate_measurement(result)


def test_rejects_missing_component_instead_of_excluding_the_app(tmp_path: Path) -> None:
    evidence_root, registry = _build_evidence(tmp_path)
    target = evidence_root / aggregate.APP_SPECS["webgoat"]["components"]["negative"]["path"]
    target.unlink()

    with pytest.raises(ValueError, match="webgoat_negative_path_invalid"):
        aggregate.build_aggregate(evidence_root, registry)


def test_rejects_component_with_raw_boundary_violation(tmp_path: Path) -> None:
    evidence_root, registry = _build_evidence(tmp_path)
    target = evidence_root / aggregate.APP_SPECS["crapi"]["components"]["positive"]["path"]
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["raw_returned"] = True
    target.write_bytes(aggregate.canonical_json_bytes(payload))

    with pytest.raises(ValueError, match="crapi_positive_raw_boundary_invalid"):
        aggregate.build_aggregate(evidence_root, registry)


def test_rejects_source_registry_binding_drift(tmp_path: Path) -> None:
    evidence_root, registry = _build_evidence(tmp_path)
    payload = json.loads(registry.read_text(encoding="utf-8"))
    payload["apps"][0]["receipt_sha256"] = "0" * 64
    registry.write_bytes(aggregate.canonical_json_bytes(payload))

    with pytest.raises(ValueError, match="crapi_source_registry_binding_invalid"):
        aggregate.build_aggregate(evidence_root, registry)


def test_refuses_repository_or_existing_output(tmp_path: Path) -> None:
    evidence_root, registry = _build_evidence(tmp_path)
    result = aggregate.build_aggregate(evidence_root, registry)

    with pytest.raises(ValueError, match="aggregate_output_must_be_external"):
        aggregate.write_measurement(ROOT / "aggregate.json", result)

    output = tmp_path / "external-output" / "aggregate.json"
    output.parent.mkdir(parents=True)
    output.write_text("existing\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing_to_overwrite"):
        aggregate.write_measurement(output, result)
