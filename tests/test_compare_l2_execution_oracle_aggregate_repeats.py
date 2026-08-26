from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
AGGREGATOR_SCRIPT = ROOT / "scripts" / "aggregate_l2_execution_oracles.py"
COMPARATOR_SCRIPT = ROOT / "scripts" / "compare_l2_execution_oracle_aggregate_repeats.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


aggregate = _load("aggregate_l2_execution_oracles_for_repeat_test", AGGREGATOR_SCRIPT)
comparison = _load("compare_l2_execution_oracle_aggregate_repeats_test", COMPARATOR_SCRIPT)


def _write(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(aggregate.canonical_json_bytes(payload))


def _sha(label: str) -> str:
    return aggregate.hashlib.sha256(label.encode("utf-8")).hexdigest()


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
        for role in aggregate.EXPECTED_COMPONENT_ROLES:
            component = spec["components"][role]
            payload: dict[str, object] = {
                "schema": component["schema"],
                "status": "FIX",
                "repeat_exact": True,
                "raw_returned": False,
                "authority": {
                    "may_mark_field_fix": True,
                    "may_affect_oracle_labels": False,
                    "may_affect_performance_metrics": False,
                    "may_affect_h100_or_release": False,
                },
                "first_receipt_sha256": _sha(f"{app_id}-{role}-first"),
                "second_receipt_sha256": _sha(f"{app_id}-{role}-second"),
                "first_semantic_fingerprint_sha256": _sha(f"{app_id}-{role}-semantic"),
                "second_semantic_fingerprint_sha256": _sha(f"{app_id}-{role}-semantic"),
            }
            if role == "supervisor":
                payload["field_id"] = component["field_id"]
                payload["run_count"] = 2
            _write(evidence_root / component["path"], payload)
    registry = evidence_root / "phase2-p23a" / "materialization-r2.json"
    _write(
        registry,
        {
            "schema": aggregate.SOURCE_REGISTRY_SCHEMA,
            "expected_app_count": 6,
            "materialized_app_count": 6,
            "source_license_admission": "PASS",
            "isolation_contract_declared": "PASS",
            "phase_2_status": "HOLD",
            "release_gate_passed": False,
            "raw_returned": False,
            "apps": apps,
        },
    )
    return evidence_root, registry


def test_compares_two_identical_measurements(tmp_path: Path) -> None:
    evidence_root, registry = _build_evidence(tmp_path)
    first = tmp_path / "external-output" / "first.json"
    second = tmp_path / "external-output" / "second.json"
    aggregate.write_measurement(first, aggregate.build_aggregate(evidence_root, registry))
    aggregate.write_measurement(second, aggregate.build_aggregate(evidence_root, registry))

    result = comparison.compare_measurements(first, second)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["authority"]["may_mark_field_fix"] is True
    assert result["authority"]["may_affect_h100_or_release"] is False


def test_returns_hold_when_component_evidence_changes_between_runs(tmp_path: Path) -> None:
    evidence_root, registry = _build_evidence(tmp_path)
    first = tmp_path / "external-output" / "first.json"
    second = tmp_path / "external-output" / "second.json"
    first_payload = aggregate.build_aggregate(evidence_root, registry)
    second_payload = aggregate.build_aggregate(evidence_root, registry)
    second_payload["apps"][0]["comparators"][0]["sha256"] = "0" * 64
    aggregate.write_measurement(first, first_payload)
    aggregate.write_measurement(second, second_payload)

    result = comparison.compare_measurements(first, second)

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False
    assert result["authority"]["may_mark_field_fix"] is False


def test_refuses_repository_or_existing_comparison_output(tmp_path: Path) -> None:
    evidence_root, registry = _build_evidence(tmp_path)
    first = tmp_path / "external-output" / "first.json"
    second = tmp_path / "external-output" / "second.json"
    aggregate.write_measurement(first, aggregate.build_aggregate(evidence_root, registry))
    aggregate.write_measurement(second, aggregate.build_aggregate(evidence_root, registry))
    result = comparison.compare_measurements(first, second)

    with pytest.raises(ValueError, match="aggregate_comparison_output_must_be_external"):
        comparison.write_comparison(ROOT / "aggregate-comparison.json", result)

    output = tmp_path / "external-output" / "comparison.json"
    output.write_text("existing\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing_to_overwrite"):
        comparison.write_comparison(output, result)
