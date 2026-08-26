from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts import aggregate_l3_source_flow as aggregate


def _digest(seed: str) -> str:
    return aggregate.sha256_bytes(seed.encode("ascii"))


def _source_comparison(slot_id: str) -> dict[str, object]:
    fingerprint = _digest(f"source:{slot_id}")
    return {
        "schema": "k_guard_l3_source_flow_slot_repeat_comparison.v2",
        "slot_id": slot_id,
        "first_semantic_fingerprint_sha256": fingerprint,
        "second_semantic_fingerprint_sha256": fingerprint,
        "repeat_exact": True,
        "status": "FIX",
        "authority": {
            "may_mark_field_fix": True,
            "may_affect_other_slots": False,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "claim_boundary": {
            "source_triplets_materialized": True,
            "execution_oracles_proved": False,
            "detector_accuracy_proven": False,
            "release_gate_admitted": False,
        },
        "raw_source_returned": False,
    }


def _supervisor_comparison(slot_id: str) -> dict[str, object]:
    fingerprint = _digest(f"supervisor:{slot_id}")
    return {
        "schema": "k_guard_supervisor_repeat_comparison.v1",
        "field_id": f"p2.4b.{slot_id}.source-flow",
        "first_semantic_fingerprint_sha256": fingerprint,
        "second_semantic_fingerprint_sha256": fingerprint,
        "repeat_exact": True,
        "status": "FIX",
        "authority": {
            "may_mark_field_fix": True,
            "may_affect_oracle_labels": False,
            "may_affect_performance_metrics": False,
            "may_affect_h100_or_release": False,
        },
        "raw_returned": False,
    }


def _write_canonical(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(aggregate.canonical_json_bytes(value))
    return path


def _input_with_evidence(tmp_path: Path, name: str) -> tuple[Path, list[dict[str, str]]]:
    evidence_dir = tmp_path / name / "evidence"
    leaves: list[dict[str, str]] = []
    for slot_id in aggregate.SLOT_ORDER:
        source = _write_canonical(evidence_dir / f"{slot_id}-source.json", _source_comparison(slot_id))
        supervisor = _write_canonical(evidence_dir / f"{slot_id}-supervisor.json", _supervisor_comparison(slot_id))
        leaves.append(
            {
                "slot_id": slot_id,
                "source_comparison_path": str(source.resolve()),
                "supervisor_comparison_path": str(supervisor.resolve()),
            }
        )
    input_path = tmp_path / name / "input.json"
    _write_canonical(
        input_path,
        {"schema": aggregate.INPUT_SCHEMA, "leaves": leaves, "raw_returned": False},
    )
    return input_path, leaves


def test_builds_a_raw_free_fixed_order_aggregate(tmp_path: Path) -> None:
    input_path, _ = _input_with_evidence(tmp_path, "first")
    output_path = tmp_path / "first" / "aggregate.json"

    result = aggregate.build_aggregate(input_path, output_path)

    assert result["slot_order"] == list(aggregate.SLOT_ORDER)
    assert result["counts"] == aggregate.EXPECTED_COUNTS
    assert result["excluded_slot_ids"] == []
    assert result["claim_boundary"]["execution_oracles_proved"] is False
    assert aggregate.load_aggregate(output_path) == result
    serialized = json.dumps(result, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "source_comparison_path" not in serialized
    assert "supervisor_comparison_path" not in serialized


def test_rejects_cross_role_evidence_reuse_and_scope_or_raw_drift(tmp_path: Path) -> None:
    input_path, leaves = _input_with_evidence(tmp_path, "overlap")
    overlapping = copy.deepcopy(leaves)
    overlapping[1]["supervisor_comparison_path"] = overlapping[0]["source_comparison_path"]
    overlap_input = tmp_path / "overlap" / "overlap-input.json"
    _write_canonical(overlap_input, {"schema": aggregate.INPUT_SCHEMA, "leaves": overlapping, "raw_returned": False})
    with pytest.raises(aggregate.SourceFlowAggregateError, match="evidence_path_overlap"):
        aggregate.build_aggregate(overlap_input, tmp_path / "overlap" / "aggregate.json")

    raw_path = Path(leaves[0]["source_comparison_path"])
    raw = json.loads(raw_path.read_text(encoding="utf-8"))
    raw["raw_source_returned"] = True
    raw_path.write_bytes(aggregate.canonical_json_bytes(raw))
    with pytest.raises(aggregate.SourceFlowAggregateError, match="source_comparison_raw_invalid"):
        aggregate.build_aggregate(input_path, tmp_path / "overlap" / "raw.json")

    raw["raw_source_returned"] = False
    raw["authority"]["may_affect_other_slots"] = True
    raw_path.write_bytes(aggregate.canonical_json_bytes(raw))
    with pytest.raises(aggregate.SourceFlowAggregateError, match="authority_slot_scope_invalid"):
        aggregate.build_aggregate(input_path, tmp_path / "overlap" / "scope.json")


def test_rejects_tampered_result_and_existing_or_repository_output(tmp_path: Path) -> None:
    input_path, _ = _input_with_evidence(tmp_path, "tamper")
    output_path = tmp_path / "tamper" / "aggregate.json"
    result = aggregate.build_aggregate(input_path, output_path)
    tampered = copy.deepcopy(result)
    tampered["counts"]["source_file_count"] = 0
    output_path.write_bytes(aggregate.canonical_json_bytes(tampered))
    with pytest.raises(aggregate.SourceFlowAggregateError, match="denominator_invalid"):
        aggregate.load_aggregate(output_path)

    existing_output = tmp_path / "tamper" / "existing.json"
    existing_output.write_text("existing\n", encoding="ascii")
    with pytest.raises(aggregate.SourceFlowAggregateError, match="output_must_be_new_external_path"):
        aggregate.build_aggregate(input_path, existing_output)
    with pytest.raises(aggregate.SourceFlowAggregateError, match="output_must_be_new_external_path"):
        aggregate.build_aggregate(input_path, aggregate.REPOSITORY_ROOT / "aggregate.json")
