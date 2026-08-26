from __future__ import annotations

import copy

import pytest

from scripts import aggregate_l3_source_flow as aggregate
from scripts.compare_l3_source_flow_aggregate_repeats import compare_aggregate_repeats, write_comparison
from tests.test_aggregate_l3_source_flow import _input_with_evidence


def _build(tmp_path, name: str):
    input_path, _ = _input_with_evidence(tmp_path, name)
    output_path = tmp_path / name / "aggregate.json"
    return output_path, aggregate.build_aggregate(input_path, output_path)


def test_identical_aggregate_runs_are_a_narrow_fix(tmp_path) -> None:
    first_path, _ = _build(tmp_path, "first")
    second_path, _ = _build(tmp_path, "second")

    result = compare_aggregate_repeats(first_path, second_path)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["authority"]["may_affect_h100_or_release"] is False
    assert result["claim_boundary"]["execution_oracles_proved"] is False
    assert result["raw_returned"] is False


def test_semantic_difference_holds_and_output_refuses_overwrite(tmp_path) -> None:
    first_path, _ = _build(tmp_path, "first")
    second_path, second = _build(tmp_path, "second")
    tampered = copy.deepcopy(second)
    tampered["leaf_evidence"][0]["source_comparison"]["semantic_fingerprint_sha256"] = "0" * 64
    tampered["aggregate_sha256"] = aggregate.sha256_bytes(
        aggregate.canonical_json_bytes({key: value for key, value in tampered.items() if key != "aggregate_sha256"})
    )
    second_path.write_bytes(aggregate.canonical_json_bytes(tampered))

    result = compare_aggregate_repeats(first_path, second_path)
    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False

    output = tmp_path / "comparison.json"
    output.write_text("existing\n", encoding="ascii")
    with pytest.raises(ValueError, match="output_must_be_new_external_path"):
        write_comparison(output, result)


def test_rejects_same_input_and_repository_output(tmp_path) -> None:
    first_path, _ = _build(tmp_path, "first")
    with pytest.raises(ValueError, match="inputs_must_be_independent"):
        compare_aggregate_repeats(first_path, first_path)
    with pytest.raises(ValueError, match="output_must_be_new_external_path"):
        write_comparison(aggregate.REPOSITORY_ROOT / "aggregate-comparison.json", {"schema": "example"})
