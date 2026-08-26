from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import _domain_hash, build_blueprint, canonical_json_bytes, write_blueprint
from scripts.compare_l3_generated_pair_blueprint_repeats import REPOSITORY_ROOT, compare_blueprints, write_comparison


def _write_canonical(path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload))


def test_identical_blueprints_are_narrow_fix(tmp_path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    write_blueprint(first)
    write_blueprint(second)

    result = compare_blueprints(first, second)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["authority"]["may_mark_field_fix"] is True
    assert result["authority"]["may_affect_h100_or_release"] is False
    assert result["claim_boundary"]["source_triplets_materialized"] is False


def test_blueprint_drift_is_hold(tmp_path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    write_blueprint(first)
    modified = copy.deepcopy(build_blueprint())
    modified["slots"][0]["generator_profile"], modified["slots"][1]["generator_profile"] = (
        modified["slots"][1]["generator_profile"],
        modified["slots"][0]["generator_profile"],
    )
    unsigned = dict(modified)
    unsigned.pop("blueprint_sha256")
    modified["blueprint_sha256"] = _domain_hash(b"k_guard_l3_generated_pair_blueprint.v1\0", unsigned)
    _write_canonical(second, modified)

    result = compare_blueprints(first, second)

    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False
    assert result["authority"]["may_mark_field_fix"] is False


def test_comparison_refuses_repository_and_existing_output(tmp_path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    write_blueprint(first)
    write_blueprint(second)
    result = compare_blueprints(first, second)

    with pytest.raises(ValueError, match="blueprint_comparison_output_must_be_external"):
        write_comparison(REPOSITORY_ROOT / "inside.json", result)

    with pytest.raises(ValueError, match="blueprint_comparison_inputs_must_be_external"):
        compare_blueprints(REPOSITORY_ROOT / "first.json", second)

    output = tmp_path / "comparison.json"
    output.write_text("existing\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing_to_overwrite_blueprint_comparison"):
        write_comparison(output, result)
