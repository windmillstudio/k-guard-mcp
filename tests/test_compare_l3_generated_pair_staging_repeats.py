from __future__ import annotations

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, write_blueprint
from scripts.compare_l3_generated_pair_staging_repeats import (
    compare_staging_repeats,
    write_comparison,
)
from scripts.stage_l3_generated_pair_source_triplets import stage_source_triplets


def _run(tmp_path, name: str):
    blueprint = tmp_path / f"{name}-blueprint.json"
    stage_root = tmp_path / f"{name}-stage"
    receipt = tmp_path / f"{name}-receipt.json"
    write_blueprint(blueprint)
    stage_source_triplets(blueprint, stage_root, receipt)
    return blueprint, stage_root, receipt


def test_identical_staging_runs_are_narrow_fix(tmp_path) -> None:
    first_blueprint, first_stage_root, first_receipt = _run(tmp_path, "first")
    second_blueprint, second_stage_root, second_receipt = _run(tmp_path, "second")

    result = compare_staging_repeats(
        first_receipt_path=first_receipt,
        first_blueprint_path=first_blueprint,
        first_stage_root=first_stage_root,
        second_receipt_path=second_receipt,
        second_blueprint_path=second_blueprint,
        second_stage_root=second_stage_root,
    )

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["authority"]["may_mark_field_fix"] is True
    assert result["authority"]["may_affect_h100_or_release"] is False
    assert result["claim_boundary"]["source_triplets_materialized"] is False


def test_comparison_refuses_repository_inputs_and_existing_output(tmp_path) -> None:
    first_blueprint, first_stage_root, first_receipt = _run(tmp_path, "first")
    second_blueprint, second_stage_root, second_receipt = _run(tmp_path, "second")
    result = compare_staging_repeats(
        first_receipt_path=first_receipt,
        first_blueprint_path=first_blueprint,
        first_stage_root=first_stage_root,
        second_receipt_path=second_receipt,
        second_blueprint_path=second_blueprint,
        second_stage_root=second_stage_root,
    )

    with pytest.raises(ValueError, match="staging_comparison_inputs_must_be_external"):
        compare_staging_repeats(
            first_receipt_path=REPOSITORY_ROOT / "receipt.json",
            first_blueprint_path=first_blueprint,
            first_stage_root=first_stage_root,
            second_receipt_path=second_receipt,
            second_blueprint_path=second_blueprint,
            second_stage_root=second_stage_root,
        )
    with pytest.raises(ValueError, match="staging_comparison_output_must_be_external"):
        write_comparison(REPOSITORY_ROOT / "comparison.json", result)

    output = tmp_path / "comparison.json"
    output.write_text("existing\n", encoding="ascii")
    with pytest.raises(ValueError, match="refusing_to_overwrite_staging_comparison"):
        write_comparison(output, result)
