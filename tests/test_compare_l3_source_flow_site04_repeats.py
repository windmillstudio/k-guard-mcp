from __future__ import annotations

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, write_blueprint
from scripts.compare_l3_source_flow_site04_repeats import compare_site04_repeats, write_comparison
from scripts.materialize_l3_source_flow_site04 import materialize_site04
from scripts.stage_l3_generated_pair_source_triplets import stage_source_triplets


def _run(tmp_path, name: str):
    blueprint = tmp_path / f"{name}-blueprint.json"
    staging_root = tmp_path / f"{name}-stage"
    staging_receipt = tmp_path / f"{name}-staging.json"
    materialization_root = tmp_path / f"{name}-materialization"
    materialization_receipt = tmp_path / f"{name}-materialization.json"
    write_blueprint(blueprint)
    stage_source_triplets(blueprint, staging_root, staging_receipt)
    materialize_site04(
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=staging_root,
        materialization_root=materialization_root,
        output=materialization_receipt,
    )
    return blueprint, staging_receipt, staging_root, materialization_root, materialization_receipt


def test_identical_site04_materializations_are_narrow_fix(tmp_path) -> None:
    first = _run(tmp_path, "first")
    second = _run(tmp_path, "second")
    result = compare_site04_repeats(
        first_blueprint_path=first[0],
        first_staging_receipt_path=first[1],
        first_staging_root=first[2],
        first_materialization_root=first[3],
        first_receipt_path=first[4],
        second_blueprint_path=second[0],
        second_staging_receipt_path=second[1],
        second_staging_root=second[2],
        second_materialization_root=second[3],
        second_receipt_path=second[4],
    )
    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["authority"]["may_mark_field_fix"] is True
    assert result["authority"]["may_affect_other_slots"] is False
    assert result["claim_boundary"]["execution_oracles_proved"] is False


def test_comparison_rejects_tamper_repository_inputs_and_existing_output(tmp_path) -> None:
    first = _run(tmp_path, "first")
    second = _run(tmp_path, "second")
    (first[3] / "slots" / "site-04" / "candidate-0" / "fixed" / "app" / "api" / "report" / "route.ts").write_text(
        "tampered\n", encoding="ascii"
    )
    with pytest.raises(ValueError, match="site04_materialization_source_content_invalid"):
        compare_site04_repeats(
            first_blueprint_path=first[0],
            first_staging_receipt_path=first[1],
            first_staging_root=first[2],
            first_materialization_root=first[3],
            first_receipt_path=first[4],
            second_blueprint_path=second[0],
            second_staging_receipt_path=second[1],
            second_staging_root=second[2],
            second_materialization_root=second[3],
            second_receipt_path=second[4],
        )

    with pytest.raises(ValueError, match="site04_repeat_inputs_must_be_external"):
        compare_site04_repeats(
            first_blueprint_path=REPOSITORY_ROOT / "blueprint.json",
            first_staging_receipt_path=first[1],
            first_staging_root=first[2],
            first_materialization_root=first[3],
            first_receipt_path=first[4],
            second_blueprint_path=second[0],
            second_staging_receipt_path=second[1],
            second_staging_root=second[2],
            second_materialization_root=second[3],
            second_receipt_path=second[4],
        )

    result = {"schema": "example", "status": "FIX"}
    with pytest.raises(ValueError, match="site04_repeat_output_must_be_external"):
        write_comparison(REPOSITORY_ROOT / "comparison.json", result)
    output = tmp_path / "comparison.json"
    output.write_text("existing\n", encoding="ascii")
    with pytest.raises(ValueError, match="refusing_to_overwrite_site04_repeat_comparison"):
        write_comparison(output, result)
