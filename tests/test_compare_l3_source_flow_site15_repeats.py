from __future__ import annotations

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, write_blueprint
from scripts.compare_l3_source_flow_slot_repeats import compare_source_flow_slot_repeats, write_comparison
from scripts.materialize_l3_source_flow_slot import materialize_slot
from scripts.stage_l3_generated_pair_source_triplets import stage_source_triplets


SLOT_ID = "site-15"


def _run(tmp_path, name: str):
    blueprint = tmp_path / f"{name}-blueprint.json"
    staging_root = tmp_path / f"{name}-stage"
    staging_receipt = tmp_path / f"{name}-staging.json"
    materialization_root = tmp_path / f"{name}-materialization"
    materialization_receipt = tmp_path / f"{name}-materialization.json"
    write_blueprint(blueprint)
    stage_source_triplets(blueprint, staging_root, staging_receipt)
    materialize_slot(
        slot_id=SLOT_ID,
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=staging_root,
        materialization_root=materialization_root,
        output=materialization_receipt,
    )
    return blueprint, staging_receipt, staging_root, materialization_root, materialization_receipt


def test_identical_site15_materializations_are_narrow_fix(tmp_path) -> None:
    first = _run(tmp_path, "first")
    second = _run(tmp_path, "second")
    result = compare_source_flow_slot_repeats(
        slot_id=SLOT_ID,
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


def test_site15_comparison_rejects_tamper_repository_inputs_and_existing_output(tmp_path) -> None:
    first = _run(tmp_path, "first")
    second = _run(tmp_path, "second")
    (
        first[3] / "slots" / SLOT_ID / "candidate-0" / "fixed" / "internal" / "checkout" / "orders.go"
    ).write_text("tampered\n", encoding="ascii")
    with pytest.raises(ValueError, match="source_flow_slot_materialization_source_content_invalid"):
        compare_source_flow_slot_repeats(
            slot_id=SLOT_ID,
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
    with pytest.raises(ValueError, match="source_flow_slot_repeat_inputs_must_be_external"):
        compare_source_flow_slot_repeats(
            slot_id=SLOT_ID,
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
    output = tmp_path / "comparison.json"
    output.write_text("existing\n", encoding="ascii")
    with pytest.raises(ValueError, match="refusing_to_overwrite_source_flow_slot_repeat_comparison"):
        write_comparison(output, {"schema": "example", "status": "FIX"})
