from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.compare_l3_source_flow_slot_repeats import compare_source_flow_slot_repeats, write_comparison
from scripts.materialize_l3_source_flow_slot import (
    LEGACY_WHOLE_MODULE_SHA256_BY_SLOT,
    SCHEMA_V1,
    VERSION_V1,
    load_materialization_receipt,
    materialize_slot,
)
from scripts.stage_l3_generated_pair_source_triplets import stage_source_triplets


SLOT_ID = "data-03"


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


def test_identical_data03_materializations_are_narrow_fix(tmp_path) -> None:
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
    assert result["schema"] == "k_guard_l3_source_flow_slot_repeat_comparison.v2"
    assert "materializer_sha256" not in result
    assert result["materializer_identity"]["slot_id"] == SLOT_ID
    assert result["authority"]["may_mark_field_fix"] is True
    assert result["authority"]["may_affect_other_slots"] is False
    assert result["claim_boundary"]["execution_oracles_proved"] is False


def test_data03_v1_and_v2_receipts_compare_under_explicit_migration_identity(tmp_path) -> None:
    first = _run(tmp_path, "first")
    second = _run(tmp_path, "second")
    first_receipt = load_materialization_receipt(
        slot_id=SLOT_ID,
        blueprint_path=first[0],
        staging_receipt_path=first[1],
        staging_root=first[2],
        materialization_root=first[3],
        receipt_path=first[4],
    )
    legacy = copy.deepcopy(first_receipt)
    legacy["schema"] = SCHEMA_V1
    legacy["version"] = VERSION_V1
    legacy.pop("materializer_identity")
    legacy["materializer_sha256"] = next(iter(LEGACY_WHOLE_MODULE_SHA256_BY_SLOT[SLOT_ID]))
    first[4].write_bytes(canonical_json_bytes(legacy))

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
    assert result["input_receipt_schemas"] == {
        "first": {"schema": SCHEMA_V1, "version": VERSION_V1},
        "second": {"schema": "k_guard_l3_source_flow_slot_materialization.v2", "version": "2.0.0"},
    }
    assert result["legacy_receipt_migration_verified"] is True
    assert result["authority"]["may_mark_field_fix"] is False
    assert result["authority"]["may_revalidate_legacy_evidence"] is True


def test_data03_comparison_rejects_tamper_repository_inputs_and_existing_output(tmp_path) -> None:
    first = _run(tmp_path, "first")
    second = _run(tmp_path, "second")
    (
        first[3] / "slots" / SLOT_ID / "candidate-0" / "fixed" / "src" / "data" / "checkout" / "orders.ts"
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
