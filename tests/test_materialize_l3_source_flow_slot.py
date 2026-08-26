from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.materialize_l3_source_flow_slot import (
    CLAIM_BOUNDARY,
    SLOT_CONFIGS,
    load_materialization_receipt,
    materializer_identity,
    materialize_slot,
)
from scripts.stage_l3_generated_pair_source_triplets import stage_source_triplets


SLOT_ID = "site-02"


def _stage_inputs(tmp_path, name: str):
    blueprint = tmp_path / f"{name}-blueprint.json"
    stage_root = tmp_path / f"{name}-stage"
    staging_receipt = tmp_path / f"{name}-staging.json"
    write_blueprint(blueprint)
    stage_source_triplets(blueprint, stage_root, staging_receipt)
    return blueprint, stage_root, staging_receipt


def _materialize(tmp_path, name: str = "run"):
    blueprint, stage_root, staging_receipt = _stage_inputs(tmp_path, name)
    materialization_root = tmp_path / f"{name}-materialization"
    receipt = tmp_path / f"{name}-materialization.json"
    result = materialize_slot(
        slot_id=SLOT_ID,
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        output=receipt,
    )
    return blueprint, stage_root, staging_receipt, materialization_root, receipt, result


def test_materializes_only_site02_primary_and_reserve_source_triplets(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)

    assert receipt["slot_id"] == SLOT_ID
    assert receipt["counts"] == {
        "slot_count": 1,
        "candidate_count": 2,
        "primary_candidate_count": 1,
        "reserve_candidate_count": 1,
        "source_triplet_count": 6,
        "source_file_count": 18,
    }
    assert receipt["claim_boundary"] == CLAIM_BOUNDARY
    assert receipt["raw_source_returned"] is False
    vulnerable = materialization_root / "slots" / SLOT_ID / "candidate-0" / "vulnerable" / "routes" / "account.js"
    fixed = materialization_root / "slots" / SLOT_ID / "candidate-0" / "fixed" / "routes" / "account.js"
    negative = materialization_root / "slots" / SLOT_ID / "candidate-1" / "negative" / "routes" / "invoice.js"
    assert b"const sql" in vulnerable.read_bytes()
    assert b"+ email +" in vulnerable.read_bytes()
    assert b"db.query(\"SELECT id FROM records WHERE value = ?\", [email])" in fixed.read_bytes()
    assert b"[\"issued\"]" in negative.read_bytes()
    assert b"SELECT id FROM records" not in receipt_path.read_bytes()
    assert load_materialization_receipt(
        slot_id=SLOT_ID,
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        receipt_path=receipt_path,
    ) == receipt


def test_rejects_unregistered_slot_receipt_and_source_tree_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt = _stage_inputs(tmp_path, "unsupported")
    with pytest.raises(ValueError, match="source_flow_slot_not_preregistered"):
        materialize_slot(
            slot_id="site-03",
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "unsupported-materialization",
            output=tmp_path / "unsupported.json",
        )

    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path, "tamper")
    tampered = copy.deepcopy(receipt)
    tampered["candidates"][0]["template_id"] = "different-template"
    receipt_path.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError, match="source_flow_slot_materialization_candidates_invalid"):
        load_materialization_receipt(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    receipt_path.write_bytes(canonical_json_bytes(receipt))
    (materialization_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="source_flow_slot_materialization_file_set_invalid"):
        load_materialization_receipt(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )


def test_rejects_root_binding_and_staging_tree_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, _ = _materialize(tmp_path)
    other_root = tmp_path / "other-materialization"
    other_root.mkdir()
    with pytest.raises(ValueError, match="source_flow_slot_materialization_root_binding_mismatch"):
        load_materialization_receipt(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=other_root,
            receipt_path=receipt_path,
        )

    (stage_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="staging_tree_files_invalid"):
        load_materialization_receipt(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )


def test_rejects_source_content_tamper_and_vulnerable_fixed_role_swap(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, _ = _materialize(tmp_path)
    vulnerable = materialization_root / "slots" / SLOT_ID / "candidate-0" / "vulnerable" / "routes" / "account.js"
    fixed = materialization_root / "slots" / SLOT_ID / "candidate-0" / "fixed" / "routes" / "account.js"
    original_vulnerable = vulnerable.read_bytes()
    original_fixed = fixed.read_bytes()

    fixed.write_bytes(original_vulnerable)
    with pytest.raises(ValueError, match="source_flow_slot_materialization_source_content_invalid"):
        load_materialization_receipt(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    fixed.write_bytes(original_fixed)
    vulnerable.write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="source_flow_slot_materialization_source_content_invalid"):
        load_materialization_receipt(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )


def test_refuses_repository_overlap_and_overwrite(tmp_path) -> None:
    blueprint, stage_root, staging_receipt = _stage_inputs(tmp_path, "guard")
    with pytest.raises(ValueError, match="source_flow_slot_materialization_root_must_be_external"):
        materialize_slot(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=REPOSITORY_ROOT / "materialization",
            output=tmp_path / "receipt.json",
        )
    with pytest.raises(ValueError, match="source_flow_slot_materialization_receipt_output_must_be_external"):
        materialize_slot(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=REPOSITORY_ROOT / "receipt.json",
        )
    with pytest.raises(ValueError, match="source_flow_slot_materialization_paths_must_not_overlap_inputs_or_receipt"):
        materialize_slot(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=tmp_path / "materialization" / "receipt.json",
        )
    existing_root = tmp_path / "existing-materialization"
    existing_root.mkdir()
    with pytest.raises(ValueError, match="refusing_to_overwrite_source_flow_slot_materialization_root"):
        materialize_slot(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=existing_root,
            output=tmp_path / "receipt.json",
        )

    _, _, _, _, receipt_path, _ = _materialize(tmp_path, "overwrite")
    with pytest.raises(ValueError, match="refusing_to_overwrite_source_flow_slot_materialization_receipt"):
        materialize_slot(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "new-materialization",
            output=receipt_path,
        )


def test_slot_identity_isolated_from_unrelated_slot_configuration(monkeypatch) -> None:
    before = materializer_identity(SLOT_ID)
    monkeypatch.setitem(
        SLOT_CONFIGS,
        "unrelated-source-flow-slot",
        {"expected": {}, "renderer": "unregistered-renderer.v1", "candidates": {}},
    )

    assert materializer_identity(SLOT_ID) == before
    assert "materializer_sha256" not in before
    assert all(len(item["sha256"]) == 64 for item in before["renderer_implementation"]["function_sha256"])
