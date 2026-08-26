from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.materialize_l3_auth_rls_db_api03 import (
    CLAIM_BOUNDARY,
    load_materialization_receipt,
    materialize_api03,
)
from scripts.stage_l3_generated_pair_source_triplets import stage_source_triplets


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
    result = materialize_api03(
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        output=receipt,
    )
    return blueprint, stage_root, staging_receipt, materialization_root, receipt, result


def _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path):
    return load_materialization_receipt(
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        receipt_path=receipt_path,
    )


def test_materializes_only_api03_primary_and_reserve_source_triplets(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)

    assert receipt["slot_id"] == "api-03"
    assert receipt["counts"] == {
        "slot_count": 1,
        "candidate_count": 2,
        "primary_candidate_count": 1,
        "reserve_candidate_count": 1,
        "source_triplet_count": 6,
        "source_file_count": 22,
    }
    assert receipt["claim_boundary"] == CLAIM_BOUNDARY
    assert receipt["raw_source_returned"] is False

    vulnerable = materialization_root / "slots" / "api-03" / "candidate-0" / "vulnerable" / "supabase" / "migrations" / "20260724_create_team_notes.sql"
    fixed = materialization_root / "slots" / "api-03" / "candidate-0" / "fixed" / "supabase" / "migrations" / "20260724_create_team_notes.sql"
    negative = materialization_root / "slots" / "api-03" / "candidate-1" / "negative" / "src" / "status.ts"
    assert b"create table public.team_notes" in vulnerable.read_bytes()
    assert b"enable row level security" not in vulnerable.read_bytes()
    assert b"create policy" not in vulnerable.read_bytes()
    assert b"alter table public.team_notes enable row level security;" in fixed.read_bytes()
    assert b"using (auth.uid() = owner_id)" in fixed.read_bytes()
    assert b"with check (auth.uid() = owner_id);" in fixed.read_bytes()
    assert b'export const status = "ok";' in negative.read_bytes()
    assert b"create table" not in negative.read_bytes()
    receipt_raw = receipt_path.read_bytes()
    assert b"team_notes" not in receipt_raw
    assert b"supabase/migrations" not in receipt_raw
    assert _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path) == receipt


def test_rejects_receipt_tree_and_source_role_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)
    tampered = copy.deepcopy(receipt)
    tampered["candidates"][0]["fixture_id"] = "different-fixture"
    receipt_path.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError, match="api03_materialization_candidates_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)

    receipt_path.write_bytes(canonical_json_bytes(receipt))
    vulnerable = materialization_root / "slots" / "api-03" / "candidate-0" / "vulnerable" / "supabase" / "migrations" / "20260724_create_team_notes.sql"
    fixed = materialization_root / "slots" / "api-03" / "candidate-0" / "fixed" / "supabase" / "migrations" / "20260724_create_team_notes.sql"
    original_fixed = fixed.read_bytes()
    fixed.write_bytes(vulnerable.read_bytes())
    with pytest.raises(ValueError, match="api03_materialization_source_content_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)

    fixed.write_bytes(original_fixed)
    (materialization_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="api03_materialization_file_set_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)


def test_rejects_root_binding_and_staging_tree_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, _ = _materialize(tmp_path)
    other_root = tmp_path / "other-materialization"
    other_root.mkdir()
    with pytest.raises(ValueError, match="api03_materialization_root_binding_mismatch"):
        _load(blueprint, stage_root, staging_receipt, other_root, receipt_path)

    (stage_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="staging_tree_files_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)


def test_refuses_repository_overlap_and_overwrite(tmp_path) -> None:
    blueprint, stage_root, staging_receipt = _stage_inputs(tmp_path, "guard")
    with pytest.raises(ValueError, match="api03_materialization_root_must_be_external"):
        materialize_api03(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=REPOSITORY_ROOT / "materialization",
            output=tmp_path / "receipt.json",
        )
    with pytest.raises(ValueError, match="api03_materialization_receipt_output_must_be_external"):
        materialize_api03(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=REPOSITORY_ROOT / "receipt.json",
        )
    with pytest.raises(ValueError, match="api03_materialization_paths_must_not_overlap_inputs_or_receipt"):
        materialize_api03(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=stage_root / "receipt.json",
        )
    existing_root = tmp_path / "existing-materialization"
    existing_root.mkdir()
    with pytest.raises(ValueError, match="refusing_to_overwrite_api03_materialization_root"):
        materialize_api03(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=existing_root,
            output=tmp_path / "receipt.json",
        )

    _, _, _, _, receipt_path, _ = _materialize(tmp_path, "overwrite")
    with pytest.raises(ValueError, match="refusing_to_overwrite_api03_materialization_receipt"):
        materialize_api03(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "new-materialization",
            output=receipt_path,
        )
