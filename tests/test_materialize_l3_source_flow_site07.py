from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.materialize_l3_source_flow_site07 import (
    CLAIM_BOUNDARY,
    load_materialization_receipt,
    materialize_site07,
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
    result = materialize_site07(
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        output=receipt,
    )
    return blueprint, stage_root, staging_receipt, materialization_root, receipt, result


def test_materializes_only_site07_primary_and_reserve_source_triplets(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)

    assert receipt["slot_id"] == "site-07"
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
    vulnerable = materialization_root / "slots" / "site-07" / "candidate-0" / "vulnerable" / "app" / "api" / "preferences" / "route.ts"
    fixed = materialization_root / "slots" / "site-07" / "candidate-0" / "fixed" / "app" / "api" / "preferences" / "route.ts"
    negative = materialization_root / "slots" / "site-07" / "candidate-1" / "negative" / "app" / "api" / "profile" / "route.ts"
    assert b"const preferences = (await request.json()).preferences ?? {};" in vulnerable.read_bytes()
    assert b"Object.assign(defaults, preferences);" in vulnerable.read_bytes()
    assert b'Object.prototype.hasOwnProperty.call(source, "__proto__")' in fixed.read_bytes()
    assert b"const themeValue = values.theme;" in fixed.read_bytes()
    assert b'locale: localeValue ?? "ko-KR"' in fixed.read_bytes()
    assert b"Object.assign" not in fixed.read_bytes()
    assert b'displayName: "guest"' in negative.read_bytes()
    assert b'timeZone: "Asia/Seoul"' in negative.read_bytes()
    assert b"request.json" not in negative.read_bytes()
    assert b"const profile =" not in negative.read_bytes()
    assert b"Object.assign" not in negative.read_bytes()
    assert b"NextResponse" not in receipt_path.read_bytes()
    assert load_materialization_receipt(
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        receipt_path=receipt_path,
    ) == receipt


def test_rejects_receipt_and_source_tree_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)
    tampered = copy.deepcopy(receipt)
    tampered["candidates"][0]["template_id"] = "different-template"
    receipt_path.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError, match="site07_materialization_candidates_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    receipt_path.write_bytes(canonical_json_bytes(receipt))
    (materialization_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="site07_materialization_file_set_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )


def test_rejects_source_content_role_root_and_staging_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, _ = _materialize(tmp_path)
    vulnerable = materialization_root / "slots" / "site-07" / "candidate-0" / "vulnerable" / "app" / "api" / "preferences" / "route.ts"
    fixed = materialization_root / "slots" / "site-07" / "candidate-0" / "fixed" / "app" / "api" / "preferences" / "route.ts"
    original_vulnerable = vulnerable.read_bytes()
    original_fixed = fixed.read_bytes()

    fixed.write_bytes(original_vulnerable)
    with pytest.raises(ValueError, match="site07_materialization_source_content_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    fixed.write_bytes(original_fixed)
    vulnerable.write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="site07_materialization_source_content_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    other_root = tmp_path / "other-materialization"
    other_root.mkdir()
    with pytest.raises(ValueError, match="site07_materialization_root_binding_mismatch"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=other_root,
            receipt_path=receipt_path,
        )

    (stage_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="staging_tree_files_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )


def test_refuses_repository_overlap_and_overwrite(tmp_path) -> None:
    blueprint, stage_root, staging_receipt = _stage_inputs(tmp_path, "guard")
    with pytest.raises(ValueError, match="site07_materialization_root_must_be_external"):
        materialize_site07(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=REPOSITORY_ROOT / "materialization",
            output=tmp_path / "receipt.json",
        )
    with pytest.raises(ValueError, match="site07_materialization_receipt_output_must_be_external"):
        materialize_site07(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=REPOSITORY_ROOT / "receipt.json",
        )
    with pytest.raises(ValueError, match="site07_materialization_paths_must_not_overlap_inputs_or_receipt"):
        materialize_site07(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=tmp_path / "materialization" / "receipt.json",
        )
    existing_root = tmp_path / "existing-materialization"
    existing_root.mkdir()
    with pytest.raises(ValueError, match="refusing_to_overwrite_site07_materialization_root"):
        materialize_site07(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=existing_root,
            output=tmp_path / "receipt.json",
        )

    _, _, _, _, receipt_path, _ = _materialize(tmp_path, "overwrite")
    with pytest.raises(ValueError, match="refusing_to_overwrite_site07_materialization_receipt"):
        materialize_site07(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "new-materialization",
            output=receipt_path,
        )
