from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.materialize_l3_source_flow_site08 import (
    CLAIM_BOUNDARY,
    load_materialization_receipt,
    materialize_site08,
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
    result = materialize_site08(
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        output=receipt,
    )
    return blueprint, stage_root, staging_receipt, materialization_root, receipt, result


def test_materializes_only_site08_primary_and_reserve_source_triplets(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)

    assert receipt["slot_id"] == "site-08"
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
    vulnerable = materialization_root / "slots" / "site-08" / "candidate-0" / "vulnerable" / "routes" / "import-settings.js"
    fixed = materialization_root / "slots" / "site-08" / "candidate-0" / "fixed" / "routes" / "import-settings.js"
    negative = materialization_root / "slots" / "site-08" / "candidate-1" / "negative" / "routes" / "restore-session.js"
    assert b"const serializedSettings = req.body.serializedSettings;" in vulnerable.read_bytes()
    assert b"legacySerializer.deserialize(serializedSettings)" in vulnerable.read_bytes()
    assert b"JSON.parse(serializedSettings)" in fixed.read_bytes()
    assert b'const allowedKeys = new Set(["theme", "locale"]);' in fixed.read_bytes()
    assert b"legacySerializer" not in fixed.read_bytes()
    assert b"Object.keys(parsed).some" in fixed.read_bytes()
    assert b'role: "viewer"' in negative.read_bytes()
    assert b"ttlSeconds: 900" in negative.read_bytes()
    assert b"req.body" not in negative.read_bytes()
    assert b"legacySerializer" not in negative.read_bytes()
    assert b"legacySerializer" not in receipt_path.read_bytes()
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
    with pytest.raises(ValueError, match="site08_materialization_candidates_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    receipt_path.write_bytes(canonical_json_bytes(receipt))
    (materialization_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="site08_materialization_file_set_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )


def test_rejects_source_content_role_root_and_staging_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, _ = _materialize(tmp_path)
    vulnerable = materialization_root / "slots" / "site-08" / "candidate-0" / "vulnerable" / "routes" / "import-settings.js"
    fixed = materialization_root / "slots" / "site-08" / "candidate-0" / "fixed" / "routes" / "import-settings.js"
    original_vulnerable = vulnerable.read_bytes()
    original_fixed = fixed.read_bytes()

    fixed.write_bytes(original_vulnerable)
    with pytest.raises(ValueError, match="site08_materialization_source_content_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    fixed.write_bytes(original_fixed)
    vulnerable.write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="site08_materialization_source_content_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    other_root = tmp_path / "other-materialization"
    other_root.mkdir()
    with pytest.raises(ValueError, match="site08_materialization_root_binding_mismatch"):
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
    with pytest.raises(ValueError, match="site08_materialization_root_must_be_external"):
        materialize_site08(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=REPOSITORY_ROOT / "materialization",
            output=tmp_path / "receipt.json",
        )
    with pytest.raises(ValueError, match="site08_materialization_receipt_output_must_be_external"):
        materialize_site08(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=REPOSITORY_ROOT / "receipt.json",
        )
    with pytest.raises(ValueError, match="site08_materialization_paths_must_not_overlap_inputs_or_receipt"):
        materialize_site08(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=tmp_path / "materialization" / "receipt.json",
        )
    existing_root = tmp_path / "existing-materialization"
    existing_root.mkdir()
    with pytest.raises(ValueError, match="refusing_to_overwrite_site08_materialization_root"):
        materialize_site08(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=existing_root,
            output=tmp_path / "receipt.json",
        )

    _, _, _, _, receipt_path, _ = _materialize(tmp_path, "overwrite")
    with pytest.raises(ValueError, match="refusing_to_overwrite_site08_materialization_receipt"):
        materialize_site08(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "new-materialization",
            output=receipt_path,
        )
