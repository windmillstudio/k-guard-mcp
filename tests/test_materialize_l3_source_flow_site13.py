from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.materialize_l3_source_flow_site13 import (
    CLAIM_BOUNDARY,
    load_materialization_receipt,
    materialize_site13,
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
    result = materialize_site13(
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        output=receipt,
    )
    return blueprint, stage_root, staging_receipt, materialization_root, receipt, result


def test_materializes_only_site13_primary_and_reserve_source_triplets(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)

    assert receipt["slot_id"] == "site-13"
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
    vulnerable = (
        materialization_root
        / "slots"
        / "site-13"
        / "candidate-0"
        / "vulnerable"
        / "src"
        / "main"
        / "java"
        / "dev"
        / "kguard"
        / "checkout"
        / "OrderLookupController.java"
    )
    fixed = (
        materialization_root
        / "slots"
        / "site-13"
        / "candidate-0"
        / "fixed"
        / "src"
        / "main"
        / "java"
        / "dev"
        / "kguard"
        / "checkout"
        / "OrderLookupController.java"
    )
    negative = (
        materialization_root
        / "slots"
        / "site-13"
        / "candidate-1"
        / "negative"
        / "src"
        / "main"
        / "java"
        / "dev"
        / "kguard"
        / "integrations"
        / "IntegrationLookupController.java"
    )
    pom = materialization_root / "slots" / "site-13" / "candidate-0" / "fixed" / "pom.xml"
    assert b"import java.sql.Statement;" in vulnerable.read_bytes()
    assert b'@GetMapping("/orders")' in vulnerable.read_bytes()
    assert b"@RequestParam String id" in vulnerable.read_bytes()
    assert b"connection.createStatement()" in vulnerable.read_bytes()
    assert b"statement.executeQuery(query)" in vulnerable.read_bytes()
    assert b"SELECT status FROM orders WHERE id = '" in vulnerable.read_bytes()
    assert b"import java.sql.PreparedStatement;" in fixed.read_bytes()
    assert b'@GetMapping("/orders")' in fixed.read_bytes()
    assert b"@RequestParam String id" in fixed.read_bytes()
    assert b"SELECT status FROM orders WHERE id = ?" in fixed.read_bytes()
    assert b"connection.prepareStatement(query)" in fixed.read_bytes()
    assert b"statement.setString(1, id)" in fixed.read_bytes()
    assert b"createStatement()" not in fixed.read_bytes()
    assert b"@RequestParam" not in negative.read_bytes()
    assert b"DataSource" not in negative.read_bytes()
    assert b'ResponseEntity.ok("integrations-ready")' in negative.read_bytes()
    assert b"spring-boot-starter-web" in pom.read_bytes()
    assert b"maven.compiler.release>21" in pom.read_bytes()
    assert b"SELECT status" not in receipt_path.read_bytes()
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
    with pytest.raises(ValueError, match="site13_materialization_candidates_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    receipt_path.write_bytes(canonical_json_bytes(receipt))
    (materialization_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="site13_materialization_file_set_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )


def test_rejects_source_content_role_root_and_staging_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, _ = _materialize(tmp_path)
    vulnerable = (
        materialization_root
        / "slots"
        / "site-13"
        / "candidate-0"
        / "vulnerable"
        / "src"
        / "main"
        / "java"
        / "dev"
        / "kguard"
        / "checkout"
        / "OrderLookupController.java"
    )
    fixed = (
        materialization_root
        / "slots"
        / "site-13"
        / "candidate-0"
        / "fixed"
        / "src"
        / "main"
        / "java"
        / "dev"
        / "kguard"
        / "checkout"
        / "OrderLookupController.java"
    )
    original_vulnerable = vulnerable.read_bytes()
    original_fixed = fixed.read_bytes()

    fixed.write_bytes(original_vulnerable)
    with pytest.raises(ValueError, match="site13_materialization_source_content_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    fixed.write_bytes(original_fixed)
    vulnerable.write_bytes(b"tampered\n")
    with pytest.raises(ValueError, match="site13_materialization_source_content_invalid"):
        load_materialization_receipt(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )

    other_root = tmp_path / "other-materialization"
    other_root.mkdir()
    with pytest.raises(ValueError, match="site13_materialization_root_binding_mismatch"):
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
    with pytest.raises(ValueError, match="site13_materialization_root_must_be_external"):
        materialize_site13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=REPOSITORY_ROOT / "materialization",
            output=tmp_path / "receipt.json",
        )
    with pytest.raises(ValueError, match="site13_materialization_receipt_output_must_be_external"):
        materialize_site13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=REPOSITORY_ROOT / "receipt.json",
        )
    with pytest.raises(ValueError, match="site13_materialization_paths_must_not_overlap_inputs_or_receipt"):
        materialize_site13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=tmp_path / "materialization" / "receipt.json",
        )
    existing_root = tmp_path / "existing-materialization"
    existing_root.mkdir()
    with pytest.raises(ValueError, match="refusing_to_overwrite_site13_materialization_root"):
        materialize_site13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=existing_root,
            output=tmp_path / "receipt.json",
        )

    _, _, _, _, receipt_path, _ = _materialize(tmp_path, "overwrite")
    with pytest.raises(ValueError, match="refusing_to_overwrite_site13_materialization_receipt"):
        materialize_site13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "new-materialization",
            output=receipt_path,
        )
