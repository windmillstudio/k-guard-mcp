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


SLOT_ID = "data-09"
DATA07_IDENTITY_SHA256 = "d6adff11f104c943640e83e752fccc8626be11297ff781acfdaabc27b9071981"


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


def _source(root, candidate_rank: int, state: str, relative_path: str):
    return root / "slots" / SLOT_ID / f"candidate-{candidate_rank}" / state / relative_path


def test_materializes_only_data09_spring_jdbc_concat_triplets(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)

    assert receipt["slot_id"] == SLOT_ID
    assert receipt["materializer_identity"] == materializer_identity(SLOT_ID)
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

    vulnerable = _source(
        materialization_root, 0, "vulnerable", "src/main/java/com/kguard/checkout/OrdersController.java"
    )
    fixed = _source(materialization_root, 0, "fixed", "src/main/java/com/kguard/checkout/OrdersController.java")
    negative = _source(
        materialization_root, 1, "negative", "src/main/java/com/kguard/integrations/ProvidersController.java"
    )
    pom = materialization_root / "slots" / SLOT_ID / "candidate-0" / "fixed" / "pom.xml"
    assert b'@GetMapping("/orders/{id}")' in vulnerable.read_bytes()
    assert b"public String findOrderById(@PathVariable String id)" in vulnerable.read_bytes()
    assert b"Statement statement = connection.createStatement();" in vulnerable.read_bytes()
    assert b'WHERE id = \'" + id + "\'' in vulnerable.read_bytes()
    assert b"PreparedStatement statement = connection.prepareStatement" in fixed.read_bytes()
    assert b'WHERE id = ?' in fixed.read_bytes()
    assert b"statement.setString(1, id);" in fixed.read_bytes()
    assert b"createStatement" not in fixed.read_bytes()
    assert b'@GetMapping("/integrations")' in negative.read_bytes()
    assert b"public ResponseEntity<String> findProviderBySlug()" in negative.read_bytes()
    assert b'ResponseEntity.ok("integrations-ready")' in negative.read_bytes()
    assert b"java.sql" not in negative.read_bytes()
    assert b"spring-boot-starter-web" in pom.read_bytes()
    assert b"executeQuery" not in receipt_path.read_bytes()
    assert load_materialization_receipt(
        slot_id=SLOT_ID,
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        receipt_path=receipt_path,
    ) == receipt


def test_data09_binding_is_explicit_and_data07_identity_is_unchanged() -> None:
    config = SLOT_CONFIGS[SLOT_ID]
    assert config["expected"] == {
        "scenario_id": "dev-data-09-jdbc-concat",
        "oracle_id": "l3-gen-data-09-jdbc-concat",
        "plane": "data",
        "family": "source-flow",
        "language": "java",
        "framework": "spring",
        "coverage_tags": ["sql-rls"],
        "cwe": "CWE-89",
        "severity": "high",
        "generator_profile": "deterministic-transform-v1",
    }
    assert config["renderer"] == "java-spring-jdbc-concat.v1"
    assert materializer_identity("data-07")["sha256"] == DATA07_IDENTITY_SHA256


def test_rejects_data09_receipt_source_role_root_and_staging_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)
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
    vulnerable = _source(
        materialization_root, 0, "vulnerable", "src/main/java/com/kguard/checkout/OrdersController.java"
    )
    fixed = _source(materialization_root, 0, "fixed", "src/main/java/com/kguard/checkout/OrdersController.java")
    original_fixed = fixed.read_bytes()
    fixed.write_bytes(vulnerable.read_bytes())
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


def test_refuses_data09_repository_overlap_and_overwrite(tmp_path) -> None:
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
