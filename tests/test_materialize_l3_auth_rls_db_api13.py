from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.materialize_l3_auth_rls_db_api13 import (
    CLAIM_BOUNDARY,
    load_materialization_receipt,
    materialize_api13,
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
    result = materialize_api13(
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


def test_materializes_only_api13_primary_and_reserve_source_triplets(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)

    assert receipt["slot_id"] == "api-13"
    assert receipt["counts"] == {
        "slot_count": 1,
        "candidate_count": 2,
        "primary_candidate_count": 1,
        "reserve_candidate_count": 1,
        "source_triplet_count": 6,
        "source_file_count": 20,
    }
    assert receipt["claim_boundary"] == CLAIM_BOUNDARY
    assert receipt["raw_source_returned"] is False

    primary_root = materialization_root / "slots" / "api-13" / "candidate-0"
    reserve_root = materialization_root / "slots" / "api-13" / "candidate-1"
    kotlin_root = Path("src") / "main" / "kotlin" / "com" / "kguard" / "generated"
    vulnerable = primary_root / "vulnerable" / kotlin_root / "DocumentRoute.kt"
    fixed = primary_root / "fixed" / kotlin_root / "DocumentRoute.kt"
    marker = primary_root / "fixed" / kotlin_root / "ResourceOwnerMarker.kt"
    negative = reserve_root / "negative" / kotlin_root / "Status.kt"
    reserve_vulnerable = reserve_root / "vulnerable" / kotlin_root / "FileRoute.kt"
    reserve_fixed = reserve_root / "fixed" / kotlin_root / "FileRoute.kt"
    reserve_marker = reserve_root / "fixed" / kotlin_root / "ResourceOwnerMarker.kt"
    assert b'get("/accounts/{accountId}/documents/{documentId}")' in vulnerable.read_bytes()
    assert b"repository.findById(documentId)" in vulnerable.read_bytes()
    assert b"findByIdAndOwnerId" not in vulnerable.read_bytes()
    assert b'call.request.headers["X-Actor-Id"]' in fixed.read_bytes()
    assert b"repository.findByIdAndOwnerId(documentId, actorId)" in fixed.read_bytes()
    assert b"resource owner enforcement not materialized" in marker.read_bytes()
    assert b'get("/workspaces/{workspaceId}/files/{fileId}")' in reserve_vulnerable.read_bytes()
    assert b"repository.findById(fileId)" in reserve_vulnerable.read_bytes()
    assert b"repository.findByIdAndOwnerId(fileId, actorId)" in reserve_fixed.read_bytes()
    assert b"resource owner enforcement not materialized" in reserve_marker.read_bytes()
    assert b'const val STATUS = "ok"' in negative.read_bytes()
    assert b"io.ktor" not in negative.read_bytes()
    assert b"findByIdAndOwnerId" not in negative.read_bytes()
    receipt_raw = receipt_path.read_bytes()
    assert b"findByIdAndOwnerId" not in receipt_raw
    assert b"DocumentRoute.kt" not in receipt_raw
    assert _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path) == receipt


def test_rejects_receipt_tree_and_source_role_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)
    tampered = copy.deepcopy(receipt)
    tampered["candidates"][0]["fixture_id"] = "different-fixture"
    receipt_path.write_bytes(canonical_json_bytes(tampered))
    with pytest.raises(ValueError, match="api13_materialization_candidates_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)

    receipt_path.write_bytes(canonical_json_bytes(receipt))
    kotlin_root = Path("src") / "main" / "kotlin" / "com" / "kguard" / "generated"
    vulnerable = materialization_root / "slots" / "api-13" / "candidate-0" / "vulnerable" / kotlin_root / "DocumentRoute.kt"
    fixed = materialization_root / "slots" / "api-13" / "candidate-0" / "fixed" / kotlin_root / "DocumentRoute.kt"
    original_fixed = fixed.read_bytes()
    fixed.write_bytes(vulnerable.read_bytes())
    with pytest.raises(ValueError, match="api13_materialization_source_content_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)

    fixed.write_bytes(original_fixed)
    marker = materialization_root / "slots" / "api-13" / "candidate-0" / "fixed" / kotlin_root / "ResourceOwnerMarker.kt"
    original_marker = marker.read_bytes()
    marker.write_text("package com.kguard.generated\nobject ResourceOwnerMarker {}\n", encoding="ascii")
    with pytest.raises(ValueError, match="api13_materialization_source_content_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)

    marker.write_bytes(original_marker)
    (materialization_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="api13_materialization_file_set_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)


def test_rejects_root_binding_and_staging_tree_tamper(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, _ = _materialize(tmp_path)
    other_root = tmp_path / "other-materialization"
    other_root.mkdir()
    with pytest.raises(ValueError, match="api13_materialization_root_binding_mismatch"):
        _load(blueprint, stage_root, staging_receipt, other_root, receipt_path)

    (stage_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="staging_tree_files_invalid"):
        _load(blueprint, stage_root, staging_receipt, materialization_root, receipt_path)


def test_refuses_repository_overlap_and_overwrite(tmp_path) -> None:
    blueprint, stage_root, staging_receipt = _stage_inputs(tmp_path, "guard")
    with pytest.raises(ValueError, match="api13_materialization_root_must_be_external"):
        materialize_api13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=REPOSITORY_ROOT / "materialization",
            output=tmp_path / "receipt.json",
        )
    with pytest.raises(ValueError, match="api13_materialization_receipt_output_must_be_external"):
        materialize_api13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=REPOSITORY_ROOT / "receipt.json",
        )
    with pytest.raises(ValueError, match="api13_materialization_paths_must_not_overlap_inputs_or_receipt"):
        materialize_api13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "materialization",
            output=stage_root / "receipt.json",
        )
    existing_root = tmp_path / "existing-materialization"
    existing_root.mkdir()
    with pytest.raises(ValueError, match="refusing_to_overwrite_api13_materialization_root"):
        materialize_api13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=existing_root,
            output=tmp_path / "receipt.json",
        )

    _, _, _, _, receipt_path, _ = _materialize(tmp_path, "overwrite")
    with pytest.raises(ValueError, match="refusing_to_overwrite_api13_materialization_receipt"):
        materialize_api13(
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=tmp_path / "new-materialization",
            output=receipt_path,
        )
