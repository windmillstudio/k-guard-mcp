from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.materialize_l3_source_flow_slot import (
    CLAIM_BOUNDARY,
    LEGACY_WHOLE_MODULE_SHA256_BY_SLOT,
    SCHEMA,
    SCHEMA_V1,
    VERSION,
    VERSION_V1,
    load_materialization_receipt,
    materializer_identity,
    materialize_slot,
)
from scripts.stage_l3_generated_pair_source_triplets import stage_source_triplets


SLOT_ID = "data-03"


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


def test_materializes_only_data03_prisma_raw_query_triplets(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)

    assert receipt["slot_id"] == SLOT_ID
    assert receipt["schema"] == SCHEMA
    assert receipt["version"] == VERSION
    assert receipt["materializer_identity"] == materializer_identity(SLOT_ID)
    assert "materializer_sha256" not in receipt
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
    vulnerable = _source(materialization_root, 0, "vulnerable", "src/data/checkout/orders.ts")
    fixed = _source(materialization_root, 0, "fixed", "src/data/checkout/orders.ts")
    negative = _source(materialization_root, 1, "negative", "src/data/integrations/providers.ts")
    package = materialization_root / "slots" / SLOT_ID / "candidate-0" / "fixed" / "package.json"
    assert b"export async function findOrderById(prisma: PrismaClient, id: string)" in vulnerable.read_bytes()
    assert b"const query = `SELECT status FROM orders WHERE id = '${id}'`;" in vulnerable.read_bytes()
    assert b"return prisma.$queryRawUnsafe(query);" in vulnerable.read_bytes()
    assert b"const query = Prisma.sql`SELECT status FROM orders WHERE id = ${id}`;" in fixed.read_bytes()
    assert b"return prisma.$queryRaw(query);" in fixed.read_bytes()
    assert b"$queryRawUnsafe" not in fixed.read_bytes()
    assert b"export function findProviderBySlug()" in negative.read_bytes()
    assert b"@prisma/client" not in negative.read_bytes()
    assert b"$queryRaw" not in negative.read_bytes()
    assert b'"integrations-ready"' in negative.read_bytes()
    assert b'"@prisma/client": "6.0.0"' in package.read_bytes()
    assert b"$queryRawUnsafe" not in receipt_path.read_bytes()
    assert load_materialization_receipt(
        slot_id=SLOT_ID,
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        receipt_path=receipt_path,
    ) == receipt


def test_data03_legacy_receipt_accepts_only_the_pinned_v1_provenance(tmp_path) -> None:
    blueprint, stage_root, staging_receipt, materialization_root, receipt_path, receipt = _materialize(tmp_path)
    legacy = copy.deepcopy(receipt)
    legacy["schema"] = SCHEMA_V1
    legacy["version"] = VERSION_V1
    legacy.pop("materializer_identity")
    legacy["materializer_sha256"] = next(iter(LEGACY_WHOLE_MODULE_SHA256_BY_SLOT[SLOT_ID]))
    receipt_path.write_bytes(canonical_json_bytes(legacy))

    assert load_materialization_receipt(
        slot_id=SLOT_ID,
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        receipt_path=receipt_path,
    ) == legacy

    legacy["materializer_sha256"] = "0" * 64
    receipt_path.write_bytes(canonical_json_bytes(legacy))
    with pytest.raises(ValueError, match="source_flow_slot_materializer_sha256_mismatch"):
        load_materialization_receipt(
            slot_id=SLOT_ID,
            blueprint_path=blueprint,
            staging_receipt_path=staging_receipt,
            staging_root=stage_root,
            materialization_root=materialization_root,
            receipt_path=receipt_path,
        )


def test_rejects_data03_receipt_source_role_root_and_staging_tamper(tmp_path) -> None:
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
    vulnerable = _source(materialization_root, 0, "vulnerable", "src/data/checkout/orders.ts")
    fixed = _source(materialization_root, 0, "fixed", "src/data/checkout/orders.ts")
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


def test_refuses_data03_repository_overlap_and_overwrite(tmp_path) -> None:
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
