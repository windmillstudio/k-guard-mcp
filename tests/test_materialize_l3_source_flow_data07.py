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


SLOT_ID = "data-07"
DATA03_IDENTITY_SHA256 = "0ee88866766e7b78f4f7b45859dd5bafa15d108d6b49f745db62e1f3334dd99f"


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


def test_materializes_only_data07_fastapi_parameterized_query_triplets(tmp_path) -> None:
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

    vulnerable = _source(materialization_root, 0, "vulnerable", "app/api/checkout/orders.py")
    fixed = _source(materialization_root, 0, "fixed", "app/api/checkout/orders.py")
    negative = _source(materialization_root, 1, "negative", "app/api/integrations/providers.py")
    pyproject = materialization_root / "slots" / SLOT_ID / "candidate-0" / "fixed" / "pyproject.toml"
    assert b'@app.get("/orders/{order_id}")' in vulnerable.read_bytes()
    assert b"def get_order_by_id(order_id: str):" in vulnerable.read_bytes()
    assert b"query = f\"SELECT status FROM orders WHERE id = '{order_id}'\"" in vulnerable.read_bytes()
    assert b"connection.execute(query).fetchone()" in vulnerable.read_bytes()
    assert b'query = "SELECT status FROM orders WHERE id = ?"' in fixed.read_bytes()
    assert b"connection.execute(query, (order_id,)).fetchone()" in fixed.read_bytes()
    assert b"f\"SELECT" not in fixed.read_bytes()
    assert b'@app.get("/integrations")' in negative.read_bytes()
    assert b"def get_provider_by_slug():" in negative.read_bytes()
    assert b'JSONResponse({"endpoint": "integrations-ready"})' in negative.read_bytes()
    assert b"sqlite3" not in negative.read_bytes()
    assert b'fastapi==0.115.0' in pyproject.read_bytes()
    assert b"connection.execute" not in receipt_path.read_bytes()
    assert load_materialization_receipt(
        slot_id=SLOT_ID,
        blueprint_path=blueprint,
        staging_receipt_path=staging_receipt,
        staging_root=stage_root,
        materialization_root=materialization_root,
        receipt_path=receipt_path,
    ) == receipt


def test_data07_binding_is_explicit_and_data03_identity_is_unchanged() -> None:
    config = SLOT_CONFIGS[SLOT_ID]
    assert config["expected"] == {
        "scenario_id": "dev-data-07-parameterized-query",
        "oracle_id": "l3-gen-data-07-parameterized-query",
        "plane": "data",
        "family": "source-flow",
        "language": "python",
        "framework": "fastapi",
        "coverage_tags": ["sql-rls"],
        "cwe": "CWE-89",
        "severity": "high",
        "generator_profile": "deterministic-fixture-v1",
    }
    assert config["renderer"] == "python-fastapi-parameterized-query.v1"
    assert materializer_identity("data-03")["sha256"] == DATA03_IDENTITY_SHA256


def test_rejects_data07_receipt_source_role_root_and_staging_tamper(tmp_path) -> None:
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
    vulnerable = _source(materialization_root, 0, "vulnerable", "app/api/checkout/orders.py")
    fixed = _source(materialization_root, 0, "fixed", "app/api/checkout/orders.py")
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


def test_refuses_data07_repository_overlap_and_overwrite(tmp_path) -> None:
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
