from __future__ import annotations

import copy

import pytest

from scripts.build_l3_generated_pair_blueprint import REPOSITORY_ROOT, canonical_json_bytes, write_blueprint
from scripts.stage_l3_generated_pair_source_triplets import (
    CLAIM_BOUNDARY,
    MARKER_FILENAME,
    STAGING_CONTRACT,
    load_staging_receipt,
    stage_source_triplets,
)


def _stage(tmp_path, name: str = "run"):
    blueprint = tmp_path / f"{name}-blueprint.json"
    stage_root = tmp_path / f"{name}-stage"
    receipt = tmp_path / f"{name}-receipt.json"
    write_blueprint(blueprint)
    result = stage_source_triplets(blueprint, stage_root, receipt)
    return blueprint, stage_root, receipt, result


def test_stage_reserves_exactly_60_slots_and_120_raw_free_candidates(tmp_path) -> None:
    blueprint, stage_root, receipt_path, receipt = _stage(tmp_path)

    assert receipt["counts"] == {
        "slot_count": 60,
        "candidate_count": 120,
        "primary_candidate_count": 60,
        "reserve_candidate_count": 60,
        "triplet_directory_count": 360,
        "plane_candidate_counts": {"api": 30, "data": 30, "operations": 30, "site": 30},
        "family_candidate_counts": {
            "auth-rls-db": 38,
            "dependency-sca": 14,
            "gha-docker-iac": 16,
            "policy-kpriv": 14,
            "source-flow": 38,
        },
    }
    assert receipt["staging_contract"] == STAGING_CONTRACT
    assert receipt["claim_boundary"] == CLAIM_BOUNDARY
    assert receipt["raw_source_returned"] is False
    assert receipt["claim_boundary"]["source_triplets_materialized"] is False
    assert (stage_root / "slots" / "site-01" / "candidate-0" / MARKER_FILENAME).is_file()
    assert list((stage_root / "slots" / "site-01" / "candidate-0" / "vulnerable").iterdir()) == []
    assert list((stage_root / "slots" / "site-01" / "candidate-0" / "fixed").iterdir()) == []
    assert list((stage_root / "slots" / "site-01" / "candidate-0" / "negative").iterdir()) == []
    assert load_staging_receipt(receipt_path, blueprint, stage_root) == receipt


def test_stage_rejects_receipt_candidate_tamper_and_tree_tamper(tmp_path) -> None:
    blueprint, stage_root, receipt_path, receipt = _stage(tmp_path)
    tampered = copy.deepcopy(receipt)
    tampered["candidates"][0]["candidate_role"] = "reserve"
    receipt_path.write_bytes(canonical_json_bytes(tampered))

    with pytest.raises(ValueError, match="staging_candidates_invalid"):
        load_staging_receipt(receipt_path, blueprint, stage_root)

    receipt_path.write_bytes(canonical_json_bytes(receipt))
    (stage_root / "unexpected.txt").write_text("not allowed\n", encoding="ascii")
    with pytest.raises(ValueError, match="staging_tree_files_invalid"):
        load_staging_receipt(receipt_path, blueprint, stage_root)


def test_stage_rejects_root_binding_and_marker_tamper(tmp_path) -> None:
    blueprint, stage_root, receipt_path, receipt = _stage(tmp_path)
    other_root = tmp_path / "other-stage"
    other_root.mkdir()
    with pytest.raises(ValueError, match="staging_stage_root_binding_mismatch"):
        load_staging_receipt(receipt_path, blueprint, other_root)

    marker_path = stage_root / "slots" / "site-01" / "candidate-0" / MARKER_FILENAME
    marker = marker_path.read_bytes()
    marker_path.write_bytes(marker.replace(b'"primary"', b'"reserve"'))
    with pytest.raises(ValueError, match="staging_marker_content_invalid"):
        load_staging_receipt(receipt_path, blueprint, stage_root)


def test_stage_refuses_repository_output_overlap_and_overwrite(tmp_path) -> None:
    blueprint = tmp_path / "blueprint.json"
    write_blueprint(blueprint)

    with pytest.raises(ValueError, match="stage_root_must_be_external"):
        stage_source_triplets(blueprint, REPOSITORY_ROOT / "stage-root", tmp_path / "receipt.json")
    with pytest.raises(ValueError, match="staging_receipt_output_must_be_external"):
        stage_source_triplets(blueprint, tmp_path / "stage-root", REPOSITORY_ROOT / "receipt.json")
    with pytest.raises(ValueError, match="staging_root_and_receipt_must_not_overlap"):
        stage_source_triplets(blueprint, tmp_path / "stage-root", tmp_path / "stage-root" / "receipt.json")

    stage_root = tmp_path / "existing-stage"
    stage_root.mkdir()
    with pytest.raises(ValueError, match="refusing_to_overwrite_staging_root"):
        stage_source_triplets(blueprint, stage_root, tmp_path / "receipt.json")

    _, _, receipt_path, _ = _stage(tmp_path, "overwrite")
    with pytest.raises(ValueError, match="refusing_to_overwrite_staging_receipt"):
        stage_source_triplets(blueprint, tmp_path / "new-stage", receipt_path)
