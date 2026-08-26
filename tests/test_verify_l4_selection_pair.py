from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from k_guard_mcp.public_lineage import (
    OUTPUT_SCHEMA,
    QUOTAS,
    SOURCE_RECEIPT_SCHEMA,
    canonical_json_bytes,
    source_receipt_canonical_json_bytes,
)
from scripts import verify_l4_selection_pair as verifier
from scripts.holdout_source_materialization import (
    build_git_materialization_receipt,
)
from scripts.verify_l4_selection_pair import (
    L4PairVerificationError,
    verify_selection_pair,
    write_verification,
)


IMPLEMENTATION_SHA256 = "a" * 64
SOURCE_VERIFIER_SHA256 = "b" * 64
QUERY_SHA256 = "c" * 64
CAPTURE_MANIFEST_SHA256 = "d" * 64
SEED_SHA256 = "e" * 64


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _candidate_pool() -> dict:
    return {
        "source_population_count": 65,
        "candidate_count": 64,
        "materialization_rejection_ledger": [
            {"repository_id": "rejected/app", "reasons": ["fixture"]}
        ],
        "provenance": {
            "capture_implementation_sha256": IMPLEMENTATION_SHA256,
            "candidate_materializer_sha256": IMPLEMENTATION_SHA256,
        },
    }


def _payload() -> dict:
    selected = []
    for stratum, quota in QUOTAS.items():
        selected.extend(
            {
                "repository_id": f"owner-{stratum}/app-{index:03d}",
                "star_stratum": stratum,
            }
            for index in range(quota)
        )
    return {
        "schema": OUTPUT_SCHEMA,
        "selection": {
            "selected_count": 59,
            "stratum_counts": dict(QUOTAS),
            "quotas": dict(QUOTAS),
        },
        "selected": selected,
        "reserves": {
            stratum: [
                {
                    "repository_id": f"reserve-{stratum}/app",
                    "star_stratum": stratum,
                }
            ]
            for stratum in QUOTAS
        },
        "rejection_ledger": [
            {
                "repository_id": "overlap/app",
                "reasons": ["overlaps_prior_evidence_105"],
            }
        ],
        "counts": {"input_candidates": 64},
        "network_accessed": False,
        "scanner_output_observed": False,
        "accuracy_ground_truth": False,
        "qualification_authority": False,
        "claim_boundary": {
            "new_59_called_unseen": False,
            "new_59_used_as_accuracy_ground_truth": False,
            "findings_may_be_called_tp_fp_fn": False,
            "source_population_fully_accounted": True,
            "source_runtime_deployment_proven": False,
            "license_file_content_classified_to_github_spdx": False,
            "population_representative_of_all_github_apps": False,
            "requires_bound_artifact_root_for_replay": True,
            "self_contained_evidence_archive": False,
            "allowed_claims": ["actionability_proxy", "output_burden"],
        },
        "bindings": {
            "candidate_manifest_sha256": "candidate-placeholder",
            "source_verifier_sha256": SOURCE_VERIFIER_SHA256,
            "github_metadata_query_sha256": QUERY_SHA256,
            "capture_manifest_sha256": CAPTURE_MANIFEST_SHA256,
            "capture_implementation_sha256": IMPLEMENTATION_SHA256,
            "candidate_materializer_sha256": IMPLEMENTATION_SHA256,
            "selection_implementation_sha256": IMPLEMENTATION_SHA256,
            "selection_cli_sha256": IMPLEMENTATION_SHA256,
        },
    }


def _fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict, dict, dict]:
    candidate_payload = _candidate_pool()
    candidate_raw = canonical_json_bytes(candidate_payload)
    candidate_path = tmp_path / "candidate-pool.json"
    candidate_path.write_bytes(candidate_raw)
    candidate_sha256 = hashlib.sha256(candidate_raw).hexdigest()
    selection_payload = _payload()
    selection_payload["bindings"]["candidate_manifest_sha256"] = candidate_sha256
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    raw = canonical_json_bytes(selection_payload)
    first.write_bytes(raw)
    second.write_bytes(raw)

    monkeypatch.setattr(verifier, "implementation_sha256", lambda path: IMPLEMENTATION_SHA256)
    monkeypatch.setattr(
        verifier,
        "materialize_candidate_pool",
        lambda **kwargs: candidate_payload,
    )
    monkeypatch.setattr(verifier, "load_prefetched_pool", lambda *args, **kwargs: object())
    monkeypatch.setattr(verifier, "load_source_verifier", lambda *args, **kwargs: object())
    monkeypatch.setattr(
        verifier,
        "_recompute_materialization_rejections",
        lambda *args, **kwargs: 1,
    )
    monkeypatch.setattr(
        verifier,
        "build_l4_public_selection",
        lambda *args, **kwargs: selection_payload,
    )

    kwargs = {
        "first": first,
        "second": second,
        "candidate_pool": candidate_path,
        "artifact_root": tmp_path,
        "source_receipts": tmp_path / "receipts",
        "source_checkouts": tmp_path / "sources",
        "capture_root": tmp_path / "capture",
        "existing_41": tmp_path / "existing.json",
        "prior_evidence_105": tmp_path / "prior.json",
        "source_verifier": tmp_path / "source-verifier.py",
        "expected_seed_sha256": SEED_SHA256,
        "expected_candidate_manifest_sha256": candidate_sha256,
        "expected_source_verifier_sha256": SOURCE_VERIFIER_SHA256,
        "expected_github_query_sha256": QUERY_SHA256,
        "expected_capture_manifest_sha256": CAPTURE_MANIFEST_SHA256,
        "expected_capture_implementation_sha256": IMPLEMENTATION_SHA256,
        "expected_candidate_materializer_sha256": IMPLEMENTATION_SHA256,
        "expected_selection_implementation_sha256": IMPLEMENTATION_SHA256,
        "expected_selection_cli_sha256": IMPLEMENTATION_SHA256,
        "verification_implementation_sha256": IMPLEMENTATION_SHA256,
    }
    return kwargs, candidate_payload, selection_payload


def test_pair_verifier_recomputes_full_population_before_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, _, _ = _fixture(tmp_path, monkeypatch)

    result = verify_selection_pair(**kwargs)

    assert result["evidence_gate"] == "PASS"
    assert result["field_fix"] is False
    assert result["field_status"] == "PENDING_DUAL_SUPERVISOR_GO"
    assert result["byte_identical"] is True
    assert result["selected_count"] == 59
    assert result["candidate_pool_recomputed"] is True
    assert result["physical_source_recomputed"] is True
    assert result["reserve_counts"] == {stratum: 1 for stratum in QUOTAS}
    output = tmp_path / "verification.json"
    write_verification(output, result)
    assert output.read_bytes() == canonical_json_bytes(result)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_verification(output, result)


def test_pair_verifier_rejects_empty_forged_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, _, _ = _fixture(tmp_path, monkeypatch)
    forged = _payload()
    forged["selected"] = []
    forged["bindings"]["candidate_manifest_sha256"] = kwargs[
        "expected_candidate_manifest_sha256"
    ]
    raw = canonical_json_bytes(forged)
    kwargs["first"].write_bytes(raw)
    kwargs["second"].write_bytes(raw)

    with pytest.raises(L4PairVerificationError, match="full recomputation"):
        verify_selection_pair(**kwargs)


def test_pair_verifier_rejects_a_b_byte_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, _, _ = _fixture(tmp_path, monkeypatch)
    kwargs["second"].write_bytes(kwargs["second"].read_bytes() + b" ")

    with pytest.raises(L4PairVerificationError, match="not byte-identical"):
        verify_selection_pair(**kwargs)


def test_pair_verifier_rejects_source_population_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, candidate_payload, _ = _fixture(tmp_path, monkeypatch)
    changed = dict(candidate_payload)
    changed["source_population_count"] = 66
    monkeypatch.setattr(
        verifier,
        "materialize_candidate_pool",
        lambda **ignored: changed,
    )

    with pytest.raises(L4PairVerificationError, match="recomputed source population"):
        verify_selection_pair(**kwargs)


def test_pair_verifier_rejects_implementation_or_binding_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, _, selection_payload = _fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(verifier, "implementation_sha256", lambda path: "f" * 64)
    with pytest.raises(L4PairVerificationError, match="executable bytes"):
        verify_selection_pair(**kwargs)

    monkeypatch.setattr(verifier, "implementation_sha256", lambda path: IMPLEMENTATION_SHA256)
    selection_payload["bindings"]["capture_manifest_sha256"] = "f" * 64
    raw = canonical_json_bytes(selection_payload)
    kwargs["first"].write_bytes(raw)
    kwargs["second"].write_bytes(raw)
    with pytest.raises(L4PairVerificationError, match="capture_manifest_sha256 mismatch"):
        verify_selection_pair(**kwargs)


def test_pair_verifier_rejects_pre_admission_candidate_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    kwargs, _, selection_payload = _fixture(tmp_path, monkeypatch)
    selection_payload["rejection_ledger"][0]["reasons"] = [
        "source_checkout_verification_failed"
    ]
    raw = canonical_json_bytes(selection_payload)
    kwargs["first"].write_bytes(raw)
    kwargs["second"].write_bytes(raw)

    with pytest.raises(L4PairVerificationError, match="full source and metadata"):
        verify_selection_pair(**kwargs)


def test_materialization_rejection_receipt_is_physically_recomputed(
    tmp_path: Path,
) -> None:
    repository_id = "rejected/app"
    sources = tmp_path / "sources"
    checkout = sources / "rejected--app"
    checkout.mkdir(parents=True)
    _git(checkout, "init")
    _git(checkout, "config", "user.email", "fixture@example.com")
    _git(checkout, "config", "user.name", "K-Guard Fixture")
    _git(checkout, "config", "core.autocrlf", "false")
    _git(
        checkout,
        "remote",
        "add",
        "origin",
        "https://github.com/rejected/app.git",
    )
    source_file = checkout / "app.txt"
    source_file.write_bytes(b"bound source\n")
    _git(checkout, "add", "app.txt")
    _git(checkout, "commit", "-m", "fixture")
    commit = _git(checkout, "rev-parse", "HEAD")
    tree = _git(checkout, "rev-parse", "HEAD^{tree}")
    receipt = build_git_materialization_receipt(
        checkout,
        expected_repository_id=repository_id,
        expected_commit=commit,
        expected_tree=tree,
    )
    assert receipt["schema"] == SOURCE_RECEIPT_SCHEMA
    raw = source_receipt_canonical_json_bytes(receipt)
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    (receipts / "rejected--app.json").write_bytes(raw)
    candidate_payload = {
        "materialization_rejection_ledger": [
            {
                "repository_id": repository_id,
                "source_receipt_sha256": hashlib.sha256(raw).hexdigest(),
            }
        ]
    }

    assert verifier._recompute_materialization_rejections(
        candidate_payload,
        source_receipts=receipts,
        source_checkouts=sources,
        bound_source_verifier=build_git_materialization_receipt,
    ) == 1

    source_file.write_bytes(b"tampered source\n")
    with pytest.raises(L4PairVerificationError, match="recomputation failed"):
        verifier._recompute_materialization_rejections(
            candidate_payload,
            source_receipts=receipts,
            source_checkouts=sources,
            bound_source_verifier=build_git_materialization_receipt,
        )

    source_file.write_bytes(b"bound source\n")
    noncanonical = raw + b" "
    (receipts / "rejected--app.json").write_bytes(noncanonical)
    candidate_payload["materialization_rejection_ledger"][0][
        "source_receipt_sha256"
    ] = hashlib.sha256(noncanonical).hexdigest()
    with pytest.raises(L4PairVerificationError, match="contract is invalid"):
        verifier._recompute_materialization_rejections(
            candidate_payload,
            source_receipts=receipts,
            source_checkouts=sources,
            bound_source_verifier=build_git_materialization_receipt,
        )
