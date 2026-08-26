from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from collections import Counter
from pathlib import Path
from typing import Any

import k_guard_mcp.public_lineage as public_lineage_module

from k_guard_mcp.public_lineage import (
    OUTPUT_SCHEMA,
    QUOTAS,
    PublicPoolContractError,
    SOURCE_RECEIPT_SCHEMA,
    build_l4_public_selection,
    canonical_json_bytes,
    source_receipt_canonical_json_bytes,
)
try:
    from scripts.build_l4_public_pool import (
        implementation_sha256,
        load_prefetched_pool,
        load_source_verifier,
    )
    from scripts.materialize_l4_candidate_pool import (
        CandidatePoolMaterializationError,
        materialize_candidate_pool,
    )
except ModuleNotFoundError as exc:
    if exc.name is None or not exc.name.startswith("scripts"):
        raise
    from build_l4_public_pool import (  # type: ignore[no-redef]
        implementation_sha256,
        load_prefetched_pool,
        load_source_verifier,
    )
    from materialize_l4_candidate_pool import (  # type: ignore[no-redef]
        CandidatePoolMaterializationError,
        materialize_candidate_pool,
    )


PAIR_SCHEMA = "k_guard_l4_selection_pair_verification.v1"
MAX_SELECTION_BYTES = 256 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
_SCRIPT_ROOT = Path(__file__).resolve().parent
_POST_ADMISSION_REASONS = frozenset(
    {
        "duplicate_repository_id",
        "lineage_cluster_duplicate",
        "lineage_cluster_id_conflict",
        "lineage_cluster_stratum_conflict",
        "overlaps_existing_41",
        "overlaps_prior_evidence_105",
    }
)


class L4PairVerificationError(RuntimeError):
    pass


def _read_stable(path: Path, *, label: str) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise L4PairVerificationError(f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or bool(
            getattr(before, "st_file_attributes", 0)
            & FILE_ATTRIBUTE_REPARSE_POINT
        )
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > MAX_SELECTION_BYTES
    ):
        raise L4PairVerificationError(
            f"{label} must be a bounded regular file"
        )
    raw = path.read_bytes()
    after = os.lstat(path)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field, None) != getattr(after, field, None) for field in stable):
        raise L4PairVerificationError(f"{label} changed during read")
    if len(raw) != before.st_size:
        raise L4PairVerificationError(f"{label} changed during read")
    return raw


def _decode(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise L4PairVerificationError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or raw != canonical_json_bytes(value):
        raise L4PairVerificationError(f"{label} is not canonical JSON")
    return value


def _require_sha256(value: str, *, label: str) -> None:
    if _SHA256_RE.fullmatch(value) is None:
        raise L4PairVerificationError(f"{label} is not a SHA-256 value")


def _recompute_materialization_rejections(
    candidate_payload: dict[str, Any],
    *,
    source_receipts: Path,
    source_checkouts: Path,
    bound_source_verifier: Any,
) -> int:
    ledger = candidate_payload.get("materialization_rejection_ledger")
    if not isinstance(ledger, list):
        raise L4PairVerificationError("materialization rejection ledger is invalid")
    count = 0
    for rejection in ledger:
        if not isinstance(rejection, dict):
            raise L4PairVerificationError("materialization rejection row is invalid")
        repository_id = rejection.get("repository_id")
        if (
            not isinstance(repository_id, str)
            or _REPOSITORY_RE.fullmatch(repository_id) is None
        ):
            raise L4PairVerificationError("materialization rejection identity is invalid")
        receipt_path = source_receipts / f"{repository_id.replace('/', '--')}.json"
        receipt_raw = _read_stable(receipt_path, label="rejected source receipt")
        if hashlib.sha256(receipt_raw).hexdigest() != rejection.get(
            "source_receipt_sha256"
        ):
            raise L4PairVerificationError("rejected source receipt SHA-256 mismatch")
        try:
            receipt = json.loads(receipt_raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise L4PairVerificationError("rejected source receipt is invalid") from exc
        if (
            not isinstance(receipt, dict)
            or receipt.get("schema") != SOURCE_RECEIPT_SCHEMA
            or receipt.get("passed") is not True
            or receipt.get("repository_id") != repository_id
            or receipt_raw != source_receipt_canonical_json_bytes(receipt)
        ):
            raise L4PairVerificationError(
                "rejected source receipt contract is invalid"
            )
        checkout = source_checkouts / repository_id.replace("/", "--")
        try:
            recomputed = bound_source_verifier(
                checkout,
                expected_repository_id=repository_id,
                expected_commit=str(receipt.get("commit")),
                expected_tree=str(receipt.get("commit_tree")),
            )
        except Exception as exc:
            raise L4PairVerificationError(
                "rejected source checkout recomputation failed"
            ) from exc
        if not isinstance(recomputed, dict) or recomputed != receipt:
            raise L4PairVerificationError(
                "rejected source receipt differs from physical checkout"
            )
        count += 1
    return count


def verify_selection_pair(
    *,
    first: Path,
    second: Path,
    candidate_pool: Path,
    artifact_root: Path,
    source_receipts: Path,
    source_checkouts: Path,
    capture_root: Path,
    existing_41: Path,
    prior_evidence_105: Path,
    source_verifier: Path,
    expected_seed_sha256: str,
    expected_candidate_manifest_sha256: str,
    expected_source_verifier_sha256: str,
    expected_github_query_sha256: str,
    expected_capture_manifest_sha256: str,
    expected_capture_implementation_sha256: str,
    expected_candidate_materializer_sha256: str,
    expected_selection_implementation_sha256: str,
    expected_selection_cli_sha256: str,
    verification_implementation_sha256: str,
) -> dict[str, Any]:
    expected = {
        "candidate_manifest_sha256": expected_candidate_manifest_sha256,
        "source_verifier_sha256": expected_source_verifier_sha256,
        "github_metadata_query_sha256": expected_github_query_sha256,
        "capture_manifest_sha256": expected_capture_manifest_sha256,
        "capture_implementation_sha256": expected_capture_implementation_sha256,
        "candidate_materializer_sha256": expected_candidate_materializer_sha256,
        "selection_implementation_sha256": expected_selection_implementation_sha256,
        "selection_cli_sha256": expected_selection_cli_sha256,
    }
    for label, value in expected.items():
        _require_sha256(value, label=label)
    _require_sha256(expected_seed_sha256, label="expected_seed_sha256")
    _require_sha256(
        verification_implementation_sha256,
        label="verification_implementation_sha256",
    )

    actual_implementations = {
        "capture_implementation_sha256": implementation_sha256(
            _SCRIPT_ROOT / "capture_l4_github_metadata.py"
        ),
        "candidate_materializer_sha256": implementation_sha256(
            _SCRIPT_ROOT / "materialize_l4_candidate_pool.py"
        ),
        "selection_implementation_sha256": implementation_sha256(
            Path(public_lineage_module.__file__)
        ),
        "selection_cli_sha256": implementation_sha256(
            _SCRIPT_ROOT / "build_l4_public_pool.py"
        ),
        "verification_implementation_sha256": implementation_sha256(Path(__file__)),
    }
    expected_implementations = {
        "capture_implementation_sha256": expected_capture_implementation_sha256,
        "candidate_materializer_sha256": expected_candidate_materializer_sha256,
        "selection_implementation_sha256": expected_selection_implementation_sha256,
        "selection_cli_sha256": expected_selection_cli_sha256,
        "verification_implementation_sha256": verification_implementation_sha256,
    }
    for field, actual in actual_implementations.items():
        if actual != expected_implementations[field]:
            raise L4PairVerificationError(f"{field} does not match executable bytes")

    candidate_raw = _read_stable(candidate_pool, label="candidate pool")
    if hashlib.sha256(candidate_raw).hexdigest() != expected_candidate_manifest_sha256:
        raise L4PairVerificationError("candidate pool SHA-256 mismatch")
    candidate_payload = _decode(candidate_raw, label="candidate pool")
    try:
        recomputed_pool = materialize_candidate_pool(
            artifact_root=artifact_root,
            source_receipts=source_receipts,
            source_checkouts=source_checkouts,
            capture_root=capture_root,
            expected_capture_manifest_sha256=expected_capture_manifest_sha256,
            existing_41=existing_41,
            prior_evidence_105=prior_evidence_105,
        )
    except CandidatePoolMaterializationError as exc:
        raise L4PairVerificationError(
            "candidate pool source-population recomputation failed"
        ) from exc
    if canonical_json_bytes(recomputed_pool) != candidate_raw:
        raise L4PairVerificationError(
            "candidate pool does not match recomputed source population"
        )
    if (
        recomputed_pool.get("provenance", {}).get("capture_implementation_sha256")
        != expected_capture_implementation_sha256
        or recomputed_pool.get("provenance", {}).get(
            "candidate_materializer_sha256"
        )
        != expected_candidate_materializer_sha256
    ):
        raise L4PairVerificationError("candidate pool implementation binding mismatch")

    try:
        sealed_pool = load_prefetched_pool(
            candidate_pool,
            expected_sha256=expected_candidate_manifest_sha256,
        )
        bound_source_verifier = load_source_verifier(
            source_verifier,
            expected_sha256=expected_source_verifier_sha256,
        )
        materialization_rejection_source_recompute_count = (
            _recompute_materialization_rejections(
                candidate_payload,
                source_receipts=source_receipts,
                source_checkouts=source_checkouts,
                bound_source_verifier=bound_source_verifier,
            )
        )
        recomputed_selection = build_l4_public_selection(
            sealed_pool,
            seed_sha256=expected_seed_sha256,
            artifact_root=artifact_root,
            source_verifier=bound_source_verifier,
            selection_implementation_sha256=expected_selection_implementation_sha256,
            selection_cli_sha256=expected_selection_cli_sha256,
        )
    except PublicPoolContractError as exc:
        raise L4PairVerificationError("full L4 selection recomputation failed") from exc
    recomputed_raw = canonical_json_bytes(recomputed_selection)

    first_raw = _read_stable(first, label="first selection")
    second_raw = _read_stable(second, label="second selection")
    if first_raw != second_raw:
        raise L4PairVerificationError("L4 selections are not byte-identical")
    if first_raw != recomputed_raw:
        raise L4PairVerificationError("L4 selection differs from full recomputation")
    payload = _decode(first_raw, label="selection")
    if payload.get("schema") != OUTPUT_SCHEMA:
        raise L4PairVerificationError("L4 selection schema is invalid")
    selection = payload.get("selection")
    if (
        not isinstance(selection, dict)
        or selection.get("selected_count") != 59
        or selection.get("stratum_counts") != QUOTAS
        or selection.get("quotas") != QUOTAS
    ):
        raise L4PairVerificationError("L4 selection quota contract failed")
    selected = payload.get("selected")
    reserves = payload.get("reserves")
    selection_rejections = payload.get("rejection_ledger")
    counts = payload.get("counts")
    if not isinstance(selected, list) or len(selected) != 59:
        raise L4PairVerificationError("L4 selected population is incomplete")
    selected_counts = Counter(
        row.get("star_stratum") for row in selected if isinstance(row, dict)
    )
    repository_ids = [
        row.get("repository_id") for row in selected if isinstance(row, dict)
    ]
    if (
        len(repository_ids) != 59
        or len(set(repository_ids)) != 59
        or dict(selected_counts) != QUOTAS
        or not isinstance(reserves, dict)
        or set(reserves) != set(QUOTAS)
        or any(
            not isinstance(reserves[stratum], list)
            or len(reserves[stratum]) < 1
            for stratum in QUOTAS
        )
    ):
        raise L4PairVerificationError("L4 membership and reserve contract failed")
    if (
        not isinstance(selection_rejections, list)
        or not isinstance(counts, dict)
        or counts.get("input_candidates") != recomputed_pool["candidate_count"]
        or any(
            not isinstance(row, dict)
            or not isinstance(row.get("reasons"), list)
            or any(
                reason not in _POST_ADMISSION_REASONS
                for reason in row["reasons"]
            )
            for row in selection_rejections
        )
    ):
        raise L4PairVerificationError(
            "not every candidate passed full source and metadata admission"
        )
    if (
        payload.get("network_accessed") is not False
        or payload.get("scanner_output_observed") is not False
        or payload.get("accuracy_ground_truth") is not False
        or payload.get("qualification_authority") is not False
    ):
        raise L4PairVerificationError("L4 selection claim boundary failed")
    claim_boundary = payload.get("claim_boundary")
    if (
        not isinstance(claim_boundary, dict)
        or claim_boundary.get("new_59_called_unseen") is not False
        or claim_boundary.get("new_59_used_as_accuracy_ground_truth") is not False
        or claim_boundary.get("findings_may_be_called_tp_fp_fn") is not False
        or claim_boundary.get("source_population_fully_accounted") is not True
        or claim_boundary.get("source_runtime_deployment_proven") is not False
        or claim_boundary.get(
            "license_file_content_classified_to_github_spdx"
        )
        is not False
        or claim_boundary.get("population_representative_of_all_github_apps")
        is not False
        or claim_boundary.get("requires_bound_artifact_root_for_replay") is not True
        or claim_boundary.get("self_contained_evidence_archive") is not False
        or claim_boundary.get("allowed_claims")
        != ["actionability_proxy", "output_burden"]
    ):
        raise L4PairVerificationError("L4 selection allowed claims are invalid")
    bindings = payload.get("bindings")
    if not isinstance(bindings, dict):
        raise L4PairVerificationError("L4 selection bindings are invalid")
    for field, value in expected.items():
        if bindings.get(field) != value:
            raise L4PairVerificationError(f"L4 selection {field} mismatch")
    selection_sha256 = hashlib.sha256(first_raw).hexdigest()
    return {
        "schema": PAIR_SCHEMA,
        "evidence_gate": "PASS",
        "field_fix": False,
        "field_status": "PENDING_DUAL_SUPERVISOR_GO",
        "selection_a_sha256": selection_sha256,
        "selection_b_sha256": selection_sha256,
        "byte_identical": True,
        "selected_count": 59,
        "stratum_counts": dict(QUOTAS),
        "source_population_count": recomputed_pool["source_population_count"],
        "candidate_count": recomputed_pool["candidate_count"],
        "materialization_rejection_count": len(
            recomputed_pool["materialization_rejection_ledger"]
        ),
        "materialization_rejection_source_recompute_count": (
            materialization_rejection_source_recompute_count
        ),
        "reserve_counts": {
            stratum: len(reserves[stratum]) for stratum in QUOTAS
        },
        "bindings": expected,
        "seed_sha256": expected_seed_sha256,
        "verification_implementation_sha256": verification_implementation_sha256,
        "candidate_pool_recomputed": True,
        "physical_source_recomputed": True,
        "github_responses_reverified": True,
        "bound_artifact_root_replayed": True,
        "network_accessed_during_selection": False,
        "scanner_output_observed": False,
        "accuracy_ground_truth": False,
        "allowed_claims": ["actionability_proxy", "output_burden"],
        "requires_bound_artifact_root_for_replay": True,
        "self_contained_evidence_archive": False,
        "raw_returned": False,
    }


def write_verification(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite L4 pair verification: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(canonical_json_bytes(payload))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify repeated L4 selections and their provenance bindings."
    )
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--candidate-pool", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--source-receipts", type=Path, required=True)
    parser.add_argument("--source-checkouts", type=Path, required=True)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--existing-41", type=Path, required=True)
    parser.add_argument("--prior-evidence-105", type=Path, required=True)
    parser.add_argument("--source-verifier", type=Path, required=True)
    parser.add_argument("--expected-seed-sha256", required=True)
    parser.add_argument("--expected-candidate-manifest-sha256", required=True)
    parser.add_argument("--expected-source-verifier-sha256", required=True)
    parser.add_argument("--expected-github-query-sha256", required=True)
    parser.add_argument("--expected-capture-manifest-sha256", required=True)
    parser.add_argument("--expected-capture-implementation-sha256", required=True)
    parser.add_argument("--expected-candidate-materializer-sha256", required=True)
    parser.add_argument("--expected-selection-implementation-sha256", required=True)
    parser.add_argument("--expected-selection-cli-sha256", required=True)
    parser.add_argument(
        "--expected-verification-implementation-sha256", required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify_selection_pair(
        first=args.first,
        second=args.second,
        candidate_pool=args.candidate_pool,
        artifact_root=args.artifact_root,
        source_receipts=args.source_receipts,
        source_checkouts=args.source_checkouts,
        capture_root=args.capture_root,
        existing_41=args.existing_41,
        prior_evidence_105=args.prior_evidence_105,
        source_verifier=args.source_verifier,
        expected_seed_sha256=args.expected_seed_sha256,
        expected_candidate_manifest_sha256=args.expected_candidate_manifest_sha256,
        expected_source_verifier_sha256=args.expected_source_verifier_sha256,
        expected_github_query_sha256=args.expected_github_query_sha256,
        expected_capture_manifest_sha256=args.expected_capture_manifest_sha256,
        expected_capture_implementation_sha256=args.expected_capture_implementation_sha256,
        expected_candidate_materializer_sha256=args.expected_candidate_materializer_sha256,
        expected_selection_implementation_sha256=args.expected_selection_implementation_sha256,
        expected_selection_cli_sha256=args.expected_selection_cli_sha256,
        verification_implementation_sha256=(
            args.expected_verification_implementation_sha256
        ),
    )
    write_verification(args.output, result)
    print(
        json.dumps(
            {
                "evidence_gate": result["evidence_gate"],
                "field_fix": result["field_fix"],
                "field_status": result["field_status"],
                "selection_sha256": result["selection_a_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
