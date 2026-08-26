from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


INPUT_SCHEMA = "k_guard_l4_public_candidate_pool.v1"
OUTPUT_SCHEMA = "k_guard_l4_public_selection.v1"
SOURCE_RECEIPT_SCHEMA = "k_guard_git_source_materialization.v2"
SOURCE_TREE_SCHEMA = "k_guard_materialized_source_tree.v1"
GITHUB_METADATA_API = "github_graphql_v4"
SELECTION_ALGORITHM = "sha256_seed_nul_lineage_id_v1"
QUOTAS = {"top": 26, "mid": 26, "long_tail": 7}
STRATA = tuple(QUOTAS)
STAR_STRATUM_THRESHOLDS = {
    "top_minimum": 1000,
    "mid_minimum": 50,
    "long_tail_minimum": 0,
}
GITHUB_METADATA_QUERY_BYTES = b"""query KGuardRepositoryMetadata($owner: String!, $name: String!) {
  repository(owner: $owner, name: $name) {
    id
    nameWithOwner
    url
    isFork
    isTemplate
    isArchived
    stargazerCount
    description
    licenseInfo { spdxId }
    repositoryTopics(first: 20) { nodes { topic { name } } }
    parent { id nameWithOwner }
  }
}
"""

MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_SOURCE_VERIFIER_BYTES = 2 * 1024 * 1024
MAX_PATH_DEPTH = 256
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/+=-]{0,255}$")
_UTC_TIMESTAMP_RE = re.compile(r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z$")
_SPDX_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:AND|OR)\s+[A-Za-z0-9][A-Za-z0-9.+-]*)*$"
)
_ROOT_LICENSE_RE = re.compile(
    r"^(?:[A-Za-z0-9]+[-_.])?(?:licen[cs]e|copying|copyright|notice)(?:[._-][A-Za-z0-9._-]+)?$",
    re.IGNORECASE,
)
_WINDOWS_INVALID_COMPONENT_CHARS = frozenset('<>:"/\\|?*')
_WINDOWS_RESERVED_COMPONENTS = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "conin$",
        "conout$",
        "nul",
        "prn",
        *(f"com{suffix}" for suffix in (*range(1, 10), "¹", "²", "³")),
        *(f"lpt{suffix}" for suffix in (*range(1, 10), "¹", "²", "³")),
    }
)
_WINDOWS_SHORT_NAME_RE = re.compile(
    r"^\.?[^.]{1,6}~[1-9][0-9]*(?:\.[^.]{0,3})?$", re.IGNORECASE
)
_LAB_SIGNAL_RE = re.compile(
    r"(?:^|[^a-z0-9])(?:ctf|capture[- ]the[- ]flag|damn[- ]vulnerable|"
    r"intentionally[- ]vulnerable|security[- ]lab|scanner[- ]fixture|"
    r"benchmark[- ]suite|pentest[- ]training|owasp[- ]juice[- ]shop)(?:$|[^a-z0-9])",
    re.IGNORECASE,
)

_POOL_FIELDS = frozenset(
    {
        "schema",
        "selection_boundary",
        "source_population_count",
        "source_population_repository_set_sha256",
        "candidate_count",
        "candidates_sha256",
        "materialization_rejection_ledger",
        "github_query_reference",
        "provenance",
        "existing_41_reference",
        "prior_evidence_105_reference",
        "candidates",
    }
)
_MATERIALIZATION_REJECTION_FIELDS = frozenset(
    {
        "repository_id",
        "source_receipt_sha256",
        "github_metadata_sha256",
        "reasons",
    }
)
_MATERIALIZATION_REJECTION_REASONS = frozenset(
    {
        "github_license_spdx_missing_or_invalid",
        "root_license_file_missing",
        "source_build_or_container_manifest_missing",
    }
)
_PROVENANCE_FIELDS = frozenset(
    {
        "capture_manifest_sha256",
        "capture_implementation_sha256",
        "candidate_materializer_sha256",
        "scanner_imported",
        "scanner_output_observed",
    }
)
_GITHUB_QUERY_REFERENCE_FIELDS = frozenset(
    {"artifact_path", "artifact_sha256", "api", "captured_at_utc"}
)
_GITHUB_RESPONSE_FIELDS = frozenset({"data"})
_GITHUB_DATA_FIELDS = frozenset({"repository"})
_GITHUB_REPOSITORY_FIELDS = frozenset(
    {
        "id",
        "nameWithOwner",
        "url",
        "isFork",
        "isTemplate",
        "isArchived",
        "stargazerCount",
        "description",
        "licenseInfo",
        "repositoryTopics",
        "parent",
    }
)

_CANDIDATE_FIELDS = frozenset(
    {
        "repository_id",
        "github_node_id",
        "commit",
        "commit_tree",
        "source_tree_sha256",
        "source_checkout_path",
        "source_receipt_path",
        "source_materialization_receipt_sha256",
        "github_metadata_path",
        "github_metadata_sha256",
        "is_fork",
        "is_template",
        "archived",
        "natural_app_status",
        "lab_status",
        "license_status",
        "deployable_app_status",
        "deployable_app_evidence",
        "excluded_as_lab",
        "excluded_as_ctf",
        "excluded_as_benchmark",
        "excluded_as_scanner_fixture",
        "root_license_path",
        "license_spdx",
        "license_sha256",
        "stars_at_seal",
        "star_stratum",
        "first_party_file_set_sha256",
        "parent_repository_id",
        "source_repository_id",
        "template_repository_id",
        "lineage_id",
        "candidate_sha256",
    }
)
_EVIDENCE_FIELDS = frozenset({"kind", "path", "sha256"})
_EVIDENCE_KINDS = frozenset(
    {
        "application_entrypoint",
        "build_manifest",
        "container_manifest",
        "ci_manifest",
        "deployment_manifest",
        "framework_manifest",
    }
)
_SOURCE_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "passed",
        "repository_id",
        "origin_repository_id",
        "origin_repository_match",
        "commit",
        "commit_match",
        "commit_object_hash_match",
        "commit_tree",
        "commit_tree_match",
        "tree_object_reconstruction_match",
        "git_object_format",
        "git_repository_layout",
        "source_worktree_clean",
        "source_worktree_clean_method",
        "git_porcelain_clean",
        "index_tree_match",
        "physical_bytes_match_git_blobs",
        "git_fsck_strict_passed",
        "git_fsck_output_sha256",
        "scanner_visible_tree_contract",
        "source_tree_schema",
        "source_tree_sha256",
        "file_count",
        "total_bytes",
        "files",
        "raw_returned",
    }
)
_RECEIPT_FILE_FIELDS = frozenset(
    {"path", "mode", "git_blob_sha1", "sha256", "byte_count"}
)


class PublicPoolContractError(ValueError):
    """Raised when the pre-scan L4 population contract cannot be trusted."""


class _ArtifactError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class SealedCandidatePool:
    _raw: bytes
    manifest_sha256: str

    @property
    def payload(self) -> dict[str, Any]:
        return _decode_json_object(self._raw, label="sealed candidate manifest")


_SOURCE_VERIFIER_BINDING_TOKEN = object()


class BoundSourceVerifier:
    __slots__ = ("_source_bytes", "_verifier", "_sha256")

    def __init__(
        self,
        source_bytes: bytes,
        verifier: Callable[..., Mapping[str, Any]],
        sha256: str,
        *,
        _token: object,
    ) -> None:
        if _token is not _SOURCE_VERIFIER_BINDING_TOKEN:
            raise TypeError("BoundSourceVerifier must be created from verified bytes")
        object.__setattr__(self, "_source_bytes", bytes(source_bytes))
        object.__setattr__(self, "_verifier", verifier)
        object.__setattr__(self, "_sha256", sha256)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("BoundSourceVerifier is immutable")

    @property
    def sha256(self) -> str:
        return self._sha256

    def assert_integrity(self) -> None:
        if hashlib.sha256(self._source_bytes).hexdigest() != self.sha256:
            raise PublicPoolContractError("bound source verifier integrity failed")

    def __call__(self, *args: Any, **kwargs: Any) -> Mapping[str, Any]:
        self.assert_integrity()
        return self._verifier(*args, **kwargs)


def compile_source_verifier_bytes(
    raw: bytes, *, expected_sha256: str, filename: str
) -> BoundSourceVerifier:
    if not _is_sha256(expected_sha256):
        raise PublicPoolContractError("expected source verifier SHA-256 is invalid")
    if not raw or len(raw) > MAX_SOURCE_VERIFIER_BYTES:
        raise PublicPoolContractError("source verifier size is invalid")
    actual_sha256 = hashlib.sha256(raw).hexdigest()
    if actual_sha256 != expected_sha256:
        raise PublicPoolContractError("source verifier SHA-256 mismatch")
    namespace: dict[str, Any] = {
        "__name__": "k_guard_bound_source_verifier",
        "__file__": filename,
    }
    try:
        code = compile(raw, filename, "exec", dont_inherit=True)
        exec(code, namespace)
    except Exception as exc:
        raise PublicPoolContractError("source verifier could not be loaded") from exc
    verifier = namespace.get("build_git_materialization_receipt")
    if not callable(verifier):
        raise PublicPoolContractError(
            "source verifier does not export build_git_materialization_receipt"
        )
    return BoundSourceVerifier(
        raw,
        verifier,
        actual_sha256,
        _token=_SOURCE_VERIFIER_BINDING_TOKEN,
    )


def canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PublicPoolContractError("value is not canonical-JSON serializable") from exc


def source_receipt_canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PublicPoolContractError(
            "source receipt is not canonical-JSON serializable"
        ) from exc


def seal_candidate_pool_bytes(
    raw: bytes, *, expected_manifest_sha256: str
) -> SealedCandidatePool:
    if not _is_sha256(expected_manifest_sha256):
        raise PublicPoolContractError("expected candidate manifest SHA-256 is invalid")
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise PublicPoolContractError("candidate manifest size is invalid")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_manifest_sha256:
        raise PublicPoolContractError("candidate manifest SHA-256 mismatch")
    payload = _decode_json_object(raw, label="candidate manifest")
    if raw != canonical_json_bytes(payload):
        raise PublicPoolContractError("candidate manifest is not canonical JSON")
    return SealedCandidatePool(_raw=bytes(raw), manifest_sha256=actual)


def candidate_record_sha256(candidate: Mapping[str, Any]) -> str:
    subject = dict(candidate)
    subject.pop("candidate_sha256", None)
    return hashlib.sha256(
        b"k_guard_l4_public_candidate.v1\0" + canonical_json_bytes(subject)
    ).hexdigest()


def candidate_pool_sha256(candidates: Sequence[Mapping[str, Any]]) -> str:
    try:
        rows = [dict(row) for row in candidates]
    except (TypeError, ValueError) as exc:
        raise PublicPoolContractError("candidate pool contains a non-object row") from exc
    rows.sort(key=canonical_json_bytes)
    return hashlib.sha256(
        b"k_guard_l4_public_candidate_pool.v1\0" + canonical_json_bytes(rows)
    ).hexdigest()


def first_party_file_set_sha256(paths: Sequence[str]) -> str:
    return hashlib.sha256(
        b"k_guard_l4_first_party_file_set.v1\0"
        + canonical_json_bytes(sorted(paths))
    ).hexdigest()


def build_l4_public_selection(
    sealed_pool: SealedCandidatePool,
    *,
    seed_sha256: str,
    artifact_root: Path,
    source_verifier: BoundSourceVerifier,
    selection_implementation_sha256: str,
    selection_cli_sha256: str,
) -> dict[str, Any]:
    """Verify sealed receipts and deterministically select the L4 population."""

    if not isinstance(sealed_pool, SealedCandidatePool):
        raise PublicPoolContractError("candidate pool must be externally SHA-256 sealed")
    if type(source_verifier) is not BoundSourceVerifier:
        raise PublicPoolContractError(
            "source verifier must be bound to verified module bytes"
        )
    source_verifier.assert_integrity()
    if not _is_sha256(selection_implementation_sha256):
        raise PublicPoolContractError("selection implementation SHA-256 is invalid")
    if not _is_sha256(selection_cli_sha256):
        raise PublicPoolContractError("selection CLI SHA-256 is invalid")
    seed = _validate_seed(seed_sha256)
    root = _safe_artifact_root(artifact_root)
    payload = _require_pool(sealed_pool.payload)
    raw_candidates = payload["candidates"]
    github_query = _load_github_query_reference(
        payload.get("github_query_reference"), root
    )
    existing = _load_existing_41(payload.get("existing_41_reference"), root)
    prior_evidence = _load_prior_evidence_105(
        payload.get("prior_evidence_105_reference"), root
    )

    admitted: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    repository_occurrences = Counter(
        row.get("repository_id")
        for row in raw_candidates
        if isinstance(row, Mapping) and isinstance(row.get("repository_id"), str)
    )
    existing_ids = set(existing["repository_ids"])
    prior_ids = set(prior_evidence["repository_ids"])
    for index, raw in enumerate(raw_candidates):
        normalized, reasons = _admit_candidate(
            raw,
            index=index,
            artifact_root=root,
            source_verifier=source_verifier,
        )
        repository_id = _bounded_identity(raw, "repository_id", index)
        if repository_occurrences[repository_id] > 1:
            reasons.append("duplicate_repository_id")
        if repository_id in existing_ids:
            reasons.append("overlaps_existing_41")
        if repository_id in prior_ids:
            reasons.append("overlaps_prior_evidence_105")
        if reasons:
            rejections.append(
                _rejection(
                    index=index,
                    repository_id=repository_id,
                    candidate_sha256=_bounded_hash(raw),
                    reasons=reasons,
                )
            )
        elif normalized is not None:
            admitted.append(normalized)

    representatives, cluster_rejections, clusters = _cluster_candidates(admitted)
    rejections.extend(cluster_rejections)
    selected: list[dict[str, Any]] = []
    reserves: dict[str, list[dict[str, Any]]] = {}
    for stratum in STRATA:
        ranked = sorted(
            (row for row in representatives if row["star_stratum"] == stratum),
            key=lambda row: (
                hashlib.sha256(
                    seed + b"\0" + row["lineage_id"].encode("utf-8")
                ).digest(),
                row["lineage_id"],
                row["repository_id"],
            ),
        )
        quota = QUOTAS[stratum]
        if len(ranked) < quota + 1:
            raise PublicPoolContractError(
                f"insufficient receipt-backed lineage clusters for {stratum}: "
                f"required={quota + 1} including reserve, available={len(ranked)}"
            )
        selected.extend(_selection_row(row, seed) for row in ranked[:quota])
        reserves[stratum] = [
            {**_selection_row(row, seed), "reserve_position": position}
            for position, row in enumerate(ranked[quota:], start=1)
        ]

    selected.sort(key=lambda row: (STRATA.index(row["star_stratum"]), row["rank_sha256"]))
    rejections.sort(key=lambda row: (row["repository_id"], row["input_index"], row["reasons"]))
    counts = Counter(row["star_stratum"] for row in selected)
    if len(selected) != 59 or dict(counts) != QUOTAS:
        raise PublicPoolContractError("internal L4 selection quota invariant failed")
    if len({row["lineage_id"] for row in selected}) != 59:
        raise PublicPoolContractError("selected lineage IDs are not unique")

    result: dict[str, Any] = {
        "schema": OUTPUT_SCHEMA,
        "population_role": "l4_natural_public_actionability_and_output_burden",
        "qualification_authority": False,
        "accuracy_ground_truth": False,
        "scanner_output_observed": False,
        "network_accessed": False,
        "selection": {
            "algorithm": SELECTION_ALGORITHM,
            "seed_sha256": seed_sha256,
            "source_population_count": payload["source_population_count"],
            "admitted_candidate_count": len(raw_candidates),
            "materialization_rejection_count": len(
                payload["materialization_rejection_ledger"]
            ),
            "required_count": 59,
            "selected_count": len(selected),
            "quotas": dict(QUOTAS),
            "stratum_counts": {stratum: counts[stratum] for stratum in STRATA},
            "star_stratum_thresholds": dict(STAR_STRATUM_THRESHOLDS),
            "reserve_required_per_stratum": 1,
            "seed_affects_membership": True,
        },
        "bindings": {
            "candidate_manifest_sha256": sealed_pool.manifest_sha256,
            "input_candidate_pool_sha256": payload["candidates_sha256"],
            "source_population_repository_set_sha256": payload[
                "source_population_repository_set_sha256"
            ],
            "materialization_rejection_ledger_sha256": hashlib.sha256(
                canonical_json_bytes(payload["materialization_rejection_ledger"])
            ).hexdigest(),
            "selected_repository_set_sha256": _repository_set_sha256(selected),
            "source_verifier_sha256": source_verifier.sha256,
            "github_metadata_query_sha256": github_query["artifact_sha256"],
            "capture_manifest_sha256": payload["provenance"][
                "capture_manifest_sha256"
            ],
            "capture_implementation_sha256": payload["provenance"][
                "capture_implementation_sha256"
            ],
            "candidate_materializer_sha256": payload["provenance"][
                "candidate_materializer_sha256"
            ],
            "selection_implementation_sha256": selection_implementation_sha256,
            "selection_cli_sha256": selection_cli_sha256,
        },
        "github_query_reference": github_query,
        "existing_41_reference": existing,
        "prior_evidence_105_reference": prior_evidence,
        "selected": selected,
        "reserves": reserves,
        "rejection_ledger": rejections,
        "cluster_ledger": clusters,
        "counts": {
            "input_candidates": len(raw_candidates),
            "admitted_before_clustering": len(admitted),
            "independent_lineage_clusters": len(representatives),
            "rejected_candidates": len(rejections),
            "reserve_candidates": sum(len(rows) for rows in reserves.values()),
        },
        "claim_boundary": {
            "existing_41_and_new_59_are_separate": True,
            "prior_evidence_105_and_new_59_are_separate": True,
            "existing_41_called_unseen": False,
            "existing_41_used_as_accuracy_ground_truth": False,
            "new_59_called_unseen": False,
            "new_59_used_as_accuracy_ground_truth": False,
            "findings_may_be_called_tp_fp_fn": False,
            "source_checkouts_recomputed": True,
            "github_primary_metadata_prefetched_and_verified": True,
            "source_population_fully_accounted": True,
            "source_runtime_deployment_proven": False,
            "license_file_content_classified_to_github_spdx": False,
            "population_representative_of_all_github_apps": False,
            "requires_bound_artifact_root_for_replay": True,
            "self_contained_evidence_archive": False,
            "allowed_claims": ["actionability_proxy", "output_burden"],
        },
    }
    result["bindings"]["output_subject_sha256"] = _output_subject_sha256(result)
    return result


def _require_pool(pool: object) -> dict[str, Any]:
    if not isinstance(pool, Mapping) or pool.get("schema") != INPUT_SCHEMA:
        raise PublicPoolContractError(f"candidate pool schema must be {INPUT_SCHEMA}")
    if set(pool) != _POOL_FIELDS:
        raise PublicPoolContractError("candidate pool fields are invalid")
    expected_boundary = {
        "prefetched_only": True,
        "network_accessed": False,
        "scanner_imported": False,
        "scanner_output_observed": False,
    }
    if pool.get("selection_boundary") != expected_boundary:
        raise PublicPoolContractError("candidate pool selection boundary is invalid")
    rows = pool.get("candidates")
    if isinstance(rows, (str, bytes)) or not isinstance(rows, Sequence) or not rows:
        raise PublicPoolContractError("candidate pool must contain candidates")
    if isinstance(pool.get("candidate_count"), bool) or pool.get("candidate_count") != len(rows):
        raise PublicPoolContractError("candidate pool count is invalid")
    expected_hash = pool.get("candidates_sha256")
    if not _is_sha256(expected_hash) or candidate_pool_sha256(rows) != expected_hash:  # type: ignore[arg-type]
        raise PublicPoolContractError("candidate pool hash mismatch")
    _validate_materialization_population(pool, rows)
    provenance = pool.get("provenance")
    if not isinstance(provenance, Mapping) or set(provenance) != _PROVENANCE_FIELDS:
        raise PublicPoolContractError("candidate pool provenance fields are invalid")
    for field in (
        "capture_manifest_sha256",
        "capture_implementation_sha256",
        "candidate_materializer_sha256",
    ):
        if not _is_sha256(provenance.get(field)):
            raise PublicPoolContractError(f"candidate pool {field} is invalid")
    if (
        provenance.get("scanner_imported") is not False
        or provenance.get("scanner_output_observed") is not False
    ):
        raise PublicPoolContractError("candidate pool provenance boundary is invalid")
    return dict(pool)


def _validate_materialization_population(
    pool: Mapping[str, Any], rows: Sequence[object]
) -> None:
    source_count = pool.get("source_population_count")
    source_hash = pool.get("source_population_repository_set_sha256")
    ledger = pool.get("materialization_rejection_ledger")
    if (
        isinstance(source_count, bool)
        or not isinstance(source_count, int)
        or source_count < sum(QUOTAS.values()) + len(QUOTAS)
        or not _is_sha256(source_hash)
        or not isinstance(ledger, list)
    ):
        raise PublicPoolContractError("source population contract is invalid")

    repository_ids: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping) or not _is_repository_id(
            row.get("repository_id")
        ):
            raise PublicPoolContractError("candidate repository identity is invalid")
        repository_ids.append(str(row["repository_id"]))

    for rejection in ledger:
        if (
            not isinstance(rejection, Mapping)
            or set(rejection) != _MATERIALIZATION_REJECTION_FIELDS
            or not _is_repository_id(rejection.get("repository_id"))
            or not _is_sha256(rejection.get("source_receipt_sha256"))
            or not _is_sha256(rejection.get("github_metadata_sha256"))
        ):
            raise PublicPoolContractError(
                "materialization rejection ledger row is invalid"
            )
        reasons = rejection.get("reasons")
        if (
            not isinstance(reasons, list)
            or not reasons
            or reasons != sorted(set(reasons))
            or any(reason not in _MATERIALIZATION_REJECTION_REASONS for reason in reasons)
        ):
            raise PublicPoolContractError(
                "materialization rejection reasons are invalid"
            )
        repository_ids.append(str(rejection["repository_id"]))

    repository_ids.sort()
    if len(repository_ids) != source_count or len(set(repository_ids)) != source_count:
        raise PublicPoolContractError("source population count or uniqueness is invalid")
    actual_hash = hashlib.sha256(
        json.dumps(repository_ids, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    if actual_hash != source_hash:
        raise PublicPoolContractError("source population repository set hash mismatch")


def _load_github_query_reference(value: object, root: Path) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _GITHUB_QUERY_REFERENCE_FIELDS:
        raise PublicPoolContractError("GitHub query reference fields are invalid")
    if value.get("api") != GITHUB_METADATA_API:
        raise PublicPoolContractError("GitHub metadata API is invalid")
    captured_at = value.get("captured_at_utc")
    if not isinstance(captured_at, str) or _UTC_TIMESTAMP_RE.fullmatch(captured_at) is None:
        raise PublicPoolContractError("GitHub metadata capture time is invalid")
    try:
        datetime.strptime(captured_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise PublicPoolContractError("GitHub metadata capture time is invalid") from exc
    try:
        raw = _read_bound_artifact(
            root,
            value.get("artifact_path"),
            value.get("artifact_sha256"),
            label="github_query",
        )
    except _ArtifactError as exc:
        raise PublicPoolContractError(f"github_query:{exc.code}") from exc
    if raw != GITHUB_METADATA_QUERY_BYTES:
        raise PublicPoolContractError("GitHub metadata query contract mismatch")
    return dict(value)


def _load_existing_41(value: object, root: Path) -> dict[str, Any]:
    reference, payload = _load_exclusion_artifact(
        value,
        root,
        label="existing_41",
        expected_role="stress_noise_regression_actionability_only",
    )
    if (
        payload.get("schema") != "k_guard_independent_holdout_selection.v1"
        or payload.get("raw_returned") is not False
        or payload.get("repository_count") != 41
    ):
        raise PublicPoolContractError("existing 41 artifact contract is invalid")
    rows = payload.get("apps")
    if not isinstance(rows, list):
        raise PublicPoolContractError("existing 41 artifact apps are invalid")
    ids = _derive_repository_ids(rows, expected_count=41, label="existing 41")
    _verify_repository_set(payload, ids, label="existing 41")
    return {**reference, "app_count": 41, "repository_ids": ids}


def _load_prior_evidence_105(value: object, root: Path) -> dict[str, Any]:
    reference, payload = _load_exclusion_artifact(
        value,
        root,
        label="prior_evidence_105",
        expected_role="historical_evidence_exclusion_only",
    )
    if (
        payload.get("schema") != "k_guard_holdout_exclusions.v1"
        or payload.get("raw_returned") is not False
        or payload.get("repository_count") != 105
    ):
        raise PublicPoolContractError("prior evidence 105 artifact contract is invalid")
    rows = payload.get("repositories")
    if not isinstance(rows, list):
        raise PublicPoolContractError("prior evidence 105 repositories are invalid")
    ids = _derive_repository_ids(rows, expected_count=105, label="prior evidence 105")
    _verify_repository_set(payload, ids, label="prior evidence 105")
    return {**reference, "app_count": 105, "repository_ids": ids}


def _load_exclusion_artifact(
    value: object, root: Path, *, label: str, expected_role: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    required = {
        "artifact_path",
        "artifact_sha256",
        "role",
        "called_unseen",
        "accuracy_ground_truth",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise PublicPoolContractError(f"{label} reference fields are invalid")
    if (
        value.get("role") != expected_role
        or value.get("called_unseen") is not False
        or value.get("accuracy_ground_truth") is not False
    ):
        raise PublicPoolContractError(f"{label} claim boundary is invalid")
    try:
        raw = _read_bound_artifact(
            root,
            value.get("artifact_path"),
            value.get("artifact_sha256"),
            label=label,
        )
        payload = _decode_json_object(raw, label=label)
    except _ArtifactError as exc:
        raise PublicPoolContractError(f"{label}:{exc.code}") from exc
    return dict(value), payload


def _derive_repository_ids(
    rows: Sequence[object], *, expected_count: int, label: str
) -> list[str]:
    ids: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping) or not _is_repository_id(row.get("repository_id")):
            raise PublicPoolContractError(f"{label} repository row is invalid")
        ids.append(str(row["repository_id"]))
    ids.sort()
    if len(ids) != expected_count or len(set(ids)) != expected_count:
        raise PublicPoolContractError(f"{label} repository count or uniqueness is invalid")
    return ids


def _verify_repository_set(payload: Mapping[str, Any], ids: list[str], *, label: str) -> None:
    actual = hashlib.sha256(
        json.dumps(ids, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    if payload.get("repository_set_sha256") != actual:
        raise PublicPoolContractError(f"{label} repository set hash mismatch")


def _admit_candidate(
    raw: object,
    *,
    index: int,
    artifact_root: Path,
    source_verifier: BoundSourceVerifier,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(raw, Mapping):
        return None, ["candidate_not_object"]
    reasons: list[str] = []
    if set(raw) != _CANDIDATE_FIELDS:
        reasons.append("candidate_fields_invalid")
    repository_id = raw.get("repository_id")
    if not _is_repository_id(repository_id):
        reasons.append("repository_id_invalid")
    if not _is_identifier(raw.get("github_node_id")):
        reasons.append("github_node_id_invalid")
    for field in ("commit", "commit_tree"):
        if not isinstance(raw.get(field), str) or _GIT_SHA1_RE.fullmatch(raw[field]) is None:
            reasons.append(f"{field}_invalid")
    for field in (
        "source_tree_sha256",
        "source_materialization_receipt_sha256",
        "github_metadata_sha256",
        "license_sha256",
        "first_party_file_set_sha256",
    ):
        if not _is_sha256(raw.get(field)):
            reasons.append(f"{field}_invalid")
    if not _is_safe_relative_path(raw.get("source_checkout_path")):
        reasons.append("source_checkout_path_invalid")
    if not _is_safe_relative_path(raw.get("github_metadata_path")):
        reasons.append("github_metadata_path_invalid")
    for field in ("is_fork", "is_template", "archived"):
        if raw.get(field) is not False:
            reasons.append(f"{field}_not_false")
    for field, expected in (
        (
            "natural_app_status",
            "public_repository_with_build_or_container_manifest",
        ),
        ("lab_status", "github_metadata_screened_not_lab"),
        (
            "license_status",
            "root_license_bytes_and_github_spdx_bound_not_content_matched",
        ),
        (
            "deployable_app_status",
            "source_build_or_container_manifest_bound_not_runtime_proven",
        ),
    ):
        if raw.get(field) != expected:
            reasons.append(f"{field}_inconclusive_or_invalid")
    for field in (
        "excluded_as_lab",
        "excluded_as_ctf",
        "excluded_as_benchmark",
        "excluded_as_scanner_fixture",
    ):
        if raw.get(field) is not False:
            reasons.append(f"{field}_not_false")
    _validate_deployable_evidence_shape(raw.get("deployable_app_evidence"), reasons)
    if not isinstance(raw.get("root_license_path"), str) or _ROOT_LICENSE_RE.fullmatch(raw["root_license_path"]) is None:
        reasons.append("root_license_path_invalid")
    spdx = raw.get("license_spdx")
    if not isinstance(spdx, str) or spdx in {"NOASSERTION", "NONE"} or _SPDX_RE.fullmatch(spdx) is None:
        reasons.append("license_spdx_invalid")
    stars = raw.get("stars_at_seal")
    if isinstance(stars, bool) or not isinstance(stars, int) or stars < 0:
        reasons.append("stars_at_seal_invalid")
    if raw.get("star_stratum") not in QUOTAS:
        reasons.append("star_stratum_invalid")
    elif isinstance(stars, int) and not isinstance(stars, bool):
        if raw.get("star_stratum") != star_stratum_for_count(stars):
            reasons.append("star_stratum_threshold_mismatch")
    for field in ("parent_repository_id", "source_repository_id", "template_repository_id"):
        if raw.get(field) is not None and not _is_repository_id(raw.get(field)):
            reasons.append(f"{field}_invalid")
    if not _is_identifier(raw.get("lineage_id")):
        reasons.append("lineage_id_invalid")
    elif raw.get("lineage_id") != f"github-node:{raw.get('github_node_id')}":
        reasons.append("lineage_id_not_github_node_bound")
    if not _is_sha256(raw.get("candidate_sha256")):
        reasons.append("candidate_sha256_invalid")
    elif candidate_record_sha256(raw) != raw.get("candidate_sha256"):
        reasons.append("candidate_sha256_mismatch")

    if not reasons:
        reasons.extend(_verify_github_metadata(raw, artifact_root))
    if not reasons:
        reasons.extend(
            _verify_candidate_receipt(raw, artifact_root, source_verifier)
        )
    if reasons:
        return None, sorted(set(reasons))
    normalized = {field: raw[field] for field in sorted(_CANDIDATE_FIELDS)}
    normalized["input_index"] = index
    normalized["receipt_backed"] = True
    return normalized, []


def star_stratum_for_count(stars: int) -> str:
    if isinstance(stars, bool) or not isinstance(stars, int) or stars < 0:
        raise ValueError("star count must be a non-negative integer")
    if stars >= STAR_STRATUM_THRESHOLDS["top_minimum"]:
        return "top"
    if stars >= STAR_STRATUM_THRESHOLDS["mid_minimum"]:
        return "mid"
    return "long_tail"


def _verify_github_metadata(
    candidate: Mapping[str, Any], root: Path
) -> list[str]:
    try:
        raw = _read_bound_artifact(
            root,
            candidate.get("github_metadata_path"),
            candidate.get("github_metadata_sha256"),
            label="github_metadata",
        )
        response = _decode_json_object(raw, label="GitHub metadata response")
    except (_ArtifactError, PublicPoolContractError) as exc:
        code = exc.code if isinstance(exc, _ArtifactError) else "json_invalid"
        return [f"github_metadata_{code}"]
    if set(response) != _GITHUB_RESPONSE_FIELDS:
        return ["github_metadata_response_fields_invalid"]
    data = response.get("data")
    if not isinstance(data, Mapping) or set(data) != _GITHUB_DATA_FIELDS:
        return ["github_metadata_data_fields_invalid"]
    repository = data.get("repository")
    if not isinstance(repository, Mapping) or set(repository) != _GITHUB_REPOSITORY_FIELDS:
        return ["github_metadata_repository_fields_invalid"]

    errors: list[str] = []
    repository_id = str(candidate.get("repository_id"))
    node_id = repository.get("id")
    if not _is_identifier(node_id) or node_id != candidate.get("github_node_id"):
        errors.append("github_metadata_node_id_mismatch")
    name_with_owner = repository.get("nameWithOwner")
    if (
        not isinstance(name_with_owner, str)
        or name_with_owner.casefold() != repository_id
    ):
        errors.append("github_metadata_repository_id_mismatch")
    url = repository.get("url")
    expected_url = f"https://github.com/{repository_id}"
    if not isinstance(url, str) or url.casefold() != expected_url:
        errors.append("github_metadata_url_mismatch")
    expected_flags = {
        "isFork": candidate.get("is_fork"),
        "isTemplate": candidate.get("is_template"),
        "isArchived": candidate.get("archived"),
    }
    for field, expected in expected_flags.items():
        if repository.get(field) is not expected:
            errors.append(f"github_metadata_{field}_mismatch")
    stars = repository.get("stargazerCount")
    if (
        isinstance(stars, bool)
        or not isinstance(stars, int)
        or stars < 0
        or stars != candidate.get("stars_at_seal")
    ):
        errors.append("github_metadata_stars_mismatch")

    description = repository.get("description")
    if description is not None and (
        not isinstance(description, str) or len(description) > 4096
    ):
        errors.append("github_metadata_description_invalid")
        description = ""
    topics = repository.get("repositoryTopics")
    topic_names: list[str] = []
    if not isinstance(topics, Mapping) or set(topics) != {"nodes"}:
        errors.append("github_metadata_topics_invalid")
    else:
        nodes = topics.get("nodes")
        if not isinstance(nodes, list) or len(nodes) > 20:
            errors.append("github_metadata_topics_invalid")
        else:
            for node in nodes:
                if (
                    not isinstance(node, Mapping)
                    or set(node) != {"topic"}
                    or not isinstance(node.get("topic"), Mapping)
                    or set(node["topic"]) != {"name"}
                ):
                    errors.append("github_metadata_topics_invalid")
                    continue
                name = node["topic"].get("name")
                if not isinstance(name, str) or not name or len(name) > 128:
                    errors.append("github_metadata_topics_invalid")
                    continue
                topic_names.append(name)
            if len(topic_names) != len(set(value.casefold() for value in topic_names)):
                errors.append("github_metadata_topics_duplicate")
    screening_text = " ".join(
        [repository_id, description or "", *topic_names]
    )
    if _LAB_SIGNAL_RE.search(screening_text) is not None:
        errors.append("github_metadata_lab_signal_present")

    license_info = repository.get("licenseInfo")
    if (
        not isinstance(license_info, Mapping)
        or set(license_info) != {"spdxId"}
        or license_info.get("spdxId") != candidate.get("license_spdx")
    ):
        errors.append("github_metadata_license_mismatch")
    if repository.get("parent") is not None:
        errors.append("github_metadata_parent_not_null")
    for field in (
        "parent_repository_id",
        "source_repository_id",
        "template_repository_id",
    ):
        if candidate.get(field) is not None:
            errors.append(f"github_metadata_{field}_not_null")
    return sorted(set(errors))


def _verify_candidate_receipt(
    candidate: Mapping[str, Any],
    root: Path,
    source_verifier: BoundSourceVerifier,
) -> list[str]:
    try:
        raw = _read_bound_artifact(
            root,
            candidate.get("source_receipt_path"),
            candidate.get("source_materialization_receipt_sha256"),
            label="source_receipt",
        )
        receipt = _decode_json_object(raw, label="source receipt")
    except (_ArtifactError, PublicPoolContractError) as exc:
        if isinstance(exc, _ArtifactError):
            code = exc.code
        else:
            code = "json_invalid"
        return [f"source_receipt_{code}"]
    errors: list[str] = []
    if set(receipt) != _SOURCE_RECEIPT_FIELDS or receipt.get("schema") != SOURCE_RECEIPT_SCHEMA:
        return ["source_receipt_contract_invalid"]
    if raw != source_receipt_canonical_json_bytes(receipt):
        errors.append("source_receipt_not_canonical")
    required_true = (
        "passed",
        "origin_repository_match",
        "commit_match",
        "commit_object_hash_match",
        "commit_tree_match",
        "tree_object_reconstruction_match",
        "source_worktree_clean",
        "index_tree_match",
        "physical_bytes_match_git_blobs",
        "git_fsck_strict_passed",
    )
    if any(receipt.get(field) is not True for field in required_true):
        errors.append("source_receipt_verification_not_passed")
    expected_scalars = {
        "repository_id": candidate.get("repository_id"),
        "origin_repository_id": candidate.get("repository_id"),
        "commit": candidate.get("commit"),
        "commit_tree": candidate.get("commit_tree"),
        "source_tree_sha256": candidate.get("source_tree_sha256"),
        "git_object_format": "sha1",
        "git_repository_layout": "ordinary_non_shallow_standalone_clone",
        "source_worktree_clean_method": "git_blob_sha256_file_set_plus_index_tree_v2",
        "scanner_visible_tree_contract": "regular-file paths and raw Git blob bytes; Git modes remain commit-bound metadata",
        "source_tree_schema": SOURCE_TREE_SCHEMA,
        "raw_returned": False,
    }
    for field, expected in expected_scalars.items():
        if receipt.get(field) != expected:
            errors.append(f"source_receipt_{field}_mismatch")
    if not isinstance(receipt.get("git_porcelain_clean"), bool):
        errors.append("source_receipt_git_porcelain_clean_invalid")
    if not _is_sha256(receipt.get("git_fsck_output_sha256")):
        errors.append("source_receipt_fsck_hash_invalid")
    files, file_errors = _receipt_file_map(receipt)
    errors.extend(file_errors)
    if not file_errors:
        paths = sorted(files)
        if first_party_file_set_sha256(paths) != candidate.get("first_party_file_set_sha256"):
            errors.append("first_party_file_set_sha256_mismatch")
        license_path = str(candidate.get("root_license_path"))
        license_row = files.get(license_path)
        if license_row is None or license_row["sha256"] != candidate.get("license_sha256"):
            errors.append("license_evidence_mismatch")
        for evidence in candidate.get("deployable_app_evidence", []):
            row = files.get(str(evidence["path"]))
            if row is None or row["sha256"] != evidence["sha256"]:
                errors.append("deployable_evidence_mismatch")
    try:
        checkout = _resolve_artifact_directory(
            root,
            candidate.get("source_checkout_path"),
            label="source_checkout",
        )
    except _ArtifactError as exc:
        errors.append(f"source_checkout_{exc.code}")
    else:
        try:
            recomputed = source_verifier(
                checkout,
                expected_repository_id=str(candidate.get("repository_id")),
                expected_commit=str(candidate.get("commit")),
                expected_tree=str(candidate.get("commit_tree")),
            )
        except Exception:
            errors.append("source_checkout_verification_failed")
        else:
            if not isinstance(recomputed, Mapping):
                errors.append("source_verifier_result_invalid")
            elif dict(recomputed) != receipt:
                errors.append("source_receipt_recomputed_mismatch")
    return errors


def _receipt_file_map(
    receipt: Mapping[str, Any],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    rows = receipt.get("files")
    if not isinstance(rows, list) or not rows:
        return {}, ["source_receipt_files_invalid"]
    files: dict[str, dict[str, Any]] = {}
    windows_prefixes: dict[str, str] = {}
    errors: list[str] = []
    source_rows: list[dict[str, Any]] = []
    total_bytes = 0
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != _RECEIPT_FILE_FIELDS:
            errors.append("source_receipt_file_row_invalid")
            continue
        path = row.get("path")
        byte_count = row.get("byte_count")
        if (
            not _is_safe_relative_path(path)
            or row.get("mode") not in {"100644", "100755"}
            or not isinstance(row.get("git_blob_sha1"), str)
            or _GIT_SHA1_RE.fullmatch(str(row.get("git_blob_sha1"))) is None
            or not _is_sha256(row.get("sha256"))
            or isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count < 0
        ):
            errors.append("source_receipt_file_row_invalid")
            continue
        if path in files:
            errors.append("source_receipt_duplicate_file_path")
            continue
        try:
            _register_windows_path(str(path), windows_prefixes)
        except ValueError:
            errors.append("source_receipt_windows_path_invalid")
        normalized = dict(row)
        files[str(path)] = normalized
        total_bytes += byte_count
        source_rows.append(
            {
                "path": path,
                "sha256": row["sha256"],
                "git_blob_sha1": row["git_blob_sha1"],
                "byte_count": byte_count,
            }
        )
    source_rows.sort(key=lambda row: row["path"])
    tree_hash = hashlib.sha256(
        (SOURCE_TREE_SCHEMA + "\0").encode("ascii")
        + json.dumps(
            source_rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    if receipt.get("file_count") != len(files) or receipt.get("total_bytes") != total_bytes:
        errors.append("source_receipt_file_totals_mismatch")
    if receipt.get("source_tree_sha256") != tree_hash:
        errors.append("source_receipt_source_tree_recompute_mismatch")
    return files, sorted(set(errors))


def _validate_deployable_evidence_shape(value: object, reasons: list[str]) -> None:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        reasons.append("deployable_app_evidence_missing")
        return
    seen: set[tuple[str, str]] = set()
    kinds: set[str] = set()
    for item in value:
        if not isinstance(item, Mapping) or set(item) != _EVIDENCE_FIELDS:
            reasons.append("deployable_app_evidence_invalid")
            continue
        if item.get("kind") not in _EVIDENCE_KINDS:
            reasons.append("deployable_app_evidence_kind_invalid")
        else:
            kinds.add(str(item["kind"]))
        if not _is_safe_relative_path(item.get("path")):
            reasons.append("deployable_app_evidence_path_invalid")
        if not _is_sha256(item.get("sha256")):
            reasons.append("deployable_app_evidence_sha256_invalid")
        key = (str(item.get("kind")), str(item.get("path")))
        if key in seen:
            reasons.append("deployable_app_evidence_duplicate")
        seen.add(key)
    if not kinds.intersection({"build_manifest", "container_manifest"}):
        reasons.append("deployable_app_build_or_container_manifest_missing")


def _safe_artifact_root(root: Path) -> Path:
    absolute = root.absolute()
    try:
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise PublicPoolContractError("artifact root is unavailable") from exc
    if _is_link_or_reparse(absolute, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise PublicPoolContractError("artifact root must be a real directory")
    return absolute.resolve(strict=True)


def _resolve_artifact_directory(
    root: Path, relative_value: object, *, label: str
) -> Path:
    if not _is_safe_relative_path(relative_value):
        raise _ArtifactError("path_invalid")
    relative = Path(str(relative_value))
    current = root
    for part in relative.parts:
        try:
            _windows_component_key(part)
        except ValueError as exc:
            raise _ArtifactError("path_invalid") from exc
        current = current / part
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise _ArtifactError("missing") from exc
        if _is_link_or_reparse(current, metadata):
            raise _ArtifactError("symlink_or_reparse")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise _ArtifactError("outside_root") from exc
    metadata = os.lstat(resolved)
    if not stat.S_ISDIR(metadata.st_mode):
        raise _ArtifactError("not_directory")
    return resolved


def _read_bound_artifact(
    root: Path, relative_value: object, expected_sha256: object, *, label: str
) -> bytes:
    if not _is_sha256(expected_sha256):
        raise _ArtifactError("sha256_invalid")
    if not _is_safe_relative_path(relative_value):
        raise _ArtifactError("path_invalid")
    relative = Path(str(relative_value))
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise _ArtifactError("missing") from exc
        if _is_link_or_reparse(current, metadata):
            raise _ArtifactError("symlink_or_reparse")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise _ArtifactError("outside_root") from exc
    metadata = os.lstat(resolved)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > MAX_ARTIFACT_BYTES:
        raise _ArtifactError("not_bounded_regular_file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise _ArtifactError("open_failed") from exc
    try:
        before = os.fstat(descriptor)
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    # CPython 3.12 changed ``st_ctime`` on Windows to the creation time for
    # path-based stat calls, while the CRT-backed ``fstat`` used for an open
    # descriptor can still expose the legacy metadata-change value.  Comparing
    # those two values therefore rejects an unchanged file nondeterministically.
    # ``st_birthtime_ns`` is the cross-API creation-time field on 3.12+; on
    # older supported interpreters the file ID, size and mtime still bind the
    # path to the descriptor.  Descriptor-to-descriptor checks below retain
    # ctime so a change during the read remains fail-closed.
    path_to_descriptor = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if os.name == "nt" and hasattr(metadata, "st_birthtime_ns"):
        path_to_descriptor += ("st_birthtime_ns",)
    elif os.name != "nt":
        path_to_descriptor += ("st_ctime_ns",)
    if any(
        getattr(metadata, field, None) != getattr(before, field, None)
        for field in path_to_descriptor
    ):
        raise _ArtifactError("changed_before_read")
    descriptor_stable = (
        "st_dev",
        "st_ino",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if any(
        getattr(before, field, None) != getattr(after, field, None)
        for field in descriptor_stable
    ):
        raise _ArtifactError("changed_during_read")
    if len(raw) != metadata.st_size or len(raw) > MAX_ARTIFACT_BYTES:
        raise _ArtifactError("changed_during_read")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise _ArtifactError("sha256_mismatch")
    return raw


def _decode_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PublicPoolContractError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                PublicPoolContractError(f"{label} contains non-finite number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PublicPoolContractError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise PublicPoolContractError(f"{label} must be a JSON object")
    return payload


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _register_windows_path(path: str, seen: dict[str, str]) -> None:
    parts = path.split("/")
    if len(parts) > MAX_PATH_DEPTH + 1:
        raise ValueError("path depth")
    normalized_parts: list[str] = []
    original_parts: list[str] = []
    for part in parts:
        normalized_parts.append(_windows_component_key(part))
        original_parts.append(part)
        normalized_prefix = "/".join(normalized_parts)
        original_prefix = "/".join(original_parts)
        previous = seen.setdefault(normalized_prefix, original_prefix)
        if previous != original_prefix:
            raise ValueError("path collision")


def _windows_component_key(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or value.endswith((".", " "))
        or any(ord(character) < 32 for character in value)
        or any(character in _WINDOWS_INVALID_COMPONENT_CHARS for character in value)
        or len(value.encode("utf-16-le")) // 2 > 255
    ):
        raise ValueError("unsafe Windows path")
    normalized = unicodedata.normalize("NFC", value).casefold()
    device_stem = normalized.split(".", 1)[0].rstrip(" .")
    if (
        normalized == ".git"
        or device_stem == ".git"
        or device_stem in _WINDOWS_RESERVED_COMPONENTS
        or _WINDOWS_SHORT_NAME_RE.fullmatch(normalized) is not None
    ):
        raise ValueError("reserved Windows path")
    return normalized


def _cluster_candidates(
    candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    parent = list(range(len(candidates)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    token_owner: dict[str, int] = {}
    for index, candidate in enumerate(candidates):
        for token in _lineage_tokens(candidate):
            union(index, token_owner.setdefault(token, index))
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, candidate in enumerate(candidates):
        grouped[find(index)].append(candidate)

    representatives: list[dict[str, Any]] = []
    rejections: list[dict[str, Any]] = []
    ledger: list[dict[str, Any]] = []
    for members in grouped.values():
        members.sort(key=lambda row: row["repository_id"])
        cluster_id = _cluster_id(members)
        strata = {row["star_stratum"] for row in members}
        lineage_ids = {row["lineage_id"] for row in members}
        if len(strata) != 1 or len(lineage_ids) != 1:
            reasons = []
            if len(strata) != 1:
                reasons.append("lineage_cluster_stratum_conflict")
            if len(lineage_ids) != 1:
                reasons.append("lineage_cluster_id_conflict")
            for member in members:
                rejections.append(
                    _rejection(
                        index=member["input_index"],
                        repository_id=member["repository_id"],
                        candidate_sha256=member["candidate_sha256"],
                        reasons=reasons,
                        cluster_id=cluster_id,
                    )
                )
            disposition, representative_id = "rejected_conflict", None
        else:
            representative = dict(members[0])
            representative["cluster_id"] = cluster_id
            representatives.append(representative)
            for member in members[1:]:
                rejections.append(
                    _rejection(
                        index=member["input_index"],
                        repository_id=member["repository_id"],
                        candidate_sha256=member["candidate_sha256"],
                        reasons=["lineage_cluster_duplicate"],
                        cluster_id=cluster_id,
                    )
                )
            disposition, representative_id = "admitted_one_repository", representative["repository_id"]
        ledger.append(
            {
                "cluster_id": cluster_id,
                "disposition": disposition,
                "member_repository_ids": [row["repository_id"] for row in members],
                "representative_repository_id": representative_id,
            }
        )
    ledger.sort(key=lambda row: row["cluster_id"])
    return representatives, rejections, ledger


def _lineage_tokens(candidate: Mapping[str, Any]) -> set[str]:
    tokens = {
        f"node:{candidate['github_node_id']}",
        f"repository:{candidate['repository_id']}",
        f"tree:{candidate['commit_tree']}",
        f"first-party:{candidate['first_party_file_set_sha256']}",
        f"lineage:{candidate['lineage_id']}",
    }
    for field in ("parent_repository_id", "source_repository_id", "template_repository_id"):
        if candidate[field] is not None:
            tokens.add(f"repository:{candidate[field]}")
    return tokens


def _cluster_id(members: Sequence[Mapping[str, Any]]) -> str:
    tokens = sorted({token for member in members for token in _lineage_tokens(member)})
    return "sha256:" + hashlib.sha256(
        b"k_guard_l4_lineage_cluster.v1\0" + canonical_json_bytes(tokens)
    ).hexdigest()


def _selection_row(candidate: Mapping[str, Any], seed: bytes) -> dict[str, Any]:
    rank = hashlib.sha256(
        seed + b"\0" + candidate["lineage_id"].encode("utf-8")
    ).hexdigest()
    row = {field: candidate[field] for field in sorted(_CANDIDATE_FIELDS)}
    row.update({"cluster_id": candidate["cluster_id"], "rank_sha256": rank, "receipt_backed": True})
    return row


def _rejection(
    *,
    index: int,
    repository_id: str,
    candidate_sha256: str | None,
    reasons: Sequence[str],
    cluster_id: str | None = None,
) -> dict[str, Any]:
    return {
        "input_index": index,
        "repository_id": repository_id,
        "candidate_sha256": candidate_sha256,
        "cluster_id": cluster_id,
        "reasons": sorted(set(reasons)),
    }


def _validate_seed(value: object) -> bytes:
    if not _is_sha256(value):
        raise PublicPoolContractError("seed_sha256 must be 64 lowercase hex characters")
    return bytes.fromhex(str(value))


def _output_subject_sha256(result: Mapping[str, Any]) -> str:
    subject = json.loads(json.dumps(result))
    subject["bindings"].pop("output_subject_sha256", None)
    return hashlib.sha256(
        b"k_guard_l4_public_selection.v1\0" + canonical_json_bytes(subject)
    ).hexdigest()


def _repository_set_sha256(rows: Sequence[Mapping[str, Any]]) -> str:
    ids = sorted(row["repository_id"] for row in rows)
    return hashlib.sha256(json.dumps(ids, separators=(",", ":")).encode("ascii")).hexdigest()


def _bounded_identity(raw: object, field: str, index: int) -> str:
    if isinstance(raw, Mapping):
        value = raw.get(field)
        if isinstance(value, str) and value and len(value) <= 256 and "\x00" not in value:
            return value
    return f"invalid-candidate-{index:06d}"


def _bounded_hash(raw: object) -> str | None:
    if isinstance(raw, Mapping) and _is_sha256(raw.get("candidate_sha256")):
        return str(raw["candidate_sha256"])
    return None


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _is_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER_RE.fullmatch(value) is not None


def _is_repository_id(value: object) -> bool:
    return isinstance(value, str) and _REPOSITORY_RE.fullmatch(value) is not None


def _is_safe_relative_path(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\x00" in value:
        return False
    if value.startswith(("/", "\\")) or "\\" in value or ":" in value:
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} for part in parts)
