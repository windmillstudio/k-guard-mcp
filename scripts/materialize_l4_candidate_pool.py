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

from k_guard_mcp.public_lineage import (
    GITHUB_METADATA_API,
    GITHUB_METADATA_QUERY_BYTES,
    INPUT_SCHEMA,
    QUOTAS,
    SOURCE_RECEIPT_SCHEMA,
    candidate_pool_sha256,
    candidate_record_sha256,
    canonical_json_bytes,
    first_party_file_set_sha256,
    star_stratum_for_count,
)
CAPTURE_SCHEMA = "k_guard_l4_github_metadata_capture.v1"
MAX_JSON_BYTES = 256 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REPOSITORY_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
_SPDX_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9.+-]*(?:\s+(?:AND|OR)\s+[A-Za-z0-9][A-Za-z0-9.+-]*)*$"
)
_ROOT_LICENSE_RE = re.compile(
    r"^(?:[A-Za-z0-9]+[-_.])?(?:licen[cs]e|copying|copyright|notice)(?:[._-][A-Za-z0-9._-]+)?$",
    re.IGNORECASE,
)
_CAPTURE_FIELDS = frozenset(
    {
        "schema",
        "capture_implementation_sha256",
        "api",
        "captured_at_utc",
        "query_path",
        "query_sha256",
        "repository_count",
        "repository_set_sha256",
        "responses",
        "network_accessed_during_capture",
        "network_accessed_during_selection",
        "scanner_imported",
        "scanner_output_observed",
        "raw_returned",
    }
)
_CAPTURE_ROW_FIELDS = frozenset(
    {"repository_id", "response_path", "response_sha256"}
)
_BUILD_MANIFEST_NAMES = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "cargo.toml",
        "go.mod",
        "gemfile",
        "composer.json",
        "mix.exs",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "deno.json",
        "deno.jsonc",
    }
)
_CONTAINER_MANIFEST_NAMES = frozenset(
    {
        "dockerfile",
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    }
)
_DEPLOYMENT_MANIFEST_NAMES = frozenset(
    {"procfile", "vercel.json", "fly.toml", "render.yaml", "render.yml"}
)


class CandidatePoolMaterializationError(RuntimeError):
    pass


def _is_link_or_reparse(path: Path, metadata: os.stat_result) -> bool:
    return path.is_symlink() or bool(
        getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _real_directory(path: Path, *, label: str) -> Path:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise CandidatePoolMaterializationError(f"{label} is unavailable") from exc
    if _is_link_or_reparse(path, metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise CandidatePoolMaterializationError(f"{label} must be a real directory")
    return path.resolve(strict=True)


def _read_regular_file(
    path: Path, *, expected_sha256: str | None = None, label: str
) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise CandidatePoolMaterializationError(f"{label} is unavailable") from exc
    if (
        _is_link_or_reparse(path, before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > MAX_JSON_BYTES
    ):
        raise CandidatePoolMaterializationError(
            f"{label} must be a bounded regular file"
        )
    raw = path.read_bytes()
    after = os.lstat(path)
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field, None) != getattr(after, field, None) for field in stable):
        raise CandidatePoolMaterializationError(f"{label} changed during read")
    if len(raw) != before.st_size:
        raise CandidatePoolMaterializationError(f"{label} changed during read")
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise CandidatePoolMaterializationError(f"{label} SHA-256 mismatch")
    return raw


def _decode_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CandidatePoolMaterializationError(
                    f"{label} contains duplicate JSON key"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                CandidatePoolMaterializationError(
                    f"{label} contains non-finite JSON: {token}"
                )
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CandidatePoolMaterializationError(
            f"{label} is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict):
        raise CandidatePoolMaterializationError(f"{label} must be a JSON object")
    return value


def _safe_relative_child(root: Path, value: object, *, label: str) -> Path:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith(("/", "\\"))
        or "\\" in value
        or ":" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise CandidatePoolMaterializationError(f"{label} path is invalid")
    path = root / Path(value)
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise CandidatePoolMaterializationError(f"{label} path is invalid") from exc
    return resolved


def _artifact_relative_path(root: Path, path: Path, *, label: str) -> str:
    try:
        resolved = path.resolve(strict=True)
        relative = resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise CandidatePoolMaterializationError(
            f"{label} must be inside artifact root"
        ) from exc
    return relative.as_posix()


def _repository_set_sha256(repository_ids: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(sorted(repository_ids), separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _load_capture(
    capture_root: Path, *, expected_manifest_sha256: str
) -> tuple[dict[str, Any], dict[str, tuple[Path, str]]]:
    capture_root = _real_directory(capture_root, label="capture root")
    if _SHA256_RE.fullmatch(expected_manifest_sha256) is None:
        raise CandidatePoolMaterializationError("capture manifest SHA-256 is invalid")
    raw = _read_regular_file(
        capture_root / "capture-manifest.json",
        expected_sha256=expected_manifest_sha256,
        label="capture manifest",
    )
    manifest = _decode_json_object(raw, label="capture manifest")
    if raw != canonical_json_bytes(manifest) or set(manifest) != _CAPTURE_FIELDS:
        raise CandidatePoolMaterializationError("capture manifest contract is invalid")
    expected_scalars = {
        "schema": CAPTURE_SCHEMA,
        "api": GITHUB_METADATA_API,
        "query_sha256": hashlib.sha256(GITHUB_METADATA_QUERY_BYTES).hexdigest(),
        "network_accessed_during_capture": True,
        "network_accessed_during_selection": False,
        "scanner_imported": False,
        "scanner_output_observed": False,
        "raw_returned": False,
    }
    if any(manifest.get(field) != expected for field, expected in expected_scalars.items()):
        raise CandidatePoolMaterializationError("capture manifest boundary is invalid")
    if (
        not isinstance(manifest.get("capture_implementation_sha256"), str)
        or _SHA256_RE.fullmatch(manifest["capture_implementation_sha256"]) is None
    ):
        raise CandidatePoolMaterializationError(
            "capture implementation SHA-256 is invalid"
        )
    query_path = _safe_relative_child(
        capture_root, manifest.get("query_path"), label="capture query"
    )
    if _read_regular_file(
        query_path,
        expected_sha256=str(manifest["query_sha256"]),
        label="capture query",
    ) != GITHUB_METADATA_QUERY_BYTES:
        raise CandidatePoolMaterializationError("capture query contract mismatch")
    rows = manifest.get("responses")
    if not isinstance(rows, list) or not rows:
        raise CandidatePoolMaterializationError("capture response rows are invalid")
    responses: dict[str, tuple[Path, str]] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != _CAPTURE_ROW_FIELDS:
            raise CandidatePoolMaterializationError("capture response row is invalid")
        repository_id = row.get("repository_id")
        response_sha256 = row.get("response_sha256")
        if (
            not isinstance(repository_id, str)
            or _REPOSITORY_RE.fullmatch(repository_id) is None
            or not isinstance(response_sha256, str)
            or _SHA256_RE.fullmatch(response_sha256) is None
            or repository_id in responses
        ):
            raise CandidatePoolMaterializationError("capture response identity is invalid")
        response_path = _safe_relative_child(
            capture_root, row.get("response_path"), label="GitHub response"
        )
        _read_regular_file(
            response_path,
            expected_sha256=response_sha256,
            label="GitHub response",
        )
        responses[repository_id] = (response_path, response_sha256)
    repository_ids = sorted(responses)
    if (
        manifest.get("repository_count") != len(repository_ids)
        or manifest.get("repository_set_sha256")
        != _repository_set_sha256(repository_ids)
    ):
        raise CandidatePoolMaterializationError("capture repository set mismatch")
    return manifest, responses


def _source_receipts(source_receipts: Path) -> dict[str, tuple[Path, dict[str, Any]]]:
    source_receipts = _real_directory(
        source_receipts, label="source receipt directory"
    )
    receipts: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(source_receipts.glob("*.json"), key=lambda value: value.name):
        raw = _read_regular_file(path, label="source receipt")
        receipt = _decode_json_object(raw, label="source receipt")
        repository_id = receipt.get("repository_id")
        if (
            receipt.get("schema") != SOURCE_RECEIPT_SCHEMA
            or receipt.get("passed") is not True
            or not isinstance(repository_id, str)
            or _REPOSITORY_RE.fullmatch(repository_id) is None
            or repository_id in receipts
        ):
            raise CandidatePoolMaterializationError("source receipt identity is invalid")
        receipts[repository_id] = (path, receipt)
    if not receipts:
        raise CandidatePoolMaterializationError("source receipts are empty")
    return receipts


def _receipt_files(receipt: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = receipt.get("files")
    if not isinstance(rows, list) or not rows:
        raise CandidatePoolMaterializationError("source receipt files are invalid")
    files: dict[str, dict[str, Any]] = {}
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or not isinstance(row.get("sha256"), str)
            or _SHA256_RE.fullmatch(row["sha256"]) is None
            or row["path"] in files
        ):
            raise CandidatePoolMaterializationError("source receipt file row is invalid")
        files[row["path"]] = row
    return files


def _root_license(files: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rows = [
        row
        for path, row in files.items()
        if "/" not in path and _ROOT_LICENSE_RE.fullmatch(path) is not None
    ]
    if not rows:
        raise CandidatePoolMaterializationError("root license evidence is missing")
    return min(
        rows,
        key=lambda row: (
            str(row["path"]).casefold() not in {"license", "license.md", "license.txt"},
            len(str(row["path"])),
            str(row["path"]).casefold(),
        ),
    )


def _deployable_evidence(
    files: dict[str, dict[str, Any]],
) -> list[dict[str, str]]:
    candidates: list[tuple[int, str, str, str]] = []
    for path, row in files.items():
        name = Path(path).name.casefold()
        if name in _CONTAINER_MANIFEST_NAMES:
            candidates.append((0, "container_manifest", path, row["sha256"]))
        elif name in _DEPLOYMENT_MANIFEST_NAMES or path.casefold().startswith(
            ("k8s/", "kubernetes/")
        ):
            candidates.append((1, "deployment_manifest", path, row["sha256"]))
        elif name in _BUILD_MANIFEST_NAMES or Path(path).suffix.casefold() in {
            ".csproj",
            ".sln",
        }:
            candidates.append((2, "build_manifest", path, row["sha256"]))
        elif path.casefold().startswith(".github/workflows/"):
            candidates.append((3, "ci_manifest", path, row["sha256"]))
    candidates.sort()
    selected: list[dict[str, str]] = []
    seen_kinds: set[str] = set()
    for _, kind, path, sha256 in candidates:
        if kind in seen_kinds:
            continue
        selected.append({"kind": kind, "path": path, "sha256": sha256})
        seen_kinds.add(kind)
        if len(selected) == 4:
            break
    return selected


def _github_repository(response_path: Path, response_sha256: str) -> dict[str, Any]:
    response = _decode_json_object(
        _read_regular_file(
            response_path,
            expected_sha256=response_sha256,
            label="GitHub response",
        ),
        label="GitHub response",
    )
    data = response.get("data")
    repository = data.get("repository") if isinstance(data, dict) else None
    if not isinstance(repository, dict):
        raise CandidatePoolMaterializationError("GitHub repository response is invalid")
    return repository


def _artifact_reference(
    root: Path, path: Path, *, role: str
) -> dict[str, Any]:
    raw = _read_regular_file(path, label=role)
    return {
        "artifact_path": _artifact_relative_path(root, path, label=role),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "role": role,
        "called_unseen": False,
        "accuracy_ground_truth": False,
    }


def materialize_candidate_pool(
    *,
    artifact_root: Path,
    source_receipts: Path,
    source_checkouts: Path,
    capture_root: Path,
    expected_capture_manifest_sha256: str,
    existing_41: Path,
    prior_evidence_105: Path,
) -> dict[str, Any]:
    root = _real_directory(artifact_root, label="artifact root")
    source_checkouts = _real_directory(
        source_checkouts, label="source checkout directory"
    )
    capture_manifest, responses = _load_capture(
        capture_root,
        expected_manifest_sha256=expected_capture_manifest_sha256,
    )
    receipts = _source_receipts(source_receipts)
    if set(receipts) != set(responses):
        raise CandidatePoolMaterializationError(
            "source receipt and GitHub response repository sets differ"
        )
    candidates: list[dict[str, Any]] = []
    materialization_rejections: list[dict[str, Any]] = []
    source_population_ids = sorted(receipts)
    for repository_id in sorted(receipts):
        receipt_path, receipt = receipts[repository_id]
        response_path, response_sha256 = responses[repository_id]
        repository = _github_repository(response_path, response_sha256)
        name_with_owner = repository.get("nameWithOwner")
        stars = repository.get("stargazerCount")
        node_id = repository.get("id")
        parent = repository.get("parent")
        if (
            not isinstance(name_with_owner, str)
            or name_with_owner.casefold() != repository_id
            or isinstance(stars, bool)
            or not isinstance(stars, int)
            or stars < 0
            or not isinstance(node_id, str)
            or not node_id
            or not isinstance(repository.get("isFork"), bool)
            or not isinstance(repository.get("isTemplate"), bool)
            or not isinstance(repository.get("isArchived"), bool)
            or (
                parent is not None
                and (
                    not isinstance(parent, dict)
                    or not isinstance(parent.get("nameWithOwner"), str)
                    or _REPOSITORY_RE.fullmatch(
                        parent["nameWithOwner"].casefold()
                    )
                    is None
                )
            )
        ):
            raise CandidatePoolMaterializationError(
                f"GitHub candidate fields are invalid: {repository_id}"
            )
        files = _receipt_files(receipt)
        source_receipt_sha256 = hashlib.sha256(
            _read_regular_file(receipt_path, label="source receipt")
        ).hexdigest()
        policy_reasons: list[str] = []
        try:
            license_row = _root_license(files)
        except CandidatePoolMaterializationError:
            license_row = None
            policy_reasons.append("root_license_file_missing")
        evidence = _deployable_evidence(files)
        if not any(
            row["kind"] in {"build_manifest", "container_manifest"}
            for row in evidence
        ):
            policy_reasons.append("source_build_or_container_manifest_missing")
        license_info = repository.get("licenseInfo")
        spdx = license_info.get("spdxId") if isinstance(license_info, dict) else None
        if (
            not isinstance(spdx, str)
            or spdx in {"NOASSERTION", "NONE"}
            or _SPDX_RE.fullmatch(spdx) is None
        ):
            policy_reasons.append("github_license_spdx_missing_or_invalid")
        checkout_path = source_checkouts / repository_id.replace("/", "--")
        try:
            checkout_metadata = os.lstat(checkout_path)
        except OSError as exc:
            raise CandidatePoolMaterializationError(
                f"source checkout is missing: {repository_id}"
            ) from exc
        if _is_link_or_reparse(checkout_path, checkout_metadata) or not stat.S_ISDIR(
            checkout_metadata.st_mode
        ):
            raise CandidatePoolMaterializationError(
                f"source checkout is invalid: {repository_id}"
            )
        if policy_reasons:
            materialization_rejections.append(
                {
                    "repository_id": repository_id,
                    "source_receipt_sha256": source_receipt_sha256,
                    "github_metadata_sha256": response_sha256,
                    "reasons": sorted(set(policy_reasons)),
                }
            )
            continue
        assert license_row is not None
        assert isinstance(spdx, str)
        parent_repository_id = (
            parent["nameWithOwner"].casefold() if isinstance(parent, dict) else None
        )
        row: dict[str, Any] = {
            "repository_id": repository_id,
            "github_node_id": node_id,
            "commit": receipt.get("commit"),
            "commit_tree": receipt.get("commit_tree"),
            "source_tree_sha256": receipt.get("source_tree_sha256"),
            "source_checkout_path": _artifact_relative_path(
                root, checkout_path, label="source checkout"
            ),
            "source_receipt_path": _artifact_relative_path(
                root, receipt_path, label="source receipt"
            ),
            "source_materialization_receipt_sha256": source_receipt_sha256,
            "github_metadata_path": _artifact_relative_path(
                root, response_path, label="GitHub response"
            ),
            "github_metadata_sha256": response_sha256,
            "is_fork": repository["isFork"],
            "is_template": repository["isTemplate"],
            "archived": repository["isArchived"],
            "natural_app_status": "public_repository_with_build_or_container_manifest",
            "lab_status": "github_metadata_screened_not_lab",
            "license_status": "root_license_bytes_and_github_spdx_bound_not_content_matched",
            "deployable_app_status": "source_build_or_container_manifest_bound_not_runtime_proven",
            "deployable_app_evidence": evidence,
            "excluded_as_lab": False,
            "excluded_as_ctf": False,
            "excluded_as_benchmark": False,
            "excluded_as_scanner_fixture": False,
            "root_license_path": license_row["path"],
            "license_spdx": spdx,
            "license_sha256": license_row["sha256"],
            "stars_at_seal": stars,
            "star_stratum": star_stratum_for_count(stars),
            "first_party_file_set_sha256": first_party_file_set_sha256(
                sorted(files)
            ),
            "parent_repository_id": parent_repository_id,
            "source_repository_id": None,
            "template_repository_id": None,
            "lineage_id": f"github-node:{node_id}",
        }
        row["candidate_sha256"] = candidate_record_sha256(row)
        candidates.append(row)
    counts = Counter(row["star_stratum"] for row in candidates)
    if any(
        counts[stratum] < quota + 1 for stratum, quota in QUOTAS.items()
    ):
        raise CandidatePoolMaterializationError(
            "L4 stratum reserve contract failed: "
            f"count={len(candidates)}, strata={dict(counts)}"
        )
    query_path = capture_root / str(capture_manifest["query_path"])
    return {
        "schema": INPUT_SCHEMA,
        "selection_boundary": {
            "prefetched_only": True,
            "network_accessed": False,
            "scanner_imported": False,
            "scanner_output_observed": False,
        },
        "source_population_count": len(source_population_ids),
        "source_population_repository_set_sha256": _repository_set_sha256(
            source_population_ids
        ),
        "candidate_count": len(candidates),
        "candidates_sha256": candidate_pool_sha256(candidates),
        "materialization_rejection_ledger": materialization_rejections,
        "github_query_reference": {
            "artifact_path": _artifact_relative_path(
                root, query_path, label="GitHub query"
            ),
            "artifact_sha256": capture_manifest["query_sha256"],
            "api": GITHUB_METADATA_API,
            "captured_at_utc": capture_manifest["captured_at_utc"],
        },
        "provenance": {
            "capture_manifest_sha256": expected_capture_manifest_sha256,
            "capture_implementation_sha256": capture_manifest[
                "capture_implementation_sha256"
            ],
            "candidate_materializer_sha256": hashlib.sha256(
                _read_regular_file(Path(__file__), label="candidate materializer")
            ).hexdigest(),
            "scanner_imported": False,
            "scanner_output_observed": False,
        },
        "existing_41_reference": _artifact_reference(
            root,
            existing_41,
            role="stress_noise_regression_actionability_only",
        ),
        "prior_evidence_105_reference": _artifact_reference(
            root,
            prior_evidence_105,
            role="historical_evidence_exclusion_only",
        ),
        "candidates": candidates,
    }


def write_candidate_pool(path: Path, payload: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite L4 candidate pool: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(canonical_json_bytes(payload))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the offline, source- and GitHub-bound L4 candidate pool."
    )
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--source-receipts", type=Path, required=True)
    parser.add_argument("--source-checkouts", type=Path, required=True)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--expected-capture-manifest-sha256", required=True)
    parser.add_argument("--existing-41", type=Path, required=True)
    parser.add_argument("--prior-evidence-105", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = materialize_candidate_pool(
        artifact_root=args.artifact_root,
        source_receipts=args.source_receipts,
        source_checkouts=args.source_checkouts,
        capture_root=args.capture_root,
        expected_capture_manifest_sha256=args.expected_capture_manifest_sha256,
        existing_41=args.existing_41,
        prior_evidence_105=args.prior_evidence_105,
    )
    write_candidate_pool(args.output, result)
    print(
        json.dumps(
            {
                "schema": result["schema"],
                "source_population_count": result["source_population_count"],
                "candidate_count": result["candidate_count"],
                "materialization_rejection_count": len(
                    result["materialization_rejection_ledger"]
                ),
                "strata": dict(Counter(row["star_stratum"] for row in result["candidates"])),
                "network_accessed": False,
                "scanner_output_observed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
