from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from k_guard_mcp.public_lineage import (
    GITHUB_METADATA_API,
    GITHUB_METADATA_QUERY_BYTES,
    INPUT_SCHEMA,
    QUOTAS,
    PublicPoolContractError,
    build_l4_public_selection,
    candidate_pool_sha256,
    candidate_record_sha256,
    canonical_json_bytes,
    compile_source_verifier_bytes,
    first_party_file_set_sha256,
    seal_candidate_pool_bytes,
    source_receipt_canonical_json_bytes,
)
from scripts.build_l4_public_pool import (
    load_prefetched_pool,
    load_source_verifier,
    write_selection,
)


SEED = "7" * 64
SELECTION_IMPLEMENTATION_SHA256 = "d" * 64
SELECTION_CLI_SHA256 = "e" * 64
SOURCE_TREE_SCHEMA = "k_guard_materialized_source_tree.v1"


def _source_tree_sha256(files: list[dict]) -> str:
    rows = [
        {
            "path": row["path"],
            "sha256": row["sha256"],
            "git_blob_sha1": row["git_blob_sha1"],
            "byte_count": row["byte_count"],
        }
        for row in files
    ]
    rows.sort(key=lambda row: row["path"])
    return hashlib.sha256(
        (SOURCE_TREE_SCHEMA + "\0").encode("ascii")
        + json.dumps(
            rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _repository_set_sha256(ids: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(sorted(ids), separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _write_json(path: Path, payload: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_json_bytes(payload)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _write_source_receipt(path: Path, payload: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = source_receipt_canonical_json_bytes(payload)
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _file(path: str, content: bytes, *, mode: str = "100644") -> dict:
    return {
        "path": path,
        "mode": mode,
        "git_blob_sha1": hashlib.sha1(
            f"blob {len(content)}\0".encode("ascii") + content,
            usedforsecurity=False,
        ).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "byte_count": len(content),
    }


def _source_contents(repository_id: str) -> dict[str, bytes]:
    return {
        "LICENSE": b"MIT License fixture\n",
        "package.json": b'{"scripts":{"start":"node app.js"}}\n',
        f"src/{repository_id.replace('/', '-')}.js": (
            f"export const app = {repository_id!r};\n".encode("utf-8")
        ),
    }


def _receipt(repository_id: str, commit: str, tree: str) -> dict:
    files = [
        _file(path, content)
        for path, content in sorted(_source_contents(repository_id).items())
    ]
    return {
        "schema": "k_guard_git_source_materialization.v2",
        "passed": True,
        "repository_id": repository_id,
        "origin_repository_id": repository_id,
        "origin_repository_match": True,
        "commit": commit,
        "commit_match": True,
        "commit_object_hash_match": True,
        "commit_tree": tree,
        "commit_tree_match": True,
        "tree_object_reconstruction_match": True,
        "git_object_format": "sha1",
        "git_repository_layout": "ordinary_non_shallow_standalone_clone",
        "source_worktree_clean": True,
        "source_worktree_clean_method": "git_blob_sha256_file_set_plus_index_tree_v2",
        "git_porcelain_clean": True,
        "index_tree_match": True,
        "physical_bytes_match_git_blobs": True,
        "git_fsck_strict_passed": True,
        "git_fsck_output_sha256": hashlib.sha256(b"").hexdigest(),
        "scanner_visible_tree_contract": "regular-file paths and raw Git blob bytes; Git modes remain commit-bound metadata",
        "source_tree_schema": SOURCE_TREE_SCHEMA,
        "source_tree_sha256": _source_tree_sha256(files),
        "file_count": len(files),
        "total_bytes": sum(row["byte_count"] for row in files),
        "files": files,
        "raw_returned": False,
    }


def _materialize_source(root: Path, relative: str, repository_id: str) -> None:
    checkout = root / relative
    for path, content in _source_contents(repository_id).items():
        target = checkout / Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _fixture_stars(stratum: str, index: int) -> int:
    if stratum == "top":
        return 1000 + index
    if stratum == "mid":
        return 50 + index
    return index


def _github_metadata_response(
    repository_id: str, *, node_id: str, stars: int, license_spdx: str = "MIT"
) -> dict:
    owner, name = repository_id.split("/", 1)
    return {
        "data": {
            "repository": {
                "id": node_id,
                "nameWithOwner": f"{owner}/{name}",
                "url": f"https://github.com/{owner}/{name}",
                "isFork": False,
                "isTemplate": False,
                "isArchived": False,
                "stargazerCount": stars,
                "description": "Deployable self-hosted application fixture",
                "licenseInfo": {"spdxId": license_spdx},
                "repositoryTopics": {
                    "nodes": [{"topic": {"name": "self-hosted"}}]
                },
                "parent": None,
            }
        }
    }


FIXTURE_SOURCE_VERIFIER_BYTES = b'''\
import hashlib
import json
from pathlib import Path

SOURCE_TREE_SCHEMA = "k_guard_materialized_source_tree.v1"

def _contents(repository_id):
    return {
        "LICENSE": b"MIT License fixture\\n",
        "package.json": b'{"scripts":{"start":"node app.js"}}\\n',
        f"src/{repository_id.replace('/', '-')}.js": (
            f"export const app = {repository_id!r};\\n".encode("utf-8")
        ),
    }

def _file(path, content):
    return {
        "path": path,
        "mode": "100644",
        "git_blob_sha1": hashlib.sha1(
            f"blob {len(content)}\\0".encode("ascii") + content,
            usedforsecurity=False,
        ).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
        "byte_count": len(content),
    }

def _tree(files):
    rows = [
        {
            "path": row["path"],
            "sha256": row["sha256"],
            "git_blob_sha1": row["git_blob_sha1"],
            "byte_count": row["byte_count"],
        }
        for row in files
    ]
    rows.sort(key=lambda row: row["path"])
    return hashlib.sha256(
        (SOURCE_TREE_SCHEMA + "\\0").encode("ascii")
        + json.dumps(
            rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

def build_git_materialization_receipt(
    root, *, expected_repository_id, expected_commit, expected_tree
):
    root = Path(root)
    actual = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("fixture checkout contains a symlink")
        if path.is_file():
            actual[path.relative_to(root).as_posix()] = path.read_bytes()
    baseline = _contents(expected_repository_id)
    mit_named = dict(baseline)
    mit_named["MIT-LICENSE"] = mit_named.pop("LICENSE")
    if actual not in (baseline, mit_named):
        raise ValueError("fixture checkout bytes differ from preregistration")
    files = [_file(path, actual[path]) for path in sorted(actual)]
    return {
        "schema": "k_guard_git_source_materialization.v2",
        "passed": True,
        "repository_id": expected_repository_id,
        "origin_repository_id": expected_repository_id,
        "origin_repository_match": True,
        "commit": expected_commit,
        "commit_match": True,
        "commit_object_hash_match": True,
        "commit_tree": expected_tree,
        "commit_tree_match": True,
        "tree_object_reconstruction_match": True,
        "git_object_format": "sha1",
        "git_repository_layout": "ordinary_non_shallow_standalone_clone",
        "source_worktree_clean": True,
        "source_worktree_clean_method": "git_blob_sha256_file_set_plus_index_tree_v2",
        "git_porcelain_clean": True,
        "index_tree_match": True,
        "physical_bytes_match_git_blobs": True,
        "git_fsck_strict_passed": True,
        "git_fsck_output_sha256": hashlib.sha256(b"").hexdigest(),
        "scanner_visible_tree_contract": "regular-file paths and raw Git blob bytes; Git modes remain commit-bound metadata",
        "source_tree_schema": SOURCE_TREE_SCHEMA,
        "source_tree_sha256": _tree(files),
        "file_count": len(files),
        "total_bytes": sum(row["byte_count"] for row in files),
        "files": files,
        "raw_returned": False,
    }
'''
SOURCE_VERIFIER_SHA256 = hashlib.sha256(FIXTURE_SOURCE_VERIFIER_BYTES).hexdigest()
FIXTURE_SOURCE_VERIFIER = compile_source_verifier_bytes(
    FIXTURE_SOURCE_VERIFIER_BYTES,
    expected_sha256=SOURCE_VERIFIER_SHA256,
    filename="fixture_source_verifier.py",
)


def _candidate(root: Path, stratum: str, index: int) -> dict:
    repository_id = f"owner-{stratum}/app-{index:03d}"
    node_id = f"NODE-{stratum}-{index:03d}="
    stars = _fixture_stars(stratum, index)
    commit = f"{index + 1:040x}"[-40:]
    tree = hashlib.sha1(f"tree-{stratum}-{index}".encode()).hexdigest()
    receipt = _receipt(repository_id, commit, tree)
    receipt_path = f"receipts/{stratum}-{index:03d}.json"
    source_checkout_path = f"sources/{stratum}-{index:03d}"
    metadata_path = f"github/{stratum}-{index:03d}.json"
    receipt_sha256 = _write_source_receipt(root / receipt_path, receipt)
    metadata_sha256 = _write_json(
        root / metadata_path,
        _github_metadata_response(
            repository_id,
            node_id=node_id,
            stars=stars,
        ),
    )
    _materialize_source(root, source_checkout_path, repository_id)
    files = receipt["files"]
    license_row = next(row for row in files if row["path"] == "LICENSE")
    deploy_row = next(row for row in files if row["path"] == "package.json")
    row = {
        "repository_id": repository_id,
        "github_node_id": node_id,
        "commit": commit,
        "commit_tree": tree,
        "source_tree_sha256": receipt["source_tree_sha256"],
        "source_checkout_path": source_checkout_path,
        "source_receipt_path": receipt_path,
        "source_materialization_receipt_sha256": receipt_sha256,
        "github_metadata_path": metadata_path,
        "github_metadata_sha256": metadata_sha256,
        "is_fork": False,
        "is_template": False,
        "archived": False,
        "natural_app_status": "public_repository_with_build_or_container_manifest",
        "lab_status": "github_metadata_screened_not_lab",
        "license_status": "root_license_bytes_and_github_spdx_bound_not_content_matched",
        "deployable_app_status": "source_build_or_container_manifest_bound_not_runtime_proven",
        "deployable_app_evidence": [
            {
                "kind": "build_manifest",
                "path": deploy_row["path"],
                "sha256": deploy_row["sha256"],
            }
        ],
        "excluded_as_lab": False,
        "excluded_as_ctf": False,
        "excluded_as_benchmark": False,
        "excluded_as_scanner_fixture": False,
        "root_license_path": license_row["path"],
        "license_spdx": "MIT",
        "license_sha256": license_row["sha256"],
        "stars_at_seal": stars,
        "star_stratum": stratum,
        "first_party_file_set_sha256": first_party_file_set_sha256(
            [item["path"] for item in files]
        ),
        "parent_repository_id": None,
        "source_repository_id": None,
        "template_repository_id": None,
        "lineage_id": f"github-node:{node_id}",
    }
    row["candidate_sha256"] = candidate_record_sha256(row)
    return row


def _write_exclusions(root: Path) -> tuple[dict, dict]:
    existing_ids = [f"historic/app-{index:02d}" for index in range(41)]
    existing_payload = {
        "schema": "k_guard_independent_holdout_selection.v1",
        "repository_count": 41,
        "repository_set_sha256": _repository_set_sha256(existing_ids),
        "apps": [{"repository_id": value} for value in existing_ids],
        "raw_returned": False,
    }
    existing_path = "exclusions/existing-41.json"
    existing_hash = _write_json(root / existing_path, existing_payload)

    prior_ids = [f"prior/app-{index:03d}" for index in range(105)]
    prior_payload = {
        "schema": "k_guard_holdout_exclusions.v1",
        "repository_count": 105,
        "repository_set_sha256": _repository_set_sha256(prior_ids),
        "repositories": [{"repository_id": value} for value in prior_ids],
        "raw_returned": False,
    }
    prior_path = "exclusions/prior-105.json"
    prior_hash = _write_json(root / prior_path, prior_payload)
    return (
        {
            "artifact_path": existing_path,
            "artifact_sha256": existing_hash,
            "role": "stress_noise_regression_actionability_only",
            "called_unseen": False,
            "accuracy_ground_truth": False,
        },
        {
            "artifact_path": prior_path,
            "artifact_sha256": prior_hash,
            "role": "historical_evidence_exclusion_only",
            "called_unseen": False,
            "accuracy_ground_truth": False,
        },
    )


def _pool(root: Path, *, reserve_per_stratum: int = 2) -> dict:
    query_path = "github/query.graphql"
    root.joinpath(query_path).parent.mkdir(parents=True, exist_ok=True)
    root.joinpath(query_path).write_bytes(GITHUB_METADATA_QUERY_BYTES)
    query_reference = {
        "artifact_path": query_path,
        "artifact_sha256": hashlib.sha256(GITHUB_METADATA_QUERY_BYTES).hexdigest(),
        "api": GITHUB_METADATA_API,
        "captured_at_utc": "2026-07-19T00:00:00Z",
    }
    candidates = [
        _candidate(root, stratum, index)
        for stratum, quota in QUOTAS.items()
        for index in range(quota + reserve_per_stratum)
    ]
    existing, prior = _write_exclusions(root)
    return _seal(
        candidates,
        github_query=query_reference,
        existing=existing,
        prior=prior,
    )


def _seal(
    candidates: list[dict],
    *,
    github_query: dict,
    existing: dict,
    prior: dict,
) -> dict:
    repository_ids = [row["repository_id"] for row in candidates]
    return {
        "schema": INPUT_SCHEMA,
        "selection_boundary": {
            "prefetched_only": True,
            "network_accessed": False,
            "scanner_imported": False,
            "scanner_output_observed": False,
        },
        "source_population_count": len(repository_ids),
        "source_population_repository_set_sha256": _repository_set_sha256(
            repository_ids
        ),
        "candidate_count": len(candidates),
        "candidates_sha256": candidate_pool_sha256(candidates),
        "materialization_rejection_ledger": [],
        "github_query_reference": github_query,
        "provenance": {
            "capture_manifest_sha256": "a" * 64,
            "capture_implementation_sha256": "b" * 64,
            "candidate_materializer_sha256": "c" * 64,
            "scanner_imported": False,
            "scanner_output_observed": False,
        },
        "existing_41_reference": existing,
        "prior_evidence_105_reference": prior,
        "candidates": candidates,
    }


def _reseal_candidate(row: dict) -> None:
    row["candidate_sha256"] = candidate_record_sha256(row)


def _sealed(pool: dict):
    raw = canonical_json_bytes(pool)
    return seal_candidate_pool_bytes(
        raw, expected_manifest_sha256=hashlib.sha256(raw).hexdigest()
    )


def _build(pool: dict, root: Path) -> dict:
    return build_l4_public_selection(
        _sealed(pool),
        seed_sha256=SEED,
        artifact_root=root,
        source_verifier=FIXTURE_SOURCE_VERIFIER,
        selection_implementation_sha256=SELECTION_IMPLEMENTATION_SHA256,
        selection_cli_sha256=SELECTION_CLI_SHA256,
    )


def _rewrite_receipt(root: Path, candidate: dict, receipt: dict) -> None:
    receipt["file_count"] = len(receipt["files"])
    receipt["total_bytes"] = sum(row["byte_count"] for row in receipt["files"])
    receipt["source_tree_sha256"] = _source_tree_sha256(receipt["files"])
    path = root / candidate["source_receipt_path"]
    candidate["source_materialization_receipt_sha256"] = _write_source_receipt(
        path, receipt
    )
    candidate["source_tree_sha256"] = receipt["source_tree_sha256"]
    candidate["first_party_file_set_sha256"] = first_party_file_set_sha256(
        [row["path"] for row in receipt["files"]]
    )
    _reseal_candidate(candidate)


def _rewrite_github_metadata(root: Path, candidate: dict, response: dict) -> None:
    path = root / candidate["github_metadata_path"]
    candidate["github_metadata_sha256"] = _write_json(path, response)
    _reseal_candidate(candidate)


def test_receipt_backed_selection_runs_twice_with_exact_same_output(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    sealed = _sealed(pool)

    first = build_l4_public_selection(
        sealed,
        seed_sha256=SEED,
        artifact_root=tmp_path,
        source_verifier=FIXTURE_SOURCE_VERIFIER,
        selection_implementation_sha256=SELECTION_IMPLEMENTATION_SHA256,
        selection_cli_sha256=SELECTION_CLI_SHA256,
    )
    second = build_l4_public_selection(
        sealed,
        seed_sha256=SEED,
        artifact_root=tmp_path,
        source_verifier=FIXTURE_SOURCE_VERIFIER,
        selection_implementation_sha256=SELECTION_IMPLEMENTATION_SHA256,
        selection_cli_sha256=SELECTION_CLI_SHA256,
    )

    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert first["selection"]["selected_count"] == 59
    assert first["selection"]["stratum_counts"] == QUOTAS
    assert all(row["receipt_backed"] is True for row in first["selected"])
    assert first["existing_41_reference"]["app_count"] == 41
    assert first["prior_evidence_105_reference"]["app_count"] == 105
    assert first["bindings"]["source_verifier_sha256"] == SOURCE_VERIFIER_SHA256
    assert first["bindings"]["capture_manifest_sha256"] == "a" * 64
    assert first["bindings"]["capture_implementation_sha256"] == "b" * 64
    assert first["bindings"]["candidate_materializer_sha256"] == "c" * 64
    assert (
        first["bindings"]["selection_implementation_sha256"]
        == SELECTION_IMPLEMENTATION_SHA256
    )
    assert first["bindings"]["selection_cli_sha256"] == SELECTION_CLI_SHA256
    assert first["claim_boundary"]["source_checkouts_recomputed"] is True


def test_unsealed_mapping_is_never_admissible(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    with pytest.raises(PublicPoolContractError, match="externally SHA-256 sealed"):
        build_l4_public_selection(  # type: ignore[arg-type]
            pool,
            seed_sha256=SEED,
            artifact_root=tmp_path,
            source_verifier=FIXTURE_SOURCE_VERIFIER,
            selection_implementation_sha256=SELECTION_IMPLEMENTATION_SHA256,
            selection_cli_sha256=SELECTION_CLI_SHA256,
        )


def test_sealed_pool_exposes_only_fresh_payload_copies(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    sealed = _sealed(pool)
    exposed = sealed.payload
    exposed["candidates"][0]["stars_at_seal"] = 999_999_999

    result = build_l4_public_selection(
        sealed,
        seed_sha256=SEED,
        artifact_root=tmp_path,
        source_verifier=FIXTURE_SOURCE_VERIFIER,
        selection_implementation_sha256=SELECTION_IMPLEMENTATION_SHA256,
        selection_cli_sha256=SELECTION_CLI_SHA256,
    )

    selected_and_reserves = [
        *result["selected"],
        *(row for rows in result["reserves"].values() for row in rows),
    ]
    assert all(row["stars_at_seal"] != 999_999_999 for row in selected_and_reserves)


def test_unbound_or_mutated_source_verifier_is_never_admissible(
    tmp_path: Path,
) -> None:
    pool = _pool(tmp_path)
    sealed = _sealed(pool)

    with pytest.raises(PublicPoolContractError, match="verified module bytes"):
        build_l4_public_selection(
            sealed,
            seed_sha256=SEED,
            artifact_root=tmp_path,
            source_verifier=lambda *args, **kwargs: {},  # type: ignore[arg-type]
            selection_implementation_sha256=SELECTION_IMPLEMENTATION_SHA256,
            selection_cli_sha256=SELECTION_CLI_SHA256,
        )
    with pytest.raises(AttributeError, match="immutable"):
        FIXTURE_SOURCE_VERIFIER._verifier = lambda *args, **kwargs: {}  # type: ignore[misc]


def test_candidate_manifest_tamper_fails_external_seal() -> None:
    raw = canonical_json_bytes({"schema": INPUT_SCHEMA})
    with pytest.raises(PublicPoolContractError, match="manifest SHA-256 mismatch"):
        seal_candidate_pool_bytes(raw + b" ", expected_manifest_sha256=hashlib.sha256(raw).hexdigest())


def test_forged_all_true_boolean_metadata_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    target["regular_files_only"] = True
    target["windows_paths_valid"] = True
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == target["repository_id"])
    assert "candidate_fields_invalid" in rejected["reasons"]


def test_duplicate_repository_identity_fails_pool_contract(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    pool["candidates"].append(copy.deepcopy(pool["candidates"][0]))
    repository_ids = [row["repository_id"] for row in pool["candidates"]]
    pool["candidate_count"] = len(pool["candidates"])
    pool["source_population_count"] = len(repository_ids)
    pool["source_population_repository_set_sha256"] = _repository_set_sha256(
        repository_ids
    )
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    with pytest.raises(
        PublicPoolContractError, match="source population count or uniqueness"
    ):
        _build(pool, tmp_path)


def test_duplicate_lineage_id_is_clustered_and_not_double_counted(
    tmp_path: Path,
) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    left, right = pool["candidates"][:2]
    right["github_node_id"] = left["github_node_id"]
    right["lineage_id"] = left["lineage_id"]
    metadata_path = tmp_path / right["github_metadata_path"]
    response = json.loads(metadata_path.read_text(encoding="utf-8"))
    response["data"]["repository"]["id"] = left["github_node_id"]
    _rewrite_github_metadata(tmp_path, right, response)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == right["repository_id"]
    )
    assert rejected["reasons"] == ["lineage_cluster_duplicate"]
    assert result["counts"]["independent_lineage_clusters"] == len(
        pool["candidates"]
    ) - 1


def test_shared_tree_with_conflicting_lineage_ids_rejects_cluster(
    tmp_path: Path,
) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    left, right = pool["candidates"][:2]
    right["commit_tree"] = left["commit_tree"]
    receipt_path = tmp_path / right["source_receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["commit_tree"] = left["commit_tree"]
    _rewrite_receipt(tmp_path, right, receipt)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = {
        row["repository_id"]: row
        for row in result["rejection_ledger"]
        if row["repository_id"] in {left["repository_id"], right["repository_id"]}
    }
    assert set(rejected) == {left["repository_id"], right["repository_id"]}
    assert all(
        row["reasons"] == ["lineage_cluster_id_conflict"]
        for row in rejected.values()
    )


def test_receipt_byte_tamper_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    receipt_path = tmp_path / target["source_receipt_path"]
    receipt_path.write_bytes(receipt_path.read_bytes() + b" ")

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == target["repository_id"])
    assert "source_receipt_sha256_mismatch" in rejected["reasons"]


def test_noncanonical_receipt_cannot_be_resealed_and_admitted(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    receipt_path = tmp_path / target["source_receipt_path"]
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    raw = json.dumps(receipt, sort_keys=False).encode("utf-8")
    receipt_path.write_bytes(raw)
    target["source_materialization_receipt_sha256"] = hashlib.sha256(raw).hexdigest()
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "source_receipt_not_canonical" in rejected["reasons"]


def test_receipt_swap_cannot_change_candidate_identity(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    left, right = pool["candidates"][:2]
    left["source_receipt_path"] = right["source_receipt_path"]
    left["source_materialization_receipt_sha256"] = right["source_materialization_receipt_sha256"]
    _reseal_candidate(left)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == left["repository_id"])
    assert "source_receipt_repository_id_mismatch" in rejected["reasons"]


def test_receipt_path_traversal_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    target["source_receipt_path"] = "../outside.json"
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == target["repository_id"])
    assert "source_receipt_path_invalid" in rejected["reasons"]


def test_receipt_symlink_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    original = tmp_path / target["source_receipt_path"]
    link = tmp_path / "receipts" / "linked.json"
    try:
        link.symlink_to(original)
    except OSError as exc:
        pytest.fail(f"test environment could not create required symlink fixture: {exc}")
    target["source_receipt_path"] = "receipts/linked.json"
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == target["repository_id"])
    assert "source_receipt_symlink_or_reparse" in rejected["reasons"]


def test_github_metadata_byte_tamper_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    path = tmp_path / target["github_metadata_path"]
    path.write_bytes(path.read_bytes() + b" ")

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "github_metadata_sha256_mismatch" in rejected["reasons"]


def test_github_metadata_swap_cannot_change_candidate_identity(
    tmp_path: Path,
) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    left, right = pool["candidates"][:2]
    left["github_metadata_path"] = right["github_metadata_path"]
    left["github_metadata_sha256"] = right["github_metadata_sha256"]
    _reseal_candidate(left)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == left["repository_id"]
    )
    assert "github_metadata_repository_id_mismatch" in rejected["reasons"]
    assert "github_metadata_node_id_mismatch" in rejected["reasons"]


def test_github_metadata_path_traversal_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    target["github_metadata_path"] = "../outside.json"
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "github_metadata_path_invalid" in rejected["reasons"]


def test_github_metadata_symlink_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    original = tmp_path / target["github_metadata_path"]
    link = tmp_path / "github" / "linked-response.json"
    try:
        link.symlink_to(original)
    except OSError as exc:
        pytest.fail(f"test environment could not create required symlink fixture: {exc}")
    target["github_metadata_path"] = "github/linked-response.json"
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "github_metadata_symlink_or_reparse" in rejected["reasons"]


def test_github_node_and_star_values_must_match_primary_response(
    tmp_path: Path,
) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    target["github_node_id"] = "FORGED-NODE="
    target["lineage_id"] = "github-node:FORGED-NODE="
    target["stars_at_seal"] += 1
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "github_metadata_node_id_mismatch" in rejected["reasons"]
    assert "github_metadata_stars_mismatch" in rejected["reasons"]


def test_star_stratum_is_derived_from_locked_thresholds(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    target["star_stratum"] = "mid"
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "star_stratum_threshold_mismatch" in rejected["reasons"]


def test_github_lab_signal_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    path = tmp_path / target["github_metadata_path"]
    response = json.loads(path.read_text(encoding="utf-8"))
    response["data"]["repository"]["description"] = (
        "An intentionally vulnerable security lab"
    )
    _rewrite_github_metadata(tmp_path, target, response)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "github_metadata_lab_signal_present" in rejected["reasons"]


def test_github_repository_state_and_license_must_match_candidate(
    tmp_path: Path,
) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    path = tmp_path / target["github_metadata_path"]
    response = json.loads(path.read_text(encoding="utf-8"))
    repository = response["data"]["repository"]
    repository["isArchived"] = True
    repository["licenseInfo"]["spdxId"] = "Apache-2.0"
    _rewrite_github_metadata(tmp_path, target, response)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "github_metadata_isArchived_mismatch" in rejected["reasons"]
    assert "github_metadata_license_mismatch" in rejected["reasons"]


def test_source_checkout_byte_tamper_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    checkout = tmp_path / target["source_checkout_path"]
    (checkout / "package.json").write_bytes(b'{"scripts":{"start":"forged"}}\n')

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "source_checkout_verification_failed" in rejected["reasons"]


def test_source_checkout_swap_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    left, right = pool["candidates"][:2]
    left["source_checkout_path"] = right["source_checkout_path"]
    _reseal_candidate(left)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == left["repository_id"]
    )
    assert "source_checkout_verification_failed" in rejected["reasons"]


def test_source_checkout_path_traversal_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    target["source_checkout_path"] = "../outside"
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "source_checkout_path_invalid" in rejected["reasons"]


def test_source_checkout_symlink_is_rejected(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    original = tmp_path / target["source_checkout_path"]
    link = tmp_path / "sources" / "linked-checkout"
    try:
        link.symlink_to(original, target_is_directory=True)
    except OSError as exc:
        pytest.fail(f"test environment could not create required symlink fixture: {exc}")
    target["source_checkout_path"] = "sources/linked-checkout"
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert "source_checkout_symlink_or_reparse" in rejected["reasons"]


def test_receipt_pass_and_git_contract_cannot_be_forged(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    path = tmp_path / target["source_receipt_path"]
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["passed"] = False
    receipt["git_fsck_strict_passed"] = False
    _rewrite_receipt(tmp_path, target, receipt)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == target["repository_id"])
    assert "source_receipt_verification_not_passed" in rejected["reasons"]


def test_malformed_receipt_is_ledgered_not_silently_admitted(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    path = tmp_path / target["source_receipt_path"]
    raw = b'{"schema":"first","schema":"second"}\n'
    path.write_bytes(raw)
    target["source_materialization_receipt_sha256"] = hashlib.sha256(raw).hexdigest()
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == target["repository_id"])
    assert "source_receipt_json_invalid" in rejected["reasons"]


def test_windows_path_collision_is_derived_from_receipt_rows(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    path = tmp_path / target["source_receipt_path"]
    receipt = json.loads(path.read_text(encoding="utf-8"))
    receipt["files"].extend(
        [_file("Case/file.txt", b"one"), _file("case/File.txt", b"two")]
    )
    _rewrite_receipt(tmp_path, target, receipt)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == target["repository_id"])
    assert "source_receipt_windows_path_invalid" in rejected["reasons"]


def test_root_mit_license_filename_is_receipt_bound_and_accepted(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    target = pool["candidates"][0]
    path = tmp_path / target["source_receipt_path"]
    receipt = json.loads(path.read_text(encoding="utf-8"))
    license_row = next(row for row in receipt["files"] if row["path"] == "LICENSE")
    license_row["path"] = "MIT-LICENSE"
    checkout = tmp_path / target["source_checkout_path"]
    (checkout / "LICENSE").rename(checkout / "MIT-LICENSE")
    target["root_license_path"] = "MIT-LICENSE"
    _rewrite_receipt(tmp_path, target, receipt)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    assert target["repository_id"] in {row["repository_id"] for row in result["selected"]} | {
        row["repository_id"] for rows in result["reserves"].values() for row in rows
    }


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("license_sha256", "f" * 64, "license_evidence_mismatch"),
        (
            "deployable_app_evidence",
            [{"kind": "build_manifest", "path": "package.json", "sha256": "f" * 64}],
            "deployable_evidence_mismatch",
        ),
    ],
)
def test_license_and_deploy_evidence_must_match_receipt_files(
    tmp_path: Path, field: str, value: object, reason: str
) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    target[field] = value
    _reseal_candidate(target)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    result = _build(pool, tmp_path)
    rejected = next(row for row in result["rejection_ledger"] if row["repository_id"] == target["repository_id"])
    assert reason in rejected["reasons"]


def test_exclusion_artifact_byte_tamper_fails_closed(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    path = tmp_path / pool["existing_41_reference"]["artifact_path"]
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(PublicPoolContractError, match="existing_41:sha256_mismatch"):
        _build(pool, tmp_path)


def test_exclusion_repository_set_is_derived_and_hash_checked(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    reference = pool["prior_evidence_105_reference"]
    path = tmp_path / reference["artifact_path"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["repositories"][0]["repository_id"] = "forged/repository"
    reference["artifact_sha256"] = _write_json(path, payload)
    pool["candidates_sha256"] = candidate_pool_sha256(pool["candidates"])

    with pytest.raises(PublicPoolContractError, match="repository set hash mismatch"):
        _build(pool, tmp_path)


@pytest.mark.parametrize(
    ("reference_field", "rows_field", "reason"),
    [
        ("existing_41_reference", "apps", "overlaps_existing_41"),
        (
            "prior_evidence_105_reference",
            "repositories",
            "overlaps_prior_evidence_105",
        ),
    ],
)
def test_existing_or_prior_overlap_is_rejected_before_quota_selection(
    tmp_path: Path, reference_field: str, rows_field: str, reason: str
) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=3)
    target = pool["candidates"][0]
    reference = pool[reference_field]
    path = tmp_path / reference["artifact_path"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload[rows_field][0]["repository_id"] = target["repository_id"]
    repository_ids = [row["repository_id"] for row in payload[rows_field]]
    payload["repository_set_sha256"] = _repository_set_sha256(repository_ids)
    reference["artifact_sha256"] = _write_json(path, payload)

    result = _build(pool, tmp_path)
    rejected = next(
        row
        for row in result["rejection_ledger"]
        if row["repository_id"] == target["repository_id"]
    )
    assert reason in rejected["reasons"]
    selected_and_reserves = {
        row["repository_id"] for row in result["selected"]
    } | {
        row["repository_id"]
        for rows in result["reserves"].values()
        for row in rows
    }
    assert target["repository_id"] not in selected_and_reserves


def test_overlap_that_consumes_last_reserve_fails_closed(tmp_path: Path) -> None:
    pool = _pool(tmp_path, reserve_per_stratum=1)
    target = pool["candidates"][0]
    reference = pool["prior_evidence_105_reference"]
    path = tmp_path / reference["artifact_path"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["repositories"][0]["repository_id"] = target["repository_id"]
    repository_ids = [row["repository_id"] for row in payload["repositories"]]
    payload["repository_set_sha256"] = _repository_set_sha256(repository_ids)
    reference["artifact_sha256"] = _write_json(path, payload)

    with pytest.raises(
        PublicPoolContractError,
        match="insufficient receipt-backed lineage clusters for top",
    ):
        _build(pool, tmp_path)


def test_exclusion_path_traversal_and_symlink_fail_closed(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    reference = pool["existing_41_reference"]
    reference["artifact_path"] = "../outside.json"
    with pytest.raises(PublicPoolContractError, match="existing_41:path_invalid"):
        _build(pool, tmp_path)

    pool = _pool(tmp_path / "second")
    root = tmp_path / "second"
    reference = pool["existing_41_reference"]
    original = root / reference["artifact_path"]
    link = root / "exclusions" / "linked.json"
    try:
        link.symlink_to(original)
    except OSError as exc:
        pytest.fail(f"test environment could not create required symlink fixture: {exc}")
    reference["artifact_path"] = "exclusions/linked.json"
    with pytest.raises(PublicPoolContractError, match="existing_41:symlink_or_reparse"):
        _build(pool, root)


def test_github_query_tamper_fails_closed(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    reference = pool["github_query_reference"]
    path = tmp_path / reference["artifact_path"]
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(PublicPoolContractError, match="github_query:sha256_mismatch"):
        _build(pool, tmp_path)

    reference["artifact_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(PublicPoolContractError, match="query contract mismatch"):
        _build(pool, tmp_path)


def test_github_query_capture_time_is_contract_bound(tmp_path: Path) -> None:
    pool = _pool(tmp_path)
    for invalid in ("sometime", "2026-19-39T25:61:61Z"):
        pool["github_query_reference"]["captured_at_utc"] = invalid
        with pytest.raises(PublicPoolContractError, match="capture time is invalid"):
            _build(pool, tmp_path)


def test_loader_rejects_duplicate_keys_and_requires_expected_file_hash(tmp_path: Path) -> None:
    source = tmp_path / "pool.json"
    source.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with pytest.raises(PublicPoolContractError, match="duplicate JSON key"):
        load_prefetched_pool(source, expected_sha256=digest)
    with pytest.raises(PublicPoolContractError, match="SHA-256 mismatch"):
        load_prefetched_pool(source, expected_sha256="0" * 64)


def test_source_verifier_loader_executes_only_hash_bound_bytes(tmp_path: Path) -> None:
    source = tmp_path / "verifier.py"
    raw = (
        b"def build_git_materialization_receipt(root, *, expected_repository_id, "
        b"expected_commit, expected_tree):\n"
        b"    return {'repository_id': expected_repository_id, 'root': str(root)}\n"
    )
    source.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()

    verifier = load_source_verifier(source, expected_sha256=digest)

    assert verifier(
        tmp_path,
        expected_repository_id="owner/app",
        expected_commit="1" * 40,
        expected_tree="2" * 40,
    ) == {"repository_id": "owner/app", "root": str(tmp_path)}
    with pytest.raises(PublicPoolContractError, match="SHA-256 mismatch"):
        load_source_verifier(source, expected_sha256="0" * 64)


def test_source_verifier_loader_rejects_missing_export_and_symlink(tmp_path: Path) -> None:
    missing = tmp_path / "missing.py"
    raw = b"VALUE = 1\n"
    missing.write_bytes(raw)
    with pytest.raises(PublicPoolContractError, match="does not export"):
        load_source_verifier(
            missing, expected_sha256=hashlib.sha256(raw).hexdigest()
        )

    link = tmp_path / "linked.py"
    try:
        link.symlink_to(missing)
    except OSError as exc:
        pytest.fail(f"test environment could not create required symlink fixture: {exc}")
    with pytest.raises(PublicPoolContractError, match="bounded regular file"):
        load_source_verifier(
            link, expected_sha256=hashlib.sha256(raw).hexdigest()
        )


def test_loader_accepts_only_exact_canonical_manifest_bytes(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    pool = _pool(root)
    source = tmp_path / "pool.json"
    raw = canonical_json_bytes(pool)
    source.write_bytes(raw)

    sealed = load_prefetched_pool(
        source, expected_sha256=hashlib.sha256(raw).hexdigest()
    )
    result = build_l4_public_selection(
        sealed,
        seed_sha256=SEED,
        artifact_root=root,
        source_verifier=FIXTURE_SOURCE_VERIFIER,
        selection_implementation_sha256=SELECTION_IMPLEMENTATION_SHA256,
        selection_cli_sha256=SELECTION_CLI_SHA256,
    )

    assert result["bindings"]["candidate_manifest_sha256"] == hashlib.sha256(raw).hexdigest()


def test_output_is_canonical_and_refuses_overwrite(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    result = _build(_pool(root), root)
    output = tmp_path / "selection.json"
    write_selection(output, result)
    assert output.read_bytes() == canonical_json_bytes(result)
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        write_selection(output, result)
