from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse


SOURCE_METADATA_SCHEMA = "k_guard_holdout_source_metadata.v2"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_ID_RE = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
ALLOWED_GIT_TREE_ENTRY_TYPES = {
    ("040000", "tree"),
    ("100644", "blob"),
    ("100755", "blob"),
}
GIT_TREE_ENTRY_POLICY = "regular_files_and_directories_only_v1"


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _normalize_repository(value: Any) -> str:
    candidate = str(value or "").strip()
    if candidate.startswith("git@github.com:"):
        candidate = candidate[len("git@github.com:") :]
    elif "://" in candidate:
        parsed = urlparse(candidate)
        if str(parsed.hostname or "").casefold() not in {"github.com", "www.github.com"}:
            raise ValueError("source seed repository must be hosted on github.com")
        candidate = parsed.path.strip("/")
    if candidate.casefold().endswith(".git"):
        candidate = candidate[:-4]
    repository_id = candidate.strip("/").casefold()
    if REPOSITORY_ID_RE.fullmatch(repository_id) is None:
        raise ValueError(f"source seed repository identity is invalid: {candidate}")
    return repository_id


def _repository_set_sha256(repository_ids: list[str]) -> str:
    encoded = json.dumps(sorted(set(repository_ids)), separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _github_json(url: str, token: str | None) -> dict[str, Any]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "k-guard-holdout-structural-preflight/1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(10 * 1024 * 1024 + 1)
    except (OSError, urllib.error.HTTPError, urllib.error.URLError) as exc:
        raise RuntimeError(f"GitHub metadata request failed: {url}") from exc
    if len(raw) > 10 * 1024 * 1024:
        raise RuntimeError("GitHub metadata response exceeded the preflight budget")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GitHub metadata response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("GitHub metadata response must be an object")
    return payload


def _git_tree_structure(
    payload: dict[str, Any],
    *,
    repository_id: str,
    expected_tree: str,
) -> dict[str, Any]:
    if str(payload.get("sha") or "") != expected_tree:
        raise ValueError(f"GitHub recursive tree identity mismatch: {repository_id}")
    if payload.get("truncated") is not False:
        raise ValueError(f"GitHub recursive tree is truncated: {repository_id}")
    rows = payload.get("tree")
    if not isinstance(rows, list):
        raise ValueError(f"GitHub recursive tree is invalid: {repository_id}")

    normalized: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    mode_counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"GitHub recursive tree entry is invalid: {repository_id}")
        path = str(row.get("path") or "")
        mode = str(row.get("mode") or "")
        entry_type = str(row.get("type") or "")
        object_id = str(row.get("sha") or "")
        parts = path.split("/")
        if (
            not path
            or path in seen_paths
            or path.startswith("/")
            or "\\" in path
            or any(part in {"", ".", ".."} for part in parts)
            or REVISION_RE.fullmatch(object_id) is None
        ):
            raise ValueError(f"GitHub recursive tree path is unsafe: {repository_id}")
        if (mode, entry_type) not in ALLOWED_GIT_TREE_ENTRY_TYPES:
            raise ValueError(
                f"Git tree contains a symlink, submodule, or unsupported entry: "
                f"{repository_id}:{path}"
            )
        seen_paths.add(path)
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        normalized.append(
            {
                "mode": mode,
                "path": path,
                "sha": object_id,
                "type": entry_type,
            }
        )

    normalized.sort(key=lambda row: row["path"])
    structure_bytes = json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "git_tree_entry_count": len(normalized),
        "git_tree_mode_counts": dict(sorted(mode_counts.items())),
        "git_tree_recursive_truncated": False,
        "git_tree_structure_sha256": hashlib.sha256(structure_bytes).hexdigest(),
    }


def build_source_metadata(seed_path: Path, *, token: str | None = None) -> dict[str, Any]:
    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    rows = seed.get("apps") if isinstance(seed, dict) else seed
    if not isinstance(rows, list) or not rows:
        raise ValueError("source seed must contain a non-empty apps list")

    repositories: list[dict[str, Any]] = []
    for seed_row in rows:
        if not isinstance(seed_row, dict):
            raise ValueError("source seed row is invalid")
        repository_id = _normalize_repository(
            seed_row.get("repository_id") or seed_row.get("repository")
        )
        commit = str(seed_row.get("commit") or "")
        if REVISION_RE.fullmatch(commit) is None:
            raise ValueError(f"source seed commit must be a full lowercase SHA: {repository_id}")
        owner, name = repository_id.split("/", 1)
        api_base = f"https://api.github.com/repos/{quote(owner)}/{quote(name)}"
        repo_payload = _github_json(api_base, token)
        commit_payload = _github_json(f"{api_base}/git/commits/{commit}", token)
        actual_repository_id = str(repo_payload.get("full_name") or "").casefold()
        if actual_repository_id != repository_id:
            raise ValueError(f"GitHub repository identity changed: {repository_id}")
        if repo_payload.get("fork") is not False:
            raise ValueError(f"holdout source is a fork: {repository_id}")
        if repo_payload.get("archived") is not False:
            raise ValueError(f"holdout source is archived: {repository_id}")
        if str(commit_payload.get("sha") or "") != commit:
            raise ValueError(f"GitHub commit identity mismatch: {repository_id}")
        tree = commit_payload.get("tree")
        commit_tree = str(tree.get("sha") or "") if isinstance(tree, dict) else ""
        if REVISION_RE.fullmatch(commit_tree) is None:
            raise ValueError(f"GitHub commit tree is invalid: {repository_id}")
        tree_payload = _github_json(
            f"{api_base}/git/trees/{commit_tree}?recursive=1",
            token,
        )
        tree_structure = _git_tree_structure(
            tree_payload,
            repository_id=repository_id,
            expected_tree=commit_tree,
        )
        license_payload = repo_payload.get("license")
        license_spdx = (
            str(license_payload.get("spdx_id") or "")
            if isinstance(license_payload, dict)
            else ""
        )
        repositories.append(
            {
                "repository": f"https://github.com/{repository_id}.git",
                "repository_id": repository_id,
                "github_node_id": str(repo_payload.get("node_id") or ""),
                "default_branch": str(repo_payload.get("default_branch") or ""),
                "is_fork": False,
                "fork_parent_repository_id": None,
                "archived": False,
                "commit": commit,
                "commit_tree": commit_tree,
                "stars_at_registration": repo_payload.get("stargazers_count"),
                "language": repo_payload.get("language"),
                "license_spdx": license_spdx if license_spdx and license_spdx != "NOASSERTION" else None,
                **tree_structure,
            }
        )

    repositories.sort(key=lambda row: row["repository_id"])
    repository_ids = [str(row["repository_id"]) for row in repositories]
    node_ids = [str(row["github_node_id"]) for row in repositories]
    commit_trees = [str(row["commit_tree"]) for row in repositories]
    if len(repository_ids) != len(set(repository_ids)):
        raise ValueError("source seed repositories must be unique")
    if any(not value for value in node_ids) or len(node_ids) != len(set(node_ids)):
        raise ValueError("GitHub node ids must be present and unique")
    if len(commit_trees) != len(set(commit_trees)):
        raise ValueError("holdout source commit trees must be unique")
    if any(
        not isinstance(row["stars_at_registration"], int)
        or isinstance(row["stars_at_registration"], bool)
        or row["stars_at_registration"] < 0
        or not row["default_branch"]
        for row in repositories
    ):
        raise ValueError("GitHub source metadata is incomplete")

    retrieved_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schema": SOURCE_METADATA_SCHEMA,
        "metadata_source": "github_api_v3",
        "retrieved_at": retrieved_at,
        "selection_boundary": {
            "k_guard_imported": False,
            "scanner_output_observed": False,
            "github_metadata_cryptographically_attested": False,
            "git_tree_entry_modes_verified": True,
        },
        "git_tree_entry_policy": GIT_TREE_ENTRY_POLICY,
        "all_source_trees_structurally_eligible": True,
        "repository_count": len(repositories),
        "repository_set_sha256": _repository_set_sha256(repository_ids),
        "repositories": repositories,
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch GitHub identity and pinned-tree metadata without importing or running K-Guard."
    )
    parser.add_argument("--seed", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-token-env", default="GITHUB_TOKEN")
    args = parser.parse_args()
    payload = build_source_metadata(args.seed, token=os.environ.get(args.github_token_env))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(_canonical_bytes(payload))
    print(
        json.dumps(
            {
                "schema": payload["schema"],
                "repository_count": payload["repository_count"],
                "repository_set_sha256": payload["repository_set_sha256"],
                "raw_returned": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
