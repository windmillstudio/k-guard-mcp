from __future__ import annotations

import argparse
import io
import json
import subprocess
import tarfile
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from scripts.holdout_integrity import (
        HOLDOUT_EXCLUSION_SCHEMA,
        REVISION_RE,
        normalize_github_repository,
        repository_set_sha256,
    )
except ModuleNotFoundError:
    from holdout_integrity import (
        HOLDOUT_EXCLUSION_SCHEMA,
        REVISION_RE,
        normalize_github_repository,
        repository_set_sha256,
    )


ROOT = Path(__file__).resolve().parents[1]


def _git_bytes(root: Path, *args: str) -> bytes:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return completed.stdout


def _repository_ids(value: Any) -> set[str]:
    repositories: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {"repository", "repository_url"} and isinstance(child, str):
                repository_id = normalize_github_repository(child)
                if repository_id:
                    repositories.add(repository_id)
            elif key == "holdout_exclusions" and isinstance(child, list):
                for item in child:
                    if isinstance(item, str):
                        repository_id = normalize_github_repository(item)
                        if repository_id:
                            repositories.add(repository_id)
            repositories.update(_repository_ids(child))
    elif isinstance(value, list):
        for child in value:
            repositories.update(_repository_ids(child))
    return repositories


def build_snapshot(root: Path, source_revision: str) -> dict[str, Any]:
    if REVISION_RE.fullmatch(source_revision) is None:
        raise ValueError("source revision must be a full lowercase Git commit SHA")
    root = root.resolve(strict=True)
    resolved_revision = _git_bytes(root, "rev-parse", source_revision).decode("ascii").strip()
    if resolved_revision != source_revision:
        raise ValueError("source revision did not resolve exactly")
    source_commit_time = _git_bytes(root, "show", "-s", "--format=%cI", source_revision).decode("ascii").strip()
    evidence_paths: defaultdict[str, set[str]] = defaultdict(set)
    parsed_json_files = 0
    archive = _git_bytes(root, "archive", "--format=tar", source_revision, "evidence")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as evidence_archive:
        for member in evidence_archive.getmembers():
            path = member.name
            if not member.isfile() or not path.endswith(".json"):
                continue
            source = evidence_archive.extractfile(member)
            if source is None:
                continue
            try:
                payload = json.loads(source.read().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            parsed_json_files += 1
            for repository_id in _repository_ids(payload):
                evidence_paths[repository_id].add(path)
    repository_ids = sorted(evidence_paths)
    if not repository_ids:
        raise ValueError("no prior GitHub repositories were found in evidence")
    return {
        "schema": HOLDOUT_EXCLUSION_SCHEMA,
        "source_revision": source_revision,
        "source_commit_time": source_commit_time,
        "collection_contract": {
            "source_tree": "Every parseable JSON file under evidence/ at source_revision.",
            "repository_fields": ["repository", "repository_url", "holdout_exclusions"],
            "normalization": "case-folded GitHub owner/repository without transport or .git suffix",
            "purpose": "Exclude every public GitHub source previously used by development, replay, or holdout evidence.",
        },
        "parsed_json_file_count": parsed_json_files,
        "repository_count": len(repository_ids),
        "repository_set_sha256": repository_set_sha256(repository_ids),
        "repositories": [
            {
                "repository_id": repository_id,
                "evidence_paths": sorted(evidence_paths[repository_id]),
            }
            for repository_id in repository_ids
        ],
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a prior-evidence GitHub corpus exclusion snapshot.")
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    snapshot = build_snapshot(ROOT, args.source_revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(snapshot, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps({"repository_count": snapshot["repository_count"], "source_revision": snapshot["source_revision"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
