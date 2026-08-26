from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


TARGET_SCHEMA = "k_guard_supervisor_target.v2"
WORKTREE_FINGERPRINT_SCHEMA = "k_guard_supervisor_worktree_fingerprint.v1"


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _git(root: Path, *args: str) -> bytes:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("Git target capture command failed") from exc


def _relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or str(path) != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or "\\" in value
    ):
        raise ValueError("Git status contains an unsafe relative path")
    return value


def _status_records(root: Path) -> list[dict[str, str]]:
    raw = _git(root, "status", "--porcelain=v1", "--untracked-files=all", "-z")
    fields = [field for field in raw.decode("utf-8").split("\0") if field]
    records: list[dict[str, str]] = []
    index = 0
    while index < len(fields):
        field = fields[index]
        if len(field) < 4 or field[2] != " ":
            raise ValueError("Git status record is malformed")
        status = field[:2]
        path = _relative_path(field[3:])
        record = {"status": status, "path": path}
        if "R" in status or "C" in status:
            index += 1
            if index >= len(fields):
                raise ValueError("Git rename status record is incomplete")
            record["original_path"] = _relative_path(fields[index])
        records.append(record)
        index += 1
    return sorted(records, key=canonical_json_bytes)


def _path_state(root: Path, relative: str) -> dict[str, Any]:
    safe = _relative_path(relative)
    candidate = root.joinpath(*PurePosixPath(safe).parts)
    try:
        metadata = os.lstat(candidate)
    except FileNotFoundError:
        return {"path": safe, "kind": "missing"}
    if os.path.islink(candidate):
        return {
            "path": safe,
            "kind": "symlink",
            "target_sha256": sha256_bytes(os.readlink(candidate).encode("utf-8")),
        }
    if candidate.is_file():
        raw = candidate.read_bytes()
        return {
            "path": safe,
            "kind": "file",
            "byte_count": metadata.st_size,
            "sha256": sha256_bytes(raw),
        }
    if candidate.is_dir():
        children: list[dict[str, Any]] = []
        for child in sorted(candidate.rglob("*"), key=lambda item: item.as_posix()):
            child_relative = child.relative_to(root).as_posix()
            if child.is_dir() and not child.is_symlink():
                continue
            children.append(_path_state(root, child_relative))
        return {"path": safe, "kind": "directory", "children": children}
    return {"path": safe, "kind": "other", "mode": metadata.st_mode}


def capture_target(repo_root: Path) -> dict[str, str]:
    root = repo_root.resolve(strict=True)
    discovered = Path(_git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()).resolve(strict=True)
    if discovered != root:
        raise ValueError("repository root must be the Git worktree root")
    head = _git(root, "rev-parse", "HEAD").decode("ascii").strip()
    if len(head) != 40 or any(character not in "0123456789abcdef" for character in head):
        raise ValueError("Git HEAD is not a full lower-hex revision")
    records = _status_records(root)
    path_set = sorted({record["path"] for record in records} | {
        record["original_path"] for record in records if "original_path" in record
    })
    path_set_sha256 = sha256_bytes(
        b"k_guard_supervisor_dirty_path_set.v2\0" + canonical_json_bytes(path_set)
    )
    paths_for_state = sorted({record["path"] for record in records})
    worktree_state = {
        "schema": WORKTREE_FINGERPRINT_SCHEMA,
        "head_git_oid": head,
        "status_records": records,
        "git_diff_head_sha256": sha256_bytes(_git(root, "diff", "--no-ext-diff", "--binary", "--full-index", "HEAD", "--")),
        "path_states": [_path_state(root, path) for path in paths_for_state],
        "raw_returned": False,
    }
    return {
        "head_git_oid": head,
        "dirty_path_set_sha256": path_set_sha256,
        "dirty_worktree_sha256": sha256_bytes(canonical_json_bytes(worktree_state)),
    }


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Capture a content-bound supervisor-review target.")
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    target = capture_target(args.repo_root)
    print(json.dumps({"schema": TARGET_SCHEMA, "target": target, "raw_returned": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
