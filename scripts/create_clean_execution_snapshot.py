from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


ROOT = Path(__file__).resolve(strict=True).parents[1]
SCRIPTS_ROOT = ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from capture_supervisor_target import capture_target
from evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256


SCHEMA = "k_guard_clean_execution_snapshot.v1"
SCOPE_HASH_SCHEMA = "k_guard_clean_execution_snapshot_scope.v1"
PACKAGE_PATH = Path("src/k_guard_mcp")
REQUIRED_ROOT_FILES = (Path("pyproject.toml"),)
OPTIONAL_ROOT_FILES = (
    Path(".gitignore"),
    Path("README.md"),
    Path("LICENSE"),
    Path("THIRD_PARTY_NOTICES.md"),
    Path("requirements-build.lock"),
    Path("requirements-evidence.lock"),
)
OPTIONAL_ROOT_DIRECTORIES = (Path("LICENSES"),)
REQUIRED_DIRECTORIES = (Path("src"), Path("scripts"))
EXCLUDED_DIRECTORY_NAMES = frozenset({".git", ".pytest_cache", "__pycache__"})
EXCLUDED_SUFFIXES = frozenset({".pyc", ".pyo"})
WINDOWS_SNAPSHOT_PATH_BUDGET = 240
TEMPORARY_SNAPSHOT_PATH_OVERHEAD = 48


class SnapshotError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _safe_relative(value: Path) -> str:
    text = value.as_posix()
    pure = PurePosixPath(text)
    if not text or pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise SnapshotError("snapshot_relative_path_invalid")
    return text


def _included(relative: Path) -> bool:
    return not (
        any(part in EXCLUDED_DIRECTORY_NAMES for part in relative.parts)
        or relative.suffix.casefold() in EXCLUDED_SUFFIXES
    )


def _scope_paths(root: Path) -> list[Path]:
    selected: list[Path] = []
    for relative in REQUIRED_ROOT_FILES:
        path = root / relative
        if not path.is_file():
            raise SnapshotError(f"snapshot_required_file_missing:{relative.as_posix()}")
        selected.append(relative)
    for relative in OPTIONAL_ROOT_FILES:
        if (root / relative).is_file():
            selected.append(relative)
    for relative in OPTIONAL_ROOT_DIRECTORIES:
        if (root / relative).is_dir():
            selected.append(relative)
    for relative in REQUIRED_DIRECTORIES:
        if not (root / relative).is_dir():
            raise SnapshotError(f"snapshot_required_directory_missing:{relative.as_posix()}")
        selected.append(relative)
    return sorted(set(selected), key=lambda path: path.as_posix())


def scope_manifest(root: Path) -> dict[str, Any]:
    base = root.resolve(strict=True)
    entries: list[dict[str, Any]] = []
    for selected in _scope_paths(base):
        path = base / selected
        if path.is_symlink():
            raise SnapshotError(f"snapshot_symlink_not_supported:{selected.as_posix()}")
        if path.is_file():
            relative = _safe_relative(selected)
            raw = path.read_bytes()
            entries.append(
                {
                    "path": relative,
                    "byte_count": len(raw),
                    "sha256": sha256_bytes(raw),
                }
            )
            continue
        for item in sorted(path.rglob("*"), key=lambda value: value.as_posix()):
            relative_path = item.relative_to(base)
            if not _included(relative_path):
                continue
            if item.is_symlink():
                raise SnapshotError(
                    f"snapshot_symlink_not_supported:{relative_path.as_posix()}"
                )
            if not item.is_file():
                continue
            raw = item.read_bytes()
            entries.append(
                {
                    "path": _safe_relative(relative_path),
                    "byte_count": len(raw),
                    "sha256": sha256_bytes(raw),
                }
            )
    if not entries:
        raise SnapshotError("snapshot_scope_empty")
    ordered = sorted(entries, key=lambda entry: str(entry["path"]))
    if len({str(entry["path"]) for entry in ordered}) != len(ordered):
        raise SnapshotError("snapshot_scope_duplicate_path")
    return {
        "schema": SCOPE_HASH_SCHEMA,
        "file_count": len(ordered),
        "files": ordered,
        "sha256": sha256_bytes(canonical_json_bytes(ordered)),
    }


def _copy_scope(source_root: Path, destination_root: Path) -> None:
    for relative in _scope_paths(source_root):
        source = source_root / relative
        destination = destination_root / relative
        if source.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        else:
            shutil.copytree(
                source,
                destination,
                ignore=shutil.ignore_patterns(
                    ".git", ".pytest_cache", "__pycache__", "*.pyc", "*.pyo"
                ),
                copy_function=shutil.copy2,
            )


def _validate_destination_path_budget(source_root: Path, snapshot_root: Path) -> None:
    source = source_root.resolve(strict=True)
    snapshot_text_length = len(str(snapshot_root.resolve()))
    longest_relative = max(
        (len(str(entry["path"])) for entry in scope_manifest(source)["files"]),
        default=0,
    )
    if (
        snapshot_text_length
        + 1
        + longest_relative
        + TEMPORARY_SNAPSHOT_PATH_OVERHEAD
        > WINDOWS_SNAPSHOT_PATH_BUDGET
    ):
        raise SnapshotError("snapshot_destination_path_too_long")


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise SnapshotError(f"snapshot_git_failed:{arguments[0] if arguments else 'unknown'}")
    return completed.stdout.strip()


def _commit_snapshot(snapshot_root: Path) -> str:
    _git(snapshot_root, "init", "--quiet")
    _git(snapshot_root, "config", "user.email", "snapshot@k-guard.invalid")
    _git(snapshot_root, "config", "user.name", "K-Guard Execution Snapshot")
    _git(snapshot_root, "add", "--all")
    _git(snapshot_root, "commit", "--quiet", "-m", "K-Guard isolated execution snapshot")
    if _git(snapshot_root, "status", "--porcelain"):
        raise SnapshotError("snapshot_git_worktree_not_clean")
    revision = _git(snapshot_root, "rev-parse", "HEAD")
    if len(revision) != 40:
        raise SnapshotError("snapshot_git_revision_invalid")
    return revision


def _validate_manifest_shape(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "source_target",
        "source_scope",
        "snapshot_scope",
        "snapshot_git_revision",
        "analyzer",
        "claim_boundary",
        "raw_returned",
    }:
        raise SnapshotError("snapshot_manifest_shape_invalid")
    if value["schema"] != SCHEMA or value["raw_returned"] is not False:
        raise SnapshotError("snapshot_manifest_schema_invalid")
    source_target = value["source_target"]
    if not isinstance(source_target, dict) or set(source_target) != {
        "head_git_oid",
        "dirty_path_set_sha256",
        "dirty_worktree_sha256",
    }:
        raise SnapshotError("snapshot_source_target_invalid")
    for key, length in (
        ("head_git_oid", 40),
        ("dirty_path_set_sha256", 64),
        ("dirty_worktree_sha256", 64),
    ):
        item = source_target[key]
        if not isinstance(item, str) or len(item) != length:
            raise SnapshotError("snapshot_source_target_invalid")
    for key in ("source_scope", "snapshot_scope"):
        scope = value[key]
        if (
            not isinstance(scope, dict)
            or scope.get("schema") != SCOPE_HASH_SCHEMA
            or not isinstance(scope.get("file_count"), int)
            or not isinstance(scope.get("files"), list)
            or not isinstance(scope.get("sha256"), str)
            or len(scope["sha256"]) != 64
        ):
            raise SnapshotError("snapshot_scope_invalid")
        if scope["file_count"] != len(scope["files"]):
            raise SnapshotError("snapshot_scope_count_invalid")
        if sha256_bytes(canonical_json_bytes(scope["files"])) != scope["sha256"]:
            raise SnapshotError("snapshot_scope_hash_invalid")
    if value["source_scope"] != value["snapshot_scope"]:
        raise SnapshotError("snapshot_scope_mismatch")
    revision = value["snapshot_git_revision"]
    if not isinstance(revision, str) or len(revision) != 40:
        raise SnapshotError("snapshot_git_revision_invalid")
    analyzer = value["analyzer"]
    if (
        not isinstance(analyzer, dict)
        or analyzer.get("package_path") != PACKAGE_PATH.as_posix()
        or analyzer.get("tree_hash_schema") != TREE_HASH_SCHEMA
        or not isinstance(analyzer.get("package_tree_sha256"), str)
        or len(analyzer["package_tree_sha256"]) != 64
    ):
        raise SnapshotError("snapshot_analyzer_binding_invalid")
    boundary = value["claim_boundary"]
    if (
        not isinstance(boundary, dict)
        or boundary != {
            "is_isolated_execution_carrier": True,
            "is_release_qualification": False,
            "may_change_release_thresholds": False,
            "raw_returned": False,
        }
    ):
        raise SnapshotError("snapshot_claim_boundary_invalid")
    return value


def validate_snapshot(manifest: object, snapshot_root: Path) -> dict[str, Any]:
    payload = _validate_manifest_shape(manifest)
    root = snapshot_root.resolve(strict=True)
    if scope_manifest(root) != payload["snapshot_scope"]:
        raise SnapshotError("snapshot_content_changed")
    if package_tree_sha256(root / PACKAGE_PATH) != payload["analyzer"]["package_tree_sha256"]:
        raise SnapshotError("snapshot_analyzer_changed")
    if _git(root, "status", "--porcelain"):
        raise SnapshotError("snapshot_git_worktree_not_clean")
    if _git(root, "rev-parse", "HEAD") != payload["snapshot_git_revision"]:
        raise SnapshotError("snapshot_git_revision_changed")
    return payload


def create_snapshot(source_root: Path, snapshot_root: Path, manifest_path: Path) -> dict[str, Any]:
    source = source_root.resolve(strict=True)
    snapshot = snapshot_root.resolve()
    manifest_destination = manifest_path.resolve()
    if not (source / ".git").exists():
        raise SnapshotError("snapshot_source_not_git_worktree")
    if snapshot.exists() or manifest_destination.exists():
        raise SnapshotError("snapshot_output_already_exists")
    if _is_inside(snapshot, source) or _is_inside(manifest_destination, source):
        raise SnapshotError("snapshot_output_must_be_external")
    if _is_inside(manifest_destination, snapshot):
        raise SnapshotError("snapshot_manifest_must_not_dirty_snapshot")
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    manifest_destination.parent.mkdir(parents=True, exist_ok=True)
    _validate_destination_path_budget(source, snapshot)
    before_target = capture_target(source)
    before_scope = scope_manifest(source)
    temporary = snapshot.parent / f".{snapshot.name}.tmp-{uuid.uuid4().hex}"
    try:
        temporary.mkdir(parents=False, exist_ok=False)
        _copy_scope(source, temporary)
        copied_scope = scope_manifest(temporary)
        if copied_scope != before_scope:
            raise SnapshotError("snapshot_copy_scope_mismatch")
        revision = _commit_snapshot(temporary)
        analyzer_hash = package_tree_sha256(temporary / PACKAGE_PATH)
        if analyzer_hash != package_tree_sha256(source / PACKAGE_PATH):
            raise SnapshotError("snapshot_analyzer_copy_mismatch")
        if capture_target(source) != before_target:
            raise SnapshotError("snapshot_source_changed_during_copy")
        payload: dict[str, Any] = {
            "schema": SCHEMA,
            "source_target": before_target,
            "source_scope": before_scope,
            "snapshot_scope": copied_scope,
            "snapshot_git_revision": revision,
            "analyzer": {
                "package_path": PACKAGE_PATH.as_posix(),
                "tree_hash_schema": TREE_HASH_SCHEMA,
                "package_tree_sha256": analyzer_hash,
            },
            "claim_boundary": {
                "is_isolated_execution_carrier": True,
                "is_release_qualification": False,
                "may_change_release_thresholds": False,
                "raw_returned": False,
            },
            "raw_returned": False,
        }
        _validate_manifest_shape(payload)
        os.replace(temporary, snapshot)
        validate_snapshot(payload, snapshot)
        manifest_destination.write_bytes(canonical_json_bytes(payload))
        return payload
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        if snapshot.exists() and not manifest_destination.exists():
            shutil.rmtree(snapshot)
        raise


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.resolve(strict=True).read_bytes()
        payload = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotError("snapshot_manifest_unreadable") from exc
    if canonical_json_bytes(payload) != raw:
        raise SnapshotError("snapshot_manifest_not_canonical")
    return _validate_manifest_shape(payload)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create or validate a clean, content-bound execution carrier outside the source worktree."
    )
    parser.add_argument("--source-root", type=Path, default=ROOT)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--create", type=Path, help="New external clean snapshot directory.")
    action.add_argument("--validate", type=Path, help="Existing external snapshot directory.")
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.create is not None:
        payload = create_snapshot(args.source_root, args.create, args.manifest)
    else:
        payload = validate_snapshot(_load_manifest(args.manifest), args.validate)
    print(
        json.dumps(
            {
                "analyzer_package_tree_sha256": payload["analyzer"]["package_tree_sha256"],
                "raw_returned": False,
                "snapshot_git_revision": payload["snapshot_git_revision"],
                "valid": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
