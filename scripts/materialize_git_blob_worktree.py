from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "k_guard_git_blob_worktree_receipt.v1"
ALLOWED_FILE_MODES = {"100644", "100755"}


class BlobWorktreeError(ValueError):
    pass


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(root: Path, *arguments: str, binary: bool = False) -> bytes | str:
    completed = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise BlobWorktreeError(f"git_failed:{arguments[0] if arguments else 'unknown'}")
    return completed.stdout if binary else completed.stdout.decode("utf-8", "strict").strip()


def _safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise BlobWorktreeError("unsafe_tree_path")
    return path


def _tree_entries(repository: Path, revision: str) -> list[tuple[str, str, str]]:
    raw = _git(repository, "ls-tree", "-r", "-z", revision, binary=True)
    assert isinstance(raw, bytes)
    entries: list[tuple[str, str, str]] = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise BlobWorktreeError("tree_record_invalid") from exc
        _safe_relative(path)
        if object_type != "blob" or mode not in ALLOWED_FILE_MODES or len(object_id) != 40:
            raise BlobWorktreeError("tree_entry_unsupported")
        entries.append((path, mode, object_id))
    if not entries or len({item[0] for item in entries}) != len(entries):
        raise BlobWorktreeError("tree_entries_invalid")
    return sorted(entries)


def _extract_blobs(repository: Path, destination: Path, entries: list[tuple[str, str, str]]) -> None:
    process = subprocess.Popen(
        ["git", "-c", "core.autocrlf=false", "-C", str(repository), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        for relative, mode, expected_oid in entries:
            # Read each batch response before submitting the next object. On Windows,
            # preloading a large request list can deadlock against the stdout pipe.
            process.stdin.write(f"{expected_oid}\n".encode("ascii"))
            process.stdin.flush()
            header = process.stdout.readline().decode("ascii", "strict").strip().split(" ")
            if len(header) != 3:
                raise BlobWorktreeError("blob_header_invalid")
            observed_oid, object_type, size_text = header
            if observed_oid != expected_oid or object_type != "blob":
                raise BlobWorktreeError("blob_identity_invalid")
            size = int(size_text)
            if size < 0:
                raise BlobWorktreeError("blob_size_invalid")
            payload = process.stdout.read(size)
            if len(payload) != size or process.stdout.read(1) != b"\n":
                raise BlobWorktreeError("blob_read_invalid")
            target = destination.joinpath(*_safe_relative(relative).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            if mode == "100755":
                target.chmod(target.stat().st_mode | stat.S_IXUSR)
        process.stdin.close()
        if process.wait(timeout=60) != 0:
            raise BlobWorktreeError("blob_extraction_failed")
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise


def _clone_no_checkout(source: Path, destination: Path) -> None:
    completed = subprocess.run(
        ["git", "clone", "--quiet", "--no-checkout", "--local", str(source), str(destination)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise BlobWorktreeError("clone_failed")


def materialize(source: Path, output: Path, revision: str, origin: str) -> dict[str, Any]:
    source_root = source.resolve(strict=True)
    target = output.resolve()
    if not (source_root / ".git").exists() or target.exists():
        raise BlobWorktreeError("source_or_output_invalid")
    if target.is_relative_to(source_root):
        raise BlobWorktreeError("output_must_be_external")
    if len(revision) != 40 or not origin.startswith("https://github.com/"):
        raise BlobWorktreeError("binding_invalid")
    entries = _tree_entries(source_root, revision)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
    try:
        _clone_no_checkout(source_root, temporary)
        _git(temporary, "config", "core.autocrlf", "false")
        _git(temporary, "config", "core.eol", "lf")
        _git(temporary, "remote", "set-url", "origin", origin)
        _git(temporary, "update-ref", "HEAD", revision)
        _git(temporary, "read-tree", revision)
        _extract_blobs(temporary, temporary, entries)
        if _git(temporary, "rev-parse", "HEAD") != revision:
            raise BlobWorktreeError("revision_binding_invalid")
        if _git(temporary, "status", "--porcelain"):
            raise BlobWorktreeError("materialized_worktree_not_clean")
        tree = _git(temporary, "rev-parse", f"{revision}^{{tree}}")
        assert isinstance(tree, str)
        receipt = {
            "schema": SCHEMA,
            "revision": revision,
            "tree": tree,
            "origin": origin,
            "file_count": len(entries),
            "worktree_clean": True,
            "byte_source": "git_cat_file_raw_blob",
            "raw_returned": False,
        }
        os.replace(temporary, target)
        return receipt
    except Exception:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Materialize a filter-free clean worktree from pinned raw Git blobs.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.receipt.exists() or args.receipt.resolve().is_relative_to(args.output.resolve()):
        raise SystemExit("receipt_path_invalid")
    receipt = materialize(args.source, args.output, args.revision, args.origin)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_bytes(canonical_json_bytes(receipt))
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
