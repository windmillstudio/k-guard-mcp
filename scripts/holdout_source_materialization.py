from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import tempfile
import time
import unicodedata
from pathlib import Path
from typing import Any


MATERIALIZED_TREE_SCHEMA = "k_guard_materialized_source_tree.v1"
GIT_MATERIALIZATION_SCHEMA = "k_guard_git_source_materialization.v2"
BLOB_EXACT_CLEAN_METHOD = "git_blob_sha256_file_set_plus_index_tree_v2"
SCANNER_VISIBLE_TREE_CONTRACT = (
    "regular-file paths and raw Git blob bytes; Git modes remain commit-bound metadata"
)
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_FILE_MODES = {"100644", "100755"}
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
GIT_COMMAND_TIMEOUT_SECONDS = 300.0
MAX_GIT_OUTPUT_BYTES = 512 * 1024 * 1024
MAX_BLOB_BYTES = 256 * 1024 * 1024
MAX_CONFIG_OUTPUT_BYTES = 1024 * 1024
MAX_FSCK_OUTPUT_BYTES = 1024 * 1024
MAX_PATH_DEPTH = 256
WINDOWS_INVALID_COMPONENT_CHARS = frozenset('<>:"/\\|?*')
WINDOWS_RESERVED_COMPONENTS = frozenset(
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
WINDOWS_SHORT_NAME_RE = re.compile(
    r"^\.?[^.]{1,6}~[1-9][0-9]*(?:\.[^.]{0,3})?$",
    flags=re.IGNORECASE,
)


def _filesystem_path(path: Path) -> Path:
    absolute = os.path.abspath(path)
    if os.name != "nt" or absolute.startswith("\\\\?\\"):
        return Path(absolute)
    if absolute.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + absolute[2:])
    return Path("\\\\?\\" + absolute)


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def _source_tree_sha256(rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        (MATERIALIZED_TREE_SCHEMA + "\0").encode("ascii")
        + json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _safe_root(root: Path) -> Path:
    unresolved = root.absolute()
    if unresolved.is_symlink():
        raise ValueError("source workspace root must not be a symlink")
    metadata = unresolved.stat(follow_symlinks=False)
    if _is_reparse(metadata):
        raise ValueError("source workspace root must not be a reparse point")
    resolved = unresolved.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("source workspace root must be a directory")
    return resolved


def _windows_component_key(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or value.endswith((".", " "))
        or any(ord(character) < 32 for character in value)
        or any(character in WINDOWS_INVALID_COMPONENT_CHARS for character in value)
        or len(value.encode("utf-16-le")) // 2 > 255
    ):
        raise ValueError("source path contains a Windows-unsafe component")
    normalized = unicodedata.normalize("NFC", value).casefold()
    device_stem = normalized.split(".", 1)[0].rstrip(" .")
    if (
        normalized == ".git"
        or device_stem == ".git"
        or device_stem in WINDOWS_RESERVED_COMPONENTS
        or WINDOWS_SHORT_NAME_RE.fullmatch(normalized) is not None
    ):
        raise ValueError("source path contains a reserved Windows or NTFS alias")
    return normalized


def _register_path_prefixes(path: str, seen: dict[str, str]) -> None:
    normalized_parts: list[str] = []
    original_parts: list[str] = []
    parts = path.split("/")
    if len(parts) > MAX_PATH_DEPTH + 1:
        raise ValueError("source path exceeds the maximum depth")
    for part in parts:
        normalized_parts.append(_windows_component_key(part))
        original_parts.append(part)
        normalized_prefix = "/".join(normalized_parts)
        original_prefix = "/".join(original_parts)
        previous = seen.setdefault(normalized_prefix, original_prefix)
        if previous != original_prefix:
            raise ValueError("source path prefix collision under Windows semantics")


def _hash_regular_file(path: Path, before: os.stat_result) -> tuple[str, str, int]:
    sha256 = hashlib.sha256()
    git_sha1 = hashlib.sha1(usedforsecurity=False)
    git_sha1.update(f"blob {before.st_size}\0".encode("ascii"))
    byte_count = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            sha256.update(chunk)
            git_sha1.update(chunk)
            byte_count += len(chunk)
    after = path.stat(follow_symlinks=False)
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if byte_count != before.st_size or any(
        getattr(before, field, None) != getattr(after, field, None) for field in stable_fields
    ):
        raise RuntimeError("source file changed while its materialization was captured")
    if _is_reparse(after) or not stat.S_ISREG(after.st_mode) or after.st_nlink != 1:
        raise RuntimeError("source file type changed while its materialization was captured")
    return sha256.hexdigest(), git_sha1.hexdigest(), byte_count


def capture_materialized_tree(root: Path) -> dict[str, Any]:
    """Hash every scanner-visible file without consulting Git or executing a child process."""

    resolved_root = _safe_root(root)
    rows: list[dict[str, Any]] = []
    seen_prefixes: dict[str, str] = {}
    pending: list[tuple[Path, tuple[str, ...]]] = [
        (_filesystem_path(resolved_root), ())
    ]
    while pending:
        directory, parent_parts = pending.pop()
        with os.scandir(directory) as entries:
            ordered = sorted(entries, key=lambda value: value.name.casefold())
        for entry in ordered:
            path = Path(entry.path)
            relative_parts = (*parent_parts, entry.name)
            relative = "/".join(relative_parts)
            if not parent_parts and entry.name.casefold() == ".git":
                continue
            metadata = path.stat(follow_symlinks=False)
            if entry.is_symlink() or _is_reparse(metadata):
                raise ValueError(f"source workspace contains a link or reparse point: {relative}")
            _register_path_prefixes(relative, seen_prefixes)
            if entry.is_dir(follow_symlinks=False):
                pending.append((path, relative_parts))
                continue
            if not entry.is_file(follow_symlinks=False) or not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"source workspace contains a non-regular entry: {relative}")
            if metadata.st_nlink != 1:
                raise ValueError(f"source workspace contains a hardlinked file: {relative}")
            sha256, blob_sha1, byte_count = _hash_regular_file(path, metadata)
            rows.append(
                {
                    "path": relative,
                    "sha256": sha256,
                    "git_blob_sha1": blob_sha1,
                    "byte_count": byte_count,
                }
            )
    rows.sort(key=lambda row: str(row["path"]))
    return {
        "schema": MATERIALIZED_TREE_SCHEMA,
        "tree_sha256": _source_tree_sha256(rows),
        "file_count": len(rows),
        "total_bytes": sum(int(row["byte_count"]) for row in rows),
        "files": rows,
        "raw_returned": False,
    }


def normalize_github_repository(value: str) -> str | None:
    normalized = value.strip().replace("\\", "/")
    match = re.fullmatch(
        r"(?:https?://github\.com/|ssh://git@github\.com/|git@github\.com:)([^/\s]+)/([^/\s]+?)(?:\.git)?/?",
        normalized,
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    return f"{match.group(1)}/{match.group(2)}".casefold()


def _git_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _process_group_options() -> dict[str, Any]:
    if os.name == "nt":
        return {
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        }
    return {"start_new_session": True}


def _terminate_process_tree(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            process.kill()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
    maximum_output_bytes: int,
    label: str,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    with (
        tempfile.TemporaryFile() as stdin,
        tempfile.TemporaryFile() as stdout,
        tempfile.TemporaryFile() as stderr,
    ):
        if input_bytes is not None:
            stdin.write(input_bytes)
            stdin.seek(0)
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=stdin if input_bytes is not None else subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            **_process_group_options(),
        )
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None:
            output_bytes = os.fstat(stdout.fileno()).st_size + os.fstat(
                stderr.fileno()
            ).st_size
            if output_bytes > maximum_output_bytes:
                _terminate_process_tree(process)
                raise ValueError(f"{label} exceeded its output budget")
            if time.monotonic() >= deadline:
                _terminate_process_tree(process)
                raise ValueError(f"{label} exceeded its time budget")
            time.sleep(0.02)
        output_bytes = os.fstat(stdout.fileno()).st_size + os.fstat(
            stderr.fileno()
        ).st_size
        if output_bytes > maximum_output_bytes:
            raise ValueError(f"{label} exceeded its output budget")
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(
            command,
            process.returncode,
            stdout.read(),
            stderr.read(),
        )


def _run_git(
    root: Path,
    *args: str,
    check: bool = True,
    timeout_seconds: float = GIT_COMMAND_TIMEOUT_SECONDS,
    maximum_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    completed = _run_bounded_process(
        [
            "git",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.longpaths=true",
            "-c",
            f"core.hooksPath={os.devnull}",
            *args,
        ],
        cwd=root,
        environment=_git_environment(),
        timeout_seconds=timeout_seconds,
        maximum_output_bytes=maximum_output_bytes,
        label=f"Git source {args[0]}",
        input_bytes=input_bytes,
    )
    if check and completed.returncode != 0:
        detail = hashlib.sha256(completed.stderr).hexdigest()[:20]
        raise ValueError(f"Git source verification failed ({args[0]}:{detail})")
    return completed


def _git_line(root: Path, *args: str) -> str:
    raw = _run_git(root, *args).stdout
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Git source verification returned non-UTF-8 text") from exc
    if not value or "\n" in value or "\r" in value:
        raise ValueError("Git source verification expected one line")
    return value


def _read_local_config(config_path: Path, *, label: str) -> dict[str, str]:
    unresolved = config_path.absolute()
    if unresolved.is_symlink():
        raise ValueError(f"{label} config must not be a symlink")
    metadata = unresolved.stat(follow_symlinks=False)
    if _is_reparse(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} config must be a regular file")
    completed = _run_bounded_process(
        [
            "git",
            "config",
            "--file",
            str(unresolved),
            "--null",
            "--list",
            "--no-includes",
        ],
        cwd=unresolved.parent,
        environment=_git_environment(),
        timeout_seconds=GIT_COMMAND_TIMEOUT_SECONDS,
        maximum_output_bytes=MAX_CONFIG_OUTPUT_BYTES,
        label=f"{label} config parse",
    )
    if completed.returncode != 0:
        detail = hashlib.sha256(completed.stderr).hexdigest()[:20]
        raise ValueError(f"{label} config is invalid ({detail})")
    config: dict[str, str] = {}
    records = completed.stdout.split(b"\0")
    if records[-1:] != [b""]:
        raise ValueError(f"{label} config output is unterminated")
    for record in records[:-1]:
        if b"\n" not in record:
            raise ValueError(f"{label} config record is malformed")
        raw_key, raw_value = record.split(b"\n", 1)
        try:
            key = raw_key.decode("utf-8").casefold()
            value = raw_value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{label} config is not UTF-8") from exc
        if not key or key in config:
            raise ValueError(f"{label} config contains a duplicate or empty key")
        config[key] = value
    return config


def _validate_worktree_config(
    git_directory: Path, expected_repository_id: str
) -> str:
    config = _read_local_config(git_directory / "config", label="holdout source")
    exact_values = {
        "core.repositoryformatversion": "0",
        "core.bare": "false",
    }
    boolean_keys = {
        "core.filemode",
        "core.ignorecase",
        "core.logallrefupdates",
        "core.longpaths",
        "core.precomposeunicode",
        "core.protecthfs",
        "core.protectntfs",
        "core.symlinks",
    }
    optional_exact = {
        "remote.origin.fetch": "+refs/heads/*:refs/remotes/origin/*",
        "remote.origin.tagopt": "--no-tags",
    }
    for key, value in config.items():
        if key in exact_values:
            if value.casefold() != exact_values[key]:
                raise ValueError("holdout source local config is unsafe")
        elif key in boolean_keys:
            if value.casefold() not in {"true", "false"}:
                raise ValueError("holdout source local config is unsafe")
        elif key == "core.autocrlf":
            if value.casefold() not in {"true", "false", "input"}:
                raise ValueError("holdout source local config is unsafe")
        elif key in {"user.email", "user.name"}:
            if not value or any(character in value for character in "\0\r\n"):
                raise ValueError("holdout source local config is unsafe")
        elif key in optional_exact:
            if value != optional_exact[key]:
                raise ValueError("holdout source local config is unsafe")
        elif key == "remote.origin.url":
            continue
        elif re.fullmatch(r"branch\..+\.remote", key):
            if value.casefold() != "origin":
                raise ValueError("holdout source local config is unsafe")
        elif re.fullmatch(r"branch\..+\.merge", key):
            if not value.startswith("refs/heads/") or any(
                character in value for character in "\0\r\n"
            ):
                raise ValueError("holdout source local config is unsafe")
        else:
            raise ValueError(f"holdout source local config key is not allowed: {key}")
    if not set(exact_values).issubset(config) or "remote.origin.url" not in config:
        raise ValueError("holdout source local config is incomplete")
    origin = normalize_github_repository(config["remote.origin.url"])
    if origin != expected_repository_id.casefold():
        raise ValueError("holdout source origin differs from preregistration")
    return origin


def _reject_promisor_markers(objects: Path) -> None:
    unresolved = objects.absolute()
    if unresolved.is_symlink():
        raise ValueError("holdout source object directory must not be a symlink")
    metadata = unresolved.stat(follow_symlinks=False)
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("holdout source object directory must be a regular directory")
    for entry in unresolved.rglob("*"):
        if entry.name.casefold().endswith(".promisor"):
            raise ValueError("holdout source must not contain promisor object markers")


def _ordinary_git_directory_path(root: Path) -> Path:
    git_path = root / ".git"
    if not git_path.is_dir() or git_path.is_symlink():
        raise ValueError("holdout source must be an ordinary standalone Git clone")
    metadata = git_path.stat(follow_symlinks=False)
    if _is_reparse(metadata):
        raise ValueError("holdout source Git directory must not be a reparse point")
    absolute_git_dir = git_path.resolve(strict=True)
    for relative in ("objects/info/alternates", "info/grafts", "shallow"):
        if (absolute_git_dir / relative).exists():
            raise ValueError(f"holdout source uses a forbidden Git indirection: {relative}")
    return absolute_git_dir


def _ordinary_git_directory(root: Path) -> Path:
    expected_git_dir = _ordinary_git_directory_path(root)
    absolute_git_dir = Path(_git_line(root, "rev-parse", "--absolute-git-dir")).resolve(
        strict=True
    )
    common_git_dir = Path(_git_line(root, "rev-parse", "--git-common-dir"))
    if not common_git_dir.is_absolute():
        common_git_dir = root / common_git_dir
    common_git_dir = common_git_dir.resolve(strict=True)
    if absolute_git_dir != expected_git_dir or common_git_dir != absolute_git_dir:
        raise ValueError("holdout source must not use an external or shared Git directory")
    return absolute_git_dir


def _parse_ls_tree(raw: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_prefixes: dict[str, str] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode_raw, object_type, object_id = header.split(b" ", 2)
            relative = raw_path.decode("utf-8")
            mode = mode_raw.decode("ascii")
            kind = object_type.decode("ascii")
            oid = object_id.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Git tree contains an unsupported path or record") from exc
        path_parts = raw_path.split(b"/")
        if (
            not relative
            or relative in seen_paths
            or any(part in {b"", b".", b".."} for part in path_parts)
        ):
            raise ValueError("Git tree contains an unsafe or duplicate path")
        if mode not in GIT_FILE_MODES or kind != "blob" or REVISION_RE.fullmatch(oid) is None:
            raise ValueError(f"Git tree contains a symlink, submodule, or unsupported entry: {relative}")
        _register_path_prefixes(relative, seen_prefixes)
        seen_paths.add(relative)
        rows.append(
            {
                "path": relative,
                "raw_path": raw_path,
                "mode": mode,
                "git_blob_sha1": oid,
            }
        )
    rows.sort(key=lambda row: str(row["path"]))
    return rows


def _independent_tree_object(entries: list[dict[str, Any]]) -> tuple[str, bytes]:
    root: dict[bytes, dict[str, Any]] = {}
    for row in entries:
        parts = bytes(row["raw_path"]).split(b"/")
        if len(parts) > MAX_PATH_DEPTH + 1:
            raise ValueError("Git tree exceeds the maximum path depth")
        node = root
        for part in parts[:-1]:
            current = node.setdefault(part, {"kind": "tree", "children": {}})
            if current.get("kind") != "tree":
                raise ValueError("Git tree contains a file/directory path conflict")
            node = current["children"]
        if parts[-1] in node:
            raise ValueError("Git tree contains a duplicate entry")
        node[parts[-1]] = {
            "kind": "blob",
            "mode": str(row["mode"]),
            "oid": str(row["git_blob_sha1"]),
        }

    def build(node: dict[bytes, dict[str, Any]]) -> tuple[str, bytes]:
        body = bytearray()
        ordered = sorted(
            node.items(),
            key=lambda item: item[0] + (b"/" if item[1]["kind"] == "tree" else b""),
        )
        for name, value in ordered:
            if value["kind"] == "tree":
                oid, _child_body = build(value["children"])
                mode = "40000"
            else:
                oid = value["oid"]
                mode = value["mode"]
            body.extend(mode.encode("ascii") + b" " + name + b"\0" + bytes.fromhex(oid))
        raw = bytes(body)
        digest = hashlib.sha1(usedforsecurity=False)
        digest.update(f"tree {len(raw)}\0".encode("ascii"))
        digest.update(raw)
        return digest.hexdigest(), raw

    return build(root)


def _git_object_sha1(kind: str, raw: bytes) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"{kind} {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _git_porcelain_clean(root: Path) -> bool:
    return not _run_git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    ).stdout


def _parse_ls_files_stage(raw: bytes) -> list[dict[str, Any]]:
    if not raw:
        return []
    records = raw.split(b"\0")
    if records[-1] != b"":
        raise ValueError("Git index stage output is unterminated")
    rows: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_prefixes: dict[str, str] = {}
    for record in records[:-1]:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode_raw, object_id_raw, stage_raw = header.split(b" ")
            mode = mode_raw.decode("ascii")
            object_id = object_id_raw.decode("ascii")
            stage = stage_raw.decode("ascii")
            relative = raw_path.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Git index stage output contains a malformed record") from exc
        path_parts = raw_path.split(b"/")
        if (
            not relative
            or relative in seen_paths
            or any(part in {b"", b".", b".."} for part in path_parts)
        ):
            raise ValueError("Git index contains an unsafe or duplicate path")
        if stage != "0":
            raise ValueError("Git index contains unmerged or nonzero-stage entries")
        if (
            mode not in GIT_FILE_MODES
            or REVISION_RE.fullmatch(object_id) is None
        ):
            raise ValueError(
                f"Git index contains a symlink, submodule, or unsupported entry: {relative}"
            )
        _register_path_prefixes(relative, seen_prefixes)
        seen_paths.add(relative)
        rows.append(
            {
                "path": relative,
                "raw_path": raw_path,
                "mode": mode,
                "git_blob_sha1": object_id,
            }
        )
    rows.sort(key=lambda row: str(row["path"]))
    return rows


def _require_exact_index_tree(root: Path, expected_tree: str) -> None:
    if REVISION_RE.fullmatch(expected_tree) is None:
        raise ValueError("expected Git tree must be a full lowercase SHA-1 value")
    index_entries = _parse_ls_files_stage(
        _run_git(root, "ls-files", "--stage", "-z").stdout
    )
    index_tree, _index_tree_raw = _independent_tree_object(index_entries)
    if index_tree != expected_tree:
        raise ValueError("holdout source index differs from the preregistered tree")


def _read_git_blobs(root: Path, object_ids: list[str]) -> dict[str, bytes]:
    ordered = sorted(set(object_ids))
    if not ordered:
        return {}
    if any(REVISION_RE.fullmatch(value) is None for value in ordered):
        raise ValueError("Git blob request contains an invalid object id")
    request = b"".join(value.encode("ascii") + b"\n" for value in ordered)
    raw = _run_git(
        root,
        "cat-file",
        "--batch",
        input_bytes=request,
        maximum_output_bytes=MAX_GIT_OUTPUT_BYTES,
    ).stdout
    offset = 0
    blobs: dict[str, bytes] = {}
    for expected_oid in ordered:
        header_end = raw.find(b"\n", offset)
        if header_end < 0:
            raise ValueError("Git blob batch response ended before its header")
        header = raw[offset:header_end].split(b" ")
        if len(header) != 3:
            raise ValueError("Git blob batch response header is invalid")
        try:
            actual_oid = header[0].decode("ascii")
            object_type = header[1].decode("ascii")
            size = int(header[2].decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Git blob batch response header is invalid") from exc
        if (
            actual_oid != expected_oid
            or object_type != "blob"
            or size < 0
            or size > MAX_BLOB_BYTES
        ):
            raise ValueError("Git blob batch response object contract is invalid")
        body_start = header_end + 1
        body_end = body_start + size
        if body_end >= len(raw) or raw[body_end : body_end + 1] != b"\n":
            raise ValueError("Git blob batch response ended before its object terminator")
        body = raw[body_start:body_end]
        if _git_object_sha1("blob", body) != expected_oid:
            raise ValueError("Git blob failed independent hashing")
        blobs[expected_oid] = body
        offset = body_end + 1
    if offset != len(raw):
        raise ValueError("Git blob batch response contains trailing bytes")
    return blobs


def _replace_regular_file(path: Path, raw: bytes, mode: str) -> None:
    target = _filesystem_path(path)
    before = target.stat(follow_symlinks=False)
    if _is_reparse(before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("source materialization target is not an independent regular file")
    descriptor, temporary_value = tempfile.mkstemp(
        prefix=f".{target.name}.kguard-blob-",
        dir=target.parent,
    )
    temporary = Path(temporary_value)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if os.name != "nt":
            temporary.chmod(0o755 if mode == "100755" else 0o644)
        os.replace(temporary, target)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def materialize_git_blob_exact_worktree(
    root: Path,
    *,
    expected_repository_id: str,
    expected_commit: str,
    expected_tree: str,
    confirm_disposable_worktree: bool = False,
) -> int:
    """Rewrite an explicitly disposable checkout to raw commit blobs."""

    resolved_root = _safe_root(root)
    if not confirm_disposable_worktree:
        raise ValueError("raw blob materialization requires disposable-worktree confirmation")
    if (
        normalize_github_repository(f"https://github.com/{expected_repository_id}")
        != expected_repository_id.casefold()
    ):
        raise ValueError("expected GitHub repository id is invalid")
    if (
        REVISION_RE.fullmatch(expected_commit) is None
        or REVISION_RE.fullmatch(expected_tree) is None
    ):
        raise ValueError("expected Git commit and tree must be full lowercase SHA-1 values")
    git_directory = _ordinary_git_directory_path(resolved_root)
    _validate_worktree_config(git_directory, expected_repository_id)
    _reject_promisor_markers(git_directory / "objects")
    _ordinary_git_directory(resolved_root)
    if _git_line(resolved_root, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("holdout source must not be a shallow clone")
    actual_commit = _git_line(resolved_root, "rev-parse", "HEAD")
    actual_tree = _git_line(resolved_root, "rev-parse", "HEAD^{tree}")
    if actual_commit != expected_commit or actual_tree != expected_tree:
        raise ValueError("holdout source commit or tree differs from preregistration")
    entries = _parse_ls_tree(
        _run_git(
            resolved_root,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            actual_commit,
        ).stdout
    )
    physical = capture_materialized_tree(resolved_root)
    physical_by_path = {str(row["path"]): row for row in physical["files"]}
    git_by_path = {str(row["path"]): row for row in entries}
    if set(physical_by_path) != set(git_by_path):
        raise ValueError("materialized source has missing, untracked, or ignored files")
    _require_exact_index_tree(resolved_root, actual_tree)
    blobs = _read_git_blobs(
        resolved_root,
        [str(row["git_blob_sha1"]) for row in entries],
    )
    rewritten: list[str] = []
    for relative in sorted(git_by_path):
        source_row = physical_by_path[relative]
        git_row = git_by_path[relative]
        raw = blobs[str(git_row["git_blob_sha1"])]
        if (
            source_row["byte_count"] == len(raw)
            and source_row["sha256"] == hashlib.sha256(raw).hexdigest()
        ):
            continue
        rewritten.append(relative)
    for relative in rewritten:
        git_row = git_by_path[relative]
        _replace_regular_file(
            resolved_root / Path(relative),
            blobs[str(git_row["git_blob_sha1"])],
            str(git_row["mode"]),
        )
    post = capture_materialized_tree(resolved_root)
    post_by_path = {str(row["path"]): row for row in post["files"]}
    if set(post_by_path) != set(git_by_path):
        raise RuntimeError("raw Git blob materialization changed the source file set")
    for relative, git_row in git_by_path.items():
        raw = blobs[str(git_row["git_blob_sha1"])]
        source_row = post_by_path[relative]
        if (
            source_row["byte_count"] != len(raw)
            or source_row["sha256"] != hashlib.sha256(raw).hexdigest()
        ):
            raise RuntimeError(f"raw Git blob materialization failed: {relative}")
    _require_exact_index_tree(resolved_root, actual_tree)
    return len(rewritten)


def build_git_materialization_receipt(
    root: Path,
    *,
    expected_repository_id: str,
    expected_commit: str,
    expected_tree: str,
) -> dict[str, Any]:
    resolved_root = _safe_root(root)
    if normalize_github_repository(f"https://github.com/{expected_repository_id}") != expected_repository_id.casefold():
        raise ValueError("expected GitHub repository id is invalid")
    if REVISION_RE.fullmatch(expected_commit) is None or REVISION_RE.fullmatch(expected_tree) is None:
        raise ValueError("expected Git commit and tree must be full lowercase SHA-1 values")
    git_directory = _ordinary_git_directory_path(resolved_root)
    origin_repository_id = _validate_worktree_config(
        git_directory, expected_repository_id
    )
    _reject_promisor_markers(git_directory / "objects")
    _ordinary_git_directory(resolved_root)
    top_level = Path(_git_line(resolved_root, "rev-parse", "--show-toplevel")).resolve(
        strict=True
    )
    if top_level != resolved_root:
        raise ValueError("holdout source workspace is not the Git repository root")
    if _git_line(resolved_root, "rev-parse", "--show-object-format") != "sha1":
        raise ValueError("holdout source Git repository must use SHA-1 object identifiers")
    if _git_line(resolved_root, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("holdout source must not be a shallow clone")
    if _run_git(resolved_root, "for-each-ref", "--format=%(refname)", "refs/replace").stdout.strip():
        raise ValueError("holdout source must not contain replacement refs")

    actual_commit = _git_line(resolved_root, "rev-parse", "HEAD")
    actual_tree = _git_line(resolved_root, "rev-parse", "HEAD^{tree}")
    if actual_commit != expected_commit or actual_tree != expected_tree:
        raise ValueError("holdout source commit or tree differs from preregistration")
    commit_raw = _run_git(resolved_root, "cat-file", "commit", actual_commit).stdout
    if _git_object_sha1("commit", commit_raw) != actual_commit:
        raise ValueError("Git commit object failed independent hashing")
    first_line = commit_raw.splitlines()[0] if commit_raw else b""
    if first_line != f"tree {actual_tree}".encode("ascii"):
        raise ValueError("Git commit object does not bind the expected tree")

    entries = _parse_ls_tree(
        _run_git(resolved_root, "ls-tree", "-r", "-z", "--full-tree", actual_commit).stdout
    )
    recomputed_tree, recomputed_tree_raw = _independent_tree_object(entries)
    git_tree_raw = _run_git(resolved_root, "cat-file", "tree", actual_tree).stdout
    if (
        recomputed_tree != actual_tree
        or _git_object_sha1("tree", git_tree_raw) != actual_tree
        or recomputed_tree_raw != git_tree_raw
    ):
        raise ValueError("Git tree object failed independent reconstruction")

    blobs = _read_git_blobs(
        resolved_root,
        [str(row["git_blob_sha1"]) for row in entries],
    )
    physical = capture_materialized_tree(resolved_root)
    physical_by_path = {str(row["path"]): row for row in physical["files"]}
    git_by_path = {str(row["path"]): row for row in entries}
    if set(physical_by_path) != set(git_by_path):
        raise ValueError("materialized source has missing, untracked, or ignored files")
    receipt_files: list[dict[str, Any]] = []
    for relative in sorted(git_by_path):
        source_row = physical_by_path[relative]
        git_row = git_by_path[relative]
        raw_blob = blobs[str(git_row["git_blob_sha1"])]
        if (
            source_row["git_blob_sha1"] != git_row["git_blob_sha1"]
            or source_row["byte_count"] != len(raw_blob)
            or source_row["sha256"] != hashlib.sha256(raw_blob).hexdigest()
        ):
            raise ValueError(f"materialized source bytes differ from the Git blob: {relative}")
        receipt_files.append(
            {
                "path": relative,
                "mode": git_row["mode"],
                "git_blob_sha1": git_row["git_blob_sha1"],
                "sha256": source_row["sha256"],
                "byte_count": source_row["byte_count"],
            }
        )

    _require_exact_index_tree(resolved_root, actual_tree)
    fsck = _run_git(
        resolved_root,
        "fsck",
        "--strict",
        "--no-dangling",
        "--no-reflogs",
        "--no-progress",
        actual_commit,
        maximum_output_bytes=MAX_FSCK_OUTPUT_BYTES,
    )
    fsck_output = fsck.stdout + fsck.stderr
    final_physical = capture_materialized_tree(resolved_root)
    if final_physical != physical:
        raise RuntimeError("materialized source changed during Git verification")
    if (
        _git_line(resolved_root, "rev-parse", "HEAD") != actual_commit
        or _git_line(resolved_root, "rev-parse", "HEAD^{tree}") != actual_tree
    ):
        raise RuntimeError("holdout source revision changed during Git verification")
    _require_exact_index_tree(resolved_root, actual_tree)
    porcelain_clean = _git_porcelain_clean(resolved_root)
    return {
        "schema": GIT_MATERIALIZATION_SCHEMA,
        "passed": True,
        "repository_id": expected_repository_id.casefold(),
        "origin_repository_id": origin_repository_id,
        "origin_repository_match": True,
        "commit": actual_commit,
        "commit_match": True,
        "commit_object_hash_match": True,
        "commit_tree": actual_tree,
        "commit_tree_match": True,
        "tree_object_reconstruction_match": True,
        "git_object_format": "sha1",
        "git_repository_layout": "ordinary_non_shallow_standalone_clone",
        "source_worktree_clean": True,
        "source_worktree_clean_method": BLOB_EXACT_CLEAN_METHOD,
        "git_porcelain_clean": porcelain_clean,
        "index_tree_match": True,
        "physical_bytes_match_git_blobs": True,
        "git_fsck_strict_passed": True,
        "git_fsck_output_sha256": hashlib.sha256(fsck_output).hexdigest(),
        "scanner_visible_tree_contract": SCANNER_VISIBLE_TREE_CONTRACT,
        "source_tree_schema": physical["schema"],
        "source_tree_sha256": physical["tree_sha256"],
        "file_count": physical["file_count"],
        "total_bytes": physical["total_bytes"],
        "files": receipt_files,
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bind a materialized holdout source tree to its preregistered Git objects."
    )
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--repository-id", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--materialize-git-blobs",
        action="store_true",
        help="rewrite this explicitly disposable checkout to the commit's raw blob bytes",
    )
    args = parser.parse_args()
    if args.materialize_git_blobs:
        materialize_git_blob_exact_worktree(
            args.workspace,
            expected_repository_id=args.repository_id,
            expected_commit=args.commit,
            expected_tree=args.tree,
            confirm_disposable_worktree=True,
        )
    receipt = build_git_materialization_receipt(
        args.workspace,
        expected_repository_id=args.repository_id,
        expected_commit=args.commit,
        expected_tree=args.tree,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json_bytes(receipt))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
