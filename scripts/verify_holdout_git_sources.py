from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time
import unicodedata
from pathlib import Path
from typing import Any


VERIFICATION_SCHEMA = "k_guard_independent_git_verification.v3"
LEGACY_SOURCE_RECEIPT_SCHEMA = "k_guard_git_source_materialization.v1"
SOURCE_RECEIPT_SCHEMA = "k_guard_git_source_materialization.v2"
SOURCE_RECEIPT_SCHEMAS = {
    LEGACY_SOURCE_RECEIPT_SCHEMA,
    SOURCE_RECEIPT_SCHEMA,
}
SOURCE_TREE_SCHEMA = "k_guard_materialized_source_tree.v1"
FILE_SET_SCHEMA = "k_guard_independent_git_file_set.v1"
STORAGE_MANIFEST_SCHEMA = "k_guard_git_mirror_storage_manifest.v1"
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_APP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GIT_FILE_MODES = {"100644", "100755"}
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
MAX_JSON_BYTES = 250 * 1024 * 1024
MAX_COMMIT_BYTES = 8 * 1024 * 1024
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_FILE_COUNT = 2_000_000
MAX_REACHABLE_OBJECTS = 5_000_000
MAX_REACHABLE_BLOB_BYTES = 1024 * 1024 * 1024 * 1024
MAX_REACHABLE_TREE_BYTES = 16 * 1024 * 1024 * 1024
MAX_REACHABLE_COMMIT_BYTES = 8 * 1024 * 1024 * 1024
MAX_BLOB_BYTES = 256 * 1024 * 1024
MAX_STORAGE_ENTRIES = 5_000_000
MAX_STORAGE_BYTES = 2 * 1024 * 1024 * 1024 * 1024
MAX_PATH_DEPTH = 256
MAX_GIT_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_FSCK_OUTPUT_BYTES = 1024 * 1024
MAX_GIT_STDERR_BYTES = 1024 * 1024
GIT_COMMAND_TIMEOUT_SECONDS = 120.0
GIT_CLONE_TIMEOUT_SECONDS = 600.0
CAT_FILE_OBJECT_TIMEOUT_SECONDS = 120.0
CAT_FILE_IDLE_TIMEOUT_SECONDS = 30.0
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


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def _canonical_rows_sha256(schema: str, rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        (schema + "\0").encode("ascii")
        + json.dumps(
            rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()


def _source_tree_sha256(rows: list[dict[str, Any]]) -> str:
    physical_rows = [
        {
            "path": row["path"],
            "sha256": row["sha256"],
            "git_blob_sha1": row["git_blob_sha1"],
            "byte_count": row["byte_count"],
        }
        for row in rows
    ]
    return _canonical_rows_sha256(SOURCE_TREE_SCHEMA, physical_rows)


def _file_set_sha256(rows: list[dict[str, Any]]) -> str:
    return _canonical_rows_sha256(FILE_SET_SCHEMA, rows)


def _git_object_sha1(kind: str, raw: bytes) -> str:
    # Git SHA-1 binds the object graph; per-file SHA-256 remains the exact-byte authority.
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"{kind} {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _windows_component_key(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or value.endswith((".", " "))
        or any(ord(character) < 32 for character in value)
        or any(character in WINDOWS_INVALID_COMPONENT_CHARS for character in value)
        or len(value.encode("utf-16-le")) // 2 > 255
    ):
        raise ValueError("Git path contains a Windows-unsafe component")
    normalized = unicodedata.normalize("NFC", value).casefold()
    device_stem = normalized.split(".", 1)[0].rstrip(" .")
    if (
        normalized == ".git"
        or device_stem == ".git"
        or device_stem in WINDOWS_RESERVED_COMPONENTS
        or WINDOWS_SHORT_NAME_RE.fullmatch(normalized) is not None
    ):
        raise ValueError("Git path contains a reserved Windows or NTFS alias")
    return normalized


def _register_path_prefixes(path: str, seen: dict[str, str]) -> None:
    normalized_parts: list[str] = []
    original_parts: list[str] = []
    for part in path.split("/"):
        normalized_parts.append(_windows_component_key(part))
        original_parts.append(part)
        normalized_prefix = "/".join(normalized_parts)
        original_prefix = "/".join(original_parts)
        previous = seen.setdefault(normalized_prefix, original_prefix)
        if previous != original_prefix:
            raise ValueError(
                "Git path prefix collision under Windows or Unicode semantics"
            )


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _safe_directory(path: Path, *, label: str) -> Path:
    unresolved = path.absolute()
    if unresolved.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    metadata = unresolved.stat(follow_symlinks=False)
    if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a regular directory")
    return unresolved.resolve(strict=True)


def _normalized_windows_path(value: str | Path) -> str:
    normalized = str(value)
    if normalized.startswith("\\\\?\\UNC\\"):
        normalized = "\\\\" + normalized[8:]
    elif normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    return os.path.normcase(os.path.abspath(normalized))


def _windows_open_handle(
    path: Path,
    *,
    desired_access: int,
    share_mode: int,
    creation_disposition: int,
) -> int:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        desired_access,
        share_mode,
        None,
        creation_disposition,
        0x00000080 | 0x00200000 | 0x08000000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(ctypes.get_last_error(), f"CreateFileW failed: {path.name}")
    return int(handle)


def _windows_final_handle_path(handle: int) -> str:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    get_final_path.restype = wintypes.DWORD
    required = get_final_path(handle, None, 0, 0)
    if required == 0:
        raise OSError(ctypes.get_last_error(), "GetFinalPathNameByHandleW failed")
    buffer = ctypes.create_unicode_buffer(required + 1)
    written = get_final_path(handle, buffer, len(buffer), 0)
    if written == 0 or written >= len(buffer):
        raise OSError(ctypes.get_last_error(), "GetFinalPathNameByHandleW failed")
    return _normalized_windows_path(buffer.value)


def _windows_close_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(handle):
        raise OSError(ctypes.get_last_error(), "CloseHandle failed")


def _read_stable_bytes(path: Path, *, maximum_bytes: int, label: str) -> bytes:
    unresolved = path.absolute()
    if unresolved.is_symlink():
        raise ValueError(f"{label} must not be a symlink")
    before_path = unresolved.stat(follow_symlinks=False)
    if (
        _is_reparse(before_path)
        or not stat.S_ISREG(before_path.st_mode)
        or before_path.st_nlink != 1
    ):
        raise ValueError(f"{label} must be one regular unlinked file")
    expected_path = unresolved.resolve(strict=True)
    raw_handle: int | None = None
    fd: int | None = None
    try:
        if os.name == "nt":
            import msvcrt

            raw_handle = _windows_open_handle(
                unresolved,
                desired_access=0x80000000,
                share_mode=0x00000001,
                creation_disposition=3,
            )
            if _windows_final_handle_path(raw_handle) != _normalized_windows_path(
                expected_path
            ):
                raise ValueError(f"{label} resolved outside its checked path")
            fd = msvcrt.open_osfhandle(raw_handle, os.O_RDONLY | os.O_BINARY)
            raw_handle = None
        else:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
                os, "O_NOFOLLOW", 0
            )
            fd = os.open(unresolved, flags)
        before = os.fstat(fd)
        if before.st_size > maximum_bytes:
            raise ValueError(f"{label} exceeds its byte budget")
        if (
            _path_descriptor_identity(before_path)
            != _path_descriptor_identity(before)
            or _is_reparse(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise ValueError(f"{label} changed before its stable read")
        with os.fdopen(fd, "rb", closefd=True) as source:
            fd = None
            raw = source.read(before.st_size + 1)
            after = os.fstat(source.fileno())
        if (
            len(raw) != before.st_size
            or len(raw) > maximum_bytes
            or _storage_identity(before) != _storage_identity(after)
        ):
            raise ValueError(f"{label} changed during its stable read")
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        if raw_handle is not None:
            _windows_close_handle(raw_handle)


def _load_canonical_json_with_raw(
    path: Path, *, maximum_bytes: int = MAX_JSON_BYTES
) -> tuple[dict[str, Any], bytes]:
    raw = _read_stable_bytes(
        path,
        maximum_bytes=maximum_bytes,
        label=f"JSON artifact {path.name}",
    )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"JSON artifact is invalid: {path.name}") from exc
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise ValueError(f"JSON artifact is not canonical: {path.name}")
    return payload, raw


def _load_canonical_json(
    path: Path, *, maximum_bytes: int = MAX_JSON_BYTES
) -> dict[str, Any]:
    payload, _raw = _load_canonical_json_with_raw(
        path,
        maximum_bytes=maximum_bytes,
    )
    return payload


def _safe_evidence_artifact(evidence_root: Path, relative_value: Any) -> Path:
    relative = Path(str(relative_value or ""))
    unresolved = evidence_root / relative
    candidate = unresolved.resolve()
    current = evidence_root
    has_link_or_reparse = False
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError:
            break
        if current.is_symlink() or _is_reparse(metadata):
            has_link_or_reparse = True
            break
    if (
        not relative.name
        or relative.is_absolute()
        or ".." in relative.parts
        or not candidate.is_relative_to(evidence_root)
        or has_link_or_reparse
        or not candidate.is_file()
    ):
        raise ValueError("source receipt path is invalid")
    return candidate


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
) -> subprocess.CompletedProcess[bytes]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
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
        maximum_output_bytes=MAX_GIT_OUTPUT_BYTES,
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


def _validate_mirror_config(
    mirror: Path, expected_repository_id: str
) -> str:
    config = _read_local_config(mirror / "config", label="independent Git mirror")
    exact_values = {
        "core.repositoryformatversion": "0",
        "core.bare": "true",
        "remote.origin.fetch": "+refs/*:refs/*",
        "remote.origin.mirror": "true",
    }
    boolean_keys = {
        "core.filemode",
        "core.ignorecase",
        "core.logallrefupdates",
        "core.precomposeunicode",
        "core.symlinks",
    }
    optional_exact = {"remote.origin.tagopt": "--no-tags"}
    for key, value in config.items():
        if key in exact_values:
            if value != exact_values[key]:
                raise ValueError("independent Git mirror local config is unsafe")
        elif key in boolean_keys:
            if value.casefold() not in {"true", "false"}:
                raise ValueError("independent Git mirror local config is unsafe")
        elif key in optional_exact:
            if value != optional_exact[key]:
                raise ValueError("independent Git mirror local config is unsafe")
        elif key == "remote.origin.url":
            continue
        else:
            raise ValueError(
                f"independent Git mirror local config key is not allowed: {key}"
            )
    if not set(exact_values).issubset(config) or "remote.origin.url" not in config:
        raise ValueError("independent Git mirror local config is incomplete")
    origin = normalize_github_repository(config["remote.origin.url"])
    if origin != expected_repository_id:
        raise ValueError("independent Git mirror origin differs from preregistration")
    return origin


def _reject_promisor_markers(objects: Path, *, label: str) -> None:
    resolved = _safe_directory(objects, label=f"{label} object directory")
    for entry in resolved.rglob("*"):
        if entry.name.casefold().endswith(".promisor"):
            raise ValueError(f"{label} must not contain promisor object markers")


def _storage_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return tuple(
        int(getattr(metadata, field, 0))
        for field in (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_file_attributes",
        )
    )


def _path_descriptor_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Return fields stable between path ``stat`` and descriptor ``fstat``.

    On CPython 3.12+ for Windows, path-based ``st_ctime_ns`` is creation time,
    while the CRT descriptor path can still report the legacy change time.
    ``st_birthtime_ns`` is consistent across both APIs.  File identity, type,
    link count, length and mtime remain mandatory on every supported runtime;
    descriptor-to-descriptor mutation checks continue to use the stricter
    :func:`_storage_identity` above.
    """

    fields = [
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
    ]
    if os.name == "nt":
        if hasattr(metadata, "st_birthtime_ns"):
            fields.append("st_birthtime_ns")
    else:
        fields.append("st_ctime_ns")
    fields.append("st_file_attributes")
    return tuple(int(getattr(metadata, field, 0)) for field in fields)


def _hash_storage_file(path: Path, before: os.stat_result) -> tuple[str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            byte_count += len(chunk)
    after = path.stat(follow_symlinks=False)
    if (
        _storage_identity(before) != _storage_identity(after)
        or byte_count != before.st_size
        or _is_reparse(after)
        or not stat.S_ISREG(after.st_mode)
        or after.st_nlink != 1
    ):
        raise ValueError("Git mirror storage changed while it was hashed")
    return digest.hexdigest(), byte_count


def _capture_mirror_storage(root: Path, *, label: str) -> dict[str, Any]:
    resolved = _safe_directory(root, label=label)
    rows: list[dict[str, Any]] = []
    identities: list[tuple[str, str, tuple[int, ...]]] = []
    pending: list[tuple[Path, str]] = [(resolved, "")]
    entry_count = 0
    total_bytes = 0
    while pending:
        directory, prefix = pending.pop()
        before_directory = directory.stat(follow_symlinks=False)
        if _is_reparse(before_directory) or not stat.S_ISDIR(before_directory.st_mode):
            raise ValueError(f"{label} contains a linked or non-directory entry")
        with os.scandir(directory) as entries:
            ordered = sorted(entries, key=lambda entry: entry.name)
        after_directory = directory.stat(follow_symlinks=False)
        if _storage_identity(before_directory) != _storage_identity(after_directory):
            raise ValueError(f"{label} changed while it was enumerated")
        identities.append((prefix, "directory", _storage_identity(after_directory)))
        for entry in ordered:
            entry_count += 1
            if entry_count > MAX_STORAGE_ENTRIES:
                raise ValueError(f"{label} exceeds the storage entry budget")
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            path = Path(entry.path)
            metadata = path.stat(follow_symlinks=False)
            if entry.is_symlink() or _is_reparse(metadata):
                raise ValueError(f"{label} contains a symlink or reparse point: {relative}")
            if entry.is_dir(follow_symlinks=False):
                rows.append({"path": relative, "kind": "directory"})
                pending.append((path, relative))
                continue
            if (
                not entry.is_file(follow_symlinks=False)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise ValueError(f"{label} contains a non-regular entry: {relative}")
            if metadata.st_nlink != 1:
                raise ValueError(f"{label} contains a hardlinked file: {relative}")
            sha256, byte_count = _hash_storage_file(path, metadata)
            total_bytes += byte_count
            if total_bytes > MAX_STORAGE_BYTES:
                raise ValueError(f"{label} exceeds the storage byte budget")
            stable = path.stat(follow_symlinks=False)
            rows.append(
                {
                    "path": relative,
                    "kind": "file",
                    "sha256": sha256,
                    "byte_count": byte_count,
                }
            )
            identities.append((relative, "file", _storage_identity(stable)))
    rows.sort(key=lambda row: (str(row["path"]), str(row["kind"])))
    identities.sort(key=lambda row: (row[0], row[1]))
    manifest_sha256 = hashlib.sha256(
        (STORAGE_MANIFEST_SCHEMA + "\0").encode("ascii")
        + json.dumps(
            rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    return {
        "manifest_sha256": manifest_sha256,
        "rows": rows,
        "identities": identities,
    }


def _require_stable_storage(
    before: dict[str, Any], after: dict[str, Any], *, label: str
) -> None:
    if before != after:
        raise ValueError(f"{label} changed during independent verification")


def _clone_private_mirror(
    source: Path,
    destination: Path,
    *,
    expected_repository_id: str,
) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError("private Git mirror destination already exists")
    completed = _run_bounded_process(
        [
            "git",
            "clone",
            "--mirror",
            "--no-local",
            str(source),
            str(destination),
        ],
        cwd=destination.parent,
        environment=_git_environment(),
        timeout_seconds=GIT_CLONE_TIMEOUT_SECONDS,
        maximum_output_bytes=MAX_GIT_OUTPUT_BYTES,
        label="private Git mirror clone",
    )
    if completed.returncode != 0:
        detail = hashlib.sha256(completed.stderr).hexdigest()[:20]
        raise ValueError(f"private Git mirror clone failed ({detail})")
    _run_git(
        destination,
        "remote",
        "set-url",
        "origin",
        f"https://github.com/{expected_repository_id}.git",
    )


def _git_command(mirror: Path, *args: str) -> list[str]:
    return [
        "git",
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        f"--git-dir={mirror}",
        *args,
    ]


def _run_git(
    mirror: Path,
    *args: str,
    check: bool = True,
    timeout_seconds: float = GIT_COMMAND_TIMEOUT_SECONDS,
    maximum_output_bytes: int = MAX_GIT_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[bytes]:
    completed = _run_bounded_process(
        _git_command(mirror, *args),
        cwd=mirror.parent,
        environment=_git_environment(),
        timeout_seconds=timeout_seconds,
        maximum_output_bytes=maximum_output_bytes,
        label=f"independent Git {args[0]}",
    )
    if check and completed.returncode != 0:
        detail = hashlib.sha256(completed.stderr).hexdigest()[:20]
        raise ValueError(f"independent Git verification failed ({args[0]}:{detail})")
    return completed


def _git_line(mirror: Path, *args: str) -> str:
    raw = _run_git(mirror, *args).stdout
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError(
            "independent Git verification returned non-UTF-8 text"
        ) from exc
    if not value or "\n" in value or "\r" in value:
        raise ValueError("independent Git verification expected one line")
    return value


def _validate_bare_mirror(mirror: Path, expected_repository_id: str) -> str:
    resolved = _safe_directory(mirror, label="independent Git mirror")
    origin = _validate_mirror_config(resolved, expected_repository_id)
    _reject_promisor_markers(resolved / "objects", label="independent Git mirror")
    if _git_line(resolved, "rev-parse", "--is-bare-repository") != "true":
        raise ValueError("independent Git source must be a bare mirror")
    absolute_git_dir = Path(
        _git_line(resolved, "rev-parse", "--absolute-git-dir")
    ).resolve(strict=True)
    common_git_dir = Path(_git_line(resolved, "rev-parse", "--git-common-dir"))
    if not common_git_dir.is_absolute():
        common_git_dir = resolved.parent / common_git_dir
    if absolute_git_dir != resolved or common_git_dir.resolve(strict=True) != resolved:
        raise ValueError(
            "independent Git mirror uses an external or shared Git directory"
        )
    if _git_line(resolved, "rev-parse", "--show-object-format") != "sha1":
        raise ValueError("independent Git mirror must use SHA-1 object identifiers")
    if _git_line(resolved, "rev-parse", "--is-shallow-repository") != "false":
        raise ValueError("independent Git mirror must not be shallow")
    for relative in ("objects/info/alternates", "info/grafts", "shallow"):
        if (resolved / relative).exists():
            raise ValueError(
                f"independent Git mirror uses a forbidden indirection: {relative}"
            )
    if (resolved / "worktrees").exists():
        raise ValueError("independent Git mirror must not contain linked worktrees")
    if _run_git(
        resolved, "for-each-ref", "--format=%(refname)", "refs/replace"
    ).stdout.strip():
        raise ValueError("independent Git mirror must not contain replacement refs")
    return origin


class _CatFileBatch:
    def __init__(self, mirror: Path) -> None:
        self._stderr = tempfile.TemporaryFile()
        self._deadline_lock = threading.Lock()
        self._watchdog_stop = threading.Event()
        self._absolute_deadline: float | None = None
        self._idle_deadline: float | None = None
        self._failure_reason: str | None = None
        try:
            self._process = subprocess.Popen(
                _git_command(mirror, "cat-file", "--batch"),
                cwd=mirror.parent,
                env=_git_environment(),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
                **_process_group_options(),
            )
        except BaseException:
            self._stderr.close()
            raise
        if self._process.stdin is None or self._process.stdout is None:
            raise RuntimeError("git cat-file batch streams are unavailable")
        self._stdin = self._process.stdin
        self._stdout = self._process.stdout
        self._watchdog = threading.Thread(
            target=self._watch_batch,
            name="kguard-cat-file-watchdog",
            daemon=True,
        )
        self._watchdog.start()

    def _begin_request(self) -> None:
        now = time.monotonic()
        with self._deadline_lock:
            if self._failure_reason is not None:
                raise ValueError(self._failure_reason)
            self._absolute_deadline = now + CAT_FILE_OBJECT_TIMEOUT_SECONDS
            self._idle_deadline = now + CAT_FILE_IDLE_TIMEOUT_SECONDS

    def _mark_progress(self) -> None:
        with self._deadline_lock:
            if self._absolute_deadline is not None:
                self._idle_deadline = time.monotonic() + CAT_FILE_IDLE_TIMEOUT_SECONDS

    def _finish_request(self) -> None:
        with self._deadline_lock:
            self._absolute_deadline = None
            self._idle_deadline = None

    def _abort(self, reason: str) -> None:
        with self._deadline_lock:
            if self._failure_reason is None:
                self._failure_reason = reason
        _terminate_process_tree(self._process)

    def _watch_batch(self) -> None:
        while not self._watchdog_stop.wait(0.05):
            if self._process.poll() is not None:
                return
            try:
                stderr_size = os.fstat(self._stderr.fileno()).st_size
            except OSError:
                return
            if stderr_size > MAX_GIT_STDERR_BYTES:
                self._abort("git cat-file batch exceeded its stderr budget")
                return
            now = time.monotonic()
            with self._deadline_lock:
                absolute = self._absolute_deadline
                idle = self._idle_deadline
            if absolute is not None and now >= absolute:
                self._abort("git cat-file object exceeded its time budget")
                return
            if idle is not None and now >= idle:
                self._abort("git cat-file object exceeded its idle budget")
                return

    def _raise_failure(self, fallback: str) -> None:
        with self._deadline_lock:
            reason = self._failure_reason
        raise ValueError(reason or fallback)

    def read(
        self, oid: str, *, expected_type: str, capture_limit: int | None
    ) -> dict[str, Any]:
        if REVISION_RE.fullmatch(oid) is None:
            raise ValueError("Git object id is invalid")
        self._begin_request()
        try:
            self._stdin.write(oid.encode("ascii") + b"\n")
            self._stdin.flush()
            header = self._stdout.readline()
            if not header:
                self._raise_failure("git cat-file batch header is unavailable")
            self._mark_progress()
            try:
                returned_oid, kind_raw, size_raw = header.rstrip(b"\n").split(
                    b" ", 2
                )
                kind = kind_raw.decode("ascii")
                size = int(size_raw)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError("git cat-file batch header is invalid") from exc
            if (
                returned_oid.decode("ascii", errors="strict") != oid
                or kind != expected_type
                or size < 0
            ):
                raise ValueError("git cat-file returned an unexpected object")
            capture = capture_limit is not None
            if (capture and size > capture_limit) or (
                kind == "blob" and size > MAX_BLOB_BYTES
            ):
                self._abort(f"Git {kind} object exceeds the verification budget")
                raise ValueError(f"Git {kind} object exceeds the verification budget")
            sha1 = hashlib.sha1(usedforsecurity=False)
            sha1.update(f"{kind} {size}\0".encode("ascii"))
            sha256 = hashlib.sha256()
            chunks: list[bytes] = []
            remaining = size
            while remaining:
                chunk = self._stdout.read(min(1024 * 1024, remaining))
                if not chunk:
                    self._raise_failure("git cat-file batch stream ended early")
                self._mark_progress()
                sha1.update(chunk)
                sha256.update(chunk)
                if capture:
                    chunks.append(chunk)
                remaining -= len(chunk)
            if self._stdout.read(1) != b"\n":
                self._raise_failure("git cat-file batch object terminator is invalid")
            self._mark_progress()
            if sha1.hexdigest() != oid:
                raise ValueError(f"Git {kind} object failed independent hashing")
            return {
                "kind": kind,
                "byte_count": size,
                "sha256": sha256.hexdigest(),
                "raw": b"".join(chunks),
            }
        finally:
            self._finish_request()

    def close(self) -> None:
        self._finish_request()
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
        except OSError:
            pass
        try:
            return_code = self._process.wait(timeout=30)
        except subprocess.TimeoutExpired as exc:
            _terminate_process_tree(self._process)
            detail = self._stderr_sha256()[:20]
            self._watchdog_stop.set()
            self._watchdog.join(timeout=5)
            self._stderr.close()
            raise ValueError(f"git cat-file batch did not terminate ({detail})") from exc
        self._watchdog_stop.set()
        self._watchdog.join(timeout=5)
        detail = self._stderr_sha256()[:20]
        self._stderr.close()
        with self._deadline_lock:
            reason = self._failure_reason
        if reason is not None:
            raise ValueError(reason)
        if return_code != 0:
            raise ValueError(f"git cat-file batch failed ({detail})")

    def _stderr_sha256(self) -> str:
        digest = hashlib.sha256()
        self._stderr.seek(0)
        while chunk := self._stderr.read(1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()

    def __enter__(self) -> "_CatFileBatch":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if exc_type is not None:
            try:
                self._finish_request()
                _terminate_process_tree(self._process)
            finally:
                self._watchdog_stop.set()
                self._watchdog.join(timeout=5)
                self._stderr.close()
            return
        try:
            self.close()
        except (OSError, subprocess.SubprocessError, ValueError):
            if exc_type is None:
                raise


def _parse_tree(raw: bytes) -> list[tuple[str, bytes, str]]:
    rows: list[tuple[str, bytes, str]] = []
    cursor = 0
    seen_names: set[bytes] = set()
    seen_components: dict[str, str] = {}
    while cursor < len(raw):
        space = raw.find(b" ", cursor)
        nul = raw.find(b"\0", space + 1)
        if space <= cursor or nul <= space + 1 or nul + 21 > len(raw):
            raise ValueError("Git tree object record is malformed")
        mode_raw = raw[cursor:space]
        name = raw[space + 1 : nul]
        oid = raw[nul + 1 : nul + 21].hex()
        try:
            mode = mode_raw.decode("ascii")
            decoded_name = name.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Git tree contains a non-UTF-8 path or mode") from exc
        if (
            not name
            or name in seen_names
            or name in {b".", b".."}
            or b"/" in name
            or b"\\" in name
            or mode not in {*GIT_FILE_MODES, "40000"}
        ):
            raise ValueError("Git tree contains an unsafe or unsupported entry")
        component_key = _windows_component_key(decoded_name)
        previous = seen_components.setdefault(component_key, decoded_name)
        if previous != decoded_name:
            raise ValueError("Git tree entry collision under Windows semantics")
        seen_names.add(name)
        rows.append((mode, name, oid))
        cursor = nul + 21
    if cursor != len(raw):
        raise ValueError("Git tree object has trailing bytes")
    return rows


def _parse_graph_tree(raw: bytes) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    cursor = 0
    seen_names: set[bytes] = set()
    allowed_modes = {*GIT_FILE_MODES, "120000", "160000", "40000"}
    while cursor < len(raw):
        space = raw.find(b" ", cursor)
        nul = raw.find(b"\0", space + 1)
        if space <= cursor or nul <= space + 1 or nul + 21 > len(raw):
            raise ValueError("Git history tree object record is malformed")
        mode_raw = raw[cursor:space]
        name = raw[space + 1 : nul]
        oid = raw[nul + 1 : nul + 21].hex()
        try:
            mode = mode_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Git history tree contains a non-ASCII mode") from exc
        if (
            not name
            or name in seen_names
            or name in {b".", b".."}
            or b"/" in name
            or mode not in allowed_modes
        ):
            raise ValueError("Git history tree contains an unsafe entry")
        seen_names.add(name)
        rows.append((mode, oid))
        cursor = nul + 21
    if cursor != len(raw):
        raise ValueError("Git history tree object has trailing bytes")
    return rows


def _parse_commit_links(raw: bytes) -> tuple[str, list[str]]:
    header, separator, _message = raw.partition(b"\n\n")
    if not separator:
        raise ValueError("Git commit object has no header terminator")
    tree: str | None = None
    parents: list[str] = []
    previous_header = False
    for line in header.split(b"\n"):
        if line.startswith(b" "):
            if not previous_header:
                raise ValueError("Git commit continuation header is malformed")
            continue
        key, delimiter, value = line.partition(b" ")
        if not delimiter or not key or not value:
            raise ValueError("Git commit header is malformed")
        previous_header = True
        if key == b"tree":
            if tree is not None:
                raise ValueError("Git commit contains duplicate tree headers")
            try:
                candidate = value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("Git commit tree id is malformed") from exc
            if REVISION_RE.fullmatch(candidate) is None:
                raise ValueError("Git commit tree id is malformed")
            tree = candidate
        elif key == b"parent":
            try:
                parent = value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("Git commit parent id is malformed") from exc
            if REVISION_RE.fullmatch(parent) is None or parent in parents:
                raise ValueError("Git commit parent id is malformed")
            parents.append(parent)
    if tree is None or not header.startswith(f"tree {tree}".encode("ascii")):
        raise ValueError("Git commit does not start with one valid tree header")
    return tree, parents


def _reconstruct_tree_sha1(rows: list[dict[str, Any]]) -> str:
    root: dict[bytes, dict[str, Any]] = {}
    seen_prefixes: dict[str, str] = {}
    for row in rows:
        path = str(row["path"])
        _register_path_prefixes(path, seen_prefixes)
        parts = path.encode("utf-8").split(b"/")
        if len(parts) > MAX_PATH_DEPTH + 1:
            raise ValueError("Git source exceeds the maximum path depth")
        node = root
        for part in parts[:-1]:
            current = node.setdefault(part, {"kind": "tree", "children": {}})
            if current.get("kind") != "tree":
                raise ValueError("Git source contains a file/directory conflict")
            node = current["children"]
        if parts[-1] in node:
            raise ValueError("Git source contains a duplicate path")
        node[parts[-1]] = {
            "kind": "blob",
            "mode": row["mode"],
            "oid": row["git_blob_sha1"],
        }

    computed: dict[int, str] = {}
    pending: list[tuple[dict[bytes, dict[str, Any]], bool]] = [(root, False)]
    while pending:
        node, expanded = pending.pop()
        if not expanded:
            pending.append((node, True))
            for value in node.values():
                if value["kind"] == "tree":
                    pending.append((value["children"], False))
            continue
        body = bytearray()
        ordered = sorted(
            node.items(),
            key=lambda item: item[0] + (b"/" if item[1]["kind"] == "tree" else b""),
        )
        for name, value in ordered:
            if value["kind"] == "tree":
                oid = computed[id(value["children"])]
                mode = "40000"
            else:
                oid = value["oid"]
                mode = value["mode"]
            body.extend(mode.encode("ascii") + b" " + name + b"\0" + bytes.fromhex(oid))
            if len(body) > MAX_TREE_BYTES:
                raise ValueError("Git reconstructed tree exceeds the verification budget")
        computed[id(node)] = _git_object_sha1("tree", bytes(body))
    return computed[id(root)]


def _walk_commit(
    batch: _CatFileBatch, commit: str, expected_tree: str
) -> tuple[bytes, list[dict[str, Any]]]:
    commit_cache: dict[str, tuple[bytes, str, list[str]]] = {}
    tree_cache: dict[str, bytes] = {}
    blob_hashes: dict[str, tuple[str, int]] = {}
    reachable_object_count = 0
    reachable_blob_bytes = 0
    reachable_tree_bytes = 0
    reachable_commit_bytes = 0

    def reserve_object() -> None:
        nonlocal reachable_object_count
        reachable_object_count += 1
        if reachable_object_count > MAX_REACHABLE_OBJECTS:
            raise ValueError("Git history exceeds the reachable-object budget")

    def read_commit(oid: str) -> tuple[bytes, str, list[str]]:
        nonlocal reachable_commit_bytes
        cached = commit_cache.get(oid)
        if cached is not None:
            return cached
        reserve_object()
        result = batch.read(
            oid, expected_type="commit", capture_limit=MAX_COMMIT_BYTES
        )
        raw = result["raw"]
        reachable_commit_bytes += int(result["byte_count"])
        if reachable_commit_bytes > MAX_REACHABLE_COMMIT_BYTES:
            raise ValueError("Git history exceeds the reachable-commit byte budget")
        tree_oid, parents = _parse_commit_links(raw)
        cached = (raw, tree_oid, parents)
        commit_cache[oid] = cached
        return cached

    def read_tree(oid: str) -> bytes:
        nonlocal reachable_tree_bytes
        cached = tree_cache.get(oid)
        if cached is not None:
            return cached
        reserve_object()
        result = batch.read(
            oid, expected_type="tree", capture_limit=MAX_TREE_BYTES
        )
        raw = result["raw"]
        reachable_tree_bytes += int(result["byte_count"])
        if reachable_tree_bytes > MAX_REACHABLE_TREE_BYTES:
            raise ValueError("Git history exceeds the reachable-tree byte budget")
        tree_cache[oid] = raw
        return raw

    def read_blob(oid: str) -> tuple[str, int]:
        nonlocal reachable_blob_bytes
        cached = blob_hashes.get(oid)
        if cached is not None:
            return cached
        reserve_object()
        blob = batch.read(oid, expected_type="blob", capture_limit=None)
        cached = (str(blob["sha256"]), int(blob["byte_count"]))
        reachable_blob_bytes += cached[1]
        if reachable_blob_bytes > MAX_REACHABLE_BLOB_BYTES:
            raise ValueError("Git history exceeds the reachable-blob byte budget")
        blob_hashes[oid] = cached
        return cached

    commit_object, target_tree, _target_parents = read_commit(commit)
    if target_tree != expected_tree:
        raise ValueError("Git commit object does not bind the preregistered tree")

    rows: list[dict[str, Any]] = []
    prefix_collisions: dict[str, str] = {}

    pending_target = [(expected_tree, b"", 0)]
    while pending_target:
        tree_oid, prefix, depth = pending_target.pop()
        if depth > MAX_PATH_DEPTH:
            raise ValueError("Git tree exceeds the maximum path depth")
        tree = read_tree(tree_oid)
        for mode, name, oid in _parse_tree(tree):
            raw_path = prefix + name
            path = raw_path.decode("utf-8")
            _register_path_prefixes(path, prefix_collisions)
            if mode == "40000":
                pending_target.append((oid, raw_path + b"/", depth + 1))
                continue
            cached_blob = read_blob(oid)
            rows.append(
                {
                    "path": path,
                    "mode": mode,
                    "git_blob_sha1": oid,
                    "sha256": cached_blob[0],
                    "byte_count": cached_blob[1],
                }
            )
            if len(rows) > MAX_FILE_COUNT:
                raise ValueError("Git source exceeds the maximum file count")
    rows.sort(key=lambda row: str(row["path"]))
    if _reconstruct_tree_sha1(rows) != expected_tree:
        raise ValueError("Git root tree failed independent flat-file reconstruction")

    pending_commits = [commit]
    walked_commits: set[str] = set()
    walked_trees: set[str] = set()
    while pending_commits:
        commit_oid = pending_commits.pop()
        if commit_oid in walked_commits:
            continue
        walked_commits.add(commit_oid)
        _raw, tree_oid, parents = read_commit(commit_oid)
        pending_commits.extend(parents)
        pending_trees = [tree_oid]
        while pending_trees:
            current_tree = pending_trees.pop()
            if current_tree in walked_trees:
                continue
            walked_trees.add(current_tree)
            for mode, oid in _parse_graph_tree(read_tree(current_tree)):
                if mode == "40000":
                    pending_trees.append(oid)
                elif mode != "160000":
                    read_blob(oid)
    return commit_object, rows


def _validate_source_receipt(
    receipt: dict[str, Any],
    *,
    app: dict[str, Any],
    expected_schema: str,
) -> list[dict[str, Any]]:
    required = {
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
    if expected_schema == SOURCE_RECEIPT_SCHEMA:
        required.update(
            {
                "source_worktree_clean_method",
                "git_porcelain_clean",
                "index_tree_match",
                "physical_bytes_match_git_blobs",
            }
        )
    if set(receipt) != required:
        raise ValueError("source materialization receipt fields are invalid")
    repository_id = str(app.get("repository_id") or "").casefold()
    current_contract_invalid = (
        expected_schema == SOURCE_RECEIPT_SCHEMA
        and (
            receipt.get("source_worktree_clean_method")
            != "git_blob_sha256_file_set_plus_index_tree_v2"
            or not isinstance(receipt.get("git_porcelain_clean"), bool)
            or receipt.get("index_tree_match") is not True
            or receipt.get("physical_bytes_match_git_blobs") is not True
            or receipt.get("scanner_visible_tree_contract")
            != (
                "regular-file paths and raw Git blob bytes; "
                "Git modes remain commit-bound metadata"
            )
        )
    )
    legacy_contract_invalid = (
        expected_schema == LEGACY_SOURCE_RECEIPT_SCHEMA
        and receipt.get("scanner_visible_tree_contract")
        != "regular-file paths and exact bytes; Git modes remain commit-bound metadata"
    )
    if (
        expected_schema not in SOURCE_RECEIPT_SCHEMAS
        or receipt.get("schema") != expected_schema
        or receipt.get("passed") is not True
        or receipt.get("repository_id") != repository_id
        or receipt.get("origin_repository_id") != repository_id
        or receipt.get("origin_repository_match") is not True
        or receipt.get("commit") != app.get("commit")
        or receipt.get("commit_match") is not True
        or receipt.get("commit_object_hash_match") is not True
        or receipt.get("commit_tree") != app.get("commit_tree")
        or receipt.get("commit_tree_match") is not True
        or receipt.get("tree_object_reconstruction_match") is not True
        or receipt.get("git_object_format") != "sha1"
        or receipt.get("git_repository_layout")
        != "ordinary_non_shallow_standalone_clone"
        or receipt.get("source_worktree_clean") is not True
        or current_contract_invalid
        or legacy_contract_invalid
        or receipt.get("git_fsck_strict_passed") is not True
        or SHA256_RE.fullmatch(str(receipt.get("git_fsck_output_sha256") or "")) is None
        or receipt.get("source_tree_schema") != SOURCE_TREE_SCHEMA
        or receipt.get("raw_returned") is not False
    ):
        raise ValueError("source materialization receipt contract is invalid")
    rows = receipt.get("files")
    if not isinstance(rows, list) or len(rows) > MAX_FILE_COUNT:
        raise ValueError("source materialization file rows are invalid")
    normalized: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    seen_prefixes: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "path",
            "mode",
            "git_blob_sha1",
            "sha256",
            "byte_count",
        }:
            raise ValueError("source materialization file row fields are invalid")
        path = str(row.get("path") or "")
        mode = str(row.get("mode") or "")
        blob = str(row.get("git_blob_sha1") or "")
        digest = str(row.get("sha256") or "")
        byte_count = row.get("byte_count")
        parts = path.split("/")
        if (
            not path
            or path in seen_paths
            or len(parts) > MAX_PATH_DEPTH + 1
            or any(
                part in {"", ".", ".."} or part.casefold() == ".git" for part in parts
            )
            or "\\" in path
            or mode not in GIT_FILE_MODES
            or REVISION_RE.fullmatch(blob) is None
            or SHA256_RE.fullmatch(digest) is None
            or not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
            or byte_count < 0
        ):
            raise ValueError("source materialization file row is invalid")
        _register_path_prefixes(path, seen_prefixes)
        seen_paths.add(path)
        normalized.append(
            {
                "path": path,
                "mode": mode,
                "git_blob_sha1": blob,
                "sha256": digest,
                "byte_count": byte_count,
            }
        )
    if normalized != sorted(normalized, key=lambda row: row["path"]):
        raise ValueError("source materialization file rows are not sorted")
    if (
        receipt.get("file_count") != len(normalized)
        or receipt.get("total_bytes") != sum(row["byte_count"] for row in normalized)
        or receipt.get("source_tree_sha256") != _source_tree_sha256(normalized)
        or _reconstruct_tree_sha1(normalized) != app.get("commit_tree")
    ):
        raise ValueError("source materialization receipt aggregates are invalid")
    return normalized


def build_independent_verification(
    preregistration_path: Path,
    evidence_dir: Path,
    mirror_root: Path,
) -> dict[str, Any]:
    preregistration_path = preregistration_path.absolute()
    evidence_root = _safe_directory(evidence_dir, label="campaign evidence root")
    mirrors = _safe_directory(mirror_root, label="independent Git mirror root")
    preregistration, preregistration_raw = _load_canonical_json_with_raw(
        preregistration_path, maximum_bytes=10 * 1024 * 1024
    )
    campaign_path = evidence_root / "campaign.json"
    campaign, campaign_raw = _load_canonical_json_with_raw(campaign_path)
    prereg_apps = {
        str(row.get("app") or ""): row
        for row in preregistration.get("apps", [])
        if isinstance(row, dict) and row.get("app")
    }
    campaign_rows = (
        campaign.get("apps") if isinstance(campaign.get("apps"), list) else []
    )
    campaign_apps = {
        str(row.get("app") or ""): row
        for row in campaign_rows
        if isinstance(row, dict) and row.get("app")
    }
    protocol = campaign.get("holdout_protocol")
    protocol_schema = (
        str(protocol.get("holdout_protocol_schema") or "")
        if isinstance(protocol, dict)
        else ""
    )
    expected_receipt_schema = (
        SOURCE_RECEIPT_SCHEMA
        if protocol_schema
        in {"k_guard_holdout_protocol.v5", "k_guard_holdout_protocol.v6"}
        else LEGACY_SOURCE_RECEIPT_SCHEMA
    )
    if (
        not prereg_apps
        or len(prereg_apps) != len(preregistration.get("apps", []))
        or set(campaign_apps) != set(prereg_apps)
        or len(campaign_apps) != len(campaign_rows)
        or not isinstance(protocol, dict)
        or protocol_schema
        not in {
            "k_guard_holdout_protocol.v3",
            "k_guard_holdout_protocol.v4",
            "k_guard_holdout_protocol.v5",
            "k_guard_holdout_protocol.v6",
        }
        or SHA256_RE.fullmatch(
            str(protocol.get("independent_git_verifier_sha256") or "")
        )
        is None
    ):
        raise ValueError(
            "campaign is not bound to the independent Git verification protocol"
        )

    expected_receipts: set[str] = set()
    app_results: list[dict[str, Any]] = []
    for app_name in sorted(prereg_apps):
        if SAFE_APP_RE.fullmatch(app_name) is None:
            raise ValueError("holdout app name is unsafe for independent mirror lookup")
        app = prereg_apps[app_name]
        campaign_app = campaign_apps[app_name]
        repository_id = str(app.get("repository_id") or "").casefold()
        if (
            normalize_github_repository(str(app.get("repository") or ""))
            != repository_id
            or REVISION_RE.fullmatch(str(app.get("commit") or "")) is None
            or REVISION_RE.fullmatch(str(app.get("commit_tree") or "")) is None
        ):
            raise ValueError("preregistered Git source identity is invalid")
        for field in ("repository", "repository_id", "commit", "commit_tree"):
            if campaign_app.get(field) != app.get(field):
                raise ValueError(
                    f"campaign source binding differs from preregistration: {app_name}"
                )
        receipt_relative = str(
            campaign_app.get("source_materialization_receipt_path") or ""
        )
        expected_receipts.add(receipt_relative)
        receipt_path = _safe_evidence_artifact(evidence_root, receipt_relative)
        receipt, receipt_raw = _load_canonical_json_with_raw(receipt_path)
        if hashlib.sha256(receipt_raw).hexdigest() != campaign_app.get(
            "source_materialization_receipt_sha256"
        ):
            raise ValueError(f"source receipt hash differs from campaign: {app_name}")
        receipt_rows = _validate_source_receipt(
            receipt,
            app=app,
            expected_schema=expected_receipt_schema,
        )
        if (
            campaign_app.get("source_materialization_schema")
            != expected_receipt_schema
            or campaign_app.get("source_tree_sha256")
            != receipt.get("source_tree_sha256")
            or campaign_app.get("tracked_files") != receipt.get("file_count")
            or campaign_app.get("source_total_bytes") != receipt.get("total_bytes")
        ):
            raise ValueError(
                f"campaign source receipt projection is invalid: {app_name}"
            )

        input_mirror = mirrors / f"{app_name}.git"
        input_storage_before = _capture_mirror_storage(
            input_mirror,
            label="independent Git input mirror",
        )
        origin = _validate_bare_mirror(input_mirror, repository_id)
        commit = str(app["commit"])
        tree = str(app["commit_tree"])
        with tempfile.TemporaryDirectory(prefix="kguard-git-verifier-") as private_value:
            private_root = _safe_directory(
                Path(private_value),
                label="private Git verification root",
            )
            private_mirror = private_root / f"{app_name}.git"
            _clone_private_mirror(
                input_mirror,
                private_mirror,
                expected_repository_id=repository_id,
            )
            input_storage_after = _capture_mirror_storage(
                input_mirror,
                label="independent Git input mirror",
            )
            _require_stable_storage(
                input_storage_before,
                input_storage_after,
                label="independent Git input mirror",
            )
            private_storage_before = _capture_mirror_storage(
                private_mirror,
                label="verifier-owned Git mirror snapshot",
            )
            _validate_bare_mirror(private_mirror, repository_id)
            with _CatFileBatch(private_mirror) as batch:
                commit_object, independent_rows = _walk_commit(batch, commit, tree)
            if independent_rows != receipt_rows:
                raise ValueError(
                    f"independent Git mirror differs from scanned source receipt: {app_name}"
                )
            fsck = _run_git(
                private_mirror,
                "fsck",
                "--strict",
                "--full",
                "--no-dangling",
                "--no-reflogs",
                "--no-progress",
                commit,
                maximum_output_bytes=MAX_FSCK_OUTPUT_BYTES,
            )
            fsck_output = fsck.stdout + fsck.stderr
            private_storage_after = _capture_mirror_storage(
                private_mirror,
                label="verifier-owned Git mirror snapshot",
            )
            _require_stable_storage(
                private_storage_before,
                private_storage_after,
                label="verifier-owned Git mirror snapshot",
            )
        app_results.append(
            {
                "app": app_name,
                "repository_id": repository_id,
                "origin_repository_id": origin,
                "origin_repository_match": True,
                "commit": commit,
                "commit_object_base64": base64.b64encode(commit_object).decode("ascii"),
                "commit_object_hash_match": True,
                "commit_tree": tree,
                "tree_object_reconstruction_match": True,
                "git_object_format": "sha1",
                "git_repository_layout": (
                    "verifier_owned_unlinked_full_bare_sha1_mirror_snapshot"
                ),
                "git_fsck_strict_passed": True,
                "git_fsck_output_sha256": hashlib.sha256(fsck_output).hexdigest(),
                "input_mirror_storage_manifest_sha256": input_storage_before[
                    "manifest_sha256"
                ],
                "private_snapshot_method": "git_clone_mirror_no_local",
                "private_snapshot_storage_manifest_sha256": private_storage_before[
                    "manifest_sha256"
                ],
                "storage_stable": True,
                "source_materialization_receipt_path": receipt_relative,
                "source_materialization_receipt_sha256": hashlib.sha256(
                    receipt_raw
                ).hexdigest(),
                "source_tree_sha256": _source_tree_sha256(independent_rows),
                "file_set_sha256": _file_set_sha256(independent_rows),
                "file_count": len(independent_rows),
                "total_bytes": sum(row["byte_count"] for row in independent_rows),
                "files": independent_rows,
                "raw_returned": False,
            }
        )

    receipt_root = _safe_directory(
        evidence_root / "source-receipts",
        label="source receipt directory",
    )
    receipt_entries = list(receipt_root.iterdir())
    if any(
        entry.is_symlink()
        or _is_reparse(entry.stat(follow_symlinks=False))
        or not entry.is_file()
        for entry in receipt_entries
    ):
        raise ValueError("source receipt directory contains a non-regular direct artifact")
    actual_receipts = {
        path.relative_to(evidence_root).as_posix() for path in receipt_entries
    }
    if actual_receipts != expected_receipts:
        raise ValueError("source receipt artifact set differs from the campaign")
    return {
        "schema": VERIFICATION_SCHEMA,
        "campaign_id": preregistration.get("campaign_id"),
        "preregistration_sha256": hashlib.sha256(preregistration_raw).hexdigest(),
        "campaign_sha256": hashlib.sha256(campaign_raw).hexdigest(),
        "holdout_protocol_manifest_sha256": protocol.get("protocol_manifest_sha256"),
        "independent_git_verifier_sha256": protocol.get(
            "independent_git_verifier_sha256"
        ),
        "verification_method": (
            "verifier_owned_no_local_mirror_snapshot_raw_git_object_reconstruction"
        ),
        "byte_binding": "git_sha1_graph_plus_independent_sha256_file_bytes",
        "storage_binding": "pre_post_sha256_manifest_plus_file_identity",
        "path_policy": "windows_ntfs_materialization_fail_closed_v1",
        "execution_provenance": "unsigned_local_replay_receipt",
        "external_signed_provenance_required_for_contest_go": True,
        "acquisition_boundary": (
            "input origin is configuration metadata; an unlinked verifier-owned no-local mirror "
            "snapshot is storage-manifested before and after content-addressed reconstruction"
        ),
        "source_contents_embedded": False,
        "app_count": len(app_results),
        "apps": app_results,
        "raw_returned": False,
    }


def _trusted_output_parent(evidence_root: Path, parent: Path) -> Path:
    candidate = Path(os.path.abspath(parent))
    if not candidate.is_relative_to(evidence_root):
        raise ValueError("independent verification output parent is outside evidence-dir")
    current = evidence_root
    for part in candidate.relative_to(evidence_root).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("independent verification output parent contains a symlink")
        metadata = current.stat(follow_symlinks=False)
        if _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(
                "independent verification output parent is not a trusted directory"
            )
    resolved = current.resolve(strict=True)
    if resolved != candidate:
        raise ValueError("independent verification output parent changed during validation")
    return resolved


def _write_new_artifact(output: Path, raw: bytes, *, evidence_root: Path) -> None:
    parent = _trusted_output_parent(evidence_root, output.parent)
    destination = parent / output.name
    raw_handle: int | None = None
    fd: int | None = None
    try:
        if os.name == "nt":
            import msvcrt

            raw_handle = _windows_open_handle(
                destination,
                desired_access=0x40000000,
                share_mode=0,
                creation_disposition=1,
            )
            if _windows_final_handle_path(raw_handle) != _normalized_windows_path(
                destination
            ):
                raise ValueError(
                    "independent verification output resolved outside its trusted parent"
                )
            fd = msvcrt.open_osfhandle(raw_handle, os.O_WRONLY | os.O_BINARY)
            raw_handle = None
        else:
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            fd = os.open(destination, flags, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as target:
            fd = None
            written = target.write(raw)
            target.flush()
            os.fsync(target.fileno())
            metadata = os.fstat(target.fileno())
        if (
            written != len(raw)
            or metadata.st_size != len(raw)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or _is_reparse(metadata)
        ):
            raise ValueError("independent verification output write was not stable")
        if _trusted_output_parent(evidence_root, parent) != parent:
            raise ValueError("independent verification output parent changed after write")
    finally:
        if fd is not None:
            os.close(fd)
        if raw_handle is not None:
            _windows_close_handle(raw_handle)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independently replay holdout Git objects from full bare mirrors."
    )
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--mirror-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    evidence_root = args.evidence_dir.resolve(strict=True)
    payload = build_independent_verification(
        args.preregistration,
        args.evidence_dir,
        args.mirror_root,
    )
    _write_new_artifact(
        output,
        canonical_json_bytes(payload),
        evidence_root=evidence_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
