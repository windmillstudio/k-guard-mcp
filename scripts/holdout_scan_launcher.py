from __future__ import annotations

import _imp
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import CodeType, ModuleType
from typing import Any


RECEIPT_SCHEMA = "k_guard_holdout_scan_runtime_receipt.v4"
RUNTIME_SCHEMA = "k_guard_holdout_runtime_environment.v2"
MUTATION_GUARD = "windows_read_directory_changes_overlapped_v2"
RUNTIME_NOTIFICATION_CLASSIFIER = "prewarmed_zero_notification_boundary_v2"
NATIVE_RUNTIME_LOCK_SCHEMA = "k_guard_windows_native_runtime_lock.v1"
NATIVE_RUNTIME_LOCK_GUARD = "createfile_deny_write_delete_share_v1"
NATIVE_RUNTIME_PREWARM_SCHEMA = "k_guard_windows_native_runtime_prewarm.v1"
NATIVE_RUNTIME_PREWARM_GUARD = "sec_image_readonly_mapping_policy_bound_v1"
RUNTIME_OBJECT_ATTESTATION_SCHEMA = "k_guard_windows_runtime_object_attestation.v2"
RUNTIME_OBJECT_ATTESTATION_GUARD = (
    "prewarm_boundary_file_basic_owner_group_dacl_file_id_usn_v2"
)
CHILD_PROCESS_POLICY_SCHEMA = "k_guard_windows_child_process_policy.v1"
PROCESS_MITIGATION_CHILD_PROCESS_POLICY = 13
NO_CHILD_PROCESS_CREATION = 0x00000001
ERROR_CHILD_PROCESS_BLOCKED = 367
ERROR_SHARING_VIOLATION = 32
ERROR_APPLICATION_CONTROL_BLOCKED = 4551
DELETE_ACCESS = 0x00010000
READ_CONTROL = 0x00020000
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
ACCESS_SYSTEM_SECURITY = 0x01000000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_READ_ATTRIBUTES = 0x00000080
FILE_WRITE_ATTRIBUTES = 0x00000100
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
PAGE_READONLY = 0x00000002
SEC_IMAGE = 0x01000000
FILE_MAP_READ = 0x00000004
OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION = 0x00000004
FSCTL_READ_FILE_USN_DATA = 0x000900EB
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
FILE_NOTIFY_CHANGE_CREATION = 0x00000040
FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
MUTATION_NOTIFY_FILTER = (
    FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_DIR_NAME
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SIZE
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_CREATION
    | FILE_NOTIFY_CHANGE_SECURITY
)
PROCESS_CREATION_AUDIT_EVENTS: frozenset[str] = frozenset(
    {
        "_posixsubprocess.fork_exec",
        "_winapi.CreateProcess",
        "os.exec",
        "os.fork",
        "os.forkpty",
        "os.posix_spawn",
        "os.spawn",
        "os.startfile",
        "os.startfile/2",
        "os.system",
        "pty.spawn",
        "subprocess.Popen",
    }
)
ALLOWED_DYNAMIC_EXEC_CALLERS: frozenset[str] = frozenset(
    {
        "<base_prefix>/Lib/collections/__init__.py",
        "<base_prefix>/Lib/dataclasses.py",
    }
)
ALLOWED_DATACLASS_GENERATORS: frozenset[str] = frozenset(
    {"_cmp_fn", "_frozen_get_del_attr", "_hash_fn", "_init_fn", "_repr_fn"}
)
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
CLICK_WINCONSOLE_SYMBOLS: dict[str, frozenset[str]] = {
    "kernel32.dll": frozenset(
        {
            "GetCommandLineW",
            "GetConsoleMode",
            "GetLastError",
            "GetStdHandle",
            "LocalFree",
            "ReadConsoleW",
            "WriteConsoleW",
        }
    ),
    "shell32.dll": frozenset({"CommandLineToArgvW"}),
    "python-runtime": frozenset({"PyBuffer_Release", "PyObject_GetBuffer"}),
}


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_runtime_path(path: Path, prefix: Path, base_prefix: Path) -> str | None:
    if path.is_relative_to(prefix):
        return "<prefix>/" + path.relative_to(prefix).as_posix()
    if path.is_relative_to(base_prefix):
        return "<base_prefix>/" + path.relative_to(base_prefix).as_posix()
    return None


def _attested_runtime_files(
    expected_runtime: dict[str, Any],
    prefix: Path,
    base_prefix: Path,
    *,
    native_only: bool = False,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for tree_name, root, normalized_root in (
        ("prefix_tree", prefix, "<prefix>/"),
        ("base_runtime_tree", base_prefix, "<base_prefix>/"),
    ):
        tree = expected_runtime.get(tree_name)
        files = tree.get("files") if isinstance(tree, dict) else None
        if not isinstance(files, list):
            raise ValueError(f"expected runtime {tree_name} file inventory is missing")
        for row in files:
            relative_value = str(row.get("path") or "") if isinstance(row, dict) else ""
            digest = str(row.get("sha256") or "") if isinstance(row, dict) else ""
            relative = Path(relative_value)
            normalized = normalized_root + relative.as_posix()
            if (
                not relative_value
                or relative.is_absolute()
                or ".." in relative.parts
                or normalized in seen
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                raise ValueError("expected runtime file inventory is invalid")
            seen.add(normalized)
            if native_only and relative.suffix.casefold() not in {".dll", ".pyd"}:
                continue
            path = (root / relative).resolve(strict=True)
            if not path.is_relative_to(root):
                raise ValueError("expected runtime file resolves outside its attested root")
            rows.append(
                {
                    "absolute_path": path,
                    "path": normalized,
                    "sha256": digest,
                }
            )
    return sorted(rows, key=lambda row: row["path"])


class _WindowsNativeRuntimeLock:
    def __init__(
        self,
        expected_runtime: dict[str, Any],
        prefix: Path,
        base_prefix: Path,
    ) -> None:
        if sys.platform != "win32":
            raise RuntimeError("native runtime locking is currently available only on Windows")
        from ctypes import wintypes

        self._wintypes = wintypes
        self._files = _attested_runtime_files(
            expected_runtime,
            prefix,
            base_prefix,
            native_only=True,
        )
        self._handles: list[int] = []
        self._errors: list[str] = []
        self._activated = False
        self._released = False
        self._released_file_count = 0
        self._classification_completed_while_active = False
        self._read_canary: dict[str, Any] | None = None
        self._write_canary: dict[str, Any] | None = None
        self._delete_canary: dict[str, Any] | None = None
        self._metadata_access_canaries: list[dict[str, Any]] = []
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32 = kernel32
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        self._invalid_handle = wintypes.HANDLE(-1).value

    def _open(self, path: Path, desired_access: int, share_mode: int) -> tuple[int | None, int]:
        ctypes.set_last_error(0)
        handle = self._kernel32.CreateFileW(
            str(path),
            desired_access,
            share_mode,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == self._invalid_handle:
            return None, ctypes.get_last_error()
        return int(handle), 0

    def _close(self, handle: int) -> bool:
        ctypes.set_last_error(0)
        closed = bool(self._kernel32.CloseHandle(self._wintypes.HANDLE(handle)))
        if not closed:
            self._errors.append(f"CloseHandle:{ctypes.get_last_error()}")
        return closed

    def start(self) -> bool:
        if not self._files:
            self._errors.append("attested_native_file_inventory_empty")
            return False
        for row in self._files:
            handle, error = self._open(
                row["absolute_path"],
                GENERIC_READ,
                FILE_SHARE_READ,
            )
            if handle is None:
                self._errors.append(f"lock_open:{row['path']}:{error}")
                break
            self._handles.append(handle)
            if _sha256_file(row["absolute_path"]) != row["sha256"]:
                self._errors.append(f"lock_hash_mismatch:{row['path']}")
                break
        if self._errors or len(self._handles) != len(self._files):
            self.stop()
            return False

        canary = next(
            (row for row in self._files if str(row["path"]).startswith("<prefix>/")),
            self._files[0],
        )
        read_handle, read_error = self._open(
            canary["absolute_path"],
            GENERIC_READ,
            FILE_SHARE_READ,
        )
        read_succeeded = read_handle is not None
        if read_handle is not None:
            self._close(read_handle)
        self._read_canary = {
            "path": canary["path"],
            "succeeded": read_succeeded,
            "winerror": read_error,
        }
        all_shares = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        write_handle, write_error = self._open(
            canary["absolute_path"],
            GENERIC_WRITE,
            all_shares,
        )
        if write_handle is not None:
            self._close(write_handle)
        self._write_canary = {
            "path": canary["path"],
            "blocked": write_handle is None,
            "winerror": write_error,
        }
        delete_handle, delete_error = self._open(
            canary["absolute_path"],
            DELETE_ACCESS,
            all_shares,
        )
        if delete_handle is not None:
            self._close(delete_handle)
        self._delete_canary = {
            "path": canary["path"],
            "blocked": delete_handle is None,
            "winerror": delete_error,
        }
        for access_name, desired_access in (
            ("file_write_attributes", FILE_WRITE_ATTRIBUTES),
            ("write_dac", WRITE_DAC),
            ("write_owner", WRITE_OWNER),
            ("access_system_security", ACCESS_SYSTEM_SECURITY),
        ):
            metadata_handle, metadata_error = self._open(
                canary["absolute_path"],
                desired_access,
                all_shares,
            )
            opened = metadata_handle is not None
            if metadata_handle is not None:
                self._close(metadata_handle)
            self._metadata_access_canaries.append(
                {
                    "path": canary["path"],
                    "access": access_name,
                    "opened": opened,
                    "winerror": metadata_error,
                }
            )
        if (
            self._read_canary != {
                "path": canary["path"],
                "succeeded": True,
                "winerror": 0,
            }
            or self._write_canary
            != {
                "path": canary["path"],
                "blocked": True,
                "winerror": ERROR_SHARING_VIOLATION,
            }
            or self._delete_canary
            != {
                "path": canary["path"],
                "blocked": True,
                "winerror": ERROR_SHARING_VIOLATION,
            }
        ):
            self._errors.append("native_runtime_lock_canary_failed")
            self.stop()
            return False
        self._activated = True
        return True

    @property
    def active(self) -> bool:
        return self._activated and not self._released and len(self._handles) == len(self._files)

    @property
    def locked_files(self) -> dict[str, str]:
        if not self.active:
            return {}
        return {str(row["path"]): str(row["sha256"]) for row in self._files}

    def mark_classification_completed(self) -> None:
        self._classification_completed_while_active = self.active

    def stop(self) -> None:
        if self._released:
            return
        for handle in reversed(self._handles):
            self._released_file_count += int(self._close(handle))
        self._handles.clear()
        self._released = True

    def receipt(self) -> dict[str, Any]:
        rows = [{"path": row["path"], "sha256": row["sha256"]} for row in self._files]
        passed = bool(
            self._activated
            and self._released
            and self._released_file_count == len(rows)
            and self._classification_completed_while_active
            and self._read_canary is not None
            and self._read_canary.get("succeeded") is True
            and self._read_canary.get("winerror") == 0
            and self._write_canary is not None
            and self._write_canary.get("blocked") is True
            and self._write_canary.get("winerror") == ERROR_SHARING_VIOLATION
            and self._delete_canary is not None
            and self._delete_canary.get("blocked") is True
            and self._delete_canary.get("winerror") == ERROR_SHARING_VIOLATION
            and not self._errors
        )
        return {
            "schema": NATIVE_RUNTIME_LOCK_SCHEMA,
            "guard": NATIVE_RUNTIME_LOCK_GUARD,
            "expected_file_count": len(rows),
            "locked_file_count": len(rows) if self._activated else 0,
            "released_file_count": self._released_file_count,
            "file_set_sha256": _row_set_sha256(NATIVE_RUNTIME_LOCK_SCHEMA, rows),
            "files": rows,
            "read_open_canary": self._read_canary,
            "write_open_canary": self._write_canary,
            "delete_open_canary": self._delete_canary,
            "metadata_access_canaries": self._metadata_access_canaries,
            "metadata_integrity_guard": RUNTIME_OBJECT_ATTESTATION_GUARD,
            "classification_completed_while_active": (
                self._classification_completed_while_active
            ),
            "errors": self._errors,
            "activated": self._activated,
            "released": self._released,
            "passed": passed,
            "raw_returned": False,
        }


class _WindowsNativeRuntimePrewarm:
    def __init__(
        self,
        expected_runtime: dict[str, Any],
        prefix: Path,
        base_prefix: Path,
    ) -> None:
        if sys.platform != "win32":
            raise RuntimeError("native runtime prewarming is currently available only on Windows")
        from ctypes import wintypes

        self._wintypes = wintypes
        self._files = _attested_runtime_files(
            expected_runtime,
            prefix,
            base_prefix,
            native_only=True,
        )
        self._rows: list[dict[str, Any]] = []
        self._errors: list[str] = []
        self._completed = False
        self._native_lock_active = False
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32 = kernel32
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileMappingW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPCWSTR,
        ]
        kernel32.CreateFileMappingW.restype = wintypes.HANDLE
        kernel32.MapViewOfFile.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_size_t,
        ]
        kernel32.MapViewOfFile.restype = wintypes.LPVOID
        kernel32.UnmapViewOfFile.argtypes = [wintypes.LPCVOID]
        kernel32.UnmapViewOfFile.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        self._invalid_handle = wintypes.HANDLE(-1).value

    def _close(self, handle: int, label: str) -> None:
        ctypes.set_last_error(0)
        if not self._kernel32.CloseHandle(self._wintypes.HANDLE(handle)):
            self._errors.append(f"{label}:close:{ctypes.get_last_error()}")

    def run(self, *, native_lock_active: bool) -> bool:
        if self._completed:
            raise RuntimeError("native runtime prewarm cannot be repeated")
        self._completed = True
        self._native_lock_active = native_lock_active
        if not native_lock_active:
            self._errors.append("native_runtime_lock_inactive")
            return False
        if not self._files:
            self._errors.append("attested_native_file_inventory_empty")
            return False

        for row in self._files:
            path = row["absolute_path"]
            ctypes.set_last_error(0)
            file_handle = self._kernel32.CreateFileW(
                str(path),
                GENERIC_READ,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            if file_handle == self._invalid_handle:
                error = ctypes.get_last_error()
                self._errors.append(f"open:{row['path']}:{error}")
                continue

            mapping_handle: int | None = None
            view: int | None = None
            outcome = "failed"
            winerror = 0
            try:
                ctypes.set_last_error(0)
                raw_mapping = self._kernel32.CreateFileMappingW(
                    file_handle,
                    None,
                    PAGE_READONLY | SEC_IMAGE,
                    0,
                    0,
                    None,
                )
                if not raw_mapping:
                    winerror = ctypes.get_last_error()
                    if winerror == ERROR_APPLICATION_CONTROL_BLOCKED:
                        outcome = "policy_blocked"
                    else:
                        self._errors.append(
                            f"image_mapping:{row['path']}:{winerror}"
                        )
                else:
                    mapping_handle = int(raw_mapping)
                    ctypes.set_last_error(0)
                    raw_view = self._kernel32.MapViewOfFile(
                        mapping_handle,
                        FILE_MAP_READ,
                        0,
                        0,
                        0,
                    )
                    if not raw_view:
                        winerror = ctypes.get_last_error()
                        self._errors.append(f"map_view:{row['path']}:{winerror}")
                    else:
                        view = int(raw_view)
                        outcome = "mapped"
            finally:
                if view is not None:
                    ctypes.set_last_error(0)
                    if not self._kernel32.UnmapViewOfFile(
                        self._wintypes.LPCVOID(view)
                    ):
                        self._errors.append(
                            f"unmap_view:{row['path']}:{ctypes.get_last_error()}"
                        )
                if mapping_handle is not None:
                    self._close(mapping_handle, f"mapping:{row['path']}")
                self._close(int(file_handle), f"file:{row['path']}")

            observed_sha256 = _sha256_file(path)
            if observed_sha256 != row["sha256"]:
                self._errors.append(f"content:{row['path']}:mismatch")
            self._rows.append(
                {
                    "path": row["path"],
                    "sha256": observed_sha256,
                    "outcome": outcome,
                    "winerror": winerror,
                }
            )
        return self.passed

    @property
    def passed(self) -> bool:
        return bool(
            self._completed
            and self._native_lock_active
            and len(self._rows) == len(self._files)
            and not self._errors
            and all(
                row["outcome"] == "mapped"
                and row["winerror"] == 0
                or row["outcome"] == "policy_blocked"
                and row["winerror"] == ERROR_APPLICATION_CONTROL_BLOCKED
                for row in self._rows
            )
        )

    def receipt(self) -> dict[str, Any]:
        rows = sorted(self._rows, key=lambda row: row["path"])
        return {
            "schema": NATIVE_RUNTIME_PREWARM_SCHEMA,
            "guard": NATIVE_RUNTIME_PREWARM_GUARD,
            "method": "CreateFileMappingW(PAGE_READONLY|SEC_IMAGE)+MapViewOfFile(FILE_MAP_READ)",
            "measurement_boundary": (
                "after native runtime lock activation and pre-prewarm object snapshot; "
                "before runtime mutation watchers, image-load monitoring, and scanner import"
            ),
            "expected_file_count": len(self._files),
            "file_count": len(rows),
            "mapped_file_count": sum(row["outcome"] == "mapped" for row in rows),
            "policy_blocked_file_count": sum(
                row["outcome"] == "policy_blocked" for row in rows
            ),
            "file_set_sha256": _row_set_sha256(
                NATIVE_RUNTIME_PREWARM_SCHEMA,
                rows,
            ),
            "files": rows,
            "native_lock_active": self._native_lock_active,
            "errors": self._errors,
            "completed": self._completed,
            "passed": self.passed,
            "raw_returned": False,
        }


class _WindowsRuntimeObjectAttestation:
    CHECKPOINT_PHASES = (
        "pre_prewarm",
        "post_prewarm",
        "pre_scan",
        "post_scan",
        "post_drain",
        "post_stop",
        "post_classification",
    )

    def __init__(
        self,
        expected_runtime: dict[str, Any],
        prefix: Path,
        base_prefix: Path,
    ) -> None:
        if sys.platform != "win32":
            raise RuntimeError("runtime object attestation is currently available only on Windows")
        from ctypes import wintypes

        class FileBasicInfo(ctypes.Structure):
            _fields_ = [
                ("CreationTime", ctypes.c_longlong),
                ("LastAccessTime", ctypes.c_longlong),
                ("LastWriteTime", ctypes.c_longlong),
                ("ChangeTime", ctypes.c_longlong),
                ("FileAttributes", wintypes.DWORD),
            ]

        class FileIdInfo(ctypes.Structure):
            _fields_ = [
                ("VolumeSerialNumber", ctypes.c_ulonglong),
                ("FileId", ctypes.c_ubyte * 16),
            ]

        self._wintypes = wintypes
        self._basic_info_type = FileBasicInfo
        self._file_id_info_type = FileIdInfo
        self._entries: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in _attested_runtime_files(
            expected_runtime,
            prefix,
            base_prefix,
            native_only=True,
        ):
            self._entries.append(
                {
                    "absolute_path": row["absolute_path"],
                    "path": row["path"],
                    "kind": "native_file",
                    "expected_content_sha256": row["sha256"],
                    "open_flags": FILE_ATTRIBUTE_NORMAL,
                }
            )
            seen.add(str(row["path"]))
        for row in _attested_runtime_files(expected_runtime, prefix, base_prefix):
            normalized_file = str(row["path"])
            root = prefix if normalized_file.startswith("<prefix>/") else base_prefix
            normalized_root = "<prefix>" if root == prefix else "<base_prefix>"
            current = row["absolute_path"].parent
            while current != root:
                normalized = normalized_root + "/" + current.relative_to(root).as_posix()
                if normalized not in seen:
                    self._entries.append(
                        {
                            "absolute_path": current,
                            "path": normalized,
                            "kind": "directory",
                            "expected_content_sha256": None,
                            "open_flags": FILE_FLAG_BACKUP_SEMANTICS,
                        }
                    )
                    seen.add(normalized)
                current = current.parent
        self._entries.sort(key=lambda row: row["path"])
        self._snapshots: dict[str, dict[str, dict[str, Any]]] = {}
        self._errors: list[str] = []
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._kernel32 = kernel32
        self._advapi32 = advapi32
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.GetFileInformationByHandleEx.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        ]
        kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        advapi32.GetKernelObjectSecurity.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        advapi32.GetKernelObjectSecurity.restype = wintypes.BOOL
        self._invalid_handle = wintypes.HANDLE(-1).value

    def _security_descriptor_sha256(self, handle: int) -> str:
        security_information = (
            OWNER_SECURITY_INFORMATION
            | GROUP_SECURITY_INFORMATION
            | DACL_SECURITY_INFORMATION
        )
        needed = self._wintypes.DWORD()
        ctypes.set_last_error(0)
        self._advapi32.GetKernelObjectSecurity(
            self._wintypes.HANDLE(handle),
            security_information,
            None,
            0,
            ctypes.byref(needed),
        )
        if needed.value < 20:
            raise OSError(
                ctypes.get_last_error(),
                "cannot size runtime object security descriptor",
            )
        buffer = ctypes.create_string_buffer(needed.value)
        ctypes.set_last_error(0)
        succeeded = bool(
            self._advapi32.GetKernelObjectSecurity(
                self._wintypes.HANDLE(handle),
                security_information,
                buffer,
                len(buffer),
                ctypes.byref(needed),
            )
        )
        if not succeeded:
            raise OSError(
                ctypes.get_last_error(),
                "cannot read runtime object security descriptor",
            )
        return hashlib.sha256(buffer.raw[: needed.value]).hexdigest()

    def _usn_record(self, handle: int) -> dict[str, Any]:
        buffer = ctypes.create_string_buffer(4096)
        returned = self._wintypes.DWORD()
        ctypes.set_last_error(0)
        succeeded = bool(
            self._kernel32.DeviceIoControl(
                self._wintypes.HANDLE(handle),
                FSCTL_READ_FILE_USN_DATA,
                None,
                0,
                buffer,
                len(buffer),
                ctypes.byref(returned),
                None,
            )
        )
        if not succeeded:
            raise OSError(ctypes.get_last_error(), "cannot read runtime object USN")
        raw = buffer.raw[: returned.value]
        if len(raw) < 48:
            raise ValueError("runtime object USN record is truncated")
        record_length, major_version, minor_version = struct.unpack_from("<IHH", raw, 0)
        if record_length > len(raw) or record_length < 48:
            raise ValueError("runtime object USN record length is invalid")
        if major_version == 2:
            file_reference = raw[8:16].hex()
            parent_reference = raw[16:24].hex()
            usn = struct.unpack_from("<q", raw, 24)[0]
        elif major_version == 3 and record_length >= 64:
            file_reference = raw[8:24].hex()
            parent_reference = raw[24:40].hex()
            usn = struct.unpack_from("<q", raw, 40)[0]
        else:
            raise ValueError("runtime object USN record version is unsupported")
        return {
            "major_version": int(major_version),
            "minor_version": int(minor_version),
            "file_reference": file_reference,
            "parent_reference": parent_reference,
            "usn": str(usn),
        }

    def _capture(self, phase: str) -> dict[str, dict[str, Any]]:
        captured: dict[str, dict[str, Any]] = {}
        all_shares = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        for row in self._entries:
            path = row["absolute_path"]
            ctypes.set_last_error(0)
            handle = self._kernel32.CreateFileW(
                str(path),
                FILE_READ_ATTRIBUTES | READ_CONTROL,
                all_shares,
                None,
                OPEN_EXISTING,
                row["open_flags"],
                None,
            )
            if handle == self._invalid_handle:
                self._errors.append(f"{phase}:open:{row['path']}:{ctypes.get_last_error()}")
                continue
            basic = self._basic_info_type()
            file_id = self._file_id_info_type()
            ctypes.set_last_error(0)
            basic_succeeded = bool(
                self._kernel32.GetFileInformationByHandleEx(
                    handle,
                    0,
                    ctypes.byref(basic),
                    ctypes.sizeof(basic),
                )
            )
            basic_error = ctypes.get_last_error() if not basic_succeeded else 0
            ctypes.set_last_error(0)
            file_id_succeeded = bool(
                self._kernel32.GetFileInformationByHandleEx(
                    handle,
                    18,
                    ctypes.byref(file_id),
                    ctypes.sizeof(file_id),
                )
            )
            file_id_error = ctypes.get_last_error() if not file_id_succeeded else 0
            try:
                security_sha256 = self._security_descriptor_sha256(int(handle))
                usn_record = self._usn_record(int(handle))
            except (OSError, ValueError) as exc:
                self._errors.append(f"{phase}:attest:{row['path']}:{type(exc).__name__}")
                security_sha256 = None
                usn_record = None
            closed = bool(self._kernel32.CloseHandle(handle))
            close_error = ctypes.get_last_error() if not closed else 0
            if not basic_succeeded:
                self._errors.append(f"{phase}:basic:{row['path']}:{basic_error}")
                continue
            if not file_id_succeeded:
                self._errors.append(f"{phase}:file_id:{row['path']}:{file_id_error}")
                continue
            if not closed:
                self._errors.append(f"{phase}:close:{row['path']}:{close_error}")
                continue
            if security_sha256 is None or usn_record is None:
                continue
            content_sha256 = (
                _sha256_file(path) if row["kind"] == "native_file" else None
            )
            if (
                row["kind"] == "native_file"
                and content_sha256 != row["expected_content_sha256"]
            ):
                self._errors.append(f"{phase}:content:{row['path']}:mismatch")
            basic_info = {
                "creation_time": int(basic.CreationTime),
                "last_write_time": int(basic.LastWriteTime),
                "change_time": int(basic.ChangeTime),
                "file_attributes": int(basic.FileAttributes),
            }
            basic_sha256 = hashlib.sha256(
                json.dumps(
                    basic_info,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            file_id_sha256 = hashlib.sha256(
                int(file_id.VolumeSerialNumber).to_bytes(8, "little")
                + bytes(file_id.FileId)
            ).hexdigest()
            attestation = {
                "kind": row["kind"],
                "basic_info": basic_info,
                "basic_sha256": basic_sha256,
                "security_sha256": security_sha256,
                "file_id_sha256": file_id_sha256,
                "usn_record": usn_record,
                "content_sha256": content_sha256,
            }
            captured[str(row["path"])] = {
                **attestation,
                "attestation_sha256": hashlib.sha256(
                    json.dumps(
                        attestation,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest(),
            }
        return captured

    def capture(self, phase: str) -> None:
        if phase not in self.CHECKPOINT_PHASES or phase in self._snapshots:
            raise ValueError("runtime object attestation phase is invalid")
        self._snapshots[phase] = self._capture(phase)

    def capture_through(self, phase: str) -> None:
        if phase not in self.CHECKPOINT_PHASES:
            raise ValueError("runtime object attestation phase is invalid")
        target = self.CHECKPOINT_PHASES.index(phase)
        while len(self._snapshots) <= target:
            self.capture(self.CHECKPOINT_PHASES[len(self._snapshots)])

    def stable_entries_for(
        self,
        phases: tuple[str, ...],
    ) -> dict[str, dict[str, Any]]:
        if (
            not phases
            or any(phase not in self._snapshots for phase in phases)
            or tuple(phase for phase in self._snapshots if phase in phases) != phases
            or self._errors
        ):
            return {}
        snapshots = [self._snapshots[phase] for phase in phases]
        if any(set(snapshot) != set(snapshots[0]) for snapshot in snapshots[1:]):
            return {}
        return {
            path: dict(snapshots[0][path])
            for path in snapshots[0]
            if all(snapshot[path] == snapshots[0][path] for snapshot in snapshots[1:])
        }

    @staticmethod
    def _prewarm_transition_valid(
        before: dict[str, Any],
        after: dict[str, Any],
    ) -> bool:
        if before.get("kind") != after.get("kind"):
            return False
        if before.get("kind") == "directory":
            return before == after
        if before.get("kind") != "native_file":
            return False
        if any(
            before.get(field) != after.get(field)
            for field in (
                "security_sha256",
                "file_id_sha256",
                "content_sha256",
            )
        ):
            return False
        before_basic = before.get("basic_info")
        after_basic = after.get("basic_info")
        if (
            not isinstance(before_basic, dict)
            or not isinstance(after_basic, dict)
            or set(before_basic)
            != {
                "creation_time",
                "last_write_time",
                "change_time",
                "file_attributes",
            }
            or set(after_basic) != set(before_basic)
            or any(
                before_basic[field] != after_basic[field]
                for field in (
                    "creation_time",
                    "last_write_time",
                    "file_attributes",
                )
            )
        ):
            return False
        before_usn = before.get("usn_record")
        after_usn = after.get("usn_record")
        if (
            not isinstance(before_usn, dict)
            or not isinstance(after_usn, dict)
            or set(before_usn) != set(after_usn)
            or any(
                before_usn[field] != after_usn[field]
                for field in (
                    "major_version",
                    "minor_version",
                    "file_reference",
                    "parent_reference",
                )
            )
        ):
            return False
        try:
            return int(after_usn["usn"]) >= int(before_usn["usn"])
        except (KeyError, TypeError, ValueError):
            return False

    @property
    def prewarm_transition_passed(self) -> bool:
        if (
            self._errors
            or tuple(self._snapshots)[:2] != self.CHECKPOINT_PHASES[:2]
        ):
            return False
        before = self._snapshots["pre_prewarm"]
        after = self._snapshots["post_prewarm"]
        return bool(
            self._entries
            and set(before) == set(after)
            and len(before) == len(self._entries)
            and all(
                self._prewarm_transition_valid(before[path], after[path])
                for path in before
            )
        )

    @property
    def classification_entries(self) -> dict[str, dict[str, Any]]:
        return self.stable_entries_for(self.CHECKPOINT_PHASES[1:-1])

    @property
    def classification_passed(self) -> bool:
        return bool(
            self._entries
            and self.prewarm_transition_passed
            and len(self.classification_entries) == len(self._entries)
        )

    @property
    def stable_entries(self) -> dict[str, dict[str, Any]]:
        return self.stable_entries_for(self.CHECKPOINT_PHASES[1:])

    @property
    def passed(self) -> bool:
        return bool(
            self._entries
            and tuple(self._snapshots) == self.CHECKPOINT_PHASES
            and not self._errors
            and self.prewarm_transition_passed
            and len(self.stable_entries) == len(self._entries)
        )

    def receipt(self) -> dict[str, Any]:
        expected_by_path = {str(row["path"]): row for row in self._entries}
        paths = sorted(expected_by_path)
        rows = [
            {
                "path": path,
                "kind": expected_by_path.get(path, {}).get("kind"),
                "expected_content_sha256": expected_by_path.get(path, {}).get(
                    "expected_content_sha256"
                ),
                "checkpoints": [
                    {
                        "phase": phase,
                        **self._snapshots.get(phase, {}).get(path, {}),
                    }
                    for phase in self.CHECKPOINT_PHASES
                ],
            }
            for path in paths
        ]
        prewarm_changed = [
            row["path"]
            for row in rows
            if row["checkpoints"][0].get("attestation_sha256")
            != row["checkpoints"][1].get("attestation_sha256")
        ]
        changed = [
            row["path"]
            for row in rows
            if len(
                {
                    checkpoint.get("attestation_sha256")
                    for checkpoint in row["checkpoints"][1:]
                }
            )
            != 1
        ]
        native_count = sum(row["kind"] == "native_file" for row in rows)
        directory_count = sum(row["kind"] == "directory" for row in rows)
        return {
            "schema": RUNTIME_OBJECT_ATTESTATION_SCHEMA,
            "guard": RUNTIME_OBJECT_ATTESTATION_GUARD,
            "security_descriptor_scope": "owner_group_dacl",
            "sacl_requires_elevated_security_privilege": True,
            "usn_required": True,
            "checkpoint_phases": list(self.CHECKPOINT_PHASES),
            "measurement_boundary": (
                "pre-prewarm snapshot under the active native lock; controlled SEC_IMAGE "
                "prewarm transition; post-prewarm through post-classification must remain "
                "object-identical before handle release"
            ),
            "prewarm_transition_policy": {
                "native_file_mutable_fields": [
                    "basic_info.change_time",
                    "usn_record.usn",
                ],
                "native_file_immutable_fields": [
                    "basic_info.creation_time",
                    "basic_info.last_write_time",
                    "basic_info.file_attributes",
                    "security_sha256",
                    "file_id_sha256",
                    "content_sha256",
                    "usn_record.major_version",
                    "usn_record.minor_version",
                    "usn_record.file_reference",
                    "usn_record.parent_reference",
                ],
                "directory_mutable_fields": [],
            },
            "prewarm_transition_passed": self.prewarm_transition_passed,
            "expected_entry_count": len(self._entries),
            "entry_count": len(rows),
            "native_file_count": native_count,
            "directory_count": directory_count,
            "entry_set_sha256": _row_set_sha256(
                RUNTIME_OBJECT_ATTESTATION_SCHEMA,
                rows,
            ),
            "entries": rows,
            "prewarm_changed_entry_count": len(prewarm_changed),
            "prewarm_changed_entries": prewarm_changed,
            "changed_entry_count": len(changed),
            "changed_entries": changed,
            "errors": self._errors,
            "passed": self.passed,
            "raw_returned": False,
        }


def _classify_runtime_notifications(
    monitor_rows: list[dict[str, Any]],
    root_paths: dict[str, Path],
    **_unused_attestation_context: Any,
) -> dict[str, Any]:
    classified_monitors: list[dict[str, Any]] = []
    classifier_errors: list[str] = []
    total_notifications = 0
    total_mutations = 0
    total_unclassified = 0
    for monitor in monitor_rows:
        label = str(monitor.get("root") or "")
        root = root_paths.get(label)
        raw_events = monitor.get("events")
        notification_count = monitor.get("event_count")
        events = raw_events if isinstance(raw_events, list) else []
        if (
            root is None
            or not isinstance(notification_count, int)
            or isinstance(notification_count, bool)
            or notification_count < 0
            or not isinstance(raw_events, list)
        ):
            classifier_errors.append(f"{label or 'unknown'}:notification_contract_invalid")
            notification_count = len(events)
        malformed_events = [
            index
            for index, event in enumerate(events)
            if (
                not isinstance(event, dict)
                or set(event) != {"action", "relative_path"}
                or not isinstance(event.get("action"), int)
                or isinstance(event.get("action"), bool)
                or not isinstance(event.get("relative_path"), str)
            )
        ]
        if malformed_events:
            classifier_errors.append(
                f"{label or 'unknown'}:malformed_notification_events:"
                + ",".join(str(index) for index in malformed_events)
            )
        unclassified_count = max(notification_count - len(events), 0)
        if notification_count != len(events):
            classifier_errors.append(f"{label}:notification_event_count_mismatch")
        mutation_count = len(events) + unclassified_count
        classified_monitors.append(
            {
                "root": label,
                "notification_event_count": notification_count,
                "notification_events": events,
                "accepted_native_load_metadata_event_count": 0,
                "accepted_native_load_metadata_events": [],
                "accepted_stable_directory_metadata_event_count": 0,
                "accepted_stable_directory_metadata_events": [],
                "unclassified_notification_count": unclassified_count,
                "event_count": mutation_count,
                "events": events,
                "error": monitor.get("error"),
                "liveness": monitor.get("liveness"),
            }
        )
        total_notifications += notification_count
        total_mutations += mutation_count
        total_unclassified += unclassified_count
    return {
        "runtime_notification_classifier": RUNTIME_NOTIFICATION_CLASSIFIER,
        "notification_event_count": total_notifications,
        "accepted_native_load_metadata_event_count": 0,
        "accepted_stable_directory_metadata_event_count": 0,
        "unclassified_notification_count": total_unclassified,
        "mutation_event_count": total_mutations,
        "mutation_monitors": classified_monitors,
        "runtime_notification_classifier_errors": classifier_errors,
    }


def _code_constant_contract(value: Any) -> dict[str, Any]:
    if value is None:
        return {"type": "none"}
    if value is Ellipsis:
        return {"type": "ellipsis"}
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        return {"type": "int", "value": str(value)}
    if isinstance(value, float):
        return {"type": "float", "ieee754": struct.pack(">d", value).hex()}
    if isinstance(value, complex):
        return {
            "type": "complex",
            "real_ieee754": struct.pack(">d", value.real).hex(),
            "imag_ieee754": struct.pack(">d", value.imag).hex(),
        }
    if isinstance(value, str):
        return {"type": "str", "value": value}
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, tuple):
        return {"type": "tuple", "items": [_code_constant_contract(item) for item in value]}
    if isinstance(value, frozenset):
        items = [_code_constant_contract(item) for item in value]
        items.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        return {"type": "frozenset", "items": items}
    if isinstance(value, CodeType):
        return {"type": "code", "value": _code_object_contract(value)}
    raise TypeError(f"unsupported code constant type: {type(value).__name__}")


def _code_object_contract(code: CodeType) -> dict[str, Any]:
    return {
        "argcount": code.co_argcount,
        "posonlyargcount": code.co_posonlyargcount,
        "kwonlyargcount": code.co_kwonlyargcount,
        "nlocals": code.co_nlocals,
        "stacksize": code.co_stacksize,
        "flags": code.co_flags,
        "bytecode": code.co_code.hex(),
        "constants": [_code_constant_contract(value) for value in code.co_consts],
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
        "filename": code.co_filename,
        "name": code.co_name,
        "qualname": code.co_qualname,
        "firstlineno": code.co_firstlineno,
        "linetable": code.co_linetable.hex(),
        "exceptiontable": code.co_exceptiontable.hex(),
        "freevars": list(code.co_freevars),
        "cellvars": list(code.co_cellvars),
    }


def _code_object_sha256(code: Any) -> str:
    if not isinstance(code, CodeType):
        raise TypeError("execution audit expected a Python code object")
    return hashlib.sha256(
        json.dumps(
            _code_object_contract(code),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class _WindowsRecursiveWatcher:
    def __init__(self, root: Path, label: str = "runtime") -> None:
        if sys.platform != "win32":
            raise RuntimeError("strict runtime mutation monitoring is currently available only on Windows")
        from ctypes import wintypes

        self.root = root.resolve(strict=True)
        self.label = label
        self._wintypes = wintypes
        self._changed = threading.Event()
        self._ready = threading.Event()
        self._armed = threading.Event()
        self._stop = threading.Event()
        self._error: str | None = None
        self._event_count = 0
        self._events: list[dict[str, Any]] = []
        self._started = False
        self._closed = False
        self._registration_count = 0
        self._heartbeat_count = 0
        self._drain_completed = False
        self._stop_acknowledged = False
        self._thread_terminated = False

        class Overlapped(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.c_size_t),
                ("InternalHigh", ctypes.c_size_t),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        self._overlapped_type = Overlapped
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32 = kernel32
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateEventW.argtypes = [
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        ]
        kernel32.CreateEventW.restype = wintypes.HANDLE
        kernel32.ReadDirectoryChangesW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
            wintypes.LPVOID,
            ctypes.POINTER(Overlapped),
            wintypes.LPVOID,
        ]
        kernel32.ReadDirectoryChangesW.restype = wintypes.BOOL
        kernel32.GetOverlappedResult.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(Overlapped),
            ctypes.POINTER(wintypes.DWORD),
            wintypes.BOOL,
        ]
        kernel32.GetOverlappedResult.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.ResetEvent.argtypes = [wintypes.HANDLE]
        kernel32.ResetEvent.restype = wintypes.BOOL
        kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(Overlapped)]
        kernel32.CancelIoEx.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        self._handle = kernel32.CreateFileW(
            str(self.root),
            0x0001,
            0x00000001 | 0x00000002 | 0x00000004,
            None,
            3,
            0x02000000 | 0x40000000,
            None,
        )
        if self._handle == wintypes.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), f"cannot monitor runtime tree: {self.root.name}")
        self._change_event = kernel32.CreateEventW(None, True, False, None)
        if not self._change_event:
            kernel32.CloseHandle(self._handle)
            raise OSError(ctypes.get_last_error(), "cannot create runtime mutation event")
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _set_error(self, message: str) -> None:
        if self._error is None:
            self._error = message
        self._changed.set()

    def _record_events(self, raw: bytes) -> None:
        offset = 0
        parsed_count = 0
        while offset + 12 <= len(raw):
            next_offset, action, name_length = struct.unpack_from("<III", raw, offset)
            start = offset + 12
            end = start + name_length
            if end > len(raw):
                self._set_error("runtime mutation notification was malformed")
                break
            relative = raw[start:end].decode("utf-16-le", errors="replace")
            parsed_count += 1
            if len(self._events) < 100:
                self._events.append({"action": action, "relative_path": relative})
            if next_offset == 0:
                break
            if next_offset < 12 or offset + next_offset <= offset:
                self._set_error("runtime mutation notification offset was invalid")
                break
            offset += next_offset
        self._event_count += max(parsed_count, 1)
        self._changed.set()

    def _complete_request(self, overlapped: ctypes.Structure, buffer: ctypes.Array[Any]) -> bool:
        returned = self._wintypes.DWORD()
        ok = self._kernel32.GetOverlappedResult(
            self._handle,
            ctypes.byref(overlapped),
            ctypes.byref(returned),
            False,
        )
        if not ok:
            error = ctypes.get_last_error()
            if self._stop.is_set() and error == 995:
                self._stop_acknowledged = True
                return False
            if error in {234, 1022}:
                self._set_error("runtime mutation notification buffer overflow")
            else:
                self._set_error(f"GetOverlappedResult:{error}")
            return False
        if returned.value == 0:
            self._set_error("runtime mutation notification buffer overflow")
            return False
        self._record_events(buffer.raw[: returned.value])
        return True

    def _cancel_request(self, overlapped: ctypes.Structure, buffer: ctypes.Array[Any]) -> None:
        cancelled = self._kernel32.CancelIoEx(self._handle, ctypes.byref(overlapped))
        cancel_error = ctypes.get_last_error() if not cancelled else 0
        if not cancelled and cancel_error != 1168:
            self._set_error(f"CancelIoEx:{cancel_error}")
            return
        status = self._kernel32.WaitForSingleObject(self._change_event, 2000)
        if status == 0:
            self._complete_request(overlapped, buffer)
            self._stop_acknowledged = True
        elif status == 258 and cancel_error == 1168:
            self._stop_acknowledged = True
        else:
            self._set_error(f"runtime mutation watcher cancellation wait failed:{status}")

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                buffer = ctypes.create_string_buffer(64 * 1024)
                overlapped = self._overlapped_type()
                overlapped.hEvent = self._change_event
                if not self._kernel32.ResetEvent(self._change_event):
                    self._set_error(f"ResetEvent:{ctypes.get_last_error()}")
                    self._ready.set()
                    return
                ok = self._kernel32.ReadDirectoryChangesW(
                    self._handle,
                    buffer,
                    len(buffer),
                    True,
                    MUTATION_NOTIFY_FILTER,
                    None,
                    ctypes.byref(overlapped),
                    None,
                )
                error = ctypes.get_last_error() if not ok else 0
                if not ok and error != 997:
                    self._set_error(f"ReadDirectoryChangesW:{error}")
                    self._ready.set()
                    return
                self._registration_count += 1
                self._armed.set()
                self._ready.set()
                while True:
                    status = self._kernel32.WaitForSingleObject(self._change_event, 25)
                    if status == 0:
                        self._armed.clear()
                        if not self._complete_request(overlapped, buffer):
                            return
                        break
                    if status != 258:
                        self._set_error(f"runtime mutation watcher wait failed:{status}")
                        return
                    self._heartbeat_count += 1
                    if self._stop.is_set():
                        self._cancel_request(overlapped, buffer)
                        return
        finally:
            if self._stop.is_set() and not self._stop_acknowledged:
                self._stop_acknowledged = True
            self._thread_terminated = True

    def start(self) -> None:
        self._thread.start()
        self._started = True
        if not self._ready.wait(timeout=5):
            raise RuntimeError("runtime mutation watcher did not start")
        if self._error is not None or self._registration_count < 1:
            raise RuntimeError(self._error or "runtime mutation watcher did not register")

    def wait_for_event_count(self, minimum: int, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._event_count >= minimum:
                return True
            if self._error is not None or not self._thread.is_alive():
                return False
            time.sleep(0.01)
        self._set_error("runtime mutation watcher did not observe the liveness canary")
        return False

    def wait_for_registration_count(self, minimum: int, timeout: float = 3.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._registration_count >= minimum:
                return True
            if self._error is not None or not self._thread.is_alive():
                return False
            time.sleep(0.01)
        self._set_error("runtime mutation watcher did not rearm after the liveness canary")
        return False

    def wait_for_path_actions(
        self,
        relative_path: str,
        required_actions: set[int],
        timeout: float = 3.0,
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            actions = {
                int(row["action"])
                for row in self.events
                if row.get("relative_path") == relative_path
            }
            if required_actions.issubset(actions) and self._armed.wait(timeout=0.5):
                return True
            if self._error is not None or not self._thread.is_alive():
                return False
            time.sleep(0.01)
        self._set_error("runtime mutation watcher did not observe the complete liveness canary")
        return False

    def drain(self, quiet_seconds: float = 0.1, timeout: float = 3.0) -> bool:
        if not self._started or self._error is not None or not self._thread.is_alive():
            self._set_error("runtime mutation watcher was not live at drain")
            return False
        deadline = time.monotonic() + timeout
        quiet_since = time.monotonic()
        last_event_count = self._event_count
        starting_heartbeat = self._heartbeat_count
        while time.monotonic() < deadline:
            now = time.monotonic()
            if self._error is not None or not self._thread.is_alive():
                self._set_error("runtime mutation watcher died before drain")
                return False
            if self._event_count != last_event_count:
                last_event_count = self._event_count
                quiet_since = now
            if self._heartbeat_count > starting_heartbeat and now - quiet_since >= quiet_seconds:
                self._drain_completed = True
                return True
            time.sleep(0.01)
        self._set_error("runtime mutation watcher drain timed out")
        return False

    def stop(self) -> None:
        if self._closed:
            return
        if not self._started:
            self._kernel32.CloseHandle(self._handle)
            self._kernel32.CloseHandle(self._change_event)
            self._closed = True
            return
        if not self._drain_completed and self._error is None:
            self.drain()
        self._stop.set()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            self._set_error("runtime mutation watcher did not stop")
        self._kernel32.CloseHandle(self._handle)
        self._kernel32.CloseHandle(self._change_event)
        self._closed = True

    @property
    def changed(self) -> bool:
        return self._changed.is_set()

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def error(self) -> str | None:
        return self._error

    @property
    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    @property
    def liveness(self) -> dict[str, Any]:
        passed = bool(
            self._registration_count >= 1
            and self._heartbeat_count >= 1
            and self._drain_completed
            and self._stop_acknowledged
            and self._thread_terminated
            and self._error is None
        )
        return {
            "registration_count": self._registration_count,
            "heartbeat_count": self._heartbeat_count,
            "drain_completed": self._drain_completed,
            "stop_acknowledged": self._stop_acknowledged,
            "thread_terminated": self._thread_terminated,
            "passed": passed,
        }


class _WindowsImageLoadMonitor:
    SCHEMA = "k_guard_windows_image_load_monitor.v1"

    def __init__(self, system32: Path) -> None:
        if sys.platform != "win32":
            raise RuntimeError("Windows image-load monitoring requires Windows")
        from ctypes import wintypes

        class UnicodeString(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR),
            ]

        class NotificationDataRow(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.ULONG),
                ("FullDllName", ctypes.POINTER(UnicodeString)),
                ("BaseDllName", ctypes.POINTER(UnicodeString)),
                ("DllBase", ctypes.c_void_p),
                ("SizeOfImage", wintypes.ULONG),
            ]

        class NotificationData(ctypes.Union):
            _fields_ = [
                ("Loaded", NotificationDataRow),
                ("Unloaded", NotificationDataRow),
            ]

        callback_type = ctypes.WINFUNCTYPE(
            None,
            wintypes.ULONG,
            ctypes.POINTER(NotificationData),
            ctypes.c_void_p,
        )
        ntdll = ctypes.WinDLL(str((system32 / "ntdll.dll").resolve(strict=True)))
        kernel32 = ctypes.WinDLL(str((system32 / "kernel32.dll").resolve(strict=True)))
        register = ntdll.LdrRegisterDllNotification
        unregister = ntdll.LdrUnregisterDllNotification
        load_library = kernel32.LoadLibraryExW
        free_library = kernel32.FreeLibrary
        register.argtypes = [
            wintypes.ULONG,
            callback_type,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        register.restype = wintypes.LONG
        unregister.argtypes = [ctypes.c_void_p]
        unregister.restype = wintypes.LONG
        load_library.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
        load_library.restype = wintypes.HMODULE
        free_library.argtypes = [wintypes.HMODULE]
        free_library.restype = wintypes.BOOL
        self._system32 = system32.resolve(strict=True)
        self._register = register
        self._unregister = unregister
        self._load_library = load_library
        self._free_library = free_library
        self._cookie = ctypes.c_void_p()
        self._phase = "bootstrap"
        self._events: list[tuple[str, int, str]] = []
        self._callback_errors: list[str] = []
        self._canaries: list[dict[str, Any]] = []
        self._registered = False
        self._unregistered = False

        def callback(reason: int, data: Any, _context: Any) -> None:
            try:
                row = data.contents.Loaded if reason == 1 else data.contents.Unloaded
                value = row.FullDllName.contents
                path = ctypes.wstring_at(value.Buffer, value.Length // 2)
                self._events.append((self._phase, int(reason), path))
            except Exception as exc:
                self._callback_errors.append(type(exc).__name__)

        self._callback = callback_type(callback)

    def start(self) -> None:
        status = int(self._register(0, self._callback, None, ctypes.byref(self._cookie)))
        if status != 0 or not self._cookie.value:
            raise OSError(status, "cannot register Windows DLL notification callback")
        self._registered = True

    def begin_scan(self) -> None:
        self._phase = "scan"

    def end_scan(self) -> None:
        self._phase = "post-scan"

    def exercise_canary(self, root: Path, phase: str) -> bool:
        source = (self._system32 / "version.dll").resolve(strict=True)
        marker = root / f"image-monitor-{phase}.dll"
        marker.write_bytes(source.read_bytes())
        self._phase = f"canary:{phase}"
        start_index = len(self._events)
        ctypes.set_last_error(0)
        module = self._load_library(str(marker), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
        load_error = ctypes.get_last_error() if not module else 0
        free_succeeded = bool(module and self._free_library(module))
        free_error = ctypes.get_last_error() if module and not free_succeeded else 0
        self._phase = "bootstrap" if phase == "before-scan" else "post-scan"
        observed = self._events[start_index:]
        normalized_marker = os.path.normcase(str(marker.resolve(strict=True)))
        load_seen = any(
            reason == 1 and os.path.normcase(path) == normalized_marker
            for _event_phase, reason, path in observed
        )
        unload_seen = any(
            reason == 2 and os.path.normcase(path) == normalized_marker
            for _event_phase, reason, path in observed
        )
        marker.unlink(missing_ok=True)
        row = {
            "phase": phase,
            "load_succeeded": bool(module),
            "load_error": load_error,
            "free_succeeded": free_succeeded,
            "free_error": free_error,
            "load_notification_seen": load_seen,
            "unload_notification_seen": unload_seen,
            "passed": bool(module and free_succeeded and load_seen and unload_seen),
        }
        self._canaries.append(row)
        return row["passed"]

    def stop(self) -> None:
        if not self._registered or self._unregistered:
            return
        status = int(self._unregister(self._cookie))
        self._unregistered = status == 0
        if status != 0:
            self._callback_errors.append(f"LdrUnregisterDllNotification:{status}")

    def receipt(self, prefix: Path, base_prefix: Path, windows_root: Path) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        outside: list[dict[str, Any]] = []
        errors = list(self._callback_errors)
        scan_events = [row for row in self._events if row[0] == "scan"]
        for sequence, (_phase, reason, raw_path) in enumerate(scan_events, start=1):
            action = "load" if reason == 1 else "unload" if reason == 2 else "unknown"
            if action == "unknown":
                errors.append(f"unknown_loader_reason:{reason}")
            try:
                resolved = Path(raw_path).resolve(strict=True)
                if resolved.is_relative_to(prefix):
                    normalized = "<prefix>/" + resolved.relative_to(prefix).as_posix()
                elif _is_base_site_package(resolved, base_prefix):
                    normalized = None
                elif resolved.is_relative_to(base_prefix):
                    normalized = "<base_prefix>/" + resolved.relative_to(base_prefix).as_posix()
                elif resolved.is_relative_to(windows_root):
                    normalized = "<windows_tcb>/" + resolved.relative_to(windows_root).as_posix()
                else:
                    normalized = None
                digest = _sha256_file(resolved)
            except (OSError, ValueError) as exc:
                normalized = None
                digest = None
                errors.append(f"image_path:{type(exc).__name__}")
            if normalized is None or digest is None:
                outside.append(
                    {
                        "sequence": sequence,
                        "action": action,
                        "path_sha256": hashlib.sha256(raw_path.encode("utf-8")).hexdigest()[:20],
                    }
                )
                continue
            rows.append(
                {
                    "sequence": sequence,
                    "action": action,
                    "path": normalized,
                    "sha256": digest,
                }
            )
        passed = bool(
            self._registered
            and self._unregistered
            and [row.get("phase") for row in self._canaries]
            == ["before-scan", "after-scan"]
            and all(row.get("passed") is True for row in self._canaries)
            and not outside
            and not errors
            and len(rows) == len(scan_events)
        )
        return {
            "schema": self.SCHEMA,
            "guard": "ntdll_ldr_dll_notification_v1",
            "registered": self._registered,
            "unregistered": self._unregistered,
            "canaries": self._canaries,
            "scan_event_count": len(scan_events),
            "scan_load_count": sum(row[1] == 1 for row in scan_events),
            "scan_unload_count": sum(row[1] == 2 for row in scan_events),
            "event_set_sha256": _row_set_sha256(self.SCHEMA, rows),
            "events": rows,
            "outside_image_events": outside,
            "callback_errors": errors,
            "proof_boundary": "windows_loader_managed_images",
            "passed": passed,
            "raw_returned": False,
        }


def _exercise_monitor_canary(watcher: _WindowsRecursiveWatcher, root: Path, phase: str) -> bool:
    marker = root / f"{phase}.canary"
    with marker.open("xb") as stream:
        stream.write(phase.encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    marker.unlink()
    return watcher.wait_for_path_actions(marker.name, {1, 2})


def _load_probe(path: Path, module_name: str = "holdout_runtime_probe_bound") -> ModuleType:
    specification = importlib.util.spec_from_file_location(module_name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError("bound runtime probe cannot be loaded")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _is_base_site_package(path: Path, base_prefix: Path) -> bool:
    if not path.is_relative_to(base_prefix):
        return False
    return any(
        part.casefold() in {"site-packages", "dist-packages"}
        for part in path.relative_to(base_prefix).parts
    )


def _attested_path_name(
    path: Path,
    prefix: Path,
    base_prefix: Path,
    allowed_external_files: set[Path],
) -> str | None:
    if path.is_relative_to(prefix):
        return "<prefix>/" + path.relative_to(prefix).as_posix()
    if _is_base_site_package(path, base_prefix):
        return None
    if path.is_relative_to(base_prefix):
        return "<base_prefix>/" + path.relative_to(base_prefix).as_posix()
    if path in allowed_external_files:
        return "<bound_protocol>/" + path.name
    return None


def _row_set_sha256(schema: str, rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        (schema + "\0").encode("ascii")
        + json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class _ExecutionAudit:
    SCHEMA = "k_guard_python_execution_audit.v3"

    def __init__(
        self,
        prefix: Path,
        base_prefix: Path,
        allowed_external_files: set[Path],
        windows_root: Path,
        get_module_filename: Any,
        get_current_process: Any,
    ) -> None:
        self.prefix = prefix
        self.base_prefix = base_prefix
        self.allowed_external_files = allowed_external_files
        self.windows_root = windows_root.resolve(strict=True)
        self._get_module_filename = get_module_filename
        self._get_current_process = get_current_process
        self._lock = threading.Lock()
        self._event_count = 0
        self._files: dict[str, dict[str, Any]] = {}
        self._outside: set[str] = set()
        self._dynamic: set[str] = set()
        self._dynamic_events: dict[str, dict[str, Any]] = {}
        self._process_events: list[dict[str, Any]] = []
        self._native_symbol_events: list[dict[str, Any]] = []
        self._code_object_events: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self._errors: set[str] = set()
        self._last_violation = "unknown"

    def _caller_frames(self) -> list[dict[str, str]]:
        try:
            frame = sys._getframe(2)
        except ValueError:
            return []
        rows: list[dict[str, str]] = []
        while frame is not None and len(rows) < 8:
            value = str(frame.f_code.co_filename or "")
            if value and not (value.startswith("<") and value.endswith(">")):
                try:
                    resolved = Path(value).resolve(strict=True)
                except OSError:
                    frame = frame.f_back
                    continue
                normalized = _attested_path_name(
                    resolved,
                    self.prefix,
                    self.base_prefix,
                    self.allowed_external_files,
                )
                if normalized is not None and normalized != "<bound_protocol>/holdout_scan_launcher.py":
                    rows.append({"path": normalized, "function": frame.f_code.co_name})
            frame = frame.f_back
        return rows

    def _record_dynamic(self, code: Any, *, allow_standard_generator: bool = True) -> bool:
        label = str(getattr(code, "co_filename", "<unknown>"))
        try:
            digest = _code_object_sha256(code)
        except (TypeError, ValueError) as exc:
            self._errors.add(type(exc).__name__)
            return False
        caller_frames = self._caller_frames()
        caller = caller_frames[0]["path"] if caller_frames else None
        allowed_reason: str | None = None
        frozen_match = re.fullmatch(r"<frozen ([A-Za-z0-9_.]+)>", label)
        if frozen_match is not None:
            module_name = frozen_match.group(1)
            try:
                trusted_code = _imp.get_frozen_object(module_name) if _imp.is_frozen(module_name) else None
                trusted_digest = (
                    _code_object_sha256(trusted_code)
                    if trusted_code is not None
                    else None
                )
            except (ImportError, TypeError, ValueError) as exc:
                self._errors.add(type(exc).__name__)
                trusted_digest = None
            if trusted_digest == digest:
                allowed_reason = "cpython_frozen_code_hash"
        elif allow_standard_generator and label == "<string>":
            frame_pairs = [(row["path"], row["function"]) for row in caller_frames]
            dataclasses_path = "<base_prefix>/Lib/dataclasses.py"
            collections_path = "<base_prefix>/Lib/collections/__init__.py"
            if (
                len(frame_pairs) >= 2
                and frame_pairs[0] == (dataclasses_path, "_create_fn")
                and frame_pairs[1][0] == dataclasses_path
                and frame_pairs[1][1] in ALLOWED_DATACLASS_GENERATORS
            ):
                allowed_reason = "stdlib_dataclass_generator_stack"
            elif frame_pairs and frame_pairs[0] == (collections_path, "namedtuple"):
                allowed_reason = "stdlib_namedtuple_generator_stack"
        allowed = allowed_reason is not None
        row = {
            "label": label if re.fullmatch(r"<(?:frozen [A-Za-z0-9_.]+|string)>", label) else "<redacted>",
            "label_sha256": hashlib.sha256(label.encode("utf-8")).hexdigest()[:20],
            "code_sha256": digest,
            "caller_path": caller,
            "caller_frames": caller_frames,
            "allowed": allowed,
            "allowed_reason": allowed_reason,
        }
        self._dynamic_events[digest] = row
        if row["allowed"] is not True:
            self._dynamic.add(digest)
            self._last_violation = f"dynamic:{row['label']}:{digest}:{caller or 'none'}"
        return allowed

    def _record_code_object_control(self, event: str, args: tuple[Any, ...]) -> bool:
        try:
            immediate = sys._getframe(2)
        except ValueError:
            immediate = None
        bytecode_loader_frame = immediate
        bytecode_loader_observed = False
        for _ in range(8):
            if bytecode_loader_frame is None:
                break
            if (
                bytecode_loader_frame.f_code.co_filename
                == "<frozen importlib._bootstrap_external>"
                and bytecode_loader_frame.f_code.co_name == "_compile_bytecode"
            ):
                bytecode_loader_observed = True
                break
            bytecode_loader_frame = bytecode_loader_frame.f_back
        immediate_label = str(immediate.f_code.co_filename or "") if immediate is not None else ""
        immediate_function = immediate.f_code.co_name if immediate is not None else ""
        normalized_caller: str | None = None
        if immediate_label == "<frozen importlib._bootstrap_external>":
            normalized_caller = immediate_label
        elif immediate_label and not (
            immediate_label.startswith("<") and immediate_label.endswith(">")
        ):
            try:
                normalized_caller = _attested_path_name(
                    Path(immediate_label).resolve(strict=True),
                    self.prefix,
                    self.base_prefix,
                    self.allowed_external_files,
                )
            except OSError:
                normalized_caller = None

        payload_digest = hashlib.sha256(repr(type(args[0]) if args else None).encode("ascii")).hexdigest()
        previous_digest: str | None = None
        allowed_reason: str | None = None
        if event in {"marshal.load", "marshal.loads"}:
            payload = args[0] if args else None
            if isinstance(payload, (bytes, bytearray, memoryview)):
                payload_digest = hashlib.sha256(bytes(payload)).hexdigest()
            if bytecode_loader_observed:
                allowed_reason = "frozen_importlib_bytecode_loader"
                normalized_caller = "<frozen importlib._bootstrap_external>"
                immediate_function = "_compile_bytecode"
        elif event == "code.__new__":
            payload = args[0] if args else None
            if isinstance(payload, (bytes, bytearray, memoryview)):
                payload_digest = hashlib.sha256(bytes(payload)).hexdigest()
            if (
                normalized_caller == "<base_prefix>/Lib/types.py"
                and immediate_function == "coroutine"
            ):
                allowed_reason = "stdlib_types_coroutine_code_replace"
        elif event == "function.__new__":
            code = args[0] if args else None
            try:
                payload_digest = _code_object_sha256(code)
            except (TypeError, ValueError) as exc:
                self._errors.add(type(exc).__name__)
        elif event == "object.__setattr__":
            target = args[0] if args else None
            replacement = args[2] if len(args) > 2 else None
            previous = getattr(target, "__code__", None)
            try:
                previous_contract = _code_object_contract(previous)
                replacement_contract = _code_object_contract(replacement)
                previous_digest = _code_object_sha256(previous)
                payload_digest = _code_object_sha256(replacement)
            except (AttributeError, TypeError, ValueError) as exc:
                self._errors.add(type(exc).__name__)
            else:
                previous_flags = previous_contract.pop("flags")
                replacement_flags = replacement_contract.pop("flags")
                if (
                    normalized_caller == "<base_prefix>/Lib/types.py"
                    and immediate_function == "coroutine"
                    and replacement_contract == previous_contract
                    and replacement_flags == previous_flags | 0x100
                ):
                    allowed_reason = "stdlib_types_coroutine_flag_transform"

        allowed = allowed_reason is not None
        row_key = (
            event,
            payload_digest,
            previous_digest or "",
            allowed_reason or "blocked",
        )
        row = self._code_object_events.get(row_key)
        if row is None:
            row = {
                "event": event,
                "payload_sha256": payload_digest,
                "previous_code_sha256": previous_digest,
                "caller_path": normalized_caller or "<redacted>",
                "caller_function": immediate_function if normalized_caller is not None else "<redacted>",
                "caller_frames": self._caller_frames(),
                "allowed": allowed,
                "allowed_reason": allowed_reason,
                "event_count": 0,
            }
            self._code_object_events[row_key] = row
        row["event_count"] += 1
        if not allowed:
            self._dynamic.add(payload_digest)
            self._last_violation = f"code-object:{event}:{payload_digest}"
        return allowed

    def _record_file(self, kind: str, raw_path: Any, code: Any = None) -> bool:
        if raw_path is None:
            return False
        value = str(raw_path)
        if not value:
            return False
        if value.startswith("<") and value.endswith(">"):
            return False
        try:
            resolved = Path(value).resolve(strict=True)
            normalized = _attested_path_name(
                resolved,
                self.prefix,
                self.base_prefix,
                self.allowed_external_files,
            )
            if normalized is None:
                self._outside.add(hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:20])
                return False
            digest = _sha256_file(resolved)
        except (OSError, ValueError) as exc:
            self._errors.add(type(exc).__name__)
            return False
        code_digest: str | None = None
        if code is not None:
            try:
                code_digest = _code_object_sha256(code)
                source = resolved.read_bytes()
                expected_code = compile(
                    source,
                    value,
                    "exec",
                    dont_inherit=True,
                    optimize=sys.flags.optimize,
                )
                expected_digest = _code_object_sha256(expected_code)
            except (OSError, SyntaxError, TypeError, ValueError) as exc:
                self._errors.add(type(exc).__name__)
                return False
            if code_digest != expected_digest:
                self._record_dynamic(code, allow_standard_generator=False)
                self._last_violation = f"source-code-mismatch:{normalized}:{code_digest}"
                return False
        key = f"{normalized}\0{digest}"
        row = self._files.setdefault(
            key,
            {
                "path": normalized,
                "sha256": digest,
                "event_kinds": set(),
                "event_count": 0,
                "executed_code_sha256": set(),
            },
        )
        row["event_kinds"].add(kind)
        row["event_count"] += 1
        if code_digest is not None:
            row["executed_code_sha256"].add(code_digest)
        return True

    def _record_native_load(self, raw_path: Any) -> bool:
        value = str(raw_path or "")
        if not value or not Path(value).is_absolute():
            self._outside.add(hashlib.sha256(value.encode("utf-8")).hexdigest()[:20])
            return False
        try:
            resolved = Path(value).resolve(strict=True)
            if resolved.is_relative_to(self.windows_root):
                normalized = "<windows_tcb>/" + resolved.relative_to(self.windows_root).as_posix()
                digest = _sha256_file(resolved)
                key = f"{normalized}\0{digest}"
                row = self._files.setdefault(
                    key,
                    {
                        "path": normalized,
                        "sha256": digest,
                        "event_kinds": set(),
                        "event_count": 0,
                        "executed_code_sha256": set(),
                    },
                )
                row["event_kinds"].add("native_load")
                row["event_count"] += 1
                return True
        except OSError as exc:
            self._errors.add(type(exc).__name__)
            return False
        return self._record_file("native_load", value)

    def _native_handle_path(self, library: Any) -> str | None:
        from ctypes import wintypes

        raw_handle = library if isinstance(library, int) else getattr(library, "_handle", None)
        if not isinstance(raw_handle, int) or raw_handle <= 0:
            return None
        buffer = ctypes.create_unicode_buffer(32768)
        length = self._get_module_filename(
            self._get_current_process(),
            wintypes.HMODULE(raw_handle),
            buffer,
            len(buffer),
        )
        if length == 0 or length >= len(buffer):
            return None
        try:
            resolved = Path(buffer.value).resolve(strict=True)
        except OSError:
            return None
        if resolved.is_relative_to(self.prefix):
            return "<prefix>/" + resolved.relative_to(self.prefix).as_posix()
        if resolved.is_relative_to(self.base_prefix):
            return "<base_prefix>/" + resolved.relative_to(self.base_prefix).as_posix()
        if resolved.is_relative_to(self.windows_root):
            return "<windows_tcb>/" + resolved.relative_to(self.windows_root).as_posix()
        return None

    def _record_native_symbol(self, event: str, args: tuple[Any, ...]) -> bool:
        symbol = str(args[1] if len(args) > 1 else "")
        library_path = self._native_handle_path(args[0]) if args else None
        caller_frames = self._caller_frames()
        click_caller = any(
            row == {
                "path": "<prefix>/Lib/site-packages/click/_winconsole.py",
                "function": "<module>",
            }
            for row in caller_frames
        )
        library_name = Path(library_path or "").name.casefold()
        contract_key = (
            "python-runtime"
            if library_path is not None
            and library_path.startswith("<base_prefix>/")
            and library_name.startswith("python")
            and library_name.endswith(".dll")
            else library_name
        )
        allowed = bool(
            event in {"ctypes.dlsym", "ctypes.dlsym/handle"}
            and click_caller
            and symbol in CLICK_WINCONSOLE_SYMBOLS.get(contract_key, frozenset())
        )
        self._native_symbol_events.append(
            {
                "event": event,
                "symbol": symbol if allowed else "<redacted>",
                "symbol_sha256": hashlib.sha256(symbol.encode("utf-8")).hexdigest()[:20],
                "library_path": library_path,
                "caller_frames": caller_frames,
                "allowed": allowed,
                "allowed_reason": "click_winconsole_exact_contract" if allowed else None,
            }
        )
        return allowed

    def __call__(self, event: str, args: tuple[Any, ...]) -> None:
        if event == "exec" and args:
            code = args[0]
            filename = getattr(code, "co_filename", None)
            with self._lock:
                self._event_count += 1
                label = str(filename or "")
                if not label or (label.startswith("<") and label.endswith(">")):
                    allowed = self._record_dynamic(code)
                else:
                    allowed = self._record_file("exec", filename, code)
                if not allowed:
                    raise RuntimeError(
                        "unattested dynamic or spoofed Python execution was blocked:"
                        + self._last_violation
                    )
        elif event == "import" and len(args) > 1 and args[1]:
            with self._lock:
                self._event_count += 1
                if not self._record_file("import", args[1]):
                    raise RuntimeError("out-of-bound Python import was blocked")
        elif event == "ctypes.dlopen" and args and args[0]:
            with self._lock:
                self._event_count += 1
                if not self._record_native_load(args[0]):
                    raise RuntimeError("relative or out-of-bound native load was blocked")
        elif event in PROCESS_CREATION_AUDIT_EVENTS:
            with self._lock:
                self._event_count += 1
                self._process_events.append(
                    {
                        "event": event,
                        "target_sha256": hashlib.sha256(
                            str(args[0] if args else "").encode("utf-8")
                        ).hexdigest()[:20],
                        "caller_frames": self._caller_frames(),
                    }
                )
            raise RuntimeError("child process creation is forbidden during a holdout scan")
        elif event in {"marshal.load", "marshal.loads", "code.__new__", "function.__new__"} or (
            event == "object.__setattr__" and len(args) > 1 and args[1] == "__code__"
        ):
            with self._lock:
                self._event_count += 1
                allowed = self._record_code_object_control(event, args)
            if not allowed:
                raise RuntimeError(
                    "unattested Python code-object construction or replacement was blocked:"
                    + self._last_violation
                )
        elif event in {"ctypes.dlsym", "ctypes.dlsym/handle", "ctypes.call_function"}:
            with self._lock:
                self._event_count += 1
                allowed = self._record_native_symbol(event, args)
            if not allowed:
                raise RuntimeError(
                    "native symbol resolution and raw native calls are forbidden during a holdout scan"
                )

    def receipt(self) -> dict[str, Any]:
        with self._lock:
            rows = [
                {
                    "path": row["path"],
                    "sha256": row["sha256"],
                    "event_kinds": sorted(row["event_kinds"]),
                    "event_count": row["event_count"],
                    "executed_code_sha256": sorted(row["executed_code_sha256"]),
                }
                for row in self._files.values()
            ]
            rows.sort(key=lambda row: (row["path"], row["sha256"]))
            outside = sorted(self._outside)
            dynamic = sorted(self._dynamic)
            dynamic_events = sorted(
                self._dynamic_events.values(),
                key=lambda row: (row["code_sha256"], str(row["caller_path"] or "")),
            )
            errors = sorted(self._errors)
            event_count = self._event_count
            process_events = list(self._process_events)
            native_symbol_events = list(self._native_symbol_events)
            code_object_events = sorted(
                self._code_object_events.values(),
                key=lambda row: (
                    row["event"],
                    row["payload_sha256"],
                    str(row["previous_code_sha256"] or ""),
                ),
            )
        passed = bool(
            rows
            and not outside
            and not dynamic
            and not errors
            and not process_events
            and all(row.get("allowed") is True for row in code_object_events)
            and all(row.get("allowed") is True for row in native_symbol_events)
        )
        return {
            "schema": self.SCHEMA,
            "event_count": event_count,
            "executed_file_count": len(rows),
            "executed_file_set_sha256": _row_set_sha256(self.SCHEMA, rows),
            "executed_files": rows,
            "outside_executed_code": outside,
            "dynamic_executed_code": dynamic,
            "dynamic_exec_events": dynamic_events,
            "audit_errors": errors,
            "process_creation_events": process_events,
            "code_object_control_events": code_object_events,
            "native_symbol_resolution_events": native_symbol_events,
            "passed": passed,
            "raw_returned": False,
        }


def _prepare_native_inventory() -> tuple[Path, Any, Any, Any]:
    from ctypes import wintypes

    known_kernel32 = ctypes.WinDLL(
        "kernel32.dll",
        use_last_error=True,
        winmode=LOAD_LIBRARY_SEARCH_SYSTEM32,
    )
    known_kernel32.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    known_kernel32.GetSystemDirectoryW.restype = wintypes.UINT
    system_buffer = ctypes.create_unicode_buffer(32768)
    system_length = known_kernel32.GetSystemDirectoryW(system_buffer, len(system_buffer))
    if system_length == 0 or system_length >= len(system_buffer):
        raise OSError(ctypes.get_last_error(), "cannot resolve the trusted Windows system directory")
    system32 = Path(system_buffer.value).resolve(strict=True)
    psapi = ctypes.WinDLL(str(system32 / "psapi.dll"), use_last_error=True)
    kernel32 = ctypes.WinDLL(str(system32 / "kernel32.dll"), use_last_error=True)
    shell32 = ctypes.WinDLL(str(system32 / "shell32.dll"), use_last_error=True)
    ctypes.windll.kernel32 = kernel32
    ctypes.windll.shell32 = shell32
    psapi.EnumProcessModules.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    psapi.EnumProcessModules.restype = wintypes.BOOL
    psapi.GetModuleFileNameExW.argtypes = [
        wintypes.HANDLE,
        wintypes.HMODULE,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    psapi.GetModuleFileNameExW.restype = wintypes.DWORD
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    return (
        system32,
        psapi.EnumProcessModules,
        psapi.GetModuleFileNameExW,
        kernel32.GetCurrentProcess,
    )


def _activate_child_process_policy() -> tuple[dict[str, Any], Any]:
    from ctypes import wintypes

    class ChildProcessPolicy(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD)]

    class StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class ProcessInformation(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL(
        "kernel32.dll",
        use_last_error=True,
        winmode=LOAD_LIBRARY_SEARCH_SYSTEM32,
    )
    shell32 = ctypes.WinDLL(
        "shell32.dll",
        use_last_error=True,
        winmode=LOAD_LIBRARY_SEARCH_SYSTEM32,
    )
    set_policy = kernel32.SetProcessMitigationPolicy
    get_policy = kernel32.GetProcessMitigationPolicy
    get_current_process = kernel32.GetCurrentProcess
    create_process = kernel32.CreateProcessW
    terminate_process = kernel32.TerminateProcess
    wait_for_single_object = kernel32.WaitForSingleObject
    close_handle = kernel32.CloseHandle
    shell_execute = shell32.ShellExecuteW
    set_policy.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.c_size_t]
    set_policy.restype = wintypes.BOOL
    get_policy.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    get_policy.restype = wintypes.BOOL
    get_current_process.restype = wintypes.HANDLE
    create_process.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(StartupInfo),
        ctypes.POINTER(ProcessInformation),
    ]
    create_process.restype = wintypes.BOOL
    terminate_process.argtypes = [wintypes.HANDLE, wintypes.UINT]
    terminate_process.restype = wintypes.BOOL
    wait_for_single_object.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wait_for_single_object.restype = wintypes.DWORD
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    shell_execute.argtypes = [
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_int,
    ]
    shell_execute.restype = ctypes.c_void_p
    process_handle = get_current_process()

    def query_flags() -> int:
        observed = ChildProcessPolicy()
        ctypes.set_last_error(0)
        if not get_policy(
            process_handle,
            PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
            ctypes.byref(observed),
            ctypes.sizeof(observed),
        ):
            raise OSError(ctypes.get_last_error(), "cannot query child-process mitigation policy")
        return int(observed.Flags)

    before_flags = query_flags()
    requested = ChildProcessPolicy(NO_CHILD_PROCESS_CREATION)
    ctypes.set_last_error(0)
    set_succeeded = bool(
        set_policy(
            PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
            ctypes.byref(requested),
            ctypes.sizeof(requested),
        )
    )
    set_error = ctypes.get_last_error() if not set_succeeded else 0
    after_flags = query_flags()

    ctypes.set_last_error(0)
    disable_succeeded = bool(
        set_policy(
            PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
            ctypes.byref(ChildProcessPolicy(0)),
            ctypes.sizeof(ChildProcessPolicy),
        )
    )
    disable_error = ctypes.get_last_error() if not disable_succeeded else 0
    after_disable_flags = query_flags()

    startup = StartupInfo()
    startup.cb = ctypes.sizeof(startup)
    process_info = ProcessInformation()
    command = ctypes.create_unicode_buffer(
        f'"{Path(sys.executable).resolve(strict=True)}" -I -B -S -c "pass"'
    )
    ctypes.set_last_error(0)
    unexpectedly_created = bool(
        create_process(
            None,
            command,
            None,
            None,
            False,
            0,
            None,
            None,
            ctypes.byref(startup),
            ctypes.byref(process_info),
        )
    )
    canary_error = ctypes.get_last_error() if not unexpectedly_created else 0
    if unexpectedly_created:
        terminate_process(process_info.hProcess, 86)
        wait_for_single_object(process_info.hProcess, 5000)
        close_handle(process_info.hThread)
        close_handle(process_info.hProcess)
    ctypes.set_last_error(0)
    shell_result = int(shell_execute(None, "open", "cmd.exe", "/c exit 0", None, 0) or 0)
    shell_error = ctypes.get_last_error()
    receipt = {
        "schema": CHILD_PROCESS_POLICY_SCHEMA,
        "policy_id": PROCESS_MITIGATION_CHILD_PROCESS_POLICY,
        "required_flags": NO_CHILD_PROCESS_CREATION,
        "before_flags": before_flags,
        "set_succeeded": set_succeeded,
        "set_error": set_error,
        "after_flags": after_flags,
        "disable_attempt_canary": {
            "blocked": not disable_succeeded,
            "winerror": disable_error,
            "flags_after_attempt": after_disable_flags,
        },
        "prebound_create_process_canary": {
            "api": "kernel32.CreateProcessW",
            "blocked": not unexpectedly_created and canary_error == ERROR_CHILD_PROCESS_BLOCKED,
            "winerror": canary_error,
            "unexpected_process_created": unexpectedly_created,
        },
        "prebound_shell_execute_canary": {
            "api": "shell32.ShellExecuteW",
            "blocked": shell_result <= 32 and shell_error == ERROR_CHILD_PROCESS_BLOCKED,
            "result": shell_result,
            "winerror": shell_error,
        },
        "final_query_succeeded": False,
        "final_flags": None,
        "passed": False,
        "raw_returned": False,
    }
    return receipt, query_flags


def _finalize_child_process_policy(receipt: dict[str, Any], query_flags: Any) -> None:
    try:
        final_flags = int(query_flags())
    except (OSError, TypeError, ValueError):
        receipt["final_query_succeeded"] = False
        receipt["final_flags"] = None
    else:
        receipt["final_query_succeeded"] = True
        receipt["final_flags"] = final_flags
    canary = receipt.get("prebound_create_process_canary")
    disable_canary = receipt.get("disable_attempt_canary")
    shell_canary = receipt.get("prebound_shell_execute_canary")
    receipt["passed"] = bool(
        receipt.get("set_succeeded") is True
        and receipt.get("set_error") == 0
        and int(receipt.get("after_flags") or 0) & NO_CHILD_PROCESS_CREATION
        and receipt.get("final_query_succeeded") is True
        and int(receipt.get("final_flags") or 0) & NO_CHILD_PROCESS_CREATION
        and isinstance(canary, dict)
        and canary.get("blocked") is True
        and canary.get("winerror") == ERROR_CHILD_PROCESS_BLOCKED
        and canary.get("unexpected_process_created") is False
        and isinstance(disable_canary, dict)
        and disable_canary.get("blocked") is True
        and disable_canary.get("winerror") == 5
        and int(disable_canary.get("flags_after_attempt") or 0)
        & NO_CHILD_PROCESS_CREATION
        and isinstance(shell_canary, dict)
        and shell_canary.get("blocked") is True
        and shell_canary.get("winerror") == ERROR_CHILD_PROCESS_BLOCKED
        and int(shell_canary.get("result") or 0) <= 32
    )


def _native_module_receipt(
    prefix: Path,
    base_prefix: Path,
    windows_root: Path,
    native_api: tuple[Any, Any, Any],
) -> dict[str, Any]:
    from ctypes import wintypes

    schema = "k_guard_windows_native_module_receipt.v1"
    enum_process_modules, get_module_filename, get_current_process = native_api
    process = get_current_process()
    capacity = 256
    modules: Any = None
    needed = wintypes.DWORD()
    while capacity <= 4096:
        modules = (wintypes.HMODULE * capacity)()
        if not enum_process_modules(process, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "cannot enumerate scanner native modules")
        if needed.value <= ctypes.sizeof(modules):
            break
        capacity *= 2
    if modules is None or needed.value > ctypes.sizeof(modules):
        raise RuntimeError("scanner native module inventory exceeded its bound")
    rows: list[dict[str, Any]] = []
    outside: list[str] = []
    count = needed.value // ctypes.sizeof(wintypes.HMODULE)
    for module in modules[:count]:
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_module_filename(process, module, buffer, len(buffer))
        if length == 0 or length >= len(buffer):
            raise OSError(ctypes.get_last_error(), "cannot resolve scanner native module")
        resolved = Path(buffer.value).resolve(strict=True)
        if resolved.is_relative_to(prefix):
            normalized = "<prefix>/" + resolved.relative_to(prefix).as_posix()
        elif _is_base_site_package(resolved, base_prefix):
            outside.append(hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:20])
            continue
        elif resolved.is_relative_to(base_prefix):
            normalized = "<base_prefix>/" + resolved.relative_to(base_prefix).as_posix()
        elif resolved.is_relative_to(windows_root):
            normalized = "<windows_tcb>/" + resolved.relative_to(windows_root).as_posix()
        else:
            outside.append(hashlib.sha256(str(resolved).encode("utf-8")).hexdigest()[:20])
            continue
        rows.append({"path": normalized, "sha256": _sha256_file(resolved)})
    rows = sorted({(row["path"], row["sha256"]) for row in rows})
    normalized_rows = [{"path": path, "sha256": digest} for path, digest in rows]
    return {
        "schema": schema,
        "module_count": len(normalized_rows),
        "module_set_sha256": _row_set_sha256(schema, normalized_rows),
        "modules": normalized_rows,
        "outside_native_modules": sorted(set(outside)),
        "passed": bool(normalized_rows and not outside),
        "raw_returned": False,
    }


def _loaded_module_receipt(
    prefix: Path,
    base_prefix: Path,
    allowed_external_files: set[Path],
) -> tuple[str, int, list[str]]:
    entries: dict[str, str] = {}
    outside: list[str] = []
    for name, module in sorted(sys.modules.items()):
        raw_path = getattr(module, "__file__", None)
        if not raw_path:
            continue
        path = Path(str(raw_path))
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            outside.append(f"missing:{name}")
            continue
        if resolved.is_relative_to(prefix):
            normalized = "<prefix>/" + resolved.relative_to(prefix).as_posix()
        elif _is_base_site_package(resolved, base_prefix):
            outside.append(f"base-site-packages:{name}")
            continue
        elif resolved.is_relative_to(base_prefix):
            normalized = "<base_prefix>/" + resolved.relative_to(base_prefix).as_posix()
        elif resolved in allowed_external_files:
            normalized = "<bound_protocol>/" + resolved.name
        else:
            outside.append(name)
            continue
        entries[normalized] = _sha256_file(resolved)
    digest = hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return digest, len(entries), sorted(outside)


def run(args: argparse.Namespace) -> int:
    expected_runtime_path = args.expected_runtime.resolve(strict=True)
    probe_path = args.probe_script.resolve(strict=True)
    source_probe_path = args.source_probe_script.resolve(strict=True)
    workspace = args.workspace.resolve(strict=True)
    output_path = args.output.resolve()
    receipt_path = args.receipt.resolve()
    if re.fullmatch(r"[0-9a-f]{64}", args.expected_source_tree_sha256) is None:
        raise ValueError("expected source tree hash is invalid")
    if args.expected_source_file_count < 1:
        raise ValueError("expected source file count must be positive")
    expected_raw = expected_runtime_path.read_bytes()
    if hashlib.sha256(expected_raw).hexdigest() != args.expected_runtime_sha256:
        raise RuntimeError("expected runtime artifact hash is invalid")
    expected_runtime = json.loads(expected_raw.decode("utf-8"))
    if (
        not isinstance(expected_runtime, dict)
        or expected_runtime.get("schema") != RUNTIME_SCHEMA
        or _canonical_bytes(expected_runtime) != expected_raw
    ):
        raise RuntimeError("expected runtime artifact is invalid")

    if sys.platform != "win32" or sys.flags.no_site != 1:
        raise RuntimeError("holdout scan launcher must start on Windows with Python -S")
    executable = Path(sys.executable).resolve(strict=True)
    prefix = executable.parents[1]
    base_prefix = Path(sys.base_prefix).resolve(strict=True)
    if (
        expected_runtime.get("python", {}).get("executable_sha256") != _sha256_file(executable)
        or expected_runtime.get("python", {}).get("no_site_flag") != 1
        or expected_runtime.get("python", {}).get("manual_site_bootstrap") is not True
    ):
        raise RuntimeError("expected runtime does not bind the no-site scanner executable")
    protocol_root = Path(__file__).resolve().parents[1]
    watched_roots = [prefix, base_prefix, protocol_root]
    for path in (output_path, receipt_path, workspace):
        if any(path == root or path.is_relative_to(root) for root in watched_roots):
            raise RuntimeError("scan workspace and outputs must be outside monitored runtime roots")

    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    canary_root = Path(
        tempfile.mkdtemp(prefix="k-guard-runtime-monitor-", dir=receipt_path.parent)
    ).resolve(strict=True)
    watchers = [
        _WindowsRecursiveWatcher(root, label)
        for root, label in zip(watched_roots, ("scanner_prefix", "base_runtime", "protocol_repository"))
    ]
    source_watcher = _WindowsRecursiveWatcher(workspace, "workspace_source")
    canary_watcher = _WindowsRecursiveWatcher(canary_root, "monitor_canary")
    all_watchers = [*watchers, source_watcher, canary_watcher]
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "expected_runtime_sha256": args.expected_runtime_sha256,
        "scanner_python_sha256": _sha256_file(Path(sys.executable)),
        "launcher_sha256": _sha256_file(Path(__file__).resolve()),
        "probe_sha256": _sha256_file(probe_path),
        "source_probe_sha256": _sha256_file(source_probe_path),
        "expected_source_tree_sha256": args.expected_source_tree_sha256,
        "expected_source_file_count": args.expected_source_file_count,
        "mutation_guard": MUTATION_GUARD,
        "runtime_notification_classifier": RUNTIME_NOTIFICATION_CLASSIFIER,
        "native_runtime_lock_guard": NATIVE_RUNTIME_LOCK_GUARD,
        "native_runtime_prewarm_guard": NATIVE_RUNTIME_PREWARM_GUARD,
        "runtime_object_attestation_guard": RUNTIME_OBJECT_ATTESTATION_GUARD,
        "mutation_guard_canary": {
            "before_scan": False,
            "after_scan": False,
            "cleanup_passed": False,
        },
        "source_mutation_guard_canary": False,
        "raw_returned": False,
    }
    execution_audit: _ExecutionAudit | None = None
    child_process_policy_query: Any = None
    image_load_monitor: _WindowsImageLoadMonitor | None = None
    native_runtime_lock: _WindowsNativeRuntimeLock | None = None
    native_runtime_prewarm: _WindowsNativeRuntimePrewarm | None = None
    runtime_object_attestation: _WindowsRuntimeObjectAttestation | None = None
    source_probe: ModuleType | None = None
    source_canary_event_count = 0
    source_canary_events: list[dict[str, Any]] = []
    try:
        native_runtime_lock = _WindowsNativeRuntimeLock(
            expected_runtime,
            prefix,
            base_prefix,
        )
        native_runtime_prewarm = _WindowsNativeRuntimePrewarm(
            expected_runtime,
            prefix,
            base_prefix,
        )
        runtime_object_attestation = _WindowsRuntimeObjectAttestation(
            expected_runtime,
            prefix,
            base_prefix,
        )
        if native_runtime_lock.start() is not True:
            raise RuntimeError("attested native runtime lock failed")
        runtime_object_attestation.capture("pre_prewarm")
        native_runtime_prewarm.run(native_lock_active=native_runtime_lock.active)
        runtime_object_attestation.capture("post_prewarm")
        receipt["native_runtime_prewarm"] = native_runtime_prewarm.receipt()
        if native_runtime_prewarm.passed is not True:
            raise RuntimeError("attested native runtime prewarm failed")
        if runtime_object_attestation.prewarm_transition_passed is not True:
            raise RuntimeError("native runtime prewarm changed a protected object field")
        for watcher in all_watchers:
            watcher.start()
        runtime_object_attestation.capture("pre_scan")
        receipt["mutation_guard_canary"]["before_scan"] = _exercise_monitor_canary(
            canary_watcher,
            canary_root,
            "before-scan",
        )
        if receipt["mutation_guard_canary"]["before_scan"] is not True:
            raise RuntimeError("runtime mutation monitor failed its pre-scan canary")
        receipt["source_mutation_guard_canary"] = _exercise_monitor_canary(
            source_watcher,
            workspace,
            ".k-guard-source-monitor",
        )
        if not source_watcher.drain():
            receipt["source_mutation_guard_canary"] = False
        source_canary_event_count = source_watcher.event_count
        source_canary_events = source_watcher.events
        if (
            len(source_canary_events) != source_canary_event_count
            or any(
                row.get("relative_path") != ".k-guard-source-monitor.canary"
                for row in source_canary_events
            )
        ):
            receipt["source_mutation_guard_canary"] = False
        if receipt["source_mutation_guard_canary"] is not True:
            raise RuntimeError("source mutation monitor failed its pre-scan canary")
        windows_root, *native_api = _prepare_native_inventory()
        image_load_monitor = _WindowsImageLoadMonitor(windows_root)
        image_load_monitor.start()
        if image_load_monitor.exercise_canary(canary_root, "before-scan") is not True:
            raise RuntimeError("Windows image-load monitor failed its pre-scan canary")
        child_process_policy, child_process_policy_query = _activate_child_process_policy()
        receipt["child_process_policy"] = child_process_policy
        if (
            child_process_policy.get("set_succeeded") is not True
            or not int(child_process_policy.get("after_flags") or 0)
            & NO_CHILD_PROCESS_CREATION
            or child_process_policy.get("prebound_create_process_canary", {}).get("blocked")
            is not True
            or child_process_policy.get("disable_attempt_canary", {}).get("blocked") is not True
            or child_process_policy.get("prebound_shell_execute_canary", {}).get("blocked")
            is not True
        ):
            raise RuntimeError("Windows child-process mitigation policy failed its canary")
        image_load_monitor.begin_scan()
        execution_audit = _ExecutionAudit(
            prefix,
            base_prefix,
            {Path(__file__).resolve(), probe_path, source_probe_path},
            windows_root,
            native_api[1],
            native_api[2],
        )
        sys.addaudithook(execution_audit)
        probe = _load_probe(probe_path)
        source_probe = _load_probe(
            source_probe_path,
            "holdout_source_materialization_bound",
        )
        capture_source = getattr(source_probe, "capture_materialized_tree", None)
        if not callable(capture_source):
            raise RuntimeError("bound source probe does not expose materialized-tree capture")
        pre_source = capture_source(workspace)
        receipt["pre_source_tree_sha256"] = pre_source.get("tree_sha256")
        receipt["pre_source_file_count"] = pre_source.get("file_count")
        receipt["pre_source_total_bytes"] = pre_source.get("total_bytes")
        if (
            pre_source.get("tree_sha256") != args.expected_source_tree_sha256
            or pre_source.get("file_count") != args.expected_source_file_count
        ):
            raise RuntimeError("materialized source differs before scan execution")
        configure = getattr(probe, "configure_no_site_runtime", None)
        if not callable(configure) or configure() != prefix:
            raise RuntimeError("bound runtime probe did not configure the scanner prefix")
        scanner_scaffold = expected_runtime.get("scanner_scaffold")
        if not isinstance(scanner_scaffold, dict):
            raise RuntimeError("expected runtime does not bind the scanner scaffold")
        pre = probe.capture(scanner_scaffold)
        pre_hash = hashlib.sha256(_canonical_bytes(pre)).hexdigest()
        receipt["pre_runtime_sha256"] = pre_hash
        if pre != expected_runtime:
            raise RuntimeError("scanner runtime differs before scan execution")

        from k_guard_mcp.cli import main as cli_main

        try:
            exit_code = int(cli_main(["scan", str(workspace), "--json", str(output_path)]))
        except Exception as exc:
            exit_code = 86
            receipt["scanner_failure"] = {
                "type": type(exc).__name__,
                "message_sha256": hashlib.sha256(str(exc).encode("utf-8")).hexdigest(),
            }
        post = probe.capture(scanner_scaffold)
        post_hash = hashlib.sha256(_canonical_bytes(post)).hexdigest()
        receipt["post_runtime_sha256"] = post_hash
        receipt["scanner_exit_code"] = exit_code
        if post != expected_runtime:
            raise RuntimeError("scanner runtime differs after scan execution")
        module_hash, module_count, outside_modules = _loaded_module_receipt(
            prefix,
            base_prefix,
            {Path(__file__).resolve(), probe_path, source_probe_path},
        )
        receipt.update(
            {
                "loaded_module_set_sha256": module_hash,
                "loaded_module_file_count": module_count,
                "outside_loaded_modules": outside_modules,
            }
        )
        if outside_modules:
            raise RuntimeError("scanner loaded a module outside the attested runtime")
        receipt["native_module_receipt"] = _native_module_receipt(
            prefix,
            base_prefix,
            windows_root,
            tuple(native_api),
        )
        receipt["execution_audit"] = execution_audit.receipt()
        receipt["mutation_guard_canary"]["after_scan"] = _exercise_monitor_canary(
            canary_watcher,
            canary_root,
            "after-scan",
        )
    except Exception as exc:
        receipt.setdefault("scanner_exit_code", 86)
        receipt["runtime_failure"] = {
            "type": type(exc).__name__,
            "message_sha256": hashlib.sha256(str(exc).encode("utf-8")).hexdigest(),
        }
    finally:
        if runtime_object_attestation is not None:
            runtime_object_attestation.capture_through("post_scan")
        if (
            native_runtime_prewarm is not None
            and "native_runtime_prewarm" not in receipt
        ):
            receipt["native_runtime_prewarm"] = native_runtime_prewarm.receipt()
        if source_probe is not None:
            try:
                capture_source = getattr(source_probe, "capture_materialized_tree")
                post_source = capture_source(workspace)
                receipt["post_source_tree_sha256"] = post_source.get("tree_sha256")
                receipt["post_source_file_count"] = post_source.get("file_count")
                receipt["post_source_total_bytes"] = post_source.get("total_bytes")
            except Exception as exc:
                receipt["source_post_capture_error"] = type(exc).__name__
        if image_load_monitor is not None:
            image_load_monitor.end_scan()
            try:
                image_load_monitor.exercise_canary(canary_root, "after-scan")
            except Exception as exc:
                image_load_monitor._callback_errors.append(
                    f"after_scan_canary:{type(exc).__name__}"
                )
            image_load_monitor.stop()
            receipt["image_load_monitor"] = image_load_monitor.receipt(
                prefix,
                base_prefix,
                windows_root,
            )
        if child_process_policy_query is not None and isinstance(
            receipt.get("child_process_policy"), dict
        ):
            _finalize_child_process_policy(
                receipt["child_process_policy"],
                child_process_policy_query,
            )
        for watcher in all_watchers:
            watcher.drain()
        if runtime_object_attestation is not None:
            runtime_object_attestation.capture_through("post_drain")
        for watcher in all_watchers:
            watcher.drain()
        for watcher in reversed(all_watchers):
            watcher.stop()
        if runtime_object_attestation is not None:
            runtime_object_attestation.capture_through("post_stop")
        try:
            shutil.rmtree(canary_root)
            receipt["mutation_guard_canary"]["cleanup_passed"] = not canary_root.exists()
        except OSError:
            receipt["mutation_guard_canary"]["cleanup_passed"] = False
        raw_monitor_rows = [
            {
                "root": watcher.label,
                "event_count": watcher.event_count,
                "events": watcher.events,
                "error": watcher.error,
                "liveness": watcher.liveness,
            }
            for watcher in watchers
        ]
        try:
            classification = _classify_runtime_notifications(
                raw_monitor_rows,
                {watcher.label: watcher.root for watcher in watchers},
            )
        except Exception as exc:
            classification = {
                "runtime_notification_classifier": RUNTIME_NOTIFICATION_CLASSIFIER,
                "notification_event_count": sum(
                    int(row.get("event_count") or 0) for row in raw_monitor_rows
                ),
                "accepted_native_load_metadata_event_count": 0,
                "accepted_stable_directory_metadata_event_count": 0,
                "unclassified_notification_count": 0,
                "mutation_event_count": sum(
                    int(row.get("event_count") or 0) for row in raw_monitor_rows
                ),
                "mutation_monitors": [
                    {
                        "root": row["root"],
                        "notification_event_count": row["event_count"],
                        "notification_events": row["events"],
                        "accepted_native_load_metadata_event_count": 0,
                        "accepted_native_load_metadata_events": [],
                        "accepted_stable_directory_metadata_event_count": 0,
                        "accepted_stable_directory_metadata_events": [],
                        "unclassified_notification_count": 0,
                        "event_count": row["event_count"],
                        "events": row["events"],
                        "error": row["error"],
                        "liveness": row["liveness"],
                    }
                    for row in raw_monitor_rows
                ],
                "runtime_notification_classifier_errors": [
                    f"classifier_exception:{type(exc).__name__}"
                ],
            }
        receipt.update(classification)
        if runtime_object_attestation is not None:
            runtime_object_attestation.capture_through("post_classification")
            receipt["runtime_object_attestation"] = (
                runtime_object_attestation.receipt()
            )
        if native_runtime_lock is not None:
            native_runtime_lock.mark_classification_completed()
            native_runtime_lock.stop()
            receipt["native_runtime_lock"] = native_runtime_lock.receipt()
        receipt["mutation_monitor_errors"] = [
            watcher.error for watcher in all_watchers if watcher.error is not None
        ]
        receipt["mutation_canary_monitor"] = {
            "root": canary_watcher.label,
            "event_count": canary_watcher.event_count,
            "events": canary_watcher.events,
            "error": canary_watcher.error,
            "liveness": canary_watcher.liveness,
        }
        receipt["mutation_monitor_liveness_passed"] = all(
            watcher.liveness["passed"] for watcher in all_watchers
        )
        receipt["runtime_mutation_observed"] = receipt.get("mutation_event_count", 0) > 0
        source_mutation_event_count = max(
            0,
            source_watcher.event_count - source_canary_event_count,
        )
        receipt["source_mutation_monitor"] = {
            "root": source_watcher.label,
            "guard": MUTATION_GUARD,
            "canary_boundary": (
                "temporary excluded root file created and deleted before pre-source capture"
            ),
            "measurement_boundary": (
                "after canary drain through post-source capture and watcher termination"
            ),
            "canary_event_count": source_canary_event_count,
            "scan_event_count": source_mutation_event_count,
            "events": source_watcher.events,
            "error": source_watcher.error,
            "liveness": source_watcher.liveness,
            "passed": bool(
                receipt.get("source_mutation_guard_canary") is True
                and len(source_canary_events) == source_canary_event_count
                and source_mutation_event_count == 0
                and source_watcher.error is None
                and source_watcher.liveness["passed"] is True
            ),
        }
        receipt["source_mutation_observed"] = source_mutation_event_count > 0
        if execution_audit is not None and "execution_audit" not in receipt:
            receipt["execution_audit"] = execution_audit.receipt()

    passed = bool(
        receipt.get("scanner_exit_code") == 0
        and receipt.get("pre_runtime_sha256") == args.expected_runtime_sha256
        and receipt.get("post_runtime_sha256") == args.expected_runtime_sha256
        and receipt.get("outside_loaded_modules") == []
        and receipt.get("runtime_mutation_observed") is False
        and receipt.get("mutation_event_count") == 0
        and receipt.get("unclassified_notification_count") == 0
        and receipt.get("runtime_notification_classifier")
        == RUNTIME_NOTIFICATION_CLASSIFIER
        and receipt.get("runtime_notification_classifier_errors") == []
        and receipt.get("native_runtime_lock_guard") == NATIVE_RUNTIME_LOCK_GUARD
        and receipt.get("native_runtime_lock", {}).get("passed") is True
        and receipt.get("native_runtime_prewarm_guard")
        == NATIVE_RUNTIME_PREWARM_GUARD
        and receipt.get("native_runtime_prewarm", {}).get("passed") is True
        and receipt.get("runtime_object_attestation_guard")
        == RUNTIME_OBJECT_ATTESTATION_GUARD
        and receipt.get("runtime_object_attestation", {}).get("passed") is True
        and receipt.get("pre_source_tree_sha256") == args.expected_source_tree_sha256
        and receipt.get("post_source_tree_sha256") == args.expected_source_tree_sha256
        and receipt.get("pre_source_file_count") == args.expected_source_file_count
        and receipt.get("post_source_file_count") == args.expected_source_file_count
        and receipt.get("source_mutation_observed") is False
        and receipt.get("source_mutation_monitor", {}).get("passed") is True
        and receipt.get("mutation_monitor_errors") == []
        and receipt.get("mutation_monitor_liveness_passed") is True
        and receipt.get("mutation_guard_canary")
        == {"before_scan": True, "after_scan": True, "cleanup_passed": True}
        and receipt.get("child_process_policy", {}).get("passed") is True
        and receipt.get("image_load_monitor", {}).get("passed") is True
        and receipt.get("execution_audit", {}).get("passed") is True
        and receipt.get("native_module_receipt", {}).get("passed") is True
        and output_path.is_file()
    )
    receipt["output_sha256"] = _sha256_file(output_path) if output_path.is_file() else None
    receipt["passed"] = passed
    receipt_path.write_bytes(_canonical_bytes(receipt))
    if not passed:
        output_path.unlink(missing_ok=True)
        return 86
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one holdout scan inside a continuously monitored runtime.")
    parser.add_argument("--probe-script", type=Path, required=True)
    parser.add_argument("--expected-runtime", type=Path, required=True)
    parser.add_argument("--expected-runtime-sha256", required=True)
    parser.add_argument("--source-probe-script", type=Path, required=True)
    parser.add_argument("--expected-source-tree-sha256", required=True)
    parser.add_argument("--expected-source-file-count", type=int, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except Exception as exc:
        failure = {
            "schema": RECEIPT_SCHEMA,
            "passed": False,
            "failure_type": type(exc).__name__,
            "failure_message": str(exc)[:500],
            "raw_returned": False,
        }
        args.output.unlink(missing_ok=True)
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        args.receipt.write_bytes(_canonical_bytes(failure))
        return 86


if __name__ == "__main__":
    raise SystemExit(main())
