from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path, PureWindowsPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
try:
    from scripts.evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256
except ModuleNotFoundError:
    from evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256
from k_guard_mcp import redaction as _redaction_module
from k_guard_mcp.redaction import redact_text


ANALYZER_PACKAGE_DIR = Path(_redaction_module.__file__).resolve().parent
EXPECTED_ANALYZER_PACKAGE_DIR = (SOURCE_ROOT / "k_guard_mcp").resolve()
if ANALYZER_PACKAGE_DIR != EXPECTED_ANALYZER_PACKAGE_DIR:
    raise RuntimeError(
        "public-app campaign must import k_guard_mcp from this repository's src tree"
    )


MANIFEST_SCHEMA = "k_guard_public_app_manifest.v2"
CAMPAIGN_SCHEMA = "k_guard_public_app_campaign.v2"
CANDIDATE_SCHEMA = "k_guard_public_candidate_queue.v2"
PROBE_SCHEMA = "k_guard_public_reference_probe_run.v2"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RUNTIME_RECEIPT_SCHEMA = "k_guard_holdout_scan_runtime_receipt.v4"
RUNTIME_NOTIFICATION_CLASSIFIER = "prewarmed_zero_notification_boundary_v2"
NATIVE_RUNTIME_LOCK_SCHEMA = "k_guard_windows_native_runtime_lock.v1"
NATIVE_RUNTIME_LOCK_GUARD = "createfile_deny_write_delete_share_v1"
NATIVE_RUNTIME_PREWARM_SCHEMA = "k_guard_windows_native_runtime_prewarm.v1"
NATIVE_RUNTIME_PREWARM_GUARD = "sec_image_readonly_mapping_policy_bound_v1"
RUNTIME_OBJECT_ATTESTATION_SCHEMA = "k_guard_windows_runtime_object_attestation.v2"
RUNTIME_OBJECT_ATTESTATION_GUARD = (
    "prewarm_boundary_file_basic_owner_group_dacl_file_id_usn_v2"
)
RUNTIME_OBJECT_ATTESTATION_PHASES = [
    "pre_prewarm",
    "post_prewarm",
    "pre_scan",
    "post_scan",
    "post_drain",
    "post_stop",
    "post_classification",
]
PUBLIC_APP_SCAN_TIMEOUT_SECONDS = 300.0
NONISOLATED_SCANNER_EXECUTION_MODE = "repo_src_isolated_bootstrap_v1"


class ScanTimeoutError(RuntimeError):
    pass


def _json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return payload


def _git(*args: str, cwd: Path = ROOT) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.stdout.strip()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _path_variants(path: Path) -> tuple[str, ...]:
    original = path.resolve().as_posix().rstrip("/")
    redacted = redact_text(original).replace("\\", "/").rstrip("/")
    return tuple(sorted({original, redacted}, key=len, reverse=True))


def _normalize_workspace_paths(value: Any, workspace: Path) -> Any:
    if isinstance(value, dict):
        return {key: _normalize_workspace_paths(child, workspace) for key, child in value.items()}
    if isinstance(value, list):
        return [_normalize_workspace_paths(child, workspace) for child in value]
    if not isinstance(value, str):
        return value
    normalized = value.replace("\\", "/")
    replacement_count = 0
    for root in _path_variants(workspace):
        normalized, count = re.subn(
            re.escape(root) + r"(?=/|$)",
            "<workspace>",
            normalized,
            flags=re.IGNORECASE,
        )
        replacement_count += count
    return normalized if replacement_count else value


def _contains_workspace_path(value: Any, workspace: Path) -> bool:
    if isinstance(value, dict):
        return any(_contains_workspace_path(child, workspace) for child in value.values())
    if isinstance(value, list):
        return any(_contains_workspace_path(child, workspace) for child in value)
    if not isinstance(value, str):
        return False
    normalized = value.replace("\\", "/")
    return any(
        re.search(re.escape(root) + r"(?=/|$)", normalized, flags=re.IGNORECASE) is not None
        for root in _path_variants(workspace)
    )


def _contains_local_home_path(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_local_home_path(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_local_home_path(child) for child in value)
    if not isinstance(value, str):
        return False
    normalized = value.replace("\\", "/")
    return any(
        re.search(re.escape(root) + r"(?=/|$)", normalized, flags=re.IGNORECASE) is not None
        for root in _path_variants(Path.home())
    )


def _write_report(path: Path, report: dict[str, Any]) -> str:
    encoded = (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    path.write_bytes(encoded)
    return _sha256_bytes(encoded)


def _mutation_canary_contract_valid(receipt: dict[str, Any]) -> bool:
    canary = receipt.get("mutation_canary_monitor")
    if not isinstance(canary, dict):
        return False
    canary_liveness = canary.get("liveness")
    canary_events = canary.get("events")
    return bool(
        canary.get("root") == "monitor_canary"
        and isinstance(canary.get("event_count"), int)
        and canary["event_count"] >= 4
        and isinstance(canary_events, list)
        and len(canary_events) == canary["event_count"]
        and canary.get("error") is None
        and isinstance(canary_liveness, dict)
        and canary_liveness.get("passed") is True
        and isinstance(canary_liveness.get("registration_count"), int)
        and canary_liveness["registration_count"] >= 2
        and isinstance(canary_liveness.get("heartbeat_count"), int)
        and canary_liveness["heartbeat_count"] >= 1
        and canary_liveness.get("drain_completed") is True
        and canary_liveness.get("stop_acknowledged") is True
        and canary_liveness.get("thread_terminated") is True
    )


def _legacy_runtime_monitor_contract_valid(receipt: dict[str, Any]) -> bool:
    monitors = receipt.get("mutation_monitors")
    if (
        not isinstance(monitors, list)
        or [row.get("root") for row in monitors if isinstance(row, dict)]
        != ["scanner_prefix", "base_runtime", "protocol_repository"]
        or len(monitors) != 3
    ):
        return False
    for row in monitors:
        liveness = row.get("liveness") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or row.get("event_count") != 0
            or row.get("events") != []
            or row.get("error") is not None
            or not isinstance(liveness, dict)
            or liveness.get("passed") is not True
            or not isinstance(liveness.get("registration_count"), int)
            or liveness["registration_count"] < 1
            or not isinstance(liveness.get("heartbeat_count"), int)
            or liveness["heartbeat_count"] < 1
            or liveness.get("drain_completed") is not True
            or liveness.get("stop_acknowledged") is not True
            or liveness.get("thread_terminated") is not True
        ):
            return False
    return _mutation_canary_contract_valid(receipt)


def _native_runtime_lock_contract_valid(receipt: dict[str, Any]) -> bool:
    lock = receipt.get("native_runtime_lock")
    if not isinstance(lock, dict) or set(lock) != {
        "schema",
        "guard",
        "expected_file_count",
        "locked_file_count",
        "released_file_count",
        "file_set_sha256",
        "files",
        "read_open_canary",
        "write_open_canary",
        "delete_open_canary",
        "metadata_access_canaries",
        "metadata_integrity_guard",
        "classification_completed_while_active",
        "errors",
        "activated",
        "released",
        "passed",
        "raw_returned",
    }:
        return False
    files = lock.get("files")
    read_canary = lock.get("read_open_canary")
    write_canary = lock.get("write_open_canary")
    delete_canary = lock.get("delete_open_canary")
    metadata_canaries = lock.get("metadata_access_canaries")
    if (
        not isinstance(files, list)
        or not files
        or not isinstance(read_canary, dict)
        or not isinstance(write_canary, dict)
        or not isinstance(delete_canary, dict)
        or not isinstance(metadata_canaries, list)
    ):
        return False
    paths: set[str] = set()
    for row in files:
        path = str(row.get("path") or "") if isinstance(row, dict) else ""
        digest = str(row.get("sha256") or "") if isinstance(row, dict) else ""
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "sha256"}
            or not path.startswith(("<prefix>/", "<base_prefix>/"))
            or Path(path).suffix.casefold() not in {".dll", ".pyd"}
            or path in paths
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            return False
        paths.add(path)
    if files != sorted(files, key=lambda row: row["path"]):
        return False
    canary_path = str(read_canary.get("path") or "")
    expected_metadata_accesses = [
        "file_write_attributes",
        "write_dac",
        "write_owner",
        "access_system_security",
    ]
    if (
        [row.get("access") for row in metadata_canaries if isinstance(row, dict)]
        != expected_metadata_accesses
        or len(metadata_canaries) != len(expected_metadata_accesses)
        or any(
            not isinstance(row, dict)
            or set(row) != {"path", "access", "opened", "winerror"}
            or row.get("path") != canary_path
            or not isinstance(row.get("opened"), bool)
            or not isinstance(row.get("winerror"), int)
            or isinstance(row.get("winerror"), bool)
            or (row["opened"] and row["winerror"] != 0)
            or (not row["opened"] and row["winerror"] <= 0)
            for row in metadata_canaries
        )
    ):
        return False
    return bool(
        lock.get("schema") == NATIVE_RUNTIME_LOCK_SCHEMA
        and lock.get("guard") == NATIVE_RUNTIME_LOCK_GUARD
        and lock.get("expected_file_count") == len(files)
        and lock.get("locked_file_count") == len(files)
        and lock.get("released_file_count") == len(files)
        and lock.get("file_set_sha256")
        == _sha256_bytes(
            NATIVE_RUNTIME_LOCK_SCHEMA.encode("ascii")
            + b"\0"
            + json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        and canary_path in paths
        and read_canary
        == {"path": canary_path, "succeeded": True, "winerror": 0}
        and write_canary
        == {"path": canary_path, "blocked": True, "winerror": 32}
        and delete_canary
        == {"path": canary_path, "blocked": True, "winerror": 32}
        and lock.get("metadata_integrity_guard")
        == RUNTIME_OBJECT_ATTESTATION_GUARD
        and lock.get("classification_completed_while_active") is True
        and lock.get("errors") == []
        and lock.get("activated") is True
        and lock.get("released") is True
        and lock.get("passed") is True
        and lock.get("raw_returned") is False
    )


def _native_runtime_prewarm_contract_valid(receipt: dict[str, Any]) -> bool:
    prewarm = receipt.get("native_runtime_prewarm")
    if not isinstance(prewarm, dict) or set(prewarm) != {
        "schema",
        "guard",
        "method",
        "measurement_boundary",
        "expected_file_count",
        "file_count",
        "mapped_file_count",
        "policy_blocked_file_count",
        "file_set_sha256",
        "files",
        "native_lock_active",
        "errors",
        "completed",
        "passed",
        "raw_returned",
    }:
        return False
    files = prewarm.get("files")
    if not isinstance(files, list) or not files:
        return False
    paths: set[str] = set()
    mapped = 0
    policy_blocked = 0
    for row in files:
        path = str(row.get("path") or "") if isinstance(row, dict) else ""
        digest = str(row.get("sha256") or "") if isinstance(row, dict) else ""
        outcome = row.get("outcome") if isinstance(row, dict) else None
        winerror = row.get("winerror") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or set(row) != {"path", "sha256", "outcome", "winerror"}
            or not path.startswith(("<prefix>/", "<base_prefix>/"))
            or Path(path).suffix.casefold() not in {".dll", ".pyd"}
            or path in paths
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(winerror, int)
            or isinstance(winerror, bool)
            or (
                outcome == "mapped"
                and winerror != 0
            )
            or (
                outcome == "policy_blocked"
                and winerror != 4551
            )
            or outcome not in {"mapped", "policy_blocked"}
        ):
            return False
        paths.add(path)
        mapped += int(outcome == "mapped")
        policy_blocked += int(outcome == "policy_blocked")
    return bool(
        files == sorted(files, key=lambda row: row["path"])
        and prewarm.get("schema") == NATIVE_RUNTIME_PREWARM_SCHEMA
        and prewarm.get("guard") == NATIVE_RUNTIME_PREWARM_GUARD
        and prewarm.get("method")
        == "CreateFileMappingW(PAGE_READONLY|SEC_IMAGE)+MapViewOfFile(FILE_MAP_READ)"
        and prewarm.get("measurement_boundary")
        == (
            "after native runtime lock activation and pre-prewarm object snapshot; "
            "before runtime mutation watchers, image-load monitoring, and scanner import"
        )
        and prewarm.get("expected_file_count") == len(files)
        and prewarm.get("file_count") == len(files)
        and prewarm.get("mapped_file_count") == mapped
        and prewarm.get("policy_blocked_file_count") == policy_blocked
        and prewarm.get("file_set_sha256")
        == _sha256_bytes(
            NATIVE_RUNTIME_PREWARM_SCHEMA.encode("ascii")
            + b"\0"
            + json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        and prewarm.get("native_lock_active") is True
        and prewarm.get("errors") == []
        and prewarm.get("completed") is True
        and prewarm.get("passed") is True
        and prewarm.get("raw_returned") is False
    )


def _runtime_object_attestation_contract_valid(receipt: dict[str, Any]) -> bool:
    attestation = receipt.get("runtime_object_attestation")
    if not isinstance(attestation, dict) or set(attestation) != {
        "schema",
        "guard",
        "security_descriptor_scope",
        "sacl_requires_elevated_security_privilege",
        "usn_required",
        "checkpoint_phases",
        "measurement_boundary",
        "prewarm_transition_policy",
        "prewarm_transition_passed",
        "expected_entry_count",
        "entry_count",
        "native_file_count",
        "directory_count",
        "entry_set_sha256",
        "entries",
        "prewarm_changed_entry_count",
        "prewarm_changed_entries",
        "changed_entry_count",
        "changed_entries",
        "errors",
        "passed",
        "raw_returned",
    }:
        return False
    entries = attestation.get("entries")
    if not isinstance(entries, list) or not entries:
        return False
    paths: set[str] = set()
    native_file_count = 0
    directory_count = 0
    prewarm_changed_entries: list[str] = []
    for row in entries:
        path = str(row.get("path") or "") if isinstance(row, dict) else ""
        kind = row.get("kind") if isinstance(row, dict) else None
        expected_content = (
            row.get("expected_content_sha256") if isinstance(row, dict) else None
        )
        checkpoints = row.get("checkpoints") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "path",
                "kind",
                "expected_content_sha256",
                "checkpoints",
            }
            or not path.startswith(("<prefix>/", "<base_prefix>/"))
            or kind not in {"native_file", "directory"}
            or path in paths
            or not isinstance(checkpoints, list)
            or len(checkpoints) != len(RUNTIME_OBJECT_ATTESTATION_PHASES)
        ):
            return False
        if kind == "native_file":
            if (
                Path(path).suffix.casefold() not in {".dll", ".pyd"}
                or re.fullmatch(r"[0-9a-f]{64}", str(expected_content or ""))
                is None
            ):
                return False
            native_file_count += 1
        else:
            if expected_content is not None:
                return False
            directory_count += 1
        checkpoint_hashes: list[str] = []
        checkpoint_payloads: list[dict[str, Any]] = []
        for phase, checkpoint in zip(
            RUNTIME_OBJECT_ATTESTATION_PHASES,
            checkpoints,
        ):
            if not isinstance(checkpoint, dict) or set(checkpoint) != {
                "phase",
                "kind",
                "basic_info",
                "basic_sha256",
                "security_sha256",
                "file_id_sha256",
                "usn_record",
                "content_sha256",
                "attestation_sha256",
            }:
                return False
            basic_info = checkpoint.get("basic_info")
            usn = checkpoint.get("usn_record")
            if (
                checkpoint.get("phase") != phase
                or checkpoint.get("kind") != kind
                or not isinstance(basic_info, dict)
                or set(basic_info)
                != {
                    "creation_time",
                    "last_write_time",
                    "change_time",
                    "file_attributes",
                }
                or any(
                    not isinstance(value, int) or isinstance(value, bool)
                    for value in basic_info.values()
                )
                or re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(checkpoint.get("basic_sha256") or ""),
                )
                is None
                or re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(checkpoint.get("security_sha256") or ""),
                )
                is None
                or re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(checkpoint.get("file_id_sha256") or ""),
                )
                is None
                or not isinstance(usn, dict)
                or set(usn)
                != {
                    "major_version",
                    "minor_version",
                    "file_reference",
                    "parent_reference",
                    "usn",
                }
                or usn.get("major_version") not in {2, 3}
                or not isinstance(usn.get("minor_version"), int)
                or isinstance(usn.get("minor_version"), bool)
                or re.fullmatch(
                    r"[0-9a-f]+",
                    str(usn.get("file_reference") or ""),
                )
                is None
                or re.fullmatch(
                    r"[0-9a-f]+",
                    str(usn.get("parent_reference") or ""),
                )
                is None
                or re.fullmatch(r"\d+", str(usn.get("usn") or "")) is None
            ):
                return False
            if checkpoint["basic_sha256"] != _sha256_bytes(
                json.dumps(
                    basic_info,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ):
                return False
            content_sha256 = checkpoint.get("content_sha256")
            if (
                kind == "native_file"
                and content_sha256 != expected_content
            ) or (kind == "directory" and content_sha256 is not None):
                return False
            payload = {
                "kind": kind,
                "basic_info": basic_info,
                "basic_sha256": checkpoint["basic_sha256"],
                "security_sha256": checkpoint["security_sha256"],
                "file_id_sha256": checkpoint["file_id_sha256"],
                "usn_record": usn,
                "content_sha256": content_sha256,
            }
            expected_attestation_hash = _sha256_bytes(
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            if checkpoint.get("attestation_sha256") != expected_attestation_hash:
                return False
            checkpoint_hashes.append(expected_attestation_hash)
            checkpoint_payloads.append(payload)
        before, after = checkpoint_payloads[:2]
        if kind == "directory":
            prewarm_transition_valid = before == after
        else:
            before_basic = before["basic_info"]
            after_basic = after["basic_info"]
            before_usn = before["usn_record"]
            after_usn = after["usn_record"]
            prewarm_transition_valid = bool(
                all(
                    before[field] == after[field]
                    for field in (
                        "security_sha256",
                        "file_id_sha256",
                        "content_sha256",
                    )
                )
                and all(
                    before_basic[field] == after_basic[field]
                    for field in (
                        "creation_time",
                        "last_write_time",
                        "file_attributes",
                    )
                )
                and all(
                    before_usn[field] == after_usn[field]
                    for field in (
                        "major_version",
                        "minor_version",
                        "file_reference",
                        "parent_reference",
                    )
                )
                and int(after_usn["usn"]) >= int(before_usn["usn"])
            )
        if not prewarm_transition_valid or len(set(checkpoint_hashes[1:])) != 1:
            return False
        if checkpoint_hashes[0] != checkpoint_hashes[1]:
            prewarm_changed_entries.append(path)
        paths.add(path)
    prewarm_transition_policy = {
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
    }
    return bool(
        entries == sorted(entries, key=lambda row: row["path"])
        and attestation.get("schema") == RUNTIME_OBJECT_ATTESTATION_SCHEMA
        and attestation.get("guard") == RUNTIME_OBJECT_ATTESTATION_GUARD
        and attestation.get("security_descriptor_scope") == "owner_group_dacl"
        and attestation.get("sacl_requires_elevated_security_privilege") is True
        and attestation.get("usn_required") is True
        and attestation.get("checkpoint_phases")
        == RUNTIME_OBJECT_ATTESTATION_PHASES
        and attestation.get("measurement_boundary")
        == (
            "pre-prewarm snapshot under the active native lock; controlled SEC_IMAGE "
            "prewarm transition; post-prewarm through post-classification must remain "
            "object-identical before handle release"
        )
        and attestation.get("prewarm_transition_policy")
        == prewarm_transition_policy
        and attestation.get("prewarm_transition_passed") is True
        and attestation.get("expected_entry_count") == len(entries)
        and attestation.get("entry_count") == len(entries)
        and attestation.get("native_file_count") == native_file_count
        and attestation.get("directory_count") == directory_count
        and attestation.get("entry_set_sha256")
        == _sha256_bytes(
            RUNTIME_OBJECT_ATTESTATION_SCHEMA.encode("ascii")
            + b"\0"
            + json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        and attestation.get("prewarm_changed_entry_count")
        == len(prewarm_changed_entries)
        and attestation.get("prewarm_changed_entries")
        == prewarm_changed_entries
        and attestation.get("changed_entry_count") == 0
        and attestation.get("changed_entries") == []
        and attestation.get("errors") == []
        and attestation.get("passed") is True
        and attestation.get("raw_returned") is False
    )


def _normalized_windows_relative_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    path = PureWindowsPath(value)
    if (
        path.is_absolute()
        or path.drive
        or path.root
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    return "/".join(path.parts)


def _accepted_event_path_binds(
    root: str,
    relative_path: Any,
    attested_path: str,
) -> bool:
    relative = _normalized_windows_relative_path(relative_path)
    if relative is None:
        return False
    if root == "scanner_prefix":
        return (
            attested_path.startswith("<prefix>/")
            and relative == attested_path.removeprefix("<prefix>/")
        )
    if root == "base_runtime":
        return (
            attested_path.startswith("<base_prefix>/")
            and relative == attested_path.removeprefix("<base_prefix>/")
        )
    if root != "protocol_repository":
        return False
    if attested_path.startswith("<prefix>/"):
        attested_relative = attested_path.removeprefix("<prefix>/")
    elif attested_path.startswith("<base_prefix>/"):
        attested_relative = attested_path.removeprefix("<base_prefix>/")
    else:
        return False
    return relative == attested_relative or relative.endswith(
        "/" + attested_relative
    )


def _runtime_monitor_contract_valid(receipt: dict[str, Any]) -> bool:
    if receipt.get("schema") == "k_guard_holdout_scan_runtime_receipt.v3":
        return _legacy_runtime_monitor_contract_valid(receipt)
    if (
        receipt.get("schema") != RUNTIME_RECEIPT_SCHEMA
        or receipt.get("runtime_notification_classifier")
        != RUNTIME_NOTIFICATION_CLASSIFIER
        or receipt.get("native_runtime_lock_guard") != NATIVE_RUNTIME_LOCK_GUARD
        or receipt.get("native_runtime_prewarm_guard")
        != NATIVE_RUNTIME_PREWARM_GUARD
        or receipt.get("runtime_object_attestation_guard")
        != RUNTIME_OBJECT_ATTESTATION_GUARD
        or receipt.get("runtime_notification_classifier_errors") != []
        or not _native_runtime_lock_contract_valid(receipt)
        or not _native_runtime_prewarm_contract_valid(receipt)
        or not _runtime_object_attestation_contract_valid(receipt)
    ):
        return False
    monitors = receipt.get("mutation_monitors")
    if (
        not isinstance(monitors, list)
        or len(monitors) != 3
        or [row.get("root") for row in monitors if isinstance(row, dict)]
        != ["scanner_prefix", "base_runtime", "protocol_repository"]
    ):
        return False
    image_loads = {
        (str(row.get("path") or ""), str(row.get("sha256") or ""))
        for row in receipt.get("image_load_monitor", {}).get("events", [])
        if isinstance(row, dict) and row.get("action") == "load"
    }
    locked_files = {
        str(row["path"]): str(row["sha256"])
        for row in receipt["native_runtime_lock"]["files"]
    }
    stable_objects = {
        str(row["path"]): {
            "kind": row["kind"],
            "content_sha256": row["expected_content_sha256"],
            "attestation_sha256": row["checkpoints"][0]["attestation_sha256"],
        }
        for row in receipt["runtime_object_attestation"]["entries"]
    }
    notification_total = 0
    accepted_native_total = 0
    accepted_directory_total = 0
    mutation_total = 0
    unclassified_total = 0
    for row in monitors:
        if not isinstance(row, dict) or set(row) != {
            "root",
            "notification_event_count",
            "notification_events",
            "accepted_native_load_metadata_event_count",
            "accepted_native_load_metadata_events",
            "accepted_stable_directory_metadata_event_count",
            "accepted_stable_directory_metadata_events",
            "unclassified_notification_count",
            "event_count",
            "events",
            "error",
            "liveness",
        }:
            return False
        notifications = row.get("notification_events")
        accepted = row.get("accepted_native_load_metadata_events")
        accepted_directories = row.get(
            "accepted_stable_directory_metadata_events"
        )
        mutations = row.get("events")
        liveness = row.get("liveness")
        if (
            not isinstance(notifications, list)
            or not isinstance(accepted, list)
            or not isinstance(accepted_directories, list)
            or not isinstance(mutations, list)
            or row.get("notification_event_count") != len(notifications)
            or row.get("accepted_native_load_metadata_event_count") != len(accepted)
            or row.get("accepted_stable_directory_metadata_event_count")
            != len(accepted_directories)
            or accepted != []
            or accepted_directories != []
            or row.get("unclassified_notification_count") != 0
            or row.get("event_count") != len(mutations)
            or notifications != mutations
            or row.get("error") is not None
            or not isinstance(liveness, dict)
            or liveness.get("passed") is not True
            or not isinstance(liveness.get("registration_count"), int)
            or liveness["registration_count"] < 1
            or not isinstance(liveness.get("heartbeat_count"), int)
            or liveness["heartbeat_count"] < 1
            or liveness.get("drain_completed") is not True
            or liveness.get("stop_acknowledged") is not True
            or liveness.get("thread_terminated") is not True
        ):
            return False
        for event in notifications + mutations:
            if (
                not isinstance(event, dict)
                or set(event) != {"action", "relative_path"}
                or not isinstance(event.get("action"), int)
                or isinstance(event.get("action"), bool)
                or not isinstance(event.get("relative_path"), str)
            ):
                return False
        for event in accepted:
            path = str(event.get("attested_path") or "") if isinstance(event, dict) else ""
            digest = str(event.get("sha256") or "") if isinstance(event, dict) else ""
            attestation_hash = (
                str(event.get("attestation_sha256") or "")
                if isinstance(event, dict)
                else ""
            )
            stable = stable_objects.get(path)
            if (
                not isinstance(event, dict)
                or set(event)
                != {
                    "action",
                    "relative_path",
                    "attested_path",
                    "sha256",
                    "attestation_sha256",
                    "reason",
                }
                or event.get("action") != 3
                or not isinstance(event.get("relative_path"), str)
                or not path.startswith(("<prefix>/", "<base_prefix>/"))
                or Path(path).suffix.casefold() not in {".dll", ".pyd"}
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or re.fullmatch(r"[0-9a-f]{64}", attestation_hash) is None
                or event.get("reason")
                != "attested_write_locked_unchanged_native_notification"
                or locked_files.get(path) != digest
                or (path, digest) not in image_loads
                or not isinstance(stable, dict)
                or stable.get("kind") != "native_file"
                or stable.get("content_sha256") != digest
                or stable.get("attestation_sha256") != attestation_hash
                or not _accepted_event_path_binds(
                    str(row.get("root") or ""),
                    event.get("relative_path"),
                    path,
                )
            ):
                return False
        for event in accepted_directories:
            path = str(event.get("attested_path") or "") if isinstance(event, dict) else ""
            attestation_hash = (
                str(event.get("attestation_sha256") or "")
                if isinstance(event, dict)
                else ""
            )
            stable = stable_objects.get(path)
            if (
                not isinstance(event, dict)
                or set(event)
                != {
                    "action",
                    "relative_path",
                    "attested_path",
                    "attestation_sha256",
                    "reason",
                }
                or event.get("action") != 3
                or not isinstance(event.get("relative_path"), str)
                or not path.startswith(("<prefix>/", "<base_prefix>/"))
                or re.fullmatch(r"[0-9a-f]{64}", attestation_hash) is None
                or not isinstance(stable, dict)
                or stable.get("kind") != "directory"
                or stable.get("attestation_sha256") != attestation_hash
                or event.get("reason")
                != "attested_unchanged_directory_notification"
                or not _accepted_event_path_binds(
                    str(row.get("root") or ""),
                    event.get("relative_path"),
                    path,
                )
            ):
                return False
        projected = Counter(
            (event["action"], event["relative_path"]) for event in accepted
        ) + Counter(
            (event["action"], event["relative_path"])
            for event in accepted_directories
        ) + Counter((event["action"], event["relative_path"]) for event in mutations)
        observed = Counter(
            (event["action"], event["relative_path"]) for event in notifications
        )
        if projected != observed:
            return False
        notification_total += len(notifications)
        accepted_native_total += len(accepted)
        accepted_directory_total += len(accepted_directories)
        mutation_total += len(mutations)
    direct_native = {
        (
            event["action"],
            event["attested_path"],
            event["sha256"],
            event["attestation_sha256"],
        )
        for row in monitors
        if row["root"] in {"scanner_prefix", "base_runtime"}
        for event in row["accepted_native_load_metadata_events"]
    }
    direct_directories = {
        (
            event["action"],
            event["attested_path"],
            event["attestation_sha256"],
        )
        for row in monitors
        if row["root"] in {"scanner_prefix", "base_runtime"}
        for event in row["accepted_stable_directory_metadata_events"]
    }
    protocol_monitor = next(
        row for row in monitors if row["root"] == "protocol_repository"
    )
    if any(
        (
            event["action"],
            event["attested_path"],
            event["sha256"],
            event["attestation_sha256"],
        )
        not in direct_native
        for event in protocol_monitor["accepted_native_load_metadata_events"]
    ) or any(
        (
            event["action"],
            event["attested_path"],
            event["attestation_sha256"],
        )
        not in direct_directories
        for event in protocol_monitor[
            "accepted_stable_directory_metadata_events"
        ]
    ):
        return False
    return bool(
        receipt.get("notification_event_count") == notification_total
        and receipt.get("accepted_native_load_metadata_event_count")
        == accepted_native_total
        and receipt.get("accepted_stable_directory_metadata_event_count")
        == accepted_directory_total
        and receipt.get("unclassified_notification_count") == unclassified_total
        and receipt.get("mutation_event_count") == mutation_total
        and notification_total
        == accepted_native_total + accepted_directory_total + mutation_total
        and accepted_native_total == 0
        and accepted_directory_total == 0
        and notification_total == mutation_total
        and receipt.get("runtime_mutation_observed") is (mutation_total > 0)
        and _mutation_canary_contract_valid(receipt)
    )


def _source_monitor_contract_valid(
    receipt: dict[str, Any],
    *,
    expected_tree_sha256: str,
    expected_file_count: int,
) -> bool:
    monitor = receipt.get("source_mutation_monitor")
    if not isinstance(monitor, dict) or set(monitor) != {
        "root",
        "guard",
        "canary_boundary",
        "measurement_boundary",
        "canary_event_count",
        "scan_event_count",
        "events",
        "error",
        "liveness",
        "passed",
    }:
        return False
    events = monitor.get("events")
    liveness = monitor.get("liveness")
    canary_count = monitor.get("canary_event_count")
    if (
        monitor.get("root") != "workspace_source"
        or monitor.get("guard") != "windows_read_directory_changes_overlapped_v2"
        or monitor.get("canary_boundary")
        != "temporary excluded root file created and deleted before pre-source capture"
        or monitor.get("measurement_boundary")
        != "after canary drain through post-source capture and watcher termination"
        or not isinstance(canary_count, int)
        or isinstance(canary_count, bool)
        or canary_count < 2
        or monitor.get("scan_event_count") != 0
        or not isinstance(events, list)
        or len(events) != canary_count
        or any(
            not isinstance(row, dict)
            or set(row) != {"action", "relative_path"}
            or not isinstance(row.get("action"), int)
            or not str(row.get("relative_path") or "").startswith(
                ".k-guard-source-monitor.canary"
            )
            for row in events
        )
        or monitor.get("error") is not None
        or not isinstance(liveness, dict)
        or liveness.get("passed") is not True
        or not isinstance(liveness.get("registration_count"), int)
        or liveness["registration_count"] < 2
        or not isinstance(liveness.get("heartbeat_count"), int)
        or liveness["heartbeat_count"] < 1
        or liveness.get("drain_completed") is not True
        or liveness.get("stop_acknowledged") is not True
        or liveness.get("thread_terminated") is not True
        or monitor.get("passed") is not True
    ):
        return False
    return bool(
        receipt.get("source_mutation_guard_canary") is True
        and receipt.get("source_mutation_observed") is False
        and receipt.get("expected_source_tree_sha256") == expected_tree_sha256
        and receipt.get("pre_source_tree_sha256") == expected_tree_sha256
        and receipt.get("post_source_tree_sha256") == expected_tree_sha256
        and receipt.get("expected_source_file_count") == expected_file_count
        and receipt.get("pre_source_file_count") == expected_file_count
        and receipt.get("post_source_file_count") == expected_file_count
        and isinstance(receipt.get("pre_source_total_bytes"), int)
        and receipt.get("pre_source_total_bytes", -1) >= 0
        and receipt.get("post_source_total_bytes") == receipt.get("pre_source_total_bytes")
    )


def _child_process_policy_contract_valid(receipt: dict[str, Any]) -> bool:
    policy = receipt.get("child_process_policy")
    canary = policy.get("prebound_create_process_canary") if isinstance(policy, dict) else None
    disable_canary = policy.get("disable_attempt_canary") if isinstance(policy, dict) else None
    shell_canary = policy.get("prebound_shell_execute_canary") if isinstance(policy, dict) else None
    if (
        not isinstance(policy, dict)
        or not isinstance(canary, dict)
        or not isinstance(disable_canary, dict)
        or not isinstance(shell_canary, dict)
    ):
        return False
    if set(policy) != {
        "schema",
        "policy_id",
        "required_flags",
        "before_flags",
        "set_succeeded",
        "set_error",
        "after_flags",
        "disable_attempt_canary",
        "prebound_create_process_canary",
        "prebound_shell_execute_canary",
        "final_query_succeeded",
        "final_flags",
        "passed",
        "raw_returned",
    } or set(canary) != {"api", "blocked", "winerror", "unexpected_process_created"}:
        return False
    if set(disable_canary) != {"blocked", "winerror", "flags_after_attempt"} or set(
        shell_canary
    ) != {"api", "blocked", "result", "winerror"}:
        return False
    before_flags = policy.get("before_flags")
    after_flags = policy.get("after_flags")
    final_flags = policy.get("final_flags")
    return bool(
        policy.get("schema") == "k_guard_windows_child_process_policy.v1"
        and policy.get("policy_id") == 13
        and policy.get("required_flags") == 1
        and isinstance(before_flags, int)
        and not isinstance(before_flags, bool)
        and before_flags >= 0
        and policy.get("set_succeeded") is True
        and policy.get("set_error") == 0
        and isinstance(after_flags, int)
        and not isinstance(after_flags, bool)
        and after_flags & 1 == 1
        and policy.get("final_query_succeeded") is True
        and isinstance(final_flags, int)
        and not isinstance(final_flags, bool)
        and final_flags & 1 == 1
        and policy.get("passed") is True
        and policy.get("raw_returned") is False
        and disable_canary.get("blocked") is True
        and disable_canary.get("winerror") == 5
        and isinstance(disable_canary.get("flags_after_attempt"), int)
        and not isinstance(disable_canary.get("flags_after_attempt"), bool)
        and disable_canary["flags_after_attempt"] & 1 == 1
        and canary
        == {
            "api": "kernel32.CreateProcessW",
            "blocked": True,
            "winerror": 367,
            "unexpected_process_created": False,
        }
        and shell_canary.get("api") == "shell32.ShellExecuteW"
        and shell_canary.get("blocked") is True
        and shell_canary.get("winerror") == 367
        and isinstance(shell_canary.get("result"), int)
        and not isinstance(shell_canary.get("result"), bool)
        and 0 <= shell_canary["result"] <= 32
    )


def _image_load_monitor_contract_valid(receipt: dict[str, Any]) -> bool:
    monitor = receipt.get("image_load_monitor")
    if not isinstance(monitor, dict) or set(monitor) != {
        "schema",
        "guard",
        "registered",
        "unregistered",
        "canaries",
        "scan_event_count",
        "scan_load_count",
        "scan_unload_count",
        "event_set_sha256",
        "events",
        "outside_image_events",
        "callback_errors",
        "proof_boundary",
        "passed",
        "raw_returned",
    }:
        return False
    events = monitor.get("events")
    canaries = monitor.get("canaries")
    if not isinstance(events, list) or not isinstance(canaries, list):
        return False
    if [row.get("phase") for row in canaries if isinstance(row, dict)] != [
        "before-scan",
        "after-scan",
    ]:
        return False
    canary_keys = {
        "phase",
        "load_succeeded",
        "load_error",
        "free_succeeded",
        "free_error",
        "load_notification_seen",
        "unload_notification_seen",
        "passed",
    }
    if any(
        not isinstance(row, dict)
        or set(row) != canary_keys
        or row.get("load_succeeded") is not True
        or row.get("load_error") != 0
        or row.get("free_succeeded") is not True
        or row.get("free_error") != 0
        or row.get("load_notification_seen") is not True
        or row.get("unload_notification_seen") is not True
        or row.get("passed") is not True
        for row in canaries
    ):
        return False
    for sequence, row in enumerate(events, start=1):
        if (
            not isinstance(row, dict)
            or set(row) != {"sequence", "action", "path", "sha256"}
            or row.get("sequence") != sequence
            or row.get("action") not in {"load", "unload"}
            or not str(row.get("path") or "").startswith(
                ("<prefix>/", "<base_prefix>/", "<windows_tcb>/")
            )
            or re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256") or "")) is None
        ):
            return False
    load_count = sum(row["action"] == "load" for row in events)
    unload_count = sum(row["action"] == "unload" for row in events)
    return bool(
        monitor.get("schema") == "k_guard_windows_image_load_monitor.v1"
        and monitor.get("guard") == "ntdll_ldr_dll_notification_v1"
        and monitor.get("registered") is True
        and monitor.get("unregistered") is True
        and monitor.get("scan_event_count") == len(events)
        and monitor.get("scan_load_count") == load_count
        and monitor.get("scan_unload_count") == unload_count
        and monitor.get("event_set_sha256")
        == _sha256_bytes(
            b"k_guard_windows_image_load_monitor.v1\0"
            + json.dumps(events, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        and monitor.get("outside_image_events") == []
        and monitor.get("callback_errors") == []
        and monitor.get("proof_boundary") == "windows_loader_managed_images"
        and monitor.get("passed") is True
        and monitor.get("raw_returned") is False
    )


def _runtime_execution_contract_valid(
    receipt: dict[str, Any],
    *,
    expected_runtime: dict[str, Any],
    launcher_sha256: str,
    probe_sha256: str,
    source_probe_sha256: str | None = None,
) -> bool:
    if not _child_process_policy_contract_valid(receipt) or not _image_load_monitor_contract_valid(
        receipt
    ):
        return False
    audit = receipt.get("execution_audit")
    native = receipt.get("native_module_receipt")
    if not isinstance(audit, dict) or not isinstance(native, dict):
        return False
    executed = audit.get("executed_files")
    dynamic_events = audit.get("dynamic_exec_events")
    code_object_events = audit.get("code_object_control_events")
    process_events = audit.get("process_creation_events")
    native_symbol_events = audit.get("native_symbol_resolution_events")
    modules = native.get("modules")
    if (
        not isinstance(executed, list)
        or not isinstance(dynamic_events, list)
        or not isinstance(code_object_events, list)
        or not isinstance(process_events, list)
        or not isinstance(native_symbol_events, list)
        or not isinstance(modules, list)
        or not executed
        or not modules
    ):
        return False
    if (
        audit.get("schema") != "k_guard_python_execution_audit.v3"
        or audit.get("passed") is not True
        or audit.get("outside_executed_code") != []
        or audit.get("dynamic_executed_code") != []
        or audit.get("audit_errors") != []
        or process_events != []
        or audit.get("raw_returned") is not False
        or audit.get("executed_file_count") != len(executed)
        or not isinstance(audit.get("event_count"), int)
        or audit["event_count"] < 1
        or native.get("schema") != "k_guard_windows_native_module_receipt.v1"
        or native.get("passed") is not True
        or native.get("outside_native_modules") != []
        or native.get("raw_returned") is not False
        or native.get("module_count") != len(modules)
    ):
        return False
    for row in executed:
        event_kinds = row.get("event_kinds") if isinstance(row, dict) else None
        code_hashes = row.get("executed_code_sha256") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or not str(row.get("path") or "").startswith(
                ("<prefix>/", "<base_prefix>/", "<bound_protocol>/", "<windows_tcb>/")
            )
            or re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256") or "")) is None
            or not isinstance(event_kinds, list)
            or not event_kinds
            or event_kinds != sorted(set(event_kinds))
            or not set(event_kinds).issubset({"exec", "import", "native_load"})
            or not isinstance(row.get("event_count"), int)
            or row["event_count"] < 1
            or not isinstance(code_hashes, list)
            or code_hashes != sorted(set(code_hashes))
            or any(re.fullmatch(r"[0-9a-f]{64}", str(value)) is None for value in code_hashes)
            or ("exec" in event_kinds and not code_hashes)
            or ("exec" not in event_kinds and bool(code_hashes))
        ):
            return False
    for row in modules:
        if (
            not isinstance(row, dict)
            or not str(row.get("path") or "").startswith(
                ("<prefix>/", "<base_prefix>/", "<windows_tcb>/")
            )
            or re.fullmatch(r"[0-9a-f]{64}", str(row.get("sha256") or "")) is None
        ):
            return False
    for row in dynamic_events:
        label = str(row.get("label") or "") if isinstance(row, dict) else ""
        reason = row.get("allowed_reason") if isinstance(row, dict) else None
        caller = row.get("caller_path") if isinstance(row, dict) else None
        caller_frames = row.get("caller_frames") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or row.get("allowed") is not True
            or not isinstance(caller_frames, list)
            or len(caller_frames) > 8
            or any(
                not isinstance(frame, dict)
                or not str(frame.get("path") or "").startswith(
                    ("<prefix>/", "<base_prefix>/", "<bound_protocol>/")
                )
                or not isinstance(frame.get("function"), str)
                or not frame["function"]
                for frame in caller_frames
            )
            or caller != (caller_frames[0]["path"] if caller_frames else None)
            or re.fullmatch(r"[0-9a-f]{64}", str(row.get("code_sha256") or "")) is None
            or re.fullmatch(r"[0-9a-f]{20}", str(row.get("label_sha256") or "")) is None
            or row.get("label_sha256") != hashlib.sha256(label.encode("utf-8")).hexdigest()[:20]
        ):
            return False
        frame_pairs = [(frame["path"], frame["function"]) for frame in caller_frames]
        if reason == "stdlib_dataclass_generator_stack":
            if (
                label != "<string>"
                or len(frame_pairs) < 2
                or frame_pairs[0] != ("<base_prefix>/Lib/dataclasses.py", "_create_fn")
                or frame_pairs[1][0] != "<base_prefix>/Lib/dataclasses.py"
                or frame_pairs[1][1]
                not in {"_cmp_fn", "_frozen_get_del_attr", "_hash_fn", "_init_fn", "_repr_fn"}
            ):
                return False
        elif reason == "stdlib_namedtuple_generator_stack":
            if (
                label != "<string>"
                or not frame_pairs
                or frame_pairs[0]
                != ("<base_prefix>/Lib/collections/__init__.py", "namedtuple")
            ):
                return False
        elif reason == "cpython_frozen_code_hash":
            if re.fullmatch(r"<frozen [A-Za-z0-9_.]+>", label) is None:
                return False
        else:
            return False
    for row in code_object_events:
        caller_frames = row.get("caller_frames") if isinstance(row, dict) else None
        if (
            not isinstance(row, dict)
            or row.get("allowed") is not True
            or re.fullmatch(r"[0-9a-f]{64}", str(row.get("payload_sha256") or "")) is None
            or not isinstance(row.get("event_count"), int)
            or row["event_count"] < 1
            or not isinstance(caller_frames, list)
            or len(caller_frames) > 8
            or any(
                not isinstance(frame, dict)
                or not str(frame.get("path") or "").startswith(
                    ("<prefix>/", "<base_prefix>/", "<bound_protocol>/")
                )
                or not isinstance(frame.get("function"), str)
                or not frame["function"]
                for frame in caller_frames
            )
        ):
            return False
        reason = row.get("allowed_reason")
        previous_digest = row.get("previous_code_sha256")
        if reason == "frozen_importlib_bytecode_loader":
            if (
                row.get("event") not in {"marshal.load", "marshal.loads"}
                or row.get("caller_path") != "<frozen importlib._bootstrap_external>"
                or row.get("caller_function") != "_compile_bytecode"
                or previous_digest is not None
            ):
                return False
        elif reason == "stdlib_types_coroutine_code_replace":
            if (
                row.get("event") != "code.__new__"
                or row.get("caller_path") != "<base_prefix>/Lib/types.py"
                or row.get("caller_function") != "coroutine"
                or previous_digest is not None
            ):
                return False
        elif reason == "stdlib_types_coroutine_flag_transform":
            if (
                row.get("event") != "object.__setattr__"
                or row.get("caller_path") != "<base_prefix>/Lib/types.py"
                or row.get("caller_function") != "coroutine"
                or re.fullmatch(r"[0-9a-f]{64}", str(previous_digest or "")) is None
                or previous_digest == row.get("payload_sha256")
            ):
                return False
        else:
            return False
    click_symbols = {
        "kernel32.dll": {
            "GetCommandLineW",
            "GetConsoleMode",
            "GetLastError",
            "GetStdHandle",
            "LocalFree",
            "ReadConsoleW",
            "WriteConsoleW",
        },
        "shell32.dll": {"CommandLineToArgvW"},
        "python-runtime": {"PyBuffer_Release", "PyObject_GetBuffer"},
    }
    for row in native_symbol_events:
        symbol = str(row.get("symbol") or "") if isinstance(row, dict) else ""
        library_path = str(row.get("library_path") or "") if isinstance(row, dict) else ""
        caller_frames = row.get("caller_frames") if isinstance(row, dict) else None
        library_name = Path(library_path).name.casefold()
        contract_key = (
            "python-runtime"
            if library_path.startswith("<base_prefix>/")
            and library_name.startswith("python")
            and library_name.endswith(".dll")
            else library_name
        )
        if (
            not isinstance(row, dict)
            or row.get("event") not in {"ctypes.dlsym", "ctypes.dlsym/handle"}
            or row.get("allowed") is not True
            or row.get("allowed_reason") != "click_winconsole_exact_contract"
            or symbol not in click_symbols.get(contract_key, set())
            or row.get("symbol_sha256")
            != hashlib.sha256(symbol.encode("utf-8")).hexdigest()[:20]
            or not isinstance(caller_frames, list)
            or {
                "path": "<prefix>/Lib/site-packages/click/_winconsole.py",
                "function": "<module>",
            }
            not in caller_frames
        ):
            return False
    if audit["event_count"] < (
        sum(row["event_count"] for row in executed)
        + len(dynamic_events)
        + sum(row["event_count"] for row in code_object_events)
        + len(native_symbol_events)
    ):
        return False
    expected_audit_hash = _sha256_bytes(
        b"k_guard_python_execution_audit.v3\0"
        + json.dumps(executed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    expected_native_hash = _sha256_bytes(
        b"k_guard_windows_native_module_receipt.v1\0"
        + json.dumps(modules, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    if (
        audit.get("executed_file_set_sha256") != expected_audit_hash
        or native.get("module_set_sha256") != expected_native_hash
    ):
        return False
    attested_files: dict[str, str] = {}
    for tree_name, prefix_name in (
        ("prefix_tree", "<prefix>/"),
        ("base_runtime_tree", "<base_prefix>/"),
    ):
        tree = expected_runtime.get(tree_name)
        tree_rows = tree.get("files") if isinstance(tree, dict) else None
        if not isinstance(tree_rows, list) or not tree_rows:
            return False
        for row in tree_rows:
            path = str(row.get("path") or "") if isinstance(row, dict) else ""
            digest = str(row.get("sha256") or "") if isinstance(row, dict) else ""
            normalized = prefix_name + path
            if (
                not isinstance(row, dict)
                or not path
                or normalized in attested_files
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                return False
            attested_files[normalized] = digest
    attested_files["<bound_protocol>/holdout_scan_launcher.py"] = launcher_sha256
    attested_files["<bound_protocol>/holdout_runtime_probe.py"] = probe_sha256
    if source_probe_sha256 is not None:
        attested_files["<bound_protocol>/holdout_source_materialization.py"] = (
            source_probe_sha256
        )
    native_files = {str(row["path"]): str(row["sha256"]) for row in modules}
    for row in executed:
        path = str(row["path"])
        expected_hash = (
            native_files.get(path)
            if path.startswith("<windows_tcb>/")
            else attested_files.get(path)
        )
        if expected_hash != row["sha256"]:
            return False
    for row in modules:
        path = str(row["path"])
        if path.startswith(("<prefix>/", "<base_prefix>/")) and attested_files.get(path) != row[
            "sha256"
        ]:
            return False
    for row in receipt["image_load_monitor"]["events"]:
        path = str(row["path"])
        if path.startswith(("<prefix>/", "<base_prefix>/")) and attested_files.get(path) != row[
            "sha256"
        ]:
            return False
    expected_locked_native_files = {
        path: digest
        for path, digest in attested_files.items()
        if path.startswith(("<prefix>/", "<base_prefix>/"))
        and Path(path).suffix.casefold() in {".dll", ".pyd"}
    }
    locked_native_files = {
        str(row["path"]): str(row["sha256"])
        for row in receipt.get("native_runtime_lock", {}).get("files", [])
    }
    if locked_native_files != expected_locked_native_files:
        return False
    prewarmed_native_files = {
        str(row["path"]): str(row["sha256"])
        for row in receipt.get("native_runtime_prewarm", {}).get("files", [])
    }
    if prewarmed_native_files != expected_locked_native_files:
        return False
    expected_directories: set[str] = set()
    for path in attested_files:
        if path.startswith("<prefix>/"):
            normalized_root = "<prefix>"
            relative = Path(path.removeprefix("<prefix>/"))
        elif path.startswith("<base_prefix>/"):
            normalized_root = "<base_prefix>"
            relative = Path(path.removeprefix("<base_prefix>/"))
        else:
            continue
        parent = relative.parent
        while parent != Path("."):
            expected_directories.add(normalized_root + "/" + parent.as_posix())
            parent = parent.parent
    attested_objects = {
        str(row.get("path") or ""): row
        for row in receipt.get("runtime_object_attestation", {}).get("entries", [])
        if isinstance(row, dict)
    }
    if set(attested_objects) != set(expected_locked_native_files) | expected_directories:
        return False
    if any(
        attested_objects[path].get("kind") != "native_file"
        or attested_objects[path].get("expected_content_sha256") != digest
        for path, digest in expected_locked_native_files.items()
    ):
        return False
    if any(
        attested_objects[path].get("kind") != "directory"
        or attested_objects[path].get("expected_content_sha256") is not None
        for path in expected_directories
    ):
        return False
    return True


def _run_scan(
    workspace: Path,
    output: Path,
    *,
    timeout_seconds: float | None = None,
    python_executable: Path | None = None,
    isolated: bool = False,
    runtime_launcher: Path | None = None,
    runtime_probe: Path | None = None,
    source_probe: Path | None = None,
    expected_source_tree_sha256: str | None = None,
    expected_source_file_count: int | None = None,
    expected_runtime: Path | None = None,
    execution_receipt: Path | None = None,
) -> tuple[int, float, str, dict[str, Any]]:
    if timeout_seconds is not None and timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    raw_output = output.with_suffix(".raw.json")
    env = dict(os.environ)
    for key in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONUSERBASE"):
        env.pop(key, None)
    env.update({"PYTHONHASHSEED": "0", "PYTHONUTF8": "1"})
    scanner_python = str((python_executable or Path(sys.executable)).resolve(strict=True))
    command = [scanner_python]
    if isolated:
        if any(
            value is None
            for value in (
                runtime_launcher,
                runtime_probe,
                source_probe,
                expected_source_tree_sha256,
                expected_source_file_count,
                expected_runtime,
                execution_receipt,
            )
        ):
            raise ValueError(
                "isolated scan requires the bound launcher, runtime/source probes, source tree, runtime, and receipt paths"
            )
        assert runtime_launcher is not None
        assert runtime_probe is not None
        assert source_probe is not None
        assert expected_source_tree_sha256 is not None
        assert expected_source_file_count is not None
        assert expected_runtime is not None
        assert execution_receipt is not None
        if execution_receipt.exists():
            raise ValueError("isolated scan execution receipt must not already exist")
        expected_runtime_hash = _sha256_bytes(expected_runtime.read_bytes())
        command.extend(
            [
                "-I",
                "-B",
                "-S",
                str(runtime_launcher.resolve(strict=True)),
                "--probe-script",
                str(runtime_probe.resolve(strict=True)),
                "--expected-runtime",
                str(expected_runtime.resolve(strict=True)),
                "--expected-runtime-sha256",
                expected_runtime_hash,
                "--source-probe-script",
                str(source_probe.resolve(strict=True)),
                "--expected-source-tree-sha256",
                expected_source_tree_sha256,
                "--expected-source-file-count",
                str(expected_source_file_count),
                "--workspace",
                str(workspace),
                "--output",
                str(raw_output),
                "--receipt",
                str(execution_receipt),
            ]
        )
    else:
        bootstrap = (
            "import pathlib,runpy,sys;"
            f"sys.path.insert(0,{str(SOURCE_ROOT.resolve())!r});"
            "import k_guard_mcp;"
            f"expected=pathlib.Path({str(EXPECTED_ANALYZER_PACKAGE_DIR)!r});"
            "actual=pathlib.Path(k_guard_mcp.__file__).resolve().parent;"
            "actual==expected or sys.exit('repository analyzer import binding failed');"
            "runpy.run_module('k_guard_mcp.cli',run_name='__main__')"
        )
        command.extend(
            [
                "-I",
                "-B",
                "-c",
                bootstrap,
                "scan",
                str(workspace),
                "--json",
                str(raw_output),
            ]
        )
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raw_output.unlink(missing_ok=True)
        elapsed = round(time.perf_counter() - started, 3)
        raise ScanTimeoutError(f"scan exceeded the locked {timeout_seconds:g}s timeout after {elapsed:g}s") from exc
    duration = round(time.perf_counter() - started, 3)
    if not raw_output.is_file():
        receipt_message = ""
        if execution_receipt is not None and execution_receipt.is_file():
            receipt_payload = _json(execution_receipt)
            receipt_message = str(receipt_payload.get("failure_message") or "")
        message = receipt_message or completed.stderr.strip() or completed.stdout.strip() or "scan did not produce a report"
        raise RuntimeError(message)
    if isolated:
        assert execution_receipt is not None
        receipt_raw = execution_receipt.read_bytes() if execution_receipt.is_file() else b""
        receipt = _json(execution_receipt) if receipt_raw else {}
        launcher_hash = _sha256_bytes(runtime_launcher.resolve(strict=True).read_bytes())
        probe_hash = _sha256_bytes(runtime_probe.resolve(strict=True).read_bytes())
        source_probe_hash = _sha256_bytes(source_probe.resolve(strict=True).read_bytes())
        scanner_hash = _sha256_bytes(Path(scanner_python).read_bytes())
        expected_runtime_payload = _json(expected_runtime)
        if (
            receipt.get("schema") != RUNTIME_RECEIPT_SCHEMA
            or receipt.get("passed") is not True
            or receipt.get("runtime_mutation_observed") is not False
            or receipt.get("mutation_event_count") != 0
            or receipt.get("unclassified_notification_count") != 0
            or receipt.get("runtime_notification_classifier")
            != RUNTIME_NOTIFICATION_CLASSIFIER
            or receipt.get("runtime_notification_classifier_errors") != []
            or receipt.get("native_runtime_lock_guard") != NATIVE_RUNTIME_LOCK_GUARD
            or receipt.get("native_runtime_prewarm_guard")
            != NATIVE_RUNTIME_PREWARM_GUARD
            or receipt.get("runtime_object_attestation_guard")
            != RUNTIME_OBJECT_ATTESTATION_GUARD
            or receipt.get("mutation_monitor_errors") != []
            or receipt.get("mutation_guard")
            != "windows_read_directory_changes_overlapped_v2"
            or receipt.get("mutation_monitor_liveness_passed") is not True
            or receipt.get("mutation_guard_canary")
            != {"before_scan": True, "after_scan": True, "cleanup_passed": True}
            or not _runtime_monitor_contract_valid(receipt)
            or not _source_monitor_contract_valid(
                receipt,
                expected_tree_sha256=expected_source_tree_sha256,
                expected_file_count=expected_source_file_count,
            )
            or not _runtime_execution_contract_valid(
                receipt,
                expected_runtime=expected_runtime_payload,
                launcher_sha256=launcher_hash,
                probe_sha256=probe_hash,
                source_probe_sha256=source_probe_hash,
            )
            or receipt.get("scanner_python_sha256") != scanner_hash
            or receipt.get("launcher_sha256") != launcher_hash
            or receipt.get("probe_sha256") != probe_hash
            or receipt.get("source_probe_sha256") != source_probe_hash
            or receipt.get("scanner_exit_code") != completed.returncode
            or not isinstance(receipt.get("loaded_module_file_count"), int)
            or receipt.get("loaded_module_file_count", 0) < 1
            or re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("loaded_module_set_sha256") or ""))
            is None
            or receipt.get("outside_loaded_modules") != []
            or receipt.get("pre_runtime_sha256") != expected_runtime_hash
            or receipt.get("post_runtime_sha256") != expected_runtime_hash
            or receipt.get("output_sha256") != _sha256_bytes(raw_output.read_bytes())
            or receipt.get("raw_returned") is not False
            or (json.dumps(receipt, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
            != receipt_raw
        ):
            raw_output.unlink(missing_ok=True)
            raise RuntimeError("isolated scan runtime receipt is invalid")
    report = _normalize_workspace_paths(_json(raw_output), workspace)
    raw_output.unlink()
    if _contains_workspace_path(report, workspace) or _contains_local_home_path(report):
        raise RuntimeError("normalized report still contains a local workspace or home path")
    report_hash = _write_report(output, report)
    return completed.returncode, duration, report_hash, report


def _finding_counts(report: dict[str, Any]) -> dict[str, int]:
    counts = Counter(str(item.get("severity") or "info") for item in report.get("findings", []) if isinstance(item, dict))
    return {**{severity: counts[severity] for severity in ("critical", "high", "medium", "low", "info")}, "total": sum(counts.values())}


def _supported_file_count(report: dict[str, Any]) -> int:
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    coverage = metadata.get("review_coverage") if isinstance(metadata.get("review_coverage"), dict) else {}
    inventory = coverage.get("inventory") if isinstance(coverage.get("inventory"), dict) else {}
    return int(inventory.get("supported_file_count", 0) or 0)


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ValueError(f"manifest schema must be {MANIFEST_SCHEMA}")
    apps = manifest.get("apps")
    probes = manifest.get("probes")
    if not isinstance(apps, list) or not apps:
        raise ValueError("manifest must contain at least one app")
    if not isinstance(probes, list) or not probes:
        raise ValueError("manifest must contain at least one reference probe")
    app_names: list[str] = []
    for app in apps:
        if not isinstance(app, dict):
            raise ValueError("invalid app row")
        name = str(app.get("app") or "")
        commit = str(app.get("commit") or "")
        if not name or not app.get("repository") or not app.get("local_dir"):
            raise ValueError("each app needs app, local_dir, and repository")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError(f"app commit must be a full lowercase SHA-1: {name}")
        if app.get("stratum") not in {"top", "mid", "long_tail"}:
            raise ValueError(f"invalid app stratum: {name}")
        app_names.append(name)
    if len(app_names) != len(set(app_names)):
        raise ValueError("app names must be unique")
    app_set = set(app_names)
    probe_ids: list[str] = []
    for probe in probes:
        if not isinstance(probe, dict):
            raise ValueError("invalid probe row")
        probe_id = str(probe.get("probe_id") or "")
        if not probe_id or probe.get("app") not in app_set:
            raise ValueError(f"probe must reference a manifest app: {probe_id or 'missing'}")
        if not probe.get("oracle_refs") or not probe.get("accepted_rule_ids"):
            raise ValueError(f"probe needs oracle refs and accepted rules: {probe_id}")
        probe_ids.append(probe_id)
    if len(probe_ids) != len(set(probe_ids)):
        raise ValueError("probe ids must be unique")


def _eligible_release_blocking_findings(
    report: dict[str, Any],
    release_policy: str | None = None,
) -> list[dict[str, Any]]:
    return [
        finding
        for finding in _release_blocking_findings(report, release_policy)
        if str(finding.get("file") or "") and int(finding.get("line_start") or 0) > 0
    ]


def _candidate_rows(
    app: str,
    report_hash: str,
    report: dict[str, Any],
    limit: int | None,
    release_policy: str | None = None,
) -> list[dict[str, Any]]:
    findings = _eligible_release_blocking_findings(report, release_policy)
    findings.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity")), 9),
            str(item.get("file") or ""),
            int(item.get("line_start") or 0),
            str(item.get("rule_id") or ""),
        )
    )
    if limit is not None and limit <= 0:
        raise ValueError("candidate limit must be positive or None for a census")
    selected: list[dict[str, Any]] = list(findings) if limit is None else []
    selected_ids: set[int] = set()
    seen_rules: set[str] = set()
    for index, finding in enumerate(findings if limit is not None else []):
        rule_id = str(finding.get("rule_id") or "")
        if rule_id in seen_rules:
            continue
        selected.append(finding)
        selected_ids.add(index)
        seen_rules.add(rule_id)
        if len(selected) == limit:
            break
    if limit is not None and len(selected) < limit:
        seen_rule_files = {(str(item.get("rule_id") or ""), str(item.get("file") or "")) for item in selected}
        for index, finding in enumerate(findings):
            key = (str(finding.get("rule_id") or ""), str(finding.get("file") or ""))
            if index in selected_ids or key in seen_rule_files:
                continue
            selected.append(finding)
            selected_ids.add(index)
            seen_rule_files.add(key)
            if len(selected) == limit:
                break
    if limit is not None and len(selected) < limit:
        for index, finding in enumerate(findings):
            if index in selected_ids:
                continue
            selected.append(finding)
            if len(selected) == limit:
                break
    rows: list[dict[str, Any]] = []
    for finding in selected:
        evidence = str(finding.get("evidence") or "")
        subtype_match = re.search(r"\bdetector_subtype=([^\s;]+)", evidence)
        identity = {
            "app": app,
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "file": finding.get("file"),
            "line_start": finding.get("line_start"),
            "evidence": evidence,
        }
        fingerprint = _sha256_bytes(_canonical_json(identity).encode("utf-8"))
        source_location = _source_location(finding)
        evidence_refs = _redacted_evidence_refs(evidence)
        rows.append(
            {
                "candidate_id": fingerprint[:20],
                "redacted_fingerprint": f"sha256-truncated:{fingerprint[:20]}",
                "app": app,
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "rule_id": finding.get("rule_id"),
                "detector_subtype": subtype_match.group(1) if subtype_match else str(finding.get("source") or "unknown"),
                "source_location": source_location,
                "location": {
                    "kind": "source",
                    "source": source_location,
                    "body_or_header": None,
                },
                "evidence_refs": evidence_refs,
                "response_hash": evidence_refs.get("response_hash"),
                "artifact_scope": finding.get("artifact_scope"),
                "scan_report_sha256": report_hash,
                "label": "unreviewed",
                "rationale": "",
                "raw_returned": False,
            }
        )
    return rows


def _release_blocking_findings(
    report: dict[str, Any],
    release_policy: str | None = None,
) -> list[dict[str, Any]]:
    from k_guard_mcp.release_policy import (
        RELEASE_BLOCKING_LANE,
        release_lane,
        release_lane_for_policy,
    )

    return [
        item
        for item in report.get("findings", [])
        if isinstance(item, dict)
        and (
            release_lane(item, "high")
            if release_policy is None
            else release_lane_for_policy(item, release_policy, "high")
        )
        == RELEASE_BLOCKING_LANE
    ]


def _redacted_evidence_refs(evidence: str) -> dict[str, str]:
    refs = {
        key: value
        for key, value in re.findall(
            r"\b([a-z][a-z0-9_]*(?:hash|ref|sha256))=([A-Za-z0-9:._-]{8,128})",
            evidence,
        )
    }
    return dict(sorted(refs.items()))


def _source_location(finding: dict[str, Any]) -> str:
    file = str(finding.get("file") or "")
    line = int(finding.get("line_start") or 0)
    if file.startswith("<workspace>/"):
        file = file[len("<workspace>/") :]
    return f"{file}:{line}" if line else file


def _probe_result(probe: dict[str, Any], report_hash: str, report: dict[str, Any]) -> dict[str, Any]:
    accepted = {str(value) for value in probe.get("accepted_rule_ids", [])}
    oracle_files = {
        str(value).rsplit(":", 1)[0].replace("\\", "/")
        for value in probe.get("oracle_refs", [])
        if isinstance(value, str)
    }
    matches: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        if not isinstance(finding, dict) or str(finding.get("rule_id") or "") not in accepted:
            continue
        file = str(finding.get("file") or "").replace("\\", "/")
        relative = file[len("<workspace>/") :] if file.startswith("<workspace>/") else file
        if not any(relative == oracle or relative.endswith("/" + oracle) for oracle in oracle_files):
            continue
        matches.append(
            {
                "rule_id": finding.get("rule_id"),
                "source_location": _source_location(finding),
                "finding_ref": _sha256_bytes(_canonical_json(finding).encode("utf-8"))[:20],
            }
        )
    detected = bool(matches)
    return {
        "probe_id": probe.get("probe_id"),
        "app": probe.get("app"),
        "risk_domain": probe.get("risk_domain"),
        "oracle_classification": probe.get("oracle_classification", "true_positive"),
        "vulnerability": probe.get("vulnerability"),
        "oracle_refs": probe.get("oracle_refs", []),
        "accepted_rule_ids": sorted(accepted),
        "entire_report_reviewed": True,
        "detected": detected,
        "result": "detected" if detected else "false_negative",
        "matching_findings": matches,
        "scan_report_sha256": report_hash,
        "reviewer_kind": "deterministic_source_oracle",
        "raw_returned": False,
    }


def run_campaign(manifest_path: Path, apps_root: Path, output_dir: Path, runs: int = 2, candidates_per_app: int = 3) -> dict[str, Any]:
    if runs < 2:
        raise ValueError("at least two fresh-process runs are required")
    manifest = _json(manifest_path)
    _validate_manifest(manifest)
    worktree_clean = _git("status", "--porcelain") == ""
    if not worktree_clean:
        raise RuntimeError("tracked worktree must be clean before public campaign execution")
    source_revision = _git("rev-parse", "HEAD")
    analyzer_package_tree_sha256 = package_tree_sha256(ROOT / "src" / "k_guard_mcp")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_dir = output_dir / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)

    campaign_apps: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    probe_results: list[dict[str, Any]] = []
    probes_by_app: dict[str, list[dict[str, Any]]] = {}
    for probe in manifest.get("probes", []):
        if isinstance(probe, dict):
            probes_by_app.setdefault(str(probe.get("app") or ""), []).append(probe)

    for app in manifest.get("apps", []):
        if not isinstance(app, dict):
            raise ValueError("invalid app row")
        name = str(app.get("app") or "")
        workspace = (apps_root / str(app.get("local_dir") or name)).resolve()
        if not workspace.is_dir():
            raise FileNotFoundError(workspace)
        actual_commit = _git("rev-parse", "HEAD", cwd=workspace)
        if actual_commit != app.get("commit"):
            raise RuntimeError(f"commit mismatch for {name}: {actual_commit}")
        if _git("status", "--porcelain", cwd=workspace):
            raise RuntimeError(f"source worktree must be clean for {name}")
        run_rows: list[dict[str, Any]] = []
        first_report: dict[str, Any] | None = None
        for run_number in range(1, runs + 1):
            report_path = report_dir / f"{name}-run{run_number}.json"
            exit_code, duration, report_hash, report = _run_scan(
                workspace,
                report_path,
                timeout_seconds=PUBLIC_APP_SCAN_TIMEOUT_SECONDS,
            )
            run_rows.append(
                {
                    "run": run_number,
                    "exit_code": exit_code,
                    "duration_seconds": duration,
                    "report_sha256": report_hash,
                }
            )
            first_report = first_report or report
        hashes = {row["report_sha256"] for row in run_rows}
        if len(hashes) != 1 or any(row["exit_code"] != 0 for row in run_rows):
            raise RuntimeError(f"non-reproducible or failed scan for {name}")
        assert first_report is not None
        report_hash = run_rows[0]["report_sha256"]
        campaign_apps.append(
            {
                "app": name,
                "stratum": app.get("stratum"),
                "repository": app.get("repository"),
                "commit": actual_commit,
                "source_worktree_clean": True,
                "tracked_files": len(_git("ls-files", cwd=workspace).splitlines()),
                "supported_files": _supported_file_count(first_report),
                "finding_counts": _finding_counts(first_report),
                "runs": run_rows,
                "exact_repeat": True,
            }
        )
        app_candidates = _candidate_rows(name, report_hash, first_report, candidates_per_app)
        available_release_blocking = len(_release_blocking_findings(first_report))
        campaign_apps[-1]["available_release_blocking_findings"] = available_release_blocking
        campaign_apps[-1]["sampled_release_blocking_candidates"] = len(app_candidates)
        candidates.extend(app_candidates)
        probe_results.extend(_probe_result(probe, report_hash, first_report) for probe in probes_by_app.get(name, []))

    campaign = {
        "schema": CAMPAIGN_SCHEMA,
        "campaign_id": manifest.get("campaign_id"),
        "campaign_kind": manifest.get("campaign_kind"),
        "source_revision": source_revision,
        "analyzer_package_tree_sha256": analyzer_package_tree_sha256,
        "analyzer_package_tree_hash_schema": TREE_HASH_SCHEMA,
        "tracked_worktree_clean": worktree_clean,
        "run_contract": {
            "fresh_process_per_run": True,
            "minimum_runs_per_app": runs,
            "scan_timeout_seconds": int(PUBLIC_APP_SCAN_TIMEOUT_SECONDS),
            "scanner_execution_mode": NONISOLATED_SCANNER_EXECUTION_MODE,
            "scanner_import_binding": "child_module_path_guard_v1",
            "isolated_runtime_receipt": False,
            "report_path_normalization": "absolute workspace prefix replaced with <workspace>",
            "report_json": "UTF-8, sorted keys, two-space indent",
            "python_hash_seed": "0",
        },
        "apps": campaign_apps,
        "claim_boundary": manifest.get("claim_boundary", {}),
        "raw_returned": False,
    }
    candidate_bundle = {
        "schema": CANDIDATE_SCHEMA,
        "campaign_id": manifest.get("campaign_id"),
        "source_revision": source_revision,
        "analyzer_package_tree_sha256": analyzer_package_tree_sha256,
        "analyzer_package_tree_hash_schema": TREE_HASH_SCHEMA,
        "selection": (
            f"Up to {candidates_per_app} deterministic policy-defined release-blocking candidates per app; "
            "require an exact source line, prioritize distinct rule IDs, then distinct rule/file pairs, "
            "then severity/path/line/rule order."
        ),
        "sampling": {
            "target_per_app": candidates_per_app,
            "sample_all_available_when_below_target": True,
            "available_by_app": {row["app"]: row["available_release_blocking_findings"] for row in campaign_apps},
            "sampled_by_app": {row["app"]: row["sampled_release_blocking_candidates"] for row in campaign_apps},
        },
        "candidates": candidates,
        "raw_returned": False,
    }
    probe_bundle = {
        "schema": PROBE_SCHEMA,
        "campaign_id": manifest.get("campaign_id"),
        "source_revision": source_revision,
        "analyzer_package_tree_sha256": analyzer_package_tree_sha256,
        "analyzer_package_tree_hash_schema": TREE_HASH_SCHEMA,
        "probes": probe_results,
        "metrics": {
            "probe_count": len(probe_results),
            "detected": sum(row["detected"] is True for row in probe_results),
            "false_negative": sum(row["detected"] is False for row in probe_results),
        },
        "claim_boundary": "Selected source-oracle detection rate is a development regression metric, not full-app recall or a blind holdout score.",
        "raw_returned": False,
    }
    _write_report(output_dir / "campaign.json", campaign)
    _write_report(output_dir / "candidate-queue.json", candidate_bundle)
    _write_report(output_dir / "reference-probes.json", probe_bundle)
    return {"campaign": campaign, "candidates": candidate_bundle, "probes": probe_bundle}


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a reproducible public-app static validation campaign.")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--apps-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--candidates-per-app", type=int, default=3)
    args = parser.parse_args()
    result = run_campaign(
        args.manifest.resolve(),
        args.apps_root.resolve(),
        args.output_dir.resolve(),
        args.runs,
        args.candidates_per_app,
    )
    print(
        json.dumps(
            {
                "campaign_id": result["campaign"]["campaign_id"],
                "app_count": len(result["campaign"]["apps"]),
                "candidate_count": len(result["candidates"]["candidates"]),
                "probe_metrics": result["probes"]["metrics"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
