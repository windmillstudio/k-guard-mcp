from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import math
import re
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from scripts.run_public_field_campaign import _validate_preregistration
except ModuleNotFoundError:
    from run_public_field_campaign import _validate_preregistration

try:
    from scripts.holdout_protocol import validate_bound_protocol
except ModuleNotFoundError:
    from holdout_protocol import validate_bound_protocol

try:
    from scripts.holdout_integrity import (
        PROTOCOL_RECOVERY_REPLAY_STATUS,
        protocol_recovery_qualification_boundary,
    )
except ModuleNotFoundError:
    from holdout_integrity import (
        PROTOCOL_RECOVERY_REPLAY_STATUS,
        protocol_recovery_qualification_boundary,
    )

from k_guard_mcp.release_policy import (
    RELEASE_BLOCKING_POLICY,
    automatic_release_rules_for_policy,
    release_hold_counts_for_policy,
)

try:
    from scripts.assemble_public_field_labels import (
        REQUIRED_VENDORS,
        REVIEW_SCHEMA,
        candidate_bindings_sha256,
    )
    from scripts.run_public_app_campaign import (
        _candidate_rows,
        _eligible_release_blocking_findings,
        _finding_counts,
        _release_blocking_findings,
        _runtime_execution_contract_valid,
        _runtime_monitor_contract_valid,
        _source_monitor_contract_valid,
        _supported_file_count,
    )
except ModuleNotFoundError:
    from assemble_public_field_labels import REQUIRED_VENDORS, REVIEW_SCHEMA, candidate_bindings_sha256
    from run_public_app_campaign import (
        _candidate_rows,
        _eligible_release_blocking_findings,
        _finding_counts,
        _release_blocking_findings,
        _runtime_execution_contract_valid,
        _runtime_monitor_contract_valid,
        _source_monitor_contract_valid,
        _supported_file_count,
    )


PREREGISTRATION_SCHEMA = "k_guard_public_field_preregistration.v1"
CAMPAIGN_SCHEMA = "k_guard_public_field_campaign.v1"
QUEUE_SCHEMA = "k_guard_public_field_candidate_queue.v1"
LABEL_SCHEMA = "k_guard_public_field_candidate_labels.v1"
STATUS_SCHEMA = "k_guard_public_field_effectiveness_status.v3"
ALLOWED_LABELS = {"true_positive", "false_positive", "benign", "inconclusive"}
ALLOWED_AGREEMENTS = {"unanimous", "majority", "no_consensus"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
REVIEWER_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_REPORT_BYTES = 100 * 1024 * 1024
MAX_REVIEW_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_SOURCE_VERIFICATION_BYTES = 250 * 1024 * 1024
MAX_GIT_TREE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_PATH_DEPTH = 256
LEGACY_SOURCE_RECEIPT_SCHEMA = "k_guard_git_source_materialization.v1"
SOURCE_RECEIPT_SCHEMA = "k_guard_git_source_materialization.v2"
SOURCE_RECEIPT_SCHEMAS = {
    LEGACY_SOURCE_RECEIPT_SCHEMA,
    SOURCE_RECEIPT_SCHEMA,
}
SOURCE_TREE_SCHEMA = "k_guard_materialized_source_tree.v1"
INDEPENDENT_VERIFICATION_SCHEMA = "k_guard_independent_git_verification.v3"
INDEPENDENT_FILE_SET_SCHEMA = "k_guard_independent_git_file_set.v1"
PREEXECUTION_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v3"
STRUCTURAL_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v4"
BLOB_EXACT_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v5"
CURRENT_PROTOCOL_SCHEMA = "k_guard_holdout_protocol.v6"
RUNTIME_RECEIPT_SCHEMA = "k_guard_holdout_scan_runtime_receipt.v4"
RUNTIME_NOTIFICATION_CLASSIFIER = "prewarmed_zero_notification_boundary_v2"
NATIVE_RUNTIME_LOCK_GUARD = "createfile_deny_write_delete_share_v1"
NATIVE_RUNTIME_PREWARM_GUARD = "sec_image_readonly_mapping_policy_bound_v1"
RUNTIME_OBJECT_ATTESTATION_GUARD = (
    "prewarm_boundary_file_basic_owner_group_dacl_file_id_usn_v2"
)
INDEPENDENT_GIT_PROTOCOL_SCHEMAS = {
    PREEXECUTION_PROTOCOL_SCHEMA,
    STRUCTURAL_PROTOCOL_SCHEMA,
    BLOB_EXACT_PROTOCOL_SCHEMA,
    CURRENT_PROTOCOL_SCHEMA,
}
GIT_FILE_MODES = {"100644", "100755"}
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


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _canonical_report_bytes(report: dict[str, Any]) -> bytes:
    return (json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _safe_evidence_artifact(evidence_dir: Path, relative_value: Any) -> Path:
    relative = Path(str(relative_value or ""))
    root = evidence_dir.resolve()
    unresolved = root / relative
    candidate = unresolved.resolve()
    current = root
    has_link_or_reparse = False
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.stat(follow_symlinks=False)
        except OSError:
            break
        if current.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
            has_link_or_reparse = True
            break
    if (
        not relative.name
        or relative.is_absolute()
        or ".." in relative.parts
        or not candidate.is_relative_to(root)
        or has_link_or_reparse
    ):
        raise ValueError("evidence artifact path is invalid")
    return candidate


def _artifact_hash_matches(evidence_dir: Path, relative_value: Any, expected_hash: Any) -> bool:
    try:
        artifact = _safe_evidence_artifact(evidence_dir, relative_value)
        if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size > MAX_REVIEW_ARTIFACT_BYTES:
            return False
        return hashlib.sha256(artifact.read_bytes()).hexdigest() == expected_hash
    except OSError:
        return False


def _canonical_payload_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _git_object_sha1(kind: str, raw: bytes) -> str:
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(f"{kind} {len(raw)}\0".encode("ascii"))
    digest.update(raw)
    return digest.hexdigest()


def _canonical_rows_sha256(schema: str, rows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        (schema + "\0").encode("ascii")
        + json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
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


def _independent_file_set_sha256(rows: list[dict[str, Any]]) -> str:
    return _canonical_rows_sha256(INDEPENDENT_FILE_SET_SCHEMA, rows)


def _windows_component_key(value: str) -> str:
    if (
        not value
        or value in {".", ".."}
        or value.endswith((".", " "))
        or any(ord(character) < 32 for character in value)
        or any(character in WINDOWS_INVALID_COMPONENT_CHARS for character in value)
        or len(value.encode("utf-16-le")) // 2 > 255
    ):
        raise ValueError("source evidence path contains a Windows-unsafe component")
    normalized = unicodedata.normalize("NFC", value).casefold()
    device_stem = normalized.split(".", 1)[0].rstrip(" .")
    if (
        normalized == ".git"
        or device_stem == ".git"
        or device_stem in WINDOWS_RESERVED_COMPONENTS
        or WINDOWS_SHORT_NAME_RE.fullmatch(normalized) is not None
    ):
        raise ValueError("source evidence path contains a reserved Windows or NTFS alias")
    return normalized


def _register_path_prefixes(path: str, seen: dict[str, str]) -> None:
    normalized_parts: list[str] = []
    original_parts: list[str] = []
    parts = path.split("/")
    if len(parts) > MAX_SOURCE_PATH_DEPTH + 1:
        raise ValueError("source evidence path exceeds the maximum depth")
    for part in parts:
        normalized_parts.append(_windows_component_key(part))
        original_parts.append(part)
        normalized_prefix = "/".join(normalized_parts)
        original_prefix = "/".join(original_parts)
        previous = seen.setdefault(normalized_prefix, original_prefix)
        if previous != original_prefix:
            raise ValueError(
                "source evidence path prefix collision under Windows or Unicode semantics"
            )


def _reconstruct_git_tree_sha1(rows: list[dict[str, Any]]) -> str:
    root: dict[bytes, dict[str, Any]] = {}
    seen_prefixes: dict[str, str] = {}
    for row in rows:
        path = str(row["path"])
        _register_path_prefixes(path, seen_prefixes)
        parts = path.encode("utf-8").split(b"/")
        node = root
        for part in parts[:-1]:
            current = node.setdefault(part, {"kind": "tree", "children": {}})
            if current.get("kind") != "tree":
                raise ValueError("source file/directory conflict")
            node = current["children"]
        if parts[-1] in node:
            raise ValueError("duplicate source path")
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
            if len(body) > MAX_GIT_TREE_BYTES:
                raise ValueError("source evidence tree exceeds the verification budget")
        computed[id(node)] = _git_object_sha1("tree", bytes(body))
    return computed[id(root)]


def _validated_source_file_rows(rows: Any) -> list[dict[str, Any]]:
    if not isinstance(rows, list) or len(rows) > 2_000_000:
        raise ValueError("source file rows are invalid")
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
            raise ValueError("source file row fields are invalid")
        path = str(row.get("path") or "")
        mode = str(row.get("mode") or "")
        blob = str(row.get("git_blob_sha1") or "")
        digest = str(row.get("sha256") or "")
        byte_count = row.get("byte_count")
        if (
            not path
            or path in seen_paths
            or "\\" in path
            or mode not in GIT_FILE_MODES
            or REVISION_RE.fullmatch(blob) is None
            or SHA256_RE.fullmatch(digest) is None
            or not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
            or byte_count < 0
        ):
            raise ValueError("source file row is invalid")
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
        raise ValueError("source file rows are not sorted")
    return normalized


def _load_v4_report_artifact(evidence_dir: Path, run: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    if run.get("report_artifact_encoding") != "canonical-json+gzip-mtime-zero":
        raise ValueError("report artifact encoding is invalid")
    artifact = _safe_evidence_artifact(evidence_dir, run.get("report_artifact_path"))
    if not artifact.is_file() or artifact.suffixes[-2:] != [".json", ".gz"]:
        raise ValueError("report artifact is missing")
    compressed = artifact.read_bytes()
    if hashlib.sha256(compressed).hexdigest() != run.get("report_artifact_sha256"):
        raise ValueError("report artifact hash is invalid")
    try:
        with gzip.open(artifact, "rb") as source:
            raw = source.read(MAX_REPORT_BYTES + 1)
    except (OSError, EOFError) as exc:
        raise ValueError("report artifact gzip stream is invalid") from exc
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("report artifact exceeds the verification budget")
    if hashlib.sha256(raw).hexdigest() != run.get("report_sha256"):
        raise ValueError("canonical report hash is invalid")
    try:
        report = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("report artifact JSON is invalid") from exc
    if not isinstance(report, dict) or _canonical_report_bytes(report) != raw:
        raise ValueError("report artifact is not canonical JSON")
    return report, raw


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 0.0
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = proportion + z * z / (2 * total)
    margin = z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total)
    return round((centre - margin) / denominator, 6)


def _majority(reviews: list[dict[str, Any]]) -> tuple[str, str]:
    counts = Counter(str(row.get("label") or "") for row in reviews)
    if not counts:
        return "inconclusive", "no_consensus"
    label, votes = counts.most_common(1)[0]
    if votes < 2 or list(counts.values()).count(votes) > 1:
        return "inconclusive", "no_consensus"
    return label, "unanimous" if votes == len(reviews) else "majority"


def _v4_origin_binding_valid(row: dict[str, Any], expected_repository_id: str | None) -> bool:
    return bool(
        expected_repository_id
        and row.get("origin_repository_match") is True
        and row.get("repository_id") == expected_repository_id
        and row.get("origin_repository_id") == expected_repository_id
    )


def _load_canonical_evidence_json(
    evidence_dir: Path,
    relative_value: Any,
    *,
    maximum_bytes: int = MAX_SOURCE_VERIFICATION_BYTES,
) -> tuple[Path, dict[str, Any], bytes]:
    path = _safe_evidence_artifact(evidence_dir, relative_value)
    if not path.is_file() or path.stat().st_size > maximum_bytes:
        raise ValueError("evidence JSON artifact is missing or too large")
    raw = path.read_bytes()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("evidence JSON artifact is invalid") from exc
    if not isinstance(payload, dict) or _canonical_report_bytes(payload) != raw:
        raise ValueError("evidence JSON artifact is not canonical")
    return path, payload, raw


def _source_receipt_contract(
    evidence_dir: Path,
    app: dict[str, Any],
    campaign_app: dict[str, Any],
    *,
    expected_schema: str,
) -> tuple[str, str, dict[str, Any], list[dict[str, Any]]]:
    relative = str(campaign_app.get("source_materialization_receipt_path") or "")
    path, receipt, raw = _load_canonical_evidence_json(evidence_dir, relative)
    digest = hashlib.sha256(raw).hexdigest()
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
        set(receipt) != required
        or expected_schema not in SOURCE_RECEIPT_SCHEMAS
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
        or receipt.get("git_repository_layout") != "ordinary_non_shallow_standalone_clone"
        or receipt.get("source_worktree_clean") is not True
        or current_contract_invalid
        or legacy_contract_invalid
        or receipt.get("git_fsck_strict_passed") is not True
        or SHA256_RE.fullmatch(str(receipt.get("git_fsck_output_sha256") or "")) is None
        or receipt.get("source_tree_schema") != SOURCE_TREE_SCHEMA
        or receipt.get("raw_returned") is not False
        or campaign_app.get("source_materialization_receipt_sha256") != digest
        or campaign_app.get("source_materialization_schema") != expected_schema
    ):
        raise ValueError("source receipt identity contract is invalid")
    rows = _validated_source_file_rows(receipt.get("files"))
    source_tree = _source_tree_sha256(rows)
    if (
        receipt.get("file_count") != len(rows)
        or receipt.get("total_bytes") != sum(row["byte_count"] for row in rows)
        or receipt.get("source_tree_sha256") != source_tree
        or _reconstruct_git_tree_sha1(rows) != app.get("commit_tree")
        or campaign_app.get("source_tree_sha256") != source_tree
        or campaign_app.get("source_total_bytes") != receipt.get("total_bytes")
        or campaign_app.get("tracked_files") != receipt.get("file_count")
    ):
        raise ValueError("source receipt aggregate contract is invalid")
    return path.relative_to(evidence_dir.resolve()).as_posix(), digest, receipt, rows


def _v4_source_provenance_errors(
    evidence_dir: Path,
    preregistration: dict[str, Any],
    preregistration_path: Path,
    campaign: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    try:
        bound_protocol = validate_bound_protocol(preregistration, preregistration_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return ["v4_source_provenance_protocol_invalid"]
    manifest = bound_protocol.get("manifest", {})
    verification_contract = manifest.get("independent_git_verification")
    if manifest.get("schema") not in INDEPENDENT_GIT_PROTOCOL_SCHEMAS or not isinstance(
        verification_contract, dict
    ):
        return ["v4_independent_git_verification_protocol_missing"]
    source_materialization_contract = manifest.get("source_materialization")
    expected_receipt_schema = (
        str(source_materialization_contract.get("schema") or "")
        if isinstance(source_materialization_contract, dict)
        else ""
    )
    if expected_receipt_schema not in SOURCE_RECEIPT_SCHEMAS:
        return ["v4_source_materialization_protocol_missing"]

    prereg_rows = preregistration.get("apps") if isinstance(preregistration.get("apps"), list) else []
    campaign_rows = campaign.get("apps") if isinstance(campaign.get("apps"), list) else []
    prereg_apps = {
        str(row.get("app") or ""): row
        for row in prereg_rows
        if isinstance(row, dict) and row.get("app")
    }
    campaign_apps = {
        str(row.get("app") or ""): row
        for row in campaign_rows
        if isinstance(row, dict) and row.get("app")
    }
    if (
        len(prereg_apps) != len(prereg_rows)
        or len(campaign_apps) != len(campaign_rows)
        or set(prereg_apps) != set(campaign_apps)
    ):
        return ["v4_source_provenance_app_set_mismatch"]

    receipts: dict[str, tuple[str, str, dict[str, Any], list[dict[str, Any]]]] = {}
    expected_receipt_paths: set[str] = set()
    for app_name, app in prereg_apps.items():
        try:
            contract = _source_receipt_contract(
                evidence_dir,
                app,
                campaign_apps[app_name],
                expected_schema=expected_receipt_schema,
            )
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            errors.append(f"v4_source_receipt_invalid:{app_name}")
            continue
        receipts[app_name] = contract
        expected_receipt_paths.add(contract[0])
    receipt_root = evidence_dir / "source-receipts"
    try:
        receipt_root_metadata = receipt_root.stat(follow_symlinks=False)
        receipt_entries = list(receipt_root.iterdir())
    except OSError:
        receipt_entries = []
        errors.append("v4_source_receipt_directory_invalid")
    else:
        invalid_receipt_entry = False
        for entry in receipt_entries:
            try:
                entry_metadata = entry.stat(follow_symlinks=False)
            except OSError:
                invalid_receipt_entry = True
                break
            if (
                entry.is_symlink()
                or getattr(entry_metadata, "st_file_attributes", 0) & 0x400
                or not entry.is_file()
            ):
                invalid_receipt_entry = True
                break
        if receipt_root.is_symlink() or getattr(
            receipt_root_metadata, "st_file_attributes", 0
        ) & 0x400 or invalid_receipt_entry:
            errors.append("v4_source_receipt_directory_invalid")
    actual_receipt_paths = {
        path.relative_to(evidence_dir).as_posix()
        for path in receipt_entries
        if path.is_file() and not path.is_symlink()
    }
    if actual_receipt_paths != expected_receipt_paths:
        errors.append("v4_source_receipt_artifact_set_mismatch")

    artifact_relative = verification_contract.get("artifact_path")
    try:
        _artifact_path, verification, verification_raw = _load_canonical_evidence_json(
            evidence_dir,
            artifact_relative,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        errors.append("v4_independent_git_verification_artifact_invalid")
        return sorted(set(errors))
    required_top = {
        "schema",
        "campaign_id",
        "preregistration_sha256",
        "campaign_sha256",
        "holdout_protocol_manifest_sha256",
        "independent_git_verifier_sha256",
        "verification_method",
        "byte_binding",
        "storage_binding",
        "path_policy",
        "execution_provenance",
        "external_signed_provenance_required_for_contest_go",
        "acquisition_boundary",
        "source_contents_embedded",
        "app_count",
        "apps",
        "raw_returned",
    }
    protocol_execution = campaign.get("holdout_protocol")
    campaign_path = evidence_dir / "campaign.json"
    expected_verifier_hash = bound_protocol.get("protocol_files", {}).get(
        "scripts/verify_holdout_git_sources.py"
    )
    if (
        set(verification) != required_top
        or verification.get("schema") != INDEPENDENT_VERIFICATION_SCHEMA
        or verification.get("campaign_id") != preregistration.get("campaign_id")
        or verification.get("preregistration_sha256")
        != hashlib.sha256(preregistration_path.read_bytes()).hexdigest()
        or verification.get("campaign_sha256")
        != hashlib.sha256(campaign_path.read_bytes()).hexdigest()
        or verification.get("holdout_protocol_manifest_sha256")
        != bound_protocol.get("manifest_sha256")
        or verification.get("independent_git_verifier_sha256") != expected_verifier_hash
        or not isinstance(protocol_execution, dict)
        or protocol_execution.get("independent_git_verifier_sha256") != expected_verifier_hash
        or verification.get("verification_method")
        != "verifier_owned_no_local_mirror_snapshot_raw_git_object_reconstruction"
        or verification.get("byte_binding")
        != "git_sha1_graph_plus_independent_sha256_file_bytes"
        or verification.get("storage_binding")
        != "pre_post_sha256_manifest_plus_file_identity"
        or verification.get("path_policy")
        != "windows_ntfs_materialization_fail_closed_v1"
        or verification.get("execution_provenance") != "unsigned_local_replay_receipt"
        or verification.get("external_signed_provenance_required_for_contest_go") is not True
        or verification.get("acquisition_boundary")
        != (
            "input origin is configuration metadata; an unlinked verifier-owned no-local mirror "
            "snapshot is storage-manifested before and after content-addressed reconstruction"
        )
        or verification.get("source_contents_embedded") is not False
        or verification.get("raw_returned") is not False
        or not verification_raw
    ):
        errors.append("v4_independent_git_verification_binding_invalid")

    independent_rows = verification.get("apps") if isinstance(verification.get("apps"), list) else []
    independent_apps = {
        str(row.get("app") or ""): row
        for row in independent_rows
        if isinstance(row, dict) and row.get("app")
    }
    if (
        len(independent_apps) != len(independent_rows)
        or set(independent_apps) != set(prereg_apps)
        or verification.get("app_count") != len(independent_apps)
    ):
        errors.append("v4_independent_git_verification_app_set_mismatch")
    required_app = {
        "app",
        "repository_id",
        "origin_repository_id",
        "origin_repository_match",
        "commit",
        "commit_object_base64",
        "commit_object_hash_match",
        "commit_tree",
        "tree_object_reconstruction_match",
        "git_object_format",
        "git_repository_layout",
        "git_fsck_strict_passed",
        "git_fsck_output_sha256",
        "input_mirror_storage_manifest_sha256",
        "private_snapshot_method",
        "private_snapshot_storage_manifest_sha256",
        "storage_stable",
        "source_materialization_receipt_path",
        "source_materialization_receipt_sha256",
        "source_tree_sha256",
        "file_set_sha256",
        "file_count",
        "total_bytes",
        "files",
        "raw_returned",
    }
    for app_name, app in prereg_apps.items():
        row = independent_apps.get(app_name)
        receipt_contract = receipts.get(app_name)
        if row is None or receipt_contract is None:
            errors.append(f"v4_independent_git_verification_app_invalid:{app_name}")
            continue
        receipt_path, receipt_hash, receipt, receipt_rows = receipt_contract
        try:
            commit_raw = base64.b64decode(
                str(row.get("commit_object_base64") or ""),
                validate=True,
            )
            independent_files = _validated_source_file_rows(row.get("files"))
            reconstructed_tree = _reconstruct_git_tree_sha1(independent_files)
        except (ValueError, UnicodeError):
            errors.append(f"v4_independent_git_verification_app_invalid:{app_name}")
            continue
        repository_id = str(app.get("repository_id") or "").casefold()
        first_line = commit_raw.splitlines()[0] if commit_raw else b""
        if (
            set(row) != required_app
            or row.get("repository_id") != repository_id
            or row.get("origin_repository_id") != repository_id
            or row.get("origin_repository_match") is not True
            or row.get("commit") != app.get("commit")
            or _git_object_sha1("commit", commit_raw) != app.get("commit")
            or row.get("commit_object_hash_match") is not True
            or row.get("commit_tree") != app.get("commit_tree")
            or first_line != f"tree {app.get('commit_tree')}".encode("ascii")
            or reconstructed_tree != app.get("commit_tree")
            or row.get("tree_object_reconstruction_match") is not True
            or row.get("git_object_format") != "sha1"
            or row.get("git_repository_layout")
            != "verifier_owned_unlinked_full_bare_sha1_mirror_snapshot"
            or row.get("git_fsck_strict_passed") is not True
            or SHA256_RE.fullmatch(str(row.get("git_fsck_output_sha256") or "")) is None
            or SHA256_RE.fullmatch(
                str(row.get("input_mirror_storage_manifest_sha256") or "")
            )
            is None
            or row.get("private_snapshot_method") != "git_clone_mirror_no_local"
            or SHA256_RE.fullmatch(
                str(row.get("private_snapshot_storage_manifest_sha256") or "")
            )
            is None
            or row.get("storage_stable") is not True
            or row.get("source_materialization_receipt_path") != receipt_path
            or row.get("source_materialization_receipt_sha256") != receipt_hash
            or independent_files != receipt_rows
            or row.get("source_tree_sha256") != receipt.get("source_tree_sha256")
            or row.get("source_tree_sha256") != _source_tree_sha256(independent_files)
            or row.get("file_set_sha256")
            != _independent_file_set_sha256(independent_files)
            or row.get("file_count") != len(independent_files)
            or row.get("total_bytes")
            != sum(file_row["byte_count"] for file_row in independent_files)
            or row.get("raw_returned") is not False
        ):
            errors.append(f"v4_independent_git_verification_app_invalid:{app_name}")
    return sorted(set(errors))


def _v4_report_contract_errors(
    evidence_dir: Path,
    preregistration: dict[str, Any],
    campaign: dict[str, Any],
    queue: dict[str, Any],
    preregistration_path: Path,
) -> list[str]:
    errors: list[str] = []
    bound_policy = RELEASE_BLOCKING_POLICY
    try:
        bound_protocol = validate_bound_protocol(preregistration, preregistration_path)
        expected_runtime = bound_protocol["runtime_environment"]
        bound_manifest = bound_protocol["manifest"]
        bound_policy = str(
            bound_manifest.get("release_blocking_policy")
            or RELEASE_BLOCKING_POLICY
        )
        expected_runtime_receipt_schema = str(
            bound_manifest.get("source_materialization", {}).get(
                "runtime_receipt_schema"
            )
            or ""
        )
        expected_notification_classifier = bound_manifest.get(
            "runtime_environment", {}
        ).get("runtime_notification_classifier")
        expected_native_lock_guard = bound_manifest.get("runtime_environment", {}).get(
            "native_runtime_lock_guard"
        )
        expected_native_prewarm_guard = bound_manifest.get(
            "runtime_environment", {}
        ).get("native_runtime_prewarm_guard")
        expected_object_attestation_guard = bound_manifest.get(
            "runtime_environment", {}
        ).get("runtime_object_attestation_guard")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, KeyError):
        expected_runtime = {}
        expected_runtime_receipt_schema = ""
        expected_notification_classifier = None
        expected_native_lock_guard = None
        expected_native_prewarm_guard = None
        expected_object_attestation_guard = None
        errors.append("v4_runtime_attestation_artifact_invalid")
    prereg_apps = {
        str(row.get("app") or ""): row
        for row in preregistration.get("apps", [])
        if isinstance(row, dict) and row.get("app")
    }
    campaign_rows = campaign.get("apps") if isinstance(campaign.get("apps"), list) else []
    campaign_apps = {
        str(row.get("app") or ""): row
        for row in campaign_rows
        if isinstance(row, dict) and row.get("app")
    }
    if set(campaign_apps) != set(prereg_apps) or len(campaign_apps) != len(campaign_rows):
        errors.append("v4_campaign_app_set_mismatch")

    queue_rows = queue.get("candidates") if isinstance(queue.get("candidates"), list) else []
    queued_by_app: dict[str, list[dict[str, Any]]] = {}
    for row in queue_rows:
        if isinstance(row, dict):
            queued_by_app.setdefault(str(row.get("app") or ""), []).append(row)

    expected_artifacts: set[str] = set()
    expected_runtime_receipts: set[str] = set()
    protocol_execution = (
        campaign.get("holdout_protocol")
        if isinstance(campaign.get("holdout_protocol"), dict)
        else {}
    )
    expected_runtime_sha256 = str(protocol_execution.get("runtime_environment_sha256") or "")
    expected_scanner_sha256 = str(protocol_execution.get("scanner_python_sha256") or "")
    expected_launcher_sha256 = str(protocol_execution.get("runtime_launcher_sha256") or "")
    expected_probe_sha256 = str(protocol_execution.get("runtime_probe_sha256") or "")
    expected_source_probe_sha256 = str(
        protocol_execution.get("source_materialization_probe_sha256") or ""
    )
    for app, prereg_row in prereg_apps.items():
        campaign_row = campaign_apps.get(app)
        if campaign_row is None:
            continue
        for field in (
            "stratum",
            "repository",
            "repository_id",
            "commit",
            "language",
            "stars_at_registration",
            "github_node_id",
            "default_branch",
            "is_fork",
            "fork_parent_repository_id",
            "archived",
            "commit_tree",
            "license_spdx",
        ):
            if campaign_row.get(field) != prereg_row.get(field):
                errors.append(f"v4_campaign_app_binding_mismatch:{app}:{field}")
        if campaign_row.get("commit_tree_match") is not True:
            errors.append(f"v4_campaign_commit_tree_not_verified:{app}")
        runs = campaign_row.get("runs") if isinstance(campaign_row.get("runs"), list) else []
        if len(runs) != 2 or [row.get("run") for row in runs if isinstance(row, dict)] != [1, 2]:
            errors.append(f"v4_report_run_contract_invalid:{app}")
            continue
        reports: list[dict[str, Any]] = []
        report_hashes: list[str] = []
        expected_source_tree = str(campaign_row.get("source_tree_sha256") or "")
        expected_source_file_count = campaign_row.get("tracked_files")
        for run in runs:
            if not isinstance(run, dict):
                errors.append(f"v4_report_run_contract_invalid:{app}")
                continue
            try:
                report, _raw = _load_v4_report_artifact(evidence_dir, run)
            except (OSError, ValueError):
                errors.append(f"v4_report_artifact_invalid:{app}:run{run.get('run')}")
                continue
            expected_artifacts.add(str(run.get("report_artifact_path") or ""))
            receipt_relative = str(run.get("runtime_receipt_path") or "")
            expected_runtime_receipts.add(receipt_relative)
            if not _artifact_hash_matches(
                evidence_dir,
                receipt_relative,
                run.get("runtime_receipt_sha256"),
            ):
                errors.append(f"v4_runtime_receipt_invalid:{app}:run{run.get('run')}")
            else:
                receipt_raw = b""
                try:
                    receipt_path = _safe_evidence_artifact(evidence_dir, receipt_relative)
                    receipt_raw = receipt_path.read_bytes()
                    receipt = json.loads(receipt_raw.decode("utf-8"))
                except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
                    receipt = {}
                if (
                    not isinstance(receipt, dict)
                    or _canonical_report_bytes(receipt) != receipt_raw
                    or receipt.get("schema") != expected_runtime_receipt_schema
                    or receipt.get("passed") is not True
                    or receipt.get("scanner_python_sha256") != expected_scanner_sha256
                    or receipt.get("launcher_sha256") != expected_launcher_sha256
                    or receipt.get("probe_sha256") != expected_probe_sha256
                    or receipt.get("source_probe_sha256") != expected_source_probe_sha256
                    or receipt.get("pre_runtime_sha256") != expected_runtime_sha256
                    or receipt.get("post_runtime_sha256") != expected_runtime_sha256
                    or receipt.get("runtime_mutation_observed") is not False
                    or receipt.get("mutation_event_count") != 0
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and receipt.get("unclassified_notification_count") != 0
                    )
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and receipt.get("runtime_notification_classifier")
                        != expected_notification_classifier
                    )
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and receipt.get("native_runtime_lock_guard")
                        != expected_native_lock_guard
                    )
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and receipt.get("native_runtime_prewarm_guard")
                        != expected_native_prewarm_guard
                    )
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and receipt.get("runtime_object_attestation_guard")
                        != expected_object_attestation_guard
                    )
                    or receipt.get("mutation_monitor_errors") != []
                    or receipt.get("mutation_monitor_liveness_passed") is not True
                    or receipt.get("mutation_guard_canary")
                    != {"before_scan": True, "after_scan": True, "cleanup_passed": True}
                    or not _runtime_monitor_contract_valid(receipt)
                    or not _source_monitor_contract_valid(
                        receipt,
                        expected_tree_sha256=expected_source_tree,
                        expected_file_count=expected_source_file_count,
                    )
                    or not _runtime_execution_contract_valid(
                        receipt,
                        expected_runtime=expected_runtime,
                        launcher_sha256=expected_launcher_sha256,
                        probe_sha256=expected_probe_sha256,
                        source_probe_sha256=expected_source_probe_sha256,
                    )
                    or receipt.get("outside_loaded_modules") != []
                    or receipt.get("scanner_exit_code") != 0
                    or not isinstance(receipt.get("loaded_module_file_count"), int)
                    or receipt.get("loaded_module_file_count", 0) < 1
                    or SHA256_RE.fullmatch(str(receipt.get("loaded_module_set_sha256") or ""))
                    is None
                    or receipt.get("mutation_guard")
                    != "windows_read_directory_changes_overlapped_v2"
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and run.get("runtime_notification_classifier")
                        != expected_notification_classifier
                    )
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and run.get("native_runtime_lock_guard")
                        != expected_native_lock_guard
                    )
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and run.get("native_runtime_prewarm_guard")
                        != expected_native_prewarm_guard
                    )
                    or (
                        expected_runtime_receipt_schema == RUNTIME_RECEIPT_SCHEMA
                        and run.get("runtime_object_attestation_guard")
                        != expected_object_attestation_guard
                    )
                    or receipt.get("output_sha256") != run.get("raw_report_sha256")
                    or run.get("source_tree_sha256") != expected_source_tree
                    or run.get("source_mutation_observed") is not False
                    or receipt.get("raw_returned") is not False
                ):
                    errors.append(f"v4_runtime_receipt_contract_invalid:{app}:run{run.get('run')}")
            reports.append(report)
            report_hashes.append(str(run.get("report_sha256") or ""))
        if len(reports) != 2:
            continue
        if reports[0] != reports[1] or len(set(report_hashes)) != 1:
            errors.append(f"v4_report_repeat_mismatch:{app}")
            continue

        report = reports[0]
        report_hash = report_hashes[0]
        release_blockers = _release_blocking_findings(report, bound_policy)
        eligible = _eligible_release_blocking_findings(report, bound_policy)
        recomputed_candidates = _candidate_rows(
            app,
            report_hash,
            report,
            None,
            bound_policy,
        )
        if queued_by_app.get(app, []) != recomputed_candidates:
            errors.append(f"v4_candidate_census_mismatch:{app}")
        high_critical = [
            finding
            for finding in report.get("findings", [])
            if isinstance(finding, dict) and finding.get("severity") in {"critical", "high"}
        ]
        lane_counts = release_hold_counts_for_policy(
            high_critical,
            bound_policy,
            "high",
        )
        lane_counts["supporting_review_high_critical_count"] = (
            len(high_critical) - lane_counts["blocking_count"]
        )
        expected_campaign_fields = {
            "supported_files": _supported_file_count(report),
            "finding_counts": _finding_counts(report),
            "available_release_blocking_findings": len(release_blockers),
            "eligible_release_blocking_findings": len(eligible),
            "unlocatable_release_blocking_findings": len(release_blockers) - len(eligible),
            "sampled_release_blocking_candidates": len(recomputed_candidates),
            "release_lane_counts": lane_counts,
        }
        for field, expected in expected_campaign_fields.items():
            if campaign_row.get(field) != expected:
                errors.append(f"v4_campaign_report_projection_mismatch:{app}:{field}")

    if set(queued_by_app) - set(prereg_apps):
        errors.append("v4_candidate_unknown_app")
    report_root = evidence_dir / "reports"
    actual_artifacts = (
        {
            path.relative_to(evidence_dir).as_posix()
            for path in report_root.rglob("*.json.gz")
            if path.is_file()
        }
        if report_root.is_dir()
        else set()
    )
    if actual_artifacts != expected_artifacts:
        errors.append("v4_report_artifact_set_mismatch")
    receipt_root = evidence_dir / "runtime-receipts"
    actual_receipts = (
        {
            path.relative_to(evidence_dir).as_posix()
            for path in receipt_root.glob("*.json")
            if path.is_file()
        }
        if receipt_root.is_dir()
        else set()
    )
    if actual_receipts != expected_runtime_receipts:
        errors.append("v4_runtime_receipt_artifact_set_mismatch")

    try:
        snapshot = _safe_evidence_artifact(evidence_dir, campaign.get("preregistration_path"))
        snapshot_bytes = snapshot.read_bytes()
        source_bytes = preregistration_path.read_bytes()
    except (OSError, ValueError):
        errors.append("v4_preregistration_snapshot_missing")
    else:
        if (
            snapshot_bytes != source_bytes
            or hashlib.sha256(snapshot_bytes).hexdigest() != campaign.get("preregistration_sha256")
        ):
            errors.append("v4_preregistration_snapshot_mismatch")
    return sorted(set(errors))


def _v4_protocol_contract_errors(
    preregistration: dict[str, Any],
    preregistration_path: Path,
    campaign: dict[str, Any],
    queue: dict[str, Any],
    labels: dict[str, Any],
) -> list[str]:
    try:
        protocol = validate_bound_protocol(preregistration, preregistration_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return ["v4_holdout_protocol_artifact_invalid"]
    manifest = protocol["manifest"]
    execution = campaign.get("holdout_protocol")
    if not isinstance(execution, dict):
        return ["v4_holdout_protocol_execution_missing"]

    errors: list[str] = []
    expected = {
        "holdout_protocol_schema": manifest.get("schema"),
        "implementation_revision": manifest.get("implementation_revision"),
        "protocol_manifest_sha256": protocol.get("manifest_sha256"),
        "analyzer_package_tree_sha256": manifest.get("analyzer_package_tree_sha256"),
        "wheel_sha256": manifest.get("wheel", {}).get("sha256"),
        "runtime_environment_sha256": manifest.get("runtime_environment", {}).get("sha256"),
        "scanner_python_sha256": manifest.get("runtime_environment", {}).get(
            "scanner_python_sha256"
        ),
        "runtime_launcher_sha256": protocol.get("protocol_files", {}).get(
            "scripts/holdout_scan_launcher.py"
        ),
        "runtime_probe_sha256": protocol.get("protocol_files", {}).get(
            "scripts/holdout_runtime_probe.py"
        ),
        "source_materialization_probe_sha256": protocol.get("protocol_files", {}).get(
            "scripts/holdout_source_materialization.py"
        ),
        "independent_git_verifier_sha256": protocol.get("protocol_files", {}).get(
            "scripts/verify_holdout_git_sources.py"
        ),
        "installed_distribution_set_sha256": manifest.get("runtime_environment", {}).get(
            "installed_distribution_set_sha256"
        ),
        "prefix_tree_sha256": manifest.get("runtime_environment", {}).get(
            "prefix_tree_sha256"
        ),
        "base_runtime_tree_sha256": manifest.get("runtime_environment", {}).get(
            "base_runtime_tree_sha256"
        ),
        "scanner_scaffold_tree_sha256": manifest.get("runtime_environment", {}).get(
            "scanner_scaffold_tree_sha256"
        ),
        "runtime_mutation_guard": manifest.get("runtime_environment", {}).get(
            "runtime_mutation_guard"
        ),
        "runtime_notification_classifier": manifest.get("runtime_environment", {}).get(
            "runtime_notification_classifier"
        ),
        "native_runtime_lock_guard": manifest.get("runtime_environment", {}).get(
            "native_runtime_lock_guard"
        ),
        "native_runtime_prewarm_guard": manifest.get(
            "runtime_environment", {}
        ).get("native_runtime_prewarm_guard"),
        "runtime_object_attestation_guard": manifest.get(
            "runtime_environment", {}
        ).get("runtime_object_attestation_guard"),
        "pip_install_report_sha256": manifest.get("runtime_environment", {})
        .get("pip_install_report", {})
        .get("sha256"),
        "pip_install_artifact_set_sha256": manifest.get("runtime_environment", {})
        .get("pip_install_report", {})
        .get("artifact_set_sha256"),
        "wheelhouse_manifest_sha256": manifest.get("runtime_environment", {})
        .get("wheelhouse", {})
        .get("manifest_sha256"),
        "wheelhouse_artifact_set_sha256": manifest.get("runtime_environment", {})
        .get("wheelhouse", {})
        .get("artifact_set_sha256"),
        "source_metadata_sha256": manifest.get("source_metadata", {}).get("sha256"),
        "release_blocking_policy": manifest.get("release_blocking_policy"),
        "automatic_release_rule_ids": manifest.get("automatic_release_rule_ids"),
        "raw_returned": False,
    }
    for field, value in expected.items():
        if execution.get(field) != value:
            errors.append(f"v4_holdout_protocol_execution_mismatch:{field}")
    execution_revision = str(execution.get("execution_revision") or "")
    if REVISION_RE.fullmatch(execution_revision) is None or campaign.get("source_revision") != execution_revision:
        errors.append("v4_holdout_protocol_execution_revision_invalid")

    committed = execution.get("tracked_artifacts_committed_at_execution_head")
    committed_hashes: set[str] = set()
    committed_paths: set[str] = set()
    if not isinstance(committed, list):
        errors.append("v4_holdout_protocol_committed_artifacts_missing")
    else:
        for row in committed:
            if not isinstance(row, dict):
                errors.append("v4_holdout_protocol_committed_artifact_invalid")
                continue
            path = str(row.get("path") or "")
            digest = str(row.get("sha256") or "")
            if (
                not path
                or path in committed_paths
                or Path(path).is_absolute()
                or ".." in Path(path).parts
                or SHA256_RE.fullmatch(digest) is None
            ):
                errors.append("v4_holdout_protocol_committed_artifact_invalid")
                continue
            committed_paths.add(path)
            committed_hashes.add(digest)
    required_hashes = {
        str(campaign.get("preregistration_sha256") or ""),
        str(protocol.get("manifest_sha256") or ""),
        str(manifest.get("wheel", {}).get("sha256") or ""),
        str(manifest.get("runtime_environment", {}).get("sha256") or ""),
        str(
            manifest.get("runtime_environment", {})
            .get("pip_install_report", {})
            .get("sha256")
            or ""
        ),
        str(
            manifest.get("runtime_environment", {})
            .get("wheelhouse", {})
            .get("manifest_sha256")
            or ""
        ),
        *{
            str(row.get("sha256") or "")
            for row in protocol.get("wheelhouse", {}).get("artifacts", [])
            if isinstance(row, dict)
        },
        str(manifest.get("source_metadata", {}).get("sha256") or ""),
        str(preregistration.get("holdout_integrity", {}).get("exclusion_snapshot_sha256") or ""),
        str(preregistration.get("selection", {}).get("discovery_population_sha256") or ""),
        str(preregistration.get("selection", {}).get("qualification_population_sha256") or ""),
    }
    if preregistration.get("status") == PROTOCOL_RECOVERY_REPLAY_STATUS:
        replay = (
            preregistration.get("replay_provenance")
            if isinstance(preregistration.get("replay_provenance"), dict)
            else {}
        )
        required_hashes.add(
            str(
                replay.get("prior_execution_manifest_sha256")
                or ""
            )
        )
    if (
        any(SHA256_RE.fullmatch(value) is None for value in required_hashes)
        or not required_hashes.issubset(committed_hashes)
    ):
        errors.append("v4_holdout_protocol_committed_artifact_set_incomplete")

    execution_boundary = campaign.get("execution_boundary")
    if (
        not isinstance(execution_boundary, dict)
        or execution_boundary.get("scanner_python_isolated") is not True
        or execution_boundary.get("python_no_site_startup") is not True
        or execution_boundary.get("scanner_python_sha256")
        != manifest.get("runtime_environment", {}).get("scanner_python_sha256")
        or execution_boundary.get("post_execution_runtime_verified") is not True
        or execution_boundary.get("runtime_mutation_guard")
        != manifest.get("runtime_environment", {}).get("runtime_mutation_guard")
        or execution_boundary.get("runtime_notification_classifier")
        != manifest.get("runtime_environment", {}).get("runtime_notification_classifier")
        or execution_boundary.get("native_runtime_lock_guard")
        != manifest.get("runtime_environment", {}).get("native_runtime_lock_guard")
        or execution_boundary.get("native_runtime_prewarm_guard")
        != manifest.get("runtime_environment", {}).get(
            "native_runtime_prewarm_guard"
        )
        or execution_boundary.get("runtime_object_attestation_guard")
        != manifest.get("runtime_environment", {}).get(
            "runtime_object_attestation_guard"
        )
        or (
            manifest.get("schema") == CURRENT_PROTOCOL_SCHEMA
            and execution_boundary.get("runtime_actual_mutation_event_count_required") != 0
        )
        or execution_boundary.get("runtime_launcher_sha256")
        != protocol.get("protocol_files", {}).get("scripts/holdout_scan_launcher.py")
        or execution_boundary.get("runtime_probe_sha256")
        != protocol.get("protocol_files", {}).get("scripts/holdout_runtime_probe.py")
        or execution_boundary.get("source_materialization_probe_sha256")
        != protocol.get("protocol_files", {}).get("scripts/holdout_source_materialization.py")
        or execution_boundary.get("git_blob_exact_materialization_required") is not True
        or execution_boundary.get("source_pre_post_tree_match_required") is not True
        or execution_boundary.get("source_mutation_event_count_required") != 0
        or execution_boundary.get("independent_git_verifier_sha256")
        != protocol.get("protocol_files", {}).get("scripts/verify_holdout_git_sources.py")
        or execution_boundary.get("independent_git_verification_post_campaign_required") is not True
    ):
        errors.append("v4_holdout_isolated_scanner_execution_invalid")

    manifest_hash = protocol["manifest_sha256"]
    if any(
        payload.get("holdout_protocol_manifest_sha256") != manifest_hash
        for payload in (queue, labels)
    ):
        errors.append("v4_holdout_protocol_downstream_binding_invalid")
    return sorted(set(errors))


def _v4_review_contract_errors(
    evidence_dir: Path,
    preregistration: dict[str, Any],
    queue: dict[str, Any],
    labels: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    queue_path = evidence_dir / "candidate-queue.json"
    try:
        queue_hash = hashlib.sha256(queue_path.read_bytes()).hexdigest()
    except OSError:
        return ["v4_candidate_queue_artifact_missing"]
    queue_rows = queue.get("candidates") if isinstance(queue.get("candidates"), list) else []
    binding_hash = candidate_bindings_sha256(queue_rows)
    queued_ids = {
        str(row.get("candidate_id") or "")
        for row in queue_rows
        if isinstance(row, dict) and row.get("candidate_id")
    }
    locked_review = (
        preregistration.get("locked_review")
        if isinstance(preregistration.get("locked_review"), dict)
        else {}
    )
    required_vendors = set(locked_review.get("required_vendors") or [])
    reviewer_rows = labels.get("reviewers") if isinstance(labels.get("reviewers"), list) else []
    if len(reviewer_rows) != int(locked_review.get("required_reviewer_count") or 0):
        errors.append("v4_reviewer_count_invalid")
    vendors: set[str] = set()
    sessions: set[str] = set()
    responses: set[str] = set()
    reviewer_decisions: dict[str, dict[str, dict[str, str]]] = {}
    for reviewer in reviewer_rows:
        if not isinstance(reviewer, dict):
            errors.append("v4_reviewer_row_invalid")
            continue
        vendor = str(reviewer.get("vendor") or "")
        session_id = str(reviewer.get("session_id") or "")
        response_id = str(reviewer.get("response_id") or "")
        reviewer_ref = str(reviewer.get("reviewer_ref") or "")
        if (
            vendor not in required_vendors
            or vendor in vendors
            or not session_id
            or session_id in sessions
            or not response_id
            or response_id in responses
        ):
            errors.append("v4_reviewer_identity_invalid")
        vendors.add(vendor)
        sessions.add(session_id)
        responses.add(response_id)
        for path_field, hash_field in (
            ("review_file_path", "review_file_sha256"),
            ("prompt_artifact_path", "prompt_sha256"),
            ("response_artifact_path", "response_sha256"),
        ):
            if not _artifact_hash_matches(evidence_dir, reviewer.get(path_field), reviewer.get(hash_field)):
                errors.append(f"v4_reviewer_artifact_invalid:{vendor}:{path_field}")
        try:
            review_path = _safe_evidence_artifact(evidence_dir, reviewer.get("review_file_path"))
            review_payload = json.loads(review_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            errors.append(f"v4_review_file_invalid:{vendor}")
            continue
        if not isinstance(review_payload, dict):
            errors.append(f"v4_review_file_invalid:{vendor}")
            continue
        expected_reviewer = {
            "reviewer_alias": review_payload.get("reviewer_alias"),
            "reviewer_kind": review_payload.get("reviewer_kind"),
            "vendor": review_payload.get("vendor"),
            "model": review_payload.get("model"),
            "session_id": review_payload.get("session_id"),
            "response_id": review_payload.get("response_id"),
            "reviewer_ref": "sha256:" + _canonical_payload_sha256(review_payload),
            "prompt_artifact_path": review_payload.get("prompt_artifact_path"),
            "prompt_sha256": review_payload.get("prompt_sha256"),
            "response_artifact_path": review_payload.get("response_artifact_path"),
            "response_sha256": review_payload.get("response_sha256"),
            "candidate_queue_sha256": review_payload.get("candidate_queue_sha256"),
            "candidate_bindings_sha256": review_payload.get("candidate_bindings_sha256"),
        }
        for field, expected in expected_reviewer.items():
            if reviewer.get(field) != expected:
                errors.append(f"v4_reviewer_projection_mismatch:{vendor}:{field}")
        if (
            review_payload.get("schema") != REVIEW_SCHEMA
            or review_payload.get("raw_returned") is not False
            or review_payload.get("campaign_id") != queue.get("campaign_id")
            or review_payload.get("source_revision") != queue.get("source_revision")
            or review_payload.get("analyzer_package_tree_sha256")
            != queue.get("analyzer_package_tree_sha256")
            or review_payload.get("holdout_protocol_manifest_sha256")
            != queue.get("holdout_protocol_manifest_sha256")
            or review_payload.get("candidate_queue_sha256") != queue_hash
            or review_payload.get("candidate_bindings_sha256") != binding_hash
        ):
            errors.append(f"v4_review_binding_invalid:{vendor}")
        review_candidates = (
            review_payload.get("candidates")
            if isinstance(review_payload.get("candidates"), list)
            else []
        )
        decisions: dict[str, dict[str, str]] = {}
        for decision in review_candidates:
            if not isinstance(decision, dict):
                continue
            candidate_id = str(decision.get("candidate_id") or "")
            if candidate_id and candidate_id not in decisions:
                decisions[candidate_id] = {
                    "label": str(decision.get("label") or ""),
                    "rationale": str(decision.get("rationale") or ""),
                }
        if set(decisions) != queued_ids:
            errors.append(f"v4_review_coverage_invalid:{vendor}")
        reviewer_decisions[reviewer_ref] = decisions
    if vendors != required_vendors or required_vendors != REQUIRED_VENDORS:
        errors.append("v4_reviewer_vendor_set_invalid")

    label_rows = labels.get("candidates") if isinstance(labels.get("candidates"), list) else []
    for row in label_rows:
        if not isinstance(row, dict):
            continue
        candidate_id = str(row.get("candidate_id") or "")
        reviews = row.get("reviews") if isinstance(row.get("reviews"), list) else []
        for review in reviews:
            if not isinstance(review, dict):
                continue
            reviewer_ref = str(review.get("reviewer_ref") or "")
            expected = reviewer_decisions.get(reviewer_ref, {}).get(candidate_id)
            if expected is None or review.get("label") != expected["label"] or review.get("rationale") != expected["rationale"]:
                errors.append(f"v4_label_review_projection_mismatch:{candidate_id}")

    provenance = labels.get("review_provenance") if isinstance(labels.get("review_provenance"), dict) else {}
    if (
        provenance.get("cross_vendor_review") is not True
        or provenance.get("required_vendors") != sorted(REQUIRED_VENDORS)
        or provenance.get("distinct_vendor_count") != 3
        or provenance.get("same_provider_model_family_ai_only") is not False
        or provenance.get("not_cross_vendor_review") is not False
        or provenance.get("not_human_review") is not True
        or provenance.get("candidate_bindings_sha256") != binding_hash
        or provenance.get("candidate_queue_sha256") != queue_hash
    ):
        errors.append("v4_review_provenance_invalid")
    return sorted(set(errors))


def build_status(evidence_dir: Path, preregistration_path: Path) -> dict[str, Any]:
    preregistration = _read_json(preregistration_path)
    campaign = _read_json(evidence_dir / "campaign.json")
    queue = _read_json(evidence_dir / "candidate-queue.json")
    labels = _read_json(evidence_dir / "candidate-labels.json")
    errors: list[str] = []
    for payload, schema, name in (
        (preregistration, PREREGISTRATION_SCHEMA, "preregistration"),
        (campaign, CAMPAIGN_SCHEMA, "campaign"),
        (queue, QUEUE_SCHEMA, "candidate_queue"),
        (labels, LABEL_SCHEMA, "candidate_labels"),
    ):
        if payload.get("schema") != schema:
            errors.append(f"{name}_schema_invalid")
        if payload.get("raw_returned") is not False:
            errors.append(f"{name}_raw_boundary_invalid")
    try:
        _validate_preregistration(preregistration, preregistration_path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        errors.append("preregistration_contract_invalid")
    if preregistration.get("qualification_contract") == "release_blocker_actionability_v4":
        errors.extend(
            _v4_protocol_contract_errors(
                preregistration,
                preregistration_path,
                campaign,
                queue,
                labels,
            )
        )
        errors.extend(
            _v4_report_contract_errors(
                evidence_dir,
                preregistration,
                campaign,
                queue,
                preregistration_path,
            )
        )
        errors.extend(
            _v4_source_provenance_errors(
                evidence_dir,
                preregistration,
                preregistration_path,
                campaign,
            )
        )
        errors.extend(_v4_review_contract_errors(evidence_dir, preregistration, queue, labels))
        expected_boundary = preregistration.get("claim_boundary", {})
        if any(
            payload.get("claim_boundary") != expected_boundary
            for payload in (campaign, queue, labels)
        ):
            errors.append("v4_claim_boundary_binding_invalid")
        if preregistration.get("status") == PROTOCOL_RECOVERY_REPLAY_STATUS:
            expected_qualification_boundary = (
                protocol_recovery_qualification_boundary(preregistration)
            )
            if any(
                payload.get("qualification_boundary")
                != expected_qualification_boundary
                for payload in (campaign, queue, labels)
            ):
                errors.append("v4_recovery_qualification_boundary_invalid")
            campaign_contract = (
                campaign.get("release_decision_contract")
                if isinstance(campaign.get("release_decision_contract"), dict)
                else {}
            )
            candidate_population = (
                queue.get("candidate_population")
                if isinstance(queue.get("candidate_population"), dict)
                else {}
            )
            if (
                campaign_contract.get("release_qualification_allowed")
                is not False
                or candidate_population.get("release_qualification_allowed")
                is not False
            ):
                errors.append("v4_recovery_release_authority_invalid")

    campaign_id = str(preregistration.get("campaign_id") or "")
    if not campaign_id or any(payload.get("campaign_id") != campaign_id for payload in (campaign, queue, labels)):
        errors.append("campaign_binding_invalid")
    analyzer_tree = str(preregistration.get("analyzer_package_tree_sha256") or "")
    if SHA256_RE.fullmatch(analyzer_tree) is None or any(
        payload.get("analyzer_package_tree_sha256") != analyzer_tree for payload in (campaign, queue, labels)
    ):
        errors.append("analyzer_tree_binding_invalid")

    locked_execution = (
        preregistration.get("locked_execution")
        if isinstance(preregistration.get("locked_execution"), dict)
        else {}
    )
    locked_policy = locked_execution.get("release_blocking_policy")
    if preregistration.get("qualification_contract") in {
        "release_blocker_actionability_v2",
        "release_blocker_actionability_v3",
        "release_blocker_actionability_v4",
    }:
        if (
            preregistration.get("status") == "locked_before_scanner_execution"
            and automatic_release_rules_for_policy(str(locked_policy or ""))
            is None
        ):
            errors.append("release_blocking_policy_not_preregistered")
    if locked_policy is not None:
        campaign_contract = (
            campaign.get("release_decision_contract")
            if isinstance(campaign.get("release_decision_contract"), dict)
            else {}
        )
        candidate_population = (
            queue.get("candidate_population")
            if isinstance(queue.get("candidate_population"), dict)
            else {}
        )
        if (
            automatic_release_rules_for_policy(str(locked_policy)) is None
            or campaign_contract.get("blocking_policy") != locked_policy
            or candidate_population.get("blocking_policy") != locked_policy
            or candidate_population.get("lane") != "release_blocking"
            or candidate_population.get("excluded_holds_still_fail_closed") is not True
        ):
            errors.append("release_blocking_policy_binding_invalid")
    thresholds = (
        preregistration.get("locked_thresholds")
        if isinstance(preregistration.get("locked_thresholds"), dict)
        else {}
    )
    app_rows = campaign.get("apps") if isinstance(campaign.get("apps"), list) else []
    preregistered_repository_ids = {
        str(row.get("app") or ""): str(row.get("repository_id") or "")
        for row in preregistration.get("apps", [])
        if isinstance(row, dict)
    }
    apps: set[str] = set()
    app_strata: dict[str, str] = {}
    strata: Counter[str] = Counter()
    exact_repeat = 0
    report_hashes: dict[str, str] = {}
    campaign_blocker_counts: dict[str, tuple[int, int, int]] = {}
    for row in app_rows:
        if not isinstance(row, dict):
            errors.append("app_row_invalid")
            continue
        app = str(row.get("app") or "")
        if not app or app in apps:
            errors.append(f"app_identity_invalid:{app or 'missing'}")
            continue
        apps.add(app)
        stratum = str(row.get("stratum") or "")
        app_strata[app] = stratum
        strata[stratum] += 1
        if preregistration.get("qualification_contract") == "release_blocker_actionability_v4":
            expected_repository_id = preregistered_repository_ids.get(app)
            if not _v4_origin_binding_valid(row, expected_repository_id):
                errors.append(f"campaign_origin_binding_invalid:{app}")
        blocker_fields = (
            "available_release_blocking_findings",
            "eligible_release_blocking_findings",
            "unlocatable_release_blocking_findings",
        )
        if all(field in row for field in blocker_fields):
            total_blockers, eligible_blockers, unlocatable_blockers = (
                int(row.get(field) or 0) for field in blocker_fields
            )
            if (
                min(total_blockers, eligible_blockers, unlocatable_blockers) < 0
                or total_blockers != eligible_blockers + unlocatable_blockers
            ):
                errors.append(f"campaign_blocker_population_invalid:{app}")
            campaign_blocker_counts[app] = (
                total_blockers,
                eligible_blockers,
                unlocatable_blockers,
            )
            if locked_policy is not None:
                lane_counts = (
                    row.get("release_lane_counts")
                    if isinstance(row.get("release_lane_counts"), dict)
                    else {}
                )
                finding_counts = row.get("finding_counts") if isinstance(row.get("finding_counts"), dict) else {}
                automatic = int(lane_counts.get("automatic_release_blocking_count") or 0)
                manual = int(lane_counts.get("manual_review_hold_count") or 0)
                integrity = int(lane_counts.get("policy_integrity_hold_count") or 0)
                blocking = int(lane_counts.get("blocking_count") or 0)
                supporting = int(lane_counts.get("supporting_review_high_critical_count") or 0)
                high_critical = int(finding_counts.get("critical") or 0) + int(finding_counts.get("high") or 0)
                if (
                    automatic != total_blockers
                    or blocking != automatic + manual + integrity
                    or blocking + supporting != high_critical
                ):
                    errors.append(f"campaign_release_lane_population_invalid:{app}")
        runs = row.get("runs") if isinstance(row.get("runs"), list) else []
        hashes = [str(value.get("report_sha256") or "") for value in runs if isinstance(value, dict)]
        exits = [value.get("exit_code") for value in runs if isinstance(value, dict)]
        if len(runs) < 2 or any(SHA256_RE.fullmatch(value) is None for value in hashes):
            errors.append(f"repeat_run_invalid:{app}")
        elif len(set(hashes)) != 1 or any(value != 0 for value in exits):
            errors.append(f"repeat_execution_invalid:{app}")
        else:
            report_hashes[app] = hashes[0]
            if row.get("exact_repeat") is True:
                exact_repeat += 1
            else:
                errors.append(f"exact_repeat_flag_invalid:{app}")

    queue_rows = queue.get("candidates") if isinstance(queue.get("candidates"), list) else []
    queued: dict[str, dict[str, Any]] = {}
    sampled_actual: Counter[str] = Counter()
    candidate_rule_counts: Counter[str] = Counter()
    apps_with_candidates: set[str] = set()
    for row in queue_rows:
        if not isinstance(row, dict):
            errors.append("candidate_queue_row_invalid")
            continue
        candidate_id = str(row.get("candidate_id") or "")
        app = str(row.get("app") or "")
        if not candidate_id or candidate_id in queued:
            errors.append(f"candidate_queue_identity_invalid:{candidate_id or 'missing'}")
            continue
        queued[candidate_id] = row
        sampled_actual[app] += 1
        apps_with_candidates.add(app)
        candidate_rule_counts[str(row.get("rule_id") or "")] += 1
        if app not in apps or row.get("severity") not in {"high", "critical"}:
            errors.append(f"candidate_queue_binding_invalid:{candidate_id}")
        if row.get("scan_report_sha256") != report_hashes.get(app):
            errors.append(f"candidate_queue_report_invalid:{candidate_id}")

    sampling = queue.get("sampling") if isinstance(queue.get("sampling"), dict) else {}
    sampling_mode = str(sampling.get("mode") or "quota_three_per_app")
    if sampling_mode not in {"quota_three_per_app", "all_eligible_release_blockers"}:
        errors.append("candidate_sampling_mode_invalid")
    target = int(sampling.get("target_per_app") or 0)
    available = sampling.get("available_by_app") if isinstance(sampling.get("available_by_app"), dict) else {}
    all_available = (
        sampling.get("all_release_blockers_by_app")
        if isinstance(sampling.get("all_release_blockers_by_app"), dict)
        else {}
    )
    sampled = sampling.get("sampled_by_app") if isinstance(sampling.get("sampled_by_app"), dict) else {}
    unlocatable = (
        sampling.get("unlocatable_by_app")
        if isinstance(sampling.get("unlocatable_by_app"), dict)
        else {}
    )
    unlocatable_count = 0
    sampled_correctly = 0
    for app in apps:
        available_count = int(available.get(app, -1))
        if sampling_mode == "all_eligible_release_blockers":
            expected = available_count
        else:
            expected = min(target, available_count) if target > 0 else -1
        if int(sampled.get(app, -1)) == expected and sampled_actual[app] == expected:
            sampled_correctly += 1
        else:
            errors.append(f"candidate_sampling_invalid:{app}")
        missing_location = int(unlocatable.get(app, 0))
        if missing_location < 0:
            errors.append(f"unlocatable_candidate_count_invalid:{app}")
        else:
            unlocatable_count += missing_location
        campaign_counts = campaign_blocker_counts.get(app)
        if campaign_counts is not None and (
            int(all_available.get(app, -1)) != campaign_counts[0]
            or available_count != campaign_counts[1]
            or missing_location != campaign_counts[2]
        ):
            errors.append(f"candidate_population_binding_invalid:{app}")

    reviewer_rows = labels.get("reviewers") if isinstance(labels.get("reviewers"), list) else []
    reviewers: set[str] = set()
    reviewer_vendors: set[str] = set()
    for row in reviewer_rows:
        if not isinstance(row, dict):
            errors.append("reviewer_row_invalid")
            continue
        reviewer_ref = str(row.get("reviewer_ref") or "")
        if REVIEWER_RE.fullmatch(reviewer_ref) is None or reviewer_ref in reviewers:
            errors.append("reviewer_identity_invalid")
        else:
            reviewers.add(reviewer_ref)
        vendor = str(row.get("vendor") or "")
        if vendor:
            reviewer_vendors.add(vendor)

    label_rows = labels.get("candidates") if isinstance(labels.get("candidates"), list) else []
    labeled: set[str] = set()
    label_counts: Counter[str] = Counter()
    agreement_counts: Counter[str] = Counter()
    app_label_counts: Counter[str] = Counter()
    app_true_positive_counts: Counter[str] = Counter()
    individual_label_counts: Counter[str] = Counter()
    for row in label_rows:
        if not isinstance(row, dict):
            errors.append("candidate_label_row_invalid")
            continue
        candidate_id = str(row.get("candidate_id") or "")
        queued_row = queued.get(candidate_id)
        if queued_row is None or candidate_id in labeled:
            errors.append(f"candidate_label_identity_invalid:{candidate_id or 'missing'}")
            continue
        labeled.add(candidate_id)
        for field in (
            "redacted_fingerprint",
            "app",
            "severity",
            "confidence",
            "rule_id",
            "detector_subtype",
            "source_location",
            "artifact_scope",
            "scan_report_sha256",
        ):
            if row.get(field) != queued_row.get(field):
                errors.append(f"candidate_label_binding_invalid:{candidate_id}:{field}")
        reviews = row.get("reviews") if isinstance(row.get("reviews"), list) else []
        if len(reviews) != 3:
            errors.append(f"candidate_review_count_invalid:{candidate_id}")
        seen_reviewers: set[str] = set()
        for review in reviews:
            if not isinstance(review, dict):
                errors.append(f"candidate_review_row_invalid:{candidate_id}")
                continue
            reviewer_ref = str(review.get("reviewer_ref") or "")
            label = str(review.get("label") or "")
            if reviewer_ref not in reviewers or reviewer_ref in seen_reviewers:
                errors.append(f"candidate_reviewer_binding_invalid:{candidate_id}")
            seen_reviewers.add(reviewer_ref)
            if label not in ALLOWED_LABELS or not str(review.get("rationale") or "").strip():
                errors.append(f"candidate_review_invalid:{candidate_id}:{reviewer_ref}")
            else:
                individual_label_counts[label] += 1
        label, agreement = _majority(reviews)
        if row.get("label") != label or row.get("agreement") != agreement or agreement not in ALLOWED_AGREEMENTS:
            errors.append(f"candidate_adjudication_invalid:{candidate_id}")
        else:
            label_counts[label] += 1
            agreement_counts[agreement] += 1
            app = str(row.get("app") or "")
            app_label_counts[app] += 1
            if label == "true_positive":
                app_true_positive_counts[app] += 1
    if labeled != set(queued):
        errors.append("candidate_label_coverage_invalid")

    app_count = len(apps)
    candidate_count = len(queued)
    tp = label_counts["true_positive"]
    fp = label_counts["false_positive"]
    evaluable = tp + fp
    tp_fp_only_precision = _ratio(tp, evaluable)
    tp_fp_only_precision_lower = _wilson_lower(tp, evaluable)
    blocker_actionability = _ratio(tp, candidate_count)
    blocker_actionability_lower = _wilson_lower(tp, candidate_count)
    non_actionable_blockers = candidate_count - tp
    fully_actionable_apps = {
        app
        for app in apps_with_candidates
        if app_label_counts[app] > 0 and app_true_positive_counts[app] == app_label_counts[app]
    }
    candidate_app_count = len(apps_with_candidates)
    fully_actionable_app_count = len(fully_actionable_apps)
    fully_actionable_app_rate = _ratio(fully_actionable_app_count, candidate_app_count)
    fully_actionable_app_lower = _wilson_lower(fully_actionable_app_count, candidate_app_count)
    repeat_rate = _ratio(exact_repeat, app_count)
    sample_coverage = _ratio(sampled_correctly, app_count)
    label_coverage = _ratio(len(labeled), candidate_count)
    unanimous_rate = _ratio(agreement_counts["unanimous"], candidate_count)
    inconclusive_rate = _ratio(label_counts["inconclusive"], candidate_count)
    individual_review_count = sum(individual_label_counts.values())
    individual_inconclusive_rate = _ratio(
        individual_label_counts["inconclusive"],
        individual_review_count,
    )
    distinct_blocker_rule_count = len(candidate_rule_counts)
    single_rule_candidate_share = _ratio(
        max(candidate_rule_counts.values(), default=0),
        candidate_count,
    )
    strata_with_candidates = {
        app_strata[app]
        for app in apps_with_candidates
        if app in app_strata and app_strata[app]
    }

    blockers: list[str] = []
    if errors:
        blockers.append("field_campaign_contract_invalid")
    if preregistration.get("status") == PROTOCOL_RECOVERY_REPLAY_STATUS:
        blockers.append("protocol_recovery_replay_nonqualifying")
    if app_count < int(thresholds.get("minimum_app_count") or 0):
        blockers.append("app_count_below_locked_minimum")
    minimum_stratum = int(thresholds.get("minimum_stratum_count") or 0)
    if any(strata[name] < minimum_stratum for name in ("top", "mid", "long_tail")):
        blockers.append("stratum_count_below_locked_minimum")
    if "minimum_blocker_candidates" in thresholds:
        if candidate_count < int(thresholds.get("minimum_blocker_candidates") or 0):
            blockers.append("blocker_candidate_count_below_locked_minimum")
    elif evaluable < int(thresholds.get("minimum_evaluable_candidates") or 0):
        blockers.append("evaluable_candidate_count_below_locked_minimum")
    if distinct_blocker_rule_count < int(thresholds.get("minimum_distinct_blocker_rule_ids") or 0):
        blockers.append("blocker_rule_diversity_below_locked_minimum")
    if len(apps_with_candidates) < int(thresholds.get("minimum_apps_with_blocker_candidates") or 0):
        blockers.append("blocker_app_diversity_below_locked_minimum")
    if len(strata_with_candidates) < int(thresholds.get("minimum_strata_with_blocker_candidates") or 0):
        blockers.append("blocker_stratum_diversity_below_locked_minimum")
    if "maximum_single_rule_candidate_share" in thresholds and single_rule_candidate_share > float(
        thresholds.get("maximum_single_rule_candidate_share") or 0
    ):
        blockers.append("single_rule_candidate_share_above_locked_maximum")
    if repeat_rate < float(thresholds.get("required_exact_repeat_rate") or 0):
        blockers.append("repeatability_below_locked_minimum")
    if sample_coverage < float(thresholds.get("required_candidate_sample_coverage") or 0):
        blockers.append("candidate_sampling_below_locked_minimum")
    if "maximum_unlocatable_release_blockers" in thresholds and unlocatable_count > int(
        thresholds.get("maximum_unlocatable_release_blockers") or 0
    ):
        blockers.append("unlocatable_release_blockers_above_locked_maximum")
    if label_coverage < float(thresholds.get("required_candidate_label_coverage") or 0):
        blockers.append("candidate_label_coverage_below_locked_minimum")
    required_reviewer_count = int(
        (
            preregistration.get("locked_review")
            if isinstance(preregistration.get("locked_review"), dict)
            else {}
        ).get("required_reviewer_count")
        or 3
    )
    if len(reviewers) < required_reviewer_count:
        blockers.append("reviewer_count_below_locked_minimum")
    if preregistration.get("qualification_contract") == "release_blocker_actionability_v4":
        if len(reviewers) != required_reviewer_count:
            blockers.append("reviewer_count_not_locked_exact")
        required_vendor_count = len(
            (
                preregistration.get("locked_review")
                if isinstance(preregistration.get("locked_review"), dict)
                else {}
            ).get("required_vendors")
            or []
        )
        if len(reviewer_vendors) != required_vendor_count:
            blockers.append("reviewer_vendor_count_below_locked_minimum")
    if unanimous_rate < float(thresholds.get("minimum_reviewer_unanimous_rate") or 0):
        blockers.append("reviewer_unanimity_below_locked_minimum")
    if inconclusive_rate > float(thresholds.get("maximum_inconclusive_rate") or 0):
        blockers.append("inconclusive_rate_above_locked_maximum")
    if (
        "maximum_individual_inconclusive_rate" in thresholds
        and individual_inconclusive_rate
        > float(thresholds.get("maximum_individual_inconclusive_rate") or 0)
    ):
        blockers.append("individual_inconclusive_rate_above_locked_maximum")
    minimum_actionability = float(
        thresholds.get(
            "minimum_blocker_actionability",
            thresholds.get("minimum_adjudicated_precision") or 0,
        )
    )
    minimum_actionability_lower = float(
        thresholds.get(
            "minimum_blocker_actionability_wilson_95_lower",
            thresholds.get("minimum_adjudicated_precision_wilson_95_lower") or 0,
        )
    )
    if blocker_actionability < minimum_actionability:
        blockers.append("blocker_actionability_below_locked_minimum")
    if blocker_actionability_lower < minimum_actionability_lower:
        blockers.append("blocker_actionability_wilson_lower_below_locked_minimum")
    if "minimum_fully_actionable_app_rate" in thresholds and fully_actionable_app_rate < float(
        thresholds.get("minimum_fully_actionable_app_rate") or 0
    ):
        blockers.append("fully_actionable_app_rate_below_locked_minimum")
    if (
        "minimum_fully_actionable_app_wilson_95_lower" in thresholds
        and fully_actionable_app_lower
        < float(thresholds.get("minimum_fully_actionable_app_wilson_95_lower") or 0)
    ):
        blockers.append("fully_actionable_app_wilson_lower_below_locked_minimum")

    qualified = not blockers
    return {
        "schema": STATUS_SCHEMA,
        "campaign_id": campaign_id,
        "analyzer_package_tree_sha256": analyzer_tree,
        "integrity_passed": not errors,
        "qualified": qualified,
        "verdict": "pass" if qualified else "hold",
        "metrics": {
            "app_count": app_count,
            "stratum_counts": dict(sorted(strata.items())),
            "exact_repeat_app_count": exact_repeat,
            "exact_repeat_rate": repeat_rate,
            "candidate_count": candidate_count,
            "distinct_blocker_rule_count": distinct_blocker_rule_count,
            "candidate_rule_counts": dict(sorted(candidate_rule_counts.items())),
            "single_rule_candidate_share": single_rule_candidate_share,
            "apps_with_blocker_candidates": len(apps_with_candidates),
            "fully_actionable_blocker_app_count": fully_actionable_app_count,
            "fully_actionable_blocker_app_rate": fully_actionable_app_rate,
            "fully_actionable_blocker_app_wilson_95_lower": fully_actionable_app_lower,
            "strata_with_blocker_candidates": sorted(strata_with_candidates),
            "evaluable_candidate_count": evaluable,
            "candidate_label_counts": dict(sorted(label_counts.items())),
            "actionable_blocker_count": tp,
            "non_actionable_blocker_count": non_actionable_blockers,
            "blocker_actionability": blocker_actionability,
            "blocker_actionability_wilson_95_lower": blocker_actionability_lower,
            "candidate_sample_coverage": sample_coverage,
            "candidate_sampling_mode": sampling_mode,
            "unlocatable_release_blocker_count": unlocatable_count,
            "candidate_label_coverage": label_coverage,
            "reviewer_count": len(reviewers),
            "reviewer_vendor_count": len(reviewer_vendors),
            "reviewer_vendors": sorted(reviewer_vendors),
            "reviewer_unanimous_rate": unanimous_rate,
            "inconclusive_rate": inconclusive_rate,
            "individual_review_count": individual_review_count,
            "individual_review_label_counts": dict(sorted(individual_label_counts.items())),
            "individual_inconclusive_rate": individual_inconclusive_rate,
            "adjudicated_precision_tp_fp_only": tp_fp_only_precision,
            "adjudicated_precision_tp_fp_only_wilson_95_lower": tp_fp_only_precision_lower,
        },
        "metric_contract": {
            "release_blocker_actionability_denominator": "all_labeled_release_blockers",
            "benign_counts_as_non_actionable": True,
            "inconclusive_counts_as_non_actionable": True,
            "tp_fp_only_precision_is_diagnostic_only": True,
            "fully_actionable_app_success": "every automatic blocker in the app is labeled true_positive",
            "fully_actionable_app_denominator": "apps with one or more automatic release blockers",
            "individual_inconclusive_denominator": "all independent reviewer decisions before majority adjudication",
        },
        "thresholds": thresholds,
        "blockers": blockers,
        "validation_errors": sorted(set(errors)),
        "claim_boundary": preregistration.get("claim_boundary", {}),
        "qualification_boundary": protocol_recovery_qualification_boundary(
            preregistration
        ),
        "raw_returned": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score a preregistered public field-like campaign.")
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--require-qualified",
        action="store_true",
        help="Compatibility flag; qualification is fail-closed by default.",
    )
    mode.add_argument(
        "--integrity-only",
        action="store_true",
        help="Check evidence integrity without treating a HOLD verdict as a process failure.",
    )
    args = parser.parse_args()
    status = build_status(args.evidence_dir, args.preregistration)
    output = args.output or args.evidence_dir / "effectiveness-status.json"
    output.write_text(json.dumps(status, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: status[key] for key in ("integrity_passed", "qualified", "verdict", "blockers")}, ensure_ascii=False))
    required = status["integrity_passed"] if args.integrity_only else status["qualified"]
    return 0 if required else 1


if __name__ == "__main__":
    raise SystemExit(main())
