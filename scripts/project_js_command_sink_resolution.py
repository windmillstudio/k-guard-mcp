from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for candidate in (str(ROOT), str(SRC)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from k_guard_mcp.collector import read_text  # noqa: E402
from k_guard_mcp.hashing import evidence_hash, evidence_hash_scheme  # noqa: E402
from k_guard_mcp.scanner import KGuardScanner  # noqa: E402
from k_guard_mcp.release_policy import release_lane  # noqa: E402
from k_guard_mcp.taint import JS_TS_SUFFIXES  # noqa: E402
from scripts.evidence_tree import package_tree_sha256  # noqa: E402


RULE_ID = "WEB_UNTRUSTED_INPUT_TO_COMMAND"
AFFECTED_SUBTYPES = frozenset(
    {"direct_request_to_command", "js_ts_bounded_request_to_command"}
)
ACCEPTED_LABELS = frozenset(
    {"true_positive", "false_positive", "benign", "inconclusive"}
)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _wilson_lower(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 0.0
    proportion = successes / total
    denominator = 1 + z * z / total
    center = proportion + z * z / (2 * total)
    margin = z * math.sqrt(
        (proportion * (1 - proportion) + z * z / (4 * total)) / total
    )
    return (center - margin) / denominator


def _evidence_value(evidence: str, key: str) -> str | None:
    match = re.search(rf"(?:^|\s){re.escape(key)}=([^\s]+)", evidence)
    return match.group(1) if match else None


def _candidate_location(candidate: dict[str, Any]) -> tuple[str, int]:
    raw = str(candidate.get("source_location") or "")
    location, separator, line = raw.rpartition(":")
    if not separator or not location or not line.isdigit():
        raise ValueError(f"invalid source_location: {raw!r}")
    return location.replace("\\", "/"), int(line)


def _safe_campaign_artifact(campaign_dir: Path, relative: str) -> Path:
    if not relative:
        raise ValueError("campaign artifact path missing")
    base = campaign_dir.resolve()
    candidate = campaign_dir / relative
    if candidate.is_symlink():
        raise ValueError(f"campaign artifact uses a symlink: {relative}")
    resolved = candidate.resolve()
    if resolved != base and base not in resolved.parents:
        raise ValueError(f"campaign artifact escapes evidence root: {relative}")
    if not resolved.is_file():
        raise ValueError(f"campaign artifact missing: {relative}")
    return resolved


def _workspace_relative_path(raw: str | None, app_root: Path) -> str | None:
    value = str(raw or "").replace("\\", "/")
    if value.startswith("<workspace>/"):
        relative = value[len("<workspace>/") :]
    elif value == "<workspace>":
        return None
    else:
        candidate = Path(str(raw or ""))
        if candidate.is_absolute():
            try:
                relative = candidate.resolve().relative_to(app_root.resolve()).as_posix()
            except ValueError as exc:
                raise ValueError(
                    f"finding path escapes app root: {value}"
                ) from exc
        else:
            relative = value
    normalized = Path(relative).as_posix().lstrip("/")
    parts = Path(normalized).parts
    if not normalized or ".." in parts:
        raise ValueError(f"finding path is not contained: {value}")
    return normalized


def _command_finding_record(
    *,
    app: str,
    relative_path: str,
    line: int,
    source: str,
    severity: str,
    confidence: str,
    evidence: str,
) -> dict[str, Any]:
    subtype = _evidence_value(evidence, "detector_subtype")
    line_hash = _evidence_value(evidence, "line_hash")
    source_hash = _evidence_value(evidence, "source_hash")
    sink_hash = _evidence_value(evidence, "sink_hash")
    family = subtype or f"source:{source}"
    evidence_ref = line_hash or sink_hash or ""
    semantic_key = _canonical_sha256(
        {
            "app": app,
            "relative_path": relative_path,
            "line": line,
            "family": family,
            "evidence_ref": evidence_ref,
        }
    )
    return {
        "app": app,
        "relative_path": relative_path,
        "line": line,
        "source": source,
        "severity": severity,
        "confidence": confidence,
        "detector_subtype": subtype,
        "line_hash": line_hash,
        "source_hash": source_hash,
        "sink_hash": sink_hash,
        "semantic_key": semantic_key,
        "redacted_fingerprint": f"sha256-truncated:{semantic_key[:20]}",
        "raw_returned": False,
    }


def _baseline_command_findings(
    app: str,
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        if finding.get("rule_id") != RULE_ID:
            continue
        raw_file = str(finding.get("file") or "")
        relative = _workspace_relative_path(raw_file, Path("<workspace>"))
        if relative is None or Path(relative).suffix.lower() not in JS_TS_SUFFIXES:
            continue
        line = int(finding.get("line_start") or 0)
        if line <= 0:
            raise ValueError(f"baseline command finding has no source line: {app}")
        rows.append(
            _command_finding_record(
                app=app,
                relative_path=relative,
                line=line,
                source=str(finding.get("source") or ""),
                severity=str(finding.get("severity") or ""),
                confidence=str(finding.get("confidence") or ""),
                evidence=str(finding.get("evidence") or ""),
            )
        )
    keys = [row["semantic_key"] for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError(f"baseline command findings are not unique: {app}")
    return sorted(rows, key=lambda row: row["semantic_key"])


def _analysis_limit_records(
    app: str,
    findings: list[Any],
    app_root: Path,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = (
            str(finding.get("rule_id") or "")
            if isinstance(finding, dict)
            else str(finding.rule_id)
        )
        if rule_id != "STATIC_ANALYSIS_LIMIT_REACHED" and not rule_id.endswith(
            "_LIMIT_REACHED"
        ):
            continue
        raw_file = (
            finding.get("file")
            if isinstance(finding, dict)
            else finding.file
        )
        relative = _workspace_relative_path(raw_file, app_root)
        line = int(
            (finding.get("line_start") if isinstance(finding, dict) else finding.line_start)
            or 0
        )
        evidence = str(
            (finding.get("evidence") if isinstance(finding, dict) else finding.evidence)
            or ""
        )
        fingerprint = _canonical_sha256(
            {
                "app": app,
                "rule_id": rule_id,
                "relative_path": relative,
                "line": line,
                "detector_subtype": _evidence_value(evidence, "detector_subtype"),
                "limit_ref": _evidence_value(evidence, "limit_ref"),
            }
        )
        rows.append(
            {
                "app": app,
                "rule_id": rule_id,
                "relative_path": relative,
                "line": line,
                "detector_subtype": _evidence_value(
                    evidence, "detector_subtype"
                ),
                "limit_ref": _evidence_value(evidence, "limit_ref"),
                "redacted_fingerprint": f"sha256-truncated:{fingerprint[:20]}",
                "raw_returned": False,
            }
        )
    return sorted(rows, key=lambda row: row["redacted_fingerprint"])


def _normalized_inventory(metadata: dict[str, Any]) -> dict[str, Any]:
    coverage = metadata.get("review_coverage") or {}
    inventory = coverage.get("inventory") or {}
    return {
        "candidate_content_set_sha256": inventory.get(
            "candidate_content_set_sha256"
        ),
        "candidate_path_set_sha256": inventory.get("candidate_path_set_sha256"),
        "candidate_set_complete": inventory.get("candidate_set_complete") is True,
        "content_fingerprint_complete": (
            inventory.get("content_fingerprint_complete") is True
        ),
        "full_semantic_analysis_candidate_count": int(
            inventory.get("full_semantic_analysis_candidate_count") or 0
        ),
        "full_semantic_candidate_set_complete": (
            inventory.get("full_semantic_candidate_set_complete") is True
        ),
        "reviewed_candidate_count": int(
            inventory.get("reviewed_candidate_count") or 0
        ),
        "semantic_analysis_limited_candidate_count": int(
            inventory.get("semantic_analysis_limited_candidate_count") or 0
        ),
        "supported_file_count": int(inventory.get("supported_file_count") or 0),
        "unscanned_candidate_count": int(
            inventory.get("unscanned_candidate_count") or 0
        ),
        "flow_analysis_executed": coverage.get("flow_analysis_executed") is True,
        "raw_returned": False,
    }


def _normalized_workspace_scan(app: str, app_root: Path) -> dict[str, Any]:
    result = KGuardScanner().scan_workspace(app_root, include_flow=True)
    rows: list[dict[str, Any]] = []
    for finding in result.findings:
        if finding.rule_id != RULE_ID:
            continue
        relative = _workspace_relative_path(finding.file, app_root)
        if relative is None or Path(relative).suffix.lower() not in JS_TS_SUFFIXES:
            continue
        line = int(finding.line_start or 0)
        if line <= 0:
            raise ValueError(f"current command finding has no source line: {app}")
        rows.append(
            _command_finding_record(
                app=app,
                relative_path=relative,
                line=line,
                source=finding.source,
                severity=finding.severity,
                confidence=finding.confidence,
                evidence=finding.evidence,
            )
        )
    keys = [row["semantic_key"] for row in rows]
    if len(keys) != len(set(keys)):
        raise ValueError(f"current command findings are not unique: {app}")
    inventory = _normalized_inventory(result.metadata)
    report = result.to_dict()
    normalized = {
        "command_findings": sorted(rows, key=lambda row: row["semantic_key"]),
        "analysis_limits": _analysis_limit_records(
            app,
            result.findings,
            app_root,
        ),
        "inventory": inventory,
        "full_report_sha256": _canonical_sha256(report),
    }
    normalized["normalized_sha256"] = _canonical_sha256(normalized)
    return normalized


def _contained_source_path(source_root: Path, app: str, relative: str) -> Path:
    if not app or Path(app).name != app:
        raise ValueError(f"invalid app source key: {app!r}")
    root = source_root.resolve()
    app_candidate = root / app
    target_candidate = app_candidate / relative
    current = target_candidate
    while current != root:
        if current.is_symlink():
            raise ValueError(f"source target uses a symlink: {app}/{relative}")
        if root not in current.parents:
            break
        current = current.parent
    app_root = app_candidate.resolve()
    target = target_candidate.resolve()
    if app_root != target and app_root not in target.parents:
        raise ValueError(f"source path escapes app root: {app}/{relative}")
    if not target.is_file():
        raise ValueError(f"source target is not a regular file: {app}/{relative}")
    return target


def _source_binding(
    *,
    campaign_dir: Path,
    app: str,
    relative: str,
    target: Path,
    campaign_app: dict[str, Any] | None = None,
) -> dict[str, Any]:
    receipt_path = campaign_dir / "source-receipts" / f"{app}.json"
    if not receipt_path.is_file() or receipt_path.is_symlink():
        raise ValueError(f"source receipt missing: {app}")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("schema") != "k_guard_git_source_materialization.v2":
        raise ValueError(f"source receipt schema invalid: {app}")
    if receipt.get("raw_returned") is not False:
        raise ValueError(f"source receipt redaction contract invalid: {app}")
    expected_repository_id = app.replace("--", "/", 1)
    if receipt.get("repository_id") != expected_repository_id:
        raise ValueError(f"source receipt repository mismatch: {app}")
    if campaign_app is not None:
        expected_receipt_path = (
            f"source-receipts/{app}.json"
        )
        if campaign_app.get("source_materialization_receipt_path") != expected_receipt_path:
            raise ValueError(f"campaign source receipt path mismatch: {app}")
        if (
            campaign_app.get("source_materialization_receipt_sha256")
            != _sha256_file(receipt_path)
        ):
            raise ValueError(f"campaign source receipt hash mismatch: {app}")
        for field in ("commit", "commit_tree", "source_tree_sha256"):
            if campaign_app.get(field) != receipt.get(field):
                raise ValueError(
                    f"campaign/source receipt {field} mismatch: {app}"
                )
        if campaign_app.get("repository_id") != receipt.get("repository_id"):
            raise ValueError(f"campaign/source repository mismatch: {app}")
    required_truths = (
        "passed",
        "commit_match",
        "commit_tree_match",
        "physical_bytes_match_git_blobs",
    )
    if any(receipt.get(field) is not True for field in required_truths):
        raise ValueError(f"source receipt not qualified: {app}")
    matches = [
        row
        for row in receipt.get("files", [])
        if str(row.get("path") or "").replace("\\", "/") == relative
    ]
    if len(matches) != 1:
        raise ValueError(
            f"source receipt target cardinality mismatch: {app}/{relative}"
        )
    receipt_file = matches[0]
    expected_sha256 = str(receipt_file.get("sha256") or "").lower()
    actual_sha256 = _sha256_file(target)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError(f"source receipt target hash invalid: {app}/{relative}")
    if actual_sha256 != expected_sha256:
        raise ValueError(f"source receipt hash mismatch: {app}/{relative}")
    receipt_byte_count = receipt_file.get("byte_count")
    if (
        not isinstance(receipt_byte_count, int)
        or receipt_byte_count < 0
        or receipt_byte_count != target.stat().st_size
    ):
        raise ValueError(f"source receipt byte count mismatch: {app}/{relative}")
    commit = str(receipt.get("commit") or "")
    commit_tree = str(receipt.get("commit_tree") or "")
    source_tree_sha256 = str(receipt.get("source_tree_sha256") or "")
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError(f"source receipt commit invalid: {app}")
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit_tree):
        raise ValueError(f"source receipt tree invalid: {app}")
    if not re.fullmatch(r"[0-9a-f]{64}", source_tree_sha256):
        raise ValueError(f"source receipt source tree invalid: {app}")
    return {
        "app": app,
        "relative_path": relative,
        "file_sha256": actual_sha256,
        "byte_count": target.stat().st_size,
        "commit": commit,
        "commit_tree": commit_tree,
        "source_tree_sha256": source_tree_sha256,
        "receipt_sha256": _sha256_file(receipt_path),
        "raw_returned": False,
    }


def _load_campaign_contract(
    campaign_dir: Path,
    campaign_id: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    campaign_path = campaign_dir / "campaign.json"
    if not campaign_path.is_file() or campaign_path.is_symlink():
        raise ValueError("campaign manifest missing")
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    if campaign.get("schema") != "k_guard_public_field_campaign.v1":
        raise ValueError("campaign manifest schema invalid")
    if campaign.get("campaign_id") != campaign_id:
        raise ValueError("campaign manifest id mismatch")
    if campaign.get("raw_returned") is not False:
        raise ValueError("campaign manifest redaction contract invalid")
    if campaign.get("tracked_worktree_clean") is not True:
        raise ValueError("baseline campaign worktree was not clean")
    if campaign.get("analyzer_package_tree_hash_schema") != (
        "k_guard_package_tree_sha256.v2"
    ):
        raise ValueError("baseline analyzer package hash schema invalid")
    for field, lengths in (
        ("source_revision", {40, 64}),
        ("analyzer_package_tree_sha256", {64}),
    ):
        value = str(campaign.get(field) or "")
        if len(value) not in lengths or not re.fullmatch(r"[0-9a-f]+", value):
            raise ValueError(f"campaign {field} invalid")

    app_rows = campaign.get("apps", [])
    app_ids = [str(row.get("app") or "") for row in app_rows]
    if not app_ids or not all(app_ids) or len(app_ids) != len(set(app_ids)):
        raise ValueError("campaign apps contain missing or duplicate ids")
    app_by_id = {
        app_id: row
        for app_id, row in zip(app_ids, app_rows, strict=True)
    }
    receipt_names = {
        path.name
        for path in (campaign_dir / "source-receipts").glob("*.json")
        if path.is_file() and not path.is_symlink()
    }
    if receipt_names != {f"{app_id}.json" for app_id in app_ids}:
        raise ValueError("campaign source receipt set mismatch")

    for app_id, row in app_by_id.items():
        if row.get("exact_repeat") is not True:
            raise ValueError(f"baseline app repeat incomplete: {app_id}")
        runs = row.get("runs", [])
        if len(runs) != 2:
            raise ValueError(f"baseline app run count invalid: {app_id}")
        report_hashes = {
            str(run.get("report_sha256") or "")
            for run in runs
        }
        if (
            len(report_hashes) != 1
            or not all(re.fullmatch(r"[0-9a-f]{64}", item) for item in report_hashes)
            or any(run.get("exit_code") != 0 for run in runs)
            or any(run.get("source_mutation_observed") is not False for run in runs)
            or any(
                run.get("source_tree_sha256") != row.get("source_tree_sha256")
                for run in runs
            )
        ):
            raise ValueError(f"baseline app run contract invalid: {app_id}")
        receipt_path = campaign_dir / str(
            row.get("source_materialization_receipt_path") or ""
        )
        if (
            receipt_path.resolve()
            != (campaign_dir / "source-receipts" / f"{app_id}.json").resolve()
            or not receipt_path.is_file()
            or _sha256_file(receipt_path)
            != row.get("source_materialization_receipt_sha256")
        ):
            raise ValueError(f"baseline app receipt binding invalid: {app_id}")

    preregistration_path = campaign_dir / str(
        campaign.get("preregistration_path") or ""
    )
    if (
        not preregistration_path.is_file()
        or _sha256_file(preregistration_path)
        != campaign.get("preregistration_sha256")
    ):
        raise ValueError("campaign preregistration binding invalid")
    return campaign, app_by_id


def _verify_source_materialization(
    *,
    campaign_dir: Path,
    source_root: Path,
    app: str,
    campaign_app: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    app_root = source_root / app
    if app_root.is_symlink() or not app_root.is_dir():
        raise ValueError(f"app source root is missing or linked: {app}")
    receipt_path = _safe_campaign_artifact(
        campaign_dir,
        str(campaign_app.get("source_materialization_receipt_path") or ""),
    )
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("schema") != "k_guard_git_source_materialization.v2":
        raise ValueError(f"source receipt schema invalid: {app}")
    if receipt.get("raw_returned") is not False:
        raise ValueError(f"source receipt redaction contract invalid: {app}")
    required_truths = (
        "passed",
        "commit_match",
        "commit_object_hash_match",
        "commit_tree_match",
        "git_fsck_strict_passed",
        "index_tree_match",
        "origin_repository_match",
        "physical_bytes_match_git_blobs",
        "source_worktree_clean",
        "tree_object_reconstruction_match",
    )
    if any(receipt.get(field) is not True for field in required_truths):
        raise ValueError(f"source receipt qualification incomplete: {app}")
    expected_repository_id = app.replace("--", "/", 1)
    if (
        receipt.get("repository_id") != expected_repository_id
        or receipt.get("origin_repository_id") != expected_repository_id
        or campaign_app.get("repository_id") != expected_repository_id
    ):
        raise ValueError(f"source repository identity mismatch: {app}")
    for field in ("commit", "commit_tree", "source_tree_sha256"):
        if campaign_app.get(field) != receipt.get(field):
            raise ValueError(f"campaign/source receipt {field} mismatch: {app}")
    if (
        campaign_app.get("source_materialization_receipt_sha256")
        != _sha256_file(receipt_path)
    ):
        raise ValueError(f"campaign source receipt hash mismatch: {app}")

    receipt_rows = receipt.get("files", [])
    relative_paths = [str(row.get("path") or "").replace("\\", "/") for row in receipt_rows]
    if (
        not relative_paths
        or not all(relative_paths)
        or len(relative_paths) != len(set(relative_paths))
    ):
        raise ValueError(f"source receipt file set invalid: {app}")
    verified_rows: list[dict[str, Any]] = []
    file_index: dict[str, dict[str, Any]] = {}
    for row, relative in zip(receipt_rows, relative_paths, strict=True):
        path_parts = Path(relative).parts
        if Path(relative).is_absolute() or ".." in path_parts:
            raise ValueError(f"source receipt path is not contained: {app}/{relative}")
        target = _contained_source_path(source_root, app, relative)
        expected_sha256 = str(row.get("sha256") or "").lower()
        expected_bytes = row.get("byte_count")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError(f"source receipt file hash invalid: {app}/{relative}")
        if not isinstance(expected_bytes, int) or expected_bytes < 0:
            raise ValueError(f"source receipt byte count invalid: {app}/{relative}")
        if _sha256_file(target) != expected_sha256:
            raise ValueError(f"source receipt hash mismatch: {app}/{relative}")
        if target.stat().st_size != expected_bytes:
            raise ValueError(f"source receipt byte count mismatch: {app}/{relative}")
        normalized = {
            "path": Path(relative).as_posix(),
            "sha256": expected_sha256,
            "byte_count": expected_bytes,
        }
        verified_rows.append(normalized)
        file_index[normalized["path"]] = normalized

    file_count = len(verified_rows)
    total_bytes = sum(row["byte_count"] for row in verified_rows)
    if (
        int(receipt.get("file_count") or -1) != file_count
        or int(receipt.get("total_bytes") or -1) != total_bytes
        or int(campaign_app.get("tracked_files") or -1) != file_count
        or int(campaign_app.get("source_total_bytes") or -1) != total_bytes
    ):
        raise ValueError(f"source receipt aggregate mismatch: {app}")
    summary = {
        "app": app,
        "repository_id": expected_repository_id,
        "commit": receipt["commit"],
        "commit_tree": receipt["commit_tree"],
        "source_tree_sha256": receipt["source_tree_sha256"],
        "receipt_sha256": _sha256_file(receipt_path),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "git_porcelain_clean": receipt.get("git_porcelain_clean") is True,
        "source_worktree_clean_method": receipt.get(
            "source_worktree_clean_method"
        ),
        "js_ts_file_count": sum(
            Path(row["path"]).suffix.lower() in JS_TS_SUFFIXES
            for row in verified_rows
        ),
        "physical_file_set_sha256": _canonical_sha256(
            sorted(verified_rows, key=lambda row: row["path"])
        ),
        "raw_returned": False,
    }
    return summary, file_index


def _load_report_artifact(
    campaign_dir: Path,
    app: str,
    run: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    run_number = int(run.get("run") or 0)
    if run_number not in {1, 2}:
        raise ValueError(f"baseline report run number invalid: {app}")
    if run.get("report_artifact_encoding") != "canonical-json+gzip-mtime-zero":
        raise ValueError(f"baseline report encoding invalid: {app}/run{run_number}")
    report_path = _safe_campaign_artifact(
        campaign_dir,
        str(run.get("report_artifact_path") or ""),
    )
    artifact = report_path.read_bytes()
    if _sha256_file(report_path) != run.get("report_artifact_sha256"):
        raise ValueError(f"baseline report artifact hash mismatch: {app}/run{run_number}")
    if len(artifact) < 10 or artifact[:2] != b"\x1f\x8b":
        raise ValueError(f"baseline report is not gzip: {app}/run{run_number}")
    if int.from_bytes(artifact[4:8], "little") != 0:
        raise ValueError(f"baseline report gzip mtime is not zero: {app}/run{run_number}")
    try:
        raw = gzip.decompress(artifact)
        report = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"baseline report could not be decoded: {app}/run{run_number}"
        ) from exc
    report_sha256 = hashlib.sha256(raw).hexdigest()
    if report_sha256 != run.get("report_sha256"):
        raise ValueError(f"baseline report hash mismatch: {app}/run{run_number}")
    runtime_receipt = _safe_campaign_artifact(
        campaign_dir,
        str(run.get("runtime_receipt_path") or ""),
    )
    if _sha256_file(runtime_receipt) != run.get("runtime_receipt_sha256"):
        raise ValueError(f"runtime receipt hash mismatch: {app}/run{run_number}")
    metadata = report.get("metadata") or {}
    coverage = metadata.get("review_coverage") or {}
    if (
        coverage.get("source_kind") != "workspace"
        or coverage.get("raw_returned") is not False
        or coverage.get("flow_analysis_executed") is not True
    ):
        raise ValueError(f"baseline review coverage invalid: {app}/run{run_number}")
    normalized = {
        "report_sha256": report_sha256,
        "report_artifact_sha256": _sha256_file(report_path),
        "runtime_receipt_sha256": _sha256_file(runtime_receipt),
        "command_findings": _baseline_command_findings(app, report),
        "analysis_limits": _analysis_limit_records(
            app,
            list(report.get("findings", [])),
            Path("<workspace>"),
        ),
        "inventory": _normalized_inventory(metadata),
        "raw_returned": False,
    }
    normalized["normalized_sha256"] = _canonical_sha256(normalized)
    return report, normalized


def _load_baseline_reports(
    campaign_dir: Path,
    app_by_id: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for app, campaign_app in app_by_id.items():
        run_rows = sorted(campaign_app.get("runs", []), key=lambda row: row["run"])
        loaded = [
            _load_report_artifact(campaign_dir, app, run)[1]
            for run in run_rows
        ]
        if (
            loaded[0]["report_sha256"] != loaded[1]["report_sha256"]
            or loaded[0]["command_findings"] != loaded[1]["command_findings"]
            or loaded[0]["analysis_limits"] != loaded[1]["analysis_limits"]
            or loaded[0]["inventory"] != loaded[1]["inventory"]
        ):
            raise ValueError(f"baseline repeated reports diverged: {app}")
        reports[app] = loaded[0]
    return reports


def _git_object(repo_root: Path, *arguments: str) -> str:
    value = subprocess.check_output(
        ["git", *arguments],
        cwd=repo_root,
        text=True,
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise ValueError(f"git object id invalid for {' '.join(arguments)}")
    return value


def _working_tree_change_set(repo_root: Path) -> dict[str, Any]:
    status = subprocess.check_output(
        ["git", "status", "--porcelain=v1", "-z"],
        cwd=repo_root,
    )
    modified = subprocess.check_output(
        ["git", "ls-files", "--modified", "--others", "--exclude-standard", "-z"],
        cwd=repo_root,
    )
    staged = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "-z"],
        cwd=repo_root,
    )
    paths = {
        item.decode("utf-8", errors="strict").replace("\\", "/")
        for payload in (modified, staged)
        for item in payload.split(b"\0")
        if item
    }
    rows = []
    for relative in sorted(paths):
        target = repo_root / relative
        rows.append(
            {
                "path": relative,
                "exists": target.is_file(),
                "sha256": _sha256_file(target) if target.is_file() else None,
                "byte_count": target.stat().st_size if target.is_file() else 0,
            }
        )
    return {
        "status_porcelain_v1_z_sha256": hashlib.sha256(status).hexdigest(),
        "changed_path_count": len(rows),
        "changed_path_set_sha256": _canonical_sha256(rows),
        "raw_returned": False,
    }


def _probe_lines(source: str) -> list[int]:
    findings = KGuardScanner().scan_text(source, "app/api/run/route.ts").findings
    return sorted(
        int(finding.line_start or 0)
        for finding in findings
        if finding.rule_id == RULE_ID
    )


def _regression_probes() -> dict[str, dict[str, Any]]:
    probes = {
        "bare_exec": (
            [4],
            """
export async function POST(request) {
  const command = (await request.json()).command;
  exec(command);
}
""",
        ),
        "bound_child_process_namespace": (
            [5],
            """
import * as cp from 'node:child_process';
export async function POST(request) {
  const command = (await request.json()).command;
  cp.exec(command);
}
""",
        ),
        "parenthesized_child_process_namespace": (
            [5],
            """
import * as cp from 'node:child_process';
export async function POST(request) {
  const command = (await request.json()).command;
  (cp).exec(command);
}
""",
        ),
        "regexp_receiver": (
            [],
            """
export async function POST(request) {
  const value = (await request.json()).value;
  const pattern = /[a-z]+/;
  pattern.exec(value);
}
""",
        ),
        "spaced_regexp_receiver": (
            [],
            """
export async function POST(request) {
  const value = (await request.json()).value;
  const pattern = /[a-z]+/;
  pattern . exec(value);
}
""",
        ),
        "regexp_literal_receiver": (
            [],
            """
export async function POST(request) {
  const value = (await request.json()).value;
  /[a-z]+/.exec(value);
}
""",
        ),
        "regex_literal_fake_import": (
            [],
            r"""
const docs = /import * as cp from 'node:child_process'/;
export async function POST(request) {
  const command = (await request.json()).command;
  cp.exec(command);
}
""",
        ),
        "cordova_receiver": (
            [],
            """
export async function POST(request) {
  const value = (await request.json()).value;
  cordova.exec(ok, fail, 'Plugin', 'run', [value]);
}
""",
        ),
        "block_shadow_then_outer_binding": (
            [9],
            """
import * as cp from 'node:child_process';
export async function POST(request) {
  const body = await request.json();
  if (body.pattern) {
    const cp = /[a-z]+/;
    cp.exec(body.value);
  }
  cp.exec(body.command);
}
""",
        ),
    }
    return {
        probe_id: {
            "expected_lines": expected,
            "run_1_lines": _probe_lines(source),
            "run_2_lines": _probe_lines(source),
        }
        for probe_id, (expected, source) in probes.items()
    }


def build_projection(
    *,
    repo_root: Path,
    campaign_dir: Path,
    source_root: Path,
) -> dict[str, Any]:
    queue_path = _safe_campaign_artifact(campaign_dir, "candidate-queue.json")
    labels_path = _safe_campaign_artifact(campaign_dir, "candidate-labels.json")
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    if queue.get("schema") != "k_guard_public_field_candidate_queue.v1":
        raise ValueError("candidate queue schema invalid")
    if labels.get("schema") != "k_guard_public_field_candidate_labels.v1":
        raise ValueError("candidate labels schema invalid")
    campaign_id = str(queue.get("campaign_id") or "")
    if not campaign_id or labels.get("campaign_id") != campaign_id:
        raise ValueError("candidate queue/label campaign mismatch")
    if queue.get("raw_returned") is not False or labels.get("raw_returned") is not False:
        raise ValueError("candidate queue/label redaction contract invalid")
    campaign, app_by_id = _load_campaign_contract(campaign_dir, campaign_id)
    baseline_reports = _load_baseline_reports(campaign_dir, app_by_id)

    queue_rows = queue.get("candidates", [])
    label_rows = labels.get("candidates", [])
    label_ids = [str(candidate.get("candidate_id") or "") for candidate in label_rows]
    if not all(label_ids) or len(label_ids) != len(set(label_ids)):
        raise ValueError("candidate labels contain missing or duplicate ids")
    queue_ids = [
        str(candidate.get("candidate_id") or "")
        for candidate in queue_rows
    ]
    if not all(queue_ids) or len(queue_ids) != len(set(queue_ids)):
        raise ValueError("candidate queue contains missing or duplicate ids")
    if set(queue_ids) != set(label_ids):
        raise ValueError("candidate queue/label id sets differ")
    label_by_id = {
        candidate_id: candidate
        for candidate_id, candidate in zip(label_ids, label_rows, strict=True)
    }
    queue_by_id = {
        candidate_id: candidate
        for candidate_id, candidate in zip(queue_ids, queue_rows, strict=True)
    }

    identity_fields = (
        "app",
        "artifact_scope",
        "confidence",
        "detector_subtype",
        "redacted_fingerprint",
        "rule_id",
        "scan_report_sha256",
        "severity",
        "source_location",
    )
    agreement_counts: Counter[str] = Counter()
    for candidate_id, candidate in queue_by_id.items():
        label_row = label_by_id[candidate_id]
        if candidate.get("raw_returned") is not False:
            raise ValueError(f"candidate queue row redaction invalid: {candidate_id}")
        if label_row.get("raw_returned") is not False:
            raise ValueError(f"candidate label row redaction invalid: {candidate_id}")
        for field in identity_fields:
            if candidate.get(field) != label_row.get(field):
                raise ValueError(
                    f"candidate queue/label {field} mismatch: {candidate_id}"
                )
        if candidate.get("response_hash") != label_row.get(
            "http_response_sha256"
        ):
            raise ValueError(
                f"candidate queue/label response hash mismatch: {candidate_id}"
            )
        app = str(candidate.get("app") or "")
        if app not in app_by_id:
            raise ValueError(f"candidate references unknown app: {candidate_id}")
        if candidate.get("scan_report_sha256") != baseline_reports[app].get(
            "report_sha256"
        ):
            raise ValueError(f"candidate report hash mismatch: {candidate_id}")
        fingerprint = str(candidate.get("redacted_fingerprint") or "")
        if fingerprint != f"sha256-truncated:{candidate_id}":
            raise ValueError(f"candidate fingerprint/id mismatch: {candidate_id}")

        final_label = str(label_row.get("label") or "")
        if final_label not in ACCEPTED_LABELS:
            raise ValueError(
                f"unsupported candidate label: {final_label or '<missing>'}"
            )
        reviews = label_row.get("reviews", [])
        review_labels = [str(row.get("label") or "") for row in reviews]
        reviewer_vendors = [str(row.get("reviewer_vendor") or "") for row in reviews]
        if (
            len(reviews) != 3
            or any(label not in ACCEPTED_LABELS for label in review_labels)
            or len(set(reviewer_vendors)) != 3
            or not all(reviewer_vendors)
        ):
            raise ValueError(f"candidate independent review contract invalid: {candidate_id}")
        majority = Counter(review_labels).most_common()
        if not majority or majority[0][1] < 2 or majority[0][0] != final_label:
            raise ValueError(f"candidate aggregate label is not a majority: {candidate_id}")
        expected_agreement = (
            "unanimous" if len(set(review_labels)) == 1 else "majority"
        )
        if label_row.get("agreement") != expected_agreement:
            raise ValueError(f"candidate agreement marker invalid: {candidate_id}")
        agreement_counts[expected_agreement] += 1

    prior = [
        candidate
        for candidate in queue_rows
        if candidate.get("rule_id") == RULE_ID
        and candidate.get("detector_subtype") in AFFECTED_SUBTYPES
        and Path(_candidate_location(candidate)[0]).suffix.lower()
        in JS_TS_SUFFIXES
    ]
    if not prior:
        raise ValueError(
            f"candidate queue has no affected JS/TS {RULE_ID} rows"
        )

    source_materialization: dict[str, dict[str, Any]] = {}
    source_file_indexes: dict[str, dict[str, dict[str, Any]]] = {}
    for app, campaign_app in app_by_id.items():
        summary, file_index = _verify_source_materialization(
            campaign_dir=campaign_dir,
            source_root=source_root,
            app=app,
            campaign_app=campaign_app,
        )
        source_materialization[app] = summary
        source_file_indexes[app] = file_index

    baseline_command_by_key: dict[str, dict[str, Any]] = {}
    for baseline in baseline_reports.values():
        for finding in baseline["command_findings"]:
            key = finding["semantic_key"]
            if key in baseline_command_by_key:
                raise ValueError(f"baseline command key collision: {key}")
            baseline_command_by_key[key] = finding

    prior_key_by_candidate_id: dict[str, str] = {}
    source_bindings: dict[tuple[str, str], dict[str, Any]] = {}
    for candidate in prior:
        candidate_id = str(candidate["candidate_id"])
        app = str(candidate["app"])
        relative, line = _candidate_location(candidate)
        target = _contained_source_path(source_root, app, relative)
        file_row = source_file_indexes[app].get(relative)
        if file_row is None:
            raise ValueError(f"candidate file absent from source receipt: {candidate_id}")
        if file_row["sha256"] != _sha256_file(target):
            raise ValueError(f"candidate file receipt hash mismatch: {candidate_id}")
        source_text = read_text(target)
        if source_text is None:
            raise ValueError(f"source target is not decodable: {app}/{relative}")
        source_lines = source_text.splitlines()
        if line < 1 or line > len(source_lines):
            raise ValueError(f"candidate source line out of range: {candidate_id}")
        expected_line_hash = str(
            (candidate.get("evidence_refs") or {}).get("line_hash") or ""
        )
        if evidence_hash(source_lines[line - 1]) != expected_line_hash:
            raise ValueError(f"candidate line hash mismatch: {candidate_id}")

        baseline_matches = [
            finding
            for finding in baseline_reports[app]["command_findings"]
            if finding["relative_path"] == relative
            and finding["line"] == line
            and finding["detector_subtype"] == candidate.get("detector_subtype")
            and finding["line_hash"] == expected_line_hash
            and finding["severity"] == candidate.get("severity")
            and finding["confidence"] == candidate.get("confidence")
        ]
        if len(baseline_matches) != 1:
            raise ValueError(
                f"candidate/baseline report cardinality mismatch: {candidate_id}"
            )
        prior_key_by_candidate_id[candidate_id] = baseline_matches[0]["semantic_key"]
        cache_key = (app, relative)
        if cache_key not in source_bindings:
            source_bindings[cache_key] = _source_binding(
                campaign_dir=campaign_dir,
                app=app,
                relative=relative,
                target=target,
                campaign_app=app_by_id[app],
            )

    app_scans: dict[str, dict[str, Any]] = {}
    current_command_by_key: dict[str, dict[str, Any]] = {}
    current_analysis_limits: list[dict[str, Any]] = []
    baseline_analysis_limits: list[dict[str, Any]] = []
    exact_repeat_app_count = 0
    complete_coverage_app_count = 0
    for app, campaign_app in app_by_id.items():
        app_root = source_root / app
        run_1 = _normalized_workspace_scan(app, app_root)
        run_2 = _normalized_workspace_scan(app, app_root)
        exact_repeat = (
            run_1["normalized_sha256"] == run_2["normalized_sha256"]
            and run_1["full_report_sha256"] == run_2["full_report_sha256"]
        )
        exact_repeat_app_count += int(exact_repeat)
        baseline = baseline_reports[app]
        baseline_inventory = baseline["inventory"]
        current_inventory = run_1["inventory"]
        repeat_inventory = run_2["inventory"]
        coverage_complete = bool(
            current_inventory == repeat_inventory
            and current_inventory["candidate_set_complete"]
            and current_inventory["content_fingerprint_complete"]
            and current_inventory["flow_analysis_executed"]
            and current_inventory["unscanned_candidate_count"] == 0
            and current_inventory["reviewed_candidate_count"]
            == current_inventory["supported_file_count"]
            and current_inventory["candidate_content_set_sha256"]
            == baseline_inventory["candidate_content_set_sha256"]
            and current_inventory["candidate_path_set_sha256"]
            == baseline_inventory["candidate_path_set_sha256"]
            and current_inventory["supported_file_count"]
            == baseline_inventory["supported_file_count"]
            == int(campaign_app.get("supported_files") or -1)
        )
        complete_coverage_app_count += int(coverage_complete)
        app_scans[app] = {
            "app": app,
            "exact_repeat": exact_repeat,
            "coverage_complete": coverage_complete,
            "baseline_report_sha256": baseline["report_sha256"],
            "run_1_normalized_sha256": run_1["normalized_sha256"],
            "run_2_normalized_sha256": run_2["normalized_sha256"],
            "run_1_full_report_sha256": run_1["full_report_sha256"],
            "run_2_full_report_sha256": run_2["full_report_sha256"],
            "baseline_command_finding_count": len(
                baseline["command_findings"]
            ),
            "current_command_finding_count": len(
                run_1["command_findings"]
            ),
            "baseline_analysis_limit_count": len(
                baseline["analysis_limits"]
            ),
            "current_analysis_limit_count": len(
                run_1["analysis_limits"]
            ),
            "candidate_content_set_sha256": current_inventory[
                "candidate_content_set_sha256"
            ],
            "candidate_path_set_sha256": current_inventory[
                "candidate_path_set_sha256"
            ],
            "supported_file_count": current_inventory["supported_file_count"],
            "semantic_analysis_limited_candidate_count": current_inventory[
                "semantic_analysis_limited_candidate_count"
            ],
            "raw_returned": False,
        }
        for finding in run_1["command_findings"]:
            key = finding["semantic_key"]
            if key in current_command_by_key:
                raise ValueError(f"current command key collision: {key}")
            current_command_by_key[key] = finding
        current_analysis_limits.extend(run_1["analysis_limits"])
        baseline_analysis_limits.extend(baseline["analysis_limits"])

    rows: list[dict[str, Any]] = []
    outcome_counts: Counter[str] = Counter()
    detected_label_counts: Counter[str] = Counter()
    for candidate in prior:
        candidate_id = str(candidate["candidate_id"])
        label = str(label_by_id[candidate_id].get("label") or "")
        app = str(candidate["app"])
        relative, line = _candidate_location(candidate)
        cache_key = (app, relative)
        source_binding = source_bindings[cache_key]
        semantic_key = prior_key_by_candidate_id[candidate_id]
        finding = current_command_by_key.get(semantic_key)
        detected = finding is not None
        detected_label_counts[label] += int(detected)

        if label == "true_positive":
            outcome = "true_positive_retained" if detected else "true_positive_lost"
        elif label == "false_positive":
            outcome = (
                "detector_false_positive_remaining"
                if detected
                else "detector_false_positive_removed"
            )
        elif label == "benign":
            outcome = (
                "non_actionable_mechanism_retained"
                if detected
                else "non_actionable_mechanism_lost"
            )
        else:
            outcome = "inconclusive"
        outcome_counts[outcome] += 1

        lane = None
        if finding is not None:
            projected_finding = {
                "rule_id": RULE_ID,
                "severity": finding["severity"],
                "confidence": finding["confidence"],
                "artifact_scope": str(candidate.get("artifact_scope") or "runtime_source"),
                "evidence": (
                    f"detector_subtype={finding['detector_subtype'] or 'unknown'}"
                ),
            }
            lane = release_lane(projected_finding, "high")
        rows.append(
            {
                "candidate_id": candidate_id,
                "prior_detector_subtype": candidate.get("detector_subtype"),
                "adjudicated_actionability_label": label,
                "detected": detected,
                "current_detector_subtype": (
                    finding["detector_subtype"] if finding is not None else None
                ),
                "exact_repeat": app_scans[app]["exact_repeat"],
                "candidate_line_hash_verified": True,
                "full_app_coverage_complete": app_scans[app][
                    "coverage_complete"
                ],
                "scan_run_1_sha256": app_scans[app][
                    "run_1_normalized_sha256"
                ],
                "scan_run_2_sha256": app_scans[app][
                    "run_2_normalized_sha256"
                ],
                "source_file_sha256": source_binding["file_sha256"],
                "source_receipt_sha256": source_binding["receipt_sha256"],
                "baseline_semantic_key_sha256": semantic_key,
                "outcome": outcome,
                "release_lane_if_detected": lane,
                "raw_returned": False,
            }
        )

    baseline_keys = set(baseline_command_by_key)
    current_keys = set(current_command_by_key)
    new_current_keys = sorted(current_keys - baseline_keys)
    removed_baseline_keys = sorted(baseline_keys - current_keys)
    permitted_removed_keys = {
        prior_key_by_candidate_id[candidate_id]
        for candidate_id, label_row in label_by_id.items()
        if candidate_id in prior_key_by_candidate_id
        and label_row.get("label") == "false_positive"
    }
    unadjudicated_removed_keys = sorted(
        set(removed_baseline_keys) - permitted_removed_keys
    )
    unmatched_current_candidates = [
        current_command_by_key[key] for key in new_current_keys
    ]
    unadjudicated_removed_baseline = [
        baseline_command_by_key[key] for key in unadjudicated_removed_keys
    ]

    probes = _regression_probes()
    probe_contract_passed = all(
        row["run_1_lines"] == row["expected_lines"]
        and row["run_2_lines"] == row["expected_lines"]
        and row["run_1_lines"] == row["run_2_lines"]
        for row in probes.values()
    )
    exact_repeat = exact_repeat_app_count == len(app_by_id)
    source_binding_contract_passed = all(
        row["candidate_line_hash_verified"] for row in rows
    )
    full_app_coverage_contract_passed = (
        complete_coverage_app_count == len(app_by_id)
    )
    current_analysis_limit_contract_passed = not current_analysis_limits
    baseline_analysis_limit_contract_passed = not baseline_analysis_limits
    true_positive_count = detected_label_counts["true_positive"]
    current_detection_count = sum(detected_label_counts.values())
    actionability = (
        true_positive_count / current_detection_count
        if current_detection_count
        else 0.0
    )
    detector_delta_contract_passed = bool(
        outcome_counts["true_positive_lost"] == 0
        and outcome_counts["detector_false_positive_remaining"] == 0
        and outcome_counts["non_actionable_mechanism_lost"] == 0
        and outcome_counts["inconclusive"] == 0
        and not unmatched_current_candidates
        and not unadjudicated_removed_baseline
    )
    full_universe_contract_passed = bool(
        exact_repeat
        and source_binding_contract_passed
        and full_app_coverage_contract_passed
        and current_analysis_limit_contract_passed
        and baseline_analysis_limit_contract_passed
        and probe_contract_passed
    )
    hypothesis_passed = bool(
        detector_delta_contract_passed
        and full_universe_contract_passed
    )
    working_diff = subprocess.check_output(
        ["git", "diff", "--no-color"],
        cwd=repo_root,
    )
    working_tree_change_set = _working_tree_change_set(repo_root)
    git_head = _git_object(repo_root, "rev-parse", "HEAD")
    git_head_tree = _git_object(repo_root, "rev-parse", "HEAD^{tree}")
    campaign_manifest_path = campaign_dir / "campaign.json"
    projector_path = Path(__file__).resolve()
    return {
        "schema": "k_guard_js_command_sink_resolution_projection.v3",
        "campaign_id": campaign_id,
        "evidence_use": "post_hoc_development_projection",
        "hypothesis": (
            "Qualified JS/TS .exec/.spawn calls are operating-system process sinks only "
            "when their receiver is bound to a recognized command module."
        ),
        "prior_labeled_candidate_count": len(prior),
        "baseline_full_universe_command_finding_count": len(
            baseline_command_by_key
        ),
        "current_full_universe_command_finding_count": len(
            current_command_by_key
        ),
        "affected_detector_subtypes": sorted(AFFECTED_SUBTYPES),
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "detected_actionability_label_counts": {
            label: detected_label_counts[label]
            for label in ("true_positive", "false_positive", "benign", "inconclusive")
        },
        "current_detected_candidate_count": current_detection_count,
        "current_actionability_on_prior_labels": round(actionability, 6),
        "current_actionability_wilson_95_lower": round(
            _wilson_lower(true_positive_count, current_detection_count),
            6,
        ),
        "exact_repeat": exact_repeat,
        "exact_repeat_app_count": exact_repeat_app_count,
        "campaign_app_count": len(app_by_id),
        "source_binding_contract_passed": source_binding_contract_passed,
        "full_app_coverage_contract_passed": full_app_coverage_contract_passed,
        "complete_coverage_app_count": complete_coverage_app_count,
        "baseline_analysis_limit_contract_passed": (
            baseline_analysis_limit_contract_passed
        ),
        "baseline_analysis_limit_count": len(baseline_analysis_limits),
        "baseline_analysis_limits": baseline_analysis_limits,
        "current_analysis_limit_contract_passed": (
            current_analysis_limit_contract_passed
        ),
        "current_analysis_limit_count": len(current_analysis_limits),
        "current_analysis_limits": current_analysis_limits,
        "regression_probes": probes,
        "regression_probe_contract_passed": probe_contract_passed,
        "detector_delta_contract_passed": detector_delta_contract_passed,
        "full_universe_contract_passed": full_universe_contract_passed,
        "unmatched_current_candidate_count": len(
            unmatched_current_candidates
        ),
        "unmatched_current_candidates": unmatched_current_candidates,
        "unadjudicated_removed_baseline_count": len(
            unadjudicated_removed_baseline
        ),
        "unadjudicated_removed_baseline": unadjudicated_removed_baseline,
        "hypothesis_passed": hypothesis_passed,
        "release_gate_passed": False,
        "release_gate_blockers": [
            "These exposed labels are development evidence, not a fresh unseen holdout.",
            "Intentional vulnerable applications remain correctly detected but are not release-actionable.",
            "The automatic command rule still requires a separate business-intent and release-authority hypothesis.",
            "The positive and detector-false-positive sample sizes do not clear the locked Wilson floor.",
            "Any baseline or current static-analysis limit keeps the full-universe contract fail-closed.",
        ],
        "qualification_eligible": False,
        "release_claim_allowed": False,
        "rows": rows,
        "app_scans": [
            app_scans[app] for app in sorted(app_scans)
        ],
        "source_binding_count": len(source_bindings),
        "source_materialization": [
            source_materialization[app]
            for app in sorted(source_materialization)
        ],
        "source_git_porcelain_dirty_app_count": sum(
            not row["git_porcelain_clean"]
            for row in source_materialization.values()
        ),
        "target_source_set_sha256": _canonical_sha256(
            [
                source_materialization[app]
                for app in sorted(source_materialization)
            ]
        ),
        "source_receipt_set_sha256": _canonical_sha256(
            sorted(
                (
                    app,
                    source_materialization[app]["receipt_sha256"],
                )
                for app in source_materialization
            )
        ),
        "baseline_report_set_sha256": _canonical_sha256(
            sorted(
                (
                    app,
                    baseline_reports[app]["report_sha256"],
                    baseline_reports[app]["report_artifact_sha256"],
                    baseline_reports[app]["runtime_receipt_sha256"],
                )
                for app in baseline_reports
            )
        ),
        "candidate_agreement_counts": dict(sorted(agreement_counts.items())),
        "evidence_hash_scheme": evidence_hash_scheme(),
        "source_labels_sha256": _sha256_file(labels_path),
        "source_queue_sha256": _sha256_file(queue_path),
        "campaign_manifest_sha256": _sha256_file(campaign_manifest_path),
        "campaign_source_revision": campaign["source_revision"],
        "campaign_analyzer_package_tree_sha256": campaign[
            "analyzer_package_tree_sha256"
        ],
        "pyproject_sha256": _sha256_file(repo_root / "pyproject.toml"),
        "git_head": git_head,
        "git_head_tree": git_head_tree,
        "projector_sha256": _sha256_file(projector_path),
        "working_tree_diff_sha256": hashlib.sha256(working_diff).hexdigest(),
        "working_tree_change_set": working_tree_change_set,
        "working_tree_package_sha256": package_tree_sha256(
            repo_root / "src" / "k_guard_mcp"
        ),
        "raw_returned": False,
    }


def write_projection(output: Path, payload: dict[str, Any]) -> None:
    if output.exists():
        raise FileExistsError(f"refusing to overwrite projection: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-dir", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    payload = build_projection(
        repo_root=ROOT,
        campaign_dir=args.campaign_dir.resolve(),
        source_root=args.source_root.resolve(),
    )
    write_projection(args.output.resolve(), payload)
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "prior_labeled_candidate_count": payload[
                    "prior_labeled_candidate_count"
                ],
                "outcome_counts": payload["outcome_counts"],
                "current_actionability_on_prior_labels": payload[
                    "current_actionability_on_prior_labels"
                ],
                "exact_repeat": payload["exact_repeat"],
                "hypothesis_passed": payload["hypothesis_passed"],
                "release_gate_passed": payload["release_gate_passed"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
