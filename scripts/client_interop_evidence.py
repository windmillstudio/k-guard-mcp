from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from .evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256, package_tree_sha256_at_revision
except ImportError:  # pragma: no cover - dynamic/direct script execution
    try:
        from scripts.evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256, package_tree_sha256_at_revision
    except ImportError:
        from evidence_tree import TREE_HASH_SCHEMA, package_tree_sha256, package_tree_sha256_at_revision


ROOT = Path(__file__).resolve().parents[1]
CLIENTS = ("chatgpt", "grok", "codex", "antigravity")
REQUIRED_STAGES = ("install", "restart", "tool_list", "check_my_app", "reconnect")
REQUIRED_TOOLS = ("check_my_app", "continue_review", "start_review_before_ship")
OBSERVATION_SCHEMA = "k_guard_client_interop_observation.v5"
VERIFIED_RUN_SCHEMA = "k_guard_client_interop_verified_run.v6"
STATUS_SCHEMA = "k_guard_client_interop_status.v6"
RELEASE_BINDING_RECEIPT = Path("evidence/release/fresh-wheel-stdio-smoke.json")
RELEASE_BINDING_WHEEL = Path("submission/release/k_guard_mcp-0.1.0-py3-none-any.whl")
RELEASE_BINDING_RECEIPT_SCHEMA = "k_guard_fresh_wheel_stdio_smoke.v3"
VIDEO_PROBE_RECEIPT = Path("evidence/clients/video-probe/video-probe.json")
VIDEO_PROBE_RECEIPT_SCHEMA = "k_guard.client_interop_video_probe.v1"
IDENTITY_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{5,79}$")
FINDING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
VIDEO_SUFFIXES = {".mkv", ".mov", ".mp4", ".webm"}
MIN_VIDEO_BYTES = 1024
RECORDING_EVIDENCE_MODE = "sanitized_process_log_replay_not_vendor_ui_certification"
EXPOSURE_AUDIT_METHOD = "deterministic_client_transcript_mcp_rawoutput_scan.v1"
EXPOSURE_SELF_REPORT_METHOD = "client_final_structured_self_report.v1"
EXPOSURE_PROVENANCE_DETERMINISTIC = "deterministic_local_transcript_audit"
EXPOSURE_PROVENANCE_SELF_REPORTED = "client_final_self_report"
EXPOSURE_OUT_OF_SCOPE_CLASSIFICATION = "client_startup_or_cwd_context_outside_mcp_response"
EXPOSURE_CLEAR_CLASSIFICATION = "no_client_reported_context_exposure"
CONTINUE_REVIEW_TERMINAL_COMPLETED = "completed"
COMPACT_RESPONSE_MODE = "compact"
COMPACT_RESPONSE_CONTRACT_MODE = "compact_paginated"
PAGINATION_PAGE_KEYS = {
    "finding_offset",
    "returned_count",
    "next_offset",
    "has_more",
    "finding_ids",
    "raw_returned",
}
HANDSHAKE_PRESENT_FIELDS = (
    "review_receipt",
    "primary_workflow",
    "release_review_contract",
    "guardian_handoff",
    "review_coverage",
)
HANDSHAKE_TYPED_FIELDS = {
    "next_tool": "string",
    "not_inspected": "list",
    "canonical_release_authority": "boolean",
    "repository_content_role": "string",
    "scope_reduction_for_client_timeout": "boolean",
}
HANDSHAKE_ELIGIBILITY_FIELDS = (
    "review_receipt_eligible_for_release_review",
    "primary_workflow_release_review_eligible",
    "release_contract_eligible_to_start_guardian",
    "guardian_handoff_eligible_to_start_guardian",
)
HANDSHAKE_STATUS_FIELDS = (
    "release_review_contract_status",
    "guardian_handoff_status",
)
HANDSHAKE_ALLOWED_STATUSES = {"ready", "blocked"}
HANDSHAKE_ALLOWED_COVERAGE_STATUSES = {"available_declared_scope", "unavailable_fail_closed"}
HANDSHAKE_NEXT_TOOL_FIELDS = (
    "top_level_next_tool_value",
    "primary_workflow_next_tool_value",
    "release_contract_next_tool_value",
    "guardian_handoff_next_tool_value",
)
HANDSHAKE_CANONICAL_AUTHORITY_FIELDS = (
    "top_level_canonical_release_authority_value",
    "primary_workflow_canonical_release_authority_value",
    "release_contract_canonical_release_authority_value",
    "guardian_handoff_canonical_release_authority_value",
)
HANDSHAKE_RELEASE_VERDICT_FIELDS = (
    "release_contract_release_verdict_issued",
    "guardian_handoff_release_verdict_issued",
)
HISTORICAL_VERIFIED_RUN_SCHEMAS = {
    "k_guard_client_interop_verified_run.v3",
    "k_guard_client_interop_verified_run.v4",
    "k_guard_client_interop_verified_run.v5",
}
STATUS_CLAIM_BOUNDARY = (
    "동일한 fresh-wheel release receipt에 고정된 product source revision, package tree, 설치 wheel SHA-256/바이트, 녹화 원본, 필수 5단계, "
    "host decoder가 수락한 10초 이상 녹화와 대표 sanitized frame 결속, "
    "compact 전체 pagination, release handshake, 재연결 후 tools/list와 read-only 호출, "
    "별도 review assertion이 기록된 클라이언트만 process 검증 완료로 집계한다. "
    "handshake 의미 parity는 영상과 별도 review가 보조하는 self-attested 전사이며 canonical terminal response digest에 결속되지 않았다. "
    "노출 판정은 클라이언트별 provenance를 보존한다. Grok은 로컬 transcript digest에 결속된 K-Guard MCP rawOutput audit이고, Codex와 Antigravity는 structured client self-report이며 deterministic 검증으로 승격하지 않는다. client startup/cwd context self-report는 별도 보존하고 MCP response 합격 범위에서 제외한다. "
    "review assertion은 외부 심사자 신원이나 독립성을 증명하지 않는다."
)
ALLOWED_REVIEW_SCOPES = {"owned_app", "owned_fixture", "partner_app"}
READ_ONLY_POST_RECONNECT_TOOLS = {"continue_review", "explain_rule", "suggest_fix", "security_gate"}
SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/-]{16,}", re.IGNORECASE),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?:CONTROL_PLANE_API_KEY|OPENAI_API_KEY)\s*[=:]\s*[^<\s][^\s]{7,}"),
)
LOCAL_PATH_PATTERNS = (
    re.compile(r"[A-Za-z]:\\Users\\[^\\\s]+", re.IGNORECASE),
    re.compile(r"/(?:Users|home)/[^/\s]+"),
)


def _authoritative_release_binding(root: Path) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    receipt_path = root / RELEASE_BINDING_RECEIPT
    wheel_path = root / RELEASE_BINDING_WHEEL
    try:
        receipt_bytes = receipt_path.read_bytes()
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, ["release_binding_receipt_unreadable"]
    if not isinstance(receipt, dict):
        return None, ["release_binding_receipt_invalid"]
    if receipt.get("schema") != RELEASE_BINDING_RECEIPT_SCHEMA:
        errors.append("release_binding_receipt_schema_invalid")
    product_revision = str(receipt.get("source_revision") or "").lower()
    if not REVISION_RE.fullmatch(product_revision):
        errors.append("release_binding_product_revision_invalid")
    if receipt.get("passed") is not True:
        errors.append("release_binding_receipt_not_passed")
    if receipt.get("site_packages_loaded") is not True:
        errors.append("release_binding_site_packages_not_loaded")
    if receipt.get("raw_returned") is not False:
        errors.append("release_binding_raw_boundary_invalid")
    if receipt.get("package_tree_hash_schema") != TREE_HASH_SCHEMA:
        errors.append("release_binding_tree_schema_invalid")

    wheel_artifact = receipt.get("wheel_artifact")
    if not isinstance(wheel_artifact, dict):
        wheel_artifact = {}
        errors.append("release_binding_wheel_artifact_invalid")
    wheel_sha256 = str(receipt.get("wheel_sha256") or "").lower()
    wheel_size = wheel_artifact.get("byte_count")
    package_tree = str(receipt.get("source_package_tree_sha256") or "").lower()
    tree_values = {
        package_tree,
        str(receipt.get("installed_package_tree_sha256") or "").lower(),
        str(wheel_artifact.get("package_tree_sha256") or "").lower(),
    }
    if len(tree_values) != 1 or not SHA256_RE.fullmatch(package_tree):
        errors.append("release_binding_package_tree_inconsistent")
    if not SHA256_RE.fullmatch(wheel_sha256):
        errors.append("release_binding_wheel_sha256_invalid")
    if wheel_artifact.get("sha256") != wheel_sha256:
        errors.append("release_binding_wheel_digest_inconsistent")
    if not _is_int(wheel_size) or wheel_size <= 0:
        errors.append("release_binding_wheel_size_invalid")
        wheel_size = 0
    if wheel_artifact.get("filename") != RELEASE_BINDING_WHEEL.name:
        errors.append("release_binding_wheel_filename_invalid")
    if not wheel_path.is_file():
        errors.append("release_binding_wheel_missing")
    else:
        if wheel_path.stat().st_size != wheel_size:
            errors.append("release_binding_wheel_size_mismatch")
        if SHA256_RE.fullmatch(wheel_sha256) and _file_sha256(wheel_path) != wheel_sha256:
            errors.append("release_binding_wheel_sha256_mismatch")
    try:
        current_tree = package_tree_sha256(root / "src" / "k_guard_mcp")
    except (OSError, ValueError):
        current_tree = ""
        errors.append("release_binding_working_package_tree_unreadable")
    if package_tree and current_tree != package_tree:
        errors.append("release_binding_working_package_tree_mismatch")
    if REVISION_RE.fullmatch(product_revision):
        try:
            revision_tree = package_tree_sha256_at_revision(root, product_revision)
        except (OSError, ValueError, subprocess.CalledProcessError):
            revision_tree = ""
            errors.append("release_binding_revision_package_tree_unreadable")
        if package_tree and revision_tree != package_tree:
            errors.append("release_binding_revision_package_tree_mismatch")
    if errors:
        return None, sorted(set(errors))
    return {
        "receipt_locator": RELEASE_BINDING_RECEIPT.as_posix(),
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "receipt_schema": RELEASE_BINDING_RECEIPT_SCHEMA,
        "product_source_revision": product_revision,
        "package_tree_hash_schema": TREE_HASH_SCHEMA,
        "package_tree_sha256": package_tree,
        "wheel_locator": RELEASE_BINDING_WHEEL.as_posix(),
        "wheel_sha256": wheel_sha256,
        "wheel_size_bytes": wheel_size,
        "site_packages_loaded": True,
        "source_installed_tree_equal": True,
        "raw_returned": False,
    }, []


def _optional_video_probe_binding(
    root: Path,
    *,
    client: str,
    published_locator: str,
    recording_sha256: str,
    recording_size_bytes: int,
    duration_seconds: float,
) -> tuple[dict[str, Any] | None, list[str]]:
    receipt_path = root / VIDEO_PROBE_RECEIPT
    if not receipt_path.is_file():
        return None, []
    try:
        receipt_bytes = receipt_path.read_bytes()
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None, ["video_probe_receipt_unreadable"]
    if not isinstance(receipt, dict):
        return None, ["video_probe_receipt_invalid"]
    rows = receipt.get("videos")
    if not isinstance(rows, list):
        return None, ["video_probe_rows_invalid"]
    matching = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("client") == client
        and row.get("video_path") == published_locator
    ]
    if not matching:
        return None, []
    if len(matching) != 1:
        return None, ["video_probe_row_not_unique"]
    row = matching[0]
    errors: list[str] = []
    if receipt.get("schema") != VIDEO_PROBE_RECEIPT_SCHEMA:
        errors.append("video_probe_schema_invalid")
    if receipt.get("passed") is not True:
        errors.append("video_probe_not_passed")
    if receipt.get("recording_mode") != RECORDING_EVIDENCE_MODE:
        errors.append("video_probe_recording_mode_invalid")
    if row.get("video_sha256") != recording_sha256:
        errors.append("video_probe_recording_sha256_mismatch")
    if row.get("video_size_bytes") != recording_size_bytes:
        errors.append("video_probe_recording_size_mismatch")
    probed_duration = row.get("container_duration_seconds")
    if not isinstance(probed_duration, (int, float)) or isinstance(probed_duration, bool):
        errors.append("video_probe_duration_invalid")
        probed_duration = 0
    elif abs(float(probed_duration) - float(duration_seconds)) > 0.001:
        errors.append("video_probe_duration_mismatch")
    if row.get("decoder_accepted") is not True or not str(row.get("decoder_probe") or ""):
        errors.append("video_probe_decoder_invalid")
    frame_locator = str(row.get("representative_frame_path") or "")
    frame_relative = Path(frame_locator)
    if (
        not frame_locator
        or frame_relative.is_absolute()
        or bool(frame_relative.drive)
        or ".." in frame_relative.parts
        or frame_relative.suffix.casefold() != ".png"
    ):
        errors.append("video_probe_frame_locator_invalid")
        frame_path = None
    else:
        frame_path = root / frame_relative
    frame_sha256 = str(row.get("representative_frame_sha256") or "")
    frame_size = row.get("representative_frame_size_bytes")
    if not SHA256_RE.fullmatch(frame_sha256):
        errors.append("video_probe_frame_sha256_invalid")
    if not _is_int(frame_size) or frame_size <= 0:
        errors.append("video_probe_frame_size_invalid")
        frame_size = 0
    if frame_path is None or not frame_path.is_file():
        errors.append("video_probe_frame_missing")
    else:
        if frame_path.stat().st_size != frame_size:
            errors.append("video_probe_frame_size_mismatch")
        if SHA256_RE.fullmatch(frame_sha256) and _file_sha256(frame_path) != frame_sha256:
            errors.append("video_probe_frame_sha256_mismatch")
    if errors:
        return None, sorted(set(errors))
    return {
        "receipt_locator": VIDEO_PROBE_RECEIPT.as_posix(),
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "decoder_probe": row["decoder_probe"],
        "decoder_accepted": True,
        "container_duration_seconds": probed_duration,
        "representative_frame_locator": frame_locator,
        "representative_frame_sha256": frame_sha256,
        "representative_frame_size_bytes": frame_size,
    }, []


def build_observation_template(
    client: str,
    product_source_revision: str,
    *,
    evidence_revision: str = "",
) -> dict[str, Any]:
    if client not in CLIENTS:
        raise ValueError(f"unsupported client: {client}")
    return {
        "schema": OBSERVATION_SCHEMA,
        "client": client,
        "run_id": f"{client}-YYYYMMDD-01",
        "product_source_revision": product_source_revision,
        "evidence_revision": evidence_revision,
        "recorded_at": "",
        "operator_ref": "replace_with_sha256_ref",
        "reviewer_ref": "replace_with_different_sha256_ref",
        "environment": {
            "os": "Windows 11",
            "client_version": "",
            "k_guard_version": "0.1.0",
            "profile": "local-dev",
        },
        "installation": {
            "wheel_sha256": "",
            "wheel_size_bytes": 0,
        },
        "release_binding": {
            "receipt_locator": RELEASE_BINDING_RECEIPT.as_posix(),
            "receipt_sha256": "",
            "product_source_revision": product_source_revision,
            "package_tree_hash_schema": TREE_HASH_SCHEMA,
            "package_tree_sha256": "",
            "wheel_sha256": "",
            "wheel_size_bytes": 0,
        },
        "recording": {
            "artifact": f"{client}-interop.mp4",
            "published_locator": f"submission/client-interop/{client}-interop.mp4",
            "duration_seconds": 0,
            "evidence_mode": RECORDING_EVIDENCE_MODE,
        },
        "exposure_evidence": {
            "client_self_reported_context_exposure": False,
            "deterministic_mcp_response_exposure": False,
            "audit_method": EXPOSURE_SELF_REPORT_METHOD,
            "assessment_provenance": EXPOSURE_PROVENANCE_SELF_REPORTED,
            "deterministic_verification_available": False,
            "audit_receipt_locator": None,
            "audit_receipt_sha256": None,
            "audited_mcp_call_count": 0,
            "absolute_user_path_count": 0,
            "raw_returned_true_count": 0,
            "all_mcp_tool_raw_returned_false": False,
            "classification": EXPOSURE_CLEAR_CLASSIFICATION,
            "claim_boundary": "MCP response boundary only; client startup and supplied cwd metadata are excluded",
        },
        "stages": {
            stage: {"passed": False, "timecode": "00:00-00:00", "observation": ""}
            for stage in REQUIRED_STAGES
        },
        "tool_list": {"advertised_count": 0, "required_tools_present": []},
        "check_my_app": {
            "state": "",
            "presentation_code": "",
            "first_receipt": False,
            "review_id_ref": "",
            "raw_returned": False,
            "review_scope": "owned_fixture",
        },
        "review_flow": {
            "terminal_state": "",
            "response_mode": COMPACT_RESPONSE_MODE,
            "review_id_ref": "",
            "first_receipt_used_as_verdict": False,
            "total_count": 0,
            "all_page_finding_count": 0,
            "raw_returned": False,
            "handshake": {
                "review_job_terminal": False,
                "review_receipt_present": False,
                "primary_workflow_present": False,
                "release_review_contract_present": False,
                "guardian_handoff_present": False,
                "review_coverage_present": False,
                "response_contract_mode": COMPACT_RESPONSE_CONTRACT_MODE,
                "next_tool_type": "",
                "not_inspected_type": "",
                "canonical_release_authority_type": "",
                "repository_content_role_type": "",
                "scope_reduction_for_client_timeout_type": "",
                "review_receipt_eligible_for_release_review": False,
                "primary_workflow_release_review_eligible": False,
                "release_contract_eligible_to_start_guardian": False,
                "guardian_handoff_eligible_to_start_guardian": False,
                "release_review_contract_status": "",
                "guardian_handoff_status": "",
                "top_level_next_tool_value": "",
                "primary_workflow_next_tool_value": "",
                "release_contract_next_tool_value": "",
                "guardian_handoff_next_tool_value": "",
                "top_level_canonical_release_authority_value": False,
                "primary_workflow_canonical_release_authority_value": False,
                "release_contract_canonical_release_authority_value": False,
                "guardian_handoff_canonical_release_authority_value": False,
                "release_contract_release_verdict_issued": False,
                "guardian_handoff_release_verdict_issued": False,
                "review_coverage_status": "",
                "raw_returned": False,
            },
            "pages": [],
        },
        "reconnect": {
            "server_restarted": False,
            "client_reconnected": False,
            "tools_list_after_reconnect": {"advertised_count": 0, "required_tools_present": []},
            "post_reconnect_read_only_call": {"tool": "continue_review", "succeeded": False, "raw_returned": False},
        },
        "redaction_review": {
            "secrets_visible": False,
            "personal_data_visible": False,
            "local_identity_visible": False,
        },
        "review": {"verdict": "pending", "reviewed_at": "", "notes": ""},
    }


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _installation_errors(
    installation: object,
    *,
    recording_sha256: str = "",
) -> tuple[list[str], str, int]:
    errors: list[str] = []
    if not isinstance(installation, dict):
        return ["installation_invalid", "installed_wheel_sha256_missing", "installed_wheel_size_invalid"], "", 0
    if "wheel_sha256" not in installation or installation.get("wheel_sha256") in (None, ""):
        errors.append("installed_wheel_sha256_missing")
        wheel_sha256 = ""
    else:
        wheel_sha256 = str(installation.get("wheel_sha256") or "").lower()
        if not SHA256_RE.fullmatch(wheel_sha256):
            errors.append("installed_wheel_sha256_invalid")
    size = installation.get("wheel_size_bytes")
    if not _is_int(size) or size <= 0:
        errors.append("installed_wheel_size_invalid")
        size = 0
    if recording_sha256 and wheel_sha256 and wheel_sha256 == recording_sha256.lower():
        errors.append("installed_wheel_digest_matches_recording")
    return errors, wheel_sha256, size


def _release_binding_errors(
    value: object,
    authoritative: dict[str, Any] | None,
) -> tuple[list[str], dict[str, Any]]:
    if authoritative is None:
        return ["release_binding_authority_unavailable"], {}
    if not isinstance(value, dict):
        return ["release_binding_invalid"], {}
    expected = {
        key: authoritative[key]
        for key in (
            "receipt_locator",
            "receipt_sha256",
            "product_source_revision",
            "package_tree_hash_schema",
            "package_tree_sha256",
            "wheel_sha256",
            "wheel_size_bytes",
        )
    }
    errors: list[str] = []
    for key, expected_value in expected.items():
        observed = value.get(key)
        if isinstance(expected_value, str):
            observed = str(observed or "").lower() if key.endswith("sha256") or key.endswith("revision") else observed
        if observed != expected_value:
            errors.append(f"release_binding_{key}_mismatch")
    return sorted(set(errors)), expected


def _exposure_audit_receipt_errors(
    root: Path,
    exposure: dict[str, Any],
    *,
    client: str,
    run_id: str,
    product_revision: str,
) -> list[str]:
    locator = exposure.get("audit_receipt_locator")
    digest = str(exposure.get("audit_receipt_sha256") or "").lower()
    if not isinstance(locator, str) or not re.fullmatch(
        r"evidence/clients/audits/[A-Za-z0-9._-]+\.json", locator
    ):
        return ["exposure_audit_receipt_locator_invalid"]
    if not SHA256_RE.fullmatch(digest):
        return ["exposure_audit_receipt_sha256_invalid"]
    path = root / Path(locator)
    try:
        receipt_bytes = path.read_bytes()
        receipt = json.loads(receipt_bytes.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["exposure_audit_receipt_unreadable"]
    errors: list[str] = []
    if hashlib.sha256(receipt_bytes).hexdigest() != digest:
        errors.append("exposure_audit_receipt_digest_mismatch")
    if not isinstance(receipt, dict) or receipt.get("schema") != "k_guard_client_exposure_audit.v1":
        errors.append("exposure_audit_receipt_schema_invalid")
        return errors
    expected = {
        "client": client,
        "run_id": run_id,
        "product_source_revision": product_revision,
        "audit_method": EXPOSURE_AUDIT_METHOD,
        "audited_mcp_tool_call_count": exposure.get("audited_mcp_call_count"),
        "absolute_user_path_count": 0,
        "raw_returned_true_count": 0,
        "passed": True,
        "raw_returned": False,
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            errors.append(f"exposure_audit_receipt_{key}_mismatch")
    if not SHA256_RE.fullmatch(str(receipt.get("transcript_sha256") or "")):
        errors.append("exposure_audit_receipt_transcript_sha256_invalid")
    if receipt.get("transcript_published") is not False:
        errors.append("exposure_audit_receipt_transcript_publication_invalid")
    if receipt.get("tools_list_observed_separately") is not True:
        errors.append("exposure_audit_receipt_tools_list_invalid")
    return sorted(set(errors))


def _normalize_handshake(value: object) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if not isinstance(value, dict):
        value = {}
        errors.append("release_handshake_invalid")
    if value.get("review_job_terminal") is not True:
        errors.append("release_handshake_review_job_terminal_required")
    if value.get("response_contract_mode") != COMPACT_RESPONSE_CONTRACT_MODE:
        errors.append("release_handshake_response_contract_invalid")
    if value.get("raw_returned") is not False:
        errors.append("raw_boundary_invalid")
    present_flags = {}
    for name in HANDSHAKE_PRESENT_FIELDS:
        key = f"{name}_present"
        present_flags[key] = value.get(key) is True
        if key not in value or value.get(key) is not True:
            errors.append(f"release_handshake_{name}_missing")
    typed_fields = {}
    for name, expected in HANDSHAKE_TYPED_FIELDS.items():
        key = f"{name}_type"
        observed = value.get(key)
        typed_fields[key] = observed if isinstance(observed, str) else ""
        if key not in value:
            errors.append(f"release_handshake_{name}_missing")
        elif observed != expected:
            errors.append(f"release_handshake_{name}_type_invalid")

    eligibility: dict[str, bool] = {}
    eligibility_valid = True
    for name in HANDSHAKE_ELIGIBILITY_FIELDS:
        observed = value.get(name)
        if name not in value:
            errors.append(f"release_handshake_{name}_missing")
            eligibility_valid = False
        elif type(observed) is not bool:
            errors.append(f"release_handshake_{name}_type_invalid")
            eligibility_valid = False
        eligibility[name] = observed if type(observed) is bool else False
    eligibility_values = list(eligibility.values())
    if eligibility_valid and len(set(eligibility_values)) != 1:
        errors.append("release_handshake_eligibility_parity_invalid")
    eligible = eligibility_values[0] if eligibility_valid else False

    statuses: dict[str, str] = {}
    statuses_valid = True
    for name in HANDSHAKE_STATUS_FIELDS:
        observed = value.get(name)
        if name not in value:
            errors.append(f"release_handshake_{name}_missing")
            statuses_valid = False
        elif not isinstance(observed, str) or observed not in HANDSHAKE_ALLOWED_STATUSES:
            errors.append(f"release_handshake_{name}_invalid")
            statuses_valid = False
        statuses[name] = observed if isinstance(observed, str) else ""
    if statuses_valid and len(set(statuses.values())) != 1:
        errors.append("release_handshake_status_parity_invalid")
    contract_status = statuses[HANDSHAKE_STATUS_FIELDS[0]] if statuses_valid else ""
    if eligibility_valid and statuses_valid and ((contract_status == "ready") != eligible):
        errors.append("release_handshake_status_eligibility_mismatch")

    false_semantic_values: dict[str, bool] = {}
    for name in (*HANDSHAKE_CANONICAL_AUTHORITY_FIELDS, *HANDSHAKE_RELEASE_VERDICT_FIELDS):
        observed = value.get(name)
        if name not in value:
            errors.append(f"release_handshake_{name}_missing")
        elif type(observed) is not bool:
            errors.append(f"release_handshake_{name}_type_invalid")
        elif observed is not False:
            errors.append(f"release_handshake_{name}_invalid")
        false_semantic_values[name] = False

    next_tools: dict[str, str] = {}
    next_tools_valid = True
    for name in HANDSHAKE_NEXT_TOOL_FIELDS:
        observed = value.get(name)
        if not isinstance(observed, str) or not observed:
            errors.append(f"release_handshake_{name}_invalid")
            next_tools_valid = False
        next_tools[name] = observed if isinstance(observed, str) else ""
    if next_tools_valid and len(set(next_tools.values())) != 1:
        errors.append("release_handshake_next_tool_parity_invalid")
    if next_tools_valid and statuses_valid:
        expected_next_tool = "start_review_before_ship" if contract_status == "ready" else "check_my_app"
        if next_tools[HANDSHAKE_NEXT_TOOL_FIELDS[0]] != expected_next_tool:
            errors.append("release_handshake_next_tool_status_mismatch")

    coverage_status = value.get("review_coverage_status")
    if not isinstance(coverage_status, str) or coverage_status not in HANDSHAKE_ALLOWED_COVERAGE_STATUSES:
        errors.append("release_handshake_review_coverage_status_invalid")
        coverage_status = ""
    elif coverage_status == "unavailable_fail_closed" and eligibility_valid and eligible:
        errors.append("release_handshake_unavailable_coverage_eligible")

    normalized = {
        "review_job_terminal": value.get("review_job_terminal") is True,
        "response_contract_mode": value.get("response_contract_mode"),
        "raw_returned": False,
        **present_flags,
        **typed_fields,
        **eligibility,
        **statuses,
        **false_semantic_values,
        **next_tools,
        "review_coverage_status": coverage_status,
    }
    return normalized, errors


def _normalize_review_flow(value: Any, expected_review_id_ref: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if not isinstance(value, dict):
        value = {}
        errors.append("review_flow_invalid")
    terminal_state = value.get("terminal_state")
    if terminal_state in (None, ""):
        errors.append("continue_review_terminal_state_absent")
        terminal_state = ""
    elif terminal_state == "failed":
        errors.append("continue_review_terminal_state_failed")
    elif terminal_state != CONTINUE_REVIEW_TERMINAL_COMPLETED:
        errors.append("continue_review_terminal_state_invalid")
    if value.get("first_receipt_used_as_verdict") is not False:
        errors.append("continue_review_first_receipt_used_as_verdict")
    if value.get("response_mode") != COMPACT_RESPONSE_MODE:
        errors.append("compact_response_mode_required")
    review_id_ref = str(value.get("review_id_ref") or "").lower()
    if not _valid_identity_ref(review_id_ref):
        errors.append("continue_review_review_id_ref_invalid")
    if review_id_ref != expected_review_id_ref:
        errors.append("continue_review_review_id_mismatch")
    if value.get("raw_returned") is not False:
        errors.append("raw_boundary_invalid")

    handshake, handshake_errors = _normalize_handshake(value.get("handshake"))
    errors.extend(handshake_errors)

    pages = value.get("pages")
    if not isinstance(pages, list) or not pages:
        pages = []
        errors.append("compact_pagination_pages_missing")
    normalized_pages: list[dict[str, Any]] = []
    expected_offset = 0
    all_ids: list[str] = []
    terminal_page_seen = False
    for index, page in enumerate(pages):
        if not isinstance(page, dict):
            errors.append("compact_pagination_page_invalid")
            continue
        extra_keys = set(page) - PAGINATION_PAGE_KEYS
        if extra_keys:
            errors.append("compact_pagination_raw_fields")
        offset = page.get("finding_offset", page.get("offset"))
        has_more = page.get("has_more")
        next_offset = page.get("next_offset")
        returned_count = page.get("returned_count")
        raw_ids = page.get("finding_ids", page.get("finding_id_refs"))
        if index == 0 and offset != 0:
            errors.append("compact_pagination_offset_start_invalid")
        if not _is_int(offset) or offset < 0:
            errors.append("compact_pagination_offset_invalid")
            offset = expected_offset
        elif offset > expected_offset:
            errors.append("compact_pagination_cursor_skip")
        elif offset < expected_offset:
            errors.append("compact_pagination_cursor_stall")
        if not isinstance(raw_ids, list):
            errors.append("compact_pagination_finding_ids_invalid")
            ids: list[str] = []
        else:
            ids = []
            for item in raw_ids:
                text = str(item)
                if not FINDING_ID_RE.fullmatch(text):
                    errors.append("compact_pagination_finding_id_invalid")
                else:
                    ids.append(text)
        if not _is_int(returned_count) or returned_count != len(ids):
            errors.append("compact_pagination_count_mismatch")
        if page.get("raw_returned") is not False:
            errors.append("raw_boundary_invalid")
        is_last = index == len(pages) - 1
        advanced_to = offset + len(ids)
        if has_more is True:
            if is_last:
                errors.append("compact_pagination_has_more_terminal_required")
            if not _is_int(next_offset) or next_offset <= offset:
                errors.append("compact_pagination_cursor_stall")
            elif next_offset > advanced_to:
                errors.append("compact_pagination_cursor_skip")
            elif next_offset < advanced_to:
                errors.append("compact_pagination_cursor_stall")
            expected_offset = next_offset if _is_int(next_offset) else advanced_to
        elif has_more is False:
            if not is_last:
                errors.append("compact_pagination_terminated_early")
            if next_offset not in (None, advanced_to):
                if _is_int(next_offset) and next_offset > advanced_to:
                    errors.append("compact_pagination_cursor_skip")
                else:
                    errors.append("compact_pagination_cursor_stall")
            next_offset = None
            terminal_page_seen = True
            expected_offset = advanced_to
        else:
            errors.append("compact_pagination_has_more_invalid")
        all_ids.extend(ids)
        normalized_pages.append(
            {
                "finding_offset": offset,
                "returned_count": len(ids),
                "next_offset": next_offset if has_more is True else None,
                "has_more": has_more is True,
                "finding_ids": ids,
                "raw_returned": False,
            }
        )
    if not terminal_page_seen:
        errors.append("compact_pagination_has_more_terminal_required")
    unique_ids = set(all_ids)
    if len(all_ids) != len(unique_ids):
        errors.append("compact_pagination_duplicate_finding_id")
    declared_total = value.get("total_count")
    declared_all_page = value.get("all_page_finding_count")
    if declared_total != len(unique_ids) or declared_all_page != len(all_ids) or declared_total != declared_all_page:
        errors.append("compact_pagination_count_mismatch")
    if _is_int(declared_total) and len(unique_ids) < declared_total:
        errors.append("compact_pagination_missing_finding_id")

    normalized = {
        "terminal_state": terminal_state,
        "response_mode": COMPACT_RESPONSE_MODE if value.get("response_mode") == COMPACT_RESPONSE_MODE else value.get("response_mode"),
        "review_id_ref": review_id_ref,
        "first_receipt_used_as_verdict": False,
        "total_count": declared_total if _is_int(declared_total) else len(unique_ids),
        "all_page_finding_count": declared_all_page if _is_int(declared_all_page) else len(all_ids),
        "raw_returned": False,
        "handshake": handshake,
        "pages": normalized_pages,
    }
    return normalized, sorted(set(errors))


def _normalize_reconnect(value: Any) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if not isinstance(value, dict):
        value = {}
        errors.append("reconnect_invalid")
    for field in ("server_restarted", "client_reconnected"):
        if value.get(field) is not True:
            errors.append(f"reconnect_{field}_required")
    tool_list = value.get("tools_list_after_reconnect")
    if not isinstance(tool_list, dict):
        tool_list = {}
        errors.append("reconnect_tools_list_invalid")
    advertised_count = tool_list.get("advertised_count")
    present_value = tool_list.get("required_tools_present")
    present = sorted({str(item) for item in present_value}) if isinstance(present_value, list) else []
    if not isinstance(advertised_count, int) or isinstance(advertised_count, bool) or advertised_count < len(REQUIRED_TOOLS):
        errors.append("reconnect_tools_list_count_invalid")
        advertised_count = 0
    if not set(REQUIRED_TOOLS).issubset(set(present)):
        errors.append("reconnect_required_tools_missing")
    call = value.get("post_reconnect_read_only_call")
    if not isinstance(call, dict):
        call = {}
        errors.append("post_reconnect_read_only_call_invalid")
    tool = str(call.get("tool") or "")
    if tool not in READ_ONLY_POST_RECONNECT_TOOLS:
        errors.append("post_reconnect_tool_not_read_only")
    if call.get("succeeded") is not True:
        errors.append("post_reconnect_read_only_call_required")
    if call.get("raw_returned") is not False:
        errors.append("post_reconnect_raw_boundary_invalid")
    return {
        "server_restarted": value.get("server_restarted") is True,
        "client_reconnected": value.get("client_reconnected") is True,
        "tools_list_after_reconnect": {
            "advertised_count": advertised_count,
            "required_tools_present": present,
        },
        "post_reconnect_read_only_call": {
            "tool": tool,
            "succeeded": call.get("succeeded") is True,
            "raw_returned": False,
        },
    }, sorted(set(errors))


def collect_verified_run(
    observation: dict[str, Any],
    artifact_root: Path,
    *,
    expected_revision: str | None = None,
    repository_root: Path = ROOT,
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    serialized = json.dumps(observation, ensure_ascii=False, sort_keys=True)
    if observation.get("schema") != OBSERVATION_SCHEMA:
        errors.append("schema_invalid")
    client = str(observation.get("client") or "")
    if client not in CLIENTS:
        errors.append("client_invalid")
    run_id = str(observation.get("run_id") or "")
    if not RUN_ID_RE.fullmatch(run_id):
        errors.append("run_id_invalid")
    revision = str(observation.get("product_source_revision") or "").lower()
    if not REVISION_RE.fullmatch(revision):
        errors.append("product_source_revision_invalid")
    if expected_revision and revision != expected_revision.lower():
        errors.append("product_source_revision_mismatch")
    evidence_revision = str(observation.get("evidence_revision") or "").lower()
    if evidence_revision and not REVISION_RE.fullmatch(evidence_revision):
        errors.append("evidence_revision_invalid")
    recorded_at = str(observation.get("recorded_at") or "")
    if not _is_aware_iso8601(recorded_at):
        errors.append("recorded_at_invalid")

    operator_ref = str(observation.get("operator_ref") or "").lower()
    reviewer_ref = str(observation.get("reviewer_ref") or "").lower()
    if not _valid_identity_ref(operator_ref):
        errors.append("operator_ref_invalid")
    if not _valid_identity_ref(reviewer_ref):
        errors.append("reviewer_ref_invalid")
    if operator_ref == reviewer_ref:
        errors.append("separate_reviewer_reference_required")
    if any(pattern.search(serialized) for pattern in SECRET_PATTERNS):
        errors.append("raw_secret_pattern_detected")
    if any(pattern.search(serialized) for pattern in LOCAL_PATH_PATTERNS):
        errors.append("local_identity_path_detected")

    environment = observation.get("environment")
    if not isinstance(environment, dict):
        environment = {}
        errors.append("environment_invalid")
    for field in ("os", "client_version", "k_guard_version"):
        value = environment.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"environment_{field}_missing")
    if environment.get("profile") not in {"workspace", "local-dev"}:
        errors.append("environment_profile_invalid")

    installation_errors, wheel_sha256, wheel_size_bytes = _installation_errors(observation.get("installation"))
    errors.extend(installation_errors)
    authoritative_binding, authoritative_errors = _authoritative_release_binding(repository_root)
    errors.extend(authoritative_errors)
    release_binding_errors, release_binding = _release_binding_errors(
        observation.get("release_binding"), authoritative_binding
    )
    errors.extend(release_binding_errors)
    if release_binding:
        if revision != release_binding["product_source_revision"]:
            errors.append("product_source_revision_release_binding_mismatch")
        if wheel_sha256 != release_binding["wheel_sha256"]:
            errors.append("installed_wheel_release_binding_sha256_mismatch")
        if wheel_size_bytes != release_binding["wheel_size_bytes"]:
            errors.append("installed_wheel_release_binding_size_mismatch")

    recording = observation.get("recording")
    if not isinstance(recording, dict):
        recording = {}
        errors.append("recording_invalid")
    artifact_name = str(recording.get("artifact") or "")
    artifact_path, artifact_error = _resolve_artifact(artifact_root, artifact_name)
    if artifact_error:
        errors.append(artifact_error)
    published_locator = str(recording.get("published_locator") or "")
    if not published_locator or _contains_local_path(published_locator):
        errors.append("published_locator_invalid")
    duration = recording.get("duration_seconds")
    if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration < 10:
        errors.append("recording_duration_too_short")
        duration = 0
    if recording.get("evidence_mode") != RECORDING_EVIDENCE_MODE:
        errors.append("recording_evidence_mode_invalid")

    exposure = observation.get("exposure_evidence")
    if not isinstance(exposure, dict):
        exposure = {}
        errors.append("exposure_evidence_invalid")
    client_context_exposure = exposure.get("client_self_reported_context_exposure")
    if not isinstance(client_context_exposure, bool):
        errors.append("client_self_reported_context_exposure_invalid")
        client_context_exposure = False
    if exposure.get("deterministic_mcp_response_exposure") is not False:
        errors.append("deterministic_mcp_response_exposure_detected")
    provenance = exposure.get("assessment_provenance")
    deterministic_available = exposure.get("deterministic_verification_available")
    audited_call_count = exposure.get("audited_mcp_call_count")
    if provenance == EXPOSURE_PROVENANCE_DETERMINISTIC:
        if exposure.get("audit_method") != EXPOSURE_AUDIT_METHOD:
            errors.append("exposure_audit_method_invalid")
        if deterministic_available is not True:
            errors.append("exposure_deterministic_verification_flag_invalid")
        if not _is_int(audited_call_count) or audited_call_count < 1:
            errors.append("exposure_audited_call_count_invalid")
            audited_call_count = 0
        errors.extend(
            _exposure_audit_receipt_errors(
                repository_root,
                exposure,
                client=client,
                run_id=run_id,
                product_revision=revision,
            )
        )
    elif provenance == EXPOSURE_PROVENANCE_SELF_REPORTED:
        if exposure.get("audit_method") != EXPOSURE_SELF_REPORT_METHOD:
            errors.append("exposure_audit_method_invalid")
        if deterministic_available is not False:
            errors.append("exposure_deterministic_verification_flag_invalid")
        if exposure.get("audit_receipt_locator") is not None or exposure.get("audit_receipt_sha256") is not None:
            errors.append("exposure_unverified_audit_receipt_forbidden")
        if audited_call_count != 0:
            errors.append("exposure_self_reported_call_count_must_be_zero")
        audited_call_count = 0
    else:
        errors.append("exposure_assessment_provenance_invalid")
        deterministic_available = False
        audited_call_count = 0
    for field in ("absolute_user_path_count", "raw_returned_true_count"):
        if exposure.get(field) != 0:
            errors.append(f"exposure_{field}_nonzero")
    if exposure.get("all_mcp_tool_raw_returned_false") is not True:
        errors.append("exposure_raw_returned_audit_invalid")
    expected_classification = (
        EXPOSURE_OUT_OF_SCOPE_CLASSIFICATION if client_context_exposure else EXPOSURE_CLEAR_CLASSIFICATION
    )
    if exposure.get("classification") != expected_classification:
        errors.append("exposure_classification_invalid")
    if exposure.get("claim_boundary") != "MCP response boundary only; client startup and supplied cwd metadata are excluded":
        errors.append("exposure_claim_boundary_invalid")

    stages = observation.get("stages")
    if not isinstance(stages, dict):
        stages = {}
        errors.append("stages_invalid")
    normalized_stages: dict[str, dict[str, Any]] = {}
    previous_stage_end = -1
    for stage in REQUIRED_STAGES:
        row = stages.get(stage)
        if not isinstance(row, dict):
            errors.append(f"stage_{stage}_missing")
            continue
        if row.get("passed") is not True:
            errors.append(f"stage_{stage}_not_passed")
        timecode = str(row.get("timecode") or "")
        bounds = _timecode_bounds(timecode)
        if bounds is None or bounds[1] <= bounds[0]:
            errors.append(f"stage_{stage}_timecode_invalid")
        elif duration and bounds[1] > float(duration) + 1:
            errors.append(f"stage_{stage}_timecode_out_of_range")
        elif bounds[0] < previous_stage_end:
            errors.append(f"stage_{stage}_sequence_invalid")
        else:
            previous_stage_end = bounds[1]
        note = str(row.get("observation") or "").strip()
        if not 3 <= len(note) <= 240 or "\n" in note or "\r" in note:
            errors.append(f"stage_{stage}_observation_invalid")
        normalized_stages[stage] = {"passed": row.get("passed") is True, "timecode": timecode, "observation": note}

    tool_list = observation.get("tool_list")
    if not isinstance(tool_list, dict):
        tool_list = {}
        errors.append("tool_list_invalid")
    advertised_count = tool_list.get("advertised_count")
    if not isinstance(advertised_count, int) or isinstance(advertised_count, bool) or advertised_count < len(REQUIRED_TOOLS):
        errors.append("tool_list_count_invalid")
        advertised_count = 0
    present_tools = tool_list.get("required_tools_present")
    present = {str(item) for item in present_tools} if isinstance(present_tools, list) else set()
    missing_tools = sorted(set(REQUIRED_TOOLS) - present)
    if missing_tools:
        errors.append("tool_list_required_tools_missing:" + ",".join(missing_tools))

    check_result = observation.get("check_my_app")
    if not isinstance(check_result, dict):
        check_result = {}
        errors.append("check_my_app_result_invalid")
    if check_result.get("state") != "running":
        errors.append("check_my_app_first_state_invalid")
    if check_result.get("presentation_code") != "review_in_progress":
        errors.append("check_my_app_presentation_code_invalid")
    if check_result.get("first_receipt") is not True:
        errors.append("check_my_app_first_receipt_missing")
    review_id_ref = str(check_result.get("review_id_ref") or "").lower()
    if not _valid_identity_ref(review_id_ref):
        errors.append("check_my_app_review_id_ref_invalid")
    if check_result.get("raw_returned") is not False:
        errors.append("check_my_app_raw_boundary_invalid")
    if check_result.get("review_scope") not in ALLOWED_REVIEW_SCOPES:
        errors.append("check_my_app_scope_invalid")

    review_flow, review_flow_errors = _normalize_review_flow(observation.get("review_flow"), review_id_ref)
    errors.extend(review_flow_errors)

    reconnect, reconnect_errors = _normalize_reconnect(observation.get("reconnect"))
    errors.extend(reconnect_errors)

    redaction = observation.get("redaction_review")
    if not isinstance(redaction, dict):
        redaction = {}
        errors.append("redaction_review_invalid")
    for field in ("secrets_visible", "personal_data_visible", "local_identity_visible"):
        if redaction.get(field) is not False:
            errors.append(f"redaction_{field}")

    review = observation.get("review")
    if not isinstance(review, dict):
        review = {}
        errors.append("review_invalid")
    if review.get("verdict") != "pass":
        errors.append("separate_review_assertion_not_passed")
    reviewed_at = str(review.get("reviewed_at") or "")
    if not _is_aware_iso8601(reviewed_at):
        errors.append("reviewed_at_invalid")
    elif _is_aware_iso8601(recorded_at) and _parse_iso8601(reviewed_at) < _parse_iso8601(recorded_at):
        errors.append("reviewed_before_recording")
    notes = str(review.get("notes") or "").strip()
    if not 3 <= len(notes) <= 500 or "\r" in notes:
        errors.append("review_notes_invalid")

    if errors or artifact_path is None:
        return None, sorted(set(errors))

    artifact_sha256 = _file_sha256(artifact_path)
    if wheel_sha256 == artifact_sha256:
        return None, ["installed_wheel_digest_matches_recording"]
    video_probe, video_probe_errors = _optional_video_probe_binding(
        repository_root,
        client=client,
        published_locator=published_locator,
        recording_sha256=artifact_sha256,
        recording_size_bytes=artifact_path.stat().st_size,
        duration_seconds=float(duration),
    )
    if video_probe_errors:
        return None, video_probe_errors
    record: dict[str, Any] = {
        "schema": VERIFIED_RUN_SCHEMA,
        "client": client,
        "run_id": run_id,
        "product_source_revision": revision,
        "evidence_revision": evidence_revision or None,
        "recorded_at": recorded_at,
        "operator_ref": operator_ref,
        "reviewer_ref": reviewer_ref,
        "environment": {
            "os": str(environment["os"]).strip(),
            "client_version": str(environment["client_version"]).strip(),
            "k_guard_version": str(environment["k_guard_version"]).strip(),
            "profile": environment["profile"],
        },
        "installation": {
            "wheel_sha256": wheel_sha256,
            "wheel_size_bytes": wheel_size_bytes,
        },
        "release_binding": {
            **release_binding,
            "receipt_schema": RELEASE_BINDING_RECEIPT_SCHEMA,
            "wheel_locator": RELEASE_BINDING_WHEEL.as_posix(),
            "site_packages_loaded": True,
            "source_installed_tree_equal": True,
            "raw_returned": False,
        },
        "recording": {
            "artifact_name": Path(artifact_name).as_posix(),
            "published_locator": published_locator,
            "sha256": artifact_sha256,
            "size_bytes": artifact_path.stat().st_size,
            "duration_seconds": duration,
            "evidence_mode": RECORDING_EVIDENCE_MODE,
            "visual_probe": video_probe,
        },
        "exposure_evidence": {
            "client_self_reported_context_exposure": client_context_exposure,
            "deterministic_mcp_response_exposure": False,
            "audit_method": exposure.get("audit_method"),
            "assessment_provenance": provenance,
            "deterministic_verification_available": deterministic_available,
            "audit_receipt_locator": exposure.get("audit_receipt_locator"),
            "audit_receipt_sha256": exposure.get("audit_receipt_sha256"),
            "audited_mcp_call_count": audited_call_count,
            "absolute_user_path_count": 0,
            "raw_returned_true_count": 0,
            "all_mcp_tool_raw_returned_false": True,
            "classification": expected_classification,
            "claim_boundary": "MCP response boundary only; client startup and supplied cwd metadata are excluded",
        },
        "stages": normalized_stages,
        "tool_contract": {
            "advertised_count": advertised_count,
            "required_tools": list(REQUIRED_TOOLS),
            "required_tools_present": sorted(present),
        },
        "check_my_app": {
            "state": "running",
            "presentation_code": "review_in_progress",
            "first_receipt": True,
            "review_id_ref": review_id_ref,
            "raw_returned": False,
            "review_scope": check_result["review_scope"],
        },
        "review_flow": review_flow,
        "reconnect": reconnect,
        "redaction_review": {
            "secrets_visible": False,
            "personal_data_visible": False,
            "local_identity_visible": False,
        },
        "separate_review_assertion": {
            "verdict": "pass",
            "reviewed_at": reviewed_at,
            "notes": notes,
            "provenance": "self_attested",
            "external_identity_verified": False,
            "independence_verified": False,
        },
        "release_handshake_semantic_assertion": {
            "provenance": "self_attested_operator_transcription",
            "canonical_terminal_response_digest_bound": False,
            "supporting_evidence": ["recording", "separate_review_assertion"],
            "claim_boundary": "semantic_parity_not_cryptographic_terminal_response_binding",
        },
        "verification": {
            "verified": True,
            "required_stage_count": len(REQUIRED_STAGES),
            "artifact_digest_verified": True,
            "installed_wheel_binding_verified": True,
            "release_receipt_binding_verified": True,
            "product_package_tree_binding_verified": True,
            "deterministic_mcp_response_exposure_audit_verified": deterministic_available,
            "continue_review_terminal_verified": True,
            "compact_pagination_verified": True,
            "release_handshake_verified": True,
            "reconnect_contract_verified": True,
            "separate_reviewer_reference_verified": True,
            "external_reviewer_identity_verified": False,
            "raw_returned": False,
        },
        "raw_returned": False,
    }
    record["record_sha256"] = _canonical_sha256(record)
    return record, []


def validate_verified_run(
    record: dict[str, Any],
    *,
    repository_root: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    serialized = json.dumps(record, ensure_ascii=False, sort_keys=True)
    if record.get("schema") != VERIFIED_RUN_SCHEMA:
        errors.append("schema_invalid")
    if record.get("client") not in CLIENTS:
        errors.append("client_invalid")
    if not RUN_ID_RE.fullmatch(str(record.get("run_id") or "")):
        errors.append("run_id_invalid")
    product_revision = str(record.get("product_source_revision") or "").lower()
    if not REVISION_RE.fullmatch(product_revision):
        errors.append("product_source_revision_invalid")
    evidence_revision = record.get("evidence_revision")
    if evidence_revision not in (None, "") and not REVISION_RE.fullmatch(str(evidence_revision)):
        errors.append("evidence_revision_invalid")
    if not _is_aware_iso8601(str(record.get("recorded_at") or "")):
        errors.append("recorded_at_invalid")
    operator_ref = str(record.get("operator_ref") or "")
    reviewer_ref = str(record.get("reviewer_ref") or "")
    if not _valid_identity_ref(operator_ref) or not _valid_identity_ref(reviewer_ref):
        errors.append("review_identity_invalid")
    if operator_ref == reviewer_ref:
        errors.append("separate_reviewer_reference_required")
    if any(pattern.search(serialized) for pattern in SECRET_PATTERNS):
        errors.append("raw_secret_pattern_detected")
    if any(pattern.search(serialized) for pattern in LOCAL_PATH_PATTERNS):
        errors.append("local_identity_path_detected")

    environment = record.get("environment")
    if not isinstance(environment, dict):
        environment = {}
        errors.append("environment_invalid")
    for field in ("os", "client_version", "k_guard_version"):
        if not isinstance(environment.get(field), str) or not str(environment.get(field)).strip():
            errors.append(f"environment_{field}_missing")
    if environment.get("profile") not in {"workspace", "local-dev"}:
        errors.append("environment_profile_invalid")

    recording = record.get("recording")
    if not isinstance(recording, dict):
        recording = {}
        errors.append("recording_invalid")
    if not SHA256_RE.fullmatch(str(recording.get("sha256") or "")):
        errors.append("recording_sha256_invalid")
    if not isinstance(recording.get("size_bytes"), int) or int(recording.get("size_bytes") or 0) < MIN_VIDEO_BYTES:
        errors.append("recording_size_invalid")
    if not isinstance(recording.get("duration_seconds"), (int, float)) or float(recording.get("duration_seconds") or 0) < 10:
        errors.append("recording_duration_invalid")
    if recording.get("evidence_mode") != RECORDING_EVIDENCE_MODE:
        errors.append("recording_evidence_mode_invalid")
    artifact_name = str(recording.get("artifact_name") or "")
    artifact_relative = Path(artifact_name)
    if (
        not artifact_name
        or artifact_relative.is_absolute()
        or bool(artifact_relative.drive)
        or ".." in artifact_relative.parts
        or artifact_relative.suffix.lower() not in VIDEO_SUFFIXES
    ):
        errors.append("recording_artifact_name_invalid")
    if not str(recording.get("published_locator") or "") or _contains_local_path(str(recording.get("published_locator") or "")):
        errors.append("published_locator_invalid")
    visual_probe = recording.get("visual_probe")
    if visual_probe is not None and not isinstance(visual_probe, dict):
        errors.append("video_probe_binding_invalid")
    elif isinstance(visual_probe, dict):
        if visual_probe.get("decoder_accepted") is not True:
            errors.append("video_probe_decoder_invalid")
        if not SHA256_RE.fullmatch(str(visual_probe.get("receipt_sha256") or "")):
            errors.append("video_probe_receipt_sha256_invalid")
        if not SHA256_RE.fullmatch(str(visual_probe.get("representative_frame_sha256") or "")):
            errors.append("video_probe_frame_sha256_invalid")
        if not _is_int(visual_probe.get("representative_frame_size_bytes")) or int(
            visual_probe.get("representative_frame_size_bytes") or 0
        ) <= 0:
            errors.append("video_probe_frame_size_invalid")
        if repository_root is not None:
            expected_probe, probe_errors = _optional_video_probe_binding(
                repository_root,
                client=str(record.get("client") or ""),
                published_locator=str(recording.get("published_locator") or ""),
                recording_sha256=str(recording.get("sha256") or ""),
                recording_size_bytes=(
                    int(recording["size_bytes"]) if _is_int(recording.get("size_bytes")) else 0
                ),
                duration_seconds=(
                    float(recording["duration_seconds"])
                    if isinstance(recording.get("duration_seconds"), (int, float))
                    and not isinstance(recording.get("duration_seconds"), bool)
                    else 0
                ),
            )
            errors.extend(probe_errors)
            if expected_probe is None:
                errors.append("video_probe_binding_authority_unavailable")
            elif _canonical_sha256(visual_probe) != _canonical_sha256(expected_probe):
                errors.append("video_probe_binding_mismatch")

    installation_errors, _wheel_sha256, _wheel_size = _installation_errors(
        record.get("installation"),
        recording_sha256=str(recording.get("sha256") or ""),
    )
    errors.extend(installation_errors)
    exposure = record.get("exposure_evidence")
    if not isinstance(exposure, dict):
        exposure = {}
        errors.append("exposure_evidence_invalid")
    client_context_exposure = exposure.get("client_self_reported_context_exposure")
    if not isinstance(client_context_exposure, bool):
        errors.append("client_self_reported_context_exposure_invalid")
        client_context_exposure = False
    if exposure.get("deterministic_mcp_response_exposure") is not False:
        errors.append("deterministic_mcp_response_exposure_detected")
    provenance = exposure.get("assessment_provenance")
    deterministic_available = exposure.get("deterministic_verification_available")
    if provenance == EXPOSURE_PROVENANCE_DETERMINISTIC:
        if exposure.get("audit_method") != EXPOSURE_AUDIT_METHOD:
            errors.append("exposure_audit_method_invalid")
        if deterministic_available is not True:
            errors.append("exposure_deterministic_verification_flag_invalid")
        if not _is_int(exposure.get("audited_mcp_call_count")) or exposure.get("audited_mcp_call_count", 0) < 1:
            errors.append("exposure_audited_call_count_invalid")
        if repository_root is not None:
            errors.extend(
                _exposure_audit_receipt_errors(
                    repository_root,
                    exposure,
                    client=str(record.get("client") or ""),
                    run_id=str(record.get("run_id") or ""),
                    product_revision=product_revision,
                )
            )
        elif not SHA256_RE.fullmatch(str(exposure.get("audit_receipt_sha256") or "")):
            errors.append("exposure_audit_receipt_sha256_invalid")
    elif provenance == EXPOSURE_PROVENANCE_SELF_REPORTED:
        if exposure.get("audit_method") != EXPOSURE_SELF_REPORT_METHOD:
            errors.append("exposure_audit_method_invalid")
        if deterministic_available is not False:
            errors.append("exposure_deterministic_verification_flag_invalid")
        if exposure.get("audited_mcp_call_count") != 0:
            errors.append("exposure_self_reported_call_count_must_be_zero")
        if exposure.get("audit_receipt_locator") is not None or exposure.get("audit_receipt_sha256") is not None:
            errors.append("exposure_unverified_audit_receipt_forbidden")
    else:
        errors.append("exposure_assessment_provenance_invalid")
        deterministic_available = False
    if exposure.get("absolute_user_path_count") != 0:
        errors.append("exposure_absolute_user_path_count_nonzero")
    if exposure.get("raw_returned_true_count") != 0:
        errors.append("exposure_raw_returned_true_count_nonzero")
    if exposure.get("all_mcp_tool_raw_returned_false") is not True:
        errors.append("exposure_raw_returned_audit_invalid")
    expected_classification = (
        EXPOSURE_OUT_OF_SCOPE_CLASSIFICATION if client_context_exposure else EXPOSURE_CLEAR_CLASSIFICATION
    )
    if exposure.get("classification") != expected_classification:
        errors.append("exposure_classification_invalid")
    if exposure.get("claim_boundary") != "MCP response boundary only; client startup and supplied cwd metadata are excluded":
        errors.append("exposure_claim_boundary_invalid")
    release_binding = record.get("release_binding")
    if not isinstance(release_binding, dict):
        errors.append("release_binding_invalid")
    else:
        for key in (
            "receipt_sha256",
            "package_tree_sha256",
            "wheel_sha256",
        ):
            if not SHA256_RE.fullmatch(str(release_binding.get(key) or "")):
                errors.append(f"release_binding_{key}_invalid")
        if release_binding.get("receipt_locator") != RELEASE_BINDING_RECEIPT.as_posix():
            errors.append("release_binding_receipt_locator_invalid")
        if release_binding.get("receipt_schema") != RELEASE_BINDING_RECEIPT_SCHEMA:
            errors.append("release_binding_receipt_schema_invalid")
        if release_binding.get("product_source_revision") != product_revision:
            errors.append("release_binding_product_revision_mismatch")
        if release_binding.get("package_tree_hash_schema") != TREE_HASH_SCHEMA:
            errors.append("release_binding_tree_schema_invalid")
        if release_binding.get("wheel_locator") != RELEASE_BINDING_WHEEL.as_posix():
            errors.append("release_binding_wheel_locator_invalid")
        if release_binding.get("wheel_sha256") != _wheel_sha256:
            errors.append("release_binding_installed_wheel_sha256_mismatch")
        if release_binding.get("wheel_size_bytes") != _wheel_size:
            errors.append("release_binding_installed_wheel_size_mismatch")
        if release_binding.get("site_packages_loaded") is not True:
            errors.append("release_binding_site_packages_not_loaded")
        if release_binding.get("source_installed_tree_equal") is not True:
            errors.append("release_binding_source_installed_tree_not_equal")
        if release_binding.get("raw_returned") is not False:
            errors.append("release_binding_raw_boundary_invalid")
    if repository_root is not None:
        authoritative, authoritative_errors = _authoritative_release_binding(repository_root)
        errors.extend(authoritative_errors)
        binding_errors, _ = _release_binding_errors(release_binding, authoritative)
        errors.extend(binding_errors)

    stages = record.get("stages")
    if not isinstance(stages, dict) or set(stages) != set(REQUIRED_STAGES):
        errors.append("required_stages_invalid")
    else:
        duration = float(recording.get("duration_seconds") or 0)
        previous_stage_end = -1
        for stage in REQUIRED_STAGES:
            row = stages[stage]
            if not isinstance(row, dict) or row.get("passed") is not True:
                errors.append(f"stage_{stage}_not_passed")
                continue
            bounds = _timecode_bounds(str(row.get("timecode") or ""))
            if bounds is None or bounds[1] <= bounds[0] or (duration and bounds[1] > duration + 1):
                errors.append(f"stage_{stage}_timecode_invalid")
            elif bounds[0] < previous_stage_end:
                errors.append(f"stage_{stage}_sequence_invalid")
            else:
                previous_stage_end = bounds[1]
            note = str(row.get("observation") or "").strip()
            if not 3 <= len(note) <= 240 or "\n" in note or "\r" in note:
                errors.append(f"stage_{stage}_observation_invalid")

    tool_contract = record.get("tool_contract")
    if not isinstance(tool_contract, dict):
        tool_contract = {}
        errors.append("tool_contract_invalid")
    present = tool_contract.get("required_tools_present")
    if not isinstance(present, list) or not set(REQUIRED_TOOLS).issubset({str(item) for item in present}):
        errors.append("required_tools_missing")
    if tool_contract.get("required_tools") != list(REQUIRED_TOOLS):
        errors.append("required_tools_contract_invalid")
    advertised_count = tool_contract.get("advertised_count")
    if not isinstance(advertised_count, int) or isinstance(advertised_count, bool) or advertised_count < len(REQUIRED_TOOLS):
        errors.append("advertised_tool_count_invalid")
    check_result = record.get("check_my_app")
    if not isinstance(check_result, dict) or check_result.get("state") != "running":
        errors.append("check_my_app_contract_invalid")
    elif check_result.get("presentation_code") != "review_in_progress":
        errors.append("check_my_app_contract_invalid")
    elif check_result.get("first_receipt") is not True or check_result.get("raw_returned") is not False:
        errors.append("check_my_app_contract_invalid")
    elif check_result.get("review_scope") not in ALLOWED_REVIEW_SCOPES:
        errors.append("check_my_app_scope_invalid")
    review_id_ref = str(check_result.get("review_id_ref") or "").lower() if isinstance(check_result, dict) else ""
    if not _valid_identity_ref(review_id_ref):
        errors.append("check_my_app_review_id_ref_invalid")
    normalized_review_flow, review_flow_errors = _normalize_review_flow(record.get("review_flow"), review_id_ref)
    errors.extend(review_flow_errors)
    if record.get("review_flow") != normalized_review_flow:
        errors.append("review_flow_not_canonical")
    normalized_reconnect, reconnect_errors = _normalize_reconnect(record.get("reconnect"))
    errors.extend(reconnect_errors)
    if record.get("reconnect") != normalized_reconnect:
        errors.append("reconnect_contract_not_canonical")
    redaction = record.get("redaction_review")
    if not isinstance(redaction, dict) or any(
        redaction.get(field) is not False
        for field in ("secrets_visible", "personal_data_visible", "local_identity_visible")
    ):
        errors.append("redaction_review_invalid")
    review_assertion = record.get("separate_review_assertion")
    if not isinstance(review_assertion, dict) or review_assertion.get("verdict") != "pass":
        errors.append("separate_review_assertion_invalid")
    else:
        if not _is_aware_iso8601(str(review_assertion.get("reviewed_at") or "")):
            errors.append("reviewed_at_invalid")
        elif _is_aware_iso8601(str(record.get("recorded_at") or "")) and _parse_iso8601(
            str(review_assertion.get("reviewed_at") or "")
        ) < _parse_iso8601(str(record.get("recorded_at") or "")):
            errors.append("reviewed_before_recording")
        notes = str(review_assertion.get("notes") or "")
        if not 3 <= len(notes.strip()) <= 500 or "\r" in notes:
            errors.append("review_notes_invalid")
        if review_assertion.get("provenance") != "self_attested":
            errors.append("review_assertion_provenance_invalid")
        if review_assertion.get("external_identity_verified") is not False:
            errors.append("review_assertion_external_identity_invalid")
        if review_assertion.get("independence_verified") is not False:
            errors.append("review_assertion_independence_invalid")
    semantic_assertion = record.get("release_handshake_semantic_assertion")
    if not isinstance(semantic_assertion, dict):
        errors.append("release_handshake_semantic_assertion_invalid")
    else:
        if semantic_assertion.get("provenance") != "self_attested_operator_transcription":
            errors.append("release_handshake_semantic_assertion_provenance_invalid")
        if semantic_assertion.get("canonical_terminal_response_digest_bound") is not False:
            errors.append("release_handshake_terminal_digest_boundary_invalid")
        if semantic_assertion.get("supporting_evidence") != ["recording", "separate_review_assertion"]:
            errors.append("release_handshake_supporting_evidence_invalid")
        if semantic_assertion.get("claim_boundary") != "semantic_parity_not_cryptographic_terminal_response_binding":
            errors.append("release_handshake_semantic_claim_boundary_invalid")
    verification = record.get("verification")
    if not isinstance(verification, dict) or any(
        verification.get(field) is not True
        for field in (
            "verified",
            "artifact_digest_verified",
            "installed_wheel_binding_verified",
            "release_receipt_binding_verified",
            "product_package_tree_binding_verified",
            "continue_review_terminal_verified",
            "compact_pagination_verified",
            "release_handshake_verified",
            "reconnect_contract_verified",
            "separate_reviewer_reference_verified",
        )
    ):
        errors.append("verification_contract_invalid")
    elif verification.get("deterministic_mcp_response_exposure_audit_verified") is not deterministic_available:
        errors.append("verification_exposure_provenance_mismatch")
    elif verification.get("external_reviewer_identity_verified") is not False:
        errors.append("verification_external_identity_invalid")
    elif verification.get("required_stage_count") != len(REQUIRED_STAGES):
        errors.append("verification_stage_count_invalid")
    if record.get("raw_returned") is not False or (isinstance(verification, dict) and verification.get("raw_returned") is not False):
        errors.append("raw_boundary_invalid")

    expected_record_sha256 = str(record.get("record_sha256") or "")
    unsigned = dict(record)
    unsigned.pop("record_sha256", None)
    if not SHA256_RE.fullmatch(expected_record_sha256) or _canonical_sha256(unsigned) != expected_record_sha256:
        errors.append("record_sha256_invalid")
    return sorted(set(errors))


def build_status(
    runs_dir: Path,
    *,
    required_minimum: int = 3,
    repository_root: Path = ROOT,
    release_binding_root: Path | None = None,
    expected_revision: str | None = None,
) -> dict[str, Any]:
    binding_root = release_binding_root or repository_root
    validation_errors: list[str] = []
    historical_nonqualifying_files: list[dict[str, str]] = []
    candidates: dict[str, list[tuple[dict[str, Any], str]]] = {client: [] for client in CLIENTS}
    if runs_dir.is_dir():
        for path in sorted(runs_dir.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                validation_errors.append(f"{path.name}:unreadable_json")
                continue
            if not isinstance(payload, dict):
                validation_errors.append(f"{path.name}:root_not_object")
                continue
            schema = payload.get("schema")
            if schema in HISTORICAL_VERIFIED_RUN_SCHEMAS:
                historical_nonqualifying_files.append({"file": path.name, "schema": str(schema)})
                continue
            errors = validate_verified_run(payload, repository_root=binding_root)
            errors.extend(_validate_published_artifact(payload, repository_root))
            if errors:
                validation_errors.extend(f"{path.name}:{error}" for error in errors)
                continue
            candidates[str(payload["client"])].append((payload, path.name))

    selected: dict[str, tuple[dict[str, Any], str]] = {}
    for client, rows in candidates.items():
        if rows:
            selected[client] = max(rows, key=lambda item: (str(item[0]["recorded_at"]), str(item[0]["run_id"])))

    digest_clients: dict[str, list[str]] = {}
    for client, (record, _) in selected.items():
        digest = str(record["recording"]["sha256"])
        digest_clients.setdefault(digest, []).append(client)
    duplicate_clients = {
        client
        for digest, clients in digest_clients.items()
        if len(clients) > 1
        for client in clients
    }
    for digest, clients in sorted(digest_clients.items()):
        if len(clients) > 1:
            validation_errors.append(f"recording_sha256_reused:{digest}:{','.join(sorted(clients))}")
    selected_revisions = sorted({str(record["product_source_revision"]) for record, _ in selected.values()})
    if len(selected_revisions) > 1:
        validation_errors.append("product_source_revision_mixed:" + ",".join(selected_revisions))
    if expected_revision and selected_revisions and selected_revisions != [expected_revision.lower()]:
        validation_errors.append("product_source_revision_not_release_bound:" + ",".join(selected_revisions))
    selected_wheels = sorted(
        {
            (str(record["installation"]["wheel_sha256"]), int(record["installation"]["wheel_size_bytes"]))
            for record, _ in selected.values()
        }
    )
    if len(selected_wheels) > 1:
        validation_errors.append(
            "installed_wheel_mixed:" + ",".join(f"{digest}:{size}" for digest, size in selected_wheels)
        )
    selected_release_bindings = {
        _canonical_sha256(record["release_binding"])
        for record, _ in selected.values()
    }
    if len(selected_release_bindings) > 1:
        validation_errors.append("release_binding_mixed")

    clients_status: dict[str, dict[str, Any]] = {}
    for client in CLIENTS:
        if client not in selected or client in duplicate_clients:
            clients_status[client] = {"status": "pending"}
            continue
        record, filename = selected[client]
        clients_status[client] = {
            "status": "verified",
            "run_id": record["run_id"],
            "product_source_revision": record["product_source_revision"],
            "evidence_revision": record.get("evidence_revision"),
            "installed_wheel_sha256": record["installation"]["wheel_sha256"],
            "installed_wheel_size_bytes": record["installation"]["wheel_size_bytes"],
            "recorded_at": record["recorded_at"],
            "recording_sha256": record["recording"]["sha256"],
            "recording_size_bytes": record["recording"]["size_bytes"],
            "published_locator": record["recording"]["published_locator"],
            "artifact_verified": True,
            "record_sha256": record["record_sha256"],
            "evidence_record": f"runs/{filename}",
            "release_binding_receipt_sha256": record["release_binding"]["receipt_sha256"],
            "package_tree_sha256": record["release_binding"]["package_tree_sha256"],
            "client_self_reported_context_exposure": record["exposure_evidence"][
                "client_self_reported_context_exposure"
            ],
            "deterministic_mcp_response_exposure": False,
            "exposure_assessment_provenance": record["exposure_evidence"]["assessment_provenance"],
            "deterministic_exposure_audit_verified": record["exposure_evidence"][
                "deterministic_verification_available"
            ],
            "required_stage_count": len(REQUIRED_STAGES),
            "separate_review_assertion_recorded": True,
            "external_independence_verified": False,
        }

    verified_clients = [client for client in CLIENTS if clients_status[client]["status"] == "verified"]
    ready = len(verified_clients) >= required_minimum and not validation_errors
    return {
        "schema": STATUS_SCHEMA,
        "required_minimum": required_minimum,
        "ready": ready,
        "verified_client_count": len(verified_clients),
        "verified_clients": verified_clients,
        "product_source_revision": selected_revisions[0] if len(selected_revisions) == 1 else None,
        "evidence_revisions": sorted(
            {
                str(record.get("evidence_revision"))
                for record, _ in selected.values()
                if record.get("evidence_revision")
            }
        ),
        "installed_wheel": (
            {"sha256": selected_wheels[0][0], "size_bytes": selected_wheels[0][1]}
            if len(selected_wheels) == 1
            else None
        ),
        "release_binding": (
            next(iter(selected.values()))[0]["release_binding"]
            if selected and len({
                _canonical_sha256(record["release_binding"])
                for record, _ in selected.values()
            }) == 1
            else None
        ),
        "clients": clients_status,
        "required_stages": list(REQUIRED_STAGES),
        "required_tools": list(REQUIRED_TOOLS),
        "validation_errors": sorted(validation_errors),
        "historical_nonqualifying_files": historical_nonqualifying_files,
        "review_provenance": "self_attested_separate_assertion",
        "release_handshake_semantic_assertion_provenance": "self_attested_operator_transcription",
        "canonical_terminal_response_digest_bound": False,
        "external_independence_verified": False,
        "claim_boundary": STATUS_CLAIM_BOUNDARY,
        "raw_returned": False,
    }


def validate_status(
    status: dict[str, Any],
    *,
    required_minimum: int = 3,
    repository_root: Path = ROOT,
    release_binding_root: Path | None = None,
    expected_revision: str | None = None,
) -> tuple[int, list[str]]:
    binding_root = release_binding_root or repository_root
    errors: list[str] = []
    if status.get("schema") != STATUS_SCHEMA:
        errors.append("schema_invalid")
    minimum = status.get("required_minimum")
    if (
        not isinstance(minimum, int)
        or isinstance(minimum, bool)
        or minimum < required_minimum
        or minimum > len(CLIENTS)
    ):
        errors.append("required_minimum_invalid")
        minimum = required_minimum
    clients = status.get("clients")
    if not isinstance(clients, dict):
        clients = {}
        errors.append("clients_invalid")
    if set(clients) != set(CLIENTS):
        errors.append("client_set_invalid")

    verified: list[str] = []
    recording_hashes: list[str] = []
    source_revisions: set[str] = set()
    wheel_bindings: set[tuple[str, int]] = set()
    release_receipt_digests: set[str] = set()
    package_tree_digests: set[str] = set()
    for client in CLIENTS:
        row = clients.get(client)
        if not isinstance(row, dict):
            errors.append(f"client_{client}_invalid")
            continue
        if row.get("status") == "pending":
            continue
        if row.get("status") != "verified":
            errors.append(f"client_{client}_status_invalid")
            continue
        verified.append(client)
        if not RUN_ID_RE.fullmatch(str(row.get("run_id") or "")):
            errors.append(f"client_{client}_run_id_invalid")
        row_revision = str(row.get("product_source_revision") or "")
        if not REVISION_RE.fullmatch(row_revision):
            errors.append(f"client_{client}_revision_invalid")
        else:
            source_revisions.add(row_revision)
            if expected_revision and row_revision != expected_revision.lower():
                errors.append(f"client_{client}_revision_not_release_bound")
        evidence_revision = row.get("evidence_revision")
        if evidence_revision not in (None, "") and not REVISION_RE.fullmatch(str(evidence_revision)):
            errors.append(f"client_{client}_evidence_revision_invalid")
        wheel_sha256 = str(row.get("installed_wheel_sha256") or "")
        wheel_size_bytes = row.get("installed_wheel_size_bytes")
        if not SHA256_RE.fullmatch(wheel_sha256):
            errors.append(f"client_{client}_installed_wheel_sha256_invalid")
        if not isinstance(wheel_size_bytes, int) or isinstance(wheel_size_bytes, bool) or wheel_size_bytes <= 0:
            errors.append(f"client_{client}_installed_wheel_size_invalid")
        elif SHA256_RE.fullmatch(wheel_sha256):
            wheel_bindings.add((wheel_sha256, wheel_size_bytes))
        if not _is_aware_iso8601(str(row.get("recorded_at") or "")):
            errors.append(f"client_{client}_recorded_at_invalid")
        recording_sha256 = str(row.get("recording_sha256") or "")
        if not SHA256_RE.fullmatch(recording_sha256):
            errors.append(f"client_{client}_recording_sha256_invalid")
        else:
            recording_hashes.append(recording_sha256)
        if not SHA256_RE.fullmatch(str(row.get("record_sha256") or "")):
            errors.append(f"client_{client}_record_sha256_invalid")
        size_bytes = row.get("recording_size_bytes")
        if not isinstance(size_bytes, int) or isinstance(size_bytes, bool) or size_bytes < MIN_VIDEO_BYTES:
            errors.append(f"client_{client}_recording_size_invalid")
        locator = str(row.get("published_locator") or "")
        artifact_path, artifact_error = _resolve_artifact(repository_root, locator)
        if artifact_error or artifact_path is None:
            errors.append(f"client_{client}_published_artifact_missing")
        else:
            if artifact_path.stat().st_size != size_bytes:
                errors.append(f"client_{client}_published_artifact_size_mismatch")
            if SHA256_RE.fullmatch(recording_sha256) and _file_sha256(artifact_path) != recording_sha256:
                errors.append(f"client_{client}_published_artifact_sha256_mismatch")
        if row.get("artifact_verified") is not True:
            errors.append(f"client_{client}_artifact_verification_missing")
        if row.get("required_stage_count") != len(REQUIRED_STAGES):
            errors.append(f"client_{client}_stage_count_invalid")
        if row.get("separate_review_assertion_recorded") is not True:
            errors.append(f"client_{client}_review_assertion_missing")
        if row.get("external_independence_verified") is not False:
            errors.append(f"client_{client}_external_independence_invalid")
        if not isinstance(row.get("client_self_reported_context_exposure"), bool):
            errors.append(f"client_{client}_context_exposure_self_report_invalid")
        if row.get("deterministic_mcp_response_exposure") is not False:
            errors.append(f"client_{client}_mcp_response_exposure_detected")
        provenance = row.get("exposure_assessment_provenance")
        if provenance not in {EXPOSURE_PROVENANCE_DETERMINISTIC, EXPOSURE_PROVENANCE_SELF_REPORTED}:
            errors.append(f"client_{client}_exposure_provenance_invalid")
        expected_deterministic = provenance == EXPOSURE_PROVENANCE_DETERMINISTIC
        if row.get("deterministic_exposure_audit_verified") is not expected_deterministic:
            errors.append(f"client_{client}_exposure_verification_mismatch")
        evidence_record = str(row.get("evidence_record") or "")
        if not re.fullmatch(r"runs/[A-Za-z0-9._-]+\.json", evidence_record):
            errors.append(f"client_{client}_record_path_invalid")
        receipt_digest = str(row.get("release_binding_receipt_sha256") or "")
        package_digest = str(row.get("package_tree_sha256") or "")
        if not SHA256_RE.fullmatch(receipt_digest):
            errors.append(f"client_{client}_release_receipt_sha256_invalid")
        else:
            release_receipt_digests.add(receipt_digest)
        if not SHA256_RE.fullmatch(package_digest):
            errors.append(f"client_{client}_package_tree_sha256_invalid")
        else:
            package_tree_digests.add(package_digest)

    if len(recording_hashes) != len(set(recording_hashes)):
        errors.append("recording_sha256_not_unique")
    if len(source_revisions) > 1:
        errors.append("product_source_revision_mixed")
    if len(wheel_bindings) > 1:
        errors.append("installed_wheel_mixed")
    expected_source = next(iter(source_revisions)) if len(source_revisions) == 1 else None
    if status.get("product_source_revision") != expected_source:
        errors.append("product_source_revision_summary_mismatch")
    expected_wheel = None
    if len(wheel_bindings) == 1:
        digest, size = next(iter(wheel_bindings))
        expected_wheel = {"sha256": digest, "size_bytes": size}
    if status.get("installed_wheel") != expected_wheel:
        errors.append("installed_wheel_summary_mismatch")
    if len(release_receipt_digests) > 1:
        errors.append("release_receipt_sha256_mixed")
    if len(package_tree_digests) > 1:
        errors.append("package_tree_sha256_mixed")
    authoritative, authoritative_errors = _authoritative_release_binding(binding_root)
    errors.extend(authoritative_errors)
    binding_errors, _ = _release_binding_errors(status.get("release_binding"), authoritative)
    errors.extend(binding_errors)
    if isinstance(status.get("release_binding"), dict):
        binding = status["release_binding"]
        if release_receipt_digests and release_receipt_digests != {binding.get("receipt_sha256")}:
            errors.append("release_receipt_summary_mismatch")
        if package_tree_digests and package_tree_digests != {binding.get("package_tree_sha256")}:
            errors.append("package_tree_summary_mismatch")
    evidence_revisions = status.get("evidence_revisions")
    expected_evidence_revisions = sorted(
        {
            str(row.get("evidence_revision"))
            for row in clients.values()
            if isinstance(row, dict) and row.get("status") == "verified" and row.get("evidence_revision")
        }
    )
    if evidence_revisions != expected_evidence_revisions:
        errors.append("evidence_revisions_summary_mismatch")
    expected_verified = [client for client in CLIENTS if client in verified]
    if status.get("verified_clients") != expected_verified:
        errors.append("verified_clients_mismatch")
    if status.get("verified_client_count") != len(verified):
        errors.append("verified_client_count_mismatch")
    source_errors = status.get("validation_errors")
    if not isinstance(source_errors, list):
        errors.append("validation_errors_invalid")
        source_errors = []
    elif source_errors:
        errors.extend(f"source:{item}" for item in source_errors)
    historical = status.get("historical_nonqualifying_files")
    if not isinstance(historical, list):
        errors.append("historical_nonqualifying_files_invalid")
    else:
        seen_historical: set[str] = set()
        for row in historical:
            if not isinstance(row, dict):
                errors.append("historical_nonqualifying_file_invalid")
                continue
            filename = row.get("file")
            schema = row.get("schema")
            if not isinstance(filename, str) or not re.fullmatch(r"[A-Za-z0-9._-]+\.json", filename):
                errors.append("historical_nonqualifying_filename_invalid")
            elif filename in seen_historical:
                errors.append("historical_nonqualifying_filename_duplicate")
            else:
                seen_historical.add(filename)
            if schema not in HISTORICAL_VERIFIED_RUN_SCHEMAS:
                errors.append("historical_nonqualifying_schema_invalid")
    expected_ready = len(verified) >= int(minimum) and not errors
    if status.get("ready") is not expected_ready:
        errors.append("ready_mismatch")
    if status.get("required_stages") != list(REQUIRED_STAGES):
        errors.append("required_stages_mismatch")
    if status.get("required_tools") != list(REQUIRED_TOOLS):
        errors.append("required_tools_mismatch")
    if status.get("review_provenance") != "self_attested_separate_assertion":
        errors.append("review_provenance_invalid")
    if status.get("release_handshake_semantic_assertion_provenance") != "self_attested_operator_transcription":
        errors.append("release_handshake_semantic_assertion_provenance_invalid")
    if status.get("canonical_terminal_response_digest_bound") is not False:
        errors.append("release_handshake_terminal_digest_boundary_invalid")
    if status.get("claim_boundary") != STATUS_CLAIM_BOUNDARY:
        errors.append("claim_boundary_invalid")
    if status.get("external_independence_verified") is not False:
        errors.append("external_independence_invalid")
    if status.get("raw_returned") is not False:
        errors.append("raw_boundary_invalid")
    return len(verified), sorted(set(errors))


def validate_status_against_runs(
    status: dict[str, Any],
    runs_dir: Path,
    *,
    required_minimum: int = 3,
    repository_root: Path = ROOT,
    release_binding_root: Path | None = None,
    expected_revision: str | None = None,
) -> list[str]:
    recomputed = build_status(
        runs_dir,
        required_minimum=required_minimum,
        repository_root=repository_root,
        release_binding_root=release_binding_root,
        expected_revision=expected_revision,
    )
    if _canonical_sha256(status) != _canonical_sha256(recomputed):
        return ["status_recomputed_projection_mismatch"]
    return []


def write_status_markdown(status: dict[str, Any], path: Path) -> None:
    rows = []
    for client in CLIENTS:
        row = status["clients"][client]
        if row["status"] == "verified":
            detail = f"{row['run_id']} / `{str(row['recording_sha256'])[:12]}...`"
        else:
            detail = "녹화·별도 review assertion 대기"
        rows.append(f"| {client} | {row['status']} | {detail} |")
    lines = [
        "# AI 클라이언트 상호운용 실증",
        "",
        f"- 최소 기준: `{status['required_minimum']}`개",
        f"- 검증 완료: `{status['verified_client_count']}`개",
        f"- 현재 v6 process 증거 게이트: `{'PASS' if status['ready'] else 'PENDING'}`",
        "- review provenance: `self-attested separate assertion`; 외부 심사자 신원·독립성 검증 아님",
        "- revision 경계: v6 evidence record는 fresh-wheel receipt가 고정한 product source revision, package tree, wheel SHA-256/바이트에 결속된다. evidence-only commit revision은 추적용 비게이트 필드이며 v5 이하는 현재 후보로 승격하지 않는다.",
        "",
        "| 클라이언트 | 상태 | 증거 |",
        "|---|---|---|",
        *rows,
        "",
        "## 판정 경계",
        "",
        str(status["claim_boundary"]),
    ]
    if status["validation_errors"]:
        lines.extend(["", "## 검증 오류", "", *[f"- `{item}`" for item in status["validation_errors"]]])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))


def refresh_evidence_manifest(repo_root: Path) -> Path:
    evidence_root = repo_root / "evidence"
    manifest = evidence_root / "SHA256SUMS"
    rows = []
    for path in sorted(evidence_root.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        if path.suffix.casefold() in {".csv", ".html", ".json", ".jsonl", ".md", ".txt", ".yaml", ".yml"}:
            content = path.read_bytes()
            normalized = content.replace(b"\r\n", b"\n")
            if normalized != content:
                path.write_bytes(normalized)
        relative = path.relative_to(repo_root).as_posix()
        rows.append(f"{_file_sha256(path)}  {relative}")
    manifest.write_bytes(("\n".join(rows) + "\n").encode("utf-8"))
    return manifest


def main(argv: list[str] | None = None, *, repo_root: Path | None = None) -> int:
    root = (repo_root or Path.cwd()).resolve()
    parser = argparse.ArgumentParser(description="Collect, verify, and summarize real AI-client MCP interoperability evidence.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create a fail-closed observation worksheet.")
    init_parser.add_argument("--client", choices=CLIENTS, required=True)
    init_parser.add_argument("--output")
    init_parser.add_argument("--force", action="store_true")

    collect_parser = subparsers.add_parser("collect", help="Validate an observation and hash its recording.")
    collect_parser.add_argument("--observation", required=True)
    collect_parser.add_argument("--artifact-root", required=True)
    collect_parser.add_argument("--output", required=True)
    collect_parser.add_argument("--expected-revision")

    summarize_parser = subparsers.add_parser("summarize", help="Build the four-client status and report table.")
    summarize_parser.add_argument("--runs", default=str(root / "evidence" / "clients" / "runs"))
    summarize_parser.add_argument("--output", default=str(root / "evidence" / "clients" / "interop-status.json"))
    summarize_parser.add_argument("--markdown", default=str(root / "docs" / "client-interop-status-ko.md"))
    summarize_parser.add_argument("--required-minimum", type=int, default=3)
    summarize_parser.add_argument("--refresh-manifest", action="store_true")

    verify_parser = subparsers.add_parser("verify-status", help="Recompute status invariants without trusting counts.")
    verify_parser.add_argument("--input", default=str(root / "evidence" / "clients" / "interop-status.json"))
    verify_parser.add_argument("--runs")

    args = parser.parse_args(argv)
    if args.command == "init":
        output = Path(args.output) if args.output else root / "tmp" / "client-interop" / f"{args.client}-observation.json"
        if output.exists() and not args.force:
            print(json.dumps({"ok": False, "error": "output_exists", "output": str(output)}, ensure_ascii=False))
            return 2
        binding, binding_errors = _authoritative_release_binding(root)
        if binding_errors or binding is None:
            print(json.dumps({"ok": False, "errors": binding_errors}, ensure_ascii=False))
            return 2
        observation = build_observation_template(
            args.client,
            binding["product_source_revision"],
            evidence_revision=_git_revision(root),
        )
        observation["release_binding"].update(
            {
                key: binding[key]
                for key in (
                    "receipt_locator",
                    "receipt_sha256",
                    "product_source_revision",
                    "package_tree_hash_schema",
                    "package_tree_sha256",
                    "wheel_sha256",
                    "wheel_size_bytes",
                )
            }
        )
        observation["installation"] = {
            "wheel_sha256": binding["wheel_sha256"],
            "wheel_size_bytes": binding["wheel_size_bytes"],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(
            (json.dumps(observation, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        )
        print(json.dumps({"ok": True, "output": str(output), "state": "observation_pending"}, ensure_ascii=False))
        return 0

    if args.command == "collect":
        observation_path = Path(args.observation)
        try:
            observation = json.loads(observation_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            print(json.dumps({"ok": False, "errors": ["observation_unreadable"]}, ensure_ascii=False))
            return 2
        if not isinstance(observation, dict):
            print(json.dumps({"ok": False, "errors": ["observation_root_not_object"]}, ensure_ascii=False))
            return 2
        binding, binding_errors = _authoritative_release_binding(root)
        expected_revision = args.expected_revision or (
            str(binding["product_source_revision"]) if binding else None
        )
        if binding_errors:
            print(json.dumps({"ok": False, "errors": binding_errors}, ensure_ascii=False))
            return 2
        record, errors = collect_verified_run(
            observation,
            Path(args.artifact_root),
            expected_revision=expected_revision,
            repository_root=root,
        )
        if errors or record is None:
            print(json.dumps({"ok": False, "errors": errors}, ensure_ascii=False))
            return 2
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes((json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        print(
            json.dumps(
                {
                    "ok": True,
                    "output": str(output),
                    "client": record["client"],
                    "recording_sha256": record["recording"]["sha256"],
                    "raw_returned": False,
                },
                ensure_ascii=False,
            )
        )
        return 0

    if args.command == "summarize":
        if args.required_minimum < 3 or args.required_minimum > len(CLIENTS):
            print(json.dumps({"ok": False, "error": "required_minimum_must_be_3_or_4"}, ensure_ascii=False))
            return 2
        binding, binding_errors = _authoritative_release_binding(root)
        if binding_errors or binding is None:
            print(json.dumps({"ok": False, "errors": binding_errors}, ensure_ascii=False))
            return 2
        status = build_status(
            Path(args.runs),
            required_minimum=args.required_minimum,
            repository_root=root,
            expected_revision=str(binding["product_source_revision"]),
        )
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes((json.dumps(status, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        write_status_markdown(status, Path(args.markdown))
        if args.refresh_manifest:
            refresh_evidence_manifest(root)
        print(
            json.dumps(
                {
                    "ok": not status["validation_errors"],
                    "ready": status["ready"],
                    "verified_client_count": status["verified_client_count"],
                    "validation_errors": status["validation_errors"],
                },
                ensure_ascii=False,
            )
        )
        return 0 if not status["validation_errors"] else 1

    try:
        status = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        print(json.dumps({"ok": False, "errors": ["status_unreadable"]}, ensure_ascii=False))
        return 2
    if not isinstance(status, dict):
        print(json.dumps({"ok": False, "errors": ["status_root_not_object"]}, ensure_ascii=False))
        return 2
    binding, binding_errors = _authoritative_release_binding(root)
    expected_revision = str(binding["product_source_revision"]) if binding else None
    count, errors = validate_status(status, repository_root=root, expected_revision=expected_revision)
    errors.extend(binding_errors)
    runs_dir = Path(args.runs) if args.runs else Path(args.input).resolve().parent / "runs"
    errors.extend(
        validate_status_against_runs(
            status,
            runs_dir,
            required_minimum=int(status.get("required_minimum") or 3),
            repository_root=root,
            expected_revision=expected_revision,
        )
    )
    print(json.dumps({"ok": not errors, "verified_client_count": count, "errors": errors}, ensure_ascii=False))
    return 0 if not errors else 1


def _resolve_artifact(root: Path, name: str) -> tuple[Path | None, str | None]:
    if not name:
        return None, "recording_artifact_missing"
    relative = Path(name)
    if (
        relative.is_absolute()
        or bool(relative.drive)
        or ".." in relative.parts
        or relative.suffix.lower() not in VIDEO_SUFFIXES
    ):
        return None, "recording_artifact_path_invalid"
    root_resolved = root.resolve()
    candidate = (root_resolved / relative).resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError:
        return None, "recording_artifact_path_invalid"
    if not candidate.is_file():
        return None, "recording_artifact_not_found"
    if candidate.stat().st_size < MIN_VIDEO_BYTES:
        return None, "recording_artifact_too_small"
    return candidate, None


def _validate_published_artifact(record: dict[str, Any], repository_root: Path) -> list[str]:
    recording = record.get("recording")
    if not isinstance(recording, dict):
        return ["published_artifact_recording_invalid"]
    locator = str(recording.get("published_locator") or "")
    artifact_path, artifact_error = _resolve_artifact(repository_root, locator)
    if artifact_error or artifact_path is None:
        return ["published_artifact_missing"]
    errors: list[str] = []
    if artifact_path.stat().st_size != recording.get("size_bytes"):
        errors.append("published_artifact_size_mismatch")
    expected_sha256 = str(recording.get("sha256") or "")
    if not SHA256_RE.fullmatch(expected_sha256) or _file_sha256(artifact_path) != expected_sha256:
        errors.append("published_artifact_sha256_mismatch")
    return errors


def _contains_local_path(value: str) -> bool:
    return any(pattern.search(value) for pattern in LOCAL_PATH_PATTERNS)


def _timecode_bounds(value: str) -> tuple[int, int] | None:
    parts = value.split("-")
    if len(parts) != 2:
        return None
    parsed = [_parse_timecode(part) for part in parts]
    if any(item is None for item in parsed):
        return None
    return int(parsed[0]), int(parsed[1])


def _parse_timecode(value: str) -> int | None:
    parts = value.split(":")
    if len(parts) not in {2, 3} or any(not part.isdigit() or len(part) != 2 for part in parts):
        return None
    numbers = [int(part) for part in parts]
    if numbers[-1] >= 60 or numbers[-2] >= 60:
        return None
    if len(numbers) == 2:
        return numbers[0] * 60 + numbers[1]
    return numbers[0] * 3600 + numbers[1] * 60 + numbers[2]


def _is_aware_iso8601(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() is not None


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _valid_identity_ref(value: str) -> bool:
    return bool(IDENTITY_RE.fullmatch(value)) and len(set(value.removeprefix("sha256:"))) >= 4


def _canonical_sha256(payload: dict[str, Any]) -> str:
    rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_revision(root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    revision = completed.stdout.strip().lower()
    if completed.returncode != 0 or not REVISION_RE.fullmatch(revision):
        raise RuntimeError("git revision unavailable")
    return revision


if __name__ == "__main__":
    raise SystemExit(main(repo_root=Path(__file__).resolve().parents[1]))
