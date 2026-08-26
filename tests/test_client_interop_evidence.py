from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "client_interop_evidence",
    ROOT / "scripts" / "client_interop_evidence.py",
)
assert SPEC and SPEC.loader
client_interop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client_interop)

CLIENTS = client_interop.CLIENTS
REQUIRED_STAGES = client_interop.REQUIRED_STAGES
REQUIRED_TOOLS = client_interop.REQUIRED_TOOLS
build_observation_template = client_interop.build_observation_template
build_status = client_interop.build_status
collect_verified_run = client_interop.collect_verified_run
validate_status = client_interop.validate_status
validate_status_against_runs = client_interop.validate_status_against_runs
validate_verified_run = client_interop.validate_verified_run
refresh_evidence_manifest = client_interop.refresh_evidence_manifest


if not (ROOT / client_interop.RELEASE_BINDING_RECEIPT).is_file() or not (
    ROOT / client_interop.RELEASE_BINDING_WHEEL
).is_file():
    pytest.skip(
        "release-binding wheel and receipt are distributed as release artifacts, not source files",
        allow_module_level=True,
    )


RELEASE_BINDING, RELEASE_BINDING_ERRORS = client_interop._authoritative_release_binding(ROOT)
assert RELEASE_BINDING_ERRORS == []
assert RELEASE_BINDING is not None
REVISION = str(RELEASE_BINDING["product_source_revision"])
WHEEL_SHA256 = str(RELEASE_BINDING["wheel_sha256"])
WHEEL_SIZE = int(RELEASE_BINDING["wheel_size_bytes"])


def _ref(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def _completed_observation(client: str, artifact_name: str) -> dict[str, object]:
    payload = build_observation_template(client, REVISION, evidence_revision="b" * 40)
    payload.update(
        {
            "run_id": f"{client}-20260713-01",
            "recorded_at": "2026-07-13T01:00:00Z",
            "operator_ref": "sha256:" + hashlib.sha256(b"operator-01").hexdigest(),
            "reviewer_ref": "sha256:" + hashlib.sha256(b"reviewer-01").hexdigest(),
        }
    )
    payload["environment"] = {
        "os": "Windows 11",
        "client_version": "1.2.3",
        "k_guard_version": "0.1.0",
        "profile": "local-dev",
    }
    payload["installation"] = {
        "wheel_sha256": WHEEL_SHA256,
        "wheel_size_bytes": WHEEL_SIZE,
    }
    payload["release_binding"].update(
        {
            key: RELEASE_BINDING[key]
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
    payload["recording"] = {
        "artifact": artifact_name,
        "published_locator": f"submission/client-interop/{artifact_name}",
        "duration_seconds": 90,
        "evidence_mode": client_interop.RECORDING_EVIDENCE_MODE,
    }
    payload["exposure_evidence"] = {
        "client_self_reported_context_exposure": False,
        "deterministic_mcp_response_exposure": False,
        "audit_method": client_interop.EXPOSURE_SELF_REPORT_METHOD,
        "assessment_provenance": client_interop.EXPOSURE_PROVENANCE_SELF_REPORTED,
        "deterministic_verification_available": False,
        "audit_receipt_locator": None,
        "audit_receipt_sha256": None,
        "audited_mcp_call_count": 0,
        "absolute_user_path_count": 0,
        "raw_returned_true_count": 0,
        "all_mcp_tool_raw_returned_false": True,
        "classification": client_interop.EXPOSURE_CLEAR_CLASSIFICATION,
        "claim_boundary": "MCP response boundary only; client startup and supplied cwd metadata are excluded",
    }
    payload["stages"] = {
        stage: {
            "passed": True,
            "timecode": f"00:{index * 10:02d}-00:{index * 10 + 5:02d}",
            "observation": f"{stage} 화면 확인",
        }
        for index, stage in enumerate(REQUIRED_STAGES)
    }
    payload["tool_list"] = {
        "advertised_count": 29,
        "required_tools_present": list(REQUIRED_TOOLS),
    }
    payload["check_my_app"] = {
        "state": "running",
        "presentation_code": "review_in_progress",
        "first_receipt": True,
        "review_id_ref": _ref(f"{client}-review"),
        "raw_returned": False,
        "review_scope": "owned_fixture",
    }
    payload["review_flow"] = {
        "terminal_state": "completed",
        "response_mode": "compact",
        "review_id_ref": _ref(f"{client}-review"),
        "first_receipt_used_as_verdict": False,
        "total_count": 3,
        "all_page_finding_count": 3,
        "raw_returned": False,
        "handshake": {
            "review_job_terminal": True,
            "review_receipt_present": True,
            "primary_workflow_present": True,
            "release_review_contract_present": True,
            "guardian_handoff_present": True,
            "review_coverage_present": True,
            "response_contract_mode": "compact_paginated",
            "next_tool_type": "string",
            "not_inspected_type": "list",
            "canonical_release_authority_type": "boolean",
            "repository_content_role_type": "string",
            "scope_reduction_for_client_timeout_type": "boolean",
            "review_receipt_eligible_for_release_review": True,
            "primary_workflow_release_review_eligible": True,
            "release_contract_eligible_to_start_guardian": True,
            "guardian_handoff_eligible_to_start_guardian": True,
            "release_review_contract_status": "ready",
            "guardian_handoff_status": "ready",
            "top_level_next_tool_value": "start_review_before_ship",
            "primary_workflow_next_tool_value": "start_review_before_ship",
            "release_contract_next_tool_value": "start_review_before_ship",
            "guardian_handoff_next_tool_value": "start_review_before_ship",
            "top_level_canonical_release_authority_value": False,
            "primary_workflow_canonical_release_authority_value": False,
            "release_contract_canonical_release_authority_value": False,
            "guardian_handoff_canonical_release_authority_value": False,
            "release_contract_release_verdict_issued": False,
            "guardian_handoff_release_verdict_issued": False,
            "review_coverage_status": "available_declared_scope",
            "raw_returned": False,
        },
        "pages": [
            {
                "finding_offset": 0,
                "returned_count": 2,
                "next_offset": 2,
                "has_more": True,
                "finding_ids": ["finding-0001", "finding-0002"],
                "raw_returned": False,
            },
            {
                "finding_offset": 2,
                "returned_count": 1,
                "next_offset": None,
                "has_more": False,
                "finding_ids": ["finding-0003"],
                "raw_returned": False,
            },
        ],
    }
    payload["reconnect"] = {
        "server_restarted": True,
        "client_reconnected": True,
        "tools_list_after_reconnect": {
            "advertised_count": 29,
            "required_tools_present": list(REQUIRED_TOOLS),
        },
        "post_reconnect_read_only_call": {
            "tool": "continue_review",
            "succeeded": True,
            "raw_returned": False,
        },
    }
    payload["review"] = {
        "verdict": "pass",
        "reviewed_at": "2026-07-13T02:00:00Z",
        "notes": "필수 장면과 재연결 호출을 확인함",
    }
    return payload


def _write_verified_run(
    tmp_path: Path,
    client: str,
    *,
    artifact_bytes: bytes | None = None,
    revision: str = REVISION,
) -> dict[str, object]:
    artifact_name = f"{client}.mp4"
    (tmp_path / artifact_name).write_bytes(artifact_bytes or (f"video:{client}".encode() * 256))
    observation = _completed_observation(client, artifact_name)
    observation["product_source_revision"] = revision
    observation["release_binding"]["product_source_revision"] = revision
    record, errors = collect_verified_run(observation, tmp_path, expected_revision=revision)
    assert errors == []
    assert record is not None
    published = tmp_path / str(record["recording"]["published_locator"])
    published.parent.mkdir(parents=True, exist_ok=True)
    published.write_bytes((tmp_path / artifact_name).read_bytes())
    return record


def test_collect_verified_run_hashes_recording_without_leaking_local_path(tmp_path: Path) -> None:
    record = _write_verified_run(tmp_path, "codex")

    assert validate_verified_run(record) == []
    assert record["recording"]["sha256"]
    assert record["verification"]["required_stage_count"] == 5
    assert record["installation"] == {"wheel_sha256": WHEEL_SHA256, "wheel_size_bytes": WHEEL_SIZE}
    assert record["review_flow"]["total_count"] == 3
    assert record["review_flow"]["all_page_finding_count"] == 3
    assert record["review_flow"]["pages"][-1]["has_more"] is False
    assert record["review_flow"]["handshake"]["review_receipt_eligible_for_release_review"] is True
    assert record["review_flow"]["handshake"]["release_review_contract_status"] == "ready"
    assert record["review_flow"]["handshake"]["top_level_canonical_release_authority_value"] is False
    assert {
        record["review_flow"]["handshake"][field]
        for field in client_interop.HANDSHAKE_NEXT_TOOL_FIELDS
    } == {"start_review_before_ship"}
    assert all(
        record["review_flow"]["handshake"][field] is False
        for field in (
            *client_interop.HANDSHAKE_CANONICAL_AUTHORITY_FIELDS,
            *client_interop.HANDSHAKE_RELEASE_VERDICT_FIELDS,
        )
    )
    assert record["release_handshake_semantic_assertion"] == {
        "provenance": "self_attested_operator_transcription",
        "canonical_terminal_response_digest_bound": False,
        "supporting_evidence": ["recording", "separate_review_assertion"],
        "claim_boundary": "semantic_parity_not_cryptographic_terminal_response_binding",
    }
    assert record["reconnect"]["post_reconnect_read_only_call"]["succeeded"] is True
    assert record["separate_review_assertion"]["provenance"] == "self_attested"
    assert record["separate_review_assertion"]["independence_verified"] is False
    assert str(tmp_path) not in json.dumps(record, ensure_ascii=False)


def test_collect_verified_run_fails_closed_on_secret_and_same_reviewer(tmp_path: Path) -> None:
    artifact_name = "grok.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("grok", artifact_name)
    observation["reviewer_ref"] = observation["operator_ref"]
    observation["stages"]["install"]["observation"] = "OPENAI_API_KEY=sk-abcdefghijklmnop"

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "separate_reviewer_reference_required" in errors
    assert "raw_secret_pattern_detected" in errors


def test_collect_verified_run_separates_runtime_state_from_presentation_code(tmp_path: Path) -> None:
    artifact_name = "codex.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("codex", artifact_name)
    observation["check_my_app"]["state"] = "review_in_progress"
    observation["check_my_app"]["presentation_code"] = "running"

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "check_my_app_first_state_invalid" in errors
    assert "check_my_app_presentation_code_invalid" in errors


def test_collect_verified_run_fails_closed_without_exact_wheel_binding(tmp_path: Path) -> None:
    artifact_name = "codex.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("codex", artifact_name)
    observation["installation"] = {"wheel_sha256": "not-a-hash", "wheel_size_bytes": 0}

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "installed_wheel_sha256_invalid" in errors
    assert "installed_wheel_size_invalid" in errors


def test_collect_verified_run_fails_closed_on_pagination_stall_and_duplicate(tmp_path: Path) -> None:
    artifact_name = "grok.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("grok", artifact_name)
    pages = observation["review_flow"]["pages"]
    pages[0]["next_offset"] = 0
    pages[1]["finding_ids"] = [pages[0]["finding_ids"][0]]

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "compact_pagination_cursor_stall" in errors
    assert "compact_pagination_duplicate_finding_id" in errors


def test_collect_verified_run_fails_closed_without_terminal_or_reconnect_proof(tmp_path: Path) -> None:
    artifact_name = "codex.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("codex", artifact_name)
    observation["review_flow"]["terminal_state"] = "running"
    observation["reconnect"]["tools_list_after_reconnect"]["required_tools_present"] = []
    observation["reconnect"]["post_reconnect_read_only_call"]["tool"] = "check_my_app"

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "continue_review_terminal_state_invalid" in errors
    assert "reconnect_required_tools_missing" in errors
    assert "post_reconnect_tool_not_read_only" in errors


def test_collect_verified_run_fails_closed_on_handshake_eligibility_and_status_mismatch(tmp_path: Path) -> None:
    artifact_name = "codex.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("codex", artifact_name)
    handshake = observation["review_flow"]["handshake"]
    handshake["guardian_handoff_eligible_to_start_guardian"] = False
    handshake["guardian_handoff_status"] = "blocked"

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "release_handshake_eligibility_parity_invalid" in errors
    assert "release_handshake_status_parity_invalid" in errors


def test_collect_verified_run_fails_closed_on_handshake_authority_or_verdict_claim(tmp_path: Path) -> None:
    artifact_name = "grok.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("grok", artifact_name)
    handshake = observation["review_flow"]["handshake"]
    handshake["release_contract_release_verdict_issued"] = True
    handshake["primary_workflow_canonical_release_authority_value"] = True

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "release_handshake_release_contract_release_verdict_issued_invalid" in errors
    assert "release_handshake_primary_workflow_canonical_release_authority_value_invalid" in errors


def test_collect_verified_run_fails_closed_on_handshake_next_tool_and_coverage_semantics(tmp_path: Path) -> None:
    artifact_name = "codex.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("codex", artifact_name)
    handshake = observation["review_flow"]["handshake"]
    handshake["guardian_handoff_next_tool_value"] = "check_my_app"
    handshake["review_coverage_status"] = "unavailable_fail_closed"

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "release_handshake_next_tool_parity_invalid" in errors
    assert "release_handshake_unavailable_coverage_eligible" in errors


def test_collect_verified_run_rejects_unknown_coverage_status(tmp_path: Path) -> None:
    artifact_name = "codex.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("codex", artifact_name)
    observation["review_flow"]["handshake"]["review_coverage_status"] = "looks_complete"

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert record is None
    assert "release_handshake_review_coverage_status_invalid" in errors


def test_collect_verified_run_accepts_blocked_fail_closed_handshake(tmp_path: Path) -> None:
    artifact_name = "codex.mp4"
    (tmp_path / artifact_name).write_bytes(b"video" * 256)
    observation = _completed_observation("codex", artifact_name)
    handshake = observation["review_flow"]["handshake"]
    for field in client_interop.HANDSHAKE_ELIGIBILITY_FIELDS:
        handshake[field] = False
    handshake["release_review_contract_status"] = "blocked"
    handshake["guardian_handoff_status"] = "blocked"
    for field in client_interop.HANDSHAKE_NEXT_TOOL_FIELDS:
        handshake[field] = "check_my_app"
    handshake["review_coverage_status"] = "unavailable_fail_closed"

    record, errors = collect_verified_run(observation, tmp_path, expected_revision=REVISION)

    assert errors == []
    assert record is not None
    assert record["review_flow"]["handshake"]["top_level_next_tool_value"] == "check_my_app"
    assert record["review_flow"]["handshake"]["review_coverage_status"] == "unavailable_fail_closed"


def test_status_counts_three_distinct_verified_clients(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    for client in CLIENTS[:3]:
        record = _write_verified_run(tmp_path, client)
        (runs / f"{client}.json").write_text(json.dumps(record), encoding="utf-8")

    status = build_status(runs, repository_root=tmp_path, release_binding_root=ROOT)
    verified_count, errors = validate_status(status, repository_root=tmp_path, release_binding_root=ROOT)

    assert errors == []
    assert verified_count == 3
    assert status["ready"] is True


def test_status_verification_recomputes_run_records_and_rejects_forged_projection(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    for client in CLIENTS[:3]:
        record = _write_verified_run(tmp_path, client)
        (runs / f"{client}.json").write_text(json.dumps(record), encoding="utf-8")
    status = build_status(runs, repository_root=tmp_path, release_binding_root=ROOT)
    status["clients"]["codex"]["recording_size_bytes"] += 1

    errors = validate_status_against_runs(
        status,
        runs,
        repository_root=tmp_path,
        release_binding_root=ROOT,
        expected_revision=REVISION,
    )

    assert errors == ["status_recomputed_projection_mismatch"]
    assert status["verified_clients"] == list(CLIENTS[:3])
    assert status["review_provenance"] == "self_attested_separate_assertion"
    assert status["external_independence_verified"] is False
    assert status["canonical_terminal_response_digest_bound"] is False
    assert "self-attested" in status["claim_boundary"]


def test_status_reports_known_historical_runs_without_poisoning_current_readiness(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    for client in CLIENTS[:3]:
        record = _write_verified_run(tmp_path, client)
        (runs / f"{client}.json").write_text(json.dumps(record), encoding="utf-8")
    (runs / "historical-v3.json").write_text(
        json.dumps({"schema": "k_guard_client_interop_verified_run.v3", "raw_returned": False}),
        encoding="utf-8",
    )
    (runs / "historical-v4.json").write_text(
        json.dumps({"schema": "k_guard_client_interop_verified_run.v4", "raw_returned": False}),
        encoding="utf-8",
    )

    status = build_status(runs, repository_root=tmp_path, release_binding_root=ROOT)
    verified_count, errors = validate_status(status, repository_root=tmp_path, release_binding_root=ROOT)

    assert errors == []
    assert verified_count == 3
    assert status["ready"] is True
    assert status["validation_errors"] == []
    assert status["historical_nonqualifying_files"] == [
        {"file": "historical-v3.json", "schema": "k_guard_client_interop_verified_run.v3"},
        {"file": "historical-v4.json", "schema": "k_guard_client_interop_verified_run.v4"},
    ]


def test_status_rejects_unknown_run_schema(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    (runs / "unknown.json").write_text(
        json.dumps({"schema": "k_guard_client_interop_verified_run.v999"}),
        encoding="utf-8",
    )

    status = build_status(runs, repository_root=tmp_path, release_binding_root=ROOT)

    assert status["historical_nonqualifying_files"] == []
    assert "unknown.json:schema_invalid" in status["validation_errors"]
    assert status["ready"] is False


def test_status_rejects_semantic_assertion_boundary_overstatement(tmp_path: Path) -> None:
    status = build_status(tmp_path / "missing", repository_root=tmp_path, release_binding_root=ROOT)
    status["canonical_terminal_response_digest_bound"] = True
    status["claim_boundary"] = "independently authenticated terminal output"

    _, errors = validate_status(status, repository_root=tmp_path, release_binding_root=ROOT)

    assert "release_handshake_terminal_digest_boundary_invalid" in errors
    assert "claim_boundary_invalid" in errors


def test_status_rejects_reused_recording_and_forged_count(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    shared_video = b"same recording" * 128
    for client in ("codex", "grok"):
        record = _write_verified_run(tmp_path, client, artifact_bytes=shared_video)
        (runs / f"{client}.json").write_text(json.dumps(record), encoding="utf-8")

    status = build_status(runs, repository_root=tmp_path, release_binding_root=ROOT)
    assert status["ready"] is False
    assert any(error.startswith("recording_sha256_reused:") for error in status["validation_errors"])

    empty_status = build_status(tmp_path / "missing", repository_root=tmp_path, release_binding_root=ROOT)
    empty_status["verified_client_count"] = 3
    empty_status["ready"] = True
    _, errors = validate_status(empty_status, repository_root=tmp_path, release_binding_root=ROOT)

    assert "verified_client_count_mismatch" in errors
    assert "ready_mismatch" in errors


def test_status_rejects_product_revision_not_bound_to_release_receipt(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    for index, client in enumerate(CLIENTS[:3]):
        record = _write_verified_run(tmp_path, client)
        if index == 2:
            record["product_source_revision"] = "b" * 40
            unsigned = dict(record)
            unsigned.pop("record_sha256")
            record["record_sha256"] = client_interop._canonical_sha256(unsigned)
        (runs / f"{client}.json").write_text(json.dumps(record), encoding="utf-8")

    status = build_status(runs, repository_root=tmp_path, release_binding_root=ROOT)

    assert status["ready"] is False
    assert any(
        error.endswith("release_binding_product_revision_mismatch")
        for error in status["validation_errors"]
    )


def test_status_rejects_mixed_installed_wheels(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    for index, client in enumerate(CLIENTS[:3]):
        record = _write_verified_run(tmp_path, client)
        if index == 2:
            record["installation"]["wheel_sha256"] = hashlib.sha256(b"different-wheel").hexdigest()
            unsigned = dict(record)
            unsigned.pop("record_sha256")
            record["record_sha256"] = client_interop._canonical_sha256(unsigned)
        (runs / f"{client}.json").write_text(json.dumps(record), encoding="utf-8")

    status = build_status(runs, repository_root=tmp_path, release_binding_root=ROOT)

    assert status["ready"] is False
    assert any(
        error.endswith("release_binding_installed_wheel_sha256_mismatch")
        for error in status["validation_errors"]
    )


def test_status_fails_closed_when_published_recording_is_missing(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    runs.mkdir()
    record = _write_verified_run(tmp_path, "codex")
    (runs / "codex.json").write_text(json.dumps(record), encoding="utf-8")
    (tmp_path / str(record["recording"]["published_locator"])).unlink()

    status = build_status(runs, repository_root=tmp_path, release_binding_root=ROOT)

    assert status["clients"]["codex"]["status"] == "pending"
    assert status["ready"] is False
    assert "codex.json:published_artifact_missing" in status["validation_errors"]


def test_refresh_manifest_normalizes_text_but_preserves_binary_bytes(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    text = evidence / "record.json"
    binary = evidence / "record.mp4"
    readme = evidence / "README.md"
    text.write_bytes(b'{\r\n  "passed": true\r\n}\r\n')
    binary.write_bytes(b"video\r\nbytes")
    readme.write_bytes(b"# Evidence\r\n")

    manifest = refresh_evidence_manifest(tmp_path)

    assert text.read_bytes() == b'{\n  "passed": true\n}\n'
    assert binary.read_bytes() == b"video\r\nbytes"
    assert readme.read_bytes() == b"# Evidence\n"
    assert b"\r\n" not in manifest.read_bytes()
    rows = [line.split("  ", 1) for line in manifest.read_text(encoding="utf-8").splitlines()]
    assert "evidence/README.md" in {relative for _expected, relative in rows}
    for expected, relative in rows:
        assert hashlib.sha256((tmp_path / relative).read_bytes()).hexdigest() == expected


def test_video_probe_binding_recomputes_representative_frame_digest(tmp_path: Path) -> None:
    frame = tmp_path / "evidence" / "clients" / "video-probe" / "codex-frame.png"
    frame.parent.mkdir(parents=True)
    frame.write_bytes(b"sanitized-frame")
    video_sha256 = hashlib.sha256(b"video-bytes").hexdigest()
    receipt = {
        "schema": client_interop.VIDEO_PROBE_RECEIPT_SCHEMA,
        "passed": True,
        "recording_mode": client_interop.RECORDING_EVIDENCE_MODE,
        "videos": [
            {
                "client": "codex",
                "video_path": "submission/client-interop/codex.mp4",
                "video_sha256": video_sha256,
                "video_size_bytes": 2048,
                "container_duration_seconds": 13.0,
                "decoder_probe": "test-decoder",
                "decoder_accepted": True,
                "representative_frame_path": "evidence/clients/video-probe/codex-frame.png",
                "representative_frame_sha256": hashlib.sha256(frame.read_bytes()).hexdigest(),
                "representative_frame_size_bytes": frame.stat().st_size,
            }
        ],
    }
    receipt_path = tmp_path / client_interop.VIDEO_PROBE_RECEIPT
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    binding, errors = client_interop._optional_video_probe_binding(
        tmp_path,
        client="codex",
        published_locator="submission/client-interop/codex.mp4",
        recording_sha256=video_sha256,
        recording_size_bytes=2048,
        duration_seconds=13.0,
    )
    assert errors == []
    assert binding is not None
    assert binding["representative_frame_sha256"] == hashlib.sha256(frame.read_bytes()).hexdigest()

    frame.write_bytes(b"tampered-frame")
    binding, errors = client_interop._optional_video_probe_binding(
        tmp_path,
        client="codex",
        published_locator="submission/client-interop/codex.mp4",
        recording_sha256=video_sha256,
        recording_size_bytes=2048,
        duration_seconds=13.0,
    )
    assert binding is None
    assert "video_probe_frame_sha256_mismatch" in errors
