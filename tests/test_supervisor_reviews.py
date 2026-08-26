from __future__ import annotations

from copy import deepcopy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from k_guard_mcp.supervisor_reviews import (
    PREVIOUS_REQUIRED_MODELS,
    PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
    REQUIRED_MODELS,
    SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
    canonical_json_bytes,
    evaluate_supervisor_review_receipts,
)


HEAD = "a" * 40
PATCH = "b" * 64
WORKTREE = "e" * 64
MANIFEST = "c" * 64
PACKET = "d" * 64
DIRECT_FILE_SET = "f" * 64


def _receipt(provider: str, *, scope: str = "sanitized-packet") -> dict:
    return {
        "provider": provider,
        "model": REQUIRED_MODELS[provider],
        "review_scope": scope,
        "target": {"head_git_oid": HEAD, "dirty_path_set_sha256": PATCH, "dirty_worktree_sha256": WORKTREE},
        "evidence_manifest_sha256": MANIFEST,
        "review_packet_sha256": PACKET,
        "verdict": "GO",
        "blocked_reason": None,
        "blocker_count": 0,
        "nonblocking_count": 0,
        "claim_boundary_confirmed": True,
        "blocker_codes": [],
        "nonblocking_codes": [],
        "direct_file_attestation": (
            {
                "schema": "k_guard_direct_file_tool_attestation.v1",
                "file_count": 1,
                "file_set_sha256": DIRECT_FILE_SET,
                "raw_returned": False,
            }
            if scope == "direct-files"
            else None
        ),
        "raw_returned": False,
    }


def _bundle() -> dict:
    return {
        "schema": SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
        "field_id": "l2-webgoat-idor-execution-contract",
        "target": {"head_git_oid": HEAD, "dirty_path_set_sha256": PATCH, "dirty_worktree_sha256": WORKTREE},
        "evidence_manifest_sha256": MANIFEST,
        "review_packet_sha256": PACKET,
        "test_attestation": {
            "focused_passed": True,
            "full_regression_passed": True,
            "repeat_required": True,
            "repeat_exact": True,
            "raw_returned": False,
        },
        "direct_file_count": 1,
        "direct_file_set_sha256": DIRECT_FILE_SET,
        "receipts": [
            _receipt("claude", scope="direct-files"),
            _receipt("grok"),
        ],
        "raw_returned": False,
    }


def test_both_exact_models_same_packet_and_one_direct_file_review_can_fix() -> None:
    decision = evaluate_supervisor_review_receipts(_bundle())

    assert decision["status"] == "FIX"
    assert decision["failure_reasons"] == []
    assert decision["authority"]["may_mark_field_fix"] is True
    assert decision["authority"]["may_count_as_scorecard_achievement"] is True
    assert decision["authority"]["may_affect_oracle_labels"] is False
    assert decision["authority"]["may_affect_h100_or_release"] is False
    assert decision["hold_codes"] == {}


def test_blocked_provider_can_only_create_temporary_pending_review() -> None:
    payload = _bundle()
    payload["receipts"][1].update(
        {
            "review_scope": "unavailable",
            "verdict": "BLOCKED",
            "blocked_reason": "BLOCKED_TIMEOUT",
            "claim_boundary_confirmed": False,
        }
    )

    decision = evaluate_supervisor_review_receipts(payload)

    assert decision["status"] == "TEMPORARY_PENDING_REVIEW"
    assert decision["authority"]["may_start_next_non_promoting_measurement"] is True
    assert decision["authority"]["may_mark_field_fix"] is False
    assert decision["authority"]["may_count_as_scorecard_achievement"] is False
    assert decision["authority"]["may_affect_h100_or_release"] is False


def test_active_hold_cannot_be_downgraded_to_temporary_pending_review() -> None:
    payload = _bundle()
    payload["receipts"][1].update(
        {
            "verdict": "HOLD",
            "blocker_count": 1,
            "claim_boundary_confirmed": True,
            "blocker_codes": ["CLAIM_BOUNDARY_GAP"],
        }
    )

    decision = evaluate_supervisor_review_receipts(payload)

    assert decision["status"] == "HOLD"
    assert "reviewer_hold" in decision["failure_reasons"]
    assert decision["authority"]["may_start_next_non_promoting_measurement"] is False


def test_fixed_status_requires_one_direct_file_review() -> None:
    payload = _bundle()
    payload["receipts"][0]["review_scope"] = "sanitized-packet"
    payload["receipts"][0]["direct_file_attestation"] = None

    decision = evaluate_supervisor_review_receipts(payload)

    assert decision["status"] == "HOLD"
    assert "direct_file_review_required" in decision["failure_reasons"]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda payload: payload["receipts"][1].update({"model": "grok-latest"}),
            "model identity",
        ),
        (
            lambda payload: payload["receipts"][1].update({"review_packet_sha256": "e" * 64}),
            "packet does not match",
        ),
        (
            lambda payload: payload["receipts"][1]["target"].update({"dirty_path_set_sha256": "e" * 64}),
            "target does not match",
        ),
        (
            lambda payload: payload["receipts"][1]["target"].update({"dirty_worktree_sha256": "f" * 64}),
            "target does not match",
        ),
        (
            lambda payload: payload["receipts"][1].update(
                {"verdict": "GO", "blocker_count": 1, "blocker_codes": ["CLAIM_BOUNDARY_GAP"]}
            ),
            "GO receipt",
        ),
    ],
)
def test_receipts_fail_closed_for_model_or_shared_evidence_mismatch(mutate, message: str) -> None:
    payload = deepcopy(_bundle())
    mutate(payload)

    with pytest.raises(ValueError, match=message):
        evaluate_supervisor_review_receipts(payload)


def test_receipt_bundle_requires_both_named_providers() -> None:
    payload = _bundle()
    payload["receipts"][1]["provider"] = "claude"
    payload["receipts"][1]["model"] = REQUIRED_MODELS["claude"]

    with pytest.raises(ValueError, match="duplicated"):
        evaluate_supervisor_review_receipts(payload)


def test_only_the_currently_authorized_claude_lane_may_claim_direct_file_review() -> None:
    payload = _bundle()
    payload["receipts"][1]["review_scope"] = "direct-files"

    with pytest.raises(ValueError, match="not authorized"):
        evaluate_supervisor_review_receipts(payload)


def test_v5_receipt_codes_must_match_counts_and_are_exposed_without_raw_findings() -> None:
    payload = _bundle()
    payload["receipts"][1].update(
        {
            "verdict": "HOLD",
            "blocker_count": 2,
            "claim_boundary_confirmed": True,
            "blocker_codes": ["CLAIM_BOUNDARY_GAP", "CLAIM_BOUNDARY_GAP"],
        }
    )
    decision = evaluate_supervisor_review_receipts(payload)
    assert decision["hold_codes"] == {"grok": ["CLAIM_BOUNDARY_GAP", "CLAIM_BOUNDARY_GAP"]}
    payload["receipts"][1]["blocker_codes"] = []
    with pytest.raises(ValueError, match="review codes"):
        evaluate_supervisor_review_receipts(payload)


def test_v5_direct_file_attestation_must_match_the_bound_file_set() -> None:
    payload = _bundle()
    payload["receipts"][0]["direct_file_attestation"]["file_count"] = 2
    with pytest.raises(ValueError, match="direct file attestation does not match"):
        evaluate_supervisor_review_receipts(payload)


def test_v4_three_lane_receipts_keep_their_historical_model_binding() -> None:
    payload = deepcopy(_bundle())
    payload["schema"] = PREVIOUS_SUPERVISOR_REVIEW_RECEIPTS_SCHEMA
    payload["receipts"].append(_receipt("grok"))
    payload["receipts"][-1]["provider"] = "glm"
    for receipt in payload["receipts"]:
        receipt["model"] = PREVIOUS_REQUIRED_MODELS[receipt["provider"]]

    decision = evaluate_supervisor_review_receipts(payload)

    assert decision["schema"] == "k_guard_supervisor_review_decision.v4"
    assert decision["status"] == "FIX"

    payload["receipts"][0]["model"] = REQUIRED_MODELS["claude"]
    with pytest.raises(ValueError, match="model identity"):
        evaluate_supervisor_review_receipts(payload)


def test_cli_accepts_a_canonical_fix_bundle(tmp_path: Path) -> None:
    receipt_path = tmp_path / "supervisor-receipts.json"
    receipt_path.write_bytes(canonical_json_bytes(_bundle()))
    script = Path(__file__).resolve().parents[1] / "scripts" / "validate_supervisor_review_receipts.py"

    result = subprocess.run(
        [sys.executable, str(script), "--receipts", str(receipt_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "FIX"
