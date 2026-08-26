from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_supervisor_review_repeats.py"
SPEC = importlib.util.spec_from_file_location("compare_supervisor_review_repeats_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)


TARGET = {
    "head_git_oid": "a" * 40,
    "dirty_path_set_sha256": "b" * 64,
    "dirty_worktree_sha256": "c" * 64,
}
MANIFEST = "d" * 64
PACKET = "e" * 64
DIRECT_SET = "f" * 64


def _receipt(provider: str, *, direct: bool = False) -> dict[str, object]:
    return {
        "provider": provider,
        "model": comparison.REQUIRED_MODELS[provider],
        "review_scope": "direct-files" if direct else "sanitized-packet",
        "target": TARGET,
        "evidence_manifest_sha256": MANIFEST,
        "review_packet_sha256": PACKET,
        "verdict": "GO",
        "blocked_reason": None,
        "blocker_count": 0,
        "nonblocking_count": 1,
        "claim_boundary_confirmed": True,
        "blocker_codes": [],
        "nonblocking_codes": ["REPEATABILITY_GAP"],
        "direct_file_attestation": (
            {
                "schema": "k_guard_direct_file_tool_attestation.v1",
                "file_count": 1,
                "file_set_sha256": DIRECT_SET,
                "raw_returned": False,
            }
            if direct
            else None
        ),
        "raw_returned": False,
    }


def _write_run(path: Path) -> None:
    manifest = {"schema": "manifest", "target": TARGET, "raw_returned": False}
    packet = {"schema": "packet", "target": TARGET, "raw_returned": False}
    bundle = {
        "schema": comparison.SUPERVISOR_REVIEW_RECEIPTS_SCHEMA,
        "field_id": "external-supervisor-contract",
        "target": TARGET,
        "evidence_manifest_sha256": comparison.sha256_bytes(manifest),
        "review_packet_sha256": comparison.sha256_bytes(packet),
        "test_attestation": {
            "focused_passed": True,
            "full_regression_passed": True,
            "repeat_required": True,
            "repeat_exact": False,
            "raw_returned": False,
        },
        "direct_file_count": 1,
        "direct_file_set_sha256": DIRECT_SET,
        "receipts": [_receipt("claude", direct=True), _receipt("grok")],
        "raw_returned": False,
    }
    # The fixtures use the bundle's calculated hashes, not the placeholder constants.
    for receipt in bundle["receipts"]:
        receipt["evidence_manifest_sha256"] = bundle["evidence_manifest_sha256"]
        receipt["review_packet_sha256"] = bundle["review_packet_sha256"]
    decision = comparison.evaluate_supervisor_review_receipts(bundle)
    decision["preflight_passed"] = True
    decision["target_unchanged_after_review"] = True
    path.mkdir()
    for name, payload in {
        "evidence-manifest.json": manifest,
        "review-packet.json": packet,
        "supervisor-receipts.json": bundle,
        "supervisor-decision.json": decision,
    }.items():
        (path / name).write_bytes(comparison.canonical_json_bytes(payload))


def test_identical_unpromoted_runs_produce_a_repeat_fix_without_raw_output(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write_run(first)
    _write_run(second)

    result = comparison.compare_runs(first, second)

    assert result["status"] == "FIX"
    assert result["repeat_exact"] is True
    assert result["authority"]["may_affect_h100_or_release"] is False
    assert result["raw_returned"] is False


def test_different_semantic_receipts_hold_repeat_comparison(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write_run(first)
    _write_run(second)
    bundle_path = second / "supervisor-receipts.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    packet_path = second / "review-packet.json"
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    packet["operator_note"] = "different but raw-free packet"
    packet_path.write_bytes(comparison.canonical_json_bytes(packet))
    bundle["review_packet_sha256"] = comparison.sha256_bytes(packet)
    for receipt in bundle["receipts"]:
        receipt["review_packet_sha256"] = bundle["review_packet_sha256"]
    bundle_path.write_bytes(comparison.canonical_json_bytes(bundle))
    decision = comparison.evaluate_supervisor_review_receipts(bundle)
    decision["preflight_passed"] = True
    decision["target_unchanged_after_review"] = True
    (second / "supervisor-decision.json").write_bytes(comparison.canonical_json_bytes(decision))

    result = comparison.compare_runs(first, second)
    assert result["status"] == "HOLD"
    assert result["repeat_exact"] is False


def test_missing_required_baseline_repeatability_gap_is_rejected(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    _write_run(first)
    _write_run(second)
    bundle_path = second / "supervisor-receipts.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["receipts"][1]["nonblocking_count"] = 0
    bundle["receipts"][1]["nonblocking_codes"] = []
    bundle_path.write_bytes(comparison.canonical_json_bytes(bundle))
    decision = comparison.evaluate_supervisor_review_receipts(bundle)
    decision["preflight_passed"] = True
    decision["target_unchanged_after_review"] = True
    (second / "supervisor-decision.json").write_bytes(comparison.canonical_json_bytes(decision))

    with pytest.raises(ValueError, match="required nonblocking"):
        comparison.compare_runs(first, second)
