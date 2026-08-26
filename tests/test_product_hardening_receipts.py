from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from k_guard_mcp.product_hardening_receipts import (
    CANONICAL_RECEIPT_FIELDS,
    CANONICAL_SUPERVISOR_BUNDLE_SCHEMA,
    canonical_json_bytes,
    canonicalize_actual_supervisor_receipt_file,
    evaluate_product_phase_receipts,
    seal_product_phase_supervisor_receipt,
    validate_canonical_supervisor_receipt,
    validate_contract_freeze_receipt,
    validate_qwen_parallel_health_v2,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "actual_receipts"
SHA = {
    "contract": "a" * 64,
    "packet": "b" * 64,
    "envelope": "c" * 64,
    "attestation": "d" * 64,
    "source": "e" * 64,
}
COMMIT = "f" * 40
TREE = "1" * 40


def _phase_receipt(reviewer: str, *, verdict: str = "GO") -> dict:
    models = {
        "sol": ("gpt-5.6-sol", "gpt-5.6-sol"),
        "opus": ("claude-opus-5", "claude-opus-5"),
        "grok": ("grok-4.5", "grok-4.5-build"),
    }
    attestations = {
        "sol": "deterministic",
        "opus": "source",
        "grok": "sanitized-packet",
    }
    hold = verdict == "HOLD"
    blocked = verdict == "BLOCKED"
    requested, runtime = models[reviewer]
    return seal_product_phase_supervisor_receipt(
        recorded_at="2026-07-26T12:00:00+09:00",
        phase_id="phase-0",
        attempt=1,
        reviewer=reviewer,
        requested_model_id=requested,
        runtime_model_id=runtime,
        session_id=f"session-{reviewer}",
        scope="phase-0-product-review",
        contract_file_sha256=SHA["contract"],
        sealed_packet_sha256=SHA["packet"],
        candidate_commit=COMMIT,
        candidate_tree=TREE,
        usage={"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        peer_verdict_supplied=False,
        verdict=verdict,
        source_verdict=verdict,
        product_approval=verdict == "GO",
        blockers=["provider_timeout" if blocked else "finding-1"] if verdict != "GO" else [],
        blocker_class="provider_failure" if blocked else "code_change" if hold else None,
        provider_envelope_path=f"phase-0/{reviewer}-envelope-redacted.json",
        provider_envelope_sha256=SHA["envelope"],
        attestation_kind=attestations[reviewer],
        attestation_path=f"phase-0/{reviewer}-attestation.json",
        attestation_sha256=SHA["attestation"],
        source_schema="provider-result.v1",
        source_path=f"phase-0/{reviewer}-provider-result.json",
        source_sha256=SHA["source"],
    )


def _bundle(receipts: list[dict]) -> dict:
    return {
        "schema": CANONICAL_SUPERVISOR_BUNDLE_SCHEMA,
        "phase_id": "phase-0",
        "attempt": 1,
        "sealed_packet_sha256": SHA["packet"],
        "contract_file_sha256": SHA["contract"],
        "receipts": receipts,
        "raw_returned": False,
    }


@pytest.mark.parametrize(
    ("name", "reviewer", "runtime", "total_tokens"),
    [
        ("opus5-contract-review-r4.json", "opus", "claude-opus-5", 368103),
        ("grok45-contract-review-r4.json", "grok", "grok-4.5-build", 139686),
    ],
)
def test_observed_contract_receipts_map_without_inventing_phase_evidence(
    name: str,
    reviewer: str,
    runtime: str,
    total_tokens: int,
) -> None:
    receipt = canonicalize_actual_supervisor_receipt_file(
        FIXTURES / name,
        source_path=f"archive/{name}",
    )

    assert receipt["reviewer"] == reviewer
    assert receipt["runtime_model_id"] == runtime
    assert receipt["usage"]["total_tokens"] == total_tokens
    assert receipt["decision"]["verdict"] == "HOLD"
    assert receipt["phase_id"] is None
    assert receipt["bindings"]["sealed_packet_sha256"] is None
    assert receipt["validation"]["product_gate_admissible"] is False
    assert "not_phase_review" in receipt["validation"]["failure_reasons"]
    with pytest.raises(ValueError, match="not admissible"):
        validate_canonical_supervisor_receipt(receipt)


@pytest.mark.parametrize(
    "name",
    [
        "opus5-retry-authority-receipt.json",
        "grok45-retry-authority-receipt.json",
    ],
)
def test_observed_retry_receipts_remain_historical_hold(name: str) -> None:
    receipt = canonicalize_actual_supervisor_receipt_file(FIXTURES / name)

    assert receipt["receipt_context"] == "retry_authority"
    assert receipt["decision"]["source_verdict"] == "DENY_PHASE0_RETRY"
    assert receipt["decision"]["verdict"] == "HOLD"
    assert receipt["validation"]["product_gate_admissible"] is False


def test_observed_sol_pre_gate_preserves_candidate_and_missing_model_evidence() -> None:
    receipt = canonicalize_actual_supervisor_receipt_file(FIXTURES / "sol-pre-gate-hold.json")

    assert receipt["reviewer"] == "sol"
    assert receipt["attempt"] == 2
    assert receipt["bindings"]["candidate_commit"] == "d6b47c31ba2af9dd69010d01497de6ac9ec3e337"
    assert receipt["requested_model_id"] is None
    assert receipt["usage"] is None
    assert "model_binding_invalid" in receipt["validation"]["failure_reasons"]
    assert "positive_usage_missing" in receipt["validation"]["failure_reasons"]


def test_actual_qwen_health_and_freeze_field_shapes_are_accepted() -> None:
    health = json.loads((FIXTURES / "qwen-health-v2.json").read_text(encoding="utf-8"))
    freeze = json.loads((FIXTURES / "contract-freeze-entry-v1.json").read_text(encoding="utf-8"))

    health_summary = validate_qwen_parallel_health_v2(health)
    freeze_summary = validate_contract_freeze_receipt(
        freeze,
        expected_phase_id="phase-0",
        expected_event="entry",
        expected_contract_sha256=freeze["contract_file_sha256"],
        expected_contract_byte_count=freeze["contract_byte_count"],
    )

    assert health_summary["worker_count"] == 3
    assert health_summary["requested_model_id"] == "qwen3.8-max-preview"
    assert freeze_summary["status"] == "PASS"
    assert freeze_summary["contract_byte_count"] == 67362


def test_one_canonical_schema_drives_the_product_phase_decision() -> None:
    receipts = [_phase_receipt(name) for name in ("sol", "opus", "grok")]
    decision = evaluate_product_phase_receipts(_bundle(receipts))

    assert decision["status"] == "FIX"
    assert decision["may_start_next_phase"] is True
    assert decision["verdicts"] == {"sol": "GO", "opus": "GO", "grok": "GO"}


def test_valid_hold_receipt_is_admissible_but_keeps_phase_closed() -> None:
    receipts = [_phase_receipt("sol"), _phase_receipt("opus", verdict="HOLD"), _phase_receipt("grok")]
    assert receipts[1]["validation"]["product_gate_admissible"] is True

    decision = evaluate_product_phase_receipts(_bundle(receipts))

    assert decision["status"] == "HOLD"
    assert decision["may_start_next_phase"] is False


def test_packet_mismatch_and_validation_tampering_fail_closed() -> None:
    receipts = [_phase_receipt(name) for name in ("sol", "opus", "grok")]
    receipts[2]["bindings"]["sealed_packet_sha256"] = "9" * 64

    with pytest.raises(ValueError, match="frozen target"):
        evaluate_product_phase_receipts(_bundle(receipts))

    receipts = [_phase_receipt(name) for name in ("sol", "opus", "grok")]
    receipts[2]["validation"]["failure_reasons"] = ["forged"]
    with pytest.raises(ValueError, match="stale or forged"):
        evaluate_product_phase_receipts(_bundle(receipts))


def test_json_schema_top_level_contract_matches_authoritative_validator() -> None:
    schema_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "k_guard_mcp"
        / "schemas"
        / "k-guard-product-supervisor-receipt-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert set(schema["required"]) == CANONICAL_RECEIPT_FIELDS
    assert set(schema["properties"]) == CANONICAL_RECEIPT_FIELDS
    assert schema["additionalProperties"] is False


def test_actual_fixture_hashes_are_stable() -> None:
    expected = {
        "contract-freeze-entry-v1.json": "e6796d6bec565c3f09ebaa920561a1f04e97c9cde6056f17816e22067522006e",
        "grok45-contract-review-r4.json": "0189a2ff64334a7cd3c62d56dcd42ecc42d0b8e84ee47a7665645ce9abb7c806",
        "grok45-retry-authority-receipt.json": "41a9076096bba8a243be35a2601fd97490a16642b5741860549a7876a8ead5a4",
        "opus5-contract-review-r4.json": "f9fb839be6771349f7279c43d634b646a6a84f047584e27a103bc95f8db5a026",
        "opus5-retry-authority-receipt.json": "508509ae93475482c251a7bef43fb8b19898a37f9772c81b2c15c40f6f5066ed",
        "qwen-health-v2.json": "14881879a90bffe102bf177030b355c77dff3f3fdb6f974de162edc13bfbc13f",
        "sol-pre-gate-hold.json": "50c4ab0f2e2b186051ade8c6cf2a6e77e643fa8f089053a66ac9df6b76800f47",
    }
    observed = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in FIXTURES.iterdir()
        if path.is_file()
    }
    assert observed == expected


def test_cli_writes_append_only_canonical_history_receipt(tmp_path: Path) -> None:
    output = tmp_path / "opus-canonical.json"
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "canonicalize_product_supervisor_receipt.py"
    )
    command = [
        sys.executable,
        str(script),
        "--source",
        str(FIXTURES / "opus5-contract-review-r4.json"),
        "--output",
        str(output),
        "--source-label",
        "archive/opus5-contract-review-r4.json",
    ]

    first = subprocess.run(command, check=False, capture_output=True, text=True)
    second = subprocess.run(command, check=False, capture_output=True, text=True)

    assert first.returncode == 0
    assert json.loads(first.stdout)["product_gate_admissible"] is False
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert output.read_bytes() == canonical_json_bytes(payload)
    assert second.returncode == 2
    assert json.loads(second.stdout)["status"] == "HOLD"
