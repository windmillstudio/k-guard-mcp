from __future__ import annotations

import csv
from pathlib import Path

from k_guard_mcp.guardian import build_guardian_execution_attestation
from k_guard_mcp.suppression import (
    SUPPRESSION_FIELDS,
    _guardian_row_suppression_binding,
    apply_suppressions_to_guardian_report,
    finding_fingerprint,
)


def test_attestation_mismatch_keeps_original_findings_and_applies_no_waiver(tmp_path: Path) -> None:
    finding = {
        "rule_id": "TEST_WAIVABLE_FINDING",
        "source": "test",
        "severity": "high",
        "file": "app.py",
        "line_start": 1,
        "evidence": "fixture_hash=attestation-mismatch raw_returned=false",
    }
    row = {
        "target_id": "workspace:fixture",
        "kind": "workspace",
        "status": "blocked",
        "findings": [finding],
        "review_evidence": {
            "app_id": "fixture-app",
            "audit_profile": "korean_senior",
            "source_tree_snapshot": {"tree_sha256": "a" * 64},
        },
    }
    report = {
        "execution_id": "b" * 32,
        "generated_at": "2026-07-12T00:00:00+00:00",
        "targets": [row],
    }
    report["execution_attestation"] = build_guardian_execution_attestation(
        report["execution_id"],
        report["generated_at"],
        report["generated_at"],
        report["targets"],
    )
    binding = _guardian_row_suppression_binding(row)
    bound_finding = {
        **finding,
        **binding,
        "target_id": row["target_id"],
    }
    policy = tmp_path / "suppressions.csv"
    with policy.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=SUPPRESSION_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                **binding,
                "target_id": row["target_id"],
                "rule_id": finding["rule_id"],
                "finding_fingerprint": finding_fingerprint(bound_finding),
                "owner": "test-owner",
                "reason": "bounded regression fixture",
                "expires": "2099-01-01",
            }
        )

    report["execution_attestation"]["target_evidence_sha256"] = "c" * 64
    guarded = apply_suppressions_to_guardian_report(report, policy)

    original = next(target for target in guarded["targets"] if target["target_id"] == row["target_id"])
    assert [item["rule_id"] for item in original["findings"]] == [finding["rule_id"]]
    assert guarded["suppression_policy"]["suppressed_count"] == 0
    assert guarded["suppression_policy"]["execution_input_binding"]["valid"] is False
    assert any(
        item["rule_id"] == "SUPPRESSION_EXECUTION_ATTESTATION_MISMATCH"
        for item in guarded["findings"]
    )
