from __future__ import annotations

import csv
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from k_guard_mcp.field_campaign import FIELD_APP_ROSTER_FIELDS
from k_guard_mcp.field_validation import (
    FIELD_REVIEW_FIELDS,
    GROUND_TRUTH_FIELDS,
    run_field_validation,
    sign_field_validation_inputs,
    write_field_preregistration,
    write_field_review_queue,
    write_field_validation_templates,
)
from k_guard_mcp.guardian import build_guardian_execution_attestation, guardian_toolchain_contract, refresh_guardian_evidence_bundle
from k_guard_mcp.validation import finding_fingerprint


REVIEWER_KEYS = {
    "reviewer-a": "reviewer-a-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "reviewer-b": "reviewer-b-key-9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBA",
    "reviewer-c": "reviewer-c-key-2468013579-QWERTYUIOPASDFGHJKLZXCVBNM",
}
CUSTODIAN_KEY = "custodian-key-1357902468-MNBVCXZLKJHGFDSAPOIUYTREWQ"


@pytest.fixture(autouse=True)
def _field_role_keys(monkeypatch):
    monkeypatch.setenv("K_GUARD_FIELD_REVIEWER_HMAC_KEYS", json.dumps(REVIEWER_KEYS))
    monkeypatch.setenv("K_GUARD_FIELD_CUSTODIAN_HMAC_KEY", CUSTODIAN_KEY)


def _field_pack(
    root: Path,
    *,
    missing_rules: set[str] | None = None,
    false_positive_reviews: int = 0,
    finding_count: int = 80,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    missing_rules = missing_rules or set()
    targets = []
    findings = []
    for index in range(1, 81):
        app_index = ((index - 1) % 12) + 1
        app_id = f"owned-app-{app_index:02d}"
        target_id = f"{app_id}-workspace"
        rule_id = f"FIELD_RULE_{index:03d}"
        finding = {
            "app_id": app_id,
            "target_id": target_id,
            "rule_id": rule_id,
            "source": "field-fixture",
            "severity": "critical" if index <= 5 else "high",
            "file": f"src/case_{index:03d}.ts",
            "line_start": index,
            "line_end": index,
            "evidence": f"fixture_case_hash={index:03d} raw_returned=false",
        }
        if index <= finding_count and rule_id not in missing_rules:
            findings.append(finding)
    by_target: dict[tuple[str, str], list[dict]] = {}
    for finding in findings:
        by_target.setdefault((finding["app_id"], finding["target_id"]), []).append(finding)
    for app_index in range(1, 13):
        app_id = f"owned-app-{app_index:02d}"
        target_id = f"{app_id}-workspace"
        target_findings = by_target.get((app_id, target_id), [])
        tree_sha256 = hashlib.sha256(f"source:{target_id}".encode()).hexdigest()
        targets.append(
            {
                "app_id": app_id,
                "target_id": target_id,
                "kind": "workspace",
                "status": "completed",
                "audit_profile": "korean_senior",
                "fail_on": "high",
                "coverage": {"executed": True, "coverage_gap": False, "status": "completed"},
                "scope_contract": {
                    "assertion_present": True,
                    "assertion_ref": {"hash": hashlib.sha256(f"scope:{target_id}".encode()).hexdigest()[:16], "raw_returned": False},
                    "ownership_or_partner_scope_verified_by_k_guard": False,
                    "raw_returned": False,
                },
                "review_evidence": {
                    "source_tree_snapshot": {
                        "schema": "k_guard_source_tree_snapshot.v1",
                        "tree_sha256": tree_sha256,
                        "complete": True,
                        "raw_returned": False,
                    },
                    "source_tree_consistency": {"matched": True, "raw_returned": False},
                    "scan_inventory_consistency": {"matched": True, "raw_returned": False},
                    "review_coverage": {
                        "source_kind": "workspace",
                        "inventory": {
                            "supported_file_count": 1,
                            "scanned_text_file_count": 1,
                            "candidate_set_complete": True,
                            "raw_returned": False,
                        },
                        "raw_returned": False,
                    },
                },
                "findings": target_findings,
                "rule_ids": sorted({finding["rule_id"] for finding in target_findings}),
            }
        )
    generated = datetime.now(UTC) + timedelta(seconds=5)
    primary = root / "guardian-primary.json"
    repeat = root / "guardian-repeat.json"
    toolchain = guardian_toolchain_contract()
    execution = {
        "mode": "report",
        "skipped_target_count": 0,
        "error_target_count": 0,
        "coverage_gap_target_count": 0,
    }
    summary = {"target_count": len(targets), "blocking_target_count": len(targets), "coverage_gap_target_count": 0}
    primary_generated = generated.isoformat()
    repeat_generated = (generated + timedelta(seconds=1)).isoformat()
    primary_payload = {
        "generated_at": primary_generated,
        "execution_id": "a" * 32,
        "method": "guardian_audit",
        "toolchain_contract": toolchain,
        "execution_contract": execution,
        "summary": summary,
        "targets": targets,
    }
    primary_payload["execution_attestation"] = build_guardian_execution_attestation(
        primary_payload["execution_id"], primary_generated, primary_generated, targets
    )
    repeat_payload = {
        "generated_at": repeat_generated,
        "execution_id": "b" * 32,
        "method": "guardian_audit",
        "toolchain_contract": toolchain,
        "execution_contract": execution,
        "summary": summary,
        "targets": targets,
    }
    repeat_payload["execution_attestation"] = build_guardian_execution_attestation(
        repeat_payload["execution_id"], repeat_generated, repeat_generated, targets
    )
    primary.write_text(json.dumps(primary_payload), encoding="utf-8")
    repeat.write_text(json.dumps(repeat_payload), encoding="utf-8")

    ground_truth = root / "ground-truth.csv"
    with ground_truth.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
        writer.writeheader()
        for index in range(1, 121):
            app_index = ((index - 1) % 12) + 1
            app_id = f"owned-app-{app_index:02d}"
            vulnerable = index <= 80
            severity = "critical" if index <= 5 else "high"
            writer.writerow(
                {
                    "app_id": app_id,
                    "target_id": f"{app_id}-workspace",
                    "case_id": f"field-case-{index:03d}",
                    "severity": severity,
                    "expected_outcome": "vulnerable" if vulnerable else "clean",
                    "expected_rule_ids": f"FIELD_RULE_{index:03d}",
                    "file": f"src/case_{index:03d}.ts",
                    "line_start": index,
                    "line_end": index,
                    "stratum": ("top", "mid", "long_tail")[(app_index - 1) % 3],
                    "split": "holdout" if index <= 35 or index >= 81 else "development",
                    "source_kind": "owned_partner",
                    "source_ref": f"partner-scope-{app_index:02d}-case-{index:03d}",
                    "reproduction_count": 2,
                    "reviewer_1": "reviewer-a",
                    "verdict_1": "vulnerable" if vulnerable else "clean",
                    "reviewer_2": "reviewer-b",
                    "verdict_2": "vulnerable" if vulnerable else "clean",
                    "adjudicator": "",
                    "final_verdict": "vulnerable" if vulnerable else "clean",
                    "notes": "raw-free fixture",
                }
            )

    review = root / "candidate-review.csv"
    with review.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writeheader()
        for index, finding in enumerate(findings):
            verdict = "false_positive" if index < false_positive_reviews else "true_positive"
            writer.writerow(
                {
                    "app_id": finding["app_id"],
                    "target_id": finding["target_id"],
                    "rule_id": finding["rule_id"],
                    "finding_fingerprint": finding_fingerprint(finding),
                    "reviewer_1": "reviewer-a",
                    "verdict_1": verdict,
                    "reviewer_2": "reviewer-b",
                    "verdict_2": verdict,
                    "adjudicator": "",
                    "final_verdict": verdict,
                    "notes": "raw-free fixture",
                }
            )
    sign_field_validation_inputs(ground_truth_path=ground_truth, review_path=review)
    roster = root / "field-app-roster.csv"
    with roster.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_APP_ROSTER_FIELDS)
        writer.writeheader()
        for app_index in range(1, 13):
            app_id = f"owned-app-{app_index:02d}"
            writer.writerow(
                {
                    "app_id": app_id,
                    "target_id": f"{app_id}-workspace",
                    "stratum": ("top", "mid", "long_tail")[(app_index - 1) % 3],
                    "source_revision": f"{app_index:040x}",
                    "scope_basis": "owned" if app_index % 2 else "partner",
                    "scope_assertion_ref": f"scope-ticket-{app_index:02d}",
                    "recruitment_status": "accepted",
                    "authorization_status": "approved",
                    "scan_consent": "true",
                    "aggregate_consent": "true",
                }
            )
    preregistration = root / "field-preregistration.json"
    write_field_preregistration(ground_truth, preregistration, custodian_id="custodian-one", roster_path=roster)
    for report_path in (primary, repeat):
        manifest = report_path.with_suffix(".manifest.csv")
        manifest.write_text("app_id,target_id,kind\nfixture,fixture,workspace\n", encoding="utf-8")
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        refresh_guardian_evidence_bundle(payload, manifest)
        report_path.write_text(json.dumps(payload), encoding="utf-8")
    return primary, repeat, ground_truth, review, preregistration, roster


def test_field_validation_ready_requires_ground_truth_holdout_and_repeat(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["claim_status"] == "field_validation_ready"
    assert report["sample"]["app_count"] == 12
    assert report["sample"]["case_count"] == 120
    assert report["sample"]["holdout_case_count"] == 75
    assert report["rates"]["precision"] == 1.0
    assert report["thresholds"]["min_precision"] == 0.9
    assert report["thresholds"]["min_precision_confidence_lower"] == 0.8
    assert report["metric_contract"]["schema"] == "k_guard_field_validation_metrics.v3"
    assert report["rates_confidence_intervals"]["precision_95"]["lower"] >= 0.8
    assert report["holdout"]["specificity_confidence_interval_95"]["lower"] >= 0.9
    assert "clean_case_false_positive" in report["metric_contract"]["false_positive_rate"]
    assert report["rates"]["recall"] == 1.0
    assert report["holdout"]["critical_recall"] == 1.0
    assert report["reproducibility"]["exact_candidate_set_match"] is True
    assert report["validation_evidence_envelope"]["signature"]["key_mode"] == "operator-keyed"


def test_field_validation_blocks_precision_below_ninety_percent(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path, false_positive_reviews=9)

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert 0.8 < report["rates"]["precision"] < 0.9
    assert report["claim_status"] == "blocked_candidate_precision"


def test_field_validation_requires_wilson_floor_separately_from_point_precision(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(
        tmp_path,
        false_positive_reviews=2,
        finding_count=20,
    )

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)
    checks = {item["name"]: item for item in report["gate_checks"]}

    assert report["rates"]["precision"] == 0.9
    assert checks["candidate_precision"]["passed"] is True
    assert report["rates_confidence_intervals"]["precision_95"]["lower"] < 0.8
    assert checks["candidate_precision_confidence_lower"]["passed"] is False


def test_field_validation_requires_holdout_scoped_candidate_precision(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path, false_positive_reviews=7)

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["rates"]["precision"] > 0.8
    assert report["rates"]["false_discovery_rate"] == pytest.approx(7 / 80)
    assert report["rates"]["false_positive_rate"] == 0.0
    assert report["holdout_candidate_rates"]["candidate_count"] == 35
    assert report["holdout_candidate_rates"]["precision"] == pytest.approx(28 / 35)
    assert report["holdout_candidate_rates"]["binding_complete"] is True
    assert report["claim_status"] == "blocked_holdout_candidate_precision"


def test_field_validation_uses_wilson_lower_bound_not_only_point_specificity(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    false_positive = {
        "app_id": "owned-app-09",
        "target_id": "owned-app-09-workspace",
        "rule_id": "CLEAN_SCOPE_FALSE_POSITIVE",
        "source": "field-fixture",
        "severity": "high",
        "file": "src/case_081.ts",
        "line_start": 81,
        "line_end": 81,
        "evidence": "fixture_case_hash=clean-081 raw_returned=false",
    }
    for report_path in (primary, repeat):
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        target = next(item for item in payload["targets"] if item["target_id"] == false_positive["target_id"])
        target["findings"].append(dict(false_positive))
        target["rule_ids"] = sorted({*target["rule_ids"], false_positive["rule_id"]})
        attestation = payload["execution_attestation"]
        payload["execution_attestation"] = build_guardian_execution_attestation(
            payload["execution_id"],
            attestation["started_at"],
            attestation["completed_at"],
            payload["targets"],
        )
        refresh_guardian_evidence_bundle(payload, report_path.with_suffix(".manifest.csv"))
        report_path.write_text(json.dumps(payload), encoding="utf-8")
    with review.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writerow(
            {
                "app_id": false_positive["app_id"],
                "target_id": false_positive["target_id"],
                "rule_id": false_positive["rule_id"],
                "finding_fingerprint": finding_fingerprint(false_positive),
                "reviewer_1": "reviewer-a",
                "verdict_1": "false_positive",
                "reviewer_2": "reviewer-b",
                "verdict_2": "false_positive",
                "final_verdict": "false_positive",
                "notes": "raw-free clean-scope false positive",
            }
        )
    sign_field_validation_inputs(review_path=review)

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["holdout"]["specificity"] == pytest.approx(39 / 40)
    assert report["holdout"]["specificity"] >= report["thresholds"]["min_specificity"]
    assert report["holdout"]["specificity_confidence_interval_95"]["lower"] < report["thresholds"]["min_specificity"]
    assert report["claim_status"] == "blocked_holdout_specificity_confidence_lower"


def test_field_validation_blocks_known_critical_false_negative(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path, missing_rules={"FIELD_RULE_001"})

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["case_counts"]["false_negative"] == 1
    assert report["holdout"]["critical_recall"] == 0.8
    assert report["claim_status"] == "blocked_holdout_critical_recall"


def test_field_validation_blocks_reusing_same_report_as_repeat(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, _, ground_truth, review, preregistration, roster = _field_pack(tmp_path)

    report = run_field_validation(primary, primary, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["reproducibility"]["distinct_report_paths"] is False
    assert report["claim_status"] == "blocked_distinct_repeat_report"


def test_field_validation_blocks_timestamp_changed_copy_as_repeat(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    copied = json.loads(primary.read_text(encoding="utf-8"))
    copied["generated_at"] = (datetime.now(UTC) + timedelta(seconds=20)).isoformat()
    repeat_manifest = repeat.with_suffix(".manifest.csv")
    refresh_guardian_evidence_bundle(copied, repeat_manifest)
    repeat.write_text(json.dumps(copied), encoding="utf-8")

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["repeat_guardian_evidence"]["passed"] is True
    assert report["reproducibility"]["distinct_evidence_bundles"] is True
    assert report["reproducibility"]["distinct_execution_ids"] is False
    assert report["claim_status"] == "blocked_distinct_guardian_execution_ids"


def test_field_validation_blocks_copy_with_forged_top_level_execution_id(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    copied = json.loads(primary.read_text(encoding="utf-8"))
    copied["generated_at"] = (datetime.now(UTC) + timedelta(seconds=20)).isoformat()
    copied["execution_id"] = "f" * 32
    refresh_guardian_evidence_bundle(copied, repeat.with_suffix(".manifest.csv"))
    repeat.write_text(json.dumps(copied), encoding="utf-8")

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["reproducibility"]["distinct_execution_ids"] is True
    assert report["reproducibility"]["distinct_execution_attestations"] is False
    assert report["repeat_guardian_evidence"]["canonical_execution_contract"]["checks"]["execution_attestation"] is False
    assert report["claim_status"] == "blocked_repeat_guardian_operator_evidence"


def test_field_validation_repeat_detects_severity_only_candidate_change(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    payload = json.loads(repeat.read_text(encoding="utf-8"))
    changed = next(
        finding
        for target in payload["targets"]
        for finding in target["findings"]
        if finding["severity"] == "high"
    )
    changed["severity"] = "critical"
    refresh_guardian_evidence_bundle(payload, repeat.with_suffix(".manifest.csv"))
    repeat.write_text(json.dumps(payload), encoding="utf-8")

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["reproducibility"]["candidate_jaccard"] == 1.0
    assert report["reproducibility"]["exact_candidate_multiset_match"] is False
    assert next(check for check in report["gate_checks"] if check["name"] == "repeat_candidate_set")["passed"] is False


def test_field_validation_repeat_detects_duplicate_candidate(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    payload = json.loads(repeat.read_text(encoding="utf-8"))
    payload["targets"][0]["findings"].append(dict(payload["targets"][0]["findings"][0]))
    refresh_guardian_evidence_bundle(payload, repeat.with_suffix(".manifest.csv"))
    repeat.write_text(json.dumps(payload), encoding="utf-8")

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["reproducibility"]["primary_candidate_count"] == 80
    assert report["reproducibility"]["repeat_candidate_count"] == 81
    assert report["reproducibility"]["exact_candidate_multiset_match"] is False


def test_field_validation_repeat_binds_manifest_and_target_inputs(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    payload = json.loads(repeat.read_text(encoding="utf-8"))
    payload["targets"][0]["requested_review"] = {"flow_analysis": False}
    repeat_manifest = repeat.with_suffix(".manifest.csv")
    repeat_manifest.write_text("app_id,target_id,kind\nchanged,changed,workspace\n", encoding="utf-8")
    refresh_guardian_evidence_bundle(payload, repeat_manifest)
    repeat.write_text(json.dumps(payload), encoding="utf-8")

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["reproducibility"]["guardian_manifest_content_match"] is False
    assert report["reproducibility"]["target_input_bindings_match"] is False
    failed = {check["name"] for check in report["gate_checks"] if not check["passed"]}
    assert "repeat_guardian_manifest_content_match" in failed
    assert "repeat_guardian_target_inputs_match" in failed


def test_field_validation_rejects_signed_but_incomplete_guardian_execution(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    payload = json.loads(primary.read_text(encoding="utf-8"))
    payload["execution_contract"]["error_target_count"] = 1
    refresh_guardian_evidence_bundle(payload, primary.with_suffix(".manifest.csv"))
    primary.write_text(json.dumps(payload), encoding="utf-8")

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    contract = report["primary_guardian_evidence"]["canonical_execution_contract"]
    assert report["primary_guardian_evidence"]["operator_signature_valid"] is True
    assert contract["checks"]["execution_complete"] is False
    assert report["claim_status"] == "blocked_primary_guardian_operator_evidence"


def test_field_validation_blocks_missing_prescan_preregistration(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, _, _ = _field_pack(tmp_path)

    report = run_field_validation(primary, repeat, ground_truth, review)

    assert report["field_preregistration"]["present"] is False
    assert report["claim_status"] == "blocked_field_preregistration_present"


def test_field_validation_blocks_roster_changed_after_preregistration(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    roster.write_text(roster.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    report = run_field_validation(
        primary,
        repeat,
        ground_truth,
        review,
        preregistration_path=preregistration,
        roster_path=roster,
    )

    assert report["field_preregistration"]["roster_content_bound"] is False
    assert report["claim_status"] == "blocked_field_roster_content_bound"


def test_field_validation_blocks_guardian_projection_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    payload = json.loads(primary.read_text(encoding="utf-8"))
    payload["summary"] = {"critical": 999}
    primary.write_text(json.dumps(payload), encoding="utf-8")

    report = run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)

    assert report["primary_guardian_evidence"]["operator_signature_valid"] is True
    assert report["primary_guardian_evidence"]["report_projection_bound"] is False
    assert report["claim_status"] == "blocked_primary_guardian_operator_evidence"


def test_field_validation_requires_operator_key(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "field-validation-test-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    primary, repeat, ground_truth, review, preregistration, roster = _field_pack(tmp_path)
    monkeypatch.delenv("K_GUARD_EVIDENCE_HMAC_KEY", raising=False)

    with pytest.raises(RuntimeError, match="K_GUARD_EVIDENCE_HMAC_KEY"):
        run_field_validation(primary, repeat, ground_truth, review, preregistration_path=preregistration, roster_path=roster)


def test_field_validation_template_writes_dual_review_contract(tmp_path):
    ground_truth = tmp_path / "ground-truth.csv"
    review = tmp_path / "review.csv"

    write_field_validation_templates(ground_truth, review)

    assert list(csv.DictReader(ground_truth.read_text(encoding="utf-8").splitlines()))[0]["source_kind"] == "owned_partner"
    assert list(csv.DictReader(review.read_text(encoding="utf-8").splitlines()))[0]["reviewer_2"] == "reviewer-b"


def test_field_review_queue_exports_all_high_critical_candidates(tmp_path):
    guardian = tmp_path / "guardian.json"
    guardian.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "app_id": "app-1",
                        "target_id": "target-1",
                        "findings": [
                            {
                                "rule_id": "DYN_RESPONSE_PII_LEAK",
                                "source": "dynamic",
                                "severity": "high",
                                "scope": "response_body",
                                "evidence": "response_sha256=" + "a" * 64,
                            },
                            {
                                "rule_id": "PII_EMAIL",
                                "source": "static",
                                "severity": "medium",
                                "file": "src/app.ts",
                            },
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "queue.csv"

    report = write_field_review_queue(guardian, output)

    with output.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert report["candidate_count"] == 1
    assert report["all_high_critical_candidates_exported"] is True
    assert rows[0]["detector_subtype"] == "dynamic"
    assert rows[0]["location_kind"] == "body"
    assert rows[0]["response_hash"] == "a" * 64
    assert rows[0]["finding_fingerprint"]
