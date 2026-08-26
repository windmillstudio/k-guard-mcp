from __future__ import annotations

import csv
import json
from datetime import UTC, datetime, timedelta

import pytest

from k_guard_mcp.cli import main as cli_main
from k_guard_mcp.field_validation import (
    FIELD_REVIEW_FIELDS,
    GROUND_TRUTH_FIELDS,
    _field_preregistration_status,
    _field_review_error,
    _candidate_split_metrics,
    _evaluate_ground_truth,
    _guardian_target_apps,
    _high_critical_findings,
    _load_json_object,
    _metrics,
    _normalize_ground_truth,
    _parse_timestamp,
    _review_signature_projection,
    _row_signature,
    sign_field_validation_inputs,
    write_field_preregistration,
)
from k_guard_mcp.guardian import refresh_guardian_evidence_bundle
from k_guard_mcp.validation import finding_fingerprint


REVIEWER_KEYS = {
    "reviewer-a": "edge-reviewer-a-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "reviewer-b": "edge-reviewer-b-key-9876543210-ZYXWVUTSRQPONMLKJIHGFEDCBA",
    "reviewer-c": "edge-reviewer-c-key-2468013579-QWERTYUIOPASDFGHJKLZXCVBNM",
}


@pytest.fixture(autouse=True)
def _field_role_keys(monkeypatch):
    monkeypatch.setenv("K_GUARD_FIELD_REVIEWER_HMAC_KEYS", json.dumps(REVIEWER_KEYS))
    monkeypatch.setenv("K_GUARD_FIELD_CUSTODIAN_HMAC_KEY", "edge-custodian-key-1357902468-MNBVCXZLKJHGFDSAPOIUYTREWQ")


def _sign_row(row: dict[str, str], row_kind: str) -> dict[str, str]:
    for slot in (1, 2):
        reviewer = row.get(f"reviewer_{slot}", "")
        if reviewer and row.get(f"verdict_{slot}", ""):
            row[f"reviewer_{slot}_signature"] = _row_signature(
                REVIEWER_KEYS[reviewer],
                _review_signature_projection(row, row_kind=row_kind, role=f"reviewer_{slot}"),
            )
    adjudicator = row.get("adjudicator", "")
    if adjudicator:
        row["adjudicator_signature"] = _row_signature(
            REVIEWER_KEYS[adjudicator],
            _review_signature_projection(row, row_kind=row_kind, role="adjudicator"),
        )
    return row


def _review_row() -> dict[str, str]:
    row = {field: "" for field in FIELD_REVIEW_FIELDS}
    row.update(
        {
            "app_id": "app",
            "target_id": "target",
            "rule_id": "RULE",
            "finding_fingerprint": "fingerprint",
            "reviewer_1": "reviewer-a",
            "verdict_1": "true_positive",
            "reviewer_2": "reviewer-b",
            "verdict_2": "true_positive",
            "final_verdict": "true_positive",
        }
    )
    return _sign_row(row, "candidate_review")


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"rule_id": ""}, "missing_rule_id"),
        ({"verdict_1": "maybe"}, "invalid_review_verdict"),
        ({"app_id": "other"}, "review_app_target_binding_mismatch"),
        ({"reviewer_2": ""}, "dual_review_required"),
        ({"reviewer_2": "reviewer-a"}, "reviewers_must_be_distinct"),
        ({"verdict_2": "maybe"}, "invalid_second_review_verdict"),
        ({"final_verdict": "false_positive"}, "agreed_reviews_must_bind_final_verdict"),
        ({"verdict_2": "false_positive"}, "disagreement_requires_adjudicator"),
        (
            {"verdict_2": "false_positive", "adjudicator": "reviewer-a"},
            "adjudicator_must_be_independent",
        ),
    ],
)
def test_field_review_contract_rejects_ambiguous_rows(changes, expected):
    row = _review_row()
    row.update(changes)

    assert _field_review_error(row, {"target": "app"}, require_dual=True) == expected


def test_field_review_contract_accepts_independent_adjudication():
    row = _review_row()
    row.update({"verdict_2": "false_positive", "adjudicator": "reviewer-c"})
    _sign_row(row, "candidate_review")

    assert _field_review_error(row, {"target": "app"}, require_dual=True) == ""


def test_field_review_contract_rejects_tampered_reviewer_signature():
    row = _review_row()
    replacement = "0" if not row["reviewer_2_signature"].endswith("0") else "1"
    row["reviewer_2_signature"] = row["reviewer_2_signature"][:-1] + replacement

    assert _field_review_error(row, {"target": "app"}, require_dual=True) == "invalid_reviewer_2_signature"


def test_field_signing_requires_paths_and_distinct_reviewer_keys(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="At least one"):
        sign_field_validation_inputs()

    review = tmp_path / "review.csv"
    with review.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writeheader()
        row = _review_row()
        row["reviewer_1_signature"] = ""
        row["reviewer_2_signature"] = ""
        writer.writerow(row)
    monkeypatch.setenv(
        "K_GUARD_FIELD_REVIEWER_HMAC_KEYS",
        json.dumps({"reviewer-a": REVIEWER_KEYS["reviewer-a"], "reviewer-b": REVIEWER_KEYS["reviewer-a"]}),
    )

    with pytest.raises(RuntimeError, match="at least two distinct"):
        sign_field_validation_inputs(review_path=review)


def test_field_signing_cli_requires_at_least_one_csv(capsys):
    assert cli_main(["field-validation-sign"]) == 2
    assert "requires --ground-truth and/or --review" in capsys.readouterr().err


def test_field_signing_writes_reviewer_and_adjudicator_signatures(tmp_path):
    review = tmp_path / "review.csv"
    with review.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writeheader()
        row = _review_row()
        row.update(
            {
                "verdict_2": "false_positive",
                "adjudicator": "reviewer-c",
                "final_verdict": "true_positive",
                "reviewer_1_signature": "",
                "reviewer_2_signature": "",
                "adjudicator_signature": "",
            }
        )
        writer.writerow(row)

    report = sign_field_validation_inputs(review_path=review)
    signed = list(csv.DictReader(review.read_text(encoding="utf-8").splitlines()))[0]

    assert report["signed_row_counts"]["candidate_review"] == 3
    assert signed["reviewer_1_signature"].startswith("hmac-sha256:")
    assert signed["reviewer_2_signature"].startswith("hmac-sha256:")
    assert signed["adjudicator_signature"].startswith("hmac-sha256:")


def _ground_truth_row() -> dict[str, str]:
    row = {field: "" for field in GROUND_TRUTH_FIELDS}
    row.update(
        {
            "app_id": "app",
            "target_id": "target",
            "case_id": "case-1",
            "severity": "high",
            "expected_outcome": "vulnerable",
            "expected_rule_ids": "RULE",
            "file": "src/app.ts",
            "line_start": "1",
            "line_end": "1",
            "stratum": "top",
            "split": "holdout",
            "source_kind": "owned_partner",
            "source_ref": "partner-ticket",
            "reproduction_count": "2",
            "reviewer_1": "reviewer-a",
            "verdict_1": "vulnerable",
            "reviewer_2": "reviewer-b",
            "verdict_2": "vulnerable",
            "final_verdict": "vulnerable",
        }
    )
    return _sign_row(row, "ground_truth")


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"case_id": ""}, "missing_case_id"),
        ({"app_id": "other"}, "ground_truth_app_target_binding_mismatch"),
        ({"severity": "blocker"}, "invalid_ground_truth_severity"),
        ({"expected_outcome": "maybe"}, "invalid_ground_truth_verdict"),
        ({"final_verdict": "clean"}, "ground_truth_final_verdict_mismatch"),
        ({"stratum": "unknown"}, "invalid_ground_truth_cohort"),
        ({"source_kind": "public_benchmark"}, "field_profile_requires_owned_partner_source"),
        ({"expected_rule_ids": "||"}, "expected_rule_ids_required"),
        ({"reproduction_count": "many"}, "invalid_ground_truth_integer"),
        ({"reproduction_count": "1"}, "ground_truth_requires_two_reproductions"),
        ({"line_start": "2", "line_end": "1"}, "invalid_ground_truth_line_range"),
        ({"reviewer_2": ""}, "ground_truth_dual_review_required"),
        ({"reviewer_2": "reviewer-a"}, "ground_truth_reviewers_must_be_distinct"),
        ({"verdict_2": "maybe"}, "invalid_ground_truth_reviewer_verdict"),
        ({"verdict_1": "clean", "verdict_2": "clean"}, "ground_truth_agreement_mismatch"),
        ({"verdict_2": "clean"}, "ground_truth_disagreement_requires_adjudicator"),
        (
            {"verdict_2": "clean", "adjudicator": "reviewer-a"},
            "ground_truth_adjudicator_must_be_independent",
        ),
    ],
)
def test_ground_truth_contract_rejects_invalid_rows(changes, expected):
    row = _ground_truth_row()
    row.update(changes)

    _, error = _normalize_ground_truth(row, {"target": "app"}, profile="field", require_dual=True)

    assert error == expected


def test_ground_truth_contract_accepts_independent_adjudication():
    row = _ground_truth_row()
    row.update({"verdict_2": "clean", "adjudicator": "reviewer-c"})
    _sign_row(row, "ground_truth")

    normalized, error = _normalize_ground_truth(row, {"target": "app"}, profile="field", require_dual=True)

    assert error == ""
    assert normalized["expected_rule_ids"] == ("RULE",)


def test_preregistration_detects_content_and_projection_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "edge-preregistration-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    ground_truth = tmp_path / "ground-truth.csv"
    with ground_truth.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
        writer.writeheader()
        writer.writerow(_ground_truth_row())
    preregistration = tmp_path / "preregistration.json"
    write_field_preregistration(ground_truth, preregistration, custodian_id="edge-custodian")
    primary = {"generated_at": (datetime.now(UTC) + timedelta(seconds=5)).isoformat(), "targets": []}
    refresh_guardian_evidence_bundle(primary, tmp_path / "guardian-manifest.csv")

    valid = _field_preregistration_status(preregistration, ground_truth, primary)
    assert valid["passed"] is True

    payload = json.loads(preregistration.read_text(encoding="utf-8"))
    payload["ground_truth_row_count"] = 999
    preregistration.write_text(json.dumps(payload), encoding="utf-8")
    tampered_projection = _field_preregistration_status(preregistration, ground_truth, primary)
    assert tampered_projection["operator_signature_valid"] is True
    assert tampered_projection["signed_projection_valid"] is False

    write_field_preregistration(ground_truth, preregistration, custodian_id="edge-custodian")
    with ground_truth.open("a", encoding="utf-8") as handle:
        handle.write("\n")
    tampered_ground_truth = _field_preregistration_status(preregistration, ground_truth, primary)
    assert tampered_ground_truth["ground_truth_content_bound"] is False


def test_field_validation_low_level_inputs_fail_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", "edge-preregistration-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    with pytest.raises(ValueError, match="must exist"):
        write_field_preregistration(tmp_path / "missing.csv", tmp_path / "out.json", custodian_id="edge-custodian")
    empty = tmp_path / "empty.csv"
    empty.write_text(",".join(GROUND_TRUTH_FIELDS) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="v2 field contract"):
        write_field_preregistration(empty, tmp_path / "out.json", custodian_id="edge-custodian")

    not_object = tmp_path / "list.json"
    not_object.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="JSON object"):
        _load_json_object(not_object, "fixture")

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    status = _field_preregistration_status(malformed, empty, {"generated_at": "not-a-time"})
    assert status["present"] is True
    assert status["passed"] is False
    assert _parse_timestamp("not-a-time") is None
    assert _parse_timestamp("2026-01-01T00:00:00") is None


def test_preregistration_requires_custodian_key_distinct_from_operator(tmp_path, monkeypatch):
    ground_truth = tmp_path / "ground-truth.csv"
    with ground_truth.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
        writer.writeheader()
        writer.writerow(_ground_truth_row())
    operator_key = "edge-preregistration-key-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    monkeypatch.setenv("K_GUARD_EVIDENCE_HMAC_KEY", operator_key)
    monkeypatch.setenv("K_GUARD_FIELD_CUSTODIAN_HMAC_KEY", operator_key)

    with pytest.raises(RuntimeError, match="distinct valid custodian key"):
        write_field_preregistration(ground_truth, tmp_path / "out.json", custodian_id="custodian")


def test_guardian_candidate_extractors_ignore_malformed_and_ambiguous_targets():
    report = {
        "targets": [
            "bad",
            {"app_id": "app-a", "target_id": "same", "findings": ["bad", {"severity": "medium"}]},
            {"app_id": "app-b", "target_id": "same", "findings": [{"severity": "high", "rule_id": "R"}]},
            {"app_id": "", "target_id": "missing-app", "findings": []},
        ]
    }

    findings = _high_critical_findings(report)
    assert len(findings) == 1
    assert findings[0]["app_id"] == "app-b"
    assert _guardian_target_apps(report) == {}


def test_field_metrics_distinguish_false_discovery_from_case_false_positive_rate():
    metrics = _metrics(
        {"true_positive": 8, "false_positive": 2, "benign": 0},
        {"true_positive": 9, "false_negative": 1, "false_positive": 1, "true_negative": 19},
    )

    assert metrics["precision"] == 0.8
    assert metrics["false_discovery_rate"] == 0.2
    assert metrics["false_positive_rate"] == 0.05
    assert metrics["negative_case_false_positive_rate"] == 0.05


def test_holdout_candidate_metrics_bind_wrong_rule_noise_by_case_scope():
    cases = [
        {
            "app_id": "app",
            "target_id": "target",
            "case_id": "holdout-case",
            "expected_rule_ids": ("EXPECTED_RULE",),
            "file": "src/holdout.ts",
            "line_start": 10,
            "line_end": 20,
            "split": "holdout",
        }
    ]
    wrong_rule = {
        "app_id": "app",
        "target_id": "target",
        "rule_id": "UNRELATED_HIGH_RULE",
        "severity": "high",
        "file": "src/holdout.ts",
        "line_start": 12,
        "line_end": 12,
    }
    fingerprint = finding_fingerprint(wrong_rule)
    reviews = {
        ("app", "target", "UNRELATED_HIGH_RULE", fingerprint): {"final_verdict": "false_positive"}
    }

    rates = _candidate_split_metrics(cases, [wrong_rule], reviews, split="holdout")

    assert rates["candidate_count"] == 1
    assert rates["false_positive"] == 1
    assert rates["precision"] == 0.0
    assert rates["binding_complete"] is True


def test_holdout_candidate_metrics_fail_binding_for_unassigned_candidate():
    cases = [
        {
            "app_id": "app",
            "target_id": "target",
            "case_id": "holdout-case",
            "expected_rule_ids": ("EXPECTED_RULE",),
            "file": "src/holdout.ts",
            "line_start": 1,
            "line_end": 1,
            "split": "holdout",
        }
    ]
    finding = {
        "app_id": "app",
        "target_id": "target",
        "rule_id": "NOISE",
        "severity": "high",
        "file": "src/outside.ts",
        "line_start": 1,
        "line_end": 1,
    }

    rates = _candidate_split_metrics(cases, [finding], {}, split="holdout")

    assert rates["unassigned_candidate_count"] == 1
    assert rates["binding_complete"] is False


def test_clean_case_counts_any_high_candidate_in_scope_as_false_positive():
    case = {
        "app_id": "app",
        "target_id": "target",
        "case_id": "clean-case",
        "severity": "high",
        "expected_outcome": "clean",
        "expected_rule_ids": ("EXPECTED_RULE",),
        "file": "src/clean.ts",
        "line_start": 10,
        "line_end": 20,
        "stratum": "top",
        "split": "holdout",
        "source_kind": "owned_partner",
    }
    unrelated = {
        "app_id": "app",
        "target_id": "target",
        "rule_id": "UNRELATED_HIGH_RULE",
        "severity": "high",
        "file": "src/clean.ts",
        "line_start": 12,
        "line_end": 12,
    }

    result, errors = _evaluate_ground_truth([case], [unrelated])

    assert errors == []
    assert result["counts"]["false_positive"] == 1
    assert result["counts"]["true_negative"] == 0
