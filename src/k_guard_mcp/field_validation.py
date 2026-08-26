from __future__ import annotations

import csv
import hashlib
import hmac
import json
import math
import os
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from k_guard_mcp.experience import release_target_evidence_refs
from k_guard_mcp.field_campaign import evaluate_field_campaign_readiness, load_field_app_roster
from k_guard_mcp.guardian import guardian_execution_attestation_valid, guardian_report_identity, guardian_toolchain_contract
from k_guard_mcp.hashing import EVIDENCE_HMAC_ENV, active_evidence_key, evidence_hash, evidence_hash_scheme, uses_public_evidence_key
from k_guard_mcp.provenance import evidence_bundle, object_artifact, path_artifact, verify_evidence_bundle
from k_guard_mcp.redaction import sanitize_any
from k_guard_mcp.validation import finding_fingerprint


FIELD_REVIEW_FIELDS = [
    "app_id",
    "target_id",
    "rule_id",
    "severity",
    "detector_subtype",
    "artifact_scope",
    "location_kind",
    "response_hash",
    "finding_fingerprint",
    "reviewer_1",
    "verdict_1",
    "reviewer_1_signature",
    "reviewer_2",
    "verdict_2",
    "reviewer_2_signature",
    "adjudicator",
    "adjudicator_signature",
    "final_verdict",
    "notes",
]
GROUND_TRUTH_FIELDS = [
    "app_id",
    "target_id",
    "case_id",
    "severity",
    "expected_outcome",
    "expected_rule_ids",
    "file",
    "line_start",
    "line_end",
    "stratum",
    "split",
    "source_kind",
    "source_ref",
    "reproduction_count",
    "reviewer_1",
    "verdict_1",
    "reviewer_1_signature",
    "reviewer_2",
    "verdict_2",
    "reviewer_2_signature",
    "adjudicator",
    "adjudicator_signature",
    "final_verdict",
    "notes",
]

FIELD_REVIEW_VERDICTS = {"true_positive", "false_positive", "benign", "inconclusive"}
GROUND_TRUTH_VERDICTS = {"vulnerable", "clean", "inconclusive"}
EXPECTED_OUTCOMES = {"vulnerable", "clean"}
STRATA = {"top", "mid", "long_tail"}
SPLITS = {"development", "holdout"}
SOURCE_KINDS = {"owned_partner", "public_benchmark", "seeded_mutation"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
FIELD_REVIEWER_KEYS_ENV = "K_GUARD_FIELD_REVIEWER_HMAC_KEYS"
FIELD_CUSTODIAN_KEY_ENV = "K_GUARD_FIELD_CUSTODIAN_HMAC_KEY"

VALIDATION_PROFILES: dict[str, dict[str, float | int | bool]] = {
    "field": {
        "min_app_count": 12,
        "max_app_count": 20,
        "min_case_count": 120,
        "min_positive_case_count": 50,
        "min_negative_case_count": 40,
        "min_critical_case_count": 5,
        "min_candidate_count": 20,
        "min_stratum_count": 3,
        "min_holdout_case_count": 70,
        "min_holdout_fraction": 0.30,
        "min_holdout_positive_case_count": 35,
        "min_holdout_negative_case_count": 35,
        "min_holdout_candidate_count": 35,
        "min_holdout_critical_case_count": 5,
        "min_holdout_stratum_count": 3,
        "min_holdout_app_count": 6,
        "min_precision": 0.90,
        "min_precision_confidence_lower": 0.80,
        "min_high_critical_recall": 0.90,
        "min_critical_recall": 1.0,
        "min_specificity": 0.90,
        "require_dual_review": True,
        "require_owned_partner_only": True,
    },
    "benchmark": {
        "min_app_count": 1,
        "max_app_count": 100,
        "min_case_count": 50,
        "min_positive_case_count": 25,
        "min_negative_case_count": 10,
        "min_critical_case_count": 0,
        "min_candidate_count": 1,
        "min_stratum_count": 1,
        "min_holdout_case_count": 0,
        "min_holdout_fraction": 0.0,
        "min_precision": 0.90,
        "min_precision_confidence_lower": 0.80,
        "min_high_critical_recall": 0.90,
        "min_critical_recall": 1.0,
        "min_specificity": 0.90,
        "require_dual_review": False,
        "require_owned_partner_only": False,
    },
    "mutation": {
        "min_app_count": 1,
        "max_app_count": 100,
        "min_case_count": 50,
        "min_positive_case_count": 25,
        "min_negative_case_count": 25,
        "min_critical_case_count": 0,
        "min_candidate_count": 1,
        "min_stratum_count": 3,
        "min_holdout_case_count": 0,
        "min_holdout_fraction": 0.0,
        "min_precision": 0.80,
        "min_high_critical_recall": 0.90,
        "min_critical_recall": 1.0,
        "min_specificity": 0.90,
        "require_dual_review": False,
        "require_owned_partner_only": False,
    },
    "pilot": {
        "min_app_count": 1,
        "max_app_count": 100,
        "min_case_count": 1,
        "min_positive_case_count": 1,
        "min_negative_case_count": 0,
        "min_critical_case_count": 0,
        "min_candidate_count": 1,
        "min_stratum_count": 1,
        "min_holdout_case_count": 0,
        "min_holdout_fraction": 0.0,
        "min_precision": 0.0,
        "min_high_critical_recall": 0.0,
        "min_critical_recall": 0.0,
        "min_specificity": 0.0,
        "require_dual_review": False,
        "require_owned_partner_only": False,
    },
}


def field_validation_metric_contract() -> dict[str, Any]:
    return {
        "schema": "k_guard_field_validation_metrics.v3",
        "precision": "candidate_true_positive/(candidate_true_positive+candidate_false_positive+candidate_benign)",
        "false_discovery_rate": "(candidate_false_positive+candidate_benign)/(candidate_true_positive+candidate_false_positive+candidate_benign)",
        "false_positive_rate": "clean_case_false_positive/(clean_case_false_positive+clean_case_true_negative)",
        "recall": "vulnerable_case_true_positive/(vulnerable_case_true_positive+vulnerable_case_false_negative)",
        "specificity": "clean_case_true_negative/(clean_case_true_negative+clean_case_false_positive)",
        "field_precision_gate": "overall_candidate_and_preregistered_holdout_precision_point_estimate_plus_wilson_95_lower_bound",
        "field_recall_specificity_gate": "preregistered_holdout_point_estimate_plus_wilson_95_lower_bound; critical_recall_must_equal_1",
        "confidence_interval": "two_sided_wilson_score_95_percent",
        "raw_returned": False,
    }


def write_field_validation_templates(ground_truth_path: str | Path, review_path: str | Path) -> None:
    ground_truth_output = Path(ground_truth_path)
    review_output = Path(review_path)
    ground_truth_output.parent.mkdir(parents=True, exist_ok=True)
    review_output.parent.mkdir(parents=True, exist_ok=True)
    with ground_truth_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=GROUND_TRUTH_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "app_id": "owned-app-01",
                "target_id": "owned-app-01-workspace",
                "case_id": "idor-route-001",
                "severity": "high",
                "expected_outcome": "vulnerable",
                "expected_rule_ids": "JS_TS_EXPRESS_IDOR_ROUTE_PARAM",
                "file": "src/routes/profile.ts",
                "line_start": "42",
                "line_end": "45",
                "stratum": "top",
                "split": "holdout",
                "source_kind": "owned_partner",
                "source_ref": "partner-scope-ticket-or-immutable-dataset-ref",
                "reproduction_count": "2",
                "reviewer_1": "reviewer-a",
                "verdict_1": "vulnerable",
                "reviewer_2": "reviewer-b",
                "verdict_2": "vulnerable",
                "adjudicator": "",
                "final_verdict": "vulnerable",
                "notes": "raw-free rationale",
            }
        )
    with review_output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writeheader()
        writer.writerow(
            {
                "app_id": "owned-app-01",
                "target_id": "owned-app-01-workspace",
                "rule_id": "JS_TS_EXPRESS_IDOR_ROUTE_PARAM",
                "severity": "high",
                "detector_subtype": "js-ts-taint",
                "artifact_scope": "runtime_source",
                "location_kind": "file",
                "response_hash": "",
                "finding_fingerprint": "paste-fingerprint-from-primary-guardian-report",
                "reviewer_1": "reviewer-a",
                "verdict_1": "true_positive",
                "reviewer_2": "reviewer-b",
                "verdict_2": "true_positive",
                "adjudicator": "",
                "final_verdict": "true_positive",
                "notes": "raw-free rationale",
            }
        )


def sign_field_validation_inputs(
    *,
    ground_truth_path: str | Path | None = None,
    review_path: str | Path | None = None,
) -> dict[str, Any]:
    if ground_truth_path is None and review_path is None:
        raise ValueError("At least one field-validation CSV path is required.")
    keys = _reviewer_keys()
    if len(keys) < 2:
        raise RuntimeError(f"{FIELD_REVIEWER_KEYS_ENV} must contain at least two distinct valid reviewer keys.")
    signed_counts: dict[str, int] = {}
    if ground_truth_path is not None:
        signed_counts["ground_truth"] = _sign_validation_csv(
            Path(ground_truth_path),
            GROUND_TRUTH_FIELDS,
            "ground_truth",
            keys,
        )
    if review_path is not None:
        signed_counts["candidate_review"] = _sign_validation_csv(
            Path(review_path),
            FIELD_REVIEW_FIELDS,
            "candidate_review",
            keys,
        )
    return {
        "schema": "k_guard_field_reviewer_signing.v1",
        "algorithm": "hmac-sha256",
        "signed_row_counts": signed_counts,
        "reviewer_key_count": len(keys),
        "raw_returned": False,
    }


def _sign_validation_csv(
    path: Path,
    fieldnames: list[str],
    row_kind: str,
    keys: dict[str, str],
) -> int:
    if not path.is_file():
        raise ValueError(f"Validation CSV was not found: {path.name}")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    signed = 0
    normalized_rows: list[dict[str, str]] = []
    for row in rows:
        item = {field: str(row.get(field, "") or "").strip() for field in fieldnames}
        reviewers = [item.get("reviewer_1", ""), item.get("reviewer_2", "")]
        if reviewers[0] and reviewers[1] and reviewers[0] == reviewers[1]:
            raise ValueError("Reviewer identities must be distinct before signing.")
        for slot in (1, 2):
            reviewer = item.get(f"reviewer_{slot}", "")
            verdict = item.get(f"verdict_{slot}", "")
            if not reviewer and not verdict:
                continue
            key = keys.get(reviewer)
            if not key:
                raise RuntimeError(f"No valid reviewer key is configured for reviewer_{slot}.")
            item[f"reviewer_{slot}_signature"] = _row_signature(
                key,
                _review_signature_projection(item, row_kind=row_kind, role=f"reviewer_{slot}"),
            )
            signed += 1
        adjudicator = item.get("adjudicator", "")
        if adjudicator:
            key = keys.get(adjudicator)
            if not key:
                raise RuntimeError("No valid reviewer key is configured for the adjudicator.")
            item["adjudicator_signature"] = _row_signature(
                key,
                _review_signature_projection(item, row_kind=row_kind, role="adjudicator"),
            )
            signed += 1
        normalized_rows.append(item)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(normalized_rows)
    return signed


def write_field_review_queue(guardian_report_path: str | Path, output_path: str | Path) -> dict[str, Any]:
    report = _load_json_object(Path(guardian_report_path), "guardian_report")
    findings = _high_critical_findings(report)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    rows: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for finding in findings:
        app_id = str(finding.get("app_id") or "")
        target_id = str(finding.get("target_id") or "")
        rule_id = str(finding.get("rule_id") or "")
        fingerprint = finding_fingerprint(finding)
        key = (app_id, target_id, rule_id, fingerprint)
        rows.setdefault(
            key,
            {
                "app_id": app_id,
                "target_id": target_id,
                "rule_id": rule_id,
                "severity": str(finding.get("severity") or ""),
                "detector_subtype": str(finding.get("source") or ""),
                "artifact_scope": str(finding.get("artifact_scope") or "workspace_evidence"),
                "location_kind": _finding_location_kind(finding),
                "response_hash": _finding_response_hash(finding),
                "finding_fingerprint": fingerprint,
                "reviewer_1": "",
                "verdict_1": "",
                "reviewer_2": "",
                "verdict_2": "",
                "adjudicator": "",
                "final_verdict": "",
                "notes": "",
            },
        )
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_REVIEW_FIELDS)
        writer.writeheader()
        writer.writerows(rows[key] for key in sorted(rows))
    scope_counts = Counter(row["artifact_scope"] for row in rows.values())
    severity_counts = Counter(row["severity"] for row in rows.values())
    return {
        "schema": "k_guard_field_review_queue.v1",
        "candidate_count": len(rows),
        "severity_counts": dict(sorted(severity_counts.items())),
        "artifact_scope_counts": dict(sorted(scope_counts.items())),
        "all_high_critical_candidates_exported": len(rows) == len({finding_fingerprint(item) for item in findings}),
        "reviewers_required": 2,
        "raw_returned": False,
    }


def _finding_location_kind(finding: dict[str, Any]) -> str:
    scope = str(finding.get("scope") or "").lower()
    if "header" in scope:
        return "header"
    if "body" in scope or "response" in scope:
        return "body"
    if finding.get("file"):
        return "file"
    if finding.get("url"):
        return "response"
    return "workspace"


def _finding_response_hash(finding: dict[str, Any]) -> str:
    for field in ("response_hash", "response_sha256", "body_sha256", "header_sha256"):
        value = str(finding.get(field) or "").lower()
        if re.fullmatch(r"[0-9a-f]{16,64}", value):
            return value
    evidence = str(finding.get("evidence") or "")
    match = re.search(
        r"(?:response_hash|response_sha256|body_sha256|header_sha256)=([0-9a-f]{16,64})",
        evidence,
        re.IGNORECASE,
    )
    return match.group(1).lower() if match else ""


def write_field_preregistration(
    ground_truth_path: str | Path,
    output_path: str | Path,
    *,
    custodian_id: str,
    roster_path: str | Path | None = None,
) -> dict[str, Any]:
    if uses_public_evidence_key():
        raise RuntimeError(f"{EVIDENCE_HMAC_ENV} is required to preregister field-validation ground truth.")
    ground_truth = Path(ground_truth_path)
    if not ground_truth.is_file():
        raise ValueError("Ground-truth CSV must exist before preregistration.")
    with ground_truth.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    if not rows or not set(GROUND_TRUTH_FIELDS).issubset(set(rows[0])):
        raise ValueError("Ground-truth CSV does not implement the v2 field contract.")
    custodian = str(custodian_id or "").strip()
    custodian_key = os.getenv(FIELD_CUSTODIAN_KEY_ENV, "")
    if not custodian:
        raise ValueError("A non-empty independent custodian_id is required.")
    if not _valid_custodian_key(custodian_key):
        raise RuntimeError(
            f"{FIELD_CUSTODIAN_KEY_ENV} must be a distinct valid custodian key, separate from operator and reviewer keys."
        )
    artifact = path_artifact("preregistered_ground_truth_csv", ground_truth, role="ground_truth")
    roster_artifact: dict[str, Any] | None = None
    roster_projection: dict[str, Any] | None = None
    if roster_path is not None:
        roster = Path(roster_path)
        roster_rows = load_field_app_roster(roster)
        roster_readiness = evaluate_field_campaign_readiness(roster)
        roster_artifact = path_artifact("preregistered_field_app_roster", roster, role="field_roster")
        roster_projection = _field_roster_projection(roster_readiness)
        if len(roster_rows) != int(roster_projection["app_count"]):
            raise ValueError("Field-app roster projection does not match its validated rows.")
    generated_at = datetime.now(UTC).isoformat()
    preregistered_toolchain = guardian_toolchain_contract()
    toolchain_sha256 = _canonical_sha256_input(preregistered_toolchain)
    split_projection = sorted(
        [
        {
            "app_id": str(row.get("app_id") or ""),
            "target_id": str(row.get("target_id") or ""),
            "case_id": str(row.get("case_id") or ""),
            "split": str(row.get("split") or ""),
            "source_kind": str(row.get("source_kind") or ""),
            "source_ref_hash": evidence_hash(str(row.get("source_ref") or "")),
        }
        for row in rows
        ],
        key=lambda item: (item["app_id"], item["target_id"], item["case_id"]),
    )
    split_sha256 = hashlib.sha256(
        json.dumps(split_projection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    custodian_assertion: dict[str, Any] = {
        "schema": "k_guard_field_custodian_assertion.v2" if roster_projection else "k_guard_field_custodian_assertion.v1",
        "custodian_id_ref": _ref(custodian),
        "ground_truth_content_sha256": artifact.get("content_sha256", ""),
        "split_assignment_sha256": split_sha256,
        "toolchain_contract_sha256": toolchain_sha256,
        "asserted_frozen_before_primary_scan": True,
        "asserted_custodian_separate_from_scanner_operator": True,
        "signed_at": generated_at,
        "algorithm": "hmac-sha256",
        "raw_returned": False,
    }
    if roster_projection and roster_artifact:
        custodian_assertion.update(
            {
                "roster_content_sha256": roster_artifact.get("content_sha256", ""),
                "roster_projection_sha256": _canonical_sha256_input(roster_projection),
                "asserted_roster_frozen_before_primary_scan": True,
            }
        )
    custodian_assertion["signature"] = _row_signature(custodian_key, custodian_assertion)
    payload: dict[str, Any] = {
        "schema": "k_guard_field_preregistration.v2" if roster_projection else "k_guard_field_preregistration.v1",
        "generated_at": generated_at,
        "ground_truth_content_sha256": artifact.get("content_sha256", ""),
        "ground_truth_row_count": len(rows),
        "split_counts": dict(sorted(Counter(str(row.get("split") or "") for row in rows).items())),
        "source_kind_counts": dict(sorted(Counter(str(row.get("source_kind") or "") for row in rows).items())),
        "toolchain_contract": preregistered_toolchain,
        "custodian_assertion": custodian_assertion,
        "raw_free": True,
    }
    if roster_projection and roster_artifact:
        payload.update(
            {
                "roster_content_sha256": roster_artifact.get("content_sha256", ""),
                "roster_row_count": roster_projection["row_count"],
                "roster_projection": roster_projection,
            }
        )
    preregistration_artifacts = [
        artifact,
        *([roster_artifact] if roster_artifact else []),
        object_artifact("field_preregistration_projection", payload, role="gate"),
    ]
    payload["preregistration_evidence_envelope"] = evidence_bundle(
        "field_validation_preregistration",
        "k_guard_mcp.field_validation",
        preregistration_artifacts,
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(sanitize_any(payload), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return sanitize_any(payload)


def run_field_validation(
    guardian_report_path: str | Path,
    repeat_guardian_report_path: str | Path,
    ground_truth_path: str | Path,
    review_path: str | Path,
    *,
    profile: str = "field",
    preregistration_path: str | Path | None = None,
    roster_path: str | Path | None = None,
) -> dict[str, Any]:
    if uses_public_evidence_key():
        raise RuntimeError(f"{EVIDENCE_HMAC_ENV} is required to generate signed field-validation evidence.")
    if profile not in VALIDATION_PROFILES:
        raise ValueError(f"Unknown field-validation profile {profile!r}.")

    primary_path = Path(guardian_report_path)
    repeat_path = Path(repeat_guardian_report_path)
    ground_truth_file = Path(ground_truth_path)
    review_file = Path(review_path)
    primary = _load_json_object(primary_path, "guardian_report")
    repeat = _load_json_object(repeat_path, "repeat_guardian_report")
    findings = _high_critical_findings(primary)
    repeat_findings = _high_critical_findings(repeat)
    target_apps = _guardian_target_apps(primary)
    primary_guardian_evidence = _guardian_input_evidence_status(primary, require_field=profile == "field")
    repeat_guardian_evidence = _guardian_input_evidence_status(repeat, require_field=profile == "field")
    preregistration = _field_preregistration_status(
        Path(preregistration_path) if preregistration_path else None,
        ground_truth_file,
        primary,
        Path(roster_path) if roster_path else None,
    )

    reviews, invalid_reviews = _read_field_reviews(review_file, target_apps, require_dual=bool(VALIDATION_PROFILES[profile]["require_dual_review"]))
    cases, invalid_cases = _read_ground_truth(
        ground_truth_file,
        target_apps,
        profile=profile,
        require_dual=bool(VALIDATION_PROFILES[profile]["require_dual_review"]),
    )
    candidate_result = _evaluate_candidates(findings, reviews)
    case_result, case_errors = _evaluate_ground_truth(cases, findings)
    invalid_cases.extend(case_errors)
    reproducibility = _reproducibility(primary_path, repeat_path, primary, repeat, findings, repeat_findings)
    metrics = _metrics(candidate_result["verdict_counts"], case_result["counts"])
    rate_confidence_intervals = _metric_confidence_intervals(candidate_result["verdict_counts"], case_result["counts"])
    holdout = _case_metrics(case_result["rows"], split="holdout")
    holdout_candidate_rates = _candidate_split_metrics(cases, findings, reviews, split="holdout")
    evaluation = holdout if profile == "field" else _case_metrics(case_result["rows"])
    evaluation["scope"] = (
        "holdout"
        if profile == "field"
        else "public_development"
        if profile == "benchmark"
        else "seeded_mutation_regression"
        if profile == "mutation"
        else "pilot"
    )
    evaluation["dataset_role"] = (
        "preregistered_holdout"
        if profile == "field"
        else "public_development_benchmark"
        if profile == "benchmark"
        else "seeded_mutation_regression"
        if profile == "mutation"
        else "pilot"
    )
    sample = _sample(cases, findings, reviews, invalid_reviews, invalid_cases, case_result, holdout)
    thresholds = dict(VALIDATION_PROFILES[profile])
    checks = _field_checks(
        profile,
        thresholds,
        sample,
        metrics,
        rate_confidence_intervals,
        holdout,
        holdout_candidate_rates,
        evaluation,
        reproducibility,
        candidate_result,
        invalid_reviews,
        invalid_cases,
        preregistration,
        primary_guardian_evidence,
        repeat_guardian_evidence,
    )
    claim_status = _claim_status(profile, checks)
    generated_at = datetime.now(UTC).isoformat()

    review_artifact = path_artifact("validation_review_csv", review_file, role="manual_input")
    ground_truth_artifact = path_artifact("ground_truth_csv", ground_truth_file, role="ground_truth")
    roster_artifact = path_artifact("field_app_roster_csv", roster_path or "", role="field_roster")
    repeat_artifact = path_artifact("repeat_guardian_report", repeat_path, role="repeat_input")
    review_source = _source_contract("k_guard_field_review_source.v1", review_artifact, sample["review_row_count"])
    ground_truth_source = _source_contract("k_guard_ground_truth_source.v1", ground_truth_artifact, sample["ground_truth_row_count"])
    field_roster_source = _source_contract(
        "k_guard_field_roster_source.v1",
        roster_artifact,
        int(preregistration.get("roster_row_count", 0)),
    )
    repeat_guardian_source = _source_contract("k_guard_repeat_guardian_source.v1", repeat_artifact, 1)
    reviewer_assertions = _reviewer_assertions(reviews, invalid_reviews)
    ground_truth_assertions = _ground_truth_assertions(cases, invalid_cases)

    report: dict[str, Any] = {
        "schema": "k_guard_field_validation.v1",
        "generated_at": generated_at,
        "method": "ground_truth_field_validation",
        "toolchain_contract": guardian_toolchain_contract(),
        "profile": profile,
        "evidence_tier": (
            "field"
            if profile == "field"
            else "public_benchmark"
            if profile == "benchmark"
            else "seeded_mutation"
            if profile == "mutation"
            else "pilot"
        ),
        "raw_free": True,
        "guardian_report_ref": _path_ref(primary_path),
        "guardian_report_content_ref": _content_ref(primary_path),
        "guardian_report_bundle_ref": _bundle_ref(primary.get("evidence_bundle")),
        "repeat_guardian_report_ref": _path_ref(repeat_path),
        "repeat_guardian_report_content_ref": _content_ref(repeat_path),
        "repeat_guardian_report_bundle_ref": _bundle_ref(repeat.get("evidence_bundle")),
        "review_source": review_source,
        "ground_truth_source": ground_truth_source,
        "field_roster_source": field_roster_source,
        "repeat_guardian_source": repeat_guardian_source,
        "reviewer_assertions": reviewer_assertions,
        "ground_truth_assertions": ground_truth_assertions,
        "field_preregistration": preregistration,
        "primary_guardian_evidence": primary_guardian_evidence,
        "repeat_guardian_evidence": repeat_guardian_evidence,
        "sample": sample,
        "verdict_counts": candidate_result["verdict_counts"],
        "case_counts": case_result["counts"],
        "metric_contract": field_validation_metric_contract(),
        "rates": metrics,
        "rates_confidence_intervals": rate_confidence_intervals,
        "holdout": holdout,
        "holdout_candidate_rates": holdout_candidate_rates,
        "evaluation": evaluation,
        "reproducibility": reproducibility,
        "thresholds": thresholds,
        "gate_checks": checks,
        "claim_status": claim_status,
        "candidate_app_refs": [_ref(value) for value in sorted(candidate_result["candidate_app_ids"])],
        "candidate_target_refs": [_ref(value) for value in sorted(candidate_result["candidate_target_ids"])],
        "candidate_finding_refs": [
            {"hash": value, "hash_scheme": evidence_hash_scheme(), "raw_returned": False}
            for value in sorted(candidate_result["candidate_fingerprints"])
        ],
        "evaluation_app_refs": [_ref(value) for value in sorted({case["app_id"] for case in cases})],
        "evaluation_target_refs": [_ref(value) for value in sorted({case["target_id"] for case in cases})],
        "case_refs": [_ref(_case_key(case)) for case in cases],
        "candidate_reviews": candidate_result["rows"][:500],
        "case_results": case_result["rows"][:1000],
        "invalid_reviews": invalid_reviews[:200],
        "invalid_ground_truth": invalid_cases[:200],
        "boundary": {
            "ground_truth_required": True,
            "candidate_precision_and_case_recall_are_separate": True,
            "field_candidate_precision_is_holdout_scoped": profile == "field",
            "candidate_false_discovery_rate_is_not_case_false_positive_rate": True,
            "repeat_guardian_run_required": True,
            "field_claim_requires_owned_partner_apps": True,
            "field_claim_requires_prescan_ground_truth_preregistration": True,
            "field_claim_requires_preregistered_owned_partner_roster": True,
            "role_key_separation_does_not_prove_human_identity": True,
            "reviewer_and_custodian_identity_assurance_is_external": True,
            "public_benchmark_does_not_equal_field_validation": True,
            "holdout_is_preregistered_not_cryptographically_blind": profile == "field",
            "local_execution_attestation_does_not_prove_independent_execution": True,
            "public_benchmark_is_not_an_independent_holdout": profile == "benchmark",
            "seeded_mutation_does_not_equal_field_validation": profile == "mutation",
            "not_a_certificate": True,
            "raw_returned": False,
        },
        "hash_scheme": evidence_hash_scheme(),
    }
    report["validation_evidence_envelope"] = evidence_bundle(
        "field_validation_review",
        "k_guard_mcp.field_validation",
        [
            review_artifact,
            ground_truth_artifact,
            roster_artifact,
            repeat_artifact,
            object_artifact("review_source", review_source, role="manual_input"),
            object_artifact("ground_truth_source", ground_truth_source, role="ground_truth"),
            object_artifact("field_roster_source", field_roster_source, role="field_roster"),
            object_artifact("repeat_guardian_source", repeat_guardian_source, role="repeat_input"),
            object_artifact("reviewer_assertions", reviewer_assertions, role="assertion"),
            object_artifact("ground_truth_assertions", ground_truth_assertions, role="assertion"),
            object_artifact("generated_at", {"generated_at": generated_at}, role="timestamp"),
            object_artifact("toolchain_contract", report.get("toolchain_contract", {}), role="identity"),
            object_artifact("guardian_binding", field_validation_guardian_binding(report), role="input"),
            object_artifact("repeat_guardian_binding", field_validation_repeat_binding(report), role="repeat_input"),
            object_artifact("field_validation_projection", field_validation_projection(report), role="gate"),
        ],
    )
    return sanitize_any(report)


def field_validation_projection(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": report.get("schema"),
        "method": report.get("method"),
        "toolchain_contract": report.get("toolchain_contract", {}),
        "profile": report.get("profile"),
        "evidence_tier": report.get("evidence_tier"),
        "raw_free": report.get("raw_free"),
        "sample": report.get("sample", {}),
        "verdict_counts": report.get("verdict_counts", {}),
        "case_counts": report.get("case_counts", {}),
        "metric_contract": report.get("metric_contract", {}),
        "rates": report.get("rates", {}),
        "rates_confidence_intervals": report.get("rates_confidence_intervals", {}),
        "holdout": report.get("holdout", {}),
        "holdout_candidate_rates": report.get("holdout_candidate_rates", {}),
        "evaluation": report.get("evaluation", {}),
        "reproducibility": report.get("reproducibility", {}),
        "repeat_guardian_source": report.get("repeat_guardian_source", {}),
        "field_preregistration": report.get("field_preregistration", {}),
        "field_roster_source": report.get("field_roster_source", {}),
        "primary_guardian_evidence": report.get("primary_guardian_evidence", {}),
        "repeat_guardian_evidence": report.get("repeat_guardian_evidence", {}),
        "thresholds": report.get("thresholds", {}),
        "gate_checks": report.get("gate_checks", []),
        "claim_status": report.get("claim_status"),
        "candidate_app_refs": report.get("candidate_app_refs", []),
        "candidate_target_refs": report.get("candidate_target_refs", []),
        "candidate_finding_refs": report.get("candidate_finding_refs", []),
        "evaluation_app_refs": report.get("evaluation_app_refs", []),
        "evaluation_target_refs": report.get("evaluation_target_refs", []),
        "case_refs": report.get("case_refs", []),
        "candidate_reviews": report.get("candidate_reviews", []),
        "case_results": report.get("case_results", []),
        "invalid_reviews": report.get("invalid_reviews", []),
        "invalid_ground_truth": report.get("invalid_ground_truth", []),
        "boundary": report.get("boundary", {}),
        "hash_scheme": report.get("hash_scheme"),
    }


def field_validation_guardian_binding(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "guardian_report_ref": report.get("guardian_report_ref", {}),
        "guardian_report_content_ref": report.get("guardian_report_content_ref", {}),
        "guardian_report_bundle_ref": report.get("guardian_report_bundle_ref", {}),
        "raw_returned": False,
    }


def field_validation_repeat_binding(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "repeat_guardian_report_ref": report.get("repeat_guardian_report_ref", {}),
        "repeat_guardian_report_content_ref": report.get("repeat_guardian_report_content_ref", {}),
        "repeat_guardian_report_bundle_ref": report.get("repeat_guardian_report_bundle_ref", {}),
        "raw_returned": False,
    }


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{label} must contain a JSON object.")
    return data


def _field_preregistration_status(
    path: Path | None,
    ground_truth_path: Path,
    primary_report: dict[str, Any],
    roster_path: Path | None = None,
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "present": False,
        "schema_valid": False,
        "ground_truth_content_bound": False,
        "operator_signature_valid": False,
        "custodian_assertion_valid": False,
        "signed_projection_valid": False,
        "toolchain_bound_before_scan": False,
        "generated_before_primary_scan": False,
        "roster_present": False,
        "roster_content_bound": False,
        "roster_ready": False,
        "roster_signed": False,
        "roster_target_binding": False,
        "roster_row_count": 0,
        "roster_content_sha256": "",
        "passed": False,
        "raw_returned": False,
    }
    if path is None or not path.is_file():
        return status
    status["present"] = True
    status["preregistration_ref"] = _path_ref(path)
    try:
        preregistration = _load_json_object(path, "field_preregistration")
    except (OSError, ValueError, json.JSONDecodeError):
        return status
    projection_fields = [
        "schema",
        "generated_at",
        "ground_truth_content_sha256",
        "ground_truth_row_count",
        "split_counts",
        "source_kind_counts",
        "toolchain_contract",
        "custodian_assertion",
        "raw_free",
    ]
    if preregistration.get("schema") == "k_guard_field_preregistration.v2":
        projection_fields.extend(("roster_content_sha256", "roster_row_count", "roster_projection"))
    projection = {key: preregistration.get(key) for key in projection_fields}
    status["schema_valid"] = (
        preregistration.get("schema") in {"k_guard_field_preregistration.v1", "k_guard_field_preregistration.v2"}
        and preregistration.get("raw_free") is True
    )
    preregistered_toolchain = preregistration.get("toolchain_contract", {}) if isinstance(preregistration.get("toolchain_contract"), dict) else {}
    status["toolchain_bound_before_scan"] = bool(
        preregistered_toolchain
        and preregistered_toolchain == primary_report.get("toolchain_contract")
        and preregistered_toolchain == guardian_toolchain_contract()
    )
    current_ground_truth = path_artifact("preregistered_ground_truth_csv", ground_truth_path, role="ground_truth")
    current_sha256 = str(current_ground_truth.get("content_sha256") or "")
    status["ground_truth_content_bound"] = (
        bool(current_sha256)
        and preregistration.get("ground_truth_content_sha256") == current_sha256
    )
    bundle = preregistration.get("preregistration_evidence_envelope")
    status["operator_signature_valid"] = verify_evidence_bundle(bundle, require_operator_key=True)
    custodian_assertion = preregistration.get("custodian_assertion", {}) if isinstance(preregistration.get("custodian_assertion"), dict) else {}
    assertion_projection = dict(custodian_assertion)
    assertion_signature = str(assertion_projection.pop("signature", ""))
    custodian_key = os.getenv(FIELD_CUSTODIAN_KEY_ENV, "")
    custodian_assertion_valid = bool(
        _valid_custodian_key(custodian_key)
        and custodian_assertion.get("schema") in {"k_guard_field_custodian_assertion.v1", "k_guard_field_custodian_assertion.v2"}
        and isinstance(custodian_assertion.get("custodian_id_ref"), dict)
        and custodian_assertion.get("ground_truth_content_sha256") == current_sha256
        and re.fullmatch(r"[0-9a-f]{64}", str(custodian_assertion.get("split_assignment_sha256") or ""))
        and custodian_assertion.get("toolchain_contract_sha256") == _canonical_sha256_input(preregistered_toolchain)
        and custodian_assertion.get("asserted_frozen_before_primary_scan") is True
        and custodian_assertion.get("asserted_custodian_separate_from_scanner_operator") is True
        and hmac.compare_digest(assertion_signature, _row_signature(custodian_key, assertion_projection))
    )
    status["custodian_assertion_valid"] = custodian_assertion_valid
    artifacts = bundle.get("artifacts", []) if isinstance(bundle, dict) else []
    signed_ground_truth = next(
        (
            item
            for item in artifacts
            if isinstance(item, dict)
            and item.get("label") == "preregistered_ground_truth_csv"
            and item.get("role") == "ground_truth"
        ),
        None,
    )
    expected_projection = object_artifact("field_preregistration_projection", projection, role="gate")
    signed_projection = next(
        (
            item
            for item in artifacts
            if isinstance(item, dict)
            and item.get("label") == "field_preregistration_projection"
            and item.get("role") == "gate"
        ),
        None,
    )
    signed_ground_truth_valid = (
        isinstance(signed_ground_truth, dict)
        and signed_ground_truth.get("content_sha256") == current_sha256
        and signed_ground_truth.get("byte_count") == current_ground_truth.get("byte_count")
    )
    status["signed_projection_valid"] = (
        signed_ground_truth_valid
        and isinstance(signed_projection, dict)
        and signed_projection.get("hash") == expected_projection.get("hash")
        and signed_projection.get("byte_count") == expected_projection.get("byte_count")
    )
    if preregistration.get("schema") == "k_guard_field_preregistration.v2" and roster_path is not None and roster_path.is_file():
        status["roster_present"] = True
        try:
            roster_rows = load_field_app_roster(roster_path)
            roster_readiness = evaluate_field_campaign_readiness(roster_path)
        except (OSError, ValueError):
            roster_rows = []
            roster_readiness = {}
        current_roster = path_artifact("preregistered_field_app_roster", roster_path, role="field_roster")
        current_roster_sha256 = str(current_roster.get("content_sha256") or "")
        status["roster_content_sha256"] = current_roster_sha256
        expected_roster_projection = _field_roster_projection(roster_readiness) if roster_readiness else {}
        status["roster_content_bound"] = bool(
            current_roster_sha256
            and preregistration.get("roster_content_sha256") == current_roster_sha256
            and preregistration.get("roster_projection") == expected_roster_projection
        )
        status["roster_ready"] = bool(roster_readiness.get("ready") is True and roster_rows)
        status["roster_row_count"] = int(roster_readiness.get("row_count", 0) or 0)
        signed_roster = next(
            (
                item
                for item in artifacts
                if isinstance(item, dict)
                and item.get("label") == "preregistered_field_app_roster"
                and item.get("role") == "field_roster"
            ),
            None,
        )
        status["roster_signed"] = bool(
            isinstance(signed_roster, dict)
            and signed_roster.get("content_sha256") == current_roster_sha256
            and signed_roster.get("byte_count") == current_roster.get("byte_count")
            and custodian_assertion.get("schema") == "k_guard_field_custodian_assertion.v2"
            and custodian_assertion.get("roster_content_sha256") == current_roster_sha256
            and custodian_assertion.get("roster_projection_sha256") == _canonical_sha256_input(expected_roster_projection)
            and custodian_assertion.get("asserted_roster_frozen_before_primary_scan") is True
        )
        roster_pairs = {(str(row["app_id"]), str(row["target_id"])) for row in roster_rows}
        guardian_pairs = {
            (str(target.get("app_id") or ""), str(target.get("target_id") or ""))
            for target in primary_report.get("targets", [])
            if isinstance(target, dict)
        }
        ground_truth_pairs: set[tuple[str, str]] = set()
        try:
            with ground_truth_path.open(newline="", encoding="utf-8-sig") as handle:
                ground_truth_pairs = {
                    (str(row.get("app_id") or ""), str(row.get("target_id") or ""))
                    for row in csv.DictReader(handle)
                }
        except OSError:
            ground_truth_pairs = set()
        status["roster_target_binding"] = bool(
            roster_pairs
            and roster_pairs == guardian_pairs
            and roster_pairs == ground_truth_pairs
        )
    preregistered_at = _parse_timestamp(preregistration.get("generated_at"))
    primary_bundle = primary_report.get("evidence_bundle", {}) if isinstance(primary_report.get("evidence_bundle"), dict) else {}
    primary_at = _parse_timestamp(primary_bundle.get("generated_at"))
    status["generated_before_primary_scan"] = bool(
        preregistered_at and primary_at and preregistered_at < primary_at
    )
    status["passed"] = all(
        status[name] is True
        for name in (
            "present",
            "schema_valid",
            "ground_truth_content_bound",
            "operator_signature_valid",
            "custodian_assertion_valid",
            "signed_projection_valid",
            "toolchain_bound_before_scan",
            "generated_before_primary_scan",
        )
    )
    return status


def _field_roster_projection(readiness: dict[str, Any]) -> dict[str, Any]:
    refs = readiness.get("roster_refs", []) if isinstance(readiness.get("roster_refs"), list) else []
    sorted_refs = sorted(
        (item for item in refs if isinstance(item, dict)),
        key=lambda item: str(item.get("app_ref", {}).get("hash", "")),
    )
    return {
        "schema": "k_guard_field_roster_preregistration.v1",
        "content_sha256": readiness.get("content_sha256", ""),
        "row_count": int(readiness.get("row_count", 0) or 0),
        "app_count": int(readiness.get("app_count", 0) or 0),
        "target_count": int(readiness.get("target_count", 0) or 0),
        "stratum_counts": readiness.get("stratum_counts", {}),
        "ready": readiness.get("ready") is True,
        "roster_refs": sorted_refs,
        "raw_returned": False,
    }


def _parse_timestamp(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _guardian_input_evidence_status(report: dict[str, Any], *, require_field: bool = False) -> dict[str, Any]:
    bundle = report.get("evidence_bundle")
    operator_signature_valid = verify_evidence_bundle(bundle, require_operator_key=True)
    identity_valid = (
        isinstance(bundle, dict)
        and bundle.get("subject") == "guardian_audit"
        and bundle.get("producer") == "k_guard_mcp.guardian"
    )
    expected = [
        object_artifact("report_identity", guardian_report_identity(report), role="identity"),
        object_artifact("execution_attestation", report.get("execution_attestation", {}), role="identity"),
        object_artifact("toolchain_contract", report.get("toolchain_contract", {}), role="identity"),
        object_artifact("summary", report.get("summary", {})),
        object_artifact("execution_contract", report.get("execution_contract", {})),
        object_artifact("intent_contract", report.get("intent_contract", {})),
        object_artifact("review_contract", report.get("review_contract", {})),
        object_artifact("deep_analyzer_reports", report.get("deep_analyzer_reports", []), role="analysis"),
        object_artifact("release_qualification", report.get("release_qualification", {}), role="gate"),
        object_artifact("baseline", report.get("baseline", {})),
        object_artifact("drift", report.get("drift", {})),
        object_artifact("guardian_gate", report.get("guardian_gate", {}), role="gate"),
        object_artifact("release_authority_claim", report.get("release_authority_claim", {}), role="gate"),
        object_artifact("suppression_policy", report.get("suppression_policy", {}), role="policy"),
        object_artifact("target_refs", release_target_evidence_refs(report.get("targets", []))),
        object_artifact("top_rules", report.get("top_rules", [])),
    ]
    artifacts = bundle.get("artifacts", []) if isinstance(bundle, dict) and isinstance(bundle.get("artifacts"), list) else []
    projection_bound = all(_artifact_matches(artifacts, item) for item in expected)
    manifest = next(
        (
            item
            for item in artifacts
            if isinstance(item, dict)
            and item.get("label") == "guardian_manifest"
            and item.get("role") == "input"
        ),
        {},
    )
    manifest_bound = (
        isinstance(manifest, dict)
        and manifest.get("exists_at_bundle_time") is True
        and int(manifest.get("byte_count", 0)) > 0
        and re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("content_sha256") or "")) is not None
        and manifest.get("raw_returned") is False
    )
    canonical_contract = _canonical_field_guardian_contract(report) if require_field else {"passed": True}
    passed = (
        operator_signature_valid
        and identity_valid
        and projection_bound
        and (not require_field or (manifest_bound and canonical_contract.get("passed") is True))
    )
    return {
        "operator_signature_valid": operator_signature_valid,
        "bundle_identity_valid": identity_valid,
        "report_projection_bound": projection_bound,
        "manifest_content_bound": manifest_bound,
        "canonical_execution_contract": canonical_contract,
        "passed": passed,
        "bundle_ref": _bundle_ref(bundle),
        "raw_returned": False,
    }


def _canonical_field_guardian_contract(report: dict[str, Any]) -> dict[str, Any]:
    execution = report.get("execution_contract", {}) if isinstance(report.get("execution_contract"), dict) else {}
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    targets = report.get("targets", []) if isinstance(report.get("targets"), list) else []
    execution_id = str(report.get("execution_id") or "")
    generated_at = _parse_timestamp(report.get("generated_at"))
    expected_toolchain = guardian_toolchain_contract()
    toolchain = report.get("toolchain_contract", {}) if isinstance(report.get("toolchain_contract"), dict) else {}
    target_errors: Counter[str] = Counter()
    workspace_apps: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            target_errors["non_object_target"] += 1
            continue
        kind = str(target.get("kind") or "")
        app_id = str(target.get("app_id") or "")
        target_id = str(target.get("target_id") or "")
        coverage = target.get("coverage", {}) if isinstance(target.get("coverage"), dict) else {}
        evidence = target.get("review_evidence", {}) if isinstance(target.get("review_evidence"), dict) else {}
        scope_contract = target.get("scope_contract", {}) if isinstance(target.get("scope_contract"), dict) else {}
        if not app_id or not target_id:
            target_errors["missing_target_identity"] += 1
        if target.get("status") != "completed":
            target_errors["target_not_completed"] += 1
        if target.get("audit_profile") != "korean_senior" or target.get("fail_on") != "high":
            target_errors["noncanonical_profile_or_threshold"] += 1
        if coverage.get("executed") is not True or coverage.get("coverage_gap") is not False:
            target_errors["coverage_incomplete"] += 1
        assertion_ref = scope_contract.get("assertion_ref", {}) if isinstance(scope_contract.get("assertion_ref"), dict) else {}
        if not (
            scope_contract.get("assertion_present") is True
            and bool(assertion_ref.get("hash"))
            and assertion_ref.get("raw_returned") is False
            and scope_contract.get("ownership_or_partner_scope_verified_by_k_guard") is False
        ):
            target_errors["external_scope_assertion_missing"] += 1
        if kind == "workspace":
            workspace_apps.add(app_id)
            snapshot = evidence.get("source_tree_snapshot", {}) if isinstance(evidence.get("source_tree_snapshot"), dict) else {}
            consistency = evidence.get("source_tree_consistency", {}) if isinstance(evidence.get("source_tree_consistency"), dict) else {}
            inventory_consistency = evidence.get("scan_inventory_consistency", {}) if isinstance(evidence.get("scan_inventory_consistency"), dict) else {}
            review_coverage = evidence.get("review_coverage", {}) if isinstance(evidence.get("review_coverage"), dict) else {}
            inventory = review_coverage.get("inventory", {}) if isinstance(review_coverage.get("inventory"), dict) else {}
            if not (
                snapshot.get("schema") == "k_guard_source_tree_snapshot.v1"
                and snapshot.get("complete") is True
                and re.fullmatch(r"[0-9a-f]{64}", str(snapshot.get("tree_sha256") or "")) is not None
                and consistency.get("matched") is True
                and inventory_consistency.get("matched") is True
                and inventory.get("candidate_set_complete") is True
                and int(inventory.get("supported_file_count", 0)) > 0
                and int(inventory.get("reviewed_candidate_count", inventory.get("scanned_text_file_count", 0)))
                == int(inventory.get("supported_file_count", -1))
            ):
                target_errors["workspace_source_evidence_incomplete"] += 1
        elif kind == "http":
            dynamic = evidence.get("dynamic_probe_contract", {}) if isinstance(evidence.get("dynamic_probe_contract"), dict) else {}
            if int(dynamic.get("request_count", 0)) <= 0 or int(dynamic.get("error_request_count", 0)) != 0:
                target_errors["http_probe_evidence_incomplete"] += 1
        elif kind == "mcp_events":
            runtime = evidence.get("runtime_policy", {}) if isinstance(evidence.get("runtime_policy"), dict) else {}
            if int(runtime.get("event_count", 0)) <= 0:
                target_errors["mcp_runtime_evidence_incomplete"] += 1
        else:
            target_errors["unsupported_field_target_kind"] += 1
    checks = {
        "method": report.get("method") == "guardian_audit",
        "signed_execution_identity": re.fullmatch(r"[0-9a-f]{32}", execution_id) is not None and generated_at is not None,
        "execution_attestation": guardian_execution_attestation_valid(report),
        "toolchain_exact": toolchain == expected_toolchain and toolchain.get("complete") is True,
        "execution_mode": execution.get("mode") in {"report", "release_gate"},
        "execution_complete": (
            int(execution.get("skipped_target_count", -1)) == 0
            and int(execution.get("error_target_count", -1)) == 0
            and int(execution.get("coverage_gap_target_count", -1)) == 0
        ),
        "target_summary_bound": bool(targets) and int(summary.get("target_count", -1)) == len(targets),
        "workspace_per_app": bool(workspace_apps)
        and workspace_apps == {str(target.get("app_id") or "") for target in targets if isinstance(target, dict)},
        "target_evidence": not target_errors,
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "target_error_counts": dict(sorted(target_errors.items())),
        "target_count": len(targets),
        "workspace_app_count": len(workspace_apps),
        "raw_returned": False,
    }


def _artifact_matches(artifacts: list[Any], expected: dict[str, Any]) -> bool:
    candidate = next(
        (
            item
            for item in artifacts
            if isinstance(item, dict)
            and item.get("label") == expected.get("label")
            and item.get("role", "evidence") == expected.get("role", "evidence")
        ),
        None,
    )
    if not isinstance(candidate, dict) or candidate.get("raw_returned") is not False:
        return False
    return all(
        candidate.get(key) == expected.get(key)
        for key in ("hash", "hash_scheme", "byte_count")
        if key in expected
    )


def _high_critical_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        app_id = str(target.get("app_id") or "").strip()
        target_id = str(target.get("target_id") or "").strip()
        for finding in target.get("findings", []):
            if not isinstance(finding, dict) or str(finding.get("severity") or "info").lower() not in {"critical", "high"}:
                continue
            item = dict(finding)
            item.setdefault("app_id", app_id)
            item.setdefault("target_id", target_id)
            findings.append(item)
    return findings


def _guardian_target_apps(report: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    ambiguous: set[str] = set()
    for target in report.get("targets", []):
        if not isinstance(target, dict):
            continue
        target_id = str(target.get("target_id") or "").strip()
        app_id = str(target.get("app_id") or "").strip()
        if not target_id or not app_id:
            continue
        if target_id in result and result[target_id] != app_id:
            ambiguous.add(target_id)
        else:
            result[target_id] = app_id
    for target_id in ambiguous:
        result.pop(target_id, None)
    return result


def _valid_role_key(value: str) -> bool:
    return (
        len(value) >= 32
        and len(set(value)) >= 8
        and value != active_evidence_key()
        and value != os.getenv(FIELD_CUSTODIAN_KEY_ENV, "")
    )


def _valid_custodian_key(value: str) -> bool:
    if len(value) < 32 or len(set(value)) < 8 or value == active_evidence_key():
        return False
    try:
        reviewer_payload = json.loads(os.getenv(FIELD_REVIEWER_KEYS_ENV, ""))
    except json.JSONDecodeError:
        reviewer_payload = {}
    reviewer_values = {
        str(item)
        for item in reviewer_payload.values()
    } if isinstance(reviewer_payload, dict) else set()
    return value not in reviewer_values


def _reviewer_keys() -> dict[str, str]:
    try:
        payload = json.loads(os.getenv(FIELD_REVIEWER_KEYS_ENV, ""))
    except json.JSONDecodeError:
        return {}
    if not isinstance(payload, dict):
        return {}
    keys = {
        str(name).strip(): str(value)
        for name, value in payload.items()
        if str(name).strip() and _valid_role_key(str(value))
    }
    if len(set(keys.values())) != len(keys):
        return {}
    return keys


def _row_signature(key: str, projection: dict[str, Any]) -> str:
    canonical = json.dumps(projection, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest}"


def _review_signature_projection(row: dict[str, str], *, row_kind: str, role: str) -> dict[str, Any]:
    if row_kind == "ground_truth":
        identity_fields = GROUND_TRUTH_FIELDS[: GROUND_TRUTH_FIELDS.index("reviewer_1")]
    else:
        identity_fields = FIELD_REVIEW_FIELDS[: FIELD_REVIEW_FIELDS.index("reviewer_1")]
    projection: dict[str, Any] = {
        "schema": "k_guard_field_row_signature.v1",
        "row_kind": row_kind,
        "role": role,
        "row_identity": {field: row.get(field, "") for field in identity_fields},
        "raw_returned": False,
    }
    if role in {"reviewer_1", "reviewer_2"}:
        suffix = role.rsplit("_", 1)[1]
        projection["reviewer"] = row.get(f"reviewer_{suffix}", "")
        projection["verdict"] = row.get(f"verdict_{suffix}", "")
    else:
        projection["reviewer"] = row.get("adjudicator", "")
        projection["verdict"] = row.get("final_verdict", "")
        projection["reviewer_1_verdict"] = row.get("verdict_1", "")
        projection["reviewer_2_verdict"] = row.get("verdict_2", "")
    return projection


def _review_signature_error(row: dict[str, str], *, row_kind: str) -> str:
    keys = _reviewer_keys()
    reviewer_1 = row.get("reviewer_1", "")
    reviewer_2 = row.get("reviewer_2", "")
    key_1 = keys.get(reviewer_1)
    key_2 = keys.get(reviewer_2)
    if not key_1 or not key_2:
        return "independent_reviewer_keys_required"
    if key_1 == key_2:
        return "reviewer_keys_must_be_distinct"
    for slot, key in ((1, key_1), (2, key_2)):
        expected = _row_signature(
            key,
            _review_signature_projection(row, row_kind=row_kind, role=f"reviewer_{slot}"),
        )
        if not hmac.compare_digest(row.get(f"reviewer_{slot}_signature", ""), expected):
            return f"invalid_reviewer_{slot}_signature"
    adjudicator = row.get("adjudicator", "")
    if adjudicator:
        adjudicator_key = keys.get(adjudicator)
        if not adjudicator_key or adjudicator_key in {key_1, key_2}:
            return "independent_adjudicator_key_required"
        expected = _row_signature(
            adjudicator_key,
            _review_signature_projection(row, row_kind=row_kind, role="adjudicator"),
        )
        if not hmac.compare_digest(row.get("adjudicator_signature", ""), expected):
            return "invalid_adjudicator_signature"
    return ""


def _read_field_reviews(
    path: Path,
    target_apps: dict[str, str],
    *,
    require_dual: bool,
) -> tuple[dict[tuple[str, str, str, str], dict[str, str]], list[dict[str, Any]]]:
    reviews: dict[tuple[str, str, str, str], dict[str, str]] = {}
    invalid: list[dict[str, Any]] = []
    if not path.exists():
        return reviews, [{"row": 0, "error": "review_path_not_found", "path_ref": evidence_hash(str(path))}]
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    for index, row in enumerate(rows, start=2):
        item = {field: str(row.get(field, "") or "").strip() for field in FIELD_REVIEW_FIELDS}
        error = _field_review_error(item, target_apps, require_dual=require_dual)
        if error:
            invalid.append({"row": index, "error": error})
            continue
        key = (item["app_id"], item["target_id"], item["rule_id"], item["finding_fingerprint"])
        if key in reviews:
            invalid.append({"row": index, "error": "duplicate_review_key"})
            continue
        reviews[key] = item
    return reviews, invalid


def _field_review_error(row: dict[str, str], target_apps: dict[str, str], *, require_dual: bool) -> str:
    for field in ("app_id", "target_id", "rule_id", "finding_fingerprint", "reviewer_1", "verdict_1", "final_verdict"):
        if not row.get(field):
            return f"missing_{field}"
    if row["verdict_1"] not in FIELD_REVIEW_VERDICTS or row["final_verdict"] not in FIELD_REVIEW_VERDICTS:
        return "invalid_review_verdict"
    if target_apps.get(row["target_id"]) != row["app_id"]:
        return "review_app_target_binding_mismatch"
    if require_dual:
        if not row.get("reviewer_2") or not row.get("verdict_2"):
            return "dual_review_required"
        if row["reviewer_1"] == row["reviewer_2"]:
            return "reviewers_must_be_distinct"
        if row["verdict_2"] not in FIELD_REVIEW_VERDICTS:
            return "invalid_second_review_verdict"
        if row["verdict_1"] == row["verdict_2"] and row["final_verdict"] != row["verdict_1"]:
            return "agreed_reviews_must_bind_final_verdict"
        if row["verdict_1"] != row["verdict_2"]:
            if not row.get("adjudicator"):
                return "disagreement_requires_adjudicator"
            if row["adjudicator"] in {row["reviewer_1"], row["reviewer_2"]}:
                return "adjudicator_must_be_independent"
        signature_error = _review_signature_error(row, row_kind="candidate_review")
        if signature_error:
            return signature_error
    return ""


def _read_ground_truth(
    path: Path,
    target_apps: dict[str, str],
    *,
    profile: str,
    require_dual: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    cases: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    if not path.exists():
        return cases, [{"row": 0, "error": "ground_truth_path_not_found", "path_ref": evidence_hash(str(path))}]
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    seen: set[tuple[str, str, str]] = set()
    for index, row in enumerate(rows, start=2):
        raw = {field: str(row.get(field, "") or "").strip() for field in GROUND_TRUTH_FIELDS}
        item, error = _normalize_ground_truth(raw, target_apps, profile=profile, require_dual=require_dual)
        if error:
            invalid.append({"row": index, "error": error})
            continue
        key = (item["app_id"], item["target_id"], item["case_id"])
        if key in seen:
            invalid.append({"row": index, "error": "duplicate_ground_truth_case"})
            continue
        seen.add(key)
        cases.append(item)
    return cases, invalid


def _normalize_ground_truth(
    row: dict[str, str],
    target_apps: dict[str, str],
    *,
    profile: str,
    require_dual: bool,
) -> tuple[dict[str, Any], str]:
    for field in (
        "app_id",
        "target_id",
        "case_id",
        "severity",
        "expected_outcome",
        "expected_rule_ids",
        "stratum",
        "split",
        "source_kind",
        "source_ref",
        "reproduction_count",
        "final_verdict",
    ):
        if not row.get(field):
            return {}, f"missing_{field}"
    if target_apps.get(row["target_id"]) != row["app_id"]:
        return {}, "ground_truth_app_target_binding_mismatch"
    severity = row["severity"].lower()
    expected = row["expected_outcome"].lower()
    final = row["final_verdict"].lower()
    if severity not in SEVERITIES:
        return {}, "invalid_ground_truth_severity"
    if expected not in EXPECTED_OUTCOMES or final not in GROUND_TRUTH_VERDICTS:
        return {}, "invalid_ground_truth_verdict"
    if final != expected:
        return {}, "ground_truth_final_verdict_mismatch"
    if row["stratum"] not in STRATA or row["split"] not in SPLITS or row["source_kind"] not in SOURCE_KINDS:
        return {}, "invalid_ground_truth_cohort"
    if profile == "field" and row["source_kind"] != "owned_partner":
        return {}, "field_profile_requires_owned_partner_source"
    rule_ids = tuple(sorted({value.strip() for value in row["expected_rule_ids"].split("|") if value.strip()}))
    if not rule_ids:
        return {}, "expected_rule_ids_required"
    try:
        reproduction_count = int(row["reproduction_count"])
        line_start = int(row["line_start"]) if row["line_start"] else 0
        line_end = int(row["line_end"]) if row["line_end"] else line_start
    except ValueError:
        return {}, "invalid_ground_truth_integer"
    if reproduction_count < 2:
        return {}, "ground_truth_requires_two_reproductions"
    if line_start < 0 or line_end < line_start:
        return {}, "invalid_ground_truth_line_range"
    if require_dual:
        for field in ("reviewer_1", "verdict_1", "reviewer_2", "verdict_2"):
            if not row.get(field):
                return {}, "ground_truth_dual_review_required"
        if row["reviewer_1"] == row["reviewer_2"]:
            return {}, "ground_truth_reviewers_must_be_distinct"
        if row["verdict_1"] not in EXPECTED_OUTCOMES or row["verdict_2"] not in EXPECTED_OUTCOMES:
            return {}, "invalid_ground_truth_reviewer_verdict"
        if row["verdict_1"] == row["verdict_2"] and final != row["verdict_1"]:
            return {}, "ground_truth_agreement_mismatch"
        if row["verdict_1"] != row["verdict_2"]:
            if not row.get("adjudicator"):
                return {}, "ground_truth_disagreement_requires_adjudicator"
            if row["adjudicator"] in {row["reviewer_1"], row["reviewer_2"]}:
                return {}, "ground_truth_adjudicator_must_be_independent"
        signature_error = _review_signature_error(row, row_kind="ground_truth")
        if signature_error:
            return {}, f"ground_truth_{signature_error}"
    return {
        **row,
        "severity": severity,
        "expected_outcome": expected,
        "final_verdict": final,
        "expected_rule_ids": rule_ids,
        "reproduction_count": reproduction_count,
        "line_start": line_start,
        "line_end": line_end,
    }, ""


def _evaluate_candidates(findings: list[dict[str, Any]], reviews: dict[tuple[str, str, str, str], dict[str, str]]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    app_ids: set[str] = set()
    target_ids: set[str] = set()
    fingerprints: set[str] = set()
    for finding in findings:
        app_id = str(finding.get("app_id") or "")
        target_id = str(finding.get("target_id") or "")
        rule_id = str(finding.get("rule_id") or "")
        fingerprint = finding_fingerprint(finding)
        review = reviews.get((app_id, target_id, rule_id, fingerprint))
        verdict = review["final_verdict"] if review else "inconclusive"
        counts[verdict] += 1
        app_ids.add(app_id)
        target_ids.add(target_id)
        fingerprints.add(fingerprint)
        rows.append(
            {
                "app_ref": _ref(app_id),
                "target_ref": _ref(target_id),
                "rule_id": rule_id,
                "finding_ref": _ref(fingerprint),
                "severity": str(finding.get("severity") or ""),
                "verdict": verdict,
                "dual_reviewed": bool(review and review.get("reviewer_2")),
                "raw_returned": False,
            }
        )
    return {
        "verdict_counts": {verdict: counts.get(verdict, 0) for verdict in sorted(FIELD_REVIEW_VERDICTS)},
        "rows": rows,
        "candidate_app_ids": app_ids,
        "candidate_target_ids": target_ids,
        "candidate_fingerprints": fingerprints,
    }


def _evaluate_ground_truth(cases: list[dict[str, Any]], findings: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    counts: Counter[str] = Counter()
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    finding_refs = {finding_fingerprint(finding): finding for finding in findings}
    vulnerable_matches: dict[str, str] = {}
    clean_matches: dict[str, set[str]] = {}

    for case in sorted(cases, key=lambda item: (_severity_rank(item["severity"]), _case_key(item))):
        case_key = _case_key(case)
        rule_matches = sorted(
            fingerprint
            for fingerprint, finding in finding_refs.items()
            if _finding_matches_case(finding, case)
        )
        scope_matches = sorted(
            fingerprint
            for fingerprint, finding in finding_refs.items()
            if _finding_within_case_scope(finding, case)
        )
        matches = rule_matches if case["expected_outcome"] == "vulnerable" else scope_matches
        if case["expected_outcome"] == "vulnerable":
            available = [fingerprint for fingerprint in matches if fingerprint not in vulnerable_matches]
            if not available:
                outcome = "false_negative"
            else:
                chosen = available[0]
                vulnerable_matches[chosen] = case_key
                outcome = "true_positive"
            if len(matches) > 1:
                errors.append({"case_ref": _ref(case_key), "error": "ambiguous_multiple_findings_match_case"})
        else:
            outcome = "false_positive" if matches else "true_negative"
            if matches:
                clean_matches[case_key] = set(matches)
        counts[outcome] += 1
        rows.append(
            {
                "case_ref": _ref(case_key),
                "app_ref": _ref(case["app_id"]),
                "target_ref": _ref(case["target_id"]),
                "severity": case["severity"],
                "expected_outcome": case["expected_outcome"],
                "outcome": outcome,
                "stratum": case["stratum"],
                "split": case["split"],
                "source_kind": case["source_kind"],
                "matched_finding_count": len(matches),
                "raw_returned": False,
            }
        )
    for case_key, matches in clean_matches.items():
        overlap = matches.intersection(vulnerable_matches)
        if overlap:
            errors.append({"case_ref": _ref(case_key), "error": "clean_and_vulnerable_cases_share_finding"})
    return {
        "counts": {name: counts.get(name, 0) for name in ("true_positive", "false_positive", "false_negative", "true_negative")},
        "rows": rows,
    }, errors


def _finding_matches_case(finding: dict[str, Any], case: dict[str, Any]) -> bool:
    if not _finding_within_case_scope(finding, case):
        return False
    return str(finding.get("rule_id") or "") in case["expected_rule_ids"]


def _finding_within_case_scope(finding: dict[str, Any], case: dict[str, Any]) -> bool:
    if str(finding.get("app_id") or "") != case["app_id"] or str(finding.get("target_id") or "") != case["target_id"]:
        return False
    expected_file = _normalize_path(case.get("file", ""))
    if expected_file:
        finding_file = _normalize_path(finding.get("file") or finding.get("url") or "")
        if not (finding_file == expected_file or finding_file.endswith("/" + expected_file)):
            return False
    line_start = int(case.get("line_start") or 0)
    if line_start:
        finding_start = int(finding.get("line_start") or 0)
        finding_end = int(finding.get("line_end") or finding_start)
        if finding_end < line_start or finding_start > int(case.get("line_end") or line_start):
            return False
    return True


def _candidate_split_metrics(
    cases: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    reviews: dict[tuple[str, str, str, str], dict[str, str]],
    *,
    split: str,
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    split_counts: Counter[str] = Counter()
    unassigned = 0
    ambiguous = 0
    for finding in findings:
        matched_splits = {
            str(case["split"])
            for case in cases
            if _finding_within_case_scope(finding, case)
        }
        if not matched_splits:
            unassigned += 1
            continue
        if len(matched_splits) != 1:
            ambiguous += 1
            continue
        bound_split = next(iter(matched_splits))
        split_counts[bound_split] += 1
        if bound_split != split:
            continue
        app_id = str(finding.get("app_id") or "")
        target_id = str(finding.get("target_id") or "")
        rule_id = str(finding.get("rule_id") or "")
        fingerprint = finding_fingerprint(finding)
        review = reviews.get((app_id, target_id, rule_id, fingerprint))
        counts[review["final_verdict"] if review else "inconclusive"] += 1
    candidate_tp = counts["true_positive"]
    candidate_fp = counts["false_positive"] + counts["benign"]
    selected_count = sum(counts.values())
    return {
        "split": split,
        "candidate_count": selected_count,
        "true_positive": counts["true_positive"],
        "false_positive": counts["false_positive"],
        "benign": counts["benign"],
        "inconclusive": counts["inconclusive"],
        "precision": _rate(candidate_tp, candidate_tp + candidate_fp),
        "false_discovery_rate": _rate(candidate_fp, candidate_tp + candidate_fp),
        "precision_confidence_interval_95": _wilson_interval(candidate_tp, candidate_tp + candidate_fp),
        "all_candidate_count": len(findings),
        "bound_candidate_count": sum(split_counts.values()),
        "split_candidate_counts": dict(sorted(split_counts.items())),
        "unassigned_candidate_count": unassigned,
        "ambiguous_split_candidate_count": ambiguous,
        "binding_complete": unassigned == 0 and ambiguous == 0,
        "raw_returned": False,
    }


def _metrics(candidate_counts: dict[str, int], case_counts: dict[str, int]) -> dict[str, float]:
    candidate_tp = int(candidate_counts.get("true_positive", 0))
    candidate_fp = int(candidate_counts.get("false_positive", 0)) + int(candidate_counts.get("benign", 0))
    case_tp = int(case_counts.get("true_positive", 0))
    case_fn = int(case_counts.get("false_negative", 0))
    case_fp = int(case_counts.get("false_positive", 0))
    case_tn = int(case_counts.get("true_negative", 0))
    return {
        "precision": _rate(candidate_tp, candidate_tp + candidate_fp),
        "false_discovery_rate": _rate(candidate_fp, candidate_tp + candidate_fp),
        "false_positive_rate": _rate(case_fp, case_tn + case_fp),
        "recall": _rate(case_tp, case_tp + case_fn),
        "specificity": _rate(case_tn, case_tn + case_fp),
        "negative_case_false_positive_rate": _rate(case_fp, case_tn + case_fp),
    }


def _metric_confidence_intervals(candidate_counts: dict[str, int], case_counts: dict[str, int]) -> dict[str, Any]:
    candidate_tp = int(candidate_counts.get("true_positive", 0))
    candidate_fp = int(candidate_counts.get("false_positive", 0)) + int(candidate_counts.get("benign", 0))
    case_tp = int(case_counts.get("true_positive", 0))
    case_fn = int(case_counts.get("false_negative", 0))
    case_fp = int(case_counts.get("false_positive", 0))
    case_tn = int(case_counts.get("true_negative", 0))
    return {
        "precision_95": _wilson_interval(candidate_tp, candidate_tp + candidate_fp),
        "recall_95": _wilson_interval(case_tp, case_tp + case_fn),
        "specificity_95": _wilson_interval(case_tn, case_tn + case_fp),
        "raw_returned": False,
    }


def _case_metrics(rows: list[dict[str, Any]], *, split: str | None = None) -> dict[str, Any]:
    selected = [row for row in rows if split is None or row.get("split") == split]
    counts = Counter(str(row.get("outcome") or "") for row in selected)
    positive = counts["true_positive"] + counts["false_negative"]
    negative = counts["true_negative"] + counts["false_positive"]
    critical = [row for row in selected if row.get("expected_outcome") == "vulnerable" and row.get("severity") == "critical"]
    high_critical = [row for row in selected if row.get("expected_outcome") == "vulnerable" and row.get("severity") in {"critical", "high"}]
    stratum_counts = Counter(str(row.get("stratum") or "") for row in selected)
    app_refs = {
        json.dumps(row.get("app_ref", {}), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for row in selected
    }
    true_positive = counts["true_positive"]
    true_negative = counts["true_negative"]
    critical_true_positive = sum(1 for row in critical if row.get("outcome") == "true_positive")
    high_critical_true_positive = sum(1 for row in high_critical if row.get("outcome") == "true_positive")
    return {
        "case_count": len(selected),
        "app_count": len(app_refs),
        "stratum_count": len([value for value in stratum_counts if value]),
        "stratum_case_counts": dict(sorted(stratum_counts.items())),
        "positive_case_count": positive,
        "negative_case_count": negative,
        "recall": _rate(true_positive, positive),
        "recall_confidence_interval_95": _wilson_interval(true_positive, positive),
        "specificity": _rate(true_negative, negative),
        "specificity_confidence_interval_95": _wilson_interval(true_negative, negative),
        "critical_case_count": len(critical),
        "critical_recall": _rate(critical_true_positive, len(critical)),
        "critical_recall_confidence_interval_95": _wilson_interval(critical_true_positive, len(critical)),
        "high_critical_case_count": len(high_critical),
        "high_critical_recall": _rate(high_critical_true_positive, len(high_critical)),
        "high_critical_recall_confidence_interval_95": _wilson_interval(high_critical_true_positive, len(high_critical)),
    }


def _reproducibility(
    primary_path: Path,
    repeat_path: Path,
    primary: dict[str, Any],
    repeat: dict[str, Any],
    findings: list[dict[str, Any]],
    repeat_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    first = {finding_fingerprint(item) for item in findings}
    second = {finding_fingerprint(item) for item in repeat_findings}
    first_multiset = guardian_candidate_multiset_contract(findings)
    second_multiset = guardian_candidate_multiset_contract(repeat_findings)
    first_input = guardian_repeat_input_contract(primary)
    second_input = guardian_repeat_input_contract(repeat)
    union = first | second
    intersection = first & second
    first_targets = _guardian_target_apps(primary)
    second_targets = _guardian_target_apps(repeat)
    first_generated = str(primary.get("generated_at") or "")
    second_generated = str(repeat.get("generated_at") or "")
    first_execution_id = str(primary.get("execution_id") or "")
    second_execution_id = str(repeat.get("execution_id") or "")
    first_bundle = primary.get("evidence_bundle", {}) if isinstance(primary.get("evidence_bundle"), dict) else {}
    second_bundle = repeat.get("evidence_bundle", {}) if isinstance(repeat.get("evidence_bundle"), dict) else {}
    first_bundle_sha = str(first_bundle.get("bundle_sha256") or "")
    second_bundle_sha = str(second_bundle.get("bundle_sha256") or "")
    first_snapshots = _guardian_workspace_snapshot_bindings(primary)
    second_snapshots = _guardian_workspace_snapshot_bindings(repeat)
    first_attestation = primary.get("execution_attestation", {}) if isinstance(primary.get("execution_attestation"), dict) else {}
    second_attestation = repeat.get("execution_attestation", {}) if isinstance(repeat.get("execution_attestation"), dict) else {}
    return {
        "exact_candidate_set_match": first_multiset == second_multiset,
        "exact_candidate_multiset_match": first_multiset == second_multiset,
        "candidate_jaccard": _rate(len(intersection), len(union)) if union else 1.0,
        "primary_candidate_count": first_multiset["candidate_count"],
        "repeat_candidate_count": second_multiset["candidate_count"],
        "primary_candidate_unique_count": first_multiset["unique_candidate_count"],
        "repeat_candidate_unique_count": second_multiset["unique_candidate_count"],
        "primary_candidate_multiset_sha256": first_multiset["multiset_sha256"],
        "repeat_candidate_multiset_sha256": second_multiset["multiset_sha256"],
        "target_app_binding_match": first_targets == second_targets and bool(first_targets),
        "distinct_report_paths": primary_path.resolve() != repeat_path.resolve(),
        "distinct_execution_timestamps": bool(first_generated and second_generated and first_generated != second_generated),
        "distinct_execution_ids": bool(
            re.fullmatch(r"[0-9a-f]{32}", first_execution_id)
            and re.fullmatch(r"[0-9a-f]{32}", second_execution_id)
            and first_execution_id != second_execution_id
        ),
        "distinct_execution_attestations": bool(
            guardian_execution_attestation_valid(primary)
            and guardian_execution_attestation_valid(repeat)
            and first_attestation.get("execution_id") != second_attestation.get("execution_id")
            and first_attestation.get("started_at") != second_attestation.get("started_at")
            and first_attestation.get("completed_at") != second_attestation.get("completed_at")
        ),
        "distinct_evidence_bundles": bool(first_bundle_sha and second_bundle_sha and first_bundle_sha != second_bundle_sha),
        "same_bundle_reused": bool(first_bundle_sha and first_bundle_sha == second_bundle_sha),
        "toolchain_contract_match": bool(
            primary.get("toolchain_contract")
            and primary.get("toolchain_contract") == repeat.get("toolchain_contract")
        ),
        "workspace_source_snapshots_match": bool(first_snapshots and first_snapshots == second_snapshots),
        "workspace_snapshot_count": len(first_snapshots),
        "guardian_manifest_content_match": bool(
            first_input["manifest_content_sha256"]
            and first_input["manifest_content_sha256"] == second_input["manifest_content_sha256"]
        ),
        "target_input_bindings_match": bool(
            first_input["complete"] is True
            and first_input == second_input
        ),
        "primary_repeat_input_sha256": first_input["target_input_sha256"],
        "repeat_repeat_input_sha256": second_input["target_input_sha256"],
        "raw_returned": False,
    }


_REPEAT_CANDIDATE_FIELDS = (
    "app_id",
    "target_id",
    "rule_id",
    "source",
    "severity",
    "confidence",
    "artifact_scope",
    "file",
    "url",
    "line_start",
    "line_end",
)


def guardian_candidate_multiset_contract(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counter: Counter[str] = Counter()
    for finding in findings:
        projection = {field: finding.get(field) for field in _REPEAT_CANDIDATE_FIELDS}
        projection["finding_fingerprint"] = finding_fingerprint(finding)
        counter[_canonical_sha256_input(projection)] += 1
    encoded = json.dumps(sorted(counter.items()), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return {
        "schema": "k_guard_candidate_multiset.v1",
        "candidate_count": sum(counter.values()),
        "unique_candidate_count": len(counter),
        "multiset_sha256": hashlib.sha256(encoded).hexdigest(),
        "raw_returned": False,
    }


def guardian_repeat_input_contract(report: dict[str, Any]) -> dict[str, Any]:
    projections: list[str] = []
    target_keys: set[tuple[str, str, str]] = set()
    duplicate_target = False
    kind_counts: Counter[str] = Counter()
    targets = report.get("targets", []) if isinstance(report.get("targets"), list) else []
    for target in targets:
        if not isinstance(target, dict):
            duplicate_target = True
            continue
        app_id = str(target.get("app_id") or "")
        target_id = str(target.get("target_id") or "")
        kind = str(target.get("kind") or "")
        key = (app_id, target_id, kind)
        if not all(key) or key in target_keys:
            duplicate_target = True
        target_keys.add(key)
        kind_counts[kind] += 1
        projection = {
            "app_id": app_id,
            "target_id": target_id,
            "target_ref": target.get("target_ref", {}),
            "kind": kind,
            "kind_ref": target.get("kind_ref", {}),
            "locator": target.get("locator"),
            "locator_ref": target.get("locator_ref", {}),
            "authorization": target.get("authorization", {}),
            "business_context": target.get("business_context", {}),
            "scope_contract": target.get("scope_contract", {}),
            "audit_profile": target.get("audit_profile"),
            "requested_review": target.get("requested_review", {}),
            "fail_on": target.get("fail_on"),
            "status": target.get("status"),
            "coverage": target.get("coverage", {}),
            "review_evidence": target.get("review_evidence", {}),
        }
        projections.append(_canonical_sha256_input(projection))
    manifest_sha256 = _guardian_manifest_content_sha256(report)
    encoded = json.dumps(sorted(projections), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return {
        "schema": "k_guard_guardian_repeat_input.v1",
        "manifest_content_sha256": manifest_sha256,
        "target_count": len(targets),
        "workspace_target_count": kind_counts["workspace"],
        "http_target_count": kind_counts["http"],
        "mcp_target_count": kind_counts["mcp_events"],
        "target_input_sha256": hashlib.sha256(encoded).hexdigest(),
        "complete": bool(manifest_sha256 and targets and not duplicate_target and len(projections) == len(targets)),
        "raw_returned": False,
    }


def _canonical_sha256_input(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _guardian_manifest_content_sha256(report: dict[str, Any]) -> str:
    bundle = report.get("evidence_bundle", {}) if isinstance(report.get("evidence_bundle"), dict) else {}
    artifacts = bundle.get("artifacts", []) if isinstance(bundle.get("artifacts"), list) else []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        content_sha256 = str(artifact.get("content_sha256") or "")
        if (
            artifact.get("label") == "guardian_manifest"
            and artifact.get("role") == "input"
            and artifact.get("exists_at_bundle_time") is True
            and re.fullmatch(r"[0-9a-f]{64}", content_sha256)
        ):
            return content_sha256
    return ""


def _guardian_workspace_snapshot_bindings(report: dict[str, Any]) -> dict[tuple[str, str], str]:
    bindings: dict[tuple[str, str], str] = {}
    for target in report.get("targets", []):
        if not isinstance(target, dict) or target.get("kind") != "workspace":
            continue
        evidence = target.get("review_evidence", {}) if isinstance(target.get("review_evidence"), dict) else {}
        snapshot = evidence.get("source_tree_snapshot", {}) if isinstance(evidence.get("source_tree_snapshot"), dict) else {}
        tree_sha256 = str(snapshot.get("tree_sha256") or "")
        if re.fullmatch(r"[0-9a-f]{64}", tree_sha256) is None or snapshot.get("complete") is not True:
            continue
        bindings[(str(target.get("app_id") or ""), str(target.get("target_id") or ""))] = tree_sha256
    return bindings


def _sample(
    cases: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    reviews: dict[tuple[str, str, str, str], dict[str, str]],
    invalid_reviews: list[dict[str, Any]],
    invalid_cases: list[dict[str, Any]],
    case_result: dict[str, Any],
    holdout: dict[str, Any],
) -> dict[str, Any]:
    apps = {case["app_id"] for case in cases}
    candidate_apps = {str(item.get("app_id") or "") for item in findings if str(item.get("app_id") or "")}
    candidate_targets = {str(item.get("target_id") or "") for item in findings if str(item.get("target_id") or "")}
    positive = sum(1 for case in cases if case["expected_outcome"] == "vulnerable")
    negative = sum(1 for case in cases if case["expected_outcome"] == "clean")
    critical = sum(1 for case in cases if case["expected_outcome"] == "vulnerable" and case["severity"] == "critical")
    reviewed_fingerprints = {key[3] for key in reviews}
    candidate_fingerprints = {finding_fingerprint(item) for item in findings}
    source_kinds = Counter(case["source_kind"] for case in cases)
    strata = Counter(case["stratum"] for case in cases)
    stratum_apps = {
        stratum: len({case["app_id"] for case in cases if case["stratum"] == stratum})
        for stratum in sorted(STRATA)
    }
    return {
        "app_count": len(apps),
        "candidate_app_count": len(candidate_apps),
        "candidate_target_count": len(candidate_targets),
        "candidate_count": len(findings),
        "reviewed_candidate_count": len(candidate_fingerprints.intersection(reviewed_fingerprints)),
        "review_app_id_count": len({key[0] for key in reviews}),
        "case_count": len(cases),
        "positive_case_count": positive,
        "negative_case_count": negative,
        "critical_case_count": critical,
        "holdout_case_count": int(holdout.get("case_count", 0)),
        "holdout_fraction": _rate(int(holdout.get("case_count", 0)), len(cases)),
        "stratum_count": len({case["stratum"] for case in cases}),
        "stratum_case_counts": dict(strata),
        "stratum_app_counts": stratum_apps,
        "source_kind_counts": dict(source_kinds),
        "owned_partner_app_count": len({case["app_id"] for case in cases if case["source_kind"] == "owned_partner"}),
        "invalid_review_count": len(invalid_reviews),
        "invalid_ground_truth_count": len(invalid_cases),
        "review_row_count": len(reviews) + len(invalid_reviews),
        "ground_truth_row_count": len(cases) + len(invalid_cases),
        "false_negative_count": int(case_result["counts"].get("false_negative", 0)),
    }


def _field_checks(
    profile: str,
    thresholds: dict[str, float | int | bool],
    sample: dict[str, Any],
    metrics: dict[str, float],
    rate_confidence_intervals: dict[str, Any],
    holdout: dict[str, Any],
    holdout_candidate_rates: dict[str, Any],
    evaluation: dict[str, Any],
    reproducibility: dict[str, Any],
    candidate_result: dict[str, Any],
    invalid_reviews: list[dict[str, Any]],
    invalid_cases: list[dict[str, Any]],
    preregistration: dict[str, Any],
    primary_guardian_evidence: dict[str, Any],
    repeat_guardian_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    candidate_counts = candidate_result["verdict_counts"]
    require_owned = bool(thresholds["require_owned_partner_only"])
    checks = [
        _check("valid_review_rows", not invalid_reviews, len(invalid_reviews), 0),
        _check("valid_ground_truth_rows", not invalid_cases, len(invalid_cases), 0),
        _check("minimum_apps", sample["app_count"] >= int(thresholds["min_app_count"]), sample["app_count"], thresholds["min_app_count"]),
        _check("maximum_apps", sample["app_count"] <= int(thresholds["max_app_count"]), sample["app_count"], thresholds["max_app_count"]),
        _check("minimum_cases", sample["case_count"] >= int(thresholds["min_case_count"]), sample["case_count"], thresholds["min_case_count"]),
        _check("minimum_positive_cases", sample["positive_case_count"] >= int(thresholds["min_positive_case_count"]), sample["positive_case_count"], thresholds["min_positive_case_count"]),
        _check("minimum_negative_cases", sample["negative_case_count"] >= int(thresholds["min_negative_case_count"]), sample["negative_case_count"], thresholds["min_negative_case_count"]),
        _check("minimum_critical_cases", sample["critical_case_count"] >= int(thresholds["min_critical_case_count"]), sample["critical_case_count"], thresholds["min_critical_case_count"]),
        _check("minimum_candidates", sample["candidate_count"] >= int(thresholds["min_candidate_count"]), sample["candidate_count"], thresholds["min_candidate_count"]),
        _check("all_candidates_reviewed", sample["reviewed_candidate_count"] == sample["candidate_count"] and sample["candidate_count"] > 0, sample["reviewed_candidate_count"], sample["candidate_count"]),
        _check("no_inconclusive_candidates", int(candidate_counts.get("inconclusive", 0)) == 0, candidate_counts.get("inconclusive", 0), 0),
        _check("minimum_strata", sample["stratum_count"] >= int(thresholds["min_stratum_count"]), sample["stratum_count"], thresholds["min_stratum_count"]),
        _check("candidate_precision", metrics["precision"] >= float(thresholds["min_precision"]), metrics["precision"], thresholds["min_precision"]),
        _check(f"{evaluation['scope']}_high_critical_recall", evaluation["high_critical_recall"] >= float(thresholds["min_high_critical_recall"]), evaluation["high_critical_recall"], thresholds["min_high_critical_recall"]),
        _check(
            f"{evaluation['scope']}_critical_recall",
            (evaluation["critical_case_count"] == 0 and int(thresholds["min_critical_case_count"]) == 0)
            or evaluation["critical_recall"] >= float(thresholds["min_critical_recall"]),
            evaluation["critical_recall"],
            thresholds["min_critical_recall"],
        ),
        _check(f"{evaluation['scope']}_specificity", evaluation["specificity"] >= float(thresholds["min_specificity"]), evaluation["specificity"], thresholds["min_specificity"]),
        _check("repeat_candidate_set", reproducibility["exact_candidate_set_match"] is True, reproducibility["candidate_jaccard"], 1.0),
        _check("repeat_target_binding", reproducibility["target_app_binding_match"] is True, reproducibility["target_app_binding_match"], True),
        _check("distinct_repeat_report", reproducibility["distinct_report_paths"] is True, reproducibility["distinct_report_paths"], True),
        _check("distinct_repeat_execution", reproducibility["distinct_execution_timestamps"] is True, reproducibility["distinct_execution_timestamps"], True),
        _check("owned_partner_field_scope", not require_owned or sample["owned_partner_app_count"] == sample["app_count"], sample["owned_partner_app_count"], sample["app_count"]),
    ]
    if "min_precision_confidence_lower" in thresholds:
        checks.append(
            _check(
                "candidate_precision_confidence_lower",
                float(rate_confidence_intervals.get("precision_95", {}).get("lower", 0.0))
                >= float(thresholds["min_precision_confidence_lower"]),
                rate_confidence_intervals.get("precision_95", {}).get("lower", 0.0),
                thresholds["min_precision_confidence_lower"],
            )
        )
    if profile == "field":
        checks.extend(
            [
                _check("field_preregistration_present", preregistration.get("present") is True, preregistration.get("present"), True),
                _check("field_preregistration_schema", preregistration.get("schema_valid") is True, preregistration.get("schema_valid"), True),
                _check("field_preregistration_ground_truth_binding", preregistration.get("ground_truth_content_bound") is True, preregistration.get("ground_truth_content_bound"), True),
                _check("field_preregistration_operator_signature", preregistration.get("operator_signature_valid") is True, preregistration.get("operator_signature_valid"), True),
                _check("field_preregistration_custodian_signature", preregistration.get("custodian_assertion_valid") is True, preregistration.get("custodian_assertion_valid"), True),
                _check("field_preregistration_signed_projection", preregistration.get("signed_projection_valid") is True, preregistration.get("signed_projection_valid"), True),
                _check("field_preregistration_toolchain_binding", preregistration.get("toolchain_bound_before_scan") is True, preregistration.get("toolchain_bound_before_scan"), True),
                _check("field_preregistration_before_primary", preregistration.get("generated_before_primary_scan") is True, preregistration.get("generated_before_primary_scan"), True),
                _check("field_roster_present", preregistration.get("roster_present") is True, preregistration.get("roster_present"), True),
                _check("field_roster_content_bound", preregistration.get("roster_content_bound") is True, preregistration.get("roster_content_bound"), True),
                _check("field_roster_ready", preregistration.get("roster_ready") is True, preregistration.get("roster_ready"), True),
                _check("field_roster_custodian_signed", preregistration.get("roster_signed") is True, preregistration.get("roster_signed"), True),
                _check("field_roster_target_binding", preregistration.get("roster_target_binding") is True, preregistration.get("roster_target_binding"), True),
                _check("primary_guardian_operator_evidence", primary_guardian_evidence.get("passed") is True, primary_guardian_evidence.get("passed"), True),
                _check("repeat_guardian_operator_evidence", repeat_guardian_evidence.get("passed") is True, repeat_guardian_evidence.get("passed"), True),
                _check("distinct_guardian_execution_ids", reproducibility.get("distinct_execution_ids") is True, reproducibility.get("distinct_execution_ids"), True),
                _check("distinct_guardian_execution_attestations", reproducibility.get("distinct_execution_attestations") is True, reproducibility.get("distinct_execution_attestations"), True),
                _check("distinct_guardian_evidence_bundles", reproducibility.get("distinct_evidence_bundles") is True and reproducibility.get("same_bundle_reused") is False, reproducibility.get("distinct_evidence_bundles"), True),
                _check("repeat_guardian_toolchain_match", reproducibility.get("toolchain_contract_match") is True, reproducibility.get("toolchain_contract_match"), True),
                _check("repeat_guardian_source_snapshots_match", reproducibility.get("workspace_source_snapshots_match") is True, reproducibility.get("workspace_source_snapshots_match"), True),
                _check("repeat_guardian_manifest_content_match", reproducibility.get("guardian_manifest_content_match") is True, reproducibility.get("guardian_manifest_content_match"), True),
                _check("repeat_guardian_target_inputs_match", reproducibility.get("target_input_bindings_match") is True, reproducibility.get("target_input_bindings_match"), True),
                _check("minimum_holdout_cases", sample["holdout_case_count"] >= int(thresholds["min_holdout_case_count"]), sample["holdout_case_count"], thresholds["min_holdout_case_count"]),
                _check("minimum_holdout_fraction", sample["holdout_fraction"] >= float(thresholds["min_holdout_fraction"]), sample["holdout_fraction"], thresholds["min_holdout_fraction"]),
                _check("minimum_holdout_positive_cases", int(holdout.get("positive_case_count", 0)) >= int(thresholds["min_holdout_positive_case_count"]), holdout.get("positive_case_count", 0), thresholds["min_holdout_positive_case_count"]),
                _check("minimum_holdout_negative_cases", int(holdout.get("negative_case_count", 0)) >= int(thresholds["min_holdout_negative_case_count"]), holdout.get("negative_case_count", 0), thresholds["min_holdout_negative_case_count"]),
                _check("minimum_holdout_critical_cases", int(holdout.get("critical_case_count", 0)) >= int(thresholds["min_holdout_critical_case_count"]), holdout.get("critical_case_count", 0), thresholds["min_holdout_critical_case_count"]),
                _check("minimum_holdout_strata", int(holdout.get("stratum_count", 0)) >= int(thresholds["min_holdout_stratum_count"]), holdout.get("stratum_count", 0), thresholds["min_holdout_stratum_count"]),
                _check("minimum_holdout_apps", int(holdout.get("app_count", 0)) >= int(thresholds["min_holdout_app_count"]), holdout.get("app_count", 0), thresholds["min_holdout_app_count"]),
                _check(
                    "holdout_candidate_split_binding",
                    holdout_candidate_rates.get("binding_complete") is True,
                    {
                        "unassigned": holdout_candidate_rates.get("unassigned_candidate_count", 0),
                        "ambiguous": holdout_candidate_rates.get("ambiguous_split_candidate_count", 0),
                    },
                    {"unassigned": 0, "ambiguous": 0},
                ),
                _check(
                    "minimum_holdout_candidates",
                    int(holdout_candidate_rates.get("candidate_count", 0)) >= int(thresholds["min_holdout_candidate_count"]),
                    holdout_candidate_rates.get("candidate_count", 0),
                    thresholds["min_holdout_candidate_count"],
                ),
                _check(
                    "holdout_candidate_precision",
                    float(holdout_candidate_rates.get("precision", 0.0)) >= float(thresholds["min_precision"]),
                    holdout_candidate_rates.get("precision", 0.0),
                    thresholds["min_precision"],
                ),
                _check(
                    "holdout_candidate_precision_confidence_lower",
                    float(holdout_candidate_rates.get("precision_confidence_interval_95", {}).get("lower", 0.0))
                    >= float(thresholds["min_precision_confidence_lower"]),
                    holdout_candidate_rates.get("precision_confidence_interval_95", {}).get("lower", 0.0),
                    thresholds["min_precision_confidence_lower"],
                ),
                _check(
                    "holdout_high_critical_recall_confidence_lower",
                    float(holdout.get("high_critical_recall_confidence_interval_95", {}).get("lower", 0.0)) >= float(thresholds["min_high_critical_recall"]),
                    holdout.get("high_critical_recall_confidence_interval_95", {}).get("lower", 0.0),
                    thresholds["min_high_critical_recall"],
                ),
                _check(
                    "holdout_specificity_confidence_lower",
                    float(holdout.get("specificity_confidence_interval_95", {}).get("lower", 0.0)) >= float(thresholds["min_specificity"]),
                    holdout.get("specificity_confidence_interval_95", {}).get("lower", 0.0),
                    thresholds["min_specificity"],
                ),
            ]
        )
    if profile == "pilot":
        checks.append(_check("pilot_not_field_claim", False, "pilot", "field_or_benchmark"))
    return checks


def _claim_status(profile: str, checks: list[dict[str, Any]]) -> str:
    failed = [check for check in checks if not check["passed"]]
    if not failed:
        if profile == "field":
            return "field_validation_ready"
        if profile == "benchmark":
            return "public_benchmark_ready"
        if profile == "mutation":
            return "seeded_mutation_regression_ready"
        return "pilot_ready"
    return f"blocked_{failed[0]['name']}"


def _check(name: str, passed: bool, value: object, threshold: object) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "value": value, "threshold": threshold}


def _source_contract(schema: str, artifact: dict[str, Any], row_count: int) -> dict[str, Any]:
    content_sha256 = str(artifact.get("content_sha256") or "")
    return {
        "schema": schema,
        "content_sha256": content_sha256,
        "sha256_verified_at_generation": re.fullmatch(r"[0-9a-f]{64}", content_sha256) is not None,
        "byte_count": int(artifact.get("byte_count", 0)),
        "row_count": row_count,
        "exists_at_generation": artifact.get("exists_at_bundle_time") is True,
        "path_ref": {
            "hash": artifact.get("hash", ""),
            "hash_scheme": artifact.get("hash_scheme", evidence_hash_scheme()),
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def _reviewer_assertions(
    reviews: dict[tuple[str, str, str, str], dict[str, str]],
    invalid: list[dict[str, Any]],
) -> dict[str, Any]:
    reviewers = sorted(
        {
            value
            for row in reviews.values()
            for value in (row.get("reviewer_1", ""), row.get("reviewer_2", ""), row.get("adjudicator", ""))
            if value
        }
    )
    dual_count = sum(1 for row in reviews.values() if row.get("reviewer_1") and row.get("reviewer_2") and row["reviewer_1"] != row["reviewer_2"])
    signed_count = sum(
        1
        for row in reviews.values()
        if row.get("reviewer_1_signature") and row.get("reviewer_2_signature")
        and (not row.get("adjudicator") or row.get("adjudicator_signature"))
    )
    return {
        "schema": "k_guard_field_reviewer_assertions.v1",
        "reviewed_row_count": len(reviews),
        "invalid_row_count": len(invalid),
        "dual_reviewed_row_count": dual_count,
        "cryptographically_verified_row_count": signed_count,
        "signature_algorithm": "hmac-sha256",
        "independent_role_keys_required": True,
        "reviewer_count": len(reviewers),
        "reviewer_refs": [_ref(value) for value in reviewers],
        "assertion_refs": [
            _ref("|".join((*key, row["verdict_1"], row.get("verdict_2", ""), row["final_verdict"])))
            for key, row in sorted(reviews.items())
        ],
        "raw_returned": False,
    }


def _ground_truth_assertions(cases: list[dict[str, Any]], invalid: list[dict[str, Any]]) -> dict[str, Any]:
    reviewers = sorted(
        {
            value
            for case in cases
            for value in (case.get("reviewer_1", ""), case.get("reviewer_2", ""), case.get("adjudicator", ""))
            if value
        }
    )
    return {
        "schema": "k_guard_ground_truth_assertions.v1",
        "case_count": len(cases),
        "invalid_case_count": len(invalid),
        "dual_reviewed_case_count": sum(1 for case in cases if case.get("reviewer_1") and case.get("reviewer_2") and case["reviewer_1"] != case["reviewer_2"]),
        "cryptographically_verified_case_count": sum(
            1
            for case in cases
            if case.get("reviewer_1_signature") and case.get("reviewer_2_signature")
            and (not case.get("adjudicator") or case.get("adjudicator_signature"))
        ),
        "signature_algorithm": "hmac-sha256",
        "independent_role_keys_required": True,
        "source_ref_count": sum(1 for case in cases if case.get("source_ref")),
        "reviewer_count": len(reviewers),
        "reviewer_refs": [_ref(value) for value in reviewers],
        "assertion_refs": [
            _ref(
                "|".join(
                    (
                        _case_key(case),
                        case["expected_outcome"],
                        case["final_verdict"],
                        evidence_hash(case["source_ref"]),
                    )
                )
            )
            for case in cases
        ],
        "raw_returned": False,
    }


def _path_ref(path: str | Path) -> dict[str, Any]:
    return {"hash": evidence_hash(str(path)), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _content_ref(path: str | Path) -> dict[str, Any]:
    try:
        content = Path(path).read_text(encoding="utf-8")
    except Exception:
        content = ""
    return {"hash": evidence_hash(content), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _bundle_ref(bundle: object) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        return {"bundle_sha256": "", "hash_scheme": evidence_hash_scheme(), "raw_returned": False}
    signature = bundle.get("signature", {}) if isinstance(bundle.get("signature"), dict) else {}
    return {
        "bundle_sha256": str(bundle.get("bundle_sha256") or ""),
        "signature_sha256_hash": f"h_{evidence_hash(str(signature.get('signature_sha256') or ''))}",
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _ref(value: object) -> dict[str, Any]:
    return {"hash": evidence_hash(str(value)), "hash_scheme": evidence_hash_scheme(), "raw_returned": False}


def _case_key(case: dict[str, Any]) -> str:
    return "|".join((str(case.get("app_id") or ""), str(case.get("target_id") or ""), str(case.get("case_id") or "")))


def _normalize_path(value: object) -> str:
    return str(value or "").replace("\\", "/").strip().lstrip("./").lower()


def _severity_rank(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(value, 5)


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> dict[str, Any]:
    if total <= 0:
        return {"lower": 0.0, "upper": 0.0, "successes": 0, "total": 0, "method": "wilson_95"}
    proportion = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (proportion + z2 / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt((proportion * (1.0 - proportion) + z2 / (4.0 * total)) / total)
        / denominator
    )
    return {
        "lower": round(max(0.0, center - margin), 6),
        "upper": round(min(1.0, center + margin), 6),
        "successes": successes,
        "total": total,
        "method": "wilson_95",
    }
