from __future__ import annotations

import json
import math
import re
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from k_guard_mcp.hashing import EVIDENCE_HMAC_ENV, evidence_hash, evidence_hash_scheme, uses_public_evidence_key
from k_guard_mcp.field_validation import (
    field_validation_guardian_binding,
    field_validation_metric_contract,
    field_validation_projection,
    field_validation_repeat_binding,
    guardian_candidate_multiset_contract,
    guardian_repeat_input_contract,
    run_field_validation,
)
from k_guard_mcp.experience import release_authority_claim, release_target_evidence_refs
from k_guard_mcp.guardian import guardian_current_source_snapshots, guardian_execution_attestation_valid, guardian_report_identity, guardian_toolchain_contract
from k_guard_mcp.provenance import canonical_json, evidence_bundle, object_artifact, path_artifact, verify_evidence_bundle
from k_guard_mcp.redaction import sanitize_any
from k_guard_mcp.scoreboard import MIN_GOVERNANCE_NEGATIVE_CASES, MIN_GOVERNANCE_POSITIVE_CASES, evaluate_fixture_corpus
from k_guard_mcp.suppression import _guardian_row_suppression_binding
from k_guard_mcp.validation import finding_fingerprint, validation_evidence_projection


MCP_INTERCEPT_REPORT_SCHEMA = "k_guard_mcp_intercept_report.v2"
MCP_INTERCEPT_REPORT_PRODUCER = "k_guard_mcp.cli.mcp_intercept"


def build_mcp_interceptor_release_binding(
    app_id: str,
    session_id: str,
    guardian_report_path: str | Path | None,
) -> dict[str, Any]:
    guardian_path = str(guardian_report_path or "").strip()
    guardian: dict[str, Any] = {}
    if guardian_path:
        try:
            loaded = json.loads(Path(guardian_path).read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                guardian = loaded
        except Exception:
            guardian = {}
    review = guardian.get("review_contract", {}) if isinstance(guardian.get("review_contract"), dict) else {}
    guardian_app_id = str(review.get("app_id") or "").strip()
    guardian_bundle = guardian.get("evidence_bundle") if isinstance(guardian, dict) else None
    authority_claim = release_authority_claim(guardian) if guardian else {}
    return {
        "schema": "k_guard_mcp_interceptor_release_binding.v1",
        "app_id_ref": _bound_value_ref(app_id),
        "session_id_ref": _bound_value_ref(session_id),
        "guardian_report": {
            "configured": bool(guardian_path),
            "parseable": bool(guardian),
            "method_verified": guardian.get("method") == "guardian_audit",
            "path_ref": _path_ref(guardian_path) if guardian_path else _empty_ref(),
            "content_ref": _content_ref(guardian_path) if guardian_path else _empty_ref(),
            "evidence_bundle_ref": _bundle_ref(guardian_bundle),
            "app_id_ref": _bound_value_ref(guardian_app_id),
            "release_authority_claim_ref": _bound_value_ref(canonical_json(authority_claim) if authority_claim else ""),
            "raw_returned": False,
        },
        "raw_returned": False,
    }


def mcp_interceptor_evidence_projection(report: dict[str, Any]) -> dict[str, Any]:
    metadata = report.get("metadata", {}) if isinstance(report.get("metadata"), dict) else {}
    policy = metadata.get("runtime_policy", {}) if isinstance(metadata.get("runtime_policy"), dict) else {}
    interceptor = policy.get("interceptor", {}) if isinstance(policy.get("interceptor"), dict) else {}
    return {
        "schema": report.get("schema"),
        "producer": report.get("producer"),
        "raw_free": report.get("raw_free") is True,
        "runtime_policy": {
            "parse_error_count": _safe_int(policy.get("parse_error_count", 0)),
            "interceptor": {
                "mode": interceptor.get("mode"),
                "event_count": _safe_int(interceptor.get("event_count", 0)),
                "output_event_count": _safe_int(interceptor.get("output_event_count", 0)),
                "blocked_count": _safe_int(interceptor.get("blocked_count", 0)),
                "redacted_count": _safe_int(interceptor.get("redacted_count", 0)),
                "report_raw_free": interceptor.get("report_raw_free") is True,
                "forwarded_output_ref": interceptor.get("forwarded_output_ref", {}),
            },
        },
        "release_binding": report.get("release_binding", {}),
        "raw_returned": False,
    }


def mcp_interceptor_evidence_artifacts(
    report: dict[str, Any],
    forwarded_output_path: str | Path | None,
    guardian_report_path: str | Path | None,
) -> list[dict[str, Any]]:
    return [
        object_artifact("interceptor_projection", mcp_interceptor_evidence_projection(report), role="gate"),
        object_artifact("release_binding", report.get("release_binding", {}), role="assertion"),
        path_artifact("forwarded_output", forwarded_output_path or "", role="output"),
        path_artifact("guardian_report", guardian_report_path or "", role="input"),
    ]


def run_data_release_gate(
    guardian_report_path: str | Path,
    validation_report_path: str | Path,
    korean_corpus_report_path: str | Path,
    mcp_intercept_report_path: str | Path,
    mcp_forwarded_output_path: str | Path | None = None,
    validation_source_guardian_report_path: str | Path | None = None,
    korean_fixture_corpus_path: str | Path | None = None,
    validation_repeat_guardian_report_path: str | Path | None = None,
    guardian_manifest_path: str | Path | None = None,
    validation_review_path: str | Path | None = None,
    validation_ground_truth_path: str | Path | None = None,
    validation_preregistration_path: str | Path | None = None,
    validation_roster_path: str | Path | None = None,
    *,
    min_app_count: int = 12,
    max_app_count: int = 20,
    min_candidate_count: int = 20,
    max_validation_false_positive_rate: float = 0.2,
    min_korean_recall: float = 0.98,
    max_korean_false_positive_rate: float = 0.05,
    min_korean_positive_cases: int = 35,
    min_korean_negative_cases: int = 18,
    min_korean_governance_positive_cases: int = MIN_GOVERNANCE_POSITIVE_CASES,
    min_korean_governance_negative_cases: int = MIN_GOVERNANCE_NEGATIVE_CASES,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    validation_limit = _canonical_false_positive_limit(max_validation_false_positive_rate)
    korean_limit = _canonical_false_positive_limit(max_korean_false_positive_rate)
    checks.append(
        _check(
            "max_validation_false_positive_rate_canonical",
            validation_limit is not None,
            "blocker",
            "finite_number_between_0_and_0_20_required",
            value=validation_limit,
        )
    )
    checks.append(
        _check(
            "max_korean_false_positive_rate_canonical",
            korean_limit is not None,
            "blocker",
            "finite_number_between_0_and_0_20_required",
            value=korean_limit,
        )
    )
    effective_validation_limit = validation_limit if validation_limit is not None else 0.0
    effective_korean_limit = korean_limit if korean_limit is not None else 0.0
    guardian = _load_json_input("guardian_report", guardian_report_path, checks)
    validation = _load_json_input("validation_report", validation_report_path, checks)
    validation_source_guardian = _load_json_input("validation_source_guardian_report", validation_source_guardian_report_path or "", checks)
    validation_repeat_guardian = _load_json_input("validation_repeat_guardian_report", validation_repeat_guardian_report_path or "", checks)
    korean = _load_json_input("korean_corpus_report", korean_corpus_report_path, checks)
    mcp = _load_json_input("mcp_intercept_report", mcp_intercept_report_path, checks)
    checks.append(_check("evidence_hmac_operator_key_configured", not uses_public_evidence_key(), "blocker", f"{EVIDENCE_HMAC_ENV}_required_for_release_provenance"))

    if guardian is not None:
        _guardian_checks(guardian, checks, guardian_manifest_path)
    if validation is not None:
        _validation_checks(validation, checks, min_app_count, max_app_count, min_candidate_count, effective_validation_limit)
        _validation_review_source_checks(validation, validation_review_path, checks)
    if korean is not None:
        _korean_corpus_checks(korean, checks, min_korean_recall, effective_korean_limit, min_korean_positive_cases, min_korean_negative_cases, min_korean_governance_positive_cases, min_korean_governance_negative_cases)
        _korean_corpus_recompute_checks(korean, korean_fixture_corpus_path, checks, min_korean_recall, effective_korean_limit, min_korean_positive_cases, min_korean_negative_cases, min_korean_governance_positive_cases, min_korean_governance_negative_cases)
    if mcp is not None:
        _mcp_interceptor_checks(mcp, checks, mcp_forwarded_output_path, guardian, guardian_report_path)
    if validation is not None and validation_source_guardian is not None:
        _validation_source_guardian_checks(validation_source_guardian, validation, validation_source_guardian_report_path or "", checks)
    if validation is not None and validation_source_guardian is not None and validation_repeat_guardian is not None:
        _validation_repeat_guardian_checks(
            validation_source_guardian,
            validation_repeat_guardian,
            validation,
            validation_repeat_guardian_report_path or "",
            checks,
        )
        _field_validation_recompute_checks(
            validation,
            validation_source_guardian_report_path or "",
            validation_repeat_guardian_report_path or "",
            validation_ground_truth_path,
            validation_review_path,
            validation_preregistration_path,
            validation_roster_path,
            checks,
        )

    blocking = [check for check in checks if not check["passed"] and check["severity"] == "blocker"]
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "method": "data_release_gate",
        "raw_free": True,
        "passed": not blocking,
        "data_release_gate": {
            "passed": not blocking,
            "blocking_check_count": len(blocking),
            "check_count": len(checks),
            "policy": "fail_closed_on_any_blocker",
        },
        "thresholds": {
            "min_design_partner_app_count": min_app_count,
            "max_design_partner_app_count": max_app_count,
            "min_reviewed_high_critical_candidates": min_candidate_count,
            "max_validation_false_positive_rate": validation_limit,
            "max_validation_false_negative_count": 0,
            "max_validation_benign_high_critical_candidate_count": 0,
            "min_korean_corpus_recall": min_korean_recall,
            "max_korean_corpus_false_positive_rate": korean_limit,
            "min_korean_positive_cases": min_korean_positive_cases,
            "min_korean_negative_cases": min_korean_negative_cases,
            "min_korean_governance_positive_cases": min_korean_governance_positive_cases,
            "min_korean_governance_negative_cases": min_korean_governance_negative_cases,
        },
        "inputs": {
            "guardian_report": _path_ref(guardian_report_path),
            "guardian_manifest": _path_ref(guardian_manifest_path or ""),
            "validation_report": _path_ref(validation_report_path),
            "validation_review_csv": _path_ref(validation_review_path or ""),
            "validation_ground_truth_csv": _path_ref(validation_ground_truth_path or ""),
            "validation_preregistration": _path_ref(validation_preregistration_path or ""),
            "validation_roster": _path_ref(validation_roster_path or ""),
            "korean_corpus_report": _path_ref(korean_corpus_report_path),
            "mcp_intercept_report": _path_ref(mcp_intercept_report_path),
            "mcp_forwarded_output": _path_ref(mcp_forwarded_output_path or ""),
            "validation_source_guardian_report": _path_ref(validation_source_guardian_report_path or ""),
            "validation_repeat_guardian_report": _path_ref(validation_repeat_guardian_report_path or ""),
            "korean_fixture_corpus": _path_ref(korean_fixture_corpus_path or ""),
        },
        "checks": checks,
        "commercial_mcp_contract": {
            "requires_guardian_release_gate": True,
            "requires_runtime_interceptor_forwarded_stream": True,
            "requires_interceptor_schema_and_producer": True,
            "requires_interceptor_app_session_guardian_binding": True,
            "requires_operator_keyed_interceptor_evidence": True,
            "requires_no_mcp_parse_errors": True,
            "requires_no_blocked_runtime_events": True,
            "requires_raw_free_evidence": True,
            "requires_fail_closed_control_failures": True,
            "report_only_mcp_observation_is_not_enough": True,
            "design_partner_validation_source_is_independent_from_release_app": True,
        },
        "korean_privacy_contract": {
            "requires_korean_fixture_corpus": True,
            "requires_direct_unique_identifier_coverage": True,
            "requires_combined_identifier_coverage": True,
            "requires_false_positive_controls": True,
            "requires_manual_tp_fp_fn_labels_on_owned_or_partner_apps": True,
        },
        "boundary": {
            "not_a_certificate": True,
            "requires_human_owner_for_manual_labels": True,
            "owned_partner_scope_assertion_boundary": "external assertion ref required; gate verifies raw-free refs and coverage, not legal ownership by itself",
            "business_intent_assertion_boundary": "manifest assertion required; K-Guard does not claim full human business-intent understanding",
        },
        "hash_scheme": evidence_hash_scheme(),
    }
    report["evidence_bundle"] = evidence_bundle(
        "data_release_gate",
        "k_guard_mcp.data_release",
        [
            path_artifact("guardian_report", guardian_report_path, role="input"),
            path_artifact("guardian_manifest", guardian_manifest_path or "", role="input"),
            path_artifact("validation_source_guardian_report", validation_source_guardian_report_path or "", role="input"),
            path_artifact("validation_repeat_guardian_report", validation_repeat_guardian_report_path or "", role="repeat_input"),
            path_artifact("validation_report", validation_report_path, role="input"),
            path_artifact("validation_review_csv", validation_review_path or "", role="manual_input"),
            path_artifact("validation_ground_truth_csv", validation_ground_truth_path or "", role="ground_truth"),
            path_artifact("validation_preregistration", validation_preregistration_path or "", role="preregistration"),
            path_artifact("validation_roster", validation_roster_path or "", role="field_roster"),
            path_artifact("korean_corpus_report", korean_corpus_report_path, role="input"),
            path_artifact("korean_fixture_corpus", korean_fixture_corpus_path or "", role="ground_truth"),
            path_artifact("mcp_intercept_report", mcp_intercept_report_path, role="input"),
            path_artifact("mcp_forwarded_output", mcp_forwarded_output_path or "", role="input"),
            object_artifact("checks", _check_projection(checks), role="gate"),
            object_artifact("thresholds", report["thresholds"], role="policy"),
            object_artifact("release_verdict", report["data_release_gate"], role="gate"),
        ],
    )
    return sanitize_any(report)


def _load_json_input(name: str, path: str | Path, checks: list[dict[str, Any]]) -> dict[str, Any] | None:
    text = str(path or "").strip()
    if not text:
        checks.append(_check(f"{name}_present", False, "blocker", "input_path_missing"))
        return None
    input_path = Path(text)
    if not input_path.exists() or not input_path.is_file():
        checks.append(_check(f"{name}_present", False, "blocker", "input_file_missing", path_ref=_path_ref(input_path)))
        return None
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except Exception:
        checks.append(_check(f"{name}_parseable_json", False, "blocker", "json_parse_failed", path_ref=_path_ref(input_path)))
        return None
    if not isinstance(data, dict):
        checks.append(_check(f"{name}_json_object", False, "blocker", "top_level_json_not_object", path_ref=_path_ref(input_path)))
        return None
    checks.append(_check(f"{name}_present", True, "info", "loaded", path_ref=_path_ref(input_path)))
    return data


def _guardian_checks(report: dict[str, Any], checks: list[dict[str, Any]], manifest_path: str | Path | None) -> None:
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    drift = report.get("drift", {}) if isinstance(report.get("drift"), dict) else {}
    gate = report.get("guardian_gate", {}) if isinstance(report.get("guardian_gate"), dict) else {}
    contract = report.get("execution_contract", {}) if isinstance(report.get("execution_contract"), dict) else {}
    intent = report.get("intent_contract", {}) if isinstance(report.get("intent_contract"), dict) else {}
    review = report.get("review_contract", {}) if isinstance(report.get("review_contract"), dict) else {}
    qualification = report.get("release_qualification", {}) if isinstance(report.get("release_qualification"), dict) else {}
    checks.append(_check("guardian_report_method", report.get("method") == "guardian_audit", "blocker", "guardian_audit_method_required"))
    checks.append(_check("guardian_signed_execution_identity", _valid_generated_timestamp(report.get("generated_at")) and re.fullmatch(r"[0-9a-f]{32}", str(report.get("execution_id") or "")) is not None, "blocker", "signed_generated_at_and_unique_execution_id_required"))
    checks.append(_check("guardian_execution_attestation", guardian_execution_attestation_valid(report), "blocker", "signed_runtime_execution_attestation_required"))
    checks.append(_check("guardian_current_toolchain_contract", report.get("toolchain_contract") == guardian_toolchain_contract(), "blocker", "current_complete_guardian_toolchain_contract_required"))
    checks.append(_check("guardian_raw_free", report.get("raw_free") is True, "blocker", "guardian_report_raw_free_required"))
    checks.append(_check("guardian_release_gate_present", bool(gate), "blocker", "guardian_must_run_with_fail_on"))
    checks.append(_check("guardian_release_gate_passed", bool(gate.get("passed")), "blocker", "guardian_gate_must_pass"))
    checks.append(_check("guardian_release_threshold_high", gate.get("fail_on") == "high", "blocker", "guardian_gate_fail_on_must_equal_high"))
    checks.append(_check("guardian_gate_canonical_release_authority", gate.get("canonical_release_authority") is True and gate.get("authority_blockers") == [], "blocker", "guardian_gate_must_hold_bound_canonical_authority"))
    checks.append(_check("guardian_release_qualification", _release_qualification_complete(qualification), "blocker", "deep_multilang_runtime_and_field_qualification_required"))
    checks.append(_check("guardian_gate_qualification_binding", gate.get("release_qualification_passed") is True and gate.get("failed_qualification_gates") == [], "blocker", "guardian_gate_must_bind_release_qualification"))
    checks.append(_check("guardian_release_authority_claim_matches", report.get("release_authority_claim") == release_authority_claim(report), "blocker", "release_authority_claim_must_match_current_report"))
    checks.append(_check("guardian_release_mode", contract.get("mode") == "release_gate", "blocker", "guardian_execution_contract_must_be_release_gate"))
    checks.append(_check("guardian_evidence_bundle_present", _valid_evidence_bundle(report.get("evidence_bundle"), require_operator_key=True), "blocker", "guardian_operator_keyed_evidence_bundle_required"))
    checks.append(_check("guardian_evidence_bundle_matches_report", _guardian_evidence_bundle_matches_report(report, manifest_path), "blocker", "guardian_evidence_bundle_artifacts_and_manifest_must_match_report"))
    checks.append(_check("guardian_source_snapshots_match_current_manifest", _guardian_source_snapshots_match(report, manifest_path), "blocker", "signed_workspace_snapshots_must_match_current_manifest_sources"))
    checks.append(_check("guardian_business_intent_contract_present", bool(intent), "blocker", "guardian_intent_contract_required"))
    checks.append(_check("guardian_business_purpose_asserted", intent.get("business_purpose_complete") is True, "blocker", "business_purpose_complete", value=intent.get("business_purpose_present_count", 0)))
    checks.append(_check("guardian_business_purpose_explicit", intent.get("business_purpose_explicit_complete") is True, "blocker", "business_purpose_must_be_explicit", value=intent.get("business_purpose_explicit_count", 0)))
    checks.append(_check("guardian_data_classes_asserted", intent.get("data_class_complete") is True, "blocker", "data_class_complete", value=intent.get("data_class_present_count", 0)))
    checks.append(_check("guardian_user_scope_asserted", intent.get("user_scope_complete") is True, "blocker", "user_scope_complete", value=intent.get("user_scope_present_count", 0)))
    checks.append(_check("guardian_scope_assertion_refs_present", intent.get("scope_assertion_complete") is True, "blocker", "scope_assertion_complete", value=intent.get("scope_assertion_present_count", 0)))
    checks.append(_check("guardian_target_business_contexts_present", _target_business_contexts_complete(report), "blocker", "target_business_contexts_required"))
    checks.append(_check("guardian_target_scope_assertions_present", _target_scope_assertions_complete(report), "blocker", "target_scope_assertions_required"))
    checks.append(_check("guardian_no_human_intent_overclaim", intent.get("human_business_intent_understanding_claimed") is False, "blocker", "human_intent_understanding_claim_must_be_false"))
    checks.append(_check("guardian_review_contract_present", bool(review), "blocker", "guardian_review_contract_required"))
    checks.append(_check("guardian_review_profile_korean_senior", review.get("profile") == "korean_senior", "blocker", "korean_senior_review_profile_required"))
    checks.append(_check("guardian_review_strict_domain_enforcement", review.get("strict_domain_enforcement") is True, "blocker", "korean_senior_strict_domain_enforcement_required"))
    checks.append(_check("guardian_review_release_gate_enabled", review.get("release_gate_enabled") is True, "blocker", "review_contract_must_be_generated_in_release_gate_mode"))
    checks.append(_check("guardian_canonical_release_authority", review.get("canonical_release_authority") is True and review.get("release_authority") == "canonical" and review.get("report_only") is False, "blocker", "canonical_korean_senior_release_authority_required"))
    checks.append(_check("guardian_single_app_release_scope", _guardian_single_app_scope(report), "blocker", "all_release_targets_must_share_one_nonempty_app_id"))
    checks.append(_check("guardian_review_contract_passed", review.get("passed") is True, "blocker", "four_domain_review_contract_must_pass"))
    checks.append(_check("guardian_review_domains_complete", _review_domains_complete(review), "blocker", "site_api_data_operational_domains_must_pass"))
    checks.append(_check("guardian_target_review_profiles_complete", _target_review_profiles_complete(report), "blocker", "all_guardian_targets_must_use_korean_senior_profile"))
    checks.append(_check("guardian_target_thresholds_high", _target_thresholds_high(report), "blocker", "all_guardian_targets_must_use_high_threshold"))
    checks.append(_check("guardian_no_recomputed_high_critical_findings", _guardian_has_no_high_critical_findings(report), "blocker", "target_findings_recomputed_at_high_threshold"))
    checks.append(
        _check(
            "guardian_review_contract_matches_target_evidence",
            _guardian_review_contract_matches_target_evidence(report),
            "blocker",
            "four_domain_claims_must_be_recomputed_from_target_evidence",
        )
    )
    checks.append(_check("guardian_review_no_human_or_legal_overclaim", review.get("human_business_intent_or_legal_compliance_claimed") is False, "blocker", "human_or_legal_overclaim_must_be_false"))
    checks.append(_check("guardian_no_blocking_targets", int(summary.get("blocking_target_count", 0)) == 0, "blocker", "blocking_target_count", value=summary.get("blocking_target_count", 0)))
    checks.append(_check("guardian_no_coverage_gaps", int(summary.get("coverage_gap_target_count", 0)) == 0, "blocker", "coverage_gap_target_count", value=summary.get("coverage_gap_target_count", 0)))
    checks.append(_check("guardian_no_new_blocking_drift", int(drift.get("new_blocking_finding_count", 0)) == 0, "blocker", "new_blocking_finding_count", value=drift.get("new_blocking_finding_count", 0)))
    _guardian_suppression_checks(report, checks)


def _validation_checks(
    report: dict[str, Any],
    checks: list[dict[str, Any]],
    min_app_count: int,
    max_app_count: int,
    min_candidate_count: int,
    max_false_positive_rate: float,
) -> None:
    sample = report.get("sample", {}) if isinstance(report.get("sample"), dict) else {}
    verdict_counts = report.get("verdict_counts", {}) if isinstance(report.get("verdict_counts"), dict) else {}
    case_counts = report.get("case_counts", {}) if isinstance(report.get("case_counts"), dict) else {}
    rates = report.get("rates", {}) if isinstance(report.get("rates"), dict) else {}
    rate_intervals = report.get("rates_confidence_intervals", {}) if isinstance(report.get("rates_confidence_intervals"), dict) else {}
    holdout = report.get("holdout", {}) if isinstance(report.get("holdout"), dict) else {}
    holdout_candidates = report.get("holdout_candidate_rates", {}) if isinstance(report.get("holdout_candidate_rates"), dict) else {}
    reproducibility = report.get("reproducibility", {}) if isinstance(report.get("reproducibility"), dict) else {}
    preregistration = report.get("field_preregistration", {}) if isinstance(report.get("field_preregistration"), dict) else {}
    thresholds = report.get("thresholds", {}) if isinstance(report.get("thresholds"), dict) else {}
    gate_checks = report.get("gate_checks", []) if isinstance(report.get("gate_checks"), list) else []
    app_count = _safe_int(sample.get("app_count", 0))
    review_app_id_count = _safe_int(sample.get("review_app_id_count", 0))
    candidate_app_count = _safe_int(sample.get("candidate_app_count", 0))
    candidate_target_count = _safe_int(sample.get("candidate_target_count", 0))
    candidate_count = _safe_int(sample.get("candidate_count", 0))
    reviewed_count = _safe_int(sample.get("reviewed_candidate_count", 0))
    invalid_review_count = _safe_int(sample.get("invalid_review_count", 0))
    invalid_ground_truth_count = _safe_int(sample.get("invalid_ground_truth_count", 0))
    case_count = _safe_int(sample.get("case_count", 0))
    holdout_case_count = _safe_int(sample.get("holdout_case_count", 0))
    holdout_positive_count = _safe_int(holdout.get("positive_case_count", 0))
    holdout_negative_count = _safe_int(holdout.get("negative_case_count", 0))
    holdout_critical_count = _safe_int(holdout.get("critical_case_count", 0))
    holdout_stratum_count = _safe_int(holdout.get("stratum_count", 0))
    holdout_app_count = _safe_int(holdout.get("app_count", 0))
    false_negative_count = _safe_int(case_counts.get("false_negative", 0))
    inconclusive_count = _safe_int(verdict_counts.get("inconclusive", 0))
    benign_count = _safe_int(verdict_counts.get("benign", 0))
    false_positive_rate = _finite_rate(rates.get("false_positive_rate"))
    precision = _finite_rate(rates.get("precision"))
    holdout_candidate_precision = _finite_rate(holdout_candidates.get("precision"))
    recall = _finite_rate(rates.get("recall"))
    specificity = _finite_rate(rates.get("specificity"))
    critical_recall = _finite_rate(holdout.get("critical_recall"))
    high_critical_recall = _finite_rate(holdout.get("high_critical_recall"))
    holdout_candidate_count = _safe_int(holdout_candidates.get("candidate_count", 0))
    precision_lower = _finite_rate((rate_intervals.get("precision_95") or {}).get("lower")) if isinstance(rate_intervals.get("precision_95"), dict) else None
    holdout_candidate_precision_lower = _finite_rate((holdout_candidates.get("precision_confidence_interval_95") or {}).get("lower")) if isinstance(holdout_candidates.get("precision_confidence_interval_95"), dict) else None
    holdout_high_critical_recall_lower = _finite_rate((holdout.get("high_critical_recall_confidence_interval_95") or {}).get("lower")) if isinstance(holdout.get("high_critical_recall_confidence_interval_95"), dict) else None
    holdout_specificity_lower = _finite_rate((holdout.get("specificity_confidence_interval_95") or {}).get("lower")) if isinstance(holdout.get("specificity_confidence_interval_95"), dict) else None
    unassigned_candidate_count = _safe_int(holdout_candidates.get("unassigned_candidate_count", 0))
    ambiguous_candidate_count = _safe_int(holdout_candidates.get("ambiguous_split_candidate_count", 0))
    app_refs = report.get("candidate_app_refs", [])
    evaluation_app_refs = report.get("evaluation_app_refs", [])
    target_refs = report.get("candidate_target_refs", [])
    finding_refs = report.get("candidate_finding_refs", [])
    checks.append(_check("validation_schema", report.get("schema") == "k_guard_field_validation.v1", "blocker", "ground_truth_field_validation_v1_required"))
    checks.append(_check("validation_method", report.get("method") == "ground_truth_field_validation", "blocker", "ground_truth_field_validation_method_required"))
    checks.append(_check("validation_profile", report.get("profile") == "field", "blocker", "field_profile_required"))
    checks.append(_check("validation_evidence_tier", report.get("evidence_tier") == "field", "blocker", "owned_partner_field_evidence_required"))
    checks.append(_check("validation_raw_free", report.get("raw_free") is True, "blocker", "validation_report_raw_free_required"))
    checks.append(_check("validation_metric_contract", report.get("metric_contract") == field_validation_metric_contract(), "blocker", "field_validation_metrics_v2_exact_denominators_required"))
    checks.append(_check("validation_generated_timestamp", _valid_generated_timestamp(report.get("generated_at")), "blocker", "timezone_aware_generated_at_required"))
    checks.append(_check("validation_review_source_sha256", _valid_validation_review_source(report), "blocker", "exact_review_csv_sha256_required"))
    checks.append(_check("validation_ground_truth_source_sha256", _valid_ground_truth_source(report), "blocker", "exact_ground_truth_csv_sha256_required"))
    checks.append(_check("validation_field_roster_source_sha256", _valid_field_roster_source(report), "blocker", "exact_preregistered_field_roster_sha256_required"))
    checks.append(_check("validation_reviewer_assertions", _valid_reviewer_assertions(report), "blocker", "dual_named_reviewer_assertions_required"))
    checks.append(_check("validation_ground_truth_assertions", _valid_ground_truth_assertions(report), "blocker", "dual_reviewed_ground_truth_assertions_required"))
    checks.append(_check("validation_operator_signed_evidence_envelope", _validation_evidence_envelope_matches(report), "blocker", "operator_signed_exact_review_evidence_required"))
    checks.append(_check("validation_independent_custodian_assertion", preregistration.get("custodian_assertion_valid") is True, "blocker", "distinct_key_custodian_preregistration_required"))
    checks.append(_check("validation_claim_ready", report.get("claim_status") == "field_validation_ready", "blocker", str(report.get("claim_status") or "missing_claim_status")))
    checks.append(_check("validation_internal_gate_checks_passed", bool(gate_checks) and all(isinstance(item, dict) and item.get("passed") is True for item in gate_checks), "blocker", "all_signed_field_validation_checks_must_pass"))
    checks.append(_check("validation_min_design_partner_apps", app_count >= min_app_count, "blocker", "min_app_count", value=app_count))
    checks.append(_check("validation_max_design_partner_apps", app_count <= max_app_count, "blocker", "max_app_count", value=app_count))
    checks.append(_check("validation_evaluation_app_refs_bound", _target_refs_match_count(evaluation_app_refs, app_count), "blocker", "evaluation_app_refs", value=_target_ref_count(evaluation_app_refs)))
    checks.append(_check("validation_candidate_apps_present", 0 < candidate_app_count <= app_count, "blocker", "candidate_app_count", value=candidate_app_count))
    checks.append(_check("validation_review_rows_cover_candidate_apps", review_app_id_count == candidate_app_count, "blocker", "review_app_id_count", value=review_app_id_count))
    checks.append(_check("validation_candidate_app_refs_bound", _target_refs_match_count(app_refs, candidate_app_count), "blocker", "candidate_app_refs", value=_target_ref_count(app_refs)))
    checks.append(_check("validation_candidate_target_refs_bound", _target_refs_match_count(target_refs, candidate_target_count), "blocker", "candidate_target_refs", value=_target_ref_count(target_refs)))
    checks.append(_check("validation_candidate_finding_refs_bound", _target_refs_match_count(finding_refs, candidate_count), "blocker", "candidate_finding_refs", value=_target_ref_count(finding_refs)))
    checks.append(_check("validation_min_high_critical_candidates", candidate_count >= min_candidate_count, "blocker", "min_candidate_count", value=candidate_count))
    checks.append(_check("validation_all_candidates_reviewed", reviewed_count == candidate_count and candidate_count > 0, "blocker", "reviewed_candidate_count", value=reviewed_count))
    checks.append(_check("validation_no_invalid_review_rows", invalid_review_count == 0, "blocker", "invalid_review_count", value=invalid_review_count))
    checks.append(_check("validation_no_invalid_ground_truth_rows", invalid_ground_truth_count == 0, "blocker", "invalid_ground_truth_count", value=invalid_ground_truth_count))
    checks.append(_check("validation_min_ground_truth_cases", case_count >= 120, "blocker", "minimum_120_ground_truth_cases", value=case_count))
    checks.append(_check("validation_min_holdout_cases", holdout_case_count >= 70, "blocker", "minimum_70_holdout_cases", value=holdout_case_count))
    checks.append(_check("validation_min_holdout_positive_cases", holdout_positive_count >= 35, "blocker", "minimum_35_holdout_positive_cases", value=holdout_positive_count))
    checks.append(_check("validation_min_holdout_negative_cases", holdout_negative_count >= 35, "blocker", "minimum_35_holdout_negative_cases", value=holdout_negative_count))
    checks.append(_check("validation_min_holdout_critical_cases", holdout_critical_count >= 5, "blocker", "minimum_5_holdout_critical_cases", value=holdout_critical_count))
    checks.append(_check("validation_min_holdout_strata", holdout_stratum_count >= 3, "blocker", "all_three_holdout_strata_required", value=holdout_stratum_count))
    checks.append(_check("validation_min_holdout_apps", holdout_app_count >= 6, "blocker", "minimum_6_holdout_apps", value=holdout_app_count))
    checks.append(_check("validation_no_false_negatives", false_negative_count == 0, "blocker", "false_negative_count", value=false_negative_count))
    checks.append(_check("validation_no_benign_high_critical_candidates", benign_count == 0, "blocker", "benign_count", value=benign_count))
    checks.append(_check("validation_no_inconclusive_candidates", inconclusive_count == 0, "blocker", "inconclusive_count", value=inconclusive_count))
    checks.append(_check("validation_false_positive_rate_finite", false_positive_rate is not None and 0.0 <= false_positive_rate <= 1.0, "blocker", "finite_rate_between_0_and_1_required", value=false_positive_rate))
    checks.append(_check("validation_false_positive_rate_budget", false_positive_rate is not None and false_positive_rate <= max_false_positive_rate, "blocker", "false_positive_rate", value=false_positive_rate))
    checks.append(_check("validation_precision_floor", precision is not None and precision >= 0.90, "blocker", "precision_at_least_0_90", value=precision))
    checks.append(_check("validation_precision_confidence_lower", precision_lower is not None and precision_lower >= 0.80, "blocker", "precision_wilson_95_lower_at_least_0_80", value=precision_lower))
    checks.append(_check("validation_holdout_candidates_present", holdout_candidate_count >= 35, "blocker", "at_least_35_holdout_candidates", value=holdout_candidate_count))
    checks.append(_check("validation_holdout_candidate_precision_floor", holdout_candidate_precision is not None and holdout_candidate_precision >= 0.90, "blocker", "holdout_precision_at_least_0_90", value=holdout_candidate_precision))
    checks.append(_check("validation_holdout_candidate_precision_confidence_lower", holdout_candidate_precision_lower is not None and holdout_candidate_precision_lower >= 0.80, "blocker", "holdout_precision_wilson_95_lower_at_least_0_80", value=holdout_candidate_precision_lower))
    checks.append(_check("validation_candidate_split_binding_complete", holdout_candidates.get("binding_complete") is True and unassigned_candidate_count == 0 and ambiguous_candidate_count == 0, "blocker", "all_candidates_bound_to_exactly_one_frozen_split", value={"unassigned": unassigned_candidate_count, "ambiguous": ambiguous_candidate_count}))
    checks.append(_check("validation_recall_finite", recall is not None and 0.0 <= recall <= 1.0, "blocker", "ground_truth_recall_required", value=recall))
    checks.append(_check("validation_specificity_floor", specificity is not None and specificity >= 0.90, "blocker", "specificity_at_least_0_90", value=specificity))
    checks.append(_check("validation_holdout_critical_recall", critical_recall == 1.0, "blocker", "critical_holdout_recall_must_equal_1", value=critical_recall))
    checks.append(_check("validation_holdout_high_critical_recall", high_critical_recall is not None and high_critical_recall >= 0.90, "blocker", "high_critical_holdout_recall_at_least_0_90", value=high_critical_recall))
    checks.append(_check("validation_holdout_high_critical_recall_confidence_lower", holdout_high_critical_recall_lower is not None and holdout_high_critical_recall_lower >= 0.90, "blocker", "high_critical_recall_wilson_95_lower_at_least_0_90", value=holdout_high_critical_recall_lower))
    checks.append(_check("validation_holdout_specificity_confidence_lower", holdout_specificity_lower is not None and holdout_specificity_lower >= 0.90, "blocker", "specificity_wilson_95_lower_at_least_0_90", value=holdout_specificity_lower))
    checks.append(_check("validation_repeat_candidate_set", reproducibility.get("exact_candidate_set_match") is True, "blocker", "two_runs_must_match_exactly"))
    checks.append(_check("validation_repeat_distinct_execution", reproducibility.get("distinct_report_paths") is True and reproducibility.get("distinct_execution_timestamps") is True, "blocker", "distinct_repeat_guardian_execution_required"))
    checks.append(_check("validation_threshold_contract", _field_thresholds_are_strict(thresholds), "blocker", "field_thresholds_cannot_be_lowered"))


def _validation_evidence_envelope_matches(report: dict[str, Any]) -> bool:
    if report.get("schema") == "k_guard_field_validation.v1":
        return _field_validation_evidence_envelope_matches(report)
    envelope = report.get("validation_evidence_envelope")
    if not _valid_evidence_bundle(envelope, require_operator_key=True) or not isinstance(envelope, dict):
        return False
    if envelope.get("subject") != "manual_validation_review" or envelope.get("producer") != "k_guard_mcp.validation":
        return False
    artifacts = envelope.get("artifacts", [])
    if not isinstance(artifacts, list):
        return False
    artifact_keys = {
        (str(item.get("label") or ""), str(item.get("role") or "evidence"))
        for item in artifacts
        if isinstance(item, dict)
    }
    expected_keys = {
        ("validation_review_csv", "manual_input"),
        ("review_source", "manual_input"),
        ("reviewer_assertions", "assertion"),
        ("generated_at", "timestamp"),
        ("guardian_binding", "input"),
        ("validation_projection", "gate"),
    }
    if artifact_keys != expected_keys or len(artifacts) != len(expected_keys):
        return False
    source = report.get("review_source", {}) if isinstance(report.get("review_source"), dict) else {}
    path_ref = source.get("path_ref", {}) if isinstance(source.get("path_ref"), dict) else {}
    csv_artifact = next(
        (item for item in artifacts if isinstance(item, dict) and item.get("label") == "validation_review_csv" and item.get("role") == "manual_input"),
        None,
    )
    if not isinstance(csv_artifact, dict):
        return False
    if (
        csv_artifact.get("exists_at_bundle_time") is not True
        or csv_artifact.get("content_sha256") != source.get("content_sha256")
        or csv_artifact.get("byte_count") != source.get("byte_count")
        or csv_artifact.get("hash") != path_ref.get("hash")
        or csv_artifact.get("hash_scheme") != path_ref.get("hash_scheme")
        or csv_artifact.get("raw_returned") is not False
    ):
        return False
    expected = [
        object_artifact("review_source", source, role="manual_input"),
        object_artifact("reviewer_assertions", report.get("reviewer_assertions", {}), role="assertion"),
        object_artifact("generated_at", {"generated_at": report.get("generated_at")}, role="timestamp"),
        object_artifact("guardian_binding", _validation_guardian_binding(report), role="input"),
        object_artifact("validation_projection", validation_evidence_projection(report), role="gate"),
    ]
    return _bundle_contains_expected_artifacts(envelope, expected)


def _field_validation_evidence_envelope_matches(report: dict[str, Any]) -> bool:
    envelope = report.get("validation_evidence_envelope")
    if not _valid_evidence_bundle(envelope, require_operator_key=True) or not isinstance(envelope, dict):
        return False
    if envelope.get("subject") != "field_validation_review" or envelope.get("producer") != "k_guard_mcp.field_validation":
        return False
    artifacts = envelope.get("artifacts", [])
    if not isinstance(artifacts, list):
        return False
    artifact_keys = {
        (str(item.get("label") or ""), str(item.get("role") or "evidence"))
        for item in artifacts
        if isinstance(item, dict)
    }
    expected_keys = {
        ("validation_review_csv", "manual_input"),
        ("ground_truth_csv", "ground_truth"),
        ("field_app_roster_csv", "field_roster"),
        ("repeat_guardian_report", "repeat_input"),
        ("review_source", "manual_input"),
        ("ground_truth_source", "ground_truth"),
        ("field_roster_source", "field_roster"),
        ("repeat_guardian_source", "repeat_input"),
        ("reviewer_assertions", "assertion"),
        ("ground_truth_assertions", "assertion"),
        ("generated_at", "timestamp"),
        ("toolchain_contract", "identity"),
        ("guardian_binding", "input"),
        ("repeat_guardian_binding", "repeat_input"),
        ("field_validation_projection", "gate"),
    }
    if artifact_keys != expected_keys or len(artifacts) != len(expected_keys):
        return False
    source_bindings = (
        ("validation_review_csv", "manual_input", "review_source"),
        ("ground_truth_csv", "ground_truth", "ground_truth_source"),
        ("field_app_roster_csv", "field_roster", "field_roster_source"),
        ("repeat_guardian_report", "repeat_input", "repeat_guardian_source"),
    )
    for label, role, source_key in source_bindings:
        source = report.get(source_key, {}) if isinstance(report.get(source_key), dict) else {}
        path_ref = source.get("path_ref", {}) if isinstance(source.get("path_ref"), dict) else {}
        artifact = next(
            (
                item
                for item in artifacts
                if isinstance(item, dict) and item.get("label") == label and item.get("role") == role
            ),
            None,
        )
        if not isinstance(artifact, dict):
            return False
        if (
            artifact.get("exists_at_bundle_time") is not True
            or artifact.get("content_sha256") != source.get("content_sha256")
            or artifact.get("byte_count") != source.get("byte_count")
            or artifact.get("hash") != path_ref.get("hash")
            or artifact.get("hash_scheme") != path_ref.get("hash_scheme")
            or artifact.get("raw_returned") is not False
        ):
            return False
    expected = [
        object_artifact("review_source", report.get("review_source", {}), role="manual_input"),
        object_artifact("ground_truth_source", report.get("ground_truth_source", {}), role="ground_truth"),
        object_artifact("field_roster_source", report.get("field_roster_source", {}), role="field_roster"),
        object_artifact("repeat_guardian_source", report.get("repeat_guardian_source", {}), role="repeat_input"),
        object_artifact("reviewer_assertions", report.get("reviewer_assertions", {}), role="assertion"),
        object_artifact("ground_truth_assertions", report.get("ground_truth_assertions", {}), role="assertion"),
        object_artifact("generated_at", {"generated_at": report.get("generated_at")}, role="timestamp"),
        object_artifact("toolchain_contract", report.get("toolchain_contract", {}), role="identity"),
        object_artifact("guardian_binding", field_validation_guardian_binding(report), role="input"),
        object_artifact("repeat_guardian_binding", field_validation_repeat_binding(report), role="repeat_input"),
        object_artifact("field_validation_projection", field_validation_projection(report), role="gate"),
    ]
    return _bundle_contains_expected_artifacts(envelope, expected)


def _validation_review_source_checks(
    report: dict[str, Any],
    review_path: str | Path | None,
    checks: list[dict[str, Any]],
) -> None:
    if not str(review_path or "").strip():
        checks.append(_check("validation_review_csv_present", False, "blocker", "validation_review_path_required"))
        checks.append(_check("validation_review_csv_matches_signed_sha256", False, "blocker", "current_review_csv_unavailable"))
        return
    artifact = path_artifact("validation_review_csv", review_path or "", role="manual_input")
    source = report.get("review_source", {}) if isinstance(report.get("review_source"), dict) else {}
    path_ref = source.get("path_ref", {}) if isinstance(source.get("path_ref"), dict) else {}
    present = artifact.get("exists_at_bundle_time") is True
    matches = (
        present
        and artifact.get("content_sha256") == source.get("content_sha256")
        and artifact.get("byte_count") == source.get("byte_count")
        and artifact.get("hash") == path_ref.get("hash")
        and artifact.get("hash_scheme") == path_ref.get("hash_scheme")
    )
    checks.append(_check("validation_review_csv_present", present, "blocker", "current_validation_review_csv_required"))
    checks.append(_check("validation_review_csv_matches_signed_sha256", matches, "blocker", "current_review_csv_must_match_signed_source_sha256"))


def _field_validation_recompute_checks(
    submitted: dict[str, Any],
    primary_guardian_path: str | Path,
    repeat_guardian_path: str | Path,
    ground_truth_path: str | Path | None,
    review_path: str | Path | None,
    preregistration_path: str | Path | None,
    roster_path: str | Path | None,
    checks: list[dict[str, Any]],
) -> None:
    paths = {
        "primary_guardian": primary_guardian_path,
        "repeat_guardian": repeat_guardian_path,
        "ground_truth": ground_truth_path or "",
        "review": review_path or "",
        "preregistration": preregistration_path or "",
        "roster": roster_path or "",
    }
    present = all(Path(str(path)).is_file() for path in paths.values() if str(path).strip()) and all(
        str(path).strip() for path in paths.values()
    )
    checks.append(
        _check(
            "validation_original_role_evidence_present",
            present,
            "blocker",
            "primary_repeat_ground_truth_review_and_preregistration_originals_required",
        )
    )
    if not present:
        checks.append(_check("validation_recomputed_from_originals", False, "blocker", "original_role_evidence_unavailable"))
        checks.append(_check("validation_recomputed_projection_match", False, "blocker", "recomputation_unavailable"))
        return
    try:
        recomputed = run_field_validation(
            primary_guardian_path,
            repeat_guardian_path,
            ground_truth_path or "",
            review_path or "",
            profile="field",
            preregistration_path=preregistration_path,
            roster_path=roster_path,
        )
    except Exception as exc:
        checks.append(
            _check(
                "validation_recomputed_from_originals",
                False,
                "blocker",
                "field_validation_reexecution_failed",
                value={"error_type": type(exc).__name__},
            )
        )
        checks.append(_check("validation_recomputed_projection_match", False, "blocker", "recomputation_failed"))
        return
    ready = recomputed.get("claim_status") == "field_validation_ready"
    projection_matches = field_validation_projection(recomputed) == field_validation_projection(submitted)
    checks.append(
        _check(
            "validation_recomputed_from_originals",
            ready,
            "blocker",
            "role_signatures_ground_truth_and_repeat_must_revalidate",
            value={"claim_status": recomputed.get("claim_status")},
        )
    )
    checks.append(
        _check(
            "validation_recomputed_projection_match",
            projection_matches,
            "blocker",
            "submitted_field_projection_must_equal_recomputed_projection",
        )
    )


def _validation_guardian_binding(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "guardian_report_ref": report.get("guardian_report_ref", {}),
        "guardian_report_content_ref": report.get("guardian_report_content_ref", {}),
        "guardian_report_bundle_ref": report.get("guardian_report_bundle_ref", {}),
        "raw_returned": False,
    }


def _valid_validation_review_source(report: dict[str, Any]) -> bool:
    source = report.get("review_source", {}) if isinstance(report.get("review_source"), dict) else {}
    content_sha256 = str(source.get("content_sha256") or "")
    path_ref = source.get("path_ref", {}) if isinstance(source.get("path_ref"), dict) else {}
    return (
        source.get("schema") in {"k_guard_validation_review_source.v1", "k_guard_field_review_source.v1"}
        and re.fullmatch(r"[0-9a-f]{64}", content_sha256) is not None
        and source.get("sha256_verified_at_generation") is True
        and source.get("exists_at_generation") is True
        and _safe_int(source.get("byte_count", -1), -1) > 0
        and _safe_int(source.get("row_count", 0)) > 0
        and bool(path_ref.get("hash"))
        and path_ref.get("raw_returned") is False
        and source.get("raw_returned") is False
    )


def _valid_reviewer_assertions(report: dict[str, Any]) -> bool:
    if report.get("schema") == "k_guard_field_validation.v1":
        return _valid_field_reviewer_assertions(report)
    assertions = report.get("reviewer_assertions", {}) if isinstance(report.get("reviewer_assertions"), dict) else {}
    source = report.get("review_source", {}) if isinstance(report.get("review_source"), dict) else {}
    sample = report.get("sample", {}) if isinstance(report.get("sample"), dict) else {}
    reviewer_refs = assertions.get("reviewer_refs", []) if isinstance(assertions.get("reviewer_refs"), list) else []
    assertion_refs = assertions.get("assertion_refs", []) if isinstance(assertions.get("assertion_refs"), list) else []
    reviewed_rows = _safe_int(assertions.get("reviewed_row_count", 0))
    invalid_rows = _safe_int(assertions.get("invalid_row_count", -1), -1)
    return (
        assertions.get("schema") == "k_guard_validation_reviewer_assertions.v1"
        and assertions.get("manual_labels_asserted") is True
        and assertions.get("exact_review_source_asserted") is True
        and assertions.get("named_reviewer_required") is True
        and assertions.get("all_valid_rows_have_named_reviewer") is True
        and reviewed_rows >= _safe_int(sample.get("reviewed_candidate_count", 0)) > 0
        and invalid_rows == _safe_int(sample.get("invalid_review_count", -2), -2)
        and _safe_int(source.get("row_count", -1), -1) == reviewed_rows + invalid_rows
        and _safe_int(assertions.get("reviewer_count", 0)) == len(reviewer_refs) > 0
        and len(assertion_refs) == reviewed_rows
        and all(isinstance(item, dict) and item.get("hash") and item.get("raw_returned") is False for item in reviewer_refs)
        and all(isinstance(item, dict) and item.get("assertion_hash") and item.get("raw_returned") is False for item in assertion_refs)
        and assertions.get("raw_returned") is False
    )


def _valid_field_reviewer_assertions(report: dict[str, Any]) -> bool:
    assertions = report.get("reviewer_assertions", {}) if isinstance(report.get("reviewer_assertions"), dict) else {}
    source = report.get("review_source", {}) if isinstance(report.get("review_source"), dict) else {}
    sample = report.get("sample", {}) if isinstance(report.get("sample"), dict) else {}
    reviewer_refs = assertions.get("reviewer_refs", []) if isinstance(assertions.get("reviewer_refs"), list) else []
    assertion_refs = assertions.get("assertion_refs", []) if isinstance(assertions.get("assertion_refs"), list) else []
    reviewed_rows = _safe_int(assertions.get("reviewed_row_count", 0))
    invalid_rows = _safe_int(assertions.get("invalid_row_count", -1), -1)
    return (
        assertions.get("schema") == "k_guard_field_reviewer_assertions.v1"
        and reviewed_rows == _safe_int(sample.get("reviewed_candidate_count", -1), -1) > 0
        and _safe_int(assertions.get("dual_reviewed_row_count", 0)) == reviewed_rows
        and _safe_int(assertions.get("cryptographically_verified_row_count", 0)) == reviewed_rows
        and assertions.get("signature_algorithm") == "hmac-sha256"
        and assertions.get("independent_role_keys_required") is True
        and invalid_rows == _safe_int(sample.get("invalid_review_count", -2), -2) == 0
        and _safe_int(source.get("row_count", -1), -1) == reviewed_rows
        and _safe_int(assertions.get("reviewer_count", 0)) == len(reviewer_refs) >= 2
        and len(assertion_refs) == reviewed_rows
        and all(isinstance(item, dict) and item.get("hash") and item.get("raw_returned") is False for item in reviewer_refs)
        and all(isinstance(item, dict) and item.get("hash") and item.get("raw_returned") is False for item in assertion_refs)
        and assertions.get("raw_returned") is False
    )


def _valid_ground_truth_source(report: dict[str, Any]) -> bool:
    source = report.get("ground_truth_source", {}) if isinstance(report.get("ground_truth_source"), dict) else {}
    content_sha256 = str(source.get("content_sha256") or "")
    path_ref = source.get("path_ref", {}) if isinstance(source.get("path_ref"), dict) else {}
    sample = report.get("sample", {}) if isinstance(report.get("sample"), dict) else {}
    repeat_source = report.get("repeat_guardian_source", {}) if isinstance(report.get("repeat_guardian_source"), dict) else {}
    return (
        source.get("schema") == "k_guard_ground_truth_source.v1"
        and re.fullmatch(r"[0-9a-f]{64}", content_sha256) is not None
        and source.get("sha256_verified_at_generation") is True
        and source.get("exists_at_generation") is True
        and _safe_int(source.get("byte_count", -1), -1) > 0
        and _safe_int(source.get("row_count", 0)) == _safe_int(sample.get("ground_truth_row_count", -1), -1) >= 120
        and bool(path_ref.get("hash"))
        and path_ref.get("raw_returned") is False
        and source.get("raw_returned") is False
        and repeat_source.get("schema") == "k_guard_repeat_guardian_source.v1"
        and repeat_source.get("exists_at_generation") is True
        and re.fullmatch(r"[0-9a-f]{64}", str(repeat_source.get("content_sha256") or "")) is not None
        and _safe_int(repeat_source.get("byte_count", -1), -1) > 0
        and _safe_int(repeat_source.get("row_count", 0)) == 1
    )


def _valid_field_roster_source(report: dict[str, Any]) -> bool:
    source = report.get("field_roster_source", {}) if isinstance(report.get("field_roster_source"), dict) else {}
    content_sha256 = str(source.get("content_sha256") or "")
    path_ref = source.get("path_ref", {}) if isinstance(source.get("path_ref"), dict) else {}
    preregistration = report.get("field_preregistration", {}) if isinstance(report.get("field_preregistration"), dict) else {}
    row_count = _safe_int(source.get("row_count", 0))
    return (
        source.get("schema") == "k_guard_field_roster_source.v1"
        and re.fullmatch(r"[0-9a-f]{64}", content_sha256) is not None
        and content_sha256 == str(preregistration.get("roster_content_sha256") or "")
        and source.get("sha256_verified_at_generation") is True
        and source.get("exists_at_generation") is True
        and _safe_int(source.get("byte_count", -1), -1) > 0
        and 12 <= row_count <= 20
        and row_count == _safe_int(preregistration.get("roster_row_count", -1), -1)
        and bool(path_ref.get("hash"))
        and path_ref.get("raw_returned") is False
        and source.get("raw_returned") is False
    )


def _valid_ground_truth_assertions(report: dict[str, Any]) -> bool:
    assertions = report.get("ground_truth_assertions", {}) if isinstance(report.get("ground_truth_assertions"), dict) else {}
    sample = report.get("sample", {}) if isinstance(report.get("sample"), dict) else {}
    reviewer_refs = assertions.get("reviewer_refs", []) if isinstance(assertions.get("reviewer_refs"), list) else []
    assertion_refs = assertions.get("assertion_refs", []) if isinstance(assertions.get("assertion_refs"), list) else []
    case_count = _safe_int(sample.get("case_count", 0))
    return (
        assertions.get("schema") == "k_guard_ground_truth_assertions.v1"
        and _safe_int(assertions.get("case_count", 0)) == case_count >= 120
        and _safe_int(assertions.get("invalid_case_count", -1), -1) == 0
        and _safe_int(assertions.get("dual_reviewed_case_count", 0)) == case_count
        and _safe_int(assertions.get("cryptographically_verified_case_count", 0)) == case_count
        and assertions.get("signature_algorithm") == "hmac-sha256"
        and assertions.get("independent_role_keys_required") is True
        and _safe_int(assertions.get("source_ref_count", 0)) == case_count
        and _safe_int(assertions.get("reviewer_count", 0)) == len(reviewer_refs) >= 2
        and len(assertion_refs) == case_count
        and all(isinstance(item, dict) and item.get("hash") and item.get("raw_returned") is False for item in reviewer_refs)
        and all(isinstance(item, dict) and item.get("hash") and item.get("raw_returned") is False for item in assertion_refs)
        and assertions.get("raw_returned") is False
    )


def _field_thresholds_are_strict(thresholds: dict[str, Any]) -> bool:
    required_minimums = {
        "min_app_count": 12,
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
    }
    for key, minimum in required_minimums.items():
        value = _finite_rate(thresholds.get(key))
        if value is None or value < float(minimum):
            return False
    return thresholds.get("require_dual_review") is True and thresholds.get("require_owned_partner_only") is True


def _korean_corpus_checks(
    report: dict[str, Any],
    checks: list[dict[str, Any]],
    min_recall: float,
    max_false_positive_rate: float,
    min_positive_cases: int,
    min_negative_cases: int,
    min_governance_positive_cases: int,
    min_governance_negative_cases: int,
) -> None:
    recall = _finite_rate(report.get("recall"))
    false_positive_rate = _finite_rate(report.get("false_positive_rate"))
    positive_count = _safe_int(report.get("positive_count", 0))
    negative_count = _safe_int(report.get("negative_count", 0))
    coverage = report.get("coverage", {}) if isinstance(report.get("coverage"), dict) else {}
    governance = report.get("governance_coverage", {}) if isinstance(report.get("governance_coverage"), dict) else {}
    governance_positive_count = _safe_int(report.get("workspace_positive_case_count", 0))
    governance_negative_count = _safe_int(report.get("workspace_negative_case_count", 0))
    governance_positive_passed = _safe_int(report.get("workspace_positive_passed_count", 0))
    governance_negative_passed = _safe_int(report.get("workspace_negative_passed_count", 0))
    checks.append(_check("korean_corpus_passed", report.get("passed") is True, "blocker", "fixture_corpus_must_pass"))
    checks.append(_check("korean_corpus_raw_free", report.get("raw_free") is True, "blocker", "korean_corpus_report_raw_free_required"))
    checks.append(_check("korean_corpus_recall_budget", recall is not None and recall >= min_recall, "blocker", "recall", value=recall))
    checks.append(_check("korean_corpus_false_positive_budget", false_positive_rate is not None and false_positive_rate <= max_false_positive_rate, "blocker", "false_positive_rate", value=false_positive_rate))
    checks.append(_check("korean_corpus_positive_case_floor", positive_count >= min_positive_cases, "blocker", "positive_count", value=positive_count))
    checks.append(_check("korean_corpus_negative_case_floor", negative_count >= min_negative_cases, "blocker", "negative_count", value=negative_count))
    checks.append(_check("korean_corpus_required_rule_coverage", coverage.get("all_required_rules_observed") is True, "blocker", "missing_required_rules", value=coverage.get("missing_required_rules", [])))
    checks.append(_check("korean_governance_positive_case_floor", governance_positive_count >= min_governance_positive_cases and governance_positive_passed >= min_governance_positive_cases, "blocker", "workspace_positive_cases_must_pass", value={"declared": governance_positive_count, "passed": governance_positive_passed}))
    checks.append(_check("korean_governance_negative_case_floor", governance_negative_count >= min_governance_negative_cases and governance_negative_passed >= min_governance_negative_cases, "blocker", "workspace_negative_cases_must_emit_no_KR_DATA_rules", value={"declared": governance_negative_count, "passed": governance_negative_passed}))
    checks.append(_check("korean_governance_required_rule_coverage", governance.get("all_required_rules_observed") is True, "blocker", "missing_governance_rules", value=governance.get("missing_required_rules", [])))


def _korean_corpus_recompute_checks(
    report: dict[str, Any],
    corpus_path: str | Path | None,
    checks: list[dict[str, Any]],
    min_recall: float,
    max_false_positive_rate: float,
    min_positive_cases: int,
    min_negative_cases: int,
    min_governance_positive_cases: int,
    min_governance_negative_cases: int,
) -> None:
    if not corpus_path:
        checks.append(_check("korean_fixture_corpus_present", False, "blocker", "korean_fixture_corpus_path_missing"))
        return
    path = Path(corpus_path)
    if not path.exists() or not path.is_file():
        checks.append(_check("korean_fixture_corpus_present", False, "blocker", "korean_fixture_corpus_file_missing", path_ref=_path_ref(path)))
        return
    try:
        recomputed = evaluate_fixture_corpus(path)
    except Exception:
        checks.append(_check("korean_fixture_corpus_recomputed", False, "blocker", "korean_fixture_corpus_recompute_failed", path_ref=_path_ref(path)))
        return
    checks.append(_check("korean_fixture_corpus_present", True, "info", "loaded", path_ref=_path_ref(path)))
    recall = float(recomputed.get("recall", 0.0))
    false_positive_rate = float(recomputed.get("false_positive_rate", 1.0))
    positive_count = int(recomputed.get("positive_count", 0))
    negative_count = int(recomputed.get("negative_count", 0))
    coverage = recomputed.get("coverage", {}) if isinstance(recomputed.get("coverage"), dict) else {}
    governance = recomputed.get("governance_coverage", {}) if isinstance(recomputed.get("governance_coverage"), dict) else {}
    governance_positive_count = int(recomputed.get("workspace_positive_case_count", 0))
    governance_negative_count = int(recomputed.get("workspace_negative_case_count", 0))
    governance_positive_passed = int(recomputed.get("workspace_positive_passed_count", 0))
    governance_negative_passed = int(recomputed.get("workspace_negative_passed_count", 0))
    recomputed_passed = (
        recomputed.get("passed") is True
        and recomputed.get("raw_free") is True
        and recall >= min_recall
        and false_positive_rate <= max_false_positive_rate
        and positive_count >= min_positive_cases
        and negative_count >= min_negative_cases
        and coverage.get("all_required_rules_observed") is True
        and governance_positive_count >= min_governance_positive_cases
        and governance_negative_count >= min_governance_negative_cases
        and governance_positive_passed >= min_governance_positive_cases
        and governance_negative_passed >= min_governance_negative_cases
        and governance.get("all_required_rules_observed") is True
    )
    checks.append(_check("korean_fixture_corpus_recomputed", recomputed_passed, "blocker", "recomputed_release_thresholds", value=_korean_projection(recomputed)))
    checks.append(_check("korean_corpus_report_matches_recomputed_score", _korean_projection(report) == _korean_projection(recomputed), "blocker", "reported_score_must_match_recomputed_corpus", value={"reported": _korean_projection(report), "recomputed": _korean_projection(recomputed)}))


def _korean_projection(report: dict[str, Any]) -> dict[str, Any]:
    coverage = report.get("coverage", {}) if isinstance(report.get("coverage"), dict) else {}
    governance = report.get("governance_coverage", {}) if isinstance(report.get("governance_coverage"), dict) else {}
    return {
        "raw_free": report.get("raw_free") is True,
        "passed": report.get("passed") is True,
        "positive_count": _safe_int(report.get("positive_count", 0)),
        "negative_count": _safe_int(report.get("negative_count", 0)),
        "measurable_negative_count": _safe_int(report.get("measurable_negative_count", 0)),
        "targeted_absence_case_count": _safe_int(report.get("targeted_absence_case_count", 0)),
        "false_positive_count": _safe_int(report.get("false_positive_count", 0)),
        "false_positive_rate_denominator": _safe_int(report.get("false_positive_rate_denominator", 0)),
        "false_positive_rate_denominator_name": str(report.get("false_positive_rate_denominator_name") or "measurable_negative_count"),
        "workspace_case_count": _safe_int(report.get("workspace_case_count", 0)),
        "workspace_passed_count": _safe_int(report.get("workspace_passed_count", 0)),
        "workspace_positive_case_count": _safe_int(report.get("workspace_positive_case_count", 0)),
        "workspace_negative_case_count": _safe_int(report.get("workspace_negative_case_count", 0)),
        "workspace_positive_passed_count": _safe_int(report.get("workspace_positive_passed_count", 0)),
        "workspace_negative_passed_count": _safe_int(report.get("workspace_negative_passed_count", 0)),
        "recall": _finite_rate(report.get("recall")),
        "false_positive_rate": _finite_rate(report.get("false_positive_rate")),
        "missing_required_rules": sorted(coverage.get("missing_required_rules", [])) if isinstance(coverage.get("missing_required_rules", []), list) else [],
        "all_required_rules_observed": coverage.get("all_required_rules_observed") is True,
        "required_direct_unique_rules": sorted(coverage.get("required_direct_unique_rules", [])) if isinstance(coverage.get("required_direct_unique_rules", []), list) else [],
        "required_composite_rules": sorted(coverage.get("required_composite_rules", [])) if isinstance(coverage.get("required_composite_rules", []), list) else [],
        "required_org_rules": sorted(coverage.get("required_org_rules", [])) if isinstance(coverage.get("required_org_rules", []), list) else [],
        "missing_required_governance_rules": sorted(governance.get("missing_required_rules", [])) if isinstance(governance.get("missing_required_rules", []), list) else [],
        "all_required_governance_rules_observed": governance.get("all_required_rules_observed") is True,
    }


def _mcp_interceptor_checks(
    report: dict[str, Any],
    checks: list[dict[str, Any]],
    forwarded_output_path: str | Path | None,
    guardian: dict[str, Any] | None,
    guardian_report_path: str | Path,
) -> None:
    metadata = report.get("metadata", {}) if isinstance(report.get("metadata"), dict) else {}
    policy = metadata.get("runtime_policy", {}) if isinstance(metadata.get("runtime_policy"), dict) else {}
    interceptor = policy.get("interceptor", {}) if isinstance(policy.get("interceptor"), dict) else {}
    parse_error_count = _safe_int(policy.get("parse_error_count", 0))
    blocked_count = _safe_int(interceptor.get("blocked_count", 0))
    event_count = _safe_int(interceptor.get("event_count", 0))
    output_event_count = _safe_int(interceptor.get("output_event_count", 0))
    forwarded_ref = interceptor.get("forwarded_output_ref")
    binding = report.get("release_binding", {}) if isinstance(report.get("release_binding"), dict) else {}
    app_ref = binding.get("app_id_ref", {}) if isinstance(binding.get("app_id_ref"), dict) else {}
    session_ref = binding.get("session_id_ref", {}) if isinstance(binding.get("session_id_ref"), dict) else {}
    bound_guardian = binding.get("guardian_report", {}) if isinstance(binding.get("guardian_report"), dict) else {}
    guardian = guardian if isinstance(guardian, dict) else {}
    review = guardian.get("review_contract", {}) if isinstance(guardian.get("review_contract"), dict) else {}
    guardian_app_id = str(review.get("app_id") or "").strip()
    expected_app_ref = _bound_value_ref(guardian_app_id)
    expected_guardian_bundle_ref = _bundle_ref(guardian.get("evidence_bundle"))
    expected_authority_ref = _bound_value_ref(canonical_json(release_authority_claim(guardian)) if guardian else "")
    checks.append(_check("mcp_interceptor_raw_free", report.get("raw_free") is True, "blocker", "mcp_intercept_report_raw_free_required"))
    checks.append(_check("mcp_interceptor_schema", report.get("schema") == MCP_INTERCEPT_REPORT_SCHEMA, "blocker", "mcp_intercept_report_v2_required"))
    checks.append(_check("mcp_interceptor_producer", report.get("producer") == MCP_INTERCEPT_REPORT_PRODUCER, "blocker", "trusted_interceptor_producer_required"))
    checks.append(_check("mcp_interceptor_report_raw_free", interceptor.get("report_raw_free") is True, "blocker", "interceptor_report_raw_free_required"))
    checks.append(_check("mcp_interceptor_metadata_present", bool(interceptor), "blocker", "runtime_policy_interceptor_required"))
    checks.append(_check("mcp_interceptor_mode", interceptor.get("mode") == "block_or_redact_before_forward", "blocker", "interceptor_mode", value=interceptor.get("mode", "")))
    checks.append(_check("mcp_interceptor_forwarded_stream_present", _valid_forwarded_ref_shape(forwarded_ref), "blocker", "forwarded_output_ref_required"))
    checks.append(_check("mcp_interceptor_events_observed", event_count > 0, "blocker", "event_count", value=event_count))
    checks.append(_check("mcp_interceptor_input_output_event_count_consistent", event_count == output_event_count and output_event_count > 0, "blocker", "event_count_output_event_count", value={"event_count": event_count, "output_event_count": output_event_count}))
    checks.append(_check("mcp_interceptor_no_parse_errors", parse_error_count == 0, "blocker", "parse_error_count", value=parse_error_count))
    checks.append(_check("mcp_interceptor_no_blocked_events", blocked_count == 0, "blocker", "blocked_count", value=blocked_count))
    checks.append(_check("mcp_interceptor_release_binding_schema", binding.get("schema") == "k_guard_mcp_interceptor_release_binding.v1", "blocker", "interceptor_release_binding_v1_required"))
    checks.append(_check("mcp_interceptor_app_binding_present", _valid_bound_ref(app_ref), "blocker", "nonempty_app_id_binding_required"))
    checks.append(_check("mcp_interceptor_session_binding_present", _valid_bound_ref(session_ref), "blocker", "nonempty_session_id_binding_required"))
    checks.append(_check("mcp_interceptor_app_matches_guardian", bool(guardian_app_id) and app_ref == expected_app_ref and bound_guardian.get("app_id_ref") == expected_app_ref, "blocker", "interceptor_app_id_must_match_guardian_single_app"))
    checks.append(_check("mcp_interceptor_guardian_binding_present", bound_guardian.get("configured") is True and bound_guardian.get("parseable") is True and bound_guardian.get("method_verified") is True, "blocker", "parseable_guardian_audit_binding_required"))
    checks.append(_check("mcp_interceptor_guardian_path_binding_matches", bound_guardian.get("path_ref") == _path_ref(guardian_report_path), "blocker", "guardian_report_path_ref_must_match"))
    checks.append(_check("mcp_interceptor_guardian_content_binding_matches", bound_guardian.get("content_ref") == _content_ref(guardian_report_path), "blocker", "guardian_report_content_ref_must_match"))
    checks.append(_check("mcp_interceptor_guardian_bundle_binding_matches", bound_guardian.get("evidence_bundle_ref") == expected_guardian_bundle_ref, "blocker", "guardian_evidence_bundle_ref_must_match"))
    checks.append(_check("mcp_interceptor_guardian_authority_binding_matches", bound_guardian.get("release_authority_claim_ref") == expected_authority_ref, "blocker", "guardian_release_authority_claim_ref_must_match"))
    checks.append(_check("mcp_interceptor_operator_signed_evidence", _mcp_interceptor_bundle_matches(report, forwarded_output_path, guardian_report_path), "blocker", "operator_keyed_interceptor_evidence_bundle_must_match_current_inputs"))
    forwarded = _forwarded_output_evidence(forwarded_output_path)
    checks.append(_check("mcp_forwarded_output_file_present", forwarded["present"], "blocker", forwarded["detail"]))
    checks.append(_check("mcp_forwarded_output_parseable_jsonl", forwarded["parseable"], "blocker", "parseable_jsonl", value=forwarded.get("invalid_line_count", 0)))
    checks.append(_check("mcp_forwarded_output_raw_free_scan", forwarded.get("raw_free") is True, "blocker", "forwarded_output_must_not_contain_sensitive_raw_values", value=forwarded.get("sensitive_rule_ids", [])))
    if isinstance(forwarded_ref, dict):
        checks.append(_check("mcp_forwarded_output_hash_matches", forwarded.get("content_hash") == forwarded_ref.get("content_hash"), "blocker", "content_hash_match"))
        checks.append(_check("mcp_forwarded_output_byte_count_matches", forwarded.get("byte_count") == forwarded_ref.get("byte_count"), "blocker", "byte_count_match", value=forwarded.get("byte_count", 0)))
        checks.append(_check("mcp_forwarded_output_line_count_matches", forwarded.get("line_count") == forwarded_ref.get("line_count"), "blocker", "line_count_match", value=forwarded.get("line_count", 0)))
        checks.append(_check("mcp_forwarded_output_event_count_matches_report", forwarded.get("event_count") == output_event_count == forwarded_ref.get("event_count"), "blocker", "event_count_match", value=forwarded.get("event_count", 0)))


def _mcp_interceptor_bundle_matches(
    report: dict[str, Any],
    forwarded_output_path: str | Path | None,
    guardian_report_path: str | Path | None,
) -> bool:
    bundle = report.get("evidence_bundle")
    if not _valid_evidence_bundle(bundle, require_operator_key=True) or not isinstance(bundle, dict):
        return False
    if bundle.get("subject") != "mcp_runtime_interceptor" or bundle.get("producer") != MCP_INTERCEPT_REPORT_PRODUCER:
        return False
    artifacts = bundle.get("artifacts", [])
    if not isinstance(artifacts, list):
        return False
    artifact_keys = {
        (str(item.get("label") or ""), str(item.get("role") or "evidence"))
        for item in artifacts
        if isinstance(item, dict)
    }
    expected_keys = {
        ("interceptor_projection", "gate"),
        ("release_binding", "assertion"),
        ("forwarded_output", "output"),
        ("guardian_report", "input"),
    }
    if artifact_keys != expected_keys or len(artifacts) != len(expected_keys):
        return False
    expected = mcp_interceptor_evidence_artifacts(report, forwarded_output_path, guardian_report_path)
    return _bundle_contains_expected_artifacts(bundle, expected)


def _guardian_validation_membership_checks(guardian: dict[str, Any], validation: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    guardian_hashes = _guardian_target_hashes(guardian)
    validation_hashes = _validation_target_hashes(validation)
    guardian_app_hashes = _guardian_app_hashes(guardian)
    validation_app_hashes = _validation_app_hashes(validation)
    covered = bool(validation_hashes) and validation_hashes.issubset(guardian_hashes)
    apps_covered = bool(validation_app_hashes) and validation_app_hashes.issubset(guardian_app_hashes)
    checks.append(_check("guardian_targets_present_for_validation", bool(guardian_hashes), "blocker", "guardian_targets_required", value=len(guardian_hashes)))
    checks.append(_check("validation_targets_covered_by_guardian_release_report", covered, "blocker", "validation_target_refs_subset_of_guardian_targets", value={"guardian_target_count": len(guardian_hashes), "validation_target_count": len(validation_hashes)}))
    checks.append(_check("validation_apps_covered_by_guardian_release_report", apps_covered, "blocker", "validation_app_refs_subset_of_guardian_apps", value={"guardian_app_count": len(guardian_app_hashes), "validation_app_count": len(validation_app_hashes)}))


def _validation_source_guardian_checks(source_guardian: dict[str, Any], validation: dict[str, Any], source_path: str | Path, checks: list[dict[str, Any]]) -> None:
    sample = validation.get("sample", {}) if isinstance(validation.get("sample"), dict) else {}
    validation_ref = validation.get("guardian_report_ref", {}) if isinstance(validation.get("guardian_report_ref"), dict) else {}
    validation_content_ref = validation.get("guardian_report_content_ref", {}) if isinstance(validation.get("guardian_report_content_ref"), dict) else {}
    validation_bundle_ref = validation.get("guardian_report_bundle_ref", {}) if isinstance(validation.get("guardian_report_bundle_ref"), dict) else {}
    source_contract = source_guardian.get("execution_contract", {}) if isinstance(source_guardian.get("execution_contract"), dict) else {}
    source_intent = source_guardian.get("intent_contract", {}) if isinstance(source_guardian.get("intent_contract"), dict) else {}
    expected_source_ref = _path_ref(source_path)
    expected_source_content_ref = _content_ref(source_path)
    expected_source_bundle_ref = _bundle_ref(source_guardian.get("evidence_bundle"))
    source_candidates = _guardian_high_critical_candidates(source_guardian)
    source_app_hashes = {evidence_hash(str(candidate.get("app_id") or "")) for candidate in source_candidates if str(candidate.get("app_id") or "").strip()}
    source_all_app_hashes = _guardian_app_hashes(source_guardian)
    source_target_hashes = {evidence_hash(str(candidate.get("target_id") or "")) for candidate in source_candidates if str(candidate.get("target_id") or "").strip()}
    source_finding_hashes = {finding_fingerprint(candidate) for candidate in source_candidates}
    validation_target_hashes = _validation_target_hashes(validation)
    validation_app_hashes = _validation_app_hashes(validation)
    validation_finding_hashes = _validation_finding_hashes(validation)
    validation_evaluation_app_hashes = _validation_evaluation_app_hashes(validation)
    candidate_count = int(sample.get("candidate_count", 0))
    candidate_app_count = int(sample.get("candidate_app_count", 0))
    evaluation_app_count = int(sample.get("app_count", 0))
    checks.append(_check("validation_source_guardian_raw_free", source_guardian.get("raw_free") is True, "blocker", "source_guardian_report_raw_free_required"))
    checks.append(_check("validation_source_guardian_method", source_guardian.get("method") == "guardian_audit", "blocker", "source_guardian_method_must_be_guardian_audit", value=source_guardian.get("method", "")))
    checks.append(_check("validation_source_guardian_contract_present", bool(source_contract), "blocker", "source_guardian_execution_contract_required"))
    checks.append(_check("validation_source_guardian_evidence_bundle_present", _valid_evidence_bundle(source_guardian.get("evidence_bundle"), require_operator_key=True), "blocker", "source_guardian_operator_keyed_evidence_bundle_required"))
    checks.append(_check("validation_source_guardian_evidence_bundle_matches_report", _guardian_evidence_bundle_matches_report(source_guardian), "blocker", "source_guardian_evidence_bundle_artifacts_must_match_report"))
    checks.append(_check("validation_source_guardian_intent_contract_present", bool(source_intent), "blocker", "source_guardian_intent_contract_required"))
    checks.append(_check("validation_source_guardian_scope_assertion_refs_present", source_intent.get("scope_assertion_complete") is True, "blocker", "source_guardian_scope_assertion_complete"))
    checks.append(_check("validation_source_guardian_target_business_contexts_present", _target_business_contexts_complete(source_guardian), "blocker", "source_guardian_target_business_contexts_required"))
    checks.append(_check("validation_source_guardian_target_scope_assertions_present", _target_scope_assertions_complete(source_guardian), "blocker", "source_guardian_target_scope_assertions_required"))
    checks.append(_check("validation_source_guardian_no_human_intent_overclaim", source_intent.get("human_business_intent_understanding_claimed") is False, "blocker", "source_guardian_human_intent_claim_must_be_false"))
    checks.append(_check("validation_report_bound_to_source_guardian", validation_ref.get("hash") == expected_source_ref["hash"], "blocker", "guardian_report_ref_hash_match"))
    checks.append(_check("validation_report_bound_to_source_guardian_content", validation_content_ref.get("hash") == expected_source_content_ref.get("hash") and bool(validation_content_ref.get("hash")), "blocker", "guardian_report_content_ref_hash_match"))
    checks.append(_check("validation_report_bound_to_source_guardian_bundle", validation_bundle_ref.get("bundle_sha256") == expected_source_bundle_ref.get("bundle_sha256") and bool(validation_bundle_ref.get("bundle_sha256")), "blocker", "guardian_report_bundle_ref_match"))
    checks.append(_check("validation_source_guardian_has_candidates", bool(source_finding_hashes), "blocker", "source_guardian_high_critical_candidates_required", value=len(source_finding_hashes)))
    checks.append(_check("validation_candidate_count_matches_source_guardian", candidate_count == len(source_finding_hashes), "blocker", "source_candidate_count", value={"validation_candidate_count": candidate_count, "source_candidate_count": len(source_finding_hashes)}))
    checks.append(_check("validation_app_count_matches_source_candidate_apps", candidate_app_count == len(source_app_hashes), "blocker", "source_candidate_app_count", value={"validation_candidate_app_count": candidate_app_count, "source_candidate_app_count": len(source_app_hashes)}))
    checks.append(_check("validation_app_refs_match_source_guardian_candidates", validation_app_hashes == source_app_hashes and bool(validation_app_hashes), "blocker", "source_candidate_app_refs_match", value={"validation_app_count": len(validation_app_hashes), "source_app_count": len(source_app_hashes)}))
    checks.append(_check("validation_evaluation_apps_present_in_source_guardian", validation_evaluation_app_hashes == source_all_app_hashes and len(validation_evaluation_app_hashes) == evaluation_app_count, "blocker", "all_field_apps_must_be_present_in_source_guardian", value={"validation_evaluation_app_count": len(validation_evaluation_app_hashes), "source_guardian_app_count": len(source_all_app_hashes)}))
    checks.append(_check("validation_target_refs_match_source_guardian_candidates", validation_target_hashes == source_target_hashes and bool(validation_target_hashes), "blocker", "source_candidate_target_refs_match", value={"validation_target_count": len(validation_target_hashes), "source_target_count": len(source_target_hashes)}))
    checks.append(_check("validation_finding_refs_match_source_guardian_candidates", validation_finding_hashes == source_finding_hashes and bool(validation_finding_hashes), "blocker", "source_candidate_finding_refs_match", value={"validation_finding_count": len(validation_finding_hashes), "source_finding_count": len(source_finding_hashes)}))


def _validation_repeat_guardian_checks(
    primary: dict[str, Any],
    repeat: dict[str, Any],
    validation: dict[str, Any],
    repeat_path: str | Path,
    checks: list[dict[str, Any]],
) -> None:
    repeat_ref = validation.get("repeat_guardian_report_ref", {}) if isinstance(validation.get("repeat_guardian_report_ref"), dict) else {}
    repeat_content_ref = validation.get("repeat_guardian_report_content_ref", {}) if isinstance(validation.get("repeat_guardian_report_content_ref"), dict) else {}
    repeat_bundle_ref = validation.get("repeat_guardian_report_bundle_ref", {}) if isinstance(validation.get("repeat_guardian_report_bundle_ref"), dict) else {}
    repeat_source = validation.get("repeat_guardian_source", {}) if isinstance(validation.get("repeat_guardian_source"), dict) else {}
    expected_ref = _path_ref(repeat_path)
    expected_content_ref = _content_ref(repeat_path)
    expected_bundle_ref = _bundle_ref(repeat.get("evidence_bundle"))
    repeat_sha256 = str(path_artifact("validation_repeat_guardian", repeat_path, role="repeat_input").get("content_sha256") or "")
    primary_findings = _guardian_high_critical_candidates(primary)
    repeat_findings = _guardian_high_critical_candidates(repeat)
    primary_candidates = {finding_fingerprint(item) for item in primary_findings}
    repeat_candidates = {finding_fingerprint(item) for item in repeat_findings}
    primary_multiset = guardian_candidate_multiset_contract(primary_findings)
    repeat_multiset = guardian_candidate_multiset_contract(repeat_findings)
    primary_input = guardian_repeat_input_contract(primary)
    repeat_input = guardian_repeat_input_contract(repeat)
    reproducibility = validation.get("reproducibility", {}) if isinstance(validation.get("reproducibility"), dict) else {}
    primary_execution_id = str(primary.get("execution_id") or "")
    repeat_execution_id = str(repeat.get("execution_id") or "")
    primary_bundle_sha = str((primary.get("evidence_bundle") or {}).get("bundle_sha256") or "") if isinstance(primary.get("evidence_bundle"), dict) else ""
    repeat_bundle_sha = str((repeat.get("evidence_bundle") or {}).get("bundle_sha256") or "") if isinstance(repeat.get("evidence_bundle"), dict) else ""
    primary_snapshots = _guardian_workspace_snapshot_refs(primary)
    repeat_snapshots = _guardian_workspace_snapshot_refs(repeat)
    expected_toolchain = guardian_toolchain_contract()
    checks.append(_check("validation_repeat_guardian_raw_free", repeat.get("raw_free") is True, "blocker", "repeat_guardian_raw_free_required"))
    checks.append(_check("validation_repeat_guardian_method", repeat.get("method") == "guardian_audit", "blocker", "repeat_guardian_method_must_be_guardian_audit"))
    checks.append(_check("validation_repeat_guardian_evidence_bundle", _guardian_evidence_bundle_matches_report(repeat), "blocker", "repeat_guardian_signed_projection_required"))
    checks.append(_check("validation_repeat_guardian_path_binding", repeat_ref.get("hash") == expected_ref.get("hash"), "blocker", "repeat_guardian_path_ref_match"))
    checks.append(_check("validation_repeat_guardian_content_binding", repeat_content_ref.get("hash") == expected_content_ref.get("hash") and bool(expected_content_ref.get("hash")), "blocker", "repeat_guardian_content_ref_match"))
    checks.append(_check("validation_repeat_guardian_bundle_binding", repeat_bundle_ref == expected_bundle_ref and bool(expected_bundle_ref.get("bundle_sha256")), "blocker", "repeat_guardian_bundle_ref_match"))
    checks.append(_check("validation_repeat_guardian_source_sha256", repeat_source.get("content_sha256") == repeat_sha256 and bool(repeat_sha256), "blocker", "repeat_guardian_exact_file_sha256_match"))
    checks.append(_check("validation_repeat_guardian_distinct_execution", bool(re.fullmatch(r"[0-9a-f]{32}", primary_execution_id) and re.fullmatch(r"[0-9a-f]{32}", repeat_execution_id) and primary_execution_id != repeat_execution_id), "blocker", "distinct_signed_execution_ids_required"))
    checks.append(_check("validation_repeat_guardian_distinct_attestation", guardian_execution_attestation_valid(primary) and guardian_execution_attestation_valid(repeat) and primary.get("execution_attestation") != repeat.get("execution_attestation"), "blocker", "distinct_signed_runtime_attestations_required"))
    checks.append(_check("validation_repeat_guardian_distinct_bundle", bool(primary_bundle_sha and repeat_bundle_sha and primary_bundle_sha != repeat_bundle_sha), "blocker", "distinct_signed_bundles_required"))
    checks.append(_check("validation_repeat_guardian_toolchain_exact", primary.get("toolchain_contract") == repeat.get("toolchain_contract") == expected_toolchain, "blocker", "same_current_toolchain_contract_required"))
    checks.append(_check("validation_repeat_guardian_source_snapshots", bool(primary_snapshots) and primary_snapshots == repeat_snapshots, "blocker", "same_complete_workspace_snapshots_required"))
    checks.append(_check("validation_repeat_guardian_candidate_set", bool(primary_candidates) and primary_candidates == repeat_candidates == _validation_finding_hashes(validation), "blocker", "exact_repeat_candidate_set_required", value={"primary": len(primary_candidates), "repeat": len(repeat_candidates)}))
    checks.append(_check("validation_repeat_guardian_candidate_multiset", primary_multiset["candidate_count"] > 0 and primary_multiset == repeat_multiset, "blocker", "exact_repeat_candidate_multiset_required", value={"primary_count": primary_multiset["candidate_count"], "repeat_count": repeat_multiset["candidate_count"]}))
    checks.append(_check("validation_repeat_guardian_input_contract", primary_input["complete"] is True and primary_input == repeat_input, "blocker", "manifest_and_all_target_inputs_must_match", value={"primary_target_count": primary_input["target_count"], "repeat_target_count": repeat_input["target_count"]}))
    checks.append(
        _check(
            "validation_repeat_guardian_recomputed_binding",
            reproducibility.get("primary_candidate_multiset_sha256") == primary_multiset["multiset_sha256"]
            and reproducibility.get("repeat_candidate_multiset_sha256") == repeat_multiset["multiset_sha256"]
            and reproducibility.get("primary_repeat_input_sha256") == primary_input["target_input_sha256"]
            and reproducibility.get("repeat_repeat_input_sha256") == repeat_input["target_input_sha256"]
            and reproducibility.get("guardian_manifest_content_match") is True
            and reproducibility.get("target_input_bindings_match") is True,
            "blocker",
            "signed_validation_repeat_binding_must_match_recomputed_inputs",
        )
    )


def _guardian_workspace_snapshot_refs(report: dict[str, Any]) -> dict[tuple[str, str], str]:
    result: dict[tuple[str, str], str] = {}
    for target in report.get("targets", []):
        if not isinstance(target, dict) or target.get("kind") != "workspace":
            continue
        evidence = target.get("review_evidence", {}) if isinstance(target.get("review_evidence"), dict) else {}
        snapshot = evidence.get("source_tree_snapshot", {}) if isinstance(evidence.get("source_tree_snapshot"), dict) else {}
        tree_sha256 = str(snapshot.get("tree_sha256") or "")
        if snapshot.get("complete") is True and re.fullmatch(r"[0-9a-f]{64}", tree_sha256):
            result[(str(target.get("app_id") or ""), str(target.get("target_id") or ""))] = tree_sha256
    return result


def _guardian_high_critical_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for row in report.get("targets", []):
        if not isinstance(row, dict):
            continue
        target_id = str(row.get("target_id") or "")
        for finding in row.get("findings", []):
            if not isinstance(finding, dict):
                continue
            if str(finding.get("severity") or "info") not in {"critical", "high"}:
                continue
            item = dict(finding)
            item.setdefault("app_id", row.get("app_id", ""))
            item.setdefault("target_id", target_id)
            candidates.append(item)
    return candidates


def _guardian_target_hashes(report: dict[str, Any]) -> set[str]:
    hashes: set[str] = set()
    for row in report.get("targets", []):
        if not isinstance(row, dict):
            continue
        target_id = str(row.get("target_id") or "").strip()
        if target_id:
            hashes.add(evidence_hash(target_id))
    return hashes


def _guardian_app_hashes(report: dict[str, Any]) -> set[str]:
    hashes: set[str] = set()
    for row in report.get("targets", []):
        if not isinstance(row, dict):
            continue
        app_id = str(row.get("app_id") or "").strip()
        if app_id:
            hashes.add(evidence_hash(app_id))
    return hashes


def _validation_app_hashes(report: dict[str, Any]) -> set[str]:
    refs = report.get("candidate_app_refs", [])
    if not isinstance(refs, list):
        return set()
    return {
        str(item.get("hash") or "")
        for item in refs
        if isinstance(item, dict) and str(item.get("hash") or "").strip()
    }


def _validation_evaluation_app_hashes(report: dict[str, Any]) -> set[str]:
    refs = report.get("evaluation_app_refs", [])
    if not isinstance(refs, list):
        return set()
    return {
        str(item.get("hash") or "")
        for item in refs
        if isinstance(item, dict) and str(item.get("hash") or "").strip()
    }


def _validation_target_hashes(report: dict[str, Any]) -> set[str]:
    refs = report.get("candidate_target_refs", [])
    if not isinstance(refs, list):
        return set()
    return {str(item.get("hash") or "") for item in refs if isinstance(item, dict) and str(item.get("hash") or "").strip()}


def _validation_finding_hashes(report: dict[str, Any]) -> set[str]:
    refs = report.get("candidate_finding_refs", [])
    if not isinstance(refs, list):
        return set()
    return {str(item.get("hash") or "") for item in refs if isinstance(item, dict) and str(item.get("hash") or "").strip()}


def _valid_forwarded_ref_shape(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("raw_returned") is not False:
        return False
    required = {"hash", "hash_scheme", "content_hash", "byte_count", "line_count", "event_count"}
    return required.issubset(value.keys())


def _forwarded_output_evidence(path: str | Path | None) -> dict[str, Any]:
    if not path:
        return {"present": False, "parseable": False, "raw_free": False, "detail": "forwarded_output_path_missing"}
    output = Path(path)
    if not output.exists() or not output.is_file():
        return {"present": False, "parseable": False, "raw_free": False, "detail": "forwarded_output_file_missing"}
    text = output.read_text(encoding="utf-8", errors="ignore")
    lines = [line for line in text.splitlines() if line.strip()]
    invalid = 0
    decoded_lines: list[str] = []
    for line in lines:
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if not isinstance(parsed, dict):
            invalid += 1
            continue
        decoded_lines.append(json.dumps(parsed, ensure_ascii=False, sort_keys=True))
    sensitive_rule_ids = _forwarded_sensitive_rule_ids(text + "\n" + "\n".join(decoded_lines))
    return {
        "present": True,
        "parseable": invalid == 0,
        "raw_free": not sensitive_rule_ids,
        "detail": "loaded",
        "invalid_line_count": invalid,
        "sensitive_rule_ids": sensitive_rule_ids,
        "content_hash": evidence_hash(text),
        "byte_count": len(text.encode("utf-8")),
        "line_count": len(lines),
        "event_count": len(lines),
    }


def _forwarded_sensitive_rule_ids(text: str) -> list[str]:
    from k_guard_mcp.scanner import KGuardScanner

    result = KGuardScanner().scan_text(text, "mcp-forwarded-output.jsonl")
    prefixes = ("PII_", "KR_COMBO_", "SECRET_")
    return sorted({finding.rule_id for finding in result.findings if finding.rule_id.startswith(prefixes)})


def _target_refs_match_count(value: object, expected_count: int) -> bool:
    if not isinstance(value, list) or not value:
        return False
    hashes: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            return False
        if item.get("raw_returned") is not False:
            return False
        item_hash = str(item.get("hash") or "")
        if not item_hash or not item.get("hash_scheme"):
            return False
        hashes.add(item_hash)
    return len(value) == expected_count and len(hashes) == expected_count


def _target_ref_count(value: object) -> int:
    if not isinstance(value, list):
        return 0
    return len(value)


def _review_domains_complete(review: dict[str, Any]) -> bool:
    domains = review.get("domains", {}) if isinstance(review.get("domains"), dict) else {}
    required = {"site_security", "api_exposure", "data_management", "operational_risk"}
    return required.issubset(domains) and all(isinstance(domains[name], dict) and domains[name].get("passed") is True for name in required)


def _guardian_review_contract_matches_target_evidence(report: dict[str, Any]) -> bool:
    targets = report.get("targets", [])
    review = report.get("review_contract", {}) if isinstance(report.get("review_contract"), dict) else {}
    if (
        not isinstance(targets, list)
        or not targets
        or review.get("profile") != "korean_senior"
        or review.get("profile_supported") is not True
        or review.get("strict_domain_enforcement") is not True
        or review.get("release_gate_enabled") is not True
    ):
        return False
    rows = [row for row in targets if isinstance(row, dict)]
    app_ids = {str(row.get("app_id") or "").strip() for row in rows}
    if (
        len(rows) != len(targets)
        or any(row.get("audit_profile") != "korean_senior" for row in rows)
        or "" in app_ids
        or len(app_ids) != 1
    ):
        return False
    app_id = next(iter(app_ids))
    if (
        review.get("app_id") != app_id
        or review.get("app_id_values") != [app_id]
        or review.get("app_id_complete") is not True
        or review.get("single_app_scope") is not True
        or review.get("app_scope_enforced") is not True
        or review.get("canonical_release_authority") is not True
        or review.get("release_authority") != "canonical"
        or review.get("report_only") is not False
    ):
        return False

    completed = [
        row
        for row in rows
        if row.get("status") == "completed"
        and isinstance(row.get("gate"), dict)
        and row["gate"].get("passed") is True
        and isinstance(row.get("coverage"), dict)
        and row["coverage"].get("coverage_gap") is False
    ]
    workspaces = [row for row in completed if _release_workspace_evidence_complete(row)]
    http_rows = [row for row in completed if _release_http_evidence_complete(row)]
    deep_http = [row for row in http_rows if _row_requested_review(row).get("deep_active") is True]
    flow_workspaces = [
        row
        for row in workspaces
        if _row_requested_review(row).get("flow_analysis") is True
        and _row_review_coverage(row).get("flow_analysis_executed") is True
    ]
    valid_endpoint_count = sum(_safe_int(_row_requested_review(row).get("valid_public_endpoint_count", 0)) for row in http_rows)
    invalid_endpoint_count = sum(_safe_int(_row_requested_review(row).get("invalid_public_endpoint_count", 0)) for row in rows)
    intent_ready = _target_business_contexts_complete(report) and _target_scope_assertions_complete(report)
    recomputed = {
        "site_security": bool(workspaces and deep_http),
        "api_exposure": bool(workspaces and http_rows and valid_endpoint_count > 0 and invalid_endpoint_count == 0),
        "data_management": bool(workspaces and intent_ready),
        "operational_risk": bool(workspaces and flow_workspaces),
    }
    domains = review.get("domains", {}) if isinstance(review.get("domains"), dict) else {}
    if not all(isinstance(domains.get(name), dict) and domains[name].get("passed") is passed for name, passed in recomputed.items()):
        return False
    expected_passed = bool(completed) and all(recomputed.values())
    return (
        review.get("passed") is expected_passed
        and _safe_int(review.get("app_id_present_count", -1), -1) == len(rows)
        and _safe_int(review.get("completed_target_count", -1), -1) == len(completed)
        and _safe_int(review.get("workspace_review_count", -1), -1) == len(workspaces)
        and _safe_int(review.get("http_review_count", -1), -1) == len(http_rows)
        and _safe_int(review.get("deep_http_review_count", -1), -1) == len(deep_http)
        and _safe_int(review.get("flow_review_count", -1), -1) == len(flow_workspaces)
        and _safe_int(review.get("valid_public_endpoint_count", -1), -1) == valid_endpoint_count
        and _safe_int(review.get("invalid_public_endpoint_count", -1), -1) == invalid_endpoint_count
    )


def _row_requested_review(row: dict[str, Any]) -> dict[str, Any]:
    return row.get("requested_review", {}) if isinstance(row.get("requested_review"), dict) else {}


def _row_review_coverage(row: dict[str, Any]) -> dict[str, Any]:
    evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
    return evidence.get("review_coverage", {}) if isinstance(evidence.get("review_coverage"), dict) else {}


def _release_workspace_evidence_complete(row: dict[str, Any]) -> bool:
    if row.get("kind") != "workspace":
        return False
    coverage = _row_review_coverage(row)
    evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
    snapshot = evidence.get("source_tree_snapshot", {}) if isinstance(evidence.get("source_tree_snapshot"), dict) else {}
    consistency = evidence.get("source_tree_consistency", {}) if isinstance(evidence.get("source_tree_consistency"), dict) else {}
    inventory = coverage.get("inventory", {}) if isinstance(coverage.get("inventory"), dict) else {}
    supported_count = _safe_int(inventory.get("supported_file_count", 0))
    reviewed_count = _safe_int(inventory.get("reviewed_candidate_count", inventory.get("scanned_text_file_count", 0)))
    production_count = _safe_int(inventory.get("production_source_file_count", 0))
    scanned_production_count = _safe_int(inventory.get("scanned_production_source_file_count", 0))
    substantive_production_count = _safe_int(inventory.get("substantive_production_source_file_count", 0))
    return (
        coverage.get("source_kind") == "workspace"
        and coverage.get("raw_returned") is False
        and consistency.get("matched") is True
        and consistency.get("raw_returned") is False
        and inventory.get("raw_returned") is False
        and supported_count > 0
        and 0 < reviewed_count <= supported_count
        and 0 < production_count <= reviewed_count
        and 0 < scanned_production_count <= production_count
        and 0 < substantive_production_count <= scanned_production_count
        and snapshot.get("schema") == "k_guard_source_tree_snapshot.v1"
        and snapshot.get("collector") == "bounded_independent_release_snapshot.v1"
        and isinstance(snapshot.get("tree_sha256"), str)
        and len(snapshot.get("tree_sha256", "")) == 64
        and _safe_int(snapshot.get("file_count", 0)) > 0
        and _safe_int(snapshot.get("hashed_file_count", 0)) == _safe_int(snapshot.get("file_count", -1), -1)
        and _safe_int(snapshot.get("unreadable_file_count", -1), -1) == 0
        and _safe_int(snapshot.get("oversized_file_count", -1), -1) == 0
        and _safe_int(snapshot.get("skipped_symlink_tree_count", -1), -1) == 0
        and snapshot.get("complete") is True
        and snapshot.get("limit_exceeded") is False
        and isinstance(snapshot.get("bounds"), dict)
        and snapshot.get("raw_returned") is False
    )


def _release_http_evidence_complete(row: dict[str, Any]) -> bool:
    if row.get("kind") != "http" or _row_review_coverage(row).get("source_kind") != "http":
        return False
    requested = _row_requested_review(row)
    evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
    contract = evidence.get("dynamic_probe_contract", {}) if isinstance(evidence.get("dynamic_probe_contract"), dict) else {}
    required_count = _safe_int(contract.get("required_path_count", 0))
    required_refs = contract.get("required_path_refs", []) if isinstance(contract.get("required_path_refs"), list) else []
    reached_refs = contract.get("required_path_reached_refs", []) if isinstance(contract.get("required_path_reached_refs"), list) else []
    methods = contract.get("methods", []) if isinstance(contract.get("methods"), list) else []
    return (
        _row_review_coverage(row).get("raw_returned") is False
        and contract.get("raw_returned") is False
        and _safe_int(requested.get("valid_public_endpoint_count", 0)) > 0
        and _safe_int(requested.get("invalid_public_endpoint_count", 0)) == 0
        and _safe_int(contract.get("request_count", 0)) > 0
        and _safe_int(contract.get("error_request_count", -1), -1) == 0
        and "GET" in methods
        and required_count > 0
        and _safe_int(contract.get("required_path_reached_count", 0)) == required_count
        and len(required_refs) == required_count
        and len(set(required_refs)) == required_count
        and set(reached_refs) == set(required_refs)
    )


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def _guardian_evidence_bundle_matches_report(report: dict[str, Any], manifest_path: str | Path | None = None) -> bool:
    bundle = report.get("evidence_bundle")
    if not _valid_evidence_bundle(bundle, require_operator_key=True):
        return False
    expected = [
        object_artifact("report_identity", guardian_report_identity(report), role="identity"),
        object_artifact("execution_attestation", report.get("execution_attestation", {}), role="identity"),
        object_artifact("toolchain_contract", report.get("toolchain_contract", {}), role="identity"),
        object_artifact("summary", report.get("summary", {})),
        object_artifact("execution_contract", report.get("execution_contract", {})),
        object_artifact("intent_contract", report.get("intent_contract", {})),
        object_artifact("review_contract", report.get("review_contract", {})),
        object_artifact("deep_analyzer_reports", report.get("deep_analyzer_reports", []), role="analysis"),
        object_artifact("software_composition_reports", report.get("software_composition_reports", []), role="analysis"),
        object_artifact("release_qualification", report.get("release_qualification", {}), role="gate"),
        object_artifact("baseline", report.get("baseline", {})),
        object_artifact("drift", report.get("drift", {})),
        object_artifact("guardian_gate", report.get("guardian_gate", {}), role="gate"),
        object_artifact("release_authority_claim", report.get("release_authority_claim", {}), role="gate"),
        object_artifact("suppression_policy", report.get("suppression_policy", {}), role="policy"),
        object_artifact("target_refs", release_target_evidence_refs(report.get("targets", []))),
        object_artifact("top_rules", report.get("top_rules", [])),
    ]
    if manifest_path:
        expected.insert(0, path_artifact("guardian_manifest", manifest_path, role="input"))
    return _bundle_contains_expected_artifacts(bundle, expected)


def _release_qualification_complete(value: dict[str, Any]) -> bool:
    gates = value.get("gates", {}) if isinstance(value.get("gates"), dict) else {}
    expected = {
        "deep_multilang",
        "software_composition",
        "streamable_http_runtime",
        "agent_database_controls",
        "field_accuracy",
    }
    return (
        value.get("schema") == "k_guard_release_qualification.v1"
        and value.get("passed") is True
        and value.get("canonical_release_prerequisite") is True
        and value.get("fail_closed") is True
        and value.get("missing_inputs") == []
        and set(gates) == expected
        and all(
            isinstance(gates[name], dict)
            and gates[name].get("passed") is True
            and gates[name].get("failed_checks") == []
            for name in expected
        )
    )


def _guardian_source_snapshots_match(report: dict[str, Any], manifest_path: str | Path | None) -> bool:
    if not manifest_path:
        return False
    try:
        current = guardian_current_source_snapshots(manifest_path)
    except Exception:
        return False
    reported: dict[str, dict[str, Any]] = {}
    for row in report.get("targets", []):
        if not isinstance(row, dict) or row.get("kind") != "workspace":
            continue
        evidence = row.get("review_evidence", {}) if isinstance(row.get("review_evidence"), dict) else {}
        snapshot = evidence.get("source_tree_snapshot", {}) if isinstance(evidence.get("source_tree_snapshot"), dict) else {}
        reported[str(row.get("target_id") or "")] = snapshot
    return bool(current) and set(current) == set(reported) and all(current[target_id] == reported[target_id] for target_id in current)


def _bundle_contains_expected_artifacts(bundle: object, expected: list[dict[str, Any]]) -> bool:
    if not isinstance(bundle, dict) or not isinstance(bundle.get("artifacts"), list):
        return False
    artifacts = [artifact for artifact in bundle["artifacts"] if isinstance(artifact, dict)]
    for expected_artifact in expected:
        match = next(
            (
                artifact
                for artifact in artifacts
                if artifact.get("label") == expected_artifact.get("label")
                and artifact.get("role", "evidence") == expected_artifact.get("role", "evidence")
            ),
            None,
        )
        if not match or match.get("raw_returned") is not False:
            return False
        for key in ("hash", "hash_scheme", "byte_count", "content_sha256", "exists_at_bundle_time"):
            if key in expected_artifact and match.get(key) != expected_artifact.get(key):
                return False
    return True


def _target_business_contexts_complete(report: dict[str, Any]) -> bool:
    targets = report.get("targets", [])
    if not isinstance(targets, list):
        return False
    for row in targets:
        if not isinstance(row, dict):
            return False
        business = row.get("business_context", {}) if isinstance(row.get("business_context"), dict) else {}
        if business.get("purpose_present") is not True or business.get("purpose_explicit") is not True:
            return False
        try:
            custom_data_class_count = int(business.get("custom_data_class_count", 0))
        except (TypeError, ValueError):
            custom_data_class_count = 0
        if not business.get("data_classes") and custom_data_class_count <= 0:
            return False
        if business.get("user_scope_present") is not True:
            return False
    return True


def _target_review_profiles_complete(report: dict[str, Any]) -> bool:
    targets = report.get("targets", [])
    return isinstance(targets, list) and bool(targets) and all(isinstance(row, dict) and row.get("audit_profile") == "korean_senior" for row in targets)


def _guardian_single_app_scope(report: dict[str, Any]) -> bool:
    targets = report.get("targets", [])
    review = report.get("review_contract", {}) if isinstance(report.get("review_contract"), dict) else {}
    if not isinstance(targets, list) or not targets or not all(isinstance(row, dict) for row in targets):
        return False
    app_ids = {str(row.get("app_id") or "").strip() for row in targets}
    if "" in app_ids or len(app_ids) != 1:
        return False
    app_id = next(iter(app_ids))
    return (
        review.get("app_id") == app_id
        and review.get("app_id_values") == [app_id]
        and review.get("app_id_complete") is True
        and review.get("single_app_scope") is True
        and review.get("app_scope_enforced") is True
        and _safe_int(review.get("app_id_present_count", -1), -1) == len(targets)
    )


def _target_thresholds_high(report: dict[str, Any]) -> bool:
    targets = report.get("targets", [])
    return isinstance(targets, list) and bool(targets) and all(isinstance(row, dict) and row.get("fail_on") == "high" for row in targets)


def _guardian_has_no_high_critical_findings(report: dict[str, Any]) -> bool:
    targets = report.get("targets", [])
    if not isinstance(targets, list) or not targets:
        return False
    for row in targets:
        if not isinstance(row, dict) or not isinstance(row.get("findings"), list):
            return False
        for finding in row["findings"]:
            if not isinstance(finding, dict):
                return False
            raw_severity = finding.get("severity")
            if not isinstance(raw_severity, str):
                return False
            severity = raw_severity.strip().lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                return False
            if severity in {"critical", "high"}:
                return False
    return True


def _target_scope_assertions_complete(report: dict[str, Any]) -> bool:
    targets = report.get("targets", [])
    if not isinstance(targets, list):
        return False
    for row in targets:
        if not isinstance(row, dict):
            return False
        scope = row.get("scope_contract", {}) if isinstance(row.get("scope_contract"), dict) else {}
        if scope.get("assertion_present") is not True:
            return False
        if scope.get("ownership_or_partner_scope_verified_by_k_guard") is not False:
            return False
        assertion_ref = scope.get("assertion_ref", {}) if isinstance(scope.get("assertion_ref"), dict) else {}
        if assertion_ref.get("raw_returned") is not False or not assertion_ref.get("hash"):
            return False
    return True


def _guardian_suppression_checks(report: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    if "suppression_policy" not in report:
        checks.append(_check("guardian_suppression_policy_valid", True, "info", "no_suppression_policy_applied"))
        checks.append(_check("guardian_suppression_waivers_bound", True, "info", "no_waived_findings"))
        checks.append(_check("guardian_suppression_release_scope_bound", True, "info", "no_waived_findings"))
        checks.append(_check("guardian_suppression_evidence_fresh", True, "info", "no_suppression_evidence_to_expire"))
        return
    policy = report.get("suppression_policy")
    valid_shape = _valid_suppression_policy_shape(policy)
    checks.append(_check("guardian_suppression_policy_valid", valid_shape, "blocker", "signed_policy_sha256_and_fail_closed_shape_required"))
    checks.append(_check("guardian_suppression_waivers_bound", valid_shape and _suppression_waivers_bound(policy), "blocker", "waived_finding_refs_must_match_suppressed_findings"))
    checks.append(_check("guardian_suppression_release_scope_bound", valid_shape and _suppression_release_scope_bound(policy, report), "blocker", "waivers_must_match_current_app_profile_and_release_scope"))
    checks.append(_check("guardian_suppression_evidence_fresh", valid_shape and _suppression_evidence_current(policy, report.get("evidence_bundle")), "blocker", "suppression_evidence_must_be_fresh_and_unexpired"))


def _valid_suppression_policy_shape(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    source = value.get("source", {}) if isinstance(value.get("source"), dict) else {}
    policy_sha256 = str(value.get("policy_sha256") or "")
    return (
        value.get("schema") == "k_guard_suppression_evidence.v2"
        and re.fullmatch(r"[0-9a-f]{64}", policy_sha256) is not None
        and source.get("content_sha256") == policy_sha256
        and source.get("exists_at_evaluation") is True
        and _safe_int(source.get("byte_count", -1), -1) > 0
        and _safe_int(value.get("invalid_count", -1), -1) == 0
        and _safe_int(value.get("valid_count", -1), -1) >= 0
        and value.get("fail_closed_on_invalid_policy") is True
        and value.get("required_fields") == [
            "app_id",
            "audit_profile",
            "release_scope_hash",
            "target_id",
            "rule_id",
            "finding_fingerprint",
            "owner",
            "reason",
            "expires",
        ]
        and value.get("raw_returned") is False
        and source.get("raw_returned") is False
    )


def _suppression_waivers_bound(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    suppressed = value.get("suppressed", []) if isinstance(value.get("suppressed"), list) else []
    waived = value.get("waived_finding_refs", []) if isinstance(value.get("waived_finding_refs"), list) else []
    expected = []
    for item in suppressed:
        if not isinstance(item, dict):
            return False
        expected.append(
            {
                "app_id_hash": str(item.get("app_id_hash") or ""),
                "audit_profile": str(item.get("audit_profile") or ""),
                "release_scope_hash": str(item.get("release_scope_hash") or ""),
                "target_id": str(item.get("target_id") or ""),
                "rule_id": str(item.get("rule_id") or ""),
                "finding_fingerprint": str(item.get("finding_fingerprint") or ""),
                "expires": str(item.get("expires") or ""),
                "owner_hash": evidence_hash(str(item.get("owner") or "")),
                "reason_hash": str(item.get("reason_hash") or ""),
                "raw_returned": False,
            }
        )
    expected.sort(key=lambda item: (item["app_id_hash"], item["target_id"], item["rule_id"], item["finding_fingerprint"]))
    return (
        _safe_int(value.get("suppressed_count", -1), -1) == len(suppressed) == len(waived)
        and _safe_int(value.get("valid_count", -1), -1) >= len(waived)
        and waived == expected
        and all(
            item["app_id_hash"]
            and item["audit_profile"] == "korean_senior"
            and item["release_scope_hash"]
            and item["target_id"]
            and item["rule_id"]
            and item["finding_fingerprint"]
            and item["expires"]
            for item in expected
        )
    )


def _suppression_release_scope_bound(value: object, report: dict[str, Any]) -> bool:
    if not isinstance(value, dict):
        return False
    rows = report.get("targets", []) if isinstance(report.get("targets"), list) else []
    bindings: dict[str, dict[str, str]] = {}
    for row in rows:
        if not isinstance(row, dict):
            return False
        target_id = str(row.get("target_id") or "")
        if not target_id or target_id in bindings:
            return False
        bindings[target_id] = _guardian_row_suppression_binding(row)
    for collection_name in ("suppressed", "waived_finding_refs"):
        collection = value.get(collection_name, [])
        if not isinstance(collection, list):
            return False
        for item in collection:
            if not isinstance(item, dict):
                return False
            binding = bindings.get(str(item.get("target_id") or ""))
            if binding is None:
                return False
            if (
                str(item.get("app_id_hash") or "") != evidence_hash(binding["app_id"])
                or str(item.get("audit_profile") or "") != binding["audit_profile"]
                or str(item.get("release_scope_hash") or "") != binding["release_scope_hash"]
            ):
                return False
    return True


def _suppression_evidence_current(value: object, bundle: object) -> bool:
    if not isinstance(value, dict) or not isinstance(bundle, dict):
        return False
    evaluated = _parse_aware_datetime(value.get("evaluated_at"))
    fresh_until = _parse_aware_datetime(value.get("fresh_until"))
    bundle_generated = _parse_aware_datetime(bundle.get("generated_at"))
    freshness_seconds = _safe_int(value.get("freshness_seconds", 0))
    if evaluated is None or fresh_until is None or bundle_generated is None or not 0 < freshness_seconds <= 24 * 60 * 60:
        return False
    now = datetime.now(UTC)
    if not (evaluated <= bundle_generated <= fresh_until and evaluated <= now <= fresh_until):
        return False
    if (fresh_until - evaluated).total_seconds() > freshness_seconds:
        return False
    policy_expiries = value.get("policy_expiries", []) if isinstance(value.get("policy_expiries"), list) else []
    waived = value.get("waived_finding_refs", []) if isinstance(value.get("waived_finding_refs"), list) else []
    try:
        expiry_dates = [date.fromisoformat(str(item)) for item in policy_expiries]
        waived_expiries = [date.fromisoformat(str(item.get("expires") or "")) for item in waived if isinstance(item, dict)]
    except ValueError:
        return False
    if any(expiry < now.date() for expiry in [*expiry_dates, *waived_expiries]):
        return False
    if waived and (not policy_expiries or not set(waived_expiries).issubset(set(expiry_dates))):
        return False
    return True


def _valid_evidence_bundle(value: object, *, require_operator_key: bool = False) -> bool:
    return verify_evidence_bundle(value, require_operator_key=require_operator_key)


def _check_projection(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": check.get("name"),
            "passed": check.get("passed"),
            "severity": check.get("severity"),
            "detail": check.get("detail"),
        }
        for check in checks
    ]


def _canonical_false_positive_limit(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    candidate = float(value)
    if not math.isfinite(candidate) or not 0.0 <= candidate <= 0.20:
        return None
    return candidate


def _finite_rate(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    candidate = float(value)
    return candidate if math.isfinite(candidate) else None


def _parse_aware_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _valid_generated_timestamp(value: object) -> bool:
    return _parse_aware_datetime(value) is not None


def _check(name: str, passed: bool, severity: str, detail: str, **extra: Any) -> dict[str, Any]:
    item = {
        "name": name,
        "passed": bool(passed),
        "severity": severity,
        "detail": detail,
    }
    item.update(extra)
    return item


def _bound_value_ref(value: object) -> dict[str, Any]:
    text = str(value or "").strip()
    return {
        "configured": bool(text),
        "hash": evidence_hash(text) if text else "",
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _empty_ref() -> dict[str, Any]:
    return {
        "hash": "",
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _valid_bound_ref(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get("configured") is True
        and re.fullmatch(r"[0-9a-f]{16}", str(value.get("hash") or "")) is not None
        and value.get("hash_scheme") == evidence_hash_scheme()
        and value.get("raw_returned") is False
    )


def _path_ref(path: str | Path) -> dict[str, Any]:
    text = str(path)
    return {
        "hash": evidence_hash(text),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _content_ref(path: str | Path) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except Exception:
        text = ""
    return {
        "hash": evidence_hash(text),
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }


def _bundle_ref(bundle: object) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        return {"bundle_sha256": "", "hash_scheme": evidence_hash_scheme(), "raw_returned": False}
    bundle_sha256 = str(bundle.get("bundle_sha256") or "")
    signature = bundle.get("signature", {}) if isinstance(bundle.get("signature"), dict) else {}
    return {
        "bundle_sha256": bundle_sha256,
        "signature_sha256_hash": f"h_{evidence_hash(str(signature.get('signature_sha256') or ''))}",
        "hash_scheme": evidence_hash_scheme(),
        "raw_returned": False,
    }
