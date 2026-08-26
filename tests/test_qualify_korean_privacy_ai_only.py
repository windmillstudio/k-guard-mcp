from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import qualify_korean_privacy_ai_only as qualification


ROOT = Path(__file__).resolve().parents[1]


def test_qualification_source_scope_includes_only_imported_script_helpers() -> None:
    assert qualification.QUALIFICATION_SOURCE_FILES == (
        "scripts/qualify_korean_privacy_ai_only.py",
        "scripts/evaluate_korean_privacy_holdout.py",
        "scripts/evidence_tree.py",
    )


@pytest.fixture(scope="module")
def report() -> dict:
    return qualification.build_report()


def test_report_is_deterministic_canonical_and_self_validating(report: dict) -> None:
    second = qualification.build_report()

    assert qualification.canonical_json_bytes(report) == qualification.canonical_json_bytes(second)
    assert qualification.validate_report(report) == []
    assert report["schema"] == qualification.REPORT_SCHEMA
    assert report["method"] == qualification.METHOD
    assert report["passed"] is True
    assert report["raw_returned"] is False
    assert len(report["projection_sha256"]) == 64
    assert report["analyzer"]["qualification_sources_match_revision"] is True
    sources = {
        row["path"]: row for row in report["analyzer"]["qualification_source_files"]
    }
    assert set(sources) == {
        "scripts/qualify_korean_privacy_ai_only.py",
        "scripts/evaluate_korean_privacy_holdout.py",
        "scripts/evidence_tree.py",
    }
    assert all(row["working_matches_head"] is True for row in sources.values())


def test_checked_report_matches_current_projection(report: dict) -> None:
    checked = json.loads(qualification.DEFAULT_OUTPUT.read_text(encoding="utf-8"))

    assert qualification.DEFAULT_OUTPUT.read_bytes() == qualification.canonical_json_bytes(
        checked
    )
    assert qualification.validate_report(checked) == []
    assert qualification.canonical_json_bytes(checked) == qualification.canonical_json_bytes(
        report
    )


def test_fixture_and_holdout_are_separate_non_pooled_lanes(report: dict) -> None:
    accounting = report["case_accounting"]

    assert accounting == {
        "combined_confusion_matrix": None,
        "cross_lane_deduplication_claimed": False,
        "fixture_case_count": 117,
        "holdout_case_count": 68,
        "meets_minimum_separate_lane_evaluations": True,
        "minimum_separate_lane_evaluations": 150,
        "pooled_unique_case_count": None,
        "separate_lane_evaluation_count": 185,
        "workspace_contract_case_count": 5,
    }
    fixture = report["lanes"]["current_fixture"]
    assert fixture["positive_count"] == 70
    assert fixture["negative_count"] == 47
    assert fixture["clean_negative_case_count"] == 27
    assert fixture["targeted_absence_case_count"] == 20
    assert fixture["workspace_case_count"] == 5
    assert fixture["workspace_passed_count"] == 5
    assert fixture["category_confusion"] == {
        "clean_negative_cases": {"fn": 0, "fp": 0, "tn": 27, "tp": 0},
        "positive_detection_cases": {"fn": 0, "fp": 0, "tn": 0, "tp": 70},
    }


def test_official_unique_identifier_contract_is_exact(report: dict) -> None:
    contract = report["contracts"]["official_unique_identifiers"]
    rows = {row["concept"]: row for row in contract["concepts"]}

    assert contract["concept_count"] == 4
    assert contract["passed"] is True
    assert set(rows) == {
        "resident_registration_number",
        "foreigner_registration_number",
        "passport_number",
        "driver_license_number",
    }
    assert all(row["governance_declared"] is True for row in rows.values())
    assert all(row["passed"] is True for row in rows.values())
    assert "PII_PASSPORT" in rows["passport_number"]["observed_rules"]
    assert "PII_DRIVER_LICENSE" in rows["driver_license_number"]["observed_rules"]


def test_business_corporate_and_privacy_first_boundaries_are_explicit(report: dict) -> None:
    contract = report["contracts"]["organization_identifiers"]
    rows = {row["contract_id"]: row for row in contract["contracts"]}

    assert contract["passed"] is True
    assert set(rows) == set(qualification.ORGANIZATION_BOUNDARY_CONTRACTS)
    assert all(row["passed"] is True for row in rows.values())
    assert "KR_ORG_BUSINESS_REGISTRATION" in rows["business_checksum_valid"]["observed_rules"]
    assert "KR_ORG_BUSINESS_REGISTRATION" not in rows["business_checksum_invalid"]["observed_rules"]
    assert "KR_ORG_CORPORATE_REGISTRATION" in rows["corporate_historical_checksum"]["observed_rules"]
    assert "KR_ORG_CORPORATE_REGISTRATION" in rows[
        "corporate_current_explicit_context_unverified"
    ]["observed_rules"]
    assert "KR_ORG_CORPORATE_REGISTRATION" not in rows[
        "privacy_first_person_identifier_wins"
    ]["observed_rules"]
    assert "not registry validation" in contract["registry_status"]


def test_six_sensitive_concepts_have_raw_scanner_server_semantic_parity(report: dict) -> None:
    parity = report["contracts"]["sensitive_vocabulary_surface_parity"]
    rows = {row["concept"]: row for row in parity["concepts"]}

    assert parity["concept_count"] == 6
    assert parity["passed"] is True
    assert set(rows) == {"장애", "장애정보", "생체정보", "지문", "홍채", "건강상태"}
    for row in rows.values():
        assert row["raw_predicate"] is True
        assert "SENSITIVE_INFO" in row["raw_detector_labels"]
        assert "PII_SENSITIVE_INFO" in row["scanner_rules"]
        assert "PII_SENSITIVE_INFO" in row["server_rules"]
        assert row["passed"] is True
        assert row["raw_returned"] is False


def test_holdout_exact_two_run_digest_and_category_confusion(report: dict) -> None:
    lane = report["lanes"]["frozen_evaluator_holdout"]

    assert lane["case_count"] == 68
    assert lane["positive_case_count"] == 43
    assert lane["negative_case_count"] == 25
    assert (lane["tp"], lane["fn"], lane["fp"], lane["tn"]) == (43, 0, 0, 25)
    assert lane["exact_two_run"] is True
    assert len(lane["run_digest_sha256"]) == 64
    assert lane["passed"] is True
    assert set(lane["category_confusion"]) == set(
        qualification.holdout.EXPECTED_GROUP_COUNTS
    )
    for category, expected_count in qualification.holdout.EXPECTED_GROUP_COUNTS.items():
        metrics = lane["category_confusion"][category]
        assert metrics["case_count"] == expected_count
        assert metrics["tp"] + metrics["fn"] + metrics["fp"] + metrics["tn"] == expected_count
        assert metrics["fn"] == 0
        assert metrics["fp"] == 0


def test_claim_boundary_is_explicit_and_cannot_be_promoted(report: dict) -> None:
    assert report["claim_boundary"] == {
        "ai_only_development_qualification": True,
        "evaluator_authored": True,
        "field_accuracy": False,
        "field_validation": False,
        "human_adjudication": False,
        "live_registry_validation": False,
        "owned_or_partner_evidence": False,
        "post_implementation_inspection": True,
        "pristine_blind": False,
        "release_authority": False,
        "synthetic": True,
    }

    promoted = json.loads(json.dumps(report, ensure_ascii=False))
    promoted["claim_boundary"]["field_validation"] = True
    assert "claim_boundary_invalid" in qualification.validate_report(promoted)


def test_fixture_digest_is_pinned_and_drift_fails_closed(tmp_path: Path) -> None:
    payload = json.loads(qualification.DEFAULT_FIXTURE.read_text(encoding="utf-8"))
    payload["negatives"][0]["text"] += " drift"
    changed = tmp_path / "fixture.json"
    changed.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    with pytest.raises(qualification.QualificationError, match="fixture digest"):
        qualification.build_report(changed, qualification.DEFAULT_HOLDOUT)


def test_cli_writes_the_deterministic_report(tmp_path: Path) -> None:
    output = tmp_path / "qualification.json"

    assert qualification.main(["--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert output.read_bytes() == qualification.canonical_json_bytes(report)
    assert qualification.validate_report(report) == []
    rendered = output.read_text(encoding="utf-8")
    assert "901225-1234563" not in rendered
    assert "999-99-99997" not in rendered
