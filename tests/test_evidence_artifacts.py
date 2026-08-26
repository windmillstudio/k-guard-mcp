from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_checked_in_evidence_hash_inventory_is_complete_and_valid() -> None:
    checksum_file = ROOT / "evidence" / "SHA256SUMS"
    rows = [line.split("  ", 1) for line in checksum_file.read_text(encoding="utf-8").splitlines() if line]
    listed = {relative for _digest, relative in rows}
    actual = {
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "evidence").rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }

    assert listed == actual
    for expected, relative in rows:
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected


def test_checked_in_owasp_evidence_keeps_claim_boundary_and_candidate_metrics() -> None:
    report = json.loads(
        (ROOT / "evidence" / "public" / "owasp-benchmark-python-f1291485" / "benchmark-score.json").read_text(
            encoding="utf-8"
        )
    )
    candidate = report["all_high_critical_candidate_validation"]

    assert report["score"]["total_official_case_count"] == 1230
    assert report["score"]["supported_case_count"] == 366
    assert candidate["verdict_counts"] == {
        "benign": 0,
        "false_positive": 34,
        "inconclusive": 0,
        "true_positive": 151,
    }
    assert candidate["rates"]["precision"] == 0.816216
    assert candidate["rates"]["false_positive_rate"] == 0.051163
    assert report["repeat_reproducibility"]["exact_candidate_multiset_match"] is True
    assert report["claim_boundary"]["used_for_rule_development_not_blind_holdout"] is True
    assert report["claim_boundary"]["does_not_establish_owned_partner_field_accuracy"] is True


def test_checked_in_mutation_evidence_stays_single_pattern_regression_only() -> None:
    report = json.loads(
        (ROOT / "evidence" / "mutation" / "express-idor-25" / "mutation-score.json").read_text(encoding="utf-8")
    )

    assert report["mutation_count"] == 25
    assert report["case_counts"] == {
        "true_positive": 25,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 25,
    }
    assert report["reproducibility"]["exact_candidate_multiset_match"] is True
    assert report["diversity"]["evidence_grade"] == "single_pattern_seeded_regression"
    assert report["claim_boundary"]["not_a_public_or_field_benchmark"] is True


def test_checked_in_mcp_evasion_calibration_improves_bounded_recall_without_field_overclaim() -> None:
    report = json.loads(
        (ROOT / "evidence" / "regression" / "mcp-evasion-normalization.json").read_text(encoding="utf-8")
    )

    assert report["positive_count"] == 24
    assert report["negative_count"] == 20
    assert report["legacy_direct_only"]["recall"] == 0.166667
    assert report["bounded_normalization"] == {
        "true_positive": 24,
        "false_negative": 0,
        "false_positive": 0,
        "true_negative": 20,
        "recall": 1.0,
        "false_positive_rate": 0.0,
    }
    assert report["passed"] is True
    assert report["claim_boundary"]["synthetic_evasion_regression_only"] is True
    assert report["claim_boundary"]["not_field_accuracy"] is True
    assert report["claim_boundary"]["not_competitor_benchmark"] is True


def test_checked_in_contest_demo_proves_fix_without_claiming_ship() -> None:
    report = json.loads((ROOT / "evidence" / "demo" / "contest-demo-scorecard.json").read_text(encoding="utf-8"))

    assert report["passed"] is True
    assert report["transition"] == ["hold_fix", "hold_qualification"]
    assert report["application_transition"] == ["risk_blocked", "clear_in_reviewed_scope"]
    assert all(report["checks"].values())
    assert report["release_authority_claimed"] is False
    assert report["raw_returned"] is False


def test_final_public_app_replay_stays_cold_and_fail_closed() -> None:
    evidence_dir = ROOT / "evidence" / "public" / "public-vibe-apps-16-final-r3"
    status = json.loads((evidence_dir / "effectiveness-status.json").read_text(encoding="utf-8"))
    reuse = json.loads((evidence_dir / "review-reuse.json").read_text(encoding="utf-8"))

    assert status["integrity_passed"] is True
    assert status["qualified"] is False
    assert status["verdict"] == "hold"
    assert status["metrics"]["app_count"] == 16
    assert status["metrics"]["exact_repeat_app_count"] == 16
    assert status["metrics"]["candidate_count"] == 23
    assert status["metrics"]["candidate_label_counts"] == {
        "benign": 13,
        "false_positive": 7,
        "true_positive": 3,
    }
    assert status["metrics"]["adjudicated_precision_tp_fp_only"] == 0.3
    assert status["metrics"]["adjudicated_precision_tp_fp_only_wilson_95_lower"] == 0.107791
    assert status["metrics"]["blocker_actionability"] == 0.130435
    assert status["metrics"]["blocker_actionability_wilson_95_lower"] == 0.045377
    assert status["metrics"]["non_actionable_blocker_count"] == 20
    assert status["metrics"]["reviewer_unanimous_rate"] == 0.956522
    assert status["blockers"] == [
        "evaluable_candidate_count_below_locked_minimum",
        "blocker_actionability_below_locked_minimum",
        "blocker_actionability_wilson_lower_below_locked_minimum",
    ]
    assert status["claim_boundary"]["same_provider_model_family_ai_review_only"] is True
    assert status["claim_boundary"]["does_not_grant_release_authority"] is True
    assert reuse["exact_candidate_binding_match"] is True
    assert reuse["not_human_or_cross_vendor_review"] is True


def test_precision_r5_retains_full_reports_and_honest_actionability_hold() -> None:
    evidence_dir = ROOT / "evidence" / "public" / "public-vibe-apps-16-precision-r5"
    status = json.loads((evidence_dir / "effectiveness-status.json").read_text(encoding="utf-8"))
    queue = json.loads((evidence_dir / "candidate-queue.json").read_text(encoding="utf-8"))

    assert len(list((evidence_dir / "reports").glob("*-run*.json"))) == 32
    assert status["integrity_passed"] is True
    assert status["qualified"] is False
    assert status["metrics"]["candidate_count"] == 22
    assert status["metrics"]["candidate_label_counts"] == {
        "benign": 17,
        "false_positive": 2,
        "true_positive": 3,
    }
    assert status["metrics"]["blocker_actionability"] == 0.136364
    assert status["metrics"]["blocker_actionability_wilson_95_lower"] == 0.04749
    assert status["metrics"]["candidate_sample_coverage"] == 1.0
    assert sum(queue["sampling"]["all_release_blockers_by_app"].values()) == 100
    assert sum(queue["sampling"]["available_by_app"].values()) == 99
    assert sum(queue["sampling"]["unlocatable_by_app"].values()) == 1


def test_r5_release_lane_projection_preserves_every_legacy_blocker() -> None:
    projection = json.loads(
        (ROOT / "evidence" / "development" / "r5-release-lane-projection.json").read_text(
            encoding="utf-8"
        )
    )

    assert projection["blocking_policy"] == "k_guard_release_lanes_v3"
    assert projection["population"]["high_critical_finding_count"] == 598
    assert projection["population"]["lane_counts"] == {
        "manual_review_hold": 76,
        "policy_integrity_hold": 5,
        "release_blocking": 20,
        "supporting_review": 497,
    }
    assert projection["legacy_comparison"] == {
        "current_hold_count": 101,
        "legacy_blockers_lost_count": 0,
        "legacy_blockers_lost_rule_counts": {},
        "legacy_blocking_count": 100,
        "newly_held_count": 1,
        "newly_held_rule_counts": {"CONNECTOR_LOCAL_STORAGE_COVERAGE_INCOMPLETE": 1},
    }
    assert all(projection["checks"].values())
    assert projection["claim_boundary"]["proves_detection_precision"] is False


def test_public_release_app_r1_preserves_failed_independent_result() -> None:
    evidence_dir = ROOT / "evidence" / "public" / "holdout" / "vibe-release-apps-20-r1"
    status = json.loads((evidence_dir / "effectiveness-status.json").read_text(encoding="utf-8"))
    labels = json.loads((evidence_dir / "candidate-labels.json").read_text(encoding="utf-8"))
    external = json.loads((evidence_dir / "external-cto-review.json").read_text(encoding="utf-8"))
    projection = json.loads(
        (ROOT / "evidence" / "development" / "r1-release-actionability-projection.json").read_text(
            encoding="utf-8"
        )
    )

    assert len(list((evidence_dir / "reports").glob("*-run*.json"))) == 40
    assert status["integrity_passed"] is True
    assert status["qualified"] is False
    assert status["verdict"] == "hold"
    assert status["metrics"]["app_count"] == 20
    assert status["metrics"]["exact_repeat_app_count"] == 20
    assert status["metrics"]["candidate_count"] == 54
    assert status["metrics"]["candidate_label_counts"] == {
        "benign": 9,
        "false_positive": 25,
        "true_positive": 20,
    }
    assert status["metrics"]["blocker_actionability"] == 0.37037
    assert status["metrics"]["blocker_actionability_wilson_95_lower"] == 0.254234
    assert status["metrics"]["reviewer_unanimous_rate"] == 0.759259
    assert status["thresholds"]["minimum_blocker_actionability"] == 0.9
    assert status["thresholds"]["minimum_blocker_actionability_wilson_95_lower"] == 0.8
    assert len(labels["candidates"]) == 54
    assert labels["review_provenance"]["same_provider_model_family_ai_only"] is True
    assert external["consensus"] == {
        "claim_allowed": False,
        "parse_failure_lane_correction_appropriate": True,
        "verdict": "hold",
    }
    assert external["claim_boundary"]["candidate_source_review"] is False
    assert external["claim_boundary"]["human_review"] is False
    assert projection["release_blocking_policy"] == "k_guard_release_lanes_v3"
    assert projection["population"]["candidate_count"] == 9
    assert projection["population"]["candidate_label_counts"] == {
        "benign": 0,
        "false_positive": 0,
        "inconclusive": 0,
        "true_positive": 9,
    }
    assert projection["metrics"]["automatic_block_actionability"] == 1.0
    assert projection["metrics"]["automatic_block_actionability_wilson_95_lower"] == 0.700855
    assert projection["claim_boundary"]["qualifies_release_blocking_policy"] is False


def test_public_release_app_r4_preserves_locked_hold_result() -> None:
    evidence_dir = ROOT / "evidence" / "public" / "holdout" / "vibe-release-apps-27-r4"
    status = json.loads((evidence_dir / "effectiveness-status.json").read_text(encoding="utf-8"))
    labels = json.loads((evidence_dir / "candidate-labels.json").read_text(encoding="utf-8"))

    assert status["integrity_passed"] is True
    assert status["qualified"] is False
    assert status["verdict"] == "hold"
    assert status["metrics"]["app_count"] == 27
    assert status["metrics"]["exact_repeat_app_count"] == 27
    assert status["metrics"]["candidate_count"] == 105
    assert status["metrics"]["candidate_label_counts"] == {
        "benign": 28,
        "inconclusive": 3,
        "true_positive": 74,
    }
    assert status["metrics"]["blocker_actionability"] == 0.704762
    assert status["metrics"]["blocker_actionability_wilson_95_lower"] == 0.611535
    assert status["metrics"]["fully_actionable_blocker_app_rate"] == 0.44
    assert status["metrics"]["fully_actionable_blocker_app_wilson_95_lower"] == 0.266656
    assert status["metrics"]["reviewer_unanimous_rate"] == 0.571429
    assert status["metrics"]["single_rule_candidate_share"] == 0.561905
    assert status["thresholds"]["minimum_blocker_actionability"] == 0.9
    assert status["thresholds"]["minimum_blocker_actionability_wilson_95_lower"] == 0.8
    assert status["thresholds"]["minimum_fully_actionable_app_rate"] == 0.9
    assert status["thresholds"]["minimum_fully_actionable_app_wilson_95_lower"] == 0.8
    assert len(labels["candidates"]) == 105
    assert status["claim_boundary"]["owned_or_partner_scope"] is False
    assert status["claim_boundary"]["full_app_recall_measured"] is False
    assert status["claim_boundary"]["runtime_exploitability_measured"] is False


def test_r4_v4_projection_records_improvement_without_reusing_the_holdout() -> None:
    projection = json.loads(
        (
            ROOT
            / "evidence"
            / "public"
            / "holdout"
            / "vibe-release-apps-27-r4"
            / "release-actionability-projection-v4.json"
        ).read_text(encoding="utf-8")
    )

    assert projection["release_blocking_policy"] == "k_guard_release_lanes_v4"
    assert projection["population"]["candidate_count"] == 63
    assert projection["population"]["candidate_label_counts"] == {
        "benign": 1,
        "false_positive": 0,
        "inconclusive": 0,
        "true_positive": 62,
    }
    assert projection["metrics"]["automatic_block_actionability"] == 0.984127
    assert projection["metrics"]["automatic_block_actionability_wilson_95_lower"] == 0.915415
    assert projection["claim_boundary"]["independent_post_fix_holdout"] is False
    assert projection["claim_boundary"]["qualifies_release_blocking_policy"] is False


def test_r4_docker_lane_replay_content_binds_every_manual_hold() -> None:
    replay = json.loads(
        (
            ROOT
            / "evidence"
            / "public"
            / "holdout"
            / "vibe-release-apps-27-r4"
            / "docker-lane-replay-v4.json"
        ).read_text(encoding="utf-8")
    )

    assert replay["release_blocking_policy"] == "k_guard_release_lanes_v4"
    assert replay["population"] == {
        "candidate_count": 42,
        "current_lane_counts": {"manual_review_hold": 42},
        "current_subtype_counts": {
            "docker_socket_api_endpoint": 6,
            "docker_socket_bind_mount": 24,
            "docker_socket_documentation": 5,
            "docker_socket_reference": 7,
        },
        "frozen_label_counts": {
            "benign": 27,
            "inconclusive": 3,
            "true_positive": 12,
        },
    }
    assert all(replay["checks"].values())
    assert len(replay["rows"]) == 42
    assert all(len(row["source_file_sha256"]) == 64 for row in replay["rows"])
    assert all(len(row["source_line_sha256"]) == 64 for row in replay["rows"])
    assert replay["claim_boundary"]["independent_post_fix_holdout"] is False
    assert replay["claim_boundary"]["qualifies_release_blocking_policy"] is False
    assert replay["raw_returned"] is False


def test_full_dogfood_snapshot_keeps_beta_and_authority_boundaries_separate() -> None:
    evidence_dir = ROOT / "evidence" / "dogfood" / "2026-07-15"
    wheel = json.loads((evidence_dir / "fresh-wheel-stdio-smoke.json").read_text(encoding="utf-8"))
    cisco = json.loads((evidence_dir / "cisco-yara-kguard.json").read_text(encoding="utf-8"))
    readiness = json.loads((evidence_dir / "contest-readiness-before.json").read_text(encoding="utf-8"))

    assert wheel["passed"] is True
    assert wheel["contract"]["tool_count"] == 28
    assert wheel["contract"]["guardian_passed"] is False
    assert wheel["contract"]["guardian_canonical_release_authority"] is False
    assert cisco["requested_analyzers"] == ["yara"]
    assert len(cisco["scan_results"]) == 28
    assert all(result["is_safe"] for result in cisco["scan_results"])
    assert readiness["package_ready"] is False
    assert readiness["award_evidence_ready"] is False
