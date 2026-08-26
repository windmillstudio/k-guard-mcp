#!/usr/bin/env python3
"""Run the test surface reproducible from the public source-only snapshot."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# These modules validate separately distributed evidence, contest documents,
# release binaries, host-native ACL behavior, or a committed Git boundary.
# They remain in the source tree for review but are not part of source-only CI.
EVIDENCE_BOUND_MODULES = (
    "tests/test_ai_public_benchmark_scorecard.py",
    "tests/test_compare_l1_benchmarkjava_denominator_repeats.py",
    "tests/test_compare_l1_benchmarkpython_denominator_repeats.py",
    "tests/test_compare_release_program_goal_state_repeats.py",
    "tests/test_contest_claim_contract.py",
    "tests/test_contest_demo_journey.py",
    "tests/test_contest_readiness.py",
    "tests/test_contest_report_html.py",
    "tests/test_evaluate_korean_privacy_holdout.py",
    "tests/test_evidence_artifacts.py",
    "tests/test_holdout_integrity.py",
    "tests/test_qualify_korean_privacy_ai_only.py",
    "tests/test_release_archives.py",
    "tests/test_verify_contest_report.py",
    "tests/test_verify_official_contest_report.py",
)

PUBLIC_SOURCE_DESELECTED_TESTS = (
    "tests/test_execute_supervisor_review.py::test_execute_review_binds_verified_claude_tool_attestation_without_raw_output",
    "tests/test_execute_supervisor_review.py::test_approved_payload_binds_external_direct_evidence_without_packet_path_leak",
    "tests/test_holdout_scan_launcher.py::test_runtime_object_attestation_detects_native_acl_write",
    "tests/test_installer.py::test_doctor_rejects_receipt_with_explicit_everyone_ace",
    "tests/test_js_command_sink_projection.py::test_projection_separates_detector_error_from_release_actionability",
    "tests/test_js_command_sink_projection.py::test_projection_fails_hypothesis_for_unlabeled_current_candidate",
    "tests/test_js_command_sink_projection.py::test_projection_fails_closed_on_current_analysis_limit",
    "tests/test_mutable_action_projection.py::test_projection_keeps_prior_labels_separate_from_new_shadow_candidates",
    "tests/test_probe_supervisor_long_packet_transport.py::test_probe_uses_native_executables_and_crosses_cmd_boundary",
    "tests/test_probe_supervisor_long_packet_transport.py::test_probe_fails_closed_when_a_shim_is_retained",
    "tests/test_probe_supervisor_long_packet_transport.py::test_repeat_comparator_requires_two_semantically_identical_fixed_runs",
    "tests/test_probe_supervisor_long_packet_transport.py::test_comparator_rejects_a_tampered_fixed_receipt",
    "tests/test_product_hardening_receipts.py::test_actual_fixture_hashes_are_stable",
    "tests/test_public_app_effectiveness.py::test_public_app_campaign_is_reproducible_but_not_effectiveness_qualified",
    "tests/test_public_app_effectiveness.py::test_public_app_campaign_fails_closed_when_a_label_loses_report_binding",
    "tests/test_public_field_campaign.py::test_checked_in_preregistrations_are_valid_and_stratified",
    "tests/test_release_hygiene.py::test_release_hygiene_default_report_has_release_contract",
    "tests/test_validate_release_program_goals.py::test_checked_in_goal_state_has_one_explicit_active_card",
)


def main(argv: list[str] | None = None) -> int:
    missing = [path for path in EVIDENCE_BOUND_MODULES if not (ROOT / path).is_file()]
    if missing:
        print(json.dumps({"passed": False, "missing_test_modules": missing}, ensure_ascii=False))
        return 2
    arguments = [
        "-q",
        *(f"--ignore={path}" for path in EVIDENCE_BOUND_MODULES),
        *(f"--deselect={node_id}" for node_id in PUBLIC_SOURCE_DESELECTED_TESTS),
    ]
    if argv:
        arguments.extend(argv)
    print(
        json.dumps(
            {
                "suite": "public_source_only",
                "excluded_evidence_bound_modules": len(EVIDENCE_BOUND_MODULES),
                "deselected_evidence_or_native_cases": len(PUBLIC_SOURCE_DESELECTED_TESTS),
                "reason": "separately distributed evidence, contest media/documents, release binaries, or committed Git boundary required",
            },
            ensure_ascii=False,
        )
    )
    return int(pytest.main(arguments))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
